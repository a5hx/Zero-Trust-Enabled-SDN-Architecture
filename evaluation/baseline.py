"""Baseline comparison harness: does trust-aware routing actually beat the
alternatives, and by how much?

This is the experiment behind the project's headline claim. It runs the *real*
components -- `controller.edge_selector.select_edge_node`,
`trust_engine.trust_calculator.TrustCalculator`, and
`controller.flow_monitor.evaluate_latency_tell` -- inside a seeded discrete-event
simulation, so a result here is a statement about the shipped code rather than
about a model of it. Only the network and the node agents are simulated.

It is deliberately NOT a Mininet run: 5 strategies x 4 scenarios x 30 seeds is
600 runs, which is minutes here and days on a live topology. The live runs behind
`docs/study/trust-routing-study.html` remain the ground truth for fidelity; this
harness exists to make a *statistical* claim, which needs repetition the live
system cannot give. State that limitation when reporting.

The five routers
----------------
Four baselines and the system under test. All five see the same arrivals, the
same service times, and the same attackers for a given seed, so the comparison is
paired and the only difference is the routing decision:

    random        Uniform over all nodes. The null baseline -- if the system
                  cannot beat this, nothing else matters.
    round_robin   Cyclic. Trust-blind, perfectly fair, and therefore feeds a
                  malicious node exactly its 1/N share forever.
    least_conn    Join-shortest-queue on the *claimed* load. The strongest
                  classical baseline, and the one a Sybil actively exploits:
                  claiming to be idle is precisely how you attract traffic from
                  a load-aware balancer.
    no_trust      The real EdgeScore selector with the trust term neutralised
                  (every node pinned at trust 1.0) and quarantine disabled. The
                  ablation that isolates what the *trust* term contributes, as
                  opposed to what load- and latency-aware routing contributes.
    zt_sdn        The full system: real EdgeScore weights, p2c + eps selection,
                  trust from the real calculator, quarantine on the isolation
                  threshold and the anomaly gate.

`no_trust` and `zt_sdn` both call `select_edge_node`, so the ablation differs
from the system in exactly the trust dimension and nothing else.

Scenarios
---------
    clean   No attackers. Checks the system costs nothing when there is no
            threat -- a defence that degrades normal operation is not free.
    sybil   One node lies (`claimed_cpu = 0.1`) while burning CPU, so it serves
            slowly. It never fails a task, so trust alone cannot catch it; the
            anomaly gate must. This is the project's central finding.
    drop    One node accepts tasks and never completes them. Trust catches this
            one on its own, through timeouts.
    both    Both attackers at once, on separate nodes.

Metrics
-------
Primary outcome is `slo_violation_rate`: the fraction of offered tasks that
either never completed or completed slower than `slo_ms`. It is the one number
both attacks move -- the dropper causes timeouts, the Sybil causes slow
completions -- so a single paired test covers both without cherry-picking a
metric per scenario. `failure_rate`, `mean_latency_ms`, `malicious_share`,
`time_to_isolate_s`, and `gini` are reported alongside it.

Two findings that fell out of building this, both worth reporting as results
rather than smoothing away:

**The capacity cliff.** Quarantine is not free: it removes capacity. In `both`
at the 4-node demo scale, isolating 2 of 4 nodes leaves the honest half carrying
everything at 80% utilisation, and the queueing that causes eats the entire SLO
gain -- `zt_sdn` scores *worse* than the no-trust ablation on
`slo_violation_rate` (0.425 vs 0.405) while simultaneously beating it on every
component metric (failure rate 0.005 vs 0.188, malicious share 0.015 vs 0.369,
p95 1362ms vs 2763ms). At N=6 and N=8 the cliff disappears and `zt_sdn` wins
outright. So the defence needs enough spare capacity to absorb what it isolates,
which is why the default here is the deck's full scale (8) and not the demo's 4.

**The clean-scenario cost is load staleness, not trust.** With no attacker
present the system is measurably *worse* than plain round-robin (0.091 vs 0.083,
p<0.05) -- an honest cost that should be reported, not buried. But the cause is
not the trust term. Every load-reactive strategy pays a staleness penalty here,
because the load view refreshes only every `POLL_S` while tasks finish in ~0.2s,
so each arrival in a polling window is routed on the same stale snapshot and
herds. Sweeping the poll interval isolates it exactly:

    poll      round_robin   random   zt_sdn   least_conn
    1.00s        0.0831     0.0880   0.0913     0.1898
    0.20s        0.0831     0.0880   0.0847     0.1214
    0.01s        0.0831     0.0880   0.0826     0.0826

The two load-blind strategies are flat, as they must be -- they never read the
signal. Everything that does read it improves monotonically as the signal gets
fresher, and by 0.01s `zt_sdn` is the best strategy on the board. So the clean
cost is a *tuning* property of the 1s poll, not a property of trust-aware
routing, and it is recoverable by polling faster. This is Mitzenmacher's herd
behaviour and Dahlin's "stale least-loaded performs worse than random" -- the
same references already cited in docs/LOAD_BALANCING_STARVATION.md §5, which is
also why `least_conn`, the strongest classical baseline in theory, is the weakest
here in practice.

Run:
    python3 -m evaluation.baseline                       # full 600-run experiment
    python3 -m evaluation.baseline --runs 10 --sim-s 60  # quicker
    python3 -m evaluation.baseline --csv results.csv
Then feed the CSV to `python3 -m evaluation.stats results.csv`.
"""
from __future__ import annotations

import argparse
import csv
import heapq
import itertools
import random
import statistics
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from contracts.thresholds import DEFAULT_ANOMALY_GATE, DEFAULT_ISOLATION_THRESHOLD
from contracts.trust_update import TrustUpdate
from controller.edge_selector import (
    STRATEGY_P2C, EdgeWeights, NodeState, select_edge_node,
)
from controller.flow_monitor import evaluate_latency_tell, fleet_latency_baseline
from trust_engine.trust_calculator import TrustCalculator

# --- Defaults, mirroring config/params_trust_demo.yaml + TrustState ---------
WEIGHTS = EdgeWeights(0.50, 0.30, 0.20)
# The deck's full scale (config/params.yaml: 8 edge nodes), not the 4-node demo
# config. The choice matters and is a result in itself -- see the "capacity
# cliff" note in the module docstring.
N_NODES = 8
CONCURRENCY = 4            # per-node workers
POLL_S = 1.0               # controller.monitor_interval_s
SERVICE_MEAN_S = 0.20      # mean honest service time
SIM_S = 120.0              # simulated seconds per run
# Offered load as a fraction of total farm capacity. 0.4 is chosen so the farm
# stays stable in the worst scenario: with 2 of 4 nodes quarantined, the honest
# half carries 0.4 * 4 / 2 = 80% utilisation. A higher factor would make the
# 'both' scenario queue without bound the moment the system isolates anything,
# which would measure the offered load rather than the routing strategy.
LOAD_FACTOR = 0.4
TRUST_EMA = 0.85           # trust.lambda_decay
ANOMALY_EMA = 0.85         # TrustState anomaly smoothing
BASE_RTT_MS = 50.0         # healthy /status round-trip
RTT_JITTER_MS = 4.0
TASK_TIMEOUT_S = 2.0       # client gives up on a task
SLO_MS = 500.0             # completion deadline defining an SLO violation
EPSILON = 0.05             # eps-exploration, as shipped
D_CHOICES = 2

# Attacker behaviour.
SYBIL_CLAIMED_CPU = 0.1    # what the liar reports regardless of reality
# Real service-time multiplier: the liar burns CPU, so it serves slowly. This
# has a hard ceiling. The Sybil must stay able to absorb its fair share
# (LOAD_FACTOR * CONCURRENCY / SERVICE_MEAN_S = 8 tasks/s) on the capacity the
# slowdown leaves it (CONCURRENCY / (SERVICE_MEAN_S * k)), which breaks at
# k = 2.5. Past that the liar saturates, its backlog times out, and it becomes a
# *failing* node -- which the trust score isolates on its own. That would quietly
# turn this into a much easier attack than the one being claimed: the whole point
# of the Sybil is that it never fails a task, so reputation stays high and the
# anomaly gate is what has to catch it. 2.0 keeps it comfortably below the cliff
# (10 tasks/s of capacity against 8 offered) while still degrading latency.
SYBIL_SLOWDOWN = 2.0
SYBIL_RTT_MS = 220.0       # how slowly it answers /status -- the tell

# Timeout-rate tell, mirroring TrustState.recent_timeout_rate + FlowMonitor:
# the fraction of a node's last RECENT_STATUS_WINDOW outcomes that timed out,
# flagged above HONESTY_DEVIATION_THRESHOLD once MIN_TIMEOUT_SAMPLES exist.
# This is what actually catches the dropper. Trust alone does not: a node that
# times out every task settles at T ~ 0.36 (R->0.3, B->0, H stays ~1 because it
# reports its CPU honestly), which never crosses the 0.3 isolation line.
RECENT_STATUS_WINDOW = 10
MIN_TIMEOUT_SAMPLES = 4
HONESTY_DEVIATION_THRESHOLD = 0.40  # config: controller.honesty_deviation_threshold

STRATEGIES = ('random', 'round_robin', 'least_conn', 'no_trust', 'zt_sdn')
SCENARIOS = ('clean', 'sybil', 'drop', 'both')
SYSTEM_UNDER_TEST = 'zt_sdn'


def _gini(values: Sequence[int]) -> float:
    xs = sorted(values)
    n, s = len(xs), sum(xs)
    if s == 0:
        return 0.0
    return (2 * sum((i + 1) * x for i, x in enumerate(xs)) - (n + 1) * s) / (n * s)


@dataclass
class RunResult:
    """Outcome of one seeded run of one strategy against one scenario."""

    strategy: str
    scenario: str
    seed: int
    offered: int = 0
    completed: int = 0
    failed: int = 0                 # timed out, or refused because all quarantined
    slo_violations: int = 0
    malicious_tasks: int = 0
    latencies_ms: List[float] = field(default_factory=list)
    served: List[int] = field(default_factory=list)
    time_to_isolate_s: Optional[float] = None

    @property
    def failure_rate(self) -> float:
        return self.failed / self.offered if self.offered else 0.0

    @property
    def slo_violation_rate(self) -> float:
        return self.slo_violations / self.offered if self.offered else 0.0

    @property
    def malicious_share(self) -> float:
        return self.malicious_tasks / self.offered if self.offered else 0.0

    @property
    def mean_latency_ms(self) -> float:
        return statistics.fmean(self.latencies_ms) if self.latencies_ms else 0.0

    @property
    def p95_latency_ms(self) -> float:
        if not self.latencies_ms:
            return 0.0
        ordered = sorted(self.latencies_ms)
        return ordered[min(len(ordered) - 1, int(0.95 * len(ordered)))]

    @property
    def gini(self) -> float:
        return _gini(self.served)


# Metrics exposed to the statistics layer. True == lower is better.
METRICS: Dict[str, bool] = {
    'slo_violation_rate': True,
    'failure_rate': True,
    'malicious_share': True,
    'mean_latency_ms': True,
    'p95_latency_ms': True,
    'gini': True,
}


def _malicious_roles(scenario: str, n_nodes: int) -> Dict[int, str]:
    """Which node indices misbehave, and how.

    Attackers sit at the end of the index range so they are never the node a
    round-robin happens to start on.
    """
    if scenario == 'clean':
        return {}
    if scenario == 'sybil':
        return {n_nodes - 1: 'sybil'}
    if scenario == 'drop':
        return {n_nodes - 1: 'drop'}
    if scenario == 'both':
        return {n_nodes - 1: 'sybil', n_nodes - 2: 'drop'}
    raise ValueError(f"unknown scenario {scenario!r}")


class _Router:
    """Picks a node index per arrival. One instance per run."""

    def __init__(self, strategy: str, n: int, rng: random.Random) -> None:
        self.strategy = strategy
        self.n = n
        self.rng = rng
        self._rr = itertools.cycle(range(n))

    def choose(
        self,
        trust: Sequence[float],
        claimed_cpu: Sequence[float],
        rtt_ms: Sequence[float],
        anomaly: Sequence[float],
    ) -> Optional[int]:
        """Return the chosen node index, or None if every node was refused.

        None is only ever possible for `zt_sdn`: the baselines have no notion of
        refusing a node, which is exactly the difference being measured.
        """
        if self.strategy == 'random':
            return self.rng.randrange(self.n)

        if self.strategy == 'round_robin':
            return next(self._rr)

        if self.strategy == 'least_conn':
            # Join-shortest-queue on what the nodes *claim*. A balancer with no
            # way to verify the claim must take it at face value -- which is the
            # whole attack surface a Sybil aims at.
            lowest = min(claimed_cpu)
            candidates = [i for i, c in enumerate(claimed_cpu) if c <= lowest + 1e-9]
            return self.rng.choice(candidates)

        # Both EdgeScore variants go through the real selector.
        if self.strategy == 'no_trust':
            # Trust pinned high and uniform: the w1 term becomes a constant and
            # drops out of the ranking, leaving load + latency. Quarantine is
            # disabled the same way -- nothing falls below a 0.0 threshold or
            # reaches a gate above 1.0.
            states = [
                NodeState(f'srv{i + 1}', 1.0, claimed_cpu[i], rtt_ms[i], 0.0)
                for i in range(self.n)
            ]
            isolation, gate = 0.0, 2.0
        else:
            states = [
                NodeState(f'srv{i + 1}', trust[i], claimed_cpu[i], rtt_ms[i], anomaly[i])
                for i in range(self.n)
            ]
            isolation, gate = DEFAULT_ISOLATION_THRESHOLD, DEFAULT_ANOMALY_GATE

        chosen, _, _ = select_edge_node(
            states, WEIGHTS,
            isolation_threshold=isolation, anomaly_gate=gate,
            strategy=STRATEGY_P2C, d_choices=D_CHOICES, epsilon=EPSILON,
            rng=self.rng,
        )
        return None if chosen is None else int(chosen[3:]) - 1


def simulate(
    strategy: str,
    scenario: str,
    seed: int,
    n_nodes: int = N_NODES,
    sim_s: float = SIM_S,
    load_factor: float = LOAD_FACTOR,
    slo_ms: float = SLO_MS,
) -> RunResult:
    """Run one seeded simulation and return its metrics.

    The seed fixes the arrival stream, the service demands, and the RTT jitter,
    so the same seed hands every strategy an identical workload. That pairing is
    what licenses the signed-rank test in `evaluation.stats` -- the strategies
    are compared on matched samples, not independent ones.

    Each stream gets its own Random. With a single shared stream the draws would
    interleave differently once the strategies diverge, so the k-th arrival would
    carry a different service demand under each strategy and the pairing would
    decay into independent sampling. Separate streams keep the k-th draw of each
    kind identical across strategies -- common random numbers, the standard
    variance-reduction technique for paired simulation experiments.
    """
    if strategy not in STRATEGIES:
        raise ValueError(f"unknown strategy {strategy!r}")

    arr_rng = random.Random(seed)             # interarrival times
    svc_rng = random.Random(seed + 17)        # service demands
    jit_rng = random.Random(seed + 43)        # /status RTT jitter
    sel_rng = random.Random(seed + 99)        # selection, mirrors TrustState
    roles = _malicious_roles(scenario, n_nodes)
    router = _Router(strategy, n_nodes, sel_rng)
    calc = TrustCalculator(lambda_decay=TRUST_EMA)

    capacity = n_nodes * CONCURRENCY / SERVICE_MEAN_S
    lam = load_factor * capacity

    # Each node is an M/M/c queue: CONCURRENCY workers, then a FIFO backlog.
    # Without this a task's latency would just be its own service draw, routing
    # could not affect it, and every strategy would score identically whenever
    # no attacker was present.
    busy = [0] * n_nodes
    backlog: List[deque] = [deque() for _ in range(n_nodes)]
    claimed_cpu = [0.0] * n_nodes
    rtt_ms = [BASE_RTT_MS] * n_nodes
    anomaly = [0.0] * n_nodes
    strikes = [0] * n_nodes
    trust = [calc.initial_score] * n_nodes
    recent_statuses: List[deque] = [
        deque(maxlen=RECENT_STATUS_WINDOW) for _ in range(n_nodes)
    ]

    result = RunResult(strategy=strategy, scenario=scenario, seed=seed,
                       served=[0] * n_nodes)

    # (time, tiebreak, kind, node, task). The counter keeps ordering total and
    # deterministic when two events land on the same timestamp. `task` is
    # (arrived_at, service_demand_s).
    evq: List[Tuple[float, int, str, int, Optional[Tuple[float, float]]]] = []
    counter = itertools.count()

    def begin_service(i: int, task: Tuple[float, float], now: float) -> None:
        """Occupy a worker on node i with `task`."""
        busy[i] += 1
        if roles.get(i) == 'drop':
            # Accepts the task, holds the worker, and never finishes it.
            heapq.heappush(evq, (now + TASK_TIMEOUT_S, next(counter), 'timeout', i, task))
        else:
            demand = task[1]
            if roles.get(i) == 'sybil':
                demand *= SYBIL_SLOWDOWN
            heapq.heappush(evq, (now + demand, next(counter), 'dep', i, task))

    heapq.heappush(evq, (arr_rng.expovariate(lam), next(counter), 'arr', -1, None))
    heapq.heappush(evq, (POLL_S, next(counter), 'poll', -1, None))

    while evq:
        now, _, kind, node, task = heapq.heappop(evq)
        if now > sim_s:
            break

        if kind == 'poll':
            # What each node reports, and how fast it answers.
            for i in range(n_nodes):
                if roles.get(i) == 'sybil':
                    claimed_cpu[i] = SYBIL_CLAIMED_CPU
                    rtt_ms[i] = SYBIL_RTT_MS + jit_rng.uniform(-RTT_JITTER_MS, RTT_JITTER_MS)
                else:
                    inflight = busy[i] + len(backlog[i])
                    claimed_cpu[i] = min(1.0, inflight / CONCURRENCY)
                    rtt_ms[i] = BASE_RTT_MS + jit_rng.uniform(-RTT_JITTER_MS, RTT_JITTER_MS)

            # The controller's own anomaly detection: both shipped tells, which
            # are independent and catch different attackers. The latency tell
            # catches the Sybil (claims idle, answers slowly); the timeout-rate
            # tell catches the dropper (its tasks never come back).
            baseline = fleet_latency_baseline(rtt_ms)
            for i in range(n_nodes):
                tell = evaluate_latency_tell(
                    claimed_cpu=claimed_cpu[i], measured_rtt_ms=rtt_ms[i],
                    fleet_baseline_ms=baseline, strikes=strikes[i],
                )
                strikes[i] = tell.strikes
                raw = 1.0 if tell.tripped else 0.0

                history = recent_statuses[i]
                if len(history) >= MIN_TIMEOUT_SAMPLES:
                    timeout_rate = sum(1 for s in history if s == 'timeout') / len(history)
                    if timeout_rate > HONESTY_DEVIATION_THRESHOLD:
                        raw = 1.0

                anomaly[i] = ANOMALY_EMA * raw + (1 - ANOMALY_EMA) * anomaly[i]

            # First moment every attacker is excluded from routing.
            if roles and result.time_to_isolate_s is None:
                if all(
                    trust[i] < DEFAULT_ISOLATION_THRESHOLD
                    or anomaly[i] >= DEFAULT_ANOMALY_GATE
                    for i in roles
                ):
                    result.time_to_isolate_s = now

            heapq.heappush(evq, (now + POLL_S, next(counter), 'poll', -1, None))
            continue

        if kind == 'arr':
            result.offered += 1
            # Drawn here, from its own stream, so the k-th arrival carries the
            # same service demand no matter which strategy is routing it.
            demand = svc_rng.expovariate(1 / SERVICE_MEAN_S)
            i = router.choose(trust, claimed_cpu, rtt_ms, anomaly)
            heapq.heappush(evq, (now + arr_rng.expovariate(lam), next(counter),
                                 'arr', -1, None))

            if i is None:
                # Every node quarantined: deny by default. Counts against the
                # system, so isolating the whole fleet is never free.
                result.failed += 1
                result.slo_violations += 1
                continue

            result.served[i] += 1
            if i in roles:
                result.malicious_tasks += 1

            arriving = (now, demand)
            if busy[i] < CONCURRENCY:
                begin_service(i, arriving, now)
            else:
                backlog[i].append(arriving)
            continue

        # Completion or timeout: update trust exactly as the live controller does.
        busy[node] -= 1
        arrived, _ = task
        latency_ms = (now - arrived) * 1000.0
        timed_out = kind == 'timeout'

        if timed_out:
            result.failed += 1
            result.slo_violations += 1
        else:
            result.completed += 1
            result.latencies_ms.append(latency_ms)
            if latency_ms > slo_ms:
                result.slo_violations += 1

        # Free worker: pull the next task off this node's backlog. Anything that
        # waited longer than the client timeout has already given up.
        while backlog[node] and busy[node] < CONCURRENCY:
            queued = backlog[node].popleft()
            if now - queued[0] >= TASK_TIMEOUT_S:
                result.failed += 1
                result.slo_violations += 1
                continue
            begin_service(node, queued, now)

        recent_statuses[node].append('timeout' if timed_out else 'success')
        actual_cpu = min(1.0, (busy[node] + len(backlog[node])) / CONCURRENCY)
        trust[node] = calc.update(TrustUpdate(
            device_id='sim',
            edge_node_id=f'srv{node + 1}',
            timestamp=now,
            task_status='timeout' if timed_out else 'success',
            cpu_usage=actual_cpu,
            reported_cpu=claimed_cpu[node],
            latency_ms=latency_ms,
            anomaly_flag=anomaly[node] >= DEFAULT_ANOMALY_GATE,
        ))

    return result


def run_experiment(
    runs: int = 30,
    strategies: Sequence[str] = STRATEGIES,
    scenarios: Sequence[str] = SCENARIOS,
    sim_s: float = SIM_S,
    n_nodes: int = N_NODES,
    seed0: int = 1000,
) -> List[RunResult]:
    """Run every (strategy, scenario) pair over `runs` shared seeds.

    Seeds are shared across strategies on purpose: run `k` of every strategy
    faces the identical workload, which is what makes the samples paired.
    """
    results: List[RunResult] = []
    for scenario in scenarios:
        for k in range(runs):
            seed = seed0 + k
            for strategy in strategies:
                results.append(simulate(
                    strategy, scenario, seed, n_nodes=n_nodes, sim_s=sim_s,
                ))
    return results


def write_csv(results: Sequence[RunResult], path: str) -> None:
    with open(path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow([
            'strategy', 'scenario', 'seed', 'offered', 'completed', 'failed',
            'slo_violation_rate', 'failure_rate', 'malicious_share',
            'mean_latency_ms', 'p95_latency_ms', 'gini', 'time_to_isolate_s',
        ])
        for r in results:
            w.writerow([
                r.strategy, r.scenario, r.seed, r.offered, r.completed, r.failed,
                round(r.slo_violation_rate, 6), round(r.failure_rate, 6),
                round(r.malicious_share, 6), round(r.mean_latency_ms, 3),
                round(r.p95_latency_ms, 3), round(r.gini, 4),
                '' if r.time_to_isolate_s is None else round(r.time_to_isolate_s, 3),
            ])


def summarise(results: Sequence[RunResult], metric: str = 'slo_violation_rate') -> str:
    """Median of `metric` per strategy per scenario -- the descriptive view.

    Medians, not means: the signed-rank test in `evaluation.stats` is a statement
    about medians, and reporting a mean would describe a different quantity than
    the one being tested.
    """
    by: Dict[Tuple[str, str], List[float]] = {}
    for r in results:
        by.setdefault((r.scenario, r.strategy), []).append(getattr(r, metric))

    scenarios = sorted({s for s, _ in by}, key=SCENARIOS.index)
    strategies = sorted({t for _, t in by}, key=STRATEGIES.index)

    header = f"{'scenario':>9} | " + " | ".join(f"{s:>12}" for s in strategies)
    lines = [f"median {metric}", header, "-" * len(header)]
    for scenario in scenarios:
        cells = []
        for strategy in strategies:
            vals = by.get((scenario, strategy))
            cells.append(f"{statistics.median(vals):>12.4f}" if vals else f"{'-':>12}")
        lines.append(f"{scenario:>9} | " + " | ".join(cells))
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> None:
    p = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        epilog=(
            "Simulated network and node agents driving the real selector, trust "
            "calculator, and anomaly tell. Not a Mininet run -- see "
            "docs/study/trust-routing-study.html for live-fidelity results."
        ),
    )
    p.add_argument('--runs', type=int, default=30,
                   help='seeded runs per strategy per scenario (default: 30)')
    p.add_argument('--sim-s', type=float, default=SIM_S,
                   help=f'simulated seconds per run (default: {SIM_S:.0f})')
    p.add_argument('--nodes', type=int, default=N_NODES,
                   help=f'edge servers (default: {N_NODES})')
    p.add_argument('--metric', default='slo_violation_rate', choices=sorted(METRICS),
                   help='metric to summarise (default: slo_violation_rate)')
    p.add_argument('--csv', metavar='PATH', help='write per-run results to CSV')
    p.add_argument('--seed0', type=int, default=1000)
    args = p.parse_args(argv)

    results = run_experiment(
        runs=args.runs, sim_s=args.sim_s, n_nodes=args.nodes, seed0=args.seed0,
    )
    print(f"{len(results)} runs ({len(STRATEGIES)} strategies x "
          f"{len(SCENARIOS)} scenarios x {args.runs} seeds)\n")
    print(summarise(results, args.metric))

    if args.csv:
        write_csv(results, args.csv)
        print(f"\nwrote {args.csv}")
        print(f"now run: python3 -m evaluation.stats {args.csv} --metric {args.metric}")


if __name__ == '__main__':
    main()
