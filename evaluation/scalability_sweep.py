"""Full-system scalability sweep: every headline metric as a function of N.
plan_adv.md Phase 3.

Same *pattern* as evaluation/starvation_sweep.py -- a discrete-event harness
driving the project's REAL selector (controller.edge_selector.select_edge_node)
rather than a reimplementation of it, so the result is a property of the
shipping code and not of a model of it. Live Mininet cannot answer this
question: the box is 4 cores and the 8/40/3 run already needed its workload
retuned to avoid collapse (docs/LIVE_RUN_8_40_3.md), so N=64 live would measure
the laptop, not the architecture. That constraint is why plan_adv.md §4 chose a
simulation sweep here, and it is a limitation to state plainly rather than a
result to present as if it were live.

Why this is a SEPARATE module from starvation_sweep.py
------------------------------------------------------
starvation_sweep.py deliberately models an INFINITE-SERVER farm: an arrival is
served immediately at `now + service_time`, `inflight` may exceed `concurrency`
without bound, and nothing ever queues or times out. That is exactly right for
the question it asks -- "who does the selector pick?" -- and it is why its
tables in docs/LOAD_BALANCING_STARVATION.md are trustworthy.

It is the wrong model for this question. With no queue there is no waiting, so
delay is flat in N by construction; with no timeout there is no loss, so PDR is
1.0 by construction; and throughput just equals the offered rate. Extending
that model in place would also silently invalidate the published starvation
tables, so the model here is new and the two live side by side:

    starvation_sweep.py  -> selection fairness, infinite-server
    scalability_sweep.py -> full-system metrics, M/M/c-per-node with timeouts

Model
-----
Each of the N nodes is an M/M/c queue: `concurrency` workers and an unbounded
FIFO. Arrivals are Poisson at `load_factor` x farm capacity, routed at arrival
by the real selector on the last-polled view (stale between polls -- the
"herd behaviour" condition, as in starvation_sweep.py). A task that has not
COMPLETED by `task_timeout_s` after arrival is counted as a timeout, but it is
deliberately NOT removed from the node: the client has abandoned it, the node
has no idea, and the worker stays occupied. That wasted capacity is real and is
what makes an overloaded fleet degrade rather than gracefully shed load.

The decision-cost column is a WALL-CLOCK measurement of the real selector, not
a simulated quantity -- see decision_us in SweepPoint for what it does and does
not include.

What the sweep shows (measured 2026-08-07, seed 1, 120s cells, N=4..64)
-----------------------------------------------------------------------
1. **p2c scales linearly, argmax saturates.** Offered load rises with N, so a
   system that keeps up shows LINEAR throughput and FLAT delay/PDR. At 60%
   load p2c does exactly that -- N=4/8/16/32/64 gives 48/95/192/382/762
   tasks/s (a clean doubling per doubling), PDR 99.7-99.8% and mean delay
   ~266 ms at every size. argmax saturates at ~85 tasks/s from N=8 onward and
   its PDR falls 99.2% -> 91.7% -> 45.8% -> 21.3% -> 10.5%, with delay pinned
   at ~2.0 s (the timeout ceiling, not a measurement of service).

2. **argmax fails in two different ways at the two ends of offered load**,
   which is why load is a sweep axis here rather than a fixed setting:
     * LOW load (10%): classic starvation -- 13 of 16 nodes get nothing
       (Jain 0.176), 23 of 32 at N=32. Load feedback barely moves
       `polled_cpu`, so the trust term dominates and locks in. Same effect as
       docs/LOAD_BALANCING_STARVATION.md and the starved-for-2238s node in the
       live run.
     * HIGH load (60%): almost nothing is starved (Jain 0.75-0.85) because
       queues build on the favoured nodes and the CPU term finally pushes
       traffic away -- but by then the damage is loss, not unfairness. The
       fleet is balanced and broken at the same time.
   Reporting only one end would make argmax look merely unfair, or merely
   slow, instead of both.

   The two regimes are the same phenomenon at different absolute rates, and
   the crossover is visible in one row: argmax at 10% load and N=64 offers
   128 tasks/s against the ~40 tasks/s the two favoured nodes can serve, so it
   tips OUT of starvation (0/64 starved) and INTO loss (PDR 73.5%). "Low load"
   is therefore about the rate reaching the favoured few, not about the
   configured fraction.

3. **p2c does NOT reduce the controller's per-decision cost.** Both strategies
   cost the same and both grow ~linearly with N: 3/5/9/16/30 us at
   N=4/8/16/32/64, argmax and p2c within noise of each other at every N. The
   reason is in select_edge_node itself: it scores every eligible node and
   sorts them REGARDLESS of strategy, because that ranking is returned as the
   explanation of the decision (trust_balancer.py publishes it as `ranked`, and
   showing why a node lost is a stated goal of the dashboard). p2c's O(d)
   sampling therefore rides on top of an O(N log N) base rather than replacing
   it. This is a deliberate trade -- explicability bought with CPU that is
   nowhere near a bottleneck at these sizes -- and NOT something to "optimise"
   away without deciding to give up the ranking. Stated here so the p2c win is
   claimed where it is real (fairness, throughput, delay) and not where it
   isn't.

Run:
    python3 -m evaluation.scalability_sweep
    python3 -m evaluation.scalability_sweep --ns 4,8,16,32,64 --csv scale.csv
"""

from __future__ import annotations

import argparse
import heapq
import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from controller.edge_selector import (
    STRATEGY_ARGMAX,
    STRATEGY_P2C,
    EdgeWeights,
    NodeState,
    select_edge_node,
)
from evaluation.interval_report import jain_fairness_index
from evaluation.nfr_report import _percentile

# Defaults mirror config/params_trust_demo.yaml + TrustState, and match
# starvation_sweep.py's so the two harnesses are comparable where they overlap.
WEIGHTS = EdgeWeights(0.50, 0.30, 0.20)
CONCURRENCY = 4          # TrustState default per-node worker concurrency
POLL_S = 1.0             # controller.monitor_interval_s
SERVICE_MEAN_S = 0.20    # mean task service time
LOAD_FACTOR = 0.6        # offered load as a fraction of farm capacity
TRUST_EMA = 0.85         # trust.lambda_decay
INITIAL_TRUST = 0.5      # trust.initial_score
TASK_TIMEOUT_S = 4.0     # agents.task_timeout_s in params_trust_full.yaml

# TrustCalculator's component weights: T = aR + bB + gH - dA.
#
# starvation_sweep.py can get away with treating trust AS the reliability EMA,
# because there trust only ever rises and the absolute value never matters --
# only the ordering does. Here it matters: tasks time out, so reliability
# falls, and trust is what decides whether a node is still ELIGIBLE at all
# (select_edge_node drops anything under isolation_threshold, default 0.30).
#
# Collapsing T to R alone would put an honest-but-overloaded node at 0.075
# after a single timeout and quarantine the entire fleet, which is a modelling
# artifact and not a property of the system: in the real calculator a node that
# is merely slow still scores full marks on behaviour and resource honesty, so
# its trust floors at b+g = 0.50, comfortably above isolation. Modelling the
# composition keeps saturation showing up where it genuinely does -- in latency
# and PDR -- instead of manufacturing a trust collapse.
TRUST_ALPHA = 0.35       # reputation / reliability
TRUST_BETA = 0.25        # behavioural consistency
TRUST_GAMMA = 0.25       # resource honesty
# Every node in this harness is healthy and honest (the same premise as
# starvation_sweep.py -- the only asymmetry is latency jitter), so B and H sit
# at 1.0 and the anomaly term at 0.0. Attack behaviour is Phase 1/2 territory
# and is deliberately out of scope for a capacity sweep.
TRUST_HONEST_FLOOR = TRUST_BETA + TRUST_GAMMA

#: Shorter than starvation_sweep.py's 600s. Offered load scales with N
#: (lambda = load_factor * N * c / service_mean = 12N/s at the defaults), so a
#: 600s run at N=64 is ~460k tasks per strategy and the sweep stops being
#: something you re-run casually. 120s still gives ~92k tasks at N=64, far more
#: than these statistics need.
SIM_S = 120.0


@dataclass
class SweepPoint:
    """Every headline metric for one (N, strategy) cell."""

    n: int
    strategy: str
    epsilon: float

    #: Offered load as a fraction of farm capacity for this cell. A sweep
    #: axis in its own right, not just a setting -- see run_sweep.
    load_factor: float = LOAD_FACTOR

    #: The sim_s this cell actually ran for. Stored rather than read back off
    #: the module constant so a caller passing --sim-s cannot silently get a
    #: throughput computed against the wrong denominator.
    sim_s: float = SIM_S

    offered: int = 0
    completed: int = 0
    timed_out: int = 0
    #: Arrivals the controller refused to route because every node was below
    #: the isolation threshold. Distinct from timed_out on purpose.
    denied: int = 0

    #: Per-node completion counts -- the routing spread, and the input to
    #: Jain's index.
    served: List[int] = field(default_factory=list)

    latencies: List[float] = field(default_factory=list)

    #: Mean and p95 wall-clock cost of ONE real select_edge_node call, in
    #: microseconds. This is the controller-side scalability signal and the
    #: reason argmax and p2c are expected to diverge: argmax scores all N
    #: candidates, p2c scores d of them regardless of N.
    #:
    #: What it is NOT: the live controller's `decision_ms`. That figure covers
    #: the whole PacketIn path including flow-rule installation and OpenFlow
    #: round trips, which this harness does not model at all. Compare this
    #: column against itself across N, never against a live number.
    decision_us_mean: float = 0.0
    decision_us_p95: float = 0.0

    @property
    def total(self) -> int:
        return sum(self.served) or 1

    @property
    def throughput_hz(self) -> float:
        return self.completed / self.sim_s if self.sim_s else 0.0

    @property
    def pdr(self) -> float:
        return self.completed / self.offered if self.offered else 0.0

    @property
    def mean_latency_ms(self) -> float:
        return (sum(self.latencies) / len(self.latencies) * 1000.0
                if self.latencies else 0.0)

    @property
    def p95_latency_ms(self) -> float:
        return _percentile(self.latencies, 95) * 1000.0 if self.latencies else 0.0

    @property
    def jain(self) -> Optional[float]:
        return jain_fairness_index(self.served)

    @property
    def starved(self) -> int:
        return sum(1 for s in self.served if s == 0)

    @property
    def used(self) -> int:
        return sum(1 for s in self.served if s / self.total >= 0.01)

    @property
    def busiest_share(self) -> float:
        return max(self.served) / self.total if self.served else 0.0


class _Task:
    """One offered task. Slots because there are ~100k of these per cell."""

    __slots__ = ('arrived', 'completed', 'timed_out')

    def __init__(self, arrived: float) -> None:
        self.arrived = arrived
        self.completed = False
        self.timed_out = False


def simulate(
    n: int,
    strategy: str = STRATEGY_P2C,
    epsilon: float = 0.0,
    d_choices: int = 2,
    load_factor: float = LOAD_FACTOR,
    sim_s: float = SIM_S,
    concurrency: int = CONCURRENCY,
    task_timeout_s: float = TASK_TIMEOUT_S,
    seed: int = 1,
) -> SweepPoint:
    """One controller-in-the-loop run with real per-node queueing.

    Returns a SweepPoint. Every derived metric on it comes from counted events
    in this run -- nothing is estimated from a closed-form queueing formula,
    because the whole point is to measure the real selector's behaviour under
    feedback rather than to assume it matches an analytic model.
    """
    rng = random.Random(seed)
    sel_rng = random.Random(seed + 99)          # own stream, mirrors TrustState
    capacity = n * concurrency / SERVICE_MEAN_S
    lam = load_factor * capacity

    busy = [0] * n
    queues: List[List[_Task]] = [[] for _ in range(n)]
    qhead = [0] * n                              # index into queues[i], avoids O(n) pops
    polled_cpu = [0.0] * n
    latency = [50.0 + rng.uniform(-2, 2) for _ in range(n)]
    served = [0] * n

    # Reliability EMA per node, and the composed trust the selector sees. See
    # TRUST_ALPHA above for why trust is composed rather than equated with
    # reliability.
    reliability = [INITIAL_TRUST] * n

    def trust_of(i: int) -> float:
        return TRUST_ALPHA * reliability[i] + TRUST_HONEST_FLOOR

    def record_outcome(i: int, success: float) -> None:
        reliability[i] = TRUST_EMA * success + (1 - TRUST_EMA) * reliability[i]

    point = SweepPoint(
        n=n, strategy=strategy, epsilon=epsilon, sim_s=sim_s,
        load_factor=load_factor,
    )
    decision_ns: List[int] = []

    # (time, seq, kind, node, task). seq breaks ties so heapq never has to
    # compare _Task objects, which are not orderable.
    seq = 0
    evq: List[Tuple[float, int, str, int, Optional[_Task]]] = []

    def push(t: float, kind: str, node: int = -1, task: Optional[_Task] = None) -> None:
        nonlocal seq
        seq += 1
        heapq.heappush(evq, (t, seq, kind, node, task))

    def start_service(node: int, task: _Task, now: float) -> None:
        busy[node] += 1
        push(now + rng.expovariate(1 / SERVICE_MEAN_S), 'dep', node, task)

    push(rng.expovariate(lam), 'arr')
    push(POLL_S, 'poll')

    while evq:
        now, _, kind, node, task = heapq.heappop(evq)
        if now > sim_s:
            break

        if kind == 'poll':
            for i in range(n):
                # Matches TrustState.observed_load: everything dispatched and
                # not yet reported, i.e. in service OR waiting, over capacity.
                pending = busy[i] + (len(queues[i]) - qhead[i])
                polled_cpu[i] = min(1.0, pending / concurrency)
            push(now + POLL_S, 'poll')

        elif kind == 'arr':
            point.offered += 1
            t = _Task(now)
            states = [
                NodeState(f'srv{i + 1}', trust_of(i), polled_cpu[i], latency[i])
                for i in range(n)
            ]
            started = time.perf_counter_ns()
            chosen, _, _ = select_edge_node(
                states, WEIGHTS, strategy=strategy, d_choices=d_choices,
                epsilon=epsilon, rng=sel_rng,
            )
            decision_ns.append(time.perf_counter_ns() - started)

            if chosen is None:
                # Every candidate below the isolation threshold: the real
                # controller publishes 'route_denied' and drops the request
                # rather than routing to an untrusted node. Counted as its own
                # outcome, never folded into timeouts -- refusing to route and
                # failing to deliver are different events, and this project's
                # packet-drop discipline is that they must not absorb each
                # other (see evaluation/interval_report.py).
                point.denied += 1
                push(now + rng.expovariate(lam), 'arr')
                continue

            i = int(chosen[3:]) - 1
            served[i] += 1
            if busy[i] < concurrency:
                start_service(i, t, now)
            else:
                queues[i].append(t)
            push(now + task_timeout_s, 'timeout', i, t)
            push(now + rng.expovariate(lam), 'arr')

        elif kind == 'dep':
            assert task is not None
            task.completed = True
            busy[node] -= 1
            if not task.timed_out:
                point.completed += 1
                point.latencies.append(now - task.arrived)
                record_outcome(node, 1.0)
            # Pull the next waiter, if any.
            if qhead[node] < len(queues[node]):
                nxt = queues[node][qhead[node]]
                qhead[node] += 1
                start_service(node, nxt, now)

        else:  # 'timeout'
            assert task is not None
            if not task.completed:
                # The CLIENT gives up here. The node does not know that, so the
                # task is left exactly where it is and still consumes a worker
                # when its turn comes. Removing it would model a fleet that
                # sheds load it has no way to know it should shed.
                task.timed_out = True
                point.timed_out += 1
                record_outcome(node, 0.0)

    point.served = served
    if decision_ns:
        point.decision_us_mean = sum(decision_ns) / len(decision_ns) / 1000.0
        point.decision_us_p95 = _percentile(decision_ns, 95) / 1000.0
    return point


# Strategy label -> (strategy, epsilon), same set as starvation_sweep.py.
STRATEGIES: Dict[str, Tuple[str, float]] = {
    'argmax': (STRATEGY_ARGMAX, 0.0),
    'p2c': (STRATEGY_P2C, 0.0),
    'p2c+eps': (STRATEGY_P2C, 0.05),
}


def run_sweep(
    ns: Sequence[int],
    labels: Sequence[str] = ('argmax', 'p2c', 'p2c+eps'),
    seed: int = 1,
    sim_s: float = SIM_S,
    load_factors: Sequence[float] = (LOAD_FACTOR,),
) -> List[SweepPoint]:
    """Sweep strategy x N x offered load.

    Load is a real axis here and not a fixed setting, because argmax fails in
    two DIFFERENT ways at the two ends of it and either one alone gives a
    misleading picture -- see the module docstring.
    """
    results: List[SweepPoint] = []
    for label in labels:
        strategy, epsilon = STRATEGIES[label]
        for load_factor in load_factors:
            for n in ns:
                point = simulate(
                    n, strategy=strategy, epsilon=epsilon, seed=seed,
                    sim_s=sim_s, load_factor=load_factor,
                )
                point.strategy = label   # keep the human label for reporting
                results.append(point)
    return results


def format_table(results: Sequence[SweepPoint]) -> str:
    lines = [
        f"{'strategy':>9} | {'load':>5} | {'N':>3} | {'thru/s':>7} | {'PDR':>6} | "
        f"{'mean ms':>8} | {'p95 ms':>8} | {'Jain':>5} | {'starved':>7} | "
        f"{'dec us':>7}",
        "-" * 97,
    ]
    for r in results:
        jain = f'{r.jain:.3f}' if r.jain is not None else '  n/a'
        lines.append(
            f"{r.strategy:>9} | {r.load_factor:>4.0%} | {r.n:>3} | "
            f"{r.throughput_hz:>7.1f} | "
            f"{r.pdr:>5.1%} | {r.mean_latency_ms:>8.1f} | "
            f"{r.p95_latency_ms:>8.1f} | {jain:>5} | "
            f"{r.starved:>2}/{r.n:<4} | {r.decision_us_mean:>7.1f}"
        )
    return "\n".join(lines)


def write_csv(results: Sequence[SweepPoint], path: str) -> None:
    import csv

    with open(path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow([
            'strategy', 'n', 'load_factor', 'offered', 'completed', 'timed_out',
            'denied',
            'throughput_hz', 'pdr', 'mean_latency_ms', 'p95_latency_ms',
            'jain_fairness', 'used', 'starved', 'busiest_share',
            'decision_us_mean', 'decision_us_p95',
        ])
        for r in results:
            w.writerow([
                r.strategy, r.n, r.load_factor, r.offered, r.completed,
                r.timed_out, r.denied,
                round(r.throughput_hz, 3), round(r.pdr, 5),
                round(r.mean_latency_ms, 3), round(r.p95_latency_ms, 3),
                '' if r.jain is None else round(r.jain, 5),
                r.used, r.starved, round(r.busiest_share, 5),
                round(r.decision_us_mean, 3), round(r.decision_us_p95, 3),
            ])


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--ns', default='4,8,16,32,64',
                   help='comma-separated server counts (default: 4,8,16,32,64)')
    p.add_argument('--sim-s', type=float, default=SIM_S,
                   help=f'simulated seconds per cell (default {SIM_S})')
    p.add_argument('--load-factors', default=str(LOAD_FACTOR),
                   help='comma-separated offered loads as a fraction of farm '
                        f'capacity (default {LOAD_FACTOR}). argmax fails '
                        'differently at each end, so sweeping this is worth it')
    p.add_argument('--csv', metavar='PATH', help='also write results to CSV')
    p.add_argument('--seed', type=int, default=1)
    args = p.parse_args(argv)

    ns = [int(x) for x in args.ns.split(',') if x.strip()]
    load_factors = [float(x) for x in args.load_factors.split(',') if x.strip()]
    results = run_sweep(
        ns, seed=args.seed, sim_s=args.sim_s, load_factors=load_factors,
    )

    print('Full-system scalability sweep -- controller-in-the-loop simulation')
    print(f'(M/M/{CONCURRENCY} per node, {args.sim_s:.0f}s per cell, '
          f'{TASK_TIMEOUT_S:.0f}s task timeout)')
    print('Offered load scales WITH N, so flat curves mean the system keeps up.\n')
    print(format_table(results))
    print()
    print('dec us = wall-clock cost of one real select_edge_node call on this '
          'box. Not comparable')
    print('to the live controller\'s decision_ms, which also covers flow-rule '
          'installation.')
    if args.csv:
        write_csv(results, args.csv)
        print(f'\nwrote {args.csv}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
