"""Reproducible EdgeScore fan-out / starvation sweep.

Controller-in-the-loop simulation (NOT a live Mininet run): it drives the
project's *real* selector, controller.edge_selector.select_edge_node, through a
discrete-event queue so the starvation result and the p2c / ε fix can be
reproduced in seconds on any machine, with no sudo, OVS, or os-ken. The live
Mininet runs behind docs/study/trust-routing-study.html are the ground truth;
this harness exists to sweep parameters (N, strategy) far faster than a real run
and to back the tables in docs/LOAD_BALANCING_STARVATION.md.

Model (deliberately the pessimal case for argmax, matching the live dynamics):
every server is identical, healthy, and honest -- the only asymmetry is <=2ms of
latency jitter. Trust is coupled to selection exactly as in the live system: a
node's trust only rises when it completes tasks, and it only gets tasks if it is
selected, so the heaviest EdgeScore term (trust, weight 0.50) can entrench a
couple of nodes and starve the rest. Load feedback (`claimed_cpu`) is refreshed
only every poll interval, so it is stale between polls -- Mitzenmacher's "herd
behaviour" condition.

Run:
    python3 -m evaluation.starvation_sweep
    python3 -m evaluation.starvation_sweep --csv results.csv --ns 4,8,16,32,64
"""
from __future__ import annotations

import argparse
import heapq
import random
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from controller.edge_selector import (
    STRATEGY_ARGMAX, STRATEGY_P2C, EdgeWeights, NodeState, select_edge_node,
)

# Defaults mirror config/params_trust_demo.yaml + TrustState.
WEIGHTS = EdgeWeights(0.50, 0.30, 0.20)
CONCURRENCY = 4          # TrustState default per-node worker concurrency
POLL_S = 1.0             # controller.monitor_interval_s
SERVICE_MEAN_S = 0.20    # mean task service time
SIM_S = 600.0            # simulated seconds per run
LOAD_FACTOR = 0.6        # offered load as a fraction of farm capacity
TRUST_EMA = 0.85         # trust.lambda_decay -- EMA rate on task success
INITIAL_TRUST = 0.5      # trust.initial_score


def _stdev(values: Sequence[float]) -> float:
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    return (sum((v - mean) ** 2 for v in values) / n) ** 0.5


@dataclass
class SweepResult:
    n: int
    strategy: str
    epsilon: float
    served: List[int]
    # Mean over the run of the per-poll stdev of observed load (inflight/concurrency)
    # across nodes -- exactly the quantity compute_reward's imbalance term measures.
    # None unless simulate(..., track_load=True). This is a property of the
    # SELECTION strategy, not the weights: see docs/AI_OPTIMIZER.md.
    load_imbalance: Optional[float] = None

    @property
    def total(self) -> int:
        return sum(self.served) or 1

    @property
    def used(self) -> int:
        """Servers receiving at least 1% of traffic."""
        return sum(1 for s in self.served if s / self.total >= 0.01)

    @property
    def starved(self) -> int:
        """Servers that received zero traffic."""
        return sum(1 for s in self.served if s == 0)

    @property
    def busiest_share(self) -> float:
        return max(self.served) / self.total

    @property
    def gini(self) -> float:
        xs = sorted(self.served)
        n, s = len(xs), sum(xs)
        if s == 0:
            return 0.0
        return (2 * sum((i + 1) * x for i, x in enumerate(xs)) - (n + 1) * s) / (n * s)


def simulate(
    n: int,
    strategy: str = STRATEGY_ARGMAX,
    epsilon: float = 0.0,
    d_choices: int = 2,
    load_factor: float = LOAD_FACTOR,
    sim_s: float = SIM_S,
    seed: int = 1,
    track_load: bool = False,
) -> SweepResult:
    """Run one controller-in-the-loop simulation and return its routing spread.

    track_load: also accumulate the per-poll stdev of observed load across nodes
    (the imbalance quantity the optimizer's reward penalises), returned as
    SweepResult.load_imbalance.
    """
    rng = random.Random(seed)
    sel_rng = random.Random(seed + 99)          # own stream, mirrors TrustState
    capacity = n * CONCURRENCY / SERVICE_MEAN_S  # tasks/s the farm can serve
    lam = load_factor * capacity                 # Poisson arrival rate

    inflight = [0] * n
    polled_cpu = [0.0] * n                       # what the controller "sees"
    latency = [50.0 + rng.uniform(-2, 2) for _ in range(n)]
    trust = [INITIAL_TRUST] * n
    served = [0] * n

    evq: List[Tuple[float, str, int]] = []
    heapq.heappush(evq, (rng.expovariate(lam), 'arr', -1))
    heapq.heappush(evq, (POLL_S, 'poll', -1))

    while evq:
        now, kind, node = heapq.heappop(evq)
        if now > sim_s:
            break
        if kind == 'poll':
            for i in range(n):
                polled_cpu[i] = min(1.0, inflight[i] / CONCURRENCY)
            heapq.heappush(evq, (now + POLL_S, 'poll', -1))
        elif kind == 'dep':
            inflight[node] -= 1
            # task completed successfully -> trust EMA rises toward 1.0
            trust[node] = TRUST_EMA * 1.0 + (1 - TRUST_EMA) * trust[node]
        else:  # arrival -> route through the REAL selector on the last-polled view
            states = [
                NodeState(f'srv{i + 1}', trust[i], polled_cpu[i], latency[i])
                for i in range(n)
            ]
            chosen, _, _ = select_edge_node(
                states, WEIGHTS, strategy=strategy, d_choices=d_choices,
                epsilon=epsilon, rng=sel_rng,
            )
            i = int(chosen[3:]) - 1
            served[i] += 1
            inflight[i] += 1
            heapq.heappush(evq, (now + rng.expovariate(1 / SERVICE_MEAN_S), 'dep', i))
            heapq.heappush(evq, (now + rng.expovariate(lam), 'arr', -1))

    load_imbalance = None
    if track_load:
        # Time-averaged per-node occupancy (Little's Law: mean inflight = arrival
        # rate x service time), clamped to [0,1] exactly as TrustState.observed_load
        # is. Its stdev across nodes is what compute_reward's imbalance term sees --
        # and it is set by the SELECTION strategy, essentially independent of the
        # EdgeScore weights the optimizer tunes. See docs/AI_OPTIMIZER.md.
        occupancy = [
            min(1.0, (s / sim_s) * SERVICE_MEAN_S / CONCURRENCY) for s in served
        ]
        load_imbalance = _stdev(occupancy)
    return SweepResult(
        n=n, strategy=strategy, epsilon=epsilon, served=served,
        load_imbalance=load_imbalance,
    )


# Strategy label -> (strategy, epsilon) for select_edge_node.
STRATEGIES: Dict[str, Tuple[str, float]] = {
    'argmax': (STRATEGY_ARGMAX, 0.0),
    'p2c': (STRATEGY_P2C, 0.0),
    'p2c+eps': (STRATEGY_P2C, 0.05),
}


def run_sweep(
    ns: Sequence[int],
    labels: Sequence[str] = ('argmax', 'p2c', 'p2c+eps'),
    seed: int = 1,
) -> List[SweepResult]:
    results: List[SweepResult] = []
    for label in labels:
        strategy, epsilon = STRATEGIES[label]
        for n in ns:
            r = simulate(n, strategy=strategy, epsilon=epsilon, seed=seed)
            r.strategy = label  # keep the human label for reporting
            results.append(r)
    return results


def format_table(results: Sequence[SweepResult]) -> str:
    lines = [
        f"{'strategy':>9} | {'N':>4} | {'used':>5} | {'starved':>7} "
        f"| {'busiest':>7} | {'Gini':>5}",
        "-" * 54,
    ]
    for r in results:
        lines.append(
            f"{r.strategy:>9} | {r.n:>4} | {r.used:>2}/{r.n:<2} "
            f"| {r.starved:>7} | {r.busiest_share * 100:>6.0f}% | {r.gini:>5.2f}"
        )
    return "\n".join(lines)


def write_csv(results: Sequence[SweepResult], path: str) -> None:
    import csv
    with open(path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['strategy', 'n', 'used', 'starved', 'busiest_share', 'gini'])
        for r in results:
            w.writerow([
                r.strategy, r.n, r.used, r.starved,
                round(r.busiest_share, 4), round(r.gini, 4),
            ])


def main(argv: Optional[Sequence[str]] = None) -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--ns', default='2,4,8,16,32,64',
                   help='comma-separated server counts (default: 2,4,8,16,32,64)')
    p.add_argument('--csv', metavar='PATH', help='also write results to CSV')
    p.add_argument('--seed', type=int, default=1)
    args = p.parse_args(argv)

    ns = [int(x) for x in args.ns.split(',') if x.strip()]
    results = run_sweep(ns, seed=args.seed)
    print("EdgeScore fan-out sweep -- controller-in-the-loop simulation")
    print("(identical healthy servers; trust coupled to selection; 1s poll)\n")
    print(format_table(results))
    if args.csv:
        write_csv(results, args.csv)
        print(f"\nwrote {args.csv}")


if __name__ == '__main__':
    main()
