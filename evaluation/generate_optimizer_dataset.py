"""Generate the offline Random Forest's training data: (conditions -> arm,
reward) rows, produced by running the live UCB1 bandit inside the same
discrete-event simulator `evaluation.baseline` uses for the 5-strategy
comparison -- real EdgeScore selector, real trust calculator, real anomaly
tells, simulated network -- across many seeds and all four attack scenarios.

This exists because `evaluation.baseline`'s harness does NOT, on its own,
touch the optimizer at all (its five strategies route on fixed weights); a
single live Mininet or trust_convergence_demo capture would give far fewer,
less varied samples and would not be reproducible from git (data/ is
gitignored). Running the bandit inside the simulator gives the same
"statistical volume a live run cannot" argument evaluation.baseline already
makes for its own 600-run claim (see its module docstring) -- just applied to
generating training data instead of a significance test.

Each run gets a fresh, COLD UCB1WeightOptimizer (no warm start): this is
training data, so seeding it from the very model being trained would be
circular.

Run:
    python3 -m evaluation.generate_optimizer_dataset --runs 60 --csv data/optimizer_dataset.csv
    python3 -m evaluation.generate_optimizer_dataset --runs 5 --sim-s 60  # quick smoke test
"""
from __future__ import annotations

import argparse
import csv
from typing import Dict, List, Optional, Sequence

from evaluation.baseline import (
    DEFAULT_ARMS, DEFAULT_WINDOW_S, N_NODES, SCENARIOS, SIM_S,
    STRATEGY_ZT_SDN_RF, simulate,
)
from trust_engine.ai_optimizer import UCB1WeightOptimizer

FIELDNAMES = (
    'scenario', 'seed', 'arm', 'reward',
    'mean_trust', 'mean_load', 'mean_latency_ms', 'num_quarantined',
)


def generate_rows(
    runs: int = 60,
    scenarios: Sequence[str] = SCENARIOS,
    n_nodes: int = N_NODES,
    sim_s: float = SIM_S,
    window_s: float = DEFAULT_WINDOW_S,
    seed0: int = 1000,
) -> List[Dict]:
    """Run `runs` seeded bandit sims per scenario and collect every closed
    window's (conditions -> arm, reward) row. One fresh cold optimizer per run,
    so a run's early exploration windows and later exploitation windows both
    land in the dataset -- the RF should learn from the whole trajectory, not
    just the converged tail.
    """
    rows: List[Dict] = []
    for scenario in scenarios:
        for k in range(runs):
            seed = seed0 + k
            bandit = UCB1WeightOptimizer(arms=list(DEFAULT_ARMS))
            result = simulate(
                STRATEGY_ZT_SDN_RF, scenario, seed,
                n_nodes=n_nodes, sim_s=sim_s,
                optimizer=bandit, window_s=window_s,
            )
            rows.extend(result.optimizer_rows)
    return rows


def write_csv(rows: Sequence[Dict], path: str) -> None:
    with open(path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(FIELDNAMES))
        w.writeheader()
        for row in rows:
            w.writerow({k: row[k] for k in FIELDNAMES})


def main(argv: Optional[Sequence[str]] = None) -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--runs', type=int, default=60,
                   help='seeded runs per scenario (default: 60)')
    p.add_argument('--sim-s', type=float, default=SIM_S,
                   help=f'simulated seconds per run (default: {SIM_S:.0f})')
    p.add_argument('--nodes', type=int, default=N_NODES,
                   help=f'edge servers (default: {N_NODES})')
    p.add_argument('--window-s', type=float, default=DEFAULT_WINDOW_S,
                   help=f'optimizer reward window, seconds (default: {DEFAULT_WINDOW_S})')
    p.add_argument('--seed0', type=int, default=1000)
    p.add_argument('--csv', default='data/optimizer_dataset.csv')
    args = p.parse_args(argv)

    rows = generate_rows(
        runs=args.runs, n_nodes=args.nodes, sim_s=args.sim_s,
        window_s=args.window_s, seed0=args.seed0,
    )
    write_csv(rows, args.csv)
    print(f"{len(rows)} optimizer windows across {len(SCENARIOS)} scenarios x "
          f"{args.runs} seeds -> {args.csv}")
    print(f"now run: python3 -m trust_engine.rf_optimizer train {args.csv} data/rf_optimizer.joblib")


if __name__ == '__main__':
    main()
