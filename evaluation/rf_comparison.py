"""The 6th comparison: does the offline Random Forest's warm-start prior beat
the hand-tuned static weights (`zt_sdn`)? (Step 1, docs/AI_OPTIMIZER.md Part 2.)

Runs `zt_sdn_rf` -- zt_sdn's real EdgeScore selector, but weights come from a
UCB1WeightOptimizer whose value_i estimates start from the trained Random
Forest's prediction (see trust_engine.rf_optimizer.warm_start_optimizer)
instead of zero -- against the same 5 strategies `evaluation.baseline`
already compares, on the same seeds. The output CSV has all 6 strategies, so
`evaluation.stats` needs no changes: point `--system zt_sdn_rf` at it and it
answers the question directly (zt_sdn is one of the "baselines" it is then
compared against).

The warm start uses one fixed "cold" conditions snapshot -- a healthy fleet at
t=0 (mean_trust=1.0, mean_load=0.0, mean_latency_ms=BASE_RTT_MS,
num_quarantined=0) -- because that is genuinely all `zt_sdn_rf` knows before a
run starts; after that, plain UCB1 (observe/select) takes over exactly as it
would live. A fresh optimizer is built per (scenario, seed) run so every run
starts from the same prior, matching how the other 5 strategies get a fresh,
independent run per seed.

Run:
    python3 -m evaluation.generate_optimizer_dataset --runs 60 --csv data/optimizer_dataset.csv
    python3 -m trust_engine.rf_optimizer train data/optimizer_dataset.csv data/rf_optimizer.joblib
    python3 -m evaluation.rf_comparison --model data/rf_optimizer.joblib --csv results_rf.csv
    python3 -m evaluation.stats results_rf.csv --system zt_sdn_rf
"""
from __future__ import annotations

import argparse
from typing import List, Optional, Sequence

from evaluation.baseline import (
    BASE_RTT_MS, DEFAULT_ARMS, N_NODES, RunResult, SCENARIOS, SIM_S,
    STRATEGIES, STRATEGY_ZT_SDN_RF, simulate, write_csv,
)
from trust_engine.rf_optimizer import load_model, warm_start_optimizer

COLD_CONDITIONS = {
    'mean_trust': 1.0,
    'mean_load': 0.0,
    'mean_latency_ms': BASE_RTT_MS,
    'num_quarantined': 0,
}


def run_experiment(
    model_path: str,
    runs: int = 30,
    scenarios: Sequence[str] = SCENARIOS,
    sim_s: float = SIM_S,
    n_nodes: int = N_NODES,
    seed0: int = 1000,
    pseudo_count: int = 3,
) -> List[RunResult]:
    """The 5 static-weight strategies plus zt_sdn_rf, all on the same seeds."""
    model = load_model(model_path)
    results: List[RunResult] = []
    for scenario in scenarios:
        for k in range(runs):
            seed = seed0 + k
            for strategy in STRATEGIES:
                results.append(simulate(
                    strategy, scenario, seed, n_nodes=n_nodes, sim_s=sim_s,
                ))
            bandit = warm_start_optimizer(
                model, COLD_CONDITIONS, DEFAULT_ARMS, pseudo_count=pseudo_count,
            )
            results.append(simulate(
                STRATEGY_ZT_SDN_RF, scenario, seed, n_nodes=n_nodes, sim_s=sim_s,
                optimizer=bandit,
            ))
    return results


def main(argv: Optional[Sequence[str]] = None) -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--model', required=True, help='joblib model from `trust_engine.rf_optimizer train`')
    p.add_argument('--runs', type=int, default=30, help='seeded runs per scenario (default: 30)')
    p.add_argument('--sim-s', type=float, default=SIM_S)
    p.add_argument('--nodes', type=int, default=N_NODES)
    p.add_argument('--seed0', type=int, default=1000)
    p.add_argument('--pseudo-count', type=int, default=3,
                   help='warm-start pseudo-count per arm (default: 3)')
    p.add_argument('--csv', default='results_rf.csv')
    args = p.parse_args(argv)

    results = run_experiment(
        args.model, runs=args.runs, sim_s=args.sim_s, n_nodes=args.nodes,
        seed0=args.seed0, pseudo_count=args.pseudo_count,
    )
    write_csv(results, args.csv)
    print(f"{len(results)} runs ({len(STRATEGIES) + 1} strategies x "
          f"{len(SCENARIOS)} scenarios x {args.runs} seeds) -> {args.csv}")
    print(f"now run: python3 -m evaluation.stats {args.csv} --system {STRATEGY_ZT_SDN_RF}")


if __name__ == '__main__':
    main()
