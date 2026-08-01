"""Offline Random Forest warm-start prior for the AI weight optimizer
(docs/AI_OPTIMIZER.md Part 2).

This is deliberately NOT a third WeightOptimizer implementation. It trains a
`sklearn.ensemble.RandomForestRegressor` on (conditions, arm) -> reward rows
(see evaluation/generate_optimizer_dataset.py), then predicts, for a given
snapshot of network conditions, each arm's expected reward -- and that
prediction seeds `UCB1WeightOptimizer.seed_values()` instead of starting the
bandit's value_i estimates at zero. The WeightOptimizer protocol in
trust_engine/ai_optimizer.py, and everything that consumes it (TrustState,
the controller, the REST API), does not change.

Persisted with joblib (already a project dependency, see requirements.txt),
not pickle directly, for the same reason scikit-learn's own docs recommend it:
efficient handling of the numpy arrays inside a fitted forest.

CLI:
    python3 -m trust_engine.rf_optimizer train data/optimizer_dataset.csv data/rf_optimizer.joblib
    python3 -m trust_engine.rf_optimizer predict data/rf_optimizer.joblib \\
        --mean-trust 1.0 --mean-load 0.0 --mean-latency-ms 50.0 --num-quarantined 0
"""
from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

import joblib
from sklearn.ensemble import RandomForestRegressor

from controller.edge_selector import EdgeWeights
from trust_engine.ai_optimizer import UCB1WeightOptimizer

# Order matters: it is the feature order the model is trained and queried
# with. Mirrors TrustState._conditions_snapshot_locked()'s keys exactly, so a
# live conditions dict can be fed to predict_values() unmodified.
CONDITION_KEYS = ('mean_trust', 'mean_load', 'mean_latency_ms', 'num_quarantined')


@dataclass
class OptimizerRow:
    """One closed reward window: which arm was active, under what conditions,
    and what reward it earned. See evaluation/generate_optimizer_dataset.py."""

    conditions: Dict[str, float]
    arm: int
    reward: float


def load_rows(path: str) -> List[OptimizerRow]:
    """Read the CSV evaluation.generate_optimizer_dataset writes."""
    rows: List[OptimizerRow] = []
    with open(path, newline='') as f:
        for r in csv.DictReader(f):
            rows.append(OptimizerRow(
                conditions={k: float(r[k]) for k in CONDITION_KEYS},
                arm=int(r['arm']),
                reward=float(r['reward']),
            ))
    return rows


def _features(conditions: Dict[str, float], arm: EdgeWeights) -> List[float]:
    """Conditions + the arm's own weight triple. The triple (not a bare arm
    index) is what lets the forest generalise across different `arms` lists
    rather than memorising an opaque integer label."""
    return [conditions[k] for k in CONDITION_KEYS] + [
        arm.w1_trust, arm.w2_cpu, arm.w3_latency,
    ]


def train(
    rows: Sequence[OptimizerRow],
    arms: Sequence[EdgeWeights],
    n_estimators: int = 200,
    random_state: int = 0,
) -> RandomForestRegressor:
    """Fit conditions+arm -> reward. Raises if there is no data -- training on
    nothing would silently produce a useless constant model."""
    if not rows:
        raise ValueError("no training rows: run evaluation.generate_optimizer_dataset first")
    x = [_features(r.conditions, arms[r.arm]) for r in rows]
    y = [r.reward for r in rows]
    model = RandomForestRegressor(n_estimators=n_estimators, random_state=random_state)
    model.fit(x, y)
    return model


def predict_values(
    model: RandomForestRegressor,
    conditions: Dict[str, float],
    arms: Sequence[EdgeWeights],
) -> List[float]:
    """Expected reward per arm under `conditions`, in arm order."""
    x = [_features(conditions, a) for a in arms]
    return [float(v) for v in model.predict(x)]


def warm_start_optimizer(
    model: RandomForestRegressor,
    conditions: Dict[str, float],
    arms: Sequence[EdgeWeights],
    exploration_c: float = 1.41,
    pseudo_count: int = 3,
) -> UCB1WeightOptimizer:
    """Build a UCB1WeightOptimizer whose value_i estimates start from the RF's
    prediction for `conditions` instead of zero. `pseudo_count` controls how
    fast real observations overtake the prior (see
    UCB1WeightOptimizer.seed_values's docstring)."""
    opt = UCB1WeightOptimizer(arms=list(arms), exploration_c=exploration_c)
    opt.seed_values(predict_values(model, conditions, arms), pseudo_count=pseudo_count)
    return opt


def save_model(model: RandomForestRegressor, path: str) -> None:
    joblib.dump(model, path)


def load_model(path: str) -> RandomForestRegressor:
    return joblib.load(path)


def main(argv: Optional[Sequence[str]] = None) -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest='cmd', required=True)

    train_p = sub.add_parser('train', help='fit a model from a generated dataset CSV')
    train_p.add_argument('csv', help='output of evaluation.generate_optimizer_dataset')
    train_p.add_argument('model_path', help='where to joblib.dump the fitted model')
    train_p.add_argument('--n-estimators', type=int, default=200)

    predict_p = sub.add_parser('predict', help='show predicted per-arm reward for one condition')
    predict_p.add_argument('model_path')
    predict_p.add_argument('--mean-trust', type=float, required=True)
    predict_p.add_argument('--mean-load', type=float, required=True)
    predict_p.add_argument('--mean-latency-ms', type=float, required=True)
    predict_p.add_argument('--num-quarantined', type=float, required=True)

    args = p.parse_args(argv)

    if args.cmd == 'train':
        from evaluation.baseline import DEFAULT_ARMS
        rows = load_rows(args.csv)
        model = train(rows, DEFAULT_ARMS, n_estimators=args.n_estimators)
        save_model(model, args.model_path)
        print(f"trained on {len(rows)} rows -> {args.model_path}")
        return

    if args.cmd == 'predict':
        from evaluation.baseline import DEFAULT_ARMS
        model = load_model(args.model_path)
        conditions = {
            'mean_trust': args.mean_trust,
            'mean_load': args.mean_load,
            'mean_latency_ms': args.mean_latency_ms,
            'num_quarantined': args.num_quarantined,
        }
        for arm, value in zip(DEFAULT_ARMS, predict_values(model, conditions, DEFAULT_ARMS)):
            print(f"[{arm.w1_trust:.2f}, {arm.w2_cpu:.2f}, {arm.w3_latency:.2f}] -> {value:.4f}")


if __name__ == '__main__':
    main()
