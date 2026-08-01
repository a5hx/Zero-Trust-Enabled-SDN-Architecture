"""Tests for trust_engine/rf_optimizer.py -- the offline Random Forest
warm-start prior for the AI weight optimizer (docs/AI_OPTIMIZER.md Part 2).

No Mininet/os-ken dependency: trains on small synthetic (conditions, arm,
reward) rows, the same shape evaluation.generate_optimizer_dataset produces.
"""
import csv

import pytest

from controller.edge_selector import EdgeWeights
from trust_engine.ai_optimizer import UCB1WeightOptimizer
from trust_engine.rf_optimizer import (
    CONDITION_KEYS,
    OptimizerRow,
    load_model,
    load_rows,
    predict_values,
    save_model,
    train,
    warm_start_optimizer,
)

ARMS = [
    EdgeWeights(0.50, 0.30, 0.20),  # balanced
    EdgeWeights(0.70, 0.20, 0.10),  # trust-heavy
]

# Arm 1 (trust-heavy) always earns 0.9 under "attacked" conditions
# (low mean_trust, some node quarantined); arm 0 always earns 0.2 there.
# Under "calm" conditions both earn a mediocre, close reward. A forest that
# has actually learned the split should separate the two clearly.
CALM = {'mean_trust': 1.0, 'mean_load': 0.1, 'mean_latency_ms': 50.0, 'num_quarantined': 0}
ATTACKED = {'mean_trust': 0.3, 'mean_load': 0.6, 'mean_latency_ms': 200.0, 'num_quarantined': 1}


def _synthetic_rows(n_per_cell: int = 30) -> list:
    rows = []
    for i in range(n_per_cell):
        rows.append(OptimizerRow(conditions=CALM, arm=0, reward=0.75))
        rows.append(OptimizerRow(conditions=CALM, arm=1, reward=0.70))
        rows.append(OptimizerRow(conditions=ATTACKED, arm=0, reward=0.20))
        rows.append(OptimizerRow(conditions=ATTACKED, arm=1, reward=0.90))
    return rows


def test_train_rejects_empty_dataset():
    with pytest.raises(ValueError):
        train([], ARMS)


def test_train_and_predict_recovers_the_better_arm_under_attack():
    model = train(_synthetic_rows(), ARMS, n_estimators=50, random_state=0)
    values = predict_values(model, ATTACKED, ARMS)
    assert values[1] > values[0], f"expected trust-heavy arm to win under attack, got {values}"


def test_predict_prefers_balanced_arm_when_calm():
    model = train(_synthetic_rows(), ARMS, n_estimators=50, random_state=0)
    values = predict_values(model, CALM, ARMS)
    assert values[0] > values[1]


def test_warm_start_optimizer_seeds_ucb1_toward_the_predicted_best_arm():
    model = train(_synthetic_rows(), ARMS, n_estimators=50, random_state=0)
    opt = warm_start_optimizer(model, ATTACKED, ARMS, pseudo_count=5)
    assert isinstance(opt, UCB1WeightOptimizer)
    opt.select()
    assert opt.active_index == 1


def test_load_rows_parses_the_generated_csv_shape(tmp_path):
    path = tmp_path / 'dataset.csv'
    with open(path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['scenario', 'seed', 'arm', 'reward', *CONDITION_KEYS])
        w.writeheader()
        w.writerow({
            'scenario': 'sybil', 'seed': 1000, 'arm': 1, 'reward': 0.87,
            'mean_trust': 0.5, 'mean_load': 0.4, 'mean_latency_ms': 90.0,
            'num_quarantined': 1,
        })
    rows = load_rows(str(path))
    assert len(rows) == 1
    assert rows[0].arm == 1
    assert rows[0].reward == pytest.approx(0.87)
    assert rows[0].conditions == {
        'mean_trust': 0.5, 'mean_load': 0.4, 'mean_latency_ms': 90.0, 'num_quarantined': 1.0,
    }


def test_save_and_load_model_roundtrip(tmp_path):
    model = train(_synthetic_rows(), ARMS, n_estimators=20, random_state=0)
    path = tmp_path / 'model.joblib'
    save_model(model, str(path))
    loaded = load_model(str(path))
    before = predict_values(model, ATTACKED, ARMS)
    after = predict_values(loaded, ATTACKED, ARMS)
    assert before == pytest.approx(after)
