"""Tests for evaluation/generate_optimizer_dataset.py -- the offline Random
Forest's training-data generator (Step 1, docs/AI_OPTIMIZER.md Part 2)."""
import csv

from evaluation.baseline import SCENARIOS
from evaluation.generate_optimizer_dataset import FIELDNAMES, generate_rows, write_csv


def test_generate_rows_covers_every_scenario_with_expected_row_count() -> None:
    rows = generate_rows(runs=2, sim_s=30.0, n_nodes=4, window_s=10.0, seed0=2000)
    assert {r['scenario'] for r in rows} == set(SCENARIOS)
    # floor(30/10) = 3 windows per run, 2 runs per scenario, 4 scenarios.
    assert len(rows) == 3 * 2 * len(SCENARIOS)


def test_generate_rows_are_seeded_reproducibly() -> None:
    a = generate_rows(runs=2, sim_s=30.0, n_nodes=4, seed0=2000)
    b = generate_rows(runs=2, sim_s=30.0, n_nodes=4, seed0=2000)
    assert a == b


def test_write_csv_roundtrip(tmp_path) -> None:
    rows = generate_rows(runs=1, sim_s=30.0, n_nodes=4, seed0=2000)
    path = tmp_path / 'dataset.csv'
    write_csv(rows, str(path))
    read_back = list(csv.DictReader(path.open()))
    assert len(read_back) == len(rows)
    assert set(read_back[0]) == set(FIELDNAMES)
