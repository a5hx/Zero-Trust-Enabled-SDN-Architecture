"""Smoke tests for evaluation/starvation_sweep.py -- the reproducible
controller-in-the-loop fan-out harness behind docs/LOAD_BALANCING_STARVATION.md.

These assert the qualitative result the harness exists to show, not exact counts:
argmax starves servers, p2c does not. Kept short (small N, short sim) so they run
in well under a second."""

from evaluation.starvation_sweep import SweepResult, run_sweep, simulate


def test_argmax_starves_but_p2c_does_not():
    argmax = simulate(8, strategy='argmax', epsilon=0.0, sim_s=120.0, seed=1)
    p2c = simulate(8, strategy='p2c', epsilon=0.0, sim_s=120.0, seed=1)
    assert argmax.starved > 0                 # winner-take-all leaves idle servers
    assert p2c.starved == 0                   # power-of-two-choices uses all of them
    assert p2c.used > argmax.used


def test_p2c_lowers_the_busiest_share_and_gini():
    argmax = simulate(16, strategy='argmax', sim_s=120.0, seed=2)
    p2c = simulate(16, strategy='p2c', sim_s=120.0, seed=2)
    assert p2c.busiest_share < argmax.busiest_share
    assert p2c.gini < argmax.gini


def test_result_metrics_are_self_consistent():
    r = SweepResult(n=4, strategy='p2c', epsilon=0.0, served=[10, 0, 5, 5])
    assert r.total == 20
    assert r.starved == 1                      # the zero
    assert r.busiest_share == 0.5              # 10/20
    assert 0.0 <= r.gini <= 1.0


def test_run_sweep_covers_every_strategy_and_n():
    results = run_sweep(ns=[2, 4], seed=1)
    labels = {r.strategy for r in results}
    assert labels == {'argmax', 'p2c', 'p2c+eps'}
    assert len(results) == 3 * 2               # 3 strategies x 2 sizes
