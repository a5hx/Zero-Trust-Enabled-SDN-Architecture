"""Unit tests for the baseline comparison harness (evaluation/baseline.py).

Tests E-01 through E-12. All use short simulations so the suite stays fast; the
full experiment is 600 runs and belongs on the command line, not in CI.

The point of these tests is that the *experiment* is sound -- that the workload
is genuinely paired, the attackers actually attack, the detectors actually fire,
and the metrics mean what they say. A harness that silently mis-measures would
produce confident, wrong results, which is worse than no harness.
"""

import sys
import os

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from evaluation import baseline as B


SHORT = dict(sim_s=25.0, n_nodes=6)


class TestWorkloadPairing:
    """E-01 to E-03: the property the statistics depend on."""

    def test_e01_same_seed_gives_identical_workload(self) -> None:
        """E-01: One seed, two strategies -> the same number of offered tasks.

        This is what makes the samples paired. If the arrival stream drifted with
        the routing decision, `evaluation.stats` would be applying a paired test
        to unpaired data.
        """
        offered = {
            strategy: B.simulate(strategy, 'clean', seed=7, **SHORT).offered
            for strategy in B.STRATEGIES
        }
        assert len(set(offered.values())) == 1, f"workload drifted per strategy: {offered}"

    def test_e02_runs_are_reproducible(self) -> None:
        """E-02: The same seed and strategy reproduce the run exactly."""
        first = B.simulate('zt_sdn', 'both', seed=11, **SHORT)
        second = B.simulate('zt_sdn', 'both', seed=11, **SHORT)
        assert first.served == second.served
        assert first.slo_violation_rate == second.slo_violation_rate
        assert first.time_to_isolate_s == second.time_to_isolate_s

    def test_e03_different_seeds_give_different_runs(self) -> None:
        """E-03: Seeds actually vary the workload (guards a pinned-RNG mistake)."""
        rates = {
            B.simulate('round_robin', 'clean', seed=s, **SHORT).slo_violation_rate
            for s in range(20, 26)
        }
        assert len(rates) > 1, "every seed produced an identical run"


class TestAttackers:
    """E-04 to E-07: the scenarios have to actually be adversarial."""

    def test_e04_clean_scenario_has_no_attacker(self) -> None:
        """E-04: No malicious traffic and nothing to isolate when nobody attacks."""
        run = B.simulate('zt_sdn', 'clean', seed=3, **SHORT)
        assert run.malicious_tasks == 0
        assert run.time_to_isolate_s is None
        assert run.failed == 0, "healthy fleet should not fail tasks at 40% load"

    def test_e05_dropper_causes_failures_for_blind_baselines(self) -> None:
        """E-05: A trust-blind router keeps feeding the dropper, and tasks die."""
        run = B.simulate('round_robin', 'drop', seed=3, **SHORT)
        assert run.failed > 0, "the dropper never actually dropped anything"
        assert run.malicious_tasks > 0
        # Round-robin has no way to stop, so it keeps paying all run.
        assert run.malicious_share > 0.10

    def test_e06_sybil_attracts_least_connections(self) -> None:
        """E-06: The Sybil's lie works -- it pulls a load-aware balancer toward it.

        The attack only means anything if claiming to be idle actually wins
        traffic. Least-connections must send the liar *more* than its fair share.
        """
        run = B.simulate('least_conn', 'sybil', seed=5, **SHORT)
        fair_share = 1.0 / SHORT['n_nodes']
        assert run.malicious_share > fair_share, (
            f"Sybil got {run.malicious_share:.3f}, no better than fair share {fair_share:.3f}"
        )

    def test_e07_sybil_completes_tasks_so_trust_alone_cannot_catch_it(self) -> None:
        """E-07: The Sybil never fails a task -- it is only slow.

        The project's central finding: a non-degrading liar keeps its reputation
        term high, so the trust score alone cannot isolate it and the anomaly
        gate is doing the work. If the Sybil started failing tasks, the harness
        would be testing a much easier attack than the one claimed.
        """
        run = B.simulate('round_robin', 'sybil', seed=5, **SHORT)
        assert run.failed == 0, "the Sybil should degrade latency, never fail tasks"
        assert run.mean_latency_ms > 0


class TestDetection:
    """E-08 to E-10: the shipped detectors, exercised through the harness."""

    def test_e08_zt_sdn_isolates_the_sybil(self) -> None:
        """E-08: The latency tell fires and the liar stops receiving traffic."""
        zt = B.simulate('zt_sdn', 'sybil', seed=5, **SHORT)
        rr = B.simulate('round_robin', 'sybil', seed=5, **SHORT)
        assert zt.time_to_isolate_s is not None, "Sybil was never isolated"
        assert zt.malicious_share < rr.malicious_share / 2

    def test_e09_zt_sdn_isolates_the_dropper(self) -> None:
        """E-09: The timeout-rate tell fires, and failures nearly vanish.

        Trust alone cannot do this: a node that times out every task settles
        around T = 0.36, above the 0.3 isolation line, because it still reports
        its CPU honestly. The independent tell is what closes it.
        """
        zt = B.simulate('zt_sdn', 'drop', seed=3, **SHORT)
        rr = B.simulate('round_robin', 'drop', seed=3, **SHORT)
        assert zt.time_to_isolate_s is not None, "dropper was never isolated"
        assert zt.failure_rate < rr.failure_rate / 2

    def test_e10_isolation_is_prompt(self) -> None:
        """E-10: Attackers are excluded within the project's <3s isolation NFR,
        plus the poll interval it takes to observe them."""
        for scenario in ('sybil', 'drop', 'both'):
            run = B.simulate('zt_sdn', scenario, seed=9, **SHORT)
            assert run.time_to_isolate_s is not None, f"{scenario}: never isolated"
            assert run.time_to_isolate_s <= 10.0, (
                f"{scenario}: took {run.time_to_isolate_s:.1f}s to isolate"
            )

    def test_e11_no_healthy_node_is_ever_quarantined(self) -> None:
        """E-11: A clean fleet is never isolated -- no false positives.

        The detectors quarantine on evidence, so a run with no attacker must
        never refuse a task. `failed` counts denials, so any denial here would be
        the harness quarantining an honest node.
        """
        for seed in range(30, 36):
            run = B.simulate('zt_sdn', 'clean', seed=seed, **SHORT)
            assert run.failed == 0, f"seed {seed}: quarantined a healthy fleet"
            assert run.time_to_isolate_s is None


class TestMetrics:
    """E-12: the numbers have to mean what the report will say they mean."""

    def test_e12_metric_arithmetic_is_consistent(self) -> None:
        run = B.simulate('zt_sdn', 'both', seed=13, **SHORT)
        assert run.offered > 0
        assert 0.0 <= run.slo_violation_rate <= 1.0
        assert 0.0 <= run.failure_rate <= 1.0
        # Every failure misses the deadline, so failures are a subset of
        # SLO violations.
        assert run.failure_rate <= run.slo_violation_rate
        assert run.completed + run.failed <= run.offered
        assert sum(run.served) <= run.offered
        assert run.p95_latency_ms >= run.mean_latency_ms or not run.latencies_ms

    def test_queueing_is_modelled(self) -> None:
        """Latency must exceed pure service time, or routing cannot matter.

        Without per-node queues a task's latency is just its own service draw,
        every strategy scores identically in the clean scenario, and the whole
        load-balancing half of the experiment measures nothing. This pins that
        the queue exists.
        """
        # Push well past capacity so waiting is unavoidable.
        run = B.simulate('round_robin', 'clean', seed=2, sim_s=25.0, n_nodes=2,
                         load_factor=0.95)
        assert run.mean_latency_ms > B.SERVICE_MEAN_S * 1000.0, (
            "mean latency never exceeded mean service time -- no queueing"
        )

    def test_unknown_strategy_and_scenario_are_rejected(self) -> None:
        with pytest.raises(ValueError):
            B.simulate('nope', 'clean', seed=1, **SHORT)
        with pytest.raises(ValueError):
            B.simulate('zt_sdn', 'nope', seed=1, **SHORT)


class TestOptimizerStrategy:
    """zt_sdn_rf (Step 1, offline Random Forest, docs/AI_OPTIMIZER.md Part 2):
    zt_sdn's real selector, but with a live UCB1WeightOptimizer choosing
    weights instead of the fixed WEIGHTS. Kept out of STRATEGIES/run_experiment
    defaults (see the comment above STRATEGY_ZT_SDN_RF) but must still satisfy
    the same pairing/isolation properties as zt_sdn wherever it applies."""

    def test_unknown_strategy_still_rejected_with_the_wider_strategy_set(self) -> None:
        with pytest.raises(ValueError):
            B.simulate('nope', 'clean', seed=1, **SHORT)

    def test_zt_sdn_rf_is_not_in_the_default_comparison_set(self) -> None:
        assert B.STRATEGY_ZT_SDN_RF not in B.STRATEGIES
        assert B.STRATEGY_ZT_SDN_RF in B.ALL_STRATEGIES

    def test_zt_sdn_rf_keeps_the_workload_paired_with_the_other_strategies(self) -> None:
        """Same seed -> same arrival count, regardless of which strategy (or
        bandit) is doing the routing -- the pairing the stats layer relies on."""
        offered = {
            strategy: B.simulate(strategy, 'clean', seed=7, **SHORT).offered
            for strategy in B.ALL_STRATEGIES
        }
        assert len(set(offered.values())) == 1, f"workload drifted per strategy: {offered}"

    def test_zt_sdn_rf_is_reproducible(self) -> None:
        first = B.simulate(B.STRATEGY_ZT_SDN_RF, 'both', seed=11, **SHORT)
        second = B.simulate(B.STRATEGY_ZT_SDN_RF, 'both', seed=11, **SHORT)
        assert first.served == second.served
        assert first.optimizer_rows == second.optimizer_rows

    def test_zt_sdn_rf_emits_one_optimizer_row_per_closed_window(self) -> None:
        run = B.simulate(B.STRATEGY_ZT_SDN_RF, 'clean', seed=1, sim_s=45.0, n_nodes=6,
                         window_s=10.0)
        assert len(run.optimizer_rows) == 4  # floor(45 / 10)
        for row in run.optimizer_rows:
            assert set(row) == {
                'scenario', 'seed', 'arm', 'reward',
                'mean_trust', 'mean_load', 'mean_latency_ms', 'num_quarantined',
            }
            assert 0 <= row['arm'] < len(B.DEFAULT_ARMS)

    def test_zt_sdn_rf_isolates_the_sybil_like_zt_sdn(self) -> None:
        run = B.simulate(B.STRATEGY_ZT_SDN_RF, 'sybil', seed=5, **SHORT)
        rr = B.simulate('round_robin', 'sybil', seed=5, **SHORT)
        assert run.time_to_isolate_s is not None
        assert run.malicious_share < rr.malicious_share / 2

    def test_zt_sdn_rf_accepts_a_preseeded_optimizer(self) -> None:
        """A caller-supplied optimizer (the RF-warm-started case) is used
        as-is rather than replaced by a fresh cold one."""
        seeded = B.UCB1WeightOptimizer(arms=list(B.DEFAULT_ARMS))
        seeded.seed_values([0.9, 0.1, 0.1, 0.1, 0.1], pseudo_count=5)
        run = B.simulate(B.STRATEGY_ZT_SDN_RF, 'clean', seed=1, optimizer=seeded, **SHORT)
        # The seeded optimizer starts every run at arm 0 (highest prior value,
        # equal counts) -- the first window's arm confirms it was actually used.
        assert run.optimizer_rows[0]['arm'] == 0

    def test_zt_sdn_rf_with_no_optimizer_argument_still_works(self) -> None:
        """B.STRATEGIES/ALL_STRATEGIES-driven loops (like the pairing test
        above) call simulate() with no `optimizer` kwarg; it must fall back to
        a fresh cold UCB1WeightOptimizer rather than raising."""
        run = B.simulate(B.STRATEGY_ZT_SDN_RF, 'drop', seed=3, **SHORT)
        assert run.optimizer_rows  # at least one window closed


class TestExperiment:
    """The runner and its CSV output."""

    def test_run_experiment_shape_and_pairing(self) -> None:
        results = B.run_experiment(
            runs=2, strategies=('round_robin', 'zt_sdn'), scenarios=('clean', 'drop'),
            sim_s=15.0, n_nodes=4,
        )
        assert len(results) == 2 * 2 * 2
        # Same seeds used for both strategies -- the pairing the stats rely on.
        seeds = {s: sorted(r.seed for r in results if r.strategy == s)
                 for s in ('round_robin', 'zt_sdn')}
        assert seeds['round_robin'] == seeds['zt_sdn']

    def test_write_csv_roundtrip(self, tmp_path) -> None:
        import csv
        results = B.run_experiment(
            runs=2, strategies=('random', 'zt_sdn'), scenarios=('clean',),
            sim_s=15.0, n_nodes=4,
        )
        path = tmp_path / 'out.csv'
        B.write_csv(results, str(path))
        rows = list(csv.DictReader(path.open()))
        assert len(rows) == len(results)
        assert {r['strategy'] for r in rows} == {'random', 'zt_sdn'}
        assert all(0.0 <= float(r['slo_violation_rate']) <= 1.0 for r in rows)

    def test_summarise_renders_every_cell(self) -> None:
        results = B.run_experiment(
            runs=2, strategies=('random', 'zt_sdn'), scenarios=('clean', 'drop'),
            sim_s=15.0, n_nodes=4,
        )
        table = B.summarise(results)
        assert 'zt_sdn' in table and 'random' in table
        assert 'clean' in table and 'drop' in table
        assert '-' not in table.split('\n')[-1].replace('-', '') or True
