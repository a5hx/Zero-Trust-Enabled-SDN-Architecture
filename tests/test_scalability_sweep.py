"""Tests for evaluation/scalability_sweep.py (plan_adv.md Phase 3).

Two things are worth guarding here. First the MODEL: this harness only says
anything new because it queues and times out, so if the queueing invariant
silently broke it would quietly become starvation_sweep.py with extra columns
and report perfect scaling for everything. Second the RESULTS the module
docstring claims -- asserted qualitatively (direction, not exact figures) so
they stay meaningful across seeds and machines.

Kept to small N and short sims so the file runs in a couple of seconds.
"""

import unittest

from evaluation.scalability_sweep import (
    CONCURRENCY,
    STRATEGIES,
    SweepPoint,
    format_table,
    run_sweep,
    simulate,
    write_csv,
)


class TestQueueingModel(unittest.TestCase):
    """The properties that distinguish this harness from starvation_sweep.py."""

    def test_tasks_actually_queue_and_wait(self):
        # An M/M/c queue under real load must show waiting: mean latency has to
        # exceed the 200ms mean service time. If this ever passes trivially,
        # the model has silently become infinite-server and every scaling
        # result in this module is meaningless.
        point = simulate(4, strategy='p2c', load_factor=0.8, sim_s=60.0, seed=1)
        self.assertGreater(point.mean_latency_ms, 200.0)

    def test_saturation_produces_timeouts(self):
        point = simulate(4, strategy='p2c', load_factor=1.5, sim_s=60.0, seed=1)
        self.assertGreater(point.timed_out, 0)
        self.assertLess(point.pdr, 1.0)

    def test_light_load_produces_almost_none(self):
        point = simulate(8, strategy='p2c', load_factor=0.1, sim_s=60.0, seed=1)
        self.assertGreater(point.pdr, 0.95)

    def test_outcomes_never_exceed_what_was_offered(self):
        # Not equality: tasks still in service when the clock runs out are
        # neither completed nor timed out.
        point = simulate(8, strategy='p2c', load_factor=0.6, sim_s=60.0, seed=3)
        self.assertLessEqual(
            point.completed + point.timed_out + point.denied, point.offered,
        )
        self.assertEqual(sum(point.served) + point.denied, point.offered)

    def test_a_timed_out_task_is_not_also_counted_completed(self):
        # The client abandons at the timeout but the node keeps working, so a
        # task can time out and later finish. It must be counted once, as loss.
        point = simulate(4, strategy='argmax', load_factor=1.2, sim_s=60.0, seed=2)
        self.assertGreater(point.timed_out, 0)
        self.assertLessEqual(point.completed + point.timed_out, point.offered)

    def test_throughput_uses_the_run_length_actually_simulated(self):
        short = simulate(4, strategy='p2c', sim_s=30.0, seed=1)
        self.assertEqual(short.sim_s, 30.0)
        self.assertAlmostEqual(short.throughput_hz, short.completed / 30.0, places=6)


class TestTrustComposition(unittest.TestCase):
    def test_overloaded_honest_nodes_are_never_starved_of_eligibility(self):
        """Trust is composed (aR + b + g), not equated with reliability.

        Under heavy loss a reliability-only model would drop every node below
        the 0.30 isolation threshold and the controller would deny everything
        -- a modelling artifact, since a merely-slow node is still behaving
        consistently and reporting honestly. No denials is the check.
        """
        point = simulate(4, strategy='p2c', load_factor=2.0, sim_s=60.0, seed=1)
        self.assertGreater(point.timed_out, 0)   # genuinely overloaded
        self.assertEqual(point.denied, 0)        # but never ruled ineligible


class TestHeadlineResults(unittest.TestCase):
    """The claims the module docstring makes, asserted by direction."""

    def test_p2c_scales_throughput_where_argmax_stalls(self):
        small_p2c = simulate(4, strategy='p2c', load_factor=0.6, sim_s=60.0, seed=1)
        big_p2c = simulate(16, strategy='p2c', load_factor=0.6, sim_s=60.0, seed=1)
        small_am = simulate(4, strategy='argmax', load_factor=0.6, sim_s=60.0, seed=1)
        big_am = simulate(16, strategy='argmax', load_factor=0.6, sim_s=60.0, seed=1)

        # Offered load scales with N, so keeping up means throughput scales too.
        self.assertGreater(big_p2c.throughput_hz, 3.0 * small_p2c.throughput_hz)
        # argmax cannot use the extra capacity.
        self.assertLess(big_am.throughput_hz, 2.0 * small_am.throughput_hz)

    def test_argmax_pdr_collapses_under_load_but_p2c_holds(self):
        am = simulate(16, strategy='argmax', load_factor=0.6, sim_s=60.0, seed=1)
        p2c = simulate(16, strategy='p2c', load_factor=0.6, sim_s=60.0, seed=1)
        self.assertLess(am.pdr, 0.90)
        self.assertGreater(p2c.pdr, 0.95)

    def test_argmax_starves_at_low_load_and_p2c_does_not(self):
        # The other failure mode, at the opposite end of offered load. This is
        # the effect docs/LOAD_BALANCING_STARVATION.md documents.
        am = simulate(16, strategy='argmax', load_factor=0.1, sim_s=60.0, seed=1)
        p2c = simulate(16, strategy='p2c', load_factor=0.1, sim_s=60.0, seed=1)
        self.assertGreater(am.starved, 0)
        self.assertEqual(p2c.starved, 0)
        self.assertLess(am.jain, 0.5)
        self.assertGreater(p2c.jain, 0.8)

    def test_argmax_is_balanced_but_lossy_at_high_load(self):
        """Both failure modes must be visible, or argmax looks merely unfair.

        At high load queues build on the favoured nodes and the CPU term
        finally spreads traffic, so fairness recovers while delivery does not.
        """
        am_low = simulate(16, strategy='argmax', load_factor=0.1, sim_s=60.0, seed=1)
        am_high = simulate(16, strategy='argmax', load_factor=0.6, sim_s=60.0, seed=1)
        self.assertGreater(am_high.jain, am_low.jain)   # fairer...
        self.assertLess(am_high.pdr, am_low.pdr)        # ...and worse

    def test_p2c_does_not_make_decisions_cheaper(self):
        """select_edge_node ranks every eligible node whatever the strategy,
        so p2c's O(d) sampling rides on an O(N log N) base rather than
        replacing it. Pinned so the docstring's claim 3 cannot go stale."""
        am = simulate(16, strategy='argmax', load_factor=0.3, sim_s=30.0, seed=1)
        p2c = simulate(16, strategy='p2c', load_factor=0.3, sim_s=30.0, seed=1)
        self.assertGreater(am.decision_us_mean, 0.0)
        self.assertGreater(p2c.decision_us_mean, 0.0)
        # Not cheaper. Generous bound -- this is wall-clock on a shared box and
        # the point is the absence of an order-of-magnitude win, not a precise
        # ratio.
        self.assertGreater(p2c.decision_us_mean, am.decision_us_mean * 0.5)

    def test_decision_cost_grows_with_n_under_both_strategies(self):
        small = simulate(4, strategy='p2c', load_factor=0.3, sim_s=30.0, seed=1)
        big = simulate(32, strategy='p2c', load_factor=0.3, sim_s=30.0, seed=1)
        self.assertGreater(big.decision_us_mean, small.decision_us_mean)


class TestSweepAndReporting(unittest.TestCase):
    def test_sweep_covers_every_strategy_n_and_load(self):
        results = run_sweep(
            ns=[2, 4], seed=1, sim_s=20.0, load_factors=[0.2, 0.5],
        )
        self.assertEqual(len(results), len(STRATEGIES) * 2 * 2)
        self.assertEqual({r.strategy for r in results}, set(STRATEGIES))
        self.assertEqual({r.load_factor for r in results}, {0.2, 0.5})

    def test_metrics_are_self_consistent_on_a_hand_built_point(self):
        point = SweepPoint(
            n=4, strategy='p2c', epsilon=0.0, sim_s=10.0,
            offered=100, completed=90, timed_out=10,
            served=[25, 25, 25, 25], latencies=[0.1] * 90,
        )
        self.assertEqual(point.throughput_hz, 9.0)
        self.assertEqual(point.pdr, 0.9)
        self.assertAlmostEqual(point.mean_latency_ms, 100.0)
        self.assertAlmostEqual(point.jain, 1.0)      # a perfectly even spread
        self.assertEqual(point.starved, 0)
        self.assertAlmostEqual(point.busiest_share, 0.25)

    def test_jain_reflects_a_lopsided_spread(self):
        even = SweepPoint(n=4, strategy='p2c', epsilon=0.0, served=[10, 10, 10, 10])
        skewed = SweepPoint(n=4, strategy='argmax', epsilon=0.0, served=[40, 0, 0, 0])
        self.assertAlmostEqual(even.jain, 1.0)
        self.assertAlmostEqual(skewed.jain, 0.25)    # 1/n, the floor
        self.assertEqual(skewed.starved, 3)

    def test_table_and_csv_render(self):
        import tempfile
        from pathlib import Path

        results = run_sweep(ns=[2], seed=1, sim_s=20.0, load_factors=[0.3])
        table = format_table(results)
        self.assertIn('Jain', table)
        self.assertIn('load', table)

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'out.csv'
            write_csv(results, str(path))
            rows = path.read_text().strip().splitlines()
            self.assertEqual(len(rows), len(results) + 1)
            self.assertIn('denied', rows[0])
            self.assertIn('load_factor', rows[0])

    def test_cli_runs(self):
        from evaluation.scalability_sweep import main

        self.assertEqual(
            main(['--ns', '2,4', '--sim-s', '20', '--load-factors', '0.3']), 0,
        )


if __name__ == '__main__':
    unittest.main()
