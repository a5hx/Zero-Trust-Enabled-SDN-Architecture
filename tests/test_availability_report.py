"""Tests for evaluation/availability_report.py (plan_adv.md Phase 4).

The arithmetic is checked against hand-computed timelines, because every figure
in this report is a time integral and an off-by-one in segment attribution
would produce a plausible-looking wrong number rather than a crash.

The property guarded hardest is the attacker/honest split: an isolated attacker
is the system working and an isolated honest node is the system's cost, so any
change that lets those two leak into one another should fail here.
"""

import json
import tempfile
import unittest
from pathlib import Path

from evaluation.availability_report import (
    DEFAULT_SERVING_QUORUM,
    NodeAvailability,
    compute,
    format_report,
    main,
    write_csv,
)

T0 = 1000.0


def recording(servers, events=(), end_s=100.0):
    """servers: [(id, attack, start_s)]. events: [(t_rel, type, node)]."""
    nodes = [
        {'id': n, 'kind': 'server', 'ip': f'10.0.1.{i + 1}',
         'attack': a, 'attack_start_s': s}
        for i, (n, a, s) in enumerate(servers)
    ]
    out = [{'ts': T0, 'type': 'topology', 'graph': {'nodes': nodes, 'links': []}}]
    for t_rel, etype, node in events:
        out.append({'ts': T0 + t_rel, 'type': etype, 'node': node,
                    'trust': 0.2, 'anomaly': 0.9})
    out.append({'ts': T0 + end_s, 'type': 'node_status', 'nodes': {}})
    return out


class TestPerNodeArithmetic(unittest.TestCase):
    def test_uptime_is_the_complement_of_measured_downtime(self):
        report = compute(recording(
            [('srv1', 'none', 0.0)],
            [(40.0, 'quarantine', 'srv1'), (60.0, 'recovered', 'srv1')],
        ))
        row = report.nodes[0]
        self.assertEqual(row.quarantined_s, 20.0)
        self.assertEqual(row.eligible_s, 80.0)
        self.assertAlmostEqual(row.eligible_fraction, 0.80)
        self.assertEqual(row.episodes, 1)
        self.assertEqual(row.recoveries, 1)
        self.assertEqual(row.longest_quarantine_s, 20.0)
        self.assertEqual(row.time_to_first_isolation_s, 40.0)
        self.assertFalse(row.isolated_at_end)

    def test_downtime_runs_to_the_end_when_never_recovered(self):
        report = compute(recording(
            [('srv1', 'none', 0.0)], [(25.0, 'quarantine', 'srv1')],
        ))
        row = report.nodes[0]
        self.assertEqual(row.quarantined_s, 75.0)
        self.assertTrue(row.isolated_at_end)
        self.assertTrue(row.never_recovered)

    def test_multiple_episodes_accumulate_and_longest_wins(self):
        report = compute(recording(
            [('srv1', 'none', 0.0)],
            [(10.0, 'quarantine', 'srv1'), (15.0, 'recovered', 'srv1'),
             (40.0, 'quarantine', 'srv1'), (70.0, 'recovered', 'srv1')],
        ))
        row = report.nodes[0]
        self.assertEqual(row.episodes, 2)
        self.assertEqual(row.recoveries, 2)
        self.assertEqual(row.quarantined_s, 35.0)      # 5 + 30
        self.assertEqual(row.longest_quarantine_s, 30.0)
        self.assertEqual(row.time_to_first_isolation_s, 10.0)
        self.assertFalse(row.never_recovered)

    def test_a_node_never_quarantined_is_fully_available(self):
        report = compute(recording([('srv1', 'none', 0.0)]))
        row = report.nodes[0]
        self.assertEqual(row.eligible_fraction, 1.0)
        self.assertEqual(row.episodes, 0)
        self.assertIsNone(row.time_to_first_isolation_s)
        self.assertFalse(row.never_recovered)

    def test_repeated_quarantine_events_do_not_double_count_an_episode(self):
        # The controller publishes on the transition, but a replayed or
        # duplicated recording must not inflate the episode count.
        report = compute(recording(
            [('srv1', 'none', 0.0)],
            [(20.0, 'quarantine', 'srv1'), (30.0, 'quarantine', 'srv1'),
             (50.0, 'recovered', 'srv1')],
        ))
        row = report.nodes[0]
        self.assertEqual(row.episodes, 1)
        self.assertEqual(row.quarantined_s, 30.0)

    def test_recovered_without_a_matching_quarantine_is_ignored(self):
        report = compute(recording(
            [('srv1', 'none', 0.0)], [(20.0, 'recovered', 'srv1')],
        ))
        self.assertEqual(report.nodes[0].eligible_fraction, 1.0)
        self.assertEqual(report.nodes[0].recoveries, 0)


class TestAttackerHonestSplit(unittest.TestCase):
    """The rule this module exists to enforce."""

    def setUp(self):
        # srv1/srv2 attackers isolated early and permanently; srv3 honest
        # wrongly isolated 40-60; srv4 honest clean.
        self.report = compute(recording(
            [('srv1', 'sybil', 10.0), ('srv2', 'drop', 20.0),
             ('srv3', 'none', 0.0), ('srv4', 'none', 0.0)],
            [(15.0, 'quarantine', 'srv1'), (25.0, 'quarantine', 'srv2'),
             (40.0, 'quarantine', 'srv3'), (60.0, 'recovered', 'srv3')],
        ))

    def test_headline_availability_counts_honest_nodes_only(self):
        # srv3 80% + srv4 100% -> 90%. The attackers' 15%/25% must NOT drag
        # this down: isolating them is the system working.
        self.assertAlmostEqual(self.report.honest_availability, 0.90)

    def test_containment_is_reported_as_downtime_of_attackers(self):
        # srv1 85s + srv2 75s over 100s -> 80% mean time contained.
        self.assertAlmostEqual(self.report.attacker_containment, 0.80)

    def test_first_honest_isolation_is_distinct_from_first_isolation(self):
        # The fleet's first isolation was an attacker at 15s -- enforcement.
        # The first honest one was at 40s -- damage. Conflating them would
        # report the defence as an outage.
        self.assertEqual(self.report.time_to_first_isolation_s, 15.0)
        self.assertEqual(self.report.time_to_first_honest_isolation_s, 40.0)

    def test_an_all_attacker_isolation_leaves_honest_availability_perfect(self):
        report = compute(recording(
            [('srv1', 'sybil', 0.0), ('srv2', 'none', 0.0)],
            [(10.0, 'quarantine', 'srv1')],
        ))
        self.assertEqual(report.honest_availability, 1.0)
        self.assertAlmostEqual(report.attacker_containment, 0.90)
        self.assertIsNone(report.time_to_first_honest_isolation_s)

    def test_containment_latency_is_measured_from_configured_onset(self):
        # srv1 armed at 10s, isolated at 15s.
        self.assertAlmostEqual(self.report.containment_latency_s['srv1'], 5.0)
        self.assertAlmostEqual(self.report.containment_latency_s['srv2'], 5.0)

    def test_metrics_are_none_rather_than_zero_when_a_group_is_absent(self):
        # "No attackers" must not read as "containment 0%", which would look
        # like total enforcement failure.
        report = compute(recording([('srv1', 'none', 0.0)]))
        self.assertIsNone(report.attacker_containment)
        self.assertIsNotNone(report.honest_availability)


class TestFleetLifetime(unittest.TestCase):
    def setUp(self):
        self.report = compute(recording(
            [('srv1', 'sybil', 10.0), ('srv2', 'drop', 20.0),
             ('srv3', 'none', 0.0), ('srv4', 'none', 0.0)],
            [(15.0, 'quarantine', 'srv1'), (25.0, 'quarantine', 'srv2'),
             (40.0, 'quarantine', 'srv3'), (60.0, 'recovered', 'srv3')],
        ))

    def test_mean_serving_nodes_is_time_weighted(self):
        # 4x15 + 3x10 + 2x15 + 1x20 + 2x40 = 220 node-seconds over 100s.
        self.assertAlmostEqual(self.report.mean_serving_nodes, 2.20)
        self.assertEqual(self.report.min_serving_nodes, 1)

    def test_quorum_crossing_and_time_above_it(self):
        # Quorum = 50% of 4 = 2 nodes. Serving drops to 1 only over [40, 60).
        self.assertAlmostEqual(self.report.time_to_below_quorum_s, 40.0)
        self.assertAlmostEqual(self.report.above_quorum_s, 80.0)

    def test_no_total_outage_while_any_node_serves(self):
        self.assertEqual(self.report.total_outage_s, 0.0)

    def test_total_outage_is_measured_when_every_node_is_down(self):
        report = compute(recording(
            [('srv1', 'none', 0.0), ('srv2', 'none', 0.0)],
            [(10.0, 'quarantine', 'srv1'), (20.0, 'quarantine', 'srv2'),
             (50.0, 'recovered', 'srv1')],
        ))
        self.assertAlmostEqual(report.total_outage_s, 30.0)   # [20, 50)
        self.assertEqual(report.min_serving_nodes, 0)

    def test_a_fleet_that_never_falls_reports_no_crossing(self):
        report = compute(recording(
            [('srv1', 'none', 0.0), ('srv2', 'none', 0.0)],
        ))
        self.assertIsNone(report.time_to_below_quorum_s)
        self.assertAlmostEqual(report.above_quorum_s, 100.0)

    def test_quorum_is_configurable(self):
        strict = compute(recording(
            [('srv1', 'none', 0.0), ('srv2', 'none', 0.0),
             ('srv3', 'none', 0.0), ('srv4', 'none', 0.0)],
            [(30.0, 'quarantine', 'srv1')],
        ), quorum=1.0)
        self.assertAlmostEqual(strict.time_to_below_quorum_s, 30.0)


class TestTeardownDetection(unittest.TestCase):
    def test_a_late_fleetwide_quarantine_is_flagged_not_silently_trimmed(self):
        # The signature of agents being killed while the controller polls --
        # northbound_api.py's /monitor/pause exists to avoid it.
        report = compute(recording(
            [('srv1', 'none', 0.0), ('srv2', 'none', 0.0)],
            [(98.0, 'quarantine', 'srv1'), (98.5, 'quarantine', 'srv2')],
        ))
        self.assertTrue(report.teardown_suspected)
        self.assertIn('WARNING', format_report(report))
        # Still counted as real downtime -- flagged, not discarded.
        self.assertGreater(report.nodes[0].quarantined_s, 0.0)

    def test_normal_runs_are_not_flagged(self):
        report = compute(recording(
            [('srv1', 'none', 0.0), ('srv2', 'none', 0.0)],
            [(10.0, 'quarantine', 'srv1'), (20.0, 'recovered', 'srv1')],
        ))
        self.assertFalse(report.teardown_suspected)


class TestAbsorbingStateCheck(unittest.TestCase):
    def test_a_stranded_honest_node_is_called_out(self):
        report = compute(recording(
            [('srv1', 'none', 0.0), ('srv2', 'none', 0.0)],
            [(20.0, 'quarantine', 'srv1')],
        ))
        self.assertTrue(report.nodes[0].never_recovered)
        text = format_report(report)
        self.assertIn('NEVER recovered', text)
        self.assertIn('probation', text)

    def test_a_recovering_fleet_says_so(self):
        report = compute(recording(
            [('srv1', 'none', 0.0)],
            [(20.0, 'quarantine', 'srv1'), (30.0, 'recovered', 'srv1')],
        ))
        self.assertIn('stuck in quarantine: none', format_report(report))


class TestReportingAndCli(unittest.TestCase):
    def test_report_renders_all_sections(self):
        text = format_report(compute(recording(
            [('srv1', 'sybil', 0.0), ('srv2', 'none', 0.0)],
            [(10.0, 'quarantine', 'srv1')],
        )))
        for section in ('PER-NODE', 'AVAILABILITY', 'CONTAINMENT',
                        'FLEET LIFETIME'):
            self.assertIn(section, text)

    def test_csv_round_trips(self):
        report = compute(recording(
            [('srv1', 'sybil', 0.0), ('srv2', 'none', 0.0)],
            [(10.0, 'quarantine', 'srv1')],
        ))
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'avail.csv'
            write_csv(report, str(path))
            rows = path.read_text().strip().splitlines()
            self.assertEqual(len(rows), 3)
            self.assertIn('eligible_fraction', rows[0])
            self.assertIn('is_attacker', rows[0])

    def test_cli_runs_and_refuses_a_recording_without_ground_truth(self):
        with tempfile.TemporaryDirectory() as d:
            good = Path(d) / 'good.jsonl'
            with good.open('w') as f:
                for e in recording([('srv1', 'none', 0.0)]):
                    f.write(json.dumps(e) + '\n')
            self.assertEqual(main([str(good)]), 0)

            bad = Path(d) / 'bad.jsonl'
            bad.write_text(json.dumps({'ts': T0, 'type': 'route'}) + '\n')
            self.assertEqual(main([str(bad)]), 1)

    def test_empty_roster_does_not_divide_by_zero(self):
        report = compute([{'ts': T0, 'type': 'topology',
                           'graph': {'nodes': [], 'links': []}}])
        self.assertIsNone(report.honest_availability)
        self.assertEqual(report.nodes, [])

    def test_node_row_defaults_are_sane(self):
        row = NodeAvailability(node='srv1', truth='none', run_s=0.0)
        # A zero-length run must read as "fully available", not as a
        # divide-by-zero or as 0% uptime.
        self.assertEqual(row.eligible_fraction, 1.0)
        self.assertEqual(row.mean_episode_s, 0.0)


if __name__ == '__main__':
    unittest.main()
