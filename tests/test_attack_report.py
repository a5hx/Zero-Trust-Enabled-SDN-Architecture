"""Tests for evaluation/attack_report.py (plan_adv.md Phase 2).

Builds small hand-written JSONL recordings rather than mining a real one, so
each rule is exercised in isolation and the tests do not depend on a 1 GB
gitignored artifact (memory/study-runs-and-data).
"""

import json
import tempfile
import unittest
from pathlib import Path

from controller.attack_classifier import (
    GROUND_TRUTH_ALIASES,
    ATTACK_BAD_CREDENTIALS,
    ATTACK_BLACKHOLE,
    ATTACK_FLOOD,
    ATTACK_ONOFF,
    ATTACK_SPOOF,
    ATTACK_SYBIL,
    NO_ATTACK,
    SIG_LATENCY_TELL,
    SIG_PACKET_DROP,
)
from evaluation.attack_report import (
    AUTH_KIND_BAD_RESPONSE,
    AUTH_KIND_IP_PIN,
    client_observations,
    confusion_matrix,
    format_report,
    ground_truth,
    node_cycles,
    onset_times,
    per_class_metrics,
    score_run,
    subject_aliases,
    write_csv,
)

T0 = 1000.0


def topology_event(servers, iots=()):
    nodes = [
        {'id': n, 'kind': 'server', 'ip': f'10.0.1.{i + 1}',
         'attack': a, 'attack_start_s': s}
        for i, (n, a, s) in enumerate(servers)
    ]
    nodes += [
        {'id': n, 'kind': 'iot', 'ip': f'10.0.2.{i + 1}',
         'attack': a, 'attack_start_s': s}
        for i, (n, a, s) in enumerate(iots)
    ]
    return {'ts': T0, 'type': 'topology', 'graph': {'nodes': nodes, 'links': []}}


class TestGroundTruth(unittest.TestCase):
    def test_reads_servers_and_iot_devices(self):
        events = [topology_event(
            [('srv1', 'sybil', 10.0), ('srv2', 'none', 0.0)],
            [('iot1', 'flood', 5.0)],
        )]
        truth = ground_truth(events)
        self.assertEqual(truth['srv1'], ('node', ATTACK_SYBIL))
        self.assertEqual(truth['srv2'], ('node', NO_ATTACK))
        self.assertEqual(truth['iot1'], ('client', ATTACK_FLOOD))

    def test_legacy_drop_maps_to_standard_blackhole_terminology(self):
        events = [topology_event([('srv1', 'drop', 0.0)])]
        self.assertEqual(ground_truth(events)['srv1'], ('node', ATTACK_BLACKHOLE))

    def test_onsets_and_aliases(self):
        events = [topology_event(
            [('srv1', 'sybil', 12.5)], [('iot1', 'flood', 3.0)],
        )]
        self.assertEqual(onset_times(events)['srv1'], 12.5)
        self.assertEqual(subject_aliases(events), {'10.0.2.1': 'iot1'})

    def test_no_topology_event_yields_no_ground_truth(self):
        self.assertEqual(ground_truth([{'ts': T0, 'type': 'route'}]), {})


class TestCycleReconstruction(unittest.TestCase):
    def test_node_status_supplies_the_clean_cycles(self):
        events = [
            {'ts': T0 + 0.1, 'type': 'anomaly', 'node': 'srv1',
             'reasons': ['x'], 'signals': {SIG_LATENCY_TELL: 6.0}},
            {'ts': T0 + 0.5, 'type': 'node_status', 'nodes': {}},
            {'ts': T0 + 1.5, 'type': 'node_status', 'nodes': {}},
            {'ts': T0 + 2.5, 'type': 'node_status', 'nodes': {}},
        ]
        windows = node_cycles(events, ['srv1'])
        self.assertEqual(len(windows['srv1']), 3)
        self.assertTrue(windows['srv1'][0].signals)
        # Cycles 2 and 3 had no anomaly: recorded as CLEAN, not skipped. The
        # on-off rule is entirely dependent on these existing.
        self.assertEqual(windows['srv1'][1].signals, {})
        self.assertEqual(windows['srv1'][2].signals, {})

    def test_signals_do_not_leak_across_cycles(self):
        events = [
            {'ts': T0, 'type': 'anomaly', 'node': 'srv1', 'reasons': [],
             'signals': {SIG_PACKET_DROP: 1.0}},
            {'ts': T0 + 0.5, 'type': 'node_status', 'nodes': {}},
            {'ts': T0 + 1.5, 'type': 'node_status', 'nodes': {}},
        ]
        windows = node_cycles(events, ['srv1'])
        self.assertEqual(windows['srv1'][1].signals, {})

    def test_legacy_anomaly_without_signals_counts_as_flagged_not_clean(self):
        # A recording made before structured signals existed must not have its
        # detections silently downgraded to clean cycles -- that is the one
        # direction of error this report must never make quietly.
        events = [
            {'ts': T0, 'type': 'anomaly', 'node': 'srv1', 'reasons': ['prose only']},
            {'ts': T0 + 0.5, 'type': 'node_status', 'nodes': {}},
        ]
        windows = node_cycles(events, ['srv1'])
        self.assertTrue(windows['srv1'][0].signals)

    def test_client_observations_split_by_signal_kind(self):
        events = [
            {'ts': T0, 'type': 'flood', 'client_ip': '10.0.2.1', 'ratio': 40.0},
            {'ts': T0 + 1, 'type': 'auth_denied', 'device_id': 'iot2',
             'source_ip': '10.0.2.2', 'kind': AUTH_KIND_IP_PIN},
            {'ts': T0 + 2, 'type': 'auth_denied', 'device_id': 'iot3',
             'source_ip': '10.0.2.3', 'kind': AUTH_KIND_BAD_RESPONSE},
        ]
        obs = client_observations(events)
        # Both are keyed by the SOURCE IP: the host that acted. For a spoofer
        # that is the only field naming the attacker at all -- device_id names
        # its victim.
        self.assertIn('10.0.2.1', obs)
        self.assertIn('10.0.2.2', obs)
        self.assertIn('10.0.2.3', obs)


class TestAuthKindPinning(unittest.TestCase):
    def test_kinds_match_the_real_authenticator_constants(self):
        # attack_report.py duplicates these as plain strings so the analysis
        # can run without the controller stack installed (same reason
        # interval_report.py duplicates PRIO_QUARANTINE_DROP). Pin them so the
        # two cannot drift silently.
        from security.authenticator import (
            AUTH_DENY_BAD_RESPONSE, AUTH_DENY_IP_PIN,
        )
        self.assertEqual(AUTH_KIND_IP_PIN, AUTH_DENY_IP_PIN)
        self.assertEqual(AUTH_KIND_BAD_RESPONSE, AUTH_DENY_BAD_RESPONSE)


def _build_recording():
    """A short run with one of each node-side attack plus honest nodes."""
    events = [topology_event(
        [('srv1', 'sybil', 5.0), ('srv2', 'drop', 5.0), ('srv3', 'none', 0.0)],
        [('iot1', 'flood', 5.0), ('iot2', 'spoof', 2.0), ('iot3', 'none', 0.0)],
    )]
    # iot2 is the SPOOFER here: it sends from its own address (10.0.2.2)
    # while claiming to be iot1. The denial must be filed against iot2.
    events.append({'ts': T0 + 2.2, 'type': 'auth_denied', 'device_id': 'iot1',
                   'source_ip': '10.0.2.2', 'kind': AUTH_KIND_IP_PIN,
                   'reason': 'iot1 is pinned to another IP'})
    events.append({'ts': T0 + 6.0, 'type': 'flood', 'client_ip': '10.0.2.1',
                   'ratio': 40.0, 'rate_hz': 40.0})
    for c in range(40):
        t = T0 + c
        if c >= 5:
            events.append({'ts': t, 'type': 'anomaly', 'node': 'srv1',
                           'reasons': ['latency tell'],
                           'signals': {SIG_LATENCY_TELL: 6.0}})
            events.append({'ts': t, 'type': 'anomaly', 'node': 'srv2',
                           'reasons': ['packet-drop tell'],
                           'signals': {SIG_PACKET_DROP: 1.0}})
        events.append({'ts': t + 0.5, 'type': 'node_status', 'nodes': {}})
    return events


class TestScoreRun(unittest.TestCase):
    def setUp(self):
        self.results = {r.subject: r for r in score_run(_build_recording())}

    def test_every_configured_subject_is_scored(self):
        self.assertEqual(
            set(self.results), {'srv1', 'srv2', 'srv3', 'iot1', 'iot2', 'iot3'},
        )

    def test_node_attacks_are_classified_correctly(self):
        self.assertEqual(self.results['srv1'].predicted, ATTACK_SYBIL)
        self.assertEqual(self.results['srv2'].predicted, ATTACK_BLACKHOLE)

    def test_client_attacks_are_classified_correctly(self):
        # iot1's evidence arrives keyed by IP and must be folded onto its
        # device id, or it would score as an unseen subject.
        self.assertEqual(self.results['iot1'].predicted, ATTACK_FLOOD)
        self.assertEqual(self.results['iot2'].predicted, ATTACK_SPOOF)

    def test_honest_subjects_are_not_accused(self):
        self.assertEqual(self.results['srv3'].predicted, NO_ATTACK)
        self.assertEqual(self.results['iot3'].predicted, NO_ATTACK)
        self.assertTrue(self.results['srv3'].correct)

    def test_detection_latency_is_measured_from_configured_onset(self):
        r = self.results['srv1']
        self.assertEqual(r.onset_s, 5.0)
        self.assertIsNotNone(r.detection_latency_s)
        # Flagged from cycle 5, closed by the node_status at +5.5s, against a
        # 5.0s onset.
        self.assertAlmostEqual(r.detection_latency_s, 0.5, places=3)

    def test_latency_is_unknown_rather_than_guessed_without_onset_truth(self):
        events = _build_recording()
        for node in events[0]['graph']['nodes']:
            node.pop('attack_start_s', None)
        results = {r.subject: r for r in score_run(events)}
        self.assertIsNone(results['srv1'].detection_latency_s)

    def test_run_verdict_is_modal_not_final(self):
        # An on-off attacker is correctly abstained on during a good phase, so
        # the label standing at the end of a recording says more about where
        # the run was cut than about what the system concluded.
        events = [topology_event([('srv1', 'onoff', 0.0)])]
        pattern = ([True] * 6 + [False] * 6) * 4 + [False] * 40
        for c, bad in enumerate(pattern):
            t = T0 + c
            if bad:
                events.append({'ts': t, 'type': 'anomaly', 'node': 'srv1',
                               'reasons': ['latency tell'],
                               'signals': {SIG_LATENCY_TELL: 6.0}})
            events.append({'ts': t + 0.5, 'type': 'node_status', 'nodes': {}})
        # Window sized between the two constraints: wide enough to span a full
        # 12-cycle on-off period (below ~2x the period it degrades to a sybil
        # verdict -- see DEFAULT_WINDOW_CYCLES and the test below), but
        # narrower than the 40-cycle clean tail so the classifier really does
        # abstain at the end. Without an abstaining tail "modal, not final"
        # would be indistinguishable from "final".
        result = score_run(events, window_cycles=30)[0]
        self.assertGreater(
            result.abstained_cycles, 0,
            'the tail should abstain, otherwise this test proves nothing',
        )
        self.assertEqual(result.predicted, ATTACK_ONOFF)


class TestOnOffWindowConstraint(unittest.TestCase):
    """A window narrower than one on-off period degrades to a sybil verdict.

    Not a defect and not tuned away: with only one phase in view at a time the
    evidence genuinely does look like sustained misbehaviour, and the attacker
    is still caught and quarantined either way -- only the LABEL degrades.
    Pinned here because it is the reason DEFAULT_WINDOW_CYCLES is set where it
    is, and a future "let's shrink the window to save memory" change would
    otherwise silently turn every on-off result into a sybil result.
    """

    PERIOD = 12   # 6 bad + 6 clean cycles

    def _run(self, window_cycles):
        events = [topology_event([('srv1', 'onoff', 0.0)])]
        for c, bad in enumerate(([True] * 6 + [False] * 6) * 6):
            t = T0 + c
            if bad:
                events.append({'ts': t, 'type': 'anomaly', 'node': 'srv1',
                               'reasons': ['latency tell'],
                               'signals': {SIG_LATENCY_TELL: 6.0}})
            events.append({'ts': t + 0.5, 'type': 'node_status', 'nodes': {}})
        return score_run(events, window_cycles=window_cycles)[0].predicted

    def test_window_spanning_the_period_recovers_onoff(self):
        self.assertEqual(self._run(self.PERIOD * 2), ATTACK_ONOFF)

    def test_window_narrower_than_the_period_reads_as_sybil(self):
        self.assertEqual(self._run(self.PERIOD - 2), ATTACK_SYBIL)


class TestMatrixAndMetrics(unittest.TestCase):
    def setUp(self):
        self.results = score_run(_build_recording())

    def test_confusion_matrix_is_all_diagonal_when_every_call_is_right(self):
        matrix = confusion_matrix(self.results)
        for truth, row in matrix.items():
            expected = sum(1 for r in self.results if r.truth == truth)
            self.assertEqual(row[truth], expected, msg=truth)
            off_diagonal = sum(c for p, c in row.items() if p != truth)
            self.assertEqual(off_diagonal, 0, msg=truth)

    def test_per_class_metrics_include_the_none_class(self):
        # NO_ATTACK is scored like any other class on purpose: it is the class
        # that catches false accusations of honest nodes, which is this
        # project's historically dangerous failure mode.
        metrics = per_class_metrics(self.results)
        self.assertIn(NO_ATTACK, metrics)
        self.assertEqual(metrics[NO_ATTACK]['support'], 2.0)

    def test_a_misclassification_shows_up_off_diagonal(self):
        from evaluation.attack_report import SubjectResult

        results = [
            SubjectResult('srv1', 'node', ATTACK_SYBIL, ATTACK_BLACKHOLE),
            SubjectResult('srv2', 'node', ATTACK_BLACKHOLE, ATTACK_BLACKHOLE),
        ]
        matrix = confusion_matrix(results)
        self.assertEqual(matrix[ATTACK_SYBIL][ATTACK_BLACKHOLE], 1)
        self.assertEqual(matrix[ATTACK_SYBIL][ATTACK_SYBIL], 0)

        metrics = per_class_metrics(results)
        # sybil was never predicted: recall 0 on a support of 1.
        self.assertEqual(metrics[ATTACK_SYBIL]['recall'], 0.0)
        # blackhole was predicted twice and right once: precision 0.5.
        self.assertEqual(metrics[ATTACK_BLACKHOLE]['precision'], 0.5)
        self.assertEqual(metrics[ATTACK_BLACKHOLE]['recall'], 1.0)

    def test_report_renders(self):
        text = format_report(self.results)
        self.assertIn('CONFUSION MATRIX', text)
        self.assertIn('Overall accuracy', text)
        self.assertIn('UPPER BOUND', text)
        self.assertIn('Honest subjects wrongly labelled', text)

    def test_csv_round_trips(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'out.csv'
            write_csv(self.results, str(path))
            rows = path.read_text().strip().splitlines()
            self.assertEqual(len(rows), len(self.results) + 1)
            self.assertIn('detection_latency_s', rows[0])


class TestCli(unittest.TestCase):
    def test_main_scores_a_recording_on_disk(self):
        from evaluation.attack_report import main

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'events.jsonl'
            with path.open('w') as f:
                for e in _build_recording():
                    f.write(json.dumps(e) + '\n')
            self.assertEqual(main([str(path)]), 0)

    def test_main_refuses_a_recording_with_no_ground_truth(self):
        from evaluation.attack_report import main

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'events.jsonl'
            path.write_text(json.dumps({'ts': T0, 'type': 'route'}) + '\n')
            self.assertEqual(main([str(path)]), 1)


if __name__ == '__main__':
    unittest.main()


class TestTopologyGroundTruthPlumbing(unittest.TestCase):
    """config -> the `topology` event -> ground_truth(), end to end.

    The scorer is only as honest as the ground truth it reads, and that ground
    truth is assembled in trust_balancer.topology_graph() from four separate
    config lists. This pins the whole path rather than each half, because the
    failure that matters is the two halves disagreeing -- an attack configured
    but not surfaced scores as a silent miss, which flatters the detector.
    """

    def _graph(self, sim_extra=None, security_extra=None):
        import os_ken  # noqa: F401  (skip cleanly where the stack is absent)

        from controller.trust_balancer import TrustBalancerApp
        from controller.trust_state import TrustState

        cfg = {
            'simulation': {
                'num_edge_nodes': 3,
                'num_iot_devices': 4,
                'malicious_edge_nodes': [
                    {'node': 'srv1', 'attack': 'sybil', 'start_s': 12.0},
                    {'node': 'srv2', 'attack': 'drop', 'start_s': 30.0},
                ],
                **(sim_extra or {}),
            },
            'security': dict(security_extra or {}),
        }

        class FakeApp:
            def __init__(self):
                self.cfg = cfg
                self.state = TrustState(node_ids=['srv1', 'srv2', 'srv3'])
                self.vip_ip = '10.0.99.1'
                self.vip_port = 9000

        return TrustBalancerApp.topology_graph(FakeApp())

    def setUp(self):
        try:
            import os_ken  # noqa: F401
        except ImportError:
            self.skipTest('os-ken not installed')

    def test_edge_node_attacks_and_onsets_reach_the_scorer(self):
        events = [{'ts': T0, 'type': 'topology', 'graph': self._graph()}]
        truth = ground_truth(events)
        self.assertEqual(truth['srv1'], ('node', ATTACK_SYBIL))
        self.assertEqual(truth['srv2'], ('node', ATTACK_BLACKHOLE))
        self.assertEqual(truth['srv3'], ('node', NO_ATTACK))
        self.assertEqual(onset_times(events)['srv2'], 30.0)

    def test_iot_side_attacks_reach_the_scorer(self):
        # Without these, two of the six attacks would have no ground-truth row
        # at all and would vanish from the confusion matrix rather than being
        # scored.
        graph = self._graph(
            sim_extra={
                'malicious_flood_devices': [{'device': 'iot1', 'start_s': 8.0}],
                'malicious_spoof_devices': [
                    {'device': 'iot2', 'target': 'iot3', 'start_s': 4.0},
                ],
            },
            security_extra={'malicious_iot_devices': ['iot4']},
        )
        events = [{'ts': T0, 'type': 'topology', 'graph': graph}]
        truth = ground_truth(events)
        self.assertEqual(truth['iot1'], ('client', ATTACK_FLOOD))
        self.assertEqual(truth['iot2'], ('client', ATTACK_SPOOF))
        self.assertEqual(truth['iot3'], ('client', NO_ATTACK))
        self.assertEqual(truth['iot4'], ('client', ATTACK_BAD_CREDENTIALS))
        self.assertEqual(onset_times(events)['iot1'], 8.0)

    def test_spoof_beats_flood_for_one_device_matching_topology_py(self):
        # simulation/topology.py gives spoof precedence when a device appears
        # in both lists (--malicious is a single choice). Ground truth must say
        # the same thing the agent was actually launched with.
        graph = self._graph(sim_extra={
            'malicious_flood_devices': [{'device': 'iot1'}],
            'malicious_spoof_devices': [{'device': 'iot1', 'target': 'iot2'}],
        })
        truth = ground_truth([{'ts': T0, 'type': 'topology', 'graph': graph}])
        self.assertEqual(truth['iot1'], ('client', ATTACK_SPOOF))

    def test_iot_ips_are_present_so_flood_evidence_can_be_folded(self):
        graph = self._graph(sim_extra={
            'malicious_flood_devices': [{'device': 'iot1'}],
        })
        alias = subject_aliases([{'ts': T0, 'type': 'topology', 'graph': graph}])
        self.assertIn('iot1', alias.values())


class TestShippedConfigsAreInternallyConsistent(unittest.TestCase):
    """The attack configs must not quietly contradict themselves.

    A device listed both as a spoofer and in security.malicious_iot_devices
    gets the WRONG key from topology.py, so it is refused for bad credentials
    and never gets far enough to attempt impersonation -- the run would then
    silently contain five attacks while the report still expects six, and the
    missing one would read as a detection failure rather than a config bug.
    """

    CONFIGS = ('config/params_trust_full.yaml', 'config/params_attacks_demo.yaml')

    def _cfgs(self):
        import yaml

        for path in self.CONFIGS:
            p = Path(path)
            if p.exists():
                with p.open() as f:
                    yield path, yaml.safe_load(f)

    def test_spoofers_and_flooders_are_not_also_wrong_key_devices(self):
        for path, cfg in self._cfgs():
            sim = cfg.get('simulation', {})
            bad_key = set(cfg.get('security', {}).get('malicious_iot_devices', []) or [])
            spoof = {m['device'] for m in sim.get('malicious_spoof_devices', []) or []}
            flood = {m['device'] for m in sim.get('malicious_flood_devices', []) or []}
            self.assertEqual(spoof & bad_key, set(), msg=f'{path}: spoofer needs the real key')
            self.assertEqual(flood & bad_key, set(), msg=f'{path}: flooder must be admitted')

    def test_every_named_device_and_node_exists_in_the_topology(self):
        for path, cfg in self._cfgs():
            sim = cfg.get('simulation', {})
            n_edge, n_iot = sim['num_edge_nodes'], sim['num_iot_devices']
            for m in sim.get('malicious_edge_nodes', []) or []:
                idx = int(m['node'].replace('srv', ''))
                self.assertLessEqual(idx, n_edge, msg=f'{path}: {m["node"]}')
            devices = [m['device'] for m in sim.get('malicious_spoof_devices', []) or []]
            devices += [m['device'] for m in sim.get('malicious_flood_devices', []) or []]
            devices += list(cfg.get('security', {}).get('malicious_iot_devices', []) or [])
            devices += [m['target'] for m in sim.get('malicious_spoof_devices', []) or []]
            for d in devices:
                self.assertLessEqual(int(d.replace('iot', '')), n_iot, msg=f'{path}: {d}')

    def test_configured_attacks_are_all_known_labels(self):
        for path, cfg in self._cfgs():
            for m in cfg.get('simulation', {}).get('malicious_edge_nodes', []) or []:
                self.assertIn(
                    m['attack'], GROUND_TRUTH_ALIASES,
                    msg=f'{path}: {m["attack"]} has no classifier label',
                )

    def test_configured_onoff_periods_clear_the_detectability_floor(self):
        from controller.attack_classifier import ONOFF_MIN_GOOD_PHASE_S

        for path, cfg in self._cfgs():
            for m in cfg.get('simulation', {}).get('malicious_edge_nodes', []) or []:
                if m['attack'] != 'onoff':
                    continue
                good = m.get('onoff_period_s', 20.0) * (1.0 - m.get('onoff_duty', 0.5))
                self.assertGreater(
                    good, ONOFF_MIN_GOOD_PHASE_S,
                    msg=f'{path}: {m["node"]} good phase {good}s would classify as sybil',
                )


class TestRealEventBusFormat(unittest.TestCase):
    """Pin the field names against what the REAL EventBus writes.

    This exists because the reports were first written against `event`/`t`
    while controller/event_bus.py records `type`/`ts`. Every hand-built test
    fixture agreed with the mistake, so the whole suite passed while the tools
    would have found precisely nothing in a real recording -- the worst kind of
    green. Reading a file the real bus produced is the only check that cannot
    make that mistake with it.
    """

    def _record(self, publish):
        from controller.event_bus import EventBus

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'events.jsonl'
            bus = EventBus(record_path=str(path))
            publish(bus)
            bus.close() if hasattr(bus, 'close') else None
            return [json.loads(line) for line in
                    path.read_text().strip().splitlines()]

    def test_ground_truth_reads_a_real_recording(self):
        graph = {'nodes': [
            {'id': 'srv1', 'kind': 'server', 'ip': '10.0.1.1',
             'attack': 'sybil', 'attack_start_s': 12.0},
            {'id': 'iot1', 'kind': 'iot', 'ip': '10.0.2.1',
             'attack': 'flood', 'attack_start_s': 5.0},
        ], 'links': []}
        events = self._record(lambda bus: bus.publish('topology', graph=graph))

        truth = ground_truth(events)
        self.assertEqual(truth['srv1'], ('node', ATTACK_SYBIL))
        self.assertEqual(truth['iot1'], ('client', ATTACK_FLOOD))
        self.assertEqual(onset_times(events)['srv1'], 12.0)
        self.assertEqual(subject_aliases(events), {'10.0.2.1': 'iot1'})

    def test_anomaly_and_node_status_rebuild_cycles_from_a_real_recording(self):
        def publish(bus):
            bus.publish('anomaly', node='srv1', reasons=['latency tell'],
                        signals={SIG_LATENCY_TELL: 6.0}, anomaly=0.9, gate=0.5)
            bus.publish('node_status', nodes={})
            bus.publish('node_status', nodes={})

        windows = node_cycles(self._record(publish), ['srv1'])
        self.assertEqual(len(windows['srv1']), 2)
        self.assertTrue(windows['srv1'][0].signals)
        self.assertEqual(windows['srv1'][1].signals, {})

    def test_client_evidence_reads_a_real_recording(self):
        def publish(bus):
            bus.publish('flood', client_ip='10.0.2.1', rate_hz=40.0, ratio=40.0)
            bus.publish('auth_denied', device_id='iot1', source_ip='10.0.2.2',
                        kind=AUTH_KIND_IP_PIN, reason='iot1 pinned elsewhere')

        obs = client_observations(self._record(publish))
        self.assertIn('10.0.2.1', obs)
        self.assertIn('10.0.2.2', obs)

    def test_availability_reads_a_real_recording(self):
        from evaluation.availability_report import compute

        graph = {'nodes': [
            {'id': 'srv1', 'kind': 'server', 'ip': '10.0.1.1',
             'attack': 'none', 'attack_start_s': 0.0},
        ], 'links': []}

        def publish(bus):
            bus.publish('topology', graph=graph)
            bus.publish('quarantine', node='srv1', trust=0.2, anomaly=0.9)
            bus.publish('recovered', node='srv1', trust=0.6, anomaly=0.0)

        report = compute(self._record(publish))
        self.assertEqual(len(report.nodes), 1)
        self.assertEqual(report.nodes[0].episodes, 1)
        self.assertEqual(report.nodes[0].recoveries, 1)


class TestSpoofIsBlamedOnTheAttackerNotTheVictim(unittest.TestCase):
    """Live run 7's defect, pinned.

    iot38 impersonated iot1. The defence worked -- the source-IP pin refused
    it -- but the denial was filed under the CLAIMED device_id, so the `spoof`
    label landed on iot1, the victim, and iot38 scored clean. A classifier that
    blames the impersonated party is worse than no classifier: it manufactures
    a false accusation out of a successful defence.
    """

    def _events(self):
        return [
            topology_event(
                [('srv1', 'none', 0.0)],
                [('iot1', 'none', 0.0), ('iot2', 'spoof', 2.0)],
            ),
            # iot2 (at 10.0.2.2) presents a correct response for iot1.
            {'ts': T0 + 3.0, 'type': 'auth_denied', 'device_id': 'iot1',
             'source_ip': '10.0.2.2', 'kind': AUTH_KIND_IP_PIN,
             'reason': 'iot1 is pinned to 10.0.2.1'},
        ]

    def test_the_spoofer_is_labelled(self):
        results = {r.subject: r for r in score_run(self._events())}
        self.assertEqual(results['iot2'].predicted, ATTACK_SPOOF)
        self.assertTrue(results['iot2'].correct)

    def test_the_victim_is_not_labelled(self):
        results = {r.subject: r for r in score_run(self._events())}
        self.assertEqual(results['iot1'].predicted, NO_ATTACK)
        self.assertTrue(results['iot1'].correct)
