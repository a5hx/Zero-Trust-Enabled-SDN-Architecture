"""The dashboard against the events the controller actually publishes.

Three failure shapes have blanked parts of this page before, and none of them
is visible to a test that greps the whole file for a name
(memory: dashboard-js-has-no-build-step):

  * a syntax error anywhere in the script, which blanks EVERY panel;
  * a dispatch case dropped from `handle()`, which blanks ONE panel while its
    render function still sits there, defined and never called;
  * a new event type the controller starts publishing that the page never
    learns about -- 11 of 27 types were in that state before this file.

So: the published types are derived from the controller's source by AST (the
same approach as base_model/tests/test_baseline_controller.py), every one must
be dispatched or logged or be on an allow-list with a reason; every function
the script defines must have a call site; the script must parse; and real and
synthetic event streams must run through the page's own `handle()` without
throwing and with the new panels drawing what the events said.
"""

import ast
import re
import unittest
from pathlib import Path

from tests.dashboard_js import (HTML, load_jsonl, run_events, script_source,
                                syntax_check)

# Source trees whose `bus.publish('<type>', ...)` calls reach a dashboard.
# dashboard/ itself is excluded: replay.py re-publishes recorded types
# dynamically and generate_demo_recording.py emits a subset of the real ones.
PUBLISHER_ROOTS = ('controller', 'base_model', 'blockchain', 'security', 'simulation')

# Types the page deliberately neither dispatches nor logs, each with a reason.
NOT_SHOWN = {
    # wsl_gui/'s packet-capture integration, not part of the controller and
    # not wired into it; listed so that wiring it in is a deliberate act.
    'packet_in': 'wsl_gui packet capture, not published by the controller',
    # controller/auditor.py publishes on its OWN bus, recorded to its own file
    # (controller.auditor.record_path); none of it reaches the primary's
    # /api/events. The dashboard reads the auditor live via /auditor/status.
    'auditor_start': "the auditor's own recording, not the primary's bus",
    'auditor_role': "the auditor's own recording, not the primary's bus",
    'auditor_verdict': "the auditor's own recording, not the primary's bus",
}


def published_types():
    types = {}
    for root in PUBLISHER_ROOTS + ('wsl_gui',):
        for path in Path(root).rglob('*.py'):
            if 'tests' in path.parts:
                continue
            try:
                tree = ast.parse(path.read_text())
            except SyntaxError:                  # pragma: no cover
                continue
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and node.args
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr == 'publish'):
                    continue
                first = node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    types.setdefault(first.value, f'{path}:{node.lineno}')
    return types


def _body(src, start, end):
    return src[src.index(start):src.index(end)]


def handle_body():
    src = HTML.read_text()
    return _body(src, 'function handle(ev) {',
                 '// ------------------------------------------------------- time series ----')


def log_body():
    src = HTML.read_text()
    return _body(src, 'function log(ev) {', 'const ROUTINE_TYPES')


def cases(body):
    return set(re.findall(r"case '([a-z_]+)':", body))


class TestEveryPublishedTypeIsHandled(unittest.TestCase):

    def test_the_scan_finds_the_controllers_events(self):
        """Guard the guard: an AST scan that silently found nothing would pass
        every assertion below."""
        t = published_types()
        for expected in ('route', 'quarantine', 'witness', 'attestation', 'block',
                         'client_throttled', 'ledger_rejected', 'auth_denied'):
            self.assertIn(expected, t)
        self.assertGreaterEqual(len(t), 27)

    def test_every_type_is_dispatched_logged_or_allow_listed(self):
        handled = cases(handle_body()) | cases(log_body())
        missing = {t: where for t, where in published_types().items()
                   if t not in handled and t not in NOT_SHOWN}
        self.assertEqual(missing, {}, 'event types the dashboard ignores '
                         '(add a case to handle() or log(), or allow-list with a reason)')

    def test_the_allow_list_has_no_stale_entries(self):
        published = published_types()
        handled = cases(handle_body()) | cases(log_body())
        for t in NOT_SHOWN:
            self.assertIn(t, published, f'{t} is allow-listed but nothing publishes it')
            self.assertNotIn(t, handled, f'{t} is allow-listed but is handled now')

    def test_the_new_panels_are_fed_from_handle(self):
        h = handle_body()
        for call in ('witnessIngest(ev)', 'securityIngest(ev)', 'scheduleSecurityRender()',
                     'resetForTopology(ev.graph, ev.ts)'):
            self.assertIn(call, h)
        for t in ('topology', 'witness', 'witness_hold', 'witness_trial', 'attestation',
                  'auth_denied', 'identity_unclaimed', 'classification', 'flood',
                  'client_throttled', 'ledger_rejected', 'route_ignored', 'recovered'):
            self.assertIn(f"case '{t}':", h)

    def test_recovered_clears_the_quarantine(self):
        """Before this, only node_status cleared it: a recovered node stayed
        drawn as quarantined until the next status poll."""
        h = handle_body()
        rec = h[h.index("case 'recovered':"):]
        rec = rec[:rec.index('break;')]
        self.assertIn('S.quarantined.delete(ev.node)', rec)


class TestScriptIntegrity(unittest.TestCase):

    def test_the_script_parses(self):
        proc = syntax_check()
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_every_function_has_a_call_site(self):
        js = script_source()
        names = re.findall(r'(?:^|\n)\s*(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(', js)
        self.assertGreater(len(names), 50)
        orphans = []
        for n in names:
            refs = len(re.findall(rf'(?<![\w$.]){re.escape(n)}\b', js))
            defs = len(re.findall(rf'function\s+{re.escape(n)}\s*\(', js))
            if refs - defs < 1:
                orphans.append(n)
        self.assertEqual(orphans, [], 'defined but never called')

    def test_dead_rule_highlight_state_is_gone(self):
        js = script_source()
        self.assertNotIn('recentInstall', js)
        self.assertNotIn('recentDelete', js)


# --------------------------------------------------------------------------- #
# Executing the page                                                           #
# --------------------------------------------------------------------------- #
T0 = 1_800_000_000.0


def _topology():
    nodes = [{'id': 's0', 'kind': 'core_switch', 'dpid': 1, 'label': 's0'}]
    links = []
    for i in range(1, 5):
        nodes.append({'id': f's{i}', 'kind': 'edge_switch', 'dpid': i + 1, 'label': f's{i}'})
        nodes.append({'id': f'srv{i}', 'kind': 'server', 'label': f'srv{i}',
                      'attack': 'none', 'attack_start_s': 0.0})
        links += [{'a': f's{i}', 'b': f'srv{i}', 'kind': 'server_link'},
                  {'a': 's0', 'b': f's{i}', 'kind': 'core_link'}]
    for j in range(1, 9):
        nodes.append({'id': f'iot{j}', 'kind': 'iot', 'label': f'iot{j}',
                      'ip': f'10.0.0.{j}', 'attack': 'none', 'attack_start_s': 0.0})
        links.append({'a': f'iot{j}', 'b': f's{(j - 1) % 4 + 1}', 'kind': 'iot_link'})
    return {'nodes': nodes, 'links': links, 'vip': '10.0.99.1:9000',
            'weights': {'w1_trust': 0.5, 'w2_cpu': 0.3, 'w3_latency': 0.2},
            'thresholds': {'isolation': 0.3, 'anomaly_gate': 0.5}}


def _status(**over):
    base = {'trust': 0.8, 'claimed_cpu': 0.3, 'observed_load': 0.3, 'inflight': 0,
            'latency_ms': 30.0, 'anomaly': 0.0, 'quarantined': False, 'probation': False,
            'admitted': True}
    out = {f'srv{i}': dict(base) for i in range(1, 5)}
    for node, fields in over.items():
        out[node].update(fields)
    return out


def synthetic_stream():
    """One of every event type the new panels consume, in a plausible order.

    Payload shapes are copied from the publish sites (controller/
    trust_balancer.py, flow_monitor.py, northbound_api.py), not invented.
    """
    t = T0
    evs = []

    def ev(type_, dt=0.5, **f):
        nonlocal t
        t += dt
        evs.append({'type': type_, 'ts': t, **f})

    ev('topology', graph=_topology())
    ev('switch_up', dpid=2)
    ev('node_status', nodes=_status())
    ev('attestation', node='srv1', verdict='attested', detail='', measurement='ab' * 8,
       mismatched=[], verify_ms=2.1)
    ev('attestation', node='srv2', verdict='not_in_allowlist',
       detail="differs in ['simulation/node_agent.py']", measurement='cd' * 8,
       mismatched=['simulation/node_agent.py'], verify_ms=2.4)
    ev('attestation', node='srv2', verdict='not_in_allowlist', detail='',
       measurement='cd' * 8, mismatched=['simulation/node_agent.py'], verify_ms=2.0)
    ev('auth_denied', device_id='iot8', source_ip='10.0.0.8', kind='bad_response',
       reason='Bad auth response from iot8')
    ev('auth_denied', device_id='iot1', source_ip='10.0.0.7', kind='ip_pin',
       reason='iot1 is pinned to 10.0.0.1')
    ev('classification', subject='10.0.0.7', kind='client', attack_type='spoof',
       confidence=1.0, rationale='ip_pin denial', evidence_cycles=1, first_flagged_t=t)
    ev('identity_unclaimed', dt=40, devices=['iot7', 'iot8'],
       expected_ips={'iot7': '10.0.0.7', 'iot8': '10.0.0.8'}, after_s=45.0)
    ev('witness', servers=[], switches=[], clients=[], server_rate={}, switch_rate={},
       client_rate={}, judged=0, voided=0, unseen=0)
    ev('flood', client_ip='10.0.0.6', rate_hz=4.0, ratio=8.0, expected_rate_hz=0.5)
    ev('client_throttled', dt=0, client_ip='10.0.0.6', mode='meter', mode_applied='meter',
       rate_pps=1, duration_s=10, offence=1, until=t + 10)
    ev('anomaly', node='srv3', reasons=['switch witness: 100% failed'], signals={},
       anomaly=0.9, gate=0.5)
    ev('witness', servers=['srv3'], switches=[], clients=[],
       server_rate={'srv1': 0.0, 'srv3': 1.0}, switch_rate={'2': 0.0, '4': 0.1},
       client_rate={'iot3': 0.0}, judged=40, voided=1, unseen=0)
    ev('witness_hold', node='srv3', action='held')
    ev('quarantine', dt=0.1, node='srv3', trust=0.71, anomaly=0.9, isolation_threshold=0.3,
       anomaly_gate=0.5, anomaly_rail_enforced=True)
    ev('quarantine', dt=0.1, node='srv4', trust=0.2, anomaly=0.1, isolation_threshold=0.3,
       anomaly_gate=0.5, anomaly_rail_enforced=True)
    ev('node_status', nodes=_status(srv3={'quarantined': True, 'witness_held': True},
                                    srv4={'quarantined': True, 'probation': True},
                                    srv2={'admitted': False}))
    ev('witness_trial', node='srv3', pattern='agree_failed', streak=0)
    ev('witness_trial', node='srv3', pattern='agree_served', streak=1)
    ev('route_ignored', client_ip='10.0.0.3', client_port=40000, tcp_flags=17, dpid=4,
       reason='not_syn')
    ev('ledger_rejected', replica='n2', node='srv1', reason='trust_after mismatch',
       update_ts=t, recorded_before=0.5, recorded_after=0.9, expected_before=0.5,
       expected_after=0.51)
    ev('recovered', dt=5, node='srv4', trust=0.4, anomaly=0.1, isolation_threshold=0.3,
       anomaly_gate=0.5, anomaly_rail_enforced=True)
    ev('arm', arm='baseline', strategy='p2c', observe_anomaly=True)
    ev('auth_admitted', device_id='iot2', source_ip='10.0.0.2', expected_ip='10.0.0.2',
       source_matches_identity=True, reclaimed_from=None, verified=False)
    ev('reroute', client_ip='10.0.0.3', client_port=40001, from_node='srv3',
       to_node='srv1', resteer_ms=4.2)
    return evs


class TestPanelsDrawFromEventsAlone(unittest.TestCase):
    """Replay mode: no endpoint is polled, so every row must come from events."""

    @classmethod
    def setUpClass(cls):
        cls.out = run_events(synthetic_stream())
        cls.h = cls.out['html']

    def test_no_event_throws(self):
        self.assertEqual(self.out['errors'], [])

    def test_witness_panel(self):
        w = self.h['witness']
        self.assertIn('server srv3', w)            # blamed
        self.assertIn('40</b> connections judged', w)
        self.assertIn('s1 0%', w)                   # dpid 2 drawn as s1
        self.assertIn('srv3</b>', w)                # held row
        self.assertIn('streak <b>1</b>', w)
        self.assertEqual(self.out['state']['held'], ['srv3'])

    def test_security_panel(self):
        sec = self.h['security']
        self.assertIn('not admitted', sec)
        self.assertIn('simulation/node_agent.py', sec)
        self.assertIn('right key, wrong source address (spoof)', sec)
        self.assertIn('wrong key (bad challenge response)', sec)
        self.assertIn('iot7, iot8', sec)            # roster audit
        self.assertIn('spoof', sec)                 # classification label
        self.assertIn('10.0.0.6', sec)              # flood / throttle
        self.assertIn('trust_after mismatch', sec)  # ledger_rejected
        self.assertIn('admitted without verification', sec)

    def test_trust_rows_carry_the_new_badges(self):
        tr = self.h['trust']
        self.assertIn('held by witness', tr)
        self.assertIn('probation', tr)
        self.assertIn('not admitted', tr)
        self.assertIn('QUARANTINED · witness', tr)

    def test_quarantine_rail_and_recovery(self):
        st = self.out['state']
        self.assertEqual(st['quarantined'], ['srv3'])          # srv4 recovered
        self.assertEqual(st['qRail'], {'srv3': 'witness'})

    def test_the_header_and_log_counters(self):
        self.assertIn('throttled', self.h['throttledPill'])
        self.assertIn('1 non-SYN', self.h['logNote'])
        joined = '\n'.join(self.out['log'])
        self.assertNotIn('route_ignored', joined)              # counted, never listed
        # A gate quarantine names the gate, not "trust 0.71 (< 0.3)".
        self.assertIn('Ā 0.9 ≥ gate 0.5', joined)
        self.assertNotIn('trust 0.71 &lt;', joined)

    def test_repeated_verdicts_are_logged_once(self):
        att = [l for l in self.out['log'] if 'srv2' in l and 'not_in_allowlist' in l]
        self.assertEqual(len(att), 1)

    def test_alerts_list_skips_routine_traffic(self):
        alerts = '\n'.join(self.out['alerts'])
        self.assertIn('witness_hold', alerts)
        self.assertIn('auth_denied', alerts)
        self.assertNotIn('auth_admitted', alerts)

    def test_replay_shows_no_ledger_backend_claim(self):
        self.assertIn('n/a in replay', self.h['ledgerCluster'])
        self.assertNotIn('Raft', self.h['ledgerCluster'])


class TestFeaturesThatAreOffSayso(unittest.TestCase):

    def test_off_is_not_drawn_as_clean(self):
        evs = [e for e in synthetic_stream()
               if e['type'] in ('topology', 'switch_up', 'arm')]
        # Push the run clock past the grace period with a plain status event.
        status = _status()
        for row in status.values():
            row.pop('admitted')
        evs.append({'type': 'node_status', 'ts': T0 + 60, 'nodes': status})
        out = run_events(evs)
        self.assertEqual(out['errors'], [])
        self.assertIn('not running in this run', out['html']['witness'])
        self.assertIn('Attestation is off in this run', out['html']['security'])


class TestLoopedReplayStartsClean(unittest.TestCase):

    def test_a_second_topology_event_forgets_the_first_pass(self):
        first = synthetic_stream()
        second = [dict(e, ts=e['ts'] + 1000) for e in first[:3]]
        out = run_events(first + second)
        self.assertEqual(out['errors'], [])
        st = out['state']
        self.assertEqual(st['quarantined'], [])
        self.assertEqual(st['held'], [])
        self.assertEqual(st['denials'], 0)


RECORDINGS = ('wh3_drop_hold', 'att_on_tampered', 'flood_on')


class TestRealRecordingsReplay(unittest.TestCase):
    """End to end over real runs, where they exist (data/runs/ is not in git)."""

    def _run(self, name):
        path = Path('data/runs') / name / 'r01.jsonl'
        if not path.exists():
            self.skipTest(f'{path} not present')
        out = run_events(load_jsonl(path))
        self.assertEqual(out['errors'], [])
        return out

    def test_witness_hold_run(self):
        out = self._run('wh3_drop_hold')
        self.assertIn('srv6', out['state']['held'])
        self.assertEqual(out['state']['qRail'].get('srv6'), 'witness')
        self.assertIn('Held by the witness', out['html']['witness'])

    def test_tampered_agent_run(self):
        out = self._run('att_on_tampered')
        self.assertIn('not admitted', out['html']['security'])
        self.assertIn('simulation/node_agent.py', out['html']['security'])

    def test_flood_and_spoof_run(self):
        out = self._run('flood_on')
        sec = out['html']['security']
        self.assertIn('right key, wrong source address (spoof)', sec)
        self.assertIn('10.0.0.37', sec)
        self.assertIn('throttled', out['html']['throttledPill'])


if __name__ == '__main__':
    unittest.main()
