"""Tests for the dashboard's HTTP surface (controller/northbound_api.py) and the
replay server (dashboard/replay.py).

The property worth guarding hardest here is that /api/topology matches the graph
simulation/topology.py actually builds. The dashboard draws packets moving along
those links; if the two ever disagree about which switch an IoT host hangs off,
the picture silently lies about the network -- which is the worst outcome for a
tool whose entire job is showing what really happened.
"""

import json
import threading
import time
import urllib.request

import pytest
import yaml

from controller.event_bus import EventBus
from controller.northbound_api import NorthboundAPI
from controller.trust_state import TrustState
from dashboard.replay import ReplayApp, load_events


CONFIG = 'config/params_trust_demo.yaml'


@pytest.fixture
def cfg():
    with open(CONFIG) as f:
        return yaml.safe_load(f)


# --------------------------------------------------------------------------- #
# /api/topology must agree with the real Mininet topology                      #
# --------------------------------------------------------------------------- #
def test_topology_graph_matches_mininet_attachment(cfg):
    """ZeroTrustTopo.build() attaches iot_j to edge switch (j-1) % n_edge. The
    dashboard graph must use the same rule or the drawing is wrong."""
    # This test needs Mininet's real Topo machinery: ZeroTrustTopo(cfg=...)
    # relies on mininet.topo.Topo.__init__ calling build(cfg), which populates
    # iot_to_edge. Where Mininet is not installed (e.g. the CI runner, which
    # only pip-installs os-ken), topology.py falls back to a stub Topo base and
    # this construction can't run -- skip rather than fail.
    pytest.importorskip('mininet')
    from simulation.topology import ZeroTrustTopo

    n_edge = cfg['simulation']['num_edge_nodes']
    n_iot = cfg['simulation']['num_iot_devices']

    # What Mininet will really build.
    topo = ZeroTrustTopo(cfg=cfg)
    real = topo.iot_to_edge                       # {'iot1': 1, 'iot2': 2, ...}

    # What the dashboard will draw. Rebuilt with the same formula that
    # TrustBalancerApp.topology_graph() uses, without needing os-ken.
    drawn = {f'iot{j}': (j - 1) % n_edge + 1 for j in range(1, n_iot + 1)}

    assert drawn == real, "dashboard graph disagrees with the Mininet topology"


def test_replay_recovers_topology_from_recording():
    events = [{
        'type': 'topology', 'ts': 1.0, 'seq': 1,
        'graph': {'nodes': [{'id': 's0'}], 'links': [], 'vip': '10.0.99.1:9000',
                  'weights': {}, 'thresholds': {}},
    }]
    app = ReplayApp(events)
    assert app.topology_graph()['vip'] == '10.0.99.1:9000'


def test_replay_reconstructs_topology_when_recording_has_no_topology_event():
    """Older recordings predate the `topology` event; they must still replay."""
    events = [
        {'type': 'node_status', 'ts': 1.0, 'seq': 1,
         'nodes': {'srv1': {}, 'srv2': {}}},
        {'type': 'route', 'ts': 2.0, 'seq': 2, 'client_ip': '10.0.0.3',
         'client_port': 40001, 'chosen': 'srv1'},
    ]
    graph = ReplayApp(events).topology_graph()
    ids = {n['id'] for n in graph['nodes']}

    assert {'srv1', 'srv2', 's0'} <= ids
    assert 'iot3' in ids


# --------------------------------------------------------------------------- #
# Live HTTP surface                                                            #
# --------------------------------------------------------------------------- #
class _FakeApp:
    """Minimal stand-in for TrustBalancerApp: the dashboard routes only ever use
    these three members."""

    def __init__(self):
        self.bus = EventBus(record_path=None)
        self.link_params = {}
        self._flows = [{
            'dpid': 2, 'table': 0, 'priority': 300, 'cookie': 0x5A00000000000001,
            'node': 'srv1', 'match': 'ipv4_dst=10.0.99.1,tcp_dst=9000',
            'actions': 'set ipv4_dst=10.0.1.1', 'packets': 42, 'bytes': 2688,
            'pps': 12.5, 'bps': 800.0, 'is_vip': True,
        }]

    def topology_graph(self):
        return {'nodes': [{'id': 's0', 'kind': 'core_switch'}], 'links': [],
                'vip': '10.0.99.1:9000', 'weights': {}, 'thresholds': {}}

    def flow_table(self):
        return self._flows

    def record_link_params(self, links):
        # Mirrors TrustBalancerApp.record_link_params' contract: store the
        # usable entries, skip the malformed ones, return how many were kept.
        kept = 0
        for lk in links:
            if not isinstance(lk, dict):
                continue
            a, b = lk.get('a'), lk.get('b')
            if not isinstance(a, str) or not isinstance(b, str) or a == b:
                continue
            if not any(isinstance(lk.get(k), (int, float))
                       and not isinstance(lk.get(k), bool)
                       for k in ('delay_ms', 'bw_mbps')):
                continue
            self.link_params[frozenset((a, b))] = lk
            kept += 1
        return kept

    def optimizer_status(self):
        return {
            'enabled': True,
            'active_weights': {'w1_trust': 0.70, 'w2_cpu': 0.20, 'w3_latency': 0.10},
            'arms': [
                {'arm': 0, 'weights': [0.50, 0.30, 0.20], 'count': 3,
                 'mean_reward': 0.61, 'active': False},
                {'arm': 1, 'weights': [0.70, 0.20, 0.10], 'count': 5,
                 'mean_reward': 0.82, 'active': True},
            ],
        }


@pytest.fixture
def server():
    app = _FakeApp()
    srv = NorthboundAPI(app=app, state=TrustState(node_ids=['srv1']),
                        host='127.0.0.1', port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv, app, f'http://127.0.0.1:{srv.server_address[1]}'
    srv.shutdown()
    srv.server_close()


def test_api_topology_is_served(server):
    _, _, base = server
    with urllib.request.urlopen(f'{base}/api/topology', timeout=3) as r:
        body = json.loads(r.read())
    assert body['vip'] == '10.0.99.1:9000'


def test_api_flows_exposes_live_counters(server):
    _, _, base = server
    with urllib.request.urlopen(f'{base}/api/flows', timeout=3) as r:
        flows = json.loads(r.read())['flows']

    assert len(flows) == 1
    assert flows[0]['pps'] == 12.5          # the number the animation is scaled by
    assert flows[0]['node'] == 'srv1'


def test_api_optimizer_reports_arm_stats(server):
    _, _, base = server
    with urllib.request.urlopen(f'{base}/api/optimizer', timeout=3) as r:
        body = json.loads(r.read())
    assert body['enabled'] is True
    assert body['active_weights']['w1_trust'] == 0.70
    active = [a for a in body['arms'] if a['active']]
    assert len(active) == 1 and active[0]['arm'] == 1


def test_dashboard_html_is_served(server):
    _, _, base = server
    with urllib.request.urlopen(f'{base}/', timeout=3) as r:
        assert r.headers['Content-Type'].startswith('text/html')
        assert b'<svg id="topo"' in r.read()


def test_existing_rest_endpoints_still_work(server):
    """The deck's original endpoints must be untouched by the dashboard routes."""
    _, _, base = server
    with urllib.request.urlopen(f'{base}/trust/score', timeout=3) as r:
        assert 'srv1' in json.loads(r.read())


def test_sse_stream_emits_framed_events(server):
    _, app, base = server

    req = urllib.request.urlopen(f'{base}/api/events', timeout=5)

    # The stream only carries what the controller publishes after (or shortly
    # before) the client attached -- publish from another thread so the read
    # below has something to see.
    def publish_soon():
        time.sleep(0.2)
        app.bus.publish('quarantine', node='srv3', trust=0.21, anomaly=0.87)

    threading.Thread(target=publish_soon, daemon=True).start()

    line = req.readline()
    while line in (b'\n', b': keepalive\n\n'):
        line = req.readline()

    assert line.startswith(b'data: '), f'not SSE-framed: {line!r}'
    event = json.loads(line[len(b'data: '):])
    assert event['type'] == 'quarantine'
    assert event['node'] == 'srv3'
    req.close()


def test_sse_backfills_history_to_a_late_subscriber(server):
    """A browser opened mid-run must not stare at an empty page until the next
    event happens to fire."""
    _, app, base = server
    app.bus.publish('switch_up', dpid=2)

    req = urllib.request.urlopen(f'{base}/api/events', timeout=5)
    line = req.readline()
    while not line.startswith(b'data: '):
        line = req.readline()

    assert json.loads(line[len(b'data: '):])['type'] == 'switch_up'
    req.close()


# --------------------------------------------------------------------------- #
# Recording round-trip                                                         #
# --------------------------------------------------------------------------- #
def test_recorded_run_reloads_as_replayable_events(tmp_path):
    path = tmp_path / 'events.jsonl'
    bus = EventBus(record_path=str(path))
    bus.publish('topology', graph={'nodes': [], 'links': []})
    bus.publish('route', client_ip='10.0.0.4', client_port=40001, chosen='srv2')
    bus.publish('quarantine', node='srv3', trust=0.2, anomaly=0.9)
    bus.close()

    events = load_events(path)
    assert [e['type'] for e in events] == ['topology', 'route', 'quarantine']


def test_load_events_survives_a_torn_final_line(tmp_path):
    """A run killed with Ctrl-C (the normal way this controller exits) can leave
    a half-written last line -- that must not make the whole recording
    unreplayable."""
    path = tmp_path / 'events.jsonl'
    path.write_text(
        '{"type": "route", "ts": 1.0, "seq": 1, "chosen": "srv1"}\n'
        '{"type": "quarantine", "ts": 2.0, "seq"\n'      # torn
    )
    events = load_events(path)
    assert [e['type'] for e in events] == ['route']


# --------------------------------------------------------------------------- #
# POST /topology/links -- the harness reporting what it actually built         #
# --------------------------------------------------------------------------- #
def _post(base, path, payload):
    req = urllib.request.Request(
        base + path, data=json.dumps(payload).encode(),
        headers={'Content-Type': 'application/json'}, method='POST',
    )
    with urllib.request.urlopen(req, timeout=3) as r:
        return r.status, json.loads(r.read())


def test_topology_links_accepts_the_harness_report(server):
    _, app, base = server
    status, body = _post(base, '/topology/links', {'links': [
        {'a': 's0', 'b': 's1', 'delay_ms': 5.0, 'bw_mbps': 1000.0},
        {'a': 'iot1', 'b': 's1', 'delay_ms': 7.0, 'bw_mbps': 10.0},
    ]})
    assert status == 200
    assert body['accepted'] == 2
    assert body['received'] == 2
    assert len(app.link_params) == 2


def test_topology_links_is_keyed_on_the_unordered_pair(server):
    """The harness reports a link in whatever order it called addLink();
    topology_graph() writes it in its own order. Keying on the ordered pair
    would silently fail to merge half the table."""
    _, app, base = server
    _post(base, '/topology/links', {'links': [
        {'a': 's1', 'b': 'srv1', 'delay_ms': 2.0, 'bw_mbps': 100.0},
    ]})
    assert frozenset(('srv1', 's1')) in app.link_params


def test_topology_links_skips_malformed_entries_without_failing(server):
    """The harness sends this best-effort during startup; one bad row must not
    be able to abort a run over a cosmetic annotation."""
    _, app, base = server
    status, body = _post(base, '/topology/links', {'links': [
        {'a': 's0', 'b': 's1', 'delay_ms': 5.0},   # good
        {'a': 's0'},                               # no b
        {'a': 's0', 'b': 's0', 'delay_ms': 1.0},   # self-loop
        {'a': 's0', 'b': 's2'},                    # no parameters at all
        'not-a-dict',
        {'a': 1, 'b': 2, 'delay_ms': 1.0},         # non-string endpoints
    ]})
    assert status == 200
    assert body['accepted'] == 1
    assert body['received'] == 6


def test_topology_links_rejects_a_non_list_body(server):
    _, _, base = server
    req = urllib.request.Request(
        base + '/topology/links', data=b'{"links": "s0-s1"}',
        headers={'Content-Type': 'application/json'}, method='POST',
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req, timeout=3)
    assert exc.value.code == 400


def test_topology_links_rejects_malformed_json(server):
    _, _, base = server
    req = urllib.request.Request(
        base + '/topology/links', data=b'{not json',
        headers={'Content-Type': 'application/json'}, method='POST',
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req, timeout=3)
    assert exc.value.code == 400


def test_the_real_controller_merges_link_params_into_its_graph(cfg):
    """End to end on the real TrustBalancerApp.topology_graph(), not the fake:
    a reported link must come back out of the graph carrying its parameters,
    and an unreported one must carry none at all -- not a zero."""
    from controller.trust_balancer import TrustBalancerApp

    class _Bare:
        # Borrow the real methods so this exercises the shipping code, not a
        # copy of it. Everything else the two touch is plain state.
        topology_graph = TrustBalancerApp.topology_graph
        record_link_params = TrustBalancerApp.record_link_params
        _warn_on_link_drift = TrustBalancerApp._warn_on_link_drift
        dashboard_enabled = False

    bare = _Bare()
    bare.cfg = cfg
    bare._link_params = {}
    bare.vip_ip, bare.vip_port = '10.0.99.1', 9000

    class _W:
        w1_trust, w2_cpu, w3_latency = 0.5, 0.3, 0.2

    class _S:
        edge_weights = _W()
        isolation_threshold, anomaly_gate = 0.3, 0.5
        selection_strategy, d_choices, epsilon = 'p2c', 2, 0.05

    bare.state = _S()

    accepted = bare.record_link_params([
        {'a': 's0', 'b': 's1', 'delay_ms': 5.0, 'bw_mbps': 1000.0},
    ])
    assert accepted == 1

    graph = bare.topology_graph()
    by_pair = {frozenset((lk['a'], lk['b'])): lk for lk in graph['links']}
    assert by_pair[frozenset(('s0', 's1'))]['delay_ms'] == 5.0
    # An unreported link carries no delay_ms key at all: "not measured" and
    # "zero delay" are different claims.
    assert 'delay_ms' not in by_pair[frozenset(('s1', 'srv1'))]


def test_replay_prefers_the_enriched_topology_links_graph():
    """GET /api/topology must return the same enriched graph on replay as it
    does live, so the Node structure panel is populated the moment the page
    loads rather than staying blank until the recorded event streams past."""
    events = [
        {'type': 'topology', 'ts': 1.0, 'seq': 1, 'graph': {
            'nodes': [{'id': 's0', 'kind': 'core_switch'}],
            'links': [{'a': 's0', 'b': 's1'}],
            'vip': '10.0.99.1:9000', 'weights': {}, 'thresholds': {}}},
        {'type': 'topology_links', 'ts': 2.0, 'seq': 2, 'graph': {
            'nodes': [{'id': 's0', 'kind': 'core_switch'}],
            'links': [{'a': 's0', 'b': 's1', 'delay_ms': 5.0, 'bw_mbps': 1000.0}],
            'vip': '10.0.99.1:9000', 'weights': {}, 'thresholds': {}}},
    ]
    graph = ReplayApp(events).topology_graph()
    assert graph['links'][0]['delay_ms'] == 5.0


def test_replay_still_works_on_a_recording_with_no_link_report():
    # Older recordings, and live runs where the harness POST never landed.
    events = [{'type': 'topology', 'ts': 1.0, 'seq': 1, 'graph': {
        'nodes': [{'id': 's0', 'kind': 'core_switch'}], 'links': [],
        'vip': '10.0.99.1:9000', 'weights': {}, 'thresholds': {}}}]
    assert ReplayApp(events).topology_graph()['nodes'][0]['id'] == 's0'
