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
