"""Letting the switch witness's verdicts act (controller.witness.act).

servers: a blamed server raises the anomaly gate's witness signal and is then
quarantined like any other gate verdict -- the case that matters is when the
controller's own task records are wrong (Phase 6's forged evidence), so the
signal must come from the witness and not from anything those records feed.
clients: a blamed client's reports are published but charged to no server.
"""

import pytest

from contracts.trust_update import TrustUpdate
from controller.attack_classifier import (ATTACK_FAMILIES, SIG_WITNESS, Observation,
                                          classify_node)
from controller.switch_witness import parse_act
from controller.trust_state import TrustState
from tests.test_flow_monitor import _make_monitor

HONEST = {'cpu_load': 0.0, 'latency_ms': 20, 'concurrency': 4}


# --------------------------------------------------------------------------- #
# Servers: the gate                                                            #
# --------------------------------------------------------------------------- #
def _monitor(verdict):
    state = TrustState(node_ids=['srv1', 'srv2'], anomaly_gate=0.5, anomaly_lambda=0.85)
    fm, quarantined = _make_monitor(state, {'srv1': HONEST, 'srv2': HONEST})
    events = []
    fm.bus = type('Bus', (), {'publish': lambda _s, k, **kw: events.append((k, kw))})()
    if verdict is not False:
        fm.witness_verdicts = lambda: verdict
    return state, fm, quarantined, events


def test_a_blamed_server_is_quarantined_through_the_gate():
    state, fm, quarantined, events = _monitor({'servers': ['srv1'], 'server_rate': {'srv1': 0.95}})
    fm._poll_once()
    assert state.get_anomaly('srv1') >= 0.5 and state.get_anomaly('srv2') == 0.0
    assert quarantined == ['srv1']
    (anomaly,) = [kw for k, kw in events if k == 'anomaly']
    assert anomaly['node'] == 'srv1' and anomaly['signals'] == {SIG_WITNESS: 0.95}


def test_the_signal_does_not_read_the_controllers_task_records():
    """Forged evidence (every outcome rewritten as a success) leaves the
    timeout tell blind; the witness signal must still fire."""
    state, fm, quarantined, _ = _monitor({'servers': ['srv1'], 'server_rate': {'srv1': 1.0}})
    for i in range(10):
        state.record_task_outcome(TrustUpdate(device_id='d', edge_node_id='srv1',
                                              task_status='success', latency_ms=20))
    assert state.recent_timeout_rate('srv1', min_samples=4) == 0.0
    fm._poll_once()
    assert quarantined == ['srv1']


@pytest.mark.parametrize('verdict', [False, None, {'servers': [], 'server_rate': {}}])
def test_observe_only_no_verdict_yet_or_nobody_blamed_changes_nothing(verdict):
    state, fm, quarantined, events = _monitor(verdict)
    fm._poll_once()
    assert quarantined == [] and state.get_anomaly('srv1') == 0.0
    assert not [k for k, _ in events if k == 'anomaly']


def test_a_server_the_witness_stops_blaming_recovers():
    verdict = {'servers': ['srv1'], 'server_rate': {'srv1': 1.0}}
    state, fm, quarantined, _ = _monitor(verdict)
    recovered = []
    fm.on_recover = recovered.append
    fm._poll_once()
    assert quarantined == ['srv1']
    verdict['servers'] = []
    for _ in range(10):
        fm._poll_once()
    assert recovered == ['srv1'] and not state.is_quarantined('srv1')


def test_witness_only_evidence_is_named_a_drop_attack():
    window = [Observation(t=float(i), signals={SIG_WITNESS: 1.0}) for i in range(6)]
    c = classify_node(window)
    assert c is not None and ATTACK_FAMILIES[c.attack_type] == ATTACK_FAMILIES['blackhole']


# --------------------------------------------------------------------------- #
# Clients: discounting                                                         #
# --------------------------------------------------------------------------- #
class _Bus:
    def __init__(self):
        self.events = []

    def publish(self, kind, **kw):
        self.events.append((kind, kw))


def _app(act_clients, blamed):
    from blockchain.commit_backend import LocalLedgerBackend, TimingCommitBackend
    from controller.trust_balancer import TrustBalancerApp

    class App:
        handle_client_report = TrustBalancerApp.handle_client_report

    app = App()
    app.state = TrustState(node_ids=['srv1'],
                           commit_backend=TimingCommitBackend(LocalLedgerBackend()))
    app._commit_backend = app.state.commit_backend
    app.bus = _Bus()
    app.witness = None
    app._witness_act_clients = act_clients
    app._witness_verdict = {'clients': blamed} if blamed is not None else None
    return app


def _report(app, device, port, status='timeout'):
    app.state.register_dispatch('10.0.0.3', port, 'srv1')
    return app.handle_client_report('10.0.0.3', port, device, status, 4000.0)


def test_a_blamed_clients_report_is_published_but_charged_to_nobody():
    app = _app(True, ['iot3'])
    before = app.state.trust_calc.get_score('srv1')
    assert _report(app, 'iot3', 50001) is None
    assert app.state.trust_calc.get_score('srv1') == before
    assert app.state._pending_updates == []
    (kind, ev), = [e for e in app.bus.events if e[0] == 'report']
    assert (ev['charged'], ev['attribution'], ev['status']) == (False, 'witness_discounted', 'timeout')
    assert app.state._inflight.get('srv1', 0) == 0          # the dispatch was still closed


@pytest.mark.parametrize('act,blamed,device', [
    (True, ['iot3'], 'iot4'),       # someone else is blamed
    (False, ['iot3'], 'iot3'),      # observe-only
    (True, None, 'iot3'),           # no verdict yet
])
def test_otherwise_the_report_is_charged(act, blamed, device):
    app = _app(act, blamed)
    before = app.state.trust_calc.get_score('srv1')
    assert _report(app, device, 50002) is not None
    assert app.state.trust_calc.get_score('srv1') < before


# --------------------------------------------------------------------------- #
# Configuration                                                                #
# --------------------------------------------------------------------------- #
def test_parse_act():
    assert parse_act(None) == (False, False)
    assert parse_act({'enabled': True}) == (False, False)
    assert parse_act({'enabled': True, 'act': {'servers': True}}) == (True, False)
    assert parse_act({'enabled': True, 'act': {'servers': True, 'clients': True}}) == (True, True)
    with pytest.raises(ValueError):
        parse_act({'enabled': True, 'act': {'switches': True}})
    with pytest.raises(ValueError):
        parse_act({'act': {'servers': True}})
