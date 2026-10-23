"""The witness hold (controller.witness.act.hold): a server the switch witness
blames stays quarantined until the WITNESS sees it serve `passes` trial
connections in a row -- not until its verdict lapses, and not on the
controller's own task records, which may be the thing that is wrong."""

import pytest

from controller.switch_witness import (AGREE_FAILED, AGREE_SERVED, CLIENT_FAIL_SERVED,
                                       Judged, SwitchWitness, WitnessHold, parse_hold)
from controller.trust_state import TrustState


class Clock:
    def __init__(self):
        self.t = 100.0

    def __call__(self):
        return self.t


def _state(interval=10.0):
    clock = Clock()
    st = TrustState(node_ids=['srv1', 'srv2', 'srv3'], time_source=clock)
    st.witness_trial_interval_s = interval
    return st, clock


# --------------------------------------------------------------------------- #
# TrustState: holding and trials                                               #
# --------------------------------------------------------------------------- #
def test_a_held_server_gets_one_trial_per_interval_and_nothing_else():
    st, clock = _state()
    st._anomaly['srv3'] = 0.9                      # the gate holds it quarantined
    assert st.hold_for_witness('srv3') and not st.hold_for_witness('srv3')
    assert {st.choose_edge_node() for _ in range(50)} == {'srv1', 'srv2'}   # first trial one interval on
    clock.t += 10
    assert st.choose_edge_node_ex() == ('srv3', True)
    assert st.last_routing_decision()['witness_trial'] is True
    assert {st.choose_edge_node() for _ in range(50)} == {'srv1', 'srv2'}   # one per interval
    clock.t += 10
    assert st.choose_edge_node_ex() == ('srv3', True)
    assert st.snapshot()['srv3']['witness_held'] is True


def test_trials_ignore_the_gate_and_trust_but_not_admission():
    st, clock = _state()
    st._anomaly['srv3'] = 1.0
    st.hold_for_witness('srv3')
    st.set_admission(lambda n: n != 'srv3')
    clock.t += 30
    assert st.choose_edge_node_ex()[1] is False


def test_release_ends_the_trials():
    st, clock = _state()
    st._anomaly['srv3'] = 0.9
    st.hold_for_witness('srv3')
    assert st.release_from_witness('srv3') and not st.release_from_witness('srv3')
    clock.t += 30
    assert {st.choose_edge_node() for _ in range(50)} == {'srv1', 'srv2'}
    assert 'witness_held' not in st.snapshot()['srv3']


def test_no_hold_configured_no_trials():
    st, clock = _state(interval=None)
    st._witness_held['srv3'] = clock.t
    clock.t += 100
    assert st.choose_edge_node_ex()[1] is False


# --------------------------------------------------------------------------- #
# Config and the witness                                                       #
# --------------------------------------------------------------------------- #
def test_parse_hold():
    act = lambda **h: {'enabled': True, 'act': {'servers': True, **h}}
    assert parse_hold({'enabled': True}) is None
    assert parse_hold(act(hold=True)) == WitnessHold(10.0, 3)
    assert parse_hold(act(hold={'trial_interval_s': 5, 'passes': 2})) == WitnessHold(5.0, 2)
    with pytest.raises(ValueError):
        parse_hold({'enabled': True, 'act': {'clients': True, 'hold': True}})   # needs servers
    with pytest.raises(ValueError):
        parse_hold(act(hold={'every': 5}))
    with pytest.raises(ValueError):
        parse_hold(act(hold={'passes': 0}))


def test_forget_server_drops_only_that_servers_history():
    w = SwitchWitness('10.0.99.1')
    for i, node in enumerate(['srv3', 'srv1', 'srv3']):
        w._judged.append(Judged(float(i), node, 2, f'iot{i}', '10.0.0.1', AGREE_FAILED, str(i)))
    assert w.forget_server('srv3') == 2
    assert [j.node for j in w._judged] == ['srv1']


# --------------------------------------------------------------------------- #
# The controller: scoring trials, releasing, and what the gate sees            #
# --------------------------------------------------------------------------- #
class _Bus:
    def __init__(self):
        self.events = []

    def publish(self, kind, **kw):
        self.events.append((kind, kw))


def _app(passes=3):
    from controller.trust_balancer import TrustBalancerApp

    class App:
        _advance_witness_holds = TrustBalancerApp._advance_witness_holds
        _witness_gate_verdict = TrustBalancerApp._witness_gate_verdict

    app = App()
    app.state, _ = _state()
    app.bus = _Bus()
    app.witness = SwitchWitness('10.0.99.1')
    app._witness_hold = WitnessHold(10.0, passes)
    app._witness_trials = {}
    app._hold_streak = {}
    app._witness_verdict = None
    return app


def _trial(app, port, pattern, node='srv3', register=True):
    if register:
        app._witness_trials[('10.0.0.5', str(port))] = (node, 0.0)
    return Judged(1.0, node, 2, 'iot5', '10.0.0.5', pattern, str(port))


def test_released_after_passes_served_trials_in_a_row_and_forgotten():
    app = _app()
    app.state.hold_for_witness('srv3')
    app.witness._judged.append(Judged(0.0, 'srv3', 2, 'iot9', '10.0.0.9', AGREE_FAILED, '1'))
    app._advance_witness_holds([_trial(app, 10, AGREE_SERVED), _trial(app, 11, AGREE_SERVED)])
    assert app.state.witness_held() == ['srv3']
    app._advance_witness_holds([_trial(app, 12, AGREE_FAILED)])          # a failure resets
    app._advance_witness_holds([_trial(app, n, AGREE_SERVED) for n in (13, 14)])
    assert app.state.witness_held() == ['srv3']
    app._advance_witness_holds([_trial(app, 15, AGREE_SERVED)])
    assert app.state.witness_held() == []
    assert not [j for j in app.witness._judged if j.node == 'srv3']    # not re-blamed on old failures
    assert ('witness_hold', {'node': 'srv3', 'action': 'released', 'forgotten': 1}) in app.bus.events


def test_only_the_trials_themselves_count():
    app = _app(passes=1)
    app.state.hold_for_witness('srv3')
    # A served connection judged late from before the hold, and a client's
    # dispute, are not trials and must not release it.
    app._advance_witness_holds([_trial(app, 20, AGREE_SERVED, register=False),
                                _trial(app, 21, CLIENT_FAIL_SERVED)])
    assert app.state.witness_held() == ['srv3']


def test_the_gate_sees_held_servers_after_the_verdict_lapses():
    app = _app()
    app.state.hold_for_witness('srv3')
    app._witness_verdict = {'servers': [], 'server_rate': {}}
    assert app._witness_gate_verdict()['servers'] == ['srv3']
    app._witness_verdict = {'servers': ['srv1'], 'server_rate': {'srv1': 0.4}}
    v = app._witness_gate_verdict()
    assert v['servers'] == ['srv1', 'srv3'] and v['server_rate'] == {'srv1': 0.4, 'srv3': 1.0}
    app.state.release_from_witness('srv3')
    app._witness_verdict = None
    assert app._witness_gate_verdict() is None
