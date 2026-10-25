"""evaluation/witness_act_report.py against a synthetic recording with known
answers."""

import json

from evaluation import witness_act_report as war


def _write(tmp_path, events):
    path = tmp_path / 'r01.jsonl'
    with open(path, 'w') as fh:
        for t, ev in events:
            fh.write(json.dumps({'ts': 1000.0 + t, **ev}) + '\n')
    return str(path)


def test_scores_server_and_client_actions(tmp_path):
    nodes = [{'id': 'srv1', 'kind': 'server', 'attack': 'none'},
             {'id': 'srv3', 'kind': 'server', 'attack': 'drop', 'attack_start_s': 60},
             {'id': 'iot3', 'kind': 'iot', 'attack': 'badmouth', 'attack_start_s': 30},
             {'id': 'iot4', 'kind': 'iot'}]
    ev = [(0, {'type': 'topology', 'graph': {'nodes': nodes}}),
          (40, {'type': 'node_status', 'nodes': {'srv1': {'trust': 0.42}, 'srv3': {'trust': 0.1}}}),
          (42, {'type': 'report', 'device': 'iot3', 'attribution': 'witness_discounted'}),
          (43, {'type': 'report', 'device': 'iot3', 'attribution': 'witness_discounted'}),
          (44, {'type': 'report', 'device': 'iot4', 'attribution': 'witness_discounted'}),
          (62, {'type': 'route', 'chosen': 'srv3'}),
          (65, {'type': 'route', 'chosen': 'srv3'}),
          (70, {'type': 'witness', 'servers': ['srv3'], 'switches': [], 'clients': []}),
          (71, {'type': 'anomaly', 'node': 'srv3', 'signals': {'witness_blame': 1.0}}),
          (71.5, {'type': 'quarantine', 'node': 'srv3'}),
          (100, {'type': 'recovered', 'node': 'srv3'}),
          (101, {'type': 'route', 'chosen': 'srv3'}),
          (160, {'type': 'route', 'chosen': 'srv1'})]
    r = war.score(_write(tmp_path, ev), 'x')
    assert r.acting and r.contained_s('srv3') == 11.5 and r.contained_by_witness('srv3')
    assert abs(r.quarantined_share('srv3') - 28.5 / 100.0) < 1e-9
    assert r.exposure('srv3') == 3
    assert r.discounted == {'iot3': 2, 'iot4': 1} and r.false_discounts == 1
    assert r.false_witness_actions == []
    assert r.trust_low == {'srv1': 0.42}
    assert r.witness.detect_s('server:srv3') == 10.0
    text = war.report({'x': [r]})
    assert '... with the witness signal  : 1/1' in text


def test_an_honest_server_hit_by_the_witness_signal_is_a_false_action(tmp_path):
    ev = [(0, {'type': 'topology', 'graph': {'nodes': [{'id': 'srv1', 'kind': 'server'}]}}),
          (5, {'type': 'anomaly', 'node': 'srv1', 'signals': {'witness_blame': 0.3}})]
    assert war.score(_write(tmp_path, ev)).false_witness_actions == ['srv1']


def test_scores_holds_releases_and_trials(tmp_path):
    nodes = [{'id': 'srv1', 'kind': 'server'},
             {'id': 'srv3', 'kind': 'server', 'attack': 'drop', 'attack_start_s': 60}]
    ev = [(0, {'type': 'topology', 'graph': {'nodes': nodes}}),
          (70, {'type': 'witness_hold', 'node': 'srv3', 'action': 'held'}),
          (80, {'type': 'witness_trial', 'node': 'srv3', 'pattern': 'agree_failed', 'streak': 0}),
          (90, {'type': 'witness_trial', 'node': 'srv3', 'pattern': 'agree_served', 'streak': 1}),
          (95, {'type': 'witness_hold', 'node': 'srv1', 'action': 'held'}),
          (99, {'type': 'witness_hold', 'node': 'srv1', 'action': 'released', 'forgotten': 4})]
    r = war.score(_write(tmp_path, ev), 'wh_x_hold')
    assert r.holds == {'srv3': [70.0], 'srv1': [95.0]} and r.releases == {'srv1': [99.0]}
    assert r.trials == {'srv3': ['agree_failed', 'agree_served']}
    assert r.false_holds == ['srv1']
    text = war.report({'wh_x_hold': [r]})
    assert 'trials routed / judged       : 0 / 2 (1 served)' in text
    assert 'honest servers held              : 1.0' in text


def test_scores_trial_tails_charged_to_another_server(tmp_path):
    nodes = [{'id': 'srv1', 'kind': 'server'},
             {'id': 'srv3', 'kind': 'server', 'attack': 'drop', 'attack_start_s': 60}]
    trial = {'type': 'route', 'client_ip': '10.0.0.20', 'client_port': 59628,
             'chosen': 'srv3', 'probation': True, 'witness_trial': True}
    ev = [(0, {'type': 'topology', 'graph': {'nodes': nodes}}),
          (70, {'type': 'witness_hold', 'node': 'srv3', 'action': 'held'}),
          (80, trial),
          (84.07, {**trial, 'chosen': 'srv1', 'probation': False, 'witness_trial': False}),
          (84.09, {'type': 'report', 'device': 'iot20', 'node': 'srv1', 'status': 'timeout'}),
          (90, {**trial, 'client_port': 40000}),
          (94.07, {'type': 'route_ignored', 'client_ip': '10.0.0.20', 'client_port': 40000,
                   'reason': 'not_syn'}),
          (94.09, {'type': 'report', 'device': 'iot20', 'node': 'srv3', 'status': 'timeout'}),
          (100, {'type': 'route', 'client_ip': '10.0.0.20', 'client_port': 59628, 'chosen': 'srv1'})]
    r = war.score(_write(tmp_path, ev), 'wh_x_hold')
    assert r.tails_rerouted == {'srv3': 1} and r.tails_charged == {'srv3': 1}
    assert r.routes_ignored == 1
    text = war.report({'wh_x_hold': [r]})
    assert 'trial tails re-routed / charged elsewhere: 1 / 1' in text
    assert 'non-SYN PacketIns not routed     : 1' in text
