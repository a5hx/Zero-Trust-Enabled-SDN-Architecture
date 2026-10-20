"""controller/switch_witness.py -- who is lying: server, switch or client.

A synthetic fleet shaped like the live one: 8 servers, 8 edge switches (dpid
2..9), 5 clients per switch. Each test lets one party lie and checks the
blame lands on it, and only on it."""

import random
from types import SimpleNamespace

import pytest

from controller.switch_witness import (
    AGREE_FAILED, AGREE_SERVED, CLIENT_FAIL_SERVED, CLIENT_OK_UNSERVED,
    SwitchLie, SwitchWitness, WitnessConfig, falsify, parse_switch_lies,
)

VIP = '10.0.99.1'
SERVED, NOREPLY = 598, 0


def _rules(node, idx, client, port, fwd_bytes, rev_bytes, prio=300):
    return [
        {'priority': prio, 'node': node, 'bytes': fwd_bytes,
         'match': f'eth_type=2048,ip_proto=6,ipv4_dst={VIP},ipv4_src={client},tcp_dst=9000,tcp_src={port}'},
        {'priority': prio, 'node': node, 'bytes': rev_bytes,
         'match': f'eth_type=2048,ip_proto=6,ipv4_dst={client},ipv4_src=10.0.1.{idx},tcp_dst={port},tcp_src=8000'},
    ]


def _fleet(seconds=60, dropper=None, hide_dpid=None, badmouth=(), cover=None, seed=1):
    """Drive a witness with one task per client every 2 s for `seconds`.

    dropper  -- server that never answers (client times out, switch sees no reply)
    hide_dpid -- switch that reports no reply bytes on every connection
    badmouth -- devices that report successes as timeouts
    cover    -- (dpid, node): switch reports a full reply for node's conns
    """
    rng = random.Random(seed)
    w = SwitchWitness(VIP, WitnessConfig(window_s=600))
    port = 30000
    t = 0.0
    while t < seconds:
        for sw in range(8):
            dpid = sw + 2
            for c in range(5):
                j = sw + 8 * c + 1                       # iot j sits behind s((j-1)%8+1)
                device, ip = f'iot{j}', f'10.0.0.{j}'
                idx = rng.randrange(1, 9)
                node = f'srv{idx}'
                port += 1
                served = node != dropper
                rev = SERVED if served else NOREPLY
                if dpid == hide_dpid:
                    rev = 0
                if cover and dpid == cover[0] and node == cover[1]:
                    rev = SERVED
                w.on_flow_stats(dpid, _rules(node, idx, ip, port, 548, rev), t)
                status = 'success' if served else 'timeout'
                if device in badmouth and status == 'success':
                    status = 'timeout'
                w.on_report(ip, port, node, device, status, True, t)
        t += 2.0
        w.tick(t)
    w.tick(t + 5.0)
    return w.verdicts()


def test_an_honest_fleet_blames_nobody():
    v = _fleet()
    assert (v['servers'], v['switches'], v['clients']) == ([], [], [])
    assert v['judged'] > 1000


def test_a_dropping_server_is_blamed_by_both_witnesses_agreeing():
    v = _fleet(dropper='srv6')
    assert v['servers'] == ['srv6'] and v['switches'] == [] and v['clients'] == []


def test_a_lying_switch_is_blamed_not_its_clients_nor_the_servers():
    v = _fleet(hide_dpid=4)
    assert v['switches'] == [4]
    assert v['clients'] == [] and v['servers'] == []


def test_badmouthing_clients_are_blamed_not_their_switches():
    v = _fleet(badmouth=('iot3', 'iot12'))
    assert v['clients'] == ['iot12', 'iot3']
    assert v['switches'] == [] and v['servers'] == []


def test_a_switch_covering_a_dropper_does_not_save_it():
    """Collusion through one switch: the dropper's connections behind it look
    served, but it is still seen failing through the other seven."""
    v = _fleet(dropper='srv6', cover=(4, 'srv6'))
    assert v['servers'] == ['srv6']
    assert v['switches'] == []


def test_resteered_connections_are_never_judged():
    w = SwitchWitness(VIP)
    w.on_flow_stats(3, _rules('srv1', 1, '10.0.0.1', 40001, 548, 0), 0.0)
    w.on_report('10.0.0.1', 40001, 'srv2', 'iot1', 'timeout', False, 0.1)
    assert w.tick(10.0) == [] and w.voided == 1


def test_judging_waits_for_the_counters_to_settle():
    w = SwitchWitness(VIP)
    w.on_flow_stats(3, _rules('srv1', 1, '10.0.0.1', 40001, 548, 598), 0.0)
    w.on_report('10.0.0.1', 40001, 'srv1', 'iot1', 'success', True, 0.5)
    assert w.tick(1.0) == []
    (j,) = w.tick(3.0)
    assert (j.pattern, j.dpid, j.node) == (AGREE_SERVED, 3, 'srv1')


@pytest.mark.parametrize('status,rev,pattern', [
    ('success', 598, AGREE_SERVED), ('timeout', 0, AGREE_FAILED),
    ('timeout', 598, CLIENT_FAIL_SERVED), ('success', 0, CLIENT_OK_UNSERVED),
    ('timeout', 132, AGREE_FAILED),      # a timed-out client's FIN gets ACKed: partial, not served
])
def test_patterns(status, rev, pattern):
    w = SwitchWitness(VIP)
    w.on_flow_stats(3, _rules('srv1', 1, '10.0.0.1', 40001, 548, rev), 0.0)
    w.on_report('10.0.0.1', 40001, 'srv1', 'iot1', status, True, 0.0)
    (j,) = w.tick(5.0)
    assert j.pattern == pattern


def test_the_ingress_is_the_switch_that_carried_the_request():
    """A re-steer installs the pair on every switch; only the client's own
    switch's forward rule carries bytes."""
    w = SwitchWitness(VIP)
    w.on_flow_stats(2, _rules('srv1', 1, '10.0.0.1', 40001, 0, 0), 0.0)
    w.on_flow_stats(5, _rules('srv1', 1, '10.0.0.1', 40001, 548, 598), 0.0)
    w.on_report('10.0.0.1', 40001, 'srv1', 'iot1', 'success', True, 0.0)
    (j,) = w.tick(5.0)
    assert j.dpid == 5


class TestEmulatedSwitch:
    def _stat(self, fwd, node_idx=3, client='10.0.0.7', nbytes=598, prio=300):
        match = ({'ipv4_dst': VIP, 'ipv4_src': client} if fwd
                 else {'ipv4_dst': client, 'ipv4_src': f'10.0.1.{node_idx}'})
        return SimpleNamespace(priority=prio, cookie=0x5A00000000000000 | node_idx,
                               match=SimpleNamespace(items=lambda m=match: m.items()),
                               byte_count=nbytes, packet_count=6)

    def _node(self, cookie):
        return f'srv{cookie & 0xFF}'

    def test_hide_zeroes_reverse_rules_only(self):
        fwd, rev = self._stat(True, nbytes=548), self._stat(False)
        falsify([fwd, rev], SwitchLie(3, 'hide'), VIP, self._node)
        assert (fwd.byte_count, rev.byte_count, rev.packet_count) == (548, 0, 0)

    def test_cover_fakes_a_reply_for_its_node_only(self):
        mine, other = self._stat(False, node_idx=6, nbytes=0), self._stat(False, node_idx=2, nbytes=0)
        falsify([mine, other], SwitchLie(3, 'cover', node='srv6'), VIP, self._node)
        assert mine.byte_count == 598 and other.byte_count == 0

    def test_config(self):
        cfg = {'simulation': {'malicious_switches': [
            {'dpid': 4, 'mode': 'hide', 'start_s': 60},
            {'dpid': 5, 'mode': 'cover', 'node': 'srv6'}]}}
        assert parse_switch_lies(cfg) == [SwitchLie(4, 'hide', 60.0), SwitchLie(5, 'cover', 0.0, 'srv6')]
        with pytest.raises(ValueError):
            parse_switch_lies({'simulation': {'malicious_switches': [{'dpid': 4, 'mode': 'cover'}]}})


def test_config_overrides():
    c = WitnessConfig.from_config({'witness': {'enabled': True, 'threshold': 0.3, 'min_judged': 20}})
    assert (c.threshold, c.min_judged, c.window_s) == (0.3, 20, 60.0)


class TestControllerWiring:
    @pytest.fixture()
    def app(self, tmp_path, monkeypatch):
        pytest.importorskip('os_ken')
        import yaml
        cfg = yaml.safe_load(open('config/params_trust_demo.yaml'))
        cfg['controller']['dashboard'] = {'enabled': False}
        cfg['controller']['witness'] = {'enabled': True}
        cfg['simulation']['malicious_switches'] = [{'dpid': 3, 'mode': 'hide', 'start_s': 0}]
        path = tmp_path / 'p.yaml'
        path.write_text(yaml.safe_dump(cfg))
        monkeypatch.setenv('ZTSDN_CONFIG', str(path))
        from controller.trust_balancer import TrustBalancerApp
        return TrustBalancerApp()

    def _ev(self, dpid, stats):
        return SimpleNamespace(msg=SimpleNamespace(datapath=SimpleNamespace(id=dpid), body=stats))

    def _stat(self, fwd, vip, nbytes):
        match = ({'ipv4_dst': vip, 'ipv4_src': '10.0.0.7', 'tcp_src': 41000} if fwd else
                 {'ipv4_dst': '10.0.0.7', 'ipv4_src': '10.0.1.2', 'tcp_dst': 41000})
        return SimpleNamespace(priority=300, cookie=0x5A00000000000002,
                               match=SimpleNamespace(items=lambda m=match: m.items()),
                               byte_count=nbytes, packet_count=6)

    def test_the_lying_switch_lies_to_the_witness(self, app):
        import time
        stats = [self._stat(True, app.vip_ip, 548), self._stat(False, app.vip_ip, 598)]
        app.flow_stats_reply_handler(self._ev(3, stats))
        app.witness.on_report('10.0.0.7', 41000, 'srv2', 'iot7', 'success', True, time.monotonic())
        (j,) = app.witness.tick(time.monotonic() + 5)
        assert j.dpid == 3 and j.pattern == CLIENT_OK_UNSERVED     # hidden reply

    def test_an_honest_switch_is_passed_through(self, app):
        import time
        stats = [self._stat(True, app.vip_ip, 548), self._stat(False, app.vip_ip, 598)]
        app.flow_stats_reply_handler(self._ev(4, stats))
        app.witness.on_report('10.0.0.7', 41000, 'srv2', 'iot7', 'success', True, time.monotonic())
        (j,) = app.witness.tick(time.monotonic() + 5)
        assert j.pattern == AGREE_SERVED

    def test_witness_is_off_by_default(self, tmp_path, monkeypatch):
        pytest.importorskip('os_ken')
        import yaml
        cfg = yaml.safe_load(open('config/params_trust_demo.yaml'))
        cfg['controller']['dashboard'] = {'enabled': False}
        path = tmp_path / 'p.yaml'
        path.write_text(yaml.safe_dump(cfg))
        monkeypatch.setenv('ZTSDN_CONFIG', str(path))
        from controller.trust_balancer import TrustBalancerApp
        assert TrustBalancerApp().witness is None


def test_the_live_scorer_separates_detections_from_false_accusations(tmp_path):
    import json
    from evaluation.witness_report import score
    t0 = 1000.0
    evs = [{'type': 'topology', 'ts': t0, 'graph': {'nodes': [
        {'kind': 'server', 'id': 'srv6', 'attack': 'drop', 'attack_start_s': 30.0},
        {'kind': 'server', 'id': 'srv2', 'attack': 'none'},
        {'kind': 'edge_switch', 'id': 's3', 'dpid': 4, 'attack': 'switch_hide', 'attack_start_s': 60.0},
        {'kind': 'edge_switch', 'id': 's5', 'dpid': 6, 'attack': 'switch_cover', 'cover_node': 'srv6'},
        {'kind': 'iot', 'id': 'iot3', 'attack': 'badmouth', 'attack_start_s': 30.0}]}},
        {'type': 'witness', 'ts': t0 + 40, 'servers': ['srv6'], 'switches': [], 'clients': []},
        {'type': 'witness', 'ts': t0 + 70, 'servers': ['srv6', 'srv2'], 'switches': [4], 'clients': []},
        {'type': 'witness', 'ts': t0 + 75, 'servers': [], 'switches': [4], 'clients': ['iot3']},
        {'type': 'witness', 'ts': t0 + 100, 'servers': [], 'switches': [], 'clients': []}]
    p = tmp_path / 'r01.jsonl'
    p.write_text(''.join(json.dumps(e) + '\n' for e in evs))
    r = score(str(p), 'wit')
    assert r.detect_s('server:srv6') == pytest.approx(10.0)
    assert r.detect_s('switch:4') == pytest.approx(10.0)
    assert r.detect_s('client:iot3') == pytest.approx(45.0)
    assert r.false_parties == ['server:srv2']
    assert r.blamed_s['server:srv2'] == pytest.approx(5.0)
    assert 'switch:6' in r.exempt
