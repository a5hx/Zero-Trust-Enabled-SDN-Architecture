"""Task 7: from flood *detection* to flood *response*.

The policy (controller/flood_response.py) is pinned as a pure function, and
the OpenFlow it becomes is pinned against the real os-ken 1.3 parser with a
mocked datapath, the same way tests/test_quarantine_drop.py pins quarantine:
the asserted messages are exactly what a live switch would receive.
"""

from pathlib import Path
from unittest import mock

import pytest
import yaml

from controller.flood_response import FloodResponder, FloodResponseConfig


def _responder(mode='meter', expected=0.5, **kw):
    return FloodResponder(FloodResponseConfig(mode=mode, **kw), expected_rate_hz=expected)


class TestPolicy:
    def test_off_by_default_never_throttles(self) -> None:
        cfg = FloodResponseConfig.from_config({})
        assert cfg.mode == 'off'
        assert FloodResponder(cfg, 0.5).on_tripped('10.0.0.37', 0.0) is None

    def test_meter_rate_is_a_fair_share_of_an_honest_device(self) -> None:
        r = _responder(expected=0.5, rate_factor=2.0)
        t = r.on_tripped('10.0.0.37', 100.0)
        assert t.rate_pps == 1 and t.mode == 'meter'
        assert _responder(expected=3.0, rate_factor=2.0).rate_pps() == 6

    def test_no_second_throttle_while_one_is_active(self) -> None:
        r = _responder()
        first = r.on_tripped('10.0.0.37', 100.0)
        assert r.on_tripped('10.0.0.37', 105.0) is None
        assert r.is_throttled('10.0.0.37', first.until - 0.1)
        assert not r.is_throttled('10.0.0.37', first.until)

    def test_repeat_offenders_are_throttled_longer_up_to_the_cap(self) -> None:
        r = _responder(initial_s=10, max_s=60)
        now, durations = 0.0, []
        for _ in range(5):
            t = r.on_tripped('10.0.0.37', now)
            durations.append(t.duration_s)
            now = t.until + 1          # flood resumes right after expiry
        assert durations == [10, 20, 40, 60, 60]

    def test_a_long_quiet_spell_is_forgiven(self) -> None:
        r = _responder(initial_s=10, forgive_after_s=600)
        r.on_tripped('10.0.0.37', 0.0)
        assert r.on_tripped('10.0.0.37', 20.0).offence == 2
        assert r.on_tripped('10.0.0.37', 2000.0).offence == 1

    def test_clients_are_independent(self) -> None:
        r = _responder()
        r.on_tripped('10.0.0.37', 0.0)
        assert r.on_tripped('10.0.0.29', 1.0).offence == 1
        assert set(r.active(2.0)) == {'10.0.0.37', '10.0.0.29'}

    @pytest.mark.parametrize('block', [
        {'mode': 'nuke'}, {'mode': 'meter', 'initial_s': 0},
        {'mode': 'meter', 'initial_s': 50, 'max_s': 10}, {'mode': 'drop', 'rate_factor': 0},
    ])
    def test_bad_config_is_rejected(self, block) -> None:
        with pytest.raises(ValueError):
            FloodResponseConfig.from_config({'flood_response': block})


# --------------------------------------------------------------------------- #
ofp = pytest.importorskip('os_ken.ofproto.ofproto_v1_3')
from os_ken.ofproto import ofproto_v1_3, ofproto_v1_3_parser  # noqa: E402


@pytest.fixture()
def make_app(tmp_path, monkeypatch):
    def build(flood_response):
        cfg = yaml.safe_load(Path('config/params_trust_demo.yaml').read_text())
        cfg['controller']['dashboard'] = {'enabled': False}
        cfg['controller']['flood_response'] = flood_response
        path = tmp_path / 'params_test.yaml'
        path.write_text(yaml.safe_dump(cfg))
        monkeypatch.setenv('ZTSDN_CONFIG', str(path))
        from controller.trust_balancer import TrustBalancerApp
        return TrustBalancerApp()
    return build


def _dp(dpid=1, meters=True):
    dp = mock.Mock()
    dp.id = dpid
    dp.ofproto = ofproto_v1_3
    dp.ofproto_parser = ofproto_v1_3_parser
    return dp


def _flood(app, client='10.0.0.37', n=200):
    """Hammer the flood tell the way a flooding device's PacketIns would."""
    for _ in range(n):
        app._check_flood(client)


def _sent(dp):
    return [c.args[0] for c in dp.send_msg.call_args_list]


class TestOpenFlow:
    def test_off_installs_nothing(self, make_app) -> None:
        app = make_app({'mode': 'off'})
        dp = _dp()
        app._datapaths = {dp.id: dp}
        _flood(app)
        assert _sent(dp) == []

    def test_meter_mode_meters_new_connections_from_that_client_only(self, make_app) -> None:
        app = make_app({'mode': 'meter', 'rate_factor': 2.0})
        dp = _dp()
        app._datapaths = {dp.id: dp}
        app._meters_ok = {dp.id: True}
        _flood(app)

        meters = [m for m in _sent(dp) if isinstance(m, ofproto_v1_3_parser.OFPMeterMod)]
        flows = [m for m in _sent(dp) if isinstance(m, ofproto_v1_3_parser.OFPFlowMod)]
        assert len(meters) == 1 and len(flows) == 1      # once, not once per packet
        meter, flow = meters[0], flows[0]
        assert meter.flags == ofproto_v1_3.OFPMF_PKTPS
        assert meter.meter_id >= app.CLIENT_METER_BASE
        assert meter.bands[0].rate == app.flood_responder.rate_pps()

        assert dict(flow.match.items()) == {
            'eth_type': 0x0800, 'ip_proto': 6, 'ipv4_src': '10.0.0.37',
            'ipv4_dst': app.vip_ip, 'tcp_dst': app.vip_port,
        }
        assert app.PRIO_NEW_TASK < flow.priority == app.PRIO_CLIENT_THROTTLE < app.PRIO_CONNECTION
        assert flow.hard_timeout == 10
        kinds = [type(i).__name__ for i in flow.instructions]
        assert kinds == ['OFPInstructionMeter', 'OFPInstructionActions']
        assert flow.instructions[1].actions[0].port == ofproto_v1_3.OFPP_CONTROLLER
        # Not a VIP/server cookie: flow statistics must not attribute it to a server.
        from controller.flow_stats import FlowStatsPoller
        assert not FlowStatsPoller._is_vip_cookie(flow.cookie)

    def test_a_switch_without_meters_falls_back_to_drop(self, make_app) -> None:
        app = make_app({'mode': 'meter'})
        dp = _dp()
        app._datapaths = {dp.id: dp}
        app._meters_ok = {dp.id: False}
        _flood(app)
        flows = [m for m in _sent(dp) if isinstance(m, ofproto_v1_3_parser.OFPFlowMod)]
        assert not any(isinstance(m, ofproto_v1_3_parser.OFPMeterMod) for m in _sent(dp))
        assert len(flows) == 1 and flows[0].instructions == []   # empty = drop

    def test_drop_mode_installs_a_timed_drop(self, make_app) -> None:
        app = make_app({'mode': 'drop', 'initial_s': 15})
        dp = _dp()
        app._datapaths = {dp.id: dp}
        _flood(app)
        flows = [m for m in _sent(dp) if isinstance(m, ofproto_v1_3_parser.OFPFlowMod)]
        assert len(flows) == 1
        assert flows[0].instructions == [] and flows[0].hard_timeout == 15

    def test_an_honest_rate_is_never_throttled(self, make_app) -> None:
        app = make_app({'mode': 'drop'})
        dp = _dp()
        app._datapaths = {dp.id: dp}
        # TrustState's injectable clock: one request every 2 s, the configured
        # per-device rate, for 100 s.
        tick = {'t': 0.0}
        app.state._now = lambda: tick['t']
        for i in range(50):
            tick['t'] = i * 2.0
            app._check_flood('10.0.0.5')
        assert _sent(dp) == []

    def test_every_switch_gets_the_rule_and_a_bus_event_is_published(self, make_app) -> None:
        app = make_app({'mode': 'meter'})
        dps = [_dp(1), _dp(2)]
        app._datapaths = {d.id: d for d in dps}
        app._meters_ok = {1: True, 2: False}
        app.bus = mock.Mock()
        _flood(app)
        for d in dps:
            assert any(isinstance(m, ofproto_v1_3_parser.OFPFlowMod) for m in _sent(d))
        events = [c for c in app.bus.publish.call_args_list if c.args[0] == 'client_throttled']
        assert len(events) == 1
        assert events[0].kwargs['mode_applied'] == 'mixed'
        assert events[0].kwargs['client_ip'] == '10.0.0.37'


class TestThrottleConfig:
    def test_differs_from_the_full_config_only_in_flood_response_and_record_path(self) -> None:
        with open('config/params_trust_full.yaml') as fh:
            full = yaml.safe_load(fh)
        with open('config/params_trust_throttle.yaml') as fh:
            thr = yaml.safe_load(fh)
        block = thr['controller'].pop('flood_response')
        assert thr['controller']['dashboard'].pop('record_path') == 'data/events_throttle.jsonl'
        full['controller']['dashboard'].pop('record_path')
        assert thr == full
        assert FloodResponseConfig.from_config({'flood_response': block}).mode == 'meter'


class TestHeavyFloodArms:
    """The heavy-flood experiment's two arms must differ ONLY in whether the
    throttle acts, or a difference in honest service cannot be credited to it."""

    def _load(self, name):
        with open(f'config/params_{name}.yaml') as fh:
            return yaml.safe_load(fh)

    def test_arms_differ_only_in_flood_response_and_record_path(self) -> None:
        off, on = self._load('flood_off'), self._load('flood_on')
        assert on['controller'].pop('flood_response')['mode'] == 'meter'
        assert 'flood_response' not in off['controller']
        assert off['controller']['dashboard'].pop('record_path') == 'data/events_flood_off.jsonl'
        assert on['controller']['dashboard'].pop('record_path') == 'data/events_flood_on.jsonl'
        assert off == on

    def test_only_the_flood_is_heavier_than_the_shipped_config(self) -> None:
        full, off = self._load('trust_full'), self._load('flood_off')
        flood = off['simulation'].pop('malicious_flood_devices')
        full['simulation'].pop('malicious_flood_devices')
        off['controller']['dashboard'].pop('record_path')
        full['controller']['dashboard'].pop('record_path')
        assert off == full
        assert flood == [{'device': 'iot37', 'start_s': 60, 'concurrency': 12, 'interval_s': 0.1}]
