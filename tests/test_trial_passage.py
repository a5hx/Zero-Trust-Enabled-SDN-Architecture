"""A trial connection to a quarantined server must get past the quarantine's
drop rules on EVERY switch it crosses, not only on the client's ingress switch
where its rewrite rules live (docs/predictions/withold_2026-10-23_OUTCOME.md:
327 of 369 witness trials were black-holed before this). Checked with the real
OpenFlow 1.3 parser, on the FlowMods actually sent."""

from pathlib import Path
from unittest import mock

import pytest
import yaml

pytest.importorskip('os_ken.ofproto.ofproto_v1_3')
from os_ken.ofproto import ofproto_v1_3, ofproto_v1_3_parser  # noqa: E402


@pytest.fixture()
def app(tmp_path, monkeypatch):
    cfg = yaml.safe_load(Path('config/params_trust_demo.yaml').read_text())
    cfg['controller']['dashboard'] = {'enabled': False}
    path = tmp_path / 'params_test.yaml'
    path.write_text(yaml.safe_dump(cfg))
    monkeypatch.setenv('ZTSDN_CONFIG', str(path))
    from controller.trust_balancer import TrustBalancerApp
    a = TrustBalancerApp()
    a._datapaths = {i: _dp(i) for i in (1, 2, 3)}
    return a


def _dp(dpid):
    dp = mock.Mock()
    dp.id = dpid
    dp.ofproto = ofproto_v1_3
    dp.ofproto_parser = ofproto_v1_3_parser
    return dp


def _flows(dp):
    return [c.args[0] for c in dp.send_msg.call_args_list
            if isinstance(c.args[0], ofproto_v1_3_parser.OFPFlowMod)]


def _match(fm):
    return dict(fm.match.items())


def test_a_trial_opens_a_passage_on_every_switch(app):
    ingress = app._datapaths[2]
    app._install_vip_pair(ingress, '10.0.0.7', 41234, 'srv2', probation=True)
    s_ip = app.inventory.server_ip('srv2')
    for dpid, dp in app._datapaths.items():
        passage = [f for f in _flows(dp) if f.priority == app.PRIO_TRIAL_PASSAGE]
        assert len(passage) == 4, dpid
        assert {f.cookie for f in passage} == {app.TRIAL_PASSAGE_COOKIE_BASE | 2}
        assert all(f.hard_timeout == max(2, int(round(app.task_timeout_s))) for f in passage)
        ms = [_match(f) for f in passage]
        assert {'ipv4_src': '10.0.0.7', 'tcp_src': 41234, 'ipv4_dst': s_ip,
                'tcp_dst': app.node_port}.items() <= ms[0].items()
        assert {'ipv4_src': s_ip, 'ipv4_dst': '10.0.0.7', 'tcp_dst': 41234}.items() <= ms[1].items()
        assert {m.get('arp_spa') for m in ms[2:]} == {s_ip, '10.0.0.7'}
    rewrite = [f for f in _flows(ingress) if f.priority == app.PRIO_PROBATION]
    assert len(rewrite) == 2                                # the trial's own pair, ingress only
    assert not [f for d in (1, 3) for f in _flows(app._datapaths[d]) if f.priority == app.PRIO_PROBATION]


def test_the_passage_sits_between_the_drops_and_the_rewrite(app):
    assert app.PRIO_QUARANTINE_DROP < app.PRIO_TRIAL_PASSAGE < app.PRIO_PROBATION


def test_an_ordinary_connection_opens_no_passage(app):
    app._install_vip_pair(app._datapaths[2], '10.0.0.7', 41235, 'srv2', probation=False)
    assert not [f for dp in app._datapaths.values() for f in _flows(dp)
                if f.priority == app.PRIO_TRIAL_PASSAGE]


def test_passage_rules_are_not_read_as_vip_rules():
    from controller.flow_stats import FlowStatsPoller
    from controller.trust_balancer import TrustBalancerApp
    assert not FlowStatsPoller._is_vip_cookie(TrustBalancerApp.TRIAL_PASSAGE_COOKIE_BASE | 2)
