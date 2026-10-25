"""Only a SYN opens a connection. A non-SYN PacketIn is the tail of a
connection whose rules have expired -- typically a trial's, whose hard_timeout
equals the client's task timeout, so the client's FIN on giving up arrives just
after its rules have gone. Routing it used to re-register the dead connection
on a fresh server, and the client's timeout report was then charged to that
honest server instead of the trial's (41 of 94 witness trials in the wh2 hold
arms, docs/predictions/withold2_2026-10-24_OUTCOME.md). Checked through the
real PacketIn path with packets built by the os-ken packet library."""

from pathlib import Path
from unittest import mock

import pytest
import yaml

pytest.importorskip('os_ken.ofproto.ofproto_v1_3')
from os_ken.lib.packet import ethernet, ether_types, ipv4, packet, tcp  # noqa: E402
from os_ken.ofproto import inet, ofproto_v1_3, ofproto_v1_3_parser  # noqa: E402

CLIENT_IP, CLIENT_PORT = '10.0.0.20', 59628


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
    a.bus = mock.Mock()
    return a


def _dp(dpid):
    dp = mock.Mock()
    dp.id = dpid
    dp.ofproto = ofproto_v1_3
    dp.ofproto_parser = ofproto_v1_3_parser
    return dp


def _packet_in(app, bits):
    pkt = packet.Packet()
    pkt.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_IP,
                                       src='00:00:00:00:00:14', dst='00:00:00:00:00:fe'))
    pkt.add_protocol(ipv4.ipv4(proto=inet.IPPROTO_TCP, src=CLIENT_IP, dst=app.vip_ip))
    pkt.add_protocol(tcp.tcp(src_port=CLIENT_PORT, dst_port=app.vip_port, bits=bits))
    pkt.serialize()
    msg = mock.Mock(data=pkt.data, buffer_id=ofproto_v1_3.OFP_NO_BUFFER)
    parsed = packet.Packet(pkt.data)
    return msg, parsed, parsed.get_protocols(ethernet.ethernet)[0]


def _deliver(app, bits):
    dp = app._datapaths[2]
    msg, pkt, eth = _packet_in(app, bits)
    app._handle_table_vip(dp, msg, pkt, eth, 1)
    return dp


def _published(app, kind):
    return [c.kwargs for c in app.bus.publish.call_args_list if c.args[0] == kind]


def test_a_syn_is_routed(app):
    dp = _deliver(app, tcp.TCP_SYN)
    assert (CLIENT_IP, CLIENT_PORT) in app.state._dispatches
    assert len(_published(app, 'route')) == 1
    assert dp.send_msg.called


@pytest.mark.parametrize('bits', [
    tcp.TCP_FIN | tcp.TCP_ACK, tcp.TCP_ACK, tcp.TCP_RST, tcp.TCP_SYN | tcp.TCP_ACK,
])
def test_the_tail_of_an_expired_trial_keeps_its_dispatch_and_its_report(app, bits):
    app.state.register_dispatch(CLIENT_IP, CLIENT_PORT, 'srv3')      # the trial
    dp = _deliver(app, bits)
    assert app.state._dispatches[(CLIENT_IP, CLIENT_PORT)].node_id == 'srv3'
    assert not _published(app, 'route')
    assert not dp.send_msg.called                                    # no rules, no packet-out
    assert _published(app, 'route_ignored')[0]['reason'] == 'not_syn'
    assert app.state._inflight['srv3'] == 1 == sum(app.state._inflight.values())
    assert app.state.complete_dispatch(CLIENT_IP, CLIENT_PORT).node_id == 'srv3'


def test_a_stray_tail_opens_no_dispatch(app):
    _deliver(app, tcp.TCP_FIN | tcp.TCP_ACK)
    assert not app.state._dispatches
