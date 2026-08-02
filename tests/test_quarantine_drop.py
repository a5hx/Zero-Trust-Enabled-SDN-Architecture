"""Quarantine must be containment, not just avoidance: _on_trust_collapse has
to delete the node's VIP rewrite rules AND install data-plane drop rules.

Runs against the real os-ken OpenFlow 1.3 parser with a mocked datapath, so
the asserted OFPFlowMods are exactly what a live switch would receive.
"""

from pathlib import Path
from unittest import mock

import pytest
import yaml
from os_ken.ofproto import ofproto_v1_3, ofproto_v1_3_parser

from simulation.addressing import CX_IP, srv_ip, srv_mac


@pytest.fixture()
def app(tmp_path, monkeypatch):
    # Copy the demo config but force the dashboard off: an enabled dashboard
    # constructs an EventBus, which opens record_path ('data/events.jsonl')
    # in 'w' mode -- a unit test must never truncate the demo recording.
    cfg = yaml.safe_load(Path('config/params_trust_demo.yaml').read_text())
    cfg['controller']['dashboard'] = {'enabled': False}
    cfg_path = tmp_path / 'params_test.yaml'
    cfg_path.write_text(yaml.safe_dump(cfg))
    monkeypatch.setenv('ZTSDN_CONFIG', str(cfg_path))

    from controller.trust_balancer import TrustBalancerApp
    return TrustBalancerApp()


def _fake_datapath(dpid: int = 1) -> mock.Mock:
    dp = mock.Mock()
    dp.id = dpid
    dp.ofproto = ofproto_v1_3
    dp.ofproto_parser = ofproto_v1_3_parser
    return dp


def test_quarantine_deletes_vip_rules_then_installs_drop_rules(app):
    dp = _fake_datapath()
    app._datapaths = {dp.id: dp}

    app._on_trust_collapse('srv3')

    mods = [c.args[0] for c in dp.send_msg.call_args_list]
    deletes = [m for m in mods if m.command == ofproto_v1_3.OFPFC_DELETE]
    adds = [m for m in mods if m.command == ofproto_v1_3.OFPFC_ADD]

    # One cookie-scoped delete removes every VIP rewrite rule for srv3.
    assert len(deletes) == 1
    assert deletes[0].cookie == app._cookie_for('srv3')
    assert deletes[0].table_id == app.TABLE_VIP

    # Two drop rules: srv3's MAC as source and as destination, above every
    # other TABLE_VIP priority, empty instruction set (== OpenFlow drop),
    # tagged with the node's cookie so they are identifiable/removable.
    drops = [m for m in adds if m.priority == app.PRIO_QUARANTINE_DROP]
    assert len(drops) == 2
    fields = {}
    for m in drops:
        assert m.priority > app.PRIO_ARP_PUNT
        assert m.table_id == app.TABLE_VIP
        assert m.instructions == []
        assert m.cookie == app._cookie_for('srv3')
        fields.update(dict(m.match.items()))
    assert fields == {'eth_src': srv_mac(3), 'eth_dst': srv_mac(3)}

    # ...but the controller's own health check is carved out above them, or Ā
    # stays pinned on '/status unreachable' and quarantine becomes a one-way
    # door. Two TCP directions plus the two ARP directions that keep the poll
    # working once cx's neighbour entry ages out.
    health = [m for m in adds if m.priority == app.PRIO_HEALTH_CHECK]
    assert len(health) == 4
    assert app.PRIO_HEALTH_CHECK > app.PRIO_QUARANTINE_DROP
    for m in health:
        assert m.table_id == app.TABLE_VIP
        assert m.instructions != [], 'carve-out must forward, not drop'
    tcp_hc = [dict(m.match.items()) for m in health if 'ip_proto' in dict(m.match.items())]
    assert {m['ipv4_src'] for m in tcp_hc} == {CX_IP, srv_ip(3)}
    assert all(
        m.get('tcp_dst') == app.node_port or m.get('tcp_src') == app.node_port
        for m in tcp_hc
    )


def test_recovery_removes_the_drop_rules(app):
    """is_quarantined() is derived live, but the drop rules are physical: if
    nothing deletes them on recovery the node stays black-holed forever."""
    dp = _fake_datapath()
    app._datapaths = {dp.id: dp}

    app._on_trust_collapse('srv3')
    dp.send_msg.reset_mock()

    app._on_trust_recovered('srv3')

    mods = [c.args[0] for c in dp.send_msg.call_args_list]
    deletes = [m for m in mods if m.command == ofproto_v1_3.OFPFC_DELETE]
    assert len(deletes) == 1
    assert deletes[0].cookie == app._cookie_for('srv3')
    assert deletes[0].cookie_mask == 0xFFFFFFFFFFFFFFFF
    assert deletes[0].table_id == app.TABLE_VIP
    # Nothing new installed -- recovery only removes.
    assert [m for m in mods if m.command == ofproto_v1_3.OFPFC_ADD] == []


def test_drop_rules_reach_every_switch(app):
    dps = [_fake_datapath(dpid=i) for i in (1, 2, 3)]
    app._datapaths = {dp.id: dp for dp in dps}

    app._on_trust_collapse('srv2')

    for dp in dps:
        mods = [c.args[0] for c in dp.send_msg.call_args_list]
        adds = [m for m in mods if m.command == ofproto_v1_3.OFPFC_ADD]
        drops = [m for m in adds if m.priority == app.PRIO_QUARANTINE_DROP]
        # No active dispatches -> re-dispatch adds nothing; only the 2 drops
        # plus the 4 health-check carve-outs that keep the node observable.
        assert len(drops) == 2, f'dpid {dp.id} missing drop rules'
        assert len([m for m in adds if m.priority == app.PRIO_HEALTH_CHECK]) == 4, (
            f'dpid {dp.id} missing health-check carve-out'
        )


def test_quarantine_redispatches_active_clients_to_next_best(app):
    dp = _fake_datapath()
    app._datapaths = {dp.id: dp}

    # A client is actively being served by srv3.
    app.state.register_dispatch('10.0.0.5', 5000, 'srv3')
    # Drive srv3 over the anomaly gate so it is genuinely quarantined in state
    # (in the live path poll_newly_quarantined only fires once this is true).
    # One raw-1.0 sample with lambda=0.85 lands well above the 0.5 gate.
    app.state.set_anomaly_raw('srv3', 1.0)
    assert app.state.is_quarantined('srv3')

    app._on_trust_collapse('srv3')

    # The re-dispatch re-selected a target, which must not be the dead node.
    target = app.state.last_routing_decision()['chosen']
    assert target is not None and target != 'srv3'

    # The client's dispatch now points at the target, inflight moved with it.
    assert app.state._dispatches[('10.0.0.5', 5000)].node_id == target

    # Fresh VIP rewrite rules (forward + reverse) were installed for the client,
    # tagged with the target's cookie at connection priority -- distinct from
    # srv3's drop rules.
    mods = [c.args[0] for c in dp.send_msg.call_args_list]
    vip_adds = [
        m for m in mods
        if m.command == ofproto_v1_3.OFPFC_ADD
        and m.priority == app.PRIO_CONNECTION
        and m.cookie == app._cookie_for(target)
    ]
    assert len(vip_adds) == 2, 'expected forward+reverse VIP rules to the target'


def test_probation_trial_flows_out_rank_the_quarantine_drops(app):
    """A probation trial exists to let one task reach a quarantined node so it
    can earn trust back. Installed at the ordinary PRIO_CONNECTION it would be
    black-holed by that node's own drop rules, every trial would read as a
    timeout, and probation would become a machine for confirming the verdict it
    is meant to re-test.
    """
    assert app.PRIO_PROBATION > app.PRIO_QUARANTINE_DROP

    dp = _fake_datapath()
    app._datapaths = {dp.id: dp}
    app._on_trust_collapse('srv3')  # srv3 is now dropping
    dp.send_msg.reset_mock()

    app._install_vip_pair(dp, '10.0.0.5', 5000, 'srv3', probation=True)

    adds = [
        c.args[0] for c in dp.send_msg.call_args_list
        if c.args[0].command == ofproto_v1_3.OFPFC_ADD
    ]
    assert len(adds) == 2, 'forward + reverse rewrite'
    for m in adds:
        assert m.priority == app.PRIO_PROBATION
        assert m.priority > app.PRIO_QUARANTINE_DROP
        assert m.instructions != [], 'a trial must forward, not drop'
        # The carve-out has to close on its own, or one trial would leave a
        # quarantined node reachable for the full flow_hard_timeout.
        assert 0 < m.hard_timeout <= max(2, round(app.task_timeout_s))
        assert m.idle_timeout == 0


def test_ordinary_routing_is_unchanged_by_the_probation_path(app):
    """Probation must be inert on the normal path: same priority, same
    timeouts as before it existed."""
    dp = _fake_datapath()
    app._datapaths = {dp.id: dp}

    app._install_vip_pair(dp, '10.0.0.5', 5000, 'srv3')

    adds = [
        c.args[0] for c in dp.send_msg.call_args_list
        if c.args[0].command == ofproto_v1_3.OFPFC_ADD
    ]
    assert len(adds) == 2
    for m in adds:
        assert m.priority == app.PRIO_CONNECTION
        assert m.priority < app.PRIO_QUARANTINE_DROP
        assert m.idle_timeout == app.flow_idle_timeout
        assert m.hard_timeout == app.flow_hard_timeout
