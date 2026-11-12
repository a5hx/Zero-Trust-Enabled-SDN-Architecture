"""controller/auditor.py: the read-only second controller.

Pinned here:
  * it cannot act: no write message is ever built (AST scan of the module),
    it asks every switch for the SLAVE role, reads only from switches that
    confirmed it, and drops every PacketIn;
  * it reads the server off the rewrite the switch applies, using the real
    FlowMods TrustBalancerApp installs, not the cookie;
  * its switch-only verdict: served / unanswered / partial, re-steers and
    deleted rules voided, droppers flagged and honest servers not;
  * the launcher adds it only when configured.
"""

import ast
import inspect
import json
from pathlib import Path
from unittest import mock

import pytest
import yaml

pytest.importorskip('os_ken.ofproto.ofproto_v1_3')
from os_ken.controller import ofp_event  # noqa: E402
from os_ken.controller.handler import DEAD_DISPATCHER, MAIN_DISPATCHER  # noqa: E402
from os_ken.ofproto import ofproto_v1_3, ofproto_v1_3_parser  # noqa: E402

from controller import auditor as aud  # noqa: E402
from controller.auditor import (PARTIAL, SERVED, UNANSWERED, AuditConfig,  # noqa: E402
                                SwitchAudit, rules_from_stats)

SERVERS = {f'srv{i}': (f'10.0.1.{i}', f'00:00:00:00:01:0{i}') for i in range(1, 5)}
VIP, VIP_PORT, NODE_PORT = '10.0.99.1', 9000, 8000


def _dp(dpid):
    dp = mock.Mock()
    dp.id = dpid
    dp.ofproto = ofproto_v1_3
    dp.ofproto_parser = ofproto_v1_3_parser
    return dp


def _sent(dp, cls):
    return [c.args[0] for c in dp.send_msg.call_args_list if isinstance(c.args[0], cls)]


# --------------------------------------------------------------------------- #
# It cannot act                                                                #
# --------------------------------------------------------------------------- #
WRITE_MESSAGES = ('OFPFlowMod', 'OFPPacketOut', 'OFPGroupMod', 'OFPMeterMod', 'OFPPortMod',
                  'OFPTableMod', 'OFPSetConfig', 'OFPSetAsync', 'send_delete_all_flows',
                  'OFPBarrierRequest')


def test_the_module_never_builds_a_write_message():
    tree = ast.parse(Path(aud.__file__).read_text())
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)} | \
            {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    assert not names & set(WRITE_MESSAGES)
    # And everything it does send is one of two read-side messages.
    sent = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute) and n.func.attr == 'send_msg']
    built = {ast.unparse(c.args[0]).split('(')[0].split('.')[-1] for c in sent}
    assert built == {'OFPRoleRequest', 'OFPFlowStatsRequest'}


@pytest.fixture()
def app(tmp_path, monkeypatch):
    cfg = yaml.safe_load(Path('config/params_review_demo.yaml').read_text())
    cfg['controller']['auditor'] = {'address': '127.0.0.1',
                                    'record_path': str(tmp_path / 'aud.jsonl')}
    path = tmp_path / 'cfg.yaml'
    path.write_text(yaml.safe_dump(cfg))
    monkeypatch.setenv('ZTSDN_CONFIG', str(path))
    monkeypatch.setattr(aud.hub, 'spawn', lambda *a, **k: None)
    monkeypatch.setattr(aud.AuditorApp, '_start_http', lambda self, h, p: None)
    return aud.AuditorApp()


def _state(dp, state):
    ev = ofp_event.EventOFPStateChange(dp)
    ev.state = state
    return ev


def _role_reply(dp, role):
    msg = ofproto_v1_3_parser.OFPRoleReply(dp, role=role, generation_id=0)
    msg.datapath = dp
    return ofp_event.EventOFPRoleReply(msg)


def _stats_reply(dp, body):
    msg = ofproto_v1_3_parser.OFPFlowStatsReply(dp)
    msg.body = body
    msg.datapath = dp
    return ofp_event.EventOFPFlowStatsReply(msg)


def test_it_asks_for_slave_and_reads_only_after_the_switch_confirms(app):
    dp = _dp(2)
    app._on_state(_state(dp, MAIN_DISPATCHER))
    [req] = _sent(dp, ofproto_v1_3_parser.OFPRoleRequest)
    assert req.role == ofproto_v1_3.OFPCR_ROLE_SLAVE
    assert app.roles[2] == aud.ROLE_PENDING

    app.poll_once()                                  # not confirmed: no stats request
    assert not _sent(dp, ofproto_v1_3_parser.OFPFlowStatsRequest)
    app._on_flow_stats(_stats_reply(dp, []))         # and a stray reply is not read
    assert app.replies_before_slave == 1

    app._on_role_reply(_role_reply(dp, ofproto_v1_3.OFPCR_ROLE_SLAVE))
    assert app.roles[2] == aud.ROLE_SLAVE
    app.poll_once()
    assert len(_sent(dp, ofproto_v1_3_parser.OFPFlowStatsRequest)) == 1


def test_a_refused_role_is_never_polled(app):
    dp = _dp(3)
    app._on_state(_state(dp, MAIN_DISPATCHER))
    err = ofproto_v1_3_parser.OFPErrorMsg(dp, type_=ofproto_v1_3.OFPET_ROLE_REQUEST_FAILED,
                                          code=ofproto_v1_3.OFPRRFC_STALE)
    err.datapath = dp
    app._on_error(ofp_event.EventOFPErrorMsg(err))
    assert app.roles[3] == aud.ROLE_REFUSED
    app.poll_once()
    assert not _sent(dp, ofproto_v1_3_parser.OFPFlowStatsRequest)


def test_packet_ins_are_counted_and_dropped(app):
    dp = _dp(2)
    app._on_state(_state(dp, MAIN_DISPATCHER))
    dp.send_msg.reset_mock()
    pin = ofproto_v1_3_parser.OFPPacketIn(dp, buffer_id=0xffffffff, total_len=60,
                                          reason=0, table_id=0, cookie=0,
                                          match=ofproto_v1_3_parser.OFPMatch(in_port=1),
                                          data=b'\x00' * 60)
    pin.datapath = dp
    app._on_packet_in(ofp_event.EventOFPPacketIn(pin))
    assert app.packet_ins_ignored == 1
    dp.send_msg.assert_not_called()


def test_a_disconnected_switch_is_forgotten(app):
    dp = _dp(2)
    app._on_state(_state(dp, MAIN_DISPATCHER))
    app._on_state(_state(dp, DEAD_DISPATCHER))
    assert 2 not in app.roles and 2 not in app._datapaths


def test_status_is_json_and_says_what_it_is(app):
    st = app.status()
    json.dumps(st)
    assert 'SLAVE' in st['role'] and st['switches_slave'] == 0
    assert set(st['nodes']) == {f'srv{i}' for i in range(1, 9)}


# --------------------------------------------------------------------------- #
# Server derivation from the real installed rules                             #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def primary(tmp_path, monkeypatch):
    cfg = yaml.safe_load(Path('config/params_trust_demo.yaml').read_text())
    cfg['controller']['dashboard'] = {'enabled': False}
    path = tmp_path / 'params_test.yaml'
    path.write_text(yaml.safe_dump(cfg))
    monkeypatch.setenv('ZTSDN_CONFIG', str(path))
    from controller.trust_balancer import TrustBalancerApp
    a = TrustBalancerApp()
    a._datapaths = {i: _dp(i) for i in (1, 2, 3)}
    return a


def _as_stats(flowmods, nbytes):
    """The FlowMods a switch was sent, read back as OFPFlowStats with counters."""
    return [ofproto_v1_3_parser.OFPFlowStats(
        table_id=fm.table_id, duration_sec=1, duration_nsec=0, priority=fm.priority,
        idle_timeout=fm.idle_timeout, hard_timeout=fm.hard_timeout, flags=0,
        cookie=fm.cookie, packet_count=6, byte_count=nbytes(fm), match=fm.match,
        instructions=fm.instructions) for fm in flowmods]


def _audit_for(primary):
    return SwitchAudit(primary.inventory.servers, primary.vip_ip, primary.vip_port,
                       primary.node_port)


@pytest.mark.parametrize('probation', [False, True])
def test_the_server_is_read_off_the_rewrite(primary, probation):
    ingress = primary._datapaths[2]
    primary._install_vip_pair(ingress, '10.0.0.7', 41234, 'srv2', probation=probation)
    fms = _sent(ingress, ofproto_v1_3_parser.OFPFlowMod)
    audit = _audit_for(primary)
    kinds = [audit.classify(r) for r in rules_from_stats(_as_stats(fms, lambda fm: 0))]
    vip = [k for k in kinds if k is not None]
    assert sorted(k[0] for k in vip) == ['fwd', 'rev']           # passages are not VIP rules
    assert {k[1] for k in vip} == {('10.0.0.7', '41234')}
    assert {k[2] for k in vip} == {'srv2'}


def test_the_cookie_is_not_believed(primary):
    """A rule labelled srv5 that rewrites to srv2 is srv2's connection."""
    ingress = primary._datapaths[2]
    primary._install_vip_pair(ingress, '10.0.0.7', 41234, 'srv2')
    fms = _sent(ingress, ofproto_v1_3_parser.OFPFlowMod)
    for fm in fms:
        fm.cookie = primary._cookie_for('srv5')
    audit = _audit_for(primary)
    kinds = {audit.classify(r)[2] for r in rules_from_stats(_as_stats(fms, lambda fm: 0))
             if audit.classify(r)}
    assert kinds == {'srv2'}


def test_a_served_task_end_to_end(primary):
    ingress = primary._datapaths[2]
    primary._install_vip_pair(ingress, '10.0.0.7', 41234, 'srv2')
    fms = _sent(ingress, ofproto_v1_3_parser.OFPFlowMod)
    audit = _audit_for(primary)
    fwd_first = lambda fm: 548 if dict(fm.match.items()).get('ipv4_dst') == primary.vip_ip else 598  # noqa: E731
    audit.observe(2, rules_from_stats(_as_stats(fms, fwd_first)), now=10.0)
    [j] = audit.tick(10.5)
    assert (j.node, j.outcome) == ('srv2', SERVED)


def test_quarantine_drop_rules_are_ignored(primary):
    audit = _audit_for(primary)
    drop = ofproto_v1_3_parser.OFPFlowStats(
        table_id=0, duration_sec=1, duration_nsec=0, priority=400, idle_timeout=0,
        hard_timeout=0, flags=0, cookie=0, packet_count=9, byte_count=900,
        match=ofproto_v1_3_parser.OFPMatch(eth_src='00:00:00:00:01:02'), instructions=[])
    assert [audit.classify(r) for r in rules_from_stats([drop])] == [None]


# --------------------------------------------------------------------------- #
# The verdict, on synthetic counters                                           #
# --------------------------------------------------------------------------- #
def _rules(node, port, fwd, rev, client='10.0.0.7', mac_node=None):
    ip, mac = SERVERS[node]
    mac = SERVERS[mac_node][1] if mac_node else mac
    return [
        {'priority': 300, 'match': {'ipv4_src': client, 'ipv4_dst': VIP, 'tcp_src': port,
                                    'tcp_dst': VIP_PORT},
         'set_fields': {'eth_dst': mac, 'ipv4_dst': ip, 'tcp_dst': NODE_PORT}, 'bytes': fwd},
        {'priority': 300, 'match': {'ipv4_src': ip, 'ipv4_dst': client, 'tcp_src': NODE_PORT,
                                    'tcp_dst': port},
         'set_fields': {'eth_src': '02:00:00:00:99:01', 'ipv4_src': VIP, 'tcp_src': VIP_PORT},
         'bytes': rev},
    ]


def _audit(**over):
    return SwitchAudit(SERVERS, VIP, VIP_PORT, NODE_PORT, AuditConfig(**over))


def test_unanswered_after_the_timeout_and_partial_responses():
    a = _audit()
    rules = _rules('srv1', 1, 548, 0) + _rules('srv1', 2, 548, 120)
    for t in range(0, 6):                              # polled once a second
        a.observe(2, rules, float(t))
        assert a.tick(float(t)) == []                  # still within the task timeout
    a.observe(2, rules, 6.0)
    out = sorted((j.client_port, j.outcome) for j in a.tick(6.0))
    assert out == [('1', UNANSWERED), ('2', PARTIAL)]


def test_a_judged_connection_is_not_judged_again_while_its_rules_live():
    a = _audit()
    for t in range(0, 12):
        a.observe(2, _rules('srv1', 1, 548, 598), float(t))
        a.tick(float(t))
    assert a.judged == 1
    a.tick(20.0)                                       # rules gone: forgotten
    a.observe(2, _rules('srv1', 1, 548, 598), 21.0)    # the port reused later
    assert len(a.tick(21.0)) == 1


def test_a_resteer_is_voided_not_charged():
    a = _audit()
    a.observe(2, _rules('srv1', 1, 548, 0), 0.0)
    a.observe(2, _rules('srv2', 1, 0, 0), 1.0)         # primary moved it to srv2
    assert a.voided == 1
    a.observe(2, _rules('srv2', 1, 548, 598), 2.0)
    [j] = a.tick(2.0)
    assert (j.node, j.outcome) == ('srv2', SERVED)
    assert a.verdicts(2.0)['nodes']['srv1']['unanswered'] == 0


def test_rules_deleted_before_judgement_are_voided():
    a = _audit()
    a.observe(2, _rules('srv3', 1, 548, 0), 0.0)
    assert a.tick(3.5) == []                           # gone after forget_after_s, never judged
    assert a.voided == 1 and a.judged == 0


def test_an_inconsistent_rewrite_is_counted_and_not_judged():
    a = _audit()
    a.observe(2, _rules('srv1', 1, 548, 0, mac_node='srv2'), 0.0)
    assert a.rewrite_mismatch == 1
    # The reverse rule alone opens the connection but never judges it unanswered:
    # no forward bytes were accepted for it.
    assert all(j.outcome != UNANSWERED for j in a.tick(10.0))


def _drive(a, plan, seconds, rule_life=10):
    """Poll once a second for `seconds`. `plan(i)` lists the (node, client,
    rev_bytes) connections opened at second i; each one's rules are reported
    for `rule_life` seconds (its idle timeout), as a switch would."""
    live = []
    for t in range(seconds):
        for node, client, rev in plan(t):
            live.append((t, node, client, 20000 + t, rev))
        live = [c for c in live if t - c[0] < rule_life]
        rules = []
        for opened, node, client, port, rev in live:
            rules += _rules(node, port, 548, rev, client=client)
        a.observe(2, rules, float(t))
        a.tick(float(t))
    return float(seconds - 1)


def test_a_dropper_is_flagged_and_honest_servers_are_not():
    a = _audit()
    now = _drive(a, lambda t: [('srv1', '10.0.0.1', 598), ('srv2', '10.0.0.2', 0),
                               ('srv3', '10.0.0.3', 0 if t % 2 else 598)], 40)
    v = a.verdicts(now)
    assert v['nodes']['srv1']['verdict'] == 'serving'
    assert v['nodes']['srv2']['verdict'] == 'dropping'                 # blackhole
    assert v['nodes']['srv3']['verdict'] == 'dropping'                 # grayhole 50%
    assert v['nodes']['srv4']['verdict'] == 'no recent traffic'
    assert v['dropping'] == ['srv2', 'srv3']
    assert v['nodes']['srv2']['window'] == AuditConfig().recent
    assert v['voided'] == 0


def test_a_server_that_stops_dropping_is_cleared():
    """Judged on its most recent connections, so an on-off attacker's good
    phase -- or a released server -- clears it."""
    a = _audit()
    _drive(a, lambda t: [('srv2', '10.0.0.2', 0)], 30)
    assert a.verdicts(29.0)['nodes']['srv2']['verdict'] == 'dropping'
    for t in range(30, 70):                         # same clock, honest from 30 s
        a.observe(2, _rules('srv2', 30000 + t, 548, 598, client='10.0.0.2'), float(t))
        a.tick(float(t))
    assert a.verdicts(69.0)['nodes']['srv2']['verdict'] == 'serving'


def test_too_few_connections_is_not_a_verdict():
    a = _audit()
    for i in range(3):
        a.observe(2, _rules('srv2', i, 548, 0), 0.0)
    a.tick(7.0)
    assert a.verdicts(7.0)['nodes']['srv2']['verdict'] == 'insufficient'


def test_config_overrides():
    c = AuditConfig.from_config({'threshold': 0.5, 'recent': '10', 'unknown': 1})
    assert c.threshold == 0.5 and c.recent == 10


# --------------------------------------------------------------------------- #
# Launcher and wiring                                                          #
# --------------------------------------------------------------------------- #
def test_the_launcher_adds_the_auditor_only_when_configured():
    from simulation.topology import _auditor_controller
    base = yaml.safe_load(Path('config/params_review_demo.yaml').read_text())
    assert _auditor_controller(base) is None
    base['controller']['auditor'] = {'address': '192.168.43.14'}
    assert _auditor_controller(base) == ('192.168.43.14', 6654)
    base['controller']['auditor']['ofp_port'] = 7000
    assert _auditor_controller(base) == ('192.168.43.14', 7000)


def test_run_topology_wires_it_and_the_baseline_does_not():
    from base_model import run_base
    from simulation import topology
    src = inspect.getsource(topology.run_topology)
    assert '_auditor_controller(cfg)' in src and "net.addController('c_audit'" in src
    assert src.index('net.build()') < src.index("net.addController('c_audit'") < src.index('net.start()')
    assert 'auditor' not in inspect.getsource(run_base.run_baseline_topology)


def test_the_topology_graph_names_the_auditor_only_when_configured():
    from controller.trust_balancer import auditor_status_url
    assert auditor_status_url({'controller': {}}) is None
    assert auditor_status_url({'controller': {'auditor': {'address': '10.1.1.1', 'http_port': 9}}}) \
        == 'http://10.1.1.1:9/auditor/status'


def test_importing_the_launcher_does_not_monkey_patch():
    """Patching at import greened this whole test process and hung the
    suite on the next real socket wait. Run in a fresh interpreter, since this
    one may already have imported it."""
    import subprocess
    import sys
    code = ('import controller.osken_manager, eventlet.patcher as p; '
            'print(p.is_monkey_patched("socket"), p.is_monkey_patched("thread"))')
    out = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert out.stdout.split() == ['False', 'False']


def test_osken_manager_ofp_port():
    from controller.osken_manager import parse_args
    assert parse_args(['controller.trust_balancer']) == (None, ['controller.trust_balancer'])
    assert parse_args(['--ofp-port', '6654', 'controller.auditor']) == (6654, ['controller.auditor'])
    with pytest.raises(SystemExit):
        parse_args(['--ofp-port', 'x', 'a'])


# --------------------------------------------------------------------------- #
# The dashboard's Controllers panel                                            #
# --------------------------------------------------------------------------- #
def test_the_controllers_panel_agreement_rule():
    from tests.dashboard_js import run_events
    tail = """
    __out.agree = [
      controllerAgreement(false, 'dropping'), controllerAgreement(true, 'dropping'),
      controllerAgreement(false, 'serving'), controllerAgreement(true, 'serving'),
      controllerAgreement(false, 'insufficient')].map(a => a[0]);
    """
    out = run_events([], tail=tail)
    assert out['agree'] == ['DISAGREE — primary still routes to it', 'agree', 'agree',
                            'primary stricter', '—']


def test_the_controllers_panel_says_na_in_replay():
    from tests.dashboard_js import run_events
    from tests.test_dashboard_events import synthetic_stream
    evs = synthetic_stream()
    evs[0] = dict(evs[0], graph=dict(evs[0]['graph'],
                                     auditor_url='http://10.1.1.1:8083/auditor/status'))
    out = run_events(evs, tail="__out.ctrl = document.getElementById('controllers').innerHTML;"
                               "__out.shown = document.getElementById('ctrlPanel').style.display;")
    assert out['errors'] == []
    assert 'n/a in replay' in out['ctrl']
    assert out['shown'] == ''


def test_run_demo_starts_a_local_auditor_only_when_asked(tmp_path, monkeypatch):
    import run_demo
    started = []
    monkeypatch.setattr(run_demo.subprocess, 'Popen',
                        lambda cmd, **kw: started.append((cmd, kw)) or 'proc')
    monkeypatch.chdir(tmp_path)
    (tmp_path / 'logs').mkdir()
    assert run_demo._start_local_auditor({'controller': {}}, {}) is None
    assert run_demo._start_local_auditor(
        {'controller': {'auditor': {'address': '10.0.0.5'}}}, {}) is None   # runs elsewhere
    forge = yaml.safe_load(
        (Path(__file__).resolve().parent.parent / 'config/params_review_demo_forge.yaml').read_text())
    assert run_demo._start_local_auditor(forge, {'ZTSDN_CONFIG': 'x'}) == 'proc'
    [(cmd, kw)] = started
    assert cmd[1:] == ['-m', 'controller.osken_manager', '--ofp-port', '6654', 'controller.auditor']
    assert kw['env'] == {'ZTSDN_CONFIG': 'x'}
