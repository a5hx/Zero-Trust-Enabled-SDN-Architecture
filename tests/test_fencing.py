"""Multi-controller fencing, step 1 (docs/MULTI_CONTROLLER.md).

Three layers, each tested on its own and then end to end:
  * the controller-generation register replicated by the ledger's Raft
    cluster (blockchain/commit_backend.py), and the fencing token every trust
    batch then carries;
  * the replica's HTTP API for it (blockchain/raft_replica.py) and the
    controller's client (RemoteRaftBackend.claim_generation);
  * the primary's OpenFlow handshake (controller/fencing.py wired into
    controller/trust_balancer.py): claim MASTER under the generation, install
    nothing until the switch confirms, stop writing once a switch says a newer
    controller holds it. Checked with the real OpenFlow 1.3 parser.
"""

import json
import random
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import pytest
import yaml

from blockchain.commit_backend import (
    NO_GENERATION, STALE_GENERATION, UNKNOWN_GENERATION, RaftBackend, RemoteRaftBackend,
    find_remote, build_commit_backend,
)
from blockchain.raft import InMemoryNetwork
from blockchain.raft_replica import _make_handler
from controller.fencing import (
    MASTER, PENDING, SLAVE, STALE, Fence, FencingConfig, _is_newer,
)
from tests.test_commit_backend import FAST_TIMING, _Driver, _make_cluster, _make_update, \
    _wait_for_leader


# --------------------------------------------------------------------------- #
# The register, replicated                                                     #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def cluster():
    network, backends = _make_cluster(['n1', 'n2', 'n3'])
    driver = _Driver(network, list(backends.values()))
    driver.start()
    try:
        yield network, backends
    finally:
        driver.stop()


def _converged(backends, expected, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if all(b.controller_state() == expected for b in backends.values()):
            return True
        time.sleep(0.01)
    return False


class TestGenerationRegister:
    def test_a_claim_is_granted_and_every_replica_applies_it(self, cluster):
        _, backends = cluster
        leader = _wait_for_leader(backends)
        result = leader.claim_generation('primary', 0)
        assert result is not None and result.granted
        assert (result.generation, result.holder) == (1, 'primary')
        assert _converged(backends, {'generation': 1, 'holder': 'primary'})

    def test_a_claim_on_a_stale_generation_is_refused_and_changes_nothing(self, cluster):
        _, backends = cluster
        leader = _wait_for_leader(backends)
        assert leader.claim_generation('primary', 0).granted
        late = leader.claim_generation('standby', 0)       # read 0, someone moved on
        assert late is not None and not late.granted
        assert (late.generation, late.holder) == (1, 'primary')
        assert _converged(backends, {'generation': 1, 'holder': 'primary'})

    def test_a_takeover_claims_the_next_generation(self, cluster):
        _, backends = cluster
        leader = _wait_for_leader(backends)
        leader.claim_generation('primary', 0)
        takeover = leader.claim_generation('standby', 1)
        assert takeover.granted and (takeover.generation, takeover.holder) == (2, 'standby')
        assert _converged(backends, {'generation': 2, 'holder': 'standby'})

    def test_a_retried_claim_is_answered_granted_again(self, cluster):
        _, backends = cluster
        leader = _wait_for_leader(backends)
        first = leader.claim_generation('primary', 0)
        again = leader.claim_generation('primary', 0)       # the reply was lost
        assert first.granted and again.granted
        assert again.generation == first.generation == 1

    def test_a_follower_does_not_decide_a_claim(self, cluster):
        _, backends = cluster
        leader = _wait_for_leader(backends)
        follower = next(b for b in backends.values() if b is not leader)
        assert follower.claim_generation('primary', 0) is None


class TestFencingToken:
    def test_before_any_claim_batches_without_a_generation_commit_as_before(self, cluster):
        _, backends = cluster
        leader = _wait_for_leader(backends)
        result = leader.commit_ex([_make_update('srv1', 0.8)])
        assert result is not None and result.block is not None and not result.rejected

    def test_the_current_generation_commits(self, cluster):
        _, backends = cluster
        leader = _wait_for_leader(backends)
        leader.claim_generation('primary', 0)
        result = leader.commit_ex([_make_update('srv1', 0.8)], generation=1)
        assert result.block is not None

    @pytest.mark.parametrize('generation, reason', [
        (1, STALE_GENERATION), (9, UNKNOWN_GENERATION), (None, NO_GENERATION)])
    def test_any_other_generation_is_refused_whole(self, cluster, generation, reason):
        _, backends = cluster
        leader = _wait_for_leader(backends)
        leader.claim_generation('primary', 0)
        leader.claim_generation('standby', 1)                # register now at 2
        before = leader.chain_length()
        updates = [_make_update('srv1', 0.8), _make_update('srv2', 0.7)]
        result = leader.commit_ex(updates, generation=generation)
        assert result is not None and result.block is None
        assert [r['reason'] for r in result.rejected] == [reason, reason]
        assert [r['node'] for r in result.rejected] == ['srv1', 'srv2']
        assert leader.chain_length() == before
        # The same refusal on every replica: apply is deterministic.
        time.sleep(0.2)
        assert {b.chain_length() for b in backends.values()} == {before}

    def test_status_reports_the_register(self, cluster):
        _, backends = cluster
        leader = _wait_for_leader(backends)
        leader.claim_generation('primary', 0)
        s = leader.status()
        assert (s['controller_generation'], s['controller_holder']) == (1, 'primary')


# --------------------------------------------------------------------------- #
# The replica's HTTP API and the controller's client                           #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def replica():
    """One real single-replica cluster behind the real control API."""
    network = InMemoryNetwork(rng=random.Random(0))
    backend = RaftBackend('n1', peers=[], transport=network, **FAST_TIMING)
    network.register(backend)
    driver = _Driver(network, [backend])
    driver.start()
    deadline = time.monotonic() + 2.0
    while not backend.node.is_leader and time.monotonic() < deadline:
        time.sleep(0.01)
    server = ThreadingHTTPServer(('127.0.0.1', 0), _make_handler(backend))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield backend, server.server_address[1]
    finally:
        server.shutdown()
        driver.stop()


def _http(port, method, path, body=None):
    import http.client
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
    conn.request(method, path, body=json.dumps(body).encode() if body is not None else None,
                 headers={'Content-Type': 'application/json'})
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, (json.loads(data) if data else {})


class TestReplicaApi:
    def test_read_and_claim(self, replica):
        _, port = replica
        assert _http(port, 'GET', '/controller') == (200, {'generation': 0, 'holder': None})
        status, body = _http(port, 'POST', '/controller/claim',
                             {'controller_id': 'primary', 'expect': 0})
        assert status == 200 and body == {'granted': True, 'generation': 1, 'holder': 'primary'}
        status, body = _http(port, 'POST', '/controller/claim',
                             {'controller_id': 'standby', 'expect': 0})
        assert status == 200 and not body['granted'] and body['holder'] == 'primary'

    @pytest.mark.parametrize('body', [{}, {'controller_id': 'x'}, {'expect': 0},
                                      {'controller_id': 'x', 'expect': -1},
                                      {'controller_id': 'x', 'expect': True},
                                      {'controller_id': '', 'expect': 0}])
    def test_a_malformed_claim_is_400(self, replica, body):
        _, port = replica
        assert _http(port, 'POST', '/controller/claim', body)[0] == 400

    def test_a_stale_batch_is_422_and_a_non_integer_generation_is_400(self, replica):
        _, port = replica
        _http(port, 'POST', '/controller/claim', {'controller_id': 'primary', 'expect': 0})
        _http(port, 'POST', '/controller/claim', {'controller_id': 'standby', 'expect': 1})
        row = _make_update('srv1', 0.8).to_dict()
        status, body = _http(port, 'POST', '/commit', {'updates': [row], 'generation': 1})
        assert status == 422 and body['rejected'][0]['reason'] == STALE_GENERATION
        assert _http(port, 'POST', '/commit', {'updates': [row], 'generation': '2'})[0] == 400
        status, body = _http(port, 'POST', '/commit', {'updates': [row], 'generation': 2})
        assert status == 200 and body['ok']

    def test_the_client_claims_then_stamps_every_batch(self, replica):
        backend, port = replica
        remote = RemoteRaftBackend({'n1': ('127.0.0.1', port)}, deadline_s=2.0)
        result = remote.claim_generation('primary')
        assert result.granted and remote.generation == 1
        assert remote.commit([_make_update('srv1', 0.8)]) is not None
        # A newer controller takes over: this client's next batch is refused.
        other = RemoteRaftBackend({'n1': ('127.0.0.1', port)}, deadline_s=2.0)
        assert other.claim_generation('standby', takeover=True).generation == 2
        from blockchain.verifier import BatchRejected
        with pytest.raises(BatchRejected):
            remote.commit([_make_update('srv1', 0.7)])
        assert remote.rejected_batches == 1

    def test_a_second_primary_does_not_fence_a_running_one(self, replica):
        backend, port = replica
        assert RemoteRaftBackend({'n1': ('127.0.0.1', port)}).claim_generation('primary').granted
        res = RemoteRaftBackend({'n1': ('127.0.0.1', port)}).claim_generation('standby')
        assert not res.granted and (res.generation, res.holder) == (1, 'primary')
        assert backend.controller_state() == {'generation': 1, 'holder': 'primary'}

    def test_a_restarting_primary_takes_a_fresh_generation(self, replica):
        _, port = replica
        RemoteRaftBackend({'n1': ('127.0.0.1', port)}).claim_generation('primary')
        again = RemoteRaftBackend({'n1': ('127.0.0.1', port)}).claim_generation('primary')
        assert again.granted and again.generation == 2

    def test_a_takeover_claims_over_the_holder(self, replica):
        _, port = replica
        RemoteRaftBackend({'n1': ('127.0.0.1', port)}).claim_generation('primary')
        res = RemoteRaftBackend({'n1': ('127.0.0.1', port)}).claim_generation(
            'standby', takeover=True)
        assert res.granted and (res.generation, res.holder) == (2, 'standby')

    def test_find_remote_unwraps_the_controller_backend(self, replica):
        _, port = replica
        backend = build_commit_backend({'backend': 'raft_remote',
                                        'replicas': {'n1': f'127.0.0.1:{port}'}})
        try:
            assert isinstance(find_remote(backend), RemoteRaftBackend)
        finally:
            backend.close(timeout=1.0)
        assert find_remote(build_commit_backend(None)) is None


# --------------------------------------------------------------------------- #
# The per-switch role state machine                                            #
# --------------------------------------------------------------------------- #
class TestFence:
    def test_writable_only_once_confirmed_master(self):
        f = Fence(3)
        f.requested(1)
        assert f.roles[1] == PENDING and not f.may_write(1)
        assert f.on_role_reply(1, MASTER, 3)
        assert f.may_write(1) and not f.may_write(2)

    def test_a_stale_refusal_fences_every_switch(self):
        f = Fence(3)
        f.on_role_reply(1, MASTER, 3)
        f.on_role_failed(2, stale=True, code=1)
        assert f.fenced and f.roles[2] == STALE
        assert not f.may_write(1)                 # fenced everywhere, not just on 2

    def test_a_reply_naming_a_newer_generation_fences(self):
        f = Fence(3)
        assert not f.on_role_reply(1, MASTER, 4)
        assert f.fenced and not f.may_write(1)

    def test_demotion_by_is_slave_error_fences(self):
        f = Fence(3)
        f.on_role_reply(1, MASTER, 3)
        f.on_is_slave_error(1)
        assert f.fenced and f.roles[1] == SLAVE and not f.may_write(1)

    def test_generation_starts_at_one(self):
        with pytest.raises(ValueError):
            Fence(0)

    def test_newer_uses_openflow_wraparound(self):
        assert _is_newer(4, 3) and not _is_newer(3, 4) and not _is_newer(3, 3)
        assert _is_newer(0, 0xFFFFFFFFFFFFFFFF)   # wrapped forward by one
        assert not _is_newer(0xFFFFFFFFFFFFFFFF, 0)

    def test_config_is_off_by_default(self):
        assert FencingConfig.from_config(None) == FencingConfig(False, 'primary')
        assert FencingConfig.from_config({'fencing': {'enabled': True, 'controller_id': 'a'}}) \
            == FencingConfig(True, 'a')


# --------------------------------------------------------------------------- #
# The primary's handshake, with the real OpenFlow 1.3 parser                   #
# --------------------------------------------------------------------------- #
ofp13 = pytest.importorskip('os_ken.ofproto.ofproto_v1_3')
from os_ken.ofproto import ofproto_v1_3, ofproto_v1_3_parser  # noqa: E402


def _dp(dpid):
    dp = mock.Mock()
    dp.id = dpid
    dp.ofproto = ofproto_v1_3
    dp.ofproto_parser = ofproto_v1_3_parser
    return dp


def _sent(dp, cls):
    return [c.args[0] for c in dp.send_msg.call_args_list if isinstance(c.args[0], cls)]


def _ev(**msg):
    return mock.Mock(msg=mock.Mock(**msg))


def _app(tmp_path, monkeypatch, fencing, ledger=None, controller_id='primary'):
    cfg = yaml.safe_load(Path('config/params_trust_demo.yaml').read_text())
    cfg['controller']['dashboard'] = {'enabled': False}
    if fencing:
        cfg['controller']['fencing'] = {'enabled': True, 'controller_id': controller_id}
    if ledger is not None:
        cfg['ledger'] = ledger
    path = tmp_path / f'params_{controller_id}.yaml'
    path.write_text(yaml.safe_dump(cfg))
    monkeypatch.setenv('ZTSDN_CONFIG', str(path))
    from controller.trust_balancer import TrustBalancerApp
    return TrustBalancerApp()


@pytest.fixture()
def fenced_app(tmp_path, monkeypatch):
    from controller.trust_balancer import TrustBalancerApp
    monkeypatch.setattr(TrustBalancerApp, '_claim_generation', lambda self: Fence(3))
    return _app(tmp_path, monkeypatch, fencing=True)


class TestPrimaryHandshake:
    def test_without_fencing_nothing_changes(self, tmp_path, monkeypatch):
        app = _app(tmp_path, monkeypatch, fencing=False)
        dp = _dp(1)
        app.switch_features_handler(_ev(datapath=dp))
        assert app.fence is None
        assert not _sent(dp, ofproto_v1_3_parser.OFPRoleRequest)
        assert _sent(dp, ofproto_v1_3_parser.OFPFlowMod)        # installed at once
        assert 1 in app._datapaths

    def test_claims_master_under_its_generation_and_waits(self, fenced_app):
        dp = _dp(1)
        fenced_app.switch_features_handler(_ev(datapath=dp))
        (req,) = _sent(dp, ofproto_v1_3_parser.OFPRoleRequest)
        assert req.role == ofproto_v1_3.OFPCR_ROLE_MASTER and req.generation_id == 3
        assert not _sent(dp, ofproto_v1_3_parser.OFPFlowMod)    # nothing before confirmation
        assert 1 not in fenced_app._datapaths

    def test_installs_once_the_switch_confirms_master(self, fenced_app):
        dp = _dp(1)
        fenced_app.switch_features_handler(_ev(datapath=dp))
        fenced_app.role_reply_handler(_ev(datapath=dp, role=ofproto_v1_3.OFPCR_ROLE_MASTER,
                                          generation_id=3))
        assert _sent(dp, ofproto_v1_3_parser.OFPFlowMod)
        assert fenced_app._datapaths.get(1) is dp and fenced_app.fence.may_write(1)

    def test_a_stale_refusal_installs_nothing_and_stops_all_writes(self, fenced_app):
        a, b = _dp(1), _dp(2)
        fenced_app.switch_features_handler(_ev(datapath=a))
        fenced_app.role_reply_handler(_ev(datapath=a, role=ofproto_v1_3.OFPCR_ROLE_MASTER,
                                          generation_id=3))
        fenced_app.switch_features_handler(_ev(datapath=b))
        fenced_app.fencing_error_handler(_ev(datapath=b,
                                             type=ofproto_v1_3.OFPET_ROLE_REQUEST_FAILED,
                                             code=ofproto_v1_3.OFPRRFC_STALE))
        assert not _sent(b, ofproto_v1_3_parser.OFPFlowMod)
        assert fenced_app.fence.fenced and fenced_app._datapaths == {}
        # A packet-in from the switch it still had is not routed.
        n = len(a.send_msg.call_args_list)
        fenced_app.packet_in_handler(_ev(datapath=a, match={'in_port': 1}, data=b''))
        assert len(a.send_msg.call_args_list) == n

    def test_demotion_after_confirmation_fences(self, fenced_app):
        dp = _dp(1)
        fenced_app.switch_features_handler(_ev(datapath=dp))
        fenced_app.role_reply_handler(_ev(datapath=dp, role=ofproto_v1_3.OFPCR_ROLE_MASTER,
                                          generation_id=3))
        fenced_app.fencing_error_handler(_ev(datapath=dp, type=ofproto_v1_3.OFPET_BAD_REQUEST,
                                             code=ofproto_v1_3.OFPBRC_IS_SLAVE))
        assert fenced_app.fence.fenced and fenced_app._datapaths == {}

    def test_unrelated_errors_are_ignored(self, fenced_app):
        dp = _dp(1)
        fenced_app.fencing_error_handler(_ev(datapath=dp, type=ofproto_v1_3.OFPET_BAD_REQUEST,
                                             code=ofproto_v1_3.OFPBRC_BAD_TYPE))
        assert not fenced_app.fence.fenced


class TestPrimaryClaimsFromTheCluster:
    """End to end: the real _claim_generation against a real replica."""

    def test_the_primary_claims_and_its_backend_stamps_batches(self, tmp_path, monkeypatch,
                                                               replica):
        backend, port = replica
        app = _app(tmp_path, monkeypatch, fencing=True,
                   ledger={'backend': 'raft_remote', 'replicas': {'n1': f'127.0.0.1:{port}'}})
        try:
            assert app.fence.generation == 1
            assert find_remote(app._commit_backend).generation == 1
            assert backend.controller_state() == {'generation': 1, 'holder': 'primary'}
        finally:
            app._commit_backend.close(timeout=1.0)

    def test_a_second_primary_refuses_to_start(self, tmp_path, monkeypatch, replica):
        _, port = replica
        ledger = {'backend': 'raft_remote', 'replicas': {'n1': f'127.0.0.1:{port}'}}
        first = _app(tmp_path, monkeypatch, fencing=True, ledger=ledger)
        try:
            with pytest.raises(RuntimeError, match="held by 'primary'"):
                _app(tmp_path, monkeypatch, fencing=True, ledger=ledger,
                     controller_id='second')
        finally:
            first._commit_backend.close(timeout=1.0)

    def test_fencing_without_a_replicated_ledger_refuses_to_start(self, tmp_path, monkeypatch):
        with pytest.raises(ValueError, match='raft_remote'):
            _app(tmp_path, monkeypatch, fencing=True)

    def test_an_unreachable_cluster_refuses_to_start(self, tmp_path, monkeypatch):
        with pytest.raises(RuntimeError, match='could not claim'):
            _app(tmp_path, monkeypatch, fencing=True,
                 ledger={'backend': 'raft_remote', 'replicas': {'n1': '127.0.0.1:9'},
                         'commit_deadline_s': 0.5, 'request_timeout_s': 0.2})


# --------------------------------------------------------------------------- #
# The auditor under fencing: SLAVE under the current generation                #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def auditor(tmp_path, monkeypatch, replica):
    import controller.auditor as aud
    backend, port = replica
    cfg = yaml.safe_load(Path('config/params_review_demo.yaml').read_text())
    cfg['controller']['auditor'] = {'address': '127.0.0.1',
                                    'record_path': str(tmp_path / 'aud.jsonl')}
    cfg['controller']['fencing'] = {'enabled': True}
    cfg['ledger'] = {'backend': 'raft_remote', 'replicas': {'n1': f'127.0.0.1:{port}'},
                     'commit_deadline_s': 2.0}
    path = tmp_path / 'aud_cfg.yaml'
    path.write_text(yaml.safe_dump(cfg))
    monkeypatch.setenv('ZTSDN_CONFIG', str(path))
    monkeypatch.setattr(aud.hub, 'spawn', lambda *a, **k: None)
    monkeypatch.setattr(aud.AuditorApp, '_start_http', lambda self, h, p: None)
    backend.claim_generation('primary', 0)
    backend.claim_generation('primary', 1)              # a restarted primary: generation 2
    return aud, aud.AuditorApp(), backend


class TestAuditorUnderFencing:
    def test_slave_is_requested_under_the_clusters_generation(self, auditor):
        aud, app, _ = auditor
        assert app.generation == 2
        dp = _dp(4)
        app.request_slave(dp)
        (req,) = _sent(dp, ofproto_v1_3_parser.OFPRoleRequest)
        assert req.role == ofproto_v1_3.OFPCR_ROLE_SLAVE and req.generation_id == 2

    def test_a_stale_refusal_is_retried_under_the_new_generation(self, auditor):
        aud, app, backend = auditor
        dp = _dp(5)
        app._datapaths[5] = dp
        app.roles[5] = aud.ROLE_REFUSED                  # refused: primary moved to 3
        backend.claim_generation('primary', 2)
        app.poll_once()
        reqs = _sent(dp, ofproto_v1_3_parser.OFPRoleRequest)
        assert reqs and reqs[-1].generation_id == 3 and app.roles[5] == aud.ROLE_PENDING
