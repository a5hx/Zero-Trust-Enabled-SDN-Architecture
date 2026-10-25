"""Phase 6: replicas re-verify the controller's trust arithmetic
(blockchain/verifier.py, RaftBackend, the replica's /commit, RemoteRaftBackend,
AsyncCommitter) and the test-only dishonest controller (controller/forgery.py).

The records under test come from the real controller path,
TrustState.record_task_outcome, never hand-written scores: a verifier that
only agrees with fixtures would prove nothing about the controller.
"""

import json
import random
import threading
import time
from http.client import HTTPConnection

import pytest
import yaml

from blockchain import verifier as vf
from blockchain.commit_backend import (AsyncCommitter, CommitResult, RaftBackend,
                                       RemoteRaftBackend, build_commit_backend)
from blockchain.raft import InMemoryNetwork
from contracts.trust_update import TrustUpdate
from controller.forgery import ENV_GATE, Forger, TrustForgery
from controller.trust_state import TrustState
from tests.test_commit_backend import FAST_TIMING, _Driver, _wait_for_leader
from tests.test_raft_replica import _free_port

TRUST = {'alpha': 0.35, 'beta': 0.25, 'gamma': 0.25, 'delta': 0.15,
         'lambda_decay': 0.85, 'initial_score': 0.5}
NODES = ['srv1', 'srv2', 'srv3']


class Clock:
    def __init__(self):
        self.t = 100.0

    def __call__(self):
        return self.t


class Capture:
    """A synchronous commit backend that keeps every batch it is handed."""

    def __init__(self):
        self.batches = []

    def commit(self, updates):
        self.batches.append([TrustUpdate(**u.to_dict()) for u in updates])
        return object()


def _stream(n=120, forgery=None, seed=1):
    """Run n mixed task outcomes through a real TrustState; return its batches
    and the time each record was made (seconds on the controller's clock)."""
    clock, cap = Clock(), Capture()
    st = TrustState(node_ids=NODES, commit_backend=cap, max_updates_per_block=10,
                    time_source=clock, forgery=forgery)
    rng = random.Random(seed)
    for i in range(n):
        clock.t += 1.0
        node = NODES[i % 3]
        st._anomaly[node] = 0.9 if (node == 'srv2' and 40 <= i < 60) else 0.0
        st.record_task_outcome(TrustUpdate(
            device_id=f'iot{i % 7}', edge_node_id=node, timestamp=1e9 + i,
            task_status=rng.choice(['success'] * 6 + ['failure', 'timeout']),
            cpu_usage=rng.random() * 0.4, reported_cpu=rng.random() * 0.4,
            latency_ms=rng.uniform(10, 400)))
    st.flush_pending()
    return cap.batches


def _replay(batches, trust=TRUST, h=None):
    r = vf.TrustReplay(trust)
    return r, [r.check(b, r.hash if h is None else h) for b in batches]


# --------------------------------------------------------------------------- #
# The verifier                                                                 #
# --------------------------------------------------------------------------- #
def test_honest_controller_records_all_verify():
    r, out = _replay(_stream())
    assert all(rej == [] for rej in out) and r.checked == 120 and r.rejected == 0


def test_records_still_verify_after_a_json_round_trip():
    """Replicas see the records as JSON; the floats must survive exactly."""
    batches = [[TrustUpdate(**json.loads(json.dumps(u.to_dict()))) for u in b]
               for b in _stream()]
    assert _replay(batches)[0].rejected == 0


def test_a_different_trust_config_rejects_the_whole_batch_without_advancing():
    batches = _stream(30)
    r = vf.TrustReplay(TRUST)
    rej = r.check(batches[0], vf.config_hash({**TRUST, 'delta': 0.2}))
    assert [x.reason for x in rej] == [vf.CONFIG] * 10
    assert r.score('srv1') == TRUST['initial_score']        # replay untouched
    assert r.check(batches[0], r.hash) == []


def test_config_hash_ignores_unrelated_keys_and_tracks_the_formula():
    assert vf.config_hash({**TRUST, 'isolation_threshold': 0.45}) == vf.config_hash(TRUST)
    assert vf.config_hash({**TRUST, 'lambda_decay': 0.8}) != vf.config_hash(TRUST)
    assert vf.config_hash({}) == vf.config_hash(TRUST)       # TrustCalculator's defaults


def test_score_forgery_rejects_exactly_the_forged_records():
    forged = TrustForgery(node='srv3', mode='score', delta=0.3, start_s=60.0)
    batches = _stream(forgery=forged)
    r, out = _replay(batches)
    rej = [x for b in out for x in b]
    flat = [u for b in batches for u in b]
    target = [u for u in flat if u.edge_node_id == 'srv3' and u.timestamp >= 1e9 + 59]
    assert {x.node for x in rej} == {'srv3'}
    assert len(rej) == len(target) > 0
    assert all(x.reason == vf.AFTER for x in rej)
    assert all(abs(x.recorded_after - min(1.0, x.expected_after + 0.3)) < 1e-12 for x in rej)


def test_one_forged_score_costs_at_most_two_records_not_a_cascade():
    """The replay advances on the evidence, so a single inflated score is
    caught on its own record and, because the controller kept it, on the next
    record's `before` -- and nowhere after that."""
    batches = _stream()
    flat = [u for b in batches for u in b]
    k = next(i for i, u in enumerate(flat) if u.edge_node_id == 'srv1' and i > 30)
    flat[k].trust_score_after += 0.2                     # the record lies
    nxt = next(i for i in range(k + 1, len(flat)) if flat[i].edge_node_id == 'srv1')
    flat[nxt].trust_score_before = flat[k].trust_score_after   # and so did its state
    r = vf.TrustReplay(TRUST)
    rej = r.check(flat, r.hash)
    assert [(x.position, x.reason) for x in rej] == [(k, vf.AFTER), (nxt, vf.BEFORE)]


def test_evidence_forgery_passes_verification_the_stated_limit():
    forged = TrustForgery(node='srv3', mode='evidence', start_s=60.0)
    batches = _stream(forgery=forged)
    late = [u for b in batches for u in b if u.edge_node_id == 'srv3' and u.timestamp >= 1e9 + 60]
    assert late and all(u.task_status == 'success' for u in late)
    assert _replay(batches)[0].rejected == 0


# --------------------------------------------------------------------------- #
# The forgery switch                                                           #
# --------------------------------------------------------------------------- #
def test_forgery_is_refused_without_the_environment_gate():
    cfg = {'debug_forge_trust': {'node': 'srv3', 'mode': 'score'}}
    with pytest.raises(ValueError, match=ENV_GATE):
        TrustForgery.from_config(cfg, environ={})
    assert TrustForgery.from_config(cfg, environ={ENV_GATE: '1'}).node == 'srv3'
    assert TrustForgery.from_config({}, environ={}) is None
    with pytest.raises(ValueError):
        TrustForgery.from_config({'debug_forge_trust': {'node': 'x', 'mode': 'lie'}}, {ENV_GATE: '1'})
    with pytest.raises(ValueError):
        TrustForgery.from_config({'debug_forge_trust': {'node': 'x', 'scale': 2}}, {ENV_GATE: '1'})


def test_score_forgery_also_changes_what_routing_reads():
    clock = Clock()
    st = TrustState(node_ids=NODES, commit_backend=Capture(), time_source=clock,
                    forgery=TrustForgery(node='srv1', mode='score', delta=0.25))
    clock.t += 1
    upd = TrustUpdate(device_id='d', edge_node_id='srv1', task_status='failure', latency_ms=300)
    score = st.record_task_outcome(upd)
    replay = vf.TrustReplay(TRUST)
    (rej,) = replay.check([upd], replay.hash)
    assert score == pytest.approx(rej.expected_after + 0.25)       # inflated by delta
    assert st.trust_calc.get_score('srv1') == score                 # and routed on


# --------------------------------------------------------------------------- #
# RaftBackend: a verifying cluster                                             #
# --------------------------------------------------------------------------- #
def _verifying_cluster():
    network = InMemoryNetwork(rng=random.Random(0))
    ids = ['n1', 'n2', 'n3']
    backends = {}
    for nid in ids:
        b = RaftBackend(nid, peers=[n for n in ids if n != nid], transport=network,
                        verifier=vf.TrustReplay(TRUST), **FAST_TIMING)
        network.register(b)
        backends[nid] = b
    return network, backends


def test_cluster_appends_the_honest_records_and_agrees_on_the_rest():
    forged = TrustForgery(node='srv3', mode='score', start_s=60.0)
    batches = _stream(forgery=forged)
    network, backends = _verifying_cluster()
    driver = _Driver(network, list(backends.values()))
    driver.start()
    try:
        leader = _wait_for_leader(backends)
        h = vf.config_hash(TRUST)
        results = [leader.commit_ex(b, config_hash=h) for b in batches]
        assert all(isinstance(r, CommitResult) for r in results)
        rejected = [x for r in results for x in r.rejected]
        kept = [u for r in results if r.block for u in r.block.trust_updates]
        assert {x['node'] for x in rejected} == {'srv3'}
        assert len(kept) + len(rejected) == 120
        assert all(not (u.edge_node_id == 'srv3' and u.timestamp >= 1e9 + 59) for u in kept)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and len({b.chain_length() for b in backends.values()}) > 1:
            time.sleep(0.02)
        heads = {b.ledger.head_hash() for b in backends.values()}
        assert len(heads) == 1 and all(b.verify() for b in backends.values())
        assert {b.status()['records_rejected'] for b in backends.values()} == {len(rejected)}
    finally:
        driver.stop()


def test_a_wholly_forged_batch_makes_no_block_and_a_retry_is_not_judged_twice():
    clock = Clock()
    st = TrustState(node_ids=NODES, commit_backend=Capture(), time_source=clock,
                    max_updates_per_block=5,
                    forgery=TrustForgery(node='srv1', mode='score'))
    for i in range(5):
        clock.t += 1
        st.record_task_outcome(TrustUpdate(device_id='d', edge_node_id='srv1',
                                           timestamp=2e9 + i, latency_ms=30))
    (batch,) = st.commit_backend.batches
    network, backends = _verifying_cluster()
    driver = _Driver(network, list(backends.values()))
    driver.start()
    try:
        leader = _wait_for_leader(backends)
        h = vf.config_hash(TRUST)
        first = leader.commit_ex(batch, config_hash=h)
        assert first.block is None and len(first.rejected) == 5
        checked = leader._verifier.checked
        again = leader.commit_ex(batch, config_hash=h)
        assert again.block is None and again.rejected == first.rejected
        assert leader._verifier.checked == checked             # not replayed again
        assert leader.chain_length() == 1                      # genesis only
    finally:
        driver.stop()


# --------------------------------------------------------------------------- #
# Over HTTP: the replica's /commit and the controller's client                 #
# --------------------------------------------------------------------------- #
@pytest.fixture
def verifying_replica(tmp_path):
    from blockchain.raft_replica import run
    cfg = tmp_path / 'params.yaml'
    cfg.write_text(yaml.safe_dump({'trust': TRUST}))
    raft_port, http_port = _free_port(), _free_port()
    threading.Thread(target=run, daemon=True, args=('solo', {'solo': ('127.0.0.1', raft_port)},
                                                    '127.0.0.1', http_port),
                     kwargs={'verify_config': str(cfg)}).start()
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            c = HTTPConnection('127.0.0.1', http_port, timeout=0.2)
            c.request('GET', '/status')
            if json.loads(c.getresponse().read()).get('role') == 'leader':
                break
        except OSError:
            pass
        time.sleep(0.02)
    else:
        pytest.fail('verifying replica never became leader')
    return http_port


def test_controller_client_keeps_draining_after_a_rejected_batch(verifying_replica):
    forged = TrustForgery(node='srv1', mode='score')
    clock = Clock()
    st = TrustState(node_ids=NODES, commit_backend=Capture(), time_source=clock,
                    max_updates_per_block=5, forgery=forged)
    for i in range(5):                               # batch 1: all srv1, all forged
        clock.t += 1
        st.record_task_outcome(TrustUpdate(device_id='d', edge_node_id='srv1',
                                           timestamp=3e9 + i, latency_ms=30))
    st._forger = None                                # an honest controller from here on
    for i in range(10):                              # batches 2-3: srv2/srv3, honest
        clock.t += 1
        st.record_task_outcome(TrustUpdate(device_id='d', edge_node_id=['srv2', 'srv3'][i % 2],
                                           timestamp=3e9 + 10 + i, latency_ms=30))
    heard = []
    remote = RemoteRaftBackend({'solo': ('127.0.0.1', verifying_replica)},
                               config_hash=vf.config_hash(TRUST),
                               on_rejected=lambda rid, rej: heard.extend(rej))
    committer = AsyncCommitter(remote, backoff_initial_s=0.01)
    for b in st.commit_backend.batches:
        committer.commit(b)
    assert committer.flush(timeout=10)                       # did not block on batch 1
    assert (committer.rejected, committer.committed) == (1, 2)
    assert len(heard) == 5 and {r['node'] for r in heard} == {'srv1'}
    assert remote.chain_length() == 3 and remote.verify()
    assert committer.status()['rejected'] == 1
    committer.close()


def test_replica_answers_422_for_a_wholly_rejected_batch(verifying_replica):
    rows = [TrustUpdate(device_id='d', edge_node_id='srv1', timestamp=4e9,
                        trust_score_after=0.99).to_dict()]
    c = HTTPConnection('127.0.0.1', verifying_replica, timeout=3)
    c.request('POST', '/commit', body=json.dumps({'updates': rows,
                                                  'config_hash': vf.config_hash(TRUST)}))
    resp = c.getresponse()
    body = json.loads(resp.read())
    assert resp.status == 422 and body['rejected'][0]['reason'] == vf.AFTER


# --------------------------------------------------------------------------- #
# Wiring                                                                       #
# --------------------------------------------------------------------------- #
def test_verify_needs_the_replicated_backend():
    with pytest.raises(ValueError):
        build_commit_backend({'backend': 'local', 'verify': True}, trust_cfg=TRUST)


def test_local_cluster_passes_the_config_to_every_replica(monkeypatch):
    import subprocess
    from blockchain import raft_replica
    seen = []
    monkeypatch.setattr(subprocess, 'Popen', lambda cmd, **kw: seen.append(cmd))
    ledger = {'backend': 'raft_remote', 'verify': True,
              'replicas': {'n1': '127.0.0.1:9101', 'n2': '127.0.0.1:9102'},
              'launch_local': {'raft_peers': {'n1': '127.0.0.1:9001', 'n2': '127.0.0.1:9002'}}}
    with pytest.raises(ValueError):
        raft_replica.launch_local_cluster(ledger)
    raft_replica.launch_local_cluster(ledger, log_dir='/tmp', config_path='config/x.yaml')
    assert all(cmd[cmd.index('--verify-config') + 1] == 'config/x.yaml' for cmd in seen)
    assert len(seen) == 2


def test_a_synchronous_refusal_is_counted_not_silently_cleared():
    class Refuses:
        def commit(self, updates):
            return None

    class Later(Refuses):
        is_async = True

    for backend, expect in ((Refuses(), 3), (Later(), 0)):
        st = TrustState(node_ids=NODES, commit_backend=backend, max_updates_per_block=3)
        for _ in range(3):
            st.record_task_outcome(TrustUpdate(device_id='d', edge_node_id='srv1'))
        assert st.ledger_dropped == expect


def test_forger_starts_on_time():
    clock = Clock()
    f = Forger(TrustForgery(node='srv1', mode='score', delta=0.1, start_s=10), now=clock)
    upd = TrustUpdate(device_id='d', edge_node_id='srv1')
    assert f.after(upd, 0.5) is None
    clock.t += 10
    assert f.after(upd, 0.5) == pytest.approx(0.6)
    assert f.after(TrustUpdate(device_id='d', edge_node_id='srv2'), 0.5) is None
