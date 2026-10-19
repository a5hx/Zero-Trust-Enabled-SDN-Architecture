"""Wiring the RAFT ledger into the controller (task 2 of the application plan).

What is pinned here, one class per property:

* Blocks survive a round trip as plain data, so a replica can ship one and the
  controller can re-validate it with its own Ledger.
* FileStorage keeps RAFT's persistent state (term, vote, log) across a
  restart, and tolerates the torn last line a crash mid-append can leave.
* A retried batch never becomes a second block (content-keyed idempotency),
  which is what makes client retries safe.
* AsyncCommitter keeps commits off the caller's thread and never loses a
  batch to a failed attempt -- the two blockers that kept RaftBackend out of
  the controller.
* RemoteRaftBackend commits through a real replica control API over real
  HTTP, follows a leader hint, mirrors and re-validates the chain, and the
  replica refuses requests without the bearer token when one is configured.
"""

import json
import random
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

import pytest

from blockchain.commit_backend import (
    AsyncCommitter,
    LocalLedgerBackend,
    RaftBackend,
    RemoteRaftBackend,
    TimingCommitBackend,
    batch_key,
    build_commit_backend,
    parse_replicas,
)
from blockchain.ledger import Ledger
from blockchain.raft import FileStorage, InMemoryNetwork, LogEntry, RaftNode
from blockchain.raft_replica import Ticker, _make_handler
from contracts.block_schema import Block
from contracts.trust_update import TrustUpdate

FAST_TIMING = dict(heartbeat_interval=0.02, election_timeout_min=0.05,
                   election_timeout_max=0.10)


def _update(seq: int, node: str = 'srv1') -> TrustUpdate:
    return TrustUpdate(device_id=f'iot{seq}', edge_node_id=node,
                       timestamp=1_700_000_000.0 + seq, task_status='success',
                       cpu_usage=0.3, reported_cpu=0.3, latency_ms=20.0,
                       trust_score_after=0.7)


def _single_node_backend(node_id: str = 'r1', **kwargs) -> RaftBackend:
    network = InMemoryNetwork(rng=random.Random(0))
    backend = RaftBackend(node_id, peers=[], transport=network, **{**FAST_TIMING, **kwargs})
    network.register(backend)
    return backend


def _wait(predicate, timeout: float = 2.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.01)
    return False


# --------------------------------------------------------------------------- #
class TestBlockRoundTrip:
    def test_to_dict_from_dict_round_trip_validates_in_a_fresh_ledger(self) -> None:
        source = LocalLedgerBackend()
        block = source.commit([_update(1), _update(2)])
        copy = Block.from_dict(json.loads(json.dumps(block.to_dict())))
        assert copy == block
        mirror = Ledger()
        assert mirror.append(copy)
        assert mirror.is_valid_chain()

    def test_a_tampered_copy_is_rejected_by_the_mirror(self) -> None:
        block = LocalLedgerBackend().commit([_update(1)])
        data = block.to_dict()
        data['trust_updates'][0]['trust_score_after'] = 0.99
        assert not Ledger().append(Block.from_dict(data))

    def test_block_at_and_blocks_from(self) -> None:
        backend = LocalLedgerBackend()
        b1 = backend.commit([_update(1)])
        b2 = backend.commit([_update(2)])
        assert backend.ledger.block_at(1) is b1
        assert backend.ledger.block_at(5) is None
        assert backend.ledger.blocks_from(1) == [b1, b2]


# --------------------------------------------------------------------------- #
class TestFileStorage:
    def test_vote_and_log_survive_a_reload(self, tmp_path) -> None:
        s = FileStorage(str(tmp_path))
        s.save_vote(3, 'r2')
        s.append([LogEntry(1, 1, {'a': 1}), LogEntry(2, 2, {'b': 2})])
        term, vote, entries = FileStorage(str(tmp_path)).load()
        assert (term, vote) == (3, 'r2')
        assert [e.index for e in entries] == [1, 2]
        assert entries[1].payload == {'b': 2}

    def test_truncate_drops_the_suffix(self, tmp_path) -> None:
        s = FileStorage(str(tmp_path))
        s.append([LogEntry(1, i, None) for i in (1, 2, 3)])
        s.truncate(2)
        assert [e.index for e in s.load()[2]] == [1]

    def test_a_torn_last_line_is_ignored(self, tmp_path) -> None:
        s = FileStorage(str(tmp_path))
        s.append([LogEntry(1, 1, None), LogEntry(1, 2, None)])
        with open(tmp_path / 'log.jsonl', 'a') as fh:
            fh.write('{"term": 1, "index": 3, "pay')   # crash mid-write
        assert [e.index for e in s.load()[2]] == [1, 2]

    def test_a_restarted_node_resumes_term_vote_and_log(self, tmp_path) -> None:
        network = InMemoryNetwork(rng=random.Random(0))
        node = RaftNode('r1', peers=[], transport=network,
                        storage=FileStorage(str(tmp_path)), **FAST_TIMING)
        node.tick(1.0)                      # single node elects itself
        assert node.is_leader
        node.client_append({'x': 1}, now=1.0)
        node.client_append({'x': 2}, now=1.0)

        again = RaftNode('r1', peers=[], transport=network,
                         storage=FileStorage(str(tmp_path)), **FAST_TIMING)
        assert again.current_term == node.current_term
        assert again.voted_for == 'r1'
        assert [e.payload for e in again.log[1:]] == [{'x': 1}, {'x': 2}]
        assert again.commit_index == 0     # volatile, relearned after restart

    def test_a_restarted_replica_rebuilds_the_identical_ledger(self, tmp_path) -> None:
        first = _single_node_backend(storage=FileStorage(str(tmp_path)))
        first.drive_tick(1.0)
        b1 = first.commit([_update(1)])
        b2 = first.commit([_update(2)])
        assert b1 is not None and b2 is not None

        second = _single_node_backend(storage=FileStorage(str(tmp_path)))
        second.drive_tick(5.0)              # re-elected; commits its own term
        assert second.node.is_leader
        b3 = second.commit([_update(3)])   # commit_index advances -> re-apply
        assert b3 is not None
        assert second.ledger.block_at(1).hash == b1.hash
        assert second.ledger.block_at(2).hash == b2.hash
        assert second.verify()


# --------------------------------------------------------------------------- #
class TestIdempotentCommit:
    def test_a_retried_batch_returns_the_same_block(self) -> None:
        backend = _single_node_backend()
        backend.drive_tick(1.0)
        batch = [_update(1), _update(2)]
        first = backend.commit(batch)
        again = backend.commit(list(batch))
        assert again is not None and again.hash == first.hash
        assert backend.chain_length() == 2

    def test_a_batch_that_reached_the_log_twice_is_applied_once(self) -> None:
        backend = _single_node_backend()
        backend.drive_tick(1.0)
        updates = [_update(7)]
        payload = {
            'timestamp': 1.0, 'proposer_id': 'r1', 'raft_term': backend.node.current_term,
            'batch_key': batch_key(updates), 'trust_updates': [u.to_dict() for u in updates],
        }
        with backend._lock:                 # propose the same content twice
            backend.node.client_append(payload, now=1.0)
            backend.node.client_append(dict(payload), now=1.0)
        assert backend.chain_length() == 2
        assert backend.verify()


# --------------------------------------------------------------------------- #
class _Flaky:
    """CommitBackend stub: fails `fail_first` attempts, can be slow."""

    def __init__(self, fail_first: int = 0, delay_s: float = 0.0) -> None:
        self.inner = LocalLedgerBackend()
        self.fail_left = fail_first
        self.delay_s = delay_s
        self.attempts = 0

    def commit(self, updates: List[TrustUpdate]) -> Optional[Block]:
        self.attempts += 1
        time.sleep(self.delay_s)
        if self.fail_left > 0:
            self.fail_left -= 1
            return None
        return self.inner.commit(updates)

    def latest_score(self, node_id: str) -> Optional[float]:
        return self.inner.latest_score(node_id)

    def verify(self) -> bool:
        return self.inner.verify()

    def chain_length(self) -> int:
        return self.inner.chain_length()


class TestAsyncCommitter:
    def test_commit_returns_immediately_even_when_the_backend_is_slow(self) -> None:
        committer = AsyncCommitter(_Flaky(delay_s=0.5))
        try:
            start = time.monotonic()
            committer.commit([_update(1)])
            assert time.monotonic() - start < 0.05
            assert committer.commit_count == 1
            assert committer.flush(timeout=3.0)
        finally:
            committer.close()

    def test_the_caller_may_clear_its_list_after_commit(self) -> None:
        inner = _Flaky()
        committer = AsyncCommitter(inner)
        try:
            pending = [_update(1)]
            committer.commit(pending)
            pending.clear()                 # TrustState does exactly this
            assert committer.flush(timeout=2.0)
            assert inner.chain_length() == 2
        finally:
            committer.close()

    def test_failed_attempts_are_retried_not_lost_and_order_is_kept(self) -> None:
        inner = _Flaky(fail_first=3)
        committer = AsyncCommitter(inner, backoff_initial_s=0.01, backoff_max_s=0.02)
        try:
            for i in range(5):
                committer.commit([_update(i)])
            assert committer.flush(timeout=5.0)
            assert inner.chain_length() == 6
            assert committer.retries == 3
            order = [b.trust_updates[0].device_id for b in inner.inner.ledger.blocks_from(1)]
            assert order == [f'iot{i}' for i in range(5)]
        finally:
            committer.close()

    def test_a_full_queue_drops_explicitly_and_counts_it(self) -> None:
        committer = AsyncCommitter(_Flaky(), max_queue=2, start=False)
        for i in range(3):
            committer.commit([_update(i)])
        assert committer.pending() == 2
        assert committer.dropped == 1
        assert committer.status()['dropped'] == 1

    def test_build_commit_backend_defaults_to_the_local_ledger(self) -> None:
        backend = build_commit_backend(None)
        assert isinstance(backend, TimingCommitBackend)
        assert backend.commit([_update(1)]) is not None
        with pytest.raises(ValueError):
            build_commit_backend({'backend': 'carrier-pigeon'})


# --------------------------------------------------------------------------- #
class _Replica:
    """A real replica control API (raft_replica's handler) on localhost, over a
    single-node RaftBackend driven by raft_replica's own Ticker."""

    def __init__(self, node_id: str = 'r1', token: Optional[str] = None) -> None:
        self.backend = _single_node_backend(node_id)
        self.ticker = Ticker(self.backend)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), _make_handler(self.backend, token))
        self.port = self.server.server_address[1]
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> '_Replica':
        self.ticker.start()
        self._thread.start()
        assert _wait(lambda: self.backend.node.is_leader)
        return self

    def __exit__(self, *exc: Any) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.ticker.stop()


class _NotLeader(BaseHTTPRequestHandler):
    """Answers every commit like a follower that knows who the leader is."""
    leader_id = 'r1'

    def log_message(self, *a: Any) -> None:
        pass

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get('Content-Length', 0) or 0))
        body = json.dumps({'ok': False, 'status': {'leader_id': self.leader_id}}).encode()
        self.send_response(409)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class TestRemoteRaftBackend:
    def test_parse_replicas_accepts_mapping_and_list(self) -> None:
        want = {'r1': ('127.0.0.1', 9101), 'r2': ('10.0.0.2', 9102)}
        assert parse_replicas({'r1': '127.0.0.1:9101', 'r2': '10.0.0.2:9102'}) == want
        assert parse_replicas(['r1=127.0.0.1:9101', 'r2=10.0.0.2:9102']) == want

    def test_commits_over_http_and_mirrors_a_valid_chain(self) -> None:
        with _Replica() as rep:
            remote = RemoteRaftBackend({'r1': ('127.0.0.1', rep.port)})
            b1 = remote.commit([_update(1)])
            b2 = remote.commit([_update(2)])
            assert b1 is not None and b2 is not None
            assert b2.raft_term > 0 and b2.proposer_id == 'r1'
            assert remote.chain_length() == 3 and remote.verify()
            assert remote.ledger.block_at(2).hash == rep.backend.ledger.block_at(2).hash
            assert remote.latest_score('srv1') == pytest.approx(0.7)

    def test_a_retry_after_a_lost_reply_gets_the_same_block(self) -> None:
        with _Replica() as rep:
            remote = RemoteRaftBackend({'r1': ('127.0.0.1', rep.port)})
            batch = [_update(1)]
            first = remote.commit(batch)
            again = remote.commit(list(batch))
            assert again.hash == first.hash
            assert rep.backend.chain_length() == 2 and remote.chain_length() == 2

    def test_follows_the_leader_hint_from_a_non_leader(self) -> None:
        follower = ThreadingHTTPServer(('127.0.0.1', 0), _NotLeader)
        threading.Thread(target=follower.serve_forever, daemon=True).start()
        try:
            with _Replica('r1') as rep:
                remote = RemoteRaftBackend({
                    'r2': ('127.0.0.1', follower.server_address[1]),  # tried first
                    'r1': ('127.0.0.1', rep.port),
                })
                assert remote.commit([_update(1)]) is not None
                assert remote.status()['leader_hint'] == 'r1'
        finally:
            follower.shutdown()
            follower.server_close()

    def test_sync_catches_a_fresh_mirror_up_with_the_cluster(self) -> None:
        with _Replica() as rep:
            writer = RemoteRaftBackend({'r1': ('127.0.0.1', rep.port)})
            for i in range(3):
                writer.commit([_update(i)])
            restarted = RemoteRaftBackend({'r1': ('127.0.0.1', rep.port)})
            assert restarted.sync()
            assert restarted.chain_length() == 4 and restarted.verify()

    def test_unreachable_cluster_returns_none_within_the_deadline(self) -> None:
        remote = RemoteRaftBackend({'r1': ('127.0.0.1', 9)}, request_timeout_s=0.2,
                                   deadline_s=0.5)
        start = time.monotonic()
        assert remote.commit([_update(1)]) is None
        assert time.monotonic() - start < 2.0
        assert remote.status()['last_error']

    def test_bearer_token_is_required_when_configured(self) -> None:
        with _Replica(token='s3cret') as rep:
            anonymous = RemoteRaftBackend({'r1': ('127.0.0.1', rep.port)}, deadline_s=0.5)
            assert anonymous.commit([_update(1)]) is None
            assert '401' in anonymous.status()['last_error']
            allowed = RemoteRaftBackend({'r1': ('127.0.0.1', rep.port)}, auth_token='s3cret')
            assert allowed.commit([_update(1)]) is not None

    def test_async_committer_over_remote_backend_end_to_end(self) -> None:
        with _Replica() as rep:
            committer = AsyncCommitter(TimingCommitBackend(
                RemoteRaftBackend({'r1': ('127.0.0.1', rep.port)})))
            try:
                for i in range(4):
                    committer.commit([_update(i)])
                assert committer.flush(timeout=5.0)
                assert committer.chain_length() == 5 and committer.verify()
                status = committer.status()
                assert status['backend'] == 'raft_remote'
                assert status['committed'] == 4 and status['queue_depth'] == 0
            finally:
                committer.close()


# --------------------------------------------------------------------------- #
class TestRaftConfig:
    """config/params_trust_raft.yaml must be the shipped full config plus the
    ledger block -- any other drift would make a raft run incomparable."""

    def test_differs_from_the_full_config_only_in_ledger_and_record_path(self) -> None:
        yaml = pytest.importorskip('yaml')
        with open('config/params_trust_full.yaml') as fh:
            full = yaml.safe_load(fh)
        with open('config/params_trust_raft.yaml') as fh:
            raft = yaml.safe_load(fh)
        ledger = raft.pop('ledger')
        assert raft['controller']['dashboard'].pop('record_path') == 'data/events_raft.jsonl'
        full['controller']['dashboard'].pop('record_path')
        assert raft == full
        assert ledger['backend'] == 'raft_remote'
        assert set(ledger['replicas']) == set(ledger['launch_local']['raft_peers'])
        assert len(parse_replicas(ledger['replicas'])) == 3
