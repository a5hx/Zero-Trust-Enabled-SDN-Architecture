"""Tests for blockchain/commit_backend.py -- LocalLedgerBackend (unchanged)
and RaftBackend (Step 2, RAFT wiring).

RaftBackend's tests drive blockchain.raft.InMemoryNetwork -- the same
reference transport tests/test_raft.py uses to prove RAFT's safety properties
-- but on a REAL background thread with REAL wall-clock ticks, because
RaftBackend.commit() is a genuinely blocking call (it waits on a
threading.Event for its entry to actually commit) and something else has to
keep driving the cluster while it waits. This is therefore an integration
test of RaftBackend's threading/locking design, not a re-proof of RAFT's
safety properties -- those stay in tests/test_raft.py, exercised through
RaftNode/InMemoryNetwork directly.
"""

import random
import threading
import time
from typing import Dict, List

import pytest

from blockchain.commit_backend import LocalLedgerBackend, RaftBackend
from blockchain.raft import InMemoryNetwork
from contracts.trust_update import TrustUpdate


def _make_update(node_id: str = 'srv1', score_after: float = 0.7) -> TrustUpdate:
    return TrustUpdate(
        device_id='iot_test',
        edge_node_id=node_id,
        timestamp=1_700_000_000.0,
        task_status='success',
        cpu_usage=0.3,
        reported_cpu=0.3,
        latency_ms=20.0,
        trust_score_after=score_after,
    )


# --------------------------------------------------------------------------- #
# LocalLedgerBackend -- unchanged, but re-pinned so a future edit to this file
# still catches a regression in the backend Step 2 was NOT supposed to touch.
# --------------------------------------------------------------------------- #
class TestLocalLedgerBackend:
    def test_commit_appends_and_returns_the_block(self) -> None:
        backend = LocalLedgerBackend()
        block = backend.commit([_make_update()])
        assert block is not None
        assert backend.chain_length() == 2
        assert backend.verify()

    def test_commit_with_no_updates_returns_none(self) -> None:
        backend = LocalLedgerBackend()
        assert backend.commit([]) is None
        assert backend.chain_length() == 1

    def test_latest_score_reads_the_ledger(self) -> None:
        backend = LocalLedgerBackend()
        backend.commit([_make_update('srv1', 0.91)])
        assert backend.latest_score('srv1') == pytest.approx(0.91)
        assert backend.latest_score('unknown') is None


# --------------------------------------------------------------------------- #
# RaftBackend                                                                  #
# --------------------------------------------------------------------------- #
FAST_TIMING = dict(heartbeat_interval=0.02, election_timeout_min=0.05,
                   election_timeout_max=0.10)


class _Driver:
    """Runs `drive_tick` + `network.deliver_due` on a background thread with
    real wall-clock time -- the InMemoryNetwork-only stand-in for the ticker
    thread blockchain/raft_replica.py runs against a live TcpTransport."""

    def __init__(self, network: InMemoryNetwork, backends: List[RaftBackend],
                tick_interval: float = 0.005) -> None:
        self._network = network
        self._backends = backends
        self._tick_interval = tick_interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2.0)

    def _run(self) -> None:
        while not self._stop.is_set():
            now = time.monotonic()
            for backend in self._backends:
                if not self._network.is_crashed(backend.node_id):
                    backend.drive_tick(now)
            self._network.deliver_due(now)
            time.sleep(self._tick_interval)


def _make_cluster(node_ids: List[str], **kwargs) -> tuple:
    network = InMemoryNetwork(rng=random.Random(0))
    backends: Dict[str, RaftBackend] = {}
    for nid in node_ids:
        backend = RaftBackend(
            nid, peers=[n for n in node_ids if n != nid], transport=network,
            **{**FAST_TIMING, **kwargs},
        )
        network.register(backend)
        backends[nid] = backend
    return network, backends


def _wait_for_leader(backends: Dict[str, RaftBackend], timeout: float = 2.0) -> RaftBackend:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for backend in backends.values():
            if not backend.node.is_leader:
                continue
            # Only trust a leader that isn't (about to be) crashed in a test
            # that kills nodes -- callers filter further themselves if needed.
            return backend
        time.sleep(0.01)
    raise AssertionError("no leader elected in time")


class TestRaftBackendSingleNode:
    """peers=[] -- the smallest possible cluster, and the case where
    client_append commits synchronously inside itself (RaftNode._majority()
    == 1, its own vote/replica is already enough)."""

    def test_becomes_leader_and_commits_without_blocking(self) -> None:
        network = InMemoryNetwork(rng=random.Random(0))
        backend = RaftBackend('n1', peers=[], transport=network, **FAST_TIMING)
        network.register(backend)

        driver = _Driver(network, [backend])
        driver.start()
        try:
            deadline = time.monotonic() + 1.0
            while time.monotonic() < deadline and not backend.node.is_leader:
                time.sleep(0.01)
            assert backend.node.is_leader

            updates = [_make_update('srv1', 0.9)]
            block = backend.commit(updates)
            assert block is not None
            assert block.trust_updates == updates
            assert block.raft_term == backend.node.current_term
            assert backend.chain_length() == 2
            assert backend.verify()
        finally:
            driver.stop()

    def test_commit_with_no_updates_returns_none(self) -> None:
        network = InMemoryNetwork(rng=random.Random(0))
        backend = RaftBackend('n1', peers=[], transport=network, **FAST_TIMING)
        network.register(backend)
        assert backend.commit([]) is None

    def test_status_reports_role_and_chain_length(self) -> None:
        network = InMemoryNetwork(rng=random.Random(0))
        backend = RaftBackend('n1', peers=[], transport=network, **FAST_TIMING)
        network.register(backend)
        driver = _Driver(network, [backend])
        driver.start()
        try:
            deadline = time.monotonic() + 1.0
            while time.monotonic() < deadline and not backend.node.is_leader:
                time.sleep(0.01)
            status = backend.status()
            assert status['node_id'] == 'n1'
            assert status['role'] == 'leader'
            assert status['chain_length'] == 1
        finally:
            driver.stop()


class TestRaftBackendCluster:
    """A real 3-replica cluster, driven on a background thread."""

    def test_commit_replicates_the_identical_block_to_every_replica(self) -> None:
        network, backends = _make_cluster(['n1', 'n2', 'n3'])
        driver = _Driver(network, list(backends.values()))
        driver.start()
        try:
            leader = _wait_for_leader(backends)
            updates = [_make_update('srv1', 0.77)]
            block = leader.commit(updates)
            assert block is not None
            assert block.trust_updates == updates

            deadline = time.monotonic() + 1.0
            while time.monotonic() < deadline and any(
                b.chain_length() < 2 for b in backends.values()
            ):
                time.sleep(0.01)

            for backend in backends.values():
                assert backend.chain_length() == 2, f"{backend.node_id} never applied the block"
                assert backend.verify()
            hashes = {b.ledger.head_hash() for b in backends.values()}
            assert len(hashes) == 1, f"replicas built different block hashes: {hashes}"
        finally:
            driver.stop()

    def test_follower_commit_returns_none_immediately(self) -> None:
        network, backends = _make_cluster(['n1', 'n2', 'n3'])
        driver = _Driver(network, list(backends.values()))
        driver.start()
        try:
            leader = _wait_for_leader(backends)
            follower = next(b for b in backends.values() if b is not leader)
            assert follower.commit([_make_update()]) is None
            assert follower.chain_length() == 1
        finally:
            driver.stop()

    def test_commit_times_out_when_no_majority_is_reachable(self) -> None:
        network, backends = _make_cluster(['n1', 'n2', 'n3'], commit_timeout_s=0.3)
        driver = _Driver(network, list(backends.values()))
        driver.start()
        try:
            leader = _wait_for_leader(backends)
            for backend in backends.values():
                if backend is not leader:
                    network.crash(backend.node_id)

            started = time.monotonic()
            result = leader.commit([_make_update()])
            elapsed = time.monotonic() - started

            assert result is None
            assert elapsed < 1.0, "commit() should give up at commit_timeout_s, not hang"
            # The entry was appended to the leader's own log even though it
            # never committed -- RAFT leaders always append locally first.
            assert leader.node.last_log_index >= 1
            assert leader.chain_length() == 1, "an uncommitted entry must not reach the ledger"
        finally:
            driver.stop()

    def test_killing_the_leader_lets_the_cluster_recover_and_keep_committing(self) -> None:
        network, backends = _make_cluster(['n1', 'n2', 'n3'])
        driver = _Driver(network, list(backends.values()))
        driver.start()
        try:
            first_leader = _wait_for_leader(backends)
            block1 = first_leader.commit([_make_update('srv1', 0.5)])
            assert block1 is not None

            # Let the followers actually apply block1 (RAFT commits it on the
            # leader as soon as a majority has the entry in their *log*; a
            # follower only applies it -- updates its own ledger -- on the
            # next heartbeat's leader_commit). Otherwise whichever survivor
            # becomes the next leader might not have appended block1 to its
            # own ledger yet when it proposes block2.
            deadline = time.monotonic() + 1.0
            while time.monotonic() < deadline and any(
                b.chain_length() < 2 for b in backends.values()
            ):
                time.sleep(0.01)

            network.crash(first_leader.node_id)

            deadline = time.monotonic() + 2.0
            new_leader = None
            while time.monotonic() < deadline:
                candidates = [
                    b for b in backends.values()
                    if b.node_id != first_leader.node_id and b.node.is_leader
                ]
                if candidates:
                    new_leader = candidates[0]
                    break
                time.sleep(0.01)
            assert new_leader is not None, "no new leader elected after killing the old one"

            block2 = new_leader.commit([_make_update('srv2', 0.6)])
            assert block2 is not None

            survivors = [b for b in backends.values() if b.node_id != first_leader.node_id]
            deadline = time.monotonic() + 1.0
            while time.monotonic() < deadline and any(b.chain_length() < 3 for b in survivors):
                time.sleep(0.01)
            for backend in survivors:
                assert backend.chain_length() == 3
                assert backend.verify()
        finally:
            driver.stop()
