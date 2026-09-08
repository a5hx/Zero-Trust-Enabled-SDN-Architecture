"""Trust-ledger commit seam.

The controller batches TrustUpdate records and hands them to this interface. Sprint 1
runs `LocalLedgerBackend`, which appends directly to the in-memory chain. Sprint 3
implements RAFT in `blockchain/raft.py` and drops in `RaftBackend` below — the
controller does not change.

`Block.raft_term` already exists in the schema and is already inside the block's hash
preimage (see contracts/block_schema.py::compute_hash), so a RAFT backend can populate
the term without altering how blocks hash.
"""

import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Protocol, Sequence

from blockchain.block import build_block
from blockchain.ledger import Ledger
from blockchain.raft import LogEntry, RaftNode, Transport
from contracts.block_schema import Block
from contracts.trust_update import TrustUpdate

logger = logging.getLogger(__name__)


class CommitBackend(Protocol):
    """What the controller needs from any ledger backend."""

    def commit(self, updates: List[TrustUpdate]) -> Optional[Block]:
        """Durably record a batch of trust updates as a block.

        Returns:
            The committed Block, or None if the commit was rejected.
        """
        ...

    def latest_score(self, node_id: str) -> Optional[float]:
        """Most recent trust score recorded for a node, or None if never seen."""
        ...

    def verify(self) -> bool:
        """Full-chain integrity check (backs GET /ledger/verify)."""
        ...

    def chain_length(self) -> int:
        ...


class TimingCommitBackend:
    """Wraps any CommitBackend and times each real commit() call.

    Built for the live full-scale demo's blockchain-overhead NFR
    (`evaluation/nfr_report.py`, <15%). Nothing else in the controller times a
    commit: `handle_client_report` (controller/trust_balancer.py) calls
    straight into `TrustState.record_task_outcome`, which only commits every
    `max_updates_per_block`-th report (see `_flush_pending_locked`), so there
    is no other seam to isolate "this /report happened to trigger a block
    commit" from one that didn't. `commit_count` lets the caller detect which
    of its own calls triggered a commit without changing `commit()`'s return
    type.
    """

    def __init__(
        self,
        inner: CommitBackend,
        on_commit: Optional[Callable[[Optional[Block], float, int], None]] = None,
    ) -> None:
        self._inner = inner
        self._on_commit = on_commit
        self.commit_count = 0

    def commit(self, updates: List[TrustUpdate]) -> Optional[Block]:
        if not updates:
            return self._inner.commit(updates)

        self.commit_count += 1
        start = time.monotonic()
        block = self._inner.commit(updates)
        elapsed_ms = (time.monotonic() - start) * 1000.0
        if self._on_commit is not None:
            self._on_commit(block, elapsed_ms, len(updates))
        return block

    def latest_score(self, node_id: str) -> Optional[float]:
        return self._inner.latest_score(node_id)

    def verify(self) -> bool:
        return self._inner.verify()

    def chain_length(self) -> int:
        return self._inner.chain_length()

    @property
    def ledger(self) -> Ledger:
        return self._inner.ledger  # type: ignore[attr-defined]


class LocalLedgerBackend:
    """Single-replica backend: append straight to the in-memory Ledger.

    Thread-safe, because the controller commits from OpenFlow event handlers while
    the REST API reads from its own HTTP threads (os-ken's hub is `native`, i.e.
    real OS threads).
    """

    def __init__(self, ledger: Optional[Ledger] = None, proposer_id: str = 'controller') -> None:
        self._ledger = ledger if ledger is not None else Ledger()
        self._proposer_id = proposer_id
        self._lock = threading.Lock()

    @property
    def ledger(self) -> Ledger:
        return self._ledger

    def commit(self, updates: List[TrustUpdate]) -> Optional[Block]:
        if not updates:
            return None

        with self._lock:
            block = build_block(
                index=self._ledger.get_chain_length(),
                previous_hash=self._ledger.head_hash(),
                updates=list(updates),
                proposer_id=self._proposer_id,
            )
            if not self._ledger.append(block):
                logger.error("Block %d REJECTED by ledger", block.index)
                return None

        logger.info("Block %d committed (%d updates)", block.index, len(updates))
        return block

    def latest_score(self, node_id: str) -> Optional[float]:
        with self._lock:
            return self._ledger.latest_trust_score(node_id)

    def verify(self) -> bool:
        with self._lock:
            return self._ledger.is_valid_chain()

    def chain_length(self) -> int:
        with self._lock:
            return self._ledger.get_chain_length()


# --------------------------------------------------------------------------- #
# RAFT log-entry payload                                                       #
# --------------------------------------------------------------------------- #
def _entry_payload(
    updates: List[TrustUpdate], proposer_id: str, raft_term: int, timestamp: float,
) -> Dict[str, Any]:
    """What actually replicates for one commit: *content* only -- never a
    position in the chain.

    It is tempting to have the leader build the whole Block up front (index,
    previous_hash, merkle_root, hash) and replicate that, so every replica
    just appends an identical object. That was tried and breaks: a
    newly-elected leader is only guaranteed to have every entry in its RAFT
    *log* (Election Safety), not to have already *applied* every earlier
    entry to its own `Ledger` -- entries commit indirectly, in a batch, once a
    higher-term entry above them commits (`RaftNode._advance_commit_index`'s
    current-term restriction). So a fresh leader's `_ledger.get_chain_length()`
    can be stale at the moment it proposes, and two replicas would build
    colliding `index`/`previous_hash` values for what RAFT correctly ordered
    as two different log entries.

    The fix: `index`, `previous_hash`, and `merkle_root` are recomputed by
    *each* replica inside `RaftBackend._on_apply`, never put on the wire --
    that is safe because `RaftNode._apply_committed` always applies entries
    one at a time, in strict log order, so by the time entry N is applied,
    entry N-1's block (if it had a payload) is already in that same replica's
    ledger. `merkle_root` doesn't need to travel either: it's a pure function
    of `trust_updates`, which does travel. `timestamp` is the one exception --
    it has no canonical source other than "when the leader proposed it," and
    it sits inside the hash preimage (`Block.compute_hash`), so every replica
    must use the identical value or they hash the "same" block differently.
    """
    return {
        'timestamp': timestamp,
        'proposer_id': proposer_id,
        'raft_term': raft_term,
        'trust_updates': [u.to_dict() for u in updates],
    }


# --------------------------------------------------------------------------- #
# RaftBackend                                                                  #
# --------------------------------------------------------------------------- #
class RaftBackend:
    """CommitBackend backed by real RAFT replication (blockchain/raft.py).

    Owns its own RaftNode (built here, not passed in, so this class can wire
    the node's `apply_fn` to its own `_on_apply` bound method at construction)
    and turns RAFT's async, log-index-based commit signal into the synchronous
    `commit() -> Optional[Block]` this Protocol promises.

    `transport` can be blockchain.raft's own `InMemoryNetwork` (for tests --
    the safety properties are already proven there, see tests/test_raft.py) or
    `blockchain.raft_transport.TcpTransport` (for a live cluster). Either way
    RaftBackend and RaftNode are unchanged; that is the point of the Transport
    seam. This class does not start any threads itself -- see
    `blockchain/raft_replica.py` for the driver that calls `drive_tick`
    periodically and wires a transport's inbound messages to `drive_receive`.

    Only the leader can commit, mirroring RaftNode.client_append's leader-only
    contract: a follower's commit() returns None immediately, same as a
    rejected commit. There is deliberately no client-side redirect-to-leader
    here -- a caller that wants to survive a leadership change must itself
    retry, using `node.leader_id` as a hint. That is a documented scope limit
    (see docs/RAFT.md), not an oversight: this project runs one active
    committer at a time, and the "kill one, watch it recover" demo kills a
    non-leader or restarts the whole client loop, rather than proving seamless
    mid-flight client failover -- a materially larger, separate problem.

    Thread-safety: `drive_tick`/`drive_receive` run on a driver thread while
    `commit()` is called from the controller thread. `_lock` (an RLock: RAFT's
    own `apply_fn` callback, `_on_apply`, re-enters it from inside whatever
    call is already holding it -- `tick`, `receive`, or `client_append`)
    guards all RaftNode/Ledger access. `commit()` releases `_lock` while it
    waits for its entry to commit -- holding it there would deadlock the
    driver thread trying to process the very AppendEntriesReply that completes
    that commit -- so a second lock, `_commit_lock`, serializes whole
    `commit()` calls end-to-end; without it, two interleaved proposals could
    both read the same (stale) ledger tip before either commits.
    """

    def __init__(
        self,
        node_id: str,
        peers: Sequence[str],
        transport: Transport,
        ledger: Optional[Ledger] = None,
        proposer_id: Optional[str] = None,
        commit_timeout_s: float = 2.0,
        clock: Callable[[], float] = time.monotonic,
        **raft_node_kwargs: Any,
    ) -> None:
        self._ledger = ledger if ledger is not None else Ledger()
        self._proposer_id = proposer_id or node_id
        self._commit_timeout_s = commit_timeout_s
        self._clock = clock
        self._lock = threading.RLock()
        self._commit_lock = threading.Lock()
        self._waiters: Dict[int, threading.Event] = {}
        self._results: Dict[int, Optional[Block]] = {}
        self.node = RaftNode(
            node_id=node_id, peers=peers, transport=transport,
            apply_fn=self._on_apply, **raft_node_kwargs,
        )

    # -- driver hooks (see blockchain/raft_replica.py) -------------------- #
    def drive_tick(self, now: Optional[float] = None) -> None:
        with self._lock:
            self.node.tick(self._clock() if now is None else now)

    def drive_receive(self, message: Any, now: Optional[float] = None) -> None:
        with self._lock:
            self.node.receive(message, self._clock() if now is None else now)

    @property
    def node_id(self) -> str:
        return self.node.node_id

    def receive(self, message: Any, now: float) -> None:
        """Alias for drive_receive with RaftNode's own (node_id, receive)
        shape, so a RaftBackend can be registered directly with
        blockchain.raft.InMemoryNetwork -- used by tests; a live TCP
        deployment instead points TcpTransport.on_message at drive_receive
        (see blockchain/raft_replica.py)."""
        self.drive_receive(message, now)

    # -- CommitBackend ------------------------------------------------------ #
    def commit(self, updates: List[TrustUpdate]) -> Optional[Block]:
        if not updates:
            return None

        with self._commit_lock:
            with self._lock:
                if not self.node.is_leader:
                    return None
                payload = _entry_payload(
                    updates=list(updates), proposer_id=self._proposer_id,
                    raft_term=self.node.current_term, timestamp=time.time(),
                )
                index = self.node.client_append(payload, now=self._clock())
                if index is None:
                    return None
                if index in self._results:
                    # Committed synchronously inside client_append (e.g. a
                    # single-node cluster commits against itself immediately)
                    # -- _on_apply already ran before client_append returned,
                    # so there is nothing left to wait for.
                    return self._results.pop(index)
                event = threading.Event()
                self._waiters[index] = event

            if not event.wait(timeout=self._commit_timeout_s):
                with self._lock:
                    self._waiters.pop(index, None)
                logger.warning(
                    "%s: commit timed out after %.2fs (log index %d)",
                    self.node.node_id, self._commit_timeout_s, index,
                )
                return None
            with self._lock:
                return self._results.pop(index, None)

    def _on_apply(self, entry: LogEntry) -> None:
        """RaftNode's apply_fn: fires once per committed entry, in log order,
        on every replica (leader included, via its own commit_index advancing).

        `index`/`previous_hash` come from `self._ledger` *right now*, not from
        anything the leader precomputed -- see `_entry_payload`'s docstring for
        why that is the part that must be decided locally, per replica, at
        apply time.
        """
        block: Optional[Block] = None
        if entry.payload is not None:
            try:
                updates = [TrustUpdate(**u) for u in entry.payload['trust_updates']]
            except (KeyError, TypeError) as exc:
                logger.error(
                    "%s: could not decode committed entry %d (%s)",
                    self.node.node_id, entry.index, exc,
                )
            else:
                with self._lock:
                    block = build_block(
                        index=self._ledger.get_chain_length(),
                        previous_hash=self._ledger.head_hash(),
                        updates=updates,
                        proposer_id=entry.payload['proposer_id'],
                        raft_term=entry.payload['raft_term'],
                        timestamp=entry.payload['timestamp'],
                    )
                    if not self._ledger.append(block):
                        logger.error(
                            "%s: ledger rejected committed block %d (log index %d)",
                            self.node.node_id, block.index, entry.index,
                        )
                        block = None

        with self._lock:
            self._results[entry.index] = block
            event = self._waiters.pop(entry.index, None)
        if event is not None:
            event.set()

    def latest_score(self, node_id: str) -> Optional[float]:
        with self._lock:
            return self._ledger.latest_trust_score(node_id)

    def verify(self) -> bool:
        with self._lock:
            return self._ledger.is_valid_chain()

    def chain_length(self) -> int:
        with self._lock:
            return self._ledger.get_chain_length()

    @property
    def ledger(self) -> Ledger:
        return self._ledger

    def status(self) -> Dict[str, Any]:
        """Snapshot for the live demo's control API (blockchain/raft_replica.py)."""
        with self._lock:
            return {
                'node_id': self.node.node_id,
                'role': self.node.role.value,
                'term': self.node.current_term,
                'leader_id': self.node.leader_id,
                'commit_index': self.node.commit_index,
                'chain_length': self._ledger.get_chain_length(),
            }
