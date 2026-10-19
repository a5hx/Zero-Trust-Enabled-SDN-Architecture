"""Trust-ledger commit seam.

The controller batches TrustUpdate records and hands them to this interface. Sprint 1
runs `LocalLedgerBackend`, which appends directly to the in-memory chain. Sprint 3
implements RAFT in `blockchain/raft.py` and drops in `RaftBackend` below — the
controller does not change.

`Block.raft_term` already exists in the schema and is already inside the block's hash
preimage (see contracts/block_schema.py::compute_hash), so a RAFT backend can populate
the term without altering how blocks hash.
"""

import collections
import hashlib
import http.client
import json
import logging
import threading
import time
from typing import Any, Callable, Deque, Dict, List, Optional, Protocol, Sequence, Tuple

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
def batch_key(updates: Sequence[TrustUpdate]) -> str:
    """Content hash of a batch -- the idempotency key for a RAFT commit.

    A client that times out waiting for a commit cannot tell "never happened"
    from "happened, but the reply was lost", so it must be able to retry
    safely. Keying on content (every TrustUpdate carries its own timestamp, so
    two genuinely different batches never collide) lets every replica
    recognise a retry deterministically from the log alone, with no client
    session state to replicate.
    """
    canonical = json.dumps([u.to_dict() for u in updates], sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


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
        'batch_key': batch_key(updates),
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
        # batch_key -> block index, rebuilt from the log on every replica as
        # entries apply, so a retried batch never becomes a second block.
        self._applied_batches: Dict[str, int] = {}
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
                # A retry of a batch that already committed (the caller never
                # saw the reply) gets the existing block back, not a new one.
                done = self._applied_batches.get(batch_key(updates))
                if done is not None:
                    return self._ledger.block_at(done)
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
                key = entry.payload.get('batch_key') or batch_key(updates)
                with self._lock:
                    done = self._applied_batches.get(key)
                    if done is not None:
                        # The same batch was proposed twice (a client retry
                        # raced its own first attempt) and both entries
                        # committed. Apply is in log order on every replica,
                        # so all of them skip the same second copy.
                        logger.info(
                            "%s: log index %d repeats an already-applied batch "
                            "(block %d) -- not appended again",
                            self.node.node_id, entry.index, done,
                        )
                        block = self._ledger.block_at(done)
                    else:
                        block = build_block(
                            index=self._ledger.get_chain_length(),
                            previous_hash=self._ledger.head_hash(),
                            updates=updates,
                            proposer_id=entry.payload['proposer_id'],
                            raft_term=entry.payload['raft_term'],
                            timestamp=entry.payload['timestamp'],
                        )
                        if self._ledger.append(block):
                            self._applied_batches[key] = block.index
                        else:
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

    def blocks_from(self, start: int) -> List[Block]:
        """This replica's applied blocks from `start` on (GET /blocks)."""
        with self._lock:
            return self._ledger.blocks_from(start)

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


# --------------------------------------------------------------------------- #
# RemoteRaftBackend: the controller as a client of a separate RAFT cluster      #
# --------------------------------------------------------------------------- #
Address = Tuple[str, int]


def parse_replicas(spec: Any) -> Dict[str, Address]:
    """Replica control-API addresses from config.

    Accepts a mapping ``{r1: "127.0.0.1:9101", ...}`` or a list
    ``["r1=127.0.0.1:9101", ...]``. Keys must be the replicas' RAFT node IDs,
    because a non-leader names the leader by that ID.
    """
    items: List[Tuple[str, str]]
    if isinstance(spec, dict):
        items = [(str(k), str(v)) for k, v in spec.items()]
    else:
        items = [tuple(str(s).split('=', 1)) for s in spec]  # type: ignore[misc]
    out: Dict[str, Address] = {}
    for rid, addr in items:
        host, port = addr.rsplit(':', 1)
        out[rid] = (host, int(port))
    if not out:
        raise ValueError('ledger.replicas is empty')
    return out


class RemoteRaftBackend:
    """CommitBackend for a controller that commits to a *separate* RAFT cluster.

    Each replica is a `blockchain/raft_replica.py` process (later, a separate
    machine) with its own ticker thread, so nothing in the controller has to
    drive elections. The controller talks to the replicas' HTTP control API:

    * ``POST /commit`` on the replica it believes is leader. A non-leader (or a
      leader that could not reach a majority in time) answers 409 with its
      status, whose ``leader_id`` is followed as a hint.
    * ``GET /blocks?from=N`` to fill a gap or rebuild the local mirror.

    Every committed block comes back in full and is appended to a local
    *mirror* `Ledger`, which re-validates index, previous_hash, Merkle root and
    hash itself -- the controller never takes a replica's word for a block. The
    mirror backs `/ledger/verify`, `latest_score` and the dashboard, exactly as
    the local ledger did. The cluster is the source of truth: if the mirror and
    the cluster ever disagree, the mirror is rebuilt from the cluster.

    `commit()` blocks for up to `deadline_s` and returns None when no replica
    commits the batch in that time. It is meant to sit behind `AsyncCommitter`,
    which keeps it off the request path and retries; a retry of a batch that
    did commit is answered with the existing block (`batch_key`), so retrying
    never duplicates trust records.
    """

    def __init__(
        self,
        replicas: Dict[str, Address],
        request_timeout_s: float = 3.0,
        deadline_s: float = 5.0,
        auth_token: Optional[str] = None,
        ledger: Optional[Ledger] = None,
    ) -> None:
        self._replicas = dict(replicas)
        self._order = list(replicas)
        self._timeout = request_timeout_s
        self._deadline = deadline_s
        self._token = auth_token
        self._mirror = ledger if ledger is not None else Ledger()
        self._lock = threading.Lock()
        self._leader: Optional[str] = None
        self.last_error: Optional[str] = None
        self.resyncs = 0

    # -- HTTP --------------------------------------------------------------- #
    def _request(self, rid: str, method: str, path: str,
                 body: Optional[Any] = None) -> Tuple[int, Dict[str, Any]]:
        host, port = self._replicas[rid]
        conn = http.client.HTTPConnection(host, port, timeout=self._timeout)
        try:
            headers = {'Content-Type': 'application/json'}
            if self._token:
                headers['Authorization'] = f'Bearer {self._token}'
            data = json.dumps(body).encode() if body is not None else None
            conn.request(method, path, body=data, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else {})
        finally:
            conn.close()

    def _candidates(self) -> List[str]:
        order = list(self._order)
        if self._leader in order:
            order.remove(self._leader)
            order.insert(0, self._leader)
        return order

    # -- mirror ------------------------------------------------------------- #
    def _fetch_blocks(self, rid: str, start: int) -> List[Block]:
        status, payload = self._request(rid, 'GET', f'/blocks?from={start}')
        if status != 200:
            raise OSError(f'GET /blocks from {rid}: HTTP {status}')
        return [Block.from_dict(b) for b in payload.get('blocks', [])]

    def _rebuild_mirror(self, rid: str) -> bool:
        """Replace the mirror with a freshly validated copy of `rid`'s chain."""
        try:
            blocks = self._fetch_blocks(rid, 1)
        except (OSError, http.client.HTTPException, ValueError, KeyError, TypeError) as exc:
            self.last_error = f'{rid}: resync failed: {exc}'
            return False
        fresh = Ledger()
        for b in blocks:
            if not fresh.append(b):
                self.last_error = f'{rid}: chain from replica failed validation at block {b.index}'
                logger.error("RemoteRaftBackend: %s", self.last_error)
                return False
        with self._lock:
            self._mirror = fresh
        self.resyncs += 1
        logger.warning("RemoteRaftBackend: mirror rebuilt from %s (%d blocks)", rid, len(blocks))
        return True

    def _accept(self, rid: str, block: Block) -> Optional[Block]:
        """Bring the mirror up to `block` and return the mirror's copy of it."""
        with self._lock:
            n = self._mirror.get_chain_length()
            if block.index == n and self._mirror.append(block):
                return block
            have = self._mirror.block_at(block.index)
            if have is not None and have.hash == block.hash:
                return have  # a retry answered with a block we already hold
        # Gap or disagreement: the cluster is the source of truth.
        if self._rebuild_mirror(rid):
            with self._lock:
                have = self._mirror.block_at(block.index)
            if have is not None and have.hash == block.hash:
                return have
        return None

    def sync(self) -> bool:
        """Catch the mirror up with the cluster (e.g. a controller restarting
        against replicas that kept their logs). Best effort; never raises."""
        for rid in self._candidates():
            try:
                with self._lock:
                    start = self._mirror.get_chain_length()
                blocks = self._fetch_blocks(rid, start)
            except (OSError, http.client.HTTPException, ValueError, KeyError, TypeError) as exc:
                self.last_error = f'{rid}: {exc}'
                continue
            with self._lock:
                ok = all(self._mirror.append(b) for b in blocks)
            return ok or self._rebuild_mirror(rid)
        return False

    # -- CommitBackend ------------------------------------------------------ #
    def commit(self, updates: List[TrustUpdate]) -> Optional[Block]:
        if not updates:
            return None
        body = {'updates': [u.to_dict() for u in updates]}
        deadline = time.monotonic() + self._deadline
        queue = self._candidates()
        followed: set = set()
        while queue and time.monotonic() < deadline:
            rid = queue.pop(0)
            try:
                status, payload = self._request(rid, 'POST', '/commit', body)
            except (OSError, http.client.HTTPException, ValueError) as exc:
                self.last_error = f'{rid}: {exc}'
                if self._leader == rid:
                    self._leader = None
                continue
            if status == 200 and payload.get('ok') and 'block' in payload:
                self._leader = rid
                try:
                    block = Block.from_dict(payload['block'])
                except (KeyError, TypeError, ValueError) as exc:
                    self.last_error = f'{rid}: malformed block in reply: {exc}'
                    continue
                accepted = self._accept(rid, block)
                if accepted is not None:
                    self.last_error = None
                return accepted
            if status == 409:
                hint = (payload.get('status') or {}).get('leader_id')
                self.last_error = f'{rid}: not leader (hint {hint})'
                if hint in self._replicas and hint != rid and hint not in followed:
                    followed.add(hint)
                    if hint in queue:
                        queue.remove(hint)
                    queue.insert(0, hint)
                continue
            self.last_error = f'{rid}: HTTP {status}'
        return None

    def latest_score(self, node_id: str) -> Optional[float]:
        with self._lock:
            return self._mirror.latest_trust_score(node_id)

    def verify(self) -> bool:
        with self._lock:
            return self._mirror.is_valid_chain()

    def chain_length(self) -> int:
        with self._lock:
            return self._mirror.get_chain_length()

    @property
    def ledger(self) -> Ledger:
        with self._lock:
            return self._mirror

    def status(self) -> Dict[str, Any]:
        with self._lock:
            length = self._mirror.get_chain_length()
        return {
            'backend': 'raft_remote',
            'replicas': {rid: f'{h}:{p}' for rid, (h, p) in self._replicas.items()},
            'leader_hint': self._leader,
            'mirror_chain_length': length,
            'mirror_resyncs': self.resyncs,
            'last_error': self.last_error,
        }


# --------------------------------------------------------------------------- #
# AsyncCommitter: ledger commits off the request path                          #
# --------------------------------------------------------------------------- #
class AsyncCommitter:
    """Queues commits and performs them on one background worker, in order.

    The controller reaches `commit()` from the client-report path
    (`TrustState._flush_pending_locked`), which runs on request threads with
    the trust-state lock held. A replicated commit can take a network round
    trip, or seconds during a leader election, so it must never run there.
    `commit()` here copies the batch, enqueues it and returns at once.

    The worker retries a failed batch with exponential backoff and only moves
    on once the inner backend accepts it, so a leadership change delays trust
    records but does not lose them -- the gap that made the in-process
    `RaftBackend` unsafe to wire in (its `None` was silently discarded). Order
    is preserved: one worker, FIFO.

    `commit()` returns None because the block does not exist yet; block
    events come from the inner backend's own callback (`TimingCommitBackend`)
    when the commit really happens. `commit_count` counts batches *submitted*,
    which is what `TrustBalancerApp.handle_client_report` uses to mark the
    report that triggered a flush.
    """

    def __init__(
        self,
        inner: CommitBackend,
        max_queue: int = 10_000,
        backoff_initial_s: float = 0.1,
        backoff_max_s: float = 2.0,
        start: bool = True,
    ) -> None:
        self._inner = inner
        self._queue: Deque[List[TrustUpdate]] = collections.deque()
        self._cond = threading.Condition()
        self._max_queue = max_queue
        self._backoff_initial = backoff_initial_s
        self._backoff_max = backoff_max_s
        self._busy = False
        self._stopping = False
        # Backoff sleeps on this, not on _cond: new submissions notify _cond,
        # and must not cut a retry's backoff short during an outage.
        self._stop_event = threading.Event()
        self.submitted = 0
        self.committed = 0
        self.retries = 0
        self.dropped = 0
        self._thread = threading.Thread(target=self._run, daemon=True, name='ledger-committer')
        if start:
            self._thread.start()

    @property
    def commit_count(self) -> int:
        return self.submitted

    def commit(self, updates: List[TrustUpdate]) -> Optional[Block]:
        if not updates:
            return None
        batch = list(updates)  # the caller clears its list as soon as we return
        with self._cond:
            if len(self._queue) >= self._max_queue:
                # Explicit and counted, never silent: this only happens after
                # the cluster has been unreachable for a long time.
                self.dropped += 1
                logger.error(
                    "AsyncCommitter: queue full (%d batches) -- dropping a batch of %d updates",
                    self._max_queue, len(batch),
                )
                return None
            self._queue.append(batch)
            self.submitted += 1
            self._cond.notify_all()
        return None

    def _run(self) -> None:
        backoff = self._backoff_initial
        while True:
            with self._cond:
                while not self._queue and not self._stopping:
                    self._cond.wait()
                if not self._queue:
                    return
                batch = self._queue[0]
                self._busy = True
            try:
                block = self._inner.commit(batch)
            except Exception:  # never let one bad batch kill the worker
                logger.exception("AsyncCommitter: commit raised; will retry")
                block = None
            with self._cond:
                self._busy = False
                if block is not None:
                    self._queue.popleft()
                    self.committed += 1
                    backoff = self._backoff_initial
                    self._cond.notify_all()
                    continue
                self.retries += 1
                if self._stopping:
                    logger.error(
                        "AsyncCommitter: stopping with %d uncommitted batch(es)", len(self._queue),
                    )
                    return
            self._stop_event.wait(timeout=backoff)
            backoff = min(backoff * 2, self._backoff_max)

    def pending(self) -> int:
        """Batches not yet committed, including the one being attempted."""
        with self._cond:
            return len(self._queue)

    def flush(self, timeout: float = 10.0) -> bool:
        """Wait until every submitted batch is committed. True if it drained."""
        end = time.monotonic() + timeout
        with self._cond:
            while self._queue or self._busy:
                remaining = end - time.monotonic()
                if remaining <= 0:
                    return False
                self._cond.wait(timeout=remaining)
        return True

    def close(self, timeout: float = 10.0) -> bool:
        drained = self.flush(timeout)
        with self._cond:
            self._stopping = True
            self._cond.notify_all()
        self._stop_event.set()
        if self._thread.is_alive():
            self._thread.join(timeout=2.0)
        return drained

    # -- pass-throughs ------------------------------------------------------ #
    def latest_score(self, node_id: str) -> Optional[float]:
        return self._inner.latest_score(node_id)

    def verify(self) -> bool:
        return self._inner.verify()

    def chain_length(self) -> int:
        return self._inner.chain_length()

    @property
    def ledger(self) -> Ledger:
        return self._inner.ledger  # type: ignore[attr-defined]

    def status(self) -> Dict[str, Any]:
        with self._cond:
            out: Dict[str, Any] = {
                'queue_depth': len(self._queue),
                'submitted': self.submitted,
                'committed': self.committed,
                'retries': self.retries,
                'dropped': self.dropped,
            }
        inner_status = _status_of(self._inner)
        if inner_status:
            out.update(inner_status)
        return out


def _status_of(backend: Any) -> Dict[str, Any]:
    """Walk wrapper layers (TimingCommitBackend keeps its inner as `_inner`)
    to the first backend that reports a status."""
    seen = 0
    while backend is not None and seen < 5:
        status = getattr(backend, 'status', None)
        if callable(status):
            return status()
        backend = getattr(backend, '_inner', None)
        seen += 1
    return {}


def build_commit_backend(
    ledger_cfg: Optional[Dict[str, Any]],
    on_commit: Optional[Callable[[Optional[Block], float, int], None]] = None,
) -> Any:
    """The controller's ledger backend, chosen by the config's `ledger:` block.

    * absent, or ``backend: local`` -- the single in-memory ledger every live
      run so far has used, committed synchronously (unchanged behaviour).
    * ``backend: raft_remote`` -- commits replicated by a separate RAFT cluster
      (``replicas:``), queued off the request path by `AsyncCommitter`.

    Both are wrapped in `TimingCommitBackend`, so 'block' events and the
    blockchain-overhead NFR keep working either way.
    """
    cfg = ledger_cfg or {}
    kind = cfg.get('backend', 'local')
    if kind == 'local':
        return TimingCommitBackend(LocalLedgerBackend(), on_commit=on_commit)
    if kind == 'raft_remote':
        token_env = cfg.get('auth_token_env')
        token = None
        if token_env:
            import os
            token = os.environ.get(token_env) or None
        remote = RemoteRaftBackend(
            parse_replicas(cfg['replicas']),
            request_timeout_s=float(cfg.get('request_timeout_s', 3.0)),
            deadline_s=float(cfg.get('commit_deadline_s', 5.0)),
            auth_token=token,
        )
        remote.sync()
        return AsyncCommitter(
            TimingCommitBackend(remote, on_commit=on_commit),
            max_queue=int(cfg.get('max_queue', 10_000)),
        )
    raise ValueError(f"unknown ledger.backend {kind!r} (expected 'local' or 'raft_remote')")
