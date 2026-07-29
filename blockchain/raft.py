"""RAFT consensus for replicating the trust ledger.

A transport-agnostic implementation of RAFT (D. Ongaro and J. Ousterhout, "In
Search of an Understandable Consensus Algorithm," USENIX ATC 2014), built and
tested in isolation as the SRS requires.

Scope and layering
------------------
This module implements the *consensus core* only: leader election, log
replication, and the commit rule. It knows nothing about blocks, trust, or
sockets. A ``LogEntry`` carries an opaque ``payload``, and committed entries are
handed to an ``apply`` callback in log order, exactly once per replica.

That callback is the seam to the rest of the system. A future ``RaftBackend``
(see ``blockchain/commit_backend.py``) will apply each committed entry by
building a ``Block`` from its payload and appending it to the local ``Ledger``,
populating ``Block.raft_term`` from ``LogEntry.term`` -- which is already inside
the block's hash preimage (``contracts/block_schema.py::compute_hash``), so
replication does not change how blocks hash.

**Nothing in the running controller is wired to this module yet.**
``LocalLedgerBackend`` remains the only backend in use; the swap is a separate,
later step.

Determinism
-----------
``RaftNode`` reads no wall clock and touches no global RNG. Time enters through
``tick(now)`` and ``receive(msg, now)``; randomness enters through an injected
``random.Random``. A whole cluster can therefore be driven by a virtual clock and
replayed exactly. ``InMemoryNetwork`` and ``RaftCluster`` at the bottom of this
module are that driver -- the reference transport, with injectable message loss,
delay, and partitions, used by ``tests/test_raft.py`` to exercise the safety
properties. A TCP transport can satisfy the same ``Transport`` protocol without
``RaftNode`` changing at all.

Safety properties the tests assert (paper Figure 3)
---------------------------------------------------
1. **Election Safety** -- at most one leader per term.
2. **Leader Append-Only** -- a leader never overwrites or deletes its own log.
3. **Log Matching** -- if two logs hold an entry with the same index and term,
   the logs are identical in all entries up through that index.
4. **Leader Completeness** -- an entry committed in some term is present in the
   log of every higher-term leader.
5. **State Machine Safety** -- no two replicas apply different entries at the
   same log index.

Deliberately out of scope for this milestone: log compaction / snapshotting,
cluster membership changes, and persistence to disk. ``current_term``,
``voted_for``, and ``log`` are held in memory, which matches the crash-fault
(not Byzantine) model this project claims -- see ``PROBLEM_AND_IMPACT.md`` §4.
"""

import heapq
import logging
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Protocol, Sequence, Set, Tuple

logger = logging.getLogger(__name__)

# Defaults follow the paper's guidance: an election timeout an order of
# magnitude above the heartbeat interval, randomised over a 2x spread so
# split votes resolve quickly.
DEFAULT_HEARTBEAT_INTERVAL = 0.05
DEFAULT_ELECTION_TIMEOUT_MIN = 0.15
DEFAULT_ELECTION_TIMEOUT_MAX = 0.30


class Role(Enum):
    """The three states a RAFT server can be in."""

    FOLLOWER = 'follower'
    CANDIDATE = 'candidate'
    LEADER = 'leader'


@dataclass(frozen=True)
class LogEntry:
    """One replicated log entry.

    Attributes:
        term: Term of the leader that created this entry. Used by the commit
            rule and by the log-matching check.
        index: Position in the log. 1-based; index 0 is the sentinel.
        payload: Opaque application data. The trust ledger will put a batch of
            TrustUpdate records here.
    """

    term: int
    index: int
    payload: Any = None


# --------------------------------------------------------------------------- #
# RPC messages (paper Figure 2)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class RequestVote:
    """Candidate -> peer: solicit a vote."""

    term: int
    candidate_id: str
    last_log_index: int
    last_log_term: int


@dataclass(frozen=True)
class RequestVoteReply:
    """Peer -> candidate: vote granted or refused."""

    term: int
    vote_granted: bool
    sender: str


@dataclass(frozen=True)
class AppendEntries:
    """Leader -> follower: replicate entries, or (with no entries) heartbeat."""

    term: int
    leader_id: str
    prev_log_index: int
    prev_log_term: int
    entries: Tuple[LogEntry, ...]
    leader_commit: int


@dataclass(frozen=True)
class AppendEntriesReply:
    """Follower -> leader: consistency-check result.

    Attributes:
        match_index: On success, the index of the last entry the follower now
            holds from this request. Carrying it in the reply lets the leader
            update ``match_index`` without tracking in-flight requests, which
            matters because the transport may reorder or drop them.
    """

    term: int
    success: bool
    sender: str
    match_index: int = 0


Message = Any  # One of the four RPC dataclasses above.


class Transport(Protocol):
    """What a RaftNode needs from the network.

    Delivery is best-effort and fire-and-forget: ``send`` never blocks and never
    reports failure. RAFT tolerates loss, duplication, and reordering by design,
    so a transport is free to do any of them.
    """

    def send(self, src: str, dst: str, message: Message) -> None:
        ...


class RaftNode:
    """A single RAFT server.

    The node is purely reactive: it does nothing until ``tick`` or ``receive`` is
    called, and all of its outbound traffic goes through the injected transport.
    That is what makes it testable under a virtual clock and reusable over TCP.

    Args:
        node_id: This server's unique ID.
        peers: IDs of the *other* servers in the cluster.
        transport: Where outbound RPCs go.
        apply_fn: Called once per committed entry, in log order, on every
            replica. This is the ledger seam.
        rng: Injected randomness for election timeouts. Defaults to a fresh
            unseeded Random; tests pass a seeded one.
        heartbeat_interval: Leader's time between AppendEntries broadcasts.
        election_timeout_min: Lower bound of the randomised election timeout.
        election_timeout_max: Upper bound of the randomised election timeout.
    """

    def __init__(
        self,
        node_id: str,
        peers: Sequence[str],
        transport: Transport,
        apply_fn: Optional[Callable[[LogEntry], None]] = None,
        rng: Optional[random.Random] = None,
        heartbeat_interval: float = DEFAULT_HEARTBEAT_INTERVAL,
        election_timeout_min: float = DEFAULT_ELECTION_TIMEOUT_MIN,
        election_timeout_max: float = DEFAULT_ELECTION_TIMEOUT_MAX,
    ) -> None:
        self.node_id = node_id
        self.peers: List[str] = [p for p in peers if p != node_id]
        self._transport = transport
        self._apply_fn = apply_fn
        self._rng = rng if rng is not None else random.Random()

        self.heartbeat_interval = heartbeat_interval
        self.election_timeout_min = election_timeout_min
        self.election_timeout_max = election_timeout_max

        # Persistent state (in memory here -- see the module docstring).
        self.current_term: int = 0
        self.voted_for: Optional[str] = None
        # Index 0 is a sentinel so that log[i].index == i and prev_log_index=0
        # means "the very beginning of the log" without special-casing.
        self.log: List[LogEntry] = [LogEntry(term=0, index=0, payload=None)]

        # Volatile state, all servers.
        self.role: Role = Role.FOLLOWER
        self.leader_id: Optional[str] = None
        self.commit_index: int = 0
        self.last_applied: int = 0

        # Volatile state, leaders only (reinitialised on election).
        self.next_index: Dict[str, int] = {}
        self.match_index: Dict[str, int] = {}

        # Candidate bookkeeping.
        self._votes: Set[str] = set()

        # Timers.
        self._last_heard: float = 0.0
        self._last_heartbeat: float = 0.0
        self._election_timeout: float = self._random_timeout()

    # ----------------------------------------------------------------- #
    # Introspection
    # ----------------------------------------------------------------- #

    @property
    def cluster_size(self) -> int:
        """Total number of servers, including this one."""
        return len(self.peers) + 1

    @property
    def last_log_index(self) -> int:
        """Index of the final entry (0 when only the sentinel is present)."""
        return len(self.log) - 1

    @property
    def last_log_term(self) -> int:
        """Term of the final entry (0 when only the sentinel is present)."""
        return self.log[-1].term

    @property
    def is_leader(self) -> bool:
        return self.role is Role.LEADER

    def _majority(self) -> int:
        """Votes (or replicas) needed to make a decision."""
        return self.cluster_size // 2 + 1

    def _random_timeout(self) -> float:
        return self._rng.uniform(self.election_timeout_min, self.election_timeout_max)

    # ----------------------------------------------------------------- #
    # Client entry point
    # ----------------------------------------------------------------- #

    def client_append(self, payload: Any, now: float = 0.0) -> Optional[int]:
        """Propose a new entry. Leader only.

        Appending is not committing: the entry is durable once a majority has
        replicated it, which the caller observes via ``apply_fn`` or by watching
        ``commit_index`` reach the returned index.

        Args:
            payload: Opaque application data to replicate.
            now: Current time, used to reschedule the heartbeat.

        Returns:
            The log index assigned to the entry, or None if this node is not the
            leader (the caller should redirect to ``leader_id``).
        """
        if self.role is not Role.LEADER:
            return None

        entry = LogEntry(term=self.current_term, index=len(self.log), payload=payload)
        self.log.append(entry)
        logger.debug(
            "%s: appended entry %d (term %d)", self.node_id, entry.index, entry.term
        )

        # Replicate immediately rather than waiting for the next heartbeat, and
        # re-advance the commit index so a single-node cluster commits at once.
        self._broadcast_append_entries(now)
        self._advance_commit_index()
        return entry.index

    # ----------------------------------------------------------------- #
    # Clock
    # ----------------------------------------------------------------- #

    def tick(self, now: float) -> None:
        """Drive time-based behaviour: heartbeats and election timeouts.

        Args:
            now: Current time in seconds (monotonic, or a virtual clock).
        """
        if self.role is Role.LEADER:
            if now - self._last_heartbeat >= self.heartbeat_interval:
                self._broadcast_append_entries(now)
            return

        if now - self._last_heard >= self._election_timeout:
            self._start_election(now)

    # ----------------------------------------------------------------- #
    # Message dispatch
    # ----------------------------------------------------------------- #

    def receive(self, message: Message, now: float) -> None:
        """Handle one inbound RPC.

        Args:
            message: One of RequestVote, RequestVoteReply, AppendEntries,
                AppendEntriesReply.
            now: Current time, used to reset the election timer.
        """
        # Rule for all servers: any message carrying a newer term makes this
        # node a follower of that term before anything else is considered.
        if message.term > self.current_term:
            self._step_down(message.term)

        if isinstance(message, RequestVote):
            self._handle_request_vote(message, now)
        elif isinstance(message, RequestVoteReply):
            self._handle_request_vote_reply(message, now)
        elif isinstance(message, AppendEntries):
            self._handle_append_entries(message, now)
        elif isinstance(message, AppendEntriesReply):
            self._handle_append_entries_reply(message, now)
        else:  # pragma: no cover - defensive
            logger.warning("%s: unknown message type %r", self.node_id, message)

    def _step_down(self, term: int) -> None:
        """Adopt a newer term and revert to follower."""
        if self.role is not Role.FOLLOWER:
            logger.info(
                "%s: stepping down (%s, term %d -> follower, term %d)",
                self.node_id, self.role.value, self.current_term, term,
            )
        self.current_term = term
        self.voted_for = None
        self.role = Role.FOLLOWER
        self.leader_id = None
        self._votes.clear()

    # ----------------------------------------------------------------- #
    # Elections
    # ----------------------------------------------------------------- #

    def _start_election(self, now: float) -> None:
        """Become a candidate for the next term and solicit votes."""
        self.current_term += 1
        self.role = Role.CANDIDATE
        self.voted_for = self.node_id
        self.leader_id = None
        self._votes = {self.node_id}
        self._reset_election_timer(now)

        logger.info("%s: starting election for term %d", self.node_id, self.current_term)

        request = RequestVote(
            term=self.current_term,
            candidate_id=self.node_id,
            last_log_index=self.last_log_index,
            last_log_term=self.last_log_term,
        )
        for peer in self.peers:
            self._transport.send(self.node_id, peer, request)

        # A single-node cluster elects itself: its own vote is already a majority.
        if len(self._votes) >= self._majority():
            self._become_leader(now)

    def _handle_request_vote(self, msg: RequestVote, now: float) -> None:
        """Grant a vote iff the term is current, we have not voted, and the
        candidate's log is at least as up to date as ours."""
        if msg.term < self.current_term:
            self._reply(msg.candidate_id, RequestVoteReply(
                term=self.current_term, vote_granted=False, sender=self.node_id,
            ))
            return

        # "Up to date" comparison (paper §5.4.1): later term wins; on equal
        # terms, the longer log wins. This is what makes Leader Completeness
        # hold -- a candidate missing committed entries cannot win a majority.
        up_to_date = (
            msg.last_log_term > self.last_log_term
            or (msg.last_log_term == self.last_log_term
                and msg.last_log_index >= self.last_log_index)
        )
        can_vote = self.voted_for is None or self.voted_for == msg.candidate_id
        granted = can_vote and up_to_date

        if granted:
            self.voted_for = msg.candidate_id
            # Only reset the timer when actually granting a vote, so a
            # disruptive candidate cannot keep a healthy follower from timing
            # out and standing for election itself.
            self._reset_election_timer(now)
            logger.debug(
                "%s: voted for %s in term %d", self.node_id, msg.candidate_id, self.current_term
            )

        self._reply(msg.candidate_id, RequestVoteReply(
            term=self.current_term, vote_granted=granted, sender=self.node_id,
        ))

    def _handle_request_vote_reply(self, msg: RequestVoteReply, now: float) -> None:
        # Ignore replies for an election we are no longer running.
        if self.role is not Role.CANDIDATE or msg.term != self.current_term:
            return

        if msg.vote_granted:
            self._votes.add(msg.sender)
            if len(self._votes) >= self._majority():
                self._become_leader(now)

    def _become_leader(self, now: float) -> None:
        """Win the election and start replicating."""
        self.role = Role.LEADER
        self.leader_id = self.node_id
        # Optimistic: assume every follower matches our log, and walk backwards
        # on rejection until the consistency check passes.
        self.next_index = {p: self.last_log_index + 1 for p in self.peers}
        self.match_index = {p: 0 for p in self.peers}

        logger.info(
            "%s: became LEADER for term %d (%d/%d votes, log len %d)",
            self.node_id, self.current_term, len(self._votes),
            self.cluster_size, self.last_log_index,
        )
        self._broadcast_append_entries(now)

    def _reset_election_timer(self, now: float) -> None:
        self._last_heard = now
        self._election_timeout = self._random_timeout()

    # ----------------------------------------------------------------- #
    # Log replication
    # ----------------------------------------------------------------- #

    def _broadcast_append_entries(self, now: float) -> None:
        self._last_heartbeat = now
        for peer in self.peers:
            self._send_append_entries(peer)

    def _send_append_entries(self, peer: str) -> None:
        """Send the follower everything it is missing from ``next_index`` on."""
        next_idx = self.next_index.get(peer, self.last_log_index + 1)
        # Clamp: a stale reply could otherwise push next_index past our log.
        next_idx = max(1, min(next_idx, self.last_log_index + 1))
        prev_index = next_idx - 1

        self._transport.send(self.node_id, peer, AppendEntries(
            term=self.current_term,
            leader_id=self.node_id,
            prev_log_index=prev_index,
            prev_log_term=self.log[prev_index].term,
            entries=tuple(self.log[next_idx:]),
            leader_commit=self.commit_index,
        ))

    def _handle_append_entries(self, msg: AppendEntries, now: float) -> None:
        """Run the consistency check, then splice in the leader's entries."""
        if msg.term < self.current_term:
            self._reply(msg.leader_id, AppendEntriesReply(
                term=self.current_term, success=False, sender=self.node_id,
            ))
            return

        # Valid leader for our term: defer to it and stop counting down to an
        # election. A candidate that hears from a leader of the same term loses.
        self.role = Role.FOLLOWER
        self.leader_id = msg.leader_id
        self._reset_election_timer(now)

        # Consistency check: we must already hold prev_log_index at prev_log_term.
        if msg.prev_log_index > self.last_log_index:
            self._reply(msg.leader_id, AppendEntriesReply(
                term=self.current_term, success=False, sender=self.node_id,
            ))
            return
        if self.log[msg.prev_log_index].term != msg.prev_log_term:
            self._reply(msg.leader_id, AppendEntriesReply(
                term=self.current_term, success=False, sender=self.node_id,
            ))
            return

        # Splice. Existing entries that agree are left alone -- important,
        # because a duplicated or reordered request must not truncate a log that
        # already holds *newer* entries from this same leader.
        for offset, entry in enumerate(msg.entries):
            index = msg.prev_log_index + 1 + offset
            if index <= self.last_log_index:
                if self.log[index].term == entry.term:
                    continue
                # Conflict: delete this entry and everything after it.
                logger.debug(
                    "%s: truncating log at %d (conflict term %d != %d)",
                    self.node_id, index, self.log[index].term, entry.term,
                )
                del self.log[index:]
            self.log.append(entry)

        last_new_index = msg.prev_log_index + len(msg.entries)

        if msg.leader_commit > self.commit_index:
            # Never commit past what we actually hold from this request.
            self.commit_index = min(msg.leader_commit, last_new_index)
            self._apply_committed()

        self._reply(msg.leader_id, AppendEntriesReply(
            term=self.current_term,
            success=True,
            sender=self.node_id,
            match_index=last_new_index,
        ))

    def _handle_append_entries_reply(self, msg: AppendEntriesReply, now: float) -> None:
        # Ignore replies from an older term, or ones arriving after we lost
        # leadership.
        if self.role is not Role.LEADER or msg.term != self.current_term:
            return

        if msg.success:
            # max() because replies can arrive out of order; match_index must
            # never move backwards.
            self.match_index[msg.sender] = max(
                self.match_index.get(msg.sender, 0), msg.match_index
            )
            self.next_index[msg.sender] = self.match_index[msg.sender] + 1
            self._advance_commit_index()
        else:
            # Consistency check failed: back up one entry and retry. The paper
            # notes this can be batched by having the follower return the
            # conflicting term; one-at-a-time is kept here for clarity, and
            # converges in at most (log length) rounds.
            self.next_index[msg.sender] = max(1, self.next_index.get(msg.sender, 1) - 1)
            self._send_append_entries(msg.sender)

    def _advance_commit_index(self) -> None:
        """Commit the highest index replicated on a majority *in this term*.

        The current-term restriction (paper §5.4.2) is the subtle part: counting
        replicas alone would let a leader commit an entry from an earlier term
        that a later leader could still overwrite. Entries from previous terms
        become committed indirectly, when an entry from the current term above
        them commits.
        """
        if self.role is not Role.LEADER:
            return

        for index in range(self.last_log_index, self.commit_index, -1):
            if self.log[index].term != self.current_term:
                # Terms increase monotonically along the log, so everything
                # below here is older too.
                break
            replicas = 1 + sum(
                1 for peer in self.peers if self.match_index.get(peer, 0) >= index
            )
            if replicas >= self._majority():
                logger.debug(
                    "%s: commit_index %d -> %d (%d/%d replicas)",
                    self.node_id, self.commit_index, index, replicas, self.cluster_size,
                )
                self.commit_index = index
                self._apply_committed()
                return

    def _apply_committed(self) -> None:
        """Hand every newly committed entry to ``apply_fn``, in log order."""
        while self.last_applied < self.commit_index:
            self.last_applied += 1
            entry = self.log[self.last_applied]
            if self._apply_fn is not None:
                self._apply_fn(entry)

    def _reply(self, dst: str, message: Message) -> None:
        self._transport.send(self.node_id, dst, message)


# --------------------------------------------------------------------------- #
# Reference transport: deterministic in-memory network
# --------------------------------------------------------------------------- #


@dataclass(order=True)
class _InFlight:
    """A message scheduled for delivery, ordered by (time, sequence)."""

    deliver_at: float
    seq: int
    src: str = field(compare=False)
    dst: str = field(compare=False)
    message: Message = field(compare=False)


class InMemoryNetwork:
    """An in-process transport with injectable loss, delay, and partitions.

    Deterministic given a seeded RNG and a fixed sequence of calls, which is what
    makes the safety tests reproducible. Messages are held in a priority queue
    and released by ``deliver_due(now)``.

    Args:
        rng: Injected randomness for drop decisions.
        delay: One-way delivery delay in seconds.
        drop_prob: Probability in [0, 1] that any given message is discarded.
    """

    def __init__(
        self,
        rng: Optional[random.Random] = None,
        delay: float = 0.0,
        drop_prob: float = 0.0,
    ) -> None:
        self._rng = rng if rng is not None else random.Random()
        self.delay = delay
        self.drop_prob = drop_prob

        self._nodes: Dict[str, RaftNode] = {}
        self._queue: List[_InFlight] = []
        self._seq = 0
        self._now = 0.0
        # None means "fully connected"; otherwise a list of groups that can only
        # talk within themselves.
        self._partitions: Optional[List[Set[str]]] = None
        self._crashed: Set[str] = set()

        self.sent = 0
        self.dropped = 0
        self.delivered = 0

    def register(self, node: RaftNode) -> None:
        self._nodes[node.node_id] = node

    # -- Transport protocol -------------------------------------------- #

    def send(self, src: str, dst: str, message: Message) -> None:
        self.sent += 1
        if not self._reachable(src, dst) or self._rng.random() < self.drop_prob:
            self.dropped += 1
            return
        self._seq += 1
        heapq.heappush(self._queue, _InFlight(
            deliver_at=self._now + self.delay, seq=self._seq,
            src=src, dst=dst, message=message,
        ))

    # -- Driver hooks --------------------------------------------------- #

    def deliver_due(self, now: float) -> int:
        """Deliver every message whose time has come.

        Args:
            now: Current virtual time.

        Returns:
            How many messages were delivered.
        """
        self._now = now
        count = 0
        # Re-check the head each iteration: delivering a message usually enqueues
        # a reply, and with delay == 0 that reply is due immediately, so a whole
        # RPC round trip settles within one call.
        while self._queue and self._queue[0].deliver_at <= now:
            item = heapq.heappop(self._queue)
            # Re-check reachability at delivery time, so a partition raised while
            # a message was in flight still blocks it.
            if not self._reachable(item.src, item.dst):
                self.dropped += 1
                continue
            node = self._nodes.get(item.dst)
            if node is None:
                continue
            self.delivered += 1
            count += 1
            node.receive(item.message, now)
        return count

    # -- Fault injection ------------------------------------------------ #

    def partition(self, *groups: Sequence[str]) -> None:
        """Split the cluster: messages only flow within a group.

        Args:
            *groups: Collections of node IDs that remain mutually reachable.
        """
        self._partitions = [set(g) for g in groups]
        logger.info("network partitioned into %s", self._partitions)

    def heal(self) -> None:
        """Remove all partitions."""
        self._partitions = None
        logger.info("network healed")

    def crash(self, node_id: str) -> None:
        """Cut a node off entirely: it neither sends nor receives."""
        self._crashed.add(node_id)

    def restart(self, node_id: str) -> None:
        self._crashed.discard(node_id)

    def is_crashed(self, node_id: str) -> bool:
        return node_id in self._crashed

    def _reachable(self, src: str, dst: str) -> bool:
        if src in self._crashed or dst in self._crashed:
            return False
        if self._partitions is None:
            return True
        return any(src in group and dst in group for group in self._partitions)


class RaftCluster:
    """A virtual-clock harness driving N RaftNodes over an InMemoryNetwork.

    Used by the tests, and usable as a demo without any sockets: a whole cluster
    runs inside one process, in simulated time, reproducibly from a seed.

    Args:
        node_ids: IDs of the servers to create.
        seed: Seeds both the network and each node's election-timeout RNG.
        delay: One-way network delay in seconds.
        drop_prob: Per-message drop probability.
        **node_kwargs: Passed through to every RaftNode (timeouts, etc.).
    """

    def __init__(
        self,
        node_ids: Sequence[str],
        seed: int = 0,
        delay: float = 0.0,
        drop_prob: float = 0.0,
        **node_kwargs: Any,
    ) -> None:
        self.now = 0.0
        self.network = InMemoryNetwork(
            rng=random.Random(seed), delay=delay, drop_prob=drop_prob,
        )
        self.applied: Dict[str, List[LogEntry]] = {nid: [] for nid in node_ids}
        self.nodes: Dict[str, RaftNode] = {}

        for offset, node_id in enumerate(node_ids):
            node = RaftNode(
                node_id=node_id,
                peers=[n for n in node_ids if n != node_id],
                transport=self.network,
                # Bind node_id per node so each replica records its own applies.
                apply_fn=(lambda entry, nid=node_id: self.applied[nid].append(entry)),
                # Distinct seeds, or every node would time out simultaneously
                # and split the vote repeatedly.
                rng=random.Random(seed * 1000 + offset),
                **node_kwargs,
            )
            self.nodes[node_id] = node
            self.network.register(node)

    def advance(self, duration: float, step: float = 0.01) -> None:
        """Run the cluster forward in simulated time.

        Args:
            duration: How many seconds of virtual time to simulate.
            step: Tick granularity. Must be well below the heartbeat interval.
        """
        end = self.now + duration
        while self.now < end - 1e-9:
            self.now = round(self.now + step, 9)
            for node in self.nodes.values():
                if not self.network.is_crashed(node.node_id):
                    node.tick(self.now)
            self.network.deliver_due(self.now)

    # -- Convenience ----------------------------------------------------- #

    def leaders(self) -> List[RaftNode]:
        """Every live node currently believing itself leader (any term)."""
        return [
            n for n in self.nodes.values()
            if n.is_leader and not self.network.is_crashed(n.node_id)
        ]

    def leader(self) -> Optional[RaftNode]:
        """The highest-term live leader, or None if there is no leader."""
        live = self.leaders()
        return max(live, key=lambda n: n.current_term) if live else None

    def crash(self, node_id: str) -> None:
        """Take a node offline: it stops ticking and stops passing messages."""
        self.network.crash(node_id)

    def restart(self, node_id: str) -> None:
        """Bring a crashed node back.

        Its in-memory term and log survive, which is the crash-fault model this
        project claims -- a real deployment would fsync those before replying.
        """
        self.network.restart(node_id)
        node = self.nodes[node_id]
        node.role = Role.FOLLOWER
        node.leader_id = None
        node._reset_election_timer(self.now)
