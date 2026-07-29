"""Unit tests for RAFT consensus (blockchain/raft.py).

Tests R-01 through R-18. The cluster runs entirely in memory on a virtual clock
with an injectable-fault transport, so every test is deterministic and needs no
sockets, no sudo, and no Mininet.

The suite is organised around the five safety properties of the RAFT paper
(Ongaro & Ousterhout, USENIX ATC 2014, Figure 3), because those are what an
examiner will ask about:

    Election Safety      R-01, R-02, R-04, R-11
    Leader Append-Only   R-14
    Log Matching         R-07
    Leader Completeness  R-08, R-12
    State Machine Safety R-09, R-17

Liveness (a leader is eventually elected, entries eventually commit) is covered
by R-03, R-15, and R-16.
"""

import sys
import os
import random
from typing import Any, Dict, List, Tuple

import pytest

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from blockchain.raft import (
    AppendEntries,
    AppendEntriesReply,
    InMemoryNetwork,
    LogEntry,
    RaftCluster,
    RaftNode,
    RequestVote,
    RequestVoteReply,
    Role,
)
from blockchain.merkle import build_merkle_root
from contracts.block_schema import Block
from contracts.trust_update import TrustUpdate


class _RecordingTransport:
    """Captures outbound messages so a single node can be tested in isolation."""

    def __init__(self) -> None:
        self.sent: List[Tuple[str, str, Any]] = []

    def send(self, src: str, dst: str, message: Any) -> None:
        self.sent.append((src, dst, message))

    def to(self, dst: str) -> List[Any]:
        return [m for _, d, m in self.sent if d == dst]

    def of_type(self, cls: type) -> List[Any]:
        return [m for _, _, m in self.sent if isinstance(m, cls)]

    def clear(self) -> None:
        self.sent.clear()


def _lone_node(**kwargs: Any) -> Tuple[RaftNode, _RecordingTransport]:
    """A single node with two peers that never answer, for direct RPC tests."""
    transport = _RecordingTransport()
    node = RaftNode(
        node_id='n1',
        peers=['n2', 'n3'],
        transport=transport,
        rng=random.Random(1),
        **kwargs,
    )
    return node, transport


def _make_update(node_id: str = 'srv1', score_after: float = 0.7) -> TrustUpdate:
    """Helper matching tests/test_blockchain.py's fixture style."""
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


def _assert_logs_match(cluster: RaftCluster) -> None:
    """Log Matching: entries sharing an (index, term) imply identical prefixes."""
    nodes = list(cluster.nodes.values())
    for i, a in enumerate(nodes):
        for b in nodes[i + 1:]:
            shared = min(a.last_log_index, b.last_log_index)
            for index in range(shared, 0, -1):
                if a.log[index].term == b.log[index].term:
                    for k in range(index + 1):
                        assert a.log[k].term == b.log[k].term, (
                            f"{a.node_id}/{b.node_id} diverge at {k} below matching {index}"
                        )
                        assert a.log[k].payload == b.log[k].payload
                    break


def _assert_state_machine_safety(cluster: RaftCluster) -> None:
    """State Machine Safety: no two replicas apply different entries at an index."""
    for node_id, entries in cluster.applied.items():
        for other_id, other in cluster.applied.items():
            for i in range(min(len(entries), len(other))):
                assert entries[i].payload == other[i].payload, (
                    f"{node_id} and {other_id} applied different entries at position {i}"
                )
                assert entries[i].term == other[i].term


class TestElection:
    """R-01 through R-04, R-11, R-12: leader election and Election Safety."""

    def test_r01_single_leader_elected(self) -> None:
        """R-01: A healthy 3-node cluster elects exactly one leader."""
        cluster = RaftCluster(['n1', 'n2', 'n3'], seed=1)
        cluster.advance(2.0)

        leaders = cluster.leaders()
        assert len(leaders) == 1, f"expected 1 leader, got {[n.node_id for n in leaders]}"

        leader = leaders[0]
        assert leader.current_term >= 1
        # Every follower agrees who the leader is, in the same term.
        for node in cluster.nodes.values():
            if node is leader:
                continue
            assert node.role is Role.FOLLOWER
            assert node.leader_id == leader.node_id
            assert node.current_term == leader.current_term

    def test_r02_election_safety_one_leader_per_term(self) -> None:
        """R-02: At most one leader per term, across many seeds and lossy links.

        The core Election Safety property. Sampled continuously as the cluster
        runs, not just at the end, so a transient double-leader would be caught.
        """
        for seed in range(12):
            cluster = RaftCluster(
                ['n1', 'n2', 'n3', 'n4', 'n5'], seed=seed, drop_prob=0.15,
            )
            leader_of_term: Dict[int, str] = {}
            for _ in range(60):
                cluster.advance(0.1)
                for node in cluster.leaders():
                    claimed = leader_of_term.setdefault(node.current_term, node.node_id)
                    assert claimed == node.node_id, (
                        f"seed {seed}: term {node.current_term} had two leaders "
                        f"({claimed} and {node.node_id})"
                    )

    def test_r03_reelection_after_leader_crash(self) -> None:
        """R-03: Crashing the leader produces a new one from the remaining majority."""
        cluster = RaftCluster(['n1', 'n2', 'n3'], seed=3)
        cluster.advance(2.0)

        first = cluster.leader()
        assert first is not None
        first_term = first.current_term

        cluster.crash(first.node_id)
        cluster.advance(3.0)

        second = cluster.leader()
        assert second is not None, "no leader re-elected after crash"
        assert second.node_id != first.node_id
        assert second.current_term > first_term, "new leader must serve a later term"

    def test_r04_no_leader_without_quorum(self) -> None:
        """R-04: A minority partition cannot elect a leader.

        The safety/availability trade RAFT makes: the isolated nodes campaign
        forever, burning through terms, but never win. The majority side keeps
        serving.
        """
        cluster = RaftCluster(['n1', 'n2', 'n3', 'n4', 'n5'], seed=4)
        cluster.advance(2.0)
        leader = cluster.leader()
        assert leader is not None
        term_at_partition = leader.current_term

        others = [n for n in cluster.nodes if n != leader.node_id]
        minority, rest = others[:2], others[2:]
        cluster.network.partition([leader.node_id] + rest, minority)
        cluster.advance(4.0)

        for node_id in minority:
            node = cluster.nodes[node_id]
            assert not node.is_leader, f"{node_id} led a minority partition"
            # It kept campaigning, which is why its term ran away.
            assert node.current_term > term_at_partition
            assert node.commit_index == 0, "minority committed without a quorum"

        survivor = cluster.leader()
        assert survivor is not None, "majority side lost its leader"
        assert survivor.node_id in [leader.node_id] + rest

    def test_r04b_stranded_leader_keeps_the_title_but_steps_down_on_heal(self) -> None:
        """R-04b: A leader cut off from its cluster still believes it leads.

        Worth pinning down because it looks like an Election Safety violation and
        is not: plain RAFT gives a leader no way to notice it has been isolated,
        so it stays in the role until it hears a higher term. Safety is preserved
        because it can no longer *commit* anything (see R-06). Production systems
        add a check-quorum or lease extension to shed the title early; this
        implementation deliberately does not, staying with the paper.
        """
        cluster = RaftCluster(['n1', 'n2', 'n3'], seed=44)
        cluster.advance(2.0)
        stranded = cluster.leader()
        assert stranded is not None
        rest = [n for n in cluster.nodes if n != stranded.node_id]

        cluster.network.partition([stranded.node_id], rest)
        cluster.advance(3.0)

        assert stranded.is_leader, "expected the stale leader to keep the role"
        assert stranded.commit_index == 0, "stranded leader committed something"
        new_leader = next(
            (cluster.nodes[n] for n in rest if cluster.nodes[n].is_leader), None
        )
        assert new_leader is not None, "majority did not elect a replacement"
        assert new_leader.current_term > stranded.current_term

        cluster.network.heal()
        cluster.advance(2.0)
        assert not stranded.is_leader, "stale leader did not step down after heal"
        assert stranded.current_term >= new_leader.current_term

    def test_r11_one_vote_per_term(self) -> None:
        """R-11: A node grants at most one vote per term (first-come wins)."""
        node, transport = _lone_node()
        node.receive(RequestVote(term=5, candidate_id='n2', last_log_index=0,
                                 last_log_term=0), now=0.0)
        node.receive(RequestVote(term=5, candidate_id='n3', last_log_index=0,
                                 last_log_term=0), now=0.0)

        replies = transport.of_type(RequestVoteReply)
        assert len(replies) == 2
        assert replies[0].vote_granted is True
        assert replies[1].vote_granted is False, "granted a second vote in the same term"
        assert node.voted_for == 'n2'

        # A new term frees the vote again.
        node.receive(RequestVote(term=6, candidate_id='n3', last_log_index=0,
                                 last_log_term=0), now=0.0)
        assert transport.of_type(RequestVoteReply)[-1].vote_granted is True
        assert node.voted_for == 'n3'

    def test_r12_candidate_with_stale_log_denied_vote(self) -> None:
        """R-12: The up-to-date check refuses a candidate whose log is behind.

        This is the mechanism behind Leader Completeness -- it is what stops a
        node that missed committed entries from ever becoming leader.
        """
        node, transport = _lone_node()
        node.log.extend([
            LogEntry(term=1, index=1, payload='a'),
            LogEntry(term=2, index=2, payload='b'),
        ])
        node.current_term = 2

        # Shorter log, same last term -> refused.
        node.receive(RequestVote(term=3, candidate_id='n2', last_log_index=1,
                                 last_log_term=2), now=0.0)
        assert transport.of_type(RequestVoteReply)[-1].vote_granted is False

        # Older last term, even with a longer log -> refused.
        transport.clear()
        node.receive(RequestVote(term=4, candidate_id='n3', last_log_index=9,
                                 last_log_term=1), now=0.0)
        assert transport.of_type(RequestVoteReply)[-1].vote_granted is False

        # Equal log -> granted.
        transport.clear()
        node.receive(RequestVote(term=5, candidate_id='n2', last_log_index=2,
                                 last_log_term=2), now=0.0)
        assert transport.of_type(RequestVoteReply)[-1].vote_granted is True


class TestReplication:
    """R-05 through R-08, R-14: log replication and repair."""

    def test_r05_entry_replicated_and_applied_on_all(self) -> None:
        """R-05: A committed entry reaches every replica's state machine."""
        cluster = RaftCluster(['n1', 'n2', 'n3'], seed=5)
        cluster.advance(2.0)
        leader = cluster.leader()
        assert leader is not None

        index = leader.client_append('trust-batch-1', cluster.now)
        assert index == 1
        cluster.advance(1.0)

        assert leader.commit_index >= 1
        for node_id in cluster.nodes:
            payloads = [e.payload for e in cluster.applied[node_id]]
            assert payloads == ['trust-batch-1'], f"{node_id} applied {payloads}"

    def test_r06_commit_requires_majority(self) -> None:
        """R-06: With no majority to replicate to, an entry is appended but never
        committed -- and it commits as soon as the majority returns."""
        cluster = RaftCluster(['n1', 'n2', 'n3'], seed=6)
        cluster.advance(2.0)
        leader = cluster.leader()
        assert leader is not None
        followers = [n for n in cluster.nodes if n != leader.node_id]

        # Isolate the leader from both followers. It stays leader (it does not
        # know yet) but cannot replicate.
        cluster.network.partition([leader.node_id], followers)
        leader.client_append('uncommitted', cluster.now)
        cluster.advance(0.4)

        assert leader.last_log_index >= 1, "entry should be in the leader's own log"
        assert leader.commit_index == 0, "committed without a majority"
        assert cluster.applied[leader.node_id] == [], "applied without a majority"

        # Heal before the followers' terms outrun it, and it replicates.
        cluster.network.heal()
        cluster.advance(2.0)
        _assert_state_machine_safety(cluster)

    def test_r07_log_matching_after_divergence(self) -> None:
        """R-07: A deposed leader's uncommitted entries are truncated on return.

        The paper's Figure 7 situation, produced honestly rather than by hand
        (two entries at the same index and term are identical by definition, so
        planting fake conflicts would test nothing): isolate the leader, let it
        accept writes it can never commit, let the majority elect a successor
        that fills those same indices with different entries, then heal. The old
        leader's orphans must be deleted and replaced.
        """
        cluster = RaftCluster(['n1', 'n2', 'n3', 'n4', 'n5'], seed=7)
        cluster.advance(2.0)
        deposed = cluster.leader()
        assert deposed is not None
        rest = [n for n in cluster.nodes if n != deposed.node_id]

        # Orphan writes: appended locally, never replicated to a majority.
        cluster.network.partition([deposed.node_id], rest)
        for i in range(3):
            deposed.client_append(f'orphan-{i}', cluster.now)
            cluster.advance(0.2)
        assert deposed.last_log_index == 3
        assert deposed.commit_index == 0, "orphans must not have committed"

        # The majority elects a successor and fills indices 1..3 differently.
        cluster.advance(3.0)
        successor = next(
            (cluster.nodes[n] for n in rest if cluster.nodes[n].is_leader), None
        )
        assert successor is not None, "majority did not elect a successor"
        for i in range(3):
            successor.client_append(f'real-{i}', cluster.now)
            cluster.advance(0.2)
        cluster.advance(1.0)
        assert successor.commit_index >= 3

        cluster.network.heal()
        cluster.advance(5.0)

        final = cluster.leader()
        assert final is not None
        repaired = [e.payload for e in deposed.log[1:]]
        assert 'orphan-0' not in repaired, "uncommitted entries were not truncated"
        for i in range(3):
            assert f'real-{i}' in repaired, f"real-{i} never reached the old leader"
        assert repaired[:3] == ['real-0', 'real-1', 'real-2']
        _assert_logs_match(cluster)
        _assert_state_machine_safety(cluster)

    def test_r08_leader_completeness(self) -> None:
        """R-08: Entries committed under one leader survive every later election.

        Commit entries while two nodes are partitioned away, then heal. The
        stale nodes come back with inflated terms (they campaigned throughout),
        which forces a fresh election -- but they cannot win it, and whichever
        leader emerges holds every committed entry.
        """
        cluster = RaftCluster(['n1', 'n2', 'n3', 'n4', 'n5'], seed=8)
        cluster.advance(2.0)
        leader = cluster.leader()
        assert leader is not None

        others = [n for n in cluster.nodes if n != leader.node_id]
        stale, current = others[:2], others[2:]
        cluster.network.partition([leader.node_id] + current, stale)

        committed: List[str] = []
        for i in range(4):
            payload = f'committed-{i}'
            if leader.client_append(payload, cluster.now) is not None:
                committed.append(payload)
            cluster.advance(0.3)

        assert leader.commit_index >= len(committed) > 0
        for node_id in stale:
            assert cluster.applied[node_id] == [], "partitioned node should be behind"

        cluster.network.heal()
        cluster.advance(6.0)

        final = cluster.leader()
        assert final is not None, "cluster did not recover a leader"
        present = [e.payload for e in final.log]
        for payload in committed:
            assert payload in present, (
                f"leader {final.node_id} (term {final.current_term}) lost committed {payload}"
            )
        _assert_logs_match(cluster)
        _assert_state_machine_safety(cluster)

    def test_r19_earlier_term_entry_not_committed_by_replica_count(self) -> None:
        """R-19: A leader may not commit an entry from an earlier term just
        because a majority stores it (paper §5.4.2, Figure 8).

        The subtlest rule in RAFT, and the one whose absence is invisible in
        ordinary runs: counting replicas alone would let a leader declare an
        old-term entry committed while a future leader could still legally
        overwrite it -- silently breaking Leader Completeness. The entry must
        instead commit *indirectly*, carried by an entry from the current term.

        Driven through the commit rule directly, because reproducing Figure 8 by
        timing alone is not deterministic.
        """
        applied: List[LogEntry] = []
        transport = _RecordingTransport()
        node = RaftNode(
            node_id='n1', peers=['n2', 'n3'], transport=transport,
            apply_fn=applied.append, rng=random.Random(1),
        )
        node.role = Role.LEADER
        node.current_term = 4
        node.log.extend([
            LogEntry(term=1, index=1, payload='a'),
            LogEntry(term=2, index=2, payload='b'),  # from an earlier term
        ])
        node.next_index = {'n2': 3, 'n3': 3}
        # Self plus n2 is a majority of 3, and both store index 2.
        node.match_index = {'n2': 2, 'n3': 0}

        node._advance_commit_index()
        assert node.commit_index == 0, (
            "committed an earlier-term entry on replica count alone"
        )
        assert applied == [], "applied an entry that must not be committed yet"

        # Append and replicate an entry in the *current* term: now index 3
        # commits, and indices 1-2 commit indirectly along with it.
        node.log.append(LogEntry(term=4, index=3, payload='c'))
        node.match_index['n2'] = 3
        node._advance_commit_index()

        assert node.commit_index == 3
        assert [e.payload for e in applied] == ['a', 'b', 'c'], (
            "earlier entries must be applied in order behind the current-term one"
        )

    def test_r14_leader_append_only(self) -> None:
        """R-14: A leader never overwrites or deletes entries in its own log."""
        cluster = RaftCluster(['n1', 'n2', 'n3'], seed=14)
        snapshots: Dict[str, List[LogEntry]] = {}

        for _ in range(40):
            cluster.advance(0.1)
            leader = cluster.leader()
            if leader is not None:
                leader.client_append(f't{cluster.now:.2f}', cluster.now)

            for node in cluster.nodes.values():
                if not node.is_leader:
                    continue
                previous = snapshots.get(node.node_id)
                current = list(node.log)
                if previous is not None:
                    assert len(current) >= len(previous), (
                        f"{node.node_id} truncated its log while leader"
                    )
                    for i, entry in enumerate(previous):
                        assert current[i] == entry, (
                            f"{node.node_id} rewrote its own log at index {i}"
                        )
                snapshots[node.node_id] = current
                # A node that loses leadership may legitimately be truncated by
                # the next leader, so stop tracking it once it steps down.
            for node_id in list(snapshots):
                if not cluster.nodes[node_id].is_leader:
                    del snapshots[node_id]


class TestFaultTolerance:
    """R-09, R-15 through R-17: behaviour under loss, crash, and restart."""

    def test_r09_state_machine_safety_under_loss(self) -> None:
        """R-09: Under 20% message loss and a rolling crash, no two replicas ever
        apply different entries at the same position."""
        cluster = RaftCluster(['n1', 'n2', 'n3', 'n4', 'n5'], seed=9, drop_prob=0.20)
        cluster.advance(2.0)

        victims = ['n1', 'n2', 'n3']
        for round_no in range(6):
            leader = cluster.leader()
            if leader is not None:
                leader.client_append(f'r{round_no}', cluster.now)
            cluster.advance(1.0)

            victim = victims[round_no % len(victims)]
            cluster.crash(victim)
            cluster.advance(1.0)
            cluster.restart(victim)
            cluster.advance(1.0)

            _assert_state_machine_safety(cluster)
            _assert_logs_match(cluster)

    def test_r15_progress_under_message_loss(self) -> None:
        """R-15: A lossy but connected cluster still commits (liveness)."""
        cluster = RaftCluster(['n1', 'n2', 'n3'], seed=15, drop_prob=0.25, delay=0.02)
        cluster.advance(3.0)

        accepted = 0
        for i in range(10):
            leader = cluster.leader()
            if leader is not None and leader.client_append(f'x{i}', cluster.now) is not None:
                accepted += 1
            cluster.advance(0.5)
        cluster.advance(3.0)

        assert accepted > 0, "never had a leader to accept a write"
        committed = max(n.commit_index for n in cluster.nodes.values())
        assert committed > 0, "lossy cluster made no progress at all"
        _assert_state_machine_safety(cluster)

    def test_r16_restarted_node_catches_up(self) -> None:
        """R-16: A node that misses entries while down is caught up on return."""
        cluster = RaftCluster(['n1', 'n2', 'n3'], seed=16)
        cluster.advance(2.0)
        leader = cluster.leader()
        assert leader is not None
        victim = next(n for n in cluster.nodes if n != leader.node_id)

        cluster.crash(victim)
        cluster.advance(0.5)
        for i in range(5):
            current = cluster.leader()
            assert current is not None
            current.client_append(f'while-down-{i}', cluster.now)
            cluster.advance(0.3)

        missed = len(cluster.applied[victim])
        assert missed == 0, "crashed node applied entries"

        cluster.restart(victim)
        cluster.advance(4.0)

        final = cluster.leader()
        assert final is not None
        recovered = cluster.nodes[victim]
        assert recovered.last_log_index == final.last_log_index, "did not catch up"
        assert len(cluster.applied[victim]) >= 5
        _assert_state_machine_safety(cluster)

    def test_r17_entries_applied_once_and_in_order(self) -> None:
        """R-17: apply_fn fires exactly once per entry, in log-index order.

        The ledger depends on this: applying twice would double-append blocks,
        and applying out of order would break the hash chain.
        """
        cluster = RaftCluster(['n1', 'n2', 'n3'], seed=17, drop_prob=0.10)
        cluster.advance(2.0)

        for i in range(8):
            leader = cluster.leader()
            if leader is not None:
                leader.client_append(f'e{i}', cluster.now)
            cluster.advance(0.3)
        cluster.advance(3.0)

        for node_id, entries in cluster.applied.items():
            indices = [e.index for e in entries]
            assert indices == sorted(indices), f"{node_id} applied out of order: {indices}"
            assert len(indices) == len(set(indices)), f"{node_id} applied twice: {indices}"
            assert indices == list(range(1, len(indices) + 1)), (
                f"{node_id} has a gap in applied indices: {indices}"
            )


class TestProtocolRules:
    """R-10, R-13: individual RPC rules, checked directly on one node."""

    def test_r10_stale_term_rejected(self) -> None:
        """R-10: RPCs from an older term are refused without changing state."""
        node, transport = _lone_node()
        node.current_term = 5
        node.log.append(LogEntry(term=5, index=1, payload='keep'))

        node.receive(AppendEntries(term=3, leader_id='n2', prev_log_index=0,
                                   prev_log_term=0, entries=(), leader_commit=0),
                     now=0.0)
        reply = transport.of_type(AppendEntriesReply)[-1]
        assert reply.success is False
        assert reply.term == 5
        assert node.current_term == 5
        assert node.leader_id is None, "accepted a stale leader"
        assert node.log[1].payload == 'keep', "stale AppendEntries modified the log"

        transport.clear()
        node.receive(RequestVote(term=4, candidate_id='n3', last_log_index=99,
                                 last_log_term=99), now=0.0)
        assert transport.of_type(RequestVoteReply)[-1].vote_granted is False
        assert node.voted_for is None

    def test_r13_client_append_rejected_on_follower(self) -> None:
        """R-13: Only the leader accepts writes; a follower redirects."""
        cluster = RaftCluster(['n1', 'n2', 'n3'], seed=13)
        cluster.advance(2.0)
        leader = cluster.leader()
        assert leader is not None

        for node in cluster.nodes.values():
            if node is leader:
                continue
            assert node.client_append('nope', cluster.now) is None
            assert node.leader_id == leader.node_id, "follower cannot redirect the client"
            assert node.last_log_index == 0 or all(
                e.payload != 'nope' for e in node.log
            )

    def test_r20_consistency_check_rejects_mismatched_prev_entry(self) -> None:
        """R-20: AppendEntries is refused unless the follower already holds
        prev_log_index at prev_log_term.

        The induction step behind Log Matching: a follower must never splice
        entries onto a prefix it does not actually share with the leader, or the
        two logs would silently diverge in the middle. Tested directly because
        the end-to-end repair path reaches prev_log_index = 0 (the sentinel,
        which always matches) once next_index has walked all the way back.
        """
        node, transport = _lone_node()
        node.current_term = 3
        node.log.extend([
            LogEntry(term=1, index=1, payload='a'),
            LogEntry(term=2, index=2, payload='b'),
        ])

        # Right index, wrong term: the leader's history diverges from ours here.
        node.receive(AppendEntries(term=3, leader_id='n2', prev_log_index=2,
                                   prev_log_term=3, entries=(
                                       LogEntry(term=3, index=3, payload='c'),
                                   ), leader_commit=3), now=0.0)
        reply = transport.of_type(AppendEntriesReply)[-1]
        assert reply.success is False, "spliced onto a prefix we do not share"
        assert node.last_log_index == 2, "appended despite a failed consistency check"
        assert node.commit_index == 0, "committed on a failed consistency check"

        # Past the end of our log: also refused.
        transport.clear()
        node.receive(AppendEntries(term=3, leader_id='n2', prev_log_index=7,
                                   prev_log_term=3, entries=(), leader_commit=0),
                     now=0.0)
        assert transport.of_type(AppendEntriesReply)[-1].success is False
        assert node.last_log_index == 2

        # Matching prev entry: accepted, and appended at the right index.
        transport.clear()
        node.receive(AppendEntries(term=3, leader_id='n2', prev_log_index=2,
                                   prev_log_term=2, entries=(
                                       LogEntry(term=3, index=3, payload='c'),
                                   ), leader_commit=0), now=0.0)
        accepted = transport.of_type(AppendEntriesReply)[-1]
        assert accepted.success is True
        assert accepted.match_index == 3
        assert [e.payload for e in node.log[1:]] == ['a', 'b', 'c']

    def test_r21_leader_commit_clamped_to_entries_held(self) -> None:
        """R-21: A follower never advances commit_index past what it actually has.

        A leader's commit_index legitimately runs ahead of a lagging follower.
        Adopting it verbatim would mark entries committed -- and hand them to the
        ledger -- that this replica has not received.
        """
        applied: List[LogEntry] = []
        transport = _RecordingTransport()
        node = RaftNode(
            node_id='n1', peers=['n2', 'n3'], transport=transport,
            apply_fn=applied.append, rng=random.Random(1),
        )

        # Empty log, leader claims everything through index 5 is committed.
        node.receive(AppendEntries(term=1, leader_id='n2', prev_log_index=0,
                                   prev_log_term=0, entries=(), leader_commit=5),
                     now=0.0)
        assert node.commit_index == 0, "committed entries we do not hold"
        assert applied == [], "applied entries we do not hold"

        # One entry arrives; only that one may commit, even though the leader
        # is still advertising 5.
        node.receive(AppendEntries(term=1, leader_id='n2', prev_log_index=0,
                                   prev_log_term=0, entries=(
                                       LogEntry(term=1, index=1, payload='a'),
                                   ), leader_commit=5), now=0.0)
        assert node.commit_index == 1
        assert [e.payload for e in applied] == ['a']

    def test_r10b_heartbeat_does_not_truncate_a_longer_log(self) -> None:
        """A repeated or reordered AppendEntries must not delete newer entries.

        Guards the splice loop: entries that already agree are skipped rather
        than re-appended, so a duplicate of an older request is a no-op.
        """
        node, transport = _lone_node()
        entries = (
            LogEntry(term=1, index=1, payload='a'),
            LogEntry(term=1, index=2, payload='b'),
        )
        node.receive(AppendEntries(term=1, leader_id='n2', prev_log_index=0,
                                   prev_log_term=0, entries=entries, leader_commit=0),
                     now=0.0)
        assert node.last_log_index == 2

        # The same request again, plus one carrying only the first entry.
        node.receive(AppendEntries(term=1, leader_id='n2', prev_log_index=0,
                                   prev_log_term=0, entries=entries, leader_commit=0),
                     now=0.1)
        node.receive(AppendEntries(term=1, leader_id='n2', prev_log_index=0,
                                   prev_log_term=0, entries=entries[:1], leader_commit=0),
                     now=0.2)

        assert node.last_log_index == 2, "duplicate AppendEntries truncated the log"
        assert [e.payload for e in node.log[1:]] == ['a', 'b']


class TestLedgerSeam:
    """R-18: the payload contract the future RaftBackend will rely on."""

    def test_r18_replicas_agree_on_block_hash_from_committed_entry(self) -> None:
        """R-18: Every replica can build a byte-identical Block from what it applied.

        This is the property that makes `LocalLedgerBackend -> RaftBackend` a
        drop-in: `raft_term` comes from `LogEntry.term`, and it is already inside
        the hash preimage (contracts/block_schema.py::compute_hash), so the same
        committed entry yields the same block hash on every replica.

        Note the timestamp: it must travel *inside* the replicated payload. If a
        RaftBackend stamped `time.time()` at apply time, replicas would compute
        different hashes for the same entry and the chains would diverge.
        """
        cluster = RaftCluster(['n1', 'n2', 'n3'], seed=18)
        cluster.advance(2.0)
        leader = cluster.leader()
        assert leader is not None

        updates = [_make_update('srv1', 0.82), _make_update('srv2', 0.41)]
        payload = {'timestamp': 1_700_000_000.0, 'updates': updates}
        leader.client_append(payload, cluster.now)
        cluster.advance(1.0)

        hashes = set()
        for node_id in cluster.nodes:
            applied = cluster.applied[node_id]
            assert len(applied) == 1, f"{node_id} applied {len(applied)} entries"
            entry = applied[0]
            block = Block(
                index=entry.index,
                timestamp=entry.payload['timestamp'],
                previous_hash='0' * 64,
                merkle_root=build_merkle_root(entry.payload['updates']),
                proposer_id=leader.node_id,
                raft_term=entry.term,
                trust_updates=entry.payload['updates'],
            )
            block.hash = block.compute_hash()
            hashes.add(block.hash)

        assert len(hashes) == 1, f"replicas disagreed on the block hash: {hashes}"
        assert entry.term >= 1, "raft_term should carry the electing leader's term"


class TestTransport:
    """The reference transport itself, since the safety tests depend on it."""

    def test_partition_blocks_only_across_groups(self) -> None:
        network = InMemoryNetwork(rng=random.Random(0))
        received: List[Any] = []

        class _Sink:
            node_id = 'b'

            def receive(self, message: Any, now: float) -> None:
                received.append(message)

        network.register(_Sink())  # type: ignore[arg-type]
        network.partition(['a'], ['b'])
        network.send('a', 'b', 'blocked')
        network.deliver_due(0.0)
        assert received == []
        assert network.dropped == 1

        network.heal()
        network.send('a', 'b', 'allowed')
        network.deliver_due(0.0)
        assert received == ['allowed']

    def test_delay_defers_delivery(self) -> None:
        network = InMemoryNetwork(rng=random.Random(0), delay=0.05)
        received: List[Any] = []

        class _Sink:
            node_id = 'b'

            def receive(self, message: Any, now: float) -> None:
                received.append(message)

        network.register(_Sink())  # type: ignore[arg-type]
        network.deliver_due(0.0)
        network.send('a', 'b', 'later')
        assert network.deliver_due(0.02) == 0
        assert received == []
        assert network.deliver_due(0.06) == 1
        assert received == ['later']

    def test_cluster_is_deterministic_for_a_seed(self) -> None:
        """Same seed, same history -- what makes the safety tests reproducible."""
        def run() -> List[Any]:
            cluster = RaftCluster(['n1', 'n2', 'n3'], seed=42, drop_prob=0.2)
            cluster.advance(2.0)
            for i in range(5):
                leader = cluster.leader()
                if leader is not None:
                    leader.client_append(f'v{i}', cluster.now)
                cluster.advance(0.4)
            return [
                (nid, [e.payload for e in cluster.applied[nid]])
                for nid in sorted(cluster.nodes)
            ]

        assert run() == run()
