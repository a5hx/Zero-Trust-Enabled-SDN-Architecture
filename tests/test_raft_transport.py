"""Tests for blockchain/raft_transport.py -- the TCP Transport (Step 2,
RAFT wiring). Only the transport is exercised here: real sockets, real
threads, real (loopback) network I/O. RAFT's safety properties are already
proven over the in-memory reference transport in tests/test_raft.py and are
not re-tested against this one, per the plan -- a transport swap should not
need the safety suite re-run, only its own contract (it delivers what was
sent, faithfully, to whichever node asked to receive it)."""

import socket
import threading
import time

import pytest

from blockchain.raft import (
    AppendEntries,
    AppendEntriesReply,
    LogEntry,
    RequestVote,
    RequestVoteReply,
)
from blockchain.raft_transport import TcpTransport, decode, encode


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


# --------------------------------------------------------------------------- #
# Wire codec round-trip                                                       #
# --------------------------------------------------------------------------- #
class TestCodec:
    def test_request_vote_round_trips(self) -> None:
        msg = RequestVote(term=3, candidate_id='n2', last_log_index=5, last_log_term=2)
        assert decode(encode(msg)) == msg

    def test_request_vote_reply_round_trips(self) -> None:
        msg = RequestVoteReply(term=3, vote_granted=True, sender='n1')
        assert decode(encode(msg)) == msg

    def test_append_entries_round_trips_with_entries_and_payload(self) -> None:
        entries = (
            LogEntry(term=1, index=1, payload={'index': 0, 'trust_updates': []}),
            LogEntry(term=1, index=2, payload=None),
        )
        msg = AppendEntries(term=1, leader_id='n1', prev_log_index=0, prev_log_term=0,
                            entries=entries, leader_commit=0)
        assert decode(encode(msg)) == msg

    def test_append_entries_reply_round_trips(self) -> None:
        msg = AppendEntriesReply(term=2, success=True, sender='n3', match_index=7)
        assert decode(encode(msg)) == msg

    def test_decode_rejects_unknown_type(self) -> None:
        with pytest.raises(ValueError):
            decode({'type': 'not_a_real_rpc'})

    def test_encode_rejects_unknown_message(self) -> None:
        with pytest.raises(TypeError):
            encode('just a string, not an RPC dataclass')


# --------------------------------------------------------------------------- #
# Real sockets                                                                 #
# --------------------------------------------------------------------------- #
class _Inbox:
    def __init__(self) -> None:
        self.messages = []
        self._got_one = threading.Event()

    def __call__(self, message, now) -> None:
        self.messages.append((message, now))
        self._got_one.set()

    def wait_for_one(self, timeout: float = 2.0) -> None:
        assert self._got_one.wait(timeout), "no message arrived in time"


@pytest.fixture
def two_transports():
    port_a, port_b = _free_port(), _free_port()
    inbox_a, inbox_b = _Inbox(), _Inbox()
    a = TcpTransport('a', ('127.0.0.1', port_a), {'b': ('127.0.0.1', port_b)}, on_message=inbox_a)
    b = TcpTransport('b', ('127.0.0.1', port_b), {'a': ('127.0.0.1', port_a)}, on_message=inbox_b)
    a.start()
    b.start()
    try:
        yield a, b, inbox_a, inbox_b
    finally:
        a.stop()
        b.stop()


class TestTcpTransport:
    def test_send_delivers_a_message_to_the_peer(self, two_transports) -> None:
        a, b, inbox_a, inbox_b = two_transports
        vote = RequestVote(term=1, candidate_id='a', last_log_index=0, last_log_term=0)
        a.send('a', 'b', vote)
        inbox_b.wait_for_one()
        assert inbox_b.messages[0][0] == vote

    def test_round_trip_reply(self, two_transports) -> None:
        a, b, inbox_a, inbox_b = two_transports
        a.send('a', 'b', RequestVote(term=1, candidate_id='a', last_log_index=0, last_log_term=0))
        inbox_b.wait_for_one()
        b.send('b', 'a', RequestVoteReply(term=1, vote_granted=True, sender='b'))
        inbox_a.wait_for_one()
        assert inbox_a.messages[0][0] == RequestVoteReply(term=1, vote_granted=True, sender='b')

    def test_append_entries_with_a_replicated_block_payload_survives_the_wire(self, two_transports) -> None:
        """The exact shape RaftBackend puts on the wire: a nested dict payload
        (a serialized Block), not a bare scalar."""
        a, b, inbox_a, inbox_b = two_transports
        payload = {
            'index': 1, 'timestamp': 123.456, 'previous_hash': '0' * 64,
            'merkle_root': 'deadbeef', 'proposer_id': 'a', 'raft_term': 1,
            'trust_updates': [{'device_id': 'd1', 'edge_node_id': 'srv1'}],
            'hash': 'abc123',
        }
        entry = LogEntry(term=1, index=1, payload=payload)
        msg = AppendEntries(term=1, leader_id='a', prev_log_index=0, prev_log_term=0,
                            entries=(entry,), leader_commit=0)
        a.send('a', 'b', msg)
        inbox_b.wait_for_one()
        received = inbox_b.messages[0][0]
        assert received == msg
        assert received.entries[0].payload == payload

    def test_send_to_unknown_peer_does_not_raise(self, two_transports) -> None:
        a, _, _, _ = two_transports
        a.send('a', 'ghost', RequestVote(term=1, candidate_id='a', last_log_index=0, last_log_term=0))

    def test_send_when_peer_is_down_does_not_raise(self) -> None:
        port_a, port_ghost = _free_port(), _free_port()
        inbox_a = _Inbox()
        a = TcpTransport('a', ('127.0.0.1', port_a), {'ghost': ('127.0.0.1', port_ghost)},
                          on_message=inbox_a)
        a.start()
        try:
            a.send('a', 'ghost', RequestVote(term=1, candidate_id='a', last_log_index=0, last_log_term=0))
        finally:
            a.stop()

    def test_start_requires_on_message_to_be_set(self) -> None:
        transport = TcpTransport('a', ('127.0.0.1', _free_port()), {})
        with pytest.raises(RuntimeError):
            transport.start()

    def test_stop_is_idempotent_and_marks_stopped(self, two_transports) -> None:
        a, b, _, _ = two_transports
        a.stop()
        assert a._stopped.is_set()
        a.stop()  # must not raise on a second call
