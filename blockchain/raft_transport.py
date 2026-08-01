"""TCP Transport for blockchain/raft.py's `Transport` protocol.

`RaftNode` is transport-agnostic: it only needs `send(src, dst, message)`,
fire-and-forget (see the `Transport` Protocol in blockchain/raft.py).
`InMemoryNetwork`, in that same module, is the *reference* transport used to
prove RAFT's safety properties under a virtual clock (tests/test_raft.py) --
those properties are not re-proven here. This module is the *real* one, used
to run replicas as separate OS processes talking over real sockets;
`RaftNode` does not change to use it, exactly as blockchain/raft.py's module
docstring promises.

Wire format
-----------
Each RPC is JSON, length-prefixed (4-byte big-endian length + UTF-8 JSON
body), over one persistent TCP connection per peer. JSON, not pickle: these
sockets face the network, and pickle deserializes arbitrary code on load --
an unacceptable attack surface for a project whose whole thesis is zero
trust. Every RPC dataclass in blockchain/raft.py is scalars plus nested
LogEntry/tuple structures, which round-trip through plain dicts cleanly, as
long as `LogEntry.payload` is itself already JSON-safe -- true here, since
the only payload producer is `blockchain.commit_backend.RaftBackend`, which
puts a plain dict (a serialized Block) in it, never a raw dataclass.

Delivery is best-effort: a peer that is down, unreachable, or slow to accept
a connection simply has the message dropped (logged at debug), matching
`Transport`'s documented contract that RAFT tolerates loss by design.
Connections are opened lazily on first send and reused; a broken one is
dropped and retried on the next send rather than raising out of `send()`.
"""

import json
import logging
import socket
import struct
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

from blockchain.raft import (
    AppendEntries,
    AppendEntriesReply,
    LogEntry,
    Message,
    RequestVote,
    RequestVoteReply,
)

logger = logging.getLogger(__name__)

_LEN_PREFIX = struct.Struct('!I')
Address = Tuple[str, int]


# --------------------------------------------------------------------------- #
# Wire codec                                                                   #
# --------------------------------------------------------------------------- #
def encode(message: Message) -> dict:
    if isinstance(message, RequestVote):
        return {
            'type': 'request_vote', 'term': message.term,
            'candidate_id': message.candidate_id,
            'last_log_index': message.last_log_index,
            'last_log_term': message.last_log_term,
        }
    if isinstance(message, RequestVoteReply):
        return {
            'type': 'request_vote_reply', 'term': message.term,
            'vote_granted': message.vote_granted, 'sender': message.sender,
        }
    if isinstance(message, AppendEntries):
        return {
            'type': 'append_entries', 'term': message.term,
            'leader_id': message.leader_id,
            'prev_log_index': message.prev_log_index,
            'prev_log_term': message.prev_log_term,
            'entries': [
                {'term': e.term, 'index': e.index, 'payload': e.payload}
                for e in message.entries
            ],
            'leader_commit': message.leader_commit,
        }
    if isinstance(message, AppendEntriesReply):
        return {
            'type': 'append_entries_reply', 'term': message.term,
            'success': message.success, 'sender': message.sender,
            'match_index': message.match_index,
        }
    raise TypeError(f"unencodable RAFT message type: {type(message)!r}")


def decode(d: dict) -> Message:
    kind = d['type']
    if kind == 'request_vote':
        return RequestVote(
            term=d['term'], candidate_id=d['candidate_id'],
            last_log_index=d['last_log_index'], last_log_term=d['last_log_term'],
        )
    if kind == 'request_vote_reply':
        return RequestVoteReply(
            term=d['term'], vote_granted=d['vote_granted'], sender=d['sender'],
        )
    if kind == 'append_entries':
        entries = tuple(
            LogEntry(term=e['term'], index=e['index'], payload=e['payload'])
            for e in d['entries']
        )
        return AppendEntries(
            term=d['term'], leader_id=d['leader_id'],
            prev_log_index=d['prev_log_index'], prev_log_term=d['prev_log_term'],
            entries=entries, leader_commit=d['leader_commit'],
        )
    if kind == 'append_entries_reply':
        return AppendEntriesReply(
            term=d['term'], success=d['success'], sender=d['sender'],
            match_index=d.get('match_index', 0),
        )
    raise ValueError(f"unknown RAFT message type on the wire: {kind!r}")


def _recv_exact(conn: socket.socket, n: int) -> Optional[bytes]:
    """Read exactly n bytes, or None on a clean/abrupt disconnect."""
    chunks: List[bytes] = []
    remaining = n
    while remaining > 0:
        chunk = conn.recv(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b''.join(chunks)


# --------------------------------------------------------------------------- #
# TCP transport                                                               #
# --------------------------------------------------------------------------- #
class TcpTransport:
    """`Transport` protocol implementation over TCP, for one replica.

    Args:
        node_id: This replica's ID (must match its RaftNode's node_id).
        bind_addr: (host, port) to listen on for inbound peer connections.
        peer_addrs: {peer_node_id: (host, port)} for every other replica.
        on_message: Called as `on_message(message, time.monotonic())` for
            every RPC received. Wire this to `RaftBackend.drive_receive`. May
            be set after construction (`transport.on_message = ...`), as long
            as it is set before `start()` -- the two are separate because the
            backend that owns `drive_receive` needs this transport to already
            exist before it can be built (see blockchain/raft_replica.py).
    """

    def __init__(
        self,
        node_id: str,
        bind_addr: Address,
        peer_addrs: Dict[str, Address],
        on_message: Optional[Callable[[Message, float], None]] = None,
    ) -> None:
        self.node_id = node_id
        self.bind_addr = bind_addr
        self.peer_addrs = dict(peer_addrs)
        self.on_message = on_message

        self._server: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None
        self._stopped = threading.Event()

        self._out_lock = threading.Lock()
        self._out_sockets: Dict[str, socket.socket] = {}

    # -- lifecycle ---------------------------------------------------------- #
    def start(self) -> None:
        if self.on_message is None:
            raise RuntimeError("TcpTransport.on_message must be set before start()")
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(self.bind_addr)
        self._server.listen(8)
        self._accept_thread = threading.Thread(
            target=self._accept_loop, daemon=True, name=f'raft-accept-{self.node_id}',
        )
        self._accept_thread.start()
        logger.info("%s: RAFT TCP transport listening on %s", self.node_id, self.bind_addr)

    def stop(self) -> None:
        self._stopped.set()
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass
        with self._out_lock:
            for sock in self._out_sockets.values():
                try:
                    sock.close()
                except OSError:
                    pass
            self._out_sockets.clear()

    # -- Transport protocol --------------------------------------------------#
    def send(self, src: str, dst: str, message: Message) -> None:
        try:
            body = json.dumps(encode(message)).encode('utf-8')
        except TypeError:
            logger.exception("%s: refusing to send unencodable message to %s", src, dst)
            return
        frame = _LEN_PREFIX.pack(len(body)) + body

        sock = self._get_out_socket(dst)
        if sock is None:
            return
        try:
            sock.sendall(frame)
        except OSError as exc:
            logger.debug("%s: send to %s failed (%s); dropping connection", src, dst, exc)
            self._drop_out_socket(dst, sock)

    # -- outbound connection management -------------------------------------#
    def _get_out_socket(self, dst: str) -> Optional[socket.socket]:
        with self._out_lock:
            sock = self._out_sockets.get(dst)
            if sock is not None:
                return sock

        addr = self.peer_addrs.get(dst)
        if addr is None:
            logger.warning("%s: no address known for peer %s", self.node_id, dst)
            return None
        try:
            sock = socket.create_connection(addr, timeout=0.5)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError as exc:
            logger.debug("%s: could not connect to %s at %s (%s)", self.node_id, dst, addr, exc)
            return None

        with self._out_lock:
            self._out_sockets[dst] = sock
        return sock

    def _drop_out_socket(self, dst: str, sock: socket.socket) -> None:
        with self._out_lock:
            if self._out_sockets.get(dst) is sock:
                del self._out_sockets[dst]
        try:
            sock.close()
        except OSError:
            pass

    # -- inbound -------------------------------------------------------------#
    def _accept_loop(self) -> None:
        while not self._stopped.is_set():
            try:
                conn, _ = self._server.accept()
            except OSError:
                return  # socket closed by stop()
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            threading.Thread(
                target=self._reader_loop, args=(conn,), daemon=True,
                name=f'raft-reader-{self.node_id}',
            ).start()

    def _reader_loop(self, conn: socket.socket) -> None:
        try:
            while not self._stopped.is_set():
                header = _recv_exact(conn, _LEN_PREFIX.size)
                if header is None:
                    return
                (length,) = _LEN_PREFIX.unpack(header)
                body = _recv_exact(conn, length)
                if body is None:
                    return
                try:
                    message = decode(json.loads(body.decode('utf-8')))
                except (json.JSONDecodeError, UnicodeDecodeError, KeyError, ValueError, TypeError) as exc:
                    logger.warning("%s: dropping malformed RAFT frame (%s)", self.node_id, exc)
                    continue
                self.on_message(message, time.monotonic())
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
