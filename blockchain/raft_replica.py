"""Standalone RAFT replica process (Step 2 live demo).

Runs one replica of the trust ledger's RAFT cluster: a RaftBackend
(blockchain/commit_backend.py) wired to a TcpTransport
(blockchain/raft_transport.py), ticked on a background thread, with a small
HTTP control API so an external client -- blockchain/raft_demo.py, or in a
real deployment the controller itself -- can submit commits and check status
without importing this process's Python objects. It is deliberately a
separate OS process: "kill one" in the demo means terminating a process, not
mocking a failure inside one.

Run:
    python3 -m blockchain.raft_replica --id n1 \\
        --peers n1=127.0.0.1:9001,n2=127.0.0.1:9002,n3=127.0.0.1:9003 \\
        --http-port 9101
"""

import argparse
import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Sequence, Tuple

from blockchain.commit_backend import RaftBackend
from blockchain.raft_transport import TcpTransport
from contracts.trust_update import TrustUpdate

logger = logging.getLogger(__name__)

TICK_INTERVAL_S = 0.01
Address = Tuple[str, int]


def _parse_peers(spec: str) -> Dict[str, Address]:
    """'n1=127.0.0.1:9001,n2=127.0.0.1:9002' -> {'n1': ('127.0.0.1', 9001), ...}"""
    peers: Dict[str, Address] = {}
    for part in spec.split(','):
        node_id, addr = part.split('=')
        host, port = addr.rsplit(':', 1)
        peers[node_id] = (host, int(port))
    return peers


class Ticker:
    """Drives RaftBackend.drive_tick() on a fixed real-time interval -- the
    live-process equivalent of tests/test_commit_backend.py's `_Driver`."""

    def __init__(self, backend: RaftBackend, interval_s: float = TICK_INTERVAL_S) -> None:
        self._backend = backend
        self._interval_s = interval_s
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name='raft-ticker')

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2.0)

    def _run(self) -> None:
        while not self._stop.is_set():
            self._backend.drive_tick()
            time.sleep(self._interval_s)


def _make_handler(backend: RaftBackend):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, fmt: str, *args: Any) -> None:
            logger.debug("%s - %s", self.address_string(), fmt % args)

        def _write_json(self, code: int, payload: Dict[str, Any]) -> None:
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path == '/status':
                self._write_json(200, backend.status())
            else:
                self._write_json(404, {'error': 'not found'})

        def do_POST(self) -> None:
            if self.path != '/commit':
                self._write_json(404, {'error': 'not found'})
                return
            length = int(self.headers.get('Content-Length', 0) or 0)
            raw = self.rfile.read(length) if length else b''
            try:
                rows = json.loads(raw) if raw else []
            except json.JSONDecodeError:
                self._write_json(400, {'error': 'malformed JSON body'})
                return

            try:
                updates = [TrustUpdate(**row) for row in rows]
            except TypeError as exc:
                self._write_json(400, {'error': f'malformed TrustUpdate row: {exc}'})
                return

            block = backend.commit(updates)
            if block is None:
                # Not the leader, or the commit timed out -- either way the
                # caller should retry, following leader_id if present.
                self._write_json(409, {'ok': False, 'status': backend.status()})
                return
            self._write_json(200, {
                'ok': True,
                'block_index': block.index,
                'block_hash': block.hash,
                'raft_term': block.raft_term,
            })

    return Handler


def run(
    node_id: str,
    peers: Dict[str, Address],
    http_host: str,
    http_port: int,
    commit_timeout_s: float = 2.0,
) -> None:
    bind_addr = peers[node_id]
    peer_addrs = {nid: addr for nid, addr in peers.items() if nid != node_id}

    transport = TcpTransport(node_id, bind_addr, peer_addrs)
    backend = RaftBackend(
        node_id, peers=list(peer_addrs), transport=transport,
        commit_timeout_s=commit_timeout_s,
    )
    transport.on_message = backend.drive_receive
    transport.start()

    ticker = Ticker(backend)
    ticker.start()

    server = ThreadingHTTPServer((http_host, http_port), _make_handler(backend))
    logger.info("%s: RAFT on %s, control API on http://%s:%d",
                node_id, bind_addr, http_host, http_port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        ticker.stop()
        transport.stop()


def main(argv: Optional[Sequence[str]] = None) -> None:
    logging.basicConfig(
        level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s',
    )
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--id', required=True, help="this replica's node ID (a key in --peers)")
    p.add_argument('--peers', required=True,
                   help='comma-separated node_id=host:port for every replica, including this one')
    p.add_argument('--http-port', type=int, required=True, help='control API port')
    p.add_argument('--http-host', default='127.0.0.1')
    p.add_argument('--commit-timeout-s', type=float, default=2.0)
    args = p.parse_args(argv)

    peers = _parse_peers(args.peers)
    if args.id not in peers:
        p.error(f"--id {args.id!r} must be a key in --peers")

    run(args.id, peers, args.http_host, args.http_port, args.commit_timeout_s)


if __name__ == '__main__':
    main()
