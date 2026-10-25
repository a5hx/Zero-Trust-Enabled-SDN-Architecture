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
        --http-port 9101 [--data-dir data/raft] [--auth-token-env ZTSDN_LEDGER_TOKEN]

Control API:
    GET  /status             role, term, leader_id, commit_index, chain_length
    POST /commit             body: [TrustUpdate rows]  or  {"updates": [rows],
                             "config_hash": ...}
                             200 -> {ok, block_index, block_hash, raft_term, block,
                                     rejected}  (rejected: records that failed
                                     verification and are not in the block)
                             409 -> {ok: false, status}  (not leader / no majority
                                    in time -- retry, following status.leader_id)
                             422 -> {ok: false, rejected}  (every record failed
                                    verification -- do NOT retry)
    GET  /blocks?from=N      {blocks: [block dicts from index N], chain_length}

With --data-dir, term, vote and log are kept on disk (blockchain.raft.FileStorage)
so a killed replica rejoins with its log. With --verify-config, the replica
replays the trust arithmetic of every committed record against that config's
`trust:` block and appends only the records that check out (Phase 6,
blockchain/verifier.py). With --auth-token-env, every request
must carry `Authorization: Bearer <token>` (the token is read from that
environment variable, never from the command line, so it does not show in `ps`).
"""

import argparse
import hmac
import json
import logging
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Sequence, Tuple
from urllib.parse import parse_qs, urlsplit

from blockchain.commit_backend import RaftBackend
from blockchain.verifier import TrustReplay
from blockchain.raft import FileStorage
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


def _make_handler(backend: RaftBackend, auth_token: Optional[str] = None):
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

        def _authorized(self) -> bool:
            if not auth_token:
                return True
            given = self.headers.get('Authorization', '')
            if hmac.compare_digest(given, f'Bearer {auth_token}'):
                return True
            # Drain the body so the 401 is a clean response, not a reset.
            length = int(self.headers.get('Content-Length', 0) or 0)
            if length:
                self.rfile.read(length)
            self._write_json(401, {'error': 'missing or wrong bearer token'})
            return False

        def do_GET(self) -> None:
            if not self._authorized():
                return
            url = urlsplit(self.path)
            if url.path == '/status':
                self._write_json(200, backend.status())
            elif url.path == '/blocks':
                try:
                    start = int(parse_qs(url.query).get('from', ['1'])[0])
                except ValueError:
                    self._write_json(400, {'error': 'from must be an integer'})
                    return
                blocks = backend.blocks_from(max(1, start))
                self._write_json(200, {
                    'blocks': [b.to_dict() for b in blocks],
                    'chain_length': backend.chain_length(),
                })
            else:
                self._write_json(404, {'error': 'not found'})

        def do_POST(self) -> None:
            if not self._authorized():
                return
            if self.path != '/commit':
                self._write_json(404, {'error': 'not found'})
                return
            length = int(self.headers.get('Content-Length', 0) or 0)
            raw = self.rfile.read(length) if length else b''
            try:
                body = json.loads(raw) if raw else []
            except json.JSONDecodeError:
                self._write_json(400, {'error': 'malformed JSON body'})
                return
            # Two body shapes: the demos' bare list of rows, and the
            # controller's {"updates": [...]} object.
            rows = body.get('updates', []) if isinstance(body, dict) else body

            try:
                updates = [TrustUpdate(**row) for row in rows]
            except TypeError as exc:
                self._write_json(400, {'error': f'malformed TrustUpdate row: {exc}'})
                return

            config_hash = body.get('config_hash') if isinstance(body, dict) else None
            result = backend.commit_ex(updates, config_hash=config_hash)
            if result is None:
                # Not the leader, or the commit timed out -- either way the
                # caller should retry, following leader_id if present.
                self._write_json(409, {'ok': False, 'status': backend.status()})
                return
            if result.block is None:
                # Committed to the log, and every record failed verification
                # on every replica. Retrying would get the same verdict.
                self._write_json(422, {'ok': False, 'rejected': result.rejected})
                return
            block = result.block
            self._write_json(200, {
                'ok': True,
                'block_index': block.index,
                'block_hash': block.hash,
                'raft_term': block.raft_term,
                # The full block, so a client can append it to its own ledger
                # and re-validate it (RemoteRaftBackend's mirror).
                'block': block.to_dict(),
                'rejected': result.rejected,
            })

    return Handler


def run(
    node_id: str,
    peers: Dict[str, Address],
    http_host: str,
    http_port: int,
    commit_timeout_s: float = 2.0,
    data_dir: Optional[str] = None,
    auth_token: Optional[str] = None,
    verify_config: Optional[str] = None,
) -> None:
    bind_addr = peers[node_id]
    peer_addrs = {nid: addr for nid, addr in peers.items() if nid != node_id}

    extra: Dict[str, Any] = {}
    if data_dir:
        extra['storage'] = FileStorage(os.path.join(data_dir, node_id))
    if verify_config:
        import yaml
        with open(verify_config) as fh:
            extra['verifier'] = TrustReplay(yaml.safe_load(fh).get('trust'))
        logger.info("%s: verifying trust records against %s (config %s)",
                    node_id, verify_config, extra['verifier'].hash[:12])
    transport = TcpTransport(node_id, bind_addr, peer_addrs)
    backend = RaftBackend(
        node_id, peers=list(peer_addrs), transport=transport,
        commit_timeout_s=commit_timeout_s, **extra,
    )
    transport.on_message = backend.drive_receive
    transport.start()

    ticker = Ticker(backend)
    ticker.start()

    server = ThreadingHTTPServer((http_host, http_port), _make_handler(backend, auth_token))
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
    p.add_argument('--data-dir', default=None,
                   help='keep term/vote/log on disk under DATA_DIR/<id> (survives restarts)')
    p.add_argument('--auth-token-env', default=None,
                   help='name of an environment variable holding the bearer token to require')
    p.add_argument('--verify-config', default=None,
                   help="re-verify every trust record against this config's trust: block")
    args = p.parse_args(argv)

    peers = _parse_peers(args.peers)
    if args.id not in peers:
        p.error(f"--id {args.id!r} must be a key in --peers")
    token = None
    if args.auth_token_env:
        token = os.environ.get(args.auth_token_env)
        if not token:
            p.error(f"--auth-token-env {args.auth_token_env}: variable is unset or empty")

    run(args.id, peers, args.http_host, args.http_port, args.commit_timeout_s,
        data_dir=args.data_dir, auth_token=token, verify_config=args.verify_config)


if __name__ == '__main__':
    main()


# --------------------------------------------------------------------------- #
# Local cluster launcher (used by run_demo.py --mode mininet)                  #
# --------------------------------------------------------------------------- #
def launch_local_cluster(ledger_cfg: Dict[str, Any], log_dir: str = 'logs',
                         config_path: Optional[str] = None) -> Dict[str, Any]:
    """Start every replica named in `ledger.launch_local` on this machine.

    Config shape (control-API addresses in ``replicas``, RAFT addresses in
    ``launch_local.raft_peers``, same IDs in both):

        ledger:
          backend: raft_remote
          replicas:   {n1: 127.0.0.1:9101, n2: 127.0.0.1:9102, n3: 127.0.0.1:9103}
          launch_local:
            raft_peers: {n1: 127.0.0.1:9001, n2: 127.0.0.1:9002, n3: 127.0.0.1:9003}
            data_dir: data/raft
            fresh: true        # wipe data_dir first: one chain per run
          verify: true         # Phase 6: replicas re-verify every trust record
                               # against config_path's trust: block

    On a real testbed, leave `launch_local` out and run one replica per machine
    (deploy/), pointing `replicas` at them. Returns {replica_id: Popen}.
    """
    import shutil
    import subprocess
    import sys

    launch = ledger_cfg['launch_local']
    if ledger_cfg.get('verify') and not config_path:
        raise ValueError('ledger.verify needs the config path, so the replicas can '
                         'read the same trust: block as the controller')
    control = {rid: addr for rid, addr in _parse_peers(
        ','.join(f'{k}={v}' for k, v in ledger_cfg['replicas'].items())).items()}
    raft_peers = launch['raft_peers']
    peers_arg = ','.join(f'{k}={v}' for k, v in raft_peers.items())
    data_dir = launch.get('data_dir')
    if data_dir and launch.get('fresh', True):
        shutil.rmtree(data_dir, ignore_errors=True)
    os.makedirs(log_dir, exist_ok=True)

    procs: Dict[str, Any] = {}
    for rid in raft_peers:
        host, port = control[rid]
        cmd = [sys.executable, '-m', 'blockchain.raft_replica', '--id', rid,
               '--peers', peers_arg, '--http-host', host, '--http-port', str(port),
               '--commit-timeout-s', str(launch.get('commit_timeout_s', 2.0))]
        if data_dir:
            cmd += ['--data-dir', data_dir]
        if ledger_cfg.get('auth_token_env'):
            cmd += ['--auth-token-env', ledger_cfg['auth_token_env']]
        if ledger_cfg.get('verify'):
            cmd += ['--verify-config', config_path]
        log = open(os.path.join(log_dir, f'raft_{rid}.log'), 'w')
        procs[rid] = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
    return procs


def wait_for_leader(ledger_cfg: Dict[str, Any], timeout_s: float = 15.0) -> Optional[str]:
    """Poll every replica's /status until one reports itself leader."""
    import http.client
    replicas = _parse_peers(','.join(f'{k}={v}' for k, v in ledger_cfg['replicas'].items()))
    token = os.environ.get(ledger_cfg['auth_token_env']) if ledger_cfg.get('auth_token_env') else None
    headers = {'Authorization': f'Bearer {token}'} if token else {}
    end = time.monotonic() + timeout_s
    while time.monotonic() < end:
        for rid, (host, port) in replicas.items():
            try:
                conn = http.client.HTTPConnection(host, port, timeout=0.5)
                conn.request('GET', '/status', headers=headers)
                status = json.loads(conn.getresponse().read() or b'{}')
                conn.close()
            except (OSError, ValueError, http.client.HTTPException):
                continue
            if status.get('role') == 'leader':
                return rid
        time.sleep(0.2)
    return None
