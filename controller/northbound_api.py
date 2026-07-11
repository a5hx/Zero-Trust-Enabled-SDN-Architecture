"""Northbound REST API for the trust-aware controller.

stdlib-only ThreadingHTTPServer (os-ken's os_ken.app.wsgi is confirmed
missing from Ubuntu's trimmed python3-os-ken package -- see
[[project-zerotrust-sdn-environment]]). Runs as its own os-ken hub
greenthread/OS thread, started by TrustBalancerApp.start().

Endpoints:
    POST /auth/challenge  {device_id} -> {nonce: hex}
    POST /auth/verify     {device_id, response: hex} -> {token} | 403
    GET  /trust/score     [?node_id=] -> {node_id: score} or {node_id: score, ...}
    POST /offload/request -> advisory only, installs nothing (see
        TrustBalancerApp.handle_offload_advisory -- the real routing decision
        happens on the VIP data-plane path)
    GET  /node/status     [?node_id=] -> TrustState.snapshot(), full or one node
    GET  /ledger/verify   -> {valid, chain_length}
    POST /report          {device_id, vip_src_port, status, latency_ms} -- a
        client's task-completion report. Not one of the deck's original five
        endpoints, but required for the demo to function: this is how
        real task outcomes reach TrustState at all. client_ip is taken from
        the request's own socket (self.client_address[0]), never from the
        JSON body -- the client cannot spoof which node its report applies to
        that way, since the /report POST originates from the same host as the
        /task connection it's completing (see simulation/iot_client.py).
    POST /register        {node_id, concurrency} -- agent startup registration.
"""

import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict
from urllib.parse import parse_qs, urlsplit

from security.authenticator import AuthError
from controller.trust_state import TrustState

logger = logging.getLogger(__name__)


def _make_handler(app: Any, state: TrustState):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args) -> None:
            logger.info("%s - %s", self.address_string(), fmt % args)

        def _write_json(self, code: int, payload: Dict[str, Any]) -> None:
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self) -> Dict[str, Any]:
            length = int(self.headers.get('Content-Length', 0) or 0)
            if not length:
                return {}
            raw = self.rfile.read(length)
            return json.loads(raw) if raw else {}

        def do_GET(self) -> None:
            split = urlsplit(self.path)
            path = split.path
            qs = parse_qs(split.query)
            node_id = qs.get('node_id', [None])[0]

            try:
                if path == '/trust/score':
                    if node_id:
                        self._write_json(200, {node_id: state.trust_calc.get_score(node_id)})
                    else:
                        self._write_json(200, {
                            nid: state.trust_calc.get_score(nid) for nid in state.node_ids
                        })
                elif path == '/node/status':
                    snapshot = state.snapshot()
                    if node_id:
                        if node_id not in snapshot:
                            self._write_json(404, {'error': f'unknown node {node_id!r}'})
                        else:
                            self._write_json(200, {node_id: snapshot[node_id]})
                    else:
                        self._write_json(200, snapshot)
                elif path == '/ledger/verify':
                    self._write_json(200, {
                        'valid': state.commit_backend.verify(),
                        'chain_length': state.commit_backend.chain_length(),
                    })
                else:
                    self._write_json(404, {'error': 'not found'})
            except Exception:
                logger.exception("GET %s failed", path)
                self._write_json(500, {'error': 'internal error'})

        def do_POST(self) -> None:
            path = urlsplit(self.path).path
            try:
                body = self._read_json()
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._write_json(400, {'error': 'malformed JSON body'})
                return

            try:
                if path == '/auth/challenge':
                    self._handle_auth_challenge(body)
                elif path == '/auth/verify':
                    self._handle_auth_verify(body)
                elif path == '/offload/request':
                    self._write_json(200, app.handle_offload_advisory())
                elif path == '/report':
                    self._handle_report(body)
                elif path == '/register':
                    self._handle_register(body)
                else:
                    self._write_json(404, {'error': 'not found'})
            except KeyError as exc:
                self._write_json(400, {'error': f'missing field {exc}'})
            except Exception:
                logger.exception("POST %s failed", path)
                self._write_json(500, {'error': 'internal error'})

        def _handle_auth_challenge(self, body: Dict[str, Any]) -> None:
            device_id = body['device_id']
            nonce = state.authenticator.issue_challenge(device_id)
            self._write_json(200, {'nonce': nonce.hex()})

        def _handle_auth_verify(self, body: Dict[str, Any]) -> None:
            device_id = body['device_id']
            response = bytes.fromhex(body['response'])
            try:
                token = state.authenticator.verify_response(device_id, response)
            except AuthError as exc:
                self._write_json(403, {'error': str(exc)})
                return
            self._write_json(200, {'token': token})

        def _handle_report(self, body: Dict[str, Any]) -> None:
            client_ip = self.client_address[0]
            vip_src_port = int(body['vip_src_port'])
            device_id = body['device_id']
            status = body['status']
            latency_ms = float(body['latency_ms'])

            score = app.handle_client_report(client_ip, vip_src_port, device_id, status, latency_ms)
            self._write_json(200, {'accepted': score is not None, 'trust_score': score})

        def _handle_register(self, body: Dict[str, Any]) -> None:
            node_id = body['node_id']
            concurrency = int(body.get('concurrency', 4))
            state.set_concurrency(node_id, concurrency)
            self._write_json(200, {'ok': True})

    return Handler


class NorthboundAPI(ThreadingHTTPServer):
    """Thin wrapper so callers don't have to build the handler class
    themselves. `app` is a TrustBalancerApp (duck-typed here -- not imported,
    to avoid a circular import with controller/trust_balancer.py)."""

    def __init__(self, app: Any, state: TrustState, host: str, port: int) -> None:
        handler_cls = _make_handler(app, state)
        super().__init__((host, port), handler_cls)
        logger.info("NorthboundAPI listening on %s:%d", host, port)
