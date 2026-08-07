"""Northbound REST API for the trust-aware controller.

stdlib-only ThreadingHTTPServer (os-ken's os_ken.app.wsgi is confirmed
missing from Ubuntu's trimmed python3-os-ken package -- see
[[project-zerotrust-sdn-environment]]). Runs as its own os-ken hub
greenthread/OS thread, started by TrustBalancerApp.start().

Endpoints:
    POST /auth/challenge  {device_id} -> {nonce: hex}
    POST /auth/verify     {device_id, response: hex} -> {token} | 403
        A 403 also publishes an 'auth_denied' event carrying the structured
        AuthError.kind, so a refused admission is visible to the event
        recording rather than only to the device that got refused.
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

Dashboard routes (added alongside the five deck endpoints above; all read-only,
and all inert unless controller.dashboard.enabled is set in the config):
    GET  /                -> dashboard/index.html
    GET  /api/topology    -> the node/link graph the dashboard draws
    GET  /api/events      -> Server-Sent Events stream of controller events
    GET  /api/flows       -> current flow tables with live counters ("rules")

SSE rather than WebSockets deliberately: it is one-way (controller -> browser,
which is all this needs), it is plain HTTP so it works on the stdlib
ThreadingHTTPServer already in use here, and it needs no third-party library --
which matters because this box is apt-only Python 3.14 with no pip (see
[[project-zerotrust-sdn-environment]]).
"""

import json
import logging
import queue
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlsplit

from security.authenticator import AuthError
from controller.trust_state import TrustState

logger = logging.getLogger(__name__)

_DASHBOARD_DIR = Path(__file__).resolve().parent.parent / 'dashboard'

# How long an idle SSE stream waits before emitting a keepalive comment. Without
# this, a proxy or an asleep laptop can silently drop a connection that simply
# has nothing to say during a quiet stretch of the demo.
_SSE_HEARTBEAT_S = 15.0


def _make_handler(app: Any, state: TrustState):
    class Handler(BaseHTTPRequestHandler):
        # SSE streams are long-lived; HTTP/1.1 keeps the socket framing sane.
        protocol_version = 'HTTP/1.1'

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

            # Dashboard routes are handled first and return early. /api/events
            # in particular never returns until the client disconnects, so it
            # must not fall through to the JSON paths below.
            if path in ('/', '/index.html', '/dashboard'):
                self._serve_dashboard()
                return
            if path == '/api/events':
                self._serve_events()
                return
            if path == '/api/topology':
                self._write_json(200, app.topology_graph())
                return
            if path == '/api/flows':
                self._write_json(200, {'flows': app.flow_table()})
                return
            if path == '/api/ports':
                self._write_json(200, {'ports': app.port_table()})
                return
            if path == '/api/optimizer':
                self._write_json(200, app.optimizer_status())
                return

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
                elif path == '/monitor/pause':
                    # Teardown ordering, not a security control. The harness
                    # kills the agents at end of run while the controller is
                    # still polling every second, so the last two sweeps score
                    # eight live-until-a-moment-ago nodes as unreachable and the
                    # final recorded frame shows the whole fleet quarantined --
                    # a run that served 16,586 tasks cleanly ends looking like a
                    # collapse (live runs 5 and 6, t=1719s / t=1770s).
                    #
                    # This does NOT relax "seen-then-dark is anomalous", which
                    # is a real Sprint 1 finding: polling stops entirely, so no
                    # verdict is softened -- there is simply no sweep after the
                    # operator says the fleet is going away on purpose.
                    self._write_json(200, {'paused': app.pause_monitor()})
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
            # Same discipline as _handle_report below: identity comes from the
            # request's own socket, never the JSON body, so a claim about
            # who's asking can't be forged in the body -- this is what
            # Authenticator's source-IP pinning checks against (see
            # security/authenticator.py's spoofing defence).
            source_ip = self.client_address[0]
            try:
                token = state.authenticator.verify_response(device_id, response, source_ip)
            except AuthError as exc:
                # Publish the denial. Until this existed, a refused admission
                # left no trace on the event bus at all -- the controller did
                # the right thing and then forgot it, so the JSONL recording
                # (and anything scoring it, e.g. evaluation/attack_report.py)
                # could never see an identity-spoofing attempt. `kind` is the
                # structured tag from security/authenticator.py, which is what
                # separates a spoofer (correct key, wrong source -- 'ip_pin')
                # from a device that never held the key ('bad_response').
                #
                # Safe to publish on every denial rather than only a rising
                # edge, unlike the flood tell: a denied device authenticates
                # once and then sends nothing (simulation/iot_client.py's
                # admission path never retries), so this cannot become a
                # bus-flooding event source.
                kind = getattr(exc, 'kind', None)
                app.bus.publish(
                    'auth_denied', device_id=device_id, source_ip=source_ip,
                    kind=kind, reason=str(exc),
                )
                # ...and into classification, which turns 'ip_pin' into the
                # discrete label `spoof` and 'bad_response' into
                # `bad_credentials` (plan_adv.md Phase 2).
                record = getattr(app, 'record_auth_denial', None)
                if record is not None:
                    record(device_id, source_ip, kind)
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

        # -------------------------------------------------------------- #
        # Dashboard                                                       #
        # -------------------------------------------------------------- #
        def _serve_dashboard(self) -> None:
            index = _DASHBOARD_DIR / 'index.html'
            try:
                body = index.read_bytes()
            except OSError:
                self._write_json(404, {'error': 'dashboard/index.html not found'})
                return
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _serve_events(self) -> None:
            """Server-Sent Events stream. Holds this thread (one per client, via
            ThreadingHTTPServer) until the browser goes away."""
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            # SSE is a stream of unknown length: no Content-Length, and the
            # connection must stay open -- the opposite of what _write_json does.
            self.send_header('Connection', 'keep-alive')
            self.send_header('X-Accel-Buffering', 'no')
            self.end_headers()

            q = app.bus.subscribe()
            try:
                # Backfill first, so a browser opened mid-run immediately has a
                # populated topology/rules/trust view instead of a blank page
                # until the next event happens to fire.
                for event in app.bus.history():
                    self._write_sse(event)

                while True:
                    try:
                        event = q.get(timeout=_SSE_HEARTBEAT_S)
                    except queue.Empty:
                        self.wfile.write(b': keepalive\n\n')
                        self.wfile.flush()
                        continue
                    self._write_sse(event)
            except (BrokenPipeError, ConnectionResetError):
                pass  # browser closed the tab -- entirely normal
            finally:
                app.bus.unsubscribe(q)

        def _write_sse(self, event: Dict[str, Any]) -> None:
            payload = json.dumps(event)
            self.wfile.write(f'data: {payload}\n\n'.encode())
            self.wfile.flush()

    return Handler


class NorthboundAPI(ThreadingHTTPServer):
    """Thin wrapper so callers don't have to build the handler class
    themselves. `app` is a TrustBalancerApp (duck-typed here -- not imported,
    to avoid a circular import with controller/trust_balancer.py)."""

    def __init__(self, app: Any, state: TrustState, host: str, port: int) -> None:
        handler_cls = _make_handler(app, state)
        super().__init__((host, port), handler_cls)
        logger.info("NorthboundAPI listening on %s:%d", host, port)
