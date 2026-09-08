"""Northbound HTTP API for the control arm.

Same wire contract as `controller/northbound_api.py` — it has to be, because
both arms are driven by the *same unmodified* `simulation/iot_client.py` and
`simulation/node_agent.py` binaries. If the baseline needed a patched client,
the two arms would differ in the workload as well as the architecture and
nothing measured could be attributed to either.

What is missing here is the whole point:

    /auth/verify   ALWAYS returns 200. There is no admission control in this
                   arm: no PRESENT-80 check, no source-IP pin, no roster. A
                   device holding the wrong key is admitted; a device claiming
                   to be another device is admitted as that device.

    /report        Feeds the observer and nothing else. In the treatment arm
                   this same call can move a node across the isolation
                   threshold and trigger quarantine + re-steer within one poll.
                   Here it updates a number.

    (absent)       No `/offload/request`, no dashboard HTML, no ledger
                   endpoint, no meter/rate-limit surface. Those are treatment
                   features and this arm must not contain them even unused.

ADMISSION IS RECORDED, NOT CHECKED
----------------------------------
Every successful handshake publishes an `auth_admitted` event carrying the
claimed `device_id` and the socket's real `source_ip`. That is *not* a check —
nothing is compared, nothing is refused, and the run proceeds identically
whatever the two values are. It is evidence, written down so the comparison can
be scored offline against the ground truth already in the `topology` event:

    * iot39 / iot40 hold a deliberately wrong key and are admitted anyway —
      the treatment arm published `auth_denied kind=bad_response` for these.
    * iot38 authenticates as `iot1` from 10.0.0.38 and is admitted as iot1 —
      the treatment arm published `auth_denied kind=ip_pin` and refused it.
      From that moment this recording contains two devices reporting as iot1,
      and `base_model/compare.py` reports the spoof as SUCCEEDED.

Deriving those findings from recorded facts (claimed id vs. source ip) rather
than from a verification step is what keeps this arm honestly featureless: the
controller never knew anything was wrong.
"""

import json
import logging
import os
import queue
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict
from urllib.parse import urlsplit

logger = logging.getLogger('base_model.baseline_api')


def _make_handler(app: Any):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, fmt: str, *args) -> None:  # noqa: A003
            logger.debug("%s - %s", self.address_string(), fmt % args)

        # -- plumbing ------------------------------------------------- #
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

        # -- GET ------------------------------------------------------ #
        def do_GET(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            if path == '/api/events':
                self._serve_events()
                return
            if path == '/api/status':
                self._write_json(200, {
                    'arm': 'baseline',
                    'strategy': app.router.strategy,
                    'nodes': app.observer.snapshot(),
                })
                return
            if path == '/api/bindings':
                # The routing policy, as actually applied. Served rather than
                # only logged so the map can be checked against
                # static_router.expected_static_map() while the run is live.
                self._write_json(200, {
                    'strategy': app.router.strategy,
                    'bindings': app.router.binding_table(),
                })
                return
            if path == '/health':
                self._write_json(200, {'ok': True, 'arm': 'baseline'})
                return
            self._write_json(404, {'error': 'not found'})

        def _serve_events(self) -> None:
            """SSE stream of the event bus, for watching a run live.

            Deliberately the only streaming surface: this arm ships no
            dashboard HTML. Anyone who wants the treatment arm's panels can
            replay the recording through `dashboard/replay.py`, which reads the
            JSONL both arms write.
            """
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.end_headers()
            q = app.bus.subscribe()
            try:
                for event in app.bus.history():
                    self._write_sse(event)
                while True:
                    try:
                        event = q.get(timeout=15.0)
                    except queue.Empty:
                        self.wfile.write(b': keepalive\n\n')
                        self.wfile.flush()
                        continue
                    self._write_sse(event)
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                app.bus.unsubscribe(q)

        def _write_sse(self, event: Dict[str, Any]) -> None:
            self.wfile.write(f'data: {json.dumps(event)}\n\n'.encode())
            self.wfile.flush()

        # -- POST ----------------------------------------------------- #
        def do_POST(self) -> None:  # noqa: N802
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
                elif path == '/report':
                    self._handle_report(body)
                elif path == '/register':
                    self._handle_register(body)
                elif path == '/topology/links':
                    self._write_json(200, {
                        'recorded': app.record_link_params(body.get('links') or []),
                    })
                elif path == '/monitor/pause':
                    # Same teardown ordering fix as the treatment arm. Without
                    # it the last polls of a run find eight just-killed agents
                    # and the final recorded frame reads as a fleet collapse on
                    # a run that served cleanly. It relaxes no verdict — polling
                    # simply stops when the operator says the fleet is going
                    # away on purpose.
                    self._write_json(200, {'paused': app.pause_monitor()})
                else:
                    self._write_json(404, {'error': 'not found'})
            except KeyError as exc:
                self._write_json(400, {'error': f'missing field {exc}'})
            except Exception:
                logger.exception("POST %s failed", path)
                self._write_json(500, {'error': 'internal error'})

        def _handle_auth_challenge(self, body: Dict[str, Any]) -> None:
            """Issue a nonce that will never be checked.

            The nonce is real and freshly random, so the client's PRESENT-80
            path runs exactly as it does in the treatment arm — the device
            spends the same CPU and the handshake costs the same two round
            trips. Only the verdict is absent. That keeps the workloads
            comparable: the baseline is not faster here because it skipped
            work the client still did.
            """
            device_id = body['device_id']
            nonce = os.urandom(8)
            self._write_json(200, {'nonce': nonce.hex()})
            logger.debug("challenge issued to %s (never verified)", device_id)

        def _handle_auth_verify(self, body: Dict[str, Any]) -> None:
            device_id = body['device_id']
            source_ip = self.client_address[0]
            token = app.admit(device_id, source_ip)
            self._write_json(200, {'token': token})

        def _handle_report(self, body: Dict[str, Any]) -> None:
            # Identity from the socket, never from the body — the same
            # discipline the treatment arm uses. Not a defence here (nothing
            # compares them), but it is what makes the recording able to show
            # that iot38's traffic came from 10.0.0.38 while claiming iot1.
            client_ip = self.client_address[0]
            payload = app.handle_client_report(
                client_ip=client_ip,
                vip_src_port=int(body['vip_src_port']),
                device_id=body['device_id'],
                status=body['status'],
                latency_ms=float(body['latency_ms']),
            )
            self._write_json(200, {
                'accepted': payload is not None,
                'trust_score': None if payload is None else payload['trust'],
            })

        def _handle_register(self, body: Dict[str, Any]) -> None:
            app.set_node_concurrency(
                body['node_id'], int(body.get('concurrency', 4)),
            )
            self._write_json(200, {'ok': True})

    return Handler


class BaselineAPI(ThreadingHTTPServer):
    """Threaded HTTP server for the baseline controller.

    `daemon_threads` and the deep `request_queue_size` are both carried over
    from the treatment arm on purpose. The accept queue in particular: 48 hosts
    authenticate within the same second at this scale, and a shallow queue
    resets connections during that burst. In live run 9 that reset was
    misread by a client as a denial and cost the project a successful identity
    spoof. The control arm must not reproduce a *transport* failure that would
    then be scored as an architectural difference.
    """

    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128

    def __init__(self, app: Any, host: str, port: int) -> None:
        super().__init__((host, port), _make_handler(app))
        self._thread: threading.Thread | None = None
        logger.info("Baseline northbound API listening on %s:%d", host, port)

    def start_background(self) -> None:
        self._thread = threading.Thread(
            target=self.serve_forever, name='baseline-api', daemon=True,
        )
        self._thread.start()
