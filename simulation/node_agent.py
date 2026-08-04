#!/usr/bin/env python3
"""HTTP task agent for one edge server (srvN) in the Zero Trust SDN demo.

Runs inside a Mininet host's network namespace (stdlib only — no dependency on
anything installed outside the host's own netns). Does REAL bounded work per
task (a CPU-bound hash loop, not a sleep), so a malicious node's lies about its
own load have real consequences: a Sybil liar that attracts traffic it cannot
serve genuinely degrades under it. That degradation is what lets the trust
formula's B (latency) and H (honesty) components — and flow_monitor's
observed-vs-claimed CPU check — actually catch it.

Endpoints:
    POST /task    -> do ~work_ms of real work, reply {"ok": true, "node_id": ...}
    GET  /status  -> claimed telemetry: {"node_id","cpu_load","latency_ms",
                                          "active_tasks","concurrency"}

--malicious sybil: spawns `concurrency` background CPU-burning threads (real
                   load) while /status always claims a low, fixed cpu_load —
                   the lie flow_monitor's honesty check is built to catch.
--malicious drop:  accepts /task connections and never responds. The tell is
                   NOT in this agent's own reporting (it can self-report CPU
                   honestly) — it is in the client-observed timeout rate,
                   which controller/flow_monitor.py watches separately.
"""

import argparse
import hashlib
import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

logger = logging.getLogger('node_agent')

_state_lock = threading.Lock()
_active_tasks = 0
_recent_latencies_ms: list = []
_LATENCY_WINDOW = 20

# Cumulative seconds this process has spent *inside* /task doing real work.
# Monotonic and never reset, so the controller can difference two polls and get
# a duty cycle over exactly the window it chooses -- see TrustState.claimed_load.
#
# This exists because `active_tasks / concurrency` is an instantaneous sample of
# a step function, and the controller's own occupancy estimate is an integral.
# Comparing the two compares different quantities and taxes a busy honest node
# (study Finding 6 / LIVE_RUN_8_40_3 Defect 8). A cumulative counter is the one
# shape both sides can integrate identically.
_busy_seconds_total = 0.0
_agent_started_at = time.monotonic()


def _burn_cpu_for_ms(duration_ms: float) -> None:
    """Spend roughly duration_ms of real CPU time hashing. Not a sleep — the
    point is to genuinely occupy the process, so contention (from --malicious
    sybil's background burners) genuinely slows this down."""
    end = time.monotonic() + duration_ms / 1000.0
    buf = b'zero-trust-sdn-workload'
    while time.monotonic() < end:
        buf = hashlib.sha256(buf).digest()


def _sybil_burn_loop(stop_event: threading.Event) -> None:
    """Background CPU consumer for --malicious sybil. Runs until stopped."""
    buf = b'sybil-background-load'
    while not stop_event.is_set():
        buf = hashlib.sha256(buf).digest()


class AgentHandler(BaseHTTPRequestHandler):
    # Set from main() before the server starts; shared across all request
    # instances (BaseHTTPRequestHandler is instantiated fresh per connection).
    node_id = 'srv?'
    concurrency = 4
    work_ms = 40.0
    malicious = 'none'
    claimed_cpu_lie = 0.1

    def log_message(self, fmt: str, *args) -> None:
        logger.info("%s - %s", self.address_string(), fmt % args)

    def _write_json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path != '/status':
            self._write_json(404, {'error': 'not found'})
            return

        with _state_lock:
            active = _active_tasks
            busy_seconds = _busy_seconds_total
            latency_ms = (
                sum(_recent_latencies_ms) / len(_recent_latencies_ms)
                if _recent_latencies_ms else self.work_ms
            )

        if self.malicious == 'sybil':
            cpu_load = self.claimed_cpu_lie  # the lie, regardless of real load
            # Lie *consistently*. A fabricated cpu_load next to a truthful
            # busy_seconds is an internal contradiction the controller could
            # catch for free, which would make this a strictly weaker attacker
            # than the one runs 1-6 were measured against. Advance the counter
            # at exactly the duty cycle being claimed, so the two agree and the
            # node still has to be caught on evidence it does not control (the
            # latency tell, or busy-time-per-task against the fleet median).
            uptime = time.monotonic() - _agent_started_at
            busy_seconds = uptime * cpu_load * max(1, self.concurrency)

        else:
            cpu_load = min(1.0, active / max(1, self.concurrency))

        self._write_json(200, {
            'node_id': self.node_id,
            'cpu_load': round(cpu_load, 4),
            'latency_ms': round(latency_ms, 2),
            'active_tasks': active,
            'concurrency': self.concurrency,
            # Cumulative, monotonic, in seconds. See _busy_seconds_total.
            'busy_seconds': round(busy_seconds, 6),
        })

    def do_POST(self) -> None:
        if self.path != '/task':
            self._write_json(404, {'error': 'not found'})
            return

        length = int(self.headers.get('Content-Length', 0) or 0)
        if length:
            self.rfile.read(length)

        if self.malicious == 'drop':
            # Accept, then never respond. The client's own timeout is the tell —
            # this agent has nothing dishonest to report about itself. The
            # Mininet demo runs only minutes, so parking a handler thread per
            # dropped task is harmless (each gets its own thread; no CPU spent).
            time.sleep(3600)
            return

        global _active_tasks, _busy_seconds_total
        with _state_lock:
            _active_tasks += 1
        start = time.monotonic()
        try:
            _burn_cpu_for_ms(self.work_ms)
        finally:
            elapsed = time.monotonic() - start
            elapsed_ms = elapsed * 1000.0
            with _state_lock:
                _active_tasks -= 1
                # Accrue *in-handler* time only. This is service time S, not the
                # residence time L the controller sees end-to-end (L includes
                # flow install, transit and the client's own report), which is
                # exactly the distinction the honesty check needs.
                _busy_seconds_total += elapsed
                _recent_latencies_ms.append(elapsed_ms)
                if len(_recent_latencies_ms) > _LATENCY_WINDOW:
                    _recent_latencies_ms.pop(0)

        self._write_json(200, {'ok': True, 'node_id': self.node_id})


def main() -> None:
    parser = argparse.ArgumentParser(description='Zero Trust SDN edge-server agent')
    parser.add_argument('--node-id', required=True)
    parser.add_argument('--port', type=int, default=8000)
    parser.add_argument('--concurrency', type=int, default=4)
    parser.add_argument('--work-ms', type=float, default=40.0)
    parser.add_argument('--malicious', choices=['none', 'sybil', 'drop'], default='none')
    parser.add_argument(
        '--claimed-cpu-lie', type=float, default=0.1,
        help='Fixed cpu_load reported by --malicious sybil, regardless of real load',
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
    )

    AgentHandler.node_id = args.node_id
    AgentHandler.concurrency = args.concurrency
    AgentHandler.work_ms = args.work_ms
    AgentHandler.malicious = args.malicious
    AgentHandler.claimed_cpu_lie = args.claimed_cpu_lie

    stop_event = threading.Event()
    if args.malicious == 'sybil':
        logger.warning(
            "MALICIOUS MODE: sybil -- lying cpu_load=%.2f while burning real CPU "
            "on %d background thread(s)", args.claimed_cpu_lie, args.concurrency,
        )
        for _ in range(args.concurrency):
            threading.Thread(target=_sybil_burn_loop, args=(stop_event,), daemon=True).start()
    elif args.malicious == 'drop':
        logger.warning("MALICIOUS MODE: drop -- /task will accept and never respond")

    server = ThreadingHTTPServer(('0.0.0.0', args.port), AgentHandler)
    logger.info(
        "node_agent %s listening on :%d (malicious=%s)",
        args.node_id, args.port, args.malicious,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        server.shutdown()


if __name__ == '__main__':
    main()
