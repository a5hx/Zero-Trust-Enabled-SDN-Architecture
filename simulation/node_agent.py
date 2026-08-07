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

--malicious sybil:    spawns `concurrency` background CPU-burning threads
                   (real load) while /status always claims a low, fixed
                   cpu_load — the lie flow_monitor's honesty check is built
                   to catch.
--malicious drop:     accepts /task connections and never responds (100% of
                   tasks). The tell is NOT in this agent's own reporting (it
                   can self-report CPU honestly) — it is in the
                   client-observed timeout rate, which
                   controller/flow_monitor.py watches separately. Standard
                   name for this in the routing-attack literature:
                   blackhole.
--malicious grayhole: like drop, but only for a *fraction* of tasks
                   (--grayhole-drop-rate, default 0.5) — the rest get real
                   work and a real reply. Same timeout-rate tell as drop,
                   just weaker per-sample, which is the point: it exists to
                   test whether that tell's threshold still catches a
                   partial dropper, not just an always-dropper.
--malicious onoff:    alternates between an honest phase and a sybil-style
                   CPU lie every --onoff-period-s (split by --onoff-duty),
                   instead of lying continuously. This targets the trust
                   EMA directly (lambda_decay) rather than any one
                   telemetry check: the classic "on-off"/intermittent
                   reputation attack rebuilds trust during the honest phase
                   and spends it during the bad phase. Stress-tests this
                   project's own headline claim that an independent anomaly
                   gate catches what a trust score alone cannot (README
                   Finding 1) against an attacker built specifically to
                   exploit the trust score's memory.

--malicious-start-s: delay (seconds, default 0 = old behavior) before the
                   chosen --malicious mode ARMS. Before arming, the agent is
                   indistinguishable from --malicious none -- real work, real
                   telemetry, no dropped tasks -- which is what gives a live
                   run a clean pre-attack baseline interval to compare
                   against. This was documented in
                   docs/PROJECT_GUIDE.md's `start_s` config field before it
                   was actually wired here; config files already carry it.
"""

import argparse
import hashlib
import json
import logging
import random
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

# How long a --malicious drop handler parks a connection for. A module
# constant (rather than a literal in do_POST) so tests can shrink it instead
# of actually blocking for an hour.
_DROP_HANG_S = 3600.0

# Set once the --malicious mode actually activates (immediately, at process
# start, if --malicious-start-s is 0 -- the old behavior; otherwise when the
# arming timer fires). None until then. The sybil lie's synthetic
# busy_seconds is derived from *this*, not _agent_started_at, so a delayed
# attack doesn't claim duty cycle for time it was actually behaving honestly.
_attack_armed_at: 'float | None' = None

# --malicious onoff only: when the CURRENT bad phase started (None during a
# good phase). Its own timestamp, separate from _attack_armed_at, because the
# lie must not claim duty cycle for earlier phases -- including earlier BAD
# phases -- only the one running right now.
_onoff_bad_phase_started_at: 'float | None' = None


def _burn_cpu_for_ms(duration_ms: float) -> None:
    """Spend roughly duration_ms of real CPU time hashing. Not a sleep — the
    point is to genuinely occupy the process, so contention (from --malicious
    sybil's background burners) genuinely slows this down."""
    end = time.monotonic() + duration_ms / 1000.0
    buf = b'zero-trust-sdn-workload'
    while time.monotonic() < end:
        buf = hashlib.sha256(buf).digest()


def _sybil_burn_loop(stop_event: threading.Event) -> None:
    """Background CPU consumer for --malicious sybil (and onoff's bad phase).
    Runs until stopped."""
    buf = b'sybil-background-load'
    while not stop_event.is_set():
        buf = hashlib.sha256(buf).digest()


def _onoff_toggle_loop(
    node_id: str, period_s: float, duty: float, concurrency: int,
    master_stop_event: threading.Event,
) -> None:
    """Daemon-thread target for --malicious onoff: alternate BAD/GOOD phases
    forever, starting (and fully stopping) the sybil-style CPU burners at
    each phase boundary so a GOOD phase is genuinely honest, not just
    self-reporting honestly while secretly still burning cycles from the
    previous BAD phase."""
    global _onoff_bad_phase_started_at
    bad_s = max(0.0, period_s * duty)
    good_s = max(0.0, period_s * (1.0 - duty))
    while not master_stop_event.is_set():
        # BAD phase
        _onoff_bad_phase_started_at = time.monotonic()
        AgentHandler.onoff_bad = True
        logger.warning("%s: onoff -> BAD phase (%.1fs)", node_id, bad_s)
        phase_stop = threading.Event()
        for _ in range(concurrency):
            threading.Thread(
                target=_sybil_burn_loop, args=(phase_stop,), daemon=True,
            ).start()
        if master_stop_event.wait(bad_s):
            phase_stop.set()
            return
        phase_stop.set()

        # GOOD phase
        _onoff_bad_phase_started_at = None
        AgentHandler.onoff_bad = False
        logger.info("%s: onoff -> GOOD phase (%.1fs)", node_id, good_s)
        if master_stop_event.wait(good_s):
            return


def _arm_malicious(
    node_id: str, malicious_kind: str, concurrency: int, stop_event: threading.Event,
) -> None:
    """Flip the agent from honest to --malicious behavior right now.

    Called either synchronously from main() (start_s == 0, the old behavior)
    or from the end of _arm_after_delay's sleep. Starting the sybil burner
    threads *here* rather than unconditionally in main() is what makes the
    pre-arm interval genuinely honest (no background CPU load) rather than
    just self-reporting honestly while secretly already burning cycles.
    """
    global _attack_armed_at
    _attack_armed_at = time.monotonic()
    AgentHandler.armed = True
    logger.warning("%s: malicious mode '%s' is now ARMED", node_id, malicious_kind)
    if malicious_kind == 'sybil':
        for _ in range(concurrency):
            threading.Thread(target=_sybil_burn_loop, args=(stop_event,), daemon=True).start()
    elif malicious_kind == 'onoff':
        threading.Thread(
            target=_onoff_toggle_loop,
            args=(node_id, AgentHandler.onoff_period_s, AgentHandler.onoff_duty,
                  concurrency, stop_event),
            daemon=True,
        ).start()


def _arm_after_delay(
    delay_s: float, node_id: str, malicious_kind: str, concurrency: int,
    stop_event: threading.Event,
) -> None:
    """Daemon-thread target: wait out the configured onset delay, then arm."""
    time.sleep(delay_s)
    if stop_event.is_set():
        return
    _arm_malicious(node_id, malicious_kind, concurrency, stop_event)


class AgentHandler(BaseHTTPRequestHandler):
    # Set from main() before the server starts; shared across all request
    # instances (BaseHTTPRequestHandler is instantiated fresh per connection).
    node_id = 'srv?'
    concurrency = 4
    work_ms = 40.0
    malicious = 'none'
    claimed_cpu_lie = 0.1
    # Whether the configured --malicious mode has activated yet. False for
    # the whole run when --malicious-start-s hasn't elapsed (or is 0 and
    # main() already armed synchronously before the server started).
    armed = False
    # --malicious grayhole only: fraction of /task requests dropped.
    grayhole_drop_rate = 0.5
    # --malicious onoff only: cycle length and the fraction of it spent lying.
    onoff_period_s = 8.0
    onoff_duty = 0.5
    # --malicious onoff only: True while the current phase is the bad one.
    # Irrelevant for every other --malicious kind.
    onoff_bad = False

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

        onoff_lying = self.malicious == 'onoff' and self.armed and self.onoff_bad
        if (self.malicious == 'sybil' and self.armed) or onoff_lying:
            cpu_load = self.claimed_cpu_lie  # the lie, regardless of real load
            # Lie *consistently*. A fabricated cpu_load next to a truthful
            # busy_seconds is an internal contradiction the controller could
            # catch for free, which would make this a strictly weaker attacker
            # than the one runs 1-6 were measured against. Advance the counter
            # at exactly the duty cycle being claimed, so the two agree and the
            # node still has to be caught on evidence it does not control (the
            # latency tell, or busy-time-per-task against the fleet median).
            #
            # Measured since the lie's own start, not process/arming start:
            # sybil lies continuously once armed, so _attack_armed_at is the
            # right basis; onoff only lies during its current bad phase, so
            # it must use _onoff_bad_phase_started_at instead -- using
            # _attack_armed_at there would claim duty cycle for earlier GOOD
            # phases (and earlier bad ones) it wasn't lying through.
            basis = _onoff_bad_phase_started_at if onoff_lying else _attack_armed_at
            assert basis is not None  # armed/onoff_bad implies this is set
            uptime = time.monotonic() - basis
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

        if self.malicious == 'drop' and self.armed:
            # Accept, then never respond. The client's own timeout is the tell —
            # this agent has nothing dishonest to report about itself. The
            # Mininet demo runs only minutes, so parking a handler thread per
            # dropped task is harmless (each gets its own thread; no CPU spent).
            time.sleep(_DROP_HANG_S)
            return

        if (
            self.malicious == 'grayhole' and self.armed
            and random.random() < self.grayhole_drop_rate
        ):
            # Same "accept and never respond" tell as drop, just probabilistic
            # instead of universal -- deliberately weaker per-sample so it
            # tests whether the timeout-rate tell's threshold still catches a
            # partial dropper, not just an always-dropper.
            time.sleep(_DROP_HANG_S)
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
    parser.add_argument(
        '--malicious',
        choices=['none', 'sybil', 'drop', 'grayhole', 'onoff'],
        default='none',
    )
    parser.add_argument(
        '--claimed-cpu-lie', type=float, default=0.1,
        help='Fixed cpu_load reported by --malicious sybil/onoff (while lying), '
             'regardless of real load',
    )
    parser.add_argument(
        '--malicious-start-s', type=float, default=0.0,
        help='Delay (s) after agent start before --malicious behavior arms. '
             '0 (default) arms immediately -- the pre-existing behavior. '
             'Before arming the agent is indistinguishable from --malicious none.',
    )
    parser.add_argument(
        '--grayhole-drop-rate', type=float, default=0.5,
        help='--malicious grayhole only: fraction of /task requests dropped '
             '(never answered), the rest served normally.',
    )
    parser.add_argument(
        '--onoff-period-s', type=float, default=8.0,
        help='--malicious onoff only: length of one full bad+good cycle.',
    )
    parser.add_argument(
        '--onoff-duty', type=float, default=0.5,
        help='--malicious onoff only: fraction of --onoff-period-s spent lying.',
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
    AgentHandler.grayhole_drop_rate = args.grayhole_drop_rate
    AgentHandler.onoff_period_s = args.onoff_period_s
    AgentHandler.onoff_duty = args.onoff_duty

    stop_event = threading.Event()
    if args.malicious != 'none':
        if args.malicious_start_s > 0:
            logger.warning(
                "MALICIOUS MODE: %s -- honest until t+%.1fs, then ARMS",
                args.malicious, args.malicious_start_s,
            )
            threading.Thread(
                target=_arm_after_delay,
                args=(args.malicious_start_s, args.node_id, args.malicious,
                      args.concurrency, stop_event),
                daemon=True,
            ).start()
        else:
            _arm_malicious(args.node_id, args.malicious, args.concurrency, stop_event)

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
