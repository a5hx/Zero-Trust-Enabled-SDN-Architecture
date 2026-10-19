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

--malicious liar:     claims a low, fixed cpu_load (--claimed-cpu-lie; give it
                   0.0) but does NOT burn CPU, so it serves at honest speed.
                   The sybil above slows itself, and its lie at the shipped
                   ~1% duty is higher than an honest server's truthful ~0, so
                   it repels traffic rather than attracting it; this is the
                   attacker whose lie works. --liar-busy picks its busy-seconds
                   counter: `consistent` advances it at the claimed duty cycle
                   (no internal contradiction, like the sybil), `truthful`
                   reports the real counter while the instantaneous cpu_load
                   lies -- the "split claim": routing reads the raw cpu_load,
                   the honesty check reads the busy counter.
--malicious stealthy: the adaptive liar. Every --stealth-interval-s it reads
                   the controller's GET /node/status (--stealth-observe-url),
                   claims the --stealth-rho quantile of the OTHER servers'
                   claims, and never claims less than its own true duty minus
                   --stealth-margin x the honesty threshold it is told about
                   (Kerckhoffs: the attacker knows the detector). Busy-seconds
                   stay consistent with the claim. It burns no CPU. This is
                   Burke et al. / Yu et al.'s switch-side misreporting model
                   moved to the server's own self-report.

Work model (all honest and malicious modes):
--work-mode burn:  hash for --work-ms of wall-clock time (the default and the
                   behaviour of every run before 2026-10-19). Wall-clock, so a
                   slower machine takes the SAME time per task.
--work-mode hold:  occupy a worker for --work-ms without using CPU (a sleep).
                   Raises occupancy -- the duty cycle the honesty check and the
                   load claim are about -- without loading the host, which is
                   how a 4-core laptop reaches 40-60% fleet occupancy.
--work-mode ops:   --work-ops hash iterations: a fixed amount of WORK, so a
                   slower or CPU-capped server really takes longer.
--enforce-concurrency: at most --concurrency tasks in service at once; the
                   rest wait. Without it every request gets its own thread and
                   a server that attracts traffic never queues, so a liar can
                   never be slowed by the traffic its lie wins.
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

# --enforce-concurrency only: the worker slots. None means unbounded (one
# thread per request, the behaviour of every run before 2026-10-19).
_slots: 'threading.BoundedSemaphore | None' = None

# --malicious liar/stealthy with a consistent busy counter: the fabricated
# counter is the REAL counter's value at arming plus the integral of the claim
# since then, so it never jumps backwards (the sybil's restarts from 0, which
# the controller has to special-case). _lie_busy_base is that integral up to
# _lie_busy_at; the claim in force since then is added on read.
_lie_busy_base = 0.0
_lie_busy_at: 'float | None' = None

# --malicious stealthy only: the claim the observer thread last computed, and
# the real busy counter it last sampled to measure its own true duty.
_stealth_last_busy: 'tuple | None' = None


def _burn_cpu_for_ms(duration_ms: float) -> None:
    """Spend roughly duration_ms of real CPU time hashing. Not a sleep — the
    point is to genuinely occupy the process, so contention (from --malicious
    sybil's background burners) genuinely slows this down."""
    end = time.monotonic() + duration_ms / 1000.0
    buf = b'zero-trust-sdn-workload'
    while time.monotonic() < end:
        buf = hashlib.sha256(buf).digest()


def _burn_ops(n: int) -> None:
    """A fixed amount of work: n SHA-256 iterations. Unlike _burn_cpu_for_ms,
    a slower (or cgroup-capped) machine takes proportionally longer."""
    buf = b'zero-trust-sdn-workload'
    for _ in range(n):
        buf = hashlib.sha256(buf).digest()


def _do_work(mode: str, work_ms: float, work_ops: int) -> None:
    if mode == 'hold':
        time.sleep(work_ms / 1000.0)
    elif mode == 'ops':
        _burn_ops(work_ops)
    else:
        _burn_cpu_for_ms(work_ms)


def _start_lie_busy_counter(real_busy: float, now: float) -> None:
    """Begin a consistent fabricated busy counter from the real one."""
    global _lie_busy_base, _lie_busy_at
    _lie_busy_base = real_busy
    _lie_busy_at = now


def _advance_lie_busy_counter(claim_in_force: float, concurrency: int, now: float) -> None:
    """Fold the claim that has been in force since the last change into the
    base, before the claim changes (stealthy only; liar's claim is fixed)."""
    global _lie_busy_base, _lie_busy_at
    if _lie_busy_at is not None:
        _lie_busy_base += (now - _lie_busy_at) * claim_in_force * max(1, concurrency)
    _lie_busy_at = now


def _lie_busy_seconds(claim: float, concurrency: int, now: float) -> float:
    if _lie_busy_at is None:
        return _lie_busy_base
    return _lie_busy_base + (now - _lie_busy_at) * claim * max(1, concurrency)


def _quantile(values: list, q: float) -> float:
    """Linear-interpolated quantile, q in [0, 1]. Stdlib only (the agent runs
    in a bare Mininet namespace)."""
    xs = sorted(values)
    if not xs:
        raise ValueError('no values')
    pos = q * (len(xs) - 1)
    lo = int(pos)
    hi = min(lo + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (pos - lo)


def stealth_claim(peer_claims: list, true_duty: float, rho: float,
                  margin: float, honesty_threshold: float) -> float:
    """The adaptive liar's claim: as low as the rho-quantile of the other
    servers' claims, but never so far under its own true duty cycle that the
    honesty check (|claimed duty - expected duty| > threshold) could fire.
    With no peers visible (e.g. once quarantined, when the controller API is
    out of reach) it falls back to the honesty floor alone."""
    floor = true_duty - margin * honesty_threshold
    claim = _quantile(peer_claims, rho) if peer_claims else floor
    return min(1.0, max(0.0, claim, floor))


def _fetch_peer_claims(url: str, node_id: str, timeout: float = 1.0) -> list:
    """Other servers' raw claims from the controller's GET /node/status."""
    import urllib.request
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        snap = json.loads(resp.read())
    return [float(v['claimed_cpu']) for k, v in snap.items()
            if k != node_id and isinstance(v, dict) and 'claimed_cpu' in v]


def _stealth_loop(node_id: str, concurrency: int, stop_event: threading.Event) -> None:
    """--malicious stealthy: recompute the claim every stealth_interval_s."""
    global _stealth_last_busy
    while not stop_event.wait(AgentHandler.stealth_interval_s):
        now = time.monotonic()
        with _state_lock:
            real = _busy_seconds_total
        prev = _stealth_last_busy
        _stealth_last_busy = (now, real)
        if prev is None or now <= prev[0]:
            continue
        true_duty = (real - prev[1]) / ((now - prev[0]) * max(1, concurrency))
        try:
            peers = _fetch_peer_claims(AgentHandler.stealth_observe_url, node_id)
        except (OSError, ValueError) as exc:
            logger.info("%s: stealthy cannot see peers (%s); honesty floor only", node_id, exc)
            peers = []
        claim = stealth_claim(peers, true_duty, AgentHandler.stealth_rho,
                              AgentHandler.stealth_margin,
                              AgentHandler.stealth_honesty_threshold)
        with _state_lock:
            _advance_lie_busy_counter(AgentHandler.stealth_claim_now, concurrency, now)
            AgentHandler.stealth_claim_now = claim


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
    global _attack_armed_at, _stealth_last_busy
    _attack_armed_at = time.monotonic()
    if malicious_kind in ('liar', 'stealthy'):
        with _state_lock:
            _start_lie_busy_counter(_busy_seconds_total, _attack_armed_at)
            _stealth_last_busy = (_attack_armed_at, _busy_seconds_total)
            AgentHandler.stealth_claim_now = AgentHandler.claimed_cpu_lie
    AgentHandler.armed = True
    logger.warning("%s: malicious mode '%s' is now ARMED", node_id, malicious_kind)
    if malicious_kind == 'stealthy':
        threading.Thread(target=_stealth_loop, args=(node_id, concurrency, stop_event),
                         daemon=True).start()
    elif malicious_kind == 'sybil':
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
    # Work model; see the module docstring.
    work_mode = 'burn'
    work_ops = 20000
    # --malicious liar only: 'consistent' or 'truthful' busy-seconds counter.
    liar_busy = 'consistent'
    # --malicious stealthy only.
    stealth_rho = 0.25
    stealth_margin = 0.8
    stealth_honesty_threshold = 0.40
    stealth_interval_s = 2.0
    stealth_observe_url = 'http://10.0.99.254:8081/node/status'
    stealth_claim_now = 0.0

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

        elif self.malicious in ('liar', 'stealthy') and self.armed:
            with _state_lock:
                cpu_load = (self.claimed_cpu_lie if self.malicious == 'liar'
                            else self.stealth_claim_now)
                if self.malicious == 'stealthy' or self.liar_busy == 'consistent':
                    busy_seconds = _lie_busy_seconds(cpu_load, self.concurrency,
                                                     time.monotonic())
                # else 'truthful': busy_seconds stays the real counter read above.

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
        slots = _slots
        if slots is not None:
            slots.acquire()     # queue for a worker; the wait is not service time
        with _state_lock:
            _active_tasks += 1
        start = time.monotonic()
        try:
            _do_work(self.work_mode, self.work_ms, self.work_ops)
        finally:
            if slots is not None:
                slots.release()
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


def build_parser() -> argparse.ArgumentParser:
    """The agent's CLI, split out of main() so the launch path can be checked
    without starting an agent -- tests/test_live_config_preflight.py feeds it the
    exact command simulation/topology.py would run, which is what catches an
    attack kind wired into the topology but never added to --malicious here."""
    parser = argparse.ArgumentParser(description='Zero Trust SDN edge-server agent')
    parser.add_argument('--node-id', required=True)
    parser.add_argument('--port', type=int, default=8000)
    parser.add_argument('--concurrency', type=int, default=4)
    parser.add_argument('--work-ms', type=float, default=40.0)
    parser.add_argument(
        '--malicious',
        choices=['none', 'sybil', 'drop', 'grayhole', 'onoff', 'liar', 'stealthy'],
        default='none',
    )
    parser.add_argument('--work-mode', choices=['burn', 'hold', 'ops'], default='burn',
                        help='burn: hash for --work-ms of wall time (default); '
                             'hold: occupy a worker for --work-ms without CPU; '
                             'ops: --work-ops hash iterations (fixed work).')
    parser.add_argument('--work-ops', type=int, default=20000,
                        help='--work-mode ops only: SHA-256 iterations per task.')
    parser.add_argument('--enforce-concurrency', action='store_true',
                        help='At most --concurrency tasks in service; the rest queue.')
    parser.add_argument('--liar-busy', choices=['consistent', 'truthful'],
                        default='consistent',
                        help='--malicious liar only: fabricate busy_seconds at the '
                             'claimed duty (consistent) or report the real counter '
                             '(truthful, the split claim).')
    parser.add_argument('--stealth-rho', type=float, default=0.25,
                        help='--malicious stealthy only: quantile of the other '
                             "servers' claims to claim.")
    parser.add_argument('--stealth-margin', type=float, default=0.8,
                        help='--malicious stealthy only: never claim less than true '
                             'duty minus this fraction of the honesty threshold.')
    parser.add_argument('--stealth-honesty-threshold', type=float, default=0.40,
                        help="--malicious stealthy only: the detector's honesty "
                             'threshold, as the attacker knows it.')
    parser.add_argument('--stealth-interval-s', type=float, default=2.0)
    parser.add_argument('--stealth-observe-url',
                        default='http://10.0.99.254:8081/node/status',
                        help="--malicious stealthy only: the controller's GET "
                             '/node/status.')
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
    return parser


def main() -> None:
    args = build_parser().parse_args()

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
    AgentHandler.work_mode = args.work_mode
    AgentHandler.work_ops = args.work_ops
    AgentHandler.liar_busy = args.liar_busy
    AgentHandler.stealth_rho = args.stealth_rho
    AgentHandler.stealth_margin = args.stealth_margin
    AgentHandler.stealth_honesty_threshold = args.stealth_honesty_threshold
    AgentHandler.stealth_interval_s = args.stealth_interval_s
    AgentHandler.stealth_observe_url = args.stealth_observe_url
    if args.enforce_concurrency:
        global _slots
        _slots = threading.BoundedSemaphore(max(1, args.concurrency))

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
