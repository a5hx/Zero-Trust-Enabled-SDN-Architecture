"""Per-second anomaly detection loop for the trust-aware controller.

Polls every edge agent's GET /status concurrently (never serially -- a serial
loop with a per-node timeout can burn most of a 1s budget if even one node is
dark), feeds the results into the shared TrustState, and derives three
independent quarantine signals:

    1. CPU-honesty deviation: |claimed_cpu - observed_load| > threshold.
       observed_load is the controller's own Little's-Law estimate
       (TrustState.observed_load), never the node's self-report, so a lying
       node cannot influence the check it's being judged against.
    2. Packet-drop tell: TrustState.recent_timeout_rate -- a drop attacker can
       self-report CPU honestly, so it needs its own signal entirely separate
       from (1).
    3. Latency tell: a node claiming to be idle should also be responsive. One
       burning CPU to serve slowly answers its /status poll far slower than the
       fastest peer no matter how little task traffic it gets. This is the
       *load-independent* Sybil signal: (1) only fires once the liar has
       accumulated observed load, which power-of-two-choices routing prevents by
       never concentrating traffic on it (docs/LOAD_BALANCING_STARVATION.md), so
       without this a Sybil under p2c could serve slowly forever undetected.

Any cause calls TrustState.set_anomaly_raw(1.0); a node with neither
problem this cycle gets set_anomaly_raw(0.0), so Ā decays back down under the
same EMA lambda used everywhere else once misbehaviour stops.

After each poll cycle, calls TrustState.poll_newly_quarantined() and invokes
on_quarantine(node_id) for each node that just crossed the line, and
TrustState.flush_if_stale() so a batch smaller than max_updates_per_block
doesn't sit uncommitted indefinitely once traffic quiets down.

Polls each node at its addressing.srv_ip() (the controller process itself
runs in the root network namespace, reachable into the emulated 10.0.1.0/24
server subnet only via the `cx` routing node -- see simulation/topology.py
and design fact #3 in the Sprint 1 memory), never by node_id as a hostname:
Mininet hosts have no DNS resolution for each other's names.
"""

import http.client
import json
import logging
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Sequence, Set

from os_ken.lib import hub

from controller.event_bus import NullBus
from controller.trust_state import TrustState
from simulation.addressing import srv_index, srv_ip

logger = logging.getLogger(__name__)

_STATUS_TIMEOUT_S = 0.5
_MIN_TIMEOUT_SAMPLES = 4


class LatencyTell(NamedTuple):
    """Outcome of one latency-tell evaluation.

    tripped: the node should be flagged this cycle.
    strikes: the updated leaky-bucket level, to be carried into the next call.
    ratio: measured RTT as a multiple of the fleet baseline, or None when either
        figure was unavailable.
    """

    tripped: bool
    strikes: int
    ratio: Optional[float]


def fleet_latency_baseline(rtts: Sequence[Optional[float]]) -> Optional[float]:
    """Median of the measured RTTs, ignoring failed probes.

    The MEDIAN, not the min: the min makes one lucky-fast poll brand every other
    node an outlier, while the median needs a majority to be honest (the standard
    assumption) and self-normalises when the whole host slows down uniformly.
    """
    measured = [r for r in rtts if r is not None]
    return statistics.median(measured) if measured else None


def evaluate_latency_tell(
    claimed_cpu: Optional[float],
    measured_rtt_ms: Optional[float],
    fleet_baseline_ms: Optional[float],
    strikes: int,
    idle_claim_threshold: float = 0.25,
    latency_liar_ratio: float = 3.0,
    latency_liar_floor_ms: float = 40.0,
    latency_liar_persist: int = 3,
) -> LatencyTell:
    """The load-independent Sybil tell, as a pure function.

    A node claiming to be (near) idle should answer its poll about as fast as the
    rest of the fleet. One burning CPU to serve slowly replies far slower no
    matter how little task traffic it receives -- the case p2c routing creates,
    where the CPU-honesty deviation check cannot fire because the liar never
    accumulates observed load. The RTT is the controller's own measurement, so
    the node cannot understate it.

    Extracted from FlowMonitor so the live monitor and the offline evaluation
    harness (evaluation/baseline.py) share one implementation rather than drifting
    apart -- the same reason edge_selector.py owns the routing formula outright.

    Args:
        claimed_cpu: The node's self-reported load, or None if it sent none (in
            which case nothing is inferred -- a node is not accused of lying
            about a figure it never claimed).
        measured_rtt_ms: Controller-measured probe RTT, or None if unreachable.
        fleet_baseline_ms: Result of fleet_latency_baseline for this cycle.
        strikes: The leaky-bucket level carried over from the previous call.
        idle_claim_threshold: At or below this claimed load counts as "claims idle".
        latency_liar_ratio: How many times the baseline counts as "slow".
        latency_liar_floor_ms: Absolute gap required as well, so a fast fleet
            does not make ordinary jitter look like a multiple.
        latency_liar_persist: Strikes required before flagging.

    Returns:
        A LatencyTell. Persistence is a leaky bucket, not a consecutive counter:
        a strike on a slow poll, a decrement on a fast one, capped just above the
        trip level. A CPU-burner is slow nearly every poll so it fills and stays
        full (one good poll cannot clear it); transient jitter drains back to zero
        without ever filling, keeping the quarantine steady instead of flapping.
    """
    slow_and_idle = (
        claimed_cpu is not None
        and measured_rtt_ms is not None
        and fleet_baseline_ms is not None
        and claimed_cpu <= idle_claim_threshold
        and measured_rtt_ms > fleet_baseline_ms * latency_liar_ratio
        and (measured_rtt_ms - fleet_baseline_ms) >= latency_liar_floor_ms
    )

    if slow_and_idle:
        strikes = min(latency_liar_persist + 1, strikes + 1)
    else:
        strikes = max(0, strikes - 1)

    ratio = (
        measured_rtt_ms / fleet_baseline_ms
        if measured_rtt_ms is not None and fleet_baseline_ms
        else None
    )
    return LatencyTell(
        tripped=strikes >= latency_liar_persist, strikes=strikes, ratio=ratio,
    )


class StatusProbe(NamedTuple):
    """One /status poll result.

    payload: the parsed JSON body, or None if the node was unreachable or
        answered non-200 (treated as anomalous by _poll_once).
    rtt_ms: the controller-measured round-trip time of the probe in
        milliseconds, or None when the request failed. This is the
        unspoofable latency signal fed to the EdgeScore -- unlike the
        node-reported latency_ms field, a node cannot understate how long its
        own reply actually took to arrive.
    """

    payload: Optional[dict]
    rtt_ms: Optional[float]


class FlowMonitor:
    """Owns the 1Hz polling loop. Runs as its own os-ken hub greenthread/OS
    thread (started via `hub.spawn(flow_monitor.run)` by TrustBalancerApp)."""

    def __init__(
        self,
        state: TrustState,
        node_ids: List[str],
        agent_port: int,
        poll_interval_s: float,
        honesty_deviation_threshold: float,
        on_quarantine: Callable[[str], None],
        bus: Optional[Any] = None,
        on_recover: Optional[Callable[[str], None]] = None,
        latency_liar_ratio: float = 3.0,
        latency_liar_floor_ms: float = 40.0,
        idle_claim_threshold: float = 0.25,
        latency_liar_persist: int = 3,
    ) -> None:
        self.state = state
        self.node_ids = list(node_ids)
        self.agent_port = agent_port
        self.poll_interval_s = poll_interval_s
        self.honesty_deviation_threshold = honesty_deviation_threshold
        self.on_quarantine = on_quarantine
        # Load-independent Sybil tell: a node claiming to be (near) idle should
        # answer its /status poll about as fast as the rest of the fleet. One
        # burning CPU to serve slowly is far slower to reply regardless of how
        # little task traffic it is sent -- the case p2c routing creates (it never
        # concentrates load on the liar, so the CPU-honesty deviation check can't
        # fire). Two deliberate robustness choices, because a live /status RTT is
        # noisy (GIL, scheduling, the controller host itself under load):
        #   * baseline = MEDIAN of the fleet's RTTs, not the min. The min makes one
        #     lucky-fast poll brand every other node an outlier; the median needs a
        #     majority to be honest (the standard assumption) and self-normalises
        #     when the whole host slows down uniformly (median rises with it).
        #   * PERSISTENCE: the "claims idle but slow" condition must hold for
        #     latency_liar_persist consecutive polls before it flags. A CPU-burner
        #     is slow every poll; transient jitter is not, so a single blip resets
        #     the strike counter. ~persist seconds at a 1s poll, inside the <3s NFR.
        self.latency_liar_ratio = latency_liar_ratio
        self.latency_liar_floor_ms = latency_liar_floor_ms
        self.idle_claim_threshold = idle_claim_threshold
        self.latency_liar_persist = latency_liar_persist
        self._latency_strikes: Dict[str, int] = {nid: 0 for nid in self.node_ids}
        # Nodes that have answered /status at least once. Until a node is in
        # here it is UNKNOWN rather than anomalous -- see _poll_once for why an
        # unanswered poll from a node that has never been seen must not score.
        self._ever_seen: Set[str] = set()
        # Optional so existing callers (run_demo.py, the unit tests) keep
        # working unchanged -- they never quarantine anything, so they have
        # nothing to undo.
        self.on_recover = on_recover if on_recover is not None else (lambda _nid: None)
        self.bus = bus if bus is not None else NullBus()
        self._executor = ThreadPoolExecutor(
            max_workers=max(1, len(self.node_ids)), thread_name_prefix='flow-monitor-poll',
        )
        self._stop = False

    def run(self) -> None:
        logger.info(
            "FlowMonitor started: %d node(s), interval=%.2fs, honesty_threshold=%.2f",
            len(self.node_ids), self.poll_interval_s, self.honesty_deviation_threshold,
        )
        while not self._stop:
            try:
                self._poll_once()
            except Exception:
                logger.exception("FlowMonitor poll cycle failed")
            hub.sleep(self.poll_interval_s)

    def stop(self) -> None:
        self._stop = True
        self._executor.shutdown(wait=False)

    def _poll_once(self) -> None:
        # Before reading any occupancy: drop dispatches the client never
        # reported. Driven from here rather than from register_dispatch alone so
        # the sweep keeps running when routing has stopped -- see
        # TrustState.reap_stale_dispatches.
        self.state.reap_stale_dispatches()

        results = dict(zip(
            self.node_ids,
            self._executor.map(self._fetch_status, self.node_ids),
        ))

        # Fleet baseline for the latency tell: the MEDIAN measured RTT this cycle
        # (see __init__ for why median not min). Server links are uniform
        # (topology.py), so a node far above the median is CPU-slow, not far away.
        # Uses only the controller's own measured RTTs -- a node cannot spoof how
        # long its reply actually took.
        latency_baseline = fleet_latency_baseline([p.rtt_ms for p in results.values()])

        for node_id in self.node_ids:
            probe = results[node_id]
            status = probe.payload
            anomaly_raw = 0.0
            reasons: List[str] = []

            if status is not None:
                # First contact: from here on, silence from this node is a
                # genuine failure signal rather than "not started yet".
                self._ever_seen.add(node_id)
                raw_cpu = status.get('cpu_load')
                has_claim = isinstance(raw_cpu, (int, float))
                claimed_cpu = float(raw_cpu) if has_claim else 0.5
                # Feed the *measured* RTT, not the node's self-reported
                # latency_ms, into the routing latency term. Fall back to the
                # self-report only if the probe somehow carried no RTT (it
                # always does for a real HTTP fetch; the guard is for stubs).
                latency_ms = (
                    probe.rtt_ms if probe.rtt_ms is not None
                    else status.get('latency_ms', 50.0)
                )
                concurrency = status.get('concurrency')

                self.state.report_claimed_status(node_id, claimed_cpu, latency_ms)
                if concurrency:
                    self.state.set_concurrency(node_id, int(concurrency))

                # Both sides averaged over the same window. The node samples
                # active/concurrency the instant its handler runs, so its claim
                # is a quantised step function; the controller's estimate is an
                # integral. Comparing one against the other is comparing two
                # different quantities, and it false-positives in whichever
                # direction happens to be ahead -- a node caught mid-burst reads
                # claimed 0.50 against observed 0.03, and one caught idle reads
                # claimed 0.00 against observed 0.62. Neither is dishonesty.
                observed = self.state.observed_load(node_id)
                claimed_avg = self.state.claimed_load(node_id)
                # Only cross-check a figure the node actually sent. Falling back
                # to 0.5 and then comparing against that accuses the node of
                # lying about a value it never claimed -- and the invented 0.5
                # against an idle observed 0.0 is itself a 0.50 deviation, over
                # the threshold before the node has done anything at all.
                deviation = abs(claimed_avg - observed) if has_claim else 0.0
                if has_claim and deviation > self.honesty_deviation_threshold:
                    logger.warning(
                        "%s: honesty deviation %.3f (claimed=%.3f observed=%.3f) > %.3f",
                        node_id, deviation, claimed_avg, observed,
                        self.honesty_deviation_threshold,
                    )
                    anomaly_raw = 1.0
                    reasons.append(
                        f'CPU honesty: |claimed {claimed_avg:.2f} - observed '
                        f'{observed:.2f}| = {deviation:.2f} > {self.honesty_deviation_threshold:.2f}'
                    )

                # Load-independent Sybil tell (see __init__): claims idle but is
                # far slower to answer than the fleet median, and stays that way.
                # Compares only the controller-measured RTT, so it holds no matter
                # how little task traffic the liar receives -- the case p2c creates
                # and the CPU-honesty check above then misses. Requires the
                # condition to persist so noisy single polls can't quarantine a
                # healthy node.
                measured_rtt = probe.rtt_ms
                tell = evaluate_latency_tell(
                    claimed_cpu=claimed_avg if has_claim else None,
                    measured_rtt_ms=measured_rtt,
                    fleet_baseline_ms=latency_baseline,
                    strikes=self._latency_strikes.get(node_id, 0),
                    idle_claim_threshold=self.idle_claim_threshold,
                    latency_liar_ratio=self.latency_liar_ratio,
                    latency_liar_floor_ms=self.latency_liar_floor_ms,
                    latency_liar_persist=self.latency_liar_persist,
                )
                self._latency_strikes[node_id] = tell.strikes
                if tell.tripped:
                    logger.warning(
                        "%s: latency tell -- claims idle (cpu %.2f) but rtt %.0fms is "
                        "%.1fx the fleet median %.0fms (%d/%d strikes)",
                        node_id, claimed_avg, measured_rtt, tell.ratio, latency_baseline,
                        tell.strikes, self.latency_liar_persist,
                    )
                    anomaly_raw = 1.0
                    reasons.append(
                        f'latency tell: claims idle (cpu {claimed_avg:.2f}) but rtt '
                        f'{measured_rtt:.0f}ms is {tell.ratio:.1f}x fleet median '
                        f'{latency_baseline:.0f}ms (sustained)'
                    )
            elif node_id in self._ever_seen:
                # Agent unreachable this cycle -- treat as suspicious rather
                # than silently skipping, but don't crash the loop over it.
                # The anomaly EMA (lambda=0.85 by default) means even one
                # missed poll pushes Ā above the 0.5 gate immediately, which
                # matches the project's <3s isolation NFR rather than
                # under-reacting to what could be a genuine outage.
                logger.warning("%s: /status poll failed this cycle", node_id)
                anomaly_raw = 1.0
                reasons.append('/status unreachable')
            else:
                # Never successfully polled even once: this node is UNKNOWN, not
                # anomalous. A node that has gone silent after being healthy is a
                # real failure signal and is scored as one above -- but one that
                # has never answered has not misbehaved, it has not started. The
                # controller must be listening before any switch can connect, so
                # it necessarily comes up seconds before Mininet builds the
                # network and the agents inside it; scoring that window pushed Ā
                # to 0.85 on the first poll and quarantined all 8 servers at
                # t=0.5s of the 8/40/3 live run, before a single one existed.
                # Staying silent here costs nothing: a node that never comes up
                # never gets traffic either, because it is never a routing
                # candidate until it reports.
                logger.info(
                    "%s: not seen yet (no successful /status poll) -- treating as "
                    "unknown, not anomalous", node_id,
                )

            timeout_rate = self.state.recent_timeout_rate(node_id, min_samples=_MIN_TIMEOUT_SAMPLES)
            if timeout_rate is not None and timeout_rate > self.honesty_deviation_threshold:
                logger.warning(
                    "%s: recent timeout rate %.3f > %.3f -- packet-drop tell",
                    node_id, timeout_rate, self.honesty_deviation_threshold,
                )
                anomaly_raw = 1.0
                reasons.append(
                    f'packet-drop tell: timeout rate {timeout_rate:.2f} > '
                    f'{self.honesty_deviation_threshold:.2f}'
                )

            anomaly = self.state.set_anomaly_raw(node_id, anomaly_raw)

            if reasons:
                self.bus.publish(
                    'anomaly', node=node_id, reasons=reasons,
                    anomaly=round(anomaly, 4), gate=self.state.anomaly_gate,
                )

        # One snapshot event per cycle rather than one per node: the dashboard
        # redraws the whole trust panel from it, and 4 separate events would
        # make it render torn intermediate states.
        self.bus.publish('node_status', nodes=self.state.snapshot())

        newly_quarantined, newly_recovered = self.state.poll_quarantine_transitions()
        for node_id in newly_quarantined:
            try:
                self.on_quarantine(node_id)
            except Exception:
                logger.exception("on_quarantine callback failed for %s", node_id)
        for node_id in newly_recovered:
            try:
                self.on_recover(node_id)
            except Exception:
                logger.exception("on_recover callback failed for %s", node_id)

        self.state.flush_if_stale()

        # Drive the AI weight optimizer (no-op unless it is enabled). On a window
        # close it returns a summary we log and stream to the dashboard.
        summary = self.state.optimizer_tick()
        if summary:
            logger.info(
                "OPTIMIZER: window closed reward=%.4f (%d outcomes) weights %s -> %s",
                summary['reward'], summary['outcomes'],
                summary['prev_weights'], summary['next_weights'],
            )
            self.bus.publish('optimizer', **summary)

    def _fetch_status(self, node_id: str) -> StatusProbe:
        host = srv_ip(srv_index(node_id))
        start = time.monotonic()
        try:
            conn = http.client.HTTPConnection(host, self.agent_port, timeout=_STATUS_TIMEOUT_S)
            conn.request('GET', '/status')
            resp = conn.getresponse()
            body = resp.read()
            conn.close()
            # Round trip measured from just before the request to just after
            # the full body is read -- the controller's own view of the node's
            # responsiveness, which no node-side field can misrepresent.
            rtt_ms = (time.monotonic() - start) * 1000.0
            if resp.status != 200:
                return StatusProbe(None, None)
            return StatusProbe(json.loads(body), rtt_ms)
        except OSError:
            return StatusProbe(None, None)
