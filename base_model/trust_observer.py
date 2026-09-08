"""Trust as a MEASUREMENT ONLY — the control arm's instrument.

The baseline has no defences. It still has to produce a trust value per node
per instant, or there is nothing to plot against the treatment arm. This module
is that instrument, and its one design rule is:

    every number it produces must be computed by the SAME code the treatment
    arm uses, and none of them may change what the baseline does.

Hence the shape of this file. It does not reimplement the trust formula, the
occupancy estimator, the busy-time duty cycle, or the two anomaly tells — it
*wraps* `controller.trust_state.TrustState` and calls only its observation
surface. A reimplementation would drift from the treatment arm silently, and
the first thing a reviewer will ask is whether the two trust curves were
produced by the same estimator. They are, and `check_no_enforcement()` plus
`base_model/tests/test_observer_parity.py` are how that is kept true.

WHAT IS DELIBERATELY NOT CALLED
-------------------------------
`TrustState` can enforce. This wrapper never lets it:

    choose_edge_node / choose_edge_node_ex   routing by trust
    poll_quarantine_transitions              the quarantine edge detector
    quarantined / probation_due              the isolation decisions
    trust_band                               the rate-limit bands

`check_no_enforcement()` asserts the wrapper exposes none of them, and the
baseline controller holds a `BaselineTrustObserver`, never a bare `TrustState`,
so there is no handle through which routing could accidentally consult trust.

WHY THE ESTIMATORS ARE NOT SIMPLIFIED
-------------------------------------
It is tempting to give the baseline a cheap H term — "claimed CPU minus
observed occupancy" — and be done. That would be a rigged comparison, in the
baseline's *disfavour*, and the project already knows why: `observed_load` is a
residence time and a node's claim is a service time, about 6x apart in live run
6, so the naive difference makes an honest busy node look like a liar. The
treatment arm corrects that with the busy-seconds duty cycle
(`expected_duty_cycle`, falling back to `observed_load`); if the baseline used
only the fallback, honest nodes here would lose trust for being busy and the
treatment arm would "win" on an artefact of two different formulas.

So the honesty reference is computed by the identical call chain, in the
identical order, in `record_report()` below. If that ever diverges,
`test_observer_parity.py` fails.

THE ANOMALY RAIL IS OPTIONAL, AND THE CHOICE IS A CLAIM
-------------------------------------------------------
`observe_anomaly=True` (default) runs the same two evidence-only tells the
treatment arm runs — the latency tell (imported outright from
`controller.flow_monitor`, not copied) and the packet-drop/timeout-rate tell —
and feeds A into T. Nothing acts on the result. This is the sharper control:
the baseline *sees* every attack and does nothing, so the treatment arm's
advantage cannot be waved away as "it merely had a detector".

`observe_anomaly=False` pins A at 0 and T collapses to alpha*R + beta*B +
gamma*H. That is a blind legacy controller, and a legitimate third arm — but
the two arms' trust is then no longer the same formula, so a paper reporting it
must say so. `anomaly_observed` in `snapshot()` records which way the run was
configured, so a recording can never be misread as the other one.
"""

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from contracts.thresholds import (
    DEFAULT_ANOMALY_GATE,
    DEFAULT_ISOLATION_THRESHOLD,
)
from contracts.trust_update import TrustUpdate
from controller.attack_classifier import (
    SIG_CPU_HONESTY,
    SIG_LATENCY_TELL,
    SIG_PACKET_DROP,
)

# Imported, never copied: these are the treatment arm's own tells, already
# extracted as pure functions precisely so a second harness can share them.
from controller.flow_monitor import evaluate_latency_tell, fleet_latency_baseline
from controller.trust_state import TrustState
from trust_engine.trust_calculator import TrustCalculator

logger = logging.getLogger('base_model.trust_observer')

#: Task outcomes needed before the timeout-rate tell will express an opinion.
#: Same value as controller/flow_monitor.py's `_MIN_TIMEOUT_SAMPLES`, pinned by
#: test_observer_parity.py rather than imported, because it is private there.
MIN_TIMEOUT_SAMPLES = 4

#: Enforcement entry points that must never be reachable from this wrapper.
#: Asserted by check_no_enforcement() and by the test of the same name.
FORBIDDEN_ENFORCEMENT_API = (
    'choose_edge_node',
    'choose_edge_node_ex',
    'poll_quarantine_transitions',
    'poll_newly_quarantined',
    'quarantined',
    'probation_due',
    'trust_band',
)


class NoLedgerBackend:
    """A commit backend that commits nothing.

    The baseline has no blockchain, so trust updates must not be batched into
    blocks — but `TrustState.record_task_outcome` calls its backend
    unconditionally. This satisfies the protocol and does nothing, which is the
    honest representation of "this arm has no ledger": `chain_length()` is 0
    and `verify()` is True over an empty chain, so anything reading the ledger
    reports an absence rather than a fabricated single-replica chain.

    `commit_count` stays 0 for the whole run. That is what makes the blockchain
    -overhead NFR report *no data* for a baseline recording instead of 0.0%
    overhead — "not measured" and "measured zero" are different claims, and the
    evaluation tools in this project are built to keep them apart.
    """

    def __init__(self) -> None:
        self.commit_count = 0

    def commit(self, updates: List[TrustUpdate]) -> None:
        return None

    def latest_score(self, node_id: str) -> Optional[float]:
        return None

    def verify(self) -> bool:
        return True

    def chain_length(self) -> int:
        return 0


@dataclass
class StatusSample:
    """One /status poll of one node, as the baseline poller saw it.

    `ok=False` means the poll did not answer. The baseline records that as
    missing evidence — it does NOT score it as anomalous. The treatment arm
    does score seen-then-dark as anomalous, correctly, because it is about to
    act on it; a control arm that never acts has no reason to convert silence
    into an accusation, and doing so would inflate the baseline's own anomaly
    series against nodes that are merely unreachable.
    """

    node_id: str
    ok: bool
    claimed_cpu: Optional[float] = None
    rtt_ms: Optional[float] = None
    latency_ms: Optional[float] = None
    busy_seconds: Optional[float] = None
    concurrency: Optional[int] = None


@dataclass
class AnomalyVerdict:
    """What the tells said about one node this cycle. Advisory in this arm."""

    node_id: str
    anomaly_raw: float
    anomaly: float
    reasons: List[str]
    signals: Dict[str, float]

    @property
    def would_quarantine(self) -> bool:
        """True when the treatment arm's anomaly gate would have fired here.

        Named in the conditional on purpose. This arm does not quarantine; the
        flag exists so a run can be scored for "detections that led to no
        response", which is the baseline's central number.
        """
        return self.anomaly >= DEFAULT_ANOMALY_GATE


class BaselineTrustObserver:
    """Measures trust. Decides nothing.

    Args:
        node_ids: the server roster, e.g. ['srv1', ..., 'srv8'].
        trust_cfg: the `trust:` block of the baseline config. Must be the same
            block as the treatment arm's or the curves are not comparable.
        observe_anomaly: run the two tells and feed A into T (see module
            docstring). False pins A at 0.
        load_window_s: occupancy/claim averaging window, seconds.
        latency_tell_cfg: the four `controller:` knobs the latency tell reads.
        honesty_deviation_threshold: |claimed - reference| above which the
            honesty tell fires.
        task_timeout_s: how long a client waits. Sets the dispatch reap horizon
            so an abandoned task stops counting as inflight at about the moment
            the client stops waiting for it — without this the baseline
            manufactures phantom occupancy on nodes under load and its H term
            drifts for a reason that has nothing to do with the architecture.
    """

    def __init__(
        self,
        node_ids: Sequence[str],
        trust_cfg: Dict[str, Any],
        observe_anomaly: bool = True,
        load_window_s: float = 5.0,
        latency_tell_cfg: Optional[Dict[str, Any]] = None,
        honesty_deviation_threshold: float = 0.40,
        task_timeout_s: float = 4.0,
    ) -> None:
        self.node_ids = list(node_ids)
        self.observe_anomaly = observe_anomaly
        self.honesty_deviation_threshold = honesty_deviation_threshold
        cfg = latency_tell_cfg or {}
        self._idle_claim_threshold = float(cfg.get('idle_claim_threshold', 0.25))
        self._latency_liar_ratio = float(cfg.get('latency_liar_ratio', 3.0))
        self._latency_liar_floor_ms = float(cfg.get('latency_liar_floor_ms', 40.0))
        self._latency_liar_persist = int(cfg.get('latency_liar_persist', 3))

        calc = TrustCalculator(
            alpha=float(trust_cfg.get('alpha', 0.35)),
            beta=float(trust_cfg.get('beta', 0.25)),
            gamma=float(trust_cfg.get('gamma', 0.25)),
            delta=float(trust_cfg.get('delta', 0.15)),
            lambda_decay=float(trust_cfg.get('lambda_decay', 0.85)),
            initial_score=float(trust_cfg.get('initial_score', 0.5)),
        )

        # The instrument. Constructed with every enforcement input left at a
        # value that cannot matter, because nothing in this arm reads them:
        # isolation_threshold/anomaly_gate are carried only so `snapshot()` can
        # report which side of the treatment arm's lines a node fell on.
        self._state = TrustState(
            node_ids=self.node_ids,
            trust_calculator=calc,
            commit_backend=NoLedgerBackend(),
            isolation_threshold=float(
                trust_cfg.get('isolation_threshold', DEFAULT_ISOLATION_THRESHOLD)
            ),
            anomaly_gate=float(trust_cfg.get('anomaly_gate', DEFAULT_ANOMALY_GATE)),
            anomaly_lambda=float(trust_cfg.get('lambda_decay', 0.85)),
            # One update per block would commit on every report; the backend is
            # a no-op either way, but a large batch keeps the pending list from
            # being flushed constantly for nothing.
            max_updates_per_block=10_000,
            task_timeout_s=task_timeout_s,
        )
        self._state.load_window_s = load_window_s

        # Leaky-bucket strike level per node, carried between cycles. Owned
        # here rather than by TrustState because the tell is a poller-side
        # concern in the treatment arm too (FlowMonitor holds it there).
        self._latency_strikes: Dict[str, int] = {nid: 0 for nid in self.node_ids}
        self._last_verdicts: Dict[str, AnomalyVerdict] = {}
        # Advisory A, smoothed with the same lambda, used only when
        # observe_anomaly is False -- so a blind run still reports what a
        # detector would have seen without that ever reaching T.
        self._shadow_anomaly: Dict[str, float] = {nid: 0.0 for nid in self.node_ids}

        # Counters that make the control arm's headline claim measurable:
        # how much evidence of misbehaviour accumulated that nothing acted on.
        self.detections_unactioned: Dict[str, int] = {nid: 0 for nid in self.node_ids}

        logger.info(
            "BaselineTrustObserver up: %d nodes, observe_anomaly=%s, "
            "load_window=%.1fs -- measurement only, no enforcement",
            len(self.node_ids), observe_anomaly, load_window_s,
        )

    # ------------------------------------------------------------------ #
    # Guard rail                                                          #
    # ------------------------------------------------------------------ #
    @classmethod
    def check_no_enforcement(cls) -> None:
        """Raise if this wrapper ever grows an enforcement entry point.

        Cheap, and it catches the one refactor that would silently invalidate
        every result produced by this arm: someone forwarding a convenient
        `TrustState` method through the observer, after which "the baseline"
        would be quietly consulting trust.
        """
        leaked = [name for name in FORBIDDEN_ENFORCEMENT_API if hasattr(cls, name)]
        if leaked:
            raise AssertionError(
                f"BaselineTrustObserver exposes enforcement API {leaked!r}; the "
                f"control arm must measure trust and never act on it"
            )

    # ------------------------------------------------------------------ #
    # Dispatch accounting -- the observed-load numerator                  #
    # ------------------------------------------------------------------ #
    def register_dispatch(self, client_ip: str, client_port: int, node_id: str) -> None:
        """Record that this connection was sent to node_id.

        The baseline knows the mapping for the same reason the treatment arm
        does — it installed the rewrite rule — and for no other reason. It is
        bookkeeping, not a decision: the binding was already fixed by
        `static_binding()` before this is called.
        """
        self._state.register_dispatch(client_ip, client_port, node_id)

    def reap_stale_dispatches(self) -> None:
        """Drop dispatches whose client has certainly given up.

        Must be called on the poll loop: the invariant
        `sum(inflight) == len(dispatches)` is what keeps occupancy honest, and
        a client that timed out never sends /report, so without this the node
        stays charged for a task nobody is waiting on.
        """
        self._state.reap_stale_dispatches()

    def inflight_invariant_holds(self) -> bool:
        """`sum(_inflight) == len(_dispatches)`.

        Exposed because it is the single check that separates fabricated
        occupancy from real load — if it breaks, every H value in the run is
        suspect and the trust curves are not comparable to anything.
        """
        state = self._state
        with state._lock:  # noqa: SLF001 -- the invariant is over private state
            return sum(state._inflight.values()) == len(state._dispatches)

    # ------------------------------------------------------------------ #
    # Inputs                                                              #
    # ------------------------------------------------------------------ #
    def record_status(self, sample: StatusSample) -> None:
        """Feed one /status poll into the estimators."""
        if not sample.ok or sample.claimed_cpu is None or sample.rtt_ms is None:
            return
        if sample.concurrency:
            self._state.set_concurrency(sample.node_id, int(sample.concurrency))
        # `measured_rtt_ms` is the CONTROLLER's timing of the poll, never the
        # `latency_ms` the node puts in its own payload -- a node can lie about
        # the latter and cannot touch the former. Passing the payload figure
        # here would hand the liar the latency tell's own input.
        self._state.report_claimed_status(
            sample.node_id,
            cpu_load=float(sample.claimed_cpu),
            measured_rtt_ms=float(sample.rtt_ms),
            busy_seconds=sample.busy_seconds,
        )

    def record_report(
        self, device_id: str, client_ip: str, vip_src_port: int,
        status: str, latency_ms: float,
    ) -> Optional[Dict[str, Any]]:
        """One client task outcome. Returns the published `report` payload, or
        None when the report cannot be attributed to a dispatch this controller
        made (stale, duplicate, or already reaped).

        This is the treatment arm's `handle_client_report` with every branch
        that could *act* removed — there is no re-steer attribution check here,
        because nothing in this arm re-steers, so no task can be inherited from
        a connection a quarantine tore down. Everything that MEASURES is
        identical, in the same order, including the honesty reference.
        """
        completed = self._state.complete_dispatch(client_ip, vip_src_port)
        if completed is None:
            logger.warning(
                "Unattributable /report from %s:%d (device=%s) -- stale or duplicate",
                client_ip, vip_src_port, device_id,
            )
            return None
        node_id = completed.node_id

        # Identical call chain to controller/trust_balancer.py's
        # handle_client_report. Do not "simplify" this to observed_load: see
        # the module docstring, it would tax honest busy nodes and rig the
        # comparison against this arm.
        claimed_cpu = self._state.claimed_load(node_id)
        observed = self._state.observed_load(node_id)
        expected = self._state.expected_duty_cycle(node_id)
        honesty_reference = expected if expected is not None else observed

        upd = TrustUpdate(
            device_id=device_id, edge_node_id=node_id, task_status=status,
            cpu_usage=honesty_reference, reported_cpu=claimed_cpu,
            latency_ms=latency_ms,
        )
        score = self._state.record_task_outcome(upd)

        return {
            'device': device_id,
            'node': node_id,
            'status': status,
            'latency_ms': round(latency_ms, 2),
            'trust': round(score, 4),
            'claimed_cpu': round(claimed_cpu, 4),
            'observed_load': round(observed, 4),
            'expected_duty': None if expected is None else round(expected, 4),
            'honesty_reference': round(honesty_reference, 4),
            # Present so a baseline recording is shaped like a treatment one and
            # the same tools read both. Always 0.0/False here: this arm commits
            # nothing, and that absence is the measurement.
            'report_ms': 0.0,
            'committed': False,
        }

    # ------------------------------------------------------------------ #
    # The two tells -- advisory                                           #
    # ------------------------------------------------------------------ #
    def evaluate_cycle(self, samples: Sequence[StatusSample]) -> List[AnomalyVerdict]:
        """Run the tells over one complete poll sweep and update A.

        Takes the whole sweep, not one node, because the latency tell is
        relative: it needs the fleet median RTT of the same cycle. Nodes polled
        in different sweeps must not be compared against each other's baseline.

        Returns one verdict per node that produced evidence. With
        `observe_anomaly=False` this still returns the verdicts (so a run can
        report what a detector *would* have seen) but does not feed A into T.
        """
        by_id = {s.node_id: s for s in samples}
        baseline_ms = fleet_latency_baseline(
            [s.rtt_ms for s in samples if s.ok]
        )

        verdicts: List[AnomalyVerdict] = []
        for node_id in self.node_ids:
            sample = by_id.get(node_id)
            if sample is None or not sample.ok:
                # Missing evidence, not evidence of misbehaviour. The strike
                # bucket is left untouched rather than decremented: a node that
                # stops answering has not earned the drain.
                continue

            reasons: List[str] = []
            signals: Dict[str, float] = {}
            anomaly_raw = 0.0

            # 1. CPU honesty. The three-way reference split is copied from
            #    controller/flow_monitor.py deliberately, branch for branch --
            #    a two-way version here would make this arm's honesty tell
            #    strictly less sensitive than the treatment arm's, and the
            #    comparison would then be reporting a detector difference as an
            #    architecture difference.
            #
            #    The split exists because `expected_duty_cycle() is None` has
            #    two very different causes, and live run 7 measured what
            #    conflating them costs: 175 of 175 CPU-honesty firings came from
            #    the unconditional fallback, and every false quarantine in that
            #    run with them.
            claimed = self._state.claimed_load(node_id)
            observed = self._state.observed_load(node_id)
            expected = self._state.expected_duty_cycle(node_id)
            if expected is not None:
                reference, basis = expected, 'expected duty'
            elif not self._state.reports_busy_seconds(node_id):
                # The NODE withholds its busy-seconds counter -- attacker-
                # controlled, so abstaining would let a liar switch the check
                # off by omission. Keep the degraded residence-time comparison
                # and name it as degraded in the reason, so a reader is never
                # told a residence time is a duty cycle.
                reference, basis = observed, 'observed (node sends no busy_seconds)'
            else:
                # The node reports honestly; WE lack the completions to build a
                # fleet median. Our missing evidence is not its misbehaviour.
                reference, basis = None, None

            # Only cross-check a figure the node actually sent. Inventing a
            # claim and comparing against it accuses a node of lying about a
            # value it never stated.
            if sample.claimed_cpu is not None and reference is not None:
                deviation = abs(claimed - reference)
                if deviation > self.honesty_deviation_threshold:
                    anomaly_raw = 1.0
                    reasons.append(
                        f'CPU honesty: |claimed {claimed:.2f} - {basis} '
                        f'{reference:.2f}| = {deviation:.2f} > '
                        f'{self.honesty_deviation_threshold:.2f}'
                    )
                    signals[SIG_CPU_HONESTY] = round(deviation, 4)

            # 2. Latency tell -- the treatment arm's own pure function.
            tell = evaluate_latency_tell(
                claimed_cpu=sample.claimed_cpu,
                measured_rtt_ms=sample.rtt_ms,
                fleet_baseline_ms=baseline_ms,
                strikes=self._latency_strikes.get(node_id, 0),
                idle_claim_threshold=self._idle_claim_threshold,
                latency_liar_ratio=self._latency_liar_ratio,
                latency_liar_floor_ms=self._latency_liar_floor_ms,
                latency_liar_persist=self._latency_liar_persist,
            )
            self._latency_strikes[node_id] = tell.strikes
            if tell.tripped:
                anomaly_raw = 1.0
                reasons.append(
                    f'latency tell: claims idle (cpu {sample.claimed_cpu:.2f}) but '
                    f'rtt {sample.rtt_ms:.0f}ms is {tell.ratio:.1f}x fleet median '
                    f'{baseline_ms:.0f}ms (sustained)'
                )
                if tell.ratio is not None:
                    signals[SIG_LATENCY_TELL] = round(tell.ratio, 4)

            # 3. Packet-drop tell. Same window, same minimum sample count and
            #    the same stale-evidence abstention as the treatment arm --
            #    TrustState owns all three.
            timeout_rate = self._state.recent_timeout_rate(
                node_id, min_samples=MIN_TIMEOUT_SAMPLES,
            )
            if timeout_rate is not None and timeout_rate > self.honesty_deviation_threshold:
                anomaly_raw = 1.0
                reasons.append(
                    f'packet-drop tell: timeout rate {timeout_rate:.2f} > '
                    f'{self.honesty_deviation_threshold:.2f}'
                )
                signals[SIG_PACKET_DROP] = round(timeout_rate, 4)

            if self.observe_anomaly:
                anomaly = self._state.set_anomaly_raw(node_id, anomaly_raw)
            else:
                # Reported, never fed into T. Smoothed with the same lambda so
                # the advisory series is still directly comparable.
                prev = self._shadow_anomaly.get(node_id, 0.0)
                lam = self._state.anomaly_lambda
                anomaly = lam * anomaly_raw + (1 - lam) * prev
                self._shadow_anomaly[node_id] = anomaly

            verdict = AnomalyVerdict(
                node_id=node_id, anomaly_raw=anomaly_raw, anomaly=anomaly,
                reasons=reasons, signals=signals,
            )
            if verdict.would_quarantine:
                self.detections_unactioned[node_id] += 1
            self._last_verdicts[node_id] = verdict
            verdicts.append(verdict)

        return verdicts

    # ------------------------------------------------------------------ #
    # Outputs                                                             #
    # ------------------------------------------------------------------ #
    def trust(self, node_id: str) -> float:
        return self._state.trust_calc.get_score(node_id)

    def snapshot(self) -> Dict[str, Dict[str, Any]]:
        """Per-node state, shaped like the treatment arm's `node_status` event.

        `quarantined` is always False and that is not a placeholder — it is the
        measurement. `would_quarantine` alongside it is what the treatment arm
        would have done with the very same evidence, which is the pair of
        columns the comparison is built on.
        """
        base = self._state.snapshot()
        out: Dict[str, Dict[str, Any]] = {}
        for node_id in self.node_ids:
            row = dict(base.get(node_id, {}))
            trust = float(row.get('trust', 0.5))
            anomaly = float(row.get('anomaly', 0.0))
            row['quarantined'] = False
            row['probation'] = False
            row['would_quarantine'] = bool(
                trust < self._state.isolation_threshold
                or anomaly >= self._state.anomaly_gate
            )
            row['detections_unactioned'] = self.detections_unactioned.get(node_id, 0)
            row['anomaly_observed'] = self.observe_anomaly
            out[node_id] = row
        return out
