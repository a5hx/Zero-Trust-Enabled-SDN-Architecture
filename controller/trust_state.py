"""Shared, thread-safe trust/routing state for the trust-aware controller.

controller/trust_balancer.py (OpenFlow event handling), controller/flow_monitor.py
(anomaly detection), and controller/northbound_api.py (REST) all read/write this one
object instead of touching TrustCalculator/CommitBackend/Authenticator directly.
Centralising it here means the OpenFlow-specific code carries no trust-logic
duplication, and the decision logic is unit-testable with no os-ken import at all.

Thread-safety matters because state is mutated from at least three concurrent
contexts: os-ken's per-datapath event handlers, flow_monitor's 1s polling loop
(hub.spawn), and the REST API's HTTP handler threads. os-ken's hub is `native`
(confirmed on this box: HUB_TYPE=native), i.e. real OS threads, not greenlets —
so a plain lock is required and sufficient, PROVIDED every method here stays
non-blocking (no network I/O while holding the lock). Callers must do any HTTP/
socket work *outside* a TrustState call and only report the result in. Violating
this on the OpenFlow event-handler thread would stall all PacketIn processing —
including for switches that have nothing to do with the slow call — and blow the
<200ms routing-decision NFR.
"""

import logging
import random
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

from blockchain.commit_backend import CommitBackend, LocalLedgerBackend
from contracts.thresholds import (
    DEFAULT_ANOMALY_GATE, DEFAULT_ANOMALY_WARN,
    DEFAULT_ISOLATION_THRESHOLD, DEFAULT_RATE_LIMIT_TRUST,
)
from contracts.trust_update import TrustUpdate
from controller.edge_selector import (
    DEFAULT_D_CHOICES, DEFAULT_EPSILON, DEFAULT_SELECTION_STRATEGY,
    EdgeWeights, NodeState, select_edge_node, trust_band,
)
from security.authenticator import Authenticator, NullAuthenticator
from trust_engine.ai_optimizer import (
    RewardWindow, StaticWeightOptimizer, WeightOptimizer, compute_reward,
)
from trust_engine.trust_calculator import TrustCalculator

logger = logging.getLogger(__name__)


@dataclass
class _Dispatch:
    """Records which edge node a specific (client_ip, client_port) TCP flow was
    routed to. The client is never told which server it got — it only ever
    addresses the VIP — so this is the *only* record of that mapping, and it is
    what lets a later completion report be attributed to the right node."""

    node_id: str
    dispatched_at: float


class TrustState:
    """Single source of truth for one controller instance."""

    def __init__(
        self,
        node_ids: List[str],
        trust_calculator: Optional[TrustCalculator] = None,
        commit_backend: Optional[CommitBackend] = None,
        authenticator: Optional[Authenticator] = None,
        edge_weights: Optional[EdgeWeights] = None,
        optimizer: Optional[WeightOptimizer] = None,
        optimizer_window_s: float = 10.0,
        reward_latency_penalty: float = 0.2,
        reward_imbalance_penalty: float = 0.2,
        isolation_threshold: float = DEFAULT_ISOLATION_THRESHOLD,
        anomaly_gate: float = DEFAULT_ANOMALY_GATE,
        rate_limit_trust: float = DEFAULT_RATE_LIMIT_TRUST,
        anomaly_warn: float = DEFAULT_ANOMALY_WARN,
        anomaly_lambda: float = 0.85,
        max_updates_per_block: int = 10,
        block_commit_timeout_s: float = 5.0,
        selection_strategy: str = DEFAULT_SELECTION_STRATEGY,
        d_choices: int = DEFAULT_D_CHOICES,
        epsilon: float = DEFAULT_EPSILON,
        selection_rng: Optional[random.Random] = None,
        time_source: Optional[Callable[[], float]] = None,
    ) -> None:
        # Monotonic seconds, injectable so dashboard/generate_demo_recording.py
        # can drive observed_load's averaging window from its simulated clock.
        # Left on wall time, the synthetic run would integrate occupancy over
        # real elapsed time while everything around it advanced virtually.
        self._now: Callable[[], float] = time_source or time.monotonic
        self._lock = threading.RLock()
        self.node_ids = list(node_ids)
        self.trust_calc = trust_calculator or TrustCalculator()
        self.commit_backend = commit_backend or LocalLedgerBackend()
        self.authenticator = authenticator or NullAuthenticator()

        # Weight selection goes through a WeightOptimizer so the AI optimizer can
        # tune w1/w2/w3 live. The default StaticWeightOptimizer is inert -- it
        # returns the configured fixed weights forever, so routing is byte-for-byte
        # identical to the pre-optimizer controller. `edge_weights` below is a
        # read-only property delegating to whatever optimizer is active, so the
        # REST weight-readout reflects the live arm with no change to that code.
        self.optimizer: WeightOptimizer = optimizer or StaticWeightOptimizer(
            edge_weights or EdgeWeights()
        )
        # Only a real (non-static) optimizer runs the reward-window machinery.
        self._optimizer_enabled = not isinstance(self.optimizer, StaticWeightOptimizer)
        self._optimizer_window_s = optimizer_window_s
        self._reward_latency_penalty = reward_latency_penalty
        self._reward_imbalance_penalty = reward_imbalance_penalty
        self._reward_window = RewardWindow()
        self._window_started_at = time.time()

        # How the winner is chosen among eligible nodes: 'argmax' (winner-take-all,
        # original behaviour) or 'p2c' (power-of-two-choices, starvation-resistant).
        # See controller/edge_selector.py and docs/LOAD_BALANCING_STARVATION.md.
        self.selection_strategy = selection_strategy
        self.d_choices = d_choices
        # ε-exploration fraction layered on top of the base strategy (0.0 = off).
        self.epsilon = epsilon
        # Own RNG so routing is reproducible when seeded and never perturbs any
        # other consumer of the global random stream.
        self._selection_rng = selection_rng or random.Random()

        self.isolation_threshold = isolation_threshold
        self.anomaly_gate = anomaly_gate
        self.rate_limit_trust = rate_limit_trust
        self.anomaly_warn = anomaly_warn
        self.anomaly_lambda = anomaly_lambda
        self.max_updates_per_block = max_updates_per_block
        self.block_commit_timeout_s = block_commit_timeout_s
        self._oldest_pending_at: Optional[float] = None

        # Claimed telemetry from node_agent /status reports.
        self._claimed_cpu: Dict[str, float] = {nid: 0.5 for nid in self.node_ids}
        # Trailing (timestamp, claimed_cpu) samples, so the honesty check can
        # average the node's claim over the same window it averages its own
        # occupancy estimate over. See claimed_load().
        self._claimed_hist: Dict[str, Deque[Tuple[float, float]]] = {
            nid: deque() for nid in self.node_ids
        }
        self._latency_ms: Dict[str, float] = {nid: 50.0 for nid in self.node_ids}
        # Smoothed anomaly Ā(n) in [0, 1].
        self._anomaly: Dict[str, float] = {nid: 0.0 for nid in self.node_ids}

        # Per-node worker concurrency, as advertised by the agent (fixed at
        # startup; refreshed opportunistically from /status polls).
        self._concurrency: Dict[str, int] = {nid: 4 for nid in self.node_ids}
        # Tasks dispatched to a node whose completion has not yet been reported.
        # This is the observed-load numerator: it is counted by the controller
        # itself from what it actually dispatched, so a lying node cannot affect
        # it — unlike the claimed_cpu figures above.
        self._inflight: Dict[str, int] = {nid: 0 for nid in self.node_ids}
        # Little's Law relates the *time-average* queue length to arrival rate
        # times service time, so the occupancy estimate has to be integrated
        # over a window rather than sampled. Sampling _inflight directly reads
        # near-zero for a fast handler and jumps to 0.50 for a single instant
        # with two concurrent requests -- past the 0.40 honesty threshold on its
        # own, which brands a truthful idle node a liar. These track
        # integral(inflight dt) and the trailing samples observed_load() needs.
        self._inflight_area: Dict[str, float] = {nid: 0.0 for nid in self.node_ids}
        self._inflight_area_ts: Dict[str, float] = {
            nid: self._now() for nid in self.node_ids
        }
        self._inflight_hist: Dict[str, Deque[Tuple[float, float]]] = {
            nid: deque() for nid in self.node_ids
        }
        # Averaging window for observed_load. Kept at the same order as the
        # <3s isolation NFR: a genuinely saturated node still crosses the
        # honesty threshold within the budget, while a millisecond-scale burst
        # on an honest node averages away.
        self.load_window_s: float = 3.0
        # (client_ip, client_port) -> which node that specific flow was routed to.
        self._dispatches: Dict[Tuple[str, int], _Dispatch] = {}
        # Dispatches older than this are assumed abandoned (client crashed rather
        # than reporting) and get reaped so _inflight doesn't leak upward forever.
        self._dispatch_reap_after_s = 30.0

        # Recent task_status history per node, for flow_monitor's packet-drop
        # tell: a drop attacker can self-report CPU honestly (the CPU-honesty
        # check misses it entirely — see contracts/thresholds.py), but it cannot
        # avoid a high timeout rate among its own recent task outcomes.
        self._recent_statuses: Dict[str, Deque[str]] = {
            nid: deque(maxlen=10) for nid in self.node_ids
        }

        self._pending_updates: List[TrustUpdate] = []
        self._routing_decisions: List[Dict[str, Any]] = []
        # Nodes currently quarantined by the *previous* check, so callers (the
        # OpenFlow app) can detect the instant a node crosses into quarantine and
        # react (OFPFC_DELETE) rather than only ever consulting current state.
        self._was_quarantined: Dict[str, bool] = {nid: False for nid in self.node_ids}

    @property
    def edge_weights(self) -> EdgeWeights:
        """The weights currently used for routing. Read-only: it delegates to the
        active optimizer, so callers (routing, the REST weight-readout) always see
        the live arm. When the optimizer is off this is the fixed configured
        weights, identical to the old plain attribute."""
        return self.optimizer.active_weights()

    @property
    def optimizer_enabled(self) -> bool:
        """True when a live (non-static) weight optimizer is driving routing."""
        return self._optimizer_enabled

    # ------------------------------------------------------------------ #
    # Telemetry ingestion                                                 #
    # ------------------------------------------------------------------ #
    def report_claimed_status(self, node_id: str, cpu_load: float, measured_rtt_ms: float) -> None:
        """Ingest one poll of a node's telemetry.

        Deliberate honesty asymmetry between the two values:
        - cpu_load is the node's *self-reported* load. It has to be claimed --
          only the node knows its own CPU -- which is exactly why the honesty
          gate cross-checks it against the controller's observed_load estimate.
        - measured_rtt_ms is the controller's *own* measurement of how long the
          node's /status reply took to come back (FlowMonitor times the round
          trip). A node cannot lie about this the way it can lie about the
          latency_ms field in its payload, so this is what feeds the EdgeScore
          latency term. See FlowMonitor._fetch_status.
        """
        with self._lock:
            self._claimed_cpu[node_id] = cpu_load
            self._latency_ms[node_id] = measured_rtt_ms
            # Keep the claim history the honesty check averages over. The node
            # samples active/concurrency the instant its handler runs, so this
            # series is a quantised step function ({0, 0.25, 0.5, ...} at
            # concurrency 4) -- comparing one such sample against the
            # controller's windowed occupancy is comparing two different
            # quantities, and it trips in whichever direction happens to be
            # ahead at that instant.
            hist = self._claimed_hist.setdefault(node_id, deque())
            now = self._now()
            hist.append((now, float(cpu_load)))
            cutoff = now - 2 * self.load_window_s
            while len(hist) > 1 and hist[0][0] < cutoff:
                hist.popleft()

    def get_claimed_cpu(self, node_id: str) -> float:
        with self._lock:
            return self._claimed_cpu.get(node_id, 0.5)

    def claimed_load(self, node_id: str) -> float:
        """The node's self-reported CPU, time-averaged over the same window as
        observed_load, so the honesty check compares like with like.

        The raw claim stays available via get_claimed_cpu() and still drives the
        EdgeScore CPU term, where reacting to the latest reading is wanted --
        it is only the *honesty* comparison that needs both sides smoothed.
        """
        with self._lock:
            hist = self._claimed_hist.get(node_id)
            if not hist:
                return self._claimed_cpu.get(node_id, 0.5)

            now = self._now()
            target = now - self.load_window_s
            # Time-weight each claim by how long it stood, matching the way
            # observed_load integrates occupancy rather than counting samples.
            total = 0.0
            weight = 0.0
            prev_t, prev_v = hist[0]
            for ts, val in list(hist)[1:]:
                if ts > target:
                    dt = ts - max(prev_t, target)
                    if dt > 0:
                        total += prev_v * dt
                        weight += dt
                prev_t, prev_v = ts, val
            dt = now - max(prev_t, target)
            if dt > 0:
                total += prev_v * dt
                weight += dt
            if weight <= 0:
                return prev_v
            return max(0.0, min(1.0, total / weight))

    def set_anomaly_raw(self, node_id: str, anomaly_raw: float) -> float:
        """EMA-smooth a 0/1 anomaly signal (deviation or drop detected this poll)
        into Ā(n). Uses the same lambda as the trust EMA for consistency.

        Returns the new Ā(n).
        """
        with self._lock:
            prev = self._anomaly.get(node_id, 0.0)
            new = self.anomaly_lambda * anomaly_raw + (1 - self.anomaly_lambda) * prev
            self._anomaly[node_id] = new
            return new

    def get_anomaly(self, node_id: str) -> float:
        with self._lock:
            return self._anomaly.get(node_id, 0.0)

    def set_concurrency(self, node_id: str, concurrency: int) -> None:
        with self._lock:
            self._concurrency[node_id] = max(1, concurrency)

    def get_concurrency(self, node_id: str) -> int:
        with self._lock:
            return self._concurrency.get(node_id, 4)

    # ------------------------------------------------------------------ #
    # Dispatch tracking (client is never told which node it got — this is    #
    # the only record of the mapping, and the source of the observed-load    #
    # numerator that flow_monitor turns into `inflight / concurrency`)       #
    # ------------------------------------------------------------------ #
    def register_dispatch(self, client_ip: str, client_port: int, node_id: str) -> None:
        """Called by the OpenFlow app the instant it installs a VIP rewrite pair."""
        with self._lock:
            self._reap_stale_dispatches_locked()
            self._dispatches[(client_ip, client_port)] = _Dispatch(node_id, time.time())
            self._accrue_inflight_locked(node_id)
            self._inflight[node_id] = self._inflight.get(node_id, 0) + 1

    def complete_dispatch(self, client_ip: str, client_port: int) -> Optional[str]:
        """Called when the client's completion report arrives. Returns the node_id
        that flow was routed to, or None if it was never registered (e.g. this
        report is stale / duplicated, or arrived after the reaper cleaned it up)."""
        with self._lock:
            entry = self._dispatches.pop((client_ip, client_port), None)
            if entry is None:
                return None
            self._accrue_inflight_locked(entry.node_id)
            self._inflight[entry.node_id] = max(0, self._inflight.get(entry.node_id, 0) - 1)
            return entry.node_id

    def reassign_dispatches(self, from_node_id: str, to_node_id: str) -> List[Tuple[str, int]]:
        """Move every still-active dispatch mapped to from_node_id onto
        to_node_id, transferring inflight counts. Returns the
        (client_ip, client_port) keys that were moved so the OpenFlow app can
        install fresh VIP rewrite rules for them.

        Used by the re-dispatch path when a node is quarantined: the clients it
        was serving are re-pointed at the next-best node so their retry lands
        there with no PacketIn round trip. This is connection-granularity
        re-steering -- the in-flight TCP connections are killed by the drop
        rules (a live connection cannot be migrated without server-side state),
        so it is each client's *next* connection that this fast-path serves.
        """
        with self._lock:
            moved: List[Tuple[str, int]] = []
            for key, d in list(self._dispatches.items()):
                if d.node_id == from_node_id:
                    self._dispatches[key] = _Dispatch(to_node_id, time.time())
                    self._accrue_inflight_locked(from_node_id)
                    self._accrue_inflight_locked(to_node_id)
                    self._inflight[from_node_id] = max(0, self._inflight.get(from_node_id, 0) - 1)
                    self._inflight[to_node_id] = self._inflight.get(to_node_id, 0) + 1
                    moved.append(key)
            return moved

    def _reap_stale_dispatches_locked(self) -> None:
        now = time.time()
        stale = [
            key for key, d in self._dispatches.items()
            if now - d.dispatched_at > self._dispatch_reap_after_s
        ]
        for key in stale:
            entry = self._dispatches.pop(key)
            self._accrue_inflight_locked(entry.node_id)
            self._inflight[entry.node_id] = max(0, self._inflight.get(entry.node_id, 0) - 1)
            logger.warning(
                "Reaped abandoned dispatch to %s (client never reported completion)",
                entry.node_id,
            )

    def reap_stale_dispatches(self) -> None:
        """Periodic sweep for abandoned dispatches, called from FlowMonitor's
        poll loop.

        The reap must not be driven only by new dispatches: the moment every
        node is quarantined, choose_edge_node() returns None, nothing registers,
        and the sweep stops running exactly when it is needed most. Whatever was
        inflight at that moment then stays inflight forever, pinning
        observed_load high, which keeps the honesty check tripping, which keeps
        the nodes quarantined -- a terminal state nothing can leave.
        """
        with self._lock:
            self._reap_stale_dispatches_locked()

    def get_inflight(self, node_id: str) -> int:
        with self._lock:
            return self._inflight.get(node_id, 0)

    def _accrue_inflight_locked(self, node_id: str) -> float:
        """Advance integral(inflight dt) for this node up to now and record a
        trailing sample. Must be called with the lock held, and immediately
        *before* any mutation of _inflight[node_id], so the area accumulated so
        far is attributed to the old value. Returns the current timestamp."""
        now = self._now()
        last = self._inflight_area_ts.get(node_id, now)
        area = (
            self._inflight_area.get(node_id, 0.0)
            + self._inflight.get(node_id, 0) * (now - last)
        )
        self._inflight_area[node_id] = area
        self._inflight_area_ts[node_id] = now

        hist = self._inflight_hist.setdefault(node_id, deque())
        hist.append((now, area))
        # Keep a little more than one window so there is always a sample old
        # enough to average against.
        cutoff = now - 2 * self.load_window_s
        while len(hist) > 2 and hist[0][0] < cutoff:
            hist.popleft()
        return now

    def observed_load(self, node_id: str) -> float:
        """Little's-Law utilisation estimate: the *time-averaged* number of
        inflight tasks over the last load_window_s, divided by concurrency and
        clamped to [0, 1]. This is the CPU proxy flow_monitor cross-checks the
        node's claimed CPU against — it is counted by the controller from what it
        itself dispatched, so a dishonest node cannot influence it directly (it
        can only genuinely take longer to finish tasks, which raises inflight).

        Averaged rather than sampled on purpose: an instantaneous read is a
        step function over {0, 0.25, 0.50, ...} for concurrency 4, so an honest
        node that happens to be serving two quick requests at the polling
        instant reads 0.50 against a truthful claim of 0.00 and trips the
        honesty check on its own. Occupancy is only meaningful over time.
        """
        with self._lock:
            now = self._accrue_inflight_locked(node_id)
            concurrency = max(1, self._concurrency.get(node_id, 4))

            hist = self._inflight_hist.get(node_id)
            if not hist:
                return max(0.0, min(1.0, self._inflight.get(node_id, 0) / concurrency))

            # Oldest sample still at least a full window back, else the oldest
            # we have (the window is not yet full — early in a run).
            target = now - self.load_window_s
            t0, a0 = hist[0]
            for ts, ar in hist:
                if ts > target:
                    break
                t0, a0 = ts, ar

            span = now - t0
            if span <= 0.0:
                mean_inflight = float(self._inflight.get(node_id, 0))
            else:
                mean_inflight = (self._inflight_area[node_id] - a0) / span
            return max(0.0, min(1.0, mean_inflight / concurrency))

    # ------------------------------------------------------------------ #
    # Trust updates                                                       #
    # ------------------------------------------------------------------ #
    def record_task_outcome(self, upd: TrustUpdate) -> float:
        """Feed one real task outcome through the trust calculator and batch it
        for ledger commit. The anomaly flag is read from flow_monitor's smoothed
        signal at the moment of the update, so trust math and detection stay in
        sync without flow_monitor needing to touch TrustUpdate directly.
        """
        with self._lock:
            upd.anomaly_flag = self._anomaly.get(upd.edge_node_id, 0.0) >= self.anomaly_gate
            score = self.trust_calc.update(upd)
            self._pending_updates.append(upd)
            self._recent_statuses.setdefault(
                upd.edge_node_id, deque(maxlen=10)
            ).append(upd.task_status)
            if self._optimizer_enabled:
                # Credit this outcome to the arm currently active, for the reward
                # of the window it lands in (window-granularity attribution).
                self._reward_window.record_outcome(upd.task_status)
            if self._oldest_pending_at is None:
                self._oldest_pending_at = time.time()
            if len(self._pending_updates) >= self.max_updates_per_block:
                self._flush_pending_locked()
            return score

    def recent_timeout_rate(self, node_id: str, min_samples: int = 4) -> Optional[float]:
        """Fraction of the last (up to 10) task outcomes that were timeouts.

        Returns None if fewer than min_samples outcomes have been recorded yet —
        callers should not trigger on that little data, to avoid false positives
        during a node's first few interactions.
        """
        with self._lock:
            history = self._recent_statuses.get(node_id)
            if not history or len(history) < min_samples:
                return None
            return sum(1 for s in history if s == 'timeout') / len(history)

    def _flush_pending_locked(self) -> None:
        if self._pending_updates:
            self.commit_backend.commit(self._pending_updates)
            self._pending_updates.clear()
        self._oldest_pending_at = None

    def flush_pending(self) -> None:
        with self._lock:
            self._flush_pending_locked()

    def flush_if_stale(self) -> bool:
        """Commit whatever is pending if it has been waiting longer than
        block_commit_timeout_s. Call this periodically (e.g. from the same loop
        that drives flow_monitor) — otherwise a batch smaller than
        max_updates_per_block can sit uncommitted indefinitely once traffic quiets
        down, and GET /ledger/verify silently under-reports recent activity.

        Returns:
            True if a flush happened.
        """
        with self._lock:
            if (
                self._oldest_pending_at is not None
                and time.time() - self._oldest_pending_at >= self.block_commit_timeout_s
            ):
                self._flush_pending_locked()
                return True
            return False

    # ------------------------------------------------------------------ #
    # Routing / quarantine                                                #
    # ------------------------------------------------------------------ #
    def is_quarantined(self, node_id: str) -> bool:
        with self._lock:
            t = self.trust_calc.get_score(node_id)
            a = self._anomaly.get(node_id, 0.0)
            return t < self.isolation_threshold or a >= self.anomaly_gate

    def band(self, node_id: str) -> str:
        """The graduated-response band this node is in right now: 'full',
        'rate_limited', or 'quarantined' (see controller.edge_selector)."""
        with self._lock:
            ns = NodeState(
                node_id=node_id,
                trust=self.trust_calc.get_score(node_id),
                cpu_load=self._claimed_cpu.get(node_id, 0.5),
                latency_ms=self._latency_ms.get(node_id, 50.0),
                anomaly=self._anomaly.get(node_id, 0.0),
            )
            return trust_band(
                ns, self.isolation_threshold, self.anomaly_gate,
                self.rate_limit_trust, self.anomaly_warn,
            )

    def poll_quarantine_transitions(self) -> Tuple[List[str], List[str]]:
        """Return (newly_quarantined, newly_recovered) since the last call.

        Callers (the OpenFlow app) use these edge-triggers to issue the flow
        mods exactly once per transition, rather than re-sending them every
        poll. Recovery needs an edge-trigger of its own: is_quarantined() is
        derived live from trust and Ā, so the *state* clears itself as soon as
        the node behaves, but the drop rules installed on collapse are physical
        and stay in the switch until something deletes them.
        """
        with self._lock:
            newly: List[str] = []
            recovered: List[str] = []
            for nid in self.node_ids:
                now_q = self.is_quarantined(nid)
                was_q = self._was_quarantined.get(nid, False)
                if now_q and not was_q:
                    newly.append(nid)
                elif was_q and not now_q:
                    recovered.append(nid)
                self._was_quarantined[nid] = now_q
            return newly, recovered

    def poll_newly_quarantined(self) -> List[str]:
        """Back-compat wrapper: the quarantine half of
        poll_quarantine_transitions(). Both consume the same edge state, so
        only one of the two may be called per cycle."""
        return self.poll_quarantine_transitions()[0]

    def choose_edge_node(self) -> Optional[str]:
        """n* = argmax EdgeScore(n) among non-quarantined nodes, or None if all
        candidates are quarantined (deny by default)."""
        with self._lock:
            states = [
                NodeState(
                    node_id=nid,
                    trust=self.trust_calc.get_score(nid),
                    cpu_load=self._claimed_cpu.get(nid, 0.5),
                    latency_ms=self._latency_ms.get(nid, 50.0),
                    anomaly=self._anomaly.get(nid, 0.0),
                )
                for nid in self.node_ids
            ]
            weights = self.optimizer.active_weights()
            chosen, score, ranked = select_edge_node(
                states, weights, self.isolation_threshold, self.anomaly_gate,
                strategy=self.selection_strategy, d_choices=self.d_choices,
                epsilon=self.epsilon, rng=self._selection_rng,
            )
            if self._optimizer_enabled and chosen is not None:
                # Feed the chosen node's normalized latency into the reward window,
                # so the optimizer is rewarded for routing to fast nodes even when
                # the success rate is saturated (see compute_reward's latency term).
                max_lat = max((s.latency_ms for s in states), default=1.0)
                self._reward_window.record_latency(
                    self._latency_ms.get(chosen, 50.0) / max(max_lat, 1.0)
                )
            self._routing_decisions.append({
                'timestamp': time.time(),
                'chosen': chosen,
                'score': score,
                'ranked': ranked,
            })
            return chosen

    def optimizer_tick(self) -> Optional[Dict[str, Any]]:
        """Drive the AI optimizer one step. Call ~1 Hz (flow_monitor's poll loop).

        When the reward window has elapsed: snapshot per-node load for the
        imbalance term, score the arm that was active over the window, feed that
        reward back to the optimizer, and switch to the arm it selects for the next
        window. Returns a summary on a window close (for logging / SSE), else None.

        A no-op when the optimizer is disabled (StaticWeightOptimizer), so the
        controller is unaffected unless the optimizer is explicitly turned on.
        """
        if not self._optimizer_enabled:
            return None
        with self._lock:
            if time.time() - self._window_started_at < self._optimizer_window_s:
                return None
            # observed_load re-enters the lock (RLock) -- safe, and it must be read
            # here rather than per-decision because load is a point-in-time gauge.
            self._reward_window.load_samples = [
                self.observed_load(nid) for nid in self.node_ids
            ]
            reward = compute_reward(
                self._reward_window,
                self._reward_latency_penalty,
                self._reward_imbalance_penalty,
            )
            prev = self.optimizer.active_weights()
            self.optimizer.observe(reward)
            nxt = self.optimizer.select()
            summary: Dict[str, Any] = {
                'reward': round(reward, 4),
                'outcomes': self._reward_window.total_outcomes,
                'prev_weights': [prev.w1_trust, prev.w2_cpu, prev.w3_latency],
                'next_weights': [nxt.w1_trust, nxt.w2_cpu, nxt.w3_latency],
                # Aggregate network conditions at window close. These are the
                # features the offline Random Forest will train on: (conditions ->
                # which arm/weights performed well). They ride the recorded
                # 'optimizer' event stream, so no separate training log is needed.
                'conditions': self._conditions_snapshot_locked(),
            }
            # Per-arm pull counts / mean rewards, so a dashboard driven only by
            # this event stream (e.g. the sudo-free replay) can render the full
            # bandit state without also polling /api/optimizer.
            if hasattr(self.optimizer, 'stats'):
                summary['arms'] = self.optimizer.stats()
            self._reward_window = RewardWindow()
            self._window_started_at = time.time()
            return summary

    def _conditions_snapshot_locked(self) -> Dict[str, float]:
        """Aggregate network-condition features for the optimizer log / RF.
        Caller must hold self._lock."""
        n = len(self.node_ids) or 1
        trusts = [self.trust_calc.get_score(nid) for nid in self.node_ids]
        loads = [self.observed_load(nid) for nid in self.node_ids]
        latencies = [self._latency_ms.get(nid, 50.0) for nid in self.node_ids]
        quarantined = sum(1 for nid in self.node_ids if self.is_quarantined(nid))
        return {
            'mean_trust': round(sum(trusts) / n, 4),
            'mean_load': round(sum(loads) / n, 4),
            'mean_latency_ms': round(sum(latencies) / n, 2),
            'num_quarantined': quarantined,
        }

    @property
    def routing_decisions(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._routing_decisions)

    def last_routing_decision(self) -> Optional[Dict[str, Any]]:
        """The most recent decision, O(1).

        The `routing_decisions` property above copies the whole (unbounded)
        history on every access, which is fine for end-of-run analysis but not
        for the OpenFlow event path -- the dashboard publishes one event per
        routed connection, and copying the entire history each time would make
        routing steadily slower over a run and eat the <200ms NFR.
        """
        with self._lock:
            return self._routing_decisions[-1] if self._routing_decisions else None

    # ------------------------------------------------------------------ #
    # Snapshots (REST / logging)                                          #
    # ------------------------------------------------------------------ #
    def snapshot(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return {
                nid: {
                    'trust': round(self.trust_calc.get_score(nid), 4),
                    'claimed_cpu': round(self._claimed_cpu.get(nid, 0.5), 4),
                    'observed_load': round(self.observed_load(nid), 4),
                    'inflight': self._inflight.get(nid, 0),
                    'latency_ms': round(self._latency_ms.get(nid, 50.0), 2),
                    'anomaly': round(self._anomaly.get(nid, 0.0), 4),
                    'quarantined': self.is_quarantined(nid),
                }
                for nid in self.node_ids
            }
