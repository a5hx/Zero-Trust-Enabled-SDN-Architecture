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
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Deque, Dict, List, Optional, Tuple

from blockchain.commit_backend import CommitBackend, LocalLedgerBackend
from contracts.thresholds import DEFAULT_ANOMALY_GATE, DEFAULT_ISOLATION_THRESHOLD
from contracts.trust_update import TrustUpdate
from controller.edge_selector import EdgeWeights, NodeState, select_edge_node
from security.authenticator import Authenticator, NullAuthenticator
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
        isolation_threshold: float = DEFAULT_ISOLATION_THRESHOLD,
        anomaly_gate: float = DEFAULT_ANOMALY_GATE,
        anomaly_lambda: float = 0.85,
        max_updates_per_block: int = 10,
        block_commit_timeout_s: float = 5.0,
    ) -> None:
        self._lock = threading.RLock()
        self.node_ids = list(node_ids)
        self.trust_calc = trust_calculator or TrustCalculator()
        self.commit_backend = commit_backend or LocalLedgerBackend()
        self.authenticator = authenticator or NullAuthenticator()
        self.edge_weights = edge_weights or EdgeWeights()
        self.isolation_threshold = isolation_threshold
        self.anomaly_gate = anomaly_gate
        self.anomaly_lambda = anomaly_lambda
        self.max_updates_per_block = max_updates_per_block
        self.block_commit_timeout_s = block_commit_timeout_s
        self._oldest_pending_at: Optional[float] = None

        # Claimed telemetry from node_agent /status reports.
        self._claimed_cpu: Dict[str, float] = {nid: 0.5 for nid in self.node_ids}
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

    # ------------------------------------------------------------------ #
    # Telemetry ingestion                                                 #
    # ------------------------------------------------------------------ #
    def report_claimed_status(self, node_id: str, cpu_load: float, latency_ms: float) -> None:
        """From node_agent's /status response (self-reported, possibly a lie)."""
        with self._lock:
            self._claimed_cpu[node_id] = cpu_load
            self._latency_ms[node_id] = latency_ms

    def get_claimed_cpu(self, node_id: str) -> float:
        with self._lock:
            return self._claimed_cpu.get(node_id, 0.5)

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
            self._inflight[node_id] = self._inflight.get(node_id, 0) + 1

    def complete_dispatch(self, client_ip: str, client_port: int) -> Optional[str]:
        """Called when the client's completion report arrives. Returns the node_id
        that flow was routed to, or None if it was never registered (e.g. this
        report is stale / duplicated, or arrived after the reaper cleaned it up)."""
        with self._lock:
            entry = self._dispatches.pop((client_ip, client_port), None)
            if entry is None:
                return None
            self._inflight[entry.node_id] = max(0, self._inflight.get(entry.node_id, 0) - 1)
            return entry.node_id

    def _reap_stale_dispatches_locked(self) -> None:
        now = time.time()
        stale = [
            key for key, d in self._dispatches.items()
            if now - d.dispatched_at > self._dispatch_reap_after_s
        ]
        for key in stale:
            entry = self._dispatches.pop(key)
            self._inflight[entry.node_id] = max(0, self._inflight.get(entry.node_id, 0) - 1)
            logger.warning(
                "Reaped abandoned dispatch to %s (client never reported completion)",
                entry.node_id,
            )

    def get_inflight(self, node_id: str) -> int:
        with self._lock:
            return self._inflight.get(node_id, 0)

    def observed_load(self, node_id: str) -> float:
        """Little's-Law-style utilisation estimate: inflight / concurrency,
        clamped to [0, 1]. This is the CPU proxy flow_monitor cross-checks the
        node's claimed CPU against — it is counted by the controller from what it
        itself dispatched, so a dishonest node cannot influence it directly (it
        can only genuinely take longer to finish tasks, which raises inflight)."""
        with self._lock:
            concurrency = max(1, self._concurrency.get(node_id, 4))
            inflight = self._inflight.get(node_id, 0)
            return max(0.0, min(1.0, inflight / concurrency))

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

    def poll_newly_quarantined(self) -> List[str]:
        """Return node_ids that just crossed into quarantine since the last call.

        Callers (the OpenFlow app) use this edge-trigger to issue OFPFC_DELETE
        exactly once per collapse, rather than re-deleting flows every poll.
        """
        with self._lock:
            newly: List[str] = []
            for nid in self.node_ids:
                now_q = self.is_quarantined(nid)
                if now_q and not self._was_quarantined.get(nid, False):
                    newly.append(nid)
                self._was_quarantined[nid] = now_q
            return newly

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
            chosen, score, ranked = select_edge_node(
                states, self.edge_weights, self.isolation_threshold, self.anomaly_gate
            )
            self._routing_decisions.append({
                'timestamp': time.time(),
                'chosen': chosen,
                'score': score,
                'ranked': ranked,
            })
            return chosen

    @property
    def routing_decisions(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._routing_decisions)

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
