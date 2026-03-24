"""Simplified Ryu SDN controller for trust-aware load balancing.

All Ryu imports are conditional so that the module can be imported in
standalone simulation mode without Ryu installed.
"""

import csv
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from contracts.trust_update import TrustUpdate
from trust_engine.trust_calculator import TrustCalculator
from blockchain.block import build_block
from blockchain.ledger import Ledger

logger = logging.getLogger(__name__)

# ---------- conditional Ryu imports ----------
try:
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
    from ryu.ofproto import ofproto_v1_3
    from ryu.lib.packet import packet, ethernet, ipv4

    _RYU_AVAILABLE = True
except ImportError:
    _RYU_AVAILABLE = False
    logger.info("Ryu not available - controller runs in standalone mode only")


class TrustBalancerStandalone:
    """Standalone trust-aware load balancer (no Ryu dependency).

    Provides the same EdgeScore routing logic used by the full Ryu
    controller so that run_demo.py can work without Ryu/Mininet.
    """

    def __init__(
        self,
        trust_calculator: TrustCalculator,
        ledger: Ledger,
        edge_score_weights: Dict[str, float],
        num_edge_nodes: int = 8,
        max_updates_per_block: int = 10,
    ) -> None:
        self.trust_calc = trust_calculator
        self.ledger = ledger
        self.w1 = edge_score_weights.get('w1_trust', 0.50)
        self.w2 = edge_score_weights.get('w2_cpu', 0.30)
        self.w3 = edge_score_weights.get('w3_latency', 0.20)
        self.num_edge_nodes = num_edge_nodes
        self.max_updates_per_block = max_updates_per_block

        # Pending trust updates waiting for block commit
        self._pending_updates: List[TrustUpdate] = []

        # Routing log path
        self._log_path = Path('data') / 'routing_log.csv'
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._log_initialised = False

    def _ensure_log_header(self) -> None:
        """Write CSV header if the file doesn't exist yet."""
        if not self._log_initialised:
            with open(self._log_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 'node_id', 'edge_score', 'trust_score',
                    'routing_latency_ms', 'task_status',
                ])
            self._log_initialised = True

    def select_edge_node(
        self,
        cpu_loads: Dict[str, float],
        latencies: Dict[str, float],
    ) -> str:
        """Select the best edge node using the EdgeScore formula.

        EdgeScore(n) = w1*T(n) + w2*(1 - cpu_load(n)) + w3*(1 - lat_norm(n))

        Args:
            cpu_loads: {node_id: cpu_load} where cpu_load ∈ [0, 1].
            latencies: {node_id: latency_ms}.

        Returns:
            The node_id with the highest EdgeScore.
        """
        best_node: str = f'srv1'
        best_score: float = -1.0

        # Normalise latencies to [0, 1]
        max_lat = max(latencies.values()) if latencies else 1.0
        max_lat = max(max_lat, 1.0)  # Avoid division by zero

        for i in range(1, self.num_edge_nodes + 1):
            nid = f'srv{i}'
            t_score = self.trust_calc.get_score(nid)
            cpu = cpu_loads.get(nid, 0.5)
            lat = latencies.get(nid, 50.0)
            lat_norm = lat / max_lat

            edge_score = (
                self.w1 * t_score
                + self.w2 * (1.0 - cpu)
                + self.w3 * (1.0 - lat_norm)
            )

            if edge_score > best_score:
                best_score = edge_score
                best_node = nid

        return best_node

    def update_trust(
        self,
        node_id: str,
        device_id: str,
        task_status: str,
        cpu_usage: float,
        reported_cpu: float,
        latency_ms: float,
        anomaly_flag: bool = False,
    ) -> float:
        """Create a TrustUpdate, compute the new score, and batch for block commit.

        Returns:
            The new trust score for the node.
        """
        upd = TrustUpdate(
            device_id=device_id,
            edge_node_id=node_id,
            task_status=task_status,
            cpu_usage=cpu_usage,
            reported_cpu=reported_cpu,
            latency_ms=latency_ms,
            anomaly_flag=anomaly_flag,
        )
        upd.trust_score_before = self.trust_calc.get_score(node_id)
        score = self.trust_calc.update(upd)

        self._pending_updates.append(upd)

        # Commit block when batch is full
        if len(self._pending_updates) >= self.max_updates_per_block:
            self._commit_block()

        return score

    def _commit_block(self) -> Optional[Any]:
        """Commit pending updates as a new block on the ledger."""
        if not self._pending_updates:
            return None

        block = build_block(
            index=self.ledger.get_chain_length(),
            previous_hash=self.ledger._chain[-1].hash,
            updates=list(self._pending_updates),
        )
        accepted = self.ledger.append(block)
        if accepted:
            logger.info("Block %d committed with %d updates", block.index, len(self._pending_updates))
        else:
            logger.error("Block %d REJECTED", block.index)

        self._pending_updates.clear()
        return block if accepted else None

    def flush_pending(self) -> None:
        """Force-commit any remaining pending updates."""
        if self._pending_updates:
            self._commit_block()

    def log_routing_decision(
        self,
        node_id: str,
        edge_score: float,
        trust_score: float,
        routing_latency_ms: float,
        task_status: str,
    ) -> None:
        """Append a routing decision to the CSV log."""
        self._ensure_log_header()
        with open(self._log_path, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                time.time(), node_id, f'{edge_score:.4f}',
                f'{trust_score:.4f}', f'{routing_latency_ms:.2f}', task_status,
            ])
