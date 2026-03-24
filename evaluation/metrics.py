"""Metrics collector for the Zero Trust SDN simulation.

Records routing decisions, trust updates, and block commits, then
provides summary statistics and CSV export.
"""

import csv
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class MetricsCollector:
    """Collects and aggregates simulation metrics for analysis and plotting."""

    def __init__(self) -> None:
        self._routing_events: List[Dict[str, Any]] = []
        self._trust_events: List[Dict[str, Any]] = []
        self._block_events: List[Dict[str, Any]] = []
        self._start_time: float = time.time()

    # ------------------------------------------------------------------ #
    # Recording                                                           #
    # ------------------------------------------------------------------ #
    def record_routing(
        self,
        node_id: str,
        edge_score: float,
        trust_score: float,
        latency_ms: float,
        task_status: str,
    ) -> None:
        """Record a single routing decision."""
        self._routing_events.append({
            'timestamp': time.time(),
            'elapsed_s': time.time() - self._start_time,
            'node_id': node_id,
            'edge_score': edge_score,
            'trust_score': trust_score,
            'latency_ms': latency_ms,
            'task_status': task_status,
        })

    def record_trust_update(
        self,
        node_id: str,
        score_before: float,
        score_after: float,
        anomaly_flag: bool,
    ) -> None:
        """Record a trust score change for a node."""
        self._trust_events.append({
            'timestamp': time.time(),
            'elapsed_s': time.time() - self._start_time,
            'node_id': node_id,
            'score_before': score_before,
            'score_after': score_after,
            'anomaly_flag': anomaly_flag,
        })

    def record_block_commit(
        self,
        block_index: int,
        num_updates: int,
        commit_time_ms: float,
    ) -> None:
        """Record a block commit event."""
        self._block_events.append({
            'timestamp': time.time(),
            'elapsed_s': time.time() - self._start_time,
            'block_index': block_index,
            'num_updates': num_updates,
            'commit_time_ms': commit_time_ms,
        })

    # ------------------------------------------------------------------ #
    # Summaries                                                           #
    # ------------------------------------------------------------------ #
    def get_summary(self) -> Dict[str, Any]:
        """Return per-node stats: mean trust, routing count, mean latency."""
        nodes: Dict[str, Dict[str, Any]] = {}

        for evt in self._routing_events:
            nid = evt['node_id']
            if nid not in nodes:
                nodes[nid] = {
                    'trust_scores': [],
                    'routing_count': 0,
                    'latencies': [],
                }
            nodes[nid]['trust_scores'].append(evt['trust_score'])
            nodes[nid]['routing_count'] += 1
            nodes[nid]['latencies'].append(evt['latency_ms'])

        summary: Dict[str, Any] = {}
        for nid, data in nodes.items():
            summary[nid] = {
                'mean_trust': sum(data['trust_scores']) / len(data['trust_scores']),
                'routing_count': data['routing_count'],
                'mean_latency_ms': sum(data['latencies']) / len(data['latencies']),
            }

        return summary

    def export_csv(self, path: str) -> None:
        """Write all routing events to a CSV file.

        Args:
            path: Output file path (directories created automatically).
        """
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)

        with open(out, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'timestamp', 'node_id', 'edge_score', 'trust_score',
                'routing_latency_ms', 'task_status',
            ])
            for evt in self._routing_events:
                writer.writerow([
                    evt['timestamp'], evt['node_id'],
                    f"{evt['edge_score']:.4f}", f"{evt['trust_score']:.4f}",
                    f"{evt['latency_ms']:.2f}", evt['task_status'],
                ])

        logger.info("Exported %d routing events to %s", len(self._routing_events), path)

    def get_malicious_isolation_time(
        self, malicious_nodes: List[str]
    ) -> Dict[str, Optional[float]]:
        """For each malicious node, return seconds from first anomaly to exclusion.

        A node is considered 'isolated' when its trust score drops below 0.3.

        Args:
            malicious_nodes: List of node IDs marked as malicious.

        Returns:
            Dict mapping node_id → isolation time in seconds, or None.
        """
        result: Dict[str, Optional[float]] = {}

        for node_id in malicious_nodes:
            # Find first trust event where score drops below 0.3
            first_event_time: Optional[float] = None
            isolation_time: Optional[float] = None

            for evt in self._trust_events:
                if evt['node_id'] == node_id:
                    if first_event_time is None:
                        first_event_time = evt['elapsed_s']
                    if evt['score_after'] < 0.3 and isolation_time is None:
                        isolation_time = evt['elapsed_s']

            if first_event_time is not None and isolation_time is not None:
                result[node_id] = round(isolation_time - first_event_time, 1)
            else:
                result[node_id] = None

        return result

    # ------------------------------------------------------------------ #
    # Raw accessors (for plots)                                           #
    # ------------------------------------------------------------------ #
    @property
    def routing_events(self) -> List[Dict[str, Any]]:
        return self._routing_events

    @property
    def trust_events(self) -> List[Dict[str, Any]]:
        return self._trust_events

    @property
    def block_events(self) -> List[Dict[str, Any]]:
        return self._block_events
