"""Attack simulator — injects malicious TrustUpdate records via daemon threads.

Supports two attack types for the Semester 1 demo:
  1. Sybil attack: floods fake-node trust updates
  2. Packet-drop attack: causes repeated timeouts on a real node
"""

import logging
import queue
import random
import threading
import time
from typing import Optional

from contracts.trust_update import TrustUpdate

logger = logging.getLogger(__name__)


class AttackSimulator:
    """Generates malicious TrustUpdate records and pushes them to a shared queue.

    Each attack method spawns a daemon thread that continuously injects
    crafted TrustUpdate objects until stop() is called.
    """

    def __init__(self, update_queue: queue.Queue, interval_s: float = 0.5) -> None:
        """Initialise the attack simulator.

        Args:
            update_queue: Shared queue that the main loop reads updates from.
            interval_s: Seconds between injected updates per thread.
        """
        self._queue = update_queue
        self._interval = interval_s
        self._stop_event = threading.Event()
        self._threads: list[threading.Thread] = []

    # ------------------------------------------------------------------ #
    # Sybil Attack                                                        #
    # ------------------------------------------------------------------ #
    def start_sybil_attack(
        self,
        real_node_id: str,
        num_fake_ids: int = 5,
    ) -> None:
        """Spawn a daemon thread that injects trust updates for fake node IDs.

        Fake updates look perfect (low CPU, low latency, all success) but
        carry anomaly_flag=True so the demo can show detection.

        Args:
            real_node_id: The real node being impersonated.
            num_fake_ids: Number of fake identities to create.
        """
        fake_ids = [f"fake_{real_node_id}_{i}" for i in range(num_fake_ids)]
        logger.warning(
            "Sybil attack started on %s with %d fake IDs", real_node_id, num_fake_ids
        )

        def _sybil_loop() -> None:
            while not self._stop_event.is_set():
                # Inject updates for fake node IDs (detected as anomalous)
                for fid in fake_ids:
                    if self._stop_event.is_set():
                        break
                    upd = TrustUpdate(
                        device_id=f"iot_sybil_{fid}",
                        edge_node_id=fid,
                        task_status='success',
                        cpu_usage=0.1,
                        reported_cpu=0.1,
                        latency_ms=5.0,
                        anomaly_flag=True,
                    )
                    self._queue.put(upd)
                # Also inject a poisoned update for the REAL node
                # (simulates the attacker disrupting the real node's reputation)
                if not self._stop_event.is_set():
                    real_upd = TrustUpdate(
                        device_id=f"iot_sybil_{real_node_id}",
                        edge_node_id=real_node_id,
                        task_status='failure',
                        cpu_usage=0.9,
                        reported_cpu=0.1,
                        latency_ms=400.0,
                        anomaly_flag=True,
                    )
                    self._queue.put(real_upd)
                time.sleep(self._interval)

        t = threading.Thread(target=_sybil_loop, daemon=True, name=f"sybil-{real_node_id}")
        t.start()
        self._threads.append(t)

    # ------------------------------------------------------------------ #
    # Packet-Drop Attack                                                  #
    # ------------------------------------------------------------------ #
    def start_packet_drop_attack(
        self,
        node_id: str,
        drop_rate: float = 0.8,
    ) -> None:
        """Spawn a daemon thread that injects timeout-heavy updates for a real node.

        Trust collapses from repeated timeouts — anomaly_flag is False
        because this simulates degradation detected only by the trust formula.

        Args:
            node_id: The edge node to target.
            drop_rate: Probability of 'timeout' per injected update.
        """
        logger.warning(
            "Packet-drop attack started on %s (drop_rate=%.0f%%)",
            node_id, drop_rate * 100,
        )

        def _drop_loop() -> None:
            while not self._stop_event.is_set():
                status = 'timeout' if random.random() < drop_rate else 'success'
                upd = TrustUpdate(
                    device_id=f"iot_drop_{node_id}",
                    edge_node_id=node_id,
                    task_status=status,
                    cpu_usage=random.uniform(0.3, 0.8),
                    reported_cpu=random.uniform(0.1, 0.3),
                    latency_ms=random.uniform(100, 450),
                    anomaly_flag=False,
                )
                self._queue.put(upd)
                time.sleep(self._interval)

        t = threading.Thread(target=_drop_loop, daemon=True, name=f"pktdrop-{node_id}")
        t.start()
        self._threads.append(t)

    # ------------------------------------------------------------------ #
    # Control                                                             #
    # ------------------------------------------------------------------ #
    def stop(self) -> None:
        """Signal all attack threads to stop and wait for them to finish."""
        logger.info("Stopping all attack threads...")
        self._stop_event.set()
        for t in self._threads:
            t.join(timeout=2.0)
        self._threads.clear()
        self._stop_event.clear()
        logger.info("All attack threads stopped")
