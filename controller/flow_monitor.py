"""Per-second anomaly detection loop for the trust-aware controller.

Polls every edge agent's GET /status concurrently (never serially -- a serial
loop with a per-node timeout can burn most of a 1s budget if even one node is
dark), feeds the results into the shared TrustState, and derives the two
independent quarantine signals:

    1. CPU-honesty deviation: |claimed_cpu - observed_load| > threshold.
       observed_load is the controller's own Little's-Law estimate
       (TrustState.observed_load), never the node's self-report, so a lying
       node cannot influence the check it's being judged against.
    2. Packet-drop tell: TrustState.recent_timeout_rate -- a drop attacker can
       self-report CPU honestly, so it needs its own signal entirely separate
       from (1).

Either cause calls TrustState.set_anomaly_raw(1.0); a node with neither
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
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, List, Optional

from os_ken.lib import hub

from controller.trust_state import TrustState
from simulation.addressing import srv_index, srv_ip

logger = logging.getLogger(__name__)

_STATUS_TIMEOUT_S = 0.5
_MIN_TIMEOUT_SAMPLES = 4


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
    ) -> None:
        self.state = state
        self.node_ids = list(node_ids)
        self.agent_port = agent_port
        self.poll_interval_s = poll_interval_s
        self.honesty_deviation_threshold = honesty_deviation_threshold
        self.on_quarantine = on_quarantine
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
        results = dict(zip(
            self.node_ids,
            self._executor.map(self._fetch_status, self.node_ids),
        ))

        for node_id in self.node_ids:
            status = results[node_id]
            anomaly_raw = 0.0

            if status is not None:
                claimed_cpu = status.get('cpu_load', 0.5)
                latency_ms = status.get('latency_ms', 50.0)
                concurrency = status.get('concurrency')

                self.state.report_claimed_status(node_id, claimed_cpu, latency_ms)
                if concurrency:
                    self.state.set_concurrency(node_id, int(concurrency))

                observed = self.state.observed_load(node_id)
                deviation = abs(claimed_cpu - observed)
                if deviation > self.honesty_deviation_threshold:
                    logger.warning(
                        "%s: honesty deviation %.3f (claimed=%.3f observed=%.3f) > %.3f",
                        node_id, deviation, claimed_cpu, observed,
                        self.honesty_deviation_threshold,
                    )
                    anomaly_raw = 1.0
            else:
                # Agent unreachable this cycle -- treat as suspicious rather
                # than silently skipping, but don't crash the loop over it.
                # The anomaly EMA (lambda=0.85 by default) means even one
                # missed poll pushes Ā above the 0.5 gate immediately, which
                # matches the project's <3s isolation NFR rather than
                # under-reacting to what could be a genuine outage.
                logger.warning("%s: /status poll failed this cycle", node_id)
                anomaly_raw = 1.0

            timeout_rate = self.state.recent_timeout_rate(node_id, min_samples=_MIN_TIMEOUT_SAMPLES)
            if timeout_rate is not None and timeout_rate > self.honesty_deviation_threshold:
                logger.warning(
                    "%s: recent timeout rate %.3f > %.3f -- packet-drop tell",
                    node_id, timeout_rate, self.honesty_deviation_threshold,
                )
                anomaly_raw = 1.0

            self.state.set_anomaly_raw(node_id, anomaly_raw)

        for node_id in self.state.poll_newly_quarantined():
            try:
                self.on_quarantine(node_id)
            except Exception:
                logger.exception("on_quarantine callback failed for %s", node_id)

        self.state.flush_if_stale()

    def _fetch_status(self, node_id: str) -> Optional[dict]:
        host = srv_ip(srv_index(node_id))
        try:
            conn = http.client.HTTPConnection(host, self.agent_port, timeout=_STATUS_TIMEOUT_S)
            conn.request('GET', '/status')
            resp = conn.getresponse()
            body = resp.read()
            conn.close()
            if resp.status != 200:
                return None
            return json.loads(body)
        except OSError:
            return None
