"""Replay a recorded controller run into the dashboard -- no Mininet, no sudo.

    python3 -m dashboard.replay data/events.jsonl

Serves the same dashboard endpoints the live controller does (/, /analysis,
/api/topology, /api/events, /api/flows, /api/ports, /api/optimizer,
/api/scale_compare), but sourced from a recorded events.jsonl instead of a
running network. The dashboard cannot tell the difference and needs no changes.

Two reasons this exists:

    1. The live demo needs root (Mininet creates network namespaces, veth pairs
       and OVS bridges), which makes iterating on the UI slow and makes the
       dashboard untestable in CI. Replay makes the whole frontend exercisable
       from a plain user shell.
    2. Demo-day insurance. A recorded run of the srv3 Sybil attack -- trust
       collapsing, rules being deleted, traffic re-steering -- can be replayed
       in front of an examiner even if the live network refuses to come up on
       the day.

Events are re-emitted with their original inter-event delays (scaled by
--speed), so the replay paces exactly like the run it came from: the ~20s
build-up before srv3 starts lying takes ~20s, not zero.
"""

import argparse
import json
import logging
import queue
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from controller.event_bus import EventBus
from controller.northbound_api import NorthboundAPI
from controller.trust_state import TrustState

logger = logging.getLogger(__name__)


class ReplayApp:
    """Duck-typed stand-in for TrustBalancerApp.

    Every attribute northbound_api.py reaches for on `app` must exist here or
    that route dies with an AttributeError inside the handler thread -- which
    the browser sees as a dropped connection, not as a 500, so the panel just
    stays empty with nothing in the log to point at. Adding an `/api/*` route
    to northbound_api.py therefore means adding its stand-in here, and to
    `_FakeApp` in tests/test_dashboard_api.py.
    """

    def __init__(self, events: List[Dict[str, Any]], speed: float = 1.0) -> None:
        self.events = events
        self.speed = speed
        self.bus = EventBus(record_path=None)   # replaying, don't re-record
        self._flows: List[Dict[str, Any]] = []
        # (dpid, port) -> latest entry, exactly the keying and ordering
        # controller/port_stats.py's snapshot() uses, so GET /api/ports returns
        # the same shape live and on replay.
        self._ports: Dict[Any, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._topology = self._recover_topology(events)

    # -- the three methods northbound_api's dashboard routes actually use --
    def topology_graph(self) -> Dict[str, Any]:
        return self._topology

    def flow_table(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._flows)

    def port_table(self) -> List[Dict[str, Any]]:
        """Per-port link load, accumulated from the recording's `port_stats`
        events the same way `flow_table` accumulates `flow_stats`.

        Empty until the first such event streams past -- a recording carries
        one poll cycle per interval, not a starting snapshot, so an early
        request legitimately has nothing to report.
        """
        with self._lock:
            return sorted(self._ports.values(), key=lambda p: (p['dpid'], p['port']))

    def record_link_params(self, links: List[Dict[str, Any]]) -> int:
        """POST /topology/links, refused rather than applied.

        The harness reports the links it actually built; on replay the graph
        comes from the recording, which already carries whatever the harness
        reported during the run it came from. Merging a live POST into it would
        let a caller edit a finished recording's topology, so this accepts
        nothing and says so in the response's `accepted: 0`.
        """
        logger.info("ignoring %d reported link(s): replay serves the recording's "
                    "own topology", len(links) if isinstance(links, list) else 0)
        return 0

    def optimizer_status(self) -> Dict[str, Any]:
        """Replay has no live optimizer to poll: report disabled and let the
        recorded 'optimizer' events populate the panel as they stream, which is
        exactly the "watch the bandit learn" story we want on replay."""
        return {'enabled': False, 'active_weights': self._topology['weights'], 'arms': []}

    @staticmethod
    def _recover_topology(events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Rebuild the graph from the recording itself.

        A `topology` event is written at the head of every recording (see
        TrustBalancerApp.start), so normally this is a straight read. The
        reconstruction path below only matters for recordings made before that
        event existed, or hand-trimmed ones.

        A later `topology_links` event carries the same graph plus the link
        parameters the harness actually built (delay_ms/bw_mbps). Prefer it, so
        GET /api/topology returns the same enriched graph on replay as it does
        live and the Node structure panel is populated the moment the page
        loads -- rather than staying blank until the recorded topology_links
        event happens to stream past.
        """
        graph = None
        for ev in events:
            if ev.get('type') == 'topology_links' and ev.get('graph'):
                return ev['graph']
            if graph is None and ev.get('type') == 'topology':
                graph = ev.get('graph')
        if graph is not None:
            return graph

        # Fallback: infer the servers from node_status and the IoT devices from
        # whatever client IPs appear in the routing decisions.
        servers, iots = set(), set()
        for ev in events:
            if ev.get('type') == 'node_status':
                servers.update(ev.get('nodes', {}))
            if ev.get('type') == 'route' and ev.get('client_ip'):
                iots.add(int(ev['client_ip'].split('.')[3]))

        n_edge = len(servers) or 4
        nodes: List[Dict[str, Any]] = [
            {'id': 's0', 'kind': 'core_switch', 'dpid': 1, 'label': 's0 (core)'}
        ]
        links: List[Dict[str, Any]] = []
        for i in range(1, n_edge + 1):
            nodes.append({'id': f's{i}', 'kind': 'edge_switch', 'dpid': i + 1, 'label': f's{i}'})
            nodes.append({'id': f'srv{i}', 'kind': 'server', 'label': f'srv{i}',
                          'ip': f'10.0.1.{i}', 'attack': 'none'})
            links.append({'a': f's{i}', 'b': f'srv{i}', 'kind': 'server_link'})
            links.append({'a': 's0', 'b': f's{i}', 'kind': 'core_link'})
        for j in sorted(iots) or range(1, 13):
            nodes.append({'id': f'iot{j}', 'kind': 'iot', 'label': f'iot{j}',
                          'ip': f'10.0.0.{j}'})
            links.append({'a': f'iot{j}', 'b': f's{(j - 1) % n_edge + 1}', 'kind': 'iot_link'})

        return {
            'nodes': nodes, 'links': links, 'vip': '10.0.99.1:9000',
            'weights': {'w1_trust': 0.5, 'w2_cpu': 0.3, 'w3_latency': 0.2},
            'thresholds': {'isolation': 0.3, 'anomaly_gate': 0.5},
        }

    def run(self) -> None:
        """Re-emit the recording, preserving its original pacing."""
        if not self.events:
            logger.warning("Nothing to replay")
            return

        t0 = self.events[0]['ts']
        started = time.monotonic()

        for ev in self.events:
            # Sleep until this event's own offset into the original run.
            target = (ev['ts'] - t0) / self.speed
            drift = target - (time.monotonic() - started)
            if drift > 0:
                time.sleep(drift)

            if ev.get('type') == 'flow_stats':
                with self._lock:
                    self._flows = [
                        f for f in self._flows if f['dpid'] != ev['dpid']
                    ] + ev['rules']
            elif ev.get('type') == 'port_stats':
                with self._lock:
                    for entry in ev.get('ports') or []:
                        self._ports[(entry['dpid'], entry['port'])] = entry
            elif ev.get('type') == 'flow_delete':
                with self._lock:
                    self._flows = [f for f in self._flows if f.get('node') != ev['node']]

            # Strip seq: the bus assigns a fresh one, so a dashboard that
            # reconnects mid-replay still sees a monotonic sequence.
            payload = {k: v for k, v in ev.items() if k not in ('type', 'seq', 'ts')}
            self.bus.publish(ev['type'], **payload)

        logger.info("Replay finished (%d events)", len(self.events))


def load_events(path: Path) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                # A run killed with Ctrl-C mid-write can leave a torn final
                # line. Skip it rather than refusing to replay the whole file.
                logger.warning("Skipping malformed line %d in %s", lineno, path)
    events.sort(key=lambda e: e.get('ts', 0))
    return events


def main(argv: Optional[List[str]] = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
    )
    parser = argparse.ArgumentParser(description='Replay a recorded run into the dashboard')
    parser.add_argument('events', nargs='?', default='data/events.jsonl',
                        help='recorded events.jsonl (default: data/events.jsonl)')
    parser.add_argument('--port', type=int, default=8082,
                        help='port to serve the dashboard on (default: 8082, so it '
                             'does not collide with a live controller on 8081)')
    parser.add_argument('--speed', type=float, default=1.0,
                        help='playback speed multiplier (default: 1.0 = real time)')
    parser.add_argument('--loop', action='store_true',
                        help='restart the replay when it ends')
    args = parser.parse_args(argv)

    path = Path(args.events)
    if not path.exists():
        print(f"No recording at {path}.\n"
              f"Run the live demo once with controller.dashboard.enabled: true "
              f"in config/params_trust_demo.yaml to produce one.", file=sys.stderr)
        return 1

    events = load_events(path)
    if not events:
        print(f"{path} contains no events.", file=sys.stderr)
        return 1

    app = ReplayApp(events, speed=args.speed)
    span = events[-1]['ts'] - events[0]['ts']
    logger.info(
        "Replaying %d events spanning %.1fs at %.1fx -- open http://localhost:%d/",
        len(events), span, args.speed, args.port,
    )

    def drive():
        while True:
            app.run()
            if not args.loop:
                return
            logger.info("Looping replay")

    threading.Thread(target=drive, daemon=True).start()

    # TrustState is only constructed because NorthboundAPI's signature wants
    # one; replay never touches the trust/auth/ledger endpoints.
    server = NorthboundAPI(
        app=app, state=TrustState(node_ids=[]), host='0.0.0.0', port=args.port,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Stopped")
    return 0


if __name__ == '__main__':
    sys.exit(main())
