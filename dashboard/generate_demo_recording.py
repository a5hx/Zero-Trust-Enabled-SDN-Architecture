"""Generate a dashboard recording (events.jsonl) from the real trust engine.

    python3 -m dashboard.generate_demo_recording --out data/events.jsonl

Why this exists
---------------
The live recording is produced by running the full Mininet + node_agent demo
under root. When that demo is run with the edge agents *not* answering
GET /status (as happened for data/events.jsonl before this script), the
controller correctly quarantines every node ("unreachable == anomalous") and
the recording contains no routing at all -- nothing to visualise.

This script produces a recording of the *intended* story without needing root
or Mininet, by driving the SAME components the live controller uses:

  * controller.trust_state.TrustState   -- real trust/quarantine state
  * trust_engine.trust_calculator       -- the real T = aR + bB + gH - dA
  * controller.edge_selector            -- the real EdgeScore argmax routing
  * controller.flow_monitor.FlowMonitor -- the real 1 Hz anomaly-detection loop

Only two things are simulated, and both are exactly what "standalone mode"
(run_demo.py --mode standalone, validated in Phase B) already abstracts away:
the network I/O, and the edge agents' self-reported /status telemetry. Every
trust score, EdgeScore, anomaly EMA value and quarantine decision in the output
is computed by the production code, not scripted.

The scenario mirrors config/params_trust_demo.yaml: 4 edge servers, 12 IoT
devices, srv3 running a Sybil attack (under-reporting its CPU load to attract
traffic) starting partway through the run. srv3 keeps *completing* tasks
successfully, so its trust never falls below the isolation threshold -- it is
caught solely by the CPU-honesty anomaly gate, which is the whole point of
design finding #1 (see contracts/thresholds.py). Watch it get flooded with
traffic, tripped by the gate, quarantined, and its traffic re-steered.
"""

import argparse
import json
import random
import time
from typing import Any, Dict, List, Optional, Tuple

from contracts.trust_update import TrustUpdate
from controller.edge_selector import EdgeWeights
from controller.flow_monitor import FlowMonitor, StatusProbe
from controller.trust_state import TrustState
from trust_engine.ai_optimizer import UCB1WeightOptimizer
from trust_engine.trust_calculator import TrustCalculator

# --- scenario constants (mirror config/params_trust_demo.yaml) -------------
NUM_EDGE = 4
NUM_IOT = 12
SYBIL_NODE = 'srv3'
SYBIL_START_S = 12.0          # compressed from the config's 20s for a tighter loop
DURATION_S = 28.0
POLL_S = 1.0                  # flow_monitor cadence
MICRO_S = 0.25               # routing granularity between polls
HONESTY_THRESHOLD = 0.4      # |claimed_cpu - observed_load| gate (config: ">40%")
VIP = '10.0.99.1'
VIP_PORT = 9000

# Honest baseline CPU each server self-reports (spreads routing so it isn't all
# one node). Kept <= 0.35 so |claimed - observed| never trips the gate while a
# node completes tasks promptly. srv3's honest baseline is used before it lies.
HONEST_CPU = {'srv1': 0.15, 'srv2': 0.30, 'srv3': 0.20, 'srv4': 0.25}
VIP_COOKIE = {f'srv{i}': 0x5100_0000_0000_0000 | i for i in range(1, NUM_EDGE + 1)}
DROP_COOKIE = {f'srv{i}': 0x5A00_0000_0000_0000 | i for i in range(1, NUM_EDGE + 1)}
SRV_MAC = {f'srv{i}': f'00:00:00:00:01:0{i}' for i in range(1, NUM_EDGE + 1)}

# The AI weight optimizer (online UCB1 bandit) tuning the EdgeScore weights live,
# mirroring config/params_trust_demo.yaml. window_s=0 in the sim so one window
# closes per virtual-second poll (the sim uses a virtual Clock, not wall time).
OPTIMIZER_ARMS = [
    EdgeWeights(0.50, 0.30, 0.20),   # balanced (baseline)
    EdgeWeights(0.70, 0.20, 0.10),   # trust-heavy
    EdgeWeights(0.34, 0.50, 0.16),   # load-heavy
    EdgeWeights(0.34, 0.16, 0.50),   # latency-heavy
    EdgeWeights(0.45, 0.45, 0.10),   # trust + load
]


class RecordingBus:
    """Duck-typed EventBus: records every publish() as one JSONL event.

    The controller components only call bus.publish(type, **fields); that is the
    entire surface they use, so recording is just appending a dict.
    """

    def __init__(self, clock: 'Clock') -> None:
        self.clock = clock
        self.events: List[Dict[str, Any]] = []

    def publish(self, event_type: str, **fields: Any) -> None:
        self.events.append({'type': event_type, 'ts': self.clock.now(), **fields})


class Clock:
    def __init__(self) -> None:
        self.base = time.time()
        self.t = 0.0

    def now(self) -> float:
        return self.base + self.t


class ScriptedMonitor(FlowMonitor):
    """Real FlowMonitor with the HTTP /status poll replaced by scripted
    telemetry. Everything else -- the honesty-deviation check, the anomaly EMA,
    the quarantine edge-trigger, and every event it publishes -- is the
    production code path, unchanged."""

    def __init__(self, sim: 'Sim', **kw: Any) -> None:
        super().__init__(**kw)
        self.sim = sim

    def _fetch_status(self, node_id: str) -> StatusProbe:
        # Wrap the scripted telemetry the way the real HTTP fetch does: the node's
        # self-reported latency stands in for the controller-measured RTT here.
        status = self.sim.status_for(node_id)
        return StatusProbe(status, status['latency_ms'])


class Sim:
    def __init__(self) -> None:
        self.clock = Clock()
        self.bus = RecordingBus(self.clock)
        self.node_ids = [f'srv{i}' for i in range(1, NUM_EDGE + 1)]

        self.state = TrustState(
            node_ids=self.node_ids,
            # observed_load integrates occupancy over time; feed it the same
            # simulated clock everything else here runs on, not wall time.
            time_source=lambda: self.clock.t,
            trust_calculator=TrustCalculator(
                alpha=0.35, beta=0.25, gamma=0.25, delta=0.15,
                lambda_decay=0.85, initial_score=0.5,
            ),
            edge_weights=EdgeWeights(w1_trust=0.50, w2_cpu=0.30, w3_latency=0.20),
            optimizer=UCB1WeightOptimizer(OPTIMIZER_ARMS, exploration_c=1.41),
            optimizer_window_s=0.0,   # one window per poll under the virtual clock
            isolation_threshold=0.3,
            anomaly_gate=0.5,
        )
        self.monitor = ScriptedMonitor(
            self, state=self.state, node_ids=self.node_ids, agent_port=8090,
            poll_interval_s=POLL_S, honesty_deviation_threshold=HONESTY_THRESHOLD,
            on_quarantine=self._on_quarantine, bus=self.bus,
        )

        # Dispatches awaiting completion: (ip, port) -> (node, due_t).
        self._pending: Dict[Tuple[str, int], Tuple[str, float]] = {}
        self._client_port = 40000
        # For flow_stats: cumulative packet counts per dpid, recent routes.
        self._pkts: Dict[int, int] = {}
        # Cumulative packets DROPPED at each quarantined node's drop rule -- the
        # clients that keep trying to reach it and are dropped in the data plane.
        self._dropped: Dict[str, int] = {}
        self._recent_routes: List[Tuple[float, str, str]] = []  # (t, node, iot)
        self._quarantined: set = set()
        self._first_sybil_q_t: Optional[float] = None

    # -- telemetry the scripted monitor serves -----------------------------
    def status_for(self, node_id: str) -> Dict[str, Any]:
        if node_id == SYBIL_NODE and self.clock.t >= SYBIL_START_S:
            # The lie: reports a fixed near-idle CPU regardless of real load, to
            # win the EdgeScore argmax and attract traffic. Because it ignores
            # its actual load, |claimed - observed| grows as it fills up.
            claimed = 0.05
        else:
            # An honest agent reports its ACTUAL CPU, which tracks the load the
            # controller itself observes. This is the negative feedback that
            # balances routing (a busy node reports high CPU and stops winning)
            # and keeps |claimed - observed| small, so honest nodes never trip.
            observed = self.state.observed_load(node_id)
            claimed = max(0.0, min(1.0, observed + HONEST_CPU[node_id] * 0.4 + random.uniform(-0.03, 0.03)))
        latency = random.uniform(8, 45)
        return {'cpu_load': round(claimed, 3), 'latency_ms': round(latency, 1), 'concurrency': 4}

    # -- quarantine callback (mirrors trust_balancer._on_trust_collapse) ----
    def _on_quarantine(self, node_id: str) -> None:
        if node_id == SYBIL_NODE and self._first_sybil_q_t is None:
            self._first_sybil_q_t = self.clock.t
        self._quarantined.add(node_id)
        t = self.state.trust_calc.get_score(node_id)
        a = self.state.get_anomaly(node_id)
        self.bus.publish(
            'quarantine', node=node_id, trust=round(t, 4), anomaly=round(a, 4),
            isolation_threshold=self.state.isolation_threshold,
            anomaly_gate=self.state.anomaly_gate,
        )
        # The switch(es) srv{i} hangs off: edge switch s{i} has dpid i+1.
        idx = int(node_id.replace('srv', ''))
        self.bus.publish(
            'flow_delete', node=node_id, cookie=VIP_COOKIE[node_id], dpids=[idx + 1],
        )

    # -- routing (mirrors trust_balancer's PacketIn dispatch path) ----------
    def _route_one(self) -> None:
        chosen = self.state.choose_edge_node()
        j = random.randint(1, NUM_IOT)
        client_ip = f'10.0.0.{j}'
        self._client_port += 1
        port = self._client_port
        if chosen is None:
            self.bus.publish('route_denied', client_ip=client_ip, client_port=port,
                             reason='all candidates quarantined')
            return
        self.state.register_dispatch(client_ip, port, chosen)
        last = self.state.last_routing_decision() or {}
        self.bus.publish(
            'route', client_ip=client_ip, client_port=port, chosen=chosen,
            edge_score=round(last.get('score', 0.0), 4), ranked=last.get('ranked'),
            decision_ms=round(random.uniform(0.4, 2.5), 2), dpid=int(chosen.replace('srv', '')) + 1,
        )
        self._recent_routes.append((self.clock.t, chosen, f'iot{j}'))
        # Honest nodes finish fast; the Sybil node (actually overloaded) holds
        # tasks longer, so its inflight -> observed_load climbs and the lie shows.
        if chosen == SYBIL_NODE and self.clock.t >= SYBIL_START_S:
            service = random.uniform(1.8, 3.2)
        else:
            service = random.uniform(0.3, 0.7)
        self._pending[(client_ip, port)] = (chosen, self.clock.t + service)

    def _complete_due(self) -> None:
        due = [k for k, (node, due_t) in self._pending.items()
               if due_t <= self.clock.t and node not in self._quarantined]
        # A quarantined (overloaded) node keeps its backlog of unfinished tasks
        # in-flight -- observed_load stays high, so it isn't spuriously re-admitted.
        for key in due:
            node, _ = self._pending.pop(key)
            resolved = self.state.complete_dispatch(*key)
            if resolved is None:
                continue
            # Sybil node still SERVES successfully -- trust stays high; only the
            # anomaly gate catches it. That is design finding #1, live.
            status = 'success' if random.random() < 0.92 else 'timeout'
            claimed = self.state.get_claimed_cpu(node)
            observed = self.state.observed_load(node)
            self.state.record_task_outcome(TrustUpdate(
                device_id=key[0], edge_node_id=node, task_status=status,
                cpu_usage=observed, reported_cpu=claimed,
                latency_ms=random.uniform(8, 45),
            ))

    def _emit_flow_stats(self) -> None:
        window = [n for (rt, n, _iot) in self._recent_routes if self.clock.t - rt <= 1.0]
        recent_client = {}
        for (_rt, n, iot) in self._recent_routes[-40:]:
            recent_client[n] = iot
        for i in range(1, NUM_EDGE + 1):
            dpid = i + 1
            node = f'srv{i}'
            pps = float(window.count(node))
            self._pkts[dpid] = self._pkts.get(dpid, 0) + int(pps)
            rules: List[Dict[str, Any]] = [{
                'dpid': dpid, 'table': 0, 'priority': 350, 'cookie': 0, 'node': None,
                'match': f'arp_tpa={VIP},eth_type=2054', 'actions': 'output:CONTROLLER',
                'packets': self._pkts[dpid], 'bytes': self._pkts[dpid] * 64,
                'pps': 0.0, 'bps': 0.0, 'is_vip': False,
            }]
            if node not in self._quarantined and pps > 0:
                iot = recent_client.get(node, 'iot1')
                jn = int(iot.replace('iot', ''))
                s_ip = f'10.0.1.{i}'
                rules.append({
                    'dpid': dpid, 'table': 0, 'priority': 400, 'cookie': VIP_COOKIE[node],
                    'node': node,
                    'match': f'ipv4_src=10.0.0.{jn},tcp_src={self._client_port},'
                             f'ipv4_dst={VIP},tcp_dst={VIP_PORT}',
                    'actions': f'set_field:{s_ip}->ipv4_dst,goto_table:1',
                    'packets': self._pkts[dpid] * 8, 'bytes': self._pkts[dpid] * 512,
                    'pps': round(pps, 2), 'bps': round(pps * 4096, 2), 'is_vip': True,
                })
            if node in self._quarantined:
                # A quarantined node's VIP rules are gone; the Week-1 drop rules
                # take over, dropping the packets of clients that keep trying to
                # reach it. Its dropped-packet counter climbs while it stays out.
                self._dropped[node] = self._dropped.get(node, 0) + random.randint(3, 9)
                rules.append({
                    'dpid': dpid, 'table': 0, 'priority': 400, 'cookie': DROP_COOKIE[node],
                    'node': node,
                    'match': f'eth_src={SRV_MAC[node]}',
                    'actions': 'drop',
                    'packets': self._dropped[node], 'bytes': self._dropped[node] * 64,
                    'pps': 0.0, 'bps': 0.0, 'is_vip': False,
                })
            self.bus.publish('flow_stats', dpid=dpid, rules=rules)

    def _topology(self) -> Dict[str, Any]:
        nodes: List[Dict[str, Any]] = [
            {'id': 's0', 'kind': 'core_switch', 'dpid': 1, 'label': 's0 (core)'}]
        links: List[Dict[str, Any]] = []
        for i in range(1, NUM_EDGE + 1):
            nodes.append({'id': f's{i}', 'kind': 'edge_switch', 'dpid': i + 1, 'label': f's{i}'})
            nodes.append({'id': f'srv{i}', 'kind': 'server', 'ip': f'10.0.1.{i}',
                          'label': f'srv{i}', 'attack': 'sybil' if f'srv{i}' == SYBIL_NODE else 'none'})
            links.append({'a': f's{i}', 'b': f'srv{i}', 'kind': 'server_link'})
            links.append({'a': 's0', 'b': f's{i}', 'kind': 'core_link'})
        for j in range(1, NUM_IOT + 1):
            sw = (j - 1) % NUM_EDGE + 1
            nodes.append({'id': f'iot{j}', 'kind': 'iot', 'ip': f'10.0.0.{j}', 'label': f'iot{j}'})
            links.append({'a': f'iot{j}', 'b': f's{sw}', 'kind': 'iot_link'})
        return {
            'nodes': nodes, 'links': links, 'vip': f'{VIP}:{VIP_PORT}',
            'weights': {'w1_trust': 0.50, 'w2_cpu': 0.30, 'w3_latency': 0.20},
            'thresholds': {'isolation': 0.3, 'anomaly_gate': 0.5},
        }

    def run(self) -> List[Dict[str, Any]]:
        self.bus.publish('topology', graph=self._topology())
        for dpid in range(1, NUM_EDGE + 2):
            self.clock.t += 0.05
            self.bus.publish('switch_up', dpid=dpid)

        last_poll = -1.0
        while self.clock.t <= DURATION_S:
            # ~4 connections/s -- enough to keep the busiest honest node near
            # observed_load 0.25 (well under the 0.4 gate), while the Sybil node,
            # which lies low CPU to win most routes and then serves slowly,
            # saturates and is caught.
            self._route_one()
            self._complete_due()
            if int(self.clock.t) > last_poll:
                self.monitor._poll_once()       # real detection + anomaly + node_status + quarantine
                self._emit_flow_stats()
                last_poll = int(self.clock.t)
            # End a few seconds after the Sybil node is caught, so the loop shows
            # a clean build-up -> flood -> catch -> re-steer arc.
            if self._first_sybil_q_t is not None and self.clock.t - self._first_sybil_q_t >= 5.0:
                break
            self.clock.t += MICRO_S
        return self.bus.events


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', default='data/events.jsonl')
    parser.add_argument('--seed', type=int, default=7)
    args = parser.parse_args(argv)

    random.seed(args.seed)
    events = Sim().run()
    with open(args.out, 'w') as f:
        for ev in events:
            f.write(json.dumps(ev) + '\n')

    kinds: Dict[str, int] = {}
    for ev in events:
        kinds[ev['type']] = kinds.get(ev['type'], 0) + 1
    span = events[-1]['ts'] - events[0]['ts']
    print(f'Wrote {len(events)} events spanning {span:.1f}s to {args.out}')
    for k in sorted(kinds, key=lambda k: -kinds[k]):
        print(f'  {kinds[k]:4d}  {k}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
