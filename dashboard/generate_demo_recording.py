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
MICRO_S = 0.25
#: Tasks a node serves in parallel. Matches config's agents concurrency and
#: the value TrustState is told via set_concurrency().
CONCURRENCY = 4               # routing granularity between polls
HONESTY_THRESHOLD = 0.4      # |claimed_cpu - observed_load| gate (config: ">40%")
VIP = '10.0.99.1'
VIP_PORT = 9000

# Honest baseline CPU each server self-reports (spreads routing so it isn't all
# one node). Kept <= 0.35 so |claimed - observed| never trips the gate while a
# node completes tasks promptly. srv3's honest baseline is used before it lies.
#: Baseline per-node service speed, so the four honest nodes are not
#: interchangeable. Scales how long each holds a task, which the controller
#: then sees through observed_load and RTT -- never injected into the node's
#: self-report, which must come from its own activity (see status_for).
HONEST_SPEED = {'srv1': 0.85, 'srv2': 1.25, 'srv3': 1.0, 'srv4': 1.1}
# ONE cookie per node, 0x5A base, covering that node's serving AND drop rules --
# exactly TrustBalancerApp._cookie_for(). The single shared cookie is the whole
# mechanism behind quarantine deleting every rule for a node with one
# cookie-matched OFPFC_DELETE, and 0x5A is what flow_stats._is_vip_cookie()
# tests for. The two used to be different bases (0x51 serving / 0x5A drop),
# which no real run ever produces.
VIP_COOKIE = {f'srv{i}': 0x5A00_0000_0000_0000 | i for i in range(1, NUM_EDGE + 1)}
DROP_COOKIE = VIP_COOKIE
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


# The link parameters simulation/topology.py applies, so the recording carries
# the same shape a live run reports over POST /topology/links. The per-IoT
# delay is randomised there (an unseeded randint(1, 10)); here it is drawn from
# the seeded RNG so the recording stays reproducible, and it VARIES per device
# -- a uniform column would hide the one place this metric has any spread.
LINK_PARAMS = {
    'server_link': lambda lk: {'delay_ms': 2.0, 'bw_mbps': 100.0},
    'core_link': lambda lk: {'delay_ms': 5.0, 'bw_mbps': 1000.0},
    'iot_link': lambda lk: {
        'delay_ms': float(1 + (int(lk['a'].replace('iot', '')) * 7) % 10),
        'bw_mbps': 10.0,
    },
}


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
            # Match config/params_trust_demo.yaml: power-of-two-choices + ε so the
            # replayed fallback demo shows the same load spreading (and the same
            # Load-balancing panel) as the live run, not the old argmax starvation.
            # Seeded off the module `random` (main() calls random.seed) so the
            # recording stays reproducible. See docs/LOAD_BALANCING_STARVATION.md.
            selection_strategy='p2c',
            d_choices=2,
            epsilon=0.05,
            selection_rng=random,
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
        self._busy_s: Dict[str, float] = {}
        self._first_sybil_q_t: Optional[float] = None

    # -- telemetry the scripted monitor serves -----------------------------
    def _active_tasks(self, node_id: str) -> int:
        return sum(1 for node, _due in self._pending.values() if node == node_id)

    def _accrue_busy(self, dt: float) -> None:
        """Integrate each node's real busy time, the way node_agent.py's
        _busy_seconds_total does -- cumulative, monotonic, in seconds.

        Measured from this Sim's own pending work, NOT from
        TrustState._inflight_area. The controller compares a node's self-report
        against its own occupancy estimate; sourcing the self-report from the
        controller's estimate would make the honesty check pass by
        construction, which is a self-flattering measurement rather than a
        simulated one.
        """
        active: Dict[str, int] = {}
        for node, _due in self._pending.values():
            active[node] = active.get(node, 0) + 1
        for node, n in active.items():
            self._busy_s[node] = self._busy_s.get(node, 0.0) + dt * min(n, CONCURRENCY)

    def status_for(self, node_id: str) -> Dict[str, Any]:
        if node_id == SYBIL_NODE and self.clock.t >= SYBIL_START_S:
            # The lie: reports a fixed near-idle CPU regardless of real load, to
            # win the EdgeScore argmax and attract traffic. Because it ignores
            # its actual load, |claimed - observed| grows as it fills up.
            claimed = 0.05
            # The lie is SELF-CONSISTENT: busy_seconds is derived from the
            # claimed CPU rather than reported truthfully, exactly as
            # node_agent.py does when its attack is armed
            # (busy_seconds = uptime * cpu_load * concurrency). A liar that
            # reported a truthful duty cycle alongside a false CPU would be
            # caught by an arithmetic check no real attacker would fail.
            busy_s = self.clock.t * claimed * CONCURRENCY
            # ...and it is caught anyway, by the OTHER signal. Its CPU is
            # genuinely burning, so it answers the controller's poll slowly
            # "no matter how little task traffic it receives"
            # (flow_monitor.evaluate_latency_tell) -- which is why this is
            # independent of occupancy below. That is this project's headline
            # finding running in the recording: the anomaly gate catches what
            # the trust score and the honesty check provably cannot.
            return {
                'cpu_load': round(claimed, 3),
                'latency_ms': round(random.uniform(95.0, 145.0), 1),
                'concurrency': CONCURRENCY,
                'busy_seconds': round(busy_s, 6),
            }
        else:
            # An honest agent reports its ACTUAL CPU, computed exactly as
            # node_agent.py does: min(1.0, active_tasks / concurrency).
            #
            # It matters that this and busy_seconds below come from the SAME
            # activity, because that is what makes an honest node honest: the
            # controller's H term compares the claim against a duty cycle
            # derived from busy_seconds, so a claim synthesised from anything
            # else disagrees with it and the node is quarantined for telling
            # the truth about a different quantity. A synthetic claim here
            # (observed_load plus a per-node offset) did exactly that -- srv4
            # quarantined at t=8.05 on |claimed 0.04 - expected duty 0.50|
            # while behaving perfectly.
            active = self._active_tasks(node_id)
            claimed = min(1.0, active / CONCURRENCY)
            busy_s = self._busy_s.get(node_id, 0.0)

        # The controller-measured RTT, which tracks the node's REAL occupancy
        # regardless of what it claims. This is the load-independent Sybil tell
        # (flow_monitor.evaluate_latency_tell): a node claiming to be idle
        # should answer its poll about as fast as the rest of the fleet, and
        # one that is actually saturated cannot -- the RTT is the controller's
        # own measurement, so the node cannot understate it.
        #
        # Previously every node, liar included, drew an unconditional
        # random.uniform(8, 45), so the tell could never fire and the Sybil was
        # caught only by the honesty check's fallback path. Once the fallback
        # was removed (busy_seconds above) that left it uncaught entirely --
        # a self-consistent liar defeats the duty-cycle comparison, which is
        # exactly why this project has a second, independent signal.
        # An honest node's RTT stays near the fleet baseline: it answers
        # promptly and only slows in proportion to work it is actually doing.
        # Keeping the spread tight matters -- the tell fires on a multiple of
        # the fleet MEDIAN, so noisy honest nodes would raise the bar the liar
        # has to clear and mask it.
        occupancy = min(1.0, self._active_tasks(node_id) / CONCURRENCY)
        latency = random.uniform(8.0, 16.0) * (1.0 + 0.8 * occupancy)
        return {
            'cpu_load': round(claimed, 3), 'latency_ms': round(latency, 1),
            'concurrency': CONCURRENCY,
            # Cumulative in-handler seconds. Every real node_agent sends this
            # (node_agent.py's /status), and the controller needs it to run
            # TrustState.expected_duty_cycle() -- the service-time estimator
            # the H term prefers. Without it the controller silently falls back
            # to comparing the claim against observed_load, which is residence
            # time rather than service time: a node that inherits a re-steered
            # backlog then shows a large |claimed - observed| purely because
            # the work was moved onto it, and gets quarantined for someone
            # else's load. That fallback is the documented cause of this
            # project's false quarantines (memory/live-run-7-honesty-fallback),
            # and omitting the field here drove the recording down it on every
            # poll -- a fourth defect of the same shape as panel_fix.md 6.3's
            # three: a plausible-looking wrong result, never an error.
            'busy_seconds': round(busy_s, 6),
        }

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
        self._redispatch_after_quarantine(node_id)

    # -- re-steer (mirrors trust_balancer._redispatch_after_quarantine) -----
    def _redispatch_after_quarantine(self, node_id: str) -> None:
        """Move the quarantined node's in-flight clients to the next-best
        eligible node and publish one 'reroute' per moved client.

        Uses the REAL TrustState.reassign_dispatches(), same as the controller,
        so the dispatch registry stays consistent with what the trust rail sees
        -- this generator's whole contract is that only I/O is scripted. Without
        it the recording had no 'reroute' events at all, and the routing
        reliability chart's "decisions that held" series read a flat 100% on a
        run where a node was quarantined mid-flight. That is exactly the shape
        of the three fidelity defects in panel_fix.md 6.3: a plausible-looking
        wrong chart rather than an error.

        All moved clients go to a single re-selected target, and no eligible
        target means their retry is denied -- both faithful to the controller.
        """
        target = self.state.choose_edge_node()
        if target is None:
            return
        moved = self.state.reassign_dispatches(node_id, target)
        if not moved:
            return
        for client_ip, client_port in moved:
            # Keep this Sim's own pending map in step with the registry, or the
            # moved tasks would never complete and observed_load on the target
            # would climb off a backlog that has no work behind it.
            key = (client_ip, client_port)
            if key in self._pending:
                _old, due_t = self._pending[key]
                self._pending[key] = (target, due_t)
            self.bus.publish(
                'reroute', client_ip=client_ip, client_port=client_port,
                from_node=node_id, to_node=target,
                resteer_ms=round(random.uniform(8.0, 20.0), 2),
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
            service = random.uniform(0.3, 0.7) * HONEST_SPEED.get(chosen, 1.0)
        self._pending[(client_ip, port)] = (chosen, self.clock.t + service)

    def _complete_due(self) -> None:
        due = [k for k, (node, due_t) in self._pending.items()
               if due_t <= self.clock.t and node not in self._quarantined]
        # A quarantined (overloaded) node keeps its backlog of unfinished tasks
        # in-flight -- observed_load stays high, so it isn't spuriously re-admitted.
        for key in due:
            self._pending.pop(key)
            resolved = self.state.complete_dispatch(*key)
            if resolved is None:
                continue
            # The registry is the authority on which node owns this flow, not
            # this Sim's own pending map -- a re-steer moves the former and the
            # latter only follows.
            node = resolved.node_id
            # Never charge a node for a task it inherited from a re-steer.
            # Quarantine's drop rules kill the in-flight connection, so a
            # re-steered entry can only collect the corpse of a task the
            # receiving node never saw; charging it is the defect
            # CompletedDispatch.chargeable exists to prevent (panel_fix.md
            # 6.9 / memory resteer-attribution), and it is self-amplifying --
            # the inherited load re-trips the honesty check on each survivor
            # the load is moved to, cascading the quarantine across the fleet.
            if not resolved.chargeable:
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
                    # PRIO_CONNECTION, the priority TrustBalancerApp actually
                    # installs a per-connection VIP rewrite at
                    # (_install_vip_pair). This used to say 400, which is
                    # PRIO_QUARANTINE_DROP -- so this SERVING rule advertised
                    # itself at the drop priority. Anything that tells serving
                    # traffic from dropped traffic by priority (the dashboard's
                    # throughput chart, evaluation/interval_report.py) then read
                    # it exactly backwards: its bps was discarded, so throughput
                    # was a flat zero, and its packet counter was tallied as
                    # quarantine drops.
                    'dpid': dpid, 'table': 0, 'priority': 300,
                    'cookie': VIP_COOKIE[node],
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
                    # is_vip TRUE: a quarantine drop rule carries the node's own
                    # 0x5A cookie, so flow_stats._is_vip_cookie() marks it VIP in
                    # a real run. It said False here, and since every consumer
                    # filters on is_vip first, the OpenFlow-drop series was
                    # unreachable -- flat zero even while a node sat quarantined.
                    'pps': 0.0, 'bps': 0.0, 'is_vip': True,
                })
            self.bus.publish('flow_stats', dpid=dpid, rules=rules)

    def _topology(self, with_link_params: bool = False) -> Dict[str, Any]:
        nodes: List[Dict[str, Any]] = [
            {'id': 's0', 'kind': 'core_switch', 'dpid': 1, 'label': 's0 (core)'}]
        links: List[Dict[str, Any]] = []
        for i in range(1, NUM_EDGE + 1):
            nodes.append({'id': f's{i}', 'kind': 'edge_switch', 'dpid': i + 1, 'label': f's{i}'})
            is_sybil = f'srv{i}' == SYBIL_NODE
            nodes.append({
                'id': f'srv{i}', 'kind': 'server', 'ip': f'10.0.1.{i}',
                'label': f'srv{i}',
                'attack': 'sybil' if is_sybil else 'none',
                # Ground-truth onset, matching what the live controller's
                # topology_graph() emits (plan_adv.md Phase 2). Without it
                # evaluation/attack_report.py can say the attack was classified
                # correctly but not how long that took, and the dashboard has
                # no onset to shade the metric charts from.
                'attack_start_s': SYBIL_START_S if is_sybil else 0.0,
            })
            links.append({'a': f's{i}', 'b': f'srv{i}', 'kind': 'server_link'})
            links.append({'a': 's0', 'b': f's{i}', 'kind': 'core_link'})
        for j in range(1, NUM_IOT + 1):
            sw = (j - 1) % NUM_EDGE + 1
            nodes.append({'id': f'iot{j}', 'kind': 'iot', 'ip': f'10.0.0.{j}', 'label': f'iot{j}'})
            links.append({'a': f'iot{j}', 'b': f's{sw}', 'kind': 'iot_link'})
        if with_link_params:
            for lk in links:
                lk.update(LINK_PARAMS[lk['kind']](lk))
        return {
            'nodes': nodes, 'links': links, 'vip': f'{VIP}:{VIP_PORT}',
            'weights': {'w1_trust': 0.50, 'w2_cpu': 0.30, 'w3_latency': 0.20},
            'thresholds': {'isolation': 0.3, 'anomaly_gate': 0.5},
            'selection': {'strategy': 'p2c', 'd_choices': 2, 'epsilon': 0.05},
        }

    def run(self) -> List[Dict[str, Any]]:
        # 'topology' first and WITHOUT link parameters, exactly as a live run
        # emits it: the controller publishes it from config in start(), before
        # Mininet exists, so it cannot know what the harness will build.
        self.bus.publish('topology', graph=self._topology())
        for dpid in range(1, NUM_EDGE + 2):
            self.clock.t += 0.05
            self.bus.publish('switch_up', dpid=dpid)
        # Then the harness reporting what it actually wired up
        # (simulation/topology.py -> POST /topology/links ->
        # trust_balancer.record_link_params). Arrives after the switches come
        # up in a live run, for the same reason.
        self.clock.t += 0.05
        self.bus.publish('topology_links', graph=self._topology(with_link_params=True))

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
            self._accrue_busy(MICRO_S)
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
