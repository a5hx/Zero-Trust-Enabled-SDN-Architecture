"""Predict, before any live run, what a load liar whose lie WORKS gains, and
whether the anomaly gate catches it. Novelty plan Phase 1b.

Why this exists
---------------
The shipped load-misreporting attacker (node_agent --malicious sybil) never
tested the gate against a working lie. At the shipped ~1% occupancy an honest
server truthfully reports cpu_load ~ 0, so the sybil's fixed 0.1 is a WORSE
claim than the truth, and it burns CPU, so it is slow. Re-scoring the 15-run
ablation: its post-onset route share was 1.98% under the score alone against a
fair 12.5% (evaluation/replicates.py, `route_share`). The gate caught a slow
server. The liar modelled here claims less than the honest servers and serves
at honest speed (node_agent --malicious liar / stealthy, --work-mode hold).

Same pattern as evaluation/scalability_sweep.py: a discrete-event harness
driving the project's REAL selector (controller.edge_selector.select_edge_node)
and the REAL trust arithmetic (trust_engine.trust_calculator.TrustCalculator),
so the prediction is a property of the shipping code. What is modelled rather
than run is the controller's honesty check, re-implemented from
controller/flow_monitor.py and controller/trust_state.py (claimed duty from
the busy-seconds counter over load_window_s, expected duty = completion rate x
fleet-median implied service time / concurrency, fire when the gap exceeds
honesty_deviation_threshold), and Ā's EMA from TrustState.set_anomaly_raw.

Deliberately NOT modelled, and why it does not matter for these attackers:
* the latency tell -- it needs a server that claims idle AND answers /status
  slowly. These liars burn no CPU and /status is never queued behind tasks
  (worker slots gate /task only), so it cannot fire. That is the point.
Modelled from TrustState._probation_candidate_locked: a node quarantined on
the trust rail only (T < θ, Ā below the enforced gate) gets one trial task
per PROBATION_S, highest trust first. Without it a score quarantine is
absorbing -- the node never gets the task outcomes that could raise T.
* the packet-drop tell -- these attackers never drop.

The analytic ceiling (docs/LIAR_BOUND.md)
-----------------------------------------
Under power-of-d-choices with ε-exploration, an eligible node is in the
sampled pair with probability d/N and is chosen by exploration with ε/N. A
liar that wins every comparison it is sampled into therefore gets at most

    share_max = ε/N + (1 - ε) d/N         (= 24.4% at N=8, d=2, ε=0.05)

so its gain over a fair 1/N is capped near (d - 1)/N, however large the lie.
Under argmax it would be unbounded. And a consistent liar holding share s has
true duty ~ s N ρ (ρ = fleet occupancy), so the honesty check (absolute gap
> h) can only see it once s N ρ - claim > h: at share 2/N and claim 0 that is
ρ > h/2 = 0.20. Below that occupancy the gate is blind to it; a split-claim
liar (truthful busy counter) is invisible to the honesty check at every ρ.

Run:
    python3 -m evaluation.liar_sweep                     # the prediction table
    python3 -m evaluation.liar_sweep --csv liar.csv --seeds 5
"""

from __future__ import annotations

import argparse
import csv
import heapq
import random
import statistics
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Sequence, Tuple

from contracts.trust_update import TrustUpdate
from controller.edge_selector import STRATEGY_P2C, EdgeWeights, NodeState, select_edge_node
from simulation.node_agent import stealth_claim
from trust_engine.trust_calculator import TrustCalculator

# Mirrors config/params_trust_full.yaml (trust, edge_score, controller blocks).
WEIGHTS = EdgeWeights(0.50, 0.30, 0.20)
THETA = 0.30
GATE = 0.50
EPSILON = 0.05
D_CHOICES = 2
HONESTY_THRESHOLD = 0.40
ANOMALY_LAMBDA = 0.85
LOAD_WINDOW_S = 3.0          # TrustState.load_window_s
MIN_FLEET_SAMPLES = 3        # TrustState DEFAULT_MIN_FLEET_SERVICE_SAMPLES
POLL_S = 1.0
PROBATION_S = 5.0          # controller.probation_interval_s
TASK_TIMEOUT_S = 4.0
#: End-to-end task latency on top of service time, from the live runs: honest
#: mean ~91 ms with 15 ms of work (paper §VII-E).
BASE_LATENCY_S = 0.075
STATUS_RTT_MS = 30.0         # same for every node: these liars are not slow

N = 8
LIAR = 'srv3'
ARRIVAL_HZ = 20.0            # 40 devices / report_interval_s 2.0
CONCURRENCY = 2
ONSET_S = 20.0
SIM_S = 300.0

ATTACKERS = ('liar_consistent', 'liar_truthful', 'stealthy')


@dataclass
class Cell:
    occupancy: float
    attacker: str
    gate_enforced: bool
    slots: bool
    seed: int
    # outcomes
    liar_routes: int = 0
    routes_after_onset: int = 0
    first_quarantine_s: Optional[float] = None
    polls_after_onset: int = 0
    polls_quarantined: int = 0
    honest_latencies: List[float] = field(default_factory=list)
    liar_latencies: List[float] = field(default_factory=list)
    liar_min_trust: float = 1.0
    honest_min_trust: float = 1.0
    honest_polls_quarantined: int = 0
    honest_polls: int = 0

    @property
    def share(self) -> float:
        return self.liar_routes / self.routes_after_onset if self.routes_after_onset else 0.0

    @property
    def excess(self) -> float:
        return self.share - 1.0 / N

    @property
    def honest_quarantined_frac(self) -> float:
        return self.honest_polls_quarantined / self.honest_polls if self.honest_polls else 0.0

    @property
    def quarantined_frac(self) -> float:
        return self.polls_quarantined / self.polls_after_onset if self.polls_after_onset else 0.0


def share_ceiling(n: int = N, d: int = D_CHOICES, epsilon: float = EPSILON) -> float:
    """The most a liar that wins every comparison can get under p2c+ε."""
    return epsilon / n + (1 - epsilon) * min(d, n) / n


class _Node:
    def __init__(self, nid: str) -> None:
        self.nid = nid
        self.active = 0
        self.queue: Deque[Tuple[float, int]] = deque()   # (arrived, task id)
        self.busy_total = 0.0                             # real, accrued at completion
        self.busy_hist: Deque[Tuple[float, float]] = deque()
        self.success_hist: Deque[float] = deque()         # completion times (success)
        self.anomaly = 0.0
        self.claim_raw = 0.0                              # what /status said at the last poll
        self.claimed_duty = 0.0


def simulate(occupancy: float, attacker: str, gate_enforced: bool, slots: bool,
             seed: int = 1, sim_s: float = SIM_S, claim: float = 0.0,
             stealth_rho: float = 0.25, stealth_margin: float = 0.8,
             cpu_claim: str = 'raw') -> Cell:
    """One run. cpu_claim mirrors edge_score.cpu_claim: 'raw' ranks on the
    instantaneous claim, 'verified' on the busy-counter duty cycle the honesty
    check validates (TrustState._routing_claim_locked)."""
    rng = random.Random(seed)
    sel_rng = random.Random(seed + 99)
    service_s = occupancy * N * CONCURRENCY / ARRIVAL_HZ
    cell = Cell(occupancy, attacker, gate_enforced, slots, seed)
    calc = TrustCalculator()
    nodes = {f'srv{i}': _Node(f'srv{i}') for i in range(1, N + 1)}
    liar = nodes[LIAR]
    stealth_now = claim
    lie_busy = 0.0               # consistent fabricated counter (since onset)
    lie_busy_at: Optional[float] = None
    done: Dict[int, bool] = {}
    last_probe: Dict[str, float] = {}
    seq = 0
    evq: List[Tuple[float, int, str, str, int, float]] = []

    def push(t: float, kind: str, nid: str = '', task: int = -1, arrived: float = 0.0) -> None:
        nonlocal seq
        seq += 1
        heapq.heappush(evq, (t, seq, kind, nid, task, arrived))

    def lying(now: float) -> bool:
        return now >= ONSET_S

    def window_duty(node: _Node, now: float) -> Optional[float]:
        h = [(t, b) for t, b in node.busy_hist if t >= now - LOAD_WINDOW_S]
        if len(h) < 2 or h[-1][0] - h[0][0] < 0.5:
            return None
        return (h[-1][1] - h[0][1]) / ((h[-1][0] - h[0][0]) * CONCURRENCY)

    def rate(node: _Node, now: float) -> Optional[float]:
        n_ok = sum(1 for t in node.success_hist if t >= now - LOAD_WINDOW_S)
        return n_ok / LOAD_WINDOW_S if n_ok else None

    def expected_duty(node: _Node, now: float) -> Optional[float]:
        implied = []
        for other in nodes.values():
            r = rate(other, now)
            if r:
                implied.append(other.claimed_duty * CONCURRENCY / r)
        r = rate(node, now)
        if r is None or len(implied) < MIN_FLEET_SAMPLES:
            return None
        return min(1.0, r * statistics.median(implied) / CONCURRENCY)

    def start(node: _Node, task: int, arrived: float, now: float) -> None:
        node.active += 1
        push(now + service_s, 'dep', node.nid, task, arrived)

    push(rng.expovariate(ARRIVAL_HZ), 'arr')
    push(POLL_S, 'poll')
    tid = 0
    while evq:
        now, _, kind, nid, task, arrived = heapq.heappop(evq)
        if now > sim_s:
            break
        if kind == 'poll':
            nonlocal_lie = lying(now)
            if nonlocal_lie and lie_busy_at is None:
                lie_busy, lie_busy_at = liar.busy_total, now
            true = window_duty_real(liar, now) if attacker == 'stealthy' else None
            if attacker == 'stealthy' and nonlocal_lie and round(now) % 2 == 0:
                peers = [n.claim_raw for n in nodes.values() if n is not liar]
                new = stealth_claim(peers, true if true is not None else 0.0,
                                    stealth_rho, stealth_margin, HONESTY_THRESHOLD)
                lie_busy += (now - lie_busy_at) * stealth_now * CONCURRENCY
                lie_busy_at, stealth_now = now, new
            for node in nodes.values():
                is_liar = node is liar and nonlocal_lie
                if is_liar:
                    lie = stealth_now if attacker == 'stealthy' else claim
                    node.claim_raw = lie
                    if attacker == 'liar_truthful':
                        node.busy_hist.append((now, node.busy_total))
                    else:
                        node.busy_hist.append((now, lie_busy + (now - lie_busy_at) * lie * CONCURRENCY))
                else:
                    node.claim_raw = min(1.0, node.active / CONCURRENCY)
                    node.busy_hist.append((now, node.busy_total))
                while node.busy_hist and node.busy_hist[0][0] < now - 2 * LOAD_WINDOW_S:
                    node.busy_hist.popleft()
                d = window_duty(node, now)
                node.claimed_duty = d if d is not None else node.claim_raw
            for node in nodes.values():
                exp = expected_duty(node, now)
                fired = exp is not None and abs(node.claimed_duty - exp) > HONESTY_THRESHOLD
                node.anomaly = ANOMALY_LAMBDA * (1.0 if fired else 0.0) + (1 - ANOMALY_LAMBDA) * node.anomaly
            if now >= ONSET_S:
                cell.polls_after_onset += 1
                t_l = calc.get_score(LIAR)
                excluded = t_l < THETA or (gate_enforced and liar.anomaly >= GATE)
                if excluded:
                    cell.polls_quarantined += 1
                    if cell.first_quarantine_s is None:
                        cell.first_quarantine_s = now - ONSET_S
                cell.liar_min_trust = min(cell.liar_min_trust, t_l)
                for n in nodes.values():
                    if n is liar:
                        continue
                    t_h = calc.get_score(n.nid)
                    cell.honest_min_trust = min(cell.honest_min_trust, t_h)
                    cell.honest_polls += 1
                    cell.honest_polls_quarantined += (
                        t_h < THETA or (gate_enforced and n.anomaly >= GATE))
            push(now + POLL_S, 'poll')

        elif kind == 'arr':
            tid += 1
            states = [NodeState(n.nid, calc.get_score(n.nid),
                                n.claimed_duty if cpu_claim == 'verified' else n.claim_raw,
                                STATUS_RTT_MS,
                                n.anomaly if gate_enforced else 0.0)
                      for n in nodes.values()]
            probes = [n for n in nodes.values()
                      if calc.get_score(n.nid) < THETA
                      and not (gate_enforced and n.anomaly >= GATE)
                      and now - last_probe.get(n.nid, -1e9) >= PROBATION_S]
            if probes:
                probe = max(probes, key=lambda n: calc.get_score(n.nid))
                last_probe[probe.nid] = now
                chosen = probe.nid
            else:
                chosen, _, _ = select_edge_node(
                    states, WEIGHTS, isolation_threshold=THETA, anomaly_gate=GATE,
                    strategy=STRATEGY_P2C, d_choices=D_CHOICES, epsilon=EPSILON, rng=sel_rng)
            if chosen is not None:
                node = nodes[chosen]
                if now >= ONSET_S:
                    cell.routes_after_onset += 1
                    cell.liar_routes += chosen == LIAR
                if not slots or node.active < CONCURRENCY:
                    start(node, tid, now, now)
                else:
                    node.queue.append((now, tid))
                push(now + TASK_TIMEOUT_S, 'timeout', chosen, tid, now)
            push(now + rng.expovariate(ARRIVAL_HZ), 'arr')

        elif kind == 'dep':
            node = nodes[nid]
            node.active -= 1
            node.busy_total += service_s
            latency = now - arrived + BASE_LATENCY_S
            if not done.get(task):
                done[task] = True
                node.success_hist.append(now)
                while node.success_hist and node.success_hist[0] < now - 2 * LOAD_WINDOW_S:
                    node.success_hist.popleft()
                _update_trust(calc, node, nodes, latency, 'success', now, expected_duty)
                if now >= ONSET_S:
                    (cell.liar_latencies if nid == LIAR else cell.honest_latencies).append(latency)
            if node.queue:
                a, t2 = node.queue.popleft()
                start(node, t2, a, now)

        else:  # timeout
            if not done.get(task):
                done[task] = True
                _update_trust(calc, nodes[nid], nodes, TASK_TIMEOUT_S, 'timeout', now, expected_duty)
    return cell


def window_duty_real(node: _Node, now: float) -> Optional[float]:
    """The stealthy liar measuring its OWN true duty from its real counter.
    It knows the real counter even while it reports a fabricated one, so it
    cannot read busy_hist (which holds the fabricated values for a liar)."""
    hist = getattr(node, '_real_hist', None)
    if hist is None:
        hist = node._real_hist = deque()      # type: ignore[attr-defined]
    hist.append((now, node.busy_total))
    while hist and hist[0][0] < now - 2.0:
        hist.popleft()
    if len(hist) < 2 or hist[-1][0] <= hist[0][0]:
        return None
    return (hist[-1][1] - hist[0][1]) / ((hist[-1][0] - hist[0][0]) * CONCURRENCY)


def _update_trust(calc: TrustCalculator, node: _Node, nodes: Dict[str, _Node],
                  latency_s: float, status: str, now: float, expected_duty) -> None:
    exp = expected_duty(node, now)
    ref = exp if exp is not None else min(1.0, node.active / CONCURRENCY)
    calc.update(TrustUpdate(device_id='sim', edge_node_id=node.nid, task_status=status,
                            latency_ms=latency_s * 1000.0, reported_cpu=node.claimed_duty,
                            cpu_usage=ref, anomaly_flag=node.anomaly >= GATE))


# --------------------------------------------------------------------------- #
OCCUPANCIES = (0.01, 0.1, 0.2, 0.3, 0.4, 0.5)


def run(occupancies: Sequence[float] = OCCUPANCIES, seeds: int = 5,
        sim_s: float = SIM_S, cpu_claim: str = 'raw',
        gates: Sequence[bool] = (False, True),
        slot_modes: Sequence[bool] = (False, True)) -> List[Cell]:
    out = []
    for occ in occupancies:
        for attacker in ATTACKERS:
            for gate in gates:
                for slots in slot_modes:
                    for seed in range(1, seeds + 1):
                        c = simulate(occ, attacker, gate, slots, seed, sim_s,
                                     cpu_claim=cpu_claim)
                        out.append(c)
    return out


def _mean(xs: Sequence[float]) -> Optional[float]:
    return sum(xs) / len(xs) if xs else None


def summarise(cells: Sequence[Cell]) -> List[Dict[str, object]]:
    groups: Dict[Tuple, List[Cell]] = {}
    for c in cells:
        groups.setdefault((c.occupancy, c.attacker, c.gate_enforced, c.slots), []).append(c)
    rows = []
    for (occ, att, gate, slots), cs in groups.items():
        caught = [c.first_quarantine_s for c in cs if c.first_quarantine_s is not None]
        rows.append({
            'occupancy': occ, 'attacker': att, 'gate': gate, 'slots': slots, 'runs': len(cs),
            'share_pct': 100 * _mean([c.share for c in cs]),
            'excess_pct': 100 * _mean([c.excess for c in cs]),
            'caught': f'{len(caught)}/{len(cs)}',
            'median_catch_s': statistics.median(caught) if caught else None,
            'quarantined_pct': 100 * _mean([c.quarantined_frac for c in cs]),
            'liar_min_T': min(c.liar_min_trust for c in cs),
            'honest_min_T': min(c.honest_min_trust for c in cs),
            'honest_quar_pct': 100 * _mean([c.honest_quarantined_frac for c in cs]),
            'honest_ms': 1000 * (_mean([_mean(c.honest_latencies) or 0 for c in cs]) or 0),
            'liar_ms': 1000 * (_mean([_mean(c.liar_latencies) or 0 for c in cs]) or 0),
        })
    return rows


def format_table(rows: Sequence[Dict[str, object]]) -> str:
    hdr = (f'{"occ":>5} {"attacker":<16} {"gate":<5} {"slots":<5} {"share%":>7} '
           f'{"excess%":>8} {"caught":>6} {"med s":>6} {"quar%":>6} {"minT":>5} '
           f'{"honT":>5} {"honQ%":>5} {"hon ms":>7} {"liar ms":>7}')
    lines = [f'ceiling under p2c+eps: {100 * share_ceiling():.1f}% '
             f'(fair {100 / N:.1f}%)', hdr, '-' * len(hdr)]
    for r in rows:
        med = '-' if r['median_catch_s'] is None else f'{r["median_catch_s"]:.0f}'
        lines.append(
            f'{r["occupancy"]:>5.2f} {r["attacker"]:<16} {str(r["gate"]):<5} {str(r["slots"]):<5} '
            f'{r["share_pct"]:>7.2f} {r["excess_pct"]:>+8.2f} {r["caught"]:>6} {med:>6} '
            f'{r["quarantined_pct"]:>6.1f} {r["liar_min_T"]:>5.3f} '
            f'{r["honest_min_T"]:>5.3f} {r["honest_quar_pct"]:>5.1f} '
            f'{r["honest_ms"]:>7.0f} {r["liar_ms"]:>7.0f}')
    return '\n'.join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--occupancies', default=','.join(str(o) for o in OCCUPANCIES))
    p.add_argument('--seeds', type=int, default=5)
    p.add_argument('--sim-s', type=float, default=SIM_S)
    p.add_argument('--csv', default=None)
    p.add_argument('--cpu-claim', choices=['raw', 'verified'], default='raw',
                   help='what the selector ranks on (edge_score.cpu_claim)')
    p.add_argument('--gate-only', action='store_true',
                   help='only the gate-enforced, slots-off cells')
    args = p.parse_args(argv)
    occs = [float(x) for x in args.occupancies.split(',')]
    gates, slots = ((True,), (False,)) if args.gate_only else ((False, True), (False, True))
    rows = summarise(run(occs, args.seeds, args.sim_s, args.cpu_claim, gates, slots))
    print(format_table(rows))
    if args.csv:
        with open(args.csv, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
