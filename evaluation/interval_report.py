"""Interval (metric-vs-simulation-time) report for a live run's JSONL event
recording. plan_adv.md Phase 0.

`evaluation/nfr_report.py` answers "did the whole run meet its NFR targets" as
one number per metric. That is the wrong shape for a panel review: mam wants
throughput, delay, PDR, load balancing, traffic load, and packet drop each
shown *as a function of simulation time* (bucketed into fixed-width windows,
e.g. every 10s) -- the standard AODV/DSR/LEACH-paper evaluation shape, with
an attack's onset visible as a change in the curve rather than folded into a
single mean.

No new instrumentation was added for this. Every field used here is already
published by the live controller and already lands in the JSONL
(`route`, `route_denied`, `report`, `quarantine`, `recovered`, `flow_stats`,
`port_stats`, `topology`) -- this module only bins and derives. See
plan_adv.md Phase 0 for why a separate "periodic snapshot event" turned out
to be unnecessary.

Two packet-drop notions are kept as separate series on purpose, per this
project's own established discipline (do not conflate "correctly isolated
attacker" traffic with "lost/timed-out" traffic -- see
memory/edgescore-fanout-starvation and memory/live-run-cascading-quarantine):

    * task-level drop: 'report' events with status timeout/failure -- work
      offered to the fleet that did not complete.
    * OpenFlow-level drop: packets actually hitting a quarantined node's
      PRIO_QUARANTINE_DROP rule -- zero-trust enforcement working as
      intended, not a fault.

Run:
    python3 -m evaluation.interval_report data/events.jsonl --bucket-s 10
    python3 -m evaluation.interval_report data/events.jsonl --csv out.csv
"""

from __future__ import annotations

import argparse
import statistics
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from evaluation.nfr_report import _percentile, load_events

# controller/trust_balancer.py's PRIO_QUARANTINE_DROP. Duplicated as a plain
# constant rather than imported -- importing trust_balancer.py pulls in
# os_ken, which nfr_report.py deliberately avoids so this analysis can run
# on a box with no controller stack installed. Pinned by
# tests/test_interval_report.py against the real value.
PRIO_QUARANTINE_DROP = 400

DEFAULT_BUCKET_S = 10.0


def jain_fairness_index(counts: Sequence[float]) -> Optional[float]:
    """Jain's Fairness Index (Jain, Chiu & Hawe, 1984): (sum x)^2 / (n * sum
    x^2), range (1/n, 1]. 1.0 = every node got an identical share; 1/n = one
    node took everything. None (not 0.0 -- this is "no opinion", not "totally
    unfair") when there were no nodes or no traffic to measure.

    Deliberately Jain's index and not the dashboard's live Gini coefficient
    (dashboard/index.html's `gini()`) -- Jain's is the metric actually cited
    in load-balancing literature, which is what a panel will expect the name
    to mean.
    """
    n = len(counts)
    if n == 0:
        return None
    total = sum(counts)
    if total <= 0:
        return None
    sq_sum = sum(c * c for c in counts)
    if sq_sum <= 0:
        return None
    return (total ** 2) / (n * sq_sum)


@dataclass
class IntervalMetrics:
    t_start_s: float
    t_end_s: float

    # Traffic load / load balancing
    offered: int = 0
    served: int = 0
    offered_rate_hz: float = 0.0
    routing_share: Dict[str, int] = field(default_factory=dict)
    jain_fairness: Optional[float] = None

    # Delay / response time
    mean_decision_ms: Optional[float] = None
    p95_decision_ms: Optional[float] = None
    mean_task_latency_ms: Optional[float] = None

    # PDR / task-level packet drop
    task_total: int = 0
    task_success: int = 0
    task_timeout: int = 0
    task_failure: int = 0
    pdr: Optional[float] = None

    # OpenFlow-level packet drop (zero-trust enforcement, not loss)
    quarantine_drop_packets: int = 0

    # Throughput -- sum of bps across serving (non-drop) VIP flow-table rules
    throughput_bps: float = 0.0

    # Status
    quarantined_nodes: List[str] = field(default_factory=list)
    num_quarantined: int = 0


def server_node_ids(events: Sequence[Dict[str, Any]]) -> List[str]:
    """The full server roster, from the first 'topology' event's graph.

    Falling back to "every node that ever appears in a 'route' event" would
    silently drop a node that was starved for the *entire* run from the
    fairness calculation -- exactly the failure mode this metric exists to
    catch (see memory/edgescore-fanout-starvation). Only fall back to the
    route-derived set if no 'topology' event is in the recording at all (a
    trimmed/replay-only log), and say so is a degraded reading via the
    caller's `roster_is_complete` bookkeeping -- see bucket_events().
    """
    for e in events:
        if e.get('type') == 'topology':
            nodes = (e.get('graph') or {}).get('nodes', [])
            servers = [n['id'] for n in nodes if n.get('kind') == 'server']
            if servers:
                return sorted(servers)
    return []


def bucket_events(
    events: Sequence[Dict[str, Any]],
    bucket_s: float = DEFAULT_BUCKET_S,
    node_ids: Optional[Sequence[str]] = None,
) -> List[IntervalMetrics]:
    """Bin a JSONL recording's events into fixed-width time windows.

    `node_ids`: the full server roster for the Jain's-index denominator.
    Defaults to `server_node_ids(events)` (the 'topology' event's roster);
    pass explicitly when analysing a trimmed log that lacks one.
    """
    if not events:
        return []

    roster = list(node_ids) if node_ids is not None else server_node_ids(events)

    ordered = sorted(events, key=lambda e: e.get('ts', 0.0))
    t0 = ordered[0].get('ts', 0.0)
    t1 = ordered[-1].get('ts', 0.0)
    n_buckets = max(1, int((t1 - t0) // bucket_s) + 1)

    buckets = [
        IntervalMetrics(t_start_s=i * bucket_s, t_end_s=(i + 1) * bucket_s)
        for i in range(n_buckets)
    ]
    decision_ms_by_bucket: List[List[float]] = [[] for _ in range(n_buckets)]
    latency_ms_by_bucket: List[List[float]] = [[] for _ in range(n_buckets)]
    routing_share_by_bucket: List[Dict[str, int]] = [dict() for _ in range(n_buckets)]

    # Running state carried across the whole timeline -- cumulative counters
    # must be diffed against their own last sighting, not reset per bucket,
    # and a quiet bucket inherits the last known throughput/quarantine
    # reading rather than reading as zero.
    latest_vip_flow_bps: Dict[tuple, float] = {}
    prev_quarantine_pkts: Dict[tuple, int] = {}
    quarantined: set = set()
    bucket_touched = [False] * n_buckets

    def _idx(ts: float) -> int:
        return min(max(0, int((ts - t0) // bucket_s)), n_buckets - 1)

    for e in ordered:
        i = _idx(e.get('ts', t0))
        et = e.get('type')
        b = buckets[i]

        if et == 'route':
            bucket_touched[i] = True
            b.offered += 1
            b.served += 1
            chosen = e.get('chosen')
            if chosen:
                routing_share_by_bucket[i][chosen] = (
                    routing_share_by_bucket[i].get(chosen, 0) + 1
                )
            if 'decision_ms' in e:
                decision_ms_by_bucket[i].append(e['decision_ms'])

        elif et == 'route_denied':
            bucket_touched[i] = True
            b.offered += 1

        elif et == 'report':
            bucket_touched[i] = True
            b.task_total += 1
            status = e.get('status')
            if status == 'success':
                b.task_success += 1
                if 'latency_ms' in e:
                    latency_ms_by_bucket[i].append(e['latency_ms'])
            elif status == 'timeout':
                b.task_timeout += 1
            else:
                b.task_failure += 1

        elif et == 'quarantine':
            bucket_touched[i] = True
            node = e.get('node')
            if node:
                quarantined.add(node)

        elif et == 'recovered':
            bucket_touched[i] = True
            node = e.get('node')
            if node:
                quarantined.discard(node)

        elif et == 'flow_stats':
            bucket_touched[i] = True
            for rule in e.get('rules') or []:
                if not rule.get('is_vip'):
                    continue
                key = (
                    rule.get('dpid'), rule.get('table'), rule.get('priority'),
                    rule.get('cookie'), rule.get('match'),
                )
                if rule.get('priority') == PRIO_QUARANTINE_DROP:
                    pkts = rule.get('packets', 0) or 0
                    prev = prev_quarantine_pkts.get(key, pkts)
                    b.quarantine_drop_packets += max(0, pkts - prev)
                    prev_quarantine_pkts[key] = pkts
                else:
                    # bps is already a rate (FlowStatsPoller diffs cumulative
                    # byte counts between its own polls) -- track the latest
                    # reading per rule and sum at read time, don't accumulate.
                    latest_vip_flow_bps[key] = rule.get('bps', 0.0) or 0.0

        # Snapshot running state into this bucket regardless of event type,
        # so it forward-fills to the next event even inside a quiet bucket.
        b.throughput_bps = sum(latest_vip_flow_bps.values())
        b.quarantined_nodes = sorted(quarantined)
        b.num_quarantined = len(quarantined)

    # Forward-fill throughput/quarantine state into buckets that had no
    # events of their own at all (possible at the very start, or a genuine
    # lull) from the nearest earlier touched bucket.
    last_tp, last_quar = 0.0, []
    for i in range(n_buckets):
        if bucket_touched[i]:
            last_tp = buckets[i].throughput_bps
            last_quar = buckets[i].quarantined_nodes
        else:
            buckets[i].throughput_bps = last_tp
            buckets[i].quarantined_nodes = last_quar
            buckets[i].num_quarantined = len(last_quar)

    for i, b in enumerate(buckets):
        dm = decision_ms_by_bucket[i]
        lm = latency_ms_by_bucket[i]
        b.mean_decision_ms = statistics.mean(dm) if dm else None
        b.p95_decision_ms = _percentile(dm, 95) if dm else None
        b.mean_task_latency_ms = statistics.mean(lm) if lm else None
        b.offered_rate_hz = round(b.offered / bucket_s, 4)

        completed = b.task_success + b.task_timeout + b.task_failure
        b.pdr = round(b.task_success / completed, 4) if completed > 0 else None

        share = routing_share_by_bucket[i]
        b.routing_share = share
        if roster:
            counts = [share.get(nid, 0) for nid in roster]
            b.jain_fairness = jain_fairness_index(counts)
        elif share:
            # Degraded fallback: no 'topology' event in this recording, so
            # fairness is computed only over nodes seen receiving traffic --
            # a permanently-starved node would not be penalised here. See
            # server_node_ids()'s docstring.
            b.jain_fairness = jain_fairness_index(list(share.values()))

    return buckets


# ------------------------------------------------------------------ #
# Reporting                                                            #
# ------------------------------------------------------------------ #
def format_table(buckets: Sequence[IntervalMetrics]) -> str:
    header = (
        f"{'t(s)':>8} {'offered/s':>10} {'served':>7} {'PDR':>6} "
        f"{'p95 dec(ms)':>12} {'lat(ms)':>9} {'thpt(bps)':>11} "
        f"{'Jain':>6} {'quar':>5} {'OF-drop(pkt)':>13}"
    )
    lines = [header, '-' * len(header)]
    for b in buckets:
        lines.append(
            f"{b.t_start_s:8.0f} {b.offered_rate_hz:10.2f} {b.served:7d} "
            f"{'' if b.pdr is None else f'{b.pdr:.2f}':>6} "
            f"{'' if b.p95_decision_ms is None else f'{b.p95_decision_ms:.1f}':>12} "
            f"{'' if b.mean_task_latency_ms is None else f'{b.mean_task_latency_ms:.1f}':>9} "
            f"{b.throughput_bps:11.0f} "
            f"{'' if b.jain_fairness is None else f'{b.jain_fairness:.3f}':>6} "
            f"{b.num_quarantined:5d} {b.quarantine_drop_packets:13d}"
        )
    return '\n'.join(lines)


def to_csv_rows(buckets: Sequence[IntervalMetrics]) -> List[List[Any]]:
    header = [
        't_start_s', 't_end_s', 'offered', 'served', 'offered_rate_hz',
        'pdr', 'mean_decision_ms', 'p95_decision_ms', 'mean_task_latency_ms',
        'throughput_bps', 'jain_fairness', 'num_quarantined',
        'quarantined_nodes', 'quarantine_drop_packets',
        'task_success', 'task_timeout', 'task_failure',
    ]
    rows: List[List[Any]] = [header]
    for b in buckets:
        rows.append([
            b.t_start_s, b.t_end_s, b.offered, b.served, b.offered_rate_hz,
            b.pdr, b.mean_decision_ms, b.p95_decision_ms, b.mean_task_latency_ms,
            b.throughput_bps, b.jain_fairness, b.num_quarantined,
            ';'.join(b.quarantined_nodes), b.quarantine_drop_packets,
            b.task_success, b.task_timeout, b.task_failure,
        ])
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('events_path', nargs='?', default='data/events.jsonl')
    parser.add_argument('--bucket-s', type=float, default=DEFAULT_BUCKET_S)
    parser.add_argument('--csv', default=None, help='Also write a CSV of the buckets')
    args = parser.parse_args()

    events = load_events(args.events_path)
    buckets = bucket_events(events, bucket_s=args.bucket_s)
    print(format_table(buckets))

    if args.csv:
        import csv
        with open(args.csv, 'w', newline='') as f:
            csv.writer(f).writerows(to_csv_rows(buckets))
        print(f'\nCSV written to {args.csv}')


if __name__ == '__main__':
    main()
