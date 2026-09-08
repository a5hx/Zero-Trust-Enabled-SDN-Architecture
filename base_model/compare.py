#!/usr/bin/env python3
"""Score the two arms against each other, from their two recordings.

    python3 -m base_model.compare \\
        --baseline data/base_events.jsonl \\
        --treatment data/events.jsonl \\
        --out-dir data/comparison

Produces four things:

    comparison.txt          the table to read
    comparison.json         the same numbers, machine-readable
    trust_series.csv        per-arm, per-server trust vs. time -- the file the
                            paper's trust-curve figure is plotted from
    per_node.csv            per-arm, per-server end-of-run summary

RULES THIS TOOL FOLLOWS, INHERITED FROM THE PROJECT'S OTHER SCORERS
------------------------------------------------------------------
1. **"Not measured" is never printed as zero.** A metric with no supporting
   events reports `None` and renders as `--`. The baseline genuinely has no
   quarantine events; that must read as "no such mechanism", not "0 ms
   isolation latency", which a reader would score as *better*.

2. **Attacker downtime and honest downtime are never summed.** Isolating an
   attacker is enforcement working; isolating an honest node is the system's
   cost. They are opposite quantities and the honest-node figure is the
   headline, exactly as `evaluation/availability_report.py` argues.

3. **The trust series is reported per node with its ground-truth role
   attached**, never averaged across the fleet. A fleet-mean trust curve
   averages a blackhole's collapse against seven healthy nodes and shows a
   gentle dip -- which is the opposite of the finding.

4. **Streamed, not loaded.** These recordings run to 130 MB+. Every pass here
   is line-by-line with bounded state.

WHAT "SPOOF SUCCEEDED" MEANS HERE
---------------------------------
The baseline never checks anything, so the finding is derived from recorded
facts: an `auth_admitted` whose `device_id` maps to an IP that is not the
`source_ip` the socket reported. In the treatment arm the corresponding fact is
an `auth_denied` with `kind='ip_pin'`. Both are read from ground truth in the
`topology` event, not from either controller's opinion.
"""

import argparse
import json
import math
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from evaluation.interval_report import DEFAULT_BUCKET_S, jain_fairness_index

#: Attack labels in the `topology` event that mark a SERVER as an attacker.
SERVER_ATTACKS = ('sybil', 'drop', 'blackhole', 'grayhole', 'onoff')
#: ...and a DEVICE.
DEVICE_ATTACKS = ('flood', 'spoof', 'bad_credentials')


def stream_events(path: str) -> Iterator[Dict[str, Any]]:
    """Yield one event per line, skipping unparseable tails.

    A run killed with Ctrl-C can leave a half-written final line. Skipping it
    is right; failing the whole comparison over it is not.
    """
    with open(path, 'r', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


@dataclass
class GroundTruth:
    """Roles, read from the run's own `topology` event."""

    servers: Dict[str, str] = field(default_factory=dict)        # srvN -> attack
    server_onset: Dict[str, float] = field(default_factory=dict)
    devices: Dict[str, str] = field(default_factory=dict)        # iotN -> attack
    device_onset: Dict[str, float] = field(default_factory=dict)
    device_ip: Dict[str, str] = field(default_factory=dict)
    ip_device: Dict[str, str] = field(default_factory=dict)
    bound_to: Dict[str, str] = field(default_factory=dict)

    @property
    def honest_servers(self) -> List[str]:
        return sorted(
            (n for n, a in self.servers.items() if a in ('none', '', None)),
            key=_srv_sort_key,
        )

    @property
    def attacker_servers(self) -> List[str]:
        return sorted(
            (n for n, a in self.servers.items() if a not in ('none', '', None)),
            key=_srv_sort_key,
        )


def _srv_sort_key(node_id: str) -> Tuple[int, str]:
    digits = ''.join(c for c in node_id if c.isdigit())
    return (int(digits) if digits else 0, node_id)


@dataclass
class ArmResult:
    """Everything scored for one arm. `None` means not measured."""

    name: str
    events_path: str
    arm_label: Optional[str] = None
    strategy: Optional[str] = None
    duration_s: Optional[float] = None

    truth: GroundTruth = field(default_factory=GroundTruth)

    # Task outcomes
    tasks_total: int = 0
    tasks_success: int = 0
    tasks_timeout: int = 0
    tasks_failure: int = 0
    latencies_ms: List[float] = field(default_factory=list)

    # Per-device and per-node
    device_outcomes: Dict[str, Dict[str, int]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(int))
    )
    node_outcomes: Dict[str, Dict[str, int]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(int))
    )
    # (claimed device_id, real source IP) -> outcomes. Needed because a
    # successful identity spoof makes `device_outcomes` a merge of two hosts:
    # in the baseline run, iot38 authenticated as iot1 and both then reported
    # under that one name, from different addresses, served by different
    # servers. Keeping the source IP is what lets the victim's real service
    # record be recovered instead of quietly averaged with its attacker's.
    device_source_outcomes: Dict[Tuple[str, str], Dict[str, int]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(int))
    )
    routes_per_node: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    routes_total: int = 0
    route_denied: int = 0
    decision_ms: List[float] = field(default_factory=list)

    # Trust series: node -> [(t_rel, trust, anomaly)]
    trust_series: Dict[str, List[Tuple[float, float, float]]] = field(
        default_factory=lambda: defaultdict(list)
    )
    final_trust: Dict[str, float] = field(default_factory=dict)
    final_anomaly: Dict[str, float] = field(default_factory=dict)

    # Detection & response
    anomaly_events: int = 0
    anomaly_nodes: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    quarantine_events: int = 0
    quarantined_nodes: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    recovered_events: int = 0
    reroute_events: int = 0
    resteer_ms: List[float] = field(default_factory=list)
    first_detection_s: Dict[str, float] = field(default_factory=dict)
    first_quarantine_s: Dict[str, float] = field(default_factory=dict)

    # Admission
    auth_denied: int = 0
    auth_denied_kinds: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    auth_admitted: int = 0
    spoof_admitted: List[Dict[str, Any]] = field(default_factory=list)
    bad_cred_admitted: List[str] = field(default_factory=list)

    # Ledger
    blocks: int = 0

    # ---- derived ------------------------------------------------------ #
    @property
    def pdr(self) -> Optional[float]:
        return self.tasks_success / self.tasks_total if self.tasks_total else None

    @property
    def mean_latency_ms(self) -> Optional[float]:
        return statistics.fmean(self.latencies_ms) if self.latencies_ms else None

    @property
    def p95_latency_ms(self) -> Optional[float]:
        if not self.latencies_ms:
            return None
        ordered = sorted(self.latencies_ms)
        idx = min(len(ordered) - 1, int(math.ceil(0.95 * len(ordered)) - 1))
        return ordered[idx]

    @property
    def throughput_tps(self) -> Optional[float]:
        if not self.duration_s:
            return None
        return self.tasks_success / self.duration_s

    @property
    def jain_routes(self) -> Optional[float]:
        """Fairness over the FULL server roster, zeros included.

        Over the roster, not over "servers seen receiving traffic": a server
        that received nothing is the starvation this index exists to detect,
        and dropping it from the denominator hides exactly that.
        """
        if not self.truth.servers:
            return None
        counts = [self.routes_per_node.get(n, 0) for n in sorted(self.truth.servers)]
        return jain_fairness_index(counts)

    def device_availability(self, device: str) -> Optional[float]:
        row = self.device_outcomes.get(device)
        if not row:
            return None
        total = sum(row.values())
        return row.get('success', 0) / total if total else None

    def honest_device_availability(self) -> Optional[float]:
        """Mean per-device success rate over HONEST devices only.

        Per-device then averaged, not pooled: pooling lets 35 well-served
        devices hide five that received nothing, which is the single most
        important thing a static binding does wrong.
        """
        vals = [
            v for d, a in self.truth.devices.items()
            if a in ('none', '', None)
            for v in [self.device_availability(d)] if v is not None
        ]
        return statistics.fmean(vals) if vals else None

    def starved_devices(self, threshold: float = 0.5) -> List[str]:
        """Honest devices whose success rate fell below `threshold`.

        The list, not just the count -- naming them is what lets a reader check
        the claim against the binding table.
        """
        out = []
        for device, attack in sorted(self.truth.devices.items(), key=_srv_sort_key):
            if attack not in ('none', '', None):
                continue
            avail = self.device_availability(device)
            if avail is not None and avail < threshold:
                out.append(device)
        return out

    def contaminated_identities(self) -> Dict[str, List[Dict[str, Any]]]:
        """Device ids whose reports came from more than one host.

        Only possible where an identity spoof succeeded, so in practice this is
        empty for the treatment arm and holds the spoofed identity for the
        baseline. Returned as a per-source breakdown, because the useful thing
        is not "this number is contaminated" but "here is what each host
        actually did".

        Availability figures for such an id are a merge of a victim and its
        attacker and must not be quoted as either.
        """
        by_device: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for (device, source_ip), outcomes in self.device_source_outcomes.items():
            total = sum(outcomes.values())
            by_device[device].append({
                'source_ip': source_ip,
                'real_device': self.truth.ip_device.get(source_ip),
                'is_the_owner': self.truth.device_ip.get(device) == source_ip,
                'tasks': total,
                'success': outcomes.get('success', 0),
                'availability': outcomes.get('success', 0) / total if total else None,
            })
        return {
            device: sorted(rows, key=lambda r: not r['is_the_owner'])
            for device, rows in by_device.items() if len(rows) > 1
        }

    @property
    def detections_unactioned(self) -> Optional[int]:
        """Anomaly events that produced no isolation.

        For the baseline this is every one of them. For the treatment arm it is
        the ones that fired without a quarantine following, which is a genuine
        (and much smaller) number rather than a definitional zero.
        """
        if self.anomaly_events == 0:
            return None
        return self.anomaly_events - self.quarantine_events


def score_arm(name: str, path: str) -> ArmResult:
    """One streaming pass over a recording."""
    res = ArmResult(name=name, events_path=path)
    t0: Optional[float] = None
    t_last: Optional[float] = None

    for ev in stream_events(path):
        etype = ev.get('type')
        ts = ev.get('ts')
        if ts is not None:
            if t0 is None:
                # Anchored on the FIRST event, which is the topology event in
                # both arms. Anchoring on the first `route` instead would make
                # every onset time relative to a moment that varies with how
                # fast the first client happened to connect.
                t0 = float(ts)
            # max(), not "the last line's ts". Events are published from several
            # threads and a later-written line can carry a slightly earlier
            # stamp; taking the tail would then shorten the run and inflate
            # every per-second rate divided by it.
            t_last = float(ts) if t_last is None else max(t_last, float(ts))
        t_rel = (float(ts) - t0) if (ts is not None and t0 is not None) else 0.0

        if etype == 'topology':
            _read_ground_truth(res.truth, ev.get('graph') or {})
        elif etype == 'arm':
            res.arm_label = ev.get('arm')
            res.strategy = ev.get('strategy')
        elif etype == 'route':
            res.routes_total += 1
            chosen = ev.get('chosen')
            if chosen:
                res.routes_per_node[chosen] += 1
            if res.strategy is None and ev.get('strategy'):
                res.strategy = ev.get('strategy')
            dm = ev.get('decision_ms')
            if dm is not None:
                res.decision_ms.append(float(dm))
        elif etype == 'route_denied':
            res.route_denied += 1
        elif etype == 'report':
            status = ev.get('status')
            node = ev.get('node')
            device = ev.get('device')
            res.tasks_total += 1
            if status == 'success':
                res.tasks_success += 1
            elif status == 'timeout':
                res.tasks_timeout += 1
            else:
                res.tasks_failure += 1
            lat = ev.get('latency_ms')
            if lat is not None and status == 'success':
                # Successes only. A timeout's "latency" is the client's own
                # timeout constant, so pooling them reports the configured
                # bound as a measurement -- and the arm that times out more
                # would appear to have *better-behaved* tails.
                res.latencies_ms.append(float(lat))
            if device:
                res.device_outcomes[device][status or 'unknown'] += 1
                source_ip = ev.get('source_ip')
                if source_ip:
                    res.device_source_outcomes[(device, source_ip)][
                        status or 'unknown'] += 1
            if node:
                res.node_outcomes[node][status or 'unknown'] += 1
        elif etype == 'node_status':
            for node, row in (ev.get('nodes') or {}).items():
                trust = float(row.get('trust', 0.0))
                anomaly = float(row.get('anomaly', 0.0))
                res.trust_series[node].append((t_rel, trust, anomaly))
                res.final_trust[node] = trust
                res.final_anomaly[node] = anomaly
        elif etype == 'anomaly':
            res.anomaly_events += 1
            node = ev.get('node')
            if node:
                res.anomaly_nodes[node] += 1
                res.first_detection_s.setdefault(node, t_rel)
        elif etype == 'quarantine':
            res.quarantine_events += 1
            node = ev.get('node')
            if node:
                res.quarantined_nodes[node] += 1
                res.first_quarantine_s.setdefault(node, t_rel)
        elif etype == 'recovered':
            res.recovered_events += 1
        elif etype == 'reroute':
            res.reroute_events += 1
            rm = ev.get('resteer_ms')
            if rm is not None:
                res.resteer_ms.append(float(rm))
        elif etype == 'auth_denied':
            res.auth_denied += 1
            res.auth_denied_kinds[str(ev.get('kind'))] += 1
        elif etype == 'auth_admitted':
            res.auth_admitted += 1
            device_id = ev.get('device_id')
            source_ip = ev.get('source_ip')
            expected = ev.get('expected_ip')
            if expected and source_ip and expected != source_ip:
                res.spoof_admitted.append({
                    'claimed': device_id, 'from_ip': source_ip,
                    'expected_ip': expected, 't_rel_s': round(t_rel, 2),
                    'actual_device': res.truth.ip_device.get(source_ip),
                })
            if res.truth.devices.get(device_id) == 'bad_credentials':
                res.bad_cred_admitted.append(device_id)
        elif etype == 'block':
            res.blocks += 1

    if t0 is not None and t_last is not None:
        res.duration_s = t_last - t0
    return res


def _read_ground_truth(truth: GroundTruth, graph: Dict[str, Any]) -> None:
    for node in graph.get('nodes') or []:
        kind = node.get('kind')
        node_id = node.get('id')
        attack = node.get('attack', 'none')
        if kind == 'server':
            truth.servers[node_id] = attack
            truth.server_onset[node_id] = float(node.get('attack_start_s', 0.0))
        elif kind == 'iot':
            truth.devices[node_id] = attack
            truth.device_onset[node_id] = float(node.get('attack_start_s', 0.0))
            ip = node.get('ip')
            if ip:
                truth.device_ip[node_id] = ip
                truth.ip_device[ip] = node_id
            if node.get('bound_to'):
                truth.bound_to[node_id] = node['bound_to']


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
def _fmt(value: Any, spec: str = '', scale: float = 1.0, suffix: str = '') -> str:
    """`--` for None. Never 0 for a metric that was not measured."""
    if value is None:
        return '--'
    if isinstance(value, (int, float)) and spec:
        return format(value * scale, spec) + suffix
    return f'{value}{suffix}'


def _row(label: str, base: str, treat: str, note: str = '') -> str:
    return f'{label:<38} {base:>16} {treat:>16}   {note}'


def format_comparison(base: ArmResult, treat: Optional[ArmResult]) -> str:
    lines: List[str] = []
    add = lines.append

    add('=' * 96)
    add('BASELINE vs. ZERO-TRUST SDN -- controlled comparison')
    add('=' * 96)
    add('')
    add(f'  baseline   : {base.events_path}')
    add(f'               strategy={base.strategy or "?"}  '
        f'duration={_fmt(base.duration_s, ".1f", suffix="s")}')
    if treat is None:
        add('  treatment  : NOT SUPPLIED -- baseline figures only')
        add('')
        add('  Pass --treatment data/events.jsonl to score both arms together.')
    else:
        add(f'  treatment  : {treat.events_path}')
        add(f'               duration={_fmt(treat.duration_s, ".1f", suffix="s")}')
    add('')

    t = treat  # shorthand; every access below is guarded

    def col(getter, spec='', scale=1.0, suffix=''):
        b = _fmt(getter(base), spec, scale, suffix)
        v = _fmt(getter(t), spec, scale, suffix) if t else '--'
        return b, v

    add('-' * 96)
    add(_row('METRIC', 'BASELINE', 'ZERO-TRUST', ''))
    add('-' * 96)

    add('  service')
    b, v = col(lambda r: r.tasks_total)
    add(_row('    tasks reported', b, v))
    b, v = col(lambda r: r.pdr, '.2%')
    add(_row('    packet delivery ratio', b, v, 'successes / reports'))
    b, v = col(lambda r: r.throughput_tps, '.2f')
    add(_row('    throughput (tasks/s)', b, v, 'successes / run length'))
    b, v = col(lambda r: r.mean_latency_ms, '.1f', suffix=' ms')
    add(_row('    mean task latency', b, v, 'successes only'))
    b, v = col(lambda r: r.p95_latency_ms, '.1f', suffix=' ms')
    add(_row('    p95 task latency', b, v))
    b, v = col(lambda r: r.tasks_timeout)
    add(_row('    tasks lost to timeout', b, v))
    add('')

    add('  availability (honest devices only)')
    b, v = col(lambda r: r.honest_device_availability(), '.2%')
    add(_row('    mean per-device success rate', b, v, 'per device, then averaged'))
    bs = base.starved_devices()
    vs = t.starved_devices() if t else None
    add(_row('    honest devices below 50% served',
             str(len(bs)), str(len(vs)) if vs is not None else '--'))
    if bs:
        add(f'      baseline starved: {", ".join(bs)}')
    if vs:
        add(f'      treatment starved: {", ".join(vs)}')

    # A spoofed identity's availability is a merge of two hosts and must not be
    # quoted as either one's. Broken out rather than silently included, because
    # the merged figure is exactly the kind of number that reaches a paper.
    for arm in (base, t):
        if arm is None:
            continue
        for device, rows in sorted(arm.contaminated_identities().items()):
            add(f'      !! {arm.name}: "{device}" was reported by '
                f'{len(rows)} different hosts -- its availability above is a '
                f'MERGE and is not any one device\'s figure:')
            for row in rows:
                who = ('the real ' + device if row['is_the_owner']
                       else f'{row["real_device"] or "unknown"} IMPERSONATING {device}')
                avail = ('--' if row['availability'] is None
                         else f'{row["availability"]:.1%}')
                add(f'           {row["source_ip"]:<12} {who:<34} '
                    f'{row["success"]:>5}/{row["tasks"]:<5} served = {avail}')
    add('')

    add('  load distribution')
    b, v = col(lambda r: r.jain_routes, '.3f')
    add(_row("    Jain fairness of routes", b, v, 'over the full roster'))
    b, v = col(lambda r: r.routes_total)
    add(_row('    routing decisions', b, v))
    b, v = col(lambda r: r.route_denied)
    add(_row('    requests denied (no eligible node)', b, v,
             'baseline cannot deny: no eligibility'))
    add('')

    add('  detection and response')
    b, v = col(lambda r: r.anomaly_events)
    add(_row('    anomaly events raised', b, v))
    b, v = col(lambda r: r.quarantine_events)
    add(_row('    quarantines applied', b, v, 'baseline has no isolation path'))
    b, v = col(lambda r: r.detections_unactioned)
    add(_row('    detections with NO response', b, v, 'the control arm cost'))
    b, v = col(lambda r: r.reroute_events)
    add(_row('    re-steers performed', b, v))
    add('')

    add('  containment of the four server attacks')
    for node in sorted(base.truth.attacker_servers, key=_srv_sort_key):
        attack = base.truth.servers[node]
        onset = base.truth.server_onset.get(node, 0.0)
        bq = base.first_quarantine_s.get(node)
        tq = t.first_quarantine_s.get(node) if t else None
        b_txt = 'never' if bq is None else f'{bq - onset:.1f}s'
        t_txt = ('--' if t is None else ('never' if tq is None else f'{tq - onset:.1f}s'))
        add(_row(f'    {node} ({attack}, arms t={onset:.0f}s)', b_txt, t_txt,
                 'time from onset to isolation'))
    add('')

    add('  admission control')
    b, v = col(lambda r: r.auth_denied)
    add(_row('    devices refused at admission', b, v))
    add(_row('    identity spoof outcome',
             'SUCCEEDED' if base.spoof_admitted else 'none seen',
             ('REFUSED' if (t and t.auth_denied_kinds.get('ip_pin')) else
              ('none seen' if t else '--'))))
    for hit in base.spoof_admitted:
        add(f'      baseline admitted "{hit["claimed"]}" from {hit["from_ip"]} '
            f'(really {hit["actual_device"] or "unknown"}) at t={hit["t_rel_s"]}s')
    add(_row('    wrong-key devices admitted',
             str(len(set(base.bad_cred_admitted))),
             '0' if (t and t.auth_denied_kinds.get('bad_response')) else '--'))
    add('')

    add('  ledger')
    b, v = col(lambda r: r.blocks or None)
    add(_row('    trust blocks committed', b, v, 'baseline keeps no ledger'))
    add('')

    add('-' * 96)
    add('TRUST AT END OF RUN, per server (ground truth in brackets)')
    add('-' * 96)
    add(_row('SERVER [role]', 'BASELINE T', 'ZERO-TRUST T', 'baseline A / treatment A'))
    for node in sorted(base.truth.servers, key=_srv_sort_key):
        role = base.truth.servers[node]
        bt = base.final_trust.get(node)
        tt = t.final_trust.get(node) if t else None
        ba = base.final_anomaly.get(node)
        ta = t.final_anomaly.get(node) if t else None
        add(_row(
            f'  {node} [{role}]',
            _fmt(bt, '.4f'), _fmt(tt, '.4f'),
            f'{_fmt(ba, ".3f")} / {_fmt(ta, ".3f")}',
        ))
    add('')
    add('  Read per node, never as a fleet mean: averaging a blackhole\'s collapse')
    add('  against seven healthy servers produces a gentle dip and hides the finding.')
    add('')

    add('-' * 96)
    add('HOW TO READ THIS')
    add('-' * 96)
    add('  `--` means NOT MEASURED, never zero. The baseline has no quarantine,')
    add('  re-steer, admission or ledger path, so those rows are absences of a')
    add('  mechanism -- not a mechanism that scored zero.')
    add('')
    add('  Both arms ran the same topology, the same workload and the same')
    add('  attackers on the same schedule, launched by the same code')
    add('  (simulation.topology._launch_trust_agents). Trust in both arms is')
    add('  computed by controller/trust_state.py through the same estimators.')
    add('  What differs is whether anything acted on it.')
    return '\n'.join(lines)


def write_trust_series_csv(path: Path, arms: List[ArmResult], bucket_s: float) -> None:
    """Long-format CSV: one row per (arm, node, bucket).

    Long rather than wide because the two arms will not have identical bucket
    counts -- a run interrupted a few seconds early would silently truncate or
    misalign a wide table, and the misalignment would be invisible in the plot.
    """
    rows = ['arm,node,role,attack_start_s,t_s,trust,anomaly,samples']
    for arm in arms:
        for node, series in arm.trust_series.items():
            role = arm.truth.servers.get(node, 'unknown')
            onset = arm.truth.server_onset.get(node, 0.0)
            buckets: Dict[int, List[Tuple[float, float]]] = defaultdict(list)
            for t_rel, trust, anomaly in series:
                buckets[int(t_rel // bucket_s)].append((trust, anomaly))
            for idx in sorted(buckets):
                vals = buckets[idx]
                trust = statistics.fmean(v[0] for v in vals)
                anomaly = statistics.fmean(v[1] for v in vals)
                rows.append(
                    f'{arm.name},{node},{role},{onset:g},'
                    f'{idx * bucket_s:g},{trust:.6f},{anomaly:.6f},{len(vals)}'
                )
    path.write_text('\n'.join(rows) + '\n')


def write_per_node_csv(path: Path, arms: List[ArmResult]) -> None:
    rows = [
        'arm,node,role,attack_start_s,final_trust,final_anomaly,routes,'
        'tasks_success,tasks_timeout,tasks_failure,anomaly_events,'
        'quarantines,first_detection_s,first_quarantine_s'
    ]
    for arm in arms:
        for node in sorted(arm.truth.servers, key=_srv_sort_key):
            out = arm.node_outcomes.get(node, {})
            rows.append(','.join(str(x) for x in [
                arm.name, node, arm.truth.servers[node],
                f'{arm.truth.server_onset.get(node, 0.0):g}',
                f'{arm.final_trust.get(node, float("nan")):.6f}',
                f'{arm.final_anomaly.get(node, float("nan")):.6f}',
                arm.routes_per_node.get(node, 0),
                out.get('success', 0), out.get('timeout', 0), out.get('failure', 0),
                arm.anomaly_nodes.get(node, 0),
                arm.quarantined_nodes.get(node, 0),
                (f'{arm.first_detection_s[node]:.2f}'
                 if node in arm.first_detection_s else ''),
                (f'{arm.first_quarantine_s[node]:.2f}'
                 if node in arm.first_quarantine_s else ''),
            ]))
    path.write_text('\n'.join(rows) + '\n')


def summary_dict(arm: ArmResult) -> Dict[str, Any]:
    return {
        'arm': arm.name,
        'arm_label': arm.arm_label,
        'events_path': arm.events_path,
        'strategy': arm.strategy,
        'duration_s': arm.duration_s,
        'tasks_total': arm.tasks_total,
        'tasks_success': arm.tasks_success,
        'tasks_timeout': arm.tasks_timeout,
        'tasks_failure': arm.tasks_failure,
        'pdr': arm.pdr,
        'throughput_tps': arm.throughput_tps,
        'mean_latency_ms': arm.mean_latency_ms,
        'p95_latency_ms': arm.p95_latency_ms,
        'jain_routes': arm.jain_routes,
        'routes_total': arm.routes_total,
        'route_denied': arm.route_denied,
        'honest_device_availability': arm.honest_device_availability(),
        'starved_honest_devices': arm.starved_devices(),
        'contaminated_identities': arm.contaminated_identities(),
        'anomaly_events': arm.anomaly_events,
        'quarantine_events': arm.quarantine_events,
        'detections_unactioned': arm.detections_unactioned,
        'reroute_events': arm.reroute_events,
        'auth_denied': arm.auth_denied,
        'auth_denied_kinds': dict(arm.auth_denied_kinds),
        'auth_admitted': arm.auth_admitted,
        'spoof_admitted': arm.spoof_admitted,
        'bad_cred_admitted': sorted(set(arm.bad_cred_admitted)),
        'blocks': arm.blocks,
        'final_trust': arm.final_trust,
        'final_anomaly': arm.final_anomaly,
        'first_detection_s': arm.first_detection_s,
        'first_quarantine_s': arm.first_quarantine_s,
        'ground_truth': {
            'servers': arm.truth.servers,
            'server_onset': arm.truth.server_onset,
            'devices': arm.truth.devices,
            'bound_to': arm.truth.bound_to,
        },
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--baseline', default='data/base_events.jsonl')
    parser.add_argument(
        '--treatment', default=None,
        help='The zero-trust arm\'s recording (data/events.jsonl). Optional: '
             'omit to score the baseline on its own.',
    )
    parser.add_argument('--out-dir', default='data/comparison')
    parser.add_argument('--bucket-s', type=float, default=DEFAULT_BUCKET_S)
    args = parser.parse_args(argv)

    if not Path(args.baseline).exists():
        print(f"No baseline recording at {args.baseline}.")
        print("Run it first:  sudo -E python3 -m base_model.run_base")
        return 1

    base = score_arm('baseline', args.baseline)
    treat = None
    if args.treatment:
        if not Path(args.treatment).exists():
            print(f"No treatment recording at {args.treatment} -- scoring the "
                  f"baseline alone.")
        else:
            treat = score_arm('zero_trust', args.treatment)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    text = format_comparison(base, treat)
    print(text)
    (out_dir / 'comparison.txt').write_text(text + '\n')

    arms = [base] + ([treat] if treat else [])
    write_trust_series_csv(out_dir / 'trust_series.csv', arms, args.bucket_s)
    write_per_node_csv(out_dir / 'per_node.csv', arms)
    (out_dir / 'comparison.json').write_text(
        json.dumps([summary_dict(a) for a in arms], indent=2, default=str) + '\n'
    )

    print()
    print(f"Written to {out_dir}/:")
    print("  comparison.txt    comparison.json    trust_series.csv    per_node.csv")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
