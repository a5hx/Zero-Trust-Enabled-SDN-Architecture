"""Score repeated live runs per arm and report between-run confidence intervals.

    python3 -m evaluation.replicates data/runs [--out-dir data/replicates]

Reads every ``data/runs/<arm>/rNN.jsonl`` written by ``tools/run_replicates.sh``
(any ``*.jsonl`` directly inside an arm directory counts as one run), scores
each with ``base_model.compare.score_arm`` -- the same scorer the single-run
comparison uses, so a replicate figure and a single-run figure can never mean
different things -- and adds the per-attacker measurements the single-run
table does not carry:

``score_cross_s``   seconds from onset until T first drops under theta. This is
                    the score rail on its own, measured in EVERY arm, including
                    ones that never act on it. It is the direct test of the
                    score-floor proposition.
``contain_s``       seconds from onset to the first quarantine (acting arms).
``rail``            which rail the first quarantine could have fired on:
                    ``score`` (T < theta only), ``gate`` (A-bar >= gate only,
                    and the arm enforces that rail), ``both``, or
                    ``indeterminate``. An arm with the anomaly rail switched
                    off is always ``score`` -- its gate cannot act, whatever
                    A-bar reads.
``t_at_q``          T at the first quarantine.

Continuous metrics are reported as mean, SD and a two-sided 95% Student-t
interval over runs (n-1 df). Yes/no outcomes (isolated at all, crossed theta at
all) are reported as k/n with a Wilson 95% interval, never as a mean of 0/1s
with a t-interval, which is wrong at the n this is used at. Times are reported
only over the runs where the event happened, with k/n alongside, because a run
where it never happened has no time to average -- substituting the run length
would invent one.

The unit of replication is the RUN. Per-task or per-route observations inside
one run are not independent replicates and are never pooled across runs here.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from base_model.compare import ArmResult, score_arm, stream_events
from evaluation.interval_report import jain_fairness_index

DEFAULT_THETA = 0.3
DEFAULT_GATE = 0.5

#: Arm directories in report order; anything else found is appended after.
ARM_ORDER = ('base', 'scoreonly', 'treat')
ARM_LABELS = {
    'base': 'control (static, no enforcement)',
    'scoreonly': 'score-only enforcement',
    'treat': 'score + anomaly gate (full)',
}


# --------------------------------------------------------------------------- #
# Interval estimators                                                          #
# --------------------------------------------------------------------------- #
def t_interval(values: Sequence[float], conf: float = 0.95
               ) -> Tuple[Optional[float], Optional[float], Optional[float], Optional[float]]:
    """(mean, sd, lo, hi). sd/lo/hi are None below n=2 -- one run has no spread."""
    vals = [float(v) for v in values if v is not None]
    if not vals:
        return None, None, None, None
    mean = statistics.fmean(vals)
    if len(vals) < 2:
        return mean, None, None, None
    sd = statistics.stdev(vals)
    from scipy.stats import t as student_t
    half = student_t.ppf(0.5 + conf / 2, len(vals) - 1) * sd / math.sqrt(len(vals))
    return mean, sd, mean - half, mean + half


def wilson(k: int, n: int, conf: float = 0.95) -> Tuple[Optional[float], Optional[float]]:
    """Wilson score interval for k successes in n trials."""
    if n == 0:
        return None, None
    from scipy.stats import norm
    z = norm.ppf(0.5 + conf / 2)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


# --------------------------------------------------------------------------- #
# Per-run extraction                                                           #
# --------------------------------------------------------------------------- #
@dataclass
class AttackerRun:
    node: str
    attack: str
    onset_s: float
    score_cross_s: Optional[float] = None
    contain_s: Optional[float] = None
    rail: Optional[str] = None
    t_at_q: Optional[float] = None
    a_at_q: Optional[float] = None
    min_trust: Optional[float] = None
    #: Quarantines BEFORE the configured onset: the node was still honest, so
    #: these are false positives, not fast containment. Run 9 has one (srv8 at
    #: onset-4.9 s, packet-drop tell on a 0.50 timeout rate) that
    #: availability_report prints as "contained -4.9s after onset".
    pre_onset_quarantines: int = 0


@dataclass
class RunResult:
    arm: str
    path: str
    duration_s: Optional[float]
    metrics: Dict[str, Optional[float]] = field(default_factory=dict)
    attackers: Dict[str, AttackerRun] = field(default_factory=dict)
    honest_quarantined: List[str] = field(default_factory=list)
    rail_enforced: Optional[bool] = None
    #: The isolation threshold this run was ACTUALLY run with, read from the
    #: recording's topology event. Falls back to --theta only for recordings
    #: that do not carry it (the control arm, which never enforces one).
    theta: float = DEFAULT_THETA
    theta_recorded: bool = False
    #: Lowest T each honest server reached over the whole run. In a theta sweep
    #: this is the cost side: a honest node whose T dips under theta is
    #: quarantined, whatever the attackers are doing.
    honest_min_trust: Dict[str, float] = field(default_factory=dict)


def recorded_thresholds(path: str) -> Dict[str, Any]:
    """`thresholds` from the recording's topology event ({} if absent)."""
    for ev in stream_events(path):
        if ev.get('type') == 'topology':
            return dict((ev.get('graph') or {}).get('thresholds') or {})
    return {}


def attribute_rail(rail_enforced: Optional[bool],
                   t_at_q: Optional[float], a_at_q: Optional[float],
                   theta: float, gate: Optional[float]) -> str:
    """Which rail could have caused this quarantine: 'score', 'gate', 'both',
    or 'indeterminate'.

    Not simply which threshold the recorded values clear. Two corrections:

    * An arm with the anomaly rail switched off cannot quarantine on the gate
      at all, whatever A-bar reads, so the score fired by construction. The
      score-only arm's grayhole quarantines all carry A-bar ~ 1.0 next to
      T < theta and were previously credited to a gate that was not acting.
    * When both conditions hold the honest answer is 'both'. Crediting the
      gate there overstates it -- the score would have isolated that node
      unaided.

    ``rail_enforced=None`` means the recording predates the flag, which is the
    enforced arm.
    """
    enforced = True if rail_enforced is None else bool(rail_enforced)
    by_score = t_at_q is not None and float(t_at_q) < theta
    by_gate = (enforced and a_at_q is not None and gate is not None
               and float(a_at_q) >= float(gate))
    if by_score and by_gate:
        return 'both'
    if by_gate:
        return 'gate'
    if by_score:
        return 'score'
    # Neither threshold is clear at the recorded instant -- the sample
    # straddles the transition. Say so rather than guess.
    return 'indeterminate'


def _quarantines(path: str) -> Dict[str, List[Dict[str, Any]]]:
    """node -> every quarantine event, in order, each with t_rel. score_arm
    keeps only the first time; containment needs the first one AFTER onset,
    and the rail attribution needs the T and A-bar that event carried."""
    out: Dict[str, List[Dict[str, Any]]] = {}
    t0: Optional[float] = None
    for ev in stream_events(path):
        ts = ev.get('ts')
        if t0 is None and ts is not None:
            t0 = float(ts)          # same anchor as score_arm: the first event
        if ev.get('type') != 'quarantine':
            continue
        node = ev.get('node')
        if node:
            row = dict(ev)
            row['t_rel'] = float(ts) - t0 if (ts is not None and t0 is not None) else None
            out.setdefault(node, []).append(row)
    return out


def score_run(arm: str, path: str, theta: float = DEFAULT_THETA) -> RunResult:
    res: ArmResult = score_arm(arm, path)
    run = RunResult(arm=arm, path=path, duration_s=res.duration_s)
    thresholds = recorded_thresholds(path)
    if thresholds.get('isolation') is not None:
        theta = float(thresholds['isolation'])
        run.theta_recorded = True
    run.theta = theta
    truth = res.truth
    honest = truth.honest_servers
    attackers = truth.attacker_servers

    honest_routes = [res.routes_per_node.get(n, 0) for n in honest]
    attacker_routes = sum(res.routes_per_node.get(n, 0) for n in attackers)
    routed = sum(res.routes_per_node.values())

    run.metrics = {
        'duration_s': res.duration_s,
        'pdr': res.pdr,
        'throughput_tps': res.throughput_tps,
        'mean_latency_ms': res.mean_latency_ms,
        'p95_latency_ms': res.p95_latency_ms,
        'tasks_total': float(res.tasks_total),
        'timeouts': float(res.tasks_timeout),
        'honest_device_availability': res.honest_device_availability(),
        'starved_honest_devices': float(len(res.starved_devices())),
        'jain_all': res.jain_routes,
        'jain_honest': jain_fairness_index(honest_routes) if honest_routes else None,
        'attacker_route_share': attacker_routes / routed if routed else None,
        'quarantine_events': float(res.quarantine_events),
        'anomaly_events': float(res.anomaly_events),
        'spoof_admitted': float(len(res.spoof_admitted)),
    }

    quarantines = _quarantines(path) if res.quarantine_events else {}
    for evs in quarantines.values():
        if 'anomaly_rail_enforced' in evs[0]:
            run.rail_enforced = bool(evs[0]['anomaly_rail_enforced'])
            break

    for node in attackers:
        onset = truth.server_onset.get(node, 0.0)
        a = AttackerRun(node=node, attack=truth.servers[node], onset_s=onset)
        series = res.trust_series.get(node, [])
        post = [(t, tr, an) for (t, tr, an) in series if t >= onset]
        if post:
            a.min_trust = min(tr for _, tr, _ in post)
            for t, tr, _ in post:
                if tr < theta:
                    a.score_cross_s = t - onset
                    break
        qs = [q for q in quarantines.get(node, []) if q.get('t_rel') is not None]
        a.pre_onset_quarantines = sum(1 for q in qs if q['t_rel'] < onset)
        q = next((q for q in qs if q['t_rel'] >= onset), None)
        if q is not None:
            a.contain_s = q['t_rel'] - onset
            a.t_at_q = q.get('trust')
            a.a_at_q = q.get('anomaly')
            gate = q.get('anomaly_gate', DEFAULT_GATE)
            a.rail = attribute_rail(
                rail_enforced=run.rail_enforced,
                t_at_q=a.t_at_q, a_at_q=a.a_at_q, theta=theta, gate=gate)
        run.attackers[node] = a

    for node in honest:
        series = res.trust_series.get(node, [])
        if series:
            run.honest_min_trust[node] = min(tr for _, tr, _ in series)
    run.metrics['honest_min_trust'] = (min(run.honest_min_trust.values())
                                       if run.honest_min_trust else None)

    run.honest_quarantined = sorted(n for n in honest if n in quarantines)
    run.metrics['honest_false_quarantines'] = float(len(run.honest_quarantined))
    run.metrics['pre_onset_quarantines'] = float(
        sum(a.pre_onset_quarantines for a in run.attackers.values()))
    run.metrics.update(_classification_and_containment(path))
    run.metrics.update(_device_split(path))
    return run


def _device_split(path: str) -> Dict[str, Optional[float]]:
    """Service seen by HONEST devices, kept apart from the attacking ones.

    A run-wide latency mean mixes in the attackers' own requests. Under the
    flood throttle (controller/flood_response.py) the flooder's tasks take
    seconds -- its excess connection attempts are dropped and TCP retries them
    -- which doubled the run-wide mean in the first throttle run while honest
    devices were unchanged. So honest-device latency and success are reported
    on their own, beside how much service the flooding device(s) still got and
    whether the throttle ever touched an honest device.
    """
    attack_of: Dict[str, str] = {}
    ip_attack: Dict[str, str] = {}
    lat: List[float] = []
    honest_total = honest_ok = 0
    flood_served = 0
    throttles = 0
    throttled_ips: set = set()
    with open(path) as fh:
        for line in fh:
            if '"topology"' in line[:80] and not attack_of:
                e = json.loads(line)
                if e.get('type') == 'topology':
                    for n in (e.get('graph') or e).get('nodes', []):
                        if n.get('kind') == 'iot':
                            attack_of[n['id']] = n.get('attack', 'none')
                            if n.get('ip'):
                                ip_attack[n['ip']] = n.get('attack', 'none')
                continue
            if '"report"' in line[:60]:
                e = json.loads(line)
                if e.get('type') != 'report':
                    continue
                attack = attack_of.get(e.get('device'), 'none')
                if attack == 'none':
                    honest_total += 1
                    if e.get('status') == 'success':
                        honest_ok += 1
                        if e.get('latency_ms') is not None:
                            lat.append(float(e['latency_ms']))
                elif attack == 'flood' and e.get('status') == 'success':
                    flood_served += 1
            elif '"client_throttled"' in line[:80]:
                e = json.loads(line)
                if e.get('type') == 'client_throttled':
                    throttles += 1
                    throttled_ips.add(e.get('client_ip'))
    lat.sort()
    honest_throttled = sum(1 for ip in throttled_ips if ip_attack.get(ip, 'none') == 'none')
    return {
        'honest_mean_latency_ms': statistics.mean(lat) if lat else None,
        'honest_p95_latency_ms': lat[min(len(lat) - 1, int(len(lat) * 0.95))] if lat else None,
        'honest_success_rate': honest_ok / honest_total if honest_total else None,
        'flood_tasks_served': float(flood_served),
        'client_throttles': float(throttles),
        'honest_clients_throttled': float(honest_throttled),
    }


def _classification_and_containment(path: str) -> Dict[str, Optional[float]]:
    """The attack_report and availability_report headline figures, from the
    same modules the single-run reports print them with. Together they are
    what the containment-vs-attribution claim is a claim about, so every run
    carries both and the claim can be tested across runs rather than argued
    from a hand-picked pair."""
    from evaluation import attack_report, availability_report
    from evaluation.nfr_report import load_events

    events = load_events(path)
    if not attack_report.ground_truth(events):
        return {}
    subjects = attack_report.score_run(events)
    attacks = [r for r in subjects if r.truth != attack_report.NO_ATTACK]
    honest = [r for r in subjects if r.truth == attack_report.NO_ATTACK]
    avail = availability_report.compute(events)
    return {
        'attacks_exact': float(sum(r.correct for r in attacks)),
        'attacks_family': float(sum(r.family_correct for r in attacks)),
        'attacks_total': float(len(attacks)),
        'honest_mislabelled': float(sum(not r.correct for r in honest)),
        'class_accuracy': (sum(r.correct for r in subjects) / len(subjects)
                           if subjects else None),
        'honest_node_eligible': avail.honest_availability,
        'attacker_isolated_frac': avail.attacker_containment,
    }


# --------------------------------------------------------------------------- #
# Aggregation                                                                  #
# --------------------------------------------------------------------------- #
def discover(root: Path) -> Dict[str, List[Path]]:
    arms: Dict[str, List[Path]] = {}
    for d in sorted(p for p in root.iterdir() if p.is_dir()):
        runs = sorted(d.glob('*.jsonl'))
        if runs:
            arms[d.name] = runs
    ordered = {a: arms[a] for a in ARM_ORDER if a in arms}
    ordered.update({a: r for a, r in arms.items() if a not in ordered})
    return ordered


METRIC_ROWS = (
    ('pdr', 'PDR', 100.0, '.2f', '%'),
    ('throughput_tps', 'throughput', 1.0, '.2f', ' tps'),
    ('mean_latency_ms', 'mean latency (success)', 1.0, '.1f', ' ms'),
    ('p95_latency_ms', 'p95 latency (success)', 1.0, '.1f', ' ms'),
    ('timeouts', 'timeouts', 1.0, '.1f', ''),
    ('honest_device_availability', 'honest-device availability', 100.0, '.2f', '%'),
    ('starved_honest_devices', 'starved honest devices (<50%)', 1.0, '.2f', ''),
    ('jain_honest', 'Jain, honest servers', 1.0, '.3f', ''),
    ('jain_all', 'Jain, full roster', 1.0, '.3f', ''),
    ('attacker_route_share', 'share of routes to attackers', 100.0, '.2f', '%'),
    ('honest_false_quarantines', 'honest servers ever quarantined', 1.0, '.2f', ''),
    ('honest_min_trust', 'lowest T of any honest server', 1.0, '.3f', ''),
    ('pre_onset_quarantines', 'attackers quarantined BEFORE onset', 1.0, '.2f', ''),
    ('honest_node_eligible', 'honest-node availability (eligible time)', 100.0, '.2f', '%'),
    ('attacker_isolated_frac', 'mean attacker time isolated', 100.0, '.2f', '%'),
    ('attacks_exact', 'attacks classified exactly (of 8)', 1.0, '.2f', ''),
    ('attacks_family', 'attacks in the right family (of 8)', 1.0, '.2f', ''),
    ('honest_mislabelled', 'honest subjects mislabelled', 1.0, '.2f', ''),
    ('class_accuracy', 'classification accuracy, all subjects', 100.0, '.2f', '%'),
    ('honest_mean_latency_ms', 'honest devices: mean latency', 1.0, '.1f', ' ms'),
    ('honest_p95_latency_ms', 'honest devices: p95 latency', 1.0, '.1f', ' ms'),
    ('honest_success_rate', 'honest devices: task success', 100.0, '.2f', '%'),
    ('flood_tasks_served', 'tasks served to flooding device(s)', 1.0, '.1f', ''),
    ('client_throttles', 'client throttles applied', 1.0, '.2f', ''),
    ('honest_clients_throttled', 'honest devices ever throttled', 1.0, '.2f', ''),
    ('duration_s', 'run length', 1.0, '.1f', ' s'),
)


#: Metrics with a physical range. A t-interval knows nothing about it and at
#: n=3..5 routinely reaches past it (T > 1, Jain > 1, a negative count); such an
#: end is clipped and marked with '*' rather than printed as if attainable.
BOUNDS = {
    'pdr': (0.0, 1.0), 'honest_device_availability': (0.0, 1.0),
    'jain_honest': (0.0, 1.0), 'jain_all': (0.0, 1.0),
    'attacker_route_share': (0.0, 1.0), 'trust': (0.0, 1.0),
    'timeouts': (0.0, None), 'starved_honest_devices': (0.0, None),
    'honest_false_quarantines': (0.0, None),
    'honest_node_eligible': (0.0, 1.0), 'attacker_isolated_frac': (0.0, 1.0),
    'attacks_exact': (0.0, 8.0), 'attacks_family': (0.0, 8.0),
    'honest_mislabelled': (0.0, None), 'pre_onset_quarantines': (0.0, None), 'class_accuracy': (0.0, 1.0),
    'honest_min_trust': (0.0, 1.0),
    'honest_success_rate': (0.0, 1.0), 'honest_mean_latency_ms': (0.0, None),
    'honest_p95_latency_ms': (0.0, None), 'flood_tasks_served': (0.0, None),
    'client_throttles': (0.0, None), 'honest_clients_throttled': (0.0, None),
}


def _clip(x: float, lo: Optional[float], hi: Optional[float], spec: str) -> str:
    if lo is not None and x < lo:
        return f'{lo:{spec}}*'
    if hi is not None and x > hi:
        return f'{hi:{spec}}*'
    return f'{x:{spec}}'


def _fmt_ci(values: Sequence[Optional[float]], scale: float, spec: str, suffix: str,
            bounds: Tuple[Optional[float], Optional[float]] = (None, None)) -> str:
    vals = [v * scale for v in values if v is not None]
    mean, sd, lo, hi = t_interval(vals)
    if mean is None:
        return 'not measured'
    if sd is None:
        return f'{mean:{spec}}{suffix} (n=1, no CI)'
    b_lo = bounds[0] * scale if bounds[0] is not None else None
    b_hi = bounds[1] * scale if bounds[1] is not None else None
    return (f'{mean:{spec}}{suffix}  [{_clip(lo, b_lo, b_hi, spec)}, '
            f'{_clip(hi, b_lo, b_hi, spec)}]  sd {sd:{spec}}  n={len(vals)}')


def _fmt_prop(k: int, n: int) -> str:
    lo, hi = wilson(k, n)
    if lo is None:
        return 'n=0'
    return f'{k}/{n}  [{lo * 100:.0f}%, {hi * 100:.0f}%]'


def _fmt_times(values: Sequence[Optional[float]], n: int) -> str:
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return f'never (0/{n})'
    med = statistics.median(vals)
    base = f'{len(vals)}/{n} runs; median {med:.1f} s, range {vals[0]:.1f}-{vals[-1]:.1f} s'
    if len(vals) >= 2:
        mean, _sd, lo, hi = t_interval(vals)
        base += f'; mean {mean:.1f} [{lo:.1f}, {hi:.1f}]'
    return base


def format_report(results: Dict[str, List[RunResult]], theta: float,
                  what_if: Sequence[float] = ()) -> str:
    out: List[str] = []
    w = out.append
    w('REPLICATED LIVE RUNS -- between-run 95% intervals')
    w('=' * 78)
    w('Unit of replication: one live run. Continuous: mean [95% t-CI] sd n.')
    w('Yes/no outcomes: k/n [95% Wilson]. Times: over runs where it happened.')
    w("'*' = CI end clipped to the metric's physical range.")
    w('')
    for arm, runs in results.items():
        w(f'  {arm:<10} {arm_label(arm)}: {len(runs)} run(s)')
        for r in runs:
            flag = '' if r.rail_enforced is None else f'  anomaly_rail_enforced={r.rail_enforced}'
            th = f'theta={r.theta:.2f}' + ('' if r.theta_recorded else ' (not recorded; --theta)')
            w(f'      {Path(r.path).name}  {r.duration_s or 0:.1f} s  {th}{flag}')
    w('')

    w('SERVICE AND FAIRNESS')
    w('-' * 78)
    for key, label, scale, spec, suffix in METRIC_ROWS:
        w(f'{label}')
        for arm, runs in results.items():
            w(f'    {arm:<10} {_fmt_ci([r.metrics.get(key) for r in runs], scale, spec, suffix, BOUNDS.get(key, (None, None)))}')
    w('')

    attackers = sorted({n for runs in results.values() for r in runs for n in r.attackers},
                       key=lambda s: (len(s), s))
    w(f'PER ATTACKER  (each run scored against its own recorded theta; '
      f'--theta {theta} only where none is recorded)')
    w('-' * 78)
    for node in attackers:
        attack = next(r.attackers[node].attack for runs in results.values()
                      for r in runs if node in r.attackers)
        w(f'{node} ({attack})')
        for arm, runs in results.items():
            rows = [r.attackers[node] for r in runs if node in r.attackers]
            n = len(rows)
            if not n:
                continue
            crossed = sum(1 for a in rows if a.score_cross_s is not None)
            isolated = sum(1 for a in rows if a.contain_s is not None)
            w(f'    {arm:<10} score crossed theta : {_fmt_prop(crossed, n)}')
            w(f'    {"":<10}   time to cross     : {_fmt_times([a.score_cross_s for a in rows], n)}')
            w(f'    {"":<10} min T after onset   : '
              f'{_fmt_ci([a.min_trust for a in rows], 1.0, ".3f", "", BOUNDS["trust"])}')
            if isolated or arm != 'base':
                w(f'    {"":<10} quarantined         : {_fmt_prop(isolated, n)}')
                w(f'    {"":<10}   containment       : {_fmt_times([a.contain_s for a in rows], n)}')
                rails: Dict[str, int] = {}
                for a in rows:
                    if a.rail:
                        rails[a.rail] = rails.get(a.rail, 0) + 1
                if rails:
                    w(f'    {"":<10}   rail that fired   : '
                      + ', '.join(f'{k} {v}/{isolated}' for k, v in sorted(rails.items())))
                    w(f'    {"":<10}   T at quarantine   : '
                      f'{_fmt_ci([a.t_at_q for a in rows], 1.0, ".3f", "", BOUNDS["trust"])}')
        w('')

    w('CONTAINMENT vs ATTRIBUTION  (acting arms, one point per run)')
    w('-' * 78)
    pts = [(r.metrics.get('attacker_isolated_frac'), r.metrics.get('attacks_exact'), arm)
           for arm, runs in results.items() if arm != 'base' for r in runs]
    pts = [p for p in pts if p[0] is not None and p[1] is not None]
    for iso, exact, arm in sorted(pts):
        w(f'    {arm:<10} isolated {iso * 100:5.1f}%   exact labels {exact:.0f}/8')
    rho = spearman(pts)
    if rho is None:
        w('    Spearman rho: needs >= 4 runs with varying values')
    else:
        w(f'    Spearman rho(isolation, exact labels) = {rho[0]:+.3f}, '
          f'p = {rho[1]:.3f}, n = {len(pts)}')
        w('    A trade predicts rho < 0. With n this small, only a clearly '
          'negative rho with p < 0.05 supports it; anything else does not.')
    w('')
    if what_if:
        out.extend(format_what_if(results, what_if))
    return '\n'.join(out)


def format_what_if(results: Dict[str, List[RunResult]],
                   thetas: Sequence[float]) -> List[str]:
    """PREDICTION, from each arm's recorded trust series, of what a live run at
    each candidate theta would do: in how many runs each attacker's post-onset
    T, and any honest server's T, dipped under it.

    Exact only up to the first dip in a run -- a run at a higher theta is the
    same run until something first crosses it, and different afterwards
    (quarantine moves load, and probation changes what T is fed). So this is
    the prediction to write down BEFORE a live sweep, not a substitute for it.
    """
    out = ['WHAT-IF THETA  (prediction from recorded T, not a measurement)', '-' * 78]
    for arm, runs in results.items():
        if not runs:
            continue
        n = len(runs)
        attackers = sorted({a for r in runs for a in r.attackers}, key=lambda s: (len(s), s))
        out.append(f'{arm}  (n={n}, recorded at theta '
                   f'{",".join(sorted({f"{r.theta:.2f}" for r in runs}))})')
        head = '    theta  ' + ''.join(f'{a:>14}' for a in attackers) + f'{"any honest":>14}'
        out.append(head)
        for th in thetas:
            cells = []
            for a in attackers:
                k = sum(1 for r in runs if a in r.attackers
                        and r.attackers[a].min_trust is not None
                        and r.attackers[a].min_trust < th)
                cells.append(f'{k}/{n}'.rjust(14))
            k_h = sum(1 for r in runs
                      if r.honest_min_trust and min(r.honest_min_trust.values()) < th)
            out.append(f'    {th:5.2f}  ' + ''.join(cells) + f'{k_h}/{n}'.rjust(14))
        out.append('')
    out.append('Cells: runs in which T went under that theta at least once '
               '(attackers after onset; honest nodes at any time, incl. warm-up).')
    out.append('')
    return out


def arm_label(arm: str) -> str:
    if arm in ARM_LABELS:
        return ARM_LABELS[arm]
    parent, _, t = arm.rpartition('_t')
    if parent in ARM_LABELS and t.isdigit():
        return f'{ARM_LABELS[parent]}, theta {int(t) / 100:.2f}'
    return ''


def spearman(pts: Sequence[Tuple[float, float, str]]) -> Optional[Tuple[float, float]]:
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    if len(pts) < 4 or len(set(xs)) < 2 or len(set(ys)) < 2:
        return None
    from scipy.stats import spearmanr
    r = spearmanr(xs, ys)
    return float(r.correlation), float(r.pvalue)


PER_RUN_FIELDS = (('arm', 'run', 'duration_s', 'theta', 'rail_enforced')
                  + tuple(k for k, *_ in METRIC_ROWS if k != 'duration_s')
                  + ('tasks_total', 'attacks_total', 'quarantine_events',
                     'anomaly_events', 'spoof_admitted', 'honest_quarantined'))
ATTACKER_FIELDS = ('arm', 'run', 'node', 'attack', 'onset_s', 'score_cross_s', 'min_trust',
                   'contain_s', 'rail', 't_at_q', 'a_at_q', 'pre_onset_quarantines')


def write_csvs(out_dir: Path, results: Dict[str, List[RunResult]]) -> None:
    with open(out_dir / 'per_run.csv', 'w', newline='') as f:
        wr = csv.DictWriter(f, fieldnames=PER_RUN_FIELDS)
        wr.writeheader()
        for arm, runs in results.items():
            for r in runs:
                row = {k: r.metrics.get(k) for k in PER_RUN_FIELDS if k in r.metrics}
                row.update(arm=arm, run=Path(r.path).name, duration_s=r.duration_s,
                           theta=r.theta, rail_enforced=r.rail_enforced,
                           honest_quarantined=' '.join(r.honest_quarantined))
                wr.writerow(row)
    with open(out_dir / 'per_attacker.csv', 'w', newline='') as f:
        wr = csv.DictWriter(f, fieldnames=ATTACKER_FIELDS)
        wr.writeheader()
        for arm, runs in results.items():
            for r in runs:
                for a in r.attackers.values():
                    wr.writerow(dict(arm=arm, run=Path(r.path).name, **{
                        k: getattr(a, k) for k in ATTACKER_FIELDS if hasattr(a, k)}))


def check_arm_labels(results: Dict[str, List[RunResult]]) -> List[str]:
    """A recording filed under the wrong arm is the one mistake this layout
    invites. Where the recording states its rail setting, hold it to the dir."""
    problems = []
    for arm, runs in results.items():
        parent, _, t = arm.rpartition('_t')
        if not (parent and t.isdigit() and len(t) == 3):
            parent, t = arm, ''
        for r in runs:
            if t:
                want = int(t) / 100
                if not r.theta_recorded:
                    problems.append(f'{r.path}: filed as {arm} but records no theta')
                elif abs(r.theta - want) > 1e-9:
                    problems.append(f'{r.path}: filed as {arm} (theta {want:.2f}) '
                                    f'but ran at theta {r.theta:.2f}')
            if r.rail_enforced is None:
                continue
            if parent == 'scoreonly' and r.rail_enforced:
                problems.append(f'{r.path}: filed as {arm} but the gate was enforced')
            if parent == 'treat' and not r.rail_enforced:
                problems.append(f'{r.path}: filed as {arm} but the gate was NOT enforced')
    return problems


def main(argv: Optional[Iterable[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('root', nargs='?', default='data/runs',
                    help='directory holding one sub-directory of recordings per arm')
    ap.add_argument('--out-dir', default='data/replicates')
    ap.add_argument('--theta', type=float, default=DEFAULT_THETA,
                    help='fallback theta for recordings that do not record one')
    ap.add_argument('--what-if', default='',
                    help='comma-separated thetas to PREDICT from recorded T, '
                         'e.g. 0.35,0.40,0.45,0.50')
    ap.add_argument('--arms', default='',
                    help='comma-separated arm directories to include (default: all)')
    args = ap.parse_args(list(argv) if argv is not None else None)
    what_if = [float(x) for x in args.what_if.split(',') if x.strip()]

    root = Path(args.root)
    arms = discover(root) if root.is_dir() else {}
    if args.arms:
        keep = [a.strip() for a in args.arms.split(',') if a.strip()]
        arms = {a: arms[a] for a in keep if a in arms}
    if not arms:
        print(f'No recordings under {root}/<arm>/*.jsonl -- see tools/run_replicates.sh')
        return 1

    results = {arm: [score_run(arm, str(p), args.theta) for p in paths]
               for arm, paths in arms.items()}
    problems = check_arm_labels(results)
    for p in problems:
        print('MISFILED:', p, file=sys.stderr)

    text = format_report(results, args.theta, what_if)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'summary.txt').write_text(text + '\n')
    write_csvs(out, results)
    print(text)
    print(f'\nwrote {out}/summary.txt, per_run.csv, per_attacker.csv')
    return 2 if problems else 0


if __name__ == '__main__':
    raise SystemExit(main())
