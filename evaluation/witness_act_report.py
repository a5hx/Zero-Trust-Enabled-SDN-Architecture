"""Score the switch witness when its verdicts act (controller.witness.act).

Per run, from the recording:
  * the witness's own verdicts (evaluation/witness_report.py): when each guilty
    party was first blamed, and every honest party ever blamed;
  * server actions: the misbehaving server's first quarantine after its onset,
    whether the anomaly that fired carried the witness signal, how much of
    the post-onset time it spent quarantined, and how many connections it was
    handed while not quarantined -- the work it could spoil;
  * client actions: reports charged to no server because the witness blamed
    the client (`attribution: witness_discounted`), split into badmouthers'
    and honest clients' (a false discount);
  * honest servers: every quarantine whose anomaly carried the witness signal
    (a false action), and their lowest trust after the first onset.

Times are relative to the first event, like every other scorer here.

    python3 -m evaluation.witness_act_report data/runs --arms wa_forge_observe,wa_forge_act
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from controller.attack_classifier import SIG_WITNESS
from evaluation.replicates import quarantine_intervals, t_interval, wilson
from evaluation.witness_report import WitnessRun, discover
from evaluation.witness_report import score as witness_score


@dataclass
class ActRun:
    arm: str
    run: str
    witness: WitnessRun
    acting: bool = False
    server_onset: Dict[str, float] = field(default_factory=dict)
    badmouthers: Dict[str, float] = field(default_factory=dict)
    quarantines: Dict[str, List[float]] = field(default_factory=dict)
    recovered: Dict[str, List[float]] = field(default_factory=dict)
    witness_anomaly: Dict[str, List[float]] = field(default_factory=dict)
    routes: List[tuple] = field(default_factory=list)
    discounted: Dict[str, int] = field(default_factory=dict)
    first_discount: Dict[str, float] = field(default_factory=dict)
    trust_low: Dict[str, float] = field(default_factory=dict)   # after the first onset
    servers: List[str] = field(default_factory=list)
    end: float = 0.0

    @property
    def first_onset(self) -> Optional[float]:
        on = list(self.server_onset.values()) + list(self.badmouthers.values())
        return min(on) if on else None

    def contained_s(self, node: str) -> Optional[float]:
        on = self.server_onset.get(node)
        qs = [q for q in self.quarantines.get(node, []) if on is not None and q >= on]
        return min(qs) - on if qs else None

    def contained_by_witness(self, node: str) -> bool:
        """Did the witness signal fire for `node` at or just before its first
        post-onset quarantine?"""
        c = self.contained_s(node)
        if c is None:
            return False
        tq = self.server_onset[node] + c
        return any(tq - 2.0 <= t <= tq + 0.5 for t in self.witness_anomaly.get(node, []))

    def quarantined_share(self, node: str) -> Optional[float]:
        on = self.server_onset.get(node)
        if on is None or self.end <= on:
            return None
        iv = quarantine_intervals(self.quarantines.get(node, []), self.recovered.get(node, []), self.end)
        return sum(max(0.0, b - max(a, on)) for a, b in iv) / (self.end - on)

    def exposure(self, node: str) -> Optional[int]:
        """Connections routed to `node` after its onset (the controller never
        routes to a quarantined server, so these are the unquarantined ones)."""
        on = self.server_onset.get(node)
        if on is None:
            return None
        return sum(1 for t, n in self.routes if n == node and t >= on)

    @property
    def false_witness_actions(self) -> List[str]:
        return sorted(n for n in self.witness_anomaly if n not in self.server_onset)

    @property
    def false_discounts(self) -> int:
        return sum(k for d, k in self.discounted.items() if d not in self.badmouthers)


def score(path: str, arm: str = '') -> ActRun:
    r = ActRun(arm=arm, run=Path(path).name, witness=witness_score(path, arm))
    t0 = None
    with open(path) as fh:
        for line in fh:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            ts = ev.get('ts')
            if t0 is None and ts is not None:
                t0 = float(ts)
            t = (float(ts) - t0) if ts is not None and t0 is not None else 0.0
            r.end = max(r.end, t)
            kind = ev.get('type')
            if kind == 'topology':
                for n in (ev.get('graph') or {}).get('nodes', []):
                    if n.get('kind') == 'server':
                        r.servers.append(n['id'])
                        if (n.get('attack') or 'none') != 'none':
                            r.server_onset[n['id']] = float(n.get('attack_start_s') or 0.0)
                    elif n.get('kind') == 'iot' and n.get('attack') == 'badmouth':
                        r.badmouthers[n['id']] = float(n.get('attack_start_s') or 0.0)
            elif kind == 'quarantine' and ev.get('node'):
                r.quarantines.setdefault(ev['node'], []).append(t)
            elif kind == 'recovered' and ev.get('node'):
                r.recovered.setdefault(ev['node'], []).append(t)
            elif kind == 'anomaly' and SIG_WITNESS in (ev.get('signals') or {}):
                r.acting = True
                r.witness_anomaly.setdefault(ev['node'], []).append(t)
            elif kind == 'route' and ev.get('chosen'):
                r.routes.append((t, ev['chosen']))
            elif kind == 'report' and ev.get('attribution') == 'witness_discounted':
                r.acting = True
                d = ev.get('device')
                r.discounted[d] = r.discounted.get(d, 0) + 1
                r.first_discount.setdefault(d, t)
            elif kind == 'node_status':
                on = r.first_onset
                if on is not None and t >= on:
                    for n, v in (ev.get('nodes') or {}).items():
                        if n not in r.server_onset and v.get('trust') is not None:
                            r.trust_low[n] = min(r.trust_low.get(n, 1.0), float(v['trust']))
    return r


def _ci(values: Sequence[float], fmt: str = '{:.1f}') -> str:
    vals = [float(v) for v in values if v is not None]
    if not vals:
        return 'n/a'
    mean, _sd, lo, hi = t_interval(vals)
    ci = f' [{fmt.format(lo)}, {fmt.format(hi)}]' if lo is not None else ''
    return f'{fmt.format(mean)}{ci}  n={len(vals)}'


def _prop(k: int, n: int) -> str:
    lo, hi = wilson(k, n)
    return f'{k}/{n} [{lo * 100:.0f}%, {hi * 100:.0f}%]'


def report(results: Dict[str, List[ActRun]]) -> str:
    out = ['SWITCH WITNESS, ACTING', '=' * 78]
    for arm, runs in results.items():
        n = len(runs)
        out.append(f'{arm}: {n} run(s)')
        for node in sorted({s for r in runs for s in r.server_onset}):
            blamed = [r.witness.detect_s(f'server:{node}') for r in runs]
            got = sorted(c for c in (r.contained_s(node) for r in runs) if c is not None)
            out.append(f'    {node} (misbehaves from its onset)')
            out.append(f'        blamed by the witness        : {_prop(sum(b is not None for b in blamed), n)}'
                       + (f'; median {statistics.median([b for b in blamed if b is not None]):.1f} s'
                          if any(b is not None for b in blamed) else ''))
            out.append(f'        quarantined after onset      : {_prop(len(got), n)}'
                       + (f'; median {statistics.median(got):.1f} s' if got else ''))
            out.append(f'        ... with the witness signal  : {_prop(sum(r.contained_by_witness(node) for r in runs), n)}')
            out.append(f'        share of time quarantined    : {_ci([100 * (r.quarantined_share(node) or 0) for r in runs])} %')
            out.append(f'        connections after onset      : {_ci([r.exposure(node) for r in runs], "{:.0f}")}')
        for dev in sorted({d for r in runs for d in r.badmouthers}):
            k = [r.discounted.get(dev, 0) for r in runs]
            firsts = [r.first_discount[dev] - r.badmouthers[dev] for r in runs if dev in r.first_discount]
            out.append(f'    {dev} (badmouths from its onset)')
            out.append(f'        reports discounted per run   : {_ci(k, "{:.0f}")}'
                       + (f'; first a median {statistics.median(firsts):.1f} s after onset' if firsts else ''))
        out.append(f'    honest clients\' reports discounted: {_ci([r.false_discounts for r in runs], "{:.1f}")}'
                   f'  (runs with any: {sum(1 for r in runs if r.false_discounts)}/{n})')
        out.append(f'    honest servers hit by the witness signal: {_ci([len(r.false_witness_actions) for r in runs], "{:.1f}")}'
                   f'  (runs with any: {sum(1 for r in runs if r.false_witness_actions)}/{n})')
        out.append(f'    honest parties the witness blamed: {_ci([len(r.witness.false_parties) for r in runs], "{:.1f}")}')
        lows = [min(r.trust_low.values()) for r in runs if r.trust_low]
        if lows:
            out.append(f'    lowest honest-server trust after onset: {_ci(lows, "{:.3f}")}')
    return '\n'.join(out)


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('root', nargs='?', default='data/runs')
    p.add_argument('--arms', default=None)
    p.add_argument('--out', default=None)
    args = p.parse_args(argv)
    found = discover(Path(args.root), args.arms.split(',') if args.arms else None)
    if not found:
        print('no recordings found', file=sys.stderr)
        return 1
    text = report({a: [score(str(f), a) for f in fs] for a, fs in found.items()})
    print(text)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
