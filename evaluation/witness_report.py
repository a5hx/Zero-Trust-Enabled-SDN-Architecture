"""Score the switch witness's live verdicts against ground truth (Phase 2d).

Reads the `witness` events controller/switch_witness.py publishes, and the
ground truth the `topology` event carries:
  * servers whose attack drops work (drop / blackhole / grayhole) -- the only
    server attacks the witness is meant to see; a liar that serves is the
    honesty check's job;
  * switches with `attack: switch_hide` (frames servers) or `switch_cover`
    (covers a dropper -- by design NOT blamed on the switch: its lie is
    absorbed by seeing the server through the other switches);
  * devices with `attack: badmouth`.

Per run: which guilty parties were blamed, how long after their onset, and
every honest party ever blamed (a false accusation), with how long it stayed
blamed. Times are relative to the first event, like every other scorer here.

    python3 -m evaluation.witness_report data/runs --arms wit_control,wit_drop
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from evaluation.replicates import t_interval, wilson

DROP_ATTACKS = ('drop', 'blackhole', 'grayhole')


@dataclass
class WitnessRun:
    arm: str
    run: str
    guilty: Dict[str, float] = field(default_factory=dict)      # party -> onset
    exempt: List[str] = field(default_factory=list)            # liars not in scope (cover)
    first_blamed: Dict[str, float] = field(default_factory=dict)
    blamed_s: Dict[str, float] = field(default_factory=dict)
    end: float = 0.0

    @property
    def false_parties(self) -> List[str]:
        return sorted(p for p in self.first_blamed if p not in self.guilty and p not in self.exempt)

    def detect_s(self, party: str) -> Optional[float]:
        t = self.first_blamed.get(party)
        on = self.guilty.get(party)
        return None if t is None or on is None or t < on else t - on


def _party_names(v: Dict) -> List[str]:
    return ([f'server:{s}' for s in v.get('servers', [])]
            + [f'switch:{d}' for d in v.get('switches', [])]
            + [f'client:{c}' for c in v.get('clients', [])])


def score(path: str, arm: str = '') -> WitnessRun:
    wr = WitnessRun(arm=arm, run=Path(path).name)
    t0 = None
    prev_t, prev_set = None, set()
    with open(path) as fh:
        for line in fh:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            ts = ev.get('ts')
            if t0 is None and ts is not None:
                t0 = float(ts)
            t = (float(ts) - t0) if ts is not None else 0.0
            wr.end = max(wr.end, t)
            kind = ev.get('type')
            if kind == 'topology':
                for n in (ev.get('graph') or {}).get('nodes', []):
                    att = n.get('attack') or 'none'
                    onset = float(n.get('attack_start_s') or 0.0)
                    if n.get('kind') == 'server' and att in DROP_ATTACKS:
                        wr.guilty[f"server:{n['id']}"] = onset
                    elif n.get('kind') == 'edge_switch' and att == 'switch_hide':
                        wr.guilty[f"switch:{n['dpid']}"] = onset
                    elif n.get('kind') == 'edge_switch' and att.startswith('switch_'):
                        wr.exempt.append(f"switch:{n['dpid']}")
                    elif n.get('kind') == 'iot' and att == 'badmouth':
                        wr.guilty[f"client:{n['id']}"] = onset
            elif kind == 'witness':
                cur = set(_party_names(ev))
                if prev_t is not None:
                    for p in prev_set:
                        wr.blamed_s[p] = wr.blamed_s.get(p, 0.0) + (t - prev_t)
                for p in cur:
                    wr.first_blamed.setdefault(p, t)
                prev_t, prev_set = t, cur
    if prev_t is not None:
        for p in prev_set:
            wr.blamed_s[p] = wr.blamed_s.get(p, 0.0) + (wr.end - prev_t)
    return wr


def report(results: Dict[str, List[WitnessRun]]) -> str:
    out = ['SWITCH WITNESS, LIVE VERDICTS (observe-only)', '=' * 78]
    for arm, runs in results.items():
        n = len(runs)
        out.append(f'{arm}: {n} run(s)')
        guilty = sorted({p for r in runs for p in r.guilty})
        for p in guilty:
            hits = [r for r in runs if r.detect_s(p) is not None]
            lo, hi = wilson(len(hits), n)
            times = sorted(r.detect_s(p) for r in hits)
            med = f'median {statistics.median(times):.1f} s' if times else 'never'
            out.append(f'    {p:<16} blamed {len(hits)}/{n} [{lo*100:.0f}%, {hi*100:.0f}%]  {med}')
        exempt = sorted({p for r in runs for p in r.exempt})
        for p in exempt:
            k = sum(1 for r in runs if p in r.first_blamed)
            out.append(f'    {p:<16} (covering switch, not in scope) blamed {k}/{n}')
        fp_counts = [len(r.false_parties) for r in runs]
        mean, _sd, lo, hi = t_interval([float(x) for x in fp_counts])
        out.append(f'    honest parties falsely blamed per run: mean {mean:.2f}'
                   + (f' [{max(0.0, lo):.2f}, {hi:.2f}]' if lo is not None else '')
                   + f'  (runs with any: {sum(1 for x in fp_counts if x)}/{n})')
        for r in runs:
            for p in r.false_parties:
                out.append(f'      {r.run}: {p} first at {r.first_blamed[p]:.1f} s, '
                           f'blamed {r.blamed_s.get(p, 0.0):.1f} s')
    return '\n'.join(out)


def discover(root: Path, arms: Optional[Sequence[str]]) -> Dict[str, List[Path]]:
    out = {}
    for d in sorted(p for p in root.iterdir() if p.is_dir()):
        if arms and d.name not in arms:
            continue
        files = sorted(d.glob('r[0-9][0-9].jsonl'))
        if files:
            out[d.name] = files
    if arms:
        out = {a: out[a] for a in arms if a in out}
    return out


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
    raise SystemExit(main())
