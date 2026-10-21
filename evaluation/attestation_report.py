"""Score admission by attestation against ground truth (Phase 4).

Reads the `attestation` events the controller publishes (one per quote, plus
'expired'), the routing decisions, the denials and the quarantines, and the
ground truth the `topology` event carries: which servers run a tampered image
(`tampered: true`) and which misbehave, from when (`attack`, `attack_start_s`).

Per run:
  * admission: when each server was first admitted, and how many connections
    were denied before the whole genuine fleet was in;
  * refusals: every non-attested verdict, split into the tampered servers
    (should be refused) and the genuine ones (a false refusal);
  * exposure: how many connections each misbehaving server was handed after
    its onset and before it was first quarantined -- the work it could spoil
    before behaviour caught it -- and how long that took;
  * the cost: verification time per quote.

Times are relative to the first event, like every other scorer here.

    python3 -m evaluation.attestation_report data/runs --arms att_on_clean,att_on_tampered
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
from evaluation.witness_report import discover


@dataclass
class AttestRun:
    arm: str
    run: str
    servers: List[str] = field(default_factory=list)
    tampered: List[str] = field(default_factory=list)
    onset: Dict[str, float] = field(default_factory=dict)        # misbehaving -> onset
    attesting: bool = False
    first_admitted: Dict[str, float] = field(default_factory=dict)
    refusals: List[Tuple[float, str, str, str, List[str]]] = field(default_factory=list)
    quotes: int = 0
    verify_ms: List[float] = field(default_factory=list)
    routes: Dict[str, int] = field(default_factory=dict)
    route_times: List[Tuple[float, str]] = field(default_factory=list)
    denied: List[float] = field(default_factory=list)
    first_quarantine: Dict[str, List[float]] = field(default_factory=dict)

    @property
    def genuine(self) -> List[str]:
        return [s for s in self.servers if s not in self.tampered]

    @property
    def false_refusals(self) -> List[Tuple[float, str, str, str, List[str]]]:
        return [r for r in self.refusals if r[1] not in self.tampered]

    @property
    def fleet_admitted_s(self) -> Optional[float]:
        g = self.genuine
        if not self.attesting or not all(s in self.first_admitted for s in g):
            return None
        return max(self.first_admitted[s] for s in g)

    @property
    def denied_before_fleet(self) -> int:
        t = self.fleet_admitted_s
        return sum(1 for d in self.denied if t is None or d <= t)

    def contained_s(self, node: str) -> Optional[float]:
        on = self.onset.get(node)
        qs = [q for q in self.first_quarantine.get(node, []) if on is not None and q >= on]
        return min(qs) - on if qs else None

    def exposure(self, node: str) -> Optional[int]:
        """Connections routed to `node` after its onset and before it was first
        quarantined (or the end of the run)."""
        on = self.onset.get(node)
        if on is None:
            return None
        c = self.contained_s(node)
        end = on + c if c is not None else float('inf')
        return sum(1 for t, n in self.route_times if n == node and on <= t < end)


def score(path: str, arm: str = '') -> AttestRun:
    r = AttestRun(arm=arm, run=Path(path).name)
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
            kind = ev.get('type')
            if kind == 'topology':
                for n in (ev.get('graph') or {}).get('nodes', []):
                    if n.get('kind') != 'server':
                        continue
                    r.servers.append(n['id'])
                    if n.get('tampered'):
                        r.tampered.append(n['id'])
                    if (n.get('attack') or 'none') != 'none':
                        r.onset[n['id']] = float(n.get('attack_start_s') or 0.0)
            elif kind == 'attestation':
                r.attesting = True
                node, verdict = ev.get('node'), ev.get('verdict')
                if verdict == 'attested':
                    r.quotes += 1
                    r.first_admitted.setdefault(node, t)
                elif verdict != 'expired':
                    r.quotes += 1
                if verdict != 'attested':
                    r.refusals.append((t, node, verdict, ev.get('detail', ''),
                                       list(ev.get('mismatched') or [])))
                if ev.get('verify_ms') is not None and verdict != 'expired':
                    r.verify_ms.append(float(ev['verify_ms']))
            elif kind == 'route':
                chosen = ev.get('chosen')
                if chosen:
                    r.routes[chosen] = r.routes.get(chosen, 0) + 1
                    r.route_times.append((t, chosen))
            elif kind == 'route_denied':
                r.denied.append(t)
            elif kind == 'quarantine' and ev.get('node'):
                r.first_quarantine.setdefault(ev['node'], []).append(t)
    return r


def _ci(values: Sequence[float], fmt: str = '{:.1f}') -> str:
    if not values:
        return 'n/a'
    mean, _sd, lo, hi = t_interval([float(v) for v in values])
    ci = f' [{fmt.format(lo)}, {fmt.format(hi)}]' if lo is not None else ''
    return f'{fmt.format(mean)}{ci}  n={len(values)}'


def _prop(k: int, n: int) -> str:
    lo, hi = wilson(k, n)
    return f'{k}/{n} [{lo * 100:.0f}%, {hi * 100:.0f}%]'


def report(results: Dict[str, List[AttestRun]]) -> str:
    out = ['ADMISSION BY ATTESTATION (Phase 4)', '=' * 78]
    for arm, runs in results.items():
        n = len(runs)
        att = [r for r in runs if r.attesting]
        out.append(f'{arm}: {n} run(s), attestation {"ON" if att else "off"}')
        if att:
            fleet = [r.fleet_admitted_s for r in att]
            out.append(f'    genuine fleet admitted in        : {_prop(sum(f is not None for f in fleet), len(att))}'
                       f'; by t = {_ci([f for f in fleet if f is not None])} s')
            out.append(f'    first server admitted at         : '
                       f'{_ci([min(r.first_admitted.values()) for r in att if r.first_admitted])} s')
            out.append(f'    connections denied before then   : {_ci([r.denied_before_fleet for r in att])}')
            out.append(f'    genuine servers falsely refused  : runs with any {_prop(sum(bool(r.false_refusals) for r in att), len(att))}')
            for r in att:
                for t, node, verdict, detail, _m in r.false_refusals:
                    out.append(f'      {r.run}: {node} {verdict} at {t:.1f} s {detail}')
            ms = sorted(v for r in att for v in r.verify_ms)
            if ms:
                p95 = ms[min(len(ms) - 1, int(0.95 * len(ms)))]
                out.append(f'    quotes judged per run            : {_ci([r.quotes for r in att])}')
                out.append(f'    verify time per quote            : median {statistics.median(ms):.2f} ms, p95 {p95:.2f} ms')
        out.append(f'    connections denied, whole run    : {_ci([len(r.denied) for r in runs])}')
        for node in sorted({s for r in runs for s in r.tampered}):
            refused = [r for r in att if any(x[1] == node for x in r.refusals)]
            admitted = [r for r in runs if node in r.first_admitted]
            out.append(f'    {node} (tampered image)')
            if att:
                reasons = sorted({f'{x[2]} {x[4]}' for r in att for x in r.refusals if x[1] == node})
                out.append(f'        refused                      : {_prop(len(refused), len(att))}  {reasons}')
            out.append(f'        ever admitted                : {_prop(len(admitted), n)}')
            out.append(f'        connections routed to it     : {_ci([r.routes.get(node, 0) for r in runs], "{:.0f}")}')
        for node in sorted({s for r in runs for s in r.onset}):
            cont = [r.contained_s(node) for r in runs]
            got = sorted(c for c in cont if c is not None)
            out.append(f'    {node} (misbehaves from its onset)')
            out.append(f'        quarantined after onset      : {_prop(len(got), n)}'
                       + (f'; median {statistics.median(got):.1f} s, range {got[0]:.1f}-{got[-1]:.1f} s' if got else ''))
            out.append(f'        connections before contained : {_ci([r.exposure(node) for r in runs], "{:.0f}")}')
            if att:
                passed = [r for r in att if node in r.first_admitted]
                out.append(f'        passed attestation           : {_prop(len(passed), len(att))}')
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
