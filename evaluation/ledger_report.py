"""Score the replicas' re-verification of trust records against ground truth
(Phase 6, blockchain/verifier.py).

Reads, per run:
  * ground truth from the `topology` event: `controller_forgery` (which server,
    which mode, from when -- controller/forgery.py), `ledger_verify`, and each
    server's own attack;
  * every trust record the controller wrote: the charged `report` events (a
    re-steered, uncharged report writes no record);
  * every record the replicas refused: `ledger_rejected`;
  * every block: `block`, with how many records it kept and its commit time;
  * quarantines and the switch witness's verdicts, for the forged server.

A rejection is correct when it names the forged server at or after the
forgery's onset; any other is a false rejection. Records the controller wrote
but that are neither in a block nor rejected are "unaccounted": at most the
last partial batch when the run stops, unless something is lost.

Times are relative to the first event (the controller's start), the same
clock the forgery's start_s counts from.

    python3 -m evaluation.ledger_report data/runs --arms lv_honest,lv_forge_score
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from evaluation.replicates import t_interval, wilson
from evaluation.witness_report import discover

#: The forgery starts on the trust state's clock, which starts a moment before
#: the first event; records this close to the onset could fall either side, so
#: they are counted neither as forged nor as honest.
ONSET_SLACK_S = 1.0


@dataclass
class LedgerRun:
    arm: str
    run: str
    verify: bool = False
    forged_node: Optional[str] = None
    forge_mode: Optional[str] = None
    forge_start: float = 0.0
    attack_onset: Dict[str, float] = field(default_factory=dict)
    records: List[tuple] = field(default_factory=list)        # (t, node)
    rejected: List[tuple] = field(default_factory=list)       # (t_record, node, reason)
    kept: int = 0
    blocks: int = 0
    commit_ms: List[float] = field(default_factory=list)
    quarantines: Dict[str, List[float]] = field(default_factory=dict)
    witness_blamed: Dict[str, float] = field(default_factory=dict)
    routes: List[tuple] = field(default_factory=list)          # (t, chosen)
    reject_delay_s: List[float] = field(default_factory=list)  # record -> rejection

    def route_share(self, node: str, after: bool) -> Optional[float]:
        """Share of routing decisions that chose `node` before or after the
        forgery's onset (the slack around it excluded)."""
        lo, hi = self.forge_start - ONSET_SLACK_S, self.forge_start + ONSET_SLACK_S
        sel = [c for t, c in self.routes if (t >= hi if after else t < lo)]
        return sum(1 for c in sel if c == node) / len(sel) if sel else None

    def _ambiguous(self, t: float, node: str) -> bool:
        return node == self.forged_node and abs(t - self.forge_start) < ONSET_SLACK_S

    def _is_target(self, t: float, node: str) -> bool:
        return (node == self.forged_node and t >= self.forge_start
                and not self._ambiguous(t, node))

    @property
    def target_records(self) -> int:
        return sum(1 for t, n in self.records if self._is_target(t, n))

    @property
    def caught(self) -> int:
        return sum(1 for t, n, _ in self.rejected if self._is_target(t, n))

    @property
    def false_rejections(self) -> List[tuple]:
        return [r for r in self.rejected
                if not self._is_target(r[0], r[1]) and not self._ambiguous(r[0], r[1])]

    @property
    def unaccounted(self) -> int:
        return len(self.records) - self.kept - len(self.rejected)

    def contained_s(self, node: str) -> Optional[float]:
        on = self.attack_onset.get(node)
        qs = [q for q in self.quarantines.get(node, []) if on is not None and q >= on]
        return min(qs) - on if qs else None

    def witness_s(self, node: str) -> Optional[float]:
        on = self.attack_onset.get(node)
        t = self.witness_blamed.get(node)
        return t - on if t is not None and on is not None and t >= on else None


def score(path: str, arm: str = '') -> LedgerRun:
    r = LedgerRun(arm=arm, run=Path(path).name)
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
                g = ev.get('graph') or {}
                r.verify = bool(g.get('ledger_verify'))
                f = g.get('controller_forgery')
                if f:
                    r.forged_node, r.forge_mode = f['node'], f['mode']
                    r.forge_start = float(f.get('start_s', 0.0))
                for n in g.get('nodes', []):
                    if n.get('kind') == 'server' and (n.get('attack') or 'none') != 'none':
                        r.attack_onset[n['id']] = float(n.get('attack_start_s') or 0.0)
            elif kind == 'report':
                if ev.get('charged') is not False and ev.get('node'):
                    r.records.append((t, ev['node']))
            elif kind == 'ledger_rejected':
                uts = ev.get('update_ts')
                tr = float(uts) - t0 if uts is not None and t0 is not None else t
                r.rejected.append((tr, ev.get('node'), ev.get('reason')))
                r.reject_delay_s.append(t - tr)
            elif kind == 'block' and ev.get('accepted'):
                r.blocks += 1
                r.kept += int(ev.get('records') if ev.get('records') is not None
                              else ev.get('num_updates') or 0)
                if ev.get('commit_ms') is not None:
                    r.commit_ms.append(float(ev['commit_ms']))
            elif kind == 'quarantine' and ev.get('node'):
                r.quarantines.setdefault(ev['node'], []).append(t)
            elif kind == 'route' and ev.get('chosen'):
                r.routes.append((t, ev['chosen']))
            elif kind == 'witness':
                for s in ev.get('servers') or []:
                    r.witness_blamed.setdefault(s, t)
    return r


def _ci(values: Sequence[float], fmt: str = '{:.1f}') -> str:
    if not values:
        return 'n/a'
    mean, _sd, lo, hi = t_interval([float(v) for v in values])
    ci = f' [{fmt.format(lo)}, {fmt.format(hi)}]' if lo is not None else ''
    return f'{fmt.format(mean)}{ci}  n={len(values)}'


def _prop(k: int, n: int) -> str:
    lo, hi = wilson(k, n)
    return f'{k}/{n} [{lo * 100:.1f}%, {hi * 100:.1f}%]' if n else '0/0'


def _pct(values: List[float], q: float) -> float:
    v = sorted(values)
    return v[min(len(v) - 1, int(q * len(v)))]


def report(results: Dict[str, List[LedgerRun]]) -> str:
    out = ['LEDGER RE-VERIFICATION (Phase 6)', '=' * 78]
    for arm, runs in results.items():
        n = len(runs)
        verify = any(r.verify for r in runs)
        forged = sorted({(r.forged_node, r.forge_mode) for r in runs if r.forged_node})
        out.append(f'{arm}: {n} run(s), replicas verify: {"yes" if verify else "no"}'
                   + (f', controller forges {forged}' if forged else ''))
        out.append(f'    trust records written per run    : {_ci([len(r.records) for r in runs], "{:.0f}")}')
        out.append(f'    records in blocks per run        : {_ci([r.kept for r in runs], "{:.0f}")}')
        out.append(f'    records unaccounted per run      : {_ci([r.unaccounted for r in runs], "{:.0f}")}'
                   f'  (max {max(r.unaccounted for r in runs)})')
        if forged:
            tgt = sum(r.target_records for r in runs)
            got = sum(r.caught for r in runs)
            out.append(f'    forged-server records rejected   : {_prop(got, tgt)}  (pooled records)')
            out.append(f'      per run                        : '
                       + ', '.join(f'{r.caught}/{r.target_records}' for r in runs))
            node = forged[0][0]
            pre = [x for x in (r.route_share(node, False) for r in runs) if x is not None]
            post = [x for x in (r.route_share(node, True) for r in runs) if x is not None]
            out.append(f'    {node} route share before onset    : {_ci([100 * x for x in pre], "{:.2f}")} %')
            out.append(f'    {node} route share after onset     : {_ci([100 * x for x in post], "{:.2f}")} %')
        delays = [d for r in runs for d in r.reject_delay_s]
        if delays:
            out.append(f'    record -> rejection reported     : median {statistics.median(delays):.2f} s, '
                       f'p95 {_pct(delays, 0.95):.2f} s')
        fr = [len(r.false_rejections) for r in runs]
        out.append(f'    false rejections per run         : {_ci(fr, "{:.1f}")}'
                   f'  (runs with any: {sum(1 for x in fr if x)}/{n})')
        for r in runs:
            reasons = sorted({x[2] for x in r.false_rejections})
            if r.false_rejections:
                out.append(f'      {r.run}: {len(r.false_rejections)} {reasons}')
        ms = [m for r in runs for m in r.commit_ms]
        if ms:
            out.append(f'    commit time per block            : median {statistics.median(ms):.1f} ms, '
                       f'p95 {_pct(ms, 0.95):.1f} ms  ({len(ms)} blocks)')
        for node in sorted({s for r in runs for s in r.attack_onset}):
            cont = sorted(c for c in (r.contained_s(node) for r in runs) if c is not None)
            wit = sorted(w for w in (r.witness_s(node) for r in runs) if w is not None)
            out.append(f'    {node} (misbehaves from its onset)')
            out.append(f'        quarantined by the controller: {_prop(len(cont), n)}'
                       + (f'; median {statistics.median(cont):.1f} s' if cont else ''))
            out.append(f'        blamed by the switch witness : {_prop(len(wit), n)}'
                       + (f'; median {statistics.median(wit):.1f} s' if wit else ''))
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
