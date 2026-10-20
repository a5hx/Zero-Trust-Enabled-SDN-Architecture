"""Phase 2a: what the switches already witness, measured offline.

Novelty plan, direction 2 ("two-witness verification"). The controller has
three independent accounts of what each edge server did:

* the CLIENTS' -- every task outcome a device reports (`report` events), which
  is what the trust score and the honesty check's completion count run on;
* the SWITCHES' -- OpenFlow counters on each connection's two VIP rules
  (`flow_stats` events): bytes into the server, bytes back out of it;
* the SERVER's own -- its /status self-report.

Until now only the first and third were used; `controller/flow_stats.py`
collects the second for the dashboard's packet animation and nothing else.
Every recording since the dashboard existed carries it, so whether the switch
account is precise enough to verify the client account can be answered from
the 110 archived runs, with no new run. That is this module.

Per connection (one VIP rule pair, installed on the client's ingress switch,
keyed by the client's IP and source port) it takes the largest packet and
byte count seen on each rule -- rules are polled once a second and live 10 s
after their last packet, so every connection is seen -- and classifies it:

* served      the server sent at least a full response back
              (`rev_bytes >= SERVED_MIN_BYTES`);
* unanswered  requests went in, nothing came back (`rev_bytes == 0`);
* partial     anything else.

Then, per server per run and per window, it compares:

* switch-served connections against client-reported successes -- the
  client/switch check. They should agree for an honest server; a client that
  under-reports a server (badmouthing) or a switch that hides traffic breaks
  the agreement;
* the unanswered fraction -- a drop tell that needs no client report;
* the server's own edge-switch port 1 byte count against the sum of its VIP
  rule bytes on every client switch -- flow conservation between switches
  (SPHINX-style). The residual should be the controller's /status polls and
  ARP, roughly constant.

Run:
    python3 -m evaluation.witness_offline data/runs --arms treat,liarfix3_honest
    python3 -m evaluation.witness_offline data/runs --out data/witness_2026-10-20
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import statistics
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

#: An honest task's response, as the switch sees it: 6 packets / 598 bytes
#: (measured on every honest server of treat r01). Anything at least this
#: large is a full response.
SERVED_MIN_BYTES = 400
TASK_PRIORITIES = (300, 460)        # VIP pair; 460 = probation trial
WINDOW_S = 10.0

_MATCH_KV = re.compile(r'(\w+)=([^,]+)')


@dataclass
class Conn:
    node: str
    client_ip: str
    client_port: str
    first_ts: float
    fwd_pk: int = 0
    fwd_by: int = 0
    rev_pk: int = 0
    rev_by: int = 0

    @property
    def kind(self) -> str:
        if self.rev_by >= SERVED_MIN_BYTES:
            return 'served'
        if self.rev_by == 0:
            return 'unanswered'
        return 'partial'


@dataclass
class RunWitness:
    arm: str
    run: str
    vip: str = ''
    truth: Dict[str, str] = field(default_factory=dict)          # srv -> attack
    onset: Dict[str, float] = field(default_factory=dict)
    t0: Optional[float] = None
    conns: Dict[Tuple[str, str], Conn] = field(default_factory=dict)
    reports: List[Tuple[float, str, str]] = field(default_factory=list)  # (t, node, status)
    # node -> [(t, port1 tx+rx bytes cumulative)] on that server's own edge switch
    port_bytes: Dict[str, List[Tuple[float, int]]] = field(default_factory=lambda: defaultdict(list))


def _parse_match(match: str) -> Dict[str, str]:
    return dict(_MATCH_KV.findall(match))


def load_run(path: str, arm: str = '') -> RunWitness:
    rw = RunWitness(arm=arm, run=Path(path).name)
    dpid_server: Dict[int, str] = {}
    with open(path) as fh:
        for line in fh:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            ts = ev.get('ts')
            if rw.t0 is None and ts is not None:
                rw.t0 = float(ts)
            t = ev.get('type')
            if t == 'topology':
                g = ev.get('graph', {})
                for n in g.get('nodes', []):
                    if n.get('kind') == 'server':
                        rw.truth[n['id']] = n.get('attack', 'none') or 'none'
                        if n.get('attack_start_s') is not None:
                            rw.onset[n['id']] = float(n['attack_start_s'])
                # Each server is alone on edge switch s_i (dpid i+1), port 1
                # (simulation/topology.py; port numbers follow addLink order).
                for sid in rw.truth:
                    dpid_server[int(sid[3:]) + 1] = sid
                rw.vip = str(g.get('vip') or ev.get('vip') or '').split(':')[0]   # recorded as 'ip:port'
            elif t == 'report':
                rel = float(ts) - rw.t0
                rw.reports.append((rel, ev.get('node'), ev.get('status')))
            elif t == 'flow_stats':
                rel = float(ts) - rw.t0
                for r in ev.get('rules', []):
                    if not r.get('is_vip') or r.get('priority') not in TASK_PRIORITIES:
                        continue
                    m = _parse_match(r.get('match', ''))
                    if m.get('ipv4_dst') == rw.vip:
                        key, fwd = (m['ipv4_src'], m['tcp_src']), True
                    else:
                        key, fwd = (m.get('ipv4_dst', ''), m.get('tcp_dst', '')), False
                    c = rw.conns.get(key)
                    if c is None or c.node != r.get('node'):
                        # A client port reused for a later connection: new conn.
                        if c is not None:
                            rw.conns[(key[0], key[1] + f'#{rel:.0f}')] = c
                        c = rw.conns[key] = Conn(r.get('node'), key[0], key[1], rel)
                    if fwd:
                        c.fwd_pk = max(c.fwd_pk, r.get('packets', 0))
                        c.fwd_by = max(c.fwd_by, r.get('bytes', 0))
                    else:
                        c.rev_pk = max(c.rev_pk, r.get('packets', 0))
                        c.rev_by = max(c.rev_by, r.get('bytes', 0))
            elif t == 'port_stats':
                sid = dpid_server.get(ev.get('dpid'))
                if sid is None:
                    continue
                for p in ev.get('ports', []):
                    if p.get('port') == 1:
                        rw.port_bytes[sid].append(
                            (float(ts) - rw.t0, int(p.get('tx_bytes', 0)) + int(p.get('rx_bytes', 0))))
    return rw


@dataclass
class ServerWitness:
    arm: str
    run: str
    node: str
    attack: str
    client_success: int
    client_timeout: int
    switch_served: int
    switch_unanswered: int
    switch_partial: int
    rule_bytes: int
    port_bytes: Optional[int]

    @property
    def honest(self) -> bool:
        return self.attack == 'none'

    @property
    def agreement(self) -> Optional[float]:
        """switch-served / client-reported successes (1.0 = the two agree)."""
        return self.switch_served / self.client_success if self.client_success else None

    @property
    def unanswered_frac(self) -> Optional[float]:
        n = self.switch_served + self.switch_unanswered + self.switch_partial
        return self.switch_unanswered / n if n else None


def summarise_run(rw: RunWitness, t_from: float = 0.0, t_to: float = 1e18) -> List[ServerWitness]:
    out = []
    for node in sorted(rw.truth, key=lambda s: int(s[3:])):
        cs = [c for c in rw.conns.values() if c.node == node and t_from <= c.first_ts < t_to]
        reps = [(s) for (t, n, s) in rw.reports if n == node and t_from <= t < t_to]
        pb = [b for (t, b) in rw.port_bytes.get(node, []) if t_from <= t < t_to]
        out.append(ServerWitness(
            arm=rw.arm, run=rw.run, node=node, attack=rw.truth[node],
            client_success=sum(1 for s in reps if s == 'success'),
            client_timeout=sum(1 for s in reps if s == 'timeout'),
            switch_served=sum(1 for c in cs if c.kind == 'served'),
            switch_unanswered=sum(1 for c in cs if c.kind == 'unanswered'),
            switch_partial=sum(1 for c in cs if c.kind == 'partial'),
            rule_bytes=sum(c.fwd_by + c.rev_by for c in cs),
            port_bytes=(max(pb) - min(pb)) if len(pb) >= 2 else None,
        ))
    return out


def windows(rw: RunWitness, width: float = WINDOW_S) -> Iterable[Tuple[float, List[ServerWitness]]]:
    end = max([c.first_ts for c in rw.conns.values()] or [0.0])
    t = 0.0
    while t < end:
        yield t, summarise_run(rw, t, t + width)
        t += width


def _q(xs: Sequence[float], q: float) -> float:
    xs = sorted(xs)
    pos = q * (len(xs) - 1)
    lo = int(pos)
    hi = min(lo + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (pos - lo)


def report(runs: Sequence[RunWitness], width: float = WINDOW_S) -> str:
    lines = []
    w = lines.append
    whole = [sw for rw in runs for sw in summarise_run(rw)]
    honest = [sw for sw in whole if sw.honest and sw.agreement is not None]
    w(f'SWITCH WITNESS, OFFLINE  ({len(runs)} runs)')
    w('=' * 78)
    w('Whole-run agreement, switch-served / client-reported successes, honest servers:')
    ag = [sw.agreement for sw in honest]
    if ag:
        w(f'  n={len(ag)} server-runs  median {statistics.median(ag):.4f}  '
          f'p5 {_q(ag, .05):.4f}  p95 {_q(ag, .95):.4f}  min {min(ag):.4f}  max {max(ag):.4f}')
    # Per-window agreement on honest servers (the noise a live check must tolerate).
    wa, wd = [], []
    for rw in runs:
        for t, sws in windows(rw, width):
            for sw in sws:
                if sw.honest and sw.client_success >= 5:
                    wa.append(sw.agreement)
                    wd.append(sw.switch_served - sw.client_success)
    if wa:
        w(f'Per {width:.0f} s window, honest servers with >= 5 successes:')
        w(f'  n={len(wa)} windows  agreement median {statistics.median(wa):.3f}  '
          f'p1 {_q(wa, .01):.3f}  p99 {_q(wa, .99):.3f}')
        w(f'  served - reported: median {statistics.median(wd):+.1f}  '
          f'p1 {_q(wd, .01):+.1f}  p99 {_q(wd, .99):+.1f}')
    w('')
    w('Unanswered fraction (requests in, zero bytes back), by ground truth:')
    by_attack: Dict[str, List[float]] = defaultdict(list)
    for sw in whole:
        if sw.unanswered_frac is not None:
            by_attack[sw.attack].append(sw.unanswered_frac)
    for att, xs in sorted(by_attack.items()):
        w(f'  {att:<10} n={len(xs):3d}  median {statistics.median(xs):.4f}  '
          f'min {min(xs):.4f}  max {max(xs):.4f}')
    w('')
    w('Flow conservation, own edge-switch port 1 bytes vs VIP-rule bytes (honest):')
    res = [(sw.port_bytes - sw.rule_bytes) / max(1.0, (sw.port_bytes or 1))
           for sw in whole if sw.honest and sw.port_bytes]
    if res:
        w(f'  residual share of port bytes: median {statistics.median(res):.3f}  '
          f'p5 {_q(res, .05):.3f}  p95 {_q(res, .95):.3f}')
    return '\n'.join(lines)


FIELDS = ('arm', 'run', 'node', 'attack', 'client_success', 'client_timeout',
          'switch_served', 'switch_unanswered', 'switch_partial', 'rule_bytes', 'port_bytes')


def discover(root: Path, arms: Optional[Sequence[str]]) -> Dict[str, List[Path]]:
    out = {}
    for d in sorted(p for p in root.iterdir() if p.is_dir()):
        if arms and d.name not in arms:
            continue
        files = sorted(d.glob('r[0-9][0-9].jsonl'))
        if files:
            out[d.name] = files
    return out


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('root', nargs='?', default='data/runs')
    p.add_argument('--arms', default=None)
    p.add_argument('--window-s', type=float, default=WINDOW_S)
    p.add_argument('--out', default=None, help='directory for summary.txt + per_server.csv')
    args = p.parse_args(argv)
    arms = args.arms.split(',') if args.arms else None
    runs = [load_run(str(f), arm) for arm, fs in discover(Path(args.root), arms).items() for f in fs]
    if not runs:
        print('no recordings found', file=sys.stderr)
        return 1
    text = report(runs, args.window_s)
    print(text)
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / 'summary.txt').write_text(text + '\n')
        with open(out / 'per_server.csv', 'w', newline='') as fh:
            wr = csv.DictWriter(fh, fieldnames=FIELDS)
            wr.writeheader()
            for rw in runs:
                for sw in summarise_run(rw):
                    wr.writerow({k: getattr(sw, k) for k in FIELDS})
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
