"""Turn a `blockchain/raft_timeline.py` recording into one failover figure.

Four panels on one shared time axis, because "RAFT works" is four separate
claims and a reader is entitled to see each one land:

  A  who is leader, over time      -- one lane per replica. The kill removes a
                                      leader; a survivor takes the role.
  B  RAFT term                     -- the term increments exactly once at the
                                      election, and every live replica agrees
                                      on the new number. An election that did
                                      not raise the term would not be RAFT.
  C  replicated ledger length      -- the survivors' chains advance together.
                                      This is the claim that matters for a
                                      TRUST ledger: the record survived the
                                      failure, it did not just keep running.
  D  client-observed commit latency -- service continuity, plus the outage.
                                      Failed attempts are drawn, not dropped.

COLOUR DISCIPLINE
-----------------
No series hue appears here. `base_model/figure_style.py` owns two validated
categorical slots and they mean "baseline" and "zero-trust" everywhere in this
project's figures; spending them on "leader" and "follower" would teach a
reader one meaning on page 4 and contradict it on page 5. Replica identity is
carried by lane position, linestyle and a direct label; role is carried by
value (dark = leader) and hatch. The only colour is the failure wash, used for
the injected kill and for failed commits -- the same meaning it already has in
the attack figures: ground truth the experimenter imposed, not a measurement.

Run:
    python3 -m evaluation.plot_raft_timeline --recording data/raft_timeline.jsonl
"""

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

from base_model.figure_style import (  # noqa: E402
    AXIS, GRIDLINE, INK_MUTED, INK_PRIMARY, INK_SECONDARY, ONSET_WASH,
    ONSET_WASH_ALPHA, SURFACE, style_axes,
)

DEFAULT_RECORDING = 'data/raft_timeline.jsonl'
DEFAULT_OUT_DIR = 'data/figures'
NFR_COMMIT_MS = 500.0

#: Role -> how the lane is drawn. Leader is the darkest value on the panel
#: because it is the one state a reader scans for; `down` wears the failure
#: wash so an absent replica reads as absent rather than as a third role.
ROLE_FILL = {
    'leader': dict(facecolor=INK_PRIMARY, alpha=0.85),
    'candidate': dict(facecolor=INK_MUTED, alpha=0.80, hatch='////'),
    'follower': dict(facecolor=AXIS, alpha=0.50),
    'down': dict(facecolor=ONSET_WASH, alpha=0.16),
}
#: Replica identity in the line panels: value + dash pattern, never hue.
NODE_INK = (INK_PRIMARY, INK_SECONDARY, INK_MUTED)
NODE_DASH = ('-', '--', ':')


@dataclass
class Recording:
    meta: Dict[str, Any] = field(default_factory=dict)
    statuses: List[Dict[str, Any]] = field(default_factory=list)
    commits: List[Dict[str, Any]] = field(default_factory=list)
    kills: List[Dict[str, Any]] = field(default_factory=list)
    elections: List[Dict[str, Any]] = field(default_factory=list)
    restarts: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def nodes(self) -> List[str]:
        if self.meta.get('node_ids'):
            return list(self.meta['node_ids'])
        return sorted({r['node'] for r in self.statuses})

    @property
    def t_end(self) -> float:
        times = [r['t'] for r in self.statuses] + [r['t'] for r in self.commits]
        return max(times) if times else 0.0


def load_recording(path: str) -> Recording:
    rec = Recording()
    bucket = {'status': rec.statuses, 'commit': rec.commits, 'kill': rec.kills,
              'leader_elected': rec.elections, 'restart': rec.restarts}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if row.get('type') == 'meta':
                rec.meta = row
            elif row.get('type') in bucket:
                bucket[row['type']].append(row)
    return rec


def role_runs(statuses: Sequence[Dict[str, Any]], node: str,
              t_end: float) -> List[Tuple[float, float, str, Optional[int]]]:
    """Collapse one node's samples into contiguous (start, end, role, term) runs.

    A run ends where the NEXT sample of the same node was taken, not where the
    last one showing that role was: the transition happened somewhere in
    between, and drawing it at the earlier instant would silently claim a
    precision the polling does not have.
    """
    rows = [r for r in statuses if r['node'] == node]
    rows.sort(key=lambda r: r['t'])
    runs: List[Tuple[float, float, str, Optional[int]]] = []
    for i, row in enumerate(rows):
        end = rows[i + 1]['t'] if i + 1 < len(rows) else t_end
        if runs and runs[-1][2] == row['role'] and runs[-1][3] == row.get('term'):
            start, _, role, term = runs[-1]
            runs[-1] = (start, end, role, term)
        else:
            runs.append((row['t'], end, row['role'], row.get('term')))
    return runs


def leader_changes(statuses: Sequence[Dict[str, Any]]) -> List[Tuple[float, str, Optional[int]]]:
    """Every instant a different node was first observed to be leader."""
    changes: List[Tuple[float, str, Optional[int]]] = []
    for row in sorted(statuses, key=lambda r: r['t']):
        if row['role'] != 'leader':
            continue
        if not changes or changes[-1][1] != row['node']:
            changes.append((row['t'], row['node'], row.get('term')))
    return changes


def commit_outage(commits: Sequence[Dict[str, Any]],
                  kill_t: float) -> Tuple[Optional[float], Optional[float]]:
    """(last successful commit before the kill, first successful one after it).

    Returns Nones where the recording has no such commit, rather than
    substituting the kill instant -- an outage inferred from missing data is
    not an outage that was measured.
    """
    before = [c['t'] for c in commits if c.get('ok') and c['t'] <= kill_t]
    after = [c['t'] for c in commits if c.get('ok') and c['t'] > kill_t]
    return (max(before) if before else None, min(after) if after else None)


def phases(rec: Recording) -> List[Tuple[str, float, float]]:
    """Split the recording at each kill and restart into named intervals.

    Named by how many replicas were RUNNING, because that is the variable the
    reader is being asked to compare across. A phase boundary is an event this
    process caused, so these edges are exact -- unlike the polled roles.
    """
    marks: List[Tuple[float, str]] = [(0.0, f'{len(rec.nodes)} of {len(rec.nodes)} up')]
    for k in rec.kills:
        marks.append((k['t'], f'{len(rec.nodes) - 1} of {len(rec.nodes)} up ({k["node"]} killed)'))
    for r in rec.restarts:
        marks.append((r['t'], f'{len(rec.nodes)} of {len(rec.nodes)} up ({r["node"]} rejoined)'))
    marks.sort()
    return [(label, t, marks[i + 1][0] if i + 1 < len(marks) else rec.t_end)
            for i, (t, label) in enumerate(marks)]


def phase_latencies(rec: Recording) -> List[Tuple[str, float, float, List[float]]]:
    """Successful commit latencies within each phase.

    Half-open intervals, except the last one: its end IS the end of the
    recording, so a commit landing exactly there belongs to it. Excluding it
    would drop a real measurement for no reason other than arithmetic.
    """
    spans = phases(rec)
    out = []
    for i, (label, t0, t1) in enumerate(spans):
        last = i == len(spans) - 1
        lat = [c['latency_ms'] for c in rec.commits
               if c.get('ok') and t0 <= c['t'] and (c['t'] <= t1 if last else c['t'] < t1)]
        out.append((label, t0, t1, lat))
    return out


def summarise(rec: Recording) -> List[str]:
    lines = ['RAFT FAILOVER -- recorded run', '=' * 60]
    poll = rec.meta.get('poll_interval_s')
    ok = [c for c in rec.commits if c.get('ok')]
    lines.append(f'  replicas            : {", ".join(rec.nodes)} '
                 f'(3 OS processes, loopback TCP)')
    lines.append(f'  recording length    : {rec.t_end:.1f} s')
    lines.append(f'  commits attempted   : {len(rec.commits)}')
    lines.append(f'  commits succeeded   : {len(ok)} '
                 f'({100.0 * len(ok) / len(rec.commits):.1f} %)' if rec.commits else '')
    if ok:
        latencies = sorted(c['latency_ms'] for c in ok)
        mean = sum(latencies) / len(latencies)
        verdict = 'PASS' if latencies[-1] < NFR_COMMIT_MS else 'FAIL'
        lines.append(f'  commit latency      : mean {mean:.1f} ms / '
                     f'median {latencies[len(latencies) // 2]:.1f} ms / '
                     f'max {latencies[-1]:.1f} ms  (<{NFR_COMMIT_MS:.0f} ms NFR: {verdict})')

    if len(rec.kills) + len(rec.restarts) > 0:
        lines.append('')
        lines.append('  commit latency by phase (successful commits only):')
        for label, t0, t1, lat in phase_latencies(rec):
            if not lat:
                lines.append(f'    {label:<28} t={t0:5.1f}-{t1:5.1f} s   no successful commits')
                continue
            ordered = sorted(lat)
            lines.append(
                f'    {label:<28} t={t0:5.1f}-{t1:5.1f} s   '
                f'n={len(lat):<4} mean {sum(lat) / len(lat):5.2f} ms  '
                f'median {ordered[len(ordered) // 2]:5.2f} ms  max {ordered[-1]:6.2f} ms')

    for kill in rec.kills:
        lines.append('')
        lines.append(f'  kill                : {kill["node"]} (SIGTERM) at t={kill["t"]:.2f} s')
        elected = [e for e in rec.elections if e['t'] > kill['t']]
        if elected:
            gap = elected[0]['t'] - kill['t']
            lines.append(f'  new leader          : {elected[0]["node"]} after {gap:.2f} s'
                         + (f'  (+/- {poll:.2f} s polling)' if poll else ''))
        last_ok, first_ok = commit_outage(rec.commits, kill['t'])
        if last_ok is not None and first_ok is not None:
            lines.append(f'  commit service gap  : {first_ok - last_ok:.2f} s '
                         f'(last success t={last_ok:.2f}, next t={first_ok:.2f})')
        failed = [c for c in rec.commits
                  if not c.get('ok') and last_ok is not None and first_ok is not None
                  and last_ok < c['t'] < first_ok]
        if failed:
            kinds = {}
            for c in failed:
                kinds[c['outcome']] = kinds.get(c['outcome'], 0) + 1
            lines.append('  attempts refused    : '
                         + ', '.join(f'{v} {k}' for k, v in sorted(kinds.items())))

    for restart in rec.restarts:
        lines.append('')
        lines.append(f'  restart             : {restart["node"]} at t={restart["t"]:.2f} s '
                     '-- rejoins with an EMPTY log (crash-fault only, docs/RAFT.md)')
    return [ln for ln in lines if ln != '']


# --------------------------------------------------------------------------- #
# figure
# --------------------------------------------------------------------------- #
def _mark_events(ax, rec: Recording, y_top: float, label: bool = False,
                 label_y: Optional[float] = None,
                 restart_label_y: Optional[float] = None) -> None:
    """The kill, the no-leader window and any restart, on every panel alike.

    The no-leader band is drawn even though it is a fifth of a second against a
    45-second axis and therefore nearly invisible: the annotation states the
    measured number, and a band a reader can barely see is the honest picture
    of how short the outage was. Widening it to make it legible would be a lie
    told for legibility.
    """
    for kill in rec.kills:
        elected = [e for e in rec.elections if e['t'] > kill['t']]
        if elected:
            ax.axvspan(kill['t'], elected[0]['t'], color=ONSET_WASH,
                       alpha=ONSET_WASH_ALPHA * 2.2, zorder=1, linewidth=0)
        ax.axvline(kill['t'], color=ONSET_WASH, linewidth=1.4, alpha=0.75, zorder=3)
        if label and elected:
            gap = elected[0]['t'] - kill['t']
            ax.annotate(
                f'leader {kill["node"]} SIGTERMed at t={kill["t"]:.0f} s\n'
                f'no leader for {gap:.2f} s, then {elected[0]["node"]} takes over',
                xy=(kill['t'], y_top if label_y is None else label_y),
                xytext=(kill['t'] + rec.t_end * 0.035,
                        y_top * 0.94 if label_y is None else label_y),
                color=INK_SECONDARY, fontsize=8.5, ha='left', va='center',
                linespacing=1.35, zorder=7,
                arrowprops=dict(arrowstyle='-', color=ONSET_WASH, lw=1.0, alpha=0.8))
    for restart in rec.restarts:
        ax.axvline(restart['t'], color=INK_MUTED, linewidth=1.0,
                   linestyle=(0, (4, 3)), alpha=0.8, zorder=3)
        if label and restart_label_y is not None:
            ax.annotate(
                f'{restart["node"]} restarted at t={restart["t"]:.0f} s -- rejoins as a\n'
                'follower with an EMPTY log, and is caught up by the leader',
                xy=(restart['t'], restart_label_y),
                xytext=(restart['t'] + rec.t_end * 0.035, restart_label_y),
                color=INK_SECONDARY, fontsize=8.5, ha='left', va='center',
                linespacing=1.35, zorder=7,
                arrowprops=dict(arrowstyle='-', color=INK_MUTED, lw=1.0, alpha=0.8))


def _panel_roles(ax, rec: Recording) -> None:
    nodes = rec.nodes
    t_end = rec.t_end
    style_axes(ax, t_end, 1.0,
               'A.  Who leads the trust ledger',
               'one lane per replica process; role sampled every '
               f'{rec.meta.get("poll_interval_s", 0.05):.2f} s, so each transition '
               'is located to within one sample',
               ylabel='')
    ax.set_ylim(-0.5, len(nodes) - 0.5)
    ax.set_yticks(range(len(nodes)))
    ax.set_yticklabels(list(reversed(nodes)), color=INK_SECONDARY, fontsize=10)
    ax.grid(False)

    for i, node in enumerate(reversed(nodes)):
        for start, end, role, term in role_runs(rec.statuses, node, t_end):
            fill = ROLE_FILL.get(role, ROLE_FILL['follower'])
            ax.broken_barh([(start, max(end - start, 1e-6))], (i - 0.3, 0.6),
                           edgecolor='none', zorder=2, **fill)
            if role == 'leader' and (end - start) > t_end * 0.06:
                ax.text(start + (end - start) / 2.0, i, f'LEADER  term {term}',
                        color=SURFACE, fontsize=8.5, fontweight='bold',
                        ha='center', va='center', zorder=4)
    _mark_events(ax, rec, y_top=len(nodes) - 0.5, label=True,
                 label_y=len(nodes) - 1.5, restart_label_y=len(nodes) - 2.5)

    ax.legend(handles=[Patch(label=r, **{k: v for k, v in ROLE_FILL[r].items()})
                       for r in ('leader', 'candidate', 'follower', 'down')],
              loc='upper right', frameon=False, fontsize=8.5, ncol=4,
              bbox_to_anchor=(1.0, 1.28))


def _series_with_gaps(statuses: Sequence[Dict[str, Any]], node: str,
                      key: str) -> Tuple[List[float], List[float]]:
    """One node's series, with NaN wherever the node was down.

    The NaN is the whole point. Dropping those samples instead would let
    matplotlib join the last value before the kill straight to the first value
    after the restart -- a flat segment asserting the replica held that term,
    and that many blocks, during fifteen seconds when it was not running. A
    figure must not draw a measurement across the interval where the
    measurement did not exist.
    """
    rows = sorted((r for r in statuses if r['node'] == node), key=lambda r: r['t'])
    xs = [r['t'] for r in rows]
    ys = [float('nan') if r.get(key) is None else float(r[key]) for r in rows]
    return xs, ys


def _grouped_end_labels(ax, ends: List[Tuple[str, float, float]], x_end: float,
                        y_range: float, fmt: str = '{:g}') -> None:
    """One label per distinct final value, naming every node that holds it.

    Three replicas that agree print "n1, n2, n3  850" rather than three
    identical numbers stacked into an unreadable smear -- and agreement is
    exactly what this figure exists to show, so saying it once, plainly, is
    also the more honest rendering.
    """
    groups: Dict[float, List[str]] = {}
    for node, _, y in ends:
        groups.setdefault(y, []).append(node)

    # Two replicas one block apart are two distinct values that land on the
    # same pixel. Nudge the LABELS apart -- never the values they state, which
    # are still printed exactly and still belong to the line they name.
    # The gap is a fraction of the AXIS, not of the values: two labels 1 block
    # apart on a 1000-block axis are one pixel apart however large the numbers
    # themselves are.
    ordered = sorted(groups.items())
    min_gap = 0.06 * max(y_range, 1e-9)
    label_ys: List[float] = []
    for i, (y, _) in enumerate(ordered):
        y_label = y if not label_ys else max(y, label_ys[-1] + min_gap)
        label_ys.append(y_label)
    for (y, nodes), y_label in zip(ordered, label_ys):
        ax.text(x_end * 1.025, y_label, f'{", ".join(nodes)}  {fmt.format(y)}',
                color=INK_PRIMARY, fontsize=9, fontweight='bold',
                va='center', ha='left', zorder=6)


def _panel_series(ax, rec: Recording, key: str, title: str, subtitle: str,
                  ylabel: str) -> None:
    t_end = rec.t_end
    y_max = 1.0
    series = {}
    for node in rec.nodes:
        xs, ys = _series_with_gaps(rec.statuses, node, key)
        series[node] = (xs, ys)
        finite = [y for y in ys if y == y]
        if finite:
            y_max = max(y_max, max(finite))

    style_axes(ax, t_end, y_max * 1.18, title, subtitle, ylabel=ylabel)
    _mark_events(ax, rec, y_top=y_max * 1.18)

    ends: List[Tuple[str, float, float]] = []
    for i, node in enumerate(rec.nodes):
        xs, ys = series[node]
        if not xs:
            continue
        ax.step(xs, ys, where='post', color=NODE_INK[i % len(NODE_INK)],
                linestyle=NODE_DASH[i % len(NODE_DASH)], linewidth=1.8,
                zorder=4, label=node)
        if ys[-1] == ys[-1]:
            ends.append((node, xs[-1], ys[-1]))
    _grouped_end_labels(ax, ends, t_end, y_max * 1.18)


def _panel_commits(ax, rec: Recording) -> None:
    t_end = rec.t_end
    ok = [(c['t'], c['latency_ms']) for c in rec.commits if c.get('ok')]
    bad = [(c['t'], c['outcome']) for c in rec.commits if not c.get('ok')]
    y_max = max([lat for _, lat in ok] + [NFR_COMMIT_MS]) if ok else NFR_COMMIT_MS

    style_axes(ax, t_end, y_max, 'D.  Client-observed commit latency',
               'one point per successful commit, HTTP round trip included; '
               'refused attempts as ticks along the bottom',
               xlabel='seconds since the recording started',
               ylabel='commit latency (ms, log)')
    ax.set_yscale('log')
    ax.set_ylim(0.5, NFR_COMMIT_MS * 3)
    _mark_events(ax, rec, y_top=NFR_COMMIT_MS * 3)

    ax.axhline(NFR_COMMIT_MS, color=INK_MUTED, linewidth=1.2,
               linestyle=(0, (5, 4)), zorder=3)
    ax.text(t_end * 0.995, NFR_COMMIT_MS * 1.12, f'< {NFR_COMMIT_MS:.0f} ms NFR',
            color=INK_SECONDARY, fontsize=8.5, ha='right', va='bottom')
    if ok:
        ax.scatter([t for t, _ in ok], [lat for _, lat in ok], s=7,
                   color=INK_SECONDARY, alpha=0.75, linewidths=0, zorder=4)
    if bad:
        ax.scatter([t for t, _ in bad], [0.75] * len(bad), s=26, marker='|',
                   color=ONSET_WASH, alpha=0.9, linewidths=1.2, zorder=5)
        anchor = rec.kills[0]['t'] if rec.kills else bad[0][0]
        ax.text(anchor + t_end * 0.02, 0.62,
                f'{len(bad)} attempt(s) refused here', color=ONSET_WASH,
                fontsize=8.5, ha='left', va='bottom', zorder=6)

    for label, t0, t1, lat in phase_latencies(rec):
        if not lat or (t1 - t0) < t_end * 0.08:
            continue
        ax.text((t0 + t1) / 2.0, NFR_COMMIT_MS * 0.16,
                f'{label}\nmean {sum(lat) / len(lat):.1f} ms',
                color=INK_SECONDARY, fontsize=8.5, ha='center', va='center',
                linespacing=1.35, zorder=6)

    ax.legend(handles=[
        Line2D([], [], marker='o', linestyle='none', color=INK_SECONDARY,
               markersize=4, label='commit succeeded'),
        Line2D([], [], marker='|', linestyle='none', color=ONSET_WASH,
               markersize=8, label='commit refused / unreachable'),
    ], loc='upper left', frameon=False, fontsize=8.5, ncol=2)


def _save(fig, stem: Path, no_svg: bool) -> None:
    stem.parent.mkdir(parents=True, exist_ok=True)
    kw = dict(dpi=200, facecolor=SURFACE, bbox_inches='tight')
    fig.savefig(f'{stem}.png', **kw)
    if not no_svg:
        fig.savefig(f'{stem}.svg', **kw)


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--recording', default=DEFAULT_RECORDING)
    p.add_argument('--out-dir', default=DEFAULT_OUT_DIR)
    p.add_argument('--stem', default='raft_failover')
    p.add_argument('--no-svg', action='store_true')
    args = p.parse_args(argv)

    rec = load_recording(args.recording)
    if not rec.statuses:
        print(f'{args.recording}: no status samples -- nothing to plot')
        return 1

    print('\n'.join(summarise(rec)))

    fig, axes = plt.subplots(4, 1, figsize=(11.5, 12.5), sharex=True,
                             facecolor=SURFACE,
                             gridspec_kw=dict(height_ratios=[1.15, 1.0, 1.0, 1.15]))
    _panel_roles(axes[0], rec)
    _panel_series(axes[1], rec, 'term', 'B.  RAFT term',
                  'a term is one election. It increments exactly once at the '
                  'failover, and every live replica converges on the same value.',
                  'term')
    _panel_series(axes[2], rec, 'chain_length', 'C.  Replicated ledger length',
                  'the survivors\' chains keep advancing together -- the trust '
                  'record outlived the replica that was leading it',
                  'blocks in chain')
    _panel_commits(axes[3], rec)

    for ax in axes:
        ax.set_xlim(0.0, rec.t_end * 1.02)
    fig.subplots_adjust(hspace=0.55)

    stem = Path(args.out_dir) / args.stem
    _save(fig, stem, args.no_svg)
    plt.close(fig)
    print(f'\nwrote {stem}.png' + ('' if args.no_svg else f' and {stem}.svg'))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
