"""Per-server trust/anomaly trajectories from a recorded run's node_status stream.

One PNG per edge server plus a small-multiples overview. Both rails are plotted on
a single [0,1] axis -- T(t) and A(t) are the same units on the same scale, so this
is one axis, not a dual-axis chart.

Usage: python3 plot_trust.py [events.jsonl] [outdir]
"""
import json
import os
import sys

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import Patch

EVENTS = sys.argv[1] if len(sys.argv) > 1 else 'data/events.jsonl'
OUTDIR = sys.argv[2] if len(sys.argv) > 2 else 'data/figures/trust'

# Validated categorical slots 1 and 2 (adjacent pair in the documented order) plus
# the chrome/ink tokens. Light surface only -- these are paper/report figures.
SURFACE   = '#fcfcfb'
INK       = '#0b0b0b'
INK_2     = '#52514e'
MUTED     = '#898781'
GRID      = '#e1e0d9'
BASELINE  = '#c3c2b7'
TRUST     = '#2a78d6'   # slot 1 blue
ANOMALY   = '#eb6834'   # slot 2 orange
CRITICAL  = '#d03b3b'   # status: quarantined

ISOLATION = 0.30
GATE = 0.50

ROLE = {
    'srv1': 'grayhole attacker',
    'srv2': 'honest',
    'srv3': 'sybil attacker',
    'srv4': 'honest',
    'srv5': 'honest',
    'srv6': 'blackhole attacker',
    'srv7': 'honest',
    'srv8': 'on-off attacker',
}


def load(path):
    """-> (times, {node: {trust/anomaly/quarantined/probation: [...]}}, attack_starts)."""
    times, series, attacks = [], {}, {}
    t0 = None
    with open(path) as fh:
        for line in fh:
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if t0 is None:
                t0 = e['ts']
            if e.get('type') == 'topology':
                for n in e['graph']['nodes']:
                    if n.get('kind') == 'server' and n.get('attack', 'none') != 'none':
                        attacks[n['id']] = n.get('attack_start_s')
            elif e.get('type') == 'node_status':
                times.append(e['ts'] - t0)
                for nid, v in e['nodes'].items():
                    d = series.setdefault(
                        nid, {'trust': [], 'anomaly': [], 'quarantined': [], 'probation': []})
                    d['trust'].append(v.get('trust'))
                    d['anomaly'].append(v.get('anomaly', 0.0))
                    d['quarantined'].append(bool(v.get('quarantined')))
                    d['probation'].append(bool(v.get('probation')))
    return times, series, attacks


def runs(times, flags):
    """Contiguous [start, end] spans where flags is True."""
    out, start = [], None
    for t, f in zip(times, flags):
        if f and start is None:
            start = t
        elif not f and start is not None:
            out.append((start, t))
            start = None
    if start is not None:
        out.append((start, times[-1]))
    return out


def style(ax, xmax):
    ax.set_facecolor(SURFACE)
    ax.set_ylim(-0.05, 1.08)
    ax.set_xlim(0, xmax)
    ax.grid(True, axis='y', color=GRID, linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    for side in ('top', 'right'):
        ax.spines[side].set_visible(False)
    for side in ('left', 'bottom'):
        ax.spines[side].set_color(BASELINE)
        ax.spines[side].set_linewidth(1.0)
    ax.tick_params(colors=MUTED, labelsize=9, length=0)
    for lbl in ax.get_xticklabels() + ax.get_yticklabels():
        lbl.set_color(INK_2)


def draw(ax, times, d, attack_start, xmax, compact=False):
    q_spans = runs(times, d['quarantined'])
    for a, b in q_spans:
        ax.axvspan(a, b, color=CRITICAL, alpha=0.075, linewidth=0, zorder=1)
    for a, b in runs(times, d['probation']):
        ax.plot([a, b], [-0.028, -0.028], color=MUTED, linewidth=3,
                solid_capstyle='butt', zorder=3)

    # Rails, tinted to their series so each threshold reads against its own line.
    ax.axhline(ISOLATION, color=TRUST, alpha=0.42, linestyle=(0, (5, 4)),
               linewidth=1.2, zorder=2)
    ax.axhline(GATE, color=ANOMALY, alpha=0.42, linestyle=(0, (5, 4)),
               linewidth=1.2, zorder=2)
    if attack_start is not None:
        ax.axvline(attack_start, color=INK_2, alpha=0.55,
                   linestyle=(0, (1, 3)), linewidth=1.2, zorder=4)
        ax.text(attack_start + xmax * 0.008, 1.035,
                f'attack starts {attack_start:.0f}s', ha='left', va='center',
                fontsize=8.5 if not compact else 7.5, color=INK_2)

    lw = 2.0 if not compact else 1.6
    ax.plot(times, d['anomaly'], color=ANOMALY, linewidth=lw,
            solid_capstyle='round', zorder=5)
    ax.plot(times, d['trust'], color=TRUST, linewidth=lw,
            solid_capstyle='round', zorder=6)
    return q_spans


def endlabel(ax, times, d, xmax):
    """Direct-label the two final values -- selective labels, never every point."""
    for key, color, dy in (('trust', TRUST, 0.0), ('anomaly', ANOMALY, 0.0)):
        v = d[key][-1]
        ax.plot([times[-1]], [v], marker='o', markersize=5, color=color,
                markeredgecolor=SURFACE, markeredgewidth=1.6, zorder=7)
        ax.annotate(f'{v:.3f}', (times[-1], v),
                    textcoords='offset points', xytext=(9, dy),
                    fontsize=9, color=INK, fontweight='bold',
                    va='center', ha='left', annotation_clip=False)


def summary(times, d, q_spans, compact=False):
    """Trust swings by ~0.15 between consecutive tasks at lambda_decay=0.85, so a
    single final sample is not representative -- quote the tail mean beside it."""
    tail = [v for t, v in zip(times, d['trust']) if t >= times[-1] - 30.0]
    mean = sum(tail) / len(tail)
    final_q = d['quarantined'][-1]
    caught_by = []
    if final_q or q_spans:
        if any(t < ISOLATION for t in d['trust']):
            caught_by.append('trust rail')
        if any(a >= GATE for a in d['anomaly']):
            caught_by.append('anomaly gate')
    if compact:
        state = 'quarantined at end' if final_q else (
            'eligible at end' if q_spans else 'never quarantined')
        bits = [f"T {d['trust'][-1]:.3f} (last-30s mean {mean:.3f})", state]
        if q_spans:
            bits.append(f"{len(q_spans)} cycle{'s' if len(q_spans) != 1 else ''}")
        if caught_by:
            bits.append(' + '.join(c.replace('anomaly gate', 'gate') for c in caught_by))
        return '  ·  '.join(bits)
    state = 'QUARANTINED at end of run' if final_q else (
        'eligible at end of run' if q_spans else 'never quarantined')
    bits = [f"final trust {d['trust'][-1]:.4f}",
            f"last-30s mean {mean:.4f}", state]
    if q_spans:
        bits.append(f"{len(q_spans)} quarantine cycle{'s' if len(q_spans) != 1 else ''}")
    if caught_by:
        bits.append('caught by ' + ' + '.join(caught_by))
    return '  ·  '.join(bits)


def legend(fig, ax, ncol=3, y=-0.02):
    """Thresholds are identified here rather than inline: an in-plot label at the
    right edge lands on top of the series whenever a line ends high."""
    handles = [
        Line2D([], [], color=TRUST, linewidth=2.2, label='Trust  T(t)'),
        Line2D([], [], color=ANOMALY, linewidth=2.2, label='Anomaly  Ā(t)'),
        Patch(facecolor=CRITICAL, alpha=0.20, label='quarantined'),
        Line2D([], [], color=TRUST, alpha=0.42, linewidth=1.4,
               linestyle=(0, (5, 4)), label='isolation threshold 0.30'),
        Line2D([], [], color=ANOMALY, alpha=0.42, linewidth=1.4,
               linestyle=(0, (5, 4)), label='anomaly gate 0.50'),
        Line2D([], [], color=MUTED, linewidth=3, label='probation trials'),
    ]
    leg = fig.legend(handles=handles, loc='lower center', ncol=ncol,
                     frameon=False, fontsize=9.5,
                     bbox_to_anchor=(0.5, y), handlelength=1.9,
                     columnspacing=2.0, labelspacing=0.7)
    for t in leg.get_texts():
        t.set_color(INK_2)


def main():
    times, series, attacks = load(EVENTS)
    if not times:
        sys.exit(f'no node_status samples in {EVENTS}')
    os.makedirs(OUTDIR, exist_ok=True)
    xmax = times[-1]
    nodes = sorted(series, key=lambda n: (len(n), n))

    for nid in nodes:
        d = series[nid]
        fig, ax = plt.subplots(figsize=(9.4, 4.3), dpi=150)
        fig.patch.set_facecolor(SURFACE)
        style(ax, xmax)
        q = draw(ax, times, d, attacks.get(nid), xmax)
        endlabel(ax, times, d, xmax)
        ax.set_title(f'{nid} — {ROLE.get(nid, "?")}', loc='left', pad=22,
                     fontsize=14, fontweight='bold', color=INK)
        ax.text(0, 1.045, summary(times, d, q), transform=ax.transAxes,
                fontsize=8.8, color=INK_2, va='bottom', ha='left')
        ax.set_xlabel('seconds since run start', fontsize=9.5, color=INK_2, labelpad=6)
        legend(fig, ax, ncol=3, y=0.005)
        fig.subplots_adjust(left=0.06, right=0.90, top=0.82, bottom=0.27)
        out = os.path.join(OUTDIR, f'trust_{nid}.png')
        fig.savefig(out, facecolor=SURFACE)
        plt.close(fig)
        print('wrote', out)

    # Small-multiples overview: same two series, same scale, shared axes.
    fig, axes = plt.subplots(4, 2, figsize=(13, 11), dpi=150, sharex=True, sharey=True)
    fig.patch.set_facecolor(SURFACE)
    for ax, nid in zip(axes.T.flatten(order='F') if False else axes.flatten(), nodes):
        d = series[nid]
        style(ax, xmax)
        q = draw(ax, times, d, attacks.get(nid), xmax, compact=True)
        ax.set_title(f'{nid} — {ROLE.get(nid, "?")}', loc='left', pad=16,
                     fontsize=11.5, fontweight='bold', color=INK)
        ax.text(0, 1.02, summary(times, d, q, compact=True), transform=ax.transAxes,
                fontsize=7.8, color=INK_2, va='bottom', ha='left')
    for ax in axes[-1]:
        ax.set_xlabel('seconds since run start', fontsize=9.5, color=INK_2)
    fig.suptitle('Trust and anomaly per edge server — 8 servers / 40 clients / 4 attackers',
                 x=0.045, y=0.985, ha='left', fontsize=15, fontweight='bold', color=INK)
    legend(fig, None, ncol=6, y=0.008)
    fig.subplots_adjust(left=0.05, right=0.985, top=0.925, bottom=0.085,
                        hspace=0.42, wspace=0.10)
    out = os.path.join(OUTDIR, 'trust_all_servers.png')
    fig.savefig(out, facecolor=SURFACE)
    plt.close(fig)
    print('wrote', out)


if __name__ == '__main__':
    main()
