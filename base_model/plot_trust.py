#!/usr/bin/env python3
"""Per-server trust-vs-time figures from a run recording.

    python3 -m base_model.plot_trust                      # baseline alone
    python3 -m base_model.plot_trust --treatment data/events.jsonl   # both arms

Writes into `base_model/trust/` (override with `--out-dir`):

    srvN_trust.png / .svg   one figure per server -- seconds since start (x)
                            against trust score (y)
    all_servers_trust.png   the same eight as one 2x4 grid, for the paper
    trust_data.csv          exactly the points plotted, so a reader can check
                            the figure against numbers rather than take it on
                            trust (and so the figures have a table view)

FOUR CHOICES THAT ARE NOT COSMETIC
----------------------------------
1. **The y-axis is fixed to [0, 1] on every figure.** Auto-scaling per server
   would give an honest node that sat between 0.79 and 0.81 all run a chart
   that looks like a rollercoaster, and put it beside a blackhole's collapse at
   apparently the same amplitude. Trust is defined on [0, 1]; the axis says so.

2. **The x-axis is seconds since the run's `topology` event**, not since the
   process started or since the first task. `attack_start_s` in the ground
   truth is relative to that same instant, so the shaded onset band and the
   curve share one clock. This is the same anchoring fix the live dashboard
   needed (SOURCE_OF_TRUTH §3.7a).

3. **Points are plotted raw, not smoothed.** Trust is already an EMA over
   lambda_decay; smoothing a smoothed series a second time would flatten the
   very transitions the figure exists to show, and no reader could tell how
   much of the shape was the system and how much was the plot.

4. **The onset band is labelled as the CONFIGURED arming time**, never as a
   detection. It comes from the `topology` event's ground truth. Marking it as
   anything else would let the figure imply the controller knew something at
   that instant, which is exactly the claim the detection-latency numbers are
   supposed to establish independently.

COLOUR
------
Two categorical slots from the project's validated palette -- blue `#2a78d6`
(baseline) and orange `#eb6834` (zero-trust). Checked with the dataviz
validator against the `#fcfcfb` chart surface under `--pairs all`: lightness
band, chroma floor, CVD separation (worst dE 24.7 protan), normal-vision
separation (dE 33.6) and 3:1 contrast all PASS. Do not substitute hues without
re-running it.

The isolation threshold is drawn in muted ink, not a series colour: it is a
constant, not data. Where two arms are plotted the legend is always present
AND both lines are directly labelled at their right-hand end, so identity is
never carried by colour alone.

These are light-surface figures for print. There is deliberately no dark
variant: a paper figure has one surface, and a second palette validated
against a surface the figure never renders on would be decoration.
"""

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import matplotlib
matplotlib.use('Agg')  # No display; these are files, not windows.
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402

from base_model.compare import _srv_sort_key, stream_events  # noqa: E402
from base_model.figure_style import (  # noqa: E402
    ARM_LABEL,
    INK_MUTED,
    INK_SECONDARY,
    LABEL_MIN_GAP_FRAC,
    LINE_WIDTH,
    ONSET_WASH,
    SERIES,
    SURFACE,
    X_HEADROOM,
    draw_onset,
    resolve_label_collisions,
    style_axes,
)

DEFAULT_OUT_DIR = 'base_model/trust'

#: Trust is defined on [0, 1], so that is the axis on every figure -- see the
#: module docstring. Named rather than inlined because the label de-collision
#: needs the same range to size its minimum gap.
TRUST_RANGE = 1.0


def _load_series(path: str, arm: str) -> Tuple[Dict[str, List[Tuple[float, float]]],
                                               Dict[str, str], Dict[str, float]]:
    """Stream one recording into per-server (t_seconds, trust) points.

    Returns (series, roles, onsets). `roles` and `onsets` come from the
    `topology` event's ground truth, so a figure can never disagree with the
    run about which server was the attacker.
    """
    series: Dict[str, List[Tuple[float, float]]] = defaultdict(list)
    roles: Dict[str, str] = {}
    onsets: Dict[str, float] = {}
    t0: Optional[float] = None
    declared_arm: Optional[str] = None
    enforcement_seen = 0

    for ev in stream_events(path):
        ts = ev.get('ts')
        if ts is not None and t0 is None:
            t0 = float(ts)
        etype = ev.get('type')

        if etype == 'arm':
            declared_arm = ev.get('arm')
        elif etype in ('quarantine', 'reroute', 'auth_denied'):
            # Evidence of enforcement. Only the treatment arm can produce these.
            enforcement_seen += 1
        elif etype == 'topology':
            for node in (ev.get('graph') or {}).get('nodes') or []:
                if node.get('kind') == 'server':
                    roles[node['id']] = node.get('attack', 'none')
                    onsets[node['id']] = float(node.get('attack_start_s', 0.0))
        elif etype == 'node_status' and ts is not None and t0 is not None:
            t_rel = float(ts) - t0
            for node, row in (ev.get('nodes') or {}).items():
                trust = row.get('trust')
                if trust is not None:
                    series[node].append((t_rel, float(trust)))

    if not series:
        raise SystemExit(
            f"{path} contains no `node_status` events -- nothing to plot. "
            f"Either the run produced no monitor cycles, or this is not a "
            f"controller recording."
        )
    # Sorted by time: the bus fans out from several threads, so a later line can
    # carry a slightly earlier stamp and an unsorted plot would zig-zag.
    for node in series:
        series[node].sort(key=lambda p: p[0])

    _warn_on_arm_mismatch(path, arm, declared_arm, enforcement_seen)
    return series, roles, onsets


def _warn_on_arm_mismatch(
    path: str, plotted_as: str, declared: Optional[str], enforcement_seen: int,
) -> None:
    """Shout if a recording is about to be labelled as the wrong arm.

    A figure whose legend says "baseline (no zero trust)" over a curve produced
    by the zero-trust controller is the single worst thing this script could
    emit -- it would be wrong in a paper, and nothing downstream could detect
    it. Two independent checks, because either can be absent:

      * the `arm` event, which the baseline controller publishes by name;
      * enforcement events, which ONLY the treatment arm can produce. A
        recording carrying a quarantine did not come from an arm that cannot
        quarantine.

    A warning, not an error: plotting one treatment run against another is a
    legitimate thing to do (this script's own verification did exactly that),
    and refusing would block it. But it must never happen silently.
    """
    if declared is not None and declared != plotted_as:
        print(
            f"WARNING: {path} declares arm={declared!r} but is being plotted "
            f"and labelled as {plotted_as!r}. Check --baseline/--treatment are "
            f"the right way round before using these figures."
        )
    elif plotted_as == 'baseline' and enforcement_seen:
        print(
            f"WARNING: {path} contains {enforcement_seen} enforcement event(s) "
            f"(quarantine / reroute / auth_denied). The baseline arm cannot "
            f"produce those, so this is very likely a zero-trust recording "
            f"about to be labelled 'baseline (no zero trust)'."
        )


def _style_axes(ax, x_max: float, title: str, subtitle: str = '',
                xlabel: str = 'seconds since run start',
                ylabel: str = 'trust score  T') -> None:
    """The shared house treatment, with this family's fixed [0, 1] y axis."""
    style_axes(ax, x_max, TRUST_RANGE, title, subtitle, xlabel, ylabel)
    ax.set_yticks([0.0, 0.2, 0.4, 0.6, 0.8, 1.0])


def _draw_threshold(ax, threshold: float, x_max: float, label: bool = True) -> None:
    """The isolation line, in muted ink because it is a constant, not data.

    Drawn on every figure including the baseline's -- there it marks the line
    the treatment arm WOULD have acted on, which is the whole point of putting
    the two arms on one axis.
    """
    ax.axhline(threshold, color=INK_MUTED, linewidth=1.0, linestyle=(0, (4, 3)),
               zorder=2)
    if label:
        ax.text(x_max * 0.99, threshold + 0.02,
                f'isolation threshold {threshold:g}',
                color=INK_MUTED, fontsize=8.5, ha='right', va='bottom')


def _plot_one(ax, node: str, arms: Dict[str, Dict[str, List[Tuple[float, float]]]],
              role: str, onset: float, threshold: float, x_max: float,
              compact: bool = False) -> List[str]:
    """Draw one server's panel. Returns the arms actually drawn."""
    drawn: List[str] = []
    draw_onset(ax, role, onset, x_max, TRUST_RANGE, label=not compact)

    ends: List[Tuple[str, float, float]] = []
    for arm, series in arms.items():
        points = series.get(node)
        if not points:
            continue
        xs = [p[0] for p in points]
        ys = [p[1] for p in points]
        ax.plot(xs, ys, color=SERIES[arm], linewidth=LINE_WIDTH,
                solid_capstyle='round', zorder=4, label=ARM_LABEL[arm])
        drawn.append(arm)
        ends.append((arm, xs[-1], ys[-1]))

    if not compact:
        # One selective direct label per line, at its right-hand end -- never a
        # number on every point. With two arms this is what keeps identity off
        # colour alone, alongside the legend.
        for arm, x_end, y_end, y_label in resolve_label_collisions(
                ends, TRUST_RANGE):
            if abs(y_label - y_end) > 1e-9:
                # Nudged clear of the other arm's label: draw a hairline leader
                # so the number still unambiguously belongs to its own curve.
                ax.plot([x_end, x_end + x_max * 0.018], [y_end, y_label],
                        color=SERIES[arm], linewidth=0.8, alpha=0.55,
                        zorder=5, clip_on=False)
            ax.text(x_end + x_max * 0.024, y_label, f'{y_end:.3f}',
                    color=SERIES[arm], fontsize=9.5, fontweight='bold',
                    va='center', ha='left', zorder=6)

    _draw_threshold(ax, threshold, x_max, label=not compact)
    if not drawn:
        ax.text(0.5, 0.5, 'no trust samples for this server',
                transform=ax.transAxes, color=INK_MUTED, fontsize=10,
                ha='center', va='center')
    return drawn


def _role_caption(role: str, onset: float) -> str:
    if role in ('none', '', None):
        return 'ground truth: honest'
    return f'ground truth: {role}, armed at t={onset:g}s'


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--baseline', default='data/base_events.jsonl')
    parser.add_argument(
        '--treatment', default=None,
        help='Overlay the zero-trust arm (data/events.jsonl) on every figure.',
    )
    parser.add_argument('--out-dir', default=DEFAULT_OUT_DIR)
    parser.add_argument(
        '--threshold', type=float, default=0.3,
        help='Isolation threshold to mark (trust.isolation_threshold).',
    )
    parser.add_argument(
        '--no-svg', action='store_true',
        help='PNG only. SVG is on by default -- it is the one a paper wants.',
    )
    args = parser.parse_args(argv)

    if not Path(args.baseline).exists():
        print(f"No recording at {args.baseline}.")
        print("Run the arm first:  sudo -E python3 -m base_model.run_base")
        return 1

    arms: Dict[str, Dict[str, List[Tuple[float, float]]]] = {}
    series, roles, onsets = _load_series(args.baseline, 'baseline')
    arms['baseline'] = series

    if args.treatment:
        if not Path(args.treatment).exists():
            print(f"No treatment recording at {args.treatment} -- plotting the "
                  f"baseline alone.")
        else:
            t_series, t_roles, t_onsets = _load_series(args.treatment, 'zero_trust')
            arms['zero_trust'] = t_series
            # Ground truth must agree, or the two curves are not the same
            # experiment and the onset band would be wrong for one of them.
            mismatched = {
                n for n in set(roles) & set(t_roles)
                if roles[n] != t_roles[n] or onsets[n] != t_onsets[n]
            }
            if mismatched:
                print("WARNING: the two recordings disagree on ground truth for "
                      f"{sorted(mismatched, key=_srv_sort_key)}. These are not "
                      "the same experiment; the onset bands follow the baseline.")

    nodes = sorted(
        {n for series in arms.values() for n in series},
        key=_srv_sort_key,
    )
    x_max = max(
        (p[0] for series in arms.values() for pts in series.values() for p in pts),
        default=1.0,
    )

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # -- one figure per server ---------------------------------------------- #
    for node in nodes:
        role = roles.get(node, 'unknown')
        onset = onsets.get(node, 0.0)
        fig, ax = plt.subplots(figsize=(8.0, 4.6), dpi=160)
        fig.patch.set_facecolor(SURFACE)
        _style_axes(
            ax, x_max,
            title=f'{node} — trust over time',
            subtitle=_role_caption(role, onset),
        )
        drawn = _plot_one(ax, node, arms, role, onset, args.threshold, x_max)
        # A legend for >= 2 series, none for one: with a single line the title
        # already names it, and a one-row legend box is chrome.
        if len(drawn) >= 2:
            ax.legend(
                loc='lower left', frameon=False, fontsize=9,
                labelcolor=INK_SECONDARY, handlelength=1.6,
            )
        fig.tight_layout()
        fig.savefig(out_dir / f'{node}_trust.png', facecolor=SURFACE)
        if not args.no_svg:
            fig.savefig(out_dir / f'{node}_trust.svg', facecolor=SURFACE)
        plt.close(fig)

    # -- one grid, for the paper -------------------------------------------- #
    cols = 4
    rows = (len(nodes) + cols - 1) // cols
    fig, axes = plt.subplots(rows, cols, figsize=(4.2 * cols, 2.9 * rows), dpi=160,
                             sharex=True, sharey=True)
    fig.patch.set_facecolor(SURFACE)
    flat = list(axes.flat) if hasattr(axes, 'flat') else [axes]
    drawn_any: List[str] = []
    for idx, (ax, node) in enumerate(zip(flat, nodes)):
        role = roles.get(node, 'unknown')
        onset = onsets.get(node, 0.0)
        _style_axes(ax, x_max, title=f'{node}', subtitle=_role_caption(role, onset))
        # Outer panels only. Repeating the two axis titles eight times is noise,
        # and a figure-level supxlabel would sit in the same strip as the legend
        # and overprint it.
        if idx < len(nodes) - cols:
            ax.set_xlabel('')
        if idx % cols != 0:
            ax.set_ylabel('')
        drawn_any = _plot_one(ax, node, arms, role, onset, args.threshold, x_max,
                              compact=True) or drawn_any
    for ax in flat[len(nodes):]:
        ax.set_visible(False)
    # The grid's panels are compact, so the shared context that each panel drops
    # -- the threshold line and the onset shading -- is named once here instead.
    handles = [
        Line2D([0], [0], color=SERIES[a], linewidth=LINE_WIDTH, label=ARM_LABEL[a])
        for a in arms if a in drawn_any or len(arms) == 1
    ]
    handles.append(Line2D([0], [0], color=INK_MUTED, linewidth=1.0,
                          linestyle=(0, (4, 3)),
                          label=f'isolation threshold {args.threshold:g}'))
    handles.append(Line2D([0], [0], color=ONSET_WASH, linewidth=6, alpha=0.35,
                          label='attack armed (configured, not detected)'))
    fig.tight_layout()
    # After tight_layout, so the legend is placed against the final geometry
    # rather than against a layout that is about to move underneath it.
    fig.legend(handles=handles, loc='upper center', ncol=len(handles),
               frameon=False, fontsize=9.5, labelcolor=INK_SECONDARY,
               bbox_to_anchor=(0.5, 0.02))
    fig.subplots_adjust(bottom=0.16)
    fig.savefig(out_dir / 'all_servers_trust.png', facecolor=SURFACE,
                bbox_inches='tight')
    if not args.no_svg:
        fig.savefig(out_dir / 'all_servers_trust.svg', facecolor=SURFACE,
                    bbox_inches='tight')
    plt.close(fig)

    # -- the table view ------------------------------------------------------ #
    csv_path = out_dir / 'trust_data.csv'
    with open(csv_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['arm', 'node', 'role', 'attack_start_s', 't_s', 'trust'])
        for arm, series in arms.items():
            for node in nodes:
                for t_rel, trust in series.get(node, []):
                    writer.writerow([
                        arm, node, roles.get(node, 'unknown'),
                        f'{onsets.get(node, 0.0):g}', f'{t_rel:.3f}', f'{trust:.6f}',
                    ])

    print(f"Wrote {len(nodes)} per-server figures + the grid to {out_dir}/")
    print(f"  arms plotted : {', '.join(ARM_LABEL[a] for a in arms)}")
    print(f"  run length   : {x_max:.1f}s")
    print(f"  samples/node : "
          f"{min(len(s.get(n, [])) for s in arms.values() for n in nodes)}"
          f"–{max(len(s.get(n, [])) for s in arms.values() for n in nodes)}")
    print(f"  table view   : {csv_path}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
