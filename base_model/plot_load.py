#!/usr/bin/env python3
"""Per-server load figures, and the fairness comparison that goes with them.

    python3 -m base_model.plot_load --treatment data/events.jsonl

Writes into `base_model/load/`:

    srvN_load.png / .svg      requests routed per second, per server, per arm
    all_servers_load.png      the same eight as one 2x4 grid
    load_share.png            total requests per server -- the headline figure
    fairness_over_time.png    Jain over the full roster AND over honest servers
    load_data.csv             the points plotted

WHY "LOAD" HERE MEANS REQUESTS ROUTED, NOT OCCUPANCY
-----------------------------------------------------
Requests routed is the quantity the router *controls*, so it is the honest
subject of a load-balancing comparison: it is counted from `route` events,
which are the decisions themselves.

Occupancy (`observed_load`, the Little's-Law integral) is a *consequence*, and
it is measured over `load_window_s`. Both arms now run the same 3 s window --
pinned by `test_observer_parity.py::test_load_window_matches_the_treatment_arm`
-- but the baseline's FIRST recording (2026-09-05) was taken on a 5 s window,
so occupancy from that file is not directly comparable with the treatment arm's
and this tool deliberately does not plot it. Re-run the baseline and the
caveat is gone; the metric would still be secondary.

THE ONE TRAP THIS TOOL EXISTS TO AVOID
--------------------------------------
Jain's index over the **full roster** is nearly identical in the two arms:
measured 0.622 baseline against 0.627 zero-trust. Reported alone, that reads as
"the load balancer made no difference", and it is wrong -- the two numbers are
low for opposite reasons:

  * the BASELINE is uneven because a flooding device is statically pinned to
    one server (srv5 took 2,545 of 6,773 requests) and nothing can move it;
  * the ZERO-TRUST arm is uneven because it *deliberately withheld* traffic
    from four attackers (srv3 took 44).

One is a failure to spread load; the other is the enforcement working. A single
whole-roster index cannot tell them apart, so this tool always reports **two**
populations side by side -- the full roster and the honest servers only -- plus
the share of traffic that reached an attacker at all. On the honest four the
arms separate hard: 0.689 against 0.992.

That is why `fairness_over_time` is a two-panel figure rather than one chart
with four lines. Two series per panel keeps identity inside the two validated
palette slots, and the left/right split is the comparison being made.
"""

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

from base_model.compare import _srv_sort_key, stream_events  # noqa: E402
from base_model.figure_style import (  # noqa: E402
    ARM_LABEL,
    AXIS,
    GRIDLINE,
    INK_MUTED,
    INK_PRIMARY,
    INK_SECONDARY,
    LINE_WIDTH,
    ONSET_WASH,
    ONSET_WASH_ALPHA,
    SERIES,
    SURFACE,
    draw_end_labels,
    draw_onset,
    jain,
    style_axes,
)
from evaluation.interval_report import DEFAULT_BUCKET_S  # noqa: E402

DEFAULT_OUT_DIR = 'base_model/load'
HONEST = 'none'


def _load_routes(path: str, bucket_s: float):
    """Stream a recording into per-server route counts per time bucket.

    Returns (buckets, roles, onsets, t_end) where `buckets` is
    node -> {bucket_index: count}. Bucketed at the same width
    `evaluation/interval_report.py` uses, so a number read off one of these
    figures can be checked against that report rather than merely resembling it.
    """
    buckets: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
    roles: Dict[str, str] = {}
    onsets: Dict[str, float] = {}
    t0: Optional[float] = None
    t_end = 0.0

    for ev in stream_events(path):
        ts = ev.get('ts')
        if ts is not None and t0 is None:
            t0 = float(ts)
        etype = ev.get('type')
        if etype == 'topology':
            for node in (ev.get('graph') or {}).get('nodes') or []:
                if node.get('kind') == 'server':
                    roles[node['id']] = node.get('attack', 'none')
                    onsets[node['id']] = float(node.get('attack_start_s', 0.0))
        elif etype == 'route' and ts is not None and t0 is not None:
            chosen = ev.get('chosen')
            if not chosen:
                continue
            t_rel = float(ts) - t0
            t_end = max(t_end, t_rel)
            buckets[chosen][int(t_rel // bucket_s)] += 1

    if not buckets:
        raise SystemExit(
            f"{path} contains no `route` events -- nothing to plot. Either the "
            f"run served no traffic, or this is not a controller recording."
        )
    return buckets, roles, onsets, t_end


def _rate_series(buckets: Dict[int, int], n_buckets: int, bucket_s: float):
    """Bucket counts -> (x seconds, y requests/second), zeros included.

    Zeros included and plotted: a bucket in which a server received nothing is
    the signal, not missing data. Dropping empty buckets would draw a line
    straight across a starvation gap.
    """
    xs = [i * bucket_s for i in range(n_buckets)]
    ys = [buckets.get(i, 0) / bucket_s for i in range(n_buckets)]
    return xs, ys


def complete_buckets(t_end: float, bucket_s: float) -> int:
    """How many buckets are FULL. The rest of the run lands in a partial tail.

    A run does not end on a bucket boundary, and the agents are killed a moment
    before it stops -- so the last bucket covers less wall time than the others
    AND catches the teardown. Measured on 2026-09-05: the zero-trust arm's final
    bucket held 47 requests over 1.9 s, against ~232 over 10 s for each of its
    neighbours.

    That tail is drawn, never trimmed -- `evaluation/availability_report.py`
    makes the argument and it holds here: a knob that discards inconvenient tail
    data is a knob that will eventually be used to flatter a result. It is drawn
    DASHED, and the direct labels are anchored to the last COMPLETE bucket
    instead, because a bold number computed from 1.9 s of teardown is an
    invitation to read noise as the run's headline. It was read that way once.
    """
    return max(1, int(t_end // bucket_s))


def _plot_with_partial_tail(ax, xs, ys, n_complete: int, color: str,
                            label: Optional[str] = None):
    """Solid over the complete buckets, dashed over the partial tail.

    Returns (x, y) of the last COMPLETE bucket -- the point a direct label
    should attach to.
    """
    ax.plot(xs[:n_complete], ys[:n_complete], color=color, linewidth=LINE_WIDTH,
            solid_capstyle='round', zorder=4, label=label)
    if len(xs) > n_complete:
        ax.plot(xs[n_complete - 1:], ys[n_complete - 1:], color=color,
                linewidth=LINE_WIDTH, linestyle=(0, (2, 2)), alpha=0.55,
                zorder=3)
    return xs[n_complete - 1], ys[n_complete - 1]


def _fairness_series(arm: Dict[str, Dict[int, int]], nodes: List[str],
                     n_buckets: int) -> List[float]:
    """Jain per bucket over the given population."""
    out = []
    for i in range(n_buckets):
        counts = [arm.get(n, {}).get(i, 0) for n in nodes]
        out.append(jain(counts) if sum(counts) else float('nan'))
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--baseline', default='data/base_events.jsonl')
    parser.add_argument('--treatment', default=None)
    parser.add_argument('--out-dir', default=DEFAULT_OUT_DIR)
    parser.add_argument('--bucket-s', type=float, default=DEFAULT_BUCKET_S)
    parser.add_argument('--no-svg', action='store_true')
    args = parser.parse_args(argv)

    if not Path(args.baseline).exists():
        print(f"No recording at {args.baseline}.")
        print("Run the arm first:  sudo -E python3 -m base_model.run_base")
        return 1

    arms: Dict[str, Dict[str, Dict[int, int]]] = {}
    ends: Dict[str, float] = {}
    b_buckets, roles, onsets, b_end = _load_routes(args.baseline, args.bucket_s)
    arms['baseline'] = b_buckets
    ends['baseline'] = b_end

    if args.treatment:
        if not Path(args.treatment).exists():
            print(f"No treatment recording at {args.treatment} -- baseline alone.")
        else:
            t_buckets, t_roles, t_onsets, t_end = _load_routes(
                args.treatment, args.bucket_s)
            arms['zero_trust'] = t_buckets
            ends['zero_trust'] = t_end
            mismatched = {
                n for n in set(roles) & set(t_roles)
                if roles[n] != t_roles[n] or onsets[n] != t_onsets[n]
            }
            if mismatched:
                print("WARNING: the two recordings disagree on ground truth for "
                      f"{sorted(mismatched, key=_srv_sort_key)}. These are not "
                      "the same experiment; onset bands follow the baseline.")

    nodes = sorted(roles, key=_srv_sort_key) or sorted(
        {n for a in arms.values() for n in a}, key=_srv_sort_key)
    honest = [n for n in nodes if roles.get(n, HONEST) == HONEST]
    attackers = [n for n in nodes if n not in honest]
    x_end = max(ends.values())
    n_buckets = int(x_end // args.bucket_s) + 1

    # One y scale across every per-server panel. An auto-scaled panel beside a
    # fixed one makes two servers look comparable when one carried 4x the load.
    y_max = max(
        (c / args.bucket_s
         for a in arms.values() for b in a.values() for c in b.values()),
        default=1.0,
    ) * 1.12

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # -- per-server ---------------------------------------------------------- #
    for node in nodes:
        role, onset = roles.get(node, 'unknown'), onsets.get(node, 0.0)
        fig, ax = plt.subplots(figsize=(8.0, 4.6), dpi=160)
        fig.patch.set_facecolor(SURFACE)
        style_axes(ax, x_end, y_max, title=f'{node} — offered load over time',
                   subtitle=_caption(role, onset),
                   xlabel='seconds since run start',
                   ylabel='requests routed here  (per second)')
        draw_onset(ax, role, onset, x_end, y_max)
        line_ends = []
        for arm, series in arms.items():
            xs, ys = _rate_series(series.get(node, {}), n_buckets, args.bucket_s)
            x_lab, y_lab = _plot_with_partial_tail(
                ax, xs, ys, complete_buckets(ends[arm], args.bucket_s),
                SERIES[arm], ARM_LABEL[arm])
            total = sum(series.get(node, {}).values())
            line_ends.append((arm, x_lab, y_lab))
            ax.annotate(
                f'{total:,} total', xy=(0.985, 0.93 - 0.075 * len(line_ends)),
                xycoords='axes fraction', color=SERIES[arm], fontsize=9.5,
                fontweight='bold', ha='right', va='top', zorder=6,
            )
        draw_end_labels(ax, line_ends, x_end, y_max, fmt='{:.1f}/s')
        if len(arms) >= 2:
            ax.legend(loc='upper left', frameon=False, fontsize=9,
                      labelcolor=INK_SECONDARY, handlelength=1.6)
        fig.tight_layout()
        _save(fig, out_dir / f'{node}_load', args.no_svg)

    # -- grid ---------------------------------------------------------------- #
    cols = 4
    rows = (len(nodes) + cols - 1) // cols
    fig, axes = plt.subplots(rows, cols, figsize=(4.2 * cols, 2.9 * rows),
                             dpi=160, sharex=True, sharey=True)
    fig.patch.set_facecolor(SURFACE)
    flat = list(axes.flat)
    for idx, (ax, node) in enumerate(zip(flat, nodes)):
        role, onset = roles.get(node, 'unknown'), onsets.get(node, 0.0)
        style_axes(
            ax, x_end, y_max, title=node, subtitle=_caption(role, onset),
            xlabel='seconds since run start' if idx >= len(nodes) - cols else '',
            ylabel='requests / s' if idx % cols == 0 else '',
        )
        draw_onset(ax, role, onset, x_end, y_max, label=False)
        for arm, series in arms.items():
            xs, ys = _rate_series(series.get(node, {}), n_buckets, args.bucket_s)
            _plot_with_partial_tail(
                ax, xs, ys, complete_buckets(ends[arm], args.bucket_s),
                SERIES[arm])
    for ax in flat[len(nodes):]:
        ax.set_visible(False)
    fig.tight_layout()
    fig.legend(handles=_legend_handles(arms), loc='upper center',
               ncol=len(arms) + 1, frameon=False, fontsize=9.5,
               labelcolor=INK_SECONDARY, bbox_to_anchor=(0.5, 0.02))
    fig.subplots_adjust(bottom=0.16)
    _save(fig, out_dir / 'all_servers_load', args.no_svg, tight=True)

    # -- the headline: total share ------------------------------------------- #
    _plot_share(out_dir, arms, nodes, honest, attackers, roles, args.no_svg)

    # -- fairness, two populations ------------------------------------------- #
    _plot_fairness(out_dir, arms, nodes, honest, n_buckets, args.bucket_s,
                   ends, args.no_svg)

    # -- table view ----------------------------------------------------------- #
    with open(out_dir / 'load_data.csv', 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['arm', 'node', 'role', 'attack_start_s', 't_s',
                    'requests', 'requests_per_s'])
        for arm, series in arms.items():
            for node in nodes:
                for i in range(n_buckets):
                    c = series.get(node, {}).get(i, 0)
                    w.writerow([arm, node, roles.get(node, 'unknown'),
                                f'{onsets.get(node, 0.0):g}',
                                f'{i * args.bucket_s:g}', c,
                                f'{c / args.bucket_s:.4f}'])

    print(f"Wrote load figures to {out_dir}/")
    for arm, series in arms.items():
        allv = [sum(series.get(n, {}).values()) for n in nodes]
        honv = [sum(series.get(n, {}).values()) for n in honest]
        atk = sum(sum(series.get(n, {}).values()) for n in attackers)
        print(f"  {ARM_LABEL[arm]:26} total={sum(allv):,}  "
              f"Jain(all {len(nodes)})={jain(allv):.3f}  "
              f"Jain(honest {len(honest)})={jain(honv):.3f}  "
              f"to attackers={atk / max(1, sum(allv)):.1%}")
    return 0


def _caption(role: str, onset: float) -> str:
    if role in ('none', '', None):
        return 'ground truth: honest'
    return f'ground truth: {role}, armed at t={onset:g}s'


def _legend_handles(arms) -> List[Any]:
    handles = [Line2D([0], [0], color=SERIES[a], linewidth=LINE_WIDTH,
                      label=ARM_LABEL[a]) for a in arms]
    handles.append(Patch(facecolor=ONSET_WASH, alpha=0.35,
                         label='attack armed (configured, not detected)'))
    return handles


def _plot_share(out_dir, arms, nodes, honest, attackers, roles, no_svg) -> None:
    """Total requests per server. The single figure a load-balancing claim rests on.

    Grouped bars rather than a stack: the comparison is per server between two
    arms, and a stack would invite reading the total, which is a property of the
    workload rather than of either router.
    """
    fig, ax = plt.subplots(figsize=(10.0, 4.8), dpi=160)
    fig.patch.set_facecolor(SURFACE)

    totals = {arm: [sum(series.get(n, {}).values()) for n in nodes]
              for arm, series in arms.items()}
    y_max = max(max(v) for v in totals.values()) * 1.18
    width = 0.8 / max(1, len(arms))
    xs = list(range(len(nodes)))

    # Attacker columns get the same wash the time-series figures use for the
    # armed band, so "red means this node was an attacker" holds across every
    # figure in the set rather than being re-learned per chart.
    for i, node in enumerate(nodes):
        if node in attackers:
            ax.axvspan(i - 0.5, i + 0.5, color=ONSET_WASH,
                       alpha=ONSET_WASH_ALPHA, zorder=0, linewidth=0)

    for k, (arm, values) in enumerate(totals.items()):
        offset = (k - (len(arms) - 1) / 2) * width
        ax.bar([x + offset for x in xs], values, width * 0.92,
               color=SERIES[arm], zorder=3, label=ARM_LABEL[arm],
               # A surface-coloured edge is the 2px gap between adjacent bars:
               # without it two grouped bars touch and read as one wide mark.
               edgecolor=SURFACE, linewidth=1.5)
        for x, v in zip(xs, values):
            ax.text(x + offset, v + y_max * 0.015, f'{v:,}', ha='center',
                    va='bottom', color=SERIES[arm], fontsize=8.5,
                    fontweight='bold', zorder=4)

    ax.set_xticks(xs)
    ax.set_xticklabels(
        [f'{n}\n{roles.get(n, "?") if n in attackers else "honest"}' for n in nodes],
        fontsize=9,
    )
    style_axes(ax, x_max=1.0, y_max=y_max,
               title='Total requests routed to each server',
               subtitle=_share_subtitle(totals, nodes, honest),
               ylabel='requests over the whole run')
    ax.set_xlim(-0.6, len(nodes) - 0.4)
    # The washed columns get a legend entry of their own. The role is already
    # spelled out under each tick, so the shading is never the only carrier --
    # but an unexplained band on a chart is a question the reader has to hold.
    handles, labels = ax.get_legend_handles_labels()
    handles.append(Patch(facecolor=ONSET_WASH, alpha=0.35,
                         label='attacker (ground truth)'))
    ax.legend(handles=handles, loc='upper left', frameon=False, fontsize=9.5,
              labelcolor=INK_SECONDARY, handlelength=1.6)
    fig.tight_layout()
    _save(fig, out_dir / 'load_share', no_svg)


def _share_subtitle(totals, nodes, honest) -> str:
    idx = {n: i for i, n in enumerate(nodes)}
    parts = []
    for arm, values in totals.items():
        hv = [values[idx[n]] for n in honest]
        parts.append(f'{ARM_LABEL[arm]}: Jain(all {len(nodes)})={jain(values):.3f}, '
                     f'Jain(honest {len(honest)})={jain(hv):.3f}')
    return '   |   '.join(parts)


def _plot_fairness(out_dir, arms, nodes, honest, n_buckets, bucket_s,
                   ends, no_svg) -> None:
    """Jain over time, over two populations, in two panels.

    Two panels rather than one chart with four lines: two series per panel keeps
    identity inside the two validated palette slots, and the left/right split IS
    the argument -- on the full roster the arms sit on top of each other, on the
    honest servers they separate.
    """
    fig, axes = plt.subplots(1, 2, figsize=(12.0, 4.4), dpi=160, sharey=True)
    fig.patch.set_facecolor(SURFACE)
    x_end = n_buckets * bucket_s

    panels = (
        (axes[0], nodes, f'All {len(nodes)} servers',
         'includes the four attackers — cannot tell "failed to spread load"\n'
         'from "deliberately withheld traffic from an attacker"'),
        (axes[1], honest, f'Honest servers only ({len(honest)})',
         'the population a load balancer is actually responsible for'),
    )
    for ax, population, title, subtitle in panels:
        style_axes(ax, x_end, 1.05, title=title, subtitle=subtitle,
                   xlabel='seconds since run start',
                   ylabel="Jain's fairness index" if ax is axes[0] else '')
        ax.set_yticks([0.0, 0.25, 0.5, 0.75, 1.0])
        line_ends = []
        for arm, series in arms.items():
            ys = _fairness_series(series, population, n_buckets)
            xs = [i * bucket_s for i in range(n_buckets)]
            x_lab, y_lab = _plot_with_partial_tail(
                ax, xs, ys, complete_buckets(ends[arm], bucket_s),
                SERIES[arm], ARM_LABEL[arm])
            if y_lab == y_lab:          # not NaN
                line_ends.append((arm, x_lab, y_lab))
        draw_end_labels(ax, line_ends, x_end, 1.05)
        ax.text(0.995, 0.02, 'dashed tail = final partial bucket (teardown)',
                transform=ax.transAxes, color=INK_MUTED, fontsize=8,
                ha='right', va='bottom')
        if len(arms) >= 2 and ax is axes[0]:
            ax.legend(loc='lower left', frameon=False, fontsize=9,
                      labelcolor=INK_SECONDARY, handlelength=1.6)
    fig.tight_layout()
    _save(fig, out_dir / 'fairness_over_time', no_svg)


def _save(fig, stem: Path, no_svg: bool, tight: bool = False) -> None:
    kw = {'facecolor': SURFACE}
    if tight:
        kw['bbox_inches'] = 'tight'
    fig.savefig(f'{stem}.png', **kw)
    if not no_svg:
        fig.savefig(f'{stem}.svg', **kw)
    plt.close(fig)


if __name__ == '__main__':
    raise SystemExit(main())
