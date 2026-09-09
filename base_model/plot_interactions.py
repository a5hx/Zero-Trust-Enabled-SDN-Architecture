#!/usr/bin/env python3
"""Client<->server interaction figures: structure, the server side, and speed.

    python3 -m base_model.plot_interactions --treatment data/events.jsonl

Writes into `base_model/interactions/`:

    interaction_matrix.png    client x server, one panel per arm -- who talked
                              to whom, the headline figure
    fan_out.png               distinct servers reached, per client, per arm
    binding_stability.png     how much of a client's traffic went to one server
    client_timeline.png       EVERY task as one mark: which client, which
                              server, when -- the who-used-what-when figure
    client_population.png     distinct clients per server over time (2x4 grid)
    srvN_interaction.png      the same per server, with its request rate
    outcome_by_server.png     success / timeout / failure / abandoned per server
    latency_ecdf.png          end-to-end task latency, whole distribution
    latency_over_time.png     latency p50 and p95 per bucket, per arm
    decision_time.png         controller selection cost, whole distribution
    residence_vs_latency.png  controller-observed against client-reported
    speed_summary.png         p50/p95/p99 for all three speed metrics

    interaction_matrix.csv    the points in the heatmap
    client_summary.csv        one row per client, including never-routed ones
    interaction_time.csv      one row per (server, bucket)
    task_timeline.csv         one row per task -- the raw who/what/when table
    speed_summary.csv         percentiles by metric and scope
    pairing_audit.csv         how the route<->report join actually went

WHAT THESE FIGURES ADD OVER `plot_load.py`
-------------------------------------------
`plot_load.py` already answers how much traffic each server got and how evenly
it was spread ACROSS SERVERS. Every figure here is about the dimension it
integrates away -- the client. A server taking a fair share of the fleet's
traffic can still be taking all of it from two clients and none from six, and
that is invisible in a load-share bar.

The two tools deliberately do not overlap: there is no request-rate figure and
no load-share bar here, only the client-resolved views.

WHY THE HEATMAP IS ROW-NORMALISED
---------------------------------
Cells are each client's OWN share of its traffic, not raw counts. Raw counts
cannot be read across arms or across clients here: the flood attacker sent
1,578 tasks against a typical client's ~135, and the two arms admitted
different numbers of clients (40 against 37, because three were refused).
A raw-count heatmap would render as one bright row and thirty-nine dark ones,
which says something true about the flood and nothing at all about routing.

Row-normalised, every client is one unit of demand and the question the figure
answers is the one it is for: where did that client's work go.

WHY LATENCY IS ON A LOG AXIS
----------------------------
The baseline's distribution is bimodal by construction -- roughly 60 ms when a
server answers and roughly 4,000 ms when a blackhole-bound client waits out its
`task_timeout_s`. On a linear axis the entire healthy population collapses onto
the y-axis and the figure shows two vertical lines. The log axis is what makes
both modes readable at once, and the two-decade gap between them IS the finding.
"""

import argparse
import csv
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.colors import LinearSegmentedColormap  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

from base_model.compare import _srv_sort_key  # noqa: E402
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
    draw_onset,
    save_figure,
    style_axes,
)
from base_model.interactions import (  # noqa: E402
    ARM_BASELINE,
    ARM_TREATMENT,
    AUDIT_FIELDS,
    CLIENT_FIELDS,
    DEFAULT_TASK_TIMEOUT_S,
    HONEST,
    MATRIX_FIELDS,
    SPEED_FIELDS,
    SPEED_METRICS,
    TIMELINE_FIELDS,
    TIME_FIELDS,
    ArmInteractions,
    active_clients_per_bucket,
    binding_stability,
    client_rows,
    effective_fan_out,
    latency_residence_disagreement,
    matrix_rows,
    outcome_counts,
    pairing_audit,
    score_arm_interactions,
    server_clients_per_bucket,
    speed_rows,
    speed_samples,
    speed_stats,
    time_rows,
    timeline_rows,
)
from evaluation.interval_report import DEFAULT_BUCKET_S  # noqa: E402

DEFAULT_OUT_DIR = 'base_model/interactions'

#: Outcome colours. Not series slots -- an outcome is not an arm, and a reader
#: who has learned "orange = zero-trust" must not meet orange meaning "timeout"
#: two figures later. Sequential severity instead, keyed to the onset wash the
#: rest of the family already uses for "something is wrong here".
#: Server identity needs EIGHT distinguishable colours, which the two validated
#: series slots cannot provide. This is the one deliberate departure from the
#: two-slot rule in `figure_style.py`, and it is a different KIND of scale: the
#: slots encode *which arm* (a comparison, always two), these encode *which
#: server* (an identity, always eight). Okabe-Ito, the standard CVD-safe
#: qualitative set, with its yellow (#F0E442) swapped for a dark olive because
#: yellow on the #fcfcfb chart surface fails contrast.
SERVER_COLORS = {
    'srv1': '#0072B2',   # blue
    'srv2': '#E69F00',   # orange
    'srv3': '#009E73',   # bluish green
    'srv4': '#CC79A7',   # reddish purple
    'srv5': '#D55E00',   # vermillion
    'srv6': '#56B4E9',   # sky blue
    'srv7': '#8C6D31',   # dark olive (replaces Okabe-Ito yellow)
    'srv8': '#4a4a4a',   # neutral dark
}


def _server_color(node: str) -> str:
    """Stable colour per server, wrapping past 8 rather than raising."""
    if node in SERVER_COLORS:
        return SERVER_COLORS[node]
    order = sorted(SERVER_COLORS)
    return SERVER_COLORS[order[abs(hash(node)) % len(order)]]


OUTCOME_COLORS = {
    'success': '#4b8b6b',
    'timeout': ONSET_WASH,
    'failure': '#8c3b3b',
    'abandoned': INK_MUTED,
}


# --------------------------------------------------------------------------- #
# Chrome
# --------------------------------------------------------------------------- #
def _house(ax) -> None:
    """The house chrome, WITHOUT `style_axes`'s 0-origin limits.

    `style_axes` sets `xlim(0, ...)`/`ylim(0, ...)`, which is right for a rate
    or a trust score and impossible for a log axis or an ECDF over a
    two-decade latency range. This applies the recessive grid, the dropped
    spines and the muted ticks, and leaves the limits to the caller.
    """
    ax.set_facecolor(SURFACE)
    ax.grid(True, which='major', color=GRIDLINE, linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    for side in ('top', 'right'):
        ax.spines[side].set_visible(False)
    for side in ('left', 'bottom'):
        ax.spines[side].set_color(AXIS)
        ax.spines[side].set_linewidth(1.0)
    ax.tick_params(colors=INK_MUTED, labelsize=9, length=0)


def _titles(ax, title: str, subtitle: str = '', xlabel: str = '',
            ylabel: str = '') -> None:
    if xlabel:
        ax.set_xlabel(xlabel, color=INK_SECONDARY, fontsize=10)
    if ylabel:
        ax.set_ylabel(ylabel, color=INK_SECONDARY, fontsize=10)
    lines = subtitle.count('\n') + 1 if subtitle else 0
    ax.set_title(title, color=INK_PRIMARY, fontsize=13, fontweight='bold',
                 loc='left', pad=10 + 13 * lines)
    if subtitle:
        ax.text(0.0, 1.02, subtitle, transform=ax.transAxes,
                color=INK_SECONDARY, fontsize=9.5, va='bottom', ha='left',
                linespacing=1.4)


def _ramp(arm_name: str) -> LinearSegmentedColormap:
    """A sequential ramp from the chart surface to that arm's own slot colour.

    Keeps the heatmaps inside the two validated hues instead of importing a
    third scale, so the panel a reader is looking at still says which arm it is
    even after the legend scrolls off.
    """
    return LinearSegmentedColormap.from_list(
        f'{arm_name}_ramp', [SURFACE, SERIES[arm_name]])


def _ecdf(values: Sequence[float]):
    vals = sorted(v for v in values if v is not None)
    n = len(vals)
    return vals, [(i + 1) / n for i in range(n)]


def _legend(ax, arms: List[ArmInteractions], loc: str = 'lower right') -> None:
    handles = [Line2D([0], [0], color=SERIES[a.name], linewidth=LINE_WIDTH,
                      label=f'{ARM_LABEL[a.name]}  (n={_n_clients(a)} clients)')
               for a in arms]
    ax.legend(handles=handles, loc=loc, frameon=False, fontsize=9,
              labelcolor=INK_SECONDARY, handlelength=1.8)


def _n_clients(arm: ArmInteractions) -> str:
    """The denominator, stated wherever a client count is implied.

    Never a bare "40" or "37": the two arms differ because three hosts were
    REFUSED at admission, not because the topologies differ, and a reader who
    reads it as a smaller fleet reads the fairness numbers wrong.
    """
    routed = len({c for (c, _s) in arm.routed})
    total = len(arm.truth.devices)
    if routed == total:
        return str(total)
    return f'{routed} of {total}, {total - routed} refused'


# --------------------------------------------------------------------------- #
# (a) Structure
# --------------------------------------------------------------------------- #
def fig_interaction_matrix(arms: List[ArmInteractions], out_dir: Path,
                           no_svg: bool) -> None:
    fig, axes = plt.subplots(1, len(arms), figsize=(6.4 * len(arms), 8.2), dpi=160)
    axes = [axes] if len(arms) == 1 else list(axes)
    for ax, arm in zip(axes, arms):
        servers = arm.servers
        clients = sorted({d for d in arm.truth.devices}, key=_srv_sort_key)
        grid = []
        for device in clients:
            ip = arm.truth.device_ip.get(device, device)
            row = [arm.routed.get((ip, s), 0) for s in servers]
            total = sum(row)
            # A client that was never routed is NOT a client that spread its
            # traffic evenly, and a row of zeros would render as exactly that.
            # NaN takes the `set_bad` colour instead, so "refused at admission"
            # is visibly a different kind of cell from "sent here rarely".
            grid.append([v / total for v in row] if total
                        else [float('nan')] * len(servers))

        cmap = _ramp(arm.name)
        cmap.set_bad(GRIDLINE)
        im = ax.imshow(grid, cmap=cmap, aspect='auto', vmin=0.0, vmax=1.0,
                       interpolation='nearest')
        # One scale across both panels, never per-panel autoscaling: the whole
        # comparison is that one arm's cells reach 1.0 and the other's sit near
        # 1/8, and a per-panel scale would normalise exactly that away.
        cbar = fig.colorbar(im, ax=ax, fraction=0.035, pad=0.02)
        cbar.set_ticks([0.0, 1.0 / len(servers), 0.5, 1.0])
        cbar.set_ticklabels(['0', f'1/{len(servers)}\neven', '½', '1\npinned'])
        cbar.ax.tick_params(colors=INK_MUTED, labelsize=8, length=0)
        cbar.outline.set_visible(False)
        ax.set_xticks(range(len(servers)))
        ax.set_xticklabels(servers, fontsize=8)
        ax.set_yticks(range(len(clients)))
        ax.set_yticklabels(clients, fontsize=6.5)
        ax.tick_params(colors=INK_MUTED, length=0)
        for side in ax.spines.values():
            side.set_visible(False)
        # Attacker servers marked on the axis itself, so the columns that are
        # dark in the treatment panel are legible as "withheld from an
        # attacker" rather than "starved".
        for i, s in enumerate(servers):
            if arm.role_of_server(s) != HONEST:
                ax.get_xticklabels()[i].set_color(ONSET_WASH)
        for i, d in enumerate(clients):
            if arm.role_of_device(d) != HONEST:
                ax.get_yticklabels()[i].set_color(ONSET_WASH)
        _titles(ax, ARM_LABEL[arm.name],
                f'share of each client\'s own requests  |  {_n_clients(arm)} clients\n'
                'red labels are attackers (configured, not detected); '
                'grey rows were never routed',
                xlabel='server', ylabel='client')
    fig.tight_layout()
    save_figure(fig, out_dir / 'interaction_matrix', no_svg, tight=True)


def fig_fan_out(arms: List[ArmInteractions], out_dir: Path, no_svg: bool) -> None:
    fig, ax = plt.subplots(figsize=(11.0, 4.6), dpi=160)
    devices = sorted(arms[0].truth.devices, key=_srv_sort_key)
    width = 0.8 / len(arms)
    x_max = len(devices)
    for k, arm in enumerate(arms):
        efo = effective_fan_out(arm)
        ys = [efo.get(arm.truth.device_ip.get(d, d), 0) for d in devices]
        xs = [i + k * width - 0.4 + width / 2 for i in range(len(devices))]
        ax.bar(xs, ys, width=width, color=SERIES[arm.name],
               label=f'{ARM_LABEL[arm.name]}  ({_n_clients(arm)} clients)',
               zorder=3, linewidth=0)
    # `_house` calls tick_params(colors=...), which repaints every tick label --
    # so the attacker highlighting has to come after it, not before, or it is
    # silently reset and the red labels this figure's own caption promises
    # never appear.
    _house(ax)
    ax.set_xticks(range(len(devices)))
    ax.set_xticklabels(devices, rotation=90, fontsize=6.5)
    for i, d in enumerate(devices):
        if arms[0].role_of_device(d) != HONEST:
            ax.get_xticklabels()[i].set_color(ONSET_WASH)
    ax.set_xlim(-0.8, x_max - 0.2)
    ax.set_ylim(0, max(len(a.servers) for a in arms) + 0.6)
    _titles(ax, 'How many distinct servers each client ever reached',
            'a bar of 1 is a client pinned for the whole run; 0 is a client refused at '
            'admission\nred labels are attackers (configured, not detected)',
            ylabel='distinct servers')
    # Under the axes: at 8 servers the bars reach the top of the panel across
    # the whole fleet, so any in-axes placement sits on data.
    fig.legend(loc='upper center', ncol=len(arms), frameon=False, fontsize=9.5,
               labelcolor=INK_SECONDARY, bbox_to_anchor=(0.5, 0.045))
    fig.subplots_adjust(bottom=0.26, top=0.82)
    save_figure(fig, out_dir / 'fan_out', no_svg, tight=True)


def fig_binding_stability(arms: List[ArmInteractions], out_dir: Path,
                          no_svg: bool) -> None:
    fig, ax = plt.subplots(figsize=(8.0, 4.6), dpi=160)
    for arm in arms:
        vals = [v for v in binding_stability(arm).values() if v is not None]
        xs, ys = _ecdf(vals)
        if not xs:
            continue
        ax.step(xs, ys, where='post', color=SERIES[arm.name],
                linewidth=LINE_WIDTH, zorder=4,
                label=f'{ARM_LABEL[arm.name]}  ({len(xs)} routed clients)')
    _house(ax)
    ax.set_xlim(0.0, 1.02)
    ax.set_ylim(0.0, 1.02)
    _titles(ax, 'Concentration of each client on its single busiest server',
            'x = share of that client\'s requests taken by one server.  1.0 is a '
            'static pin.\nA step at 1.0 means every client was pinned.',
            xlabel='dominant-server share', ylabel='cumulative share of clients')
    ax.legend(loc='upper left', frameon=False, fontsize=9,
              labelcolor=INK_SECONDARY, handlelength=1.8)
    fig.tight_layout()
    save_figure(fig, out_dir / 'binding_stability', no_svg, tight=True)


# --------------------------------------------------------------------------- #
# (b) The server side over time
# --------------------------------------------------------------------------- #
def _population_panel(ax, arms: List[ArmInteractions], node: str,
                      y_max: float, show_onset: bool = True) -> None:
    x_end = max(a.n_buckets * a.bucket_s for a in arms)
    for arm in arms:
        if node not in arm.truth.servers:
            continue
        counts = server_clients_per_bucket(arm, node)
        active = active_clients_per_bucket(arm)
        xs = [i * arm.bucket_s for i in range(len(counts))]
        ys = [(c / active[i]) if i < len(active) and active[i] else 0.0
              for i, c in enumerate(counts)]
        ax.plot(xs, ys, color=SERIES[arm.name], linewidth=LINE_WIDTH,
                solid_capstyle='round', zorder=4)
    style_axes(ax, x_end, y_max, node, '')
    if show_onset:
        for arm in arms:
            role = arm.role_of_server(node)
            if role != HONEST:
                draw_onset(ax, role, arm.truth.server_onset.get(node, 0.0),
                           x_end, y_max, label=False)
                break


def fig_client_population(arms: List[ArmInteractions], out_dir: Path,
                          no_svg: bool) -> None:
    nodes = sorted({n for a in arms for n in a.truth.servers}, key=_srv_sort_key)
    cols = 4
    rows = (len(nodes) + cols - 1) // cols
    # +1.5in of height reserved for the three-line header. Without it the
    # figure-level caption prints straight through the top row's panel titles --
    # the same failure `style_axes` scales its own title pad to avoid, one level
    # up where subplots_adjust is the only lever.
    fig, axes = plt.subplots(rows, cols, figsize=(4.2 * cols, 2.9 * rows + 1.5),
                             dpi=160, sharex=True, sharey=True)
    flat = axes.flatten() if hasattr(axes, 'flatten') else [axes]
    for ax, node in zip(flat, nodes):
        _population_panel(ax, arms, node, 1.0)
    for ax in flat[len(nodes):]:
        ax.set_visible(False)
    handles = [Line2D([0], [0], color=SERIES[a.name], linewidth=LINE_WIDTH,
                      label=f'{ARM_LABEL[a.name]}  ({_n_clients(a)} clients)')
               for a in arms]
    handles.append(Patch(facecolor=ONSET_WASH, alpha=ONSET_WASH_ALPHA * 4,
                         label='attack armed (configured, not detected)'))
    fig.suptitle('Share of the active fleet each server was talking to',
                 color=INK_PRIMARY, fontsize=14, fontweight='bold', x=0.01,
                 ha='left', y=0.985)
    fig.text(0.01, 0.945,
             'y = distinct clients this server served that bucket, over the clients '
             'sending anywhere in it.\nThe denominator is per bucket and per arm, so '
             'the staggered start and the three refused hosts cannot skew it.',
             color=INK_SECONDARY, fontsize=9.5, ha='left', va='top', linespacing=1.4)
    fig.legend(handles=handles, loc='upper center', ncol=len(handles),
               frameon=False, fontsize=9.5, labelcolor=INK_SECONDARY,
               bbox_to_anchor=(0.5, 0.02))
    fig.subplots_adjust(top=0.84, bottom=0.11)
    save_figure(fig, out_dir / 'client_population', no_svg, tight=True)


def fig_per_server(arms: List[ArmInteractions], out_dir: Path, no_svg: bool) -> None:
    nodes = sorted({n for a in arms for n in a.truth.servers}, key=_srv_sort_key)
    x_end = max(a.n_buckets * a.bucket_s for a in arms)
    for node in nodes:
        fig, (ax_top, ax_bot) = plt.subplots(
            2, 1, figsize=(8.0, 5.6), dpi=160, sharex=True)
        y_clients = 1.0
        y_rate = max(
            [sum(a.bucket_clients.get(node, {}).get(i, {}).values()) / a.bucket_s
             for a in arms for i in range(a.n_buckets)] + [0.1]) * 1.15
        _population_panel(ax_top, arms, node, y_clients)
        for arm in arms:
            per = arm.bucket_clients.get(node, {})
            xs = [i * arm.bucket_s for i in range(arm.n_buckets)]
            ys = [sum(per.get(i, {}).values()) / arm.bucket_s
                  for i in range(arm.n_buckets)]
            ax_bot.plot(xs, ys, color=SERIES[arm.name], linewidth=LINE_WIDTH,
                        solid_capstyle='round', zorder=4)
        style_axes(ax_bot, x_end, y_rate, '', '',
                   xlabel='seconds since run start', ylabel='requests / s')
        role = next((a.role_of_server(node) for a in arms
                     if a.role_of_server(node) != HONEST), HONEST)
        if role != HONEST:
            onset = next(a.truth.server_onset.get(node, 0.0) for a in arms
                         if a.role_of_server(node) != HONEST)
            draw_onset(ax_bot, role, onset, x_end, y_rate, label=False)
        _titles(ax_top, f'{node} — clients and demand',
                f'role: {role}  |  top: share of the active fleet served, '
                'bottom: requests per second',
                ylabel='share of active clients')
        _legend(ax_top, arms, loc='upper right')
        fig.tight_layout()
        save_figure(fig, out_dir / f'{node}_interaction', no_svg, tight=True)


def fig_client_timeline(arms: List[ArmInteractions], out_dir: Path,
                        no_svg: bool) -> None:
    """Every task as one mark: when it ran, which client, which server.

    The most literal answer to "which device was using which server, when" --
    and the only figure here that is not an aggregate. One row per client, one
    mark per task, coloured by the server that served it.

    Not bucketed. A bucket would have to pick a representative server per cell
    (the modal one, say) and would then hide exactly the thing worth seeing: a
    client bouncing between four servers inside one bucket looks identical to a
    client pinned to one. At ~135 tasks per client over ~310 s there is room to
    draw every one of them, so it draws every one of them.
    """
    devices = sorted({d for a in arms for d in a.truth.devices}, key=_srv_sort_key)
    index = {d: i for i, d in enumerate(devices)}
    x_end = max((a.duration_s or 0.0) for a in arms)

    fig, axes = plt.subplots(
        len(arms), 1, figsize=(15.0, 0.145 * len(devices) * len(arms) + 2.6),
        dpi=160, sharex=True, squeeze=False)
    axes = [row[0] for row in axes]

    for ax, arm in zip(axes, arms):
        ok_x, ok_y, ok_c = [], [], []
        bad_x, bad_y, bad_c = [], [], []
        for row in timeline_rows(arm):
            i = index.get(row['device'])
            if i is None:
                continue
            # Coloured by `blamed_on`, not by where the task ran. They differ
            # only for a flow re-steered off a quarantined node AFTER that node
            # had already swallowed the task: the survivor inherited a corpse
            # roughly a third of a second before the client gave up. Colouring
            # by the survivor draws a wall of failures on an honest server and
            # invites exactly the wrong conclusion.
            colour = _server_color(row['blamed_on'])
            if row['status'] == 'success':
                ok_x.append(row['t_s']); ok_y.append(i); ok_c.append(colour)
            else:
                bad_x.append(row['t_s']); bad_y.append(i); bad_c.append(colour)
        ax.scatter(ok_x, ok_y, c=ok_c, marker='s', s=7, linewidths=0,
                   alpha=0.95, zorder=3)
        # Failures keep their server's colour -- the useful question about a
        # failed task is which server lost it -- and change SHAPE instead, so
        # they stay legible without spending a second colour channel.
        ax.scatter(bad_x, bad_y, c=bad_c, marker='x', s=26, linewidths=1.1,
                   alpha=0.95, zorder=4)

        _house(ax)
        ax.set_xlim(-x_end * 0.01, x_end * 1.01)
        ax.set_ylim(len(devices) - 0.5, -0.5)          # iot1 at the top
        ax.set_yticks(range(len(devices)))
        ax.set_yticklabels(devices, fontsize=6.5)
        for d, i in index.items():
            if arm.role_of_device(d) != HONEST:
                ax.get_yticklabels()[i].set_color(ONSET_WASH)
        ax.grid(axis='y', visible=False)
        _titles(ax, ARM_LABEL[arm.name],
                f'one mark per task  |  {_n_clients(arm)} clients  |  '
'x = a task that timed out, failed, or never came back\n'
                'colour is the server CHARGED with the outcome, which after a '
                're-steer is the node that lost the task, not the one that '
                'inherited it\n'
                'red client labels are attackers (configured, not detected)',
                ylabel='client')
    axes[-1].set_xlabel('seconds since run start', color=INK_SECONDARY, fontsize=10)

    servers = sorted({n for a in arms for n in a.truth.servers}, key=_srv_sort_key)
    handles = []
    for n in servers:
        role = next((a.role_of_server(n) for a in arms
                     if a.role_of_server(n) != HONEST), HONEST)
        handles.append(Patch(facecolor=_server_color(n),
                             label=n if role == HONEST else f'{n} ({role})'))
    handles += [
        Line2D([0], [0], color=INK_MUTED, marker='s', linestyle='none',
               markersize=5, label='task succeeded'),
        Line2D([0], [0], color=INK_MUTED, marker='x', linestyle='none',
               markersize=7, label='timeout / failure / never returned'),
    ]
    fig.legend(handles=handles, loc='upper center', ncol=5, frameon=False,
               fontsize=9.5, labelcolor=INK_SECONDARY, bbox_to_anchor=(0.5, 0.035))
    fig.subplots_adjust(bottom=0.10, top=0.93, hspace=0.16)
    save_figure(fig, out_dir / 'client_timeline', no_svg, tight=True)


def fig_outcome_by_server(arms: List[ArmInteractions], out_dir: Path,
                          no_svg: bool) -> None:
    nodes = sorted({n for a in arms for n in a.truth.servers}, key=_srv_sort_key)
    fig, axes = plt.subplots(1, len(arms), figsize=(6.6 * len(arms), 4.8), dpi=160,
                             sharey=True)
    axes = [axes] if len(arms) == 1 else list(axes)
    order = ('success', 'timeout', 'failure', 'abandoned')
    for ax, arm in zip(axes, arms):
        counts = outcome_counts(arm)
        bottoms = [0.0] * len(nodes)
        totals = [max(1, sum(counts.get(n, {}).values())) for n in nodes]
        for key in order:
            vals = [100.0 * counts.get(n, {}).get(key, 0) / t
                    for n, t in zip(nodes, totals)]
            ax.bar(range(len(nodes)), vals, bottom=bottoms, width=0.68,
                   color=OUTCOME_COLORS[key], label=key, zorder=3, linewidth=0)
            bottoms = [b + v for b, v in zip(bottoms, vals)]
        _house(ax)
        ax.set_xticks(range(len(nodes)))
        ax.set_xticklabels(
            [f'{n}\nn={t}' for n, t in zip(nodes, totals)], fontsize=8)
        for i, n in enumerate(nodes):
            if arm.role_of_server(n) != HONEST:
                ax.get_xticklabels()[i].set_color(ONSET_WASH)
        ax.set_xlim(-0.7, len(nodes) - 0.3)
        ax.set_ylim(0, 100)
        _titles(ax, ARM_LABEL[arm.name],
                'n is tasks dispatched to that server, including the ones that never '
                'came back\nred labels are attackers (configured, not detected)',
                ylabel='share of tasks (%)')
    handles = [Patch(facecolor=OUTCOME_COLORS[k], label=k) for k in order]
    # Figure-level legend under the axes, then `bbox_inches='tight'` to grow the
    # canvas around it -- the same order plot_trust.py uses for its grid. With
    # tight_layout instead, the legend is measured before it is placed and the
    # bottom row of labels is cropped.
    fig.legend(handles=handles, loc='upper center', ncol=len(order), frameon=False,
               fontsize=9.5, labelcolor=INK_SECONDARY, bbox_to_anchor=(0.5, 0.03))
    fig.subplots_adjust(bottom=0.18, top=0.80)
    save_figure(fig, out_dir / 'outcome_by_server', no_svg, tight=True)


# --------------------------------------------------------------------------- #
# (c) Speed
# --------------------------------------------------------------------------- #
def _ecdf_figure(arms: List[ArmInteractions], metric: str, title: str,
                 subtitle: str, xlabel: str, stem: str, out_dir: Path,
                 no_svg: bool, log_x: bool = True) -> None:
    fig, ax = plt.subplots(figsize=(9.0, 4.8), dpi=160)
    for arm in arms:
        vals = speed_samples(arm, metric)
        xs, ys = _ecdf(vals)
        if not xs:
            continue
        ax.step(xs, ys, where='post', color=SERIES[arm.name],
                linewidth=LINE_WIDTH, zorder=4)
        s = speed_stats(vals)
        for pct, style in (('p50', ':'), ('p95', '--')):
            if s[pct] is not None:
                ax.axvline(s[pct], color=SERIES[arm.name], linewidth=1.0,
                           linestyle=style, alpha=0.55, zorder=2)
    _house(ax)
    if log_x:
        ax.set_xscale('log')
    ax.set_ylim(0.0, 1.02)
    _titles(ax, title, subtitle, xlabel=xlabel,
            ylabel='cumulative share of tasks')
    handles = [Line2D([0], [0], color=SERIES[a.name], linewidth=LINE_WIDTH,
                      label=f'{ARM_LABEL[a.name]}  (n={len(speed_samples(a, metric))} tasks)')
               for a in arms]
    handles += [Line2D([0], [0], color=INK_MUTED, linewidth=1.0, linestyle=':',
                       label='p50'),
                Line2D([0], [0], color=INK_MUTED, linewidth=1.0, linestyle='--',
                       label='p95')]
    ax.legend(handles=handles, loc='lower right', frameon=False, fontsize=9,
              labelcolor=INK_SECONDARY, handlelength=1.8)
    fig.tight_layout()
    save_figure(fig, out_dir / stem, no_svg, tight=True)


def fig_latency_ecdf(arms, out_dir, no_svg) -> None:
    _ecdf_figure(
        arms, 'latency_ms', 'End-to-end task latency, whole distribution',
        'client-measured round trip, honest clients only, single-request-in-flight '
        'pairings\nlog x: the healthy mode and the timeout mode are two decades apart',
        'latency (ms, log)', 'latency_ecdf', out_dir, no_svg)


def fig_decision_time(arms, out_dir, no_svg) -> None:
    _ecdf_figure(
        arms, 'decision_ms', 'Controller routing-decision time',
        'what the selection itself cost: a static table lookup against a scored '
        'ranking of 8 nodes',
        'decision time (ms, log)', 'decision_time', out_dir, no_svg)


def fig_latency_over_time(arms: List[ArmInteractions], out_dir: Path,
                          no_svg: bool) -> None:
    fig, ax = plt.subplots(figsize=(10.0, 4.8), dpi=160)
    x_end = max(a.n_buckets * a.bucket_s for a in arms)
    y_max = 0.0
    for arm in arms:
        per_bucket: Dict[int, List[float]] = {}
        for p in arm.pairings:
            if not p.trustworthy or p.latency_ms is None:
                continue
            if arm.role_of_device(p.device) != HONEST:
                continue
            per_bucket.setdefault(int(p.route_t_s // arm.bucket_s), []).append(
                p.latency_ms)
        xs = [i * arm.bucket_s for i in range(arm.n_buckets)]
        for pct, style, alpha in (('p50', '-', 1.0), ('p95', (0, (4, 2)), 0.75)):
            ys = [speed_stats(per_bucket.get(i, []))[pct] for i in range(arm.n_buckets)]
            # None, not 0, for a bucket with no completed task -- plotted as a
            # gap. A zero here would draw a latency of nothing through the exact
            # moment a server stopped answering.
            ax.plot(xs, ys, color=SERIES[arm.name], linewidth=LINE_WIDTH,
                    linestyle=style, alpha=alpha, zorder=4, solid_capstyle='round')
            y_max = max([y_max] + [y for y in ys if y is not None])
    _house(ax)
    ax.set_xlim(0.0, x_end)
    ax.set_yscale('log')
    onset = min((a.truth.server_onset.get(n, 0.0) for a in arms
                 for n in a.truth.servers if a.role_of_server(n) != HONEST),
                default=None)
    if onset is not None:
        ax.axvline(onset, color=ONSET_WASH, linewidth=1.2, alpha=0.55, zorder=2)
        ax.text(onset + x_end * 0.008, y_max, 'first attack arms\n(configured)',
                color=INK_SECONDARY, fontsize=8.5, ha='left', va='top',
                linespacing=1.35)
    _titles(ax, 'Task latency over the run',
            'honest clients only.  Solid p50, dashed p95, per '
            f'{int(arms[0].bucket_s)} s bucket.\nA gap is a bucket in which no task '
            'completed at all -- not a latency of zero.',
            xlabel='seconds since run start', ylabel='latency (ms, log)')
    handles = [Line2D([0], [0], color=SERIES[a.name], linewidth=LINE_WIDTH,
                      label=ARM_LABEL[a.name]) for a in arms]
    handles += [Line2D([0], [0], color=INK_MUTED, linewidth=LINE_WIDTH, label='p50'),
                Line2D([0], [0], color=INK_MUTED, linewidth=LINE_WIDTH,
                       linestyle=(0, (4, 2)), label='p95')]
    # Centre-right, not upper-left: the onset annotation is anchored to the top
    # of the axes at the arming time, and the band between the two arms' p95
    # traces is the only region of this figure that stays empty in both.
    ax.legend(handles=handles, loc='center right', frameon=False, fontsize=9,
              labelcolor=INK_SECONDARY, ncol=2, handlelength=1.8)
    fig.tight_layout()
    save_figure(fig, out_dir / 'latency_over_time', no_svg, tight=True)


def fig_residence_vs_latency(arms: List[ArmInteractions], out_dir: Path,
                             no_svg: bool) -> None:
    fig, axes = plt.subplots(1, len(arms), figsize=(6.4 * len(arms), 5.4), dpi=160)
    axes = [axes] if len(arms) == 1 else list(axes)
    for ax, arm in zip(axes, arms):
        pts = [(p.latency_ms, p.residence_ms) for p in arm.pairings
               if p.trustworthy and p.latency_ms is not None
               and arm.role_of_device(p.device) == HONEST
               and p.latency_ms > 0 and p.residence_ms > 0]
        if pts:
            ax.scatter([x for x, _ in pts], [y for _, y in pts], s=4, alpha=0.18,
                       color=SERIES[arm.name], linewidths=0, zorder=3)
            lo = min(min(x for x, _ in pts), min(y for _, y in pts))
            hi = max(max(x for x, _ in pts), max(y for _, y in pts))
            ax.plot([lo, hi], [lo, hi], color=INK_MUTED, linewidth=1.0,
                    linestyle=(0, (3, 3)), zorder=4)
        _house(ax)
        ax.set_xscale('log')
        ax.set_yscale('log')
        d = latency_residence_disagreement(arm)
        med = d['exact_median_ms']
        _titles(ax, ARM_LABEL[arm.name],
                'median (residence - latency) = '
                + ('--' if med is None else f'{med:.0f} ms')
                + f'  over {d["n_exact"]} pairings\n'
                'points above the dashed line are the expected case:\n'
                'residence also spans the client\'s report hop',
                xlabel='client-reported latency (ms, log)',
                ylabel='controller-observed residence (ms, log)')
    fig.tight_layout()
    save_figure(fig, out_dir / 'residence_vs_latency', no_svg, tight=True)


def fig_speed_summary(arms: List[ArmInteractions], out_dir: Path,
                      no_svg: bool) -> None:
    """A table drawn in the house palette, not matplotlib's table widget.

    The widget brings its own borders and font and would be the one figure in
    the family that visibly comes from somewhere else.
    """
    rows: List[List[str]] = []
    colors: List[str] = []
    for metric in SPEED_METRICS:
        for arm in arms:
            s = speed_stats(speed_samples(arm, metric))
            f = lambda v: '--' if v is None else (
                f'{v:,.0f}' if v >= 100 else f'{v:.1f}')
            rows.append([metric.replace('_ms', ''), ARM_LABEL[arm.name],
                         str(s['n']), f(s['p50']), f(s['p95']), f(s['p99']),
                         f(s['max'])])
            colors.append(SERIES[arm.name])

    headers = ['metric', 'arm', 'n', 'p50', 'p95', 'p99', 'max']
    widths = [0.16, 0.30, 0.10, 0.11, 0.11, 0.11, 0.11]
    xs, acc = [], 0.02
    for w in widths:
        xs.append(acc)
        acc += w

    fig, ax = plt.subplots(figsize=(9.6, 0.46 * (len(rows) + 3)), dpi=160)
    ax.set_axis_off()
    ax.set_xlim(0, 1)
    ax.set_ylim(0, len(rows) + 2.4)
    y = len(rows) + 1.4
    for x, h in zip(xs, headers):
        ax.text(x, y, h, color=INK_SECONDARY, fontsize=10, fontweight='bold',
                ha='right' if h not in ('metric', 'arm') else 'left',
                va='center')
    ax.plot([0.01, 0.99], [y - 0.45, y - 0.45], color=AXIS, linewidth=1.0)
    for r, (row, color) in enumerate(zip(rows, colors)):
        y = len(rows) - r
        for i, (x, cell) in enumerate(zip(xs, row)):
            ax.text(x, y, cell,
                    color=color if i == 1 else INK_PRIMARY,
                    fontsize=9.5, fontweight='bold' if i == 1 else 'normal',
                    ha='left' if i < 2 else 'right', va='center')
    _titles(ax, 'Speed of client<->server interaction',
            'honest clients, single-request-in-flight pairings only.  '
            'All values in milliseconds.\nlatency is client-measured; decision is the '
            'controller\'s own cost; residence spans both plus the report hop.')
    fig.tight_layout()
    save_figure(fig, out_dir / 'speed_summary', no_svg, tight=True)


# --------------------------------------------------------------------------- #
# CSV
# --------------------------------------------------------------------------- #
def _write_csv(path: Path, fields: Sequence[str], rows) -> None:
    with open(path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(fields), extrasaction='ignore')
        w.writeheader()
        for row in rows:
            # `None` is written as an empty cell, never 0 -- an unmeasured
            # quantity that renders as a number is the one failure mode every
            # scorer in this project is built to avoid.
            w.writerow({k: ('' if row.get(k) is None else row.get(k))
                        for k in fields})


def write_csvs(arms: List[ArmInteractions], out_dir: Path) -> None:
    _write_csv(out_dir / 'interaction_matrix.csv', MATRIX_FIELDS,
               (r for a in arms for r in matrix_rows(a)))
    _write_csv(out_dir / 'client_summary.csv', CLIENT_FIELDS,
               (r for a in arms for r in client_rows(a)))
    _write_csv(out_dir / 'interaction_time.csv', TIME_FIELDS,
               (r for a in arms for r in time_rows(a)))
    _write_csv(out_dir / 'task_timeline.csv', TIMELINE_FIELDS,
               (r for a in arms for r in timeline_rows(a)))
    _write_csv(out_dir / 'speed_summary.csv', SPEED_FIELDS,
               (r for a in arms for r in speed_rows(a)))
    _write_csv(out_dir / 'pairing_audit.csv', AUDIT_FIELDS,
               (pairing_audit(a) for a in arms))


def format_summary(arms: List[ArmInteractions]) -> str:
    """The short read, printed on the way out."""
    lines = ['', 'CLIENT <-> SERVER INTERACTION', '=' * 74]
    for arm in arms:
        au = pairing_audit(arm)
        fo = effective_fan_out(arm)
        routed = [v for ip, v in fo.items() if v]
        share = au['exact_share']
        lines += [
            f'{ARM_LABEL[arm.name]}   ({arm.events_path})',
            f'   clients        {_n_clients(arm)}',
            f'   fan-out        {min(routed) if routed else 0}-{max(routed) if routed else 0}'
            ' distinct servers per routed client',
            f'   pairing        {au["pairs"]} pairs, '
            + ('--' if share is None else f'{100 * share:.2f}% exact')
            + f', {au["fallback_pairs"]} fallback',
            f'   not paired     {au["abandoned_skipped"]} skipped, '
            f'{au["abandoned_aged_out"]} aged out, {au["orphan_reports"]} orphan reports',
        ]
        for metric in SPEED_METRICS:
            s = speed_stats(speed_samples(arm, metric))
            f = lambda v: '--' if v is None else f'{v:.1f}'
            lines.append(f'   {metric:<14} p50 {f(s["p50"]):>9}   p95 {f(s["p95"]):>9}'
                         f'   p99 {f(s["p99"]):>9}   (n={s["n"]})')
        lines.append('')
    return '\n'.join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--baseline', default='data/base_events.jsonl')
    parser.add_argument('--treatment', default=None)
    parser.add_argument('--out-dir', default=DEFAULT_OUT_DIR)
    parser.add_argument('--bucket-s', type=float, default=DEFAULT_BUCKET_S)
    parser.add_argument('--task-timeout-s', type=float,
                        default=DEFAULT_TASK_TIMEOUT_S,
                        help='client-side task timeout, used to age out a route '
                             'that can no longer be reported (default: matches '
                             'both arms\' configs)')
    parser.add_argument('--no-svg', action='store_true')
    args = parser.parse_args(argv)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    arms: List[ArmInteractions] = []
    for name, path in ((ARM_BASELINE, args.baseline),
                       (ARM_TREATMENT, args.treatment)):
        if not path:
            continue
        if not Path(path).exists():
            print(f'no recording at {path}\n'
                  f'  make one with:  sudo -E python3 -m '
                  f'{"base_model.run_base" if name == ARM_BASELINE else "run_demo"}')
            return 2
        arms.append(score_arm_interactions(name, path, args.bucket_s,
                                           args.task_timeout_s))

    if not arms:
        print('nothing to plot: pass --baseline and/or --treatment')
        return 2

    fig_interaction_matrix(arms, out_dir, args.no_svg)
    fig_fan_out(arms, out_dir, args.no_svg)
    fig_binding_stability(arms, out_dir, args.no_svg)
    fig_client_timeline(arms, out_dir, args.no_svg)
    fig_client_population(arms, out_dir, args.no_svg)
    fig_per_server(arms, out_dir, args.no_svg)
    fig_outcome_by_server(arms, out_dir, args.no_svg)
    fig_latency_ecdf(arms, out_dir, args.no_svg)
    fig_decision_time(arms, out_dir, args.no_svg)
    fig_latency_over_time(arms, out_dir, args.no_svg)
    fig_residence_vs_latency(arms, out_dir, args.no_svg)
    fig_speed_summary(arms, out_dir, args.no_svg)
    write_csvs(arms, out_dir)

    print(format_summary(arms))
    print(f'wrote figures and 6 CSVs into {out_dir}/')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
