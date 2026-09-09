"""Drawing primitives for the Panel Review 1 slide diagrams.

One place for the canvas, the palette and the box/arrow vocabulary so that
eight diagrams read as one system rather than eight drawings. Everything is
laid out in a 160 x 90 coordinate space, which is 16:9 exactly, so a figure
drops onto a widescreen slide with no rescaling and no surprise crop.

The palette is `base_model/figure_style.py`'s, unchanged and for the same
reasons: the two validated categorical slots keep the meanings they already
carry in every results figure in this project (blue = baseline / control arm,
orange = zero-trust / treatment arm), the failure wash keeps meaning "an
attack, a denial, or an injected fault", and structure that is neither -- a
layer box, a process boundary -- wears a neutral. A reader who learns the
colours on the results slide can read the architecture slides with them.
"""

from pathlib import Path
from typing import List, Optional, Sequence, Tuple

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Rectangle  # noqa: E402

from base_model.figure_style import (  # noqa: E402
    AXIS, GRIDLINE, INK_MUTED, INK_PRIMARY, INK_SECONDARY, ONSET_WASH, SERIES, SURFACE,
)

OUT_DIR = Path(__file__).resolve().parent / 'figures'

W, H = 160.0, 90.0          # 16:9 in drawing units
FIG_W_IN, FIG_H_IN = 13.333, 7.5
DPI = 180                    # -> 2400 x 1350 px

BLUE = SERIES['baseline']
ORANGE = SERIES['zero_trust']
RED = ONSET_WASH

#: Named box treatments. `fill` is the body, `accent` the left rule that says
#: what kind of thing the box is. Identity never rests on fill alone -- every
#: box is also labelled -- so these stay light enough to print.
STYLES = {
    'layer':     dict(fill='#f2f1ec', accent=AXIS,        ink=INK_PRIMARY),
    'module':    dict(fill='#ffffff', accent=INK_SECONDARY, ink=INK_PRIMARY),
    'zt':        dict(fill='#fdf0e9', accent=ORANGE,      ink=INK_PRIMARY),
    'ledger':    dict(fill='#eef4fc', accent=BLUE,        ink=INK_PRIMARY),
    'external':  dict(fill='#f7f7f4', accent=INK_MUTED,   ink=INK_SECONDARY),
    'danger':    dict(fill='#fdeeee', accent=RED,         ink=INK_PRIMARY),
    'store':     dict(fill='#f4f2ea', accent='#8a8262',   ink=INK_PRIMARY),
    'deferred':  dict(fill='#fbfbf9', accent=INK_MUTED,   ink=INK_MUTED),
}


def canvas(title: str, subtitle: str = '', footer: str = ''):
    """A titled 16:9 figure with the drawing area in 160 x 90 units."""
    fig = plt.figure(figsize=(FIG_W_IN, FIG_H_IN), facecolor=SURFACE)
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, W)
    ax.set_ylim(0, H)
    ax.axis('off')
    ax.set_facecolor(SURFACE)

    ax.text(5, H - 5.0, title, fontsize=19, fontweight='bold',
            color=INK_PRIMARY, va='center', ha='left')
    if subtitle:
        ax.text(5, H - 8.2, subtitle, fontsize=10.0, color=INK_SECONDARY,
                va='top', ha='left', linespacing=1.5)
    ax.plot([5, W - 5], [H - 13.5, H - 13.5], color=GRIDLINE, linewidth=1.2,
            zorder=0)
    if footer:
        ax.text(5, 1.6, footer, fontsize=8.5, color=INK_MUTED, va='center',
                ha='left', linespacing=1.5)
    return fig, ax


def box(ax, x, y, w, h, title, lines: Sequence[str] = (), style='module',
        title_size=10.5, body_size=8.2, align='center', zorder=3, mono=False):
    """A rounded box with a left accent rule, a title, and optional body lines.

    Returns (cx, cy, x, y, w, h) so callers can anchor arrows without
    recomputing the geometry they just passed in -- the arithmetic that goes
    wrong silently in a hand-laid diagram is always the anchor arithmetic.
    """
    s = STYLES[style]
    ax.add_patch(FancyBboxPatch(
        (x, y), w, h, boxstyle='round,pad=0,rounding_size=0.9',
        facecolor=s['fill'], edgecolor=s['accent'], linewidth=1.1, zorder=zorder))
    ax.add_patch(Rectangle((x, y), 0.85, h, facecolor=s['accent'],
                           edgecolor='none', zorder=zorder + 1))

    tx = x + w / 2 if align == 'center' else x + 3.0
    ha = 'center' if align == 'center' else 'left'
    if lines:
        # Body text flows DOWN from a fixed offset below the title (va='top')
        # rather than being centred on a computed midpoint. Centring makes the
        # required height a function of the line count, which is exactly the
        # arithmetic that silently pushes text out through the bottom of a box
        # when a caller adds one more line. Required height is now simply
        # 4.2 + 1.9 * len(lines) + 0.6 units.
        ax.text(tx, y + h - 2.4, title, fontsize=title_size, fontweight='bold',
                color=s['ink'], ha=ha, va='center', zorder=zorder + 2)
        # Monospace for anything tabular: a column of numbers set in a
        # proportional face does not line up, and a ragged column of measured
        # results reads as carelessness about the measurements themselves.
        ax.text(tx, y + h - 4.2, '\n'.join(lines), fontsize=body_size,
                color=INK_SECONDARY, ha=ha, va='top', linespacing=1.5,
                zorder=zorder + 2,
                family='DejaVu Sans Mono' if mono else None)
    else:
        ax.text(tx, y + h / 2, title, fontsize=title_size, fontweight='bold',
                color=s['ink'], ha=ha, va='center', zorder=zorder + 2)
    return (x + w / 2, y + h / 2, x, y, w, h)


def band(ax, x, y, w, h, label, style='layer', label_size=9.5):
    """A labelled container drawn behind the boxes it holds."""
    s = STYLES[style]
    ax.add_patch(FancyBboxPatch(
        (x, y), w, h, boxstyle='round,pad=0,rounding_size=1.1',
        facecolor=s['fill'], edgecolor=s['accent'], linewidth=1.0,
        linestyle='-', zorder=1))
    ax.text(x + 1.8, y + h - 2.4, label, fontsize=label_size,
            fontweight='bold', color=INK_SECONDARY, ha='left', va='center',
            zorder=2)


def arrow(ax, p0: Tuple[float, float], p1: Tuple[float, float], label='',
          color=INK_SECONDARY, style='-', rad=0.0, label_dx=0.0, label_dy=1.6,
          size=7.8, lw=1.3, zorder=6, label_ha='center'):
    """A connector. `style` '-' solid, '--' dashed, ':' dotted."""
    ax.add_patch(FancyArrowPatch(
        p0, p1, arrowstyle='-|>', mutation_scale=11, linewidth=lw,
        linestyle=style, color=color, zorder=zorder,
        connectionstyle=f'arc3,rad={rad}', shrinkA=1.5, shrinkB=1.5))
    if label:
        mx, my = (p0[0] + p1[0]) / 2 + label_dx, (p0[1] + p1[1]) / 2 + label_dy
        ax.text(mx, my, label, fontsize=size, color=color, ha=label_ha,
                va='center', linespacing=1.4, zorder=zorder + 1,
                bbox=dict(boxstyle='round,pad=0.18', facecolor=SURFACE,
                          edgecolor='none', alpha=0.92))


def legend(ax, entries: List[Tuple[str, str]], x, y, cols=4, gap=34.0):
    """entries: [(style_name_or_colour, label)]."""
    for i, (kind, text) in enumerate(entries):
        col, row = i % cols, i // cols
        cx, cy = x + col * gap, y - row * 4.2
        colour = STYLES[kind]['accent'] if kind in STYLES else kind
        fill = STYLES[kind]['fill'] if kind in STYLES else colour
        ax.add_patch(FancyBboxPatch(
            (cx, cy - 1.15), 3.0, 2.3, boxstyle='round,pad=0,rounding_size=0.4',
            facecolor=fill, edgecolor=colour, linewidth=1.1, zorder=5))
        ax.text(cx + 4.0, cy, text, fontsize=8.4, color=INK_SECONDARY,
                ha='left', va='center', zorder=5)


def note(ax, x, y, text, w=None, size=8.4, color=INK_MUTED, ha='left'):
    ax.text(x, y, text, fontsize=size, color=color, ha=ha, va='center',
            linespacing=1.5, zorder=7)


def save(fig, stem: str) -> Path:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / f'{stem}.png'
    fig.savefig(path, dpi=DPI, facecolor=SURFACE)
    fig.savefig(OUT_DIR / f'{stem}.svg', facecolor=SURFACE)
    plt.close(fig)
    return path
