"""One visual system for every figure this project's control arm produces.

Split out of `plot_trust.py` when `plot_load.py` arrived, for the reason any
second consumer of a palette gets one: two files each holding their own hex
values drift, and the first symptom is a paper whose trust figure and load
figure disagree about which colour means "baseline".

THE PALETTE IS VALIDATED, NOT CHOSEN
------------------------------------
Two categorical slots -- blue `#2a78d6` (baseline) and orange `#eb6834`
(zero-trust) -- checked with the dataviz validator against the `#fcfcfb` chart
surface under `--pairs all`:

    lightness band          PASS  (both inside L 0.43-0.77)
    chroma floor            PASS  (both >= 0.1)
    CVD separation          PASS  (worst dE 24.7, protan)
    normal-vision floor     PASS  (dE 33.6)
    contrast vs surface     PASS  (both >= 3:1)

Do not substitute hues without re-running it. A third series is not a new hue:
it is a third validated slot, or a facet.

WHAT IS NOT A SERIES COLOUR
---------------------------
Constants and context never wear a series hue, because a reader who has learned
"orange = zero-trust" must not meet orange meaning something else two figures
later:

    isolation threshold   muted ink, dashed   -- a constant, not data
    attack-armed band     a red wash + label  -- ground truth, not a measurement
    attacker marker       the same wash       -- so the two figure families agree

Light surface only. A paper figure has one surface; a dark palette validated
against a surface the figure never renders on would be decoration.
"""

from typing import List, Tuple

# -- chrome & ink ----------------------------------------------------------- #
SURFACE = '#fcfcfb'
INK_PRIMARY = '#0b0b0b'
INK_SECONDARY = '#52514e'
INK_MUTED = '#898781'
GRIDLINE = '#e1e0d9'
AXIS = '#c3c2b7'

# -- categorical slots ------------------------------------------------------ #
SERIES = {
    'baseline': '#2a78d6',     # slot 1
    'zero_trust': '#eb6834',   # slot 2
}
ARM_LABEL = {
    'baseline': 'baseline (no zero trust)',
    'zero_trust': 'zero-trust SDN',
}

# -- ground-truth context --------------------------------------------------- #
ONSET_WASH = '#d03b3b'
ONSET_WASH_ALPHA = 0.07

LINE_WIDTH = 2.0

#: Fraction of the x range added on the right so selective end-labels sit
#: INSIDE the axes instead of overrunning the spine. Curves and shading still
#: stop at the real end of the data -- only the viewport is wider, so nothing is
#: implied about time that was not measured.
X_HEADROOM = 0.10

#: Minimum vertical gap between two end-labels, as a fraction of the y range.
#: Below this the numbers overprint and read as one unusable smear -- which
#: happens exactly when the two arms finish close together, i.e. when the reader
#: most needs to tell them apart.
LABEL_MIN_GAP_FRAC = 0.045


def style_axes(ax, x_max: float, y_max: float, title: str, subtitle: str = '',
               xlabel: str = '', ylabel: str = '') -> None:
    """The house treatment: recessive grid, no top/right spines, muted ticks.

    `y_max` is passed rather than inferred so a caller can hold the same scale
    across a whole family of panels. An auto-scaled panel beside a fixed one is
    the fastest way to make two servers look comparable when they are not.
    """
    ax.set_facecolor(SURFACE)
    ax.set_xlim(0.0, max(x_max, 1e-9) * (1.0 + X_HEADROOM))
    ax.set_ylim(0.0, max(y_max, 1e-9))

    ax.grid(True, which='major', color=GRIDLINE, linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    for side in ('top', 'right'):
        ax.spines[side].set_visible(False)
    for side in ('left', 'bottom'):
        ax.spines[side].set_color(AXIS)
        ax.spines[side].set_linewidth(1.0)
    ax.tick_params(colors=INK_MUTED, labelsize=9, length=0)

    if xlabel:
        ax.set_xlabel(xlabel, color=INK_SECONDARY, fontsize=10)
    if ylabel:
        ax.set_ylabel(ylabel, color=INK_SECONDARY, fontsize=10)
    # Title padding scales with the subtitle's LINE COUNT, not merely its
    # presence. A two-line subtitle under a fixed 18pt pad prints straight
    # through the title -- which is what a multi-line caption always becomes
    # the moment one is written.
    lines = subtitle.count('\n') + 1 if subtitle else 0
    ax.set_title(title, color=INK_PRIMARY, fontsize=13, fontweight='bold',
                 loc='left', pad=10 + 13 * lines)
    if subtitle:
        ax.text(0.0, 1.02, subtitle, transform=ax.transAxes,
                color=INK_SECONDARY, fontsize=9.5, va='bottom', ha='left',
                linespacing=1.4)


def draw_onset(ax, role: str, onset: float, x_end: float, y_top: float,
               label: bool = True) -> None:
    """Shade from an attacker's CONFIGURED arming time to the end of its data.

    Labelled as configured, never as detected. It is ground truth read out of
    the recording; letting it read as a detection would have the figure imply
    the controller knew something at that instant, which is the claim the
    detection-latency numbers exist to establish separately.
    """
    if role in ('none', '', None) or onset >= x_end:
        return
    ax.axvspan(onset, x_end, color=ONSET_WASH, alpha=ONSET_WASH_ALPHA,
               zorder=1, linewidth=0)
    ax.axvline(onset, color=ONSET_WASH, linewidth=1.2, alpha=0.55, zorder=2)
    if label:
        ax.text(onset + x_end * 0.012, y_top * 0.965,
                f'{role} arms  t={onset:g}s\n(configured, not detected)',
                color=INK_SECONDARY, fontsize=8.5, ha='left', va='top',
                linespacing=1.35)


def resolve_label_collisions(
    ends: List[Tuple[str, float, float]], y_range: float = 1.0,
) -> List[Tuple[str, float, float, float]]:
    """Nudge overlapping end-labels apart, without moving the values they state.

    Takes [(arm, x_end, y_end)] and returns [(arm, x_end, y_end, y_label)]. Only
    `y_label` moves; `y_end` -- the number printed and the point a leader line
    attaches to -- is untouched, so a figure never displaces a datum to make
    room for its own annotation.
    """
    if len(ends) < 2:
        return [(arm, x, y, y) for arm, x, y in ends]

    gap = LABEL_MIN_GAP_FRAC * y_range
    ordered = sorted(ends, key=lambda e: e[2])
    labels = [e[2] for e in ordered]
    for i in range(1, len(labels)):
        if labels[i] - labels[i - 1] < gap:
            labels[i] = labels[i - 1] + gap
    # Re-centre the nudged block on the values it came from, so a pair near the
    # top of the axis is pushed down rather than off the chart.
    drift = ((labels[0] + labels[-1]) / 2.0
             - (ordered[0][2] + ordered[-1][2]) / 2.0)
    lo, hi = 0.015 * y_range, 0.985 * y_range
    labels = [min(hi, max(lo, y - drift)) for y in labels]
    return [(arm, x, y, lab) for (arm, x, y), lab in zip(ordered, labels)]


def draw_end_labels(ax, ends: List[Tuple[str, float, float]], x_end: float,
                    y_range: float, fmt: str = '{:.3f}') -> None:
    """One selective direct label per line, at its right-hand end.

    Never a number on every point. With two arms on one axis this is what keeps
    identity off colour alone, alongside the legend.
    """
    for arm, x, y_end, y_label in resolve_label_collisions(ends, y_range):
        if abs(y_label - y_end) > 1e-12:
            ax.plot([x, x + x_end * 0.018], [y_end, y_label],
                    color=SERIES[arm], linewidth=0.8, alpha=0.55,
                    zorder=5, clip_on=False)
        ax.text(x + x_end * 0.024, y_label, fmt.format(y_end),
                color=SERIES[arm], fontsize=9.5, fontweight='bold',
                va='center', ha='left', zorder=6)


def save_figure(fig, stem, no_svg: bool = False, tight: bool = False) -> None:
    """Write `{stem}.png`, and `{stem}.svg` unless `no_svg`, then close `fig`.

    Promoted here when a third figure family (`plot_interactions.py`) arrived.
    Two copies of five lines is a coincidence; three is a house rule that was
    never written down -- and the rule matters, because the SVG is what the
    paper embeds and the `facecolor` is what stops it rendering on a
    transparent ground that turns the muted ink unreadable.

    matplotlib is imported inside the function on purpose: every caller
    already imports it, and keeping it out of this module's import line lets
    the palette constants be read (by a test, or by a tool that emits SVG
    itself) in an environment where matplotlib is not installed.
    """
    import matplotlib.pyplot as plt

    kw = {'facecolor': SURFACE}
    if tight:
        kw['bbox_inches'] = 'tight'
    fig.savefig(f'{stem}.png', **kw)
    if not no_svg:
        fig.savefig(f'{stem}.svg', **kw)
    plt.close(fig)


def jain(values) -> float:
    """Jain's fairness index over the values given, INCLUDING zeros.

    Zeros included is the whole point: a server that received nothing is the
    starvation this index exists to detect, and dropping it from the denominator
    hides exactly that. Callers decide the population (the full roster, or the
    honest servers only) -- and that choice changes what the number means, so it
    belongs in the caller and in the figure's own caption, never in a default.
    """
    values = list(values)
    n = len(values)
    total = sum(values)
    sq = sum(v * v for v in values)
    return (total * total) / (n * sq) if (n and sq) else float('nan')
