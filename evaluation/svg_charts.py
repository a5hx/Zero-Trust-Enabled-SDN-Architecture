"""Inline-SVG chart vocabulary for the generated analysis page.

Charts are rendered here, in Python, rather than by browser JS. The analysis
page's data is fixed at generation time, so there is nothing for JS to do --
and rendering server-side means the numbers and the pixels come out of one
language, one path. The dashboard's live charts had three defects that only
showed up when someone looked at the markup (`panel_fix.md` 6.3: mixed y-tick
precision, a label overhanging the viewBox, a stretched aspect ratio); every
one of those is an ordinary assertion here.

This is NOT a copy of `renderCharts()` in dashboard/index.html. That function
is hard-wired to `CH.buckets`, `CHART_DEFS`, the 'charts' host id and an
`i * BUCKET_S` x-axis, and it draws exactly one mark type. Four of the marks
below (grouped/emphasis bars, forest plot, heatmap, stat tile) do not exist
anywhere in the project.

DESIGN RULES THIS MODULE ENCODES
--------------------------------
From the `dataviz` skill, followed rather than approximated:

* **Emphasis over categorical.** When one series is the point and the rest are
  context -- which is every baseline comparison on this page -- the subject
  gets a hue and the rest get one recessive gray. Six categorical hues for six
  routing strategies would bury the only series the reader cares about, and is
  the single most common way a comparison chart misses its point.
* **Colour is computed, not eyeballed.** Every value in PALETTE below was run
  through the skill's validator against THIS page's surface (#161b22), not the
  palette's default surface. See the provenance note on each constant.
* **Text never wears the data colour.** Marks carry the series hue; labels,
  values and axis text use the text tokens. Identity comes from a swatch
  beside the text.
* **No dual axes, ever.** Two measures of different scale get two charts.
* **Label selectively.** The endpoint or the extreme, never a number on every
  point.
* **A legend for two or more series, none for one** -- a one-swatch legend just
  restates the title.
* **None means "no data" and is drawn as a gap**, never as zero. The same rule
  `availability_report.py` and `topology_metrics.py` already enforce: a metric
  with no opinion must not render as a floor value.
"""

from __future__ import annotations

import html
import math
from typing import Any, Dict, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------- #
# Palette                                                                      #
# --------------------------------------------------------------------------- #
# Surface is dashboard/index.html's --panel, so the two pages read as one
# system. Every colour below was validated against THIS surface with
# `dataviz/scripts/validate_palette.js`, not assumed from the palette defaults:
#
#   S1,S2       2 slots, --pairs all  -> PASS (CVD dE 26.8, normal 31.8)
#   S1,S2,S3    3 slots, --pairs all  -> PASS (CVD dE 9.4 deutan, normal 20.9)
#   SEQ         5 steps, --ordinal    -> PASS (monotone L, single hue, 3 deg spread)
#   DIM         3.0:1 contrast vs surface (its low chroma is the point -- it is
#               the de-emphasis gray, deliberately not a categorical slot)
#
# Re-run the validator before changing any of them.
SURFACE = '#161b22'
SURFACE_2 = '#1c2129'
BG = '#0d1117'
BORDER = '#2d333b'
INK = '#e6edf3'
MUTED = '#8b949e'
GRID = '#2c313a'
AXIS = '#3a4048'

S1 = '#3987e5'          # categorical slot 1 (blue)
S2 = '#d95926'          # categorical slot 2 (orange)
S3 = '#199e70'          # categorical slot 3 (aqua)
DIM = '#6e7681'         # de-emphasis gray: context series in an emphasis chart

#: Sequential ramp, low -> high. On a dark surface the LOW end is the dark end,
#: so a near-zero cell recedes toward the surface instead of glowing.
SEQ = ['#184f95', '#256abf', '#3987e5', '#6da7ec', '#b7d3f6']

# Status tokens, from index.html. Reserved for state (pass/fail/warn) and never
# reused as a series colour -- and always shipped with a text label, never
# colour alone.
GOOD = '#3fb950'
WARN = '#d29922'
BAD = '#f85149'


def esc(s: Any) -> str:
    """Escape for both element text and attribute values."""
    return html.escape(str(s), quote=True)


# --------------------------------------------------------------------------- #
# Number formatting                                                            #
# --------------------------------------------------------------------------- #
def nice_ceil(v: float) -> float:
    """Round an axis top up to a clean number."""
    if not (v > 0):
        return 1.0
    mag = 10 ** math.floor(math.log10(v))
    for m in (1, 2, 2.5, 5, 10):
        if v <= m * mag:
            return m * mag
    return 10 * mag


def fmt_tick(v: float, top: float) -> str:
    """Decimal places come from the axis TOP, not each tick's own magnitude.

    Otherwise one axis reads '0.00 / 50.0 / 100' -- three precisions for three
    numbers on the same scale. That exact defect shipped once in the live
    dashboard and was caught by reading the markup (panel_fix.md 6.3).
    """
    d = 0 if top >= 10 else 1 if top >= 1 else 2
    return f'{v:.{d}f}'


def fmt_val(v: Optional[float], unit: str = '', digits: Optional[int] = None) -> str:
    """A single value for a direct label or a table cell. None -> em dash.

    `digits` overrides the magnitude-based default. It exists because the
    default hides small differences that are the entire point of a comparison:
    SLO violation rates of 0.0870 and 0.0823 differ by 6%, and both render as
    '0.09' / '0.08' at two decimals -- a table that rounds away the comparison
    it is making.
    """
    if v is None:
        return '—'
    if digits is not None:
        s = f'{v:.{digits}f}'
    else:
        a = abs(v)
        s = f'{v:.0f}' if a >= 100 else f'{v:.1f}' if a >= 10 else f'{v:.2f}'
    if unit == '%':
        return s + '%'
    return f'{s} {unit}' if unit else s


#: Approximate advance width per character at a given font size, for the
#: system sans stack these labels use. Deliberately generous: it is only ever
#: used to RESERVE space, so over-estimating costs a few pixels of margin
#: while under-estimating clips a label.
_CHAR_W = 0.60


def text_w(s: str, size: float = 10.0) -> float:
    """Estimated rendered width of a label.

    Used to size margins BEFORE drawing, which is the only way to keep a
    direct label inside the viewBox. Guessing a fixed margin is how the live
    dashboard shipped an endpoint label that ran past its box and overhung the
    next chart in the grid (panel_fix.md 6.3).
    """
    return len(str(s)) * size * _CHAR_W


def _pathify(points: Sequence[Optional[Tuple[float, float]]]) -> str:
    """Build an SVG path, BREAKING at None rather than bridging it.

    Interpolating across a gap would draw a straight line through a window
    where nothing was measured, which reads as data.
    """
    out: List[str] = []
    pen_down = False
    for p in points:
        if p is None:
            pen_down = False
            continue
        cmd = 'L' if pen_down else 'M'
        out.append(f'{cmd}{p[0]:.1f} {p[1]:.1f}')
        pen_down = True
    return ' '.join(out)


# --------------------------------------------------------------------------- #
# Figures that are not charts                                                  #
# --------------------------------------------------------------------------- #
def stat_tile(label: str, value: str, sub: str = '', tone: str = '') -> str:
    """A single headline number. `tone` in {'', 'good', 'warn', 'bad'}.

    A one-bar bar chart is not a chart; the number is. Tone is a status
    channel, so it always ships alongside the text that says the same thing --
    never colour alone.
    """
    cls = f' tone-{tone}' if tone else ''
    sub_html = f'<div class="tile-sub">{esc(sub)}</div>' if sub else ''
    return (
        f'<div class="tile{cls}">'
        f'<div class="tile-label">{esc(label)}</div>'
        f'<div class="tile-value">{esc(value)}</div>'
        f'{sub_html}</div>'
    )


def legend(items: Sequence[Tuple[str, str]]) -> str:
    """Swatch + label pairs. Callers must omit this for a single series."""
    if len(items) < 2:
        return ''
    keys = ''.join(
        f'<span class="lkey"><i style="background:{esc(color)}"></i>{esc(name)}</span>'
        for name, color in items
    )
    return f'<div class="legend">{keys}</div>'


def _figure(title: str, sub: str, body: str, legend_html: str = '') -> str:
    sub_html = f'<div class="fig-sub">{esc(sub)}</div>' if sub else ''
    return (
        f'<figure class="fig">'
        f'<div class="fig-title">{esc(title)}</div>{sub_html}'
        f'{legend_html}{body}</figure>'
    )


def empty_figure(title: str, sub: str, reason: str, command: str = '') -> str:
    """The state a block renders in when its input was not produced.

    Explicit and named, never a silently missing section and never a zero
    standing in for a missing measurement.
    """
    cmd = f'<code class="cmd">{esc(command)}</code>' if command else ''
    return _figure(
        title, sub,
        f'<div class="fig-empty"><p>{esc(reason)}</p>{cmd}</div>',
    )


# --------------------------------------------------------------------------- #
# Line chart                                                                   #
# --------------------------------------------------------------------------- #
def line_chart(
    title: str,
    sub: str,
    series: Sequence[Dict[str, Any]],
    x_ticks: Sequence[Tuple[int, str]],
    unit: str = '',
    y_max: Optional[float] = None,
    bands: Sequence[Tuple[float, str]] = (),
    width: int = 420,
    height: int = 150,
) -> str:
    """Trend over time.

    `series`: [{'name', 'color', 'values': [float|None, ...]}] -- all the same
    length. `x_ticks`: (index, label) pairs. `bands`: (index, label) marks for
    a configured attack onset; shaded, and labelled as configured arming time
    rather than as a claim about when anything was detected.
    """
    n = max((len(s['values']) for s in series), default=0)
    if n == 0:
        return empty_figure(title, sub, 'No samples in this recording.')

    flat = [v for s in series for v in s['values'] if v is not None]
    if not flat:
        return empty_figure(title, sub, 'No data points in this window.')
    top = y_max if y_max is not None else nice_ceil(max(flat) * 1.1)
    if top <= 0:
        top = 1.0

    # Reserve the right margin for the widest label that will actually be
    # drawn, rather than hoping a fixed margin is enough.
    end_v = next((v for v in reversed(list(series[0]['values'])) if v is not None), None)
    PL, PT, PB = 46, 10, 22
    PR = max(24.0, text_w(fmt_val(end_v, unit)) + 16.0)
    iw, ih = width - PL - PR, height - PT - PB
    span = max(1, n - 1)

    def X(i: float) -> float:
        return PL + (i / span) * iw

    def Y(v: float) -> float:
        return PT + ih - (min(v, top) / top) * ih

    parts: List[str] = []

    # Attack bands first, behind everything.
    for at, label in bands:
        bx = X(max(0.0, min(float(at), float(span))))
        parts.append(
            f'<rect class="band" x="{bx:.1f}" y="{PT}" '
            f'width="{max(0.0, X(span) - bx):.1f}" height="{ih}"/>'
        )
        parts.append(f'<line class="bandedge" x1="{bx:.1f}" y1="{PT}" x2="{bx:.1f}" y2="{PT + ih}"/>')
        parts.append(
            f'<text class="bandlab" x="{bx + 3:.1f}" y="{PT + 9}">{esc(label)}</text>'
        )

    # Gridlines: solid hairlines, one step off the surface. Never dashed --
    # dashing reads as "threshold" or "projection" when it is only a grid.
    for f in (0.0, 0.5, 1.0):
        gy = PT + ih - f * ih
        parts.append(f'<line class="grid" x1="{PL}" y1="{gy:.1f}" x2="{PL + iw}" y2="{gy:.1f}"/>')
        parts.append(
            f'<text class="tick y" x="{PL - 6}" y="{gy + 3:.1f}">{esc(fmt_tick(f * top, top))}</text>'
        )

    for si, s in enumerate(series):
        vals = list(s['values']) + [None] * (n - len(s['values']))
        pts = [None if v is None else (X(i), Y(v)) for i, v in enumerate(vals)]
        d = _pathify(pts)
        if d:
            parts.append(f'<path class="sline" d="{d}" stroke="{esc(s["color"])}"/>')
        # Direct-label the endpoint only, and only for the first series --
        # a value on every point is chaos and goes unread.
        last = next((p for p in reversed(list(zip(pts, vals))) if p[0] is not None), None)
        if last is not None:
            (px, py), pv = last
            parts.append(
                f'<circle class="sdot" cx="{px:.1f}" cy="{py:.1f}" r="4" '
                f'fill="{esc(s["color"])}"/>'
            )
            if si == 0:
                parts.append(
                    f'<text class="endlab" x="{px + 8:.1f}" y="{py + 3:.1f}">'
                    f'{esc(fmt_val(pv, unit))}</text>'
                )

    parts.append(f'<line class="axis" x1="{PL}" y1="{PT + ih}" x2="{PL + iw}" y2="{PT + ih}"/>')
    for i, label in x_ticks:
        parts.append(
            f'<text class="tick x" x="{X(i):.1f}" y="{height - 6}">{esc(label)}</text>'
        )

    svg = (
        f'<svg viewBox="0 0 {width} {height}" preserveAspectRatio="xMidYMid meet" '
        f'role="img" aria-label="{esc(title)}">{"".join(parts)}</svg>'
    )
    return _figure(title, sub, svg,
                   legend([(s['name'], s['color']) for s in series]))


# --------------------------------------------------------------------------- #
# Horizontal bars (emphasis form)                                              #
# --------------------------------------------------------------------------- #
def hbar(
    title: str,
    sub: str,
    rows: Sequence[Tuple[str, Optional[float]]],
    unit: str = '',
    highlight: Optional[str] = None,
    x_max: Optional[float] = None,
    lower_is_better: bool = True,
    width: int = 420,
    row_h: int = 22,
) -> str:
    """Compare magnitude across named items.

    Horizontal because the labels are words (`least_conn`, `round_robin`), and
    a rotated axis label is a tax on the reader.

    `highlight` names the one row that is the subject; it takes slot 1 and
    every other row takes the de-emphasis gray. That is the emphasis form: with
    six routing strategies, six hues would bury the only series the reader is
    here for. A row whose value is None renders as a gap with an em dash --
    "not measured" is not zero.
    """
    if not rows:
        return empty_figure(title, sub, 'Nothing to compare.')

    vals = [v for _, v in rows if v is not None]
    top = x_max if x_max is not None else nice_ceil(max(vals) * 1.15) if vals else 1.0
    if top <= 0:
        top = 1.0

    PT, PB = 6, 18
    PL = max(60.0, max(text_w(lbl, 11.0) for lbl, _ in rows) + 14.0)
    PR = max(28.0, max(text_w(fmt_val(v, unit)) for _, v in rows) + 14.0)
    iw = width - PL - PR
    height = PT + PB + row_h * len(rows)

    parts: List[str] = []
    for f in (0.0, 0.5, 1.0):
        gx = PL + f * iw
        parts.append(f'<line class="grid" x1="{gx:.1f}" y1="{PT}" x2="{gx:.1f}" y2="{PT + row_h * len(rows)}"/>')
        parts.append(
            f'<text class="tick x" x="{gx:.1f}" y="{height - 5}">{esc(fmt_tick(f * top, top))}</text>'
        )

    # Bars are capped at 14px and the band's leftover is air -- never fill the
    # slot. Adjacent bars keep a >=2px surface gap by construction.
    bar_h = min(14, row_h - 8)
    for i, (label, v) in enumerate(rows):
        y = PT + i * row_h + (row_h - bar_h) / 2
        is_subject = highlight is not None and label == highlight
        color = S1 if is_subject else DIM
        parts.append(
            f'<text class="rowlab{" is-subject" if is_subject else ""}" '
            f'x="{PL - 8}" y="{y + bar_h / 2 + 3:.1f}">{esc(label)}</text>'
        )
        if v is None:
            parts.append(
                f'<text class="rowval na" x="{PL + 4}" y="{y + bar_h / 2 + 3:.1f}">—</text>'
            )
            continue
        w = max(0.0, min(v / top, 1.0)) * iw
        # 4px rounded data-end, square at the baseline: rx on a rect rounds all
        # four corners, so draw the round end only when the bar is long enough
        # to show it and clip the baseline side with the axis line over it.
        parts.append(
            f'<rect class="bar" x="{PL}" y="{y:.1f}" width="{w:.1f}" height="{bar_h}" '
            f'rx="{min(4.0, w / 2):.1f}" fill="{esc(color)}"/>'
        )
        parts.append(
            f'<text class="rowval" x="{PL + w + 7:.1f}" y="{y + bar_h / 2 + 3:.1f}">'
            f'{esc(fmt_val(v, unit))}</text>'
        )

    parts.append(f'<line class="axis" x1="{PL}" y1="{PT}" x2="{PL}" y2="{PT + row_h * len(rows)}"/>')

    direction = 'lower is better' if lower_is_better else 'higher is better'
    svg = (
        f'<svg viewBox="0 0 {width} {height}" preserveAspectRatio="xMidYMid meet" '
        f'role="img" aria-label="{esc(title)}">{"".join(parts)}</svg>'
    )
    full_sub = f'{sub} — {direction}' if sub else direction
    return _figure(title, full_sub, svg)


# --------------------------------------------------------------------------- #
# Forest plot                                                                  #
# --------------------------------------------------------------------------- #
def forest_plot(
    title: str,
    sub: str,
    rows: Sequence[Dict[str, Any]],
    width: int = 460,
    row_h: int = 26,
) -> str:
    """Effect per comparison, signed, against a zero line.

    `rows`: [{'label', 'value', 'significant': bool, 'annotation': str}] where
    `value` is a percentage improvement (positive = the system is better).

    Diverging by construction -- the zero line is the "no effect" midpoint, and
    the two directions genuinely mean opposite things. Significance rides a
    status colour AND the annotation text, never colour alone; a
    non-significant row is drawn hollow so it is distinguishable in print and
    under full CVD.
    """
    if not rows:
        return empty_figure(title, sub, 'No comparisons available.')

    PT, PB = 6, 18
    PL = max(90.0, max(text_w(r['label'], 11.0) for r in rows) + 14.0)
    PR = max(48.0, max(
        text_w(r.get('annotation') or f'{r.get("value") or 0:+.1f}%') for r in rows
    ) + 14.0)
    iw = width - PL - PR
    height = PT + PB + row_h * len(rows)

    mag = max((abs(r['value']) for r in rows if r.get('value') is not None), default=1.0)
    top = nice_ceil(mag * 1.15) or 1.0
    zero_x = PL + iw / 2

    def X(v: float) -> float:
        return zero_x + max(-1.0, min(v / top, 1.0)) * (iw / 2)

    parts: List[str] = []
    for f in (-1.0, -0.5, 0.0, 0.5, 1.0):
        gx = zero_x + f * (iw / 2)
        cls = 'axis' if f == 0.0 else 'grid'
        parts.append(f'<line class="{cls}" x1="{gx:.1f}" y1="{PT}" x2="{gx:.1f}" y2="{PT + row_h * len(rows)}"/>')
        parts.append(
            f'<text class="tick x" x="{gx:.1f}" y="{height - 5}">{esc(f"{f * top:+.0f}%")}</text>'
        )

    bar_h = min(12, row_h - 10)
    for i, r in enumerate(rows):
        y = PT + i * row_h + (row_h - bar_h) / 2
        v = r.get('value')
        sig = bool(r.get('significant'))
        parts.append(
            f'<text class="rowlab" x="{PL - 8}" y="{y + bar_h / 2 + 3:.1f}">{esc(r["label"])}</text>'
        )
        if v is None:
            parts.append(f'<text class="rowval na" x="{zero_x + 6}" y="{y + bar_h / 2 + 3:.1f}">—</text>')
            continue
        x0, x1 = (zero_x, X(v)) if v >= 0 else (X(v), zero_x)
        color = GOOD if v >= 0 else BAD
        # Hollow when not significant: shape carries the same fact as the
        # colour, so it survives print and full CVD.
        style = (f'fill="{esc(color)}"' if sig
                 else f'fill="none" stroke="{esc(color)}" stroke-width="1.5"')
        parts.append(
            f'<rect class="bar" x="{x0:.1f}" y="{y:.1f}" width="{max(1.0, x1 - x0):.1f}" '
            f'height="{bar_h}" rx="2" {style}/>'
        )
        lx = x1 + 7 if v >= 0 else x0 - 7
        anchor = 'start' if v >= 0 else 'end'
        parts.append(
            f'<text class="rowval" x="{lx:.1f}" y="{y + bar_h / 2 + 3:.1f}" '
            f'text-anchor="{anchor}">{esc(r.get("annotation") or f"{v:+.1f}%")}</text>'
        )

    svg = (
        f'<svg viewBox="0 0 {width} {height}" preserveAspectRatio="xMidYMid meet" '
        f'role="img" aria-label="{esc(title)}">{"".join(parts)}</svg>'
    )
    return _figure(title, sub, svg)


# --------------------------------------------------------------------------- #
# Heatmap                                                                      #
# --------------------------------------------------------------------------- #
def heatmap(
    title: str,
    sub: str,
    row_labels: Sequence[str],
    col_labels: Sequence[str],
    matrix: Sequence[Sequence[Optional[float]]],
    diagonal_is_correct: bool = True,
    cell: int = 34,
) -> str:
    """A grid of magnitudes -- here, the classification confusion matrix.

    One hue, low->high, from the validated sequential ramp: on a dark surface
    the low end is the DARK end, so an empty cell recedes into the page rather
    than glowing. Never a rainbow.

    Cell text is white or ink chosen by the fill's luminance -- the one place
    the skill allows text on a coloured fill, and it needs the luminance test
    to clear contrast at both ends of the ramp.
    """
    if not row_labels or not col_labels:
        return empty_figure(title, sub, 'No labels to score.')

    PT, PB = 74, 8
    PL = max(70.0, max(text_w(r, 11.0) for r in row_labels) + 14.0)
    # The rotated column labels stick out to the right of the last column.
    width = PL + cell * len(col_labels) + max(
        14.0, max(text_w(c, 10.0) for c in col_labels) * 0.71)
    height = PT + cell * len(row_labels) + PB

    flat = [v for row in matrix for v in row if v]
    hi = max(flat) if flat else 1

    parts: List[str] = []
    for j, cl in enumerate(col_labels):
        cx = PL + j * cell + cell / 2
        # Column labels are rotated because class names are long and the grid
        # is narrow; rows stay horizontal so at least one axis reads flat.
        parts.append(
            f'<text class="hcol" transform="rotate(-45 {cx:.1f} {PT - 8})" '
            f'x="{cx:.1f}" y="{PT - 8}">{esc(cl)}</text>'
        )
    for i, rl in enumerate(row_labels):
        cy = PT + i * cell + cell / 2
        parts.append(f'<text class="rowlab" x="{PL - 8}" y="{cy + 4:.1f}">{esc(rl)}</text>')
        for j in range(len(col_labels)):
            v = matrix[i][j] if j < len(matrix[i]) else 0
            v = 0 if v is None else v
            x = PL + j * cell
            y = PT + i * cell
            if v:
                # index into the ramp by magnitude
                k = min(len(SEQ) - 1, int((v / hi) * (len(SEQ) - 1) + 0.5))
                fill = SEQ[k]
                # Ramp runs dark->light, so the top steps need dark text.
                text_fill = '#0d1117' if k >= 3 else INK
            else:
                fill = SURFACE_2
                text_fill = MUTED
            on_diagonal = diagonal_is_correct and rl == (col_labels[j] if j < len(col_labels) else None)
            extra = ' diag' if on_diagonal else ''
            # 2px surface gap between cells -- the surface does the separating,
            # never a stroke drawn around the mark.
            parts.append(
                f'<rect class="cell{extra}" x="{x + 1}" y="{y + 1}" '
                f'width="{cell - 2}" height="{cell - 2}" rx="2" fill="{esc(fill)}"/>'
            )
            if v:
                parts.append(
                    f'<text class="cellval" x="{x + cell / 2:.1f}" y="{y + cell / 2 + 4:.1f}" '
                    f'fill="{esc(text_fill)}">{esc(int(v) if float(v).is_integer() else v)}</text>'
                )

    svg = (
        f'<svg viewBox="0 0 {width} {height}" preserveAspectRatio="xMidYMid meet" '
        f'role="img" aria-label="{esc(title)}">{"".join(parts)}</svg>'
    )
    return _figure(title, sub, svg)


# --------------------------------------------------------------------------- #
# Table                                                                        #
# --------------------------------------------------------------------------- #
def table(
    headers: Sequence[str],
    rows: Sequence[Sequence[Any]],
    numeric_from: int = 1,
    row_classes: Sequence[str] = (),
) -> str:
    """A plain table. Every chart on the page has one of these near it: the
    table view is the accessibility fallback the skill requires, and it is also
    what someone will copy numbers out of."""
    head = ''.join(
        f'<th class="{"num" if i >= numeric_from else ""}">{esc(h)}</th>'
        for i, h in enumerate(headers)
    )
    body: List[str] = []
    for ri, r in enumerate(rows):
        cls = row_classes[ri] if ri < len(row_classes) else ''
        cells = ''.join(
            f'<td class="{"num" if i >= numeric_from else ""}">'
            f'{"—" if c is None else esc(c)}</td>'
            for i, c in enumerate(r)
        )
        body.append(f'<tr class="{esc(cls)}">{cells}</tr>')
    return (
        f'<div class="tablewrap"><table><thead><tr>{head}</tr></thead>'
        f'<tbody>{"".join(body)}</tbody></table></div>'
    )
