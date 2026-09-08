"""Generate inline-SVG figures for the research paper.

Colors are the validated categorical slots (see validate_palette.py run):
slot1 blue, slot2 orange, slot3 aqua, slot4 yellow, slot5 magenta.
Series colors are referenced as CSS custom properties so light/dark swap in
one place; the paper defines --s1..--s5 for both modes.
"""
import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_REPO = _os.path.dirname(_os.path.dirname(_HERE))
import json, math

S = _HERE          # figures + template live beside these scripts

ESC = {'&': '&amp;', '<': '&lt;', '>': '&gt;'}
def esc(t):
    return ''.join(ESC.get(c, c) for c in str(t))


def fmt(v):
    return f"{v:.2f}".rstrip('0').rstrip('.')


# --------------------------------------------------------------------------- #
# Figure 1 -- the two-rail result: T(t) and A(t) for four attackers            #
# --------------------------------------------------------------------------- #
def fig_two_rails():
    d = json.load(open(f'{S}/fig_trust.json'))
    order = [('srv3', 'srv3 · sybil', 'var(--s1)'),
             ('srv6', 'srv6 · blackhole', 'var(--s2)'),
             ('srv8', 'srv8 · on-off', 'var(--s3)'),
             ('srv1', 'srv1 · grayhole', 'var(--s4)')]
    ref = ('srv4', 'srv4 · honest', 'var(--ink-muted)')

    W, PH, PAD_L, PAD_R, PAD_T, GAP = 780, 176, 46, 132, 22, 40
    plot_w = W - PAD_L - PAD_R
    xmax = 215.0

    def X(t):
        return PAD_L + t / xmax * plot_w

    def Y(v, top):
        return top + (1 - v) * PH

    parts = [f'<svg viewBox="0 0 {W} {PAD_T + PH * 2 + GAP + 44}" '
             f'class="fig" role="img" aria-label="Trust score and anomaly level over time for four attacking edge servers">']

    for pi, (title, key, thr, thr_lab) in enumerate([
            ('(a) Trust score T(t) — isolation threshold 0.30', 1, 0.30, 'isolation 0.30'),
            ('(b) Anomaly level Ā(t) — quarantine gate 0.50', 2, 0.50, 'gate 0.50')]):
        top = PAD_T + pi * (PH + GAP)
        parts.append(f'<text x="{PAD_L}" y="{top - 7}" class="fig-t">{esc(title)}</text>')
        # grid + y axis
        for gv in (0, 0.25, 0.5, 0.75, 1.0):
            y = Y(gv, top)
            parts.append(f'<line x1="{PAD_L}" y1="{y:.1f}" x2="{PAD_L+plot_w}" y2="{y:.1f}" class="grid"/>')
            parts.append(f'<text x="{PAD_L-8}" y="{y+3.5:.1f}" class="fig-ax" text-anchor="end">{fmt(gv)}</text>')
        # threshold
        ty = Y(thr, top)
        parts.append(f'<line x1="{PAD_L}" y1="{ty:.1f}" x2="{PAD_L+plot_w}" y2="{ty:.1f}" class="thr"/>')
        parts.append(f'<text x="{PAD_L+plot_w-4}" y="{ty-5:.1f}" class="fig-thr" text-anchor="end">{esc(thr_lab)}</text>')
        # reference (honest) series first, recessive
        pts = ' '.join(f"{X(r[0]):.1f},{Y(r[key], top):.1f}" for r in d[ref[0]])
        parts.append(f'<polyline points="{pts}" fill="none" stroke="{ref[2]}" '
                     f'stroke-width="1.5" stroke-dasharray="4 3" opacity="0.75"/>')
        for nid, lab, col in order:
            pts = ' '.join(f"{X(r[0]):.1f},{Y(r[key], top):.1f}" for r in d[nid])
            parts.append(f'<polyline points="{pts}" fill="none" stroke="{col}" stroke-width="2" '
                         f'stroke-linejoin="round" stroke-linecap="round"/>')
        # direct labels at right edge
        ends = [(nid, lab, col, d[nid][-1][key]) for nid, lab, col in order]
        ends.append((ref[0], ref[1], ref[2], d[ref[0]][-1][key]))
        ends.sort(key=lambda e: -e[3])
        # Stack labels downward to avoid overlap, then slide the whole stack back
        # up if it ran past the panel. In panel (b) four series all finish at 0.0,
        # so an unclamped stack walks straight off the bottom of the canvas.
        GAPY = 13
        placed = []
        for _, _, _, v in ends:
            y = Y(v, top)
            while any(abs(y - u) < GAPY for u in placed):
                y += GAPY
            placed.append(y)
        # Anything past the panel floor is repacked UPWARD from the floor. A
        # blanket shift of the whole stack would drag the top label out of the
        # panel entirely (panel (b)'s srv3 sits at 1.0 while four series tie at 0.0).
        bottom = top + PH
        for i in range(len(placed) - 1, -1, -1):
            placed[i] = min(placed[i], bottom)
            if i + 1 < len(placed) and placed[i + 1] - placed[i] < GAPY:
                placed[i] = placed[i + 1] - GAPY
        for (nid, lab, col, v), y in zip(ends, placed):
            parts.append(f'<circle cx="{PAD_L+plot_w:.1f}" cy="{Y(v,top):.1f}" r="3" fill="{col}"/>')
            parts.append(f'<text x="{PAD_L+plot_w+9}" y="{y+3.5:.1f}" class="fig-lab" fill="{col}">{esc(lab)}</text>')
        # x axis
        parts.append(f'<line x1="{PAD_L}" y1="{top+PH:.1f}" x2="{PAD_L+plot_w}" y2="{top+PH:.1f}" class="axis"/>')
        for tv in (0, 50, 100, 150, 200):
            parts.append(f'<text x="{X(tv):.1f}" y="{top+PH+15:.1f}" class="fig-ax" text-anchor="middle">{tv}s</text>')

    parts.append(f'<text x="{PAD_L+plot_w/2:.0f}" y="{PAD_T+PH*2+GAP+38}" class="fig-ax" text-anchor="middle">time since topology start (s)</text>')
    parts.append('</svg>')
    return '\n'.join(parts)


# --------------------------------------------------------------------------- #
# Figure 2 -- SLO violation rate, 5 strategies x 4 scenarios                   #
# --------------------------------------------------------------------------- #
def fig_baselines():
    data = {
        'clean': [0.0870, 0.0823, 0.1886, 0.0970, 0.0911],
        'sybil': [0.1397, 0.1225, 0.2780, 0.1159, 0.0984],
        'drop':  [0.1960, 0.1933, 0.2595, 0.1329, 0.0992],
        'both':  [0.2512, 0.2325, 0.3840, 0.1707, 0.1198],
    }
    strat = [('random', 'var(--s1)'), ('round_robin', 'var(--s2)'),
             ('least_conn', 'var(--s3)'), ('no_trust', 'var(--s4)'),
             ('zt_sdn', 'var(--s5)')]
    W, H, PAD_L, PAD_T, PAD_B = 780, 300, 52, 16, 54
    plot_h = H - PAD_T - PAD_B
    ymax = 0.40
    gw = (W - PAD_L - 24) / len(data)
    bw = (gw - 26) / len(strat)

    p = [f'<svg viewBox="0 0 {W} {H}" class="fig" role="img" '
         f'aria-label="Median SLO violation rate for five routing strategies across four scenarios">']
    for gv in (0, 0.1, 0.2, 0.3, 0.4):
        y = PAD_T + (1 - gv / ymax) * plot_h
        p.append(f'<line x1="{PAD_L}" y1="{y:.1f}" x2="{W-24}" y2="{y:.1f}" class="grid"/>')
        p.append(f'<text x="{PAD_L-8}" y="{y+3.5:.1f}" class="fig-ax" text-anchor="end">{gv:.1f}</text>')
    for gi, (scen, vals) in enumerate(data.items()):
        gx = PAD_L + gi * gw + 13
        for si, (v, (name, col)) in enumerate(zip(vals, strat)):
            x = gx + si * bw
            h = v / ymax * plot_h
            y = PAD_T + plot_h - h
            # 2px surface gap between adjacent bars
            p.append(f'<rect x="{x+1:.1f}" y="{y:.1f}" width="{bw-2:.1f}" height="{h:.1f}" '
                     f'fill="{col}" rx="3" ry="3"/>')
            p.append(f'<rect x="{x+1:.1f}" y="{y+h-4:.1f}" width="{bw-2:.1f}" height="4" fill="{col}"/>')
            # Selective direct labels: only the system under test carries a number.
            # A value on all 20 bars collides and duplicates Table 9 besides.
            if name == 'zt_sdn':
                p.append(f'<text x="{x+bw/2:.1f}" y="{y-6:.1f}" class="fig-val" '
                         f'text-anchor="middle">{v:.3f}</text>')
        p.append(f'<text x="{gx + (gw-26)/2:.1f}" y="{PAD_T+plot_h+18:.1f}" class="fig-t" '
                 f'text-anchor="middle">{esc(scen)}</text>')
    p.append(f'<line x1="{PAD_L}" y1="{PAD_T+plot_h:.1f}" x2="{W-24}" y2="{PAD_T+plot_h:.1f}" class="axis"/>')
    # legend
    lx = PAD_L
    for name, col in strat:
        p.append(f'<rect x="{lx}" y="{H-26}" width="10" height="10" rx="2" fill="{col}"/>')
        # explicit fill rather than a fill on .fig-lab: that class is also worn by
        # the series-coloured direct labels in figs 1 and 3, and a CSS fill would
        # override their presentation attributes.
        p.append(f'<text x="{lx+15}" y="{H-17}" class="fig-lab" fill="var(--ink)">{esc(name)}</text>')
        lx += 24 + len(name) * 6.6
    p.append('</svg>')
    return '\n'.join(p)


# --------------------------------------------------------------------------- #
# Figure 3 -- scalability: PDR and throughput vs N, p2c vs argmax at 60% load  #
# --------------------------------------------------------------------------- #
def fig_scale():
    ns = [4, 8, 16, 32, 64]
    pdr = {'p2c': [99.7, 99.8, 99.7, 99.8, 99.8], 'argmax': [99.2, 91.7, 45.8, 21.3, 10.5]}
    thru = {'p2c': [48.0, 95.2, 191.8, 382.3, 762.0], 'argmax': [47.9, 88.6, 87.2, 81.8, 80.4]}
    col = {'p2c': 'var(--s1)', 'argmax': 'var(--s2)'}

    W, PW, PH, PAD_T = 780, 330, 200, 26
    p = [f'<svg viewBox="0 0 {W} {PH+PAD_T+66}" class="fig" role="img" '
         f'aria-label="Packet delivery ratio and throughput versus fleet size for p2c and argmax selection">']

    def panel(ox, title, series, ymax, ylab, ticks, logx=True):
        p.append(f'<text x="{ox}" y="{PAD_T-9}" class="fig-t">{esc(title)}</text>')
        def X(n):
            return ox + (math.log2(n) - 2) / 4 * (PW - 56) + 44
        def Y(v):
            return PAD_T + (1 - v / ymax) * PH
        for gv in ticks:
            y = Y(gv)
            p.append(f'<line x1="{ox+44}" y1="{y:.1f}" x2="{ox+PW-12}" y2="{y:.1f}" class="grid"/>')
            p.append(f'<text x="{ox+38}" y="{y+3.5:.1f}" class="fig-ax" text-anchor="end">{gv:g}</text>')
        for name, vals in series.items():
            pts = ' '.join(f"{X(n):.1f},{Y(v):.1f}" for n, v in zip(ns, vals))
            p.append(f'<polyline points="{pts}" fill="none" stroke="{col[name]}" stroke-width="2" '
                     f'stroke-linejoin="round"/>')
            for n, v in zip(ns, vals):
                p.append(f'<circle cx="{X(n):.1f}" cy="{Y(v):.1f}" r="4" fill="{col[name]}" '
                         f'stroke="var(--surface-2)" stroke-width="2"/>')
            p.append(f'<text x="{X(ns[-1]):.1f}" y="{Y(vals[-1])-11:.1f}" class="fig-lab" '
                     f'fill="{col[name]}" text-anchor="end">{esc(name)}</text>')
        p.append(f'<line x1="{ox+44}" y1="{Y(0):.1f}" x2="{ox+PW-12}" y2="{Y(0):.1f}" class="axis"/>')
        for n in ns:
            p.append(f'<text x="{X(n):.1f}" y="{Y(0)+15:.1f}" class="fig-ax" text-anchor="middle">{n}</text>')
        p.append(f'<text x="{ox+(PW)/2:.0f}" y="{Y(0)+34:.1f}" class="fig-ax" text-anchor="middle">'
                 f'fleet size N (log₂ scale)</text>')

    panel(0, '(a) Packet delivery ratio (%)', pdr, 100, '%', [0, 25, 50, 75, 100])
    panel(400, '(b) Throughput (tasks/s)', thru, 800, 'tasks/s', [0, 200, 400, 600, 800])
    p.append('</svg>')
    return '\n'.join(p)


# --------------------------------------------------------------------------- #
# Figure 4 -- confusion matrix                                                 #
# --------------------------------------------------------------------------- #
def fig_confusion():
    labels = ['sybil', 'blackhole', 'grayhole', 'onoff', 'flood', 'spoof', 'bad_cred', 'none']
    M = [[0,0,0,1,0,0,0,0],
         [0,0,1,0,0,0,0,0],
         [0,0,1,0,0,0,0,0],
         [0,0,0,1,0,0,0,0],
         [0,0,0,0,1,0,0,0],
         [0,0,0,0,0,1,0,0],
         [0,0,0,0,0,0,2,0],
         [0,0,0,0,0,0,0,40]]
    CELL, PAD_L, PAD_T = 46, 92, 74
    W = PAD_L + CELL * 8 + 16
    H = PAD_T + CELL * 8 + 34
    p = [f'<svg viewBox="0 0 {W} {H}" class="fig" role="img" '
         f'aria-label="Confusion matrix of attack classification across 48 subjects">']
    p.append(f'<text x="{PAD_L}" y="20" class="fig-t">predicted →</text>')
    p.append(f'<text x="8" y="{PAD_T-10}" class="fig-t">truth ↓</text>')
    for j, lab in enumerate(labels):
        x = PAD_L + j * CELL + CELL / 2
        p.append(f'<text x="{x}" y="{PAD_T-10}" class="fig-ax" text-anchor="end" '
                 f'transform="rotate(-45 {x} {PAD_T-10})">{esc(lab)}</text>')
    for i, lab in enumerate(labels):
        y = PAD_T + i * CELL + CELL / 2 + 4
        p.append(f'<text x="{PAD_L-10}" y="{y}" class="fig-ax" text-anchor="end">{esc(lab)}</text>')
    for i in range(8):
        for j in range(8):
            v = M[i][j]
            x, y = PAD_L + j * CELL, PAD_T + i * CELL
            if v == 0:
                fill, cls = 'var(--cell-0)', 'fig-ax'
            elif i == j:
                # correct: sequential single-hue ramp by magnitude
                fill = 'var(--cell-hi)' if v >= 40 else ('var(--cell-md)' if v >= 2 else 'var(--cell-lo)')
                cls = 'fig-cell-hi' if v >= 40 else 'fig-cell'
            else:
                fill, cls = 'var(--cell-err)', 'fig-cell-err'
            p.append(f'<rect x="{x+1}" y="{y+1}" width="{CELL-2}" height="{CELL-2}" rx="4" fill="{fill}"/>')
            if v:
                p.append(f'<text x="{x+CELL/2}" y="{y+CELL/2+5}" class="{cls}" text-anchor="middle">{v}</text>')
    p.append('</svg>')
    return '\n'.join(p)




# --------------------------------------------------------------------------- #
# Figure 5 -- ledger: tamper localisation + commit cost vs batch size          #
# --------------------------------------------------------------------------- #
def fig_ledger():
    N = 21              # genesis + 20 blocks, as run in the experiment
    VICTIM, BROKEN = 10, 11
    W, H = 780, 286          # tall enough for panel (b)'s axis caption
    CW, CH, GAPX = 30, 34, 4
    x0, ytop = 8, 46

    p = [f'<svg viewBox="0 0 {W} {H}" class="fig" role="img" '
         f'aria-label="Tamper localisation across a 21-block ledger, and commit cost versus batch size">']

    # ---- panel (a): the chain ribbon
    p.append(f'<text x="{x0}" y="18" class="fig-t">'
             f'(a) One hex digit of block 10’s Merkle root flipped — damage stops at the seam</text>')
    for i in range(N):
        x = x0 + i * (CW + GAPX)
        if i == VICTIM:
            fill, lab = 'var(--cell-err)', 'var(--cell-ink-hi)'
        elif i == BROKEN:
            # near-black on amber: white measures 2.17:1 here and fails the floor
            fill, lab = 'var(--s4)', 'var(--ink-on-amber)'
        else:
            fill, lab = 'var(--cell-lo)', 'var(--ink)'
        p.append(f'<rect x="{x}" y="{ytop}" width="{CW}" height="{CH}" rx="3" fill="{fill}"/>')
        p.append(f'<text x="{x+CW/2}" y="{ytop+CH/2+4.5}" class="fig-cell" text-anchor="middle" '
                 f'fill="{lab}" style="font-size:11px">{i}</text>')
        if i:   # hash link
            p.append(f'<line x1="{x-GAPX}" y1="{ytop+CH/2}" x2="{x}" y2="{ytop+CH/2}" '
                     f'stroke="{"var(--cell-err)" if i == BROKEN else "var(--rule-strong)"}" '
                     f'stroke-width="{2.5 if i == BROKEN else 1.5}"/>')
    # callouts
    vx = x0 + VICTIM * (CW + GAPX) + CW / 2
    bx = x0 + BROKEN * (CW + GAPX) + CW / 2
    p.append(f'<line x1="{vx}" y1="{ytop+CH+3}" x2="{vx}" y2="{ytop+CH+13}" class="axis"/>')
    p.append(f'<text x="{vx-4}" y="{ytop+CH+25}" class="fig-ax" text-anchor="end" '
             f'fill="var(--cell-err)">hash mismatch</text>')
    p.append(f'<line x1="{bx}" y1="{ytop+CH+3}" x2="{bx}" y2="{ytop+CH+31}" class="axis"/>')
    p.append(f'<text x="{bx+4}" y="{ytop+CH+43}" class="fig-ax" fill="var(--s4)">broken link</text>')
    p.append(f'<text x="{x0}" y="{ytop-9}" class="fig-ax">'
             f'19 of 21 blocks still verify · blocks 12–20 chain correctly to an untouched predecessor</text>')

    # ---- panel (b): commit cost vs batch size
    bs = [1, 5, 10, 25, 50, 100]
    per = [0.0238, 0.0150, 0.0141, 0.0127, 0.0133, 0.0177]
    by, bh, bx0 = 176, 62, 60
    pw = 300
    p.append(f'<text x="{x0}" y="{by-14}" class="fig-t">(b) Ledger append cost per trust update vs batch size</text>')
    import math as _m
    def BX(v):
        return bx0 + (_m.log10(v) / 2.0) * pw
    def BY(v):
        return by + bh - (v / 0.026) * bh
    for gv in (0.0, 0.01, 0.02):
        y = BY(gv)
        p.append(f'<line x1="{bx0}" y1="{y:.1f}" x2="{bx0+pw}" y2="{y:.1f}" class="grid"/>')
        p.append(f'<text x="{bx0-7}" y="{y+3.5:.1f}" class="fig-ax" text-anchor="end">{gv:.3f}</text>')
    pts = ' '.join(f"{BX(b):.1f},{BY(v):.1f}" for b, v in zip(bs, per))
    p.append(f'<polyline points="{pts}" fill="none" stroke="var(--s1)" stroke-width="2"/>')
    for b, v in zip(bs, per):
        p.append(f'<circle cx="{BX(b):.1f}" cy="{BY(v):.1f}" r="4" fill="var(--s1)" '
                 f'stroke="var(--surface-2)" stroke-width="2"/>')
        p.append(f'<text x="{BX(b):.1f}" y="{BY(0)+15:.1f}" class="fig-ax" text-anchor="middle">{b}</text>')
    p.append(f'<line x1="{bx0}" y1="{BY(0):.1f}" x2="{bx0+pw}" y2="{BY(0):.1f}" class="axis"/>')
    p.append(f'<text x="{bx0+pw/2:.0f}" y="{BY(0)+32:.0f}" class="fig-ax" text-anchor="middle">'
             f'trust updates per block</text>')
    p.append(f'<text x="{bx0-7}" y="{by-2}" class="fig-ax" text-anchor="end">ms</text>')
    # shipped operating point
    p.append(f'<circle cx="{BX(10):.1f}" cy="{BY(0.0141):.1f}" r="8" fill="none" '
             f'stroke="var(--s2)" stroke-width="2"/>')
    p.append(f'<text x="{BX(10)+14:.1f}" y="{BY(0.0141)-8:.1f}" class="fig-lab" fill="var(--s2)">'
             f'shipped: 10/block</text>')
    p.append('</svg>')
    return '\n'.join(p)


# --------------------------------------------------------------------------- #
# Figure 6 -- UCB1 arm rewards, and the cold-start artifact                    #
# --------------------------------------------------------------------------- #
def fig_optimizer():
    # (label, pulls, mean reward as reported, warm-only mean or None)
    arms = [
        ('0.50 / 0.30 / 0.20', 2, 0.3546, 0.9213, 'hand-tuned default'),
        ('0.70 / 0.20 / 0.10', 5, 0.8689, None, ''),
        ('0.34 / 0.50 / 0.16', 5, 0.8743, None, ''),
        ('0.34 / 0.16 / 0.50', 4, 0.8645, None, ''),
        ('0.45 / 0.45 / 0.10', 4, 0.8577, None, ''),
    ]
    W, H = 780, 276        # room for the footnote line under the axis
    PAD_L, PAD_T, BARH, GAPY = 132, 58, 22, 12   # PAD_T clears title + ticks + annotation
    pw = 400

    def X(v):
        return PAD_L + max(0.0, v) / 1.0 * pw

    p = [f'<svg viewBox="0 0 {W} {H}" class="fig" role="img" '
         f'aria-label="Mean reward per UCB1 weight arm, showing the cold-start artifact on the default arm">']
    p.append(f'<text x="8" y="16" class="fig-t">Mean reward per weight arm over 20 windows '
             f'(w1 trust / w2 cpu / w3 latency)</text>')
    for gv in (0.0, 0.25, 0.5, 0.75, 1.0):
        x = X(gv)
        p.append(f'<line x1="{x:.1f}" y1="{PAD_T-6}" x2="{x:.1f}" '
                 f'y2="{PAD_T + len(arms)*(BARH+GAPY):.1f}" class="grid"/>')
        p.append(f'<text x="{x:.1f}" y="{PAD_T-11}" class="fig-ax" text-anchor="middle">{gv:g}</text>')
    for i, (lab, pulls, mean, warm, note) in enumerate(arms):
        y = PAD_T + i * (BARH + GAPY)
        col = 'var(--ink-muted)' if warm is not None else 'var(--s1)'
        p.append(f'<text x="{PAD_L-10}" y="{y+BARH/2+4:.1f}" class="fig-ax" text-anchor="end">{esc(lab)}</text>')
        p.append(f'<rect x="{PAD_L}" y="{y}" width="{X(mean)-PAD_L:.1f}" height="{BARH}" '
                 f'rx="3" fill="{col}"/>')
        p.append(f'<text x="{X(mean)+8:.1f}" y="{y+BARH/2+4:.1f}" class="fig-val">{mean:.4f}</text>')
        p.append(f'<text x="{PAD_L+pw+70:.1f}" y="{y+BARH/2+4:.1f}" class="fig-ax">{pulls} pulls</text>')
        if warm is not None:
            # the same arm, with the zero-outcome cold-start window excluded
            p.append(f'<line x1="{X(warm):.1f}" y1="{y-4}" x2="{X(warm):.1f}" y2="{y+BARH+4}" '
                     f'stroke="var(--s2)" stroke-width="2.5"/>')
            p.append(f'<text x="{X(warm)+7:.1f}" y="{PAD_T-30:.1f}" class="fig-lab" '
                     f'fill="var(--s2)" text-anchor="end">'
                     f'{warm:.4f} excluding the cold-start window  &#8595;</text>')
    yb = PAD_T + len(arms)*(BARH+GAPY)
    p.append(f'<line x1="{PAD_L}" y1="{yb:.1f}" x2="{PAD_L+pw:.1f}" y2="{yb:.1f}" class="axis"/>')
    p.append(f'<text x="{PAD_L+pw/2:.0f}" y="{yb+20:.0f}" class="fig-ax" text-anchor="middle">'
             f'mean reward  =  success rate − 0.2·latency − 0.2·load imbalance</text>')
    p.append(f'<text x="8" y="{yb+42:.0f}" class="fig-ax">'
             f'The four arms that never held a cold-start window span just 0.0166 — '
             f'the bandit cannot separate them.</text>')
    p.append('</svg>')
    return '\n'.join(p)


if __name__ == '__main__':
    # Numbered in the order the figures appear in the paper, not in the order the
    # generators were written -- a Figure 4 that appears before Figure 2 is a defect.
    figs = {'fig1': fig_two_rails(), 'fig2': fig_confusion(),
            'fig3': fig_baselines(), 'fig4': fig_scale(),
            'fig5': fig_ledger(), 'fig6': fig_optimizer()}
    for k, v in figs.items():
        open(f'{S}/{k}.svg', 'w').write(v)
        print(k, len(v), 'bytes')
