"""Python twin of dataviz/scripts/validate_palette.js -- same constants, same math.

Ported because this box has no JS runtime. Matrices, thresholds and the OKLab
conversion are copied verbatim from the JS so the two agree.
"""
import math, sys

BAND = {'light': (0.43, 0.77), 'dark': (0.48, 0.67)}
CHROMA_FLOOR = 0.10
CVD_TARGET, CVD_FLOOR = 8.0, 6.0
NORMAL_FLOOR = 15.0
CONTRAST_MIN = 3.0
DEFAULT_SURFACE = {'light': '#fcfcfb', 'dark': '#1a1a19'}

MACHADO = {
    'protan': [[0.152286, 1.052583, -0.204868],
               [0.114503, 0.786281, 0.099216],
               [-0.003882, -0.048116, 1.051998]],
    'deutan': [[0.367322, 0.860646, -0.227968],
               [0.280085, 0.672501, 0.047413],
               [-0.011820, 0.042940, 0.968881]],
    'tritan': [[1.255528, -0.076749, -0.178779],
               [-0.078411, 0.930809, 0.147602],
               [0.004733, 0.691367, 0.303900]],
}


def hex2srgb(h):
    h = h.strip().lstrip('#')
    return [int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)]


def s2lin(c):
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def lin(h):
    return [s2lin(c) for c in hex2srgb(h)]


def rel_lum(h):
    r, g, b = lin(h)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a, b):
    hi, lo = sorted([rel_lum(a), rel_lum(b)], reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def oklab_from_lin(rgb):
    r, g, b = rgb
    l = (0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b) ** (1 / 3)
    m = (0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b) ** (1 / 3)
    s = (0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b) ** (1 / 3)
    return [0.2104542553 * l + 0.7936177850 * m - 0.0040720468 * s,
            1.9779984951 * l - 2.4285922050 * m + 0.4505937099 * s,
            0.0259040371 * l + 0.7827717662 * m - 0.8086757660 * s]


def oklch(h):
    L, a, b = oklab_from_lin(lin(h))
    return L, math.hypot(a, b)


def simulate(h, kind):
    r, g, b = lin(h)
    M = MACHADO[kind]
    return [max(0.0, min(1.0, M[i][0] * r + M[i][1] * g + M[i][2] * b)) for i in range(3)]


def delta_e(h1, h2, kind=None):
    a = oklab_from_lin(simulate(h1, kind) if kind else lin(h1))
    b = oklab_from_lin(simulate(h2, kind) if kind else lin(h2))
    return 100 * math.dist(a, b)


def validate(palette, mode='light', surface=None, pairs='adjacent'):
    surface = surface or DEFAULT_SURFACE[mode]
    lo, hi = BAND[mode]
    failed = False
    print(f"\n=== mode={mode} surface={surface} pairs={pairs} ===")
    print(f"{'slot':>4} {'hex':>9} {'L':>6} {'C':>6} {'contrast':>9}  checks")
    for i, h in enumerate(palette, 1):
        L, C = oklch(h)
        cr = contrast(h, surface)
        notes = []
        if not (lo <= L <= hi):
            notes.append(f"FAIL lightness band ({lo}-{hi})"); failed = True
        if C < CHROMA_FLOOR:
            notes.append("FAIL chroma floor"); failed = True
        if cr < CONTRAST_MIN:
            notes.append(f"WARN contrast <{CONTRAST_MIN} (relief rule: labels/table)")
        print(f"{i:>4} {h:>9} {L:6.3f} {C:6.3f} {cr:9.2f}  {'; '.join(notes) or 'ok'}")

    idx = ([(i, i + 1) for i in range(len(palette) - 1)] if pairs == 'adjacent'
           else [(i, j) for i in range(len(palette)) for j in range(i + 1, len(palette))])
    print(f"\n{'pair':>9} {'normal':>7} {'protan':>7} {'deutan':>7} {'tritan':>7}  verdict")
    worst_normal = 1e9
    worst_cvd = 1e9
    for i, j in idx:
        a, b = palette[i], palette[j]
        n = delta_e(a, b)
        p = delta_e(a, b, 'protan')
        d = delta_e(a, b, 'deutan')
        t = delta_e(a, b, 'tritan')
        cvd = min(p, d)
        worst_normal = min(worst_normal, n)
        worst_cvd = min(worst_cvd, cvd)
        v = []
        if n < NORMAL_FLOOR:
            v.append("FAIL normal-vision floor"); failed = True
        if cvd < CVD_FLOOR:
            v.append("FAIL CVD"); failed = True
        elif cvd < CVD_TARGET:
            v.append("WARN CVD 6-8 (needs secondary encoding)")
        print(f"{i+1}-{j+1:<7} {n:7.1f} {p:7.1f} {d:7.1f} {t:7.1f}  {'; '.join(v) or 'ok'}")
    print(f"\nworst normal-vision dE {worst_normal:.1f} (floor {NORMAL_FLOOR}) | "
          f"worst CVD dE {worst_cvd:.1f} (target {CVD_TARGET}, floor {CVD_FLOOR})")
    print("RESULT:", "FAIL" if failed else "PASS")
    return not failed


if __name__ == '__main__':
    pal = [c.strip() for c in sys.argv[1].split(',') if c.strip()]
    mode = 'light'
    surface = None
    pairs = 'adjacent'
    args = sys.argv[2:]
    for k, a in enumerate(args):
        if a == '--mode':
            mode = args[k + 1]
        elif a == '--surface':
            surface = args[k + 1]
        elif a == '--pairs':
            pairs = args[k + 1]
    ok = validate(pal, mode, surface, pairs)
    sys.exit(0 if ok else 1)
