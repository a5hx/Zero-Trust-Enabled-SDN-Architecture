"""Assemble the paper: substitute the generated SVG figures into the template."""
import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_REPO = _os.path.dirname(_os.path.dirname(_HERE))
import re

S = _HERE          # figures + template live beside these scripts
OUT = _os.path.join(_HERE, 'zero-trust-sdn-paper.html')   # intermediate, not a deliverable

CAPTIONS = {
    'FIG1': (
        'Figure 1',
        'The two detection rails over the 215 s live run, for four attacking edge servers '
        '(one honest server shown dashed for reference). <b>Panel (a):</b> the trust score never '
        'brings srv3 (sybil) or srv8 (on-off) below the 0.30 isolation line — srv3 bottoms out at '
        '0.312 and ends the run at 0.696. <b>Panel (b):</b> the anomaly level catches both, but '
        'never rises at all for srv6 (blackhole), which answers health checks at full speed and '
        'lies about nothing. Values are read from the controller\'s own 1 Hz node-status stream.'),
    'FIG2': (
        'Figure 2',
        'Confusion matrix over all 48 subjects in the live run (rows = ground truth, columns = '
        'predicted). Cell shade encodes count on a single-hue ramp; the two off-diagonal cells are '
        'the misclassifications, both of which stay within the correct attack family. The 40 honest '
        'subjects on the bottom-right diagonal are scored as a real class — they are what catches '
        'false accusation, and none was wrongly labelled.'),
    'FIG3': (
        'Figure 3',
        'Median SLO violation rate over 30 paired seeds, five strategies across four scenarios '
        '(lower is better). <b>zt_sdn</b> is the full system; <b>no_trust</b> is the same selector '
        'with trust pinned uniform and quarantine disabled, isolating the contribution of trust '
        'itself. The clean scenario is the one the system loses — see §7.4. Exact values in Table 10.'),
    'FIG4': (
        'Figure 4',
        'Scalability at 60% offered load, N = 4…64, driving the real selector inside an M/M/c '
        'queueing model. Offered load scales with N. <b>p2c</b> doubles throughput per doubling of '
        'the fleet at a flat 99.7–99.8% delivery ratio; <b>argmax</b> saturates at ~85 tasks/s from '
        'N = 8 and its delivery ratio collapses to 10.5%. Exact values in Table 14.'),
    'FIG5': (
        'Figure 5',
        'Ledger integrity and cost. <b>Panel (a):</b> after flipping one hex digit of block 10\'s '
        'Merkle root in a 21-block chain, block 10 fails its own digest and block 11 fails its link '
        '— every other block still verifies, because each chains to an untouched predecessor. The '
        'damage is localised to the seam rather than invalidating everything downstream. '
        '<b>Panel (b):</b> ledger append cost per trust update against batch size, with an interior '
        'minimum near 25; the shipped setting of 10 sits within 11% of it. Exact values in Tables 15 and 16.'),
    'FIG6': (
        'Figure 6',
        'Mean reward per UCB1 weight arm over the live run\'s 20 windows. The four arms that never '
        'held a cold-start window span just <b>0.0166</b> of reward — the bandit has no separable '
        'winner to converge on. The default arm (grey) is not comparable: one of its two windows was '
        'the run\'s opening window, in which zero tasks completed and the reward scored −0.2122; its '
        'only measured window scored 0.9213, the highest of the run. Exact values in Table 17.'),
}


def build():
    tpl = open(f'{S}/paper_template.html').read()
    for key, (label, caption) in CAPTIONS.items():
        svg = open(f'{S}/{key.lower()}.svg').read()
        block = (
            f'<figure>\n  <div class="fig-frame">\n{svg}\n  </div>\n'
            f'  <figcaption><b>{label}.</b> {caption}</figcaption>\n</figure>'
        )
        marker = '{{' + key + '}}'
        assert marker in tpl, f'missing marker {marker}'
        tpl = tpl.replace(marker, block)
    assert '{{' not in tpl, 'unsubstituted marker remains'
    open(OUT, 'w').write(tpl)
    print(f'wrote {OUT}  ({len(tpl):,} bytes)')


if __name__ == '__main__':
    build()
