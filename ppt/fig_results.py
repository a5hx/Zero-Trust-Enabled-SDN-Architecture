"""Section 2/3 results visuals, drawn from the two scored live runs.

Sources, all in-repo:
  data/comparison/comparison.txt   baseline vs zero-trust, same config
  data/nfr_report.txt              the four NFRs
  data/raft_timeline.jsonl         the recorded Raft failover
Nothing on these figures is illustrative or rounded for effect.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402

from diagram_kit import (  # noqa: E402
    BLUE, DPI, FIG_H_IN, FIG_W_IN, INK_MUTED, INK_PRIMARY, INK_SECONDARY,
    ORANGE, OUT_DIR, RED, SURFACE, GRIDLINE, AXIS, box, canvas, note, save,
)

#: (title, unit, baseline, zero-trust, better_is)  — every number from
#: data/comparison/comparison.txt over the 2026-09-05 pair of runs.
METRICS = [
    ('Packet delivery ratio',      '%',      94.29, 99.10, 'up'),
    ('Honest device availability', '%',      85.67, 99.00, 'up'),
    ('Tasks lost to timeout',      'tasks',  380.0,  58.0, 'down'),
    ('p95 task latency',           'ms',     260.0, 134.3, 'down'),
    ('Jain fairness, honest only',  '',       0.689, 0.992, 'up'),
    ('Requests to attacker nodes', '%',       30.5,  12.5, 'down'),
]

#: onset → first isolation, seconds. The baseline never isolates anything,
#: which is an absent mechanism and is labelled as such rather than as a bar
#: of height zero.
CONTAINMENT = [('srv3\nsybil', 8.2), ('srv6\nblackhole', 8.7),
               ('srv8\non-off', 9.9), ('srv1\ngrayhole', 11.3)]


def _bar_panel(ax, title, unit, base, treat, better):
    ax.set_facecolor(SURFACE)
    bars = ax.bar([0, 1], [base, treat], width=0.62,
                  color=[BLUE, ORANGE], zorder=3)
    top = max(base, treat)
    ax.set_ylim(0, top * 1.34)
    ax.set_xlim(-0.62, 1.62)
    ax.set_xticks([0, 1])
    ax.set_xticklabels(['baseline', 'zero-trust'], fontsize=8.4,
                       color=INK_SECONDARY)
    ax.set_yticks([])
    for side in ('top', 'right', 'left'):
        ax.spines[side].set_visible(False)
    ax.spines['bottom'].set_color(AXIS)
    ax.tick_params(length=0)
    fmt = '{:.0f}' if unit == 'tasks' else ('{:.3f}' if unit == '' else '{:.2f}')
    for b, v in zip(bars, (base, treat)):
        ax.text(b.get_x() + b.get_width() / 2, v + top * 0.05,
                fmt.format(v) + (f' {unit}' if unit not in ('', 'tasks') else ''),
                ha='center', va='bottom', fontsize=9.0, fontweight='bold',
                color=INK_PRIMARY)
    arrow_txt = '↓ lower is better' if better == 'down' else '↑ higher is better'
    ax.set_title(title, fontsize=9.8, fontweight='bold', color=INK_PRIMARY,
                 loc='left', pad=13)
    ax.text(0.0, 1.02, arrow_txt, transform=ax.transAxes, fontsize=7.8,
            color=INK_MUTED, ha='left', va='bottom')


def results_comparison():
    fig = plt.figure(figsize=(FIG_W_IN, FIG_H_IN), facecolor=SURFACE)
    fig.text(0.037, 0.945, 'Results — controlled comparison against the no-zero-trust control arm',
             fontsize=19, fontweight='bold', color=INK_PRIMARY, va='center')
    fig.text(0.037, 0.893,
             'Two live Mininet runs, 2026-09-05: baseline 307.5 s (6 764 tasks), zero-trust 313.2 s (6 530 tasks). Same topology, same 40 devices,\n'
             'same six attacks on the same schedule, launched by the same code. The arms differ in who routes, and in whether anything acts on trust.',
             fontsize=10.0, color=INK_SECONDARY, va='top', linespacing=1.5)

    for i, (title, unit, b, t, better) in enumerate(METRICS):
        ax = fig.add_axes([0.037 + (i % 3) * 0.323, 0.635 - (i // 3) * 0.220,
                           0.245, 0.145])
        _bar_panel(ax, title, unit, b, t, better)

    # containment panel
    ax = fig.add_axes([0.037, 0.165, 0.40, 0.155])
    ax.set_facecolor(SURFACE)
    xs = range(len(CONTAINMENT))
    bars = ax.bar(xs, [v for _, v in CONTAINMENT], width=0.6, color=ORANGE, zorder=3)
    ax.set_ylim(0, 16.5)
    ax.set_xticks(list(xs))
    ax.set_xticklabels([n for n, _ in CONTAINMENT], fontsize=8.2, color=INK_SECONDARY)
    ax.set_ylabel('seconds from onset', fontsize=8.6, color=INK_SECONDARY)
    ax.tick_params(colors=INK_MUTED, labelsize=8.2, length=0)
    ax.grid(True, axis='y', color=GRIDLINE, linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    for side in ('top', 'right'):
        ax.spines[side].set_visible(False)
    for side in ('left', 'bottom'):
        ax.spines[side].set_color(AXIS)
    for b, (_, v) in zip(bars, CONTAINMENT):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.4, f'{v:.1f} s', ha='center',
                va='bottom', fontsize=9.0, fontweight='bold', color=INK_PRIMARY)
    ax.set_title('Time from attack onset to isolation', fontsize=9.8,
                 fontweight='bold', color=INK_PRIMARY, loc='left', pad=13)
    ax.text(0.0, 1.02, 'baseline: never, for all four — it has no isolation path',
            transform=ax.transAxes, fontsize=7.8, color=RED, ha='left', va='bottom')

    # NFR + integrity panel, as text
    fig.text(0.475, 0.330, 'Non-functional requirements — data/nfr_report.txt',
             fontsize=9.8, fontweight='bold', color=INK_PRIMARY, va='top')
    fig.text(0.475, 0.298,
             'Routing decision    < 200 ms   mean 0.53 ms · p95 0.71 ms · max 6.64 ms  (n=6 611)   PASS\n'
             'Isolation           < 3 000 ms mean 25.6 ms · max 47.3 ms  (n=38 re-steers)          PASS\n'
             'Blockchain overhead < 15 %     0.049 % — commit mean 0.437 ms over 649 blocks        PASS\n'
             'RAFT commit         < 500 ms   mean 4.3–4.8 ms · failover 0.21 s  (standalone)       PASS',
             fontsize=8.6, color=INK_SECONDARY, va='top', linespacing=1.65,
             family='DejaVu Sans Mono')

    fig.text(0.475, 0.190, 'Security outcomes the baseline did not achieve',
             fontsize=9.8, fontweight='bold', color=INK_PRIMARY, va='top')
    fig.text(0.475, 0.158,
             'identity spoof (iot38 impersonating iot1)   baseline ADMITTED at t=19.6 s   zero-trust REFUSED\n'
             'wrong-key devices admitted                  baseline 2                      zero-trust 0\n'
             'anomalies raised / acted on                 baseline 502 / 0                zero-trust 372 / 33\n'
             'trust blocks committed                      baseline — (no ledger)          zero-trust 649',
             fontsize=8.6, color=INK_SECONDARY, va='top', linespacing=1.65,
             family='DejaVu Sans Mono')

    fig.text(0.037, 0.038,
             'Throughput is unchanged (20.74 → 20.66 task/s) and mean latency is 4.8 ms worse: the gain is in the tail and in containment, not in raw speed. '
             'Single run per arm — see Section 3, limitations.',
             fontsize=8.4, color=INK_MUTED, va='center')

    path = OUT_DIR / 'fig8_results_comparison.png'
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=DPI, facecolor=SURFACE)
    fig.savefig(OUT_DIR / 'fig8_results_comparison.svg', facecolor=SURFACE)
    plt.close(fig)
    return path


def test_evidence():
    """The testing slide: what the suite covers and what it deliberately pins."""
    fig, ax = canvas(
        'Preliminary Testing — 1 004 tests, 993 passing, 11 skipped, 0 failing',
        'The suite is not a coverage number. Most of these tests exist because a specific defect reached a live run first; each one now fails\n'
        'loudly if that defect is reintroduced. Run: python3 -m pytest -q  (50.7 s on the 4-core box).',
        'Live runs are excluded from the suite by design — one costs sudo and five minutes. '
        'scripts/preflight_live_run.py checks the config against the real launcher before a run is started.')

    box(ax, 5, 46.0, 49, 28.0, 'Unit — pure logic, no I/O', [
        'test_raft.py            R-01..R-18, five safety',
        '                        properties, virtual clock',
        'test_attack_classifier  32+ · both resolution limits',
        'test_trust_state.py     dispatch accounting, probation',
        'test_flood_detector.py  9 · the per-client tell',
        'test_blockchain.py      B-02 tamper detection',
        'test_authenticator.py   nonce reuse, IP pin, TOFU',
        'test_plot_raft_timeline 10 · the failover analysis',
    ], style='module', align='left', title_size=10.0, body_size=7.5, mono=True)

    box(ax, 56, 46.0, 49, 28.0, 'Integration — real sockets, real processes', [
        'test_commit_backend.py  3-replica cluster over TCP;',
        '                        kill the leader, keep committing',
        'test_raft_replica.py    the HTTP control API',
        'test_iot_client_spoof   denial stops traffic, success',
        '                        sends it, delayed onset honoured',
        'test_node_agent.py      grayhole, on-off, delayed onset',
        'test_live_config_prefl. 12+ · real launcher vs real',
        '                        argparse, before a live run',
    ], style='zt', align='left', title_size=10.0, body_size=7.5, mono=True)

    box(ax, 107, 46.0, 48, 28.0, 'Parity — the control arm must match', [
        'test_base_config_parity  every shared key identical',
        'test_observer_parity     load_window_s pinned to the',
        '                         treatment default (3.0 s)',
        'test_launcher_parity     both arms launch agents',
        '                         through the same function',
        'test_compare.py          a spoofed identity is broken',
        '                         out, never silently merged',
        'test_plot_load.py        whole-roster Jain hides it',
    ], style='ledger', align='left', title_size=10.0, body_size=7.5, mono=True)

    box(ax, 5, 3.0, 89, 40.0, 'Tests that exist so a future change fails loudly', [
        'Each encodes a defect that reached a live run before it was caught,',
        'and each states the rule that fixed it:',
        '',
        '·  a detector with no recent evidence ABSTAINS — it never re-asserts',
        '   a stale verdict            (quarantine had become an absorbing state)',
        '·  sum(_inflight) == len(_dispatches), the occupancy invariant',
        '                              (a register leak was fabricating load)',
        '·  a re-steered dispatch is not chargeable to the node it was torn from',
        '                              (nodes were charged for tasks never received)',
        '·  "correctly isolated attacker" and "wrongly quarantined honest node"',
        '   never share a metric       (averaging hides whichever one matters)',
        '·  task-level loss and OpenFlow drop-rule hits never share a series',
        '·  the dashboard recomputes the chain hash in the browser rather than',
        '   trusting the controller’s own valid flag',
        '',
        'Known limitations, stated rather than hidden: one run per configuration',
        '(no confidence intervals) · detection latency is an upper bound, bounded',
        'by the 1 s poll · scalability past 8 nodes is a queueing simulation, not',
        'a live run · DDoS is detected and classified, but not throttled.',
    ], style='layer', align='left', title_size=10.0, body_size=7.5)

    box(ax, 97, 3.0, 58, 40.0, 'Live failover test — recorded, not asserted', [
        'blockchain/raft_timeline.py runs the 3-replica cluster',
        'under continuous load, SIGTERMs the leader mid-run and',
        'records every role change and every commit attempt;',
        'evaluation/plot_raft_timeline.py draws it.',
        '',
        'Measured, 45 s run of 2026-09-07:',
        '',
        '   commits attempted            853',
        '   commits succeeded            850   (99.6 %)',
        '   commit latency        mean 2.6 ms · max 19.4 ms',
        '   leader failover              0.21 s  (± 0.05 s poll)',
        '   service gap                  0.21 s',
        '   attempts refused during it   3',
        '   commit cost, 3/3 → 2/3 → 3/3   2.23 → 3.08 → 2.58 ms',
        '',
        'The restarted replica rejoins with an EMPTY log and is',
        'caught up by the leader — crash-fault only, no disk',
        'persistence. That limit is on the figure, not in a footnote.',
    ], style='ledger', align='left', title_size=10.0, body_size=7.5)

    return save(fig, 'fig9_testing_evidence')
