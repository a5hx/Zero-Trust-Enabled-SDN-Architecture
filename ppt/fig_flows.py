"""Section 2/3 diagrams: system workflow, zero-trust security flow, load balancing.

Numbers quoted on these figures come from the two live runs scored on
2026-09-05 (data/events.jsonl, 313.2 s; data/base_events.jsonl, 307.5 s) and
from data/nfr_report.txt. Nothing here is illustrative.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from diagram_kit import (  # noqa: E402
    BLUE, INK_MUTED, INK_PRIMARY, INK_SECONDARY, ORANGE, RED, SURFACE, STYLES,
    arrow, band, box, canvas, legend, note, save,
)


def lifeline(ax, x, top, bottom, label, sub, style='module', w=26):
    box(ax, x - w / 2, top, w, 7.0, label, [sub], style,
        title_size=9.6, body_size=7.4)
    ax.plot([x, x], [bottom, top], color=INK_MUTED, linewidth=1.0,
            linestyle=(0, (3, 3)), zorder=2)
    return x


def step(ax, n, y, x0, x1, text, color=INK_SECONDARY, style='-', note_text=''):
    """One numbered message on the sequence diagram."""
    arrow(ax, (x0, y), (x1, y), '', color=color, style=style, lw=1.3)
    mid = (x0 + x1) / 2
    ax.text(mid, y + 1.5, f'{n}  {text}', fontsize=7.8, color=color,
            ha='center', va='bottom', zorder=8,
            bbox=dict(boxstyle='round,pad=0.2', facecolor=SURFACE,
                      edgecolor='none', alpha=0.95))
    if note_text:
        ax.text(mid, y - 1.6, note_text, fontsize=7.2, color=INK_MUTED,
                ha='center', va='top', zorder=8)


# --------------------------------------------------------------------------- #
def system_workflow():
    fig, ax = canvas(
        'System Workflow — one task, end to end',
        'The full path of a single IoT task through the implemented system: admission, routing, execution, trust update, ledger commit.\n'
        'Grey annotations are measured, from data/nfr_report.txt over the 313.2 s live run of 2026-09-05.',
        'Steps 1–4 run once per device · 5–9 once per TCP connection · 10–14 once per task, ~20/s across the fleet.    '
        'Ledger commit: 0.437 ms per block of 10 = 0.049 % of task latency (NFR < 15 %).')

    box(ax, 5, 69.5, 150, 6.0,
        'Concurrently, once per second: FlowMonitor polls every node’s /status. Latency and reported-vs-observed CPU feed anomaly A;',
        ['a node crossing T < 0.30 or A ≥ 0.50 is quarantined and its clients re-steered mid-run — measured mean 25.6 ms over 38 re-steers.'],
        style='zt', align='left', title_size=8.8, body_size=8.0)

    top, bottom = 62.0, 3.0
    a = lifeline(ax, 16, top, bottom, 'IoT device', 'iot_client.py', 'external')
    b = lifeline(ax, 46, top, bottom, 'OVS switch', 's0 / s1..s8', 'module')
    c = lifeline(ax, 79, top, bottom, 'Controller', 'trust_balancer.py', 'zt', w=30)
    d = lifeline(ax, 111, top, bottom, 'TrustState +\nTrustCalculator', '', 'zt', w=28)
    e = lifeline(ax, 132, top, bottom, 'Ledger', 'blockchain/', 'ledger', w=18)
    srv = lifeline(ax, 151, top, bottom, 'Edge server', 'node_agent.py', 'module', w=15)

    step(ax, 1, 58.0, a, c, 'POST /auth/challenge  {device_id}')
    step(ax, 2, 54.5, c, a, 'nonce — 64-bit, TTL 30 s')
    step(ax, 3, 51.0, a, c, 'POST /auth/verify  {PRESENT-80(key, nonce)}',
         note_text='the source IP is taken from the socket, never from the request body')
    step(ax, 4, 44.5, c, a, 'token  —  or 403 auth_denied', color=RED)
    step(ax, 5, 41.5, a, b, 'TCP SYN → VIP 10.0.99.254:9000')
    step(ax, 6, 37.5, b, c, 'PacketIn  (priority-250 punt)')
    step(ax, 7, 33.5, c, d, 'snapshot() — trust, load, quarantine state')
    step(ax, 8, 29.5, d, c, 'eligible nodes  →  EdgeScore + p2c  →  srvN')
    step(ax, 9, 25.5, c, b, 'flow-mod: priority-300 rewrite pair',
         note_text='routing decision NFR < 200 ms — measured mean 0.53 ms, p95 0.71 ms, max 6.64 ms (n = 6 611)')
    step(ax, 10, 19.5, b, srv, 'rewritten task → srvN:9000')
    step(ax, 11, 15.5, srv, a, 'result')
    step(ax, 12, 11.5, a, c, 'POST /report  {status, latency_ms}')
    step(ax, 13, 7.5, c, d, 'update(TrustUpdate) → new T')
    step(ax, 14, 4.0, d, e, 'commit() every 10 updates → Block')
    return save(fig, 'fig5_system_workflow')



# --------------------------------------------------------------------------- #
def zero_trust_flow():
    fig, ax = canvas(
        'Zero Trust Security Flow — never trust, always verify',
        'Three gates, each enforced on a different clock: identity once per device, verification continuously, response proportionally.\n'
        'Red = the request is refused or the node is contained. Counts are from the 313.2 s live run of 2026-09-05.',
        'The fleet key is shared, so PRESENT-80 authenticates possession of the key — not the device. Source-IP pinning is what closes that gap.')

    band(ax, 5, 51.0, 108, 23.0, 'GATE 1 — Identity   ·   once, at admission   ·   security/authenticator.py')
    box(ax, 8, 54.0, 23, 15.5, '1  Challenge', [
        'device asks for', 'admission;', 'controller issues', 'a 64-bit nonce,', 'TTL 30 s'],
        'zt', title_size=9.4, body_size=7.4)
    box(ax, 33.5, 54.0, 23, 15.5, '2  Response', [
        'device returns', 'PRESENT-80', '(fleet key, nonce);', 'nonce is popped', 'on first use'],
        'zt', title_size=9.4, body_size=7.4)
    box(ax, 59, 54.0, 23, 15.5, '3  Identity pin', [
        'provisioned roster:', 'IP must match.', 'Unknown device:', 'TOFU — first', 'claim binds'],
        'zt', title_size=9.4, body_size=7.4)
    box(ax, 84.5, 54.0, 26, 15.5, '4  Admitted', [
        'token issued;', 'device_id bound', 'to its source IP', 'for the rest of', 'the run'],
        'zt', title_size=9.4, body_size=7.4)
    for x0, x1 in ((31, 33.5), (56.5, 59), (82, 84.5)):
        arrow(ax, (x0, 61.7), (x1, 61.7), lw=1.4)

    band(ax, 5, 27.0, 108, 22.0, 'GATE 2 — Continuous verification   ·   every report and every 1 s poll   ·   trust_state.py')
    box(ax, 8, 30.0, 33, 15.0, 'Evidence', [
        'task outcome      → R',
        'observed latency  → B',
        'reported vs actual CPU → H',
        'detector tells    → A',
        'EMA λ = 0.85 on all four',
    ], 'zt', align='left', title_size=9.4, body_size=7.4)
    box(ax, 43.5, 30.0, 33, 15.0, 'Score', [
        'T = 0.35R + 0.25B',
        '        + 0.25H − 0.15A',
        '',
        'A is a separate gate, not a',
        'term: a node can lie and still',
        'hold a high T (see §3).',
    ], 'zt', align='left', title_size=9.4, body_size=7.4)
    box(ax, 79, 30.0, 31.5, 15.0, 'Verdict, per request', [
        'T ≥ 0.30  and  A < 0.50',
        '   →  eligible for routing',
        '',
        'otherwise → not eligible;',
        'if nothing is eligible the',
        'request is refused outright.',
    ], 'zt', align='left', title_size=9.4, body_size=7.4)
    for x0, x1 in ((41, 43.5), (76.5, 79)):
        arrow(ax, (x0, 37.5), (x1, 37.5), lw=1.4)

    band(ax, 5, 3.0, 108, 21.0, 'GATE 3 — Graduated response   ·   proportional, not binary   ·   OpenFlow enforcement')
    box(ax, 8, 6.0, 33, 14.0, 'Full service', [
        'T ≥ 0.50  and  A < 0.25',
        '',
        'priority-300 VIP rewrite',
        'pair, no meter attached',
    ], 'module', align='left', title_size=9.4, body_size=7.4)
    box(ax, 43.5, 6.0, 33, 14.0, 'Rate limited', [
        'T < 0.50  or  A ≥ 0.25',
        '',
        'same rewrite pair, plus an',
        'OpenFlow meter (drop band)',
    ], 'module', align='left', title_size=9.4, body_size=7.4)
    box(ax, 79, 6.0, 31.5, 14.0, 'Quarantined', [
        'T < 0.30  or  A ≥ 0.50',
        '',
        'delete rules by cookie,',
        'install priority-400 drops,',
        're-steer the clients',
    ], 'danger', align='left', title_size=9.4, body_size=7.4)
    for x0, x1 in ((41, 43.5), (76.5, 79)):
        arrow(ax, (x0, 13.0), (x1, 13.0), lw=1.4, color=RED)

    # measured outcomes column
    box(ax, 116, 51.0, 39, 23.0, 'Measured at Gate 1', [
        'identity spoof (iot38 → iot1)',
        '        REFUSED  — kind = ip_pin',
        '        the same spoof SUCCEEDED',
        '        in the baseline at t = 19.6 s',
        'wrong-key devices admitted   0',
        '        (2 admitted in the baseline)',
        'devices refused at admission 3',
    ], style='danger', align='left', title_size=9.8, body_size=7.5, mono=True)

    box(ax, 116, 27.0, 39, 22.0, 'Measured at Gate 2', [
        'anomaly events raised     372',
        'of those, acted on         33',
        '',
        'Baseline raised 502 anomalies and',
        'acted on none — the control arm',
        'computes the identical score with',
        'the identical code, and does',
        'nothing with it.',
    ], style='store', align='left', title_size=9.8, body_size=7.5, mono=True)

    box(ax, 116, 3.0, 39, 21.0, 'Measured at Gate 3', [
        'quarantines applied        33',
        're-steers performed        38',
        'containment, from onset:',
        '   srv3 sybil      8.2 s',
        '   srv6 blackhole  8.7 s',
        '   srv8 on-off     9.9 s',
        '   srv1 grayhole  11.3 s',
        'Baseline: never, all four.',
    ], style='danger', align='left', title_size=9.8, body_size=7.5, mono=True)
    return save(fig, 'fig6_zero_trust_flow')


# --------------------------------------------------------------------------- #
def load_balancing_flow():
    fig, ax = canvas(
        'Secure Load-Balancing Flow — trust as a first-class routing input',
        'The routing decision runs on the first packet of every VIP connection. Trust does not merely re-rank nodes: it removes them\n'
        'from the candidate set entirely, and a quarantine mid-connection tears down rules that are already installed.',
        'Weights, strategy and exploration rate are config, not constants: edge_score.w1/w2/w3, selection: p2c, d_choices: 2, epsilon: 0.05.')

    box(ax, 5, 58.0, 27, 15.0, '1  New connection', [
        'client SYN → VIP',
        '10.0.99.254:9000',
        '',
        'priority-250 punt',
        'fires one PacketIn',
    ], 'module', title_size=9.6, body_size=7.5)

    box(ax, 35, 58.0, 30, 15.0, '2  Eligibility filter', [
        'drop every node with',
        'T < 0.30  or  A ≥ 0.50',
        '',
        'This is the zero-trust step:',
        'exclusion, not re-ranking.',
    ], 'zt', title_size=9.6, body_size=7.5)

    box(ax, 68, 58.0, 42, 15.0, '3  EdgeScore over the survivors', [
        'EdgeScore(n) = w1·T(n) + w2·(1 − cpu(n)) + w3·(1 − lat(n))',
        '                       0.50            0.30                 0.20',
        '',
        'cpu is controller-OBSERVED occupancy, not the node’s claim —',
        'a node that lies about its load cannot win by lying.',
    ], 'zt', align='left', title_size=9.6, body_size=7.4)

    box(ax, 113, 58.0, 42, 15.0, '4  Power-of-two-choices', [
        'sample d = 2 eligible nodes uniformly at random,',
        'dispatch to the better of the two;  ε = 0.05 random',
        '',
        'argmax sends every request to one node until its load',
        'catches up — measured to starve the fleet at N > 8.',
    ], 'zt', align='left', title_size=9.6, body_size=7.4)

    for x0, x1 in ((32, 35), (65, 68), (110, 113)):
        arrow(ax, (x0, 65.5), (x1, 65.5), lw=1.5)

    box(ax, 5, 39.0, 27, 15.0, '6  Task runs', [
        'server executes,',
        'client reports',
        'status + latency',
        '',
        '→ trust update',
    ], 'module', title_size=9.6, body_size=7.5)

    box(ax, 35, 39.0, 30, 15.0, '5  Install the decision', [
        'priority-300 rewrite pair,',
        'cookie 0x5A..0N,',
        'idle 10 s / hard 30 s',
        '',
        '+ meter if rate-limited',
    ], 'module', title_size=9.6, body_size=7.5)

    box(ax, 68, 39.0, 42, 15.0, '7  If the node is quarantined mid-run', [
        'delete its rules by cookie  →  install priority-400 drops  →',
        're-dispatch that client’s next connection to the next-best node',
        '',
        'Isolation NFR < 3 000 ms.  Measured mean 25.6 ms, max 47.3 ms over',
        '38 re-steers; detection itself bounded by the 1 s poll interval.',
    ], 'danger', align='left', title_size=9.6, body_size=7.4)

    box(ax, 113, 39.0, 42, 15.0, '8  Weights are tuned online', [
        'trust_engine/ai_optimizer.py — UCB1 over 5 weight arms,',
        '10 s window, reward penalises latency and imbalance.',
        '',
        '[.50 .30 .20] [.70 .20 .10] [.34 .50 .16]',
        '[.34 .16 .50] [.45 .45 .10]',
    ], 'zt', align='left', title_size=9.6, body_size=7.4)

    arrow(ax, (134, 58.0), (134, 54.0), lw=1.5)
    arrow(ax, (113, 46.5), (110, 46.5), lw=1.5)
    arrow(ax, (68, 46.5), (65, 46.5), lw=1.5)
    arrow(ax, (35, 46.5), (32, 46.5), lw=1.5)
    arrow(ax, (18.5, 39.0), (18.5, 35.5), '', lw=1.5)
    note(ax, 22.0, 36.0, 'evidence returns to TrustState  →  a new T  →  a new eligibility verdict', size=7.8)

    def _rows(pairs):
        """Right-align the two result columns.

        Hand-spaced columns drift the moment a value changes width; formatting
        them here means the alignment is a property of the code, not of how
        carefully somebody counted spaces.
        """
        out = [f'{"":<40}{"baseline":>12}{"zero-trust":>14}']
        out += [f'{label:<40}{b:>12}{t:>14}' for label, b, t in pairs]
        return out

    box(ax, 5, 3.0, 74, 30.0, 'What the load balancing is worth', [
        'Same topology, same workload, same attackers, same schedule.',
    ] + _rows([
        ('Jain fairness, honest servers only', '0.689', '0.992'),
        ('Jain fairness, whole roster', '0.622', '0.627'),
        ('requests sent to attacker nodes', '30.5 %', '12.5 %'),
        ('honest devices served below 50 %', '5', '0'),
    ]) + [
        '',
        'Whole-roster Jain is a trap, and is shown for that reason: the',
        'two arms score almost the same for OPPOSITE reasons. The baseline',
        'is uneven because a flooding client is statically pinned to srv5',
        'and nothing can move it; the zero-trust arm is uneven because it',
        'deliberately starved four attackers (srv3 received 44 requests',
        'all run). Report both populations, or report neither.',
    ], style='store', align='left', title_size=10.0, body_size=7.4, mono=True)

    box(ax, 82, 3.0, 73, 30.0, 'Service outcome of the same two runs', [
        'The arms differ in exactly two things: who routes, and what acts.',
    ] + _rows([
        ('packet delivery ratio', '94.29 %', '99.10 %'),
        ('tasks lost to timeout', '380', '58'),
        ('per-device success rate (honest)', '85.67 %', '99.00 %'),
        ('p95 task latency', '260.0 ms', '134.3 ms'),
        ('mean task latency', '83.7 ms', '88.5 ms'),
        ('throughput', '20.74 task/s', '20.66 task/s'),
    ]) + [
        '',
        'Mean latency is 4.8 ms WORSE, and that is the honest trade: the',
        'zero-trust arm pays a small cost in the mean to remove the long',
        'tail. p95 halves and timeouts fall 85 %. Throughput is unchanged,',
        'so the gain is not bought by simply serving less work.',
    ], style='store', align='left', title_size=10.0, body_size=7.4, mono=True)

    return save(fig, 'fig7_load_balancing_flow')
