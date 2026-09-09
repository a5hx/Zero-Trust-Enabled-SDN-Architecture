"""Section 1 diagrams: architecture, module interaction, data model, deployment.

Every box names a file, class, port or config key that exists in this
repository. Where something is built but not yet wired into the running system
(`blockchain/raft.py`), the figure says so on the figure -- not in a footnote.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from diagram_kit import (  # noqa: E402
    BLUE, INK_MUTED, INK_PRIMARY, INK_SECONDARY, ORANGE, RED, SURFACE,
    arrow, band, box, canvas, legend, note, save,
)


def row(ax, bx, bw, top, items, style='module', h=6.7, gap=2.2,
        title_size=9.5, body_size=7.6, pad=2.5):
    """Lay `items` [(title, [lines])] across one row whose TOP edge is `top`.

    An explicit top edge, not "the band's y minus some padding": a row that
    sizes itself from its container is why the first draft of this figure
    printed its boxes straight through the band labels above them. The height
    rule (4.2 + 1.9 per body line + 0.6) is asserted rather than trusted,
    because overflow is silent in a rendered PNG.
    """
    needed = 4.2 + 1.9 * max((len(l) for _, l in items), default=0) + 0.6
    assert h >= needed - 1e-9, f'row height {h} too small; needs {needed:.1f}'
    n = len(items)
    w = (bw - 2 * pad - gap * (n - 1)) / n
    return [box(ax, bx + pad + i * (w + gap), top - h, w, h, title, lines,
                style, title_size=title_size, body_size=body_size)
            for i, (title, lines) in enumerate(items)]


def fields(ax, x, y, w, name, source, rows, style='store',
           title_size=9.8, body_size=7.3):
    """An entity box: a name, its defining file, then a field list.

    Height is derived from the row count using box()'s own rule, counting the
    source line and the blank separator this function itself inserts. Omitting
    those two is what pushed the first draft's last field out through the
    bottom border of every entity on the slide.
    """
    h = 8.8 + 1.9 * len(rows)
    box(ax, x, y, w, h, name, [source, ''] + list(rows), style,
        align='left', title_size=title_size, body_size=body_size, mono=True)
    return (x + w / 2, y + h / 2, x, y, w, h)



# --------------------------------------------------------------------------- #
def software_architecture():
    fig, ax = canvas(
        'Software Architecture — layered decomposition',
        'Five layers, one operating-system process. The controller is a single os-ken application; the trust engine and the\n'
        'ledger are libraries it calls in-process, not network services. Every box is a module that exists in the repository.',
        'Runtime: Ubuntu 26.04 · Python 3.14 · os-ken (Ryu fork) · Mininet + Open vSwitch, OpenFlow 1.3.     '
        'Orange = zero-trust decision path · blue = trust ledger · grey = supporting · olive = state and artefacts.')

    x0, bw = 5.0, 108.0
    L5, L4, L3, L2, L1 = (63.6, 12.2), (50.1, 12.2), (29.7, 18.4), (15.5, 12.2), (3.0, 10.5)

    band(ax, x0, L5[0], bw, L5[1], 'L5   Presentation & offline analysis')
    row(ax, x0, bw, L5[0] + L5[1] - 4.2, [
        ('dashboard/index.html', ['live SSE panels · in-browser SHA-256']),
        ('evaluation/   19 analysis tools', ['nfr · attack · availability · scalability']),
        ('base_model/   control arm', ['static_router · compare · plot_trust · plot_load']),
    ], style='external', body_size=7.4)

    band(ax, x0, L4[0], bw, L4[1],
         'L4   Northbound REST API — stdlib ThreadingHTTPServer on :8081')
    row(ax, x0, bw, L4[0] + L4[1] - 4.2, [
        ('Admission', ['POST /auth/challenge · /auth/verify']),
        ('Telemetry in', ['POST /report · /register']),
        ('State out', ['GET /trust/score · /node/status']),
        ('Ledger & stream', ['GET /ledger/verify · /api/events (SSE)']),
    ], style='zt', title_size=9.2, body_size=7.3)

    band(ax, x0, L3[0], bw, L3[1],
         'L3   SDN control plane — controller/trust_balancer.py   (os-ken OpenFlow 1.3 application)')
    row(ax, x0, bw, L3[0] + L3[1] - 4.2, [
        ('edge_selector', ['EdgeScore · p2c · eligibility']),
        ('trust_state', ['score · quarantine · load']),
        ('flow_monitor', ['1 s /status poll · tells']),
        ('flood_detector', ['per-client rate tell']),
        ('attack_classifier', ['label over a window']),
    ], style='zt', title_size=9.2, body_size=7.2)
    row(ax, x0, bw, L3[0] + L3[1] - 12.1, [
        ('learning_switch_13', []), ('flow_stats / port_stats', []),
        ('event_bus', []), ('osken_manager', []),
    ], style='module', h=5.0, title_size=9.0)

    band(ax, x0, L2[0], bw, L2[1], 'L2   Trust, security & consensus engines')
    row(ax, x0, bw, L2[0] + L2[1] - 4.2, [
        ('trust_calculator', ['T = αR + βB + γH − δA']),
        ('ai_optimizer  (UCB1)', ['tunes w1 / w2 / w3']),
        ('authenticator', ['PRESENT-80 · IP pin']),
        ('ledger · merkle', ['SHA-256 hash chain']),
        ('raft.py  (not wired)', ['3-replica consensus']),
    ], style='ledger', title_size=8.6, body_size=7.2)

    band(ax, x0, L1[0], bw, L1[1],
         'L1   Data plane — Mininet virtual network, OpenFlow 1.3 to the controller on :6653')
    row(ax, x0, bw, L1[0] + L1[1] - 4.2, [
        ('1 core switch   s0', []), ('8 edge switches   s1..s8', []),
        ('8 edge servers   srv1..srv8', []), ('40 IoT devices   iot1..iot40', []),
    ], style='layer', h=5.0, title_size=9.0)

    for lower, upper in ((L1, L2), (L2, L3), (L3, L4), (L4, L5)):
        arrow(ax, (x0 + bw / 2, lower[0] + lower[1]), (x0 + bw / 2, upper[0]),
              color=INK_MUTED, lw=1.1)

    box(ax, 116.5, 63.6, 38.5, 12.2, 'Persistent artefacts', [
        'data/events.jsonl — append-only recording',
        '20 event types · 26k–43k events per run',
        'data/comparison/ · base_model/trust/*.png',
    ], style='store', align='left', title_size=9.8, body_size=7.6)

    box(ax, 116.5, 40.0, 38.5, 22.3, 'In-memory state  (no RDBMS)', [
        'TrustState         score · A · inflight · quarantine',
        'Ledger             hash-chained list of Blocks',
        'IdentityBinding    device_id → source IP',
        'EventBus           SSE subscriber queues',
        '',
        'The ledger is the store of record for trust;',
        'the JSONL recording is the store of record',
        'for evidence. See the data-model slide.',
    ], style='store', align='left', title_size=9.8, body_size=7.5)

    box(ax, 116.5, 14.0, 38.5, 24.0, 'Configuration', [
        'config/params_trust_full.yaml',
        '    8 servers · 40 IoT · 6 attacks · 300 s',
        '    α .35   β .25   γ .25   δ .15   λ .85',
        '    isolation 0.30 · anomaly gate 0.50',
        '    w1 .50  w2 .30  w3 .20 · p2c d=2 · ε .05',
        '    optimizer ucb1 · 5 weight arms',
        '',
        'base_model/config/params_base_full.yaml',
        '    identical above its baseline: block —',
        '    config parity is enforced by a test',
    ], style='layer', align='left', title_size=9.8, body_size=7.5)

    arrow(ax, (113.0, 56.2), (116.3, 56.2), color=INK_MUTED)
    arrow(ax, (116.3, 26.0), (113.0, 26.0), color=INK_MUTED)
    return save(fig, 'fig1_software_architecture')


# --------------------------------------------------------------------------- #
def module_interaction():
    fig, ax = canvas(
        'Module Interaction — the request path and the control loop',
        'Solid = the request path.   Dashed = the periodic control loop (1 s poll).   Red = a refusal.\n'
        'Class names are the real ones; every arrow is a call that exists in the code.',
        'The two loops meet at TrustState: the request path writes evidence into it, the control loop reads decisions out of it.')

    box(ax, 5, 61, 24, 9, 'IoTClient', ['simulation/iot_client.py', '40 devices · 0.5 Hz'], 'external')
    box(ax, 33, 61, 25, 9, 'NorthboundAPI', ['/auth/* · /report', ':8081'], 'zt')
    box(ax, 62, 61, 30, 9, 'PRESENT80Authenticator', ['+ IdentityBinding', 'nonce TTL 30 s · source-IP pin'], 'zt')
    box(ax, 96, 61, 27, 9, 'TrustBalancerApp', ['os-ken OpenFlow 1.3', 'PacketIn → flow-mod'], 'zt')
    box(ax, 127, 61, 28, 9, 'edge_selector', ['edge_score() · p2c', 'select_edge_node()'], 'zt')

    for x0, x1, lbl in ((29, 33, '1  challenge'), (58, 62, '2  verify'),
                        (92, 96, '3  token'), (123, 127, '4  choose')):
        arrow(ax, (x0, 65.5), (x1, 65.5), lbl, size=7.4, label_dy=5.0)

    box(ax, 62, 50, 30, 8.2, 'auth_denied  →  403', ['kind = ip_pin | bad_response', '| nonce_expired'],
        'danger', title_size=9.5, body_size=7.4)
    arrow(ax, (77, 61), (77, 58.2), color=RED)

    box(ax, 118, 34, 37, 11, 'Open vSwitch   s0 / s1..s8', [
        'prio 400 quarantine drop  >  350 ARP punt  >',
        '300 VIP rewrite pair  >  250 new-conn punt',
        'cookie 0x5A..0N · idle 10 s / hard 30 s'], 'module', title_size=9.5, body_size=7.3)
    arrow(ax, (141, 61), (141, 45), '5  install\nVIP pair', size=7.2, label_dx=8.5)

    box(ax, 56, 28, 40, 14, 'TrustState   controller/trust_state.py', [
        'record_dispatch · register_dispatch · report',
        'observed_load · claimed_load · anomaly A',
        'quarantine · probation · stale-evidence abstain',
        'snapshot() → API and dashboard'], 'zt', title_size=9.8, body_size=7.4)
    arrow(ax, (77, 50), (77, 42), color=INK_SECONDARY)
    arrow(ax, (36, 61), (58, 40), '6  POST /report\nclient_ip from the socket,\nnever from the body',
          rad=-0.16, size=7.2, label_dy=-3.0, label_dx=-4.0)

    box(ax, 5, 28, 45, 14, 'TrustCalculator   trust_engine/', [
        'R  task outcome      B  latency      H  reported-vs-observed CPU',
        'A  anomaly            all four EMA-smoothed, λ = 0.85',
        'T = 0.35R + 0.25B + 0.25H − 0.15A,  clipped to [0,1]'],
        'zt', title_size=9.8, body_size=7.3)
    arrow(ax, (56, 35), (50, 35), '7  update()', size=7.2, label_dy=2.2)

    box(ax, 100, 20, 26, 8.2, 'flow_monitor', ['1 s /status poll', 'latency + honesty tells'],
        'module', title_size=9.2, body_size=7.3)
    box(ax, 129, 20, 26, 8.2, 'flood_detector', ['per-client rate tell'],
        'module', title_size=9.2, body_size=7.3)
    arrow(ax, (113, 28.2), (96, 33), 'anomaly A', style='--', rad=0.12, size=7.2, label_dy=2.4)
    arrow(ax, (142, 28.2), (96, 31), '', style='--', rad=0.10)

    box(ax, 100, 6, 55, 10, 'attack_classifier — a pure function over an evidence window', [
        'sybil · blackhole · grayhole · on-off · flood · spoof  →  one label per subject',
        'the same implementation serves the live controller and the offline scorer'],
        'module', title_size=9.5, body_size=7.4)
    arrow(ax, (113, 20), (113, 16), style='--', color=INK_SECONDARY)

    box(ax, 5, 6, 45, 14, 'CommitBackend → Ledger → Block', [
        'TimingCommitBackend(LocalLedgerBackend())',
        'batches 10 TrustUpdates → build_merkle_root()',
        'Block.compute_hash() links previous_hash → hash',
        'RaftBackend exists and is NOT wired in (Section 3)'],
        'ledger', title_size=9.8, body_size=7.3)
    arrow(ax, (27, 28), (27, 20), '8  commit(updates)', size=7.2, label_dx=13.5)

    box(ax, 56, 6, 40, 10, 'EventBus  →  data/events.jsonl  +  SSE', [
        'every decision, detection and block is published once and',
        'recorded; the dashboard and every analysis tool read it back'],
        'store', title_size=9.5, body_size=7.4)
    arrow(ax, (70, 28), (70, 16), '9  publish', size=7.2, label_dx=7.5)

    legend(ax, [('zt', 'zero-trust decision path'), ('ledger', 'trust ledger'),
                ('module', 'controller module'), ('danger', 'refusal path')],
           x=5, y=74.3, cols=4, gap=30)
    return save(fig, 'fig2_module_interaction')


# --------------------------------------------------------------------------- #
def data_model():
    fig, ax = canvas(
        'Data Model — entities, keys and relationships',
        'There is no relational database in this system, and the diagram says so rather than inventing one. Trust is stored in an append-only\n'
        'hash-chained ledger; evidence is stored in an append-only JSONL recording. Integrity here is cryptographic, not referential.',
        'Field lists are taken verbatim from contracts/trust_update.py, contracts/block_schema.py, '
        'controller/trust_state.py, security/authenticator.py and trust_engine/trust_calculator.py.')

    fields(ax, 5, 51.9, 45, 'Block', 'contracts/block_schema.py · blockchain/block.py', [
        'index             PK   position in the chain',
        'timestamp         float  (genesis pinned to 0.0)',
        'previous_hash     FK → Block.hash   (self-chain)',
        'merkle_root       SHA-256 over this block’s updates',
        'proposer_id       "controller" while single-replica',
        'raft_term         int — 0 until Raft is wired in',
        'hash              SHA-256 over the header fields',
    ], style='ledger')

    fields(ax, 57.5, 48.1, 47, 'TrustUpdate', 'contracts/trust_update.py', [
        'device_id             FK → IdentityBinding',
        'edge_node_id          FK → NodeState',
        'timestamp             float',
        'task_status           success | failure | timeout',
        'cpu_usage             observed CPU  [0.0, 1.0]',
        'reported_cpu          claimed CPU   [0.0, 1.0]',
        'latency_ms            observed round trip',
        'trust_score_before / trust_score_after',
        'anomaly_flag          bool',
    ], style='zt')

    fields(ax, 112, 48.1, 43, 'NodeState', 'controller/trust_state.py :: snapshot()', [
        'node_id        PK   srv1 .. srv8',
        'trust          T ∈ [0, 1]',
        'claimed_cpu    what the node reported',
        'observed_load  controller-side occupancy',
        'inflight       dispatches outstanding',
        'latency_ms     smoothed /status latency',
        'anomaly        A ∈ [0, 1]  (EMA)',
        'quarantined    bool',
        'probation      bool — earning its way back',
    ], style='zt')

    fields(ax, 5, 27.6, 45, 'IdentityBinding', 'security/authenticator.py', [
        'device_id      PK   iot1 .. iot40',
        'expected_ip    provisioned roster (strict)',
        'session_ip     TOFU binding (first claim wins)',
        'authenticated  bool — has ever passed',
    ], style='zt')

    fields(ax, 57.5, 23.8, 47, 'Event   (the run recording)',
           'data/events.jsonl — append-only, one JSON object per line', [
        'type    20 kinds:  route · report · flow_install ·',
        '        flow_delete · block · anomaly · quarantine ·',
        '        recovered · reroute · classification · flood ·',
        '        auth_denied · optimizer · node_status · …',
        'ts      wall clock        seq   publish order',
        '+ the per-type payload, flattened',
    ], style='store')

    fields(ax, 112, 27.6, 43, 'EMA state', 'trust_engine/trust_calculator.py', [
        'node_id   PK',
        'R  reputation          B  behaviour',
        'H  honesty             A  anomaly',
        'λ = 0.85 decay, applied on every update',
    ], style='zt')

    arrow(ax, (50, 66), (57.5, 66), '1 : N\nbatched 10 per block', size=7.4, label_dy=4.6)
    arrow(ax, (104.5, 66), (112, 66), 'N : 1\nedge_node_id', size=7.4, label_dy=4.6)
    arrow(ax, (62, 48.1), (35, 44.0), 'N : 1   device_id', size=7.4, rad=0.14, label_dy=2.6)
    arrow(ax, (27.5, 51.9), (27.5, 44.0), '', color=INK_MUTED, style=':')
    arrow(ax, (80, 48.1), (80, 44.0), 'projected into', color=INK_MUTED, style=':', size=7.2)

    box(ax, 5, 3.0, 45, 20.5, 'Why there is no RDBMS', [
        'The ledger IS the store of record for trust. Integrity',
        'comes from SHA-256 chaining plus a Merkle root per',
        'block — verified by GET /ledger/verify and re-verified',
        'independently inside the browser — not from',
        'foreign-key constraints. The JSONL recording is the',
        'durable evidence log every analysis tool reads back.',
        'Configuration lives in YAML under config/.',
    ], style='layer', align='left', title_size=9.8, body_size=7.5)

    box(ax, 112, 3.0, 43, 20.5, 'Cardinalities', [
        'Block            1 —— N   TrustUpdate',
        'Block            1 —— 1   Block  (previous_hash)',
        'NodeState        1 —— N   TrustUpdate',
        'IdentityBinding  1 —— N   TrustUpdate',
        '',
        'Every entity above is also projected,',
        'flattened, into the Event recording.',
    ], style='layer', align='left', title_size=9.8, body_size=7.5)
    return save(fig, 'fig3_data_model_er')



# --------------------------------------------------------------------------- #
def deployment():
    fig, ax = canvas(
        'Deployment Architecture — one host, three process groups',
        'Everything runs on a single 4-core WSL2 machine. The controller is one OS process; the network is Mininet namespaces;\n'
        'the Raft cluster is three further processes that are deliberately NOT connected to the controller yet.',
        'Both arms bind :6653 and :8081, so the zero-trust arm and the base_model control arm are run one at a time, back to back on an idle machine.')

    band(ax, 4, 3.0, 152, 71.0,
         'Host — WSL2 · Ubuntu 26.04 · Python 3.14 · 4 cores · no venv, apt packages only', style='layer')

    box(ax, 7, 40.0, 34, 29.0, 'Process 1 — SDN controller', [
        'sudo python3 -m controller.osken_manager \\',
        '            controller.trust_balancer',
        '',
        'listens  :6653   OpenFlow 1.3',
        'serves   :8081   REST + SSE',
        '',
        'threads',
        '  FlowMonitor       1 s /status poll',
        '  FlowStatsPoller   flow counters',
        '  PortStatsPoller   port counters',
        '  ledger commit     every 10 updates',
        '  NorthboundAPI     ThreadingHTTPServer',
    ], style='zt', align='left', title_size=10.0, body_size=7.4)

    band(ax, 51, 40.0, 57, 29.0, 'Process group 2 — Mininet network namespaces  (sudo)', style='module')
    box(ax, 54, 57.5, 51, 6.7, 'core switch  s0   —   OVS, dpid 0x…01',
        ['every VIP task transits it'], style='layer', title_size=9.2, body_size=7.4)
    box(ax, 54, 48.5, 24.5, 8.6, 'edge switches  s1..s8',
        ['OVS · OpenFlow 1.3', '5 ms / 1 Gb link to s0'], style='layer', title_size=9.2, body_size=7.4)
    box(ax, 80.5, 48.5, 24.5, 8.6, 'cx  —  control host',
        ['not in a namespace,', 'bridged to s0'], style='external', title_size=9.2, body_size=7.4)
    box(ax, 54, 41.0, 24.5, 6.7, '8 × srv   node_agent.py',
        ['HTTP /status · /task'], style='module', title_size=9.2, body_size=7.4)
    box(ax, 80.5, 41.0, 24.5, 6.7, '40 × iot   iot_client.py',
        ['1–10 ms / 10 Mb links'], style='module', title_size=9.2, body_size=7.4)

    box(ax, 111, 40.0, 42, 29.0, 'Process group 3 — RAFT cluster', [
        'python3 -m blockchain.raft_timeline',
        '',
        'n1    RAFT :9001    control API :9101',
        'n2    RAFT :9002    control API :9102',
        'n3    RAFT :9003    control API :9103',
        '',
        'Real OS processes, real loopback TCP,',
        'a real SIGTERM of the leader.',
        '',
        'NOT connected to Process 1 — the live',
        'controller still commits single-replica.',
    ], style='deferred', align='left', title_size=10.0, body_size=7.4)

    arrow(ax, (41, 55.5), (54, 55.5), 'OpenFlow 1.3\n:6653', size=7.4, label_dy=3.6)
    arrow(ax, (54, 44.4), (41, 44.4), 'POST /report\n/auth/*  →  :8081', size=7.4, label_dy=-3.6)
    ax.plot([108, 111], [54.5, 54.5], color=INK_MUTED, lw=1.5,
            linestyle=(0, (4, 3)), zorder=6)
    note(ax, 109.5, 57.5, 'no link\n(Section 3)', size=7.2, ha='center', color=RED)

    box(ax, 7, 21.5, 71, 16.0, 'Addressing & service model', [
        'IoT devices  10.0.0.1 – 10.0.0.40        edge servers  10.0.1.1 – 10.0.1.8',
        'Virtual service IP (VIP)     10.0.99.254 : 9000',
        '',
        'A client never addresses a server. It opens a TCP connection to the VIP; the',
        'controller rewrites destination MAC + IP in the data plane (the priority-300',
        'pair), so the routing decision is invisible to the client — and revocable.',
    ], style='store', align='left', title_size=10.0, body_size=7.5)

    box(ax, 82, 21.5, 71, 16.0, 'Operator access & the control arm', [
        'Dashboard        http://localhost:8081/            live SSE panels',
        'Offline report   http://localhost:8081/analysis    built by evaluation/',
        'Flow tables      mininet> dpctl dump-flows -O OpenFlow13 | grep cookie=0x5a',
        '',
        'Control arm      sudo -E python3 -m base_model.run_base --duration 300',
        '                 same topology, same workload, same attackers, no defences.',
    ], style='external', align='left', title_size=10.0, body_size=7.5)

    box(ax, 7, 5.5, 146, 13.5,
        'Start-up order — enforced by scripts/preflight_live_run.py, because a live run costs sudo and five minutes', [
        '1.  sudo service openvswitch-switch start       2.  sudo modprobe -a sch_htb sch_netem sch_tbf sch_prio ifb       3.  sudo mn -c',
        '4.  start the controller FIRST — a switch that connects to nothing installs no rules, and the run is silently empty',
        '5.  sudo python3 run_demo.py --mode mininet --config config/params_trust_full.yaml      6.  python3 -m evaluation.nfr_report data/events.jsonl',
    ], style='layer', align='left', title_size=10.0, body_size=7.5)
    return save(fig, 'fig4_deployment')
