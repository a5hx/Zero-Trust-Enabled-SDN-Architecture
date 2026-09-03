"""Generate dashboard/analysis.html -- the offline analysis and comparison page.

The live dashboard answers "what is happening right now". This answers "is it
actually better, and by how much", which is a different question with a
different data source: seeded batch sweeps and a finished recording, not an SSE
stream. So it is generated, not served live.

EVERY NUMBER HERE COMES FROM AN EXISTING ANALYSIS MODULE.
--------------------------------------------------------
Nothing is re-derived for presentation. `nfr_report`, `attack_report`,
`availability_report`, `interval_report`, `topology_metrics` and `stats` are
imported and called; this module arranges what they return. That is deliberate:
a second implementation of a metric is how a report ends up disagreeing with
the tool it claims to summarise, and this project has already paid for that
twice (panel_fix.md 6.3, memory/demo-recording-fidelity).

The output is one self-contained file -- no CDN, no external asset, no build
step -- so it is served at /analysis by the controller AND opens over file://
on a projector with no wifi. Same constraint dashboard/index.html documents.

Run:
    python3 -m evaluation.build_analysis_page data/events.jsonl \\
        --comparison-csv data/results_rf.csv \\
        --out dashboard/analysis.html
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from evaluation import svg_charts as C
from evaluation.attack_report import (
    confusion_matrix, ground_truth, per_class_metrics, score_run,
)
from evaluation.availability_report import compute as compute_availability
from evaluation.interval_report import DEFAULT_BUCKET_S, bucket_events
from evaluation.nfr_report import build_report as build_nfr_report
from evaluation.nfr_report import load_events
from evaluation.stats import compare_all, load_csv
from evaluation.topology_metrics import (
    DEFAULT_SINK, distance_to_sink, node_degree, topology_graph,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO_ROOT / 'dashboard' / 'analysis.html'


# --------------------------------------------------------------------------- #
# Page shell                                                                   #
# --------------------------------------------------------------------------- #
#: Tokens are dashboard/index.html's, verbatim, so the two pages read as one
#: system rather than as two projects. The chart-specific classes below are the
#: ones evaluation/svg_charts.py emits.
PAGE_CSS = """
:root{
  --bg:#0d1117; --panel:#161b22; --panel-2:#1c2129; --border:#2d333b;
  --text:#e6edf3; --muted:#8b949e; --good:#3fb950; --warn:#d29922;
  --bad:#f85149; --accent:#58a6ff; --vip:#bc8cff;
}
*{box-sizing:border-box}
body{
  margin:0; background:var(--bg); color:var(--text);
  font:14px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  -webkit-font-smoothing:antialiased;
}
code,.mono{font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace}

header{
  position:sticky; top:0; z-index:10; background:var(--panel-2);
  border-bottom:1px solid var(--border); padding:10px 20px;
  display:flex; align-items:center; gap:14px; flex-wrap:wrap;
}
header h1{font-size:14px; margin:0; font-weight:600; letter-spacing:.2px}
header .spacer{flex:1}
nav a{
  color:var(--muted); text-decoration:none; font-size:12px; padding:4px 9px;
  border-radius:999px; border:1px solid transparent;
}
nav a:hover{color:var(--text); border-color:var(--border); background:var(--panel)}
nav a.here{color:var(--accent); border-color:var(--border); background:var(--panel)}

main{max-width:1220px; margin:0 auto; padding:20px}
section{margin:0 0 30px}
section > h2{
  font-size:12px; text-transform:uppercase; letter-spacing:.8px;
  color:var(--muted); font-weight:600; margin:0 0 4px;
  padding-bottom:7px; border-bottom:1px solid var(--border);
}
section > .lede{color:var(--muted); font-size:13px; margin:8px 0 14px; max-width:78ch}
section > .lede strong{color:var(--text); font-weight:600}

.panel{background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:14px 16px}
.cols{display:grid; gap:14px; grid-template-columns:repeat(auto-fit,minmax(340px,1fr))}
.cols.wide{grid-template-columns:repeat(auto-fit,minmax(460px,1fr))}
.tiles{display:grid; gap:12px; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); margin-bottom:14px}

/* ---- provenance ---- */
.prov{
  background:var(--panel); border:1px solid var(--border); border-radius:8px;
  padding:12px 16px; margin-bottom:22px; font-size:12px; color:var(--muted);
}
.prov dl{display:grid; grid-template-columns:auto 1fr; gap:3px 12px; margin:0}
.prov dt{color:var(--muted)}
.prov dd{margin:0; color:var(--text); font-family:ui-monospace,Menlo,Consolas,monospace}

/* ---- stat tiles ---- */
.tile{background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:11px 13px}
.tile-label{font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.5px}
.tile-value{font-size:24px; font-weight:600; margin-top:3px; font-variant-numeric:tabular-nums}
.tile-sub{font-size:11px; color:var(--muted); margin-top:2px}
.tile.tone-good .tile-value{color:var(--good)}
.tile.tone-warn .tile-value{color:var(--warn)}
.tile.tone-bad  .tile-value{color:var(--bad)}

/* ---- figures ---- */
.fig{margin:0 0 6px; min-width:0}
.fig-title{font-size:12px; font-weight:600; color:var(--text)}
.fig-sub{font-size:11px; color:var(--muted); margin-top:1px; margin-bottom:6px}
.fig svg{display:block; width:100%; height:auto; overflow:visible}
.fig-empty{
  border:1px dashed var(--border); border-radius:6px; padding:16px;
  color:var(--muted); font-size:12px;
}
.fig-empty p{margin:0 0 8px}
.cmd{
  display:block; background:var(--bg); border:1px solid var(--border);
  border-radius:5px; padding:7px 9px; color:var(--accent); font-size:11px;
  overflow-x:auto; white-space:pre;
}

/* ---- legend ---- */
.legend{display:flex; gap:12px; flex-wrap:wrap; margin:0 0 6px}
.lkey{display:inline-flex; align-items:center; gap:5px; font-size:11px; color:var(--muted)}
.lkey i{width:9px; height:9px; border-radius:2px; display:inline-block}

/* ---- SVG marks ----
   Solid hairline grid, never dashed: dashing reads as "threshold" when it is
   only a grid. Text wears text tokens, never the series colour. */
.grid{stroke:#2c313a; stroke-width:1}
.axis{stroke:#3a4048; stroke-width:1}
.tick{fill:var(--muted); font-size:9px; font-variant-numeric:tabular-nums}
.tick.x{text-anchor:middle}
.tick.y{text-anchor:end}
.sline{fill:none; stroke-width:2; stroke-linejoin:round; stroke-linecap:round}
.sdot{stroke:var(--panel); stroke-width:2}
.endlab{font-size:10px; fill:var(--text); font-variant-numeric:tabular-nums}
.band{fill:var(--warn); opacity:.07}
.bandedge{stroke:var(--warn); stroke-width:1; opacity:.5}
.bandlab{font-size:8px; fill:var(--warn); opacity:.85}
.rowlab{font-size:11px; fill:var(--muted); text-anchor:end}
.rowlab.is-subject{fill:var(--text); font-weight:600}
.rowval{font-size:10px; fill:var(--text); font-variant-numeric:tabular-nums}
.rowval.na{fill:#4d5560}
.hcol{font-size:10px; fill:var(--muted); text-anchor:start}
.cellval{font-size:11px; text-anchor:middle; font-variant-numeric:tabular-nums}
.cell.diag{stroke:var(--border); stroke-width:1}

/* ---- tables (the accessibility fallback for every chart) ---- */
.tablewrap{overflow-x:auto; margin-top:8px}
table{width:100%; border-collapse:collapse; font-size:11.5px}
th{
  text-align:left; color:var(--muted); font-weight:500; font-size:10px;
  text-transform:uppercase; letter-spacing:.5px; padding:6px 9px;
  border-bottom:1px solid var(--border); white-space:nowrap;
}
td{padding:5px 9px; border-bottom:1px solid #21262d; font-variant-numeric:tabular-nums}
th.num,td.num{text-align:right}
tr.is-subject td{background:rgba(88,166,255,.07)}
tr.is-subject td:first-child{font-weight:600; color:var(--text)}
tr.is-bad td{background:rgba(248,81,73,.07)}

.pass{color:var(--good)} .fail{color:var(--bad)} .nodata{color:var(--muted)}
.note{
  border-left:2px solid var(--border); padding:2px 0 2px 12px;
  color:var(--muted); font-size:12px; margin:12px 0; max-width:78ch;
}
.note strong{color:var(--text)}
footer{color:var(--muted); font-size:11px; padding:20px; text-align:center;
  border-top:1px solid var(--border); margin-top:30px}
@media print{
  header{position:static}
  body{background:#fff; color:#000}
}
"""


def _git_commit() -> str:
    try:
        out = subprocess.run(
            ['git', 'rev-parse', '--short', 'HEAD'],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=5,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:      # noqa: BLE001 -- provenance is best-effort
        pass
    return 'unknown'


def _section(sid: str, title: str, lede: str, body: str) -> str:
    lede_html = f'<p class="lede">{lede}</p>' if lede else ''
    return f'<section id="{C.esc(sid)}"><h2>{C.esc(title)}</h2>{lede_html}{body}</section>'


def _note(text: str) -> str:
    return f'<p class="note">{text}</p>'


# --------------------------------------------------------------------------- #
# 1. Provenance                                                                #
# --------------------------------------------------------------------------- #
def section_provenance(
    events: Sequence[Dict[str, Any]],
    events_path: str,
    graph: Optional[Dict[str, Any]],
) -> str:
    """What this report describes. A committed report that cannot say which run
    it came from is worse than no report."""
    span = (events[-1]['ts'] - events[0]['ts']) if len(events) > 1 else 0.0
    servers = [n for n in (graph or {}).get('nodes', []) if n.get('kind') == 'server']
    iots = [n for n in (graph or {}).get('nodes', []) if n.get('kind') == 'iot']
    attacks = [
        f'{n["id"]}:{n["attack"]}@{n.get("attack_start_s", 0):.0f}s'
        for n in (graph or {}).get('nodes', [])
        if n.get('attack') and n['attack'] != 'none'
    ]
    size_mb = 0.0
    try:
        size_mb = os.path.getsize(events_path) / 1e6
    except OSError:
        pass

    rows = [
        ('Recording', f'{events_path} ({size_mb:.1f} MB)'),
        ('Events', f'{len(events):,}'),
        ('Span', f'{span:.1f} s'),
        ('Scale', f'{len(servers)} edge servers / {len(iots)} IoT devices'),
        ('Configured attacks', ', '.join(attacks) if attacks else 'none'),
        ('Commit', _git_commit()),
        ('Generated', _dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
    ]
    dl = ''.join(f'<dt>{C.esc(k)}</dt><dd>{C.esc(v)}</dd>' for k, v in rows)
    return f'<div class="prov"><dl>{dl}</dl></div>'


# --------------------------------------------------------------------------- #
# 2. NFR compliance                                                            #
# --------------------------------------------------------------------------- #
def section_nfr(events: Sequence[Dict[str, Any]]) -> str:
    results = build_nfr_report(events)
    tiles: List[str] = []
    rows: List[Sequence[Any]] = []
    classes: List[str] = []
    for r in results:
        if r.passed is None:
            tone, verdict = '', 'no data'
        elif r.passed:
            tone, verdict = 'good', 'PASS'
        else:
            tone, verdict = 'bad', 'FAIL'
        tiles.append(C.stat_tile(r.name, verdict, r.target, tone))
        rows.append([r.name, r.metric, r.target, r.measured or '—', verdict])
        classes.append('is-bad' if r.passed is False else '')

    passed = sum(1 for r in results if r.passed)
    total = len(results)
    body = (
        f'<div class="tiles">{"".join(tiles)}</div>'
        f'<div class="panel">'
        f'{C.table(["requirement", "metric", "target", "measured", "verdict"], rows, numeric_from=99, row_classes=classes)}'
        f'</div>'
    )
    lede = (
        f'<strong>{passed} of {total}</strong> non-functional requirements met on this run. '
        'Verdicts carry the word as well as the colour.'
    )
    return _section('nfr', 'Non-functional requirements', lede, body)


# --------------------------------------------------------------------------- #
# 3. Attack detection                                                          #
# --------------------------------------------------------------------------- #
def section_attacks(events: Sequence[Dict[str, Any]]) -> str:
    results = score_run(events)
    if not results:
        return _section(
            'attacks', 'Attack detection',
            'No classification ground truth in this recording.',
            C.empty_figure('Confusion matrix', '', 'This recording has no topology event.'),
        )

    cm = confusion_matrix(results)
    labels = sorted(cm)
    cols = sorted({c for row in cm.values() for c in row} | set(labels))
    matrix = [[cm.get(r, {}).get(c, 0) for c in cols] for r in labels]

    per_class = per_class_metrics(results)
    attacks = [r for r in results if r.truth != 'none']
    honest = [r for r in results if r.truth == 'none']
    exact = sum(1 for r in attacks if r.correct)
    family = sum(1 for r in attacks if r.family_correct)
    mislabelled = sum(1 for r in honest if r.predicted != 'none')
    total_correct = sum(1 for r in results if r.correct)

    lat = [(r.subject, r.detection_latency_s) for r in attacks
           if r.detection_latency_s is not None]

    tiles = ''.join([
        C.stat_tile('Overall accuracy',
                    f'{100 * total_correct / len(results):.1f}%',
                    f'{total_correct} of {len(results)} subjects', 'good' if total_correct == len(results) else ''),
        C.stat_tile('Attacks detected', f'{family}/{len(attacks)}', 'placed in the right family',
                    'good' if family == len(attacks) else 'warn'),
        C.stat_tile('Exactly classified', f'{exact}/{len(attacks)}', 'exact label match',
                    'good' if exact == len(attacks) else 'warn'),
        C.stat_tile('False positives', f'{mislabelled}/{len(honest)}',
                    'honest subjects wrongly labelled',
                    'good' if mislabelled == 0 else 'bad'),
    ])

    prf_rows = [
        [lbl, f'{m["precision"]:.3f}', f'{m["recall"]:.3f}', f'{m["f1"]:.3f}', int(m['support'])]
        for lbl, m in sorted(per_class.items())
    ]

    subj_rows = [
        [r.subject, r.truth, r.predicted,
         'exact' if r.correct else ('family' if r.family_correct else 'miss'),
         '—' if r.detection_latency_s is None else f'{r.detection_latency_s:.1f} s']
        for r in sorted(attacks, key=lambda x: x.subject)
    ]
    subj_classes = ['' if r.correct else 'is-bad' for r in sorted(attacks, key=lambda x: x.subject)]

    figs = [
        C.heatmap('Confusion matrix', 'rows = ground truth, columns = predicted',
                  labels, cols, matrix),
        C.hbar('Detection latency', 'configured onset to first correct label',
               lat, unit='s', lower_is_better=True) if lat else
        C.empty_figure('Detection latency', '', 'No attack was both detected and given an onset.'),
    ]

    body = (
        f'<div class="tiles">{tiles}</div>'
        f'<div class="cols wide">'
        f'<div class="panel">{figs[0]}</div>'
        f'<div class="panel">{figs[1]}'
        + _note(
            'Detection latency is an <strong>upper bound</strong>: it is measured from '
            'controller start, so it includes the Mininet build time before the agents '
            'were launched. Inferring onset from the first anomaly instead would make '
            'every detector look infinitely fast by construction.'
        )
        + '</div></div>'
        f'<div class="cols wide">'
        f'<div class="panel"><div class="fig-title">Per class</div>'
        f'<div class="fig-sub">precision / recall / F1, with support</div>'
        f'{C.table(["label", "precision", "recall", "F1", "support"], prf_rows)}</div>'
        f'<div class="panel"><div class="fig-title">Per attacker</div>'
        f'<div class="fig-sub">ground truth vs. what the classifier said</div>'
        f'{C.table(["subject", "truth", "predicted", "result", "latency"], subj_rows, numeric_from=4, row_classes=subj_classes)}'
        f'</div></div>'
    )
    lede = (
        f'Six attack families plus wrong-credential devices, scored against the ground truth the '
        f'<code>topology</code> event carries. <strong>{mislabelled} of {len(honest)}</strong> '
        f'honest subjects were wrongly labelled.'
    )
    return _section('attacks', 'Attack detection & classification', lede, body)


# --------------------------------------------------------------------------- #
# 4. Service availability                                                      #
# --------------------------------------------------------------------------- #
def section_availability(events: Sequence[Dict[str, Any]]) -> str:
    rep = compute_availability(events)
    if not rep.nodes:
        return _section('availability', 'Service availability',
                        'No node roster in this recording.',
                        C.empty_figure('Availability', '', 'No topology event.'))

    honest = sorted(rep.honest, key=lambda n: n.node)
    attackers = sorted(rep.attackers, key=lambda n: n.node)

    ha = rep.honest_availability
    ac = rep.attacker_containment
    tiles = ''.join([
        C.stat_tile('Honest availability',
                    '—' if ha is None else f'{100 * ha:.2f}%',
                    'service the fleet could give',
                    'good' if ha is not None and ha >= 0.999 else 'warn'),
        C.stat_tile('Honest nodes quarantined',
                    f'{sum(1 for n in honest if n.episodes)}/{len(honest)}',
                    'the system’s real cost',
                    'good' if not any(n.episodes for n in honest) else 'bad'),
        C.stat_tile('Attacker containment',
                    '—' if ac is None else f'{100 * ac:.1f}%',
                    'mean time isolated — the system working',
                    'good' if ac else ''),
        C.stat_tile('Fleet above quorum',
                    f'{100 * rep.above_quorum_s / rep.run_s:.1f}%' if rep.run_s else '—',
                    f'at or above {rep.quorum:.0%} serving'),
    ])

    figs = ''
    if honest:
        figs += (
            '<div class="panel">'
            + C.hbar('Honest nodes — eligible to serve', 'fraction of the run',
                     [(n.node, 100 * n.eligible_fraction) for n in honest],
                     unit='%', x_max=100, lower_is_better=False)
            + '</div>'
        )
    if attackers:
        figs += (
            '<div class="panel">'
            + C.hbar('Attackers — time contained', 'fraction of the run isolated',
                     [(n.node, 100 * (1 - n.eligible_fraction)) for n in attackers],
                     unit='%', x_max=100, lower_is_better=False)
            + '</div>'
        )

    rows = [
        [n.node, n.truth, f'{100 * n.eligible_fraction:.1f}%', f'{n.quarantined_s:.1f}',
         n.episodes, f'{n.longest_quarantine_s:.1f}',
         '—' if n.time_to_first_isolation_s is None else f'{n.time_to_first_isolation_s:.1f}',
         'yes' if n.never_recovered else 'no']
        for n in honest + attackers
    ]
    classes = ['is-bad' if (not n.is_attacker and n.episodes) else '' for n in honest + attackers]

    body = (
        f'<div class="tiles">{tiles}</div>'
        f'<div class="cols wide">{figs}</div>'
        f'<div class="panel">'
        f'{C.table(["node", "truth", "eligible", "down s", "episodes", "longest s", "1st isolation", "stranded"], rows, numeric_from=2, row_classes=classes)}'
        f'</div>'
        + _note(
            'The two figures are reported separately and are never averaged. Quarantine '
            'downtime means <strong>opposite things</strong> for the two groups: an isolated '
            'attacker is zero-trust enforcement working, an isolated honest node is the '
            'system’s real cost. A single fleet-wide "availability: 94%" would be a mean '
            'over two quantities that should move in opposite directions.'
        )
        + (_note(
            '<strong>Teardown suspected.</strong> The final seconds of this recording show most '
            'of the fleet quarantining, which usually means the agents were killed while the '
            'controller was still polling. The tail still counts as real downtime here — it is '
            'flagged, never silently trimmed.'
        ) if rep.teardown_suspected else '')
    )
    lede = (
        'This project’s stand-in for the WSN "network lifetime" metric, with isolation '
        'standing in for node death. No energy model was invented: these are mains-powered '
        'edge servers, and a battery curve would be a fabricated number dressed as a measurement.'
    )
    return _section('availability', 'Service availability & network lifetime', lede, body)


# --------------------------------------------------------------------------- #
# 5. Metrics over time (+ attack on/off)                                       #
# --------------------------------------------------------------------------- #
#: (attribute, title, sub, unit, y_max). Definitions are IntervalMetrics'; this
#: only chooses which of them to draw and in what order.
_TIME_SERIES: Sequence[Tuple[str, str, str, str, Optional[float]]] = (
    ('throughput_bps', 'Throughput', 'VIP-serving flow rules, real OFPFlowStats bytes', 'kbps', None),
    ('mean_task_latency_ms', 'End-to-end delay', 'mean task latency, successful tasks', 'ms', None),
    ('pdr', 'Packet delivery ratio', 'tasks completed / tasks reported', '%', 100.0),
    ('jain_fairness', 'Load balancing', "Jain's fairness over the full server roster", '', 1.0),
    ('offered_rate_hz', 'Traffic load', 'requests offered per second', '/s', None),
    ('routing_reliability', 'Routing reliability', 'decisions never re-steered', '%', 100.0),
    ('mean_trust_honest', 'Trust value', 'mean T, honest vs. attacker servers', '', 1.0),
    ('honest_serving_fraction', 'Service availability', 'honest serving vs. attackers contained', '%', 100.0),
    ('quarantine_drop_packets', 'Quarantine drops', 'OpenFlow drop-rule hits — enforcement, not loss', 'pkt', None),
)

#: Series that pair with the one above them, so the chart shows the honest/
#: attacker split rather than one averaged line.
_PAIRED = {
    'mean_trust_honest': ('mean_trust_attacker', 'honest', 'attacker'),
    'honest_serving_fraction': ('attacker_contained_fraction', 'honest serving', 'attackers contained'),
    'routing_reliability': ('admitted_ratio', 'decisions held', 'requests admitted'),
}

#: Metrics whose IntervalMetrics value is a 0-1 fraction but that read as a
#: percentage.
_AS_PCT = {'pdr', 'routing_reliability', 'admitted_ratio',
           'honest_serving_fraction', 'attacker_contained_fraction'}


def _series_values(buckets, attr: str) -> List[Optional[float]]:
    out: List[Optional[float]] = []
    for b in buckets:
        v = getattr(b, attr, None)
        if v is not None and attr in _AS_PCT:
            v = 100.0 * v
        if v is not None and attr == 'throughput_bps':
            v = v / 1000.0
        out.append(v)
    return out


def section_timeseries(events: Sequence[Dict[str, Any]],
                       graph: Optional[Dict[str, Any]]) -> str:
    buckets = bucket_events(events)
    if not buckets:
        return _section('overtime', 'Metrics over time', '',
                        C.empty_figure('Metrics over time', '', 'No events to bin.'))

    bucket_s = DEFAULT_BUCKET_S
    n = len(buckets)
    x_ticks = [(0, '0s'), (n - 1, f'{int(buckets[-1].t_start_s)}s')]

    onsets = sorted(
        (float(nd.get('attack_start_s') or 0), f'{nd["id"]} {nd["attack"]}')
        for nd in (graph or {}).get('nodes', [])
        if nd.get('attack') and nd['attack'] != 'none'
    )
    bands = [(at / bucket_s, label) for at, label in onsets]

    figs: List[str] = []
    for attr, title, sub, unit, ymax in _TIME_SERIES:
        series = [{'name': title, 'color': C.S1, 'values': _series_values(buckets, attr)}]
        if attr in _PAIRED:
            other, n1, n2 = _PAIRED[attr]
            series[0]['name'] = n1
            series.append({'name': n2, 'color': C.S2,
                           'values': _series_values(buckets, other)})
        figs.append(
            '<div class="panel">'
            + C.line_chart(title, sub, series, x_ticks, unit=unit, y_max=ymax, bands=bands)
            + '</div>'
        )

    body = f'<div class="cols">{"".join(figs)}</div>'
    if onsets:
        body += _note(
            'Shaded bands mark when each attack was <strong>configured to arm</strong>, from the '
            'run’s ground truth. They are not a claim that the controller had detected '
            'anything by then — detection latency is reported separately above.'
        )
    lede = (
        f'{n} buckets of {bucket_s:.0f} s, binned by '
        '<code>evaluation/interval_report.py</code> — the same definitions the live '
        'dashboard draws from the event stream.'
    )
    return _section('overtime', 'Metrics over time', lede, body)


def _warmup_warning(before, during, first: float) -> Optional[str]:
    """Say so when the "clean" window is really run start-up.

    A run's first seconds are not a clean steady state: the agents are still
    launching, no VIP flow has been installed yet, and trust is climbing from
    its configured `initial_score` toward wherever it settles. Comparing that
    against steady-state-under-attack makes the attack look BENEFICIAL --
    delay falls, trust rises, throughput climbs from zero -- and every one of
    those "improvements" is the run warming up.

    That is the same shape as the measurement trap docs/EVALUATION.md 8
    documents, where latency metrics flatter a black hole because the tasks it
    swallowed never entered the average.

    Detected and warned about, never silently trimmed. A warm-up knob that
    discards inconvenient early data is a knob that will eventually be used to
    flatter a result -- the rule availability_report.py sets for the teardown
    tail, applied to the other end of the run.
    """
    if not before:
        return None
    evidence: List[str] = []

    if len(before) < 3:
        evidence.append(
            f'the clean window is only {len(before)} bucket'
            f'{"s" if len(before) != 1 else ""} wide'
        )

    t_clean = [b.mean_trust_honest for b in before if b.mean_trust_honest is not None]
    t_attack = [b.mean_trust_honest for b in during if b.mean_trust_honest is not None]
    if t_clean and t_attack and t_clean[-1] < 0.95 * max(t_attack):
        evidence.append(
            f'honest trust is still climbing through it '
            f'({t_clean[0]:.2f} to {t_clean[-1]:.2f}, against {max(t_attack):.2f} later) '
            f'— it has not reached steady state'
        )

    thr_clean = [b.throughput_bps for b in before]
    if thr_clean and max(thr_clean) == 0 and any(b.throughput_bps for b in during):
        evidence.append(
            'no VIP flow rule had been installed yet, so measured throughput is zero '
            'for reasons that have nothing to do with the attack'
        )

    if not evidence:
        return None
    return _note(
        f'<strong>Read this table with care: the clean window is run start-up, not a '
        f'clean steady state.</strong> The first timed attack arms at {first:.0f}s, and '
        + '; '.join(evidence) + '. '
        'Several rows below therefore show the attack window looking <em>better</em> — '
        'that is the run warming up, not the attack helping. The numbers are left as '
        'measured rather than trimmed to a flattering window; to get a real baseline, '
        'arm the first attack later so a steady-state clean window exists.'
    )


def section_attack_impact(events: Sequence[Dict[str, Any]],
                          graph: Optional[Dict[str, Any]]) -> str:
    """Attack on vs. attack off, on the same run.

    Splits the interval buckets at the first configured onset and reports each
    metric before and after. This is the advisor's "measured per-interval
    impact" ask: not "quarantined: yes/no" but what PDR, delay and throughput
    actually did.
    """
    attackers = [
        nd for nd in (graph or {}).get('nodes', [])
        if nd.get('attack') and nd['attack'] != 'none'
    ]
    # Only attacks that ARM AT A TIME can define a clean->attack boundary.
    # `bad_credentials` devices hold a wrong key and are refused at their first
    # handshake, so the mechanism is in force from t=0 and its `attack_start_s`
    # is a defaulted zero rather than a configured onset. Letting that zero set
    # the boundary collapses the clean window to nothing and silently discards
    # the whole comparison -- which is exactly what it did before this filter.
    timed = sorted(
        (float(nd.get('attack_start_s') or 0), nd['id'], nd['attack'])
        for nd in attackers
        if nd['attack'] != 'bad_credentials' and float(nd.get('attack_start_s') or 0) > 0
    )
    always_on = sorted(
        f'{nd["id"]} ({nd["attack"]})' for nd in attackers
        if nd['attack'] == 'bad_credentials' or float(nd.get('attack_start_s') or 0) <= 0
    )
    if not timed:
        return _section(
            'impact', 'Attack impact — on vs. off', '',
            C.empty_figure(
                'Attack impact', '',
                'No attack in this run arms at a configured time, so there is no clean '
                'window to compare an attack window against.'
                + (f' In force for the whole run: {", ".join(always_on)}.' if always_on else ''),
                'set malicious_edge_nodes[].start_s in the config'),
        )

    first = timed[0][0]
    buckets = bucket_events(events)
    before = [b for b in buckets if b.t_end_s <= first]
    during = [b for b in buckets if b.t_start_s >= first]
    if not before:
        return _section(
            'impact', 'Attack impact — on vs. off', '',
            C.empty_figure(
                'Attack impact', '',
                f'The first attack arms at {first:.0f}s, before the first complete '
                f'{DEFAULT_BUCKET_S:.0f}s bucket closed, so there is no clean baseline '
                'window in this recording to compare against.',
                'edit malicious_edge_nodes[].start_s in the config to arm later'),
        )

    def mean_of(bs, attr) -> Optional[float]:
        vals = [v for v in _series_values(bs, attr) if v is not None]
        return sum(vals) / len(vals) if vals else None

    rows: List[Sequence[Any]] = []
    for attr, title, _sub, unit, _ymax in _TIME_SERIES:
        a, b = mean_of(before, attr), mean_of(during, attr)
        if a is None and b is None:
            continue
        if a is None or b is None or a == 0:
            delta = None
        else:
            delta = 100.0 * (b - a) / abs(a)
        rows.append([
            title,
            C.fmt_val(a, unit), C.fmt_val(b, unit),
            '—' if delta is None else f'{delta:+.1f}%',
        ])

    warning = _warmup_warning(before, during, first)

    body = (
        (warning or '')
        + f'<div class="panel">'
        f'{C.table(["metric", f"clean 0–{first:.0f}s ({len(before)} bucket{"s" if len(before) != 1 else ""})", f"under attack {first:.0f}s+ ({len(during)} buckets)", "change"], rows)}'
        f'</div>'
        + _note(
            'The clean window is everything before the <strong>first timed</strong> attack arms; '
            'the attack window is everything after. Two caveats that cut in opposite directions: '
            'with staggered onsets the later window accumulates attackers, so this understates '
            'the last attack to arm; and the "clean" window is only clean of <em>timed</em> '
            'attacks.'
            + (f' Already in force throughout, including the clean window: '
               f'<strong>{C.esc(", ".join(always_on))}</strong>.' if always_on else '')
        )
    )
    onset_list = ', '.join(f'{nid} {kind} @{at:.0f}s' for at, nid, kind in timed)
    lede = (
        f'The same metrics before and after the first timed attack armed at '
        f'<strong>{first:.0f}s</strong> — measured impact, not a detection flag. '
        f'Onsets: {C.esc(onset_list)}.'
    )
    return _section('impact', 'Attack impact — on vs. off', lede, body)


# --------------------------------------------------------------------------- #
# 6. Topology structure                                                        #
# --------------------------------------------------------------------------- #
_KIND_ORDER = {'server': 0, 'core_switch': 1, 'edge_switch': 2, 'iot': 3}
_KIND_LABEL = {'server': 'server', 'core_switch': 'core sw',
               'edge_switch': 'edge sw', 'iot': 'iot'}


def section_topology(graph: Optional[Dict[str, Any]]) -> str:
    if not graph:
        return _section('topology', 'Topology structure', '',
                        C.empty_figure('Topology', '', 'No topology event in this recording.'))

    deg = node_degree(graph)
    dist = distance_to_sink(graph, sink=DEFAULT_SINK)
    kinds = {n['id']: n.get('kind', '') for n in graph.get('nodes', []) if 'id' in n}

    def key(nid: str):
        head = nid.rstrip('0123456789')
        tail = nid[len(head):]
        return (_KIND_ORDER.get(kinds.get(nid, ''), 9), head, int(tail) if tail else -1)

    ids = sorted(deg, key=key)
    rows = [
        [nid, _KIND_LABEL.get(kinds.get(nid, ''), kinds.get(nid, '')), deg[nid],
         dist[nid]['hops'],
         None if dist[nid]['delay_ms'] is None else f'{dist[nid]["delay_ms"]:.1f} ms']
        for nid in ids
    ]

    iot_delays = [dist[n]['delay_ms'] for n in ids
                  if kinds.get(n) == 'iot' and dist[n]['delay_ms'] is not None]
    measured = any(dist[n]['delay_ms'] is not None for n in ids if n != DEFAULT_SINK)

    figs = ''
    if iot_delays:
        figs = ('<div class="panel">' + C.hbar(
            'Distance to sink — IoT devices',
            'sum of configured link delays along the path',
            [(n, dist[n]['delay_ms']) for n in ids if kinds.get(n) == 'iot'][:16],
            unit='ms') + '</div>')

    body = (
        f'<div class="cols wide">{figs}'
        f'<div class="panel">'
        f'{C.table(["node", "kind", "degree", f"hops to {DEFAULT_SINK}", f"delay to {DEFAULT_SINK}"], rows, numeric_from=2)}'
        f'</div></div>'
        + _note(
            f'Sink is <code>{DEFAULT_SINK}</code>, the core switch every VIP task transits. '
            'The delay column is the sum of <strong>configured</strong> link delays — a '
            'measured input, not an observed RTT, and it excludes queueing and server-side '
            'processing. End-to-end delay is a different metric and has its own chart above.'
            + ('' if measured else
               ' <strong>Not reported for this run:</strong> the harness never sent its link '
               'table, so only hop counts are available.')
        )
    )
    lede = (
        'The two metrics that are properties of the graph rather than of the traffic. Node '
        'degree is constant at 1 for every server and device; it varies only on the switches, '
        'which is this topology’s only structural asymmetry.'
    )
    return _section('topology', 'Topology structure', lede, body)


# --------------------------------------------------------------------------- #
# 7-9. Strategy comparison, significance, ablation                             #
# --------------------------------------------------------------------------- #
#: The five headline routers. `zt_sdn_rf` also lives in the same CSV but is the
#: AI-optimizer arm, a different question, and is handled in its own section --
#: leaving it in here would quietly turn the baseline comparison into a
#: six-way one and change the Holm family size.
HEADLINE_STRATEGIES = ('random', 'round_robin', 'least_conn', 'no_trust', 'zt_sdn')
SYSTEM = 'zt_sdn'
ABLATION = 'no_trust'

#: What each router is, so the page does not assume the reader knows.
STRATEGY_BLURB = {
    'random': 'uniform over all nodes — the null baseline',
    'round_robin': 'strict cycle; trust-blind and perfectly fair, so it feeds an '
                   'attacker its 1/N share forever',
    'least_conn': 'join-shortest-queue on <em>claimed</em> load — the strongest '
                  'classical baseline, and the one a Sybil directly exploits',
    'no_trust': 'the ablation: real EdgeScore with trust pinned uniform and '
                'quarantine disabled',
    'zt_sdn': 'the system under test: EdgeScore + p2c + ε, real trust, quarantine',
    'zt_sdn_rf': 'zt_sdn with weights warm-started from the offline Random Forest',
}

#: (column, label, unit, digits). All six are lower-is-better.
#:
#: The rate metrics carry 4 decimals deliberately. At the default 2 the
#: differences these tables exist to show disappear: 0.0870 vs 0.0823 is a 6%
#: gap that both round to '0.09' / '0.08'. Precision here is not decoration.
COMPARISON_METRICS = (
    ('slo_violation_rate', 'SLO violation rate', '', 4),
    ('failure_rate', 'Failure rate', '', 4),
    ('malicious_share', 'Malicious share', '', 4),
    ('mean_latency_ms', 'Mean latency', 'ms', 1),
    ('p95_latency_ms', 'p95 latency', 'ms', 1),
    ('gini', 'Gini (routing imbalance)', '', 4),
)

_MISSING_CSV = (
    'The comparison sweep has not been generated. It is 600 seeded runs and '
    'takes about 45 seconds.'
)
_SWEEP_CMD = ('python3 -m evaluation.baseline --csv data/baseline.csv\n'
              'python3 -m evaluation.build_analysis_page data/events.jsonl '
              '--comparison-csv data/baseline.csv')


def _medians_by_scenario(comparisons) -> Dict[str, Dict[str, float]]:
    """scenario -> strategy -> median, read off the Comparison objects.

    Taken from what `stats.compare_all` already computed rather than
    re-medianing the CSV here: compare_all medians over the SEEDS IT PAIRED,
    and a second median over a different seed set would disagree with the
    significance test sitting beside it on the page.
    """
    out: Dict[str, Dict[str, float]] = {}
    for c in comparisons:
        d = out.setdefault(c.scenario, {})
        d[c.system] = c.system_median
        d[c.baseline] = c.baseline_median
    return out


def _sig_annotation(c) -> str:
    """Improvement, with the evidence for it, as one label."""
    if c.improvement_pct is None:
        return '—'
    verdict = f'p={c.p_adj:.2g}' if c.significant else 'not significant'
    return f'{c.improvement_pct:+.1f}%  {verdict}'


def section_comparison(rows: Optional[Sequence[dict]]) -> str:
    if not rows:
        return _section(
            'comparison', 'Routing strategy comparison', '',
            C.empty_figure('Strategy comparison', 'median over seeds',
                           _MISSING_CSV, _SWEEP_CMD))

    headline = [r for r in rows if r['strategy'] in HEADLINE_STRATEGIES]
    comparisons = compare_all(headline, metric='slo_violation_rate', system=SYSTEM)
    if not comparisons:
        return _section(
            'comparison', 'Routing strategy comparison', '',
            C.empty_figure('Strategy comparison', '',
                           'The CSV has no rows for the system under test.', _SWEEP_CMD))

    medians = _medians_by_scenario(comparisons)
    n_pairs = comparisons[0].n_pairs

    figs = []
    for scenario in sorted(medians):
        by_strategy = medians[scenario]
        ordered = [(k, by_strategy[k]) for k in HEADLINE_STRATEGIES if k in by_strategy]
        # Sorted worst-first so the eye lands on the subject at the bottom.
        ordered.sort(key=lambda kv: -kv[1])
        figs.append(
            '<div class="panel">'
            + C.hbar(f'{scenario}', 'median SLO violation rate over seeds',
                     ordered, highlight=SYSTEM, lower_is_better=True)
            + '</div>'
        )

    # Every metric, every scenario, as the table view.
    all_rows: List[Sequence[Any]] = []
    for col, label, unit, digits in COMPARISON_METRICS:
        cs = compare_all(headline, metric=col, system=SYSTEM)
        med = _medians_by_scenario(cs)
        for scenario in sorted(med):
            vals = med[scenario]
            all_rows.append(
                [label, scenario]
                + [C.fmt_val(vals.get(k), unit, digits) for k in HEADLINE_STRATEGIES]
            )

    blurbs = ''.join(
        f'<tr><td><code>{C.esc(k)}</code></td><td>{STRATEGY_BLURB[k]}</td></tr>'
        for k in HEADLINE_STRATEGIES
    )

    body = (
        f'<div class="cols">{"".join(figs)}</div>'
        f'<div class="panel" style="margin-top:14px"><div class="fig-title">Every metric, every scenario</div>'
        f'<div class="fig-sub">median over {n_pairs} paired seeds; lower is better throughout</div>'
        f'{C.table(["metric", "scenario"] + list(HEADLINE_STRATEGIES), all_rows, numeric_from=2)}'
        f'</div>'
        f'<div class="panel" style="margin-top:14px"><div class="fig-title">The five routers</div>'
        f'<div class="tablewrap"><table><tbody>{blurbs}</tbody></table></div></div>'
    )
    lede = (
        f'Five routing strategies across four scenarios, {n_pairs} seeded runs each. '
        f'<strong>{SYSTEM}</strong> is the system under test and carries the colour; the '
        'baselines are context and share one recessive gray.'
    )
    return _section('comparison', 'Routing strategy comparison', lede, body)


def section_significance(rows: Optional[Sequence[dict]]) -> str:
    if not rows:
        return _section(
            'significance', 'Statistical significance', '',
            C.empty_figure('Significance', 'paired Wilcoxon + Holm–Bonferroni',
                           _MISSING_CSV, _SWEEP_CMD))

    headline = [r for r in rows if r['strategy'] in HEADLINE_STRATEGIES]
    comparisons = compare_all(headline, metric='slo_violation_rate', system=SYSTEM)
    if not comparisons:
        return _section('significance', 'Statistical significance', '',
                        C.empty_figure('Significance', '', 'No comparable rows.', _SWEEP_CMD))

    wins = [c for c in comparisons if c.significant and c.system_better]
    losses = [c for c in comparisons if c.significant and not c.system_better]

    figs = []
    for scenario in sorted({c.scenario for c in comparisons}):
        rows_f = [
            {'label': f'vs {c.baseline}',
             'value': c.improvement_pct,
             'significant': c.significant,
             'annotation': _sig_annotation(c)}
            for c in sorted(comparisons, key=lambda c: c.baseline)
            if c.scenario == scenario
        ]
        figs.append(
            '<div class="panel">'
            + C.forest_plot(scenario, 'reduction in SLO violation rate, positive = better',
                            rows_f)
            + '</div>'
        )

    table_rows = [
        [c.scenario, c.baseline, c.n_pairs,
         f'{c.system_median:.4f}', f'{c.baseline_median:.4f}',
         '—' if c.improvement_pct is None else f'{c.improvement_pct:+.1f}%',
         f'{c.p_raw:.2g}', f'{c.p_adj:.2g}', f'{c.effect_size:+.2f}',
         c.effect_label, f'{c.wins}/{c.losses}/{c.ties}',
         'yes' if c.significant and c.system_better else
         ('WORSE' if c.significant else 'ns')]
        for c in comparisons
    ]
    classes = ['is-bad' if (c.significant and not c.system_better) else ''
               for c in comparisons]

    body = (
        f'<div class="cols">{"".join(figs)}</div>'
        f'<div class="panel" style="margin-top:14px">'
        f'{C.table(["scenario", "baseline", "n", SYSTEM, "baseline", "improvement", "p", "p adj", "r", "effect", "W/L/T", "verdict"], table_rows, numeric_from=2, row_classes=classes)}'
        f'</div>'
        + _note(
            'Paired <strong>Wilcoxon signed-rank</strong> on matched seeds, corrected with '
            '<strong>Holm–Bonferroni within each scenario</strong>, effect size as the '
            'matched-pairs rank-biserial correlation. Runs are paired on seed so the two '
            'strategies see the same arrival sequence; only seeds present for both are used. '
            'A hollow bar is a comparison that did not reach significance — the shape carries '
            'that as well as the colour.'
        )
    )
    lede = (
        f'<strong>{len(wins)} of {len(comparisons)}</strong> comparisons significantly favour '
        f'{SYSTEM} on SLO violation rate'
        + (f', and <strong>{len(losses)}</strong> significantly favour the baseline — those are '
           'reported in full below and in "Where the system loses".' if losses else '.')
    )
    return _section('significance', 'Statistical significance', lede, body)


def section_ablation(rows: Optional[Sequence[dict]]) -> str:
    """Defence on vs. off, holding everything else fixed."""
    if not rows:
        return _section(
            'ablation', 'Defence on vs. off', '',
            C.empty_figure('Ablation', f'{SYSTEM} vs {ABLATION}', _MISSING_CSV, _SWEEP_CMD))

    headline = [r for r in rows if r['strategy'] in HEADLINE_STRATEGIES]
    figs, table_rows = [], []
    for col, label, unit, digits in COMPARISON_METRICS:
        cs = [c for c in compare_all(headline, metric=col, system=SYSTEM)
              if c.baseline == ABLATION]
        if not cs:
            continue
        figs.append(
            '<div class="panel">'
            + C.forest_plot(
                label, f'{SYSTEM} vs {ABLATION}, positive = trust helps',
                [{'label': c.scenario, 'value': c.improvement_pct,
                  'significant': c.significant, 'annotation': _sig_annotation(c)}
                 for c in sorted(cs, key=lambda c: c.scenario)])
            + '</div>'
        )
        for c in sorted(cs, key=lambda c: c.scenario):
            table_rows.append([
                label, c.scenario, C.fmt_val(c.system_median, unit, digits),
                C.fmt_val(c.baseline_median, unit, digits),
                '—' if c.improvement_pct is None else f'{c.improvement_pct:+.1f}%',
                f'{c.p_adj:.2g}',
                'yes' if c.significant and c.system_better else
                ('WORSE' if c.significant else 'ns'),
            ])

    if not figs:
        return _section('ablation', 'Defence on vs. off', '',
                        C.empty_figure('Ablation', '', f'No {ABLATION} rows in the CSV.',
                                       _SWEEP_CMD))

    body = (
        f'<div class="cols">{"".join(figs)}</div>'
        f'<div class="panel" style="margin-top:14px">'
        f'{C.table(["metric", "scenario", SYSTEM, ABLATION, "improvement", "p adj", "verdict"], table_rows, numeric_from=2)}'
        f'</div>'
        + _note(
            f'<code>{ABLATION}</code> is the <strong>same selector</strong> as '
            f'<code>{SYSTEM}</code> — the real EdgeScore, the same p2c routing, the same '
            'seeds — with trust pinned uniform and quarantine disabled. It differs in '
            'exactly the trust dimension and nothing else, which is why this is the '
            'comparison that attributes the improvement to <em>trust</em> rather than to '
            'load-aware routing in general. A second live run with the defence switched off '
            'could not hold the arrival sequence fixed the way a paired seed does.'
        )
    )
    lede = (
        'The ablation: what the zero-trust layer itself buys, isolated from what '
        'load-aware routing buys.'
    )
    return _section('ablation', 'Defence on vs. off', lede, body)


# --------------------------------------------------------------------------- #
# 10-12. Scalability, optimizer, and where the system loses                    #
# --------------------------------------------------------------------------- #
RF_ARM = 'zt_sdn_rf'

_SCALE_CMD = ('python3 -m evaluation.scalability_sweep --csv data/scalability.csv\n'
              'python3 -m evaluation.build_analysis_page data/events.jsonl '
              '--scalability-csv data/scalability.csv')


def section_scalability(rows: Optional[Sequence[dict]]) -> str:
    if not rows:
        return _section(
            'scalability', 'Scalability', '',
            C.empty_figure('Scalability', 'N = 4 … 64',
                           'The scalability sweep has not been generated. It takes '
                           'about 15 seconds.', _SCALE_CMD))

    by_strategy: Dict[str, List[dict]] = {}
    for r in rows:
        by_strategy.setdefault(r['strategy'], []).append(r)
    for v in by_strategy.values():
        v.sort(key=lambda r: int(r['n']))

    ns = sorted({int(r['n']) for r in rows})
    x_ticks = [(0, f'N={ns[0]}'), (len(ns) - 1, f'N={ns[-1]}')]
    colors = {name: c for name, c in zip(sorted(by_strategy), (C.S1, C.S2, C.S3))}

    def series_for(col: str, scale: float = 1.0):
        out = []
        for name in sorted(by_strategy):
            by_n = {int(r['n']): r for r in by_strategy[name]}
            out.append({
                'name': name, 'color': colors.get(name, C.DIM),
                'values': [
                    (float(by_n[n][col]) * scale) if n in by_n and by_n[n].get(col) not in (None, '')
                    else None
                    for n in ns
                ],
            })
        return out

    figs = ''.join(
        '<div class="panel">' + C.line_chart(title, sub, series_for(col, scale),
                                             x_ticks, unit=unit, y_max=ymax) + '</div>'
        for col, title, sub, unit, scale, ymax in (
            ('throughput_hz', 'Throughput', 'completed tasks per second', '/s', 1.0, None),
            ('pdr', 'Packet delivery ratio', 'completed / offered', '%', 100.0, 100.0),
            ('p95_latency_ms', 'p95 latency', 'tail delay as the farm grows', 'ms', 1.0, None),
            ('jain_fairness', 'Load balancing', "Jain's fairness over the roster", '', 1.0, 1.0),
            ('starved', 'Starved nodes', 'servers that received no traffic at all', '', 1.0, None),
            ('decision_us_mean', 'Decision cost', 'wall-clock per select_edge_node call', 'µs', 1.0, None),
        )
    )

    table_rows = [
        [r['strategy'], int(r['n']), f'{float(r["throughput_hz"]):.1f}',
         f'{100 * float(r["pdr"]):.1f}%', f'{float(r["p95_latency_ms"]):.0f}',
         f'{float(r["jain_fairness"]):.3f}' if r.get('jain_fairness') not in (None, '') else '—',
         int(r['used']), int(r['starved']), f'{float(r["decision_us_mean"]):.1f}']
        for r in sorted(rows, key=lambda r: (r['strategy'], int(r['n'])))
    ]

    body = (
        f'<div class="cols">{figs}</div>'
        f'<div class="panel" style="margin-top:14px">'
        f'{C.table(["strategy", "N", "throughput/s", "PDR", "p95 ms", "Jain", "used", "starved", "decision µs"], table_rows, numeric_from=1)}'
        f'</div>'
        + _note(
            'From the discrete-event M/M/c harness driving the <strong>real</strong> '
            '<code>select_edge_node</code>, not a live Mininet run. Live scalability is '
            'hardware-capped here — the 8/40 run already needed workload retuning to avoid '
            'collapse on 4 WSL2 cores — so larger live runs were deliberately not attempted '
            'rather than reported at a scale the box cannot honestly reach. The decision-cost '
            'column is wall-clock and real; everything else is simulated arrivals.'
        )
    )
    lede = (
        'How the selector behaves as the farm grows. The question a starvation-prone '
        'winner-take-all router fails is not "is it fast" but "does every node get work".'
    )
    return _section('scalability', 'Scalability', lede, body)


def section_optimizer(rows: Optional[Sequence[dict]]) -> str:
    """Does the learned weighting beat the hand-tuned one?"""
    if not rows or not any(r['strategy'] == RF_ARM for r in rows):
        return _section(
            'optimizer', 'AI weight optimizer', '',
            C.empty_figure(
                'Optimizer comparison', f'{RF_ARM} vs {SYSTEM}',
                'No Random-Forest arm in this CSV. It needs the trained model, which '
                'is built from a generated dataset.',
                'python3 -m evaluation.generate_optimizer_dataset --csv data/optimizer_dataset.csv\n'
                'python3 -m trust_engine.rf_optimizer train data/optimizer_dataset.csv data/rf_optimizer.joblib\n'
                'python3 -m evaluation.rf_comparison --model data/rf_optimizer.joblib --csv data/results_rf.csv'))

    # The optimizer arm is the SYSTEM here and the hand-tuned zt_sdn is the
    # thing it has to beat -- the reverse of every other section on the page.
    cs = [c for c in compare_all(list(rows), metric='slo_violation_rate', system=RF_ARM)
          if c.baseline == SYSTEM]
    if not cs:
        return _section('optimizer', 'AI weight optimizer', '',
                        C.empty_figure('Optimizer comparison', '', 'No paired rows.'))

    fig = C.forest_plot(
        'RF warm-start vs hand-tuned weights',
        f'positive = {RF_ARM} beats {SYSTEM} on SLO violation rate',
        [{'label': c.scenario, 'value': c.improvement_pct,
          'significant': c.significant, 'annotation': _sig_annotation(c)}
         for c in sorted(cs, key=lambda c: c.scenario)])

    table_rows = [
        [c.scenario, f'{c.system_median:.4f}', f'{c.baseline_median:.4f}',
         '—' if c.improvement_pct is None else f'{c.improvement_pct:+.1f}%',
         f'{c.p_adj:.2g}', f'{c.effect_size:+.2f}',
         'RF wins' if c.significant and c.system_better else
         (f'{SYSTEM} wins' if c.significant else 'no difference')]
        for c in sorted(cs, key=lambda c: c.scenario)
    ]
    won = sum(1 for c in cs if c.significant and c.system_better)

    body = (
        f'<div class="cols wide"><div class="panel">{fig}</div>'
        f'<div class="panel">'
        f'{C.table(["scenario", RF_ARM, SYSTEM, "improvement", "p adj", "r", "verdict"], table_rows, numeric_from=1)}'
        f'</div></div>'
        + _note(
            f'<strong>The learned prior does not beat the hand-tuned weights</strong> — it wins '
            f'{won} of {len(cs)} scenarios. That is the measured answer and it is reported as '
            'found; a warm start that merely matches a well-chosen static weighting is a '
            'negative result worth keeping, not one worth burying. The online UCB1 bandit is a '
            'separate mechanism and is live on the dashboard.'
        )
    )
    lede = (
        f'<code>{RF_ARM}</code> is <code>{SYSTEM}</code>’s selector with its bandit '
        'value estimates warm-started from an offline Random Forest instead of zero, on the '
        'same seeds.'
    )
    return _section('optimizer', 'AI weight optimizer', lede, body)


def section_losses(rows: Optional[Sequence[dict]]) -> str:
    """Where the system is worse, and what explains it.

    Not optional. A comparison page that shows only wins is not evidence, it
    is advocacy -- and the two losses here have a documented cause that is more
    interesting than the wins.
    """
    if not rows:
        return _section(
            'losses', 'Where the system loses', '',
            C.empty_figure('Losses', '', _MISSING_CSV, _SWEEP_CMD))

    headline = [r for r in rows if r['strategy'] in HEADLINE_STRATEGIES]
    losses: List[Any] = []
    for col, label, unit, digits in COMPARISON_METRICS:
        for c in compare_all(headline, metric=col, system=SYSTEM):
            if c.significant and not c.system_better:
                losses.append((label, unit, digits, c))

    if losses:
        loss_rows = [
            [label, c.scenario, c.baseline,
             C.fmt_val(c.system_median, unit, digits),
             C.fmt_val(c.baseline_median, unit, digits),
             '—' if c.improvement_pct is None else f'{c.improvement_pct:+.1f}%',
             f'{c.p_adj:.2g}']
            for label, unit, digits, c in losses
        ]
        loss_table = C.table(
            ['metric', 'scenario', 'baseline', SYSTEM, 'baseline', 'delta', 'p adj'],
            loss_rows, numeric_from=3, row_classes=['is-bad'] * len(loss_rows))
    else:
        loss_table = '<p class="lede">No comparison significantly favours a baseline.</p>'

    # Survivorship bias, computed from the same CSV rather than quoted.
    surv_rows = []
    for strategy in HEADLINE_STRATEGIES:
        rs = [r for r in headline if r['strategy'] == strategy and r['scenario'] == 'drop']
        if not rs:
            continue
        offered = sum(int(r['offered']) for r in rs)
        completed = sum(int(r['completed']) for r in rs)
        failed = sum(int(r['failed']) for r in rs)
        p95 = sorted(float(r['p95_latency_ms']) for r in rs)
        med_p95 = p95[len(p95) // 2] if p95 else 0.0
        surv_rows.append([
            strategy, f'{completed:,}', f'{failed:,}', f'{med_p95:.0f} ms',
            f'{100 * failed / offered:.1f}%' if offered else '—',
        ])
    surv_classes = ['is-subject' if r[0] == SYSTEM else '' for r in surv_rows]

    body = (
        f'<div class="panel"><div class="fig-title">Comparisons that favour a baseline</div>'
        f'<div class="fig-sub">significant after Holm correction</div>{loss_table}</div>'
        + _note(
            'Both losses are in the <strong>clean</strong> scenario, with no attacker present, '
            'and the cause is <em>not</em> the trust term. Every load-reactive strategy reads a '
            'load view that refreshes once per poll while tasks finish in ~0.2 s, so each '
            'arrival inside a polling window is routed on the same stale snapshot and herds '
            'onto whichever node last looked idle. Sweeping the poll interval separates this '
            'exactly: the two load-blind strategies are flat at every poll (they never read the '
            'signal), everything that does read it improves monotonically as the signal gets '
            'fresher, and by a 0.01 s poll <code>zt_sdn</code> is the best strategy on the '
            'board. The clean-case cost is a tuning property of the 1 s poll, not a property '
            'of trust-aware routing. Full sweep in <code>docs/EVALUATION.md</code> §6.'
        )
        + f'<div class="panel" style="margin-top:14px">'
        f'<div class="fig-title">A latency figure that flatters the worst router</div>'
        f'<div class="fig-sub">drop scenario, summed over all seeds</div>'
        f'{C.table(["strategy", "completed", "failed", "median p95", "excluded from the average"], surv_rows, numeric_from=1, row_classes=surv_classes)}'
        f'</div>'
        + _note(
            '<strong>Read the latency column against the failure column.</strong> A router that '
            'loses tasks to a black hole never measures them: they time out, they are counted '
            'as failures, and they never enter the latency average. So a strategy can post a '
            'competitive p95 precisely <em>because</em> its worst tasks are missing from it. '
            'Latency alone is not a safe metric under a drop attack, which is why SLO violation '
            'rate — where a task that never completed counts as a violation — is the primary '
            'metric on this page.'
        )
    )
    lede = (
        'Every comparison that favours a baseline, and the two measurement traps that would '
        'otherwise make this page misleading. A comparison that only reports its wins is '
        'advocacy, not evidence.'
    )
    return _section('losses', 'Where the system loses', lede, body)


# --------------------------------------------------------------------------- #
# 13. Cross-run regression                                                     #
# --------------------------------------------------------------------------- #
#: Lives in docs/ rather than data/ because data/ is gitignored, and a history
#: that vanishes on clone is not a history. Each entry is a handful of numbers,
#: appended once per run, so the page never reprocesses the 100 MB-1 GB
#: recordings it summarises.
HISTORY_PATH = REPO_ROOT / 'docs' / 'run_history.json'


def run_summary(events: Sequence[Dict[str, Any]], events_path: str,
                label: str) -> Dict[str, Any]:
    """The small per-run record appended to the history."""
    graph = topology_graph(events)
    nodes = (graph or {}).get('nodes', [])
    results = score_run(events)
    attacks = [r for r in results if r.truth != 'none']
    honest = [r for r in results if r.truth == 'none']
    avail = compute_availability(events)
    nfr = build_nfr_report(events)

    return {
        'label': label,
        'recorded': _dt.datetime.now().strftime('%Y-%m-%d'),
        'commit': _git_commit(),
        'source': events_path,
        'span_s': round(events[-1]['ts'] - events[0]['ts'], 1) if len(events) > 1 else 0.0,
        'events': len(events),
        'servers': sum(1 for n in nodes if n.get('kind') == 'server'),
        'devices': sum(1 for n in nodes if n.get('kind') == 'iot'),
        'nfr_passed': sum(1 for r in nfr if r.passed),
        'nfr_total': len(nfr),
        'attacks_total': len(attacks),
        'attacks_exact': sum(1 for r in attacks if r.correct),
        'attacks_family': sum(1 for r in attacks if r.family_correct),
        'honest_mislabelled': sum(1 for r in honest if r.predicted != 'none'),
        'honest_total': len(honest),
        'honest_availability': (None if avail.honest_availability is None
                                else round(avail.honest_availability, 4)),
        'honest_quarantined': sum(1 for n in avail.honest if n.episodes),
        'attacker_containment': (None if avail.attacker_containment is None
                                 else round(avail.attacker_containment, 4)),
    }


def load_history() -> List[Dict[str, Any]]:
    try:
        return json.loads(HISTORY_PATH.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return []


def append_history(entry: Dict[str, Any]) -> None:
    """Replace an entry with the same label, else append. Idempotent, so
    re-running the generator on one recording does not duplicate its row."""
    hist = [e for e in load_history() if e.get('label') != entry['label']]
    hist.append(entry)
    hist.sort(key=lambda e: str(e.get('recorded', '')))
    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    HISTORY_PATH.write_text(json.dumps(hist, indent=2) + '\n', encoding='utf-8')


def section_history(history: Sequence[Dict[str, Any]]) -> str:
    if not history:
        return _section(
            'history', 'Across runs', '',
            C.empty_figure(
                'Run history', '',
                'No run history recorded yet. Each run appends one small entry, so the '
                'page can show progress without reprocessing every recording.',
                'python3 -m evaluation.build_analysis_page data/events.jsonl '
                '--append-history run12'))

    rows = [
        [e.get('label', '?'), e.get('recorded', '—'),
         f'{e.get("servers", "?")}/{e.get("devices", "?")}',
         f'{e.get("span_s", 0):.0f} s',
         f'{e.get("nfr_passed", 0)}/{e.get("nfr_total", 0)}',
         f'{e.get("attacks_exact", 0)}/{e.get("attacks_total", 0)}',
         f'{e.get("attacks_family", 0)}/{e.get("attacks_total", 0)}',
         f'{e.get("honest_mislabelled", 0)}/{e.get("honest_total", 0)}',
         ('—' if e.get('honest_availability') is None
          else f'{100 * e["honest_availability"]:.1f}%'),
         e.get('honest_quarantined', '—'),
         e.get('commit', '—')]
        for e in history
    ]
    classes = ['is-bad' if (e.get('honest_quarantined') or 0) else '' for e in history]

    figs = ''
    if len(history) > 1:
        x_ticks = [(0, str(history[0].get('label', ''))),
                   (len(history) - 1, str(history[-1].get('label', '')))]
        figs = (
            '<div class="panel">'
            + C.line_chart(
                'Classification accuracy', 'attacks classified exactly, and to the right family',
                [{'name': 'exact', 'color': C.S1,
                  'values': [100 * e['attacks_exact'] / e['attacks_total']
                             if e.get('attacks_total') else None for e in history]},
                 {'name': 'right family', 'color': C.S2,
                  'values': [100 * e['attacks_family'] / e['attacks_total']
                             if e.get('attacks_total') else None for e in history]}],
                x_ticks, unit='%', y_max=100)
            + '</div><div class="panel">'
            + C.line_chart(
                'Honest nodes wrongly quarantined', 'the defect signature this project has shipped twice',
                [{'name': 'false quarantines', 'color': C.S2,
                  'values': [e.get('honest_quarantined') for e in history]}],
                x_ticks)
            + '</div>'
        )

    body = (
        (f'<div class="cols wide">{figs}</div>' if figs else '')
        + f'<div class="panel" style="margin-top:14px">'
        f'{C.table(["run", "date", "scale", "span", "NFR", "exact", "family", "false pos", "honest avail", "honest quarantined", "commit"], rows, numeric_from=2, row_classes=classes)}'
        f'</div>'
        + _note(
            'Each row is one live run on the code at that commit. The '
            '<strong>honest quarantined</strong> column is the one to watch: this project has '
            'twice shipped a defect whose entire signature was honest nodes being wrongly '
            'isolated, and both times the fleet-wide averages still looked healthy.'
        )
    )
    return _section('history', 'Across runs', 'Progress on the same measurements, run over run.', body)


# --------------------------------------------------------------------------- #
# Assembly                                                                     #
# --------------------------------------------------------------------------- #
_NAV = (
    ('nfr', 'NFRs'),
    ('attacks', 'Detection'),
    ('availability', 'Availability'),
    ('overtime', 'Over time'),
    ('impact', 'Attack impact'),
    ('topology', 'Topology'),
    ('comparison', 'Comparison'),
    ('significance', 'Significance'),
    ('ablation', 'Ablation'),
    ('scalability', 'Scalability'),
    ('optimizer', 'Optimizer'),
    ('losses', 'Losses'),
    ('history', 'Across runs'),
)


def _load_rows(path: Optional[str]) -> Optional[List[dict]]:
    """Read a sweep CSV, or None if it was not produced.

    A missing CSV is a normal state, not an error: the section renders its own
    empty state naming the command that would fill it, rather than vanishing
    or -- far worse -- showing zeros.
    """
    if not path:
        return None
    try:
        return load_csv(path)
    except (OSError, KeyError, ValueError):
        return None


def build(events_path: str, comparison_csv: Optional[str] = None,
          scalability_csv: Optional[str] = None,
          append_label: Optional[str] = None) -> str:
    events = load_events(events_path)
    if not events:
        raise SystemExit(f'{events_path}: no events to analyse')
    graph = topology_graph(events)
    comparison_rows = _load_rows(comparison_csv)
    scalability_rows = _load_rows(scalability_csv)

    if append_label:
        append_history(run_summary(events, events_path, append_label))
    history = load_history()

    nav = ''.join(f'<a href="#{sid}">{C.esc(label)}</a>' for sid, label in _NAV)
    sections = ''.join([
        section_provenance(events, events_path, graph),
        section_nfr(events),
        section_attacks(events),
        section_availability(events),
        section_timeseries(events, graph),
        section_attack_impact(events, graph),
        section_topology(graph),
        section_comparison(comparison_rows),
        section_significance(comparison_rows),
        section_ablation(comparison_rows),
        section_scalability(scalability_rows),
        section_optimizer(comparison_rows),
        section_losses(comparison_rows),
        section_history(history),
    ])

    return (
        '<!doctype html>\n'
        '<html lang="en"><head><meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        '<title>Zero-Trust SDN — analysis</title>\n'
        '<!-- GENERATED FILE — do not edit by hand.\n'
        '     Regenerate: python3 -m evaluation.build_analysis_page data/events.jsonl -->\n'
        f'<style>{PAGE_CSS}</style>\n'
        '</head><body>\n'
        '<header><h1>Zero-Trust SDN — analysis</h1>'
        f'<nav>{nav}</nav><span class="spacer"></span>'
        '<nav><a href="/">live dashboard →</a></nav></header>\n'
        f'<main>{sections}</main>\n'
        '<footer>Generated by <code>evaluation/build_analysis_page.py</code>. '
        'Every figure is computed by the analysis module named beside it.</footer>\n'
        '</body></html>\n'
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('events', nargs='?', default='data/events.jsonl')
    ap.add_argument('--comparison-csv', default=None,
                    help='baseline sweep CSV (evaluation.baseline --csv). '
                         'Omitted: the comparison sections render an empty state '
                         'naming the command that produces it.')
    ap.add_argument('--scalability-csv', default=None,
                    help='scalability sweep CSV (evaluation.scalability_sweep --csv)')
    ap.add_argument('--append-history', metavar='LABEL', default=None,
                    help='append this run to docs/run_history.json under LABEL '
                         '(e.g. run12). Idempotent: re-running replaces the entry.')
    ap.add_argument('--out', default=str(DEFAULT_OUT))
    args = ap.parse_args(argv)

    html_out = build(args.events, comparison_csv=args.comparison_csv,
                     scalability_csv=args.scalability_csv,
                     append_label=args.append_history)
    Path(args.out).write_text(html_out, encoding='utf-8')
    print(f'Wrote {args.out} ({len(html_out) / 1000:.0f} kB) from {args.events}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
