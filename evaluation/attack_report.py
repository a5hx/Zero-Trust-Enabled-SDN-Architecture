"""Attack-classification scoring for a live run's JSONL recording.
plan_adv.md Phase 2.

Answers the second half of mam's ask: not "was this node quarantined" but
"attack X was detected on node Y at time T, classified as [type]" -- and then
scores those labels against ground truth so the classification claim has a
confusion matrix behind it rather than an assertion.

Replays rather than summarises
------------------------------
The obvious implementation reads the `classification` events the live
controller already publishes and tallies them. This does not do that, and the
reason matters: those events are published on the rising edge only (see
FlowMonitor._publish_classification), so they record label *changes*, not the
label at each moment, and a tally of them would weight a subject that flapped
once exactly like one that held a verdict for the entire run.

Instead this rebuilds the evidence windows from the raw detector output and
re-runs controller/attack_classifier.py over them cycle by cycle, exactly as
the live path would have. Two things fall out of that which a tally cannot
give:

  * a detection latency per attack -- ground-truth onset (`start_s`) to the
    first cycle at which the classifier would have named the attack correctly.

    Read this as an UPPER BOUND, and it is labelled as one in the output.
    `start_s` is measured from the moment an agent launches, while the
    recording's t0 is the moment the controller started -- and the controller
    necessarily comes up before Mininet builds the network, by a few seconds
    (see FlowMonitor's `_ever_seen` comment, which exists because of that same
    gap). So the reported figure includes the build time and overstates the
    detector. Overstating is the safe direction; quietly subtracting an
    estimate of the gap to make the number look better is not.
  * a run verdict that reflects how long each label actually held, instead of
    whichever label happened to be published last.

It also means the offline number cannot silently disagree with the live one:
same classifier, same thresholds, one implementation. This is the discipline
`evaluate_latency_tell` already established between flow_monitor.py and
evaluation/baseline.py.

Cycle reconstruction
--------------------
`anomaly` events carry the signals but are only emitted when something fires,
so on their own they contain no clean cycles -- and without clean cycles the
on-off rule cannot see an off phase (see attack_classifier.Observation). The
missing beat comes from `node_status`, which FlowMonitor publishes once per
poll cycle unconditionally: every `anomaly` seen since the previous
`node_status` belongs to the cycle that `node_status` closes. That gives an
exact per-cycle timeline for every node, clean cycles included, from events
that were already on the bus.

Run:
    python3 -m evaluation.attack_report data/events.jsonl
    python3 -m evaluation.attack_report data/events.jsonl --csv matrix.csv
"""

from __future__ import annotations

import argparse
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Sequence, Tuple

from controller.attack_classifier import (
    ALL_LABELS,
    DEFAULT_WINDOW_CYCLES,
    GROUND_TRUTH_ALIASES,
    NO_ATTACK,
    SIG_AUTH_BAD_RESPONSE,
    SIG_AUTH_IP_PIN,
    SIG_FLOOD,
    Observation,
    classify_client,
    classify_node,
)
from evaluation.nfr_report import load_events

# security/authenticator.py's AUTH_DENY_* tags. Duplicated as plain strings
# for the same reason interval_report.py duplicates PRIO_QUARANTINE_DROP:
# this analysis must run on a box with no controller stack installed. Pinned
# against the real constants by tests/test_attack_report.py.
AUTH_KIND_IP_PIN = 'ip_pin'
AUTH_KIND_BAD_RESPONSE = 'bad_response'


@dataclass
class SubjectResult:
    """What the classifier concluded about one node or device over the run."""

    subject: str
    kind: str                          # 'node' | 'client'
    truth: str
    predicted: str
    #: How many cycles each label held. The run verdict is the modal label,
    #: NOT the final one: an on-off attacker is correctly abstained on while
    #: it is in a good phase, so whichever label happens to be standing when
    #: the recording ends says more about where the run was cut than about
    #: what the system concluded.
    label_cycles: Dict[str, int] = field(default_factory=dict)
    abstained_cycles: int = 0
    total_cycles: int = 0
    #: Ground-truth onset from config (`start_s`), when the recording carries
    #: it, else None.
    onset_s: Optional[float] = None
    #: First cycle time at which the classifier named `truth` correctly.
    first_correct_t: Optional[float] = None
    #: first_correct_t - onset. None when either end is unknown.
    detection_latency_s: Optional[float] = None
    rationale: str = ''

    @property
    def correct(self) -> bool:
        return self.predicted == self.truth


def ground_truth(events: Sequence[Dict[str, Any]]) -> Dict[str, Tuple[str, str]]:
    """subject -> (kind, label), from the first `topology` event.

    The topology event carries an `attack` field on every server and every IoT
    node, surfaced by trust_balancer.topology_graph() for exactly this purpose
    (post-hoc marking, never pre-emptive colouring). Config strings are mapped
    through GROUND_TRUTH_ALIASES so the agent's historical 'drop' becomes the
    standard 'blackhole' the report speaks in.
    """
    truth: Dict[str, Tuple[str, str]] = {}
    for ev in events:
        if ev.get('type') != 'topology':
            continue
        for node in ev.get('graph', {}).get('nodes', []):
            kind = node.get('kind')
            if kind not in ('server', 'iot'):
                continue
            raw = node.get('attack', 'none') or 'none'
            truth[node['id']] = (
                'node' if kind == 'server' else 'client',
                GROUND_TRUTH_ALIASES.get(raw, raw),
            )
        break
    return truth


def onset_times(events: Sequence[Dict[str, Any]]) -> Dict[str, float]:
    """subject -> attack onset in seconds from run start, if recoverable.

    The topology event does not carry `start_s` (it is not something the
    dashboard draws), so this is best-effort: absent, detection latency is
    reported as unknown rather than guessed from the first anomaly, which
    would make every detector look infinitely fast by definition.
    """
    onsets: Dict[str, float] = {}
    for ev in events:
        if ev.get('type') != 'topology':
            continue
        for node in ev.get('graph', {}).get('nodes', []):
            if 'attack_start_s' in node:
                onsets[node['id']] = float(node['attack_start_s'])
        break
    return onsets


def _run_start(events: Sequence[Dict[str, Any]]) -> float:
    for ev in events:
        t = ev.get('ts')
        if isinstance(t, (int, float)):
            return float(t)
    return 0.0


def node_cycles(
    events: Sequence[Dict[str, Any]], node_ids: Sequence[str],
) -> Dict[str, List[Observation]]:
    """Per-node per-cycle observations, clean cycles included.

    See the module docstring: `node_status` is the per-cycle heartbeat that
    turns a sparse stream of `anomaly` events into a dense timeline.
    """
    windows: Dict[str, List[Observation]] = {n: [] for n in node_ids}
    pending: Dict[str, Dict[str, float]] = {}

    for ev in events:
        etype = ev.get('type')
        if etype == 'anomaly':
            node = ev.get('node')
            if node in windows:
                # Recordings made before structured signals existed carry only
                # the prose `reasons`. Treat those as "flagged, cause unknown":
                # an empty dict would read as a CLEAN cycle and quietly turn a
                # detection into a non-detection, which is the one direction of
                # error this report must never make silently.
                signals = ev.get('signals')
                pending[node] = dict(signals) if signals else {'_unstructured': 1.0}
        elif etype == 'node_status':
            t = float(ev.get('ts', 0.0))
            for node in windows:
                windows[node].append(Observation(t, pending.get(node, {})))
            pending.clear()

    return windows


def client_observations(
    events: Sequence[Dict[str, Any]],
) -> Dict[str, List[Observation]]:
    """Per-device observations from `flood` and `auth_denied` events.

    Sparse by nature and that is correct here: unlike a node, which is polled
    on a fixed beat, a device only produces evidence when it does something.
    Neither client-side rule depends on counting clean cycles (see
    classify_client), so there is no heartbeat to reconstruct.

    Keyed by DEVICE ID for auth events and by CLIENT IP for flood events,
    matching what each detector actually observes -- a spoofer is only
    meaningful under the identity it tried to steal, while a flood is only
    observable as a source address. `subject_aliases` reconciles the two.
    """
    windows: Dict[str, List[Observation]] = {}

    def add(subject: str, t: float, signals: Dict[str, float]) -> None:
        windows.setdefault(subject, []).append(Observation(t, signals))

    for ev in events:
        etype = ev.get('type')
        t = float(ev.get('ts', 0.0))
        if etype == 'flood':
            client = ev.get('client_ip')
            if client:
                ratio = ev.get('ratio')
                add(client, t, {SIG_FLOOD: float(ratio) if ratio else 0.0})
        elif etype == 'auth_denied':
            device = ev.get('device_id')
            if not device:
                continue
            kind = ev.get('kind')
            if kind == AUTH_KIND_IP_PIN:
                add(device, t, {SIG_AUTH_IP_PIN: 1.0})
            elif kind == AUTH_KIND_BAD_RESPONSE:
                add(device, t, {SIG_AUTH_BAD_RESPONSE: 1.0})
            else:
                add(device, t, {})

    return windows


def subject_aliases(events: Sequence[Dict[str, Any]]) -> Dict[str, str]:
    """IP -> device id, from the topology event's iot nodes.

    Flood evidence arrives keyed by source IP while ground truth is keyed by
    device id; without this the flooding device would score as an unknown
    subject and its ground-truth row would come out as a silent miss.
    """
    alias: Dict[str, str] = {}
    for ev in events:
        if ev.get('type') != 'topology':
            continue
        for node in ev.get('graph', {}).get('nodes', []):
            if node.get('kind') == 'iot' and node.get('ip'):
                alias[node['ip']] = node['id']
        break
    return alias


def _replay(
    window: Sequence[Observation],
    truth: str,
    classify,
    window_cycles: int,
) -> Tuple[Dict[str, int], int, Optional[float], str]:
    """Re-run the classifier cycle by cycle over a bounded sliding window.

    Returns (label_cycles, abstained_cycles, first_correct_t, last_rationale).
    Mirrors the live path's bounded deque exactly rather than classifying the
    whole run at once, so the offline verdict is reachable online.
    """
    rolling: Deque[Observation] = deque(maxlen=window_cycles)
    label_cycles: Counter = Counter()
    abstained = 0
    first_correct_t: Optional[float] = None
    last_rationale = ''

    for obs in window:
        rolling.append(obs)
        # now=None: the recording is finished, so the staleness clock is not
        # meaningful here. Freshness is already guaranteed structurally -- the
        # newest observation in `rolling` IS the cycle being replayed.
        result = classify(list(rolling), None)
        if result is None:
            abstained += 1
            continue
        label_cycles[result.attack_type] += 1
        last_rationale = result.rationale
        if result.attack_type == truth and first_correct_t is None:
            first_correct_t = obs.t

    return dict(label_cycles), abstained, first_correct_t, last_rationale


def score_run(
    events: Sequence[Dict[str, Any]],
    window_cycles: int = DEFAULT_WINDOW_CYCLES,
) -> List[SubjectResult]:
    """Classify every subject in the recording and score against ground truth."""
    truth = ground_truth(events)
    onsets = onset_times(events)
    alias = subject_aliases(events)
    t0 = _run_start(events)

    node_ids = [s for s, (kind, _) in truth.items() if kind == 'node']
    windows = node_cycles(events, node_ids)
    client_windows = client_observations(events)

    # Fold IP-keyed flood evidence onto the device id ground truth is keyed by.
    folded: Dict[str, List[Observation]] = {}
    for subject, obs in client_windows.items():
        folded.setdefault(alias.get(subject, subject), []).extend(obs)
    for obs in folded.values():
        obs.sort(key=lambda o: o.t)

    results: List[SubjectResult] = []

    for subject, (kind, subject_truth) in sorted(truth.items()):
        if kind == 'node':
            window = windows.get(subject, [])
            classify = lambda w, now: classify_node(w, now=now)
        else:
            window = folded.get(subject, [])
            classify = lambda w, now: classify_client(w, now=now)

        label_cycles, abstained, first_correct_t, rationale = _replay(
            window, subject_truth, classify, window_cycles,
        )

        predicted = (
            max(label_cycles.items(), key=lambda kv: kv[1])[0]
            if label_cycles else NO_ATTACK
        )

        onset = onsets.get(subject)
        latency = (
            (first_correct_t - t0) - onset
            if first_correct_t is not None and onset is not None
            else None
        )

        results.append(SubjectResult(
            subject=subject,
            kind=kind,
            truth=subject_truth,
            predicted=predicted,
            label_cycles=label_cycles,
            abstained_cycles=abstained,
            total_cycles=len(window),
            onset_s=onset,
            first_correct_t=(
                first_correct_t - t0 if first_correct_t is not None else None
            ),
            detection_latency_s=latency,
            rationale=rationale,
        ))

    return results


def confusion_matrix(
    results: Sequence[SubjectResult],
) -> Dict[str, Dict[str, int]]:
    """truth -> predicted -> count, over the labels actually present.

    Restricted to labels that appear in this run rather than always printing
    all nine: a matrix that is mostly zeros because the run did not configure
    those attacks reads as poor performance at a glance when it is nothing of
    the sort.
    """
    present = [
        lab for lab in ALL_LABELS
        if any(r.truth == lab or r.predicted == lab for r in results)
    ]
    matrix = {t: {p: 0 for p in present} for t in present}
    for r in results:
        matrix.setdefault(r.truth, {p: 0 for p in present})
        matrix[r.truth][r.predicted] = matrix[r.truth].get(r.predicted, 0) + 1
    return matrix


def per_class_metrics(
    results: Sequence[SubjectResult],
) -> Dict[str, Dict[str, float]]:
    """Precision / recall / F1 / support per label.

    NO_ATTACK is scored like any other class on purpose. It is the class that
    catches false accusations of honest nodes, which for this project is the
    failure mode that actually matters -- see
    memory/live-run-cascading-quarantine, where every detector was right and
    the system still wrongly condemned five honest servers.
    """
    labels = sorted({r.truth for r in results} | {r.predicted for r in results})
    out: Dict[str, Dict[str, float]] = {}
    for label in labels:
        tp = sum(1 for r in results if r.truth == label and r.predicted == label)
        fp = sum(1 for r in results if r.truth != label and r.predicted == label)
        fn = sum(1 for r in results if r.truth == label and r.predicted != label)
        support = sum(1 for r in results if r.truth == label)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) else 0.0
        )
        out[label] = {
            'precision': precision, 'recall': recall, 'f1': f1,
            'support': float(support),
        }
    return out


def format_report(
    results: Sequence[SubjectResult],
    window_cycles: int = DEFAULT_WINDOW_CYCLES,
) -> str:
    lines: List[str] = []
    add = lines.append

    add('=' * 78)
    add('ATTACK CLASSIFICATION REPORT'.center(78))
    add('=' * 78)
    add(f'Subjects scored: {len(results)}   '
        f'replay window: {window_cycles} cycles')
    add('')

    add('-' * 78)
    add('PER-SUBJECT')
    add('-' * 78)
    add(f'{"subject":<10} {"truth":<16} {"predicted":<16} {"hit":<4} '
        f'{"cycles":<8} {"detect":<9}')
    for r in sorted(results, key=lambda x: (x.truth == NO_ATTACK, x.subject)):
        latency = (
            f'{r.detection_latency_s:+.1f}s' if r.detection_latency_s is not None
            else ('-' if r.truth == NO_ATTACK else 'n/a')
        )
        add(f'{r.subject:<10} {r.truth:<16} {r.predicted:<16} '
            f'{"OK" if r.correct else "MISS":<4} '
            f'{r.total_cycles:<8} {latency:<9}')
    add('')

    add('-' * 78)
    add('CONFUSION MATRIX  (rows = ground truth, cols = predicted)')
    add('-' * 78)
    matrix = confusion_matrix(results)
    if matrix:
        labels = list(matrix)
        width = max(len(lab) for lab in labels) + 2
        header = ' ' * width + ''.join(f'{lab[:9]:>10}' for lab in labels)
        add(header)
        for t in labels:
            row = ''.join(f'{matrix[t].get(p, 0):>10}' for p in labels)
            add(f'{t:<{width}}{row}')
    add('')

    add('-' * 78)
    add('PER-CLASS')
    add('-' * 78)
    add(f'{"label":<18} {"precision":>10} {"recall":>10} {"f1":>10} {"support":>9}')
    metrics = per_class_metrics(results)
    for label, m in metrics.items():
        add(f'{label:<18} {m["precision"]:>10.3f} {m["recall"]:>10.3f} '
            f'{m["f1"]:>10.3f} {int(m["support"]):>9}')
    add('')

    correct = sum(1 for r in results if r.correct)
    total = len(results)
    add(f'Overall accuracy: {correct}/{total} = '
        f'{(correct / total if total else 0.0):.1%}')

    attacks = [r for r in results if r.truth != NO_ATTACK]
    if attacks:
        detected = [r for r in attacks if r.predicted != NO_ATTACK]
        add(f'Attacks detected at all (any label): {len(detected)}/{len(attacks)}')
        add(f'Attacks classified correctly:        '
            f'{sum(1 for r in attacks if r.correct)}/{len(attacks)}')
        latencies = [
            r.detection_latency_s for r in attacks
            if r.detection_latency_s is not None
        ]
        if latencies:
            add(f'Detection latency: mean {sum(latencies) / len(latencies):.1f}s, '
                f'max {max(latencies):.1f}s   [UPPER BOUND -- measured from '
                f'controller start, so it includes the')
            add('                   Mininet build time before agents launch; '
                'see this module\'s docstring.]')
        else:
            add('Detection latency: not computable -- the recording carries no '
                'attack_start_s ground truth.')

    honest = [r for r in results if r.truth == NO_ATTACK]
    if honest:
        accused = [r for r in honest if r.predicted != NO_ATTACK]
        add(f'Honest subjects wrongly labelled:    {len(accused)}/{len(honest)}'
            + (f'  ({", ".join(f"{r.subject}->{r.predicted}" for r in accused)})'
               if accused else ''))
    add('=' * 78)
    return '\n'.join(lines)


def write_csv(results: Sequence[SubjectResult], path: str) -> None:
    import csv

    with open(path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow([
            'subject', 'kind', 'truth', 'predicted', 'correct', 'total_cycles',
            'abstained_cycles', 'onset_s', 'first_correct_t',
            'detection_latency_s', 'rationale',
        ])
        for r in results:
            w.writerow([
                r.subject, r.kind, r.truth, r.predicted, int(r.correct),
                r.total_cycles, r.abstained_cycles,
                '' if r.onset_s is None else f'{r.onset_s:.2f}',
                '' if r.first_correct_t is None else f'{r.first_correct_t:.2f}',
                '' if r.detection_latency_s is None
                else f'{r.detection_latency_s:.2f}',
                r.rationale,
            ])


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description='Score attack classification against ground truth.',
    )
    parser.add_argument('events', help='path to a JSONL event recording')
    parser.add_argument(
        '--window-cycles', type=int, default=DEFAULT_WINDOW_CYCLES,
        help='sliding evidence window, in detection cycles '
             f'(default {DEFAULT_WINDOW_CYCLES})',
    )
    parser.add_argument('--csv', help='also write per-subject rows to this path')
    args = parser.parse_args(argv)

    events = load_events(args.events)
    if not events:
        print(f'No events found in {args.events}')
        return 1

    truth = ground_truth(events)
    if not truth:
        print(
            f'No `topology` event in {args.events} -- ground truth is what this '
            f'report scores against, so there is nothing to score. Re-run with a '
            f'recording that includes the run start.'
        )
        return 1

    results = score_run(events, window_cycles=args.window_cycles)
    print(format_report(results, window_cycles=args.window_cycles))

    if args.csv:
        write_csv(results, args.csv)
        print(f'\nPer-subject rows written to {args.csv}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
