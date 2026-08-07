"""Service availability -- this project's honest stand-in for "network
lifetime". plan_adv.md Phase 4.

The advisor's metric list asked for network lifetime, which in the WSN papers
it comes from means *time until the first battery-dead node* (then 50%, then
last). There is no energy model anywhere in this repo, and inventing one would
be worse than useless here: these are mains-powered edge servers, so a battery
curve would be a fabricated number dressed as a measurement. plan_adv.md §4
therefore reframed it as **service availability**, which asks the same
underlying question -- *how long does the network keep being able to do its
job, and when does it stop?* -- against something this system actually has.

The WSN analogies map cleanly, with isolation standing in for death:

    time to first node death      -> time to first isolation
    time to 50% nodes dead        -> time to fleet below a serving quorum
    network lifetime              -> time the fleet stayed above that quorum
    per-node lifetime             -> per-node eligible fraction of the run

No new instrumentation. Everything here is derived from the `quarantine` and
`recovered` events the controller already publishes, plus the `topology`
event's ground truth (added in Phase 2).

THE RULE THIS MODULE EXISTS TO ENFORCE
--------------------------------------
Quarantine downtime means **opposite things** for an attacker and for an honest
node:

  * an isolated attacker is the system WORKING -- that is the entire point of
    zero-trust enforcement, and counting it as lost availability would penalise
    the defence for defending;
  * an isolated honest node is the system's real COST -- and this project has
    twice shipped a defect whose whole signature was honest nodes being
    wrongly quarantined (memory/live-run-cascading-quarantine,
    memory/quarantine-absorbing-state).

So a single fleet-wide "availability: 94%" would be a meaningless average over
two quantities that should move in opposite directions. Every figure below is
reported split by ground truth, and the headline availability number counts
HONEST nodes only. `format_report` refuses to print a combined one.

Run:
    python3 -m evaluation.availability_report data/events.jsonl
    python3 -m evaluation.availability_report data/events.jsonl --csv avail.csv
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from controller.attack_classifier import NO_ATTACK
from evaluation.attack_report import ground_truth, onset_times
from evaluation.nfr_report import load_events

#: Fraction of the fleet that must remain eligible for the network to count as
#: able to do its job. The WSN "50% nodes dead" convention, kept at 0.5 for the
#: same reason: it is the conventional midpoint, not a tuned figure.
DEFAULT_SERVING_QUORUM = 0.5

#: A recording whose last seconds show most of the fleet quarantining is almost
#: certainly capturing teardown, not a collapse: the harness kills the agents
#: while the controller is still polling, so the final sweeps score
#: live-until-a-moment-ago nodes as unreachable. northbound_api.py's
#: /monitor/pause exists to prevent exactly that. Detected and WARNED about
#: rather than silently trimmed -- a knob that quietly discards inconvenient
#: tail data is a knob that will eventually be used to flatter a result.
TEARDOWN_WINDOW_S = 5.0
TEARDOWN_FRACTION = 0.5


@dataclass
class NodeAvailability:
    """One node's uptime record over the run."""

    node: str
    truth: str
    run_s: float

    quarantined_s: float = 0.0
    episodes: int = 0
    #: Times this node left quarantine. Tracked separately from `episodes`
    #: because "quarantine is a one-way door" was a real defect here
    #: (memory/quarantine-absorbing-state): a fleet where nodes enter isolation
    #: and never leave looks acceptable on an availability average while being
    #: broken in precisely the way that mattered. episodes without recoveries
    #: is the signature.
    recoveries: int = 0
    longest_quarantine_s: float = 0.0
    #: Seconds from run start to this node's first isolation. None if never.
    time_to_first_isolation_s: Optional[float] = None
    #: True if the node was still quarantined when the recording ended.
    isolated_at_end: bool = False

    @property
    def eligible_s(self) -> float:
        return max(0.0, self.run_s - self.quarantined_s)

    @property
    def eligible_fraction(self) -> float:
        return self.eligible_s / self.run_s if self.run_s > 0 else 1.0

    @property
    def is_attacker(self) -> bool:
        return self.truth != NO_ATTACK

    @property
    def mean_episode_s(self) -> float:
        return self.quarantined_s / self.episodes if self.episodes else 0.0

    @property
    def never_recovered(self) -> bool:
        """Entered quarantine and never came back out."""
        return self.episodes > 0 and self.recoveries == 0


@dataclass
class AvailabilityReport:
    run_s: float
    nodes: List[NodeAvailability] = field(default_factory=list)

    #: Seconds from run start until ANY node was first isolated -- the direct
    #: analogue of the WSN "time to first node death".
    time_to_first_isolation_s: Optional[float] = None
    #: ...and the same restricted to honest nodes, which is the one that
    #: represents damage rather than enforcement.
    time_to_first_honest_isolation_s: Optional[float] = None

    #: Time-weighted mean and worst-case count of nodes eligible to serve.
    mean_serving_nodes: float = 0.0
    min_serving_nodes: int = 0
    #: Seconds with NO eligible node at all -- total outage, when every request
    #: is denied.
    total_outage_s: float = 0.0

    #: Seconds the fleet held at or above the serving quorum, and the moment it
    #: first fell below. The "network lifetime" pair.
    above_quorum_s: float = 0.0
    time_to_below_quorum_s: Optional[float] = None
    quorum: float = DEFAULT_SERVING_QUORUM

    #: Per-attacker seconds from configured onset to first isolation.
    containment_latency_s: Dict[str, float] = field(default_factory=dict)

    teardown_suspected: bool = False

    @property
    def honest(self) -> List[NodeAvailability]:
        return [n for n in self.nodes if not n.is_attacker]

    @property
    def attackers(self) -> List[NodeAvailability]:
        return [n for n in self.nodes if n.is_attacker]

    @property
    def honest_availability(self) -> Optional[float]:
        """THE availability figure. Honest nodes only -- see the module
        docstring for why a combined number would be meaningless."""
        honest = self.honest
        if not honest:
            return None
        return sum(n.eligible_fraction for n in honest) / len(honest)

    @property
    def attacker_containment(self) -> Optional[float]:
        """Mean fraction of the run each attacker spent isolated. High is good:
        this is enforcement effectiveness, not lost service."""
        attackers = self.attackers
        if not attackers:
            return None
        return sum(1.0 - n.eligible_fraction for n in attackers) / len(attackers)


def _run_window(events: Sequence[Dict[str, Any]]) -> Tuple[float, float]:
    times = [
        float(e['t']) for e in events
        if isinstance(e.get('t'), (int, float))
    ]
    return (min(times), max(times)) if times else (0.0, 0.0)


def compute(
    events: Sequence[Dict[str, Any]],
    quorum: float = DEFAULT_SERVING_QUORUM,
) -> AvailabilityReport:
    """Build the availability report from a JSONL recording's events."""
    truth = ground_truth(events)
    onsets = onset_times(events)
    roster = [s for s, (kind, _) in sorted(truth.items()) if kind == 'node']

    t0, t_end = _run_window(events)
    run_s = max(0.0, t_end - t0)

    report = AvailabilityReport(run_s=run_s, quorum=quorum)
    rows = {
        node: NodeAvailability(node=node, truth=truth[node][1], run_s=run_s)
        for node in roster
    }
    if not roster or run_s <= 0:
        report.nodes = list(rows.values())
        return report

    quarantined: set = set()
    quarantine_started: Dict[str, float] = {}
    prev_t = t0
    n_total = len(roster)
    quorum_nodes = quorum * n_total
    weighted_serving = 0.0
    min_serving = n_total
    last_quarantine_events: List[Tuple[float, str]] = []

    def close_segment(now: float) -> None:
        """Attribute [prev_t, now) to whoever was up or down across it."""
        nonlocal weighted_serving, min_serving
        dur = now - prev_t
        if dur <= 0:
            return
        for node in roster:
            if node in quarantined:
                rows[node].quarantined_s += dur
        serving = n_total - len(quarantined & set(roster))
        weighted_serving += serving * dur
        min_serving = min(min_serving, serving)
        if serving == 0:
            report.total_outage_s += dur
        if serving >= quorum_nodes:
            report.above_quorum_s += dur
        elif report.time_to_below_quorum_s is None:
            report.time_to_below_quorum_s = prev_t - t0

    for ev in events:
        etype = ev.get('event')
        if etype not in ('quarantine', 'recovered'):
            continue
        node = ev.get('node')
        if node not in rows:
            continue
        t = float(ev.get('t', t0))

        close_segment(t)
        prev_t = t

        if etype == 'quarantine':
            if node in quarantined:
                continue                      # already down; not a new episode
            quarantined.add(node)
            quarantine_started[node] = t
            row = rows[node]
            row.episodes += 1
            if row.time_to_first_isolation_s is None:
                row.time_to_first_isolation_s = t - t0
            if report.time_to_first_isolation_s is None:
                report.time_to_first_isolation_s = t - t0
            if (not row.is_attacker
                    and report.time_to_first_honest_isolation_s is None):
                report.time_to_first_honest_isolation_s = t - t0
            last_quarantine_events.append((t, node))
        else:
            if node not in quarantined:
                continue                      # already up; nothing to close
            quarantined.discard(node)
            started = quarantine_started.pop(node, t)
            rows[node].recoveries += 1
            rows[node].longest_quarantine_s = max(
                rows[node].longest_quarantine_s, t - started,
            )

    close_segment(t_end)

    for node in quarantined:
        started = quarantine_started.get(node, t_end)
        rows[node].longest_quarantine_s = max(
            rows[node].longest_quarantine_s, t_end - started,
        )
        rows[node].isolated_at_end = True

    report.nodes = [rows[node] for node in roster]
    report.mean_serving_nodes = weighted_serving / run_s if run_s else 0.0
    report.min_serving_nodes = min_serving

    for row in report.nodes:
        onset = onsets.get(row.node)
        if (row.is_attacker and onset is not None
                and row.time_to_first_isolation_s is not None):
            report.containment_latency_s[row.node] = (
                row.time_to_first_isolation_s - onset
            )

    # Teardown detection -- see TEARDOWN_WINDOW_S.
    late = [n for t, n in last_quarantine_events if t >= t_end - TEARDOWN_WINDOW_S]
    report.teardown_suspected = len(set(late)) >= TEARDOWN_FRACTION * n_total

    return report


def format_report(report: AvailabilityReport) -> str:
    lines: List[str] = []
    add = lines.append

    add('=' * 78)
    add('SERVICE AVAILABILITY REPORT'.center(78))
    add('=' * 78)
    add(f'Run length: {report.run_s:.1f}s   nodes: {len(report.nodes)}   '
        f'serving quorum: {report.quorum:.0%}')
    add('')

    if report.teardown_suspected:
        add('!! WARNING: most of the fleet was quarantined in the final '
            f'{TEARDOWN_WINDOW_S:.0f}s of this')
        add('   recording. That is the signature of agents being killed at '
            'teardown while the')
        add('   controller was still polling, NOT of a collapse. Use '
            'POST /monitor/pause before')
        add('   stopping the agents. Figures below include that tail as real '
            'downtime.')
        add('')

    add('-' * 78)
    add('PER-NODE  (eligible = able to receive traffic)')
    add('-' * 78)
    add(f'{"node":<8} {"truth":<16} {"eligible":>9} {"down s":>8} '
        f'{"episodes":>9} {"longest":>8} {"1st iso":>8}')
    for row in sorted(report.nodes, key=lambda r: (r.is_attacker, r.node)):
        first = (f'{row.time_to_first_isolation_s:.1f}'
                 if row.time_to_first_isolation_s is not None else '-')
        add(f'{row.node:<8} {row.truth:<16} {row.eligible_fraction:>8.1%} '
            f'{row.quarantined_s:>8.1f} {row.episodes:>9} '
            f'{row.longest_quarantine_s:>8.1f} {first:>8}')
    add('')

    add('-' * 78)
    add('AVAILABILITY  (honest nodes) -- service the fleet was able to give')
    add('-' * 78)
    honest_avail = report.honest_availability
    if honest_avail is None:
        add('No honest nodes in this run.')
    else:
        add(f'Honest-node availability:        {honest_avail:.2%}')
        never = sum(1 for n in report.honest if n.episodes == 0)
        add(f'Honest nodes never quarantined:  {never}/{len(report.honest)}')
        stuck = [n.node for n in report.honest if n.isolated_at_end]
        add(f'Honest nodes isolated at end:    {len(stuck)}'
            + (f'  ({", ".join(stuck)})' if stuck else ''))
        if report.time_to_first_honest_isolation_s is not None:
            add('Time to first HONEST isolation:  '
                f'{report.time_to_first_honest_isolation_s:.1f}s '
                '(this is damage, not enforcement)')
        else:
            add('Time to first HONEST isolation:  never -- no honest node was '
                'ever isolated')

        # The absorbing-state check. An honest node that entered quarantine and
        # never left is the exact shape of the defect in
        # memory/quarantine-absorbing-state, and it is invisible in an
        # availability average.
        stranded = [n.node for n in report.honest if n.never_recovered]
        if stranded:
            add(f'!! Honest nodes that NEVER recovered: {len(stranded)} '
                f'({", ".join(stranded)})')
            add('   Quarantine should be recoverable -- probation exists so a '
                'stale trust verdict')
            add('   can be re-tested. Check probation is running before '
                'reading the figure above.')
        else:
            add('Honest nodes stuck in quarantine: none (every isolated honest '
                'node recovered)')
    add('')

    add('-' * 78)
    add('CONTAINMENT  (attackers) -- downtime here is the system working')
    add('-' * 78)
    containment = report.attacker_containment
    if containment is None:
        add('No attackers configured in this run.')
    else:
        add(f'Mean attacker time isolated:     {containment:.2%}')
        loose = [n.node for n in report.attackers if n.episodes == 0]
        add(f'Attackers never isolated:        {len(loose)}'
            + (f'  ({", ".join(loose)})' if loose else ''))
        for node, latency in sorted(report.containment_latency_s.items()):
            add(f'  {node}: contained {latency:+.1f}s after onset')
        if report.containment_latency_s:
            add('  (upper bound -- measured from controller start, which '
                'precedes agent launch)')
    add('')

    add('-' * 78)
    add('FLEET LIFETIME  (the "network lifetime" analogue)')
    add('-' * 78)
    add(f'Mean nodes serving:              {report.mean_serving_nodes:.2f}'
        f' / {len(report.nodes)}')
    add(f'Worst-case nodes serving:        {report.min_serving_nodes}'
        f' / {len(report.nodes)}')
    first_iso = (f'{report.time_to_first_isolation_s:.1f}s'
                 if report.time_to_first_isolation_s is not None else 'never')
    add(f'Time to first isolation (any):   {first_iso}')
    if report.time_to_below_quorum_s is None:
        add(f'Fleet stayed at/above {report.quorum:.0%} quorum for the whole run')
    else:
        add(f'Fell below {report.quorum:.0%} quorum at:        '
            f'{report.time_to_below_quorum_s:.1f}s')
    add(f'Time at/above quorum:            {report.above_quorum_s:.1f}s '
        f'({report.above_quorum_s / report.run_s:.1%})'
        if report.run_s else '')
    if report.total_outage_s > 0:
        add(f'!! TOTAL OUTAGE (0 nodes serving): {report.total_outage_s:.1f}s '
            f'({report.total_outage_s / report.run_s:.1%}) -- every request '
            f'denied')
    else:
        add('Total outage (0 nodes serving):  none')
    add('=' * 78)
    return '\n'.join(lines)


def write_csv(report: AvailabilityReport, path: str) -> None:
    import csv

    with open(path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow([
            'node', 'truth', 'is_attacker', 'eligible_fraction',
            'quarantined_s', 'episodes', 'longest_quarantine_s',
            'time_to_first_isolation_s', 'isolated_at_end',
        ])
        for row in report.nodes:
            w.writerow([
                row.node, row.truth, int(row.is_attacker),
                round(row.eligible_fraction, 5), round(row.quarantined_s, 3),
                row.episodes, round(row.longest_quarantine_s, 3),
                '' if row.time_to_first_isolation_s is None
                else round(row.time_to_first_isolation_s, 3),
                int(row.isolated_at_end),
            ])


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description='Service-availability report for a JSONL event recording.',
    )
    parser.add_argument('events', help='path to a JSONL event recording')
    parser.add_argument(
        '--quorum', type=float, default=DEFAULT_SERVING_QUORUM,
        help='fraction of the fleet that must stay eligible for the network to '
             f'count as serving (default {DEFAULT_SERVING_QUORUM})',
    )
    parser.add_argument('--csv', help='also write per-node rows to this path')
    args = parser.parse_args(argv)

    events = load_events(args.events)
    if not events:
        print(f'No events found in {args.events}')
        return 1
    if not ground_truth(events):
        print(
            f'No `topology` event in {args.events}. Availability is reported '
            f'split by attacker/honest ground truth, which that event carries, '
            f'so there is nothing meaningful to report without it.'
        )
        return 1

    report = compute(events, quorum=args.quorum)
    print(format_report(report))
    if args.csv:
        write_csv(report, args.csv)
        print(f'\nPer-node rows written to {args.csv}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
