"""Tally per-server routing share from a live run's event recording.

Reads the controller's JSONL event log (data/events.jsonl by default, written by
controller/event_bus.py when the dashboard is enabled) and counts `route` events
by the server that was chosen. Use it to turn a live Mininet run into the same
per-node share the study reports -- e.g. to produce real before/after numbers for
Figure 11 by running the demo once under `selection: argmax` and once under
`selection: p2c` (see SETUP.md §3b-routing) and tallying each run's events.

    python3 -m evaluation.tally_route_share                 # data/events.jsonl
    python3 -m evaluation.tally_route_share run_argmax.jsonl --json
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from typing import Dict


def tally(path: str) -> Dict[str, int]:
    """Return {node_id: route_count} from the `route` events in a JSONL log."""
    counts: Counter = Counter()
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue                       # tolerate a truncated final line
            if ev.get('type') == 'route' and ev.get('chosen'):
                counts[ev['chosen']] += 1
    return dict(counts)


def main(argv=None) -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('path', nargs='?', default='data/events.jsonl',
                   help='event JSONL log (default: data/events.jsonl)')
    p.add_argument('--json', action='store_true',
                   help='emit the share dict as JSON (paste-ready for the study)')
    args = p.parse_args(argv)

    counts = tally(args.path)
    if not counts:
        print(f"No `route` events found in {args.path} "
              f"(was the dashboard enabled during the run?)")
        return

    total = sum(counts.values())
    nodes = sorted(counts, key=lambda k: (len(k), k))  # srv1..srv9, srv10..
    if args.json:
        print(json.dumps({n: counts[n] for n in nodes}))
        return

    print(f"{args.path}: {total} routing decisions\n")
    print(f"{'node':>8} | {'routes':>7} | share")
    print("-" * 34)
    for n in nodes:
        c = counts[n]
        bar = '#' * round(c / total * 20)
        print(f"{n:>8} | {c:>7} | {c / total * 100:>5.1f}% {bar}")
    starved = [n for n in nodes if counts[n] == 0]
    if starved:
        print(f"\nstarved (0 traffic): {', '.join(starved)}")


if __name__ == '__main__':
    main()
