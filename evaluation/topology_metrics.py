"""Structural per-node metrics: node degree and distance to the sink.

Two of the advisor's metrics are properties of the *graph*, not of the traffic:
node degree and distance to the sink. They do not vary over time, so they are
not interval metrics and do not belong in evaluation/interval_report.py -- a
flat line is not a chart. They are computed here and rendered as a table.

WHAT "SINK" MEANS HERE
----------------------
In the WSN papers this metric list comes from, the sink is the base station --
the single point every reading eventually converges on. This topology's
equivalent is the **core switch `s0`**: it is the only node every VIP task
transits, since a device on edge switch `s{k}` reaches a server on `s{i}`
through `iot -> s{k} -> s0 -> s{i} -> srv`. That is a structural fact about
the topology, not an analogy that had to be stretched to fit.

WHAT THE DELAY NUMBER IS, AND IS NOT
------------------------------------
`delay_ms` is the sum of the **configured** link delays along the path -- what
`simulation/topology.py` handed to `tc`, reported to the controller over
POST /topology/links and merged into the topology graph. It is a measured
input, not a measured output: it is not an observed RTT and does not include
queueing, serialisation, or any server-side processing time. The end-to-end
delay the system actually experiences is a different metric and is already
reported separately (`interval_report.mean_task_latency_ms`).

A link whose `delay_ms` was never reported makes the whole path's delay
**None**, never 0.0. "Not measured" and "zero delay" are different claims, and
a run where the harness never reported its link table must show a dash rather
than a plausible-looking zero. This is the same rule
evaluation/availability_report.py applies to absent groups.

Run:
    python3 -m evaluation.topology_metrics data/events.jsonl
"""

from __future__ import annotations

import argparse
from typing import Any, Dict, List, Optional, Sequence, Tuple

from evaluation.nfr_report import load_events

#: The core switch. See "WHAT SINK MEANS HERE" above.
DEFAULT_SINK = 's0'


def topology_graph(events: Sequence[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The best available topology graph in a recording.

    Prefers the **last** `topology_links` event over the first `topology` one.
    Both carry the same shape; only the former has the link parameters the
    harness actually applied, and it is published later precisely because the
    Mininet network does not exist when `topology` is emitted.
    """
    enriched = None
    plain = None
    for e in events:
        if e.get('type') == 'topology_links' and e.get('graph'):
            enriched = e['graph']
        elif plain is None and e.get('type') == 'topology' and e.get('graph'):
            plain = e['graph']
    return enriched or plain


def node_degree(graph: Dict[str, Any]) -> Dict[str, int]:
    """Number of links incident on each node.

    Every node in `graph['nodes']` appears, including any with no links at all
    -- an isolated node has degree 0, and dropping it from the result would
    hide exactly the case worth seeing. Self-loops and links naming a node that
    is not in `nodes` are ignored.
    """
    degree = {n['id']: 0 for n in graph.get('nodes', []) if 'id' in n}
    for lk in graph.get('links', []):
        a, b = lk.get('a'), lk.get('b')
        # Both endpoints must be known nodes, matching _adjacency()'s rule
        # exactly. Counting a half-known link here but refusing to traverse it
        # there would let degree and distance disagree about what the graph is.
        if a == b or a not in degree or b not in degree:
            continue
        degree[a] += 1
        degree[b] += 1
    return degree


def _adjacency(
    graph: Dict[str, Any],
) -> Dict[str, List[Tuple[str, Optional[float]]]]:
    """node -> [(neighbour, delay_ms or None), ...]."""
    adj: Dict[str, List[Tuple[str, Optional[float]]]] = {
        n['id']: [] for n in graph.get('nodes', []) if 'id' in n
    }
    for lk in graph.get('links', []):
        a, b = lk.get('a'), lk.get('b')
        if a == b or a not in adj or b not in adj:
            continue
        d = lk.get('delay_ms')
        d = float(d) if isinstance(d, (int, float)) and not isinstance(d, bool) else None
        adj[a].append((b, d))
        adj[b].append((a, d))
    return adj


def _better(cand: Optional[float], best: Optional[float]) -> bool:
    """Is `cand` a better path delay than `best`? A known delay beats an
    unknown one, and among known delays the smaller wins."""
    if cand is None:
        return False
    if best is None:
        return True
    return cand < best


def distance_to_sink(
    graph: Dict[str, Any],
    sink: str = DEFAULT_SINK,
) -> Dict[str, Dict[str, Optional[float]]]:
    """Shortest path from every node to the sink, as `{hops, delay_ms}`.

    Hops is the primary metric and is a plain BFS distance. Where several
    equal-hop paths exist, the one with the **lowest total configured delay**
    is reported, with an unknown delay counting as worse than any known one --
    so the tie-break is a stated rule rather than whichever edge the iteration
    happened to reach first. In the topology this project builds the question
    never arises (the graph is a tree), but a metric whose value depends on
    dict ordering is a metric that will eventually be wrong quietly.

    `hops` is None for a node not connected to the sink, and for the sink's own
    absence from the graph. `delay_ms` is None whenever any link on the chosen
    path never reported one -- see the module docstring.
    """
    adj = _adjacency(graph)
    out: Dict[str, Dict[str, Optional[float]]] = {
        nid: {'hops': None, 'delay_ms': None} for nid in adj
    }
    if sink not in adj:
        return out

    hops: Dict[str, int] = {sink: 0}
    delay: Dict[str, Optional[float]] = {sink: 0.0}
    frontier = [sink]
    level = 0

    while frontier:
        level += 1
        nxt: Dict[str, Optional[float]] = {}
        for u in frontier:
            for v, d in adj[u]:
                if v in hops:
                    continue
                base = delay[u]
                cand = None if (base is None or d is None) else base + d
                if v not in nxt or _better(cand, nxt[v]):
                    nxt[v] = cand
        for v, cand in nxt.items():
            hops[v] = level
            delay[v] = cand
        frontier = list(nxt)

    for nid in out:
        if nid in hops:
            out[nid] = {'hops': hops[nid], 'delay_ms': delay[nid]}
    return out


#: Sort order for the report: the routing targets first, then the fabric they
#: sit on, then the traffic sources. Matches how the dashboard table reads.
_KIND_ORDER = {'server': 0, 'core_switch': 1, 'edge_switch': 2, 'iot': 3}


def _natural_key(node_id: str) -> Tuple[str, int, str]:
    """'srv10' sorts after 'srv9', not between 'srv1' and 'srv2'."""
    head = node_id.rstrip('0123456789')
    tail = node_id[len(head):]
    return (head, int(tail) if tail else -1, node_id)


def format_report(graph: Dict[str, Any], sink: str = DEFAULT_SINK) -> str:
    """Human-readable table of the structural metrics."""
    degree = node_degree(graph)
    dist = distance_to_sink(graph, sink=sink)
    kinds = {n['id']: n.get('kind', '') for n in graph.get('nodes', []) if 'id' in n}

    lines: List[str] = []
    lines.append('TOPOLOGY STRUCTURE')
    lines.append('=' * 60)
    lines.append(f'sink: {sink} (the core switch every VIP task transits)')
    # The sink's own distance is trivially 0.0 and is not evidence that
    # anything was reported, so it does not count towards "we have delays".
    measured = sum(
        1 for nid, v in dist.items()
        if nid != sink and v['delay_ms'] is not None
    )
    if measured == 0:
        lines.append(
            'link delays: NOT REPORTED -- no topology_links event in this '
            'recording, so delay_ms is unavailable (hop counts still valid).'
        )
    lines.append(
        'delay is the sum of CONFIGURED link delays, not a measured RTT.'
    )
    lines.append('')
    lines.append(f'{"node":<10}{"kind":<14}{"degree":>8}{"hops":>8}{"delay":>12}')
    lines.append('-' * 60)

    for nid in sorted(
        degree, key=lambda n: (_KIND_ORDER.get(kinds.get(n, ''), 9), _natural_key(n))
    ):
        d = dist.get(nid, {'hops': None, 'delay_ms': None})
        hops = '-' if d['hops'] is None else str(int(d['hops']))
        dl = '-' if d['delay_ms'] is None else f'{d["delay_ms"]:.1f} ms'
        lines.append(
            f'{nid:<10}{kinds.get(nid, ""):<14}{degree[nid]:>8}{hops:>8}{dl:>12}'
        )
    return '\n'.join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('events', nargs='?', default='data/events.jsonl')
    ap.add_argument('--sink', default=DEFAULT_SINK)
    args = ap.parse_args(argv)

    graph = topology_graph(load_events(args.events))
    if graph is None:
        print('No topology event in this recording -- nothing to report.')
        return 1
    print(format_report(graph, sink=args.sink))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
