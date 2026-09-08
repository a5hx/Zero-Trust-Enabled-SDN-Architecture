"""Client-load sweep for the dashboard's scaling panel: 20..40 IoT devices.

One question: **what happens to the shipped 8-server fleet as the client count
grows?** The roster is held at `config/params.yaml`'s 8 edge servers and the
device count is swept 20 -> 40, where 40 is exactly the `num_iot_devices` that
config deploys. Both ends of the x axis are therefore inside the topology this
project actually builds -- the right edge of the chart IS the demo config.

argmax is plotted against p2c because a single-strategy curve here says almost
nothing: with load this far below farm capacity, ANY selector that spreads work
keeps up, and the interesting quantity is the gap. See "What the row shows".

A fleet-size row was removed (2026-08-13)
-----------------------------------------
This module briefly carried a second row sweeping 20..40 edge SERVERS. It was
dropped deliberately: the live topology has 8, no 40-server run has ever
existed, and that row extrapolated five sizes past anything ever instantiated
on the strength of a queueing model. It projected rather than measured, and a
projection sitting on the same page as live charts is a claim this project
cannot defend under questioning.

No capability was lost. `evaluation/scalability_sweep.py` has always swept N and
publishes its 4..64 table; `python3 -m evaluation.scalability_sweep --ns
20,25,30,35,40` still produces exactly those numbers on the CLI, where they read
as what they are -- a simulation result in a simulation harness's output --
rather than as a dashboard panel.

What this row is, and what it still is not
-------------------------------------------
It is a SIMULATION. Removing the fleet row removed the extrapolation beyond the
built topology; it did not make what remains a live measurement. Both axes now
sit within the deployed configuration, so this is interpolation inside the
shipped topology rather than projection outside it -- a real difference in how
much the model is being asked to carry, and not the same thing as evidence from
a run.

What is genuinely real here is the selector: every routing decision is made by
`controller.edge_selector.select_edge_node`, the function the live controller
calls, via `scalability_sweep.run_sweep`. This module contains no simulation
model of its own -- adding one for what is a different choice of axis is exactly
the drift `starvation_sweep.py` and `scalability_sweep.py` were split to avoid.

What is modelled: each server is an M/M/c queue (4 workers, 200 ms mean
service) and the network is not modelled at all -- no OpenFlow round trips, no
flow-rule installation, no propagation delay, no packet loss. Live 8/40/3
figures, which include all of that, are in docs/LIVE_RUN_8_40_3.md and are the
thing to quote for live behaviour.

Device count -> offered load
----------------------------
The harness understands an arrival rate, not a device count. The conversion is
the live arithmetic documented in config/params_trust_full.yaml: offered task
rate = num_iot / report_interval_s. config/params.yaml sets no
report_interval_s, so simulation/topology.py's default of 1.0 s applies and D
devices offer D tasks/s.

That rate is expressed as a fraction of the HARNESS's farm capacity
(8 x concurrency / SERVICE_MEAN_S = 160 tasks/s), whose 200 ms service time is
not the live `task_work_ms` of 15-40 ms. So the x axis is labelled by the device
count that produces the load, and the sweep is not calibrated against the live
run -- stated here rather than buried, because a "devices" axis invites exactly
that reading.

What the row shows (seed 1, 120 s cells)
-----------------------------------------
20..40 devices is 12.5%..25% of farm capacity, which is argmax's STARVATION
regime rather than its saturation one, and the failure is correspondingly
quiet:

  * **Throughput and PDR do not separate the two strategies.** Both track the
    offered rate (argmax 20.0 -> 40.3 tasks/s, p2c 19.4 -> 39.7) at 99.4-99.9%
    PDR throughout. An evaluation reporting only these two would conclude the
    selectors are equivalent. They are not.
  * **argmax runs the whole workload on 3 of the 8 servers.** Five complete
    nothing at all at every device count up to 35 (four at 40), so Jain sits at
    0.28-0.39 against p2c's 0.94-0.98.
  * **The cost is in delay, and it grows.** Concentrating the load means every
    added device piles onto the same three queues: argmax's mean latency climbs
    300 -> 670 ms while p2c holds ~200 ms flat.

That is why the panel plots fairness and the starved count alongside throughput
-- the failure is invisible in the headline metrics and unmistakable in these.
"""

from __future__ import annotations

import argparse
import json
import os
from typing import Dict, List, Sequence

from evaluation.scalability_sweep import (
    CONCURRENCY,
    SERVICE_MEAN_S,
    SIM_S,
    SweepPoint,
    run_sweep,
)

#: IoT device counts on the x axis. 40 is config/params.yaml's deployed
#: `num_iot_devices`, so the sweep ends at the shipped topology rather than
#: past it.
DEVICE_COUNTS = (20, 25, 30, 35, 40)

#: The fixed roster: config/params.yaml's `num_edge_nodes`. This is the
#: variable that is deliberately NOT swept -- see the module docstring.
SERVERS = 8

#: Seconds between task submissions per IoT device -- simulation/topology.py's
#: `report_interval_s` default, which config/params.yaml takes because it sets
#: no value of its own.
REPORT_INTERVAL_S = 1.0

#: p2c first: it is the shipped strategy, and it holds palette slot 1 on the
#: panel. argmax is the comparison, not the default.
STRATEGIES = ('p2c', 'argmax')


def devices_to_load_factor(devices: int, servers: int = SERVERS) -> float:
    """Offered device rate as a fraction of the harness's farm capacity.

    See the module docstring for what this conversion does and does not claim.
    """
    capacity = servers * CONCURRENCY / SERVICE_MEAN_S
    return (devices / REPORT_INTERVAL_S) / capacity


def _point_json(p: SweepPoint) -> Dict[str, object]:
    """One cell, with every metric the panel plots.

    Derived metrics are computed here rather than in the browser so the chart
    and any CSV/table of the same run cannot disagree about, say, what PDR
    means -- the same argument that pins the dashboard's bucket rules against
    interval_report.py.
    """
    return {
        'strategy': p.strategy,
        'n': p.n,
        'load_factor': round(p.load_factor, 5),
        'offered': p.offered,
        'completed': p.completed,
        'timed_out': p.timed_out,
        'denied': p.denied,
        'throughput_hz': round(p.throughput_hz, 3),
        'pdr': round(p.pdr * 100.0, 3),          # percent, as the panel plots it
        'mean_latency_ms': round(p.mean_latency_ms, 3),
        'p95_latency_ms': round(p.p95_latency_ms, 3),
        'jain': None if p.jain is None else round(p.jain, 5),
        'starved': p.starved,
        'used': p.used,
        'busiest_share': round(p.busiest_share * 100.0, 3),
        'decision_us_mean': round(p.decision_us_mean, 3),
    }


def build(
    device_counts: Sequence[int] = DEVICE_COUNTS,
    sim_s: float = SIM_S,
    seed: int = 1,
) -> Dict[str, object]:
    """Run the sweep and return the panel's JSON payload."""
    # One run_sweep call per device count, because the device count is carried
    # by load_factor and run_sweep pairs every load with every N. Looping here
    # keeps the (devices -> load) mapping one-to-one instead of producing a
    # grid of which only the diagonal is meaningful.
    points: List[SweepPoint] = []
    xs: List[int] = []
    for devices in device_counts:
        for p in run_sweep(
            [SERVERS], labels=STRATEGIES, seed=seed, sim_s=sim_s,
            load_factors=(devices_to_load_factor(devices),),
        ):
            points.append(p)
            xs.append(devices)

    return {
        'meta': {
            'sim_s': sim_s,
            'seed': seed,
            'servers': SERVERS,
            'concurrency': CONCURRENCY,
            'service_mean_s': SERVICE_MEAN_S,
            'device_counts': list(device_counts),
            'strategies': list(STRATEGIES),
            'source': 'evaluation/scale_compare.py',
        },
        'rows': [
            {
                'key': 'clients',
                'title': 'Client load',
                'xlabel': 'IoT devices',
                'sub': (f'{SERVERS} edge servers held fixed (the deployed '
                        f'roster); each device offers one task per '
                        f'{REPORT_INTERVAL_S:.0f}s'),
                'x': xs,
                'points': [_point_json(p) for p in points],
            },
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--devices', default=','.join(str(n) for n in DEVICE_COUNTS),
                   help='comma-separated IoT device counts '
                        f'(default: {",".join(str(n) for n in DEVICE_COUNTS)})')
    p.add_argument('--sim-s', type=float, default=SIM_S,
                   help=f'simulated seconds per cell (default {SIM_S})')
    p.add_argument('--seed', type=int, default=1)
    p.add_argument('--out', default='data/scale_compare.json',
                   help='where to write the panel payload '
                        '(default: data/scale_compare.json)')
    args = p.parse_args(argv)

    device_counts = [int(x) for x in args.devices.split(',') if x.strip()]
    payload = build(device_counts, sim_s=args.sim_s, seed=args.seed)

    out_dir = os.path.dirname(args.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.out, 'w') as f:
        json.dump(payload, f, indent=1)

    for row in payload['rows']:
        print(f"\n{row['title']} -- {row['sub']}")
        print(f"{'strategy':>9} | {row['xlabel']:>12} | {'thru/s':>7} | "
              f"{'PDR':>6} | {'mean ms':>8} | {'Jain':>5} | {'serving':>7}")
        print('-' * 72)
        for x, pt in zip(row['x'], row['points']):
            jain = 'n/a' if pt['jain'] is None else f"{pt['jain']:.3f}"
            print(f"{pt['strategy']:>9} | {x:>12} | {pt['throughput_hz']:>7.1f} | "
                  f"{pt['pdr']:>5.1f}% | {pt['mean_latency_ms']:>8.1f} | "
                  f"{jain:>5} | {pt['used']:>2}/{pt['n']:<4}")
    print(f"\nwrote {args.out}")
    print('Simulation, not a live run: the selector is real, the servers and '
          'the network are modelled.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
