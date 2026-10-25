#!/usr/bin/env python3
"""Audit the probation path in the recordings that predate its two fixes (S IX).

1. Trials that could reach their server: before PRIO_TRIAL_PASSAGE, a trial got
   past the quarantine's fleet-wide drop rules only from a client behind the
   server's own switch (route dpid == server index + 1).
2. Misattributed trial reports: a trial's rules expired with the client's 4 s
   timeout, the client's closing packet was routed again as a new connection,
   and the trial's report was charged to the new server. Counted as: a trial
   key routed again to a different server within REROUTE_S, and the device's
   next report within REPORT_S charged to that server.
3. Honest trust floors with and without those charges: the lowest honest
   trust after onset, then again excluding each server's EXCLUDE_S after a
   misattributed report to it.

Ground truth comes from each recording's own `topology` event.

    python3 paper-draft/tools/trial_path_audit.py [data/runs]
"""

import glob
import json
import os
import sys

ARMS = ['scoreonly', 'scoreonly_t040', 'scoreonly_t045', 'scoreonly_t050', 'treat',
        'flood_off', 'flood_on']
FLOOR_ARMS = ['scoreonly', 'scoreonly_t040', 'scoreonly_t045', 'scoreonly_t050', 'treat']
REROUTE_S = 8.0
REPORT_S = 1.0
EXCLUDE_S = 40.0


def audit(path):
    t0 = None
    honest, onset = set(), 0.0
    last, pending = {}, {}
    trials = same_switch = 0
    charged = []                     # (t, node, status, honest?)
    trust = []                       # (t, node, T) for honest servers
    with open(path) as fh:
        for line in fh:
            head = line[:45]
            if not any(k in head for k in ('"topology"', '"route"', '"report"', '"node_status"')):
                continue
            ev = json.loads(line)
            if t0 is None:
                t0 = ev['ts']
            t = ev['ts'] - t0
            kind = ev['type']
            if kind == 'topology':
                servers = [n for n in ev['graph']['nodes'] if n.get('kind') == 'server']
                honest = {n['id'] for n in servers if (n.get('attack') or 'none') == 'none'}
                onsets = [float(n.get('attack_start_s') or 0) for n in servers
                          if (n.get('attack') or 'none') != 'none']
                onset = min(onsets) if onsets else 0.0
            elif kind == 'route' and ev.get('chosen'):
                if ev.get('probation'):
                    trials += 1
                    same_switch += ev['dpid'] == int(ev['chosen'][3:]) + 1
                key = (ev['client_ip'], ev['client_port'])
                prev = last.get(key)
                if prev and prev[2] and ev['ts'] - prev[0] < REROUTE_S and ev['chosen'] != prev[1]:
                    pending['iot' + key[0].rsplit('.', 1)[-1]] = (ev['ts'], ev['chosen'])
                last[key] = (ev['ts'], ev['chosen'], bool(ev.get('probation')))
            elif kind == 'report':
                p = pending.get(ev['device'])
                if p and ev['ts'] - p[0] < REPORT_S and ev['node'] == p[1]:
                    del pending[ev['device']]
                    if ev.get('charged', True) is not False:
                        charged.append((t, ev['node'], ev['status'], ev['node'] in honest))
            elif kind == 'node_status' and t >= onset:
                for n, v in ev['nodes'].items():
                    if n in honest and v.get('trust') is not None:
                        trust.append((t, n, float(v['trust'])))
    low = min(trust, key=lambda x: x[2]) if trust else None
    clean = [x for x in trust
             if not any(c[1] == x[1] and 0 <= x[0] - c[0] <= EXCLUDE_S for c in charged)]
    clean_low = min(clean, key=lambda x: x[2]) if clean else None
    return trials, same_switch, charged, low, clean_low


def main(argv):
    root = argv[1] if len(argv) > 1 else 'data/runs'
    runs = tot_trials = tot_same = 0
    tot_charged = []
    floors = []
    print(f'Probation-path audit over {", ".join(ARMS)}')
    print(f'(re-route window {REROUTE_S} s, report window {REPORT_S} s, exclusion {EXCLUDE_S} s)\n')
    for arm in ARMS:
        for f in sorted(glob.glob(os.path.join(root, arm, 'r[0-9][0-9].jsonl'))):
            trials, same, charged, low, clean_low = audit(f)
            runs += 1
            tot_trials += trials
            tot_same += same
            tot_charged += charged
            run = f'{arm}/{os.path.basename(f)[:3]}'
            hon = [c for c in charged if c[3]]
            line = f'{run:22s} trials {trials:4d}  same-switch {same:3d}  misattributed {len(charged)} ({len(hon)} honest)'
            if arm in FLOOR_ARMS and low:
                floors.append(clean_low[2])
                line += f'  lowest honest T {low[2]:.4f} ({low[1]} at {low[0]:.1f} s)'
                line += f'  without them {clean_low[2]:.4f}'
            print(line)
            for c in hon:
                print(f'{"":24s}charged {c[2]} to honest {c[1]} at {c[0]:.1f} s')
    hon = [c for c in tot_charged if c[3]]
    print(f'\n{runs} runs: {tot_trials} trials, {tot_same} from the server\'s own switch '
          f'({100 * tot_same / tot_trials:.1f}%)')
    print(f'misattributed reports: {len(tot_charged)}, {len(hon)} to an honest server; '
          f'statuses {sorted({c[2] for c in tot_charged})}: '
          + ', '.join(f'{s} {sum(1 for c in tot_charged if c[2] == s)}'
                      for s in sorted({c[2] for c in tot_charged})))
    print(f'lowest honest trust after onset without them, over the {len(floors)} '
          f'{"/".join(FLOOR_ARMS)} runs: {min(floors):.4f}')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
