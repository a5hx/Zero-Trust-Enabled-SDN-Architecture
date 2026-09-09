"""Recorded RAFT failover experiment: 3 replicas, continuous load, a real kill.

`blockchain/raft_demo.py` already proves the mechanism live -- three processes,
real loopback TCP, a real SIGTERM -- but it prints its result and forgets it.
This module runs the same scenario under *continuous* load and RECORDS it:
every replica's role/term/log state sampled on a fixed interval, and every
commit attempt with its outcome, into one JSONL file that
`evaluation/plot_raft_timeline.py` turns into a figure.

The difference matters for what can be claimed. `raft_demo` commits in two
discrete batches with the kill in the gap between them, so it can say
"commits worked, then the leader died, then commits worked again". Here the
client never stops, so the recording also contains the *outage*: the commit
attempts that failed while no leader existed, and how long that lasted.

Same disclosure as raft_demo, in the same words: this is three OS processes
and real loopback TCP sockets on one machine, not three physically separate
hosts. The RAFT code, the sockets, and the process boundaries are all real;
only the hardware separation is not.

WHAT THE MEASUREMENT CANNOT SEE
-------------------------------
Roles are sampled by polling `/status`, so every transition in the recording
is located to within one poll interval (`--poll-interval-s`, default 50 ms).
A failover reported as 220 ms is 220 ms +/- one interval, and the figure says
so. The kill instant is exact -- it is this process calling `terminate()` --
and so is every commit latency, which is measured around its own HTTP round
trip. Only the role transitions are polled.

Run:
    python3 -m blockchain.raft_timeline
    python3 -m blockchain.raft_timeline --duration-s 45 --kill-at-s 15 --restart-at-s 30
"""

import argparse
import json
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import requests

from blockchain.raft_demo import (
    NODE_IDS, _addresses, spawn_replica, spawn_replicas, status, wait_for_leader,
)

DEFAULT_OUT = 'data/raft_timeline.jsonl'

#: Every commit attempt lands in exactly one of these. `not_leader` is the
#: documented behaviour of a follower's control API (409, no redirect -- see
#: docs/RAFT.md "No client-side leader redirect"), not a fault.
OUTCOMES = ('ok', 'not_leader', 'unreachable', 'timeout', 'error')


class Recorder:
    """Thread-safe JSONL writer with one monotonic clock for the whole run.

    Every row carries `t`, seconds since the recording started. Threads write
    concurrently (the poller and the committer both do), so the lock is not
    optional -- interleaved partial lines would corrupt the recording in a way
    that only shows up at plot time, long after the run is unrepeatable.
    """

    def __init__(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(path, 'w')
        self._lock = threading.Lock()
        self._t0 = time.monotonic()

    @property
    def t(self) -> float:
        return time.monotonic() - self._t0

    def write(self, **row) -> None:
        with self._lock:
            self._fh.write(json.dumps(row) + '\n')
            self._fh.flush()

    def close(self) -> None:
        with self._lock:
            self._fh.close()


def _poll_loop(rec: Recorder, http_ports: Dict[str, int],
               interval_s: float, stop: threading.Event) -> None:
    """Sample every replica's `/status` until told to stop.

    A replica that does not answer is recorded as role `down` rather than
    skipped: a gap in the rows would be indistinguishable from a slow poller,
    and the whole point of the figure is to show one node absent while the
    others carry on.
    """
    previous: Dict[str, tuple] = {}
    while not stop.is_set():
        for nid in NODE_IDS:
            snapshot = status(nid, http_ports)
            row = dict(type='status', t=rec.t, node=nid)
            if snapshot is None:
                row.update(role='down', term=None, leader_id=None,
                           commit_index=None, chain_length=None)
            else:
                row.update(role=snapshot['role'], term=snapshot['term'],
                           leader_id=snapshot['leader_id'],
                           commit_index=snapshot['commit_index'],
                           chain_length=snapshot['chain_length'])
            rec.write(**row)

            signature = (row['role'], row['term'])
            if previous.get(nid) != signature:
                previous[nid] = signature
                term = '' if row['term'] is None else f" (term {row['term']})"
                print(f"  t={row['t']:6.2f}s  {nid}: {row['role']}{term}")
        stop.wait(interval_s)


def _resolve_leader(http_ports: Dict[str, int]) -> Optional[str]:
    """Ask the cluster who leads now.

    A replica that believes itself leader is authoritative for this purpose;
    failing that, a follower's `leader_id` hint is followed. This is exactly
    what docs/RAFT.md tells a client to do, because the control API does not
    redirect -- so the committer below is a realistic client, not a privileged
    one with inside knowledge of the cluster.
    """
    hints = []
    for nid in NODE_IDS:
        snapshot = status(nid, http_ports)
        if not snapshot:
            continue
        if snapshot.get('role') == 'leader':
            return nid
        if snapshot.get('leader_id'):
            hints.append(snapshot['leader_id'])
    return hints[0] if hints else None


def _attempt_commit(session: requests.Session, port: int, seq: int,
                    timeout_s: float) -> tuple:
    """One commit attempt. Returns (outcome, latency_ms, block_index, term)."""
    payload = [{
        'device_id': 'demo_iot', 'edge_node_id': f'srv{seq % 4 + 1}',
        'task_status': 'success', 'cpu_usage': 0.3, 'reported_cpu': 0.3,
        'latency_ms': 20.0, 'trust_score_after': 0.8,
    }]
    started = time.monotonic()
    try:
        r = session.post(f'http://127.0.0.1:{port}/commit', json=payload,
                         timeout=timeout_s)
    except requests.Timeout:
        return 'timeout', (time.monotonic() - started) * 1000.0, None, None
    except requests.RequestException:
        return 'unreachable', (time.monotonic() - started) * 1000.0, None, None
    elapsed_ms = (time.monotonic() - started) * 1000.0

    if r.status_code == 409:
        return 'not_leader', elapsed_ms, None, None
    if r.status_code != 200:
        return 'error', elapsed_ms, None, None
    body = r.json()
    if not body.get('ok'):
        return 'error', elapsed_ms, None, None
    return 'ok', elapsed_ms, body.get('block_index'), body.get('raft_term')


def _commit_loop(rec: Recorder, http_ports: Dict[str, int], target: str,
                 interval_s: float, timeout_s: float, stop: threading.Event) -> None:
    """Commit continuously, re-resolving the leader whenever an attempt fails.

    Load does not pause for the kill. That is the point: the failed attempts
    between the leader dying and its successor being elected ARE the outage,
    and a client that politely waited would record an availability the cluster
    did not actually provide.
    """
    session = requests.Session()
    seq = 0
    while not stop.is_set():
        t = rec.t
        outcome, latency_ms, index, term = _attempt_commit(
            session, http_ports[target], seq, timeout_s)
        rec.write(type='commit', t=t, target=target, outcome=outcome,
                  ok=(outcome == 'ok'), latency_ms=round(latency_ms, 3),
                  block_index=index, raft_term=term)
        seq += 1
        if outcome != 'ok':
            found = _resolve_leader(http_ports)
            target = found if found else NODE_IDS[(NODE_IDS.index(target) + 1) % len(NODE_IDS)]
        stop.wait(interval_s)


def _wait_until(rec: Recorder, t_target: float, stop: threading.Event) -> None:
    remaining = t_target - rec.t
    if remaining > 0:
        stop.wait(remaining)


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--duration-s', type=float, default=40.0,
                   help='total recording length (default: 40)')
    p.add_argument('--kill-at-s', type=float, default=15.0,
                   help='when to SIGTERM the leader (default: 15)')
    p.add_argument('--restart-at-s', type=float, default=None,
                   help='optionally restart the killed replica at this time, to '
                        'show it rejoin and catch up')
    p.add_argument('--commit-interval-s', type=float, default=0.05)
    p.add_argument('--poll-interval-s', type=float, default=0.05,
                   help='status sampling period; bounds the resolution of every '
                        'role transition in the figure (default: 0.05)')
    p.add_argument('--commit-timeout-s', type=float, default=2.0)
    p.add_argument('--election-wait-s', type=float, default=10.0)
    p.add_argument('--out', default=DEFAULT_OUT)
    args = p.parse_args(argv)

    if args.kill_at_s >= args.duration_s:
        p.error('--kill-at-s must fall inside --duration-s')
    if args.restart_at_s is not None and not (args.kill_at_s < args.restart_at_s < args.duration_s):
        p.error('--restart-at-s must fall between --kill-at-s and --duration-s')

    _, http_ports = _addresses()
    procs = spawn_replicas(args.commit_timeout_s)
    rec: Optional[Recorder] = None
    stop = threading.Event()
    threads: List[threading.Thread] = []
    try:
        print('spawned 3 replicas, waiting for a leader...')
        first_leader = wait_for_leader(http_ports, NODE_IDS, timeout=args.election_wait_s)
        print(f'leader elected: {first_leader}\nrecording -> {args.out}\n')

        rec = Recorder(args.out)
        rec.write(type='meta', t=0.0, node_ids=list(NODE_IDS),
                  started_at=time.time(), duration_s=args.duration_s,
                  kill_at_s=args.kill_at_s, restart_at_s=args.restart_at_s,
                  poll_interval_s=args.poll_interval_s,
                  commit_interval_s=args.commit_interval_s,
                  commit_timeout_s=args.commit_timeout_s,
                  first_leader=first_leader)

        for target_fn in (
            lambda: _poll_loop(rec, http_ports, args.poll_interval_s, stop),
            lambda: _commit_loop(rec, http_ports, first_leader,
                                 args.commit_interval_s, args.commit_timeout_s, stop),
        ):
            th = threading.Thread(target=target_fn, daemon=True)
            th.start()
            threads.append(th)

        _wait_until(rec, args.kill_at_s, stop)

        victim = wait_for_leader(http_ports, NODE_IDS, timeout=args.election_wait_s)
        kill_t = rec.t
        rec.write(type='kill', t=kill_t, node=victim, signal='SIGTERM')
        print(f"\n  t={kill_t:6.2f}s  KILL {victim} (SIGTERM) -- the current leader\n")
        procs[victim].terminate()
        procs[victim].wait(timeout=5.0)

        survivors = [nid for nid in NODE_IDS if nid != victim]
        new_leader = wait_for_leader(http_ports, survivors, timeout=args.election_wait_s)
        elected_t = rec.t
        rec.write(type='leader_elected', t=elected_t, node=new_leader,
                  after_kill_s=round(elected_t - kill_t, 3), replaced=victim)
        print(f"\n  t={elected_t:6.2f}s  NEW LEADER {new_leader} "
              f"({elected_t - kill_t:.2f}s after the kill)\n")

        if args.restart_at_s is not None:
            _wait_until(rec, args.restart_at_s, stop)
            restart_t = rec.t
            procs[victim] = spawn_replica(victim, args.commit_timeout_s)
            rec.write(type='restart', t=restart_t, node=victim)
            print(f"\n  t={restart_t:6.2f}s  RESTART {victim} -- rejoins with an EMPTY log "
                  f"(crash-fault only, no disk persistence; docs/RAFT.md)\n")

        _wait_until(rec, args.duration_s, stop)
    finally:
        stop.set()
        for th in threads:
            th.join(timeout=3.0)
        if rec is not None:
            rec.close()
        for proc in procs.values():
            if proc.poll() is None:
                proc.terminate()
        for proc in procs.values():
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                proc.kill()

    print(f'\nrecorded {args.duration_s:.0f}s -> {args.out}')
    print(f'plot it:  python3 -m evaluation.plot_raft_timeline --recording {args.out}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
