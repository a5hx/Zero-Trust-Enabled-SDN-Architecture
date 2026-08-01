"""Live RAFT demo (Step 2): 3 replica processes, real TCP sockets, real kill.

Spawns three `blockchain.raft_replica` processes on localhost (each with its
own RAFT port and its own HTTP control port), waits for a leader, submits a
batch of trust-update commits measuring wall-clock commit latency against the
deck's <500ms NFR, then SIGTERMs the current leader process outright and
keeps committing against whichever replica takes over -- the viva moment.

Disclosed plainly, the same way evaluation/baseline.py discloses it is a
simulation and not a Mininet run: this is three OS processes and real
loopback TCP sockets on one machine, not three physically separate hosts.
The RAFT code, the sockets, and the process boundaries are all real; only the
hardware separation is not.

Run:
    python3 -m blockchain.raft_demo
    python3 -m blockchain.raft_demo --commits 40 --commit-interval-s 0.1
"""

import argparse
import statistics
import subprocess
import sys
import time
from typing import Dict, List, Optional, Sequence, Tuple

import requests

NODE_IDS = ('n1', 'n2', 'n3')
BASE_RAFT_PORT = 9001
BASE_HTTP_PORT = 9101


def _addresses() -> Tuple[Dict[str, Tuple[str, int]], Dict[str, int]]:
    raft_peers = {nid: ('127.0.0.1', BASE_RAFT_PORT + i) for i, nid in enumerate(NODE_IDS)}
    http_ports = {nid: BASE_HTTP_PORT + i for i, nid in enumerate(NODE_IDS)}
    return raft_peers, http_ports


def _peers_arg(raft_peers: Dict[str, Tuple[str, int]]) -> str:
    return ','.join(f'{nid}={host}:{port}' for nid, (host, port) in raft_peers.items())


def spawn_replicas(commit_timeout_s: float) -> Dict[str, subprocess.Popen]:
    raft_peers, http_ports = _addresses()
    peers_arg = _peers_arg(raft_peers)
    procs = {}
    for nid in NODE_IDS:
        procs[nid] = subprocess.Popen([
            sys.executable, '-m', 'blockchain.raft_replica',
            '--id', nid, '--peers', peers_arg,
            '--http-port', str(http_ports[nid]),
            '--commit-timeout-s', str(commit_timeout_s),
        ])
    return procs


def status(nid: str, http_ports: Dict[str, int]) -> Optional[dict]:
    try:
        r = requests.get(f'http://127.0.0.1:{http_ports[nid]}/status', timeout=0.5)
        return r.json()
    except requests.RequestException:
        return None


def wait_for_leader(http_ports: Dict[str, int], alive: Sequence[str], timeout: float = 10.0) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for nid in alive:
            s = status(nid, http_ports)
            if s and s.get('role') == 'leader':
                return nid
        time.sleep(0.1)
    raise TimeoutError(f"no leader elected among {list(alive)} within {timeout:.0f}s")


def commit_batch(nid: str, http_ports: Dict[str, int], n: int, interval_s: float) -> List[float]:
    """Submit n commits against replica `nid`'s control API, returning the
    wall-clock latency (ms) of each successful one -- HTTP round trip
    included, so this is what a real client would observe, not an internal
    RAFT-only number."""
    latencies = []
    for i in range(n):
        payload = [{
            'device_id': 'demo_iot', 'edge_node_id': f'srv{i % 4 + 1}',
            'task_status': 'success', 'cpu_usage': 0.3, 'reported_cpu': 0.3,
            'latency_ms': 20.0, 'trust_score_after': 0.8,
        }]
        started = time.monotonic()
        try:
            r = requests.post(f'http://127.0.0.1:{http_ports[nid]}/commit',
                              json=payload, timeout=5.0)
            ok = r.status_code == 200 and r.json().get('ok', False)
        except requests.RequestException:
            ok = False
        elapsed_ms = (time.monotonic() - started) * 1000.0
        if ok:
            latencies.append(elapsed_ms)
        time.sleep(interval_s)
    return latencies


def report(label: str, latencies: List[float], attempted: int, nfr_ms: float = 500.0) -> None:
    if not latencies:
        print(f"{label}: 0/{attempted} commits succeeded")
        return
    verdict = 'PASS' if max(latencies) < nfr_ms else 'FAIL'
    print(
        f"{label}: {len(latencies)}/{attempted} succeeded | "
        f"mean={statistics.fmean(latencies):.1f}ms "
        f"median={statistics.median(latencies):.1f}ms "
        f"max={max(latencies):.1f}ms  (<{nfr_ms:.0f}ms NFR: {verdict})"
    )


def main(argv: Optional[Sequence[str]] = None) -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--commits', type=int, default=20, help='commits per phase (default: 20)')
    p.add_argument('--commit-interval-s', type=float, default=0.05)
    p.add_argument('--election-wait-s', type=float, default=10.0)
    p.add_argument('--commit-timeout-s', type=float, default=2.0)
    args = p.parse_args(argv)

    _, http_ports = _addresses()
    procs = spawn_replicas(args.commit_timeout_s)
    try:
        print("spawned 3 replicas, waiting for a leader...")
        leader = wait_for_leader(http_ports, NODE_IDS, timeout=args.election_wait_s)
        print(f"leader elected: {leader}")

        before = commit_batch(leader, http_ports, args.commits, args.commit_interval_s)
        report("before kill", before, args.commits)

        print(f"\nkilling leader {leader} (SIGTERM)...")
        killed_at = time.monotonic()
        procs[leader].terminate()
        procs[leader].wait(timeout=5.0)

        survivors = [nid for nid in NODE_IDS if nid != leader]
        new_leader = wait_for_leader(http_ports, survivors, timeout=args.election_wait_s)
        recovery_s = time.monotonic() - killed_at
        print(f"new leader elected: {new_leader} ({recovery_s:.2f}s after the kill)")

        after = commit_batch(new_leader, http_ports, args.commits, args.commit_interval_s)
        report("after recovery", after, args.commits)
    finally:
        for nid, proc in procs.items():
            if proc.poll() is None:
                proc.terminate()
        for proc in procs.values():
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == '__main__':
    main()
