"""Kill the RAFT leader during a live run and check nothing is lost.

Run in a SECOND terminal while `run_demo.py --mode mininet` runs a replicated-
ledger config (the replicas are root's children, so this needs sudo too):

    sudo python3 tools/raft_failover_check.py --config config/params_trust_raft.yaml

What it does, in order:

1. Waits until the controller has committed --warmup-batches batches (traffic
   is flowing and blocks are landing).
2. Finds the leader from the replicas' GET /status and records its exact
   command line from /proc.
3. Kills it with SIGKILL -- a crash, not a polite shutdown.
4. Times how long until a different replica reports itself leader.
5. After --restart-after-s, starts the killed replica again with its original
   command line (same --data-dir, so it must rejoin from its on-disk log) and
   checks it catches up with the leader's chain.
6. Keeps sampling the controller's GET /ledger/status until the controller
   goes away at the end of the run, then writes a JSON report and prints the
   verdict: submitted == committed and nothing dropped means no trust update
   was lost across the failover.
"""

import argparse
import http.client
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml


def _get(host: str, port: int, path: str, timeout: float = 1.0) -> Optional[Dict[str, Any]]:
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request('GET', path)
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return json.loads(body) if resp.status == 200 and body else None
    except (OSError, ValueError, http.client.HTTPException):
        return None


def _replicas(cfg: Dict[str, Any]) -> Dict[str, Tuple[str, int]]:
    out = {}
    for rid, addr in cfg['ledger']['replicas'].items():
        host, port = str(addr).rsplit(':', 1)
        out[str(rid)] = (host, int(port))
    return out


def _statuses(replicas: Dict[str, Tuple[str, int]]) -> Dict[str, Optional[Dict[str, Any]]]:
    return {rid: _get(h, p, '/status', 0.5) for rid, (h, p) in replicas.items()}


def _leader(statuses: Dict[str, Optional[Dict[str, Any]]]) -> Optional[str]:
    leaders = [rid for rid, s in statuses.items() if s and s.get('role') == 'leader']
    return leaders[0] if len(leaders) == 1 else None


def _pid_of(replica_id: str) -> Optional[int]:
    out = subprocess.run(['pgrep', '-f', f'blockchain.raft_replica --id {replica_id} '],
                         capture_output=True, text=True).stdout.split()
    pids = [int(p) for p in out if int(p) != os.getpid()]
    return pids[0] if pids else None


def _cmdline(pid: int) -> Tuple[List[str], str]:
    raw = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
    return [a.decode() for a in raw if a], os.readlink(f'/proc/{pid}/cwd')


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--config', default='config/params_trust_raft.yaml')
    p.add_argument('--warmup-batches', type=int, default=60)
    p.add_argument('--restart-after-s', type=float, default=60.0)
    p.add_argument('--report', default=None, help='JSON report path (default data/raft_failover_<time>.json)')
    args = p.parse_args(argv)

    cfg = yaml.safe_load(Path(args.config).read_text())
    if (cfg.get('ledger') or {}).get('backend') != 'raft_remote':
        print(f'{args.config} does not use the replicated ledger (ledger.backend: raft_remote)')
        return 2
    ctrl = cfg['controller']
    c_host = '127.0.0.1' if ctrl.get('api_host') in (None, '0.0.0.0') else ctrl['api_host']
    c_port = int(ctrl['api_port'])
    replicas = _replicas(cfg)
    report: Dict[str, Any] = {'config': args.config, 'events': []}

    def note(msg: str, **fields: Any) -> None:
        stamp = time.time()
        print(f'[{time.strftime("%H:%M:%S")}] {msg}', flush=True)
        report['events'].append({'t': stamp, 'msg': msg, **fields})

    note('waiting for the controller and replicated commits...')
    while True:
        st = _get(c_host, c_port, '/ledger/status')
        if st and st.get('backend') == 'raft_remote' and st.get('committed', 0) >= args.warmup_batches:
            note('traffic flowing', committed=st['committed'])
            break
        time.sleep(1.0)

    statuses = _statuses(replicas)
    leader = _leader(statuses)
    if leader is None:
        note('no single leader found; aborting', statuses=statuses)
        return 1
    term_before = statuses[leader]['term']
    pid = _pid_of(leader)
    if pid is None:
        note(f'could not find the process for leader {leader}; aborting')
        return 1
    cmd, cwd = _cmdline(pid)
    report.update(killed=leader, term_before=term_before, killed_cmdline=cmd)

    os.kill(pid, signal.SIGKILL)
    t_kill = time.time()
    note(f'SIGKILL leader {leader} (pid {pid}, term {term_before})')

    new_leader = None
    while time.time() - t_kill < 30:
        cand = _leader({r: s for r, s in _statuses(replicas).items() if r != leader})
        if cand:
            new_leader = cand
            break
        time.sleep(0.05)
    failover_s = round(time.time() - t_kill, 3) if new_leader else None
    term_after = (_statuses({new_leader: replicas[new_leader]})[new_leader] or {}).get('term') if new_leader else None
    report.update(new_leader=new_leader, failover_s=failover_s, term_after=term_after)
    note(f'new leader: {new_leader} after {failover_s} s (term {term_after})')

    restarted = None
    while True:
        st = _get(c_host, c_port, '/ledger/status')
        if st is not None:
            report['last_ledger_status'] = st
        if restarted is None and time.time() - t_kill >= args.restart_after_s:
            log = open(Path(cwd) / 'logs' / f'raft_{leader}_restart.log', 'w')
            restarted = subprocess.Popen(cmd, cwd=cwd, stdout=log, stderr=subprocess.STDOUT)
            report['restarted_at'] = time.time()
            note(f'restarted {leader} with its original command line (pid {restarted.pid})')
        if restarted is not None and 'rejoin' not in report:
            # Leader first, then the restarted replica: blocks keep landing, so
            # "caught up" means it has reached the length the leader had a
            # moment earlier, not exact equality at two different instants.
            others = _statuses({r: a for r, a in replicas.items() if r != leader})
            lead = _leader(others)
            lead_len = (others.get(lead) or {}).get('chain_length') if lead else None
            mine = _statuses({leader: replicas[leader]})[leader]
            if lead_len is not None and mine and mine.get('chain_length', 0) >= lead_len:
                report['rejoin'] = {'after_s': round(time.time() - report['restarted_at'], 3),
                                    'chain_length': mine['chain_length'], 'role': mine.get('role')}
                note(f'{leader} rejoined and caught up: chain {mine["chain_length"]} '
                     f'>= leader {lead}\'s {lead_len} after {report["rejoin"]["after_s"]} s')
        if st is None and report.get('last_ledger_status'):
            # Controller gone: the run is over.
            break
        time.sleep(1.0)

    if restarted is not None and restarted.poll() is None:
        restarted.terminate()
        try:
            restarted.wait(timeout=5)
        except subprocess.TimeoutExpired:
            restarted.kill()

    final = report.get('last_ledger_status', {})
    # The controller shuts down while a batch may still be in flight, so the
    # last sample can legitimately show submitted > committed. Lossless means
    # nothing was dropped and every submitted batch is either committed or
    # still queued -- none vanished.
    sub, com = final.get('submitted', 0), final.get('committed', 0)
    lossless = final.get('dropped', 0) == 0 and sub - com == final.get('queue_depth', 0)
    report['verdict'] = {
        'failover_s': failover_s, 'submitted': final.get('submitted'),
        'committed': final.get('committed'), 'retries': final.get('retries'),
        'dropped': final.get('dropped'), 'queue_depth': final.get('queue_depth'),
        'no_updates_lost': lossless, 'killed_replica_rejoined': 'rejoin' in report,
    }
    out = Path(args.report or f'data/raft_failover_{time.strftime("%Y%m%d_%H%M%S")}.json')
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    uid, gid = os.environ.get('SUDO_UID'), os.environ.get('SUDO_GID')
    if uid and gid:
        os.chown(out, int(uid), int(gid))
    note('run over. ' + json.dumps(report['verdict']))
    print(f'report: {out}')
    return 0 if lossless else 1


if __name__ == '__main__':
    sys.exit(main())
