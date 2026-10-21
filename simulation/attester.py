"""Attester sidecar: measures one server's agent from outside and proves the
measurement to the controller (Phase 4, security/attestation.py).

Runs on the server host beside node_agent.py, started by the harness. Every
`--interval-s` it

    1. finds the agent process (pgrep, same pattern as cpu_profiles.py),
    2. asks the controller for a nonce        POST /attest/challenge {node_id}
    3. measures the code that process runs (/proc/<pid>/exe, cmdline, cwd),
    4. signs (node, nonce, measurement) with this node's Ed25519 key and sends
       the quote                              POST /attest/verify

If it cannot measure the agent -- no process, or one whose code location is
ambiguous -- it says so instead of quoting, and the controller refuses the
node. It never measures itself and the agent never sees the key.

Usage (normally from simulation/topology.py):
    python3 -u -m simulation.attester --node-id srv1 --controller 10.0.99.254 \
        --controller-port 8081 --key-file logs/attest_keys/srv1.key
"""

import argparse
import json
import logging
import os
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

from security.attestation import (AGENT_MODULE, AttestationConfig, MeasurementError,
                                  extend, measure_process, module_files,
                                  provision_keys, sign_quote)

logger = logging.getLogger('attester')

#: Where the harness builds each tampered agent image (simulation.tampered_agents).
TAMPERED_ROOT = Path('logs/tampered')
#: Appended to the tampered copy. One changed byte is enough to change the
#: measurement; what the tampered server then DOES still comes from its
#: malicious_edge_nodes entry, so a tampered and a runtime-compromised server
#: behave identically and differ only in what is on disk.
TAMPER_MARK = '\n# TAMPERED IMAGE (Phase 4 emulation): not the released agent.\n'


def tampered_dir(node_id: str) -> Path:
    return TAMPERED_ROOT / node_id


def prepare_run(cfg: Dict[str, Any], repo: Path = Path('.')) -> None:
    """Harness side, before any agent starts: fresh keys for every server and
    a tampered image for each server in simulation.tampered_agents. No-op when
    attestation is off and nothing is tampered."""
    acfg = AttestationConfig.from_config(cfg.get('security'))
    n_edge = cfg['simulation']['num_edge_nodes']
    if acfg.enabled:
        provision_keys([f'srv{i}' for i in range(1, n_edge + 1)], Path(acfg.key_dir))
    for node in cfg['simulation'].get('tampered_agents') or []:
        root = tampered_dir(node)
        for rel in module_files(AGENT_MODULE):
            dst = root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes((repo / rel).read_bytes())
        agent = root / module_files(AGENT_MODULE)[-1]
        agent.write_text(agent.read_text() + TAMPER_MARK)


def find_agent(node_id: str) -> Optional[int]:
    """The lowest-numbered *python* process running node_id's agent, or None.

    pgrep -f also matches any shell whose own command line carries the agent's
    (`sh -c 'python3 -m simulation.node_agent ...'`); measuring that shell
    would refuse a genuine server, so only interpreter processes count."""
    out = subprocess.run(['pgrep', '-f', f'{AGENT_MODULE} --node-id {node_id} '],
                         capture_output=True, text=True).stdout.split()
    for pid in sorted(int(p) for p in out if int(p) != os.getpid()):
        try:
            if 'python' in os.path.basename(os.readlink(f'/proc/{pid}/exe')):
                return pid
        except OSError:
            continue
    return None


def _post(url: str, body: Dict[str, Any], timeout: float = 2.0) -> Dict[str, Any]:
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={'Content-Type': 'application/json'}, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read() or b'{}')
    except urllib.error.HTTPError as exc:   # a refusal is a 403 with a JSON body
        return json.loads(exc.read() or b'{}')


def attest_once(node_id: str, base_url: str, private_key: bytes,
                pid: Optional[int]) -> Dict[str, Any]:
    """One challenge/quote round. Returns the controller's answer."""
    nonce = bytes.fromhex(_post(f'{base_url}/attest/challenge', {'node_id': node_id})['nonce'])
    if pid is None:
        return _post(f'{base_url}/attest/verify',
                     {'node_id': node_id, 'unmeasurable': 'no agent process'})
    try:
        comps = measure_process(pid)
    except MeasurementError as exc:
        return _post(f'{base_url}/attest/verify', {'node_id': node_id, 'unmeasurable': str(exc)})
    measurement = extend(comps)
    sig = sign_quote(private_key, node_id, nonce, measurement)
    return _post(f'{base_url}/attest/verify', {
        'node_id': node_id, 'components': comps,
        'measurement': measurement, 'signature': sig.hex(),
    })


def run(args: argparse.Namespace) -> None:
    key = bytes.fromhex(Path(args.key_file).read_text().strip())
    base = f'http://{args.controller}:{args.controller_port}'
    deadline = time.monotonic() + args.find_timeout_s
    pid = find_agent(args.node_id)
    while pid is None and time.monotonic() < deadline:
        time.sleep(0.1)
        pid = find_agent(args.node_id)
    while True:
        if pid is None or not Path(f'/proc/{pid}').exists():
            pid = find_agent(args.node_id)
        t0 = time.monotonic()
        try:
            answer = attest_once(args.node_id, base, key, pid)
        except Exception as exc:   # noqa: BLE001 -- controller not up yet: try again soon
            logger.warning('%s: attestation round failed: %s', args.node_id, exc)
            time.sleep(min(1.0, args.interval_s))
            continue
        logger.info('%s: pid=%s verdict=%s %s (%.1f ms)', args.node_id, pid,
                    answer.get('verdict'), answer.get('detail', ''),
                    1000 * (time.monotonic() - t0))
        time.sleep(args.interval_s)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description='Attester sidecar for one edge server')
    p.add_argument('--node-id', required=True)
    p.add_argument('--controller', required=True)
    p.add_argument('--controller-port', type=int, default=8081)
    p.add_argument('--key-file', required=True)
    p.add_argument('--interval-s', type=float, default=30.0)
    p.add_argument('--find-timeout-s', type=float, default=10.0,
                   help='how long to wait for the agent before reporting it missing')
    return p


def main() -> None:
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    run(build_parser().parse_args())


if __name__ == '__main__':
    main()
