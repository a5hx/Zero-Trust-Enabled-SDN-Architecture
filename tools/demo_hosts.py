"""Generate everything the multi-laptop review demo needs from one hosts file.

    python3 tools/demo_hosts.py                    # write deploy/demo/
    python3 tools/demo_hosts.py --check            # probe every role
    python3 tools/demo_hosts.py --check --wait-leader 30

Reads deploy/demo_hosts.yaml (copy deploy/demo_hosts.example.yaml) and writes,
under deploy/demo/ (gitignored -- it holds hotspot addresses and a token):

  params_review_demo_remote.yaml
        config/params_review_demo.yaml with the ledger: block replaced -- the
        replicas' hotspot addresses, a bearer token, and NO launch_local. Every
        other line is the parent's, so the trust: block the replicas re-verify
        against is byte-identical to the controller's.
  ledger_token.txt
        the bearer token the controller and the replicas share (made once,
        kept across regenerations so running replicas stay valid).
  replica_bundle.zip
        a self-contained copy for each replica laptop: blockchain/, contracts/,
        trust_engine/ (pure Python; PyYAML is the only dependency), the derived
        config, the token, and one launch script per replica. Unzip anywhere
        and run that laptop's script.
  replica_<id>.ps1 / replica_<id>.sh
        the same launch scripts, for reference.
  run_controller_A.sh
        laptop A's run command. sudo resets the environment, so the token is
        passed on the command line rather than inherited.
  portproxy_A.ps1
        laptop A, Windows side, as Administrator: forwards the dashboard port
        from the hotspot to WSL (whose address changes at every reboot, so the
        script looks it up fresh), plus a firewall rule.

Start order on the day: replicas (and wait for a leader: --check
--wait-leader), then laptop A's run_controller_A.sh. The controller syncs its
ledger mirror from the cluster at start-up, and run_demo.py starts replicas
itself only when ledger.launch_local is set, which the remote config omits.
"""

from __future__ import annotations

import argparse
import http.client
import json
import re
import secrets
import socket
import sys
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_HOSTS = ROOT / 'deploy' / 'demo_hosts.yaml'
DEFAULT_BASE = ROOT / 'config' / 'params_review_demo.yaml'
FORGE_BASE = ROOT / 'config' / 'params_review_demo_forge.yaml'
DEFAULT_OUT = ROOT / 'deploy' / 'demo'
REMOTE_CONFIG = 'params_review_demo_remote.yaml'
FORGE_REMOTE_CONFIG = 'params_review_demo_forge_remote.yaml'
# The auditor's import closure (controller/auditor.py + the inventory it maps
# addresses through); os-ken and PyYAML come from the auditor laptop's venv.
AUDITOR_FILES = ('controller/__init__.py', 'controller/auditor.py', 'controller/event_bus.py',
                 'controller/osken_manager.py', 'contracts/__init__.py', 'contracts/inventory.py',
                 'simulation/__init__.py', 'simulation/addressing.py',
                 'simulation/cpu_profiles.py')
TOKEN_FILE = 'ledger_token.txt'
TOKEN_ENV = 'ZTSDN_LEDGER_TOKEN'
# What a replica imports, and nothing else (checked by tests/test_demo_hosts.py
# by importing the replica from an extracted bundle with the repo off the path).
BUNDLE_PACKAGES = ('blockchain', 'contracts', 'trust_engine')
DEFAULT_PORTS = {'replica_http': 9101, 'replica_raft': 9001, 'dashboard': 8081,
                 'auditor_ofp': 6654, 'auditor_http': 8083}
OSES = ('windows', 'linux', 'mac')


class HostsError(ValueError):
    pass


@dataclass(frozen=True)
class Replica:
    rid: str
    host: str
    os: str
    http_port: int
    raft_port: int

    @property
    def http(self) -> str:
        return f'{self.host}:{self.http_port}'

    @property
    def raft(self) -> str:
        return f'{self.host}:{self.raft_port}'

    @property
    def script(self) -> str:
        return f'replica_{self.rid}.' + ('ps1' if self.os == 'windows' else 'sh')


@dataclass(frozen=True)
class Hosts:
    controller: str
    replicas: Tuple[Replica, ...]
    ports: Dict[str, int]
    auditor: Optional[Dict[str, str]] = None


_HOST_RE = re.compile(r'^[A-Za-z0-9.\-]+$')


def _host(v: Any, where: str) -> str:
    s = str(v or '').strip()
    if not s or not _HOST_RE.match(s):
        raise HostsError(f'{where}: {v!r} is not a host name or IPv4 address')
    return s


def load_hosts(path: Path) -> Hosts:
    if not path.exists():
        raise HostsError(f'{path} not found -- copy deploy/demo_hosts.example.yaml '
                         f'to it and fill in each laptop\'s hotspot address')
    raw = yaml.safe_load(path.read_text()) or {}
    ports = dict(DEFAULT_PORTS)
    ports.update({k: int(v) for k, v in (raw.get('ports') or {}).items()})
    ctrl = raw.get('controller') or {}
    controller = _host(ctrl.get('host') if isinstance(ctrl, dict) else ctrl, 'controller.host')

    reps: List[Replica] = []
    for rid, entry in (raw.get('replicas') or {}).items():
        if not isinstance(entry, dict):
            raise HostsError(f'replicas.{rid}: expected {{host: ..., os: ...}}')
        os_ = str(entry.get('os', 'linux')).lower()
        if os_ not in OSES:
            raise HostsError(f'replicas.{rid}.os: {os_!r} is not one of {OSES}')
        reps.append(Replica(
            rid=str(rid), host=_host(entry.get('host'), f'replicas.{rid}.host'), os=os_,
            http_port=int(entry.get('http_port', ports['replica_http'])),
            raft_port=int(entry.get('raft_port', ports['replica_raft'])),
        ))
    if len(reps) < 3 or len(reps) % 2 == 0:
        raise HostsError(f'{len(reps)} replica(s): a RAFT cluster that survives one '
                         f'loss needs an odd number, at least 3')
    endpoints = [(r.host, r.http_port) for r in reps] + [(r.host, r.raft_port) for r in reps]
    if len(set(endpoints)) != len(endpoints):
        raise HostsError('two replicas share a host:port -- give replicas on the same '
                         'machine their own http_port/raft_port')

    aud = raw.get('auditor')
    auditor = None
    if aud:
        auditor = {'host': _host(aud.get('host'), 'auditor.host'),
                   'os': str(aud.get('os', 'mac')).lower()}
    return Hosts(controller=controller, replicas=tuple(reps), ports=ports, auditor=auditor)


# --------------------------------------------------------------------------- #
# The derived config                                                           #
# --------------------------------------------------------------------------- #
def remote_config_text(base_text: str, hosts: Hosts) -> str:
    """The parent config with its ledger: block (the last top-level block)
    replaced and the recording path renamed. Text substitution, not
    load-and-dump, so every other line -- the trust: block above all -- is
    the parent's, comments included."""
    m = re.search(r'^ledger:\n', base_text, re.M)
    if not m:
        raise HostsError('the base config has no top-level ledger: block')
    rest = base_text[m.end():]
    if re.search(r'^\S', rest, re.M):
        raise HostsError('ledger: must be the last top-level block of the base config')
    head = base_text[:m.start()]
    head, n = re.subn(r'^(    record_path: data/events_review_demo[a-z_]*)\.jsonl$',
                      r'\1_remote.jsonl', head, flags=re.M)
    if n < 1:
        raise HostsError('expected a record_path: data/events_review_demo*.jsonl line')
    head = _with_auditor(head, hosts)
    head = ('# GENERATED by tools/demo_hosts.py from its config/ parent and\n'
            '# deploy/demo_hosts.yaml -- regenerate, do not edit. Differs from its\n'
            '# parent only in the recording paths, the ledger: block and where\n'
            '# the auditor runs.\n') + head
    lines = [
        'ledger:',
        '  backend: raft_remote',
        '  # One replica per laptop, on the hotspot. No launch_local: start them',
        '  # first (deploy/demo/replica_bundle.zip), then the controller.',
        '  replicas:',
        *[f'    {r.rid}: {r.http}' for r in hosts.replicas],
        '  # Hotspot links are slower and lossier than loopback; one lost commit',
        '  # round trip must not cost a batch.',
        '  request_timeout_s: 4.0',
        '  commit_deadline_s: 8.0',
        '  max_queue: 10000',
        '  verify: true',
        f'  auth_token_env: {TOKEN_ENV}',
        '',
    ]
    return head + '\n'.join(lines)


def _with_auditor(text: str, hosts: Hosts) -> str:
    """Drop any controller.auditor block (and the comment lines directly above
    it); when the hosts file names an auditor laptop, add one pointing there,
    with no launch_local -- it runs on that laptop, not beside the primary."""
    lines = text.split('\n')
    out: List[str] = []
    i = 0
    while i < len(lines):
        if lines[i] == '  auditor:':
            while out and out[-1].startswith('  #'):
                out.pop()
            i += 1
            while i < len(lines) and (lines[i].startswith('    ') or lines[i] == ''):
                if lines[i] == '' and not (i + 1 < len(lines) and lines[i + 1].startswith('    ')):
                    break
                i += 1
            continue
        out.append(lines[i])
        i += 1
    text = '\n'.join(out)
    if not hosts.auditor:
        return text
    m = re.search(r'^  dashboard:\n    enabled: true\n    record_path: data/(events_[a-z_]+)\.jsonl\n',
                  text, re.M)
    if not m:
        raise HostsError('no controller.dashboard block to place the auditor after')
    block = ('\n  # The read-only second controller (controller/auditor.py), on the\n'
             '  # auditor laptop: every switch is given it as a second controller.\n'
             '  auditor:\n'
             f'    address: {hosts.auditor["host"]}\n'
             f'    ofp_port: {hosts.ports["auditor_ofp"]}\n'
             f'    http_port: {hosts.ports["auditor_http"]}\n'
             f'    record_path: data/{m.group(1).replace("_remote", "")}_auditor_remote.jsonl\n')
    return text[:m.end()] + block + text[m.end():]


def raft_peers_arg(hosts: Hosts) -> str:
    return ','.join(f'{r.rid}={r.raft}' for r in hosts.replicas)


# --------------------------------------------------------------------------- #
# Launch scripts                                                               #
# --------------------------------------------------------------------------- #
def replica_ps1(r: Replica, hosts: Hosts) -> str:
    return f"""# Ledger replica {r.rid} -- GENERATED by tools/demo_hosts.py. Run from the
# unzipped replica_bundle folder:  powershell -ExecutionPolicy Bypass -File {r.script}
# Needs: Python 3 and PyYAML (py -3 -m pip install pyyaml).
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$env:{TOKEN_ENV} = (Get-Content -Raw '{TOKEN_FILE}').Trim()
$env:PYTHONPATH = $PSScriptRoot

# Inbound RAFT ({r.raft_port}) and control API ({r.http_port}). Needs an
# Administrator shell once; a hotspot is usually a 'Public' network, hence -Profile Any.
if (-not (Get-NetFirewallRule -DisplayName 'ZTSDN ledger replica' -ErrorAction SilentlyContinue)) {{
  try {{
    New-NetFirewallRule -DisplayName 'ZTSDN ledger replica' -Direction Inbound -Protocol TCP `
      -LocalPort {r.raft_port},{r.http_port} -Action Allow -Profile Any | Out-Null
    Write-Host 'firewall rule added'
  }} catch {{
    Write-Warning 'Could not add the firewall rule (not Administrator?). Run this once as Administrator, or other laptops cannot reach this replica.'
  }}
}}

# One chain per run, as launch_local's fresh: true.
Remove-Item -Recurse -Force 'raft_data\\{r.rid}' -ErrorAction SilentlyContinue
$replicaArgs = @('-m', 'blockchain.raft_replica', '--id', '{r.rid}', '--peers', '{raft_peers_arg(hosts)}',
          '--http-host', '0.0.0.0', '--http-port', '{r.http_port}', '--commit-timeout-s', '2.0',
          '--data-dir', 'raft_data', '--auth-token-env', '{TOKEN_ENV}',
          '--verify-config', '{REMOTE_CONFIG}')
if (Get-Command py -ErrorAction SilentlyContinue) {{ & py -3 @replicaArgs }} else {{ & python @replicaArgs }}
"""


def replica_sh(r: Replica, hosts: Hosts) -> str:
    return f"""#!/bin/sh
# Ledger replica {r.rid} -- GENERATED by tools/demo_hosts.py. Run from the
# unzipped replica_bundle folder:  sh {r.script}
# Needs: Python 3 and PyYAML (python3 -m pip install --user pyyaml; no sudo).
set -e
cd "$(dirname "$0")"
{TOKEN_ENV}="$(tr -d ' \\r\\n' < {TOKEN_FILE})"
export {TOKEN_ENV}
PYTHONPATH="$(pwd)"
export PYTHONPATH
python3 -c 'import yaml' 2>/dev/null || {{
  echo "PyYAML missing: python3 -m pip install --user pyyaml" >&2; exit 1; }}
# One chain per run, as launch_local's fresh: true.
rm -rf "raft_data/{r.rid}"
exec python3 -m blockchain.raft_replica --id {r.rid} --peers '{raft_peers_arg(hosts)}' \\
  --http-host 0.0.0.0 --http-port {r.http_port} --commit-timeout-s 2.0 \\
  --data-dir raft_data --auth-token-env {TOKEN_ENV} --verify-config {REMOTE_CONFIG}
"""


def run_controller_sh(hosts: Hosts) -> str:
    return f"""#!/bin/sh
# Laptop A: the primary controller + Mininet, against the remote replicas.
# GENERATED by tools/demo_hosts.py.
#   sh deploy/demo/run_controller_A.sh          # the main demo
#   sh deploy/demo/run_controller_A.sh forge    # the auditor scene (forging primary)
# Checks the replicas first (a leader must be elected). sudo resets the
# environment, so the token goes on the command line instead of being inherited.
set -e
cd "$(dirname "$0")/../.."
TOKEN="$(tr -d ' \\r\\n' < deploy/demo/{TOKEN_FILE})"
python3 tools/demo_hosts.py --check --wait-leader 20
if [ "$1" = "forge" ]; then
  exec sudo env {TOKEN_ENV}="$TOKEN" ZTSDN_ALLOW_FORGERY=1 python3 run_demo.py --mode mininet \\
    --config deploy/demo/{FORGE_REMOTE_CONFIG}
fi
exec sudo env {TOKEN_ENV}="$TOKEN" python3 run_demo.py --mode mininet \\
  --config deploy/demo/{REMOTE_CONFIG}
"""


def auditor_sh(hosts: Hosts) -> str:
    ofp, http = hosts.ports['auditor_ofp'], hosts.ports['auditor_http']
    return f"""#!/bin/sh
# The read-only auditor controller -- GENERATED by tools/demo_hosts.py.
# On the auditor laptop, from the unzipped auditor_bundle folder:
#   sh auditor_mac.sh            # for the main demo
#   sh auditor_mac.sh forge      # for the auditor scene
# Restart it for each run: its verdicts are per run.
# First run builds a venv with os-ken and PyYAML (needs internet once).
# macOS will ask whether python may accept incoming connections: Allow
# (laptop A's switches connect to port {ofp}; viewers read port {http}).
set -e
cd "$(dirname "$0")"
PY="$(command -v python3.12 || command -v python3.11 || command -v python3.10 || command -v python3)"
[ -d .venv ] || "$PY" -m venv .venv
.venv/bin/python -c 'import os_ken, yaml' 2>/dev/null || .venv/bin/pip install os-ken pyyaml
CFG={REMOTE_CONFIG}
[ "$1" = "forge" ] && CFG={FORGE_REMOTE_CONFIG}
mkdir -p data
PYTHONPATH="$(pwd)" ZTSDN_CONFIG="$CFG" exec .venv/bin/python -m controller.osken_manager \\
  --ofp-port {ofp} controller.auditor
"""


def portproxy_ps1(hosts: Hosts) -> str:
    port = hosts.ports['dashboard']
    return f"""# Laptop A, Windows side, in an ADMINISTRATOR PowerShell. GENERATED by
# tools/demo_hosts.py. Lets the other laptops open the dashboard at
#   http://{hosts.controller}:{port}/
# WSL2's address changes at every reboot, so it is read fresh here; re-run this
# after any reboot. (Fallback: WSL mirrored networking, networkingMode=mirrored
# in %UserProfile%\\.wslconfig, then `wsl --shutdown`.)
$ErrorActionPreference = 'Stop'
$wsl = (wsl.exe hostname -I).Trim().Split(' ')[0]
if (-not $wsl) {{ throw 'Could not read the WSL address (is the distro running?)' }}
netsh interface portproxy delete v4tov4 listenport={port} listenaddress=0.0.0.0 2>$null | Out-Null
netsh interface portproxy add v4tov4 listenport={port} listenaddress=0.0.0.0 connectport={port} connectaddress=$wsl
if (-not (Get-NetFirewallRule -DisplayName 'ZTSDN dashboard' -ErrorAction SilentlyContinue)) {{
  New-NetFirewallRule -DisplayName 'ZTSDN dashboard' -Direction Inbound -Protocol TCP `
    -LocalPort {port} -Action Allow -Profile Any | Out-Null
}}
Write-Host "dashboard: http://{hosts.controller}:{port}/  ->  WSL $wsl`:{port}"
netsh interface portproxy show v4tov4
"""


# --------------------------------------------------------------------------- #
# Writing                                                                      #
# --------------------------------------------------------------------------- #
def ensure_token(out: Path) -> str:
    path = out / TOKEN_FILE
    if path.exists() and path.read_text().strip():
        return path.read_text().strip()
    token = secrets.token_hex(24)
    path.write_text(token + '\n')
    path.chmod(0o600)
    return token


def bundle_files(root: Path = ROOT) -> List[Path]:
    files: List[Path] = []
    for pkg in BUNDLE_PACKAGES:
        files += sorted(p for p in (root / pkg).rglob('*.py') if '__pycache__' not in p.parts)
    return files


def generate(hosts: Hosts, base: Path = DEFAULT_BASE, out: Path = DEFAULT_OUT,
             root: Path = ROOT) -> Dict[str, Path]:
    out.mkdir(parents=True, exist_ok=True)
    written: Dict[str, Path] = {}

    def write(name: str, text: str, mode: int = 0o644) -> None:
        p = out / name
        p.write_text(text, newline='\n' if not name.endswith('.ps1') else '\r\n')
        p.chmod(mode)
        written[name] = p

    ensure_token(out)
    written[TOKEN_FILE] = out / TOKEN_FILE
    write(REMOTE_CONFIG, remote_config_text(base.read_text(), hosts))
    forge = base.parent / FORGE_BASE.name
    if forge.exists():
        write(FORGE_REMOTE_CONFIG, remote_config_text(forge.read_text(), hosts))
    scripts = {}
    for r in hosts.replicas:
        text = replica_ps1(r, hosts) if r.os == 'windows' else replica_sh(r, hosts)
        scripts[r.script] = text
        write(r.script, text, 0o755)
    write('run_controller_A.sh', run_controller_sh(hosts), 0o755)
    write('portproxy_A.ps1', portproxy_ps1(hosts))

    zpath = out / 'replica_bundle.zip'
    with zipfile.ZipFile(zpath, 'w', zipfile.ZIP_DEFLATED) as z:
        for f in bundle_files(root):
            z.write(f, f'replica_bundle/{f.relative_to(root).as_posix()}')
        z.write(out / REMOTE_CONFIG, f'replica_bundle/{REMOTE_CONFIG}')
        z.write(out / TOKEN_FILE, f'replica_bundle/{TOKEN_FILE}')
        for name in scripts:
            z.write(out / name, f'replica_bundle/{name}')
    written['replica_bundle.zip'] = zpath

    if hosts.auditor:
        write('auditor_mac.sh', auditor_sh(hosts), 0o755)
        apath = out / 'auditor_bundle.zip'
        with zipfile.ZipFile(apath, 'w', zipfile.ZIP_DEFLATED) as z:
            for rel in AUDITOR_FILES:
                z.write(root / rel, f'auditor_bundle/{rel}')
            for name in (REMOTE_CONFIG, FORGE_REMOTE_CONFIG, 'auditor_mac.sh'):
                if (out / name).exists():
                    z.write(out / name, f'auditor_bundle/{name}')
        written['auditor_bundle.zip'] = apath
    return written


# --------------------------------------------------------------------------- #
# --check                                                                      #
# --------------------------------------------------------------------------- #
def tcp_open(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def replica_status(r: Replica, token: Optional[str], timeout: float = 1.5) -> Optional[Dict[str, Any]]:
    try:
        conn = http.client.HTTPConnection(r.host, r.http_port, timeout=timeout)
        conn.request('GET', '/status',
                     headers={'Authorization': f'Bearer {token}'} if token else {})
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        if resp.status != 200:
            return {'error': f'HTTP {resp.status}'}
        return json.loads(body or b'{}')
    except (OSError, ValueError, http.client.HTTPException):
        return None


def check(hosts: Hosts, token: Optional[str], wait_leader_s: float = 0.0,
          controller_running: bool = False) -> bool:
    """Print one line per probe; True when every replica answers and one leads."""
    ok = True
    deadline = time.monotonic() + wait_leader_s
    while True:
        leaders = set()
        lines: List[str] = []
        up = 0
        for r in hosts.replicas:
            st = replica_status(r, token)
            raft = tcp_open(r.host, r.raft_port)
            if st is None:
                lines.append(f'  FAIL  {r.rid} control API {r.http} unreachable')
            elif 'error' in st:
                lines.append(f'  FAIL  {r.rid} control API {r.http}: {st["error"]}'
                             + (' (wrong or missing token?)' if st['error'] == 'HTTP 401' else ''))
            else:
                up += 1
                if st.get('role') == 'leader':
                    leaders.add(r.rid)
                lines.append(f'  OK    {r.rid} {r.http}: {st.get("role")}, term {st.get("term")}, '
                             f'leader {st.get("leader_id")}, chain {st.get("chain_length")}, '
                             f'verifying={st.get("verifying")}')
            if not raft:
                lines.append(f'  FAIL  {r.rid} RAFT port {r.raft} unreachable from here')
        if leaders or time.monotonic() >= deadline:
            break
        time.sleep(1.0)
    print('==> Ledger replicas')
    print('\n'.join(lines))
    majority = len(hosts.replicas) // 2 + 1
    if up < majority:
        print(f'  FAIL  only {up}/{len(hosts.replicas)} replicas answer; a leader needs {majority}')
        ok = False
    if not leaders:
        print('  FAIL  no replica reports itself leader' +
              (f' after {wait_leader_s:.0f}s' if wait_leader_s else ' (try --wait-leader 30)'))
        ok = False
    elif len(leaders) > 1:
        print(f'  WARN  more than one replica says leader ({sorted(leaders)}): a term change '
              f'in progress; check again')
    else:
        print(f'  OK    leader is {leaders.pop()}')
    if any(line.startswith('  FAIL') and 'RAFT port' in line for line in lines):
        ok = False

    if controller_running:
        print('==> Dashboard (through portproxy_A.ps1)')
        port = hosts.ports['dashboard']
        if tcp_open(hosts.controller, port):
            print(f'  OK    http://{hosts.controller}:{port}/')
        else:
            print(f'  FAIL  {hosts.controller}:{port} closed -- run portproxy_A.ps1 as '
                  f'Administrator on laptop A, and check the controller is up')
            ok = False
    if hosts.auditor:
        print('==> Auditor (reachability only)')
        for name, port in (('OpenFlow', hosts.ports['auditor_ofp']),
                           ('status API', hosts.ports['auditor_http'])):
            state = 'OK  ' if tcp_open(hosts.auditor['host'], port) else 'WARN'
            print(f'  {state}  auditor {name} {hosts.auditor["host"]}:{port}')
    return ok


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--hosts', type=Path, default=DEFAULT_HOSTS)
    ap.add_argument('--base', type=Path, default=DEFAULT_BASE)
    ap.add_argument('--out', type=Path, default=DEFAULT_OUT)
    ap.add_argument('--check', action='store_true', help='probe every role instead of generating')
    ap.add_argument('--wait-leader', type=float, default=0.0, metavar='S',
                    help='with --check: keep polling up to S seconds for a leader')
    ap.add_argument('--dashboard', action='store_true',
                    help='with --check: also probe the dashboard on laptop A (controller running)')
    args = ap.parse_args(argv)
    try:
        hosts = load_hosts(args.hosts)
    except HostsError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2
    if args.check:
        tok_path = args.out / TOKEN_FILE
        token = tok_path.read_text().strip() if tok_path.exists() else None
        if token is None:
            print(f'warning: no {tok_path}; probing without a token', file=sys.stderr)
        return 0 if check(hosts, token, args.wait_leader, args.dashboard) else 1
    try:
        written = generate(hosts, args.base, args.out)
    except HostsError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2
    for name, p in written.items():
        print(f'wrote {p.relative_to(ROOT) if p.is_relative_to(ROOT) else p}')
    print('\nNext: copy replica_bundle.zip to each replica laptop, unzip, run its script'
          + ('; auditor_bundle.zip to the auditor laptop, unzip, sh auditor_mac.sh' if hosts.auditor else '')
          + ';\nthen: python3 tools/demo_hosts.py --check --wait-leader 30')
    return 0


if __name__ == '__main__':
    sys.exit(main())
