"""tools/demo_hosts.py: the multi-laptop review demo's generator.

What matters on the day, and so what is pinned here:

  * the derived config differs from config/params_review_demo.yaml in the
    ledger: block and the recording path ONLY -- the replicas re-verify every
    trust record against the trust: block, so a drift there would make them
    reject an honest controller;
  * the replica bundle is self-contained: it runs on a laptop that has
    Python and PyYAML and none of this repository;
  * the launch scripts it ships actually start a cluster that elects a
    leader and survives losing one replica (the "close the lid" scene).
"""

import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'tools'))
import demo_hosts as dh  # noqa: E402

BASE = Path('config/params_review_demo.yaml')


def _free_ports(n):
    socks, ports = [], []
    for _ in range(n):
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        socks.append(s)
        ports.append(s.getsockname()[1])
    for s in socks:
        s.close()
    return ports


def _hosts_file(tmp_path, ports=None, os_='linux'):
    ports = ports or [9101, 9102, 9103, 9001, 9002, 9003]
    text = yaml.safe_dump({
        'controller': {'host': '127.0.0.1'},
        'replicas': {
            f'n{i + 1}': {'host': '127.0.0.1', 'os': os_,
                          'http_port': ports[i], 'raft_port': ports[i + 3]}
            for i in range(3)
        },
    })
    p = tmp_path / 'demo_hosts.yaml'
    p.write_text(text)
    return p


def test_the_example_hosts_file_loads():
    hosts = dh.load_hosts(Path('deploy/demo_hosts.example.yaml'))
    assert [r.rid for r in hosts.replicas] == ['n1', 'n2', 'n3']
    assert [r.os for r in hosts.replicas] == ['windows', 'windows', 'linux']
    assert hosts.replicas[0].http == '192.168.43.11:9101'


@pytest.mark.parametrize('bad, msg', [
    ({'controller': {'host': '1.2.3.4'}, 'replicas': {
        'n1': {'host': '1.1.1.1'}, 'n2': {'host': '1.1.1.2'}}}, 'odd number'),
    ({'controller': {'host': '1.2.3.4'}, 'replicas': {
        'n1': {'host': '1.1.1.1'}, 'n2': {'host': '1.1.1.1'}, 'n3': {'host': '1.1.1.3'}}},
     'share a host:port'),
    ({'controller': {'host': 'not an ip!'}, 'replicas': {}}, 'not a host'),
    ({'controller': {'host': '1.2.3.4'}, 'replicas': {
        'n1': {'host': '1.1.1.1', 'os': 'beos'}, 'n2': {'host': '1.1.1.2'},
        'n3': {'host': '1.1.1.3'}}}, 'not one of'),
])
def test_bad_hosts_files_are_refused(tmp_path, bad, msg):
    p = tmp_path / 'h.yaml'
    p.write_text(yaml.safe_dump(bad))
    with pytest.raises(dh.HostsError, match=msg):
        dh.load_hosts(p)


def test_the_derived_config_changes_only_the_ledger_and_recording(tmp_path):
    hosts = dh.load_hosts(Path('deploy/demo_hosts.example.yaml'))
    base = yaml.safe_load(BASE.read_text())
    derived = yaml.safe_load(dh.remote_config_text(BASE.read_text(), hosts))

    assert derived['trust'] == base['trust']          # what the replicas re-verify against
    for key in set(base) - {'ledger', 'controller'}:
        assert derived[key] == base[key], key
    ctrl_b, ctrl_d = dict(base['controller']), dict(derived['controller'])
    assert ctrl_d.pop('dashboard')['record_path'] == 'data/events_review_demo_remote.jsonl'
    ctrl_b.pop('dashboard')
    assert ctrl_d == ctrl_b

    led = derived['ledger']
    assert led['backend'] == 'raft_remote'
    assert 'launch_local' not in led
    assert led['verify'] is True
    assert led['auth_token_env'] == dh.TOKEN_ENV
    assert led['replicas'] == {'n1': '192.168.43.11:9101', 'n2': '192.168.43.12:9101',
                               'n3': '192.168.43.13:9101'}


def test_the_verifier_hash_matches_between_controller_and_replicas():
    """The controller sends config_hash(trust) with every batch; a replica
    built from the derived file must compute the same one."""
    from blockchain.verifier import TrustReplay, config_hash
    hosts = dh.load_hosts(Path('deploy/demo_hosts.example.yaml'))
    derived = yaml.safe_load(dh.remote_config_text(BASE.read_text(), hosts))
    base = yaml.safe_load(BASE.read_text())
    assert TrustReplay(derived['trust']).hash == config_hash(base['trust'])


def test_generated_files_and_scripts(tmp_path):
    hosts = dh.load_hosts(Path('deploy/demo_hosts.example.yaml'))
    out = tmp_path / 'demo'
    written = dh.generate(hosts, BASE, out)
    for name in ('params_review_demo_remote.yaml', 'ledger_token.txt', 'replica_n1.ps1',
                 'replica_n2.ps1', 'replica_n3.sh', 'run_controller_A.sh', 'portproxy_A.ps1',
                 'replica_bundle.zip'):
        assert name in written, name
    token = (out / 'ledger_token.txt').read_text().strip()
    assert len(token) >= 32
    # Kept across regenerations: running replicas must stay valid.
    dh.generate(hosts, BASE, out)
    assert (out / 'ledger_token.txt').read_text().strip() == token

    ps1 = (out / 'replica_n1.ps1').read_bytes().decode()
    assert '\r\n' in ps1                                      # Windows line endings
    assert "'--id', 'n1'" in ps1
    assert 'n1=192.168.43.11:9001,n2=192.168.43.12:9001,n3=192.168.43.13:9001' in ps1
    assert '$args' not in ps1                                 # PowerShell's automatic variable
    sh = (out / 'replica_n3.sh').read_text()
    assert '--id n3' in sh and '--verify-config params_review_demo_remote.yaml' in sh
    run = (out / 'run_controller_A.sh').read_text()
    assert f'sudo env {dh.TOKEN_ENV}=' in run                 # sudo drops the environment
    assert 'deploy/demo/params_review_demo_remote.yaml' in run
    assert '8081' in (out / 'portproxy_A.ps1').read_text()

    names = zipfile.ZipFile(out / 'replica_bundle.zip').namelist()
    assert 'replica_bundle/blockchain/raft_replica.py' in names
    assert 'replica_bundle/trust_engine/trust_calculator.py' in names
    assert 'replica_bundle/params_review_demo_remote.yaml' in names
    assert 'replica_bundle/replica_n1.ps1' in names
    assert not any('__pycache__' in n for n in names)


def _python_without_repo():
    env = {k: v for k, v in os.environ.items() if k != 'PYTHONPATH'}
    return env


@pytest.mark.skipif(sys.platform == 'win32', reason='uses the .sh launch scripts')
def test_the_bundle_runs_a_cluster_that_survives_losing_its_leader(tmp_path):
    """Unzip the bundle into an empty directory, start the three generated
    scripts from there (the repository is not on the path), wait for a
    leader through --check, kill it, and require a new one."""
    pytest.importorskip('yaml')
    ports = _free_ports(6)
    hosts = dh.load_hosts(_hosts_file(tmp_path, ports))
    out = tmp_path / 'demo'
    dh.generate(hosts, BASE, out)
    site = tmp_path / 'laptop'
    site.mkdir()
    with zipfile.ZipFile(out / 'replica_bundle.zip') as z:
        z.extractall(site)
    bundle = site / 'replica_bundle'

    # The bundle alone must import the replica.
    probe = subprocess.run([sys.executable, '-c', 'import blockchain.raft_replica'],
                           cwd=bundle, env=_python_without_repo(), capture_output=True, text=True)
    assert probe.returncode == 0, probe.stderr

    procs = {}
    try:
        for r in hosts.replicas:
            procs[r.rid] = subprocess.Popen(
                ['sh', str(bundle / r.script)], cwd=bundle, env=_python_without_repo(),
                stdout=open(tmp_path / f'{r.rid}.log', 'w'), stderr=subprocess.STDOUT,
                start_new_session=True)
        token = (out / 'ledger_token.txt').read_text().strip()
        assert dh.check(hosts, token, wait_leader_s=20), \
            '\n'.join((tmp_path / f'{r}.log').read_text() for r in procs)

        leader = next(r for r in hosts.replicas
                      if (dh.replica_status(r, token) or {}).get('role') == 'leader')
        st = dh.replica_status(leader, token)
        assert st['verifying'] is True
        assert dh.replica_status(leader, None) == {'error': 'HTTP 401'}   # token enforced

        os.killpg(procs[leader.rid].pid, signal.SIGKILL)       # close the lid
        procs[leader.rid].wait(timeout=5)
        rest = [r for r in hosts.replicas if r.rid != leader.rid]
        deadline = time.monotonic() + 20
        new = None
        while time.monotonic() < deadline and new is None:
            for r in rest:
                if (dh.replica_status(r, token) or {}).get('role') == 'leader':
                    new = r.rid
            time.sleep(0.3)
        assert new is not None and new != leader.rid
    finally:
        for p in procs.values():
            if p.poll() is None:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait(timeout=5)


def test_check_reports_unreachable_replicas(tmp_path, capsys):
    ports = _free_ports(6)
    hosts = dh.load_hosts(_hosts_file(tmp_path, ports))
    assert dh.check(hosts, 'x', wait_leader_s=0) is False
    out = capsys.readouterr().out
    assert 'unreachable' in out and 'no replica reports itself leader' in out


def test_the_committed_tree_ignores_the_generated_output():
    gi = Path('.gitignore').read_text()
    assert 'deploy/demo_hosts.yaml' in gi and 'deploy/demo/' in gi


# --------------------------------------------------------------------------- #
# The auditor laptop and the forge scene                                       #
# --------------------------------------------------------------------------- #
def _hosts_with_auditor(tmp_path):
    raw = yaml.safe_load(Path('deploy/demo_hosts.example.yaml').read_text())
    raw['auditor'] = {'host': '192.168.43.14', 'os': 'mac'}
    p = tmp_path / 'hosts_aud.yaml'
    p.write_text(yaml.safe_dump(raw))
    return dh.load_hosts(p)


def test_the_two_scenes_share_one_trust_block_and_ledger():
    """The replicas verify against ONE config's trust: block for both runs."""
    main = yaml.safe_load(BASE.read_text())
    forge = yaml.safe_load(dh.FORGE_BASE.read_text())
    assert main['trust'] == forge['trust']
    assert main['ledger'] == forge['ledger']


def test_the_auditor_moves_to_its_laptop_in_both_scenes(tmp_path):
    hosts = _hosts_with_auditor(tmp_path)
    for base in (BASE, dh.FORGE_BASE):
        text = dh.remote_config_text(base.read_text(), hosts)
        assert text.count('\n  auditor:\n') == 1
        aud = yaml.safe_load(text)['controller']['auditor']
        assert aud['address'] == '192.168.43.14' and aud['ofp_port'] == 6654
        assert 'launch_local' not in aud                     # it runs on the Mac
    forge = yaml.safe_load(dh.remote_config_text(dh.FORGE_BASE.read_text(), hosts))
    assert forge['controller']['debug_forge_trust']['node'] == 'srv3'
    assert forge['controller']['witness'] == {'enabled': False}


def test_without_an_auditor_laptop_no_config_names_one(tmp_path):
    hosts = dh.load_hosts(Path('deploy/demo_hosts.example.yaml'))
    for base in (BASE, dh.FORGE_BASE):
        cfg = yaml.safe_load(dh.remote_config_text(base.read_text(), hosts))
        assert 'auditor' not in cfg['controller']


def test_the_forge_scene_runs_with_the_forgery_gate(tmp_path):
    hosts = _hosts_with_auditor(tmp_path)
    out = tmp_path / 'demo'
    dh.generate(hosts, BASE, out)
    run = (out / 'run_controller_A.sh').read_text()
    forge_line = [l for l in run.splitlines() if dh.FORGE_REMOTE_CONFIG in l]
    assert forge_line
    assert 'ZTSDN_ALLOW_FORGERY=1' in run
    # ...and only on the forge branch: the main run never forges.
    main_exec = run[run.rindex('exec sudo'):]
    assert 'FORGERY' not in main_exec and dh.REMOTE_CONFIG in main_exec


def test_the_auditor_bundle_imports_on_its_own(tmp_path):
    pytest.importorskip('os_ken')
    hosts = _hosts_with_auditor(tmp_path)
    out = tmp_path / 'demo'
    written = dh.generate(hosts, BASE, out)
    assert 'auditor_bundle.zip' in written and 'auditor_mac.sh' in written
    site = tmp_path / 'mac'
    with zipfile.ZipFile(out / 'auditor_bundle.zip') as z:
        z.extractall(site)
    bundle = site / 'auditor_bundle'
    code = ('import yaml\n'
            'from controller.auditor import SwitchAudit, AuditorApp\n'
            'from contracts.inventory import Inventory\n'
            f'cfg = yaml.safe_load(open("{dh.FORGE_REMOTE_CONFIG}"))\n'
            'inv = Inventory.from_config(cfg)\n'
            'assert len(inv.servers) == 8, inv.servers\n'
            'print("ok")\n')
    probe = subprocess.run([sys.executable, '-c', code], cwd=bundle,
                           env=_python_without_repo(), capture_output=True, text=True)
    assert probe.returncode == 0 and probe.stdout.strip() == 'ok', probe.stderr
    sh = (bundle / 'auditor_mac.sh').read_text()
    assert '--ofp-port 6654 controller.auditor' in sh
    assert 'pip install os-ken pyyaml' in sh
