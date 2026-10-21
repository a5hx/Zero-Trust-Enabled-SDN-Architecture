"""Phase 4: admission by attestation (security/attestation.py, the attester
sidecar in simulation/attester.py, and the controller's admission filter).

The properties that matter:
  * the measurement is taken from OUTSIDE the agent and follows the code the
    process actually runs -- a tampered copy measures differently, the genuine
    one matches the reference, and an ambiguous launch is refused, not guessed;
  * a quote is bound to its nonce, its node's key and its source address;
  * a node the verifier has not admitted is never chosen, not even for a
    probation trial, and a refusal revokes admission at once.
"""

import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
import yaml

from security import attestation as at
from simulation import attester

REPO = Path(__file__).resolve().parent.parent


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def _cfg(tmp_path, **kw):
    return at.AttestationConfig(enabled=True, key_dir=str(tmp_path / 'keys'),
                                reference_root=str(REPO),
                                reference_interpreter=sys.executable, **kw)


def _verifier(tmp_path, clock=None, **kw):
    cfg = _cfg(tmp_path, **kw)
    at.provision_keys(['srv1', 'srv2'], Path(cfg.key_dir))
    return at.AttestationVerifier(cfg, at.reference_components(cfg),
                                  expected_ips={'srv1': '10.0.0.101'},
                                  clock=clock or Clock())


def _key(tmp_path, node):
    return bytes.fromhex((tmp_path / 'keys' / f'{node}.key').read_text())


def _quote(v, tmp_path, node, comps=None, key=None):
    comps = comps if comps is not None else v.reference
    nonce = v.issue_challenge(node)
    m = at.extend(comps)
    return comps, m, at.sign_quote(key or _key(tmp_path, node), node, nonce, m)


def _tampered_tree(root):
    for rel in at.module_files(at.AGENT_MODULE):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes((REPO / rel).read_bytes())
    agent = root / at.module_files(at.AGENT_MODULE)[-1]
    agent.write_text(agent.read_text() + attester.TAMPER_MARK)
    return root


# --------------------------------------------------------------------------- #
# Measurement                                                                  #
# --------------------------------------------------------------------------- #
def test_extend_depends_on_order_role_and_digest():
    a, b = ('x', '00' * 32), ('y', '11' * 32)
    base = at.extend([a, b])
    assert base != at.extend([b, a])
    assert base != at.extend([('z', a[1]), b])
    assert base != at.extend([a, ('y', '12' + '11' * 31)])
    assert base != at.extend([a])


def test_module_files_include_the_package_init():
    assert at.module_files('simulation.node_agent') == ['simulation/__init__.py',
                                                        'simulation/node_agent.py']


@pytest.mark.parametrize('argv,env', [
    (['python3', '-I', '-m', 'simulation.node_agent'], {}),
    (['python3', '-P', '-m', 'simulation.node_agent'], {}),
    (['python3', '-uE', '-m', 'simulation.node_agent'], {}),
    (['python3', 'simulation/node_agent.py'], {}),
    (['python3', '-c', 'import x'], {}),
    (['python3', '-u', '-m', 'simulation.node_agent'], {'PYTHONPATH': '/tmp/evil'}),
    (['bash', '-c', 'x'], {}),
])
def test_ambiguous_launches_are_refused_not_guessed(argv, env):
    with pytest.raises(at.MeasurementError):
        at.resolve_python_module(argv, env)


def test_plain_module_launch_resolves():
    assert at.resolve_python_module(
        ['/usr/bin/python3', '-u', '-m', 'simulation.node_agent', '--node-id', 'srv1'], {}
    ) == 'simulation.node_agent'


def _spawn_agent(cwd):
    p = subprocess.Popen(
        [sys.executable, '-u', '-m', 'simulation.node_agent', '--node-id', 'srvT', '--port', '0'],
        cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={k: v for k, v in os.environ.items() if k not in ('PYTHONPATH', 'PYTHONHOME')})
    # Popen can return while execve is still setting up the new image, when
    # /proc/<pid>/cmdline reads empty. The live attester never sees that
    # window: it finds the agent with pgrep -f, which needs the command line.
    deadline = time.monotonic() + 5
    while not Path(f'/proc/{p.pid}/cmdline').read_bytes() and time.monotonic() < deadline:
        time.sleep(0.01)
    return p


@pytest.fixture
def genuine_agent():
    p = _spawn_agent(REPO)
    yield p
    p.kill()
    p.wait()


def test_genuine_agent_measures_as_the_reference(tmp_path, genuine_agent):
    ref = at.reference_components(_cfg(tmp_path))
    assert at.measure_process(genuine_agent.pid) == ref


def test_tampered_agent_measures_differently_in_its_module_only(tmp_path):
    p = _spawn_agent(_tampered_tree(tmp_path / 'img'))
    try:
        got = dict(at.measure_process(p.pid))
    finally:
        p.kill()
        p.wait()
    ref = dict(at.reference_components(_cfg(tmp_path)))
    assert [r for r in ref if ref[r] != got[r]] == ['simulation/node_agent.py']


def test_a_process_running_something_else_is_unmeasurable():
    p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
    try:
        with pytest.raises(at.MeasurementError):
            at.measure_process(p.pid)
    finally:
        p.kill()
        p.wait()


# --------------------------------------------------------------------------- #
# Verifier                                                                     #
# --------------------------------------------------------------------------- #
def test_good_quote_admits(tmp_path):
    v = _verifier(tmp_path)
    comps, m, sig = _quote(v, tmp_path, 'srv1')
    assert not v.is_admitted('srv1')
    assert v.verify('srv1', comps, m, sig, '10.0.0.101').ok
    assert v.is_admitted('srv1') and not v.is_admitted('srv2')


def test_a_nonce_is_good_once(tmp_path):
    v = _verifier(tmp_path)
    comps, m, sig = _quote(v, tmp_path, 'srv2')
    assert v.verify('srv2', comps, m, sig).ok
    assert v.verify('srv2', comps, m, sig).verdict == at.NO_CHALLENGE


def test_stale_nonce_is_refused(tmp_path):
    clock = Clock()
    v = _verifier(tmp_path, clock)
    comps, m, sig = _quote(v, tmp_path, 'srv2')
    clock.t += at.NONCE_TTL_S + 1
    assert v.verify('srv2', comps, m, sig).verdict == at.NONCE_EXPIRED


def test_another_nodes_key_is_a_bad_signature(tmp_path):
    v = _verifier(tmp_path)
    comps, m, sig = _quote(v, tmp_path, 'srv2', key=_key(tmp_path, 'srv1'))
    assert v.verify('srv2', comps, m, sig).verdict == at.BAD_SIGNATURE


def test_a_quote_from_the_wrong_host_is_refused(tmp_path):
    v = _verifier(tmp_path)
    comps, m, sig = _quote(v, tmp_path, 'srv1')
    assert v.verify('srv1', comps, m, sig, '10.0.0.102').verdict == at.IP_PIN


def test_components_must_extend_to_the_signed_measurement(tmp_path):
    v = _verifier(tmp_path)
    comps, m, sig = _quote(v, tmp_path, 'srv2')
    lied = list(comps)
    lied[-1] = (lied[-1][0], 'ab' * 32)
    assert v.verify('srv2', lied, m, sig).verdict == at.MALFORMED


def test_no_key_on_file_is_refused(tmp_path):
    v = _verifier(tmp_path)
    comps, m, sig = _quote(v, tmp_path, 'srv3', key=_key(tmp_path, 'srv1'))
    assert v.verify('srv3', comps, m, sig).verdict == at.UNKNOWN_KEY


def test_tampered_measurement_is_refused_and_names_the_file(tmp_path):
    v = _verifier(tmp_path)
    img = _tampered_tree(tmp_path / 'img')
    interp = Path(os.path.realpath(sys.executable))
    comps = at.measure_tree(img, interpreter=interp)
    c, m, sig = _quote(v, tmp_path, 'srv2', comps=comps)
    verdict = v.verify('srv2', c, m, sig)
    assert verdict.verdict == at.NOT_IN_ALLOWLIST
    assert verdict.mismatched == ['simulation/node_agent.py']
    assert not v.is_admitted('srv2')


def test_refusal_revokes_admission_at_once(tmp_path):
    v = _verifier(tmp_path)
    assert v.verify('srv2', *_quote(v, tmp_path, 'srv2')).ok
    v.report_unmeasurable('srv2', 'no agent process')
    assert not v.is_admitted('srv2')
    assert v.status()['srv2'] == at.UNMEASURABLE


def test_admission_lapses_without_a_fresh_quote(tmp_path):
    clock = Clock()
    v = _verifier(tmp_path, clock, reattest_s=10.0, validity_s=25.0)
    assert v.verify('srv2', *_quote(v, tmp_path, 'srv2')).ok
    clock.t += 24.0
    assert v.is_admitted('srv2') and v.sweep() == []
    assert v.verify('srv2', *_quote(v, tmp_path, 'srv2')).ok      # renewed
    clock.t += 24.0
    assert v.is_admitted('srv2')
    clock.t += 2.0
    assert not v.is_admitted('srv2')
    assert v.sweep() == ['srv2'] and v.sweep() == []
    assert v.status()['srv2'] == 'expired'


def test_config_rejects_unknown_keys_and_a_validity_inside_the_period():
    with pytest.raises(ValueError):
        at.AttestationConfig.from_config({'attestation': {'enabled': True, 'renew_s': 5}})
    with pytest.raises(ValueError):
        at.AttestationConfig.from_config({'attestation': {'reattest_s': 30, 'validity_s': 30}})
    assert at.AttestationConfig.from_config({}).enabled is False


def test_private_keys_are_owner_only(tmp_path):
    at.provision_keys(['srv1'], tmp_path)
    assert (tmp_path / 'srv1.key').stat().st_mode & 0o077 == 0
    assert len(bytes.fromhex((tmp_path / 'srv1.pub').read_text())) == 32


# --------------------------------------------------------------------------- #
# Admission in routing                                                         #
# --------------------------------------------------------------------------- #
def test_unadmitted_node_is_never_chosen():
    from controller.trust_state import TrustState
    s = TrustState(node_ids=['srv1', 'srv2', 'srv3'])
    s.set_admission(lambda n: n != 'srv2')
    picks = {s.choose_edge_node() for _ in range(300)}
    assert picks == {'srv1', 'srv3'}
    assert s.snapshot()['srv2']['admitted'] is False
    s.set_admission(lambda n: False)
    assert s.choose_edge_node_ex() == (None, False)


def test_unadmitted_node_gets_no_probation_trial():
    from controller.trust_state import TrustState
    s = TrustState(node_ids=['srv1', 'srv2'])
    s.set_admission(lambda n: n != 'srv2')
    s._is_on_probation_locked = lambda n: n == 'srv2'        # srv2 would be due a trial
    assert {s.choose_edge_node_ex()[0] for _ in range(50)} == {'srv1'}


def test_without_attestation_the_snapshot_is_unchanged():
    from controller.trust_state import TrustState
    assert 'admitted' not in TrustState(node_ids=['srv1']).snapshot()['srv1']


# --------------------------------------------------------------------------- #
# End to end: the attester sidecar against the controller's endpoints         #
# --------------------------------------------------------------------------- #
class _Bus:
    def __init__(self):
        self.events = []

    def publish(self, kind, **kw):
        self.events.append((kind, kw))


@pytest.fixture
def api(tmp_path):
    from controller.northbound_api import NorthboundAPI
    from controller.trust_balancer import TrustBalancerApp
    from controller.trust_state import TrustState

    class App:
        handle_attest_challenge = TrustBalancerApp.handle_attest_challenge
        handle_attest_verify = TrustBalancerApp.handle_attest_verify

    cfg = _cfg(tmp_path)
    at.provision_keys(['srvT'], Path(cfg.key_dir))
    app = App()
    app.state = TrustState(node_ids=['srvT'])
    app.attestation = at.AttestationVerifier(cfg, at.reference_components(cfg),
                                             expected_ips={'srvT': '127.0.0.1'})
    app.state.set_admission(app.attestation.is_admitted)
    app.bus = _Bus()
    srv = NorthboundAPI(app=app, state=app.state, host='127.0.0.1', port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield app, f'http://127.0.0.1:{srv.server_address[1]}', _key(tmp_path, 'srvT')
    srv.shutdown()
    srv.server_close()


def test_sidecar_admits_the_genuine_agent(api, genuine_agent):
    app, base, key = api
    answer = attester.attest_once('srvT', base, key, genuine_agent.pid)
    assert answer['verdict'] == at.ATTESTED
    assert app.state.choose_edge_node() == 'srvT'
    (kind, ev), = app.bus.events
    assert kind == 'attestation' and ev['node'] == 'srvT' and ev['verdict'] == at.ATTESTED


def test_sidecar_gets_the_tampered_agent_refused(api, tmp_path):
    app, base, key = api
    p = _spawn_agent(_tampered_tree(tmp_path / 'img'))
    try:
        answer = attester.attest_once('srvT', base, key, p.pid)
    finally:
        p.kill()
        p.wait()
    assert answer['verdict'] == at.NOT_IN_ALLOWLIST
    assert app.state.choose_edge_node() is None
    assert app.bus.events[-1][1]['mismatched'] == ['simulation/node_agent.py']


def test_sidecar_reports_a_missing_agent(api):
    app, base, key = api
    assert attester.attest_once('srvT', base, key, None)['verdict'] == at.UNMEASURABLE


def test_unknown_node_gets_no_nonce(api):
    _, base, _ = api
    req = urllib.request.Request(f'{base}/attest/challenge', method='POST',
                                 data=json.dumps({'node_id': 'srv99'}).encode())
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req, timeout=2)
    assert exc.value.code == 404


# --------------------------------------------------------------------------- #
# Harness                                                                      #
# --------------------------------------------------------------------------- #
def _attest_cfg(tampered=('srv6',)):
    with open(REPO / 'config/params_trust_full.yaml') as fh:
        cfg = yaml.safe_load(fh)
    cfg['security']['attestation'] = {'enabled': True, 'reattest_s': 20.0, 'validity_s': 50.0}
    cfg['simulation']['tampered_agents'] = list(tampered)
    return cfg


def test_every_server_gets_an_attester_and_the_tampered_one_runs_its_image():
    from tests.test_live_config_preflight import argv_for, launch_commands
    from simulation import node_agent
    cmds = launch_commands(_attest_cfg())
    att = [(h, c) for h, c in cmds if 'simulation.attester' in c]
    assert [h for h, _ in att] == [f'srv{i}' for i in range(1, 9)]
    for host, c in att:
        mod, argv = argv_for(c)
        a = attester.build_parser().parse_args(argv)
        assert (mod, a.node_id, a.interval_s) == ('simulation.attester', host, 20.0)
        assert a.key_file == f'logs/attest_keys/{host}.key'
    agents = {h: c for h, c in cmds if 'simulation.node_agent' in c}
    assert agents['srv6'].startswith(f'(cd {attester.tampered_dir("srv6")} && exec python3 ')
    assert '> logs/srv6_agent.log' in agents['srv6']
    assert not agents['srv5'].startswith('(')
    node_agent.build_parser().parse_args(argv_for(agents['srv6'])[1])


def test_attestation_off_launches_nothing_new():
    from tests.test_live_config_preflight import launch_commands
    with open(REPO / 'config/params_trust_full.yaml') as fh:
        cfg = yaml.safe_load(fh)
    assert not any('attester' in c or c.startswith('(') for _, c in launch_commands(cfg))


def test_prepare_run_writes_keys_and_a_one_mark_tampered_image(tmp_path, monkeypatch):
    cfg = _attest_cfg()
    cfg['security']['attestation']['key_dir'] = str(tmp_path / 'keys')
    monkeypatch.setattr(attester, 'TAMPERED_ROOT', tmp_path / 'tampered')
    attester.prepare_run(cfg, repo=REPO)
    assert sorted(p.name for p in (tmp_path / 'keys').glob('*.pub')) == [f'srv{i}.pub' for i in range(1, 9)]
    img = tmp_path / 'tampered' / 'srv6' / 'simulation'
    genuine = (REPO / 'simulation/node_agent.py').read_text()
    assert (img / 'node_agent.py').read_text() == genuine + attester.TAMPER_MARK
    assert (img / '__init__.py').read_bytes() == (REPO / 'simulation/__init__.py').read_bytes()


def test_sidecar_measures_the_agent_not_the_shell_that_launched_it():
    """Rehearsal 2026-10-21: pgrep -f also matches a wrapping `sh -c '...'`,
    and measuring the shell refused a genuine server as 'not a python process'."""
    p = subprocess.Popen(
        "python3 -u -m simulation.node_agent --node-id srvZ --port 0 >/dev/null 2>&1; true",
        shell=True, cwd=REPO, start_new_session=True)
    try:
        deadline = time.monotonic() + 5
        pid = None
        while pid is None and time.monotonic() < deadline:
            time.sleep(0.05)
            pid = attester.find_agent('srvZ')
        assert pid is not None and pid != p.pid
        assert 'python' in os.path.basename(os.readlink(f'/proc/{pid}/exe'))
        assert at.measure_process(pid) == at.reference_components(
            at.AttestationConfig(reference_interpreter=sys.executable))
    finally:
        os.killpg(p.pid, 9)
        p.wait()
