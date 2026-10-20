"""The Phase 1 liar experiment's five arms (config/params_liar_*.yaml,
config/params_stealthy_treat.yaml).

A difference between arms in anything but the liar itself, the worker-slot
switch and the recording path would make a difference in the result
uncreditable to the liar -- the same discipline as
tests/test_flood_response.py::TestHeavyFloodArms and tests/test_scoreonly_arm.py.
"""

import copy
from pathlib import Path

import pytest
import yaml

from tests.test_live_config_preflight import argv_for, launch_commands

ARMS = ('liar_honest', 'liar_c_treat', 'liar_t_treat', 'liar_t_treat_slots', 'stealthy_treat')
ALLOWED = ({'simulation', 'malicious_edge_nodes'}, {'agents', 'enforce_concurrency'},
           {'controller', 'dashboard', 'record_path'})


def _load(name):
    with open(f'config/params_{name}.yaml') as fh:
        return yaml.safe_load(fh)


def _strip(cfg):
    cfg = copy.deepcopy(cfg)
    cfg['simulation'].pop('malicious_edge_nodes')
    cfg['agents'].pop('enforce_concurrency', None)
    cfg['controller']['dashboard'].pop('record_path')
    return cfg


@pytest.mark.parametrize('arm', ARMS[1:])
def test_arms_differ_from_the_control_only_in_the_liar_slots_and_recording(arm):
    assert _strip(_load(arm)) == _strip(_load('liar_honest'))


@pytest.mark.parametrize('arm', ARMS)
def test_each_arm_records_to_its_own_file(arm):
    assert _load(arm)['controller']['dashboard']['record_path'] == f'data/events_{arm}.jsonl'


def test_the_control_differs_from_the_full_config_only_in_workload_and_attacks():
    full, ctl = _load('trust_full'), _load('liar_honest')
    assert ctl['agents'] == {**full['agents'], 'task_work_ms': 320, 'work_mode': 'hold',
                             'concurrency': 2}
    assert ctl['simulation'] == {**full['simulation'], 'malicious_edge_nodes': [],
                                 'malicious_flood_devices': [], 'malicious_spoof_devices': []}
    assert ctl['security'] == {**full['security'], 'malicious_iot_devices': []}
    for key in ('trust', 'edge_score', 'optimizer', 'blockchain'):
        assert ctl[key] == full[key], key
    c_full, c_ctl = copy.deepcopy(full['controller']), copy.deepcopy(ctl['controller'])
    c_full['dashboard'].pop('record_path')
    c_ctl['dashboard'].pop('record_path')
    assert c_ctl == c_full


def test_the_workload_is_the_one_the_prediction_modelled():
    """docs/predictions/liar_2026-10-19.txt: occupancy 0.40 = 20 tasks/s x
    0.32 s / (8 servers x 2 workers)."""
    c = _load('liar_honest')
    rate = c['simulation']['num_iot_devices'] / c['agents']['report_interval_s']
    occ = rate * c['agents']['task_work_ms'] / 1000 / (
        c['simulation']['num_edge_nodes'] * c['agents']['concurrency'])
    assert occ == pytest.approx(0.40)


@pytest.mark.parametrize('arm', ARMS)
def test_every_launch_command_parses_and_the_liar_is_armed(arm):
    from simulation import iot_client, node_agent
    cfg = _load(arm)
    liars = {m['node']: m for m in cfg['simulation']['malicious_edge_nodes']}
    for host, cmd in launch_commands(cfg):
        module, argv = argv_for(cmd)
        if module == 'simulation.iot_client':
            a = iot_client.parse_args(argv)
            assert a.malicious == 'none', host
            continue
        a = node_agent.build_parser().parse_args(argv)
        assert (a.work_mode, a.work_ms, a.concurrency) == ('hold', 320.0, 2)
        assert a.enforce_concurrency == bool(cfg['agents'].get('enforce_concurrency'))
        m = liars.get(host)
        assert a.malicious == (m['attack'] if m else 'none'), host
        if m:
            assert a.malicious_start_s == 20.0 and a.claimed_cpu_lie == 0.0
            if m['attack'] == 'liar':
                assert a.liar_busy == m['liar_busy']


def test_the_replicate_runner_treats_them_as_config_arms():
    """tools/run_replicates.sh: names shaped `<x>_tNNN` are θ-sweep arms and are
    derived, not read; these must not match that."""
    import re
    for arm in ARMS:
        assert not re.fullmatch(r'[a-z]+_t[0-9]{3}', arm)
        assert Path(f'config/params_{arm}.yaml').exists()


# The re-run batch (2026-10-20), on the corrected honesty check. Each arm is a
# first-batch arm with only its recording path changed -- and, for the two
# '_verified' arms, edge_score.cpu_claim: verified.
RERUN = {'liarfix_honest': 'liar_honest', 'liarfix_c_treat': 'liar_c_treat',
         'liarfix_t_treat': 'liar_t_treat', 'liarfix_stealthy': 'stealthy_treat',
         'liarfix_t_verified': 'liar_t_treat', 'liarfix_honest_verified': 'liar_honest'}


@pytest.mark.parametrize('new,old', sorted(RERUN.items()))
def test_rerun_arms_are_the_first_batch_with_only_the_named_change(new, old):
    a, b = _load(new), _load(old)
    assert a['controller']['dashboard'].pop('record_path') == f'data/events_{new}.jsonl'
    b['controller']['dashboard'].pop('record_path')
    if new.endswith('_verified'):
        assert a['edge_score'].pop('cpu_claim') == 'verified'
    assert a == b


@pytest.mark.parametrize('arm', sorted(RERUN))
def test_rerun_arms_launch(arm):
    from simulation import node_agent
    for host, cmd in launch_commands(_load(arm)):
        module, argv = argv_for(cmd)
        if module == 'simulation.node_agent':
            node_agent.build_parser().parse_args(argv)


def test_the_app_accepts_cpu_claim_verified(tmp_path, monkeypatch):
    pytest.importorskip('os_ken')
    cfg = _load('liarfix_t_verified')
    cfg['controller']['dashboard'] = {'enabled': False}
    path = tmp_path / 'p.yaml'
    path.write_text(yaml.safe_dump(cfg))
    monkeypatch.setenv('ZTSDN_CONFIG', str(path))
    from controller.trust_balancer import TrustBalancerApp
    assert TrustBalancerApp().state.cpu_claim == 'verified'


THIRD = {'liarfix3_honest': 'liarfix_honest', 'liarfix3_honest_verified': 'liarfix_honest_verified',
         'liarfix3_c_treat': 'liarfix_c_treat'}


@pytest.mark.parametrize('new,old', sorted(THIRD.items()))
def test_third_batch_differs_only_in_the_recording_path(new, old):
    a, b = _load(new), _load(old)
    assert a['controller']['dashboard'].pop('record_path') == f'data/events_{new}.jsonl'
    b['controller']['dashboard'].pop('record_path')
    assert a == b
