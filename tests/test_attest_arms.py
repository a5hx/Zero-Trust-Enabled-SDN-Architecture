"""Phase 4 arms (config/params_att_*.yaml): each differs from the control only
in the attacker, the tampered image and whether attestation is on, so a result
can be credited to exactly that difference."""

import copy

import pytest
import yaml

from tests.test_live_config_preflight import argv_for, launch_commands

ARMS = ('att_off_clean', 'att_on_clean', 'att_off_tampered', 'att_on_tampered', 'att_on_runtime')
#            drop on srv6, tampered image, attestation on
DESIGN = {
    'att_off_clean':    (False, False, False),
    'att_on_clean':     (False, False, True),
    'att_off_tampered': (True, True, False),
    'att_on_tampered':  (True, True, True),
    'att_on_runtime':   (True, False, True),
}


def _load(name):
    with open(f'config/params_{name}.yaml') as fh:
        return yaml.safe_load(fh)


def _strip(cfg):
    cfg = copy.deepcopy(cfg)
    cfg['controller']['dashboard'].pop('record_path')
    cfg['simulation'].pop('malicious_edge_nodes')
    cfg['simulation'].pop('tampered_agents', None)
    cfg['security'].pop('attestation', None)
    return cfg


@pytest.mark.parametrize('arm', ARMS)
def test_arms_differ_only_in_the_design_cells(arm):
    assert _strip(_load(arm)) == _strip(_load('att_off_clean'))
    assert _load(arm)['controller']['dashboard']['record_path'] == f'data/events_{arm}.jsonl'


def test_control_is_the_witness_control_with_its_own_recording():
    a, b = _load('att_off_clean'), _load('witfix_control')
    for c in (a, b):
        c['controller']['dashboard'].pop('record_path')
    assert a == b


@pytest.mark.parametrize('arm', ARMS)
def test_each_arm_is_its_design_cell(arm):
    drop, tampered, attest = DESIGN[arm]
    cfg = _load(arm)
    sim = cfg['simulation']
    expect = [{'node': 'srv6', 'attack': 'drop', 'start_s': 30}] if drop else []
    assert sim['malicious_edge_nodes'] == expect
    assert sim.get('tampered_agents', []) == (['srv6'] if tampered else [])
    att = cfg['security'].get('attestation')
    assert (att == {'enabled': True, 'reattest_s': 30.0, 'validity_s': 75.0}) if attest else att is None


@pytest.mark.parametrize('arm', ARMS)
def test_launch_matches_the_design(arm):
    drop, tampered, attest = DESIGN[arm]
    cmds = launch_commands(_load(arm))
    attesters = [h for h, c in cmds if 'simulation.attester' in c]
    assert attesters == ([f'srv{i}' for i in range(1, 9)] if attest else [])
    agent6 = next(c for h, c in cmds if h == 'srv6' and 'simulation.node_agent' in c)
    assert agent6.startswith('(cd logs/tampered/srv6 && exec ') == tampered
    from simulation import node_agent
    a = node_agent.build_parser().parse_args(argv_for(agent6)[1])
    assert (a.malicious, a.malicious_start_s) == (('drop', 30.0) if drop else ('none', 0.0))
