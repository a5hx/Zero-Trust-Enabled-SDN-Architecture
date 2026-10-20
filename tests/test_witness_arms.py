"""Phase 2d arms (config/params_wit_*.yaml): each differs from the control
only in which party lies, so a blame can be credited to that lie."""

import copy

import pytest
import yaml

from tests.test_live_config_preflight import argv_for, launch_commands

ARMS = ('wit_control', 'wit_drop', 'wit_switch_hide', 'wit_badmouth', 'wit_collude')
VARYING = ('malicious_edge_nodes', 'malicious_switches', 'malicious_badmouth_devices')


def _load(name):
    with open(f'config/params_{name}.yaml') as fh:
        return yaml.safe_load(fh)


def _strip(cfg):
    cfg = copy.deepcopy(cfg)
    cfg['controller']['dashboard'].pop('record_path')
    for k in VARYING:
        cfg['simulation'].pop(k, None)
    return cfg


@pytest.mark.parametrize('arm', ARMS)
def test_arms_differ_only_in_who_lies(arm):
    assert _strip(_load(arm)) == _strip(_load('wit_control'))
    assert _load(arm)['controller']['dashboard']['record_path'] == f'data/events_{arm}.jsonl'


def test_control_is_the_full_config_with_the_witness_on_and_no_attacks():
    full, ctl = _load('trust_full'), _load('wit_control')
    for key in ('trust', 'optimizer', 'blockchain', 'agents'):
        assert ctl[key] == full[key], key
    assert ctl['edge_score'] == {**full['edge_score'], 'cpu_claim': 'verified'}
    assert ctl['controller']['witness'] == {'enabled': True}
    sim = ctl['simulation']
    assert sim['malicious_edge_nodes'] == sim['malicious_flood_devices'] == sim['malicious_spoof_devices'] == []
    assert ctl['security']['malicious_iot_devices'] == []


def test_the_lies_are_what_the_prediction_names():
    from controller.switch_witness import parse_switch_lies
    assert [l.mode for l in parse_switch_lies(_load('wit_switch_hide'))] == ['hide']
    (cover,) = parse_switch_lies(_load('wit_collude'))
    assert (cover.dpid, cover.mode, cover.node) == (4, 'cover', 'srv6')
    assert {m['node'] for m in _load('wit_collude')['simulation']['malicious_edge_nodes']} == {'srv6'}


def test_badmouthing_clients_launch_as_badmouthers_on_different_switches():
    from simulation import iot_client
    cmds = dict(launch_commands(_load('wit_badmouth')))
    for dev in ('iot3', 'iot12'):
        a = iot_client.parse_args(argv_for(cmds[dev])[1])
        assert (a.malicious, a.badmouth_rate, a.malicious_start_s) == ('badmouth', 1.0, 30.0)
    assert (3 - 1) % 8 != (12 - 1) % 8           # behind different edge switches
    assert iot_client.parse_args(argv_for(cmds['iot1'])[1]).malicious == 'none'


@pytest.mark.parametrize('arm', ARMS)
def test_every_launch_command_parses(arm):
    from simulation import iot_client, node_agent
    for host, cmd in launch_commands(_load(arm)):
        module, argv = argv_for(cmd)
        (node_agent.build_parser().parse_args if module == 'simulation.node_agent'
         else iot_client.parse_args)(argv)
