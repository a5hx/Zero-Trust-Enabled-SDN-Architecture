"""Phase 3 arms (config/params_hw_*.yaml): honest-slow versus lying.

Each arm must differ from the reference arm `hw_class` only in what it is
about -- the latency baseline, a throttle on an honest server, or one sybil --
or a difference in false quarantines could not be credited to it."""

import copy
import shlex

import pytest
import yaml

from tests.test_live_config_preflight import launch_commands

ARMS = ('hw_fleet', 'hw_class', 'hw_throttle25', 'hw_throttle10', 'hw_sybil_slow', 'hw_sybil_fast')


def _load(name):
    with open(f'config/params_{name}.yaml') as fh:
        return yaml.safe_load(fh)


def _strip(cfg):
    cfg = copy.deepcopy(cfg)
    cfg['controller']['dashboard'].pop('record_path')
    cfg['controller'].pop('latency_baseline')
    cfg['simulation'].pop('honest_throttle', None)
    cfg['simulation'].pop('malicious_edge_nodes')
    return cfg


@pytest.mark.parametrize('arm', ARMS)
def test_arms_differ_only_in_their_subject(arm):
    assert _strip(_load(arm)) == _strip(_load('hw_class'))
    assert _load(arm)['controller']['dashboard']['record_path'] == f'data/events_{arm}.jsonl'


def test_what_each_arm_varies():
    assert _load('hw_fleet')['controller']['latency_baseline'] == 'fleet'
    for arm in ARMS[1:]:
        assert _load(arm)['controller']['latency_baseline'] == 'class'
    assert _load('hw_throttle25')['simulation']['honest_throttle'][0]['cpu_max'] == '2500 10000'
    assert _load('hw_throttle10')['simulation']['honest_throttle'][0]['cpu_max'] == '1000 10000'
    assert _load('hw_sybil_slow')['simulation']['malicious_edge_nodes'][0]['node'] == 'srv5'
    assert _load('hw_sybil_fast')['simulation']['malicious_edge_nodes'][0]['node'] == 'srv3'


def test_reference_arm_is_the_full_config_with_only_phase3_changes():
    full, ref = _load('trust_full'), _load('hw_class')
    for key in ('trust', 'optimizer', 'blockchain'):
        assert ref[key] == full[key], key
    assert ref['edge_score'] == {**full['edge_score'], 'cpu_claim': 'verified'}
    assert ref['agents'] == {**full['agents'], 'work_mode': 'ops', 'work_ops': 45000}
    assert ref['security'] == {**full['security'], 'malicious_iot_devices': []}
    assert ref['simulation']['malicious_flood_devices'] == []
    assert ref['simulation']['malicious_spoof_devices'] == []
    classes = {n: p['class'] for n, p in ref['simulation']['server_profiles'].items()}
    assert sorted(n for n, c in classes.items() if c == 'slow') == ['srv5', 'srv6', 'srv7', 'srv8']
    c_full, c_ref = copy.deepcopy(full['controller']), copy.deepcopy(ref['controller'])
    for c in (c_full, c_ref):
        c['dashboard'].pop('record_path')
    assert c_ref.pop('latency_baseline') == 'class'
    assert c_ref == c_full


def test_each_class_has_enough_servers_for_its_own_baseline():
    from controller.flow_monitor import MIN_CLASS_SIZE
    from simulation.cpu_profiles import server_classes
    counts = {}
    for c in server_classes(_load('hw_class')).values():
        counts[c] = counts.get(c, 0) + 1
    assert all(n >= MIN_CLASS_SIZE for n in counts.values()), counts


@pytest.mark.parametrize('arm', ARMS)
def test_every_agent_command_parses_with_fixed_work(arm):
    from simulation import node_agent
    for host, cmd in launch_commands(_load(arm)):
        if not host.startswith('srv'):
            continue
        assert not cmd.startswith('sh -c'), host       # attached from outside, never wrapped
        argv = shlex.split(cmd.split(' > logs/')[0])
        a = node_agent.build_parser().parse_args(argv[4:])
        assert (a.work_mode, a.work_ops) == ('ops', 45000)
