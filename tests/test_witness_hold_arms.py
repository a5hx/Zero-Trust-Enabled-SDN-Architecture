"""Witness-hold arms (config/params_wh_*.yaml): each differs from its base
only in controller.witness.act; each holding arm from its acting twin only in
act.hold."""

import copy

import pytest
import yaml

ARMS = {  # arm: (base, holds)
    'wh_control_hold': ('witfix_control', True),
    'wh_forge_act': ('lv_forge_evidence', False),
    'wh_forge_hold': ('lv_forge_evidence', True),
    'wh_drop_act': ('witfix_drop', False),
    'wh_drop_hold': ('witfix_drop', True),
}


def _load(name):
    with open(f'config/params_{name}.yaml') as fh:
        return yaml.safe_load(fh)


def _strip(cfg):
    cfg = copy.deepcopy(cfg)
    cfg['controller']['dashboard'].pop('record_path')
    cfg['controller']['witness'].pop('act', None)
    return cfg


@pytest.mark.parametrize('arm', list(ARMS))
def test_arm_is_its_base_plus_act(arm):
    base, holds = ARMS[arm]
    cfg = _load(arm)
    assert _strip(cfg) == _strip(_load(base))
    assert cfg['controller']['dashboard']['record_path'] == f'data/events_{arm}.jsonl'
    act = cfg['controller']['witness']['act']
    expect = {'servers': True, 'clients': True}
    if holds:
        expect['hold'] = {'trial_interval_s': 10, 'passes': 3}
    assert act == expect


def test_holding_arms_parse():
    from controller.switch_witness import WitnessHold, parse_hold
    for arm, (_b, holds) in ARMS.items():
        assert parse_hold(_load(arm)['controller']['witness']) == (WitnessHold(10.0, 3) if holds else None)


@pytest.mark.parametrize('rerun', ['wh2_', 'wh3_'])
@pytest.mark.parametrize('arm', list(ARMS))
def test_rerun_arms_change_only_the_recording(arm, rerun):
    a, b = _load(arm), _load(arm.replace('wh_', rerun))
    assert b['controller']['dashboard'].pop('record_path') == f"data/events_{arm.replace('wh_', rerun)}.jsonl"
    a['controller']['dashboard'].pop('record_path')
    assert a == b
