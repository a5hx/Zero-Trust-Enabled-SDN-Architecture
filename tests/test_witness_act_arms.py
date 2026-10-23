"""Witness-acts arms (config/params_wa_*.yaml): each acting arm differs from
its observe-only twin only in controller.witness.act, and each twin from the
run it re-measures only in its recording path."""

import copy

import pytest
import yaml

TWINS = {  # arm: (base it was built from, acts)
    'wa_control': ('witfix_control', True),
    'wa_badmouth_observe': ('witfix_badmouth', False),
    'wa_badmouth_act': ('witfix_badmouth', True),
    'wa_forge_observe': ('lv_forge_evidence', False),
    'wa_forge_act': ('lv_forge_evidence', True),
}


def _load(name):
    with open(f'config/params_{name}.yaml') as fh:
        return yaml.safe_load(fh)


def _strip(cfg):
    cfg = copy.deepcopy(cfg)
    cfg['controller']['dashboard'].pop('record_path')
    cfg['controller']['witness'].pop('act', None)
    return cfg


@pytest.mark.parametrize('arm', list(TWINS))
def test_each_arm_is_its_base_plus_only_the_act_switch(arm):
    base, acts = TWINS[arm]
    cfg = _load(arm)
    assert _strip(cfg) == _strip(_load(base))
    assert cfg['controller']['dashboard']['record_path'] == f'data/events_{arm}.jsonl'
    act = cfg['controller']['witness'].get('act')
    assert act == ({'servers': True, 'clients': True} if acts else None)


def test_act_configs_parse():
    from controller.switch_witness import parse_act
    for arm, (_b, acts) in TWINS.items():
        assert parse_act(_load(arm)['controller']['witness']) == ((True, True) if acts else (False, False))
