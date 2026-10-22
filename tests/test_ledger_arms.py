"""Phase 6 arms (config/params_lv_*.yaml): each differs from the others only
in whether the replicas verify, what the controller forges, and srv3's attack."""

import copy

import pytest
import yaml

ARMS = ('lv_noverify', 'lv_honest', 'lv_forge_score', 'lv_forge_evidence')
#             verify, forgery mode, srv3 drops
DESIGN = {
    'lv_noverify':       (False, None, False),
    'lv_honest':         (True, None, False),
    'lv_forge_score':    (True, 'score', False),
    'lv_forge_evidence': (True, 'evidence', True),
}


def _load(name):
    with open(f'config/params_{name}.yaml') as fh:
        return yaml.safe_load(fh)


def _strip(cfg):
    cfg = copy.deepcopy(cfg)
    cfg['controller']['dashboard'].pop('record_path')
    cfg['controller'].pop('debug_forge_trust', None)
    cfg['simulation'].pop('malicious_edge_nodes')
    cfg['ledger'].pop('verify', None)
    return cfg


@pytest.mark.parametrize('arm', ARMS)
def test_arms_differ_only_in_the_design_cells(arm):
    assert _strip(_load(arm)) == _strip(_load('lv_noverify'))
    assert _load(arm)['controller']['dashboard']['record_path'] == f'data/events_{arm}.jsonl'


def test_base_is_the_witness_control_plus_the_raft_ledger():
    a, w, r = _load('lv_noverify'), _load('witfix_control'), _load('trust_raft')
    led = a.pop('ledger')
    assert led == r['ledger']
    for c in (a, w):
        c['controller']['dashboard'].pop('record_path')
    assert a == w


@pytest.mark.parametrize('arm', ARMS)
def test_each_arm_is_its_design_cell(arm):
    verify, mode, drop = DESIGN[arm]
    cfg = _load(arm)
    assert bool(cfg['ledger'].get('verify')) is verify
    forge = cfg['controller'].get('debug_forge_trust')
    assert (forge or {}).get('mode') == mode
    if forge:
        assert (forge['node'], forge['start_s']) == ('srv3', 60)
    expect = [{'node': 'srv3', 'attack': 'drop', 'start_s': 60}] if drop else []
    assert cfg['simulation']['malicious_edge_nodes'] == expect


def test_forgery_arms_start_only_with_the_gate():
    from controller.forgery import ENV_GATE, TrustForgery
    for arm in ('lv_forge_score', 'lv_forge_evidence'):
        ctl = _load(arm)['controller']
        with pytest.raises(ValueError):
            TrustForgery.from_config(ctl, environ={})
        assert TrustForgery.from_config(ctl, environ={ENV_GATE: '1'}) is not None
