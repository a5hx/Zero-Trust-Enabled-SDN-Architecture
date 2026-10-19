"""tools/derive_config.py -- theta-sweep arm configs.

A sweep arm is only a one-variable experiment if its config differs from its
parent in theta and nothing else. The runner derives it fresh before every run;
this file pins that the derivation changes exactly the two lines it claims to.
"""

import importlib.util
from pathlib import Path

import pytest

yaml = pytest.importorskip('yaml')

_spec = importlib.util.spec_from_file_location(
    'derive_config', Path(__file__).resolve().parents[1] / 'tools' / 'derive_config.py')
derive_config = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(derive_config)


def _flatten(d, prefix=()):
    for k, v in d.items():
        if isinstance(v, dict):
            yield from _flatten(v, prefix + (k,))
        else:
            yield prefix + (k,), v


@pytest.mark.parametrize('arm,parent,theta', [
    ('scoreonly_t040', 'config/params_trust_scoreonly.yaml', 0.40),
    ('scoreonly_t045', 'config/params_trust_scoreonly.yaml', 0.45),
    ('scoreonly_t050', 'config/params_trust_scoreonly.yaml', 0.50),
    ('treat_t045', 'config/params_trust_full.yaml', 0.45),
])
def test_derived_config_differs_from_parent_only_in_theta_and_recording(arm, parent, theta):
    text, record_path, got_theta = derive_config.derive(arm)
    assert got_theta == theta
    derived = dict(_flatten(yaml.safe_load(text)))
    with open(parent) as f:
        base = dict(_flatten(yaml.safe_load(f)))
    diffs = {k for k in derived.keys() | base.keys()
             if derived.get(k, KeyError) != base.get(k, KeyError)}
    assert diffs == {('trust', 'isolation_threshold'),
                     ('controller', 'dashboard', 'record_path')}
    assert derived[('trust', 'isolation_threshold')] == theta
    assert derived[('controller', 'dashboard', 'record_path')] == record_path
    assert record_path == f'data/events_{arm}.jsonl'


def test_line_level_diff_is_two_lines_plus_header():
    text, _, _ = derive_config.derive('scoreonly_t045')
    lines = text.splitlines()
    assert lines[0].startswith('# DERIVED') and lines[2] == '#'
    body = lines[3:]
    parent = Path('config/params_trust_scoreonly.yaml').read_text().splitlines()
    assert len(body) == len(parent)
    assert sum(a != b for a, b in zip(body, parent)) == 2


@pytest.mark.parametrize('arm', ['scoreonly_t051', 'scoreonly_t090', 'scoreonly_t000'])
def test_theta_outside_zero_to_initial_score_is_refused(arm):
    """Every node starts at initial_score 0.5; theta above it quarantines the
    whole fleet at start-up and measures an outage, not a threshold."""
    with pytest.raises(derive_config.DeriveError, match='initial_score'):
        derive_config.derive(arm)


@pytest.mark.parametrize('arm', ['scoreonly', 'base_t040', 'scoreonly_t45', 'treat_t0450'])
def test_non_sweep_names_are_refused(arm):
    with pytest.raises(derive_config.DeriveError):
        derive_config.derive(arm)


def test_main_writes_config_and_prints_recording(tmp_path, capsys):
    out = tmp_path / 'p.yaml'
    assert derive_config.main(['scoreonly_t040', str(out)]) == 0
    assert capsys.readouterr().out.strip() == 'data/events_scoreonly_t040.jsonl'
    assert yaml.safe_load(out.read_text())['trust']['isolation_threshold'] == 0.40
