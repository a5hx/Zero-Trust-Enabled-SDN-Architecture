"""The two arms must differ ONLY in what this project claims they differ in.

A controlled comparison is only controlled if the controlled variables are
actually held. This file is the enforcement of that: it diffs every shared key
of `base_model/config/params_base_full.yaml` against
`config/params_trust_full.yaml` and fails on any drift.

The failure it exists to prevent is quiet. Nobody sets out to give the baseline
a different workload; someone tunes `task_work_ms` in one config six weeks from
now, both arms still run, both still produce plausible numbers, and the paper
reports an architecture difference that is partly a workload difference. There
is no runtime symptom. Only this test.
"""

import pytest

yaml = pytest.importorskip('yaml')

TREATMENT = 'config/params_trust_full.yaml'
BASELINE = 'base_model/config/params_base_full.yaml'

#: Dotted paths that MUST be byte-identical across the two arms. Everything
#: here is either the network, the workload, or the attack schedule -- i.e. an
#: independent variable that is being held constant.
SHARED_PATHS = (
    # Trust formula. The two arms must score trust with the same weights or the
    # curves are not on the same axis.
    'trust.alpha', 'trust.beta', 'trust.gamma', 'trust.delta',
    'trust.lambda_decay', 'trust.initial_score',
    # Thresholds: enforced in one arm, reported in the other. Same ruler.
    'trust.isolation_threshold', 'trust.anomaly_gate',
    'trust.rate_limit_trust', 'trust.anomaly_warn',
    # Topology and run length.
    'simulation.num_edge_nodes', 'simulation.num_iot_devices',
    'simulation.num_malicious', 'simulation.duration_s',
    # The attack schedule, in full. Same attackers, same onsets, same rates.
    'simulation.malicious_edge_nodes',
    'simulation.malicious_flood_devices',
    'simulation.malicious_spoof_devices',
    # Credentials. The baseline hands out the same wrong key to the same two
    # devices; only the verification differs.
    'security.auth_scheme', 'security.shared_key_hex',
    'security.malicious_iot_devices',
    # Workload intensity -- the single most damaging thing to let drift.
    'agents.report_interval_s', 'agents.task_timeout_s',
    'agents.task_work_ms', 'agents.node_port',
    # Data plane and polling.
    'controller.vip', 'controller.vip_port', 'controller.api_port',
    'controller.flow_idle_timeout_s', 'controller.flow_hard_timeout_s',
    'controller.monitor_interval_s',
    # Detector knobs. Both arms run the same tells; only one acts on them.
    'controller.latency_liar_ratio', 'controller.latency_liar_floor_ms',
    'controller.idle_claim_threshold', 'controller.latency_liar_persist',
    'controller.honesty_deviation_threshold',
)

#: Keys that MUST NOT appear in the baseline config. Each names a treatment
#: feature; its presence here would mean the control arm carries a mechanism it
#: claims not to have, even if nothing reads it.
FORBIDDEN_IN_BASELINE = (
    'edge_score',                    # there is no EdgeScore to weight
    'optimizer',                     # nothing to tune
    'blockchain',                    # no ledger
    'controller.rate_limit',         # no metered band
    'controller.probation_interval_s',  # nothing is ever isolated
)


def _get(cfg, dotted):
    node = cfg
    for part in dotted.split('.'):
        if not isinstance(node, dict) or part not in node:
            return KeyError
        node = node[part]
    return node


@pytest.fixture(scope='module')
def configs():
    with open(TREATMENT) as f:
        treatment = yaml.safe_load(f)
    with open(BASELINE) as f:
        baseline = yaml.safe_load(f)
    return baseline, treatment


@pytest.mark.parametrize('path', SHARED_PATHS)
def test_shared_key_is_identical(configs, path):
    baseline, treatment = configs
    b, t = _get(baseline, path), _get(treatment, path)
    assert b is not KeyError, f'{path} missing from the baseline config'
    assert t is not KeyError, f'{path} missing from the treatment config'
    assert b == t, (
        f'{path} differs between the arms: baseline={b!r} treatment={t!r}. '
        f'This is a controlled variable -- either revert the change, or move '
        f'the key out of SHARED_PATHS and say in the paper that it varied.'
    )


@pytest.mark.parametrize('path', FORBIDDEN_IN_BASELINE)
def test_treatment_feature_absent_from_baseline(configs, path):
    baseline, _ = configs
    assert _get(baseline, path) is KeyError, (
        f'{path} is a treatment-arm feature and must not appear in the '
        f'baseline config, even unused -- a reader checking the control arm '
        f'should not find it there.'
    )


def test_baseline_has_its_own_block(configs):
    baseline, treatment = configs
    assert 'baseline' in baseline, 'the baseline config needs its `baseline:` block'
    assert 'baseline' not in treatment, (
        'the treatment config must not carry a `baseline:` block'
    )
    block = baseline['baseline']
    assert block['strategy'] in ('static_nearest', 'round_robin', 'random')
    assert isinstance(block['observe_anomaly'], bool)
    assert float(block['load_window_s']) > 0


def test_recordings_go_to_different_files(configs):
    """The one key that MUST differ, or one arm overwrites the other."""
    baseline, treatment = configs
    b = baseline['controller']['dashboard']['record_path']
    t = treatment['controller']['dashboard']['record_path']
    assert b != t, (
        f'both arms record to {b!r} -- running the baseline would destroy the '
        f'treatment recording it is meant to be compared against'
    )
