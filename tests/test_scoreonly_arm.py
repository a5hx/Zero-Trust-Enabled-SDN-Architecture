"""The score-only ablation arm (trust.anomaly_rail_enforced: false).

Two properties make it a fair ablation rather than a different system, and
both are pinned here:

1. The anomaly rail stops ACTING: a node at A-bar = 1.0 with healthy trust is
   neither quarantined, nor rate-limited, nor excluded from routing, and a
   trust-quarantined node stays probation-eligible whatever its A-bar.
2. The SCORE is unchanged: A-bar still reaches T through the anomaly flag, so
   the same evidence stream gives the same trust in both arms. Setting
   anomaly_gate: inf would have satisfied (1) and silently broken (2) -- the
   flag is `anomaly >= anomaly_gate`, so the -delta*A term would vanish.
"""

import pytest

from contracts.trust_update import TrustUpdate
from controller.edge_selector import BAND_FULL, BAND_QUARANTINED
from controller.trust_state import TrustState
from trust_engine.trust_calculator import TrustCalculator

yaml = pytest.importorskip('yaml')


def _state(enforced, node_ids=('srv1', 'srv2')):
    calc = TrustCalculator(alpha=0.35, beta=0.25, gamma=0.25, delta=0.15,
                           lambda_decay=0.85)
    return TrustState(node_ids=list(node_ids), trust_calculator=calc,
                      isolation_threshold=0.3, anomaly_gate=0.5,
                      anomaly_rail_enforced=enforced)


def _liar_update():
    return TrustUpdate(device_id='iot1', edge_node_id='srv1',
                       task_status='success', cpu_usage=0.95,
                       reported_cpu=0.05, latency_ms=5)


def test_default_is_enforced():
    assert TrustState(node_ids=['srv1']).anomaly_rail_enforced is True


def test_anomaly_alone_does_not_quarantine_when_rail_is_off():
    on, off = _state(True), _state(False)
    for s in (on, off):
        s.set_anomaly_raw('srv1', 1.0)
    assert on.is_quarantined('srv1')
    assert on.band('srv1') == BAND_QUARANTINED
    assert not off.is_quarantined('srv1')
    # Not rate-limited by the warn band either -- trust is still initial 0.5,
    # which is AT rate_limit_trust, not under it.
    assert off.band('srv1') == BAND_FULL
    assert off.poll_newly_quarantined() == []


def test_anomalous_node_stays_routable_when_rail_is_off():
    off = _state(False, node_ids=('srv1',))
    off.set_anomaly_raw('srv1', 1.0)
    assert off.choose_edge_node() == 'srv1'
    on = _state(True, node_ids=('srv1',))
    on.set_anomaly_raw('srv1', 1.0)
    assert on.choose_edge_node() is None


def test_score_is_identical_in_both_arms():
    """Same evidence -> same T. This is what makes the arms comparable."""
    on, off = _state(True), _state(False)
    for s in (on, off):
        s.set_anomaly_raw('srv1', 1.0)
        for _ in range(30):
            s.record_task_outcome(_liar_update())
    t_on = on.trust_calc.get_score('srv1')
    t_off = off.trust_calc.get_score('srv1')
    assert t_on == t_off
    # And A-bar really did bite: the same liar with a clear rail scores higher.
    clean = _state(False)
    for _ in range(30):
        clean.record_task_outcome(_liar_update())
    assert clean.trust_calc.get_score('srv1') > t_off


def test_trust_quarantine_still_works_and_probation_ignores_anomaly():
    off = _state(False)
    off.set_anomaly_raw('srv1', 1.0)
    for _ in range(15):
        off.record_task_outcome(TrustUpdate(
            device_id='iot1', edge_node_id='srv1', task_status='failure',
            cpu_usage=0.9, reported_cpu=0.9, latency_ms=600))
    assert off.is_quarantined('srv1')
    # In the enforced arm A-bar >= gate would bar probation; here it must not,
    # or trust-only quarantine becomes absorbing for any anomalous node.
    assert off.is_on_probation('srv1')


# --- config parity -------------------------------------------------------- #

FULL = 'config/params_trust_full.yaml'
SCOREONLY = 'config/params_trust_scoreonly.yaml'

#: The only keys the ablation arm may differ on.
ALLOWED_DIFFS = {
    ('trust', 'anomaly_rail_enforced'),
    ('controller', 'dashboard', 'record_path'),
}


def _flatten(d, prefix=()):
    for k, v in d.items():
        if isinstance(v, dict):
            yield from _flatten(v, prefix + (k,))
        else:
            yield prefix + (k,), v


def test_scoreonly_config_differs_only_in_the_ablated_keys():
    with open(FULL) as f:
        full = dict(_flatten(yaml.safe_load(f)))
    with open(SCOREONLY) as f:
        so = dict(_flatten(yaml.safe_load(f)))
    diffs = {k for k in full.keys() | so.keys() if full.get(k, KeyError) != so.get(k, KeyError)}
    assert diffs == ALLOWED_DIFFS, sorted(diffs - ALLOWED_DIFFS)
    assert so[('trust', 'anomaly_rail_enforced')] is False
    assert so[('controller', 'dashboard', 'record_path')] != \
        full[('controller', 'dashboard', 'record_path')]
