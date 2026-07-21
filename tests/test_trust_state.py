"""Tests for controller/trust_state.py -- the shared, thread-safe trust and
routing state used by TrustBalancerApp/FlowMonitor/NorthboundAPI.

test_f04_non_degrading_liar_needs_anomaly_gate documents the Sprint 1 design
finding referenced by config/params_trust_demo.yaml's comment: the published
trust formula T = 0.35R + 0.25B + 0.25H - 0.15A cannot, on its own, isolate a
node that lies about its load but still serves tasks well (it floors around
T=0.44, never crossing the 0.3 isolation threshold). The fix is the
independent anomaly-gate quarantine check, which this test exercises through
the real TrustState/TrustCalculator, not a mock.
"""

import time

from contracts.trust_update import TrustUpdate
from controller.trust_state import TrustState
from trust_engine.trust_calculator import TrustCalculator


def _make_state(node_ids=('srv1', 'srv2'), **kwargs) -> TrustState:
    return TrustState(node_ids=list(node_ids), **kwargs)


def test_dispatch_tracks_inflight_and_observed_load():
    state = _make_state()
    state.set_concurrency('srv1', 4)
    assert state.observed_load('srv1') == 0.0

    state.register_dispatch('10.0.0.5', 5000, 'srv1')
    state.register_dispatch('10.0.0.6', 5001, 'srv1')
    assert state.get_inflight('srv1') == 2
    assert state.observed_load('srv1') == 0.5

    node = state.complete_dispatch('10.0.0.5', 5000)
    assert node == 'srv1'
    assert state.get_inflight('srv1') == 1


def test_complete_dispatch_unknown_flow_returns_none():
    state = _make_state()
    assert state.complete_dispatch('10.0.0.9', 9999) is None


def test_observed_load_clamped_to_one():
    state = _make_state()
    state.set_concurrency('srv1', 2)
    for port in range(5001, 5006):
        state.register_dispatch('10.0.0.5', port, 'srv1')
    assert state.observed_load('srv1') == 1.0


def test_is_quarantined_by_trust_threshold():
    state = _make_state(isolation_threshold=0.3, anomaly_gate=0.5)
    # Drive srv1's trust down with repeated failures.
    for _ in range(15):
        state.record_task_outcome(TrustUpdate(
            device_id='iot1', edge_node_id='srv1', task_status='failure',
            cpu_usage=0.9, reported_cpu=0.9, latency_ms=600,  # b_raw floors at 0
        ))
    assert state.is_quarantined('srv1')


def test_poll_newly_quarantined_is_edge_triggered():
    state = _make_state(isolation_threshold=0.3, anomaly_gate=0.5)
    assert state.poll_newly_quarantined() == []  # healthy at t=0

    state.set_anomaly_raw('srv1', 1.0)
    newly = state.poll_newly_quarantined()
    assert newly == ['srv1']

    # Second poll while still quarantined must NOT re-fire.
    state.set_anomaly_raw('srv1', 1.0)
    assert state.poll_newly_quarantined() == []


def test_f04_non_degrading_liar_needs_anomaly_gate():
    """Replays the exact scenario from the Sprint 1 design note: a node that
    always succeeds fast (R->1, B->~1) but lies about its CPU load. Honesty
    delta drives H down, but delta=0.15 can only ever subtract 0.15 -- trust
    alone floors well above the 0.3 isolation threshold. The anomaly gate,
    fed by FlowMonitor's honesty-deviation check via set_anomaly_raw, is what
    actually excludes it."""
    calc = TrustCalculator(alpha=0.35, beta=0.25, gamma=0.25, delta=0.15, lambda_decay=0.85)
    state = _make_state(
        node_ids=['srv1'], trust_calculator=calc,
        isolation_threshold=0.3, anomaly_gate=0.5,
    )

    for _ in range(30):
        state.record_task_outcome(TrustUpdate(
            device_id='iot1', edge_node_id='srv1', task_status='success',
            cpu_usage=0.95, reported_cpu=0.05,  # big claimed-vs-actual lie
            latency_ms=5,
        ))

    trust = calc.get_score('srv1')
    assert trust > 0.3, (
        f"expected the formula alone to float above isolation_threshold "
        f"(got {trust:.4f}) -- if this fails the formula itself changed and "
        f"this regression test needs revisiting"
    )
    assert not state.is_quarantined('srv1'), "trust-only check should NOT catch this liar"

    # Now FlowMonitor's honesty-deviation check fires (deviation between
    # claimed 0.05 and controller-observed load would exceed the 0.40
    # threshold for a node this busy).
    state.set_anomaly_raw('srv1', 1.0)
    assert state.is_quarantined('srv1'), "anomaly gate must catch what trust alone cannot"


def test_recent_timeout_rate_none_below_min_samples():
    state = _make_state()
    for _ in range(3):
        state.record_task_outcome(TrustUpdate(
            device_id='iot1', edge_node_id='srv1', task_status='timeout',
            cpu_usage=0.5, reported_cpu=0.5, latency_ms=2000,
        ))
    assert state.recent_timeout_rate('srv1', min_samples=4) is None


def test_recent_timeout_rate_computed_once_enough_samples():
    state = _make_state()
    outcomes = ['timeout', 'timeout', 'timeout', 'success']
    for status in outcomes:
        state.record_task_outcome(TrustUpdate(
            device_id='iot1', edge_node_id='srv1', task_status=status,
            cpu_usage=0.5, reported_cpu=0.5, latency_ms=100,
        ))
    rate = state.recent_timeout_rate('srv1', min_samples=4)
    assert rate == 0.75


def test_flush_if_stale_commits_after_timeout():
    state = _make_state(node_ids=['srv1'], block_commit_timeout_s=0.05, max_updates_per_block=100)
    state.record_task_outcome(TrustUpdate(
        device_id='iot1', edge_node_id='srv1', task_status='success',
        cpu_usage=0.2, reported_cpu=0.2, latency_ms=10,
    ))
    assert state.commit_backend.chain_length() == 1  # genesis only, not yet flushed
    time.sleep(0.06)
    assert state.flush_if_stale() is True
    assert state.commit_backend.chain_length() == 2


def test_choose_edge_node_denies_when_all_quarantined():
    state = _make_state(node_ids=['srv1', 'srv2'])
    state.set_anomaly_raw('srv1', 1.0)
    state.set_anomaly_raw('srv2', 1.0)
    assert state.choose_edge_node() is None


# ------------------------------------------------------------------------- #
# AI weight optimizer wiring                                                 #
# ------------------------------------------------------------------------- #
from controller.edge_selector import EdgeWeights
from trust_engine.ai_optimizer import UCB1WeightOptimizer


def test_optimizer_disabled_by_default_uses_fixed_weights():
    """No optimizer passed -> StaticWeightOptimizer -> edge_weights is the fixed
    configured value and optimizer_tick does nothing (byte-for-byte the old
    behaviour)."""
    fixed = EdgeWeights(0.6, 0.3, 0.1)
    state = _make_state(edge_weights=fixed)
    assert state.edge_weights == fixed
    assert state.optimizer_tick() is None
    assert state.edge_weights == fixed  # never changes


def test_optimizer_window_rollover_swaps_to_a_valid_arm():
    arms = [EdgeWeights(0.50, 0.30, 0.20), EdgeWeights(0.70, 0.20, 0.10)]
    state = _make_state(
        node_ids=['srv1', 'srv2'],
        optimizer=UCB1WeightOptimizer(arms),
        optimizer_window_s=0.05,
    )
    # A window that has not elapsed yet does nothing.
    assert state.optimizer_tick() is None

    # Record some outcomes, wait out the window, then tick.
    for status in ('success', 'success', 'timeout'):
        state.record_task_outcome(TrustUpdate(
            device_id='iot1', edge_node_id='srv1', task_status=status,
            cpu_usage=0.3, reported_cpu=0.3, latency_ms=20,
        ))
    time.sleep(0.06)
    summary = state.optimizer_tick()
    assert summary is not None
    assert summary['outcomes'] == 3
    # The active weights are now one of the configured arms.
    assert state.edge_weights in arms


def test_optimizer_never_reenables_a_quarantined_node():
    """Whatever arm the bandit picks, a quarantined node stays excluded -- the
    optimizer tunes the score weights, never the safety gates."""
    arms = [EdgeWeights(0.50, 0.30, 0.20), EdgeWeights(0.70, 0.20, 0.10)]
    state = _make_state(
        node_ids=['srv1', 'srv2'],
        optimizer=UCB1WeightOptimizer(arms),
        optimizer_window_s=0.0,  # every tick closes a window
    )
    state.set_anomaly_raw('srv1', 1.0)  # quarantine srv1 by anomaly
    for _ in range(10):
        state.optimizer_tick()
        assert state.choose_edge_node() == 'srv2'  # never srv1, whatever the arm
