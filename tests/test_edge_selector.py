"""Tests for controller/edge_selector.py -- the single-source-of-truth
EdgeScore/quarantine logic shared by TrustBalancerStandalone and
TrustBalancerApp."""

import pytest

from controller.edge_selector import (
    EdgeWeights,
    NodeState,
    edge_score,
    is_quarantined,
    select_edge_node,
)


def test_edge_weights_reject_bad_sum():
    with pytest.raises(ValueError):
        EdgeWeights(w1_trust=0.5, w2_cpu=0.5, w3_latency=0.5)


def test_edge_weights_reject_below_floor():
    with pytest.raises(ValueError):
        EdgeWeights(w1_trust=0.92, w2_cpu=0.04, w3_latency=0.04)


def test_edge_weights_from_config_defaults():
    w = EdgeWeights.from_config({})
    assert w.w1_trust == 0.50 and w.w2_cpu == 0.30 and w.w3_latency == 0.20


def test_is_quarantined_by_trust():
    s = NodeState(node_id='srv1', trust=0.2, cpu_load=0.1, latency_ms=10, anomaly=0.0)
    assert is_quarantined(s, isolation_threshold=0.3, anomaly_gate=0.5)


def test_is_quarantined_by_anomaly_even_with_high_trust():
    s = NodeState(node_id='srv1', trust=0.9, cpu_load=0.1, latency_ms=10, anomaly=0.6)
    assert is_quarantined(s, isolation_threshold=0.3, anomaly_gate=0.5)


def test_not_quarantined_when_healthy():
    s = NodeState(node_id='srv1', trust=0.7, cpu_load=0.3, latency_ms=20, anomaly=0.1)
    assert not is_quarantined(s, isolation_threshold=0.3, anomaly_gate=0.5)


def test_edge_score_favours_lower_cpu_and_latency():
    weights = EdgeWeights()
    busy = NodeState(node_id='a', trust=0.7, cpu_load=0.9, latency_ms=100, anomaly=0.0)
    idle = NodeState(node_id='b', trust=0.7, cpu_load=0.1, latency_ms=10, anomaly=0.0)
    assert edge_score(idle, weights, max_latency_ms=100) > edge_score(busy, weights, max_latency_ms=100)


def test_select_edge_node_picks_best_eligible():
    weights = EdgeWeights()
    states = [
        NodeState(node_id='srv1', trust=0.9, cpu_load=0.1, latency_ms=10),
        NodeState(node_id='srv2', trust=0.9, cpu_load=0.8, latency_ms=90),
    ]
    chosen, score, ranked = select_edge_node(states, weights)
    assert chosen == 'srv1'
    assert ranked[0][0] == 'srv1'


def test_select_edge_node_excludes_quarantined():
    weights = EdgeWeights()
    states = [
        NodeState(node_id='srv1', trust=0.1, cpu_load=0.05, latency_ms=5),  # trust too low
        NodeState(node_id='srv2', trust=0.6, cpu_load=0.5, latency_ms=50),
    ]
    chosen, _, ranked = select_edge_node(states, weights)
    assert chosen == 'srv2'
    assert [nid for nid, _ in ranked] == ['srv2']


def test_select_edge_node_denies_when_all_quarantined():
    weights = EdgeWeights()
    states = [
        NodeState(node_id='srv1', trust=0.1, cpu_load=0.1, latency_ms=10),
        NodeState(node_id='srv2', trust=0.9, cpu_load=0.1, latency_ms=10, anomaly=0.9),
    ]
    chosen, score, ranked = select_edge_node(states, weights)
    assert chosen is None
    assert score == 0.0
    assert ranked == []


def test_select_edge_node_round_robins_exact_ties():
    weights = EdgeWeights()
    states = [
        NodeState(node_id='srv1', trust=0.5, cpu_load=0.5, latency_ms=50),
        NodeState(node_id='srv2', trust=0.5, cpu_load=0.5, latency_ms=50),
        NodeState(node_id='srv3', trust=0.5, cpu_load=0.5, latency_ms=50),
    ]
    chosen_sequence = [select_edge_node(states, weights)[0] for _ in range(6)]
    # All three should show up rather than srv1 winning every tie.
    assert set(chosen_sequence) == {'srv1', 'srv2', 'srv3'}
