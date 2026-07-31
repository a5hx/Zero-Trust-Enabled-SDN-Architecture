"""Tests for controller/edge_selector.py -- the single-source-of-truth
EdgeScore/quarantine logic shared by TrustBalancerStandalone and
TrustBalancerApp."""

import random

import pytest

from controller.edge_selector import (
    STRATEGY_ARGMAX,
    STRATEGY_P2C,
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


# --------------------------------------------------------------------------- #
# Power-of-two-choices (starvation fix, docs/LOAD_BALANCING_STARVATION.md)     #
# --------------------------------------------------------------------------- #
def test_p2c_still_excludes_quarantined_nodes():
    """Security invariant: p2c samples only among eligible nodes, so a
    quarantined (malicious) node can never be chosen no matter the draws."""
    weights = EdgeWeights()
    states = [
        NodeState(node_id='srv1', trust=0.05, cpu_load=0.0, latency_ms=1),   # trust too low
        NodeState(node_id='srv2', trust=0.9, cpu_load=0.1, latency_ms=10, anomaly=0.9),  # anomaly gate
        NodeState(node_id='srv3', trust=0.6, cpu_load=0.5, latency_ms=50),
        NodeState(node_id='srv4', trust=0.6, cpu_load=0.5, latency_ms=50),
    ]
    rng = random.Random(0)
    for _ in range(500):
        chosen, _, _ = select_edge_node(
            states, weights, strategy=STRATEGY_P2C, rng=rng,
        )
        assert chosen in {'srv3', 'srv4'}


def test_p2c_spreads_across_a_field_where_argmax_concentrates():
    """The N-scaling starvation case: a field of near-equal healthy nodes
    separated only by sub-1% score jitter. argmax funnels essentially everything
    to the single top-scoring node; p2c spreads across the whole field because
    most random pairs are between two of the many near-equal nodes."""
    weights = EdgeWeights()
    # 8 healthy nodes, monotonically tiny score gaps via latency jitter only.
    states = [
        NodeState(node_id=f'srv{i}', trust=0.7, cpu_load=0.3, latency_ms=20 + i * 0.1)
        for i in range(1, 9)
    ]
    argmax_used = {select_edge_node(states, weights)[0] for _ in range(400)}
    assert len(argmax_used) == 1                      # winner-take-all: one node

    rng = random.Random(1)
    p2c_used = {
        select_edge_node(states, weights, strategy=STRATEGY_P2C, rng=rng)[0]
        for _ in range(400)
    }
    # p2c spreads across all but at most the single strict-worst node (which is
    # never the better of any pair while scores are frozen; in the live system
    # load feedback keeps changing who is worst, so nothing is permanently
    # starved -- see scratchpad/lockin_sweep.py, 0 starved at every N).
    assert len(p2c_used) >= len(states) - 1
    assert len(p2c_used) > len(argmax_used)


def test_p2c_still_prefers_the_better_of_the_sampled_pair():
    """p2c is not random routing: within the sampled pair it always takes the
    higher score, so it stays load/trust-aware -- it only widens *which* nodes
    are eligible to win, it does not abandon the score."""
    weights = EdgeWeights()
    good = NodeState(node_id='good', trust=0.9, cpu_load=0.1, latency_ms=10)
    poor = NodeState(node_id='poor', trust=0.9, cpu_load=0.9, latency_ms=90)
    # With exactly two eligible nodes, every p2c sample is the whole pair, so the
    # better one must win every time.
    rng = random.Random(4)
    for _ in range(100):
        chosen, _, _ = select_edge_node(
            [good, poor], weights, strategy=STRATEGY_P2C, rng=rng,
        )
        assert chosen == 'good'


def test_p2c_ranked_list_is_still_the_full_eligible_ranking():
    """The 'why' array stays the complete best-first ranking even though the
    chosen node may not be its head under p2c (the dashboard relies on this)."""
    weights = EdgeWeights()
    states = [
        NodeState(node_id='srv1', trust=0.9, cpu_load=0.1, latency_ms=10),
        NodeState(node_id='srv2', trust=0.6, cpu_load=0.5, latency_ms=50),
        NodeState(node_id='srv3', trust=0.4, cpu_load=0.5, latency_ms=50),
    ]
    _, _, ranked = select_edge_node(
        states, weights, strategy=STRATEGY_P2C, rng=random.Random(2),
    )
    assert [nid for nid, _ in ranked] == ['srv1', 'srv2', 'srv3']


def test_p2c_single_eligible_node_is_returned():
    weights = EdgeWeights()
    states = [
        NodeState(node_id='srv1', trust=0.1, cpu_load=0.1, latency_ms=10),   # quarantined
        NodeState(node_id='srv2', trust=0.7, cpu_load=0.2, latency_ms=20),
    ]
    chosen, _, _ = select_edge_node(
        states, weights, strategy=STRATEGY_P2C, rng=random.Random(3),
    )
    assert chosen == 'srv2'


# --------------------------------------------------------------------------- #
# ε-exploration (the hard no-starvation guarantee that p2c alone can't give)   #
# --------------------------------------------------------------------------- #
def test_epsilon_reaches_the_strict_worst_node_that_p2c_alone_starves():
    """The frozen-score gap: 'lag' is strictly worst, so neither argmax nor p2c
    d=2 ever picks it. A positive epsilon does -- it is selected uniformly at
    random with probability epsilon/|eligible|, so it can never be starved."""
    weights = EdgeWeights()
    states = [
        NodeState(node_id='srv1', trust=0.95, cpu_load=0.1, latency_ms=10),
        NodeState(node_id='srv2', trust=0.95, cpu_load=0.1, latency_ms=10),
        NodeState(node_id='lag', trust=0.55, cpu_load=0.9, latency_ms=90),   # strict worst
    ]
    rng = random.Random(0)
    # p2c alone never reaches it.
    p2c_only = [
        select_edge_node(states, weights, strategy=STRATEGY_P2C, rng=rng)[0]
        for _ in range(600)
    ]
    assert 'lag' not in p2c_only

    # p2c + epsilon does.
    rng = random.Random(0)
    with_eps = [
        select_edge_node(
            states, weights, strategy=STRATEGY_P2C, epsilon=0.1, rng=rng,
        )[0]
        for _ in range(600)
    ]
    assert with_eps.count('lag') > 0


def test_epsilon_zero_is_identical_to_no_exploration():
    """The default epsilon=0.0 must not perturb routing at all: same seed, same
    decisions as passing no epsilon."""
    weights = EdgeWeights()
    states = [
        NodeState(node_id='srv1', trust=0.8, cpu_load=0.2, latency_ms=20),
        NodeState(node_id='srv2', trust=0.6, cpu_load=0.4, latency_ms=40),
        NodeState(node_id='srv3', trust=0.7, cpu_load=0.3, latency_ms=30),
    ]
    a = [select_edge_node(states, weights, strategy=STRATEGY_P2C,
                          rng=random.Random(7))[0] for _ in range(1)]
    b = [select_edge_node(states, weights, strategy=STRATEGY_P2C, epsilon=0.0,
                          rng=random.Random(7))[0] for _ in range(1)]
    assert a == b


def test_epsilon_still_excludes_quarantined_nodes():
    """Security invariant holds under exploration too: the random pick is over
    eligible nodes only, so a quarantined node is never explored into."""
    weights = EdgeWeights()
    states = [
        NodeState(node_id='bad', trust=0.05, cpu_load=0.0, latency_ms=1),    # quarantined
        NodeState(node_id='srv2', trust=0.7, cpu_load=0.5, latency_ms=50),
        NodeState(node_id='srv3', trust=0.7, cpu_load=0.5, latency_ms=50),
    ]
    rng = random.Random(1)
    for _ in range(500):
        chosen, _, _ = select_edge_node(
            states, weights, strategy=STRATEGY_ARGMAX, epsilon=0.5, rng=rng,
        )
        assert chosen in {'srv2', 'srv3'}
