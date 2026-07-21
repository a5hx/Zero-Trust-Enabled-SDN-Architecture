"""Tests for trust_engine/ai_optimizer.py -- the online UCB1 weight optimizer and
its reward function. All pure Python, no os-ken / Mininet."""

import math

import pytest

from controller.edge_selector import EdgeWeights
from trust_engine.ai_optimizer import (
    RewardWindow,
    StaticWeightOptimizer,
    UCB1WeightOptimizer,
    build_optimizer,
    compute_reward,
)


ARMS = [
    EdgeWeights(0.50, 0.30, 0.20),
    EdgeWeights(0.70, 0.20, 0.10),
    EdgeWeights(0.34, 0.50, 0.16),
    EdgeWeights(0.34, 0.16, 0.50),
    EdgeWeights(0.45, 0.45, 0.10),
]


# --------------------------------------------------------------------------- #
# Reward function                                                             #
# --------------------------------------------------------------------------- #
def test_compute_reward_is_success_rate_when_no_penalty_signal():
    w = RewardWindow(successes=8, failures=2, timeouts=0)
    # No latency samples, single/no load sample -> penalties are zero.
    assert compute_reward(w) == pytest.approx(0.8)


def test_compute_reward_penalizes_latency():
    fast = RewardWindow(successes=10)
    fast.latency_samples = [0.1, 0.1]
    slow = RewardWindow(successes=10)
    slow.latency_samples = [0.9, 0.9]
    assert compute_reward(fast) > compute_reward(slow)


def test_compute_reward_penalizes_load_imbalance():
    balanced = RewardWindow(successes=10, load_samples=[0.5, 0.5, 0.5])
    lopsided = RewardWindow(successes=10, load_samples=[0.0, 0.0, 1.0])
    assert compute_reward(balanced) > compute_reward(lopsided)


def test_compute_reward_flat_when_all_succeed_and_uniform():
    """The documented 'needs stress' finding: with a saturated success rate, no
    latency signal, and uniform load, every arm looks identical (reward == 1.0),
    so the bandit cannot learn until the environment actually punishes a choice."""
    a = RewardWindow(successes=10, load_samples=[0.4, 0.4, 0.4])
    b = RewardWindow(successes=10, load_samples=[0.6, 0.6, 0.6])
    assert compute_reward(a) == compute_reward(b) == pytest.approx(1.0)


def test_compute_reward_timeouts_count_against_success():
    w = RewardWindow(successes=5, timeouts=5)
    assert compute_reward(w) == pytest.approx(0.5)


def test_compute_reward_empty_window_is_zero():
    assert compute_reward(RewardWindow()) == 0.0


# --------------------------------------------------------------------------- #
# Static (off) optimizer                                                       #
# --------------------------------------------------------------------------- #
def test_static_optimizer_is_a_noop():
    fixed = EdgeWeights(0.6, 0.3, 0.1)
    opt = StaticWeightOptimizer(fixed)
    assert opt.active_weights() is fixed
    opt.observe(0.0)
    opt.observe(1.0)
    assert opt.select() is fixed
    assert opt.active_weights() is fixed  # unchanged by any feedback


# --------------------------------------------------------------------------- #
# UCB1 bandit                                                                  #
# --------------------------------------------------------------------------- #
def test_ucb1_requires_at_least_one_arm():
    with pytest.raises(ValueError):
        UCB1WeightOptimizer(arms=[])


def test_ucb1_explores_each_arm_once_before_repeating():
    opt = UCB1WeightOptimizer(ARMS)
    seen = []
    for _ in range(len(ARMS)):
        opt.select()
        seen.append(opt.active_index)
        opt.observe(0.5)  # identical reward so only the cold-start rule matters
    assert sorted(seen) == list(range(len(ARMS)))  # each arm exactly once


def test_ucb1_converges_to_the_rewarding_arm():
    opt = UCB1WeightOptimizer(ARMS, exploration_c=0.5)
    best = 3
    counts = [0] * len(ARMS)
    for _ in range(500):
        w = opt.select()
        i = opt.active_index
        counts[i] += 1
        # Arm `best` pays 1.0, everything else 0.0.
        opt.observe(1.0 if i == best else 0.0)
    # The rewarding arm should be pulled far more than any other.
    assert counts[best] == max(counts)
    assert counts[best] > sum(counts) / 2


def test_ucb1_high_c_keeps_exploring():
    """A large exploration constant should keep revisiting non-best arms rather
    than collapsing onto one, proving the exploration bonus is live."""
    opt = UCB1WeightOptimizer(ARMS, exploration_c=50.0)
    counts = [0] * len(ARMS)
    for _ in range(500):
        opt.select()
        i = opt.active_index
        counts[i] += 1
        opt.observe(1.0 if i == 0 else 0.0)
    # Every arm keeps getting meaningful attention under heavy exploration.
    assert all(c > 20 for c in counts)


def test_ucb1_active_weights_defined_before_first_select():
    opt = UCB1WeightOptimizer(ARMS)
    assert opt.active_weights() == ARMS[0]


def test_ucb1_incremental_mean_matches_plain_average():
    opt = UCB1WeightOptimizer([ARMS[0]])  # single arm so every select hits it
    rewards = [0.2, 0.8, 0.5, 1.0, 0.0]
    for r in rewards:
        opt.select()
        opt.observe(r)
    stats = opt.stats()[0]
    assert stats['mean_reward'] == pytest.approx(sum(rewards) / len(rewards))
    assert stats['count'] == len(rewards)


# --------------------------------------------------------------------------- #
# Config factory                                                               #
# --------------------------------------------------------------------------- #
def test_build_optimizer_off_by_default_returns_static():
    opt = build_optimizer(None, fallback=EdgeWeights(0.5, 0.3, 0.2))
    assert isinstance(opt, StaticWeightOptimizer)
    opt2 = build_optimizer({'enabled': False, 'arms': [[0.7, 0.2, 0.1]]},
                           fallback=EdgeWeights())
    assert isinstance(opt2, StaticWeightOptimizer)


def test_build_optimizer_enabled_returns_ucb1():
    cfg = {
        'enabled': True,
        'algorithm': 'ucb1',
        'arms': [[0.50, 0.30, 0.20], [0.70, 0.20, 0.10]],
        'exploration_c': 1.41,
    }
    opt = build_optimizer(cfg, fallback=EdgeWeights())
    assert isinstance(opt, UCB1WeightOptimizer)
    assert opt.active_weights() == EdgeWeights(0.50, 0.30, 0.20)


def test_build_optimizer_rejects_invalid_arm():
    cfg = {'enabled': True, 'arms': [[0.5, 0.5, 0.5]]}  # sums to 1.5
    with pytest.raises(ValueError):
        build_optimizer(cfg, fallback=EdgeWeights())


def test_build_optimizer_rejects_unknown_algorithm():
    cfg = {'enabled': True, 'algorithm': 'deep_q', 'arms': [[0.5, 0.3, 0.2]]}
    with pytest.raises(ValueError):
        build_optimizer(cfg, fallback=EdgeWeights())


def test_ucb1_from_config_defaults_to_single_balanced_arm():
    opt = UCB1WeightOptimizer.from_config({})
    assert opt.active_weights() == EdgeWeights(0.50, 0.30, 0.20)
