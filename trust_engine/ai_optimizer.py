"""Online AI weight optimizer for the EdgeScore routing policy.

The router scores nodes with EdgeScore(n) = w1·T(n) + w2·(1−cpu) + w3·(1−lat),
and until now w1/w2/w3 were hand-picked constants (0.50/0.30/0.20). This module
learns them instead, live, from measured outcomes.

Design (Part 1 of the deck's "AI weight optimizer"):
  - ONLINE UCB1 bandit — implemented here. Needs no dataset: it generates its own
    experience by trying weight presets ("arms") and observing a reward per window.
  - OFFLINE Random Forest — deliberately NOT here. It needs a batch of logged runs
    to train on, which the evaluation harness produces. When it lands, it plugs in
    behind the same WeightOptimizer protocol below (as its own optimizer, or as a
    warm-start prior seeding UCB1's value estimates) with no change to the
    controller. See docs/AI_OPTIMIZER.md.

Everything here is pure Python with no os-ken / Mininet / network dependency, so
it is unit-testable in isolation. TrustState owns a WeightOptimizer and drives it;
this module never touches TrustState, a lock, or a socket.

Safety invariant: the optimizer only ever rewrites w1/w2/w3. The quarantine gates
(isolation_threshold, anomaly_gate) are NOT its concern — a malicious node can
never be weighted back into eligibility, because exclusion happens before scoring
(see controller/edge_selector.select_edge_node). Every arm is a real EdgeWeights,
so the sum-to-1.0 / floor-0.05 constraints are enforced at construction.
"""

import logging
import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Protocol, Sequence, Tuple

from controller.edge_selector import EdgeWeights

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Reward                                                                       #
# --------------------------------------------------------------------------- #
@dataclass
class RewardWindow:
    """Accumulates the outcomes observed while one arm was active.

    TrustState fills this in as task reports arrive, then hands it to
    compute_reward() when the window closes. Kept dependency-free so the reward
    math is a pure, testable function of what happened.
    """

    successes: int = 0
    failures: int = 0
    timeouts: int = 0
    # Normalized latency of the chosen node at each routing decision, in [0, 1].
    latency_samples: List[float] = field(default_factory=list)
    # Per-node observed_load snapshot taken when the window closed, in [0, 1].
    load_samples: List[float] = field(default_factory=list)

    @property
    def total_outcomes(self) -> int:
        return self.successes + self.failures + self.timeouts

    def record_outcome(self, task_status: str) -> None:
        if task_status == 'success':
            self.successes += 1
        elif task_status == 'timeout':
            self.timeouts += 1
        else:  # 'failure' or anything unexpected counts against success_rate
            self.failures += 1

    def record_latency(self, normalized_latency: float) -> None:
        self.latency_samples.append(max(0.0, min(1.0, normalized_latency)))


def compute_reward(
    window: RewardWindow,
    latency_penalty: float = 0.2,
    imbalance_penalty: float = 0.2,
) -> float:
    """Scalar reward for the arm that was active during `window`. Higher is better.

        reward = success_rate − λ·mean_normalized_latency − μ·load_imbalance

    - success_rate rewards routing to nodes that actually complete tasks. This is
      the dominant term and the one that punishes routing to a failing/malicious
      node hard.
    - mean_normalized_latency (λ term) rewards fast nodes. Without it the reward is
      *flat* whenever the network is healthy enough that everything succeeds
      regardless of weights, and the bandit has no gradient to learn from — so
      this term is what lets it distinguish arms in the common, non-degraded case.
    - load_imbalance (μ term), the stdev of per-node observed_load, rewards
      spreading work rather than piling it on one node.

    Returns 0.0 for an empty window (no outcomes and no samples) so an idle window
    neither rewards nor punishes the active arm.
    """
    if window.total_outcomes == 0 and not window.latency_samples and not window.load_samples:
        return 0.0

    success_rate = (
        window.successes / window.total_outcomes if window.total_outcomes else 0.0
    )
    mean_latency = (
        sum(window.latency_samples) / len(window.latency_samples)
        if window.latency_samples else 0.0
    )
    imbalance = _stdev(window.load_samples)

    return success_rate - latency_penalty * mean_latency - imbalance_penalty * imbalance


def _stdev(values: Sequence[float]) -> float:
    """Population standard deviation; 0.0 for fewer than two samples."""
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    variance = sum((v - mean) ** 2 for v in values) / n
    return math.sqrt(variance)


# --------------------------------------------------------------------------- #
# Optimizer protocol + implementations                                         #
# --------------------------------------------------------------------------- #
class WeightOptimizer(Protocol):
    """What TrustState needs from any weight-tuning strategy.

    The controller reads active_weights() on every routing decision, and once per
    window feeds back a reward (observe) then asks for the next arm (select). The
    offline Random Forest optimizer will implement this same protocol later.
    """

    def active_weights(self) -> EdgeWeights:
        """The EdgeWeights to route with right now."""
        ...

    def observe(self, reward: float) -> None:
        """Credit the reward for the window that just closed to the active arm."""
        ...

    def select(self) -> EdgeWeights:
        """Choose (and make active) the arm for the next window; return it."""
        ...


class StaticWeightOptimizer:
    """The "optimizer off" implementation: one fixed EdgeWeights, forever.

    This is the default so TrustState always has a WeightOptimizer and callers need
    no `if optimizer_enabled:` guards — the same inert-twin trick as NullBus /
    NullAuthenticator. observe()/select() are no-ops; routing behaviour is
    byte-for-byte identical to the pre-optimizer controller.
    """

    def __init__(self, weights: Optional[EdgeWeights] = None) -> None:
        self._weights = weights or EdgeWeights()

    def active_weights(self) -> EdgeWeights:
        return self._weights

    def observe(self, reward: float) -> None:  # noqa: D401 - intentional no-op
        pass

    def select(self) -> EdgeWeights:
        return self._weights


class UCB1WeightOptimizer:
    """Upper-Confidence-Bound (UCB1) bandit over a discrete set of weight presets.

    Each arm is one EdgeWeights preset. UCB1 balances exploiting the best arm so
    far against exploring under-tried arms: after pulling every arm once, it picks

        argmax_i  value_i + c · sqrt( ln(total_pulls) / count_i )

    where value_i is the mean reward seen for arm i. The sqrt term is large for
    arms tried few times, so no arm is starved; as counts grow it shrinks and the
    choice converges on the genuinely best-performing weights.

    Discrete arms (not a continuous weight search) because UCB1 is a discrete-arm
    algorithm — this matches the deck's stated design. UCB1 also assumes a
    stationary reward distribution; if the environment shifts mid-run (e.g. an
    attack starts) the best arm can change and plain UCB1 adapts only slowly. That
    is an accepted, documented limitation for this project (discounted-UCB is a
    future option). See docs/AI_OPTIMIZER.md.
    """

    def __init__(
        self,
        arms: Sequence[EdgeWeights],
        exploration_c: float = math.sqrt(2),
    ) -> None:
        if not arms:
            raise ValueError("UCB1WeightOptimizer needs at least one arm")
        self._arms: List[EdgeWeights] = list(arms)
        self._c = exploration_c
        self._counts: List[int] = [0] * len(self._arms)
        self._values: List[float] = [0.0] * len(self._arms)
        self._total_pulls = 0
        # The arm currently active (last returned by select()). Starts at arm 0 so
        # active_weights() is well-defined before the first select().
        self._active_index = 0

    @classmethod
    def from_config(cls, cfg: Dict) -> 'UCB1WeightOptimizer':
        """Build from the `optimizer:` block of a params YAML.

        `arms` is a list of [w1, w2, w3] triples; each is validated by EdgeWeights
        (sum to 1.0, each >= 0.05), so a malformed arm raises here at startup
        rather than mid-run.
        """
        raw_arms = cfg.get('arms') or [[0.50, 0.30, 0.20]]
        arms = [
            EdgeWeights(w1_trust=a[0], w2_cpu=a[1], w3_latency=a[2])
            for a in raw_arms
        ]
        return cls(arms=arms, exploration_c=cfg.get('exploration_c', math.sqrt(2)))

    def active_weights(self) -> EdgeWeights:
        return self._arms[self._active_index]

    def observe(self, reward: float) -> None:
        """Incremental-mean update of the active arm's value estimate."""
        i = self._active_index
        self._counts[i] += 1
        self._total_pulls += 1
        n = self._counts[i]
        # Running mean: value += (reward - value) / n
        self._values[i] += (reward - self._values[i]) / n
        logger.debug(
            "UCB1 observe: arm=%d reward=%.4f -> value=%.4f count=%d",
            i, reward, self._values[i], n,
        )

    def select(self) -> EdgeWeights:
        """Pick the next arm by the UCB1 rule and make it active."""
        # Cold start: pull any never-tried arm first, so every arm has a baseline.
        for i, count in enumerate(self._counts):
            if count == 0:
                self._active_index = i
                return self._arms[i]

        best_index = 0
        best_ucb = float('-inf')
        for i in range(len(self._arms)):
            bonus = self._c * math.sqrt(math.log(self._total_pulls) / self._counts[i])
            ucb = self._values[i] + bonus
            if ucb > best_ucb:
                best_ucb = ucb
                best_index = i

        self._active_index = best_index
        return self._arms[best_index]

    def seed_values(self, values: Sequence[float], pseudo_count: int = 3) -> None:
        """Warm-start value_i from an external prior (offline Random Forest,
        docs/AI_OPTIMIZER.md Part 2), instead of the cold-start-at-zero default.

        Must be called before any observe()/select(); it does not change the
        WeightOptimizer protocol -- this is an extra method on the concrete
        UCB1 class, exactly like active_index/stats below. Setting every count
        to the same pseudo_count keeps the exploration bonus equal across arms
        at the first select() (so the prior's mean-reward ordering, not an
        artifact of unequal counts, decides which arm is picked first), while
        still letting observe()'s incremental mean bend the estimate toward
        real evidence at pseudo_count's weight rather than staying pinned to
        the prior forever.
        """
        if len(values) != len(self._arms):
            raise ValueError(
                f"expected {len(self._arms)} prior values, got {len(values)}"
            )
        if pseudo_count < 1:
            raise ValueError("pseudo_count must be >= 1")
        self._values = list(values)
        self._counts = [pseudo_count] * len(self._arms)
        self._total_pulls = pseudo_count * len(self._arms)

    # -- introspection (backs GET /api/optimizer and logging) ---------------- #
    @property
    def active_index(self) -> int:
        return self._active_index

    def stats(self) -> List[Dict]:
        """Per-arm snapshot for the REST API / dashboard / optimizer log."""
        return [
            {
                'arm': i,
                'weights': [a.w1_trust, a.w2_cpu, a.w3_latency],
                'count': self._counts[i],
                'mean_reward': round(self._values[i], 4),
                'active': i == self._active_index,
            }
            for i, a in enumerate(self._arms)
        ]


def build_optimizer(cfg: Optional[Dict], fallback: EdgeWeights) -> WeightOptimizer:
    """Factory used by the controller: turn the `optimizer:` config block into a
    WeightOptimizer. Returns a StaticWeightOptimizer (behaviour unchanged from the
    pre-optimizer controller) when the block is absent or `enabled: false`.
    """
    if not cfg or not cfg.get('enabled', False):
        return StaticWeightOptimizer(fallback)

    algorithm = cfg.get('algorithm', 'ucb1')
    if algorithm == 'ucb1':
        opt = UCB1WeightOptimizer.from_config(cfg)
        logger.info(
            "AI optimizer ON: UCB1 over %d arms, exploration_c=%.3f",
            len(opt._arms), opt._c,
        )
        return opt

    raise ValueError(f"Unknown optimizer algorithm: {algorithm!r}")
