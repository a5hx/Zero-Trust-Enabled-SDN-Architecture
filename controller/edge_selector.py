"""EdgeScore routing decision — the single source of truth for node selection.

    EdgeScore(n) = w1·T(n) + w2·(1 − cpu_load(n)) + w3·(1 − lat_norm(n))
    n* = argmax EdgeScore(n)     over non-quarantined nodes

Both the standalone balancer (controller/trust_balancer.py::TrustBalancerStandalone,
used by run_demo.py) and the live os-ken app (TrustBalancerApp) call into this, so
the formula exists in exactly one place.

Zero Trust exclusion is applied *before* ranking, not as a score penalty. A node is
quarantined when its trust falls below the isolation threshold OR its smoothed
anomaly level reaches the anomaly gate. The gate is load-bearing: see
contracts/thresholds.py for why the score alone cannot exclude a node that lies
about its load but still serves tasks well.

If every candidate is quarantined, selection returns None — deny by default rather
than fall back to an untrusted node.
"""

import random
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from contracts.thresholds import (
    DEFAULT_ANOMALY_GATE, DEFAULT_ANOMALY_WARN,
    DEFAULT_ISOLATION_THRESHOLD, DEFAULT_RATE_LIMIT_TRUST,
)

# Graduated-response bands, worst to best.
BAND_QUARANTINED = 'quarantined'
BAND_RATE_LIMITED = 'rate_limited'
BAND_FULL = 'full'

# Selection strategies (how the winner is picked among *eligible* nodes).
#   argmax -- the original winner-take-all: n* = argmax EdgeScore(n). One node
#             wins every decision; a node a hair behind never wins, and once
#             trust (the heaviest term) entrenches ~2 nodes the rest starve
#             regardless of how many servers exist. See docs/LOAD_BALANCING_STARVATION.md.
#   p2c    -- power-of-two-choices: sample d eligible nodes uniformly at random
#             and route to the best of that sample. Quarantine still excludes
#             malicious nodes *before* the sample, so security is unchanged, but
#             healthy nodes can no longer be permanently starved -- the standard
#             fix from Mitzenmacher, "The Power of Two Choices in Randomized Load
#             Balancing," IEEE TPDS 2001.
STRATEGY_ARGMAX = 'argmax'
STRATEGY_P2C = 'p2c'
DEFAULT_SELECTION_STRATEGY = STRATEGY_ARGMAX
DEFAULT_D_CHOICES = 2
# ε-exploration fraction. 0.0 disables it (routing depends only on the base
# strategy). A small positive value guarantees no eligible node is permanently
# starved even under frozen scores -- see select_edge_node's docstring.
DEFAULT_EPSILON = 0.0


@dataclass(frozen=True)
class EdgeWeights:
    """EdgeScore weights. Must sum to 1.0, each at least 0.05.

    The AI optimiser (trust_engine/ai_optimizer.py) will tune these at runtime,
    which is why the constraint is enforced here rather than assumed.
    """

    w1_trust: float = 0.50
    w2_cpu: float = 0.30
    w3_latency: float = 0.20

    def __post_init__(self) -> None:
        total = round(self.w1_trust + self.w2_cpu + self.w3_latency, 10)
        if total != 1.0:
            raise ValueError(
                f"EdgeScore weights must sum to 1.0, got {total} "
                f"(w1={self.w1_trust}, w2={self.w2_cpu}, w3={self.w3_latency})"
            )
        for name, w in (
            ('w1_trust', self.w1_trust),
            ('w2_cpu', self.w2_cpu),
            ('w3_latency', self.w3_latency),
        ):
            if w < 0.05:
                raise ValueError(f"EdgeScore weight {name} must be >= 0.05, got {w}")

    @classmethod
    def from_config(cls, cfg: Dict[str, float]) -> 'EdgeWeights':
        """Build from the `edge_score:` block of a params YAML."""
        return cls(
            w1_trust=cfg.get('w1_trust', 0.50),
            w2_cpu=cfg.get('w2_cpu', 0.30),
            w3_latency=cfg.get('w3_latency', 0.20),
        )


@dataclass
class NodeState:
    """Everything the router knows about one candidate edge node.

    Attributes:
        node_id: e.g. 'srv3'.
        trust: current trust score T(n) in [0, 1].
        cpu_load: the node's *claimed* CPU load in [0, 1]. Deliberately the claimed
            value, not the observed one — a dishonest node's lie is what makes it
            attractive here, and that is the attack we want to be able to show.
        latency_ms: observed round-trip latency for this node.
        anomaly: smoothed anomaly level Ā(n) in [0, 1], set by flow_monitor.
    """

    node_id: str
    trust: float
    cpu_load: float
    latency_ms: float
    anomaly: float = 0.0


def is_quarantined(
    state: NodeState,
    isolation_threshold: float = DEFAULT_ISOLATION_THRESHOLD,
    anomaly_gate: float = DEFAULT_ANOMALY_GATE,
) -> bool:
    """True if this node must be excluded from routing entirely."""
    return state.trust < isolation_threshold or state.anomaly >= anomaly_gate


def trust_band(
    state: NodeState,
    isolation_threshold: float = DEFAULT_ISOLATION_THRESHOLD,
    anomaly_gate: float = DEFAULT_ANOMALY_GATE,
    rate_limit_trust: float = DEFAULT_RATE_LIMIT_TRUST,
    anomaly_warn: float = DEFAULT_ANOMALY_WARN,
) -> str:
    """Classify a node into the graduated-response band it currently sits in:
    BAND_QUARANTINED (excluded), BAND_RATE_LIMITED (served but metered), or
    BAND_FULL (unrestricted). The quarantine test is applied first so the hard
    safety rails always win over the softer rate-limit band.
    """
    if is_quarantined(state, isolation_threshold, anomaly_gate):
        return BAND_QUARANTINED
    if state.trust < rate_limit_trust or state.anomaly >= anomaly_warn:
        return BAND_RATE_LIMITED
    return BAND_FULL


def edge_score(
    state: NodeState,
    weights: EdgeWeights,
    max_latency_ms: float,
) -> float:
    """Score a single node. Higher is better.

    Args:
        state: the node's current trust/load/latency.
        weights: w1/w2/w3.
        max_latency_ms: the largest latency across all candidates, used to
            normalise latency into [0, 1]. Floored at 1.0 to avoid dividing by zero.
    """
    lat_norm = state.latency_ms / max(max_latency_ms, 1.0)
    return (
        weights.w1_trust * state.trust
        + weights.w2_cpu * (1.0 - state.cpu_load)
        + weights.w3_latency * (1.0 - lat_norm)
    )


_round_robin_counter = 0


def select_edge_node(
    states: Sequence[NodeState],
    weights: EdgeWeights,
    isolation_threshold: float = DEFAULT_ISOLATION_THRESHOLD,
    anomaly_gate: float = DEFAULT_ANOMALY_GATE,
    tie_epsilon: float = 1e-9,
    strategy: str = DEFAULT_SELECTION_STRATEGY,
    d_choices: int = DEFAULT_D_CHOICES,
    epsilon: float = DEFAULT_EPSILON,
    rng: Optional[random.Random] = None,
) -> Tuple[Optional[str], float, List[Tuple[str, float]]]:
    """Pick the winning node among non-quarantined candidates.

    Quarantine is always applied first, so `strategy`/`epsilon` only ever decide
    *which* eligible node wins, never whether a malicious node can be chosen.

    strategy='argmax' (default): n* = argmax EdgeScore(n). Exact ties (e.g. every
        node at t=0 holding initial_score) are broken round-robin so the first
        seconds of a run aren't a sorting artifact. This is winner-take-all and
        can permanently starve a healthy node that sits a hair behind — see
        docs/LOAD_BALANCING_STARVATION.md.
    strategy='p2c': power-of-two-choices. Sample min(d_choices, len(eligible))
        eligible nodes uniformly at random and return the best-scoring of the
        sample. Breaks the starvation lock-in while still excluding quarantined
        nodes. `rng` is injectable for reproducible runs/tests; it defaults to
        the module `random`.

    epsilon > 0: ε-exploration on top of whichever base strategy is chosen. With
        probability epsilon the decision ignores the score and routes to a
        uniformly random eligible node. This closes the one gap p2c leaves — the
        strict-worst node under frozen scores is never the better of any sampled
        pair, so it can still be starved by p2c alone; ε-exploration guarantees
        every eligible node is selected with probability >= epsilon/|eligible|
        per decision, so no eligible node can be permanently starved. Off (0.0)
        by default, so it never perturbs a run that doesn't ask for it.

    Returns:
        (chosen_node_id, its_score, all_scores) where all_scores is
        [(node_id, score), ...] for the *eligible* nodes only, sorted best-first
        (the full ranking, for logging why a decision was made — note under p2c
        the chosen node need not be all_scores[0]). chosen_node_id is None when
        every candidate is quarantined — the caller must then deny the request
        rather than route to an untrusted node.
    """
    global _round_robin_counter

    eligible = [
        s for s in states
        if not is_quarantined(s, isolation_threshold, anomaly_gate)
    ]
    if not eligible:
        return None, 0.0, []

    # Latency is normalised over the whole eligible set (not just any sampled
    # subset) so a node's score means the same thing regardless of who it was
    # compared against this decision.
    max_latency = max((s.latency_ms for s in eligible), default=1.0)
    scored = [(s.node_id, edge_score(s, weights, max_latency)) for s in eligible]
    scored.sort(key=lambda pair: pair[1], reverse=True)

    r = rng or random

    # ε-exploration: route to a uniformly random eligible node with probability
    # epsilon, independent of the base strategy. Guarantees no eligible node is
    # permanently starved (see the epsilon note in the docstring).
    if epsilon > 0.0 and r.random() < epsilon:
        return (*r.choice(scored), scored)

    if strategy == STRATEGY_P2C:
        d = max(1, min(d_choices, len(scored)))
        sample = r.sample(scored, d)
        best_id, best_score = max(sample, key=lambda pair: pair[1])
        return best_id, best_score, scored

    top_score = scored[0][1]
    tied = [pair for pair in scored if abs(pair[1] - top_score) <= tie_epsilon]
    if len(tied) > 1:
        tied.sort(key=lambda pair: pair[0])
        best_id, best_score = tied[_round_robin_counter % len(tied)]
        _round_robin_counter += 1
    else:
        best_id, best_score = scored[0]

    return best_id, best_score, scored
