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
) -> Tuple[Optional[str], float, List[Tuple[str, float]]]:
    """Pick n* = argmax EdgeScore(n) among non-quarantined nodes.

    Ties (e.g. every node at t=0, all holding initial_score) are broken by
    round-robin rather than always picking the first node in `states` — otherwise
    the routing-distribution figure looks skewed for the first several seconds of
    any run, purely as a sorting artifact rather than a real trust/load signal.

    Returns:
        (chosen_node_id, its_score, all_scores) where all_scores is
        [(node_id, score), ...] for the *eligible* nodes only, sorted best-first
        (useful for logging why a decision was made). chosen_node_id is None when
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

    max_latency = max((s.latency_ms for s in eligible), default=1.0)
    scored = [(s.node_id, edge_score(s, weights, max_latency)) for s in eligible]
    scored.sort(key=lambda pair: pair[1], reverse=True)

    top_score = scored[0][1]
    tied = [pair for pair in scored if abs(pair[1] - top_score) <= tie_epsilon]
    if len(tied) > 1:
        tied.sort(key=lambda pair: pair[0])
        best_id, best_score = tied[_round_robin_counter % len(tied)]
        _round_robin_counter += 1
    else:
        best_id, best_score = scored[0]

    return best_id, best_score, scored
