"""EMA-based trust calculator for edge nodes in the Zero Trust SDN architecture.

Trust formula:
    T(t) = α·R̄(t) + β·B̄(t) + γ·H̄(t) − δ·Ā(t)

Where each component uses Exponential Moving Average:
    X̄(t) = λ·X(t) + (1−λ)·X̄(t−1)
"""

import logging
from typing import Dict

from contracts.trust_update import TrustUpdate

logger = logging.getLogger(__name__)

# Task status → reputation raw value mapping
_STATUS_MAP: Dict[str, float] = {
    'success': 1.0,
    'failure': 0.0,
    'timeout': 0.3,
}


class TrustCalculator:
    """Calculates and tracks per-node trust scores using EMA-smoothed components.

    Attributes:
        alpha: Reputation weight.
        beta: Behavioural consistency weight.
        gamma: Resource honesty weight.
        delta: Attack suspicion weight.
        lambda_decay: EMA decay factor.
        initial_score: Starting trust for unseen nodes.
    """

    def __init__(
        self,
        alpha: float = 0.35,
        beta: float = 0.25,
        gamma: float = 0.25,
        delta: float = 0.15,
        lambda_decay: float = 0.85,
        initial_score: float = 0.5,
    ) -> None:
        """Initialise the TrustCalculator.

        Raises:
            AssertionError: If alpha + beta + gamma + delta != 1.0
        """
        weight_sum = round(alpha + beta + gamma + delta, 10)
        assert weight_sum == 1.0, (
            f"Trust weights must sum to 1.0, got {weight_sum} "
            f"(a={alpha}, b={beta}, g={gamma}, d={delta})"
        )

        self.alpha = alpha
        self.beta = beta
        self.gamma = gamma
        self.delta = delta
        self.lambda_decay = lambda_decay
        self.initial_score = initial_score

        # Per-node EMA state: {node_id: {'R': float, 'B': float, 'H': float, 'A': float}}
        self._ema: Dict[str, Dict[str, float]] = {}
        # Per-node final trust score cache
        self._scores: Dict[str, float] = {}

        logger.info(
            "TrustCalculator initialised: a=%.2f b=%.2f g=%.2f d=%.2f lam=%.2f",
            alpha, beta, gamma, delta, lambda_decay,
        )

    def _init_node(self, node_id: str) -> None:
        """Initialise EMA state for a previously-unseen node."""
        self._ema[node_id] = {
            'R': self.initial_score,
            'B': self.initial_score,
            'H': self.initial_score,
            'A': 0.0,
        }
        self._scores[node_id] = self.initial_score

    def update(self, upd: TrustUpdate) -> float:
        """Process a TrustUpdate and return the new trust score.

        Updates the EMA state for the edge node identified in the update,
        computes the new composite trust score, and clips it to [0.0, 1.0].

        Args:
            upd: A TrustUpdate record with task outcome and telemetry.

        Returns:
            The updated trust score in [0.0, 1.0].
        """
        node_id = upd.edge_node_id

        if node_id not in self._ema:
            self._init_node(node_id)

        ema = self._ema[node_id]
        lam = self.lambda_decay

        # --- Raw component values ---
        r_raw = _STATUS_MAP.get(upd.task_status, 0.3)
        b_raw = max(0.0, 1.0 - upd.latency_ms / 500.0)
        h_raw = max(0.0, 1.0 - upd.honesty_delta() / 0.5)
        a_raw = 1.0 if upd.anomaly_flag else 0.0

        # --- EMA smoothing ---
        ema['R'] = lam * r_raw + (1 - lam) * ema['R']
        ema['B'] = lam * b_raw + (1 - lam) * ema['B']
        ema['H'] = lam * h_raw + (1 - lam) * ema['H']
        ema['A'] = lam * a_raw + (1 - lam) * ema['A']

        # --- Composite trust score ---
        score = (
            self.alpha * ema['R']
            + self.beta * ema['B']
            + self.gamma * ema['H']
            - self.delta * ema['A']
        )
        score = max(0.0, min(1.0, score))

        # Store and annotate the update
        upd.trust_score_before = self._scores.get(node_id, self.initial_score)
        self._scores[node_id] = score
        upd.trust_score_after = score

        logger.debug(
            "Trust update: node=%s status=%s score=%.4f->%.4f "
            "(R=%.3f B=%.3f H=%.3f A=%.3f)",
            node_id, upd.task_status,
            upd.trust_score_before, score,
            ema['R'], ema['B'], ema['H'], ema['A'],
        )

        return score

    def get_score(self, node_id: str) -> float:
        """Return the current trust score for a node, or initial_score if unseen."""
        return self._scores.get(node_id, self.initial_score)

    def get_all_scores(self) -> Dict[str, float]:
        """Return a copy of all tracked node trust scores."""
        return dict(self._scores)
