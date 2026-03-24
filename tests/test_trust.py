"""Unit tests for the TrustCalculator.

Tests T-01 through T-07 as specified in the Semester 1 review requirements.
"""

import sys
import os
import pytest

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from trust_engine.trust_calculator import TrustCalculator
from contracts.trust_update import TrustUpdate


def _make_update(
    node_id: str = 'srv1',
    status: str = 'success',
    cpu: float = 0.3,
    reported_cpu: float = 0.3,
    latency: float = 20.0,
    anomaly: bool = False,
) -> TrustUpdate:
    """Helper to create a TrustUpdate with sensible defaults."""
    return TrustUpdate(
        device_id='iot_test',
        edge_node_id=node_id,
        task_status=status,
        cpu_usage=cpu,
        reported_cpu=reported_cpu,
        latency_ms=latency,
        anomaly_flag=anomaly,
    )


class TestTrustCalculator:
    """T-01 through T-07: TrustCalculator test suite."""

    def test_t01_good_node_converges_high(self) -> None:
        """T-01: 20 success updates, honesty_delta=0, no anomaly → T > 0.80.

        Note: formula max is α+β+γ = 0.85 (when A̅=0), so threshold is 0.80.
        """
        tc = TrustCalculator()
        for _ in range(20):
            upd = _make_update(status='success', cpu=0.3, reported_cpu=0.3,
                               latency=0.0, anomaly=False)
            tc.update(upd)
        assert tc.get_score('srv1') > 0.80, f"Expected > 0.80, got {tc.get_score('srv1')}"

    def test_t02_bad_node_converges_low(self) -> None:
        """T-02: 20 failure updates, anomaly_flag=True → T < 0.10."""
        tc = TrustCalculator()
        for _ in range(20):
            upd = _make_update(status='failure', cpu=0.8, reported_cpu=0.1,
                               latency=400.0, anomaly=True)
            tc.update(upd)
        assert tc.get_score('srv1') < 0.10, f"Expected < 0.10, got {tc.get_score('srv1')}"

    def test_t03_weights_dont_sum_to_one(self) -> None:
        """T-03: Weights that don't sum to 1.0 → AssertionError."""
        with pytest.raises(AssertionError):
            TrustCalculator(alpha=0.5, beta=0.5, gamma=0.5, delta=0.5)

    def test_t04_unseen_node_returns_initial(self) -> None:
        """T-04: Query node before first update → returns 0.5."""
        tc = TrustCalculator()
        assert tc.get_score('srv_unseen') == 0.5

    def test_t05_trust_drops_then_recovers(self) -> None:
        """T-05: 10 good → 1 malicious → 5 good → trust drops then recovers."""
        tc = TrustCalculator()

        # 10 good updates
        for _ in range(10):
            tc.update(_make_update(status='success', anomaly=False))
        score_before_attack = tc.get_score('srv1')

        # 1 malicious update
        tc.update(_make_update(status='failure', cpu=0.9, reported_cpu=0.1,
                               latency=450.0, anomaly=True))
        score_after_attack = tc.get_score('srv1')

        # 5 good recovery updates
        for _ in range(5):
            tc.update(_make_update(status='success', anomaly=False))
        score_after_recovery = tc.get_score('srv1')

        # Trust should have dropped after the malicious update
        assert score_after_attack < score_before_attack, (
            f"Trust should drop: {score_before_attack:.4f} → {score_after_attack:.4f}"
        )
        # Trust should recover after good updates
        assert score_after_recovery > score_after_attack, (
            f"Trust should recover: {score_after_attack:.4f} → {score_after_recovery:.4f}"
        )

    def test_t06_extreme_inputs_stay_bounded(self) -> None:
        """T-06: Extreme inputs (all 0s, all 1s) → T always in [0, 1]."""
        tc = TrustCalculator()

        # All zeros
        for _ in range(10):
            upd = _make_update(status='failure', cpu=0.0, reported_cpu=1.0,
                               latency=1000.0, anomaly=True)
            score = tc.update(upd)
            assert 0.0 <= score <= 1.0, f"Score out of bounds: {score}"

        # All ones  (reset with a new node)
        for _ in range(10):
            upd = _make_update(node_id='srv2', status='success', cpu=1.0,
                               reported_cpu=1.0, latency=0.0, anomaly=False)
            score = tc.update(upd)
            assert 0.0 <= score <= 1.0, f"Score out of bounds: {score}"

    def test_t07_honesty_delta_high_pushes_h_low(self) -> None:
        """T-07: honesty_delta = 0.5 → H EMA trends toward 0."""
        tc = TrustCalculator()
        for _ in range(20):
            upd = _make_update(
                status='success',
                cpu=0.7,
                reported_cpu=0.2,  # delta = 0.5
                latency=20.0,
                anomaly=False,
            )
            tc.update(upd)

        # The H component (honesty) should have driven the score down
        # compared to a perfectly honest node
        tc_honest = TrustCalculator()
        for _ in range(20):
            upd = _make_update(
                status='success',
                cpu=0.3,
                reported_cpu=0.3,  # delta = 0.0
                latency=20.0,
                anomaly=False,
            )
            tc_honest.update(upd)

        assert tc.get_score('srv1') < tc_honest.get_score('srv1'), (
            f"Dishonest node ({tc.get_score('srv1'):.4f}) should score lower "
            f"than honest ({tc_honest.get_score('srv1'):.4f})"
        )
