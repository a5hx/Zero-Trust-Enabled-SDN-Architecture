"""evaluation/liar_sweep.py -- the offline prediction for the Phase 1 liars.

Pins the shape of the result the live runs will be compared against, on short
single-seed runs, so a change to the selector or the trust arithmetic that
moves the prediction shows up here rather than in a 30-minute live sweep."""

import pytest

from evaluation import liar_sweep as ls


def test_the_p2c_ceiling():
    assert ls.share_ceiling(8, 2, 0.05) == pytest.approx(0.05 / 8 + 0.95 * 2 / 8)
    assert ls.share_ceiling(8, 2, 0.0) == pytest.approx(0.25)


def test_a_consistent_lie_does_not_pay_at_the_shipped_occupancy():
    """At ~1% duty the honest truth is ~0 too, so claiming 0 wins no ties,
    and the fabricated busy counter costs a little honesty -- which p2c,
    deciding by score, turns into lost comparisons."""
    c = ls.simulate(0.01, 'liar_consistent', gate_enforced=True, slots=False,
                    seed=1, sim_s=120)
    assert c.share < 1 / ls.N
    assert c.first_quarantine_s is None


def test_the_split_claim_gains_traffic_and_evades_the_gate():
    c = ls.simulate(0.4, 'liar_truthful', gate_enforced=True, slots=False,
                    seed=1, sim_s=120)
    assert c.excess > 0.02
    assert c.share <= ls.share_ceiling() + 0.01
    assert c.first_quarantine_s is None
    assert c.honest_quarantined_frac == 0.0


def test_a_consistent_liar_is_caught_once_occupancy_makes_the_gap_visible():
    # True duty at share s is about s*N*rho; the gap passes 0.40 above rho=0.2.
    c = ls.simulate(0.4, 'liar_consistent', gate_enforced=True, slots=False,
                    seed=1, sim_s=120)
    assert c.first_quarantine_s is not None and c.first_quarantine_s < 30
