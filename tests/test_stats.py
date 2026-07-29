"""Unit tests for the significance layer (evaluation/stats.py).

Tests S-01 through S-13.

A statistics module that is subtly wrong produces confident, wrong conclusions,
so the correction and effect-size code is checked against hand-computable cases
and against scipy directly rather than only for self-consistency.
"""

import sys
import os

import pytest
from scipy.stats import wilcoxon

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from evaluation import stats as S


def _rows(scenario: str, strategy: str, values, metric='slo_violation_rate'):
    return [
        {'scenario': scenario, 'strategy': strategy, 'seed': str(i), metric: str(v)}
        for i, v in enumerate(values)
    ]


class TestHolmBonferroni:
    """S-01 to S-04."""

    def test_s01_matches_worked_example(self) -> None:
        """S-01: Textbook step-down values.

        p = [0.01, 0.02, 0.03, 0.04] with m=4 scales by 4,3,2,1 giving
        [0.04, 0.06, 0.06, 0.04], then monotonicity forces the running maximum:
        [0.04, 0.06, 0.06, 0.06].
        """
        assert S.holm_bonferroni([0.01, 0.02, 0.03, 0.04]) == pytest.approx(
            [0.04, 0.06, 0.06, 0.06]
        )

    def test_s02_preserves_input_order(self) -> None:
        """S-02: Adjusted values come back positionally matched, not sorted."""
        adjusted = S.holm_bonferroni([0.04, 0.01, 0.03, 0.02])
        assert adjusted == pytest.approx([0.06, 0.04, 0.06, 0.06])

    def test_s03_is_monotone_and_never_below_raw(self) -> None:
        """S-03: Correction only ever makes a p-value larger, and never reorders."""
        raw = [0.001, 0.9, 0.02, 0.049, 0.3]
        adjusted = S.holm_bonferroni(raw)
        for r, a in zip(raw, adjusted):
            assert a >= r - 1e-12, "correction made a p-value smaller"
            assert a <= 1.0
        by_rank = sorted(zip(raw, adjusted))
        assert all(
            by_rank[i][1] <= by_rank[i + 1][1] + 1e-12 for i in range(len(by_rank) - 1)
        ), "adjusted p-values are not monotone in the raw ordering"

    def test_s04_edge_cases(self) -> None:
        assert S.holm_bonferroni([]) == []
        assert S.holm_bonferroni([0.02]) == pytest.approx([0.02])   # m=1 is a no-op
        assert S.holm_bonferroni([0.5, 0.6]) == pytest.approx([1.0, 1.0])  # clipped


class TestEffectSize:
    """S-05 to S-07: matched-pairs rank-biserial correlation."""

    def test_s05_total_win_is_plus_one(self) -> None:
        """S-05: System better in every pair -> r = +1."""
        system = [0.1, 0.2, 0.3, 0.4]
        baseline = [0.5, 0.6, 0.7, 0.8]
        assert S.rank_biserial(system, baseline, lower_is_better=True) == pytest.approx(1.0)

    def test_s06_total_loss_is_minus_one(self) -> None:
        system = [0.5, 0.6, 0.7, 0.8]
        baseline = [0.1, 0.2, 0.3, 0.4]
        assert S.rank_biserial(system, baseline, lower_is_better=True) == pytest.approx(-1.0)

    def test_s07_direction_and_ties(self) -> None:
        """S-07: `lower_is_better` flips the sign; all-ties gives 0."""
        system, baseline = [0.1, 0.2], [0.5, 0.6]
        assert S.rank_biserial(system, baseline, lower_is_better=True) > 0
        assert S.rank_biserial(system, baseline, lower_is_better=False) < 0
        assert S.rank_biserial([0.3, 0.3], [0.3, 0.3]) == 0.0


class TestComparison:
    """S-08 to S-11: one paired comparison."""

    def test_s08_agrees_with_scipy(self) -> None:
        """S-08: The wrapper reports scipy's p-value, not its own arithmetic."""
        system = [0.10, 0.12, 0.09, 0.11, 0.13, 0.08, 0.10, 0.12]
        baseline = [0.20, 0.22, 0.19, 0.25, 0.21, 0.18, 0.24, 0.23]
        c = S.compare_pair(system, baseline, 'drop', 'slo_violation_rate',
                           'zt_sdn', 'round_robin')
        assert c.p_raw == pytest.approx(
            float(wilcoxon(system, baseline, method='exact').pvalue)
        )
        assert c.n_pairs == 8
        assert c.wins == 8 and c.losses == 0

    def test_s09_direction_and_medians(self) -> None:
        """S-09: A lower-is-better metric reports the system as better."""
        system = [0.1] * 6
        baseline = [0.3] * 6
        c = S.compare_pair(system, baseline, 'drop', 'failure_rate', 'zt_sdn', 'random')
        assert c.system_median == pytest.approx(0.1)
        assert c.baseline_median == pytest.approx(0.3)
        assert c.median_difference == pytest.approx(0.2)
        assert c.improvement_pct == pytest.approx(200 / 3, rel=1e-3)
        assert c.system_better

    def test_s10_identical_samples_report_the_null(self) -> None:
        """S-10: All-zero differences must not raise; they are simply no evidence.

        scipy raises on a zero-difference vector, which would surface as a crash
        on the one input where the honest answer is obvious.
        """
        c = S.compare_pair([0.2] * 5, [0.2] * 5, 'clean', 'gini', 'zt_sdn', 'random')
        assert c.p_raw == 1.0
        assert not c.is_significant()
        assert c.effect_size == 0.0
        assert c.ties == 5

    def test_s11_rejects_unpaired_or_empty_input(self) -> None:
        with pytest.raises(ValueError):
            S.compare_pair([0.1, 0.2], [0.3], 'clean', 'gini', 'zt_sdn', 'random')
        with pytest.raises(ValueError):
            S.compare_pair([], [], 'clean', 'gini', 'zt_sdn', 'random')


class TestCompareAll:
    """S-12, S-13: the whole-experiment path."""

    def test_s12_pairs_on_seed_and_corrects_within_scenario(self) -> None:
        rows = (
            _rows('drop', 'zt_sdn', [0.10, 0.11, 0.09, 0.12, 0.10, 0.11])
            + _rows('drop', 'random', [0.30, 0.31, 0.29, 0.32, 0.30, 0.33])
            + _rows('drop', 'round_robin', [0.28, 0.29, 0.27, 0.30, 0.28, 0.31])
        )
        comparisons = S.compare_all(rows, metric='slo_violation_rate')

        assert len(comparisons) == 2
        assert {c.baseline for c in comparisons} == {'random', 'round_robin'}
        for c in comparisons:
            assert c.n_pairs == 6
            assert c.system_better
            # Two tests in the family, so each raw p-value at most doubles.
            assert c.p_adj >= c.p_raw
            assert c.p_adj <= min(1.0, 2 * c.p_raw) + 1e-12

    def test_s13_uses_only_seeds_present_for_both(self) -> None:
        """S-13: An unmatched run is dropped rather than silently misaligned.

        Pairing on position instead of seed would compare run 5 of one strategy
        against run 6 of another and quietly break the test's assumption.
        """
        system = _rows('drop', 'zt_sdn', [0.1, 0.1, 0.1, 0.1, 0.1])
        baseline = _rows('drop', 'random', [0.3, 0.3, 0.3])  # seeds 0,1,2 only
        comparisons = S.compare_all(system + baseline, metric='slo_violation_rate')
        assert len(comparisons) == 1
        assert comparisons[0].n_pairs == 3

    def test_report_renders(self) -> None:
        rows = (
            _rows('drop', 'zt_sdn', [0.10, 0.11, 0.09, 0.12, 0.10, 0.11])
            + _rows('drop', 'random', [0.30, 0.31, 0.29, 0.32, 0.30, 0.33])
        )
        report = S.format_report(S.compare_all(rows))
        assert 'Wilcoxon' in report and 'Holm' in report
        assert 'zt_sdn' in report and 'random' in report
        assert S.format_report([]).startswith('no comparisons')


class TestEndToEnd:
    """The claim the project actually makes, computed from a real experiment."""

    def test_system_beats_every_baseline_under_attack(self) -> None:
        """The headline result, on a small but real run of the harness.

        Deliberately checks the *attack* scenarios only. Under `clean` the system
        is measurably worse than round-robin -- see the load-staleness finding in
        evaluation/baseline.py -- and a test that asserted otherwise would be
        asserting something untrue.
        """
        from evaluation import baseline as B

        results = B.run_experiment(
            runs=8, scenarios=('drop',), sim_s=25.0, n_nodes=6,
        )
        rows = [
            {'scenario': r.scenario, 'strategy': r.strategy, 'seed': str(r.seed),
             'slo_violation_rate': str(r.slo_violation_rate)}
            for r in results
        ]
        comparisons = S.compare_all(rows, metric='slo_violation_rate')

        assert len(comparisons) == 4, "expected one comparison per baseline"
        for c in comparisons:
            assert c.system_better, f"zt_sdn lost to {c.baseline}"
            assert c.is_significant(0.05), (
                f"zt_sdn vs {c.baseline}: p_adj={c.p_adj:.4f} not significant"
            )
            assert c.effect_size > 0.5, f"{c.baseline}: effect size only {c.effect_size}"
