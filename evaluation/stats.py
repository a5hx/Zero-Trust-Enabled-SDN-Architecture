"""Paired significance testing for the baseline comparison.

Turns the per-run CSV from `evaluation.baseline` into the claim the project is
actually making: *the full Zero-Trust system beats each baseline on this metric,
and the difference is not chance.*

Why the Wilcoxon signed-rank test
---------------------------------
Every strategy is run on the *same* seeds, so run k of `zt_sdn` and run k of
`round_robin` faced an identical workload (see `baseline.simulate` on common
random numbers). That makes the samples **paired**, and a paired test is far more
powerful than an unpaired one because it removes between-run variance from the
comparison entirely.

The signed-rank test is used rather than a paired t-test because the outcome
distributions are rates bounded in [0, 1], visibly skewed, and occasionally
zero-inflated (`zt_sdn` isolates the attacker in most runs, so its failure rate
piles up near 0). None of that is normal, and the t-test's assumption would be
doing real work in the result. Wilcoxon assumes only that the paired differences
are symmetric about their median, and it is the test the deck committed to.

Multiple comparisons
--------------------
Comparing one system against four baselines on the same data is four tests, so
the chance of at least one false positive at α=0.05 is ~19%, not 5%. Every
p-value reported here is therefore corrected with **Holm-Bonferroni** within a
scenario. Holm rather than plain Bonferroni: it is uniformly more powerful and
just as safe (it controls the same family-wise error rate), so there is no reason
to prefer the cruder correction. `p_raw` is kept alongside `p_adj` so the
correction is visible rather than hidden.

Effect size
-----------
A p-value says a difference exists, not that it matters. Each comparison also
reports the **matched-pairs rank-biserial correlation** r -- the signed-rank
statistic rescaled to [-1, 1], where +1 means the system was better in every
single pair -- plus the median difference in the metric's own units, which is
what a reader actually wants to know.

Run:
    python3 -m evaluation.stats results.csv
    python3 -m evaluation.stats results.csv --metric failure_rate --alpha 0.01
"""
from __future__ import annotations

import argparse
import csv
import statistics
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from scipy.stats import wilcoxon


def _wilcoxon_p(sample: Sequence[float], method: str) -> Tuple[float, str]:
    """Wilcoxon p-value, plus the null distribution actually used.

    Two scipy-version differences are absorbed here, and the second one changes
    the test rather than only its spelling, which is why the null used is
    returned instead of assumed:

    * **Argument name.** scipy >= 1.9 spells the null-distribution argument
      `method=`; earlier versions spell the same argument, with the same accepted
      values, `mode=`. Purely cosmetic -- translated and passed through.
    * **Exact-null coverage.** scipy < 1.9 only tabulates the exact signed-rank
      distribution up to n=25 and raises above it, whereas compare_pair's cutoff
      (50) matches scipy >= 1.9. On an older scipy an exact request for
      26 <= n <= 50 therefore cannot be honoured, and this falls back to the
      tie-corrected normal approximation. That is the conservative direction --
      the approximation yields the larger p-value -- but it is a different test
      from the one requested, so it is reported rather than silently substituted.

    Returns:
        (p_value, null_used) where null_used is 'exact' or 'approx'.
    """
    def _call(null: str) -> float:
        try:
            return float(wilcoxon(sample, method=null).pvalue)
        except TypeError:
            return float(wilcoxon(sample, mode=null).pvalue)

    try:
        return _call(method), method
    except ValueError:
        # Exact null not tabulated at this n by this scipy; fall back and say so.
        if method != 'exact':
            raise
        return _call('approx'), 'approx'

# Metric -> True if a lower value is better. Mirrors evaluation.baseline.METRICS,
# duplicated here so this module can consume any CSV without importing the sim.
LOWER_IS_BETTER: Dict[str, bool] = {
    'slo_violation_rate': True,
    'failure_rate': True,
    'malicious_share': True,
    'mean_latency_ms': True,
    'p95_latency_ms': True,
    'gini': True,
    'time_to_isolate_s': True,
}


@dataclass
class Comparison:
    """One system-vs-baseline paired comparison on one metric."""

    scenario: str
    metric: str
    system: str
    baseline: str
    n_pairs: int
    system_median: float
    baseline_median: float
    median_difference: float      # baseline - system, in the metric's units
    improvement_pct: Optional[float]
    p_raw: float
    p_adj: float                  # Holm-Bonferroni corrected within the scenario
    effect_size: float            # matched-pairs rank-biserial correlation
    wins: int                     # pairs where the system was strictly better
    losses: int
    ties: int
    # Null distribution the p-value was actually computed under ('exact',
    # 'approx', or 'none' when every pair tied and the null was reported
    # without a test). Recorded because the installed scipy can decline an
    # exact request -- see _wilcoxon_p.
    null_distribution: str = 'exact'

    @property
    def significant(self) -> bool:
        """Significant at α=0.05 after correction. Use `is_significant` for other α."""
        return self.is_significant()

    def is_significant(self, alpha: float = 0.05) -> bool:
        return self.p_adj < alpha

    @property
    def system_better(self) -> bool:
        """Which side the *test* favours.

        Read from the signed-rank direction (the effect size), not from the
        difference of medians. Those disagree whenever the medians tie but the
        pairs do not: a system that wins 10 pairs, loses 0, and ties 20 has a
        median difference of exactly 0.0 while the test correctly reports a
        significant improvement. Judging by medians alone labels that a loss.
        Median difference is only the tie-break when the ranks are perfectly
        balanced.
        """
        if self.effect_size != 0:
            return self.effect_size > 0
        return self.median_difference > 0

    @property
    def effect_label(self) -> str:
        """Cohen-style bands for rank correlations, for reporting convenience."""
        r = abs(self.effect_size)
        if r < 0.1:
            return 'negligible'
        if r < 0.3:
            return 'small'
        if r < 0.5:
            return 'medium'
        return 'large'


def holm_bonferroni(pvalues: Sequence[float]) -> List[float]:
    """Holm-Bonferroni step-down correction.

    Sort ascending, scale the k-th smallest of m p-values by (m - k), then
    enforce monotonicity so an adjusted p-value can never fall below one ranked
    before it. Results are clipped to 1.0 and returned in the input order.

    Args:
        pvalues: Raw p-values from a family of tests.

    Returns:
        Adjusted p-values, positionally matching the input.
    """
    m = len(pvalues)
    if m == 0:
        return []

    order = sorted(range(m), key=lambda i: pvalues[i])
    adjusted = [0.0] * m
    running = 0.0
    for rank, idx in enumerate(order):
        scaled = (m - rank) * pvalues[idx]
        # Step-down monotonicity: never report a smaller adjusted p-value than
        # one already assigned to a more significant test.
        running = max(running, scaled)
        adjusted[idx] = min(1.0, running)
    return adjusted


def rank_biserial(system: Sequence[float], baseline: Sequence[float],
                  lower_is_better: bool = True) -> float:
    """Matched-pairs rank-biserial correlation for paired differences.

    (W+ - W-) / (W+ + W-), where W+ and W- are the summed ranks of the absolute
    differences favouring each side. Zero differences are dropped, as in the
    signed-rank test itself. Returns a value in [-1, 1]: positive means the
    system was better.
    """
    diffs = []
    for s, b in zip(system, baseline):
        d = (b - s) if lower_is_better else (s - b)
        if d != 0:
            diffs.append(d)
    if not diffs:
        return 0.0

    # Rank absolute differences, averaging ranks within ties.
    order = sorted(range(len(diffs)), key=lambda i: abs(diffs[i]))
    ranks = [0.0] * len(diffs)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and abs(diffs[order[j + 1]]) == abs(diffs[order[i]]):
            j += 1
        shared = (i + j) / 2 + 1  # average of 1-based ranks i+1..j+1
        for k in range(i, j + 1):
            ranks[order[k]] = shared
        i = j + 1

    w_plus = sum(r for d, r in zip(diffs, ranks) if d > 0)
    w_minus = sum(r for d, r in zip(diffs, ranks) if d < 0)
    total = w_plus + w_minus
    return (w_plus - w_minus) / total if total else 0.0


def compare_pair(
    system_values: Sequence[float],
    baseline_values: Sequence[float],
    scenario: str,
    metric: str,
    system: str,
    baseline: str,
) -> Comparison:
    """Run one paired comparison. `p_adj` is set to `p_raw` until corrected."""
    if len(system_values) != len(baseline_values):
        raise ValueError(
            f"unpaired samples for {system} vs {baseline}: "
            f"{len(system_values)} != {len(baseline_values)}"
        )
    if not system_values:
        raise ValueError(f"no runs for {system} vs {baseline} in {scenario}")

    lower_better = LOWER_IS_BETTER.get(metric, True)
    diffs = [b - s for s, b in zip(system_values, baseline_values)]
    if not lower_better:
        diffs = [-d for d in diffs]

    # Drop tied pairs before testing. This is Wilcoxon's own treatment of zeros
    # and matches scipy's default zero_method='wilcox'; doing it here rather than
    # leaving it to scipy makes the exact null distribution usable, since scipy
    # refuses `method='exact'` whenever zeros are present in the input.
    nonzero = [d for d in diffs if d != 0]

    if not nonzero:
        # Identical samples are not evidence of a difference. Report the null
        # rather than letting scipy's exception on an all-zero vector surface as
        # a crash on the one input whose answer is obvious.
        p_raw = 1.0
        null_used = 'none'
    else:
        # Choose the null distribution explicitly instead of relying on scipy's
        # 'auto', which mostly picks the same thing but warns when it does.
        # Exact requires all three of:
        #   * few enough pairs that the recursive construction stays cheap --
        #     scipy's own cutoff is 50, matched here;
        #   * no ties among the absolute differences, since the exact null
        #     assumes distinct ranks and ties break that assumption;
        #   * no zero differences, which the drop above has already handled.
        # The relevant sample size is the number of *untied* pairs, not the
        # number of runs: 30 runs with 22 ties is an 8-sample test, far too small
        # to approximate with a normal.
        #
        # This deviates from scipy's `method='auto'` in two places, both
        # deliberately toward the more careful option:
        #   * zeros present -- scipy degrades to the approximation; we drop the
        #     tied pairs first (Wilcoxon's own definition), which keeps the exact
        #     test valid and is the more accurate of the two.
        #   * ties among |d| -- scipy still uses exact; we do not, because the
        #     exact null assumes distinct ranks and is anticonservative when they
        #     tie, whereas the normal approximation applies a tie correction to
        #     the variance. Erring toward larger p-values is the right direction
        #     for a significance claim.
        # Otherwise the two agree exactly (scipy's cutoff is also 50).
        magnitudes = [abs(d) for d in nonzero]
        exact_ok = len(nonzero) <= 50 and len(set(magnitudes)) == len(magnitudes)
        method = 'exact' if exact_ok else 'approx'
        p_raw, null_used = _wilcoxon_p(nonzero, method)

    sys_med = statistics.median(system_values)
    base_med = statistics.median(baseline_values)
    median_diff = (base_med - sys_med) if lower_better else (sys_med - base_med)
    improvement = (median_diff / base_med * 100.0) if base_med else None

    return Comparison(
        scenario=scenario, metric=metric, system=system, baseline=baseline,
        n_pairs=len(system_values),
        system_median=sys_med, baseline_median=base_med,
        median_difference=median_diff, improvement_pct=improvement,
        p_raw=p_raw, p_adj=p_raw,
        effect_size=rank_biserial(system_values, baseline_values, lower_better),
        wins=sum(1 for d in diffs if d > 0),
        losses=sum(1 for d in diffs if d < 0),
        ties=sum(1 for d in diffs if d == 0),
        null_distribution=null_used,
    )


def compare_all(
    rows: Sequence[dict],
    metric: str = 'slo_violation_rate',
    system: str = 'zt_sdn',
) -> List[Comparison]:
    """Compare `system` against every other strategy, per scenario.

    Rows are paired on `seed`, and only seeds present for both strategies are
    used -- an unpaired run would quietly break the test's assumption.

    Args:
        rows: Parsed CSV rows (see `load_csv`).
        metric: Column to test.
        system: The strategy under test.

    Returns:
        Comparisons with Holm-Bonferroni applied within each scenario.
    """
    by: Dict[Tuple[str, str], Dict[int, float]] = {}
    for row in rows:
        value = row.get(metric)
        if value is None or value == '':
            continue
        by.setdefault((row['scenario'], row['strategy']), {})[int(row['seed'])] = float(value)

    comparisons: List[Comparison] = []
    scenarios = sorted({s for s, _ in by})

    for scenario in scenarios:
        system_runs = by.get((scenario, system))
        if not system_runs:
            continue

        group: List[Comparison] = []
        baselines = sorted({t for s, t in by if s == scenario and t != system})
        for baseline in baselines:
            baseline_runs = by[(scenario, baseline)]
            shared = sorted(set(system_runs) & set(baseline_runs))
            if not shared:
                continue
            group.append(compare_pair(
                [system_runs[k] for k in shared],
                [baseline_runs[k] for k in shared],
                scenario, metric, system, baseline,
            ))

        # Correct within the scenario: that is the family of tests being made.
        for comparison, adjusted in zip(group, holm_bonferroni([c.p_raw for c in group])):
            comparison.p_adj = adjusted
        comparisons.extend(group)

    return comparisons


def load_csv(path: str) -> List[dict]:
    with open(path, newline='') as f:
        return list(csv.DictReader(f))


def format_report(comparisons: Sequence[Comparison], alpha: float = 0.05) -> str:
    """Human-readable results table, grouped by scenario."""
    if not comparisons:
        return "no comparisons (empty or unmatched input)"

    metric = comparisons[0].metric
    system = comparisons[0].system
    lines = [
        f"Paired Wilcoxon signed-rank: {system} vs baselines on {metric}",
        f"Holm-Bonferroni corrected within scenario, alpha = {alpha}",
        "",
        f"{'scenario':>9} {'baseline':>12} {'n':>3} {'system':>8} {'base':>8} "
        f"{'delta':>8} {'impr':>7} {'p_raw':>9} {'p_adj':>9} {'r':>6} {'W/L/T':>9}  ",
        "-" * 104,
    ]

    for c in comparisons:
        verdict = 'yes' if c.is_significant(alpha) and c.system_better else (
            'WORSE' if c.is_significant(alpha) else 'ns'
        )
        improvement = f"{c.improvement_pct:>6.1f}%" if c.improvement_pct is not None else "     --"
        lines.append(
            f"{c.scenario:>9} {c.baseline:>12} {c.n_pairs:>3} "
            f"{c.system_median:>8.4f} {c.baseline_median:>8.4f} "
            f"{c.median_difference:>+8.4f} {improvement} "
            f"{c.p_raw:>9.2e} {c.p_adj:>9.2e} {c.effect_size:>+6.2f} "
            f"{c.wins:>3}/{c.losses:>2}/{c.ties:<2} {verdict}"
        )

    wins = sum(1 for c in comparisons if c.is_significant(alpha) and c.system_better)
    losses = sum(1 for c in comparisons if c.is_significant(alpha) and not c.system_better)
    lines += [
        "-" * 104,
        f"{wins}/{len(comparisons)} comparisons significantly favour {system}; "
        f"{losses} significantly favour the baseline.",
        "",
        "delta = baseline median - system median (positive favours the system).",
        "r = matched-pairs rank-biserial effect size. W/L/T = per-seed wins/losses/ties.",
    ]

    # State the null distribution when it is not uniformly the exact one, so a
    # p-value is never quoted as exact when the installed scipy declined to
    # compute it that way (see _wilcoxon_p).
    nulls = sorted({c.null_distribution for c in comparisons})
    if nulls != ['exact']:
        counts = ', '.join(
            f"{n}: {sum(1 for c in comparisons if c.null_distribution == n)}"
            for n in nulls
        )
        lines.append(f"null distribution used ({counts}).")
        if 'approx' in nulls:
            lines.append(
                "'approx' = tie-corrected normal approximation, the conservative "
                "direction (larger p-values)."
            )
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('csv', help='per-run CSV from `python3 -m evaluation.baseline --csv`')
    p.add_argument('--metric', default='slo_violation_rate',
                   help='column to test (default: slo_violation_rate)')
    p.add_argument('--system', default='zt_sdn',
                   help='strategy under test (default: zt_sdn)')
    p.add_argument('--alpha', type=float, default=0.05,
                   help='significance level after correction (default: 0.05)')
    args = p.parse_args(argv)

    comparisons = compare_all(load_csv(args.csv), metric=args.metric, system=args.system)
    print(format_report(comparisons, alpha=args.alpha))


if __name__ == '__main__':
    main()
