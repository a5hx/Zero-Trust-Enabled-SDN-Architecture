# Outcome of the Phase 1 liar experiment, scored against the registered prediction

- Prediction: `liar_2026-10-19.txt`, committed in 3b95031 before any of these runs.
- Runs: 25 live runs, 5 per arm, under `data/runs/{liar_honest,liar_c_treat,liar_t_treat,liar_t_treat_slots,stealthy_treat}/`.
- Scored with `python3 -m evaluation.replicates data/runs --arms …`; full output in `data/liar_experiment_2026-10-20/`.

## The five predictions

| | Prediction | Model | Live | Verdict |
|---|---|---|---|---|
| P1 | Split claim gains traffic: excess > 0, interval excludes 0 | +5.2 points | **+4.51 [+3.66, +5.36]** (share 17.01%) | **Held** |
| P1 | …and is quarantined in ≤ 1/5 runs | 0/5 | **4/5** quarantined (median 51.7 s), though isolated only 0.46% of the time | **Failed**, but see the defect below: every one of its firings was the defect |
| P2 | Consistent liar below fair share, quarantined ≥ 4/5, median < 15 s | 9.6%, 5/5, 3 s | **9.37%** [9.05, 9.68], 5/5, median 8.2 s | **Held**, but only 39 of its 262 honesty firings survive the corrected estimator |
| P3 | Stealthy liar below fair share | 11.2% | **10.63%** [10.35, 10.90] | **Held** |
| P4 | 0 honest false quarantines in every arm | 0 | **3.0–4.4 honest servers quarantined per run in every arm, the control included** | **Failed**: a defect in the honesty check (below) |
| P5 | No run above the 24.4% p2c+ε ceiling | max 20.8% | arm means 9.4–17.2%; no run near 24.4% | **Held** |

The model's route-share predictions all landed within about one point of the
live values (9.6 vs 9.37, 17.7 vs 17.01, 18.1 vs 17.21, 11.2 vs 10.63). The
model has no estimator defect; it divides completions by the window. That is
why it predicted no honest false positives.

## The defect the experiment exposed: the completion rate ends its span at the last completion

`TrustState._completion_rate_locked` computes
`(c1 − c0) / (t1 − t0)`, where t1 is the time of the **last completion**, not
now. When a server finishes a burst early in the 3 s window and then goes
quiet, the span shrinks to the burst and the rate inflates. Expected duty
(rate × fleet-median service time / concurrency) then reads about 0.9 against
a true 0.3–0.4, and the honesty check fires on an honest server. The
busy-seconds side is sampled at every poll, so it has no such skew.

**Evidence, rebuilt from the recordings at each honest firing (n = 119):**

| Quantity at the firing | Median |
|---|---|
| Logged expected duty | 0.87 |
| Rebuilt, span to the last completion (shipped) | 0.81 |
| Rebuilt, span to now (fix) | **0.30** |
| Time since the server's last completion | **2.03 s** |

None of the 119 would fire with the span ending at now.

**Why the earlier 40 runs never showed it.** At the shipped ~1% occupancy even
a tripled expected duty stays far under the 0.40 threshold.
- In `base`, `scoreonly` and `treat`, the honesty check never fired on an
  honest server: 0 honest false quarantines in all 15 ablation runs.
- In `treat` it never fired at all, because the latency tell caught both
  load-dishonest attackers first.
- **The published results do not depend on the defect.** It is latent at low
  load and becomes the dominant false-positive source at 40%.

**What it did to the liar results:**

| Arm | Liar's honesty firings | Survive the fix |
|---|---|---|
| liar_c_treat | 262 | 39 (15%) |
| liar_t_treat | 7 | **0** |
| liar_t_treat_slots | 3 | **0** |
| stealthy_treat | 168 | 24 (14%) |

- The split-claim liar was **never genuinely detected**. Its brief quarantines
  were the defect.
- The consistent and stealthy liars were caught mostly by the defect too.
  Whether the corrected check still contains them, and how fast, needs the
  re-run below.

## Next (measure → fix → re-measure)

1. **Fix the span** so it ends at now. This is a bug fix, so it becomes the
   default.
2. **Close the split claim** by routing on the verified claim: the busy-counter
   duty `claimed_load()`, which the honesty check cross-validates, instead of
   the raw instantaneous `cpu_load`. Opt-in:
   `edge_score.cpu_claim: verified`.
3. **Re-run under new arm names** so these 25 recordings are kept: the control,
   the consistent liar, the split claim and the stealthy liar with fix 1; the
   split claim and the control with fixes 1 + 2.
