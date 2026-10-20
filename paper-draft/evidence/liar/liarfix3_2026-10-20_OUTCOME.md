# Outcome of the Phase 1 third batch (fix 3), scored against T1–T4

- Prediction: `liarfix3_2026-10-20.txt`, committed in ff64b87 before any of these runs.
- Runs: 15 live runs, all at ff64b87 and none short, under `data/runs/liarfix3_*/`.
- Summary: `liarfix3_2026-10-20_live_summary.txt`.

| | Prediction | Live | Verdict |
|---|---|---|---|
| T1 | Control: 0 honest false quarantines in ≥ 4/5 runs | **0, 0, 0, 1, 0** | **Held** |
| T2 | Verified-routing control: 0 in ≥ 4/5 runs | **0, 0, 0, 0, 0** | **Held** |
| T3 | Consistent liar still contained ≥ 4/5, median < 15 s | **5/5, median 6.4 s** (range 5.3–12.6); 0 honest false quarantines in this arm | **Held** |
| T4 | Honest mean latency within 5% of ~396 ms | 394.6 / 394.3 / 396.2 ms | **Held** |

**The one honest quarantine in 15 runs.** liarfix3_honest r04, srv2, at
t = 20.2 s, released after 1.0 s. It was a single honesty firing at
|0.65 − 0.24| = 0.42 against the 0.40 threshold. The server's claimed duty
was ABOVE the expected duty, the opposite direction to the span defect, during
the end of the start-up period. Nothing else fired on an honest server in any
of the three arms.

## How honest false quarantines fell across the three batches

| Batch | Code | Control arm, per run | Verified control, per run |
|---|---|---|---|
| 1 | shipped | 3.4 | — |
| 2 | fix 1 (span ends at now) | 1.4 | 2.0 |
| 3 | fixes 1 + 3 (no opinion on a partial window) | **0.2** | **0.0** |

## The Phase 1 result, all batches together

1. **A load liar whose lie is internally consistent does not pay.** It gets
   below fair share whether or not anything catches it: 9.4–10.5% against a
   fair 12.5%. The corrected gate still contains it, 5/5 in a median 6.4 s.
2. **The split claim is a real hole in the shipped design.** It lies in the
   instantaneous `cpu_load` and keeps a truthful busy counter.
   - It gains **+4.00 [3.47, 4.52] points** of traffic.
   - It is **never quarantined** on the corrected detector (0/5).
3. **Routing on the verified claim (`edge_score.cpu_claim: verified`) closes it.**
   - The split claim's excess falls to **+0.01 [−0.28, +0.30]**.
   - Honest service is unchanged (396 ms either way), with no honest false
     quarantines in 5/5 runs.
4. **The experiment found and fixed a latent false-positive defect** in the
   honesty check. It is invisible at the shipped 1% occupancy and dominant at
   40%. Honest false quarantines fell from 3.4 per run to 0.2.

Still open (novelty plan): the side effect the model predicts for verified
routing at 1% occupancy (+1.8 points for a consistent liar) has not been run
live. Whether `verified` should become the default is a decision for after
that run.
