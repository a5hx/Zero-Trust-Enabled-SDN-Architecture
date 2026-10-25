# Outcome: verified-claim routing at the shipped workload (S1–S4)

- Prediction and decision rule: `ship_verified_2026-10-20.txt`, committed in fa37a3a before any run.
- Runs: 10 live runs, all at fa37a3a and none short, under `data/runs/ship_c_{raw,verified}/`.
- Summary: `ship_verified_2026-10-20_live_summary.txt`.

| | Prediction | Model | Live | Verdict |
|---|---|---|---|---|
| S1 | Raw routing: liar share < 12.5% | 4.2% | **10.14%** [8.92, 11.36] | **Held** (the model overstated the tie-loss penalty) |
| S2 | Verified routing: liar excess > 0, interval excluding 0, < +4 points | +1.56 | **+1.08 [−0.53, +2.69]** | **Failed**: no measurable gain over fair share |
| S3 | Liar never quarantined (≥ 4/5) | 0/10 | 0/5 and 0/5 | **Held** |
| S4 | 0 honest false quarantines (≥ 4/5); honest latency within 5% | — | 0 and 0; 89.2 vs 87.7 ms | **Held** |

## Decision, by the rule registered in advance

S2 failed, so **`edge_score.cpu_claim: verified` becomes the default**
(`TrustState`, `trust_balancer.py`).
- Every config behind a recorded experiment now pins `cpu_claim: raw`
  explicitly, so its recordings stay reproducible. A test enforces this.
- The demo configs (`params_demo`, `params_trust_demo`,
  `params_attacks_demo`) take the new default.
- The scripted demo generator is pinned to `raw` (below).

## What to report alongside the decision

- **Compared with raw routing, verified routing does give a consistent liar
  more traffic at this load**: 13.58% against 10.14%, and the intervals don't
  overlap. Under raw routing the liar's fabricated claim of 0 only ties an
  honest server's truthful ~0 and loses the tie on its honesty deficit. Under
  verified routing it undercuts an honest server's ~0.01 duty.
- What it gains is the removal of a self-inflicted penalty, not an advantage:
  its share is not measurably above fair (+1.08 [−0.53, +2.69]).
- At 40% occupancy, verified routing closes a +4.00 [3.47, 4.52] point hole.
- **Synthetic-demo observation, not a live result.** The 4-node demo generator
  injects an 8% random timeout into every node. There, verified routing
  quarantined an honest node through the drop tell's 4-sample minimum in
  **5 of 20 seeds against 1 of 20** with raw routing (Fisher p ≈ 0.18).
  - The routing bursts were similar in both modes, so it is not herding.
  - Across 20 live verified-routing runs there were 0 honest quarantines.
  - The demo generator stays on raw. The drop tell's 4-sample minimum is a
    small-sample fragility worth its own follow-up.
