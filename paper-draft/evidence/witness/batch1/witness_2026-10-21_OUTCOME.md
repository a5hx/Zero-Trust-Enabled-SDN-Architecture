# Outcome: Phase 2d, two-witness verification, batch 1 (W1–W6)

- Prediction: `witness_2026-10-21.txt`, committed in 0c8d064 before any run.
- Runs: 25 live runs (wit_switch_hide r01 was the pilot), all at 0c8d064, none short.
- Verdicts: `witness_2026-10-21_live_verdicts.txt` (`evaluation.witness_report`).
- Service: `witness_2026-10-21_live_summary.txt` (`evaluation.replicates`).

| | Prediction | Live | Verdict |
|---|---|---|---|
| W1 | Control: nobody blamed (≥ 4/5) | **0 parties in 5/5** | **Held** |
| W2 | srv6 and srv1 blamed 5/5, median ≤ 20 s after onset; no honest party | srv1 **5/5**, srv6 **4/5**; medians **61.2 s** and **53.9 s**; 0 honest | **Failed** (detection count and timing) |
| W3 | Switch dpid 4 blamed 5/5 ≤ 20 s; no client or server (≥ 4/5) | switch **5/5, median 14.1 s**; **clients wrongly blamed in 3/5 runs**, 1.0–4.1 s each | **Failed** on the clients |
| W4 | iot3, iot12 blamed 5/5 ≤ 30 s; no switch or server | **5/5 each, medians 13.1 / 14.1 s**; nobody else | **Held** |
| W5 | srv6 blamed 5/5 despite the cover; dpid 4 not blamed; no client behind it | srv6 **5/5**; dpid 4 **0/5**; nobody else | **Held** |
| W6 | The witness changes nothing for honest devices | honest mean latency **90.1 ms** in the control (≈ the shipped ~91 ms); 0 honest servers quarantined in any arm | **Held** |

**Honest agreement is near perfect.** On the seven honest switches the
disagreement rate was exactly 0.0 across ~1,130 judged connections per
minute. Every honest server, switch and client was blamed for 0 s in four of
the five arms.

## The two failures are design flaws in the witness, measured

**1. Slow blame of dropping servers (W2).** Server rates were computed over
everything in a 60 s window.
- A dropping server's pre-attack successes sat in that window and diluted its
  failures. In wit_drop r01, srv6's rate went 0.014 → 0.042 → 0.055 → 0.068
  → … and reached 0.20 only 49 s after its first failure.
- Meanwhile the gate had quarantined srv6 12 s after its first failure, and
  from then on it received only a probation trial every 5 s. The quarantine
  starved the witness of new failures; in one run it never reached the
  threshold.
- Switches and badmouthing clients were blamed in ~14 s because every one of
  their connections flips at once.

**2. Transient misattribution to clients (W3).** While a lying switch's lie
builds up, its five clients cross the threshold one by one. When 1–2 of 5
had crossed, the switch-majority rule did not yet hold, so those clients were
blamed individually, for 1.0–4.1 s, until it did.

## Fixes (code, staged; each pinned by a test that fails without it)

- **Fix 1:** judge each party on its most recent connections: the last 20 for
  servers and switches, the last 10 for clients. Reproduced in simulation with
  a 4 s quarantine: without the fix the dropper is blamed ~42 s after onset;
  with it, 4 s.
- **Fix 2:** blame a client individually only if the other clients behind its
  switch look clean (their mean rate is under half the threshold).
  Reproduced in simulation: without the fix, two clients are wrongly blamed
  during the ramp; with it, none.
- **Side effect, correct:** judged on recent connections, a switch *covering*
  for a dropper can now be blamed. It is lying, so that is a detection, not a
  false accusation; batch 1 had written it off as out of scope.

Re-run: `witfix_*` arms, identical to `wit_*` except their recording path,
against `witfix_2026-10-21.txt`.
