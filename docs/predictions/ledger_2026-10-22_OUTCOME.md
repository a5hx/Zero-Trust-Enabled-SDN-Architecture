# Phase 6 outcome: the replicas re-verify the controller's trust records

Prediction `ledger_2026-10-22.txt` was committed and pushed before any run (`257b5ed`).
The 20 runs took place 2026-10-22 18:23 to 20:18 UTC, all at `257b5ed`, and all completed
cleanly (307.6–308.9 s recorded). Scored 2026-10-23:

```bash
python3 -m evaluation.ledger_report data/runs --arms lv_noverify,lv_honest,lv_forge_score,lv_forge_evidence
python3 -m evaluation.replicates data/runs --arms lv_noverify,lv_honest,lv_forge_score,lv_forge_evidence --out-dir data/ledger_experiment_2026-10-23
python3 -m evaluation.witness_report data/runs --arms lv_noverify,lv_honest,lv_forge_score,lv_forge_evidence
```

The outputs are `ledger_2026-10-22_live_ledger.txt`, `_live_summary.txt` and
`_live_witness.txt`.

## Verdict: L1–L6 all held

| # | Predicted | Measured | |
|---|---|---|---|
| L1 | `lv_honest`: 0 false rejections 5/5; ≤ 10 unaccounted; chain valid | **0** false rejections in 5/5 runs (about 5,670 records each); 1–5 unaccounted (max 5); every run's chain links correctly | **Held** |
| L2 | `lv_forge_score`: ≥ 99% of srv3's post-onset records rejected; 0 false ≥ 4/5; ≤ 10 unaccounted | **5,478 / 5,482 (99.93%)**; **0** false rejections in 5/5; 0–8 unaccounted | **Held** |
| L3 | srv3's route share higher after onset than before, every run | **13.2% → 23.9%**, higher in 5/5 (before 10.6–16.2%, after 22.8–24.8%) | **Held** |
| L4 | `lv_forge_evidence`: 0 rejections 5/5; controller quarantines srv3 ≤ 1/5; witness blames srv3 5/5, median ≤ 20 s | **0 / 3,787** rejected; controller **0/5**; witness **5/5, median 11.1 s** | **Held** |
| L5 | Commit time median within 2 ms of `lv_noverify`; honest latency intervals overlap | **9.7 vs 9.5 ms** (p95 13.1 vs 12.7 ms); 86.6 [84.9, 88.4] vs 88.7 [87.1, 90.3] ms | **Held** |
| L6 | A rejection reaches the controller within 1 s (median) | **0.22 s** median, p95 0.59 s | **Held** |

**The 4 forged records that were not rejected** are the last records of two runs, written
in the final second (r04 at 304.7 s and 305.1 s, r05 at 305.5 s and 305.7 s). They were
never committed before shutdown; they are part of the "unaccounted" partial batch, not
records the replicas accepted. **Every forged record that reached the replicas was
rejected.**

## What the experiment shows

1. **Honest replicas catch a controller that forges scores, record for record, and
   nothing else.**
   - About 1,100 forged records per run were rejected. Not one of the other 22,869
     records was.
   - Every rejection was for a wrong after-score.
   - The queue kept draining: 0–8 records unaccounted at the end, the same as with no
     forgery.
   - Verification is effectively free: commit time rose 0.2 ms on a 9.5 ms Raft commit.

2. **Detection is after the fact, not prevention.**
   - While the replicas refused every forged record, the controller kept routing on the
     inflated score. srv3's share of traffic rose from 13% to 24%, which is the
     power-of-two-choices ceiling for a single favoured server (24.4%).
   - The ledger shows that the controller is lying; it does not stop it.

3. **Forged evidence passes, and blinds the controller's own detectors.**
   - With srv3 dropping every task and the controller rewriting the outcomes as
     successes, the replicas rejected nothing (0/3,787), as designed.
   - The controller never quarantined srv3 (0/5): its drop tell and trust score both read
     the forged outcomes.
   - **Not predicted (the registration left it as "reported as measured"):** srv3 looked
     like the best server, with trust never below 0.836 after onset and 20 ms reported
     latency, and drew 23.6% of
     traffic, +11 points above its fair share. Honest-device task success fell to
     **82.6% [82.1, 83.1]** against 99.96% [99.95, 99.98] in `lv_honest`, with 736
     timeouts per run.

4. **The independent witness was the only check that saw it.**
   - The switch witness, which reads the raw client reports and the switches' counters,
     blamed srv3 in 5/5 runs, a median of 11.1 s after onset.
   - It blamed no honest party in any of the 20 runs.
   - It acts on nothing yet, so the loss continued. This is the clearest case so far for
     letting witness verdicts act.

## What this does not show

- **Not Byzantine tolerance.** The replicas are honest and crash-only, and they share the
  controller's trust configuration.
- **A crude forger.** A controller that forged evidence instead of scores was not caught
  by the ledger at all. That is exactly the stated limit.
- **One deployment.** One host, three local replicas, one forging pattern per arm.
