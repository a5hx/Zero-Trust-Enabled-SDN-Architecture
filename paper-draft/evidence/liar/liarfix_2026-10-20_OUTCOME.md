# Outcome of the Phase 1 re-run (fix 1, and fix 2 opt-in), scored against R1–R6

- Prediction: `liarfix_2026-10-20.txt`, committed in 4dfbdc2 before any of these runs.
- Runs: 30 live runs, 5 per arm, all recorded at git head 4dfbdc2 and none
  short. Recordings are under `data/runs/liarfix_*/`.
- Scored with `python3 -m evaluation.replicates`. The full summary is copied
  next to this file as `liarfix_2026-10-20_live_summary.txt`.

| | Prediction | Live | Verdict |
|---|---|---|---|
| R1 | Control: 0 honest false quarantines in ≥ 4/5 runs | per run **1, 3, 1, 2, 0** (mean 1.4, down from 3.4) | **Failed** (see below) |
| R2 | Split claim: excess > 0, interval excludes 0; quarantined ≤ 1/5 | **+4.00 [+3.47, +4.52]**; quarantined **0/5**, isolated 0.00% | **Held** |
| R3 | Consistent liar: share < 12.5%; quarantined ≥ 4/5 | **10.49%**; **5/5**, median 7.4 s | **Held** |
| R4 | Stealthy liar: share < 12.5% | **11.34%** | **Held** |
| R5 | Verified routing: split claim's excess ≈ 0 (< +1.5) | **+0.01 [−0.28, +0.30]** | **Held** |
| R6 | Verified control: 0 honest FQ in ≥ 4/5 runs; honest latency within 5% | FQ per run **2, 1, 5, 1, 1**; latency **396.3 vs 396.4 ms** | **Failed** on FQ; held on latency |

## What this settles

1. **The split claim is a real, measured hole in the shipped design.**
   - On the corrected detector it wins **+4.0 points** of traffic above fair
     share (16.5% against 12.5%).
   - It is **never quarantined** (0/5 runs, 0.00% of the time isolated).
   - It costs honest service nothing measurable, so nobody would notice it.
2. **Verified routing closes it completely**, at no cost to honest service:
   - the split claim's excess falls to **+0.01 [−0.28, +0.30]**;
   - honest mean latency is 396.2 ms with it and 396.4 ms without.
3. **The corrected gate still catches the liars whose lie is internally
   consistent** (5/5 each). They gain nothing anyway: 10.5% and 11.3% of
   traffic, both below fair share.

## Why R1 and R6 failed

Fix 1 removed the steady-state defect: honest honesty firings fell from 129
in the first batch to between 4 and 17 per arm. The remaining ones are
warm-up.
- **50 of 52** remaining honest firings happen in the first 36 s of a run.
  Only 2 happen later, in 30 runs × 300 s.
- **35** of those have no completion older than the 3 s window. All 40 clients
  start together, so the first seconds are one synchronized burst, and a rate
  over a partial window reads the burst as the steady state.
- Several compare against a claimed duty of 0.00: the busy counter has too
  little history yet, so `claimed_load()` falls back to the raw claim.
- The firings with an older reference (gaps of 3–9 s) are mostly the same
  servers again, with a gap that is likely the result of an earlier false
  quarantine rather than real idleness. That is a cascade from the warm-up
  firing.

**Fix 3** (default): `_completion_rate_locked` returns None until there is a
completion at or before the window's start, so the honesty check abstains on
a partial window. This is the existing rule that the controller's own missing
evidence is not the node's misbehaviour (the stale-evidence abstention).
- Cost to detection: at most one window (3 s) of extra delay after a server
  starts or returns from more than 6 s without completions.
- The consistent liar was contained in a median of 7.4 s here, against an
  arming time of 20 s.

## Next: the third batch

Re-run only the arms that test the remaining question, with a registered
prediction (`liarfix3_2026-10-20.txt`):
- the control, raw and verified, for honest false quarantines;
- the consistent liar, to confirm it is still contained under the stricter rule.
