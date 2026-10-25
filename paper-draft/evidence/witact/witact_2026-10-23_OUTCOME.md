# Outcome: the switch witness's verdicts act

Prediction `witact_2026-10-23.txt` was committed and pushed before any run (`13006e8`).
The 25 runs were all at `13006e8` and all completed cleanly (307.7–310.9 s recorded).
Scored 2026-10-23:

```bash
python3 -m evaluation.witness_act_report data/runs --arms wa_control,wa_badmouth_observe,wa_badmouth_act,wa_forge_observe,wa_forge_act
python3 -m evaluation.replicates data/runs --arms wa_control,wa_badmouth_observe,wa_badmouth_act,wa_forge_observe,wa_forge_act --out-dir data/witact_experiment_2026-10-23
python3 -m evaluation.witness_report data/runs --arms wa_control,wa_badmouth_observe,wa_badmouth_act,wa_forge_observe,wa_forge_act
```

The outputs are `witact_2026-10-23_live_witact.txt`, `_live_summary.txt` and
`_live_witness.txt`.

## Verdict: W1–W3, W5 and W6 held; W4 failed on its trust-floor clause

| # | Predicted | Measured | |
|---|---|---|---|
| W1 | `wa_control`: no false actions in ≥ 4/5 runs; honest success ≥ 99.9% | **0** honest servers hit by the witness signal and **0** honest reports discounted, in 5/5 runs; 99.98% [99.96, 100] | **Held** |
| W2 | `wa_forge_act`: srv3 quarantined 5/5 with the witness signal, median ≤ 20 s; quarantined ≥ 50% of post-onset time; ≤ 1/3 of the observe arm's connections | **5/5**, all with the witness signal, median **11.0 s**; quarantined **84.3% [83.2, 85.4]**; **148 [139, 157]** connections vs **770 [766, 774]** (19%) | **Held** |
| W3 | `wa_forge_act` honest success ≥ 95%, disjoint from observe; observe within 3 points of 82.6% | **97.54% [97.45, 97.64]** vs **82.24% [82.07, 82.42]**: disjoint; observe 0.4 points from 82.6% | **Held** |
| W4 | Both badmouthers discounted 5/5, first median ≤ 20 s; lowest honest trust after onset ≥ 0.45, disjoint from observe | Discounted **5/5** each (124–125 reports per run), first at a median **11.9 / 12.0 s**; lowest honest trust **0.409 [0.379, 0.440]** vs 0.361 [0.355, 0.366]: disjoint, but **below 0.45** | **Failed** on the floor |
| W5 | `wa_badmouth_observe` lowest honest trust within 0.05 of 0.357 | **0.361** | **Held** |
| W6 | No honest server hit by the witness signal in 25 runs; witness blames no honest party ≥ 23/25 | **0** and **0 in 25/25** | **Held** |

## Why W4 failed, and what the measure should have been

With the trust formula's λ = 0.85, **a single charged timeout drops an honest server from
its steady state to about 0.42**. R falls to 0.405 and B to 0.12, which gives T ≈ 0.42.
Before the witness blames a badmouther it needs 9–12 s of its reports; about 10 badmouth
reports per run are charged in that window. So in every acting run the lowest point falls
inside the first 12 s after onset: 6.7–12.3 s, at 0.36–0.42. Against λ = 0.85, no
discounting that starts after evidence accumulates can protect that floor.

**The prediction picked the wrong measure of harm.** The floor is set by the first charged
report, not by how long badmouthing goes on. Measured after the fact (not predicted, from
the same recordings):

| | `wa_badmouth_observe` | `wa_badmouth_act` |
|---|---|---|
| Badmouth reports charged after onset, per run | 257–261 | **9–12** |
| Share of honest-server polls with trust < 0.45 | 19.7% [18.5, 20.8] | **0.6% [0.2, 1.0]** |
| Mean honest-server trust after onset | 0.72 [0.72, 0.73] | **0.80 [0.80, 0.80]** |

Discounting removes 96% of the badmouthers' influence and nearly all the time honest
servers spend depressed. It cannot remove the first few seconds of it.

Badmouthing never threatened honest service here: honest task success was 99.96% in both
arms. The 95.47% PDR in both badmouth arms counts the badmouthers' own false claims.

## What the experiment shows

1. **An acting witness restores protection the controller's own detectors lost.** With
   forged evidence the controller never quarantined the dropper (0/5, again). Acting on
   the witness, it quarantined it in all 5 runs, a median 11.0 s after onset, and kept it
   quarantined 84% of the time. Connections handed to the dropper fell from 770 to 148
   per run, and honest task success rose from 82.2% to 97.5%.
2. **What remains:** about 16% of the post-onset time srv3 is back in service. The witness
   verdict lapses once its connections leave the 60 s window; the gate then releases srv3;
   its forged trust draws traffic back; and the witness needs about 10 fresh failures to
   blame it again. That cycle, not detection speed, is the remaining loss: 132 timeouts per
   run, against 745.
3. **No false actions in 25 runs.** No honest server was quarantined by the witness signal,
   no honest client's report was discounted, and the witness blamed no honest party. That
   makes 70 live runs since its fixes with no false blame.
4. **Acting does not slow the witness.** It blamed srv3 a median 10.1 s after onset in
   both forge arms, and the badmouthers 9.1–10.1 s after onset in both badmouth arms.

## What this does not show

- **No adversary targeting the witness.** A lying switch is excluded from judging rather
  than acted on. All clients of one switch lying together still look like the switch lying.
- **The forged-evidence case assumes** the forgery sits in the trust pipeline, not in the
  witness or the gate.
- **The remaining release-and-re-blame cycle** could be closed by holding a witness-blamed
  server until it passes a probation trial, as trust-rail quarantine already does. That is
  untested.
