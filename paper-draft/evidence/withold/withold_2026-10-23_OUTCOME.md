# Outcome: the witness holds a blamed server until it serves trials

Prediction `withold_2026-10-23.txt` was committed and pushed before any run (`1dd5a8d`).
All 25 runs were at `1dd5a8d` and completed cleanly. Scored 2026-10-24:

```bash
python3 -m evaluation.witness_act_report data/runs --arms wh_control_hold,wh_forge_act,wh_forge_hold,wh_drop_act,wh_drop_hold
python3 -m evaluation.replicates data/runs --arms wh_control_hold,wh_forge_act,wh_forge_hold,wh_drop_act,wh_drop_hold --out-dir data/withold_experiment_2026-10-24
```

The outputs are `withold_2026-10-23_live_withold.txt`, `_live_summary.txt` and
`_live_witness.txt`.

## Verdict: H2, H3, H4 and H6 held; H1 failed narrowly; H5 failed because of a data-plane defect

| # | Predicted | Measured | |
|---|---|---|---|
| H1 | `wh_control_hold`: no honest server held ≥ 4/5; honest success ≥ 99.9% every run | **0** held in 5/5. Honest success 99.89, 99.98, 100, 99.95, 99.95%: **r01 is 0.006 points under** | **Failed** (not by the witness, see below) |
| H2 | `wh_forge_hold`: held 5/5, released ≤ 1/5; ≥ 95% quarantined; ≤ 100 connections; honest success ≥ 98.5%, disjoint above `wh_forge_act` | held **5/5**, released **0**; **95.3% [95.0, 95.6]**; **65 [58, 72]** connections (act: 132); **99.40% [99.33, 99.48]** vs 97.75% [97.59, 97.91] | **Held** |
| H3 | `wh_forge_act` within 1 point of 97.5% | **97.75%** | **Held** |
| H4 | `wh_drop_hold`: srv6 held 5/5, never released; connections within 20 of `wh_drop_act` | held 5/5, released 0; **45 vs 30** | **Held** |
| H5 | srv1 (50% grayhole) released at least once in ≥ 3/5 runs | released **0/5** | **Failed** |
| H6 | No honest party blamed and no honest server held in 25 runs | **0 and 0** | **Held** |

## H5, and the defect behind it

**Most trial connections never reach the held server.**
- Across the three held servers, **369 trials were routed, 42 came from clients behind the
  held server's own switch, and 29 were judged.**
- A trial from any other client is black-holed and the client reports nothing: with no
  established connection there is no source port to attribute.
- srv1, a 50% grayhole, therefore got 11 judged trials in 5 runs, not the ~120 designed.
  It never had the chance to pass 3 in a row.

**Why.** Quarantine installs drop rules for the server's MAC on **every** switch
(priority 400). A trial's rules, which out-rank them (priority 460), are installed only on
the **client's ingress switch**. Once rewritten there, the trial's packets cross the core
switch and the server's own switch, where nothing out-ranks the drop rules. The same is true
of the reply.

**This is older than the hold.** The probation trials that let a server quarantined on low
trust earn its way back use the same path. On this topology, one switch per server, they
have only ever worked for clients on the quarantined server's own switch: about 1 in 8. The
code's own comment says a trial "has to out-rank the drop rules"; it did only on the first
switch. Every recorded run is affected, in one direction: trust-quarantined servers were
released more slowly than designed. That makes attacker isolation figures conservative (they
would be shorter with working trials). Honest servers falsely quarantined on trust stayed
quarantined longer. The control run below shows one: a trial from another switch at 101 s
was lost, and one from the server's own switch at 106 s released it.

## H1: a trust-rail false quarantine, not the witness

In `wh_control_hold` r01 two clients' tasks failed at the same moment (connection failures
after 209 and 666 ms). With λ = 0.85, two failures took honest srv2's trust from about 0.8
to 0.28, below θ = 0.30. It was quarantined on the trust rail at 96.1 s and released at
106.7 s. The witness blamed nobody and held nobody. Honest task success in that run was
99.894%. That is the same λ sensitivity the badmouth outcome found
(`witact_2026-10-23_OUTCOME.md`), now from real failures.

## What the experiment shows anyway

- **Against forged evidence, holding works even with trials mostly black-holed.**
  - Connections handed to the dropper fell from 132 to 65 per run.
  - Honest task success rose from 97.75% to **99.40%**. Measured from the observe-only
    baseline (82.2%) to an honest run (99.96%), that closes 97% of the gap.
  - Timeouts fell from 120 to 32.
- **Against plain droppers:**
  - The blackhole srv6 took 45 connections held, against 30 acting alone. Holding costs
    trials and saves little against a server the gate already contains.
  - The grayhole srv1 fell from 57 to 47, and honest task success rose from 99.16% to
    99.53%. But with trials this rare the release rule was never really tested.
- **No false blame or false hold in 25 runs.** That makes 95 live runs since the witness's
  fixes without blaming an honest party.

## Next

Fix the trial path, so a trial gets past the drop rules on every switch it crosses, for the
witness hold and for trust-rail probation alike. Then re-run these arms. H5 and the hold's
real cost against droppers can only be judged after that.
