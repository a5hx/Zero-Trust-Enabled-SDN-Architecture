# Outcome: the witness hold, third run (wh3_*): the trial path works end to end

Prediction `withold3_2026-10-25.txt` was committed before any run (`26e2b04`). All 25 runs
were at `26e2b04` and completed cleanly (`ok` in `data/runs/manifest.csv`, 2026-10-25,
10:48–13:12 UTC). Scored on 2026-10-25:

```bash
python3 -m evaluation.witness_act_report data/runs --arms wh3_control_hold,wh3_forge_act,wh3_forge_hold,wh3_drop_act,wh3_drop_hold
python3 -m evaluation.replicates data/runs --arms wh3_control_hold,wh3_forge_act,wh3_forge_hold,wh3_drop_act,wh3_drop_hold --out-dir data/withold3_experiment_2026-10-25
```

The outputs are `withold3_2026-10-25_live_withold.txt` and `_live_summary.txt`.

## Verdict: L1–L5 held; L6 failed, on one false witness action after a machine-wide stall

| # | Predicted | Measured | |
|---|---|---|---|
| L1 | Trial tails charged elsewhere = 0 in every holding run; non-SYN PacketIns not routed > 0 in every holding run | **0 / 0** in all 10 holding runs (wh2: 25 and 16). Not routed: 152–169 per `forge_hold` run, 222–291 per `drop_hold` run | **Held** |
| L2 | ≥ 90% of witness trials judged | **245 / 245, 100%** (wh2: 54%; batch 1: 8%) | **Held** |
| L3 | `forge_hold`: srv3 held 5/5, released 0/5; ≥ 95% quarantined; honest success ≥ 98.5%, interval disjoint above `forge_act` | held **5/5**, released **0**; **95.3% [95.1, 95.6]**; **99.06% [98.96, 99.16]** vs 97.68% [97.49, 97.87] | **Held** |
| L4 | `drop_hold`: srv1 (grayhole) released ≥ 1 in ≥ 3/5; srv6 (blackhole) held 5/5, never released | srv1 released in **5/5** (1–2 times per run, 2 holds each); srv6 held **5/5**, released **0** | **Held** |
| L5 | control: no honest server held or blamed in 5/5; honest success ≥ 99.9% in ≥ 4/5 | **0** held, **0** blamed; 100, 99.965, 99.982, 100, 99.982%: **5/5** | **Held** |
| L6 | No honest server quarantined by the witness signal in 25 runs | **1**: `wh3_forge_act` r03, srv2, at 279.5 s | **Failed** |

## Both trial-path fixes, measured

| | batch 1 (`wh_*`) | wh2 (passage fix) | **wh3 (+ SYN-only)** |
|---|---|---|---|
| Witness trials judged | 29 / 369, 8% | 49 / 90, 54% | **245 / 245, 100%** |
| Trial timeouts charged to an honest server | 4 | 41 (3 runs) | **0** |
| Grayhole srv1 released | 0 / 5 runs | 1 / 1 | **5 / 5** |
| Lowest honest trust, holding arms | 0.42–0.50 | 0.419, 0.420 | **0.731 [0.716, 0.746], 0.680 [0.534, 0.826]** |

**The hold now does what it was designed to do.**
- A dropper that forges its evidence (srv3) fails every one of its 23 trials per run, and
  is never released.
- A blackhole (srv6) fails all 26, and is never released.
- A 50% grayhole (srv1) is released after three lucky trials in a row, 1–2 times per run,
  then re-blamed and re-held. Both the release and the re-hold are what the rule predicts.
  The rule's registered weakness, that a grayhole passes 3 in a row after about 14 trials,
  is now observed as designed.

**Outside trials the guard almost never fires.** In the non-holding arms, 0–53 non-SYN
PacketIns per run were not routed, mostly in runs where a quarantine deleted rules mid-flow.
In the control arm there were 0–5 per run. Ordinary routing is untouched: the control arm's
honest success is 99.99% [99.97, 100], against 99.95% in batch 1.

## Service

| Arm | Honest task success | srv3 / srv6 connections after onset | Timeouts per run |
|---|---|---|---|
| `wh3_forge_act` | 97.68% [97.49, 97.87] | srv3: 135 | 122 |
| `wh3_forge_hold` | **99.06% [98.96, 99.16]** | srv3: **64** | 50 |
| `wh3_drop_act` | 99.11% [98.88, 99.35] | srv6: 32, srv1: 62 | 48 |
| `wh3_drop_hold` | 98.91% [98.81, 99.00] | srv6: 40, srv1: 60 | 59 |

- **Against forged evidence, holding adds 1.4 points of honest success.**
  - Measured from observe-only (82.2%, `witact` outcome) to an honest run (99.99%), it closes
    **95%** of the gap; acting alone closes 87%.
  - That is below batch 1's 99.40%, as L3 predicted. Batch 1 was flattered: its black-holed
    trials sent no report.
- **Against plain droppers, holding costs 0.2 points.**
  - The gate already contains a blackhole. The hold adds about 26 trials per run against it,
    each a lost task for an honest client.
  - Against the grayhole, the hold's release and re-blame cycle is roughly neutral.
  - So the hold earns its place only where the controller's own evidence is wrong.

## L6: the false witness action

In `wh3_forge_act` r03, at 279.5 s, the witness blamed honest srv2 ("30% of recent
connections failed with no full response at the switch"). The acting rule raised the gate,
and srv2 stayed quarantined to the end of the run (26 s).

**What happened (from the recording and `r03.controller.log`):**

1. **The whole machine stalled for about 1–2 s.**
   - From 271.8 s to 277 s the event stream has gaps of 0.5–1.5 s.
   - The controller wrote nothing at all for about 1–2 s around 12:13:38–41.
   - Every server's tasks in that window took 490–990 ms, against about 85 ms normally:
     srv2, srv4, srv5, srv7 and srv8 alike.
   - The cause is not recorded. The load average before the run was 0.34.
2. **When it cleared, the clients' backlog arrived as a burst.** Routing on stale load
   figures, the controller sent **16 connections to srv2 within 1.5 s**: srv2 had 16 in
   flight at 276.2 s, against 0–9 for the others.
3. **srv2's agent refused some of them.**
   - The agent's `ThreadingHTTPServer` keeps socketserver's default accept backlog of 5.
   - Ten tasks succeeded, and six failed with connection errors, all at 276.46 s.
   - So the failures were real, and the switch saw them correctly.
4. **Six failures was 30% of srv2's recent window**, which crossed the witness's server
   rule. With the act rule on, that raised srv2's anomaly to 0.85.

The witness was not wrong about what happened at the switch. It was wrong to read **one
burst caused by the platform** as a server that drops work. In 128 live runs since its
fixes, this is the first false blame, and it took a machine-wide stall to produce it.

The trust rail alone would not have quarantined srv2: six failures took its trust from 0.82
to 0.60, still above θ = 0.30.

**Not fixed here** (measure → fix → re-measure). Three candidates:
- **(a)** Have the witness's server rule require persistence across windows, as the
  anomaly tells already do with leaky-bucket strikes. One burst should not suffice.
- **(b)** Abstain while the fleet's latency is anomalous everywhere at once. A platform
  stall is not one server's misbehaviour.
- **(c)** Raise the agent's accept backlog (`request_queue_size`), so a burst queues
  instead of being refused. This is a harness change, but it is also what a real server
  would do.

Option (a) is the principled one. Each needs its own re-run.

## A scoring artefact: teardown quarantines

`evaluation.replicates` reports 1.40 "honest servers ever quarantined" for `wh3_forge_hold`.
All 7 of those quarantines are in r04, at **305.6 s, after the configured 300 s**.
- Mininet was tearing the network down, every `/status` poll failed in the same cycle, and
  the one-strike "unreachable" signal quarantined all 7 servers at once.
- No other run recorded past the teardown point.
- These are not behaviour, and they are excluded from every reading above.

`replicates.py` does not clip events at the configured duration. A follow-up should clip
them, and report how many earlier figures that changes.

## Next

1. **Witness persistence (a):** a server is blamed only after its rate exceeds the
   threshold in 2–3 consecutive windows. Register a prediction, then re-run `wh3_forge_act`
   and `wh3_control_hold` plus a stall-injection arm. A controlled pause of the agents, for
   example `SIGSTOP` for 1.5 s, makes the stall repeatable.
2. **Clip scoring at the configured duration** in `evaluation/replicates.py`.
3. **Paper:** witness acting (`witact` outcome) and the hold (this outcome, with both
   trial-path defects and their measured effect on probation) are ready to go in as a new
   §VII subsection. The defects also belong in the validity section, because trust-rail
   probation in every earlier recording worked only for same-switch clients.
