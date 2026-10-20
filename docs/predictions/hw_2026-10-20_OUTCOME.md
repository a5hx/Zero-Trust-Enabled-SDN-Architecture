# Outcome: Phase 3, honest-slow versus lying (H1–H6)

- Prediction: `hw_2026-10-20.txt`, committed in 0cc3719 before any hw_* run.
- Runs: 30 live runs, 5 per arm, under `data/runs/hw_*/`.
  - **The first pilot (r01) aborted at 8 s by design.** Agents couldn't join
    their cgroup from inside a Mininet host. It was fixed in d1076c4 by
    attaching from the root namespace, and the aborted run was not scored.
  - **A power loss interrupted one hw_sybil_fast run.** Its partial
    recording was archived, not scored, and the runner topped the arm up to 5.
- Summary: `hw_2026-10-20_live_summary.txt`.
- **The emulation works** (pilot r02):
  - the slow class's tasks ran ~10 ms longer, consistent with a 15 ms task
    taking ~25–30 ms at half a core;
  - throttled srv4 went from ~90 to 210–223 ms median task latency, exactly
    inside its throttle window.

| | Prediction | Live | Verdict |
|---|---|---|---|
| H1 | Mixed hardware, fleet baseline: 0 honest false quarantines in ≥ 4/5 | **0 in 5/5** | **Held** |
| H2 | Mixed hardware, class baseline: 0 in ≥ 4/5 | **0 in 5/5** | **Held** |
| H3 | 25% throttle: srv4 quarantined in ≤ 1/5 | **0/5** | **Held** |
| H4 | 10% throttle: srv4 quarantined in ≥ 3/5, released < 30 s after the throttle | **1/5**: two brief quarantines (1.5 s and 2.1 s) in r05 | **Failed** |
| H5 | Sybil contained 5/5 on both classes; slow-class median ≤ 2× fast | **5/5 and 5/5**; median 9.0 s (slow) vs 8.4 s (fast) | **Held** |
| H6 | Honest-device mean latency within 15% of hw_class (100.0 ms) | 101.2 / 101.4 / 110.8 / 110.7 / 106.5 ms | **Held** |

## Why H4 failed: the mechanism was not the one predicted

**The latency tell never fired on the throttled honest server, in any of the
five runs.**
- Its `/status` round trip stayed at a median of ~30 ms (the fleet's), with
  isolated spikes of 130–397 ms.
- The 3-strike persistence absorbed those spikes. The prediction assumed
  slow polls would cluster; they did not.
- Part of the reason: the router steered work away from the slow server, so
  it was rarely busy when polled.

**The one quarantine (r05) came from two other signals:**
1. **"/status unreachable"** at t = 129.9 s.
   - One poll exceeded the 0.5 s poll timeout while srv4 was throttled.
   - Unlike the latency tell, the unreachable signal has **no persistence**:
     a single missed poll sets Ā to 0.85, above the gate.
   - Released after 1.5 s.
2. **The honesty check, inverted**, at t = 132.5 s.
   - Just after that quarantine, srv4's claimed busy duty was 0.59 and 0.47,
     from slow tasks still running. The controller's expected duty was 0.00,
     because the quarantine had stopped the completions that expected duty is
     built from.
   - Enforcement corrupting its own input again (paper §VIII-A), this time
     in the honesty check.
   - Released after 2.1 s.

**Cost to the honest server:** 3.6 s quarantined out of 1,500 throttled
seconds across five runs, 0.57 quarantines per server-hour in that arm, and
none in any other arm.

## What this settles

- **At the shipped load, honest heterogeneity does not cause false
  quarantines.** That holds for mixed hardware classes with fleet or class
  baselines, and for a realistic 25% throttle. Even a severe 10% throttle cost
  one server 3.6 s once in five runs. The latency tell's persistence is doing
  its job.
- **The class baseline is not needed at this load, and doesn't hurt.** It
  still catches a slow liar among slow peers (5/5, 9.0 s against 8.4 s on
  fast hardware).
- **Two refinements, measured here and not yet made:**
  - (a) give the unreachable signal the same short persistence as the latency
    tell;
  - (b) have the honesty check abstain for a node while it is quarantined, or
    just after, because its completions stop for a reason that is ours, not
    the node's. That is the stale-evidence rule applied to quarantine.

  Both are small. Each needs its own re-run before it can be claimed.
- **Not tested here:** a throttled server at higher occupancy. At 40% the
  router has less room to steer away and polls will more often find it busy.
  That is the natural next run if this matters for the hardware stage.
