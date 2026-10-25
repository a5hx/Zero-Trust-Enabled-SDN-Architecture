# How much traffic can a load liar win, and when can the gate see it?

This is the analytic companion to `evaluation/liar_sweep.py`. The registered
prediction it supports is `docs/predictions/liar_2026-10-19.txt`.

## Setting

- N servers, routed by power-of-d-choices with ε-exploration (`edge_selector.py`):
  - with probability ε, a uniformly random eligible server;
  - otherwise, the higher EdgeScore of d servers sampled without replacement.
- EdgeScore = w1·T + w2·(1 − c) + w3·(1 − rtt_norm), where c is the server's
  **raw, instantaneous** `cpu_load` claim from its last `/status` poll.
- The honesty check fires when
  |claimed duty − expected duty| > h (h = 0.40).
  - Claimed duty comes from the server's busy-seconds counter over 3 s.
  - Expected duty = completion rate × fleet-median service time / concurrency.

## 1. The ceiling: p2c caps what any lie can win

An eligible server is in the sampled pair with probability d/N, since
1 − C(N−1, d)/C(N, d) = d/N. It is picked by exploration with probability
ε/N. A liar that wins **every** comparison it is sampled into therefore gets

    share_max = ε/N + (1 − ε)·d/N

At N = 8, d = 2 and ε = 0.05 that is **24.4%**, against a fair 12.5%. So the
gain is capped near (d − 1)/N whatever the lie. Under argmax there would be no
cap, and a liar holding the best score would win every decision. This
ceiling is a property of p2c, not of any detector: it holds when the gate is
blind too.

**In the model** (`liar_sweep.py`, 360 runs), the largest share any liar
reached was 20.8%.

## 2. The lie has to beat the truth

The liar wins a comparison against honest server j when

    w2·(c_j − c_liar) > w1·(T_j − T_liar) + w3·(…)

with RTTs equal, since these liars are not slow.

- **At the shipped ~1% occupancy, c_j is ~0 nearly every poll.** A claim of 0
  only ties.
- **Any honesty deficit then loses the tie.** A liar whose busy counter is
  faked to match its claim has an expected duty above its claimed duty, so
  H < 1 and T_liar < T_j. p2c decides by score, so even a deficit of 0.002 in
  T loses the comparison.
- The model's consistent liar gets **3.8%** at 1% occupancy. The live
  sybil got 1.98%, for the same reason plus its slowness.

## 3. When the gate can see a consistent liar

A consistent liar holding share s does real work at duty ≈ s·N·ρ, where ρ is
fleet occupancy, but reports a duty equal to its claim. The gap reaches h when

    s·N·ρ − claim > h   ⇒   at s = 2/N, claim = 0:   ρ > h/2 = 0.20

Below 20% occupancy the honesty check cannot see it, even at the share
ceiling. In practice it never reaches the ceiling (section 2), and the model
first catches it at ρ = 0.30.

## 4. The split claim is invisible to the honesty check

Routing reads the raw `cpu_load`, but the honesty check reads the busy-seconds
counter. A liar that reports `cpu_load = 0` but a **truthful** busy counter
therefore:

- has claimed duty = true duty, so the honesty gap is about 0 and H ≈ 1,
  with no trust deficit;
- wins every comparison in which the honest server's instantaneous claim is
  above 0. The probability of that rises with ρ.

**In the model:** excess share of +1.5 points at ρ = 0.10, +5.2 at 0.40 and
+8.3 at 0.50. It is never caught by the gate at ρ ≤ 0.40, and no honest server
is quarantined.

Two fixes follow directly. They are applied only after the live runs have
measured the hole (novelty plan 1d):
1. an internal-consistency check between the raw `cpu_load` and the duty
   implied by the busy counter;
2. routing on the time-averaged `claimed_load()` instead of the raw sample.

## What this does and does not say

- It describes the shipped selector and detectors, at N = 8 and d = 2.
  - A larger d raises the ceiling (d/N).
  - A smaller ε lowers the exploration floor.
- It is a model. The live system also has UCB1 changing w1–w3 during a run,
  1 s polling, flow-install latency, and the stale-evidence rule in probation.
  The registered prediction lists these.
- The ceiling does not say the gain is harmless. Twice the fair share of
  traffic through an attacker is exactly what Burke et al. and Yu et al. treat
  as the attacker's goal at the switch.
