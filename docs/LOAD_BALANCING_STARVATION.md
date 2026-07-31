# EdgeScore starvation: why only ~2 servers ever get traffic

> Raised by the advisor (2026-07-28): *"Two servers don't get routed — isn't
> that a load-balancing flaw? And if the number of servers grows, how many will
> EdgeScore route to?"* This document answers both, distinguishes the two very
> different "zero-traffic" cases, gives the reproduction, and records the fix.

## 1. The behaviour is real and already in the data

The two live Mininet runs behind `docs/study/trust-routing-study.html` show it
directly (the `share` / `share_total` blocks):

| run | routes | srv1 | srv2 | srv3 | srv4 |
|-----|-------:|-----:|-----:|-----:|-----:|
| **A** (498 s)  | 3,742  | 1,812 | **0**    | **0** | 1,930 |
| **B** (2,832 s)| 24,596 | 11,584 | 1,161 | **0** | 11,851 |

In run A, **2 of 4 servers carried 100 % of the traffic**. In run B, srv2's
first packet did not arrive until t = 2,238 s (19,320 decisions of starvation)
and srv3 never received a single one.

## 2. "Zero traffic" is two different things — do not conflate them

| server | traffic | verdict |
|--------|---------|---------|
| **srv3** (the sybil attacker, 154 ms mean latency) | 0 | **Correct.** Zero-trust isolation working — this is the security feature, not a bug. |
| **srv2** (healthy, honest, *best* latency at 33.5 ms) | 0 | **The real flaw.** This is *starvation*: a fully healthy node that is never selected. |

The study's own wording: *"A node that ranks last is being correctly avoided; a
node that ranks second and never wins is being starved."* srv2 reached 2nd place
in 585 decisions and 1st place in **none**.

A related correction: **starved healthy servers do not "drop" packets — they
receive none.** No node is ever selected → no VIP rewrite rule is installed → the
server simply never appears in the data plane. The only server that gets actual
OpenFlow *drop* rules is the quarantined sybil (`TrustBalancerApp._on_trust_collapse`,
priority-400 entries).

## 3. Mechanism

Routing is `select_edge_node()` in `controller/edge_selector.py`, which is
**`argmax` — winner-take-all**: exactly one node per decision. The round-robin
tie-break only fires on **exact** ties (≤ 1e-9); real telemetry jitter separates
scores at the 4th decimal, so a node a hair behind **never wins**.

Reproduce any of this with `python3 -m evaluation.starvation_sweep` (a
controller-in-the-loop simulation over the *real* selector; identical healthy
servers, configured weights 0.50/0.30/0.20, 1 s poll — no sudo/Mininet needed):

```
 strategy |    N |  used | starved | busiest |  Gini
   argmax |   32 |  2/32 |      30 |     50% |  0.94
      p2c |   32 | 32/32 |       0 |      3% |  0.04
  p2c+eps |   32 | 32/32 |       0 |      3% |  0.04
```

The two regimes that isolate the cause:

**A. Load-only differentiation — argmax spreads fine, even at N = 64.** With
honest, fresh-enough load feedback the argmax degenerates to join-shortest-queue
(busiest server ≈ 2 % share at N = 64). *So "argmax over load" is not the
problem.*

**B. Trust coupled to selection (trust weight 0.50 dominates; only completed
tasks move trust) — lock-in:**

```
N servers | ever used | starved (0 traffic) | busiest share
        2 |    2 / 2  |        0 / 2        |   50%
        4 |    2 / 4  |        2 / 4        |   50%
        8 |    2 / 8  |        6 / 8        |   50%
       16 |    2 / 16 |       14 / 16       |   50%
       32 |    2 / 32 |       30 / 32       |   50%
       64 |    3 / 64 |       61 / 64       |   39%
```

This reproduces the "2 of 4" and answers the scaling question.

## 4. Answer: how many servers does EdgeScore route to as N grows?

**≈ 2, essentially constant, independent of N.** Growing the farm does not widen
the fan-out — it manufactures idle capacity; the number of starved servers grows
*linearly* with N (30 dead servers at N = 32).

The cause is a **positive-feedback lock-in ("the rich get richer")**: whichever
~2 nodes win the initial tie-break lottery complete tasks → their trust EMA
climbs toward 1.0 → the heaviest EdgeScore term (trust, 0.50) entrenches them → a
fresh node whose trust is frozen at 0.5 can never overtake a node at ~0.9. The
load signal (`claimed_cpu`, polled every 1.0 s while tasks finish in ~0.2 s) is
too stale to counteract it, so argmax stops behaving like a load balancer.

## 5. This is a textbook failure mode (IEEE literature)

1. M. Mitzenmacher, **"The Power of Two Choices in Randomized Load Balancing,"**
   *IEEE Trans. Parallel Distrib. Syst.*, vol. 12, no. 10, pp. 1094–1104, 2001.
   DOI [10.1109/71.963420](https://dl.acm.org/doi/10.1109/71.963420) — deterministic
   "pick-the-best" is fragile; even *2 random choices* balances exponentially better.
2. M. Mitzenmacher, **"How Useful Is Old Information?,"** *IEEE Trans. Parallel
   Distrib. Syst.*, vol. 11, no. 1, pp. 6–20, 2000.
   DOI [10.1109/71.824633](https://ieeexplore.ieee.org/document/824633/) — coins
   **"herd behaviour"** with stale load info (our 1 s poll).
3. M. Dahlin, **"Interpreting Stale Load Information,"** *IEEE Trans. Parallel
   Distrib. Syst.*, vol. 11, no. 10, pp. 1033–1047, 2000.
   DOI [10.1109/71.888643](https://dl.acm.org/doi/10.1109/71.888643) — stale
   least-loaded performs *worse than random*.

## 6. The fix

Replace the hard `argmax` with **power-of-two-choices (P2C)** among the *eligible*
(non-quarantined) nodes: sample `d` (default 2) candidates uniformly at random and
route to the higher-scoring of them. Quarantine still excludes malicious nodes
*before* the sample, so security is unchanged — srv3 stays at zero. But because
most random pairs among a large idle set are starved-vs-starved, a starved healthy
node is selected often enough to complete tasks, build trust, and rejoin the
active set, which dissolves the lock-in.

P2C leaves **one** gap: while scores are frozen, the *single strict-worst* node
is never the better of any sampled pair, so P2C d=2 can still starve it. In the
live system this does not bite — load feedback constantly reshuffles who is worst,
so the dynamic sweep hits 0 starved at every N — but for a hard guarantee we layer
**ε-exploration** on top: with probability ε a decision ignores the score and
routes to a uniformly random *eligible* node. That makes every eligible node's
selection probability **≥ ε/|eligible|** per decision, so nothing can be
permanently starved even under frozen scores. Verified: a frozen 8-node field
with a strict-worst node goes from 7/8 used (`ε=0`) to 8/8 (`ε=0.05`), the worst
node receiving 0.66 % ≈ ε/8. Exploration still samples eligible nodes only, so
quarantined/malicious nodes are never explored into.

Both are configured via the `edge_score:` block:

```yaml
edge_score:
  w1_trust: 0.50
  w2_cpu: 0.30
  w3_latency: 0.20
  selection: p2c   # argmax (old behaviour) | p2c (starvation-resistant)
  d_choices: 2
  epsilon: 0.05    # ε-exploration; 0.0 disables it (hard no-starvation guarantee)
```

`selection: argmax` with `epsilon: 0.0` preserves the original winner-take-all
behaviour exactly. See `tests/test_edge_selector.py` for the P2C + ε coverage and
`evaluation/starvation_sweep.py` (`python3 -m evaluation.starvation_sweep`) for
the before/after fan-out.

## 7. Side effect: p2c can hide a load-attracting Sybil, and how we close it

Spreading load has a security cost worth stating plainly. The demo's Sybil
(`srv3`) lies `cpu_load = 0.1` while burning real CPU. It used to be caught by the
**CPU-honesty deviation** check, `|claimed − observed_load| > 0.40`. But that gap
only opens once the liar has *accumulated observed load* — and under `argmax` the
lie itself concentrated traffic onto it, which is what pushed its observed load
past the threshold. Under `p2c` the liar only ever gets its fair share, so its
observed load stays low, the deviation never reaches 0.40, and **it is never
flagged**. The load-balancing fix removed the very concentration that exposed it.

The fix is a **load-independent tell** in `controller/flow_monitor.py`: a node
claiming to be idle should also be *responsive*. One burning CPU to serve slowly
answers its `/status` poll far slower than the rest of the fleet no matter how
little task traffic it gets. Server links are uniform (`simulation/topology.py`,
2 ms each), so a sustained large RTT gap is CPU contention, not network distance —
and the RTT is the controller's own measurement, so the node can't spoof it. The
rule flags:

> `claimed_cpu ≤ idle_claim_threshold` **and** `rtt > latency_liar_ratio ×
> fleet_median` **and** `rtt − fleet_median ≥ latency_liar_floor_ms`, **sustained**
> for `latency_liar_persist` polls

(defaults 0.25 / 3.0× / 40 ms / 3, in the `controller:` config block). Two
robustness choices matter, because a live `/status` RTT is noisy (GIL, scheduling,
the controller host itself under load) and a naive version quarantined *healthy*
nodes:

- **Baseline is the fleet MEDIAN, not the min.** The min brands every node an
  outlier the moment one node has a lucky-fast poll; the median needs a majority
  to be honest (the standard assumption) and self-normalises when the whole host
  slows down uniformly (the median rises with it, so ratios stay put).
- **Persistence via a leaky bucket.** A strike on a slow poll, a decrement on a
  fast one, capped just above the trip level. A CPU-burner is slow nearly every
  poll so the bucket fills and stays full (one good poll can't clear it); jitter
  drains back to zero without ever filling — so the quarantine is steady, not
  flapping.

A fast idle node, a slow node that *admits* high CPU, and a healthy node that
merely blips slow are all left alone; only "claims idle yet *sustained* slow"
trips. Coverage in `tests/test_flow_monitor.py`
(`test_latency_tell_catches_sybil_under_p2c_with_no_load`, plus jitter and
admits-busy negatives). This is a good result to walk an advisor through: the
load-balancing fix introduced a detection blind spot, and the detector was made
independent of load — and robust to real RTT noise — to close it.
