# AI Weight Optimizer

The controller routes each new connection to `n* = argmax EdgeScore(n)` over the
non-quarantined edge nodes, where

```
EdgeScore(n) = w1·T(n) + w2·(1 − cpu_load(n)) + w3·(1 − lat_norm(n))
```

The three weights `w1/w2/w3` decide how much trust, load, and latency each count.
They used to be hand-picked constants (`0.50 / 0.30 / 0.20`). The **AI weight
optimizer learns them from measured outcomes** instead.

This document describes what is built (the online UCB1 bandit), what is
deliberately deferred (the offline Random Forest), and the seam that lets the
second drop in behind the first with no controller changes.

> Framing for the viva: this is **classical UCB1**, not deep reinforcement
> learning. It assumes a roughly stationary reward. The offline model is
> **deferred on purpose** until the evaluation harness can generate honest
> training data — building it on fabricated data would be dishonest.

---

## Scope and safety invariant

The optimizer tunes **only** `w1/w2/w3`. It never touches the security gates
(`isolation_threshold`, `anomaly_gate`). Node exclusion happens *before* scoring
in `controller/edge_selector.select_edge_node`, so **no weight setting can route
to a quarantined (malicious) node** — the bandit can only reorder the nodes that
were already eligible. Every arm is a real `EdgeWeights`, so each is validated to
sum to `1.0` with every weight `>= 0.05` at construction.

Off by default: with no `optimizer:` config block (or `enabled: false`), the
controller uses a `StaticWeightOptimizer` and behaves byte-for-byte as before.

---

## Part 1 — Online UCB1 bandit (built)

A **multi-armed bandit** repeatedly chooses among "arms" of unknown payoff,
balancing *exploration* (trying under-sampled arms) against *exploitation*
(pulling the best-known arm). **UCB1** does this with a confidence bound: after
pulling every arm once, it selects

```
argmax_i  value_i + c · sqrt( ln(total_pulls) / count_i )
```

- `value_i` — mean reward observed for arm *i*.
- the `sqrt` term — an exploration bonus, large for rarely-tried arms, shrinking
  as they are sampled, so no arm is starved and the choice converges on the
  genuinely best weights.
- `c` — exploration constant (default `√2`).

**Arms = discrete weight presets.** UCB1 is a discrete-arm algorithm (matching
the deck), so the weight space is sampled at a handful of presets rather than
searched continuously. Defaults (configurable):

| Arm | w1 trust | w2 cpu | w3 lat | intent |
|-----|----------|--------|--------|--------|
| 0 | 0.50 | 0.30 | 0.20 | balanced (baseline) |
| 1 | 0.70 | 0.20 | 0.10 | trust-heavy |
| 2 | 0.34 | 0.50 | 0.16 | load-heavy |
| 3 | 0.34 | 0.16 | 0.50 | latency-heavy |
| 4 | 0.45 | 0.45 | 0.10 | trust + load |

### The reward

Per window (default 10 s) the active arm is scored:

```
reward = success_rate − λ·mean_normalized_latency − μ·load_imbalance
         (λ = μ = 0.2 by default)
```

- **success_rate** — fraction of task outcomes in the window that succeeded
  (vs. `failure`/`timeout`). The dominant term; it punishes routing to a
  failing or malicious node hard.
- **mean_normalized_latency** — mean latency of the chosen nodes ÷ the max, in
  `[0,1]`. Rewards fast nodes.
- **load_imbalance** — standard deviation of per-node `observed_load`. Rewards
  spreading work rather than piling it on one node.

**Why the extra terms matter — the "needs stress" finding.** In a healthy
network almost everything succeeds regardless of the weights, so a
success-rate-only reward is *flat* and the bandit has nothing to learn from. The
latency and imbalance terms give it a gradient even then. But the bandit still
only *visibly* converges when the environment actually punishes bad choices —
i.e. under the attack / congestion scenario. That is a real property of bandits,
not a defect; demo it under stress.

### Where it lives

| Concern | Location |
|---|---|
| Bandit + reward (pure, no deps) | `trust_engine/ai_optimizer.py` |
| Weight selection + reward window + `optimizer_tick()` | `controller/trust_state.py` |
| ~1 Hz driver | `controller/flow_monitor.py` (`_poll_cycle`) |
| Config → optimizer factory | `controller/trust_balancer.py` (`build_optimizer`) |
| Live status | `GET /api/optimizer` |

`TrustState.edge_weights` is a read-only property delegating to the active
optimizer, so every routing decision and the REST weight-readout always reflect
the live arm.

### Configuration

```yaml
optimizer:
  enabled: true
  algorithm: ucb1
  window_s: 10.0
  exploration_c: 1.41
  reward:
    latency_penalty: 0.2
    imbalance_penalty: 0.2
  arms:
    - [0.50, 0.30, 0.20]
    - [0.70, 0.20, 0.10]
    - [0.34, 0.50, 0.16]
    - [0.34, 0.16, 0.50]
    - [0.45, 0.45, 0.10]
```

### Observing it live

- `GET /api/optimizer` → `{enabled, active_weights, arms:[{arm, weights, count,
  mean_reward, active}]}`.
- Controller log, once per window:
  `OPTIMIZER: window closed reward=… (N outcomes) weights [..] -> [..]`.
- Under the sybil/drop scenario the pull counts should shift toward the
  trust-heavy arm once the attack starts.

### Known limitation

UCB1 assumes a **stationary** reward distribution. If the best arm changes
mid-run (an attack begins, load shifts), plain UCB1 re-learns only slowly because
early samples still weigh on `value_i`. Accepted for this project; a
discounted / sliding-window UCB is the future fix.

---

## Part 2 — Offline Random Forest (deferred, seam ready)

The offline model predicts good weights (or an arm's expected reward) from the
current network conditions — because no single weight setting is best in every
condition (calm vs. congested, quiet vs. under-attack).

It is **not built yet**: it needs a batch of labelled runs to train on, which the
**evaluation harness** (a later milestone) produces. It is not blocked on RAFT or
anything else — only on having honest data.

**The seam.** Everything routes through one protocol:

```python
class WeightOptimizer(Protocol):
    def active_weights(self) -> EdgeWeights: ...
    def observe(self, reward: float) -> None: ...
    def select(self) -> EdgeWeights: ...
```

`UCB1WeightOptimizer` and `StaticWeightOptimizer` implement it today. The Random
Forest lands as a third implementation, or — better — as a **warm-start prior**
that seeds UCB1's `value_i` estimates from the model instead of starting at zero.
Either way the controller does not change.

**The training data is a byproduct of running the bandit.** Each closed window
emits an `optimizer` event carrying both the reward/arm and a `conditions`
snapshot (`mean_trust`, `mean_load`, `mean_latency_ms`, `num_quarantined`). When
dashboard recording is on, those events are already persisted to
`data/events.jsonl`. The Random Forest's training set is simply the `optimizer`
events filtered out of that recorded stream — `(conditions → arm, reward)` rows.
No separate logging path is required.
