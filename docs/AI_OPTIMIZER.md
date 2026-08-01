# AI Weight Optimizer

The controller routes each new connection to `n* = argmax EdgeScore(n)` over the
non-quarantined edge nodes, where

```
EdgeScore(n) = w1·T(n) + w2·(1 − cpu_load(n)) + w3·(1 − lat_norm(n))
```

The three weights `w1/w2/w3` decide how much trust, load, and latency each count.
They used to be hand-picked constants (`0.50 / 0.30 / 0.20`). The **AI weight
optimizer learns them from measured outcomes** instead.

This document describes what is built — the online UCB1 bandit (Part 1) and the
offline Random Forest warm-start prior (Part 2) — and the seam that lets the
second drop in behind the first with no controller changes.

> Framing for the viva: this is **classical UCB1**, not deep reinforcement
> learning. It assumes a roughly stationary reward. The offline Random Forest
> was built once the simulator could generate honest training data at scale
> (Part 2) — and the honest result is that it does **not** beat hand-tuned
> static weights here; that measured negative is reported below rather than
> smoothed over.

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

**The `load_imbalance` term is a property of the selection strategy, not the
weights.** This is the key interaction with the starvation fix
(`docs/LOAD_BALANCING_STARVATION.md`). The optimizer tunes only w1/w2/w3; it does
*not* choose between `argmax` and `p2c`. And load imbalance is set almost entirely
by that selection rule:

| selection | time-avg load imbalance (N=4, sim) | μ·imbalance penalty |
|-----------|-----------------------------------:|--------------------:|
| `argmax`  | 0.500 | 0.100 |
| `p2c`     | 0.032 | 0.006 |

Under `argmax` the imbalance is high and ~constant across *every* weight arm — the
two live runs cycled the arms the entire time and load stayed pinned to two nodes
— so the μ term was a fixed offset that gave the bandit no gradient. Under `p2c`
the imbalance collapses toward zero for every arm, so the term (correctly) goes
quiet and the bandit effectively optimizes `success_rate − λ·latency`. Either way
the μ term does **not** let the weight-optimizer control load spread; only the
selection strategy does. With `p2c` as the default it is now largely a safety term
for anyone who pins `selection: argmax`. Reproduce the table with
`evaluation/starvation_sweep.py` (`simulate(..., track_load=True).load_imbalance`).

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

## Part 2 — Offline Random Forest (built)

The offline model predicts an arm's expected reward from the current network
conditions — because no single weight setting is best in every condition (calm
vs. congested, quiet vs. under-attack).

**Correction to the original framing.** This section used to say the training
data was "already produced" by the evaluation harness. That was aspirational,
not true: `evaluation/baseline.py`'s five comparison strategies never touched
the optimizer at all, and a live capture into `data/events.jsonl` would have
been small, slow, and — since `data/` is gitignored — not reproducible from
git. The fix: a live UCB1 bandit now runs **inside** the same discrete-event
simulator the harness already uses, across many seeds and all four attack
scenarios, so the training data is real-component-driven and reproducible the
same way the 600-run comparison is (see `evaluation/baseline.py`'s own
docstring for that argument).

**The seam did not change.** Everything still routes through one protocol:

```python
class WeightOptimizer(Protocol):
    def active_weights(self) -> EdgeWeights: ...
    def observe(self, reward: float) -> None: ...
    def select(self) -> EdgeWeights: ...
```

The Random Forest is **not** a third implementation of it. It lands as a
**warm-start prior**: `UCB1WeightOptimizer.seed_values(values, pseudo_count)`
sets every arm's `value_i` and `count_i` from the model's prediction instead of
zero, so the very first `select()` of a run is informed by learned conditions
rather than blind. Real observations still overtake the prior at
`pseudo_count`'s weight via the same incremental-mean `observe()` as always.
`TrustState`/the controller are unchanged.

### Pipeline

```
evaluation/generate_optimizer_dataset.py   # cold UCB1, run inside the simulator
        -> data/optimizer_dataset.csv      # (conditions -> arm, reward) rows
trust_engine/rf_optimizer.py train         # RandomForestRegressor, joblib-persisted
        -> data/rf_optimizer.joblib
evaluation/rf_comparison.py                # zt_sdn_rf: zt_sdn's selector, RF-warm-
        -> results_rf.csv                  # started UCB1 weights, same seeds as the
                                            # other 5 strategies
evaluation/stats.py --system zt_sdn_rf     # same Wilcoxon + Holm-Bonferroni layer,
                                            # unmodified
```

Feature vector for both training and prediction: `[mean_trust, mean_load,
mean_latency_ms, num_quarantined, w1_trust, w2_cpu, w3_latency]` — conditions
plus the arm's own weight triple (not a bare arm index), so the model
generalises across different `arms` lists instead of memorising an opaque
label. `evaluation/rf_comparison.py` seeds the prior once per run from a fixed
"cold" snapshot (healthy fleet at t=0), because that is genuinely all the
system knows before a run starts; plain UCB1 (`observe`/`select`) drives
everything after that, identically to the online-only bandit.

### Measured result — does the learned prior beat static weights?

**No — and that is the honest, reportable finding**, not a bug to chase. 720
runs (6 strategies × 4 scenarios × 30 shared seeds, `config`: 8 nodes, 120s/run,
same paired Wilcoxon + Holm-Bonferroni layer as the 5-strategy comparison in
`docs/EVALUATION.md`) on `slo_violation_rate`:

| scenario | `zt_sdn_rf` vs `zt_sdn` | Δ (median) | verdict |
|---|---|---:|---|
| clean | ns (p_adj = 0.077) | −0.00% | no difference |
| sybil | **zt_sdn wins** (p_adj = 0.050) | −1.2% | RF-warm-started is worse |
| drop  | ns (p_adj = 0.177) | −1.1% | no difference |
| both  | **zt_sdn wins** (p_adj = 0.038) | −0.8% | RF-warm-started is worse |

(`zt_sdn_rf` does beat the four weak baselines — random, round_robin,
least_conn, no_trust — in 14/16 of those comparisons, same pattern as plain
`zt_sdn`: that win is the trust score + anomaly gate doing the work, not the
learned prior, exactly as it is for the static-weight system.)

Effect sizes on the two significant losses are medium (r ≈ −0.4) but the
absolute magnitude is under 1.2% relative — real, but small. The likely cause
is not the Random Forest being wrong: under p2c + ε selection the weight
arms barely differ in reward to begin with (`docs/LOAD_BALANCING_STARVATION.md`
§5's table — imbalance goes quiet, and even latency spread across the 5
presets is modest), so a policy that keeps re-selecting among near-equal arms
via UCB1 — warm-started or not — adds a little switching variance around
whatever a competent hand-tuned static point already sits at. That is a
property of running *any* multi-armed bandit in a low-arm-differentiation
regime, not specifically a Random Forest failure; it is consistent with the
"Known limitation" already documented below (UCB1 assumes stationary reward
and only visibly helps under stress).

**Reproduce:**
```
python3 -m evaluation.generate_optimizer_dataset --runs 60 --sim-s 120 --nodes 8 \
    --csv data/optimizer_dataset.csv
python3 -m trust_engine.rf_optimizer train data/optimizer_dataset.csv data/rf_optimizer.joblib
python3 -m evaluation.rf_comparison --model data/rf_optimizer.joblib --runs 30 \
    --sim-s 120 --nodes 8 --csv data/results_rf.csv
python3 -m evaluation.stats data/results_rf.csv --system zt_sdn_rf
```
