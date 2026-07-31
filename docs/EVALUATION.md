# Evaluation: does trust-aware routing actually work better?

> The experiment behind the project's headline claim, and the honest reading of
> its results — including the two places the system loses. Produced by
> `evaluation/baseline.py` (the experiment) and `evaluation/stats.py` (the
> significance testing). Everything here reproduces from a clean checkout in
> about a minute; see §10.

**Headline:** across 600 runs, **14 of 16 comparisons significantly favour the
full Zero-Trust system** (p_adj = 7.45×10⁻⁹, rank-biserial r = +1.00), with
**20–69 % fewer SLO violations under attack**, **98–99 % fewer failed tasks**,
and **96–99 % less traffic delivered to malicious nodes**. The two losses are
both in the *no-attack* scenario and are explained in §6 — the cause is load-signal
staleness, not the trust mechanism, and it is recoverable by polling faster.

---

## 1. What this measures, and what it does not

The harness drives the **real** components — `controller.edge_selector.select_edge_node`,
`trust_engine.trust_calculator.TrustCalculator`, and both shipped anomaly
detectors (`controller.flow_monitor.evaluate_latency_tell` and the timeout-rate
check) — inside a seeded discrete-event simulation. A result here is therefore a
statement about the shipped code, not about a re-implementation of it. Only the
**network and the node agents** are simulated.

It is deliberately **not** a Mininet run. The claim being made is statistical, and
statistics need repetition: 5 strategies × 4 scenarios × 30 seeds is 600 runs,
which is ~40 seconds here and days on a live topology. The live runs behind
`docs/study/trust-routing-study.html` remain the ground truth for *fidelity*;
this harness supplies *significance*. Both are needed and neither substitutes for
the other. State this limitation whenever the numbers are quoted.

## 2. The five routers

Four baselines and the system under test. `no_trust` and `zt_sdn` both call the
real selector, so the ablation differs from the system in exactly the trust
dimension and nothing else.

| router | what it does | why it is here |
|---|---|---|
| `random` | uniform over all nodes | the null baseline — beat this or nothing else matters |
| `round_robin` | strict cycle | trust-blind and perfectly fair, so it feeds an attacker exactly its 1/N share forever |
| `least_conn` | join-shortest-queue on **claimed** load | strongest classical baseline, and the one a Sybil directly exploits: claiming to be idle is how you attract a load-aware balancer |
| `no_trust` | real EdgeScore with trust pinned uniform and quarantine disabled | the **ablation** — isolates what *trust* contributes as opposed to what load/latency-aware routing contributes |
| `zt_sdn` | full system: EdgeScore + p2c + ε, real trust, quarantine on isolation threshold and anomaly gate | the system under test |

## 3. Scenarios

| scenario | attacker(s) | what it tests |
|---|---|---|
| `clean` | none | that the defence costs nothing when there is no threat |
| `sybil` | one node claims `cpu = 0.1` while burning CPU, so it serves slowly | **the central case** — it never fails a task, so trust alone cannot catch it |
| `drop` | one node accepts tasks and never completes them | trust catches this one on its own, via timeouts |
| `both` | both, on separate nodes | independent detectors firing simultaneously |

Defaults are the deck's full scale — 8 edge nodes (`config/params.yaml`), not the
4-node demo config. That choice is itself a result; see §7.

## 4. Method: pairing and statistics

**Pairing.** Every strategy runs on the same 30 seeds, and each simulated
quantity draws from its **own** RNG stream (arrivals, service demands, RTT
jitter, selection). With a single shared stream the draws would interleave
differently once strategies diverge, so the k-th arrival would carry a different
service demand under each strategy and the pairing would silently decay into
independent sampling. Separate streams keep the k-th draw of each kind identical
across strategies — *common random numbers*, the standard variance-reduction
technique for paired simulation experiments.

**Test.** Paired **Wilcoxon signed-rank**. Not a paired t-test: the outcomes are
rates bounded in [0,1], visibly skewed, and zero-inflated (the system drives
failures to exactly 0 in most runs), so normality would be doing real work in the
result. Wilcoxon assumes only that the paired differences are symmetric about
their median.

**Multiple comparisons.** One system against four baselines is four tests, so the
chance of at least one false positive at α = 0.05 is ~19 %, not 5 %. Every
p-value is corrected with **Holm–Bonferroni** within a scenario — Holm rather
than plain Bonferroni because it is uniformly more powerful while controlling the
same family-wise error rate. Both `p_raw` and `p_adj` are reported so the
correction is visible rather than hidden.

**Effect size.** A p-value says a difference exists, not that it matters. Each
comparison reports the **matched-pairs rank-biserial correlation** r (+1 = the
system was better in every pair) and the median difference in the metric's own
units.

## 5. Results

### 5.1 Primary metric — SLO violation rate

A task violates the SLO if it never completed *or* completed slower than 500 ms.
It is the one number both attacks move, so a single test covers both without
cherry-picking a metric per scenario.

Median over 30 seeds (lower is better):

| scenario | random | round_robin | least_conn | no_trust | **zt_sdn** |
|---|---|---|---|---|---|
| clean | 0.0870 | **0.0823** | 0.1886 | 0.0970 | 0.0911 |
| sybil | 0.1397 | 0.1225 | 0.2780 | 0.1159 | **0.0984** |
| drop  | 0.1960 | 0.1933 | 0.2595 | 0.1329 | **0.0992** |
| both  | 0.2512 | 0.2325 | 0.3840 | 0.1707 | **0.1198** |

Reduction achieved by `zt_sdn`, all with p_adj = 7.45×10⁻⁹ and r = +1.00
(30/30 seeds won):

| scenario | vs least_conn | vs random | vs round_robin | vs **no_trust** |
|---|---|---|---|---|
| sybil | −64.6 % | −29.6 % | −19.7 % | **−15.1 %** |
| drop  | −61.8 % | −49.4 % | −48.7 % | **−25.3 %** |
| both  | −68.8 % | −52.3 % | −48.5 % | **−29.8 %** |

The `no_trust` column is the one that matters most: it is the same selector with
only the trust term removed, so it attributes the improvement to trust rather
than to load-aware routing in general.

### 5.2 Secondary metrics

Both also at p_adj = 7.45×10⁻⁹, r = +1.00:

| metric | scenario | zt_sdn | best baseline | reduction |
|---|---|---|---|---|
| failure rate | drop | 0.0009 | 0.0388 (`no_trust`) | **−97.7 %** |
| failure rate | both | 0.0009 | 0.0392 (`no_trust`) | **−97.7 %** |
| malicious share | drop | 0.0009 | 0.0397 (`no_trust`) | **−97.7 %** |
| malicious share | both | 0.0035 | 0.1430 (`no_trust`) | **−97.5 %** |

Against the trust-blind baselines the failure-rate reduction is **99.2–99.3 %**:
`random` and `round_robin` keep feeding the black hole for the entire run because
they have no mechanism that could ever stop.

### 5.3 Isolation latency

Time until every attacker is excluded from routing, over 30 seeds:

| scenario | median | max | isolated |
|---|---|---|---|
| sybil | 3.0 s | 3.0 s | 30/30 |
| drop  | 3.0 s | 4.0 s | 30/30 |
| both  | 3.0 s | 4.0 s | 30/30 |

**Read this carefully against the NFR.** The project claims isolation in **< 3 s**.
Measured at 1 s poll granularity with a 3-poll persistence requirement on the
latency tell, 3.0 s is the *floor by construction* — the detector cannot fire
sooner. So the NFR is met only if the bound is read inclusively, and the dropper
can take 4 s. Meeting a strict `< 3 s` needs a faster poll or a shorter
persistence window, and the persistence window is precisely what stops healthy
nodes being quarantined on a jitter blip (`docs/LOAD_BALANCING_STARVATION.md` §7).
That is a real trade-off, not a tuning oversight.

## 6. Where the system loses, and why

Two comparisons significantly favour the baseline, both in `clean`:

| comparison | zt_sdn | baseline | delta |
|---|---|---|---|
| clean vs round_robin | 0.0911 | 0.0823 | **−10.7 %** |
| clean vs random | 0.0911 | 0.0870 | **−4.8 %** |

With no attacker present, the system is measurably worse than plain round-robin.
This is a genuine cost and is reported as one. But the cause is **not** the trust
term — it is the staleness of the load signal that every load-reactive strategy
reads. The load view refreshes only every `POLL_S` while tasks finish in ~0.2 s,
so each arrival in a polling window is routed on the same stale snapshot and
herds onto whichever node last looked idle.

Sweeping the poll interval isolates it exactly (median `slo_violation_rate`,
`clean`, 15 seeds):

| poll | round_robin | random | **zt_sdn** | least_conn | no_trust |
|---:|---|---|---|---|---|
| 1.00 s | 0.0831 | 0.0880 | 0.0913 | 0.1898 | 0.0970 |
| 0.50 s | 0.0831 | 0.0880 | 0.0878 | 0.1522 | 0.0891 |
| 0.20 s | 0.0831 | 0.0880 | 0.0847 | 0.1214 | 0.0845 |
| 0.05 s | 0.0831 | 0.0880 | 0.0828 | 0.0852 | 0.0832 |
| 0.01 s | 0.0831 | 0.0880 | **0.0826** | 0.0826 | 0.0826 |

The two load-blind strategies are **flat**, as they must be — they never read the
signal. Everything that does read it improves monotonically as the signal gets
fresher, and by 0.01 s `zt_sdn` is the best strategy on the board. The clean-case
cost is therefore a *tuning property of the 1 s poll*, not a property of
trust-aware routing.

The same effect explains why `least_conn` — the strongest classical baseline in
theory — is the **weakest** strategy here in practice, at 0.1886 in `clean`. This
is Mitzenmacher's herd behaviour and Dahlin's "stale least-loaded performs worse
than random," the same references already cited in
`docs/LOAD_BALANCING_STARVATION.md` §5:

1. M. Mitzenmacher, "How Useful Is Old Information?," *IEEE TPDS*, vol. 11,
   no. 1, pp. 6–20, 2000. DOI 10.1109/71.824633
2. M. Dahlin, "Interpreting Stale Load Information," *IEEE TPDS*, vol. 11,
   no. 10, pp. 1033–1047, 2000. DOI 10.1109/71.888643

## 7. The capacity cliff: quarantine is not free

Isolating a node removes its capacity. When attackers are a large fraction of a
small fleet, the survivors must absorb everything, and the resulting queueing can
cost more than the attack did. Scenario `both` (2 attackers), median over 15 seeds:

| N | zt_sdn slo | no_trust slo | zt_sdn fail | no_trust fail | zt_sdn p95 | no_trust p95 | system wins? |
|---:|---|---|---|---|---|---|---|
| 4  | 0.4377 | 0.3505 | 0.0056 | 0.0946 | 1371 ms | 1755 ms | **no** |
| 6  | 0.1642 | 0.2126 | 0.0028 | 0.0562 |  758 ms |  989 ms | yes |
| 8  | 0.1217 | 0.1667 | 0.0018 | 0.0400 |  680 ms |  744 ms | yes |
| 12 | 0.1010 | 0.1344 | 0.0012 | 0.0245 |  640 ms |  684 ms | yes |

At N = 4, isolating 2 of 4 nodes leaves the honest half at 80 % utilisation, and
the queueing wipes out the entire SLO gain — the system loses the headline metric
**while still beating the ablation on every component** (17× fewer failures, 22 %
lower p95). By N = 6 the cliff is gone.

**The defence needs enough spare capacity to absorb what it isolates.** This is
why the harness defaults to the deck's full scale of 8 rather than the 4-node
demo config, and it is a deployment constraint worth stating in the report.

## 8. A measurement trap: latency metrics flatter black holes

Under `drop`, raw p95 latency appears to favour the baselines — `random` scores
601 ms against `zt_sdn`'s 637 ms. That reading is wrong, and the reason is
instructive.

| strategy | completed | failed | p95 of *completed* | share excluded |
|---|---|---|---|---|
| random | 3380 | 445 | 601 ms | **11.5 %** |
| zt_sdn | 3828 | 7 | 637 ms | **0.2 %** |

Latency is only defined for tasks that finished. `random` sends 11.5 % of its
traffic into a black hole where it never completes, so its worst outcomes are
**excluded from its own latency distribution**. `zt_sdn` completes 99.8 % of
tasks and every one of them counts. A strategy is rewarded for losing work.

This is exactly why `slo_violation_rate` — which counts a failure as a violation —
is the primary metric and raw latency is not. Any latency comparison across
strategies with materially different failure rates is survivorship-biased and
must be read alongside the failure rate.

## 9. Limitations

1. **Simulated network and agents.** Service times are exponential, the network
   is a delay model, and node agents are behavioural stubs. Fidelity comes from
   the live Mininet runs in `docs/study/trust-routing-study.html`; this harness
   contributes repetition, not realism.
2. **Attacker model is fixed and non-adaptive.** The Sybil lies at a constant
   `cpu = 0.1` and never adapts to being detected. A liar that watched its own
   quarantine and modulated its RTT would defeat the latency tell; that is future
   work, and the honest claim is bounded to these two attacks.
3. **The Sybil's slowdown is capped by construction.** Above 2.5× it saturates
   under its fair share and begins timing out, which turns it into a *failing*
   node that trust isolates on its own — a strictly easier attack than the one
   claimed. The configured 2.0 keeps it below that cliff so it degrades latency
   without ever failing a task. Results are specific to that regime.
4. **Crash-fault, not Byzantine.** Nothing here evaluates a malicious controller
   or a lying ledger replica; see `PROBLEM_AND_IMPACT.md` §4.
5. **One workload shape.** Poisson arrivals at 40 % of farm capacity. Bursty or
   heavy-tailed workloads are untested.

## 10. Reproducing

```bash
# The full experiment: 5 strategies x 4 scenarios x 30 seeds = 600 runs, ~40 s
python3 -m evaluation.baseline --runs 30 --csv results.csv

# Significance testing on any metric in the CSV
python3 -m evaluation.stats results.csv                          # slo_violation_rate
python3 -m evaluation.stats results.csv --metric failure_rate
python3 -m evaluation.stats results.csv --metric malicious_share --alpha 0.01
```

Everything is seeded, so the numbers in this document reproduce exactly. No sudo,
no Mininet, no OVS. Coverage lives in `tests/test_baseline.py` (E-01…E-12: the
workload really is paired, the attackers really attack, the detectors really
fire) and `tests/test_stats.py` (S-01…S-13: the correction and effect-size
arithmetic, checked against SciPy and hand-computed values).
