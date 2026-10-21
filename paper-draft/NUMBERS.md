# Number → artifact → command

Every measured figure in `paper.tex` and where it came from. Re-score with
`tools/regenerate.sh`, then `make`. All commands run from the **repository
root**.

## The experiment

Forty live runs, ~320 s each, five per arm, archived under
`data/runs/<arm>/rNN.jsonl` (gitignored; ~130 MB each): the three ablation arms
below, the θ-sweep arms `scoreonly_t040/_t045/_t050`, and the flood arms
`flood_off/flood_on`. Plus one replicated-ledger run with a leader kill,
archived in `data/raft_failover_2026-10-19/`.

| Arm | Directory | Enforcement |
|---|---|---|
| `base` (CONTROL) | `data/runs/base/` | none — static routing, detectors publish, nothing acts |
| `scoreonly` (ABLATION) | `data/runs/scoreonly/` | trust rail only (`trust.anomaly_rail_enforced: false`) |
| `treat` (BOTH RAILS) | `data/runs/treat/` | `T < θ` **or** `Ā ≥ g` |

Produced by `sudo tools/run_replicates.sh` (~100 min, unattended, rotating arm
order). The ablation config differs from the full config in exactly two keys,
pinned by `tests/test_scoreonly_arm.py`.

## Tables II–IV and VI — the ablation replicates

```bash
python3 -m evaluation.replicates data/runs --out-dir paper-draft/evidence/replicates
```
→ `evidence/replicates/summary.txt` · `per_run.csv` · `per_attacker.csv`

**Table II (the ablation).** `score_cross_s` / `min_trust` / `contain_s` per
attacker per arm. Headline: srv3 (Sybil) and srv8 (on-off) cross θ=0.30 in
**0/5 runs in every arm** (0/15 each), are quarantined **0/5** in `scoreonly`
and **5/5** in `treat`. srv6 (blackhole) and srv1 (grayhole) cross in 5/5
everywhere and are quarantined 5/5 in both acting arms.

**Table III (rails).** `rail` + `t_at_q` from `per_attacker.csv`:
srv3 gate 5/5 at T=0.710 [0.630, 0.791]; srv8 gate 5/5 at T=0.709 [0.641,
0.777]; srv6 score 4/5 + both 1/5 at T=0.130; srv1 both 3/5 + gate 2/5 at
T=0.220.

> **Attribution rule.** `evaluation.replicates.attribute_rail()` — one function,
> called by the scorer and by `tests/test_replicates.py::TestRailAttribution`.
> An arm that does not enforce the gate is always credited to the score,
> whatever Ā reads; when both conditions hold the answer is `both`, not `gate`.
> Reading Ā alone mislabelled all five `scoreonly` grayhole quarantines (they
> carry Ā ≈ 1.0 beside T < θ) — fixed 2026-09-29.

**Table IV (containment).** `contain_s` medians and ranges.
**Table 8 (service).** The `SERVICE AND FAIRNESS` block, means with 95% t-CIs.
**§VII-J (detection).** `attacks classified exactly` / `right family` /
`honest subjects mislabelled` / `classification accuracy` rows.

Statistical treatment: continuous → mean + two-sided 95% Student-t over runs;
yes/no → k/n + Wilson interval (5/5 = [57%,100%], 0/5 = [0%,43%]); times only
over runs where the event happened.

## §VII-K — non-functional requirements

```bash
for r in data/runs/treat/*.jsonl; do python3 -m evaluation.nfr_report "$r"; done
```
→ `evidence/nfr_replicates.txt`. Over the five enforced runs: routing decision
mean 0.54–0.55 ms (p95 0.71–0.73, max 4.4–8.6, n=6370–6742); isolation
re-dispatch mean 12.9–23.5 ms (max 32.8, n=19–30); ledger overhead
0.045–0.052 % over 625–661 blocks. Raft 4.3–4.8 ms is the **standalone**
3-replica cluster, not the controller.

## §VII-L — simulation (labelled as such in the paper)

```bash
python3 -m evaluation.baseline --runs 30 --csv paper-draft/evidence/baseline_600runs.csv
python3 -m evaluation.stats  paper-draft/evidence/baseline_600runs.csv [--metric M]
for n in 4 6 8 12; do python3 -m evaluation.baseline --runs 15 --nodes $n \
    --csv paper-draft/evidence/capacity_cliff/cliff_$n.csv; done
python3 -m evaluation.scalability_sweep --ns 4,8,16,32,64 \
    --load-factors 0.1,0.6 --seed 1 --csv paper-draft/evidence/scalability.csv
```
14/16 favour the system at p_adj = 7.45e-09, r = +1.00 — **the smallest value
the test can return at n=30**, which the paper says in those words. Two losses
in `clean`: −10.7 % vs round-robin, −4.8 % vs random. Scalability reads
`load_factor = 0.6` rows; the 10 %-load starvation figures (13/16 idle, Jain
0.176) read the `0.1` rows.

## §VIII-A — re-steer attribution

One pass over `data/runs/treat/*.jsonl` counting `report` events with
`charged: false`: **123 of 32,107 (0.38 %)**, per-run range 0.28–0.48 %.
The "2.86 of 4.0 s remaining, would have excused 0 of 26" counterfactual is
from earlier archived runs, recorded in `SOURCE_OF_TRUTH.md` §4.1.

## §VII-C — detection-to-quarantine gap

One pass over `data/runs/treat/*.jsonl` pairing each node's first `anomaly`
event with its first `quarantine`: 20 node-run pairs, **3.5–12.5 ms**.

## §VII-D — the threshold sweep (Table 5, Fig. 2)

```bash
python3 -m evaluation.replicates data/runs \
  --arms scoreonly,scoreonly_t040,scoreonly_t045,scoreonly_t050,treat \
  --out-dir paper-draft/evidence/theta_sweep
```
→ `evidence/theta_sweep/summary.txt`. Per attacker, `quarantined` +
`containment` rows: θ 0.45 srv3 5/5 median **26.2 s**, srv8 5/5 median **207.3 s**;
θ 0.50 srv3 5/5 **50.1 s**, srv8 5/5 **76.1 s**; θ 0.40 srv3 0/5, srv8 1/5
(**228.9 s**); treat srv3 **7.6 s**, srv8 **10.4 s**. Ratios 26.2/7.6 = **3.4×**,
207.3/10.4 = **20×**. `honest servers ever quarantined` 0.20 and
`attackers quarantined BEFORE onset` 0.20 at θ 0.50 (one run each). p95 rows:
175.6 / 172.5 / 157.2 / 148.5 / 137.2 ms.

Honest dips (`per_run.csv`, `honest_min_trust` < 0.45): scoreonly_t040 r02
**0.4199**, r03 **0.4171**; treat r05 **0.4208**. Attackers' floor while serving:
`min T after onset` 0.399–0.411 in the score-only arms at θ ≤ 0.40.

The prediction registered before the sweep: `data/theta_sweep_prediction_2026-09-29.txt`.

## §VII-I — data-plane response to a flooding client (Table 9)

`tools/regenerate.sh` scores `flood_off` r01–r05 and `flood_on` r02–r05 →
`evidence/flood/summary_primary.txt`. flood_on r01 is excluded because the host
suspended mid-run (`data/runs/manifest.csv`: recorded_s 24331; gaps of 891 s and
23092 s after t = 316 s). Rows `honest devices: mean latency` 105.0 → **91.7** ms,
`honest devices: p95 latency` 177.7 → **139.4** ms, `honest devices: task
success` 98.91 vs 98.79 % (overlap), `tasks served to flooding device(s)` 8951 →
**292.8**, `honest devices ever throttled` 0. Check with r01 truncated to its
first 316 s: honest mean **93.0** ms, p95 **141.3** ms (scored 2026-10-18, recorded
in `data/flood_experiment_2026-10-18/summary_trimmed_on_r01.txt`).

## §VII-K — replicated ledger with a leader kill

`evidence/raft/failover_report.json` (written by `tools/raft_failover_check.py`
during the run) + `data/raft_failover_2026-10-19/events_raft.jsonl`: leader n3
SIGKILLed after 61 blocks; new leader n1 after **0.47 s** (term 2 → 4);
submitted **649** = committed **649**, retries 1, dropped 0; restarted n3 caught
up in **1.0 s**. From the recording's `block` events: blocks 1–649 contiguous,
every `previous_hash` links, terms {2: 61, 4: 588}, commit ms mean **14.06**,
p95 **20.24**, max **143.6**. `evidence/raft/nfr_report.txt`: routing p95 **0.77 ms**.

## §V-B — why the analytic bound is conservative

Predicted floor `α + β(1 − ℓ/500) − δ` computed per run from srv3's measured
mean success latency: **0.302 mean, range 0.278–0.328** over the ten
non-enforcing runs, against a measured minimum of **0.399–0.409**. The bound
held everywhere and held loosely. The gap is the honesty term: srv3's
|claimed − observed| load gap averaged **0.084**, so h = 1 − gap/0.5 averaged
**0.83** and γH̄ contributed ≈ +0.10 throughout.

"The lie did not attract traffic" (added 2026-10-19): the `route share
(post-onset)` lines of `evidence/replicates/summary.txt`, PER ATTACKER block
(`per_attacker.csv` columns `route_share`, `excess_share`). Each value is the
share of all `route` events at or after the attacker's onset that chose it,
with probation trials counted the way `base_model/compare.py` counts routes.
Fair share = 1/8 = 12.5 %.

| Attacker | base | scoreonly | treat |
|---|---|---|---|
| srv3 load-misreporting | **9.22 %** [8.75, 9.69] | **1.98 %** [1.59, 2.36] | **0.45 %** [0.21, 0.69] |
| srv8 on-off | 9.72 % [9.34, 10.10] | **9.53 %** [8.97, 10.08] | **5.04 %** [4.20, 5.89] |

Why: at about 1 % occupancy honest agents report `cpu_load` ≈ 0
(active/concurrency), so srv3's fixed claim of 0.10 ranks below them, and its
slowness lowers T (EdgeScore w1 = 0.5 on T).

## §VII-E and Table 6 — the liar experiment (added 2026-10-20)

80 live runs in four batches. Each was scored against a prediction file
committed before it ran (`evidence/liar/*.txt`), with the outcome written up
in `evidence/liar/*_OUTCOME.md`. Scores are in `evidence/liar/<batch>/summary.txt`,
PER ATTACKER block, lines `route share (post-onset)`, `minus fair 1/N`,
`quarantined` and `containment`.

| Table 6 row | Arm (batch) | Share | Excess | Quar. | Median |
|---|---|---|---|---|---|
| Consistent, raw, shipped | `liar_c_treat` (1) | 9.37 [9.05, 9.68] | −3.13 | 5/5 | 8.2 s |
| Consistent, raw, fix 1+3 | `liarfix3_c_treat` (3) | 10.29 [9.99, 10.60] | −2.21 | 5/5 | 6.4 s |
| Adaptive, raw, fix 1 | `liarfix_stealthy` (2) | 11.34 [10.97, 11.71] | −1.16 | 5/5 | 17.7 s |
| Split claim, raw, shipped | `liar_t_treat` (1) | 17.01 [16.16, 17.86] | +4.51 | 4/5 | 51.7 s |
| **Split claim, raw, fix 1** | `liarfix_t_treat` (2) | **16.50 [15.97, 17.02]** | **+4.00 [3.47, 4.52]** | **0/5** | — |
| Split claim, verified, fix 1 | `liarfix_t_verified` (2) | 12.51 [12.22, 12.80] | +0.01 [−0.28, +0.30] | 3/5 (isolated 0.34%) | — |
| Consistent at 1%, raw | `ship_c_raw` (4) | 10.14 [8.92, 11.36] | −2.36 | 0/5 | — |
| Consistent at 1%, verified | `ship_c_verified` (4) | 13.58 [11.97, 15.19] | +1.08 [−0.53, +2.69] | 0/5 | — |

- **Honest latency:** 397.5 (`liarfix_t_treat`), 396.4 (`liarfix_honest`) and
  396.2 ms (`liarfix_t_verified`), from the `honest devices: mean latency` lines.
- **Honest false quarantines per run**, from the `honest servers ever
  quarantined` lines: 3.4 (`liar_honest`) → 1.4 (`liarfix_honest`) → 0.2
  (`liarfix3_honest`); verified 2.0 → 0.0.
- **The defect evidence** (119 firings, expected duty 0.81 vs 0.30, quiet a
  median of 2.0 s) is rebuilt in `evidence/liar/liar_2026-10-19_OUTCOME.md`.
  The rebuild script is in that file's history; the inputs are the batch-1
  recordings.
- **Model:** `python3 -m evaluation.liar_sweep --seeds 5`. The p2c+ε ceiling
  24.4% is `share_ceiling()`.
- **Synthetic drop-tell observation** (5/20 vs 1/20 seeds) is in
  `evidence/liar/ship_verified_2026-10-20_OUTCOME.md`.
- **§VII-G offline witness (0.9992, 110 recordings):**
  `evidence/witness/summary.txt`, from `evaluation.witness_offline` over the
  22 arms listed in `tools/regenerate.sh` (later arms change it).

## §VI-F and §VII-F — honest-slow servers (added 2026-10-21)

30 live runs at `d1076c4`, scored against `evidence/hw/hw_2026-10-20.txt`;
outcome in `evidence/hw/hw_2026-10-20_OUTCOME.md`.

```bash
python3 -m evaluation.replicates data/runs \
    --arms hw_fleet,hw_class,hw_throttle25,hw_throttle10,hw_sybil_slow,hw_sybil_fast \
    --out-dir paper-draft/evidence/hw
```

- **0 honest quarantines** in `hw_fleet`, `hw_class`, `hw_throttle25` (5/5 runs
  each): `honest servers ever quarantined` and `honest quarantine seconds`.
- **`hw_throttle10`: 1/5 runs, 3.6 s** total (`throttled quarantines`,
  `honest quarantine seconds`). Path: one `/status` poll over 0.5 s
  (unreachable, no persistence), then the honesty check inverted (claimed 0.59
  vs expected 0.00). Latency tell never fired. Task latency ~90 → 210–223 ms.
  All in the OUTCOME file.
- **Sybil:** contained 5/5 in `hw_sybil_slow` (median 9.0 s) and
  `hw_sybil_fast` (8.4 s), PER ATTACKER `containment`.

## §VII-G and Table 7 — the switch witness, live (added 2026-10-21)

Two batches of 25 runs: `wit_*` at `0c8d064` and `witfix_*` at `15728ac`, each
against its own prediction (`evidence/witness/<batch>/*.txt`, outcome in
`*_OUTCOME.md`).

```bash
python3 -m evaluation.witness_report data/runs \
    --arms wit_control,wit_drop,wit_switch_hide,wit_badmouth,wit_collude
python3 -m evaluation.witness_report data/runs \
    --arms witfix_control,witfix_drop,witfix_switch_hide,witfix_badmouth,witfix_collude
```
→ `evidence/witness/{batch1,after_fixes}/witness_summary.txt`.

| Table 7 row | First batch | After fixes |
|---|---|---|
| Nobody | 0 blamed, 5/5 | 0 blamed, 5/5 |
| srv6 blackhole, srv1 grayhole | 4/5 (53.9 s), 5/5 (61.2 s) | 5/5 (12.9 s), 5/5 (14.1 s) |
| Hiding switch dpid 4 | 5/5 (14.1 s); clients in 3/5, 1.0–4.1 s | 5/5 (5.2 s) |
| iot3, iot12 badmouthing | 5/5 (14.1 s), 5/5 (13.1 s) | 5/5 (12.0 s) each |
| srv6 + covering switch | srv6 5/5 (59.2 s); switch 0/5 | srv6 5/5 (16.2 s); switch 0/5 |
| Honest parties blamed | 3 of 25 runs | 0 of 25 runs |

The fix-pinning tests are `tests/test_switch_witness.py` (the `_staggered`
fleet); each fails with its fix turned off.

## §VIII-B — the retraction

`CONTAINMENT vs ATTRIBUTION` block of `summary.txt`: ten acting runs,
containment 40.0–69.3 %, exact labels 7/8 in nine runs and 6/8 in one,
**Spearman ρ = −0.522, p = 0.122, n = 10**. Not supported; claim withdrawn.

## Test suite

```bash
python3 -m pytest tests/ base_model/tests/ -q
```
**1,320 passed, 11 skipped** on `feature/witness` (2026-10-21).

## Figures

| Figure | File | Built by |
|---|---|---|
| 1 two rails | drawn in `paper.tex` (TikZ) | — |
| 2 time to isolation vs θ | drawn in `paper.tex` (pgfplots), values from `evidence/theta_sweep/summary.txt` | — |

Both figures are drawn in LaTeX, so they hold no numbers of their own beyond the
four medians and two gate times plotted in Fig. 2, each listed above.

> The per-server trust and load-share figures used by the previous draft were
> generated from two single runs that the replicate campaign superseded. They
> are **not** used here. Regenerating them from `data/runs/` is an open item
> (`CHECKLIST.md`).

## References

Authors are given as **initials** — IEEE style, and it removes the risk of a
fabricated expansion (an earlier draft guessed full first names). Verified
against publisher records on 2026-09-29: `ali2023ztmec` (B. Ali, M. A. Gregory,
S. Li), `tren2025smartcity` (A. Iftikhar, F. B. Hussain, K. N. Qureshi,
M. Shiraz, M. Sookhak), `huang2024trustmultitier` (TDSC 21(4) 1639–1651),
`mitzenmacher2001p2c` (TPDS 12(10) 1094–1104), `dahlin2000stale` (TPDS 11(10)
1033–1047). The rest carry metadata from the project's earlier list and are
flagged in `CHECKLIST.md` as not independently re-verified this session.

Revision 3 additions were checked by web search on 2026-10-14..19; the list and
what was confirmed for each is in the header comment of `references.bib`.
