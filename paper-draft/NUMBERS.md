# Number → artifact → command

Every measured figure in `paper.tex` and where it came from. Re-score with
`tools/regenerate.sh`, then `make`. All commands run from the **repository
root**.

## The experiment

Fifteen live runs, ~320 s each, three arms × five runs, archived under
`data/runs/<arm>/rNN.jsonl` (gitignored; ~130 MB each).

| Arm | Directory | Enforcement |
|---|---|---|
| `base` (CONTROL) | `data/runs/base/` | none — static routing, detectors publish, nothing acts |
| `scoreonly` (ABLATION) | `data/runs/scoreonly/` | trust rail only (`trust.anomaly_rail_enforced: false`) |
| `treat` (BOTH RAILS) | `data/runs/treat/` | `T < θ` **or** `Ā ≥ g` |

Produced by `sudo tools/run_replicates.sh` (~100 min, unattended, rotating arm
order). The ablation config differs from the full config in exactly two keys,
pinned by `tests/test_scoreonly_arm.py`.

## Tables II–VI — everything from the replicates

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
**Table V (service).** The `SERVICE AND FAIRNESS` block, means with 95% t-CIs.
**§VII-E (detection).** `attacks classified exactly` / `right family` /
`honest subjects mislabelled` / `classification accuracy` rows.

Statistical treatment: continuous → mean + two-sided 95% Student-t over runs;
yes/no → k/n + Wilson interval (5/5 = [57%,100%], 0/5 = [0%,43%]); times only
over runs where the event happened.

## §VII-F — non-functional requirements

```bash
for r in data/runs/treat/*.jsonl; do python3 -m evaluation.nfr_report "$r"; done
```
→ `evidence/nfr_replicates.txt`. Over the five enforced runs: routing decision
mean 0.54–0.55 ms (p95 0.71–0.73, max 4.4–8.6, n=6370–6742); isolation
re-dispatch mean 12.9–23.5 ms (max 32.8, n=19–30); ledger overhead
0.045–0.052 % over 625–661 blocks. Raft 4.3–4.8 ms is the **standalone**
3-replica cluster, not the controller.

## §VII-G — simulation (labelled as such in the paper)

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

## §VII-D — detection-to-quarantine gap

One pass over `data/runs/treat/*.jsonl` pairing each node's first `anomaly`
event with its first `quarantine`: 20 node-run pairs, **3.5–12.5 ms**.

## §V-B — why the analytic bound is conservative

Predicted floor `α + β(1 − ℓ/500) − δ` computed per run from srv3's measured
mean success latency: **0.302 mean, range 0.278–0.328** over the ten
non-enforcing runs, against a measured minimum of **0.399–0.409**. The bound
held everywhere and held loosely. The gap is the honesty term: srv3's
|claimed − observed| load gap averaged **0.084**, so h = 1 − gap/0.5 averaged
**0.83** and γH̄ contributed ≈ +0.10 throughout.

## §VIII-B — the retraction

`CONTAINMENT vs ATTRIBUTION` block of `summary.txt`: ten acting runs,
containment 40.0–69.3 %, exact labels 7/8 in nine runs and 6/8 in one,
**Spearman ρ = −0.522, p = 0.122, n = 10**. Not supported; claim withdrawn.

## Test suite

```bash
python3 -m pytest tests/ -q
```

## Figures

| Figure | File | Built by |
|---|---|---|
| 1 two rails | `../ppt/figures/fig6_zero_trust_flow.png` | `ppt/fig_flows.py` |
| 2 Raft failover | `../data/figures/raft_failover.png` | `evaluation/plot_raft_timeline.py` |

Referenced at source via `\graphicspath`; nothing is copied into `paper-draft/`.

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
