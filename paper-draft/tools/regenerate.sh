#!/usr/bin/env bash
# Re-score every measured number in the paper. Run from anywhere.
#
# Writes into paper-draft/evidence/ ONLY. Never touches ../data/, which holds
# the raw recordings and the project's own scoring output.
#
# This does NOT re-run the live experiments -- those need root, Open vSwitch
# and Mininet (about 6 minutes per run):
#     sudo ARMS="base scoreonly treat" tools/run_replicates.sh
#     sudo ARMS="scoreonly_t040 scoreonly_t045 scoreonly_t050" tools/run_replicates.sh
#     sudo ARMS="flood_off flood_on" tools/run_replicates.sh
# It re-scores the 40 recordings those runs archived under data/runs/, and
# copies the replicated-ledger failover evidence from
# data/raft_failover_2026-10-19/.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/paper-draft/evidence"
cd "$ROOT"

[ -d data/runs ] || { echo "MISSING: data/runs -- see paper-draft/README.md"; exit 1; }
mkdir -p "$OUT/replicates" "$OUT/capacity_cliff" "$OUT/theta_sweep" "$OUT/flood" "$OUT/raft"

echo "== live ablation: Tables II-IV and VI =="
python3 -m evaluation.replicates data/runs --arms base,scoreonly,treat \
        --out-dir "$OUT/replicates"

echo "== live threshold sweep: Table 5, Fig. 2 =="
python3 -m evaluation.replicates data/runs \
        --arms scoreonly,scoreonly_t040,scoreonly_t045,scoreonly_t050,treat \
        --out-dir "$OUT/theta_sweep"

echo "== live flood experiment: Table VII =="
# flood_on r01 is excluded: the host suspended mid-run (recorded span 24331 s,
# gaps of 891 s and 23092 s after t=316 s). Score the other nine through links.
FL="$(mktemp -d)"; trap 'rm -rf "$FL"' EXIT
mkdir -p "$FL/flood_off" "$FL/flood_on"
for r in data/runs/flood_off/r0[1-5].jsonl; do ln -s "$ROOT/$r" "$FL/flood_off/"; done
for r in data/runs/flood_on/r0[2-5].jsonl; do ln -s "$ROOT/$r" "$FL/flood_on/"; done
python3 -m evaluation.replicates "$FL" --arms flood_off,flood_on --out-dir "$OUT/flood"
mv "$OUT/flood/summary.txt" "$OUT/flood/summary_primary.txt"

echo "== liar experiment, four batches: Table 6 (S VII-E) =="
mkdir -p "$OUT/liar/batch1" "$OUT/liar/batch2" "$OUT/liar/batch3" "$OUT/liar/shipped_load"
python3 -m evaluation.replicates data/runs \
        --arms liar_honest,liar_c_treat,liar_t_treat,liar_t_treat_slots,stealthy_treat \
        --out-dir "$OUT/liar/batch1"
python3 -m evaluation.replicates data/runs \
        --arms liarfix_honest,liarfix_c_treat,liarfix_t_treat,liarfix_stealthy,liarfix_t_verified,liarfix_honest_verified \
        --out-dir "$OUT/liar/batch2"
python3 -m evaluation.replicates data/runs \
        --arms liarfix3_honest,liarfix3_honest_verified,liarfix3_c_treat --out-dir "$OUT/liar/batch3"
python3 -m evaluation.replicates data/runs --arms ship_c_raw,ship_c_verified \
        --out-dir "$OUT/liar/shipped_load"
cp -p docs/predictions/*.txt docs/predictions/*.md "$OUT/liar/" 2>/dev/null || true
rm -f "$OUT"/liar/*_live_summary.txt

echo "== switch witness, offline (S X) =="
mkdir -p "$OUT/witness"
python3 -m evaluation.witness_offline data/runs --out "$OUT/witness" >/dev/null
rm -f "$OUT/witness/per_server.csv"

echo "== replicated ledger with a leader kill (S VII-I) =="
RF=data/raft_failover_2026-10-19
cp -p "$RF/raft_failover_20261019_140900.json" "$OUT/raft/failover_report.json"
cp -p "$RF/nfr_report.txt" "$OUT/raft/nfr_report.txt"

echo "== NFRs across the enforced runs =="
: > "$OUT/nfr_replicates.txt"
for r in data/runs/treat/*.jsonl; do
  echo "### $r" >> "$OUT/nfr_replicates.txt"
  python3 -m evaluation.nfr_report "$r" >> "$OUT/nfr_replicates.txt" 2>&1
done

echo "== simulation: 600-run baseline comparison =="
python3 -m evaluation.baseline --runs 30 --csv "$OUT/baseline_600runs.csv"
python3 -m evaluation.stats "$OUT/baseline_600runs.csv" \
        --metric slo_violation_rate > "$OUT/stats_slo.txt"
python3 -m evaluation.stats "$OUT/baseline_600runs.csv" \
        --metric failure_rate      > "$OUT/stats_failure.txt"
python3 -m evaluation.stats "$OUT/baseline_600runs.csv" \
        --metric malicious_share   > "$OUT/stats_malshare.txt"

echo "== simulation: capacity cliff =="
for n in 4 6 8 12; do
  python3 -m evaluation.baseline --runs 15 --nodes "$n" \
          --csv "$OUT/capacity_cliff/cliff_$n.csv" > /dev/null
done

echo "== simulation: selector scalability =="
python3 -m evaluation.scalability_sweep --ns 4,8,16,32,64 \
        --load-factors 0.1,0.6 --seed 1 --csv "$OUT/scalability.csv" \
        > "$OUT/scalability_sweep.txt"

echo
echo "Done. Rebuild the paper:  cd paper-draft && make"
