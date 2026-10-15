#!/usr/bin/env bash
# Re-score every measured number in the paper. Run from anywhere.
#
# Writes into paper-draft/evidence/ ONLY. Never touches ../data/, which holds
# the raw recordings and the project's own scoring output.
#
# This does NOT re-run the live experiments -- those need root, Open vSwitch
# and Mininet, and about 100 minutes:
#     sudo tools/run_replicates.sh
# It re-scores the 15 recordings that run already archived.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/paper-draft/evidence"
cd "$ROOT"

[ -d data/runs ] || { echo "MISSING: data/runs -- see paper-draft/README.md"; exit 1; }
mkdir -p "$OUT/replicates" "$OUT/capacity_cliff"

echo "== live replicates: Tables II-VI (the paper's core) =="
python3 -m evaluation.replicates data/runs --out-dir "$OUT/replicates"

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
