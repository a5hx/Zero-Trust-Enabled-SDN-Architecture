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

echo "== live flood experiment: Table 12 (S VII-L) =="
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
cp -p docs/predictions/liar*.txt docs/predictions/liar*.md docs/predictions/ship_verified* \
      "$OUT/liar/" 2>/dev/null || true
rm -f "$OUT"/liar/*_live_summary.txt

echo "== switch witness, offline (S VII-G) =="
# The 110 recordings that existed when it was scored; later arms would change it.
mkdir -p "$OUT/witness"
python3 -m evaluation.witness_offline data/runs --out "$OUT/witness" \
        --arms base,flood_off,flood_on,scoreonly,scoreonly_t040,scoreonly_t045,scoreonly_t050,treat,liar_c_treat,liar_honest,liar_t_treat,liar_t_treat_slots,stealthy_treat,liarfix_c_treat,liarfix_honest,liarfix_honest_verified,liarfix_stealthy,liarfix_t_treat,liarfix_t_verified,liarfix3_c_treat,liarfix3_honest,liarfix3_honest_verified \
        >/dev/null
rm -f "$OUT/witness/per_server.csv"

echo "== honest-slow servers (S VII-F) =="
mkdir -p "$OUT/hw"
python3 -m evaluation.replicates data/runs \
        --arms hw_fleet,hw_class,hw_throttle25,hw_throttle10,hw_sybil_slow,hw_sybil_fast \
        --out-dir "$OUT/hw"
cp -p docs/predictions/hw_2026-10-20.txt docs/predictions/hw_2026-10-20_OUTCOME.md "$OUT/hw/"

echo "== switch witness, live: Table 7 (S VII-G) =="
for b in "batch1 wit witness" "after_fixes witfix witfix"; do
  set -- $b
  mkdir -p "$OUT/witness/$1"
  ARMS="$2_control,$2_drop,$2_switch_hide,$2_badmouth,$2_collude"
  python3 -m evaluation.replicates data/runs --arms "$ARMS" --out-dir "$OUT/witness/$1"
  python3 -m evaluation.witness_report data/runs --arms "$ARMS" \
          --out "$OUT/witness/$1/witness_summary.txt" >/dev/null
  cp -p docs/predictions/$3_2026-10-21.txt docs/predictions/$3_2026-10-21_OUTCOME.md \
        docs/predictions/$3_2026-10-21_live_verdicts.txt "$OUT/witness/$1/"
done

echo "== attestation beside behaviour: Table 8 (S VII-H) =="
ATT=att_off_clean,att_on_clean,att_off_tampered,att_on_tampered,att_on_runtime
mkdir -p "$OUT/attest"
python3 -m evaluation.replicates data/runs --arms "$ATT" --out-dir "$OUT/attest"
python3 -m evaluation.attestation_report data/runs --arms "$ATT" \
        --out "$OUT/attest/attestation_summary.txt" >/dev/null
cp -p docs/predictions/attest_2026-10-21.txt docs/predictions/attest_2026-10-21_OUTCOME.md "$OUT/attest/"

echo "== ledger replicas against a forging controller: Table 9 (S VII-I) =="
LV=lv_noverify,lv_honest,lv_forge_score,lv_forge_evidence
mkdir -p "$OUT/ledger"
python3 -m evaluation.replicates data/runs --arms "$LV" --out-dir "$OUT/ledger"
python3 -m evaluation.ledger_report data/runs --arms "$LV" --out "$OUT/ledger/ledger_summary.txt" >/dev/null
python3 -m evaluation.witness_report data/runs --arms "$LV" --out "$OUT/ledger/witness_summary.txt" >/dev/null
cp -p docs/predictions/ledger_2026-10-22.txt docs/predictions/ledger_2026-10-22_OUTCOME.md "$OUT/ledger/"

echo "== the witness acting and holding: Table 10 (S VII-J) =="
# Acting batch (13006e8): its observe-only forge arm is Table 10's first row,
# and the badmouth arms are the text. Hold rows: the third hold batch
# (26e2b04), on the corrected trial path; the first two (wh_*, wh2_*) are
# described in S IX and their outcomes are copied for the record.
WA=wa_control,wa_badmouth_observe,wa_badmouth_act,wa_forge_observe,wa_forge_act
WH=wh3_control_hold,wh3_forge_act,wh3_forge_hold,wh3_drop_act,wh3_drop_hold
mkdir -p "$OUT/witact" "$OUT/withold"
python3 -m evaluation.replicates data/runs --arms "$WA" --out-dir "$OUT/witact"
python3 -m evaluation.witness_act_report data/runs --arms "$WA" --out "$OUT/witact/witact_summary.txt" >/dev/null
python3 -m evaluation.witness_report data/runs --arms "$WA" --out "$OUT/witact/witness_summary.txt" >/dev/null
cp -p docs/predictions/witact_2026-10-23.txt docs/predictions/witact_2026-10-23_OUTCOME.md "$OUT/witact/"
python3 -m evaluation.replicates data/runs --arms "$WH" --out-dir "$OUT/withold"
python3 -m evaluation.witness_act_report data/runs --arms "$WH" --out "$OUT/withold/withold_summary.txt" >/dev/null
cp -p docs/predictions/withold_2026-10-23.txt docs/predictions/withold_2026-10-23_OUTCOME.md \
      docs/predictions/withold2_2026-10-24.txt docs/predictions/withold2_2026-10-24_OUTCOME.md \
      docs/predictions/withold3_2026-10-25.txt docs/predictions/withold3_2026-10-25_OUTCOME.md "$OUT/withold/"
# S IX, "The probation path": the two trial-path defects in the earlier recordings.
python3 paper-draft/tools/trial_path_audit.py data/runs > "$OUT/withold/trial_path_audit.txt"

echo "== replicated ledger with a leader kill (S VII-N) =="
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
