#!/usr/bin/env bash
# Repeated live runs of every arm, unattended, for between-run confidence
# intervals. One command, run as root from anywhere:
#
#   sudo tools/run_replicates.sh                 # 5 runs x 3 arms, ~90 min
#   sudo REPS=3 tools/run_replicates.sh          # 3 per arm
#   sudo ARMS="treat scoreonly" tools/run_replicates.sh
#
#   # theta sweep: the score-only arm at isolation_threshold 0.40/0.45/0.50
#   sudo ARMS="scoreonly_t040 scoreonly_t045 scoreonly_t050" tools/run_replicates.sh
#
# Any arm named <scoreonly|treat>_tNNN runs that parent arm at theta = NNN/100,
# with its config derived by tools/derive_config.py (theta <= initial_score 0.5).
#
# Arms:
#   base       base_model/ control arm: static routing, trust computed, never acted on
#   scoreonly  treatment controller, anomaly gate switched OFF (score-only quarantine)
#   treat      treatment controller as shipped (score + anomaly gate)
#
# Every run lands in data/runs/<arm>/rNN.jsonl (+ rNN.controller.log,
# rNN.console.log, rNN.nfr.txt). A run whose recording is under 90% of the
# configured length is kept as rNN.jsonl.short, so the aggregator skips it
# without anything being deleted. data/runs/manifest.csv records every
# attempt, including failed ones.
#
# RESUMABLE: re-running tops each arm up to REPS; nothing already recorded is
# re-run or overwritten. Ctrl-C tears the network down cleanly.
#
# Arms are INTERLEAVED in rotating order (base,scoreonly,treat / scoreonly,
# treat,base / ...) rather than run as blocks, so slow drift on the machine
# (thermal, background load, WSL memory pressure) is spread across arms instead
# of landing on whichever arm happened to run last.
#
# Afterwards, as your normal user:
#   python3 -m evaluation.replicates data/runs --out-dir data/replicates
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

REPS="${REPS:-5}"
ARMS="${ARMS:-base scoreonly treat}"
COOLDOWN_S="${COOLDOWN_S:-30}"
DURATION_S="${DURATION_S:-300}"      # must match simulation.duration_s in all three configs
OUT="data/runs"
MANIFEST="$OUT/manifest.csv"

if [ "$(id -u)" -ne 0 ]; then
  echo "Needs root (Mininet). Run:  sudo $0"; exit 1
fi
OWNER="${SUDO_USER:-}"
[ -n "$OWNER" ] || { echo "Run via sudo from your normal user, so outputs can be handed back."; exit 1; }

give_back() { chown -R "$OWNER": "$@" 2>/dev/null || true; }

# Theta-sweep arms are named <parent>_tNNN (scoreonly_t045 = the score-only arm
# at isolation_threshold 0.45). Their config is derived fresh before every run
# by tools/derive_config.py -- the parent config with exactly two lines changed
# -- and archived beside the recording as rNN.params.yaml.
is_sweep() { [[ "$1" =~ ^[a-z]+_t[0-9]{3}$ ]]; }
sweep_cfg() { echo "logs/params_$1.yaml"; }

cmd_for() {
  case "$1" in
    base)      echo "python3 -m base_model.run_base" ;;
    scoreonly) echo "python3 run_demo.py --mode mininet --config config/params_trust_scoreonly.yaml" ;;
    treat)     echo "python3 run_demo.py --mode mininet --config config/params_trust_full.yaml" ;;
    *) is_sweep "$1" && echo "python3 run_demo.py --mode mininet --config $(sweep_cfg "$1")" || return 1 ;;
  esac
}
recording_for() {
  case "$1" in
    base)      echo "data/base_events.jsonl" ;;
    scoreonly) echo "data/events_scoreonly.jsonl" ;;
    treat)     echo "data/events.jsonl" ;;
    *)         echo "data/events_$1.jsonl" ;;   # set by derive_config.py
  esac
}
mkdir -p logs
for a in $ARMS; do
  cmd_for "$a" >/dev/null || { echo "unknown arm: $a"; exit 1; }
  # Derive once up front so a bad theta fails now, not after an hour of runs.
  if is_sweep "$a"; then
    python3 tools/derive_config.py "$a" "$(sweep_cfg "$a")" >/dev/null || exit 1
  fi
done

# --- protect the recordings the paper and deck are scored from -------------- #
# Both run paths unlink their recording at start-up. Keep a copy of whatever is
# there now, once, under a name nothing here ever writes to.
mkdir -p "$OUT"
for f in data/events.jsonl data/base_events.jsonl data/events_scoreonly.jsonl; do
  keep="${f%.jsonl}_pre_replicates.jsonl"
  if [ -f "$f" ] && [ ! -f "$keep" ]; then
    cp -p "$f" "$keep" && echo "preserved $f -> $keep"
  fi
done
give_back data/*_pre_replicates.jsonl

# --- once-per-session WSL2 prerequisites ------------------------------------ #
service openvswitch-switch start >/dev/null 2>&1 || true
modprobe -a sch_htb sch_netem sch_tbf sch_prio ifb || { echo "modprobe failed"; exit 1; }

for port in 6653 8081; do
  if ss -ltnH "sport = :$port" | grep -q .; then
    echo "Port $port is already in use -- stop the running controller first:"
    ss -ltnp "sport = :$port"; exit 1
  fi
done

[ -f "$MANIFEST" ] || echo "arm,rep,start_utc,end_utc,exit,recorded_s,bytes,status,loadavg_before,git_head" > "$MANIFEST"
GIT_HEAD="$(sudo -u "$OWNER" git rev-parse --short HEAD 2>/dev/null)$(sudo -u "$OWNER" git diff --quiet 2>/dev/null || echo '+dirty')"

count_runs() { ls "$OUT/$1"/r[0-9][0-9].jsonl 2>/dev/null | wc -l; }
next_rep()   { printf '%02d' $(( $(ls "$OUT/$1"/r[0-9][0-9].* 2>/dev/null | sed 's/.*\/r\([0-9][0-9]\)\..*/\1/' | sort -u | tail -1 | sed 's/^0*//;s/^$/0/') + 1 )); }

recorded_seconds() {   # first-to-max ts, as base_model.compare measures it
  python3 - "$1" <<'EOF'
import json, sys
t0 = tmax = None
with open(sys.argv[1]) as f:
    for line in f:
        try:
            ts = json.loads(line).get('ts')
        except ValueError:
            continue
        if ts is None:
            continue
        t0 = ts if t0 is None else t0
        tmax = ts if tmax is None else max(tmax, ts)
print(f"{(tmax - t0) if t0 is not None else 0:.1f}")
EOF
}

INTERRUPTED=0
on_int() { INTERRUPTED=1; echo; echo "Interrupted -- cleaning up after this run's teardown."; }
trap on_int INT TERM

run_one() {
  local arm="$1" rep dir rec cmd start end rc secs bytes status load
  dir="$OUT/$arm"; mkdir -p "$dir"
  rep="$(next_rep "$arm")"
  rec="$(recording_for "$arm")"
  cmd="$(cmd_for "$arm")"
  load="$(cut -d' ' -f1-3 /proc/loadavg | tr ' ' '/')"

  echo
  echo "=================================================================="
  echo " $arm  run r$rep   ($(date -u +%H:%M:%S) UTC, load $load)"
  echo " $cmd"
  echo "=================================================================="
  if is_sweep "$arm"; then
    python3 tools/derive_config.py "$arm" "$(sweep_cfg "$arm")" >/dev/null || return 1
  fi
  mn -c >/dev/null 2>&1
  touch "$dir/.run_started"
  start="$(date -u +%FT%TZ)"
  # Hard ceiling: configured length + generous start-up/teardown margin.
  timeout --signal=INT --kill-after=60 $(( DURATION_S + 300 )) $cmd 2>&1 | tee "$dir/r$rep.console.log"
  rc=${PIPESTATUS[0]}
  end="$(date -u +%FT%TZ)"
  mn -c >/dev/null 2>&1

  if [ -f "$rec" ]; then
    secs="$(recorded_seconds "$rec")"
    bytes="$(stat -c %s "$rec")"
    if python3 -c "import sys; sys.exit(0 if float('$secs') >= 0.9*$DURATION_S else 1)"; then
      mv "$rec" "$dir/r$rep.jsonl"; status=ok
    else
      mv "$rec" "$dir/r$rep.jsonl.short"; status=short
    fi
  else
    secs=0; bytes=0; status=no_recording
  fi
  cp -p logs/controller.log "$dir/r$rep.controller.log" 2>/dev/null || true
  [ "$arm" = base ] && cp -p logs/params_base_effective.yaml "$dir/r$rep.params.yaml" 2>/dev/null
  is_sweep "$arm" && cp -p "$(sweep_cfg "$arm")" "$dir/r$rep.params.yaml"
  # Only if THIS run wrote it -- the base arm writes none, and must not
  # inherit the previous treatment run's report under its own name.
  if [ data/nfr_report.txt -nt "$dir/.run_started" ]; then
    cp -p data/nfr_report.txt "$dir/r$rep.nfr.txt"
  fi
  rm -f "$dir/.run_started"
  echo "$arm,r$rep,$start,$end,$rc,$secs,$bytes,$status,$load,$GIT_HEAD" >> "$MANIFEST"
  give_back "$OUT" logs data/nfr_report.txt
  echo "--> $arm r$rep: $status, ${secs}s recorded, exit $rc"
}

arms=($ARMS)
n=${#arms[@]}
for (( round=0; round<REPS; round++ )); do
  for (( i=0; i<n; i++ )); do
    [ "$INTERRUPTED" -eq 1 ] && break 2
    arm="${arms[$(( (round + i) % n ))]}"
    if [ "$(count_runs "$arm")" -ge "$REPS" ]; then continue; fi
    run_one "$arm"
    [ "$INTERRUPTED" -eq 1 ] && break 2
    sleep "$COOLDOWN_S"
  done
done

mn -c >/dev/null 2>&1
give_back "$OUT" logs data
echo
echo "Runs per arm:"; for a in $ARMS; do echo "  $a: $(count_runs "$a") complete"; done
echo "Manifest: $MANIFEST"
echo "Next (no sudo):  python3 -m evaluation.replicates data/runs --out-dir data/replicates"
