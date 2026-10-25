#!/usr/bin/env bash
# Phase 0 feasibility checks for the novelty plan. Run as root:
#
#     sudo tools/feasibility_check.sh
#
# Installs NOTHING. Each check reports PASS / FAIL / SKIP (with the apt command
# that would make it runnable) and the whole report is written to
# logs/feasibility_<UTC>.txt, owned by the invoking user.
#
#   1. cgroup v2 cpu.max  -- Phase 3 emulates slow hardware and thermal
#      throttling by capping agent processes. Mininet's CPULimitedHost assumes
#      cgroup v1 and does not work here; this checks the v2 path directly.
#   2. eBPF (bpftrace, BCC) -- Phase 5's kernel-side witness.
#   3. swtpm + tpm2-tools  -- Phase 4's optional TPM-backed quote (socket mode;
#      this WSL kernel has no vtpm proxy). Phase 4 works without it.
set -uo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root: sudo $0" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$ROOT/logs"
REPORT="$ROOT/logs/feasibility_$(date -u +%Y%m%dT%H%M%SZ).txt"
exec > >(tee "$REPORT") 2>&1

echo "feasibility check  $(date -u)  kernel $(uname -r)"
echo

# --------------------------------------------------------------------------- #
echo "== 1. cgroup v2 cpu.max =="
CG=/sys/fs/cgroup/ztsdn-feasibility
if ! grep -qw cpu /sys/fs/cgroup/cgroup.controllers 2>/dev/null; then
  echo "FAIL: no cgroup v2 cpu controller at /sys/fs/cgroup"
else
  grep -qw cpu /sys/fs/cgroup/cgroup.subtree_control || echo "+cpu" > /sys/fs/cgroup/cgroup.subtree_control
  mkdir -p "$CG"
  echo "25000 100000" > "$CG/cpu.max"           # 25% of one CPU
  # A 3 s busy loop placed in the group before it starts spinning.
  sh -c "echo \$\$ > $CG/cgroup.procs; exec timeout 3 python3 -c 'while True: pass'"
  usage_us=$(awk '/^usage_usec/ {print $2}' "$CG/cpu.stat")
  throttled=$(awk '/^nr_throttled/ {print $2}' "$CG/cpu.stat")
  rmdir "$CG" 2>/dev/null
  share=$(python3 -c "print(f'{$usage_us / 3e6:.2f}')")
  echo "cpu used over 3 s wall: ${usage_us} us (${share} of one CPU), throttled ${throttled} periods"
  if python3 -c "import sys; sys.exit(0 if 0.15 <= $usage_us / 3e6 <= 0.35 else 1)"; then
    echo "PASS: cpu.max caps a process at the configured 25%"
  else
    echo "FAIL: expected about 0.25 of one CPU"
  fi
fi
echo

# --------------------------------------------------------------------------- #
echo "== 2. eBPF =="
if command -v bpftrace >/dev/null; then
  if out=$(timeout 10 bpftrace -e 'tracepoint:sched:sched_switch { @n = count(); } interval:s:2 { exit(); }' 2>&1); then
    echo "$out" | tail -2
    echo "PASS: bpftrace attaches to sched_switch"
  else
    echo "$out" | tail -5
    echo "FAIL: bpftrace could not attach"
  fi
else
  echo "SKIP: bpftrace not installed  ->  sudo apt install bpftrace"
fi
if python3 -c "import bcc" 2>/dev/null; then
  if python3 - <<'EOF'
from bcc import BPF
b = BPF(text='int kprobe__tcp_v4_connect(void *ctx) { return 0; }')
print("BCC compiled and attached a kprobe on tcp_v4_connect")
EOF
  then echo "PASS: BCC works"; else echo "FAIL: BCC could not compile/attach"; fi
else
  echo "SKIP: BCC not installed  ->  sudo apt install bpfcc-tools python3-bpfcc"
fi
echo

# --------------------------------------------------------------------------- #
echo "== 3. swtpm + tpm2-tools (optional) =="
if command -v swtpm >/dev/null && command -v tpm2_startup >/dev/null; then
  STATE=$(mktemp -d)
  swtpm socket --tpm2 --tpmstate dir="$STATE" \
        --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init \
        --daemon --pid file="$STATE/pid"
  sleep 0.5
  export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"
  if tpm2_startup -c && tpm2_pcrread sha256:0,10 && tpm2_getrandom --hex 8 >/dev/null; then
    echo "PASS: software TPM answers (startup, PCR read, RNG)"
  else
    echo "FAIL: swtpm started but tpm2-tools could not talk to it"
  fi
  kill "$(cat "$STATE/pid")" 2>/dev/null
  rm -rf "$STATE"
else
  echo "SKIP: not installed  ->  sudo apt install swtpm swtpm-tools tpm2-tools"
fi
echo

echo "report: $REPORT"
if [ -n "${SUDO_UID:-}" ]; then chown "$SUDO_UID:$SUDO_GID" "$REPORT"; fi
