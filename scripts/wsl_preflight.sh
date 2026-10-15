#!/usr/bin/env bash
# WSL preflight for the Zero-Trust SDN Mininet topology.
#
# WSL2 does not persist loaded kernel modules or auto-start Open vSwitch the way
# a full VM does, and a crashed Mininet run leaves stale switches/veths behind.
# This script makes a run reproducible: it loads the tc qdisc modules that TCLink
# needs (bw= -> htb, delay= -> netem), starts Open vSwitch, and clears stale
# state. Idempotent — safe to run before every launch. Re-execs under sudo.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    exec sudo -- "$0" "$@"
fi

MODULES=(sch_htb sch_netem sch_tbf sch_prio ifb)

echo "==> Loading qdisc modules"
modprobe -a "${MODULES[@]}"

echo "==> Verifying tc qdisc support"
if tc qdisc add dev lo root netem delay 1ms 2>/dev/null; then
    tc qdisc del dev lo root
    echo "    qdisc OK"
else
    echo "    ERROR: netem qdisc still unavailable after modprobe." >&2
    echo "    Kernel modules for $(uname -r) may be missing/mismatched." >&2
    exit 1
fi

echo "==> Ensuring Open vSwitch is running"
if ! ovs-vsctl show >/dev/null 2>&1; then
    service openvswitch-switch start
fi
if ovs-vsctl show >/dev/null 2>&1; then
    echo "    OVS OK"
else
    echo "    ERROR: Open vSwitch failed to start." >&2
    exit 1
fi

echo "==> Clearing stale Mininet state"
mn -c >/dev/null 2>&1 || true
echo "    clean"

echo "==> Checking SDN controller on 127.0.0.1:6653"
if ss -ltn 2>/dev/null | grep -q ':6653'; then
    echo "    controller UP"
else
    echo "    controller NOT running — start it in another terminal first:"
    echo "      python3 -m controller.osken_manager controller.trust_balancer"
fi

echo "==> Preflight complete. Launch with e.g.:"
echo "      sudo python3 -m simulation.topology --config config/params_trust_demo.yaml --interactive"
