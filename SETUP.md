# Setup & Run Guide

Working command sequence for this machine (Ubuntu 26.04, system Python 3.14).
Kept up to date as the project progresses — see `README.md` for the project
overview and `../project_presentation.pdf` for the full SRS/architecture.

## 0. Environment notes

- This box ships **only Python 3.14** in its default apt repos (no 3.9–3.13,
  no pyenv/uv). Ryu has no Ubuntu package and doesn't run on 3.14, so the SDN
  controller uses **os-ken** instead (`python3-os-ken`, apt) — an
  actively-maintained Ryu fork, same API shape under the `os_ken` package
  name, prebuilt for system Python 3.14. No venv/pip needed anywhere in this
  project.
- Ubuntu's `python3-os-ken` package is a trimmed build: it does **not**
  include the `os-ken-manager` CLI or the example apps (`simple_switch_13`
  etc.). This repo includes hand-written replacements:
  - `controller/osken_manager.py` — minimal app launcher
  - `controller/learning_switch_13.py` — minimal OF1.3 learning switch (used
    to verify connectivity before the trust-aware controller is wired in)
- `sudo` on this machine requires an interactive password — an AI assistant
  session can't supply it, so every command below marked **(sudo)** must be
  run directly in your own terminal.

## 1. Install dependencies (sudo)

```bash
sudo apt update
sudo apt install -y \
  mininet openvswitch-switch openvswitch-testcontroller \
  iperf iperf3 \
  python3-os-ken \
  python3-numpy python3-scipy python3-sklearn python3-matplotlib python3-seaborn \
  python3-pytest python3-joblib \
  wireshark
sudo service openvswitch-switch start
```

`python3-yaml` and `python3-requests` are already part of a stock Ubuntu
desktop install.

Verify:
```bash
mn --version              # 2.3.0
python3 -c "import os_ken; print(os_ken.__version__)"   # 4.1.1
python3 -c "import numpy, scipy, sklearn, matplotlib, seaborn, pytest, joblib, yaml, requests; print('deps OK')"
```

## 2. Verify the standalone trust-engine simulation

No Mininet/root needed — pure Python.

```bash
cd Zero-Trust-Enabled-SDN-Architecture
python3 -m pytest tests/ -v
python3 run_demo.py --mode standalone --duration 60 --attack both
```

Expect: 12/12 tests pass; demo prints final trust scores with the Sybil
target isolated (trust → 0.00) and writes `data/figures/fig{1..4}_*.png` +
`data/routing_log.csv`.

## 3. Mininet + SDN controller demo (advisor deliverable)

Two terminals. Repo root is `Zero-Trust-Enabled-SDN-Architecture/`.

**Terminal A — controller** (no sudo needed):
```bash
python3 -m controller.osken_manager controller.learning_switch_13
```
Wait for `Switch connected: dpid=...` lines once the topology starts.

**Terminal B — topology (sudo)**:
```bash
sudo mn -c   # clean up any leftover state from a previous/crashed run
sudo python3 simulation/topology.py --config config/params_demo.yaml --interactive
```

- `config/params_demo.yaml` is a reduced-scale config (2 edge nodes, 6 IoT
  devices, 30s) for a fast/readable demo. Use `config/params.yaml` for the
  full-scale run (8 edge nodes, 40 IoT devices, 3 malicious, 120s).
- This automatically runs `pingAll` + per-host `iperf` flows
  (`simulation/traffic_gen.py`) and writes results to
  `data/mininet_traffic.log`, then drops into the Mininet CLI.

**Useful Mininet CLI commands once at the `mininet>` prompt:**
```
mininet> pingall                        # reachability test
mininet> iperf                           # built-in bandwidth test (Ctrl+C to stop early)
mininet> dpctl dump-flows -O OpenFlow13  # dump real OpenFlow flow-table rules on every switch
mininet> exit                            # tear down
```
Note: there is **no** `dump-flows` command in Mininet's CLI — `dpctl <cmd>`
is the correct way to run an `ovs-ofctl`-style command against every switch.

## 3b. Trust-aware controller demo (Phase D Sprint 1)

Shows the real thing: `TrustBalancerApp` routing live IoT task traffic
through a virtual service IP (VIP) by EdgeScore, then re-steering away from
a malicious edge server once it's caught. Three terminals.

**Terminal A — controller** (no sudo needed):
```bash
python3 -m controller.osken_manager controller.trust_balancer
```
Wait for `TrustBalancerApp started: vip=...` and `NorthboundAPI listening on
0.0.0.0:8081`. Every edge node will log `QUARANTINE: srvN ... /status poll
failed` at first -- that's expected and correct, since no agents are running
yet (FlowMonitor treats an unreachable node as suspicious, not just idle);
it clears once Terminal B's agents come up.

**Terminal B — topology (sudo)**:
```bash
sudo mn -c   # always clean up leftover bridges from a previous run first --
             # a stale OVS bridge still pointed at 127.0.0.1:6653 will
             # reconnect to Terminal A the instant it starts and confuse
             # what you're looking at
sudo python3 -m simulation.topology --config config/params_trust_demo.yaml --interactive
```
This config is 4 edge servers / 12 IoT devices / 1 malicious server (`srv3`,
Sybil attack -- lies about its CPU load). Unlike section 3's plain demo,
this launches a real `node_agent.py` per edge server and a real
`iot_client.py` per IoT device generating continuous traffic through the
VIP -- watch Terminal A's log for `Routed <ip>:<port> -> srvN` lines as
routing decisions happen, and eventually `QUARANTINE: srv3 ...` once
FlowMonitor's honesty-deviation check catches the lie (bounded by
`monitor_interval_s`, ~1s).

**Terminal C — watch it happen, from the Mininet CLI (Terminal B)**:
```
mininet> dpctl dump-flows -O OpenFlow13 | grep cookie=0x5a
mininet> iot1 curl -s http://10.0.99.254:8081/node/status | python3 -m json.tool
mininet> iot1 curl -s http://10.0.99.254:8081/trust/score | python3 -m json.tool
```
The first shows the live per-connection VIP rewrite rules by node (cookie
low byte = server index); watch `srv3`'s rules disappear from the dump the
moment it's quarantined. The REST calls hit the northbound API through the
`cx` routing node (10.0.99.254) -- the same path `iot_client.py` itself uses
to file its `/report` calls.

Logs land in `logs/srvN_agent.log` / `logs/iotN_client.log` per host, plus
whatever Terminal A prints (routing decisions, quarantine events, honesty
deviations).

## 4. Visualizing "rules" and packet flow (Wireshark)

Two things an advisor might mean by this — both covered:

- **"Rules"** = OpenFlow flow-table entries (`OFPT_FLOW_MOD` messages) the
  controller installs. `dpctl dump-flows -O OpenFlow13` (above) shows them
  as text. Wireshark on the control channel shows them live and decoded.
- **"Visual packet flow"** = watching actual data-plane packets (ARP, ICMP,
  TCP) rather than terminal counters — Wireshark on a host interface.

Mininet hosts each run in their own network namespace, so e.g. `iot1-eth0`
is only visible *from inside* `iot1`'s namespace — you can't just run
`wireshark -i iot1-eth0` from a normal terminal. Mininet's CLI lets you run
a command scoped to a specific host with `<hostname> <command>`.

**One-time, before starting Mininet** (run as your normal user, not sudo —
Mininet runs under `sudo`, so GUI apps launched from inside it run as root
and need permission to use your display):
```bash
xhost +si:localuser:root
```

**Terminal C — capture the OpenFlow control channel** (shows the rule
installs; the controller-switch connection is plain TCP on loopback):
```bash
sudo wireshark -i lo -k -f "tcp port 6653" &
```
Type `openflow_v4` in the display filter bar to isolate/decode the OpenFlow
protocol messages once traffic starts.

**Inside the Mininet CLI** (Terminal B), launch Wireshark scoped to one host:
```
mininet> iot1 wireshark &
```
Pick `iot1-eth0` as the capture interface, then generate fresh traffic to
watch live:
```
mininet> iot1 ping -c 20 srv1
```

**Fallback if the GUI doesn't appear** (root/Wayland display permissions can
be finicky): capture to a file instead, then open it normally afterward —
```
mininet> iot1 tcpdump -i iot1-eth0 -w /tmp/iot1.pcap
```
Stop it (Ctrl+C in that host's xterm, or `iot1 kill %tcpdump`), then:
```bash
wireshark /tmp/iot1.pcap
```

## Known quirks (harmless)

- `sch_htb: quantum of class ... is big` warnings during topology startup —
  a `tc`/traffic-control tuning notice, not an error.
- If you ever see a switch log a large numeric DPID instead of a small
  sequential one, it means you're talking to a **stale bridge from a
  previous, uncleaned run** (Mininet auto-assigns from interface MAC when no
  DPID was set) — `simulation/topology.py` now assigns every switch an
  explicit, distinct, nonzero DPID, so this shouldn't happen on a fresh
  `sudo mn -c` + re-run. If it does, that's the tell to run `sudo mn -c`.

## Project status / what's left

Phases A (env), B (standalone sim verified), C (Mininet+traffic+controller
demo) are done. Phase D Sprint 1 (trust-aware controller) is done: the real
`TrustBalancerApp` os-ken app (`controller/trust_balancer.py`), anomaly
detection (`controller/flow_monitor.py`), the northbound REST API
(`controller/northbound_api.py`), and the Mininet wiring for it
(`simulation/topology.py`'s trust mode, `simulation/node_agent.py`,
`simulation/iot_client.py`) are all built, unit-tested (38/38 passing —
`pytest tests/`), and confirmed to start cleanly and talk real OpenFlow to a
live switch (see section 3b). Not yet run as a full live Mininet demo end to
end by a human — do that next (section 3b) before treating it as verified
for the advisor.

Phase D Sprint 2+ (not started): `security/present_cipher.py` (PRESENT-80,
replacing the Sprint-1 `HmacAuthenticator`), `blockchain/raft.py`,
`trust_engine/ai_optimizer.py`, `evaluation/baseline.py`,
`evaluation/stats.py`.
