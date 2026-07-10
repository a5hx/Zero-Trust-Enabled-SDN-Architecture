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
- One switch sometimes gets a large numeric DPID instead of a small
  sequential one (Mininet auto-assigns from interface MAC when not set
  explicitly) — cosmetic only, doesn't affect forwarding.

## Project status / what's left

Phases A (env), B (standalone sim verified), C (Mininet+traffic+controller
demo) are done. Phase D (not started): `blockchain/raft.py`,
`trust_engine/ai_optimizer.py`, `security/present_cipher.py`,
`controller/flow_monitor.py`, `evaluation/baseline.py`,
`evaluation/stats.py`, plus finishing the real trust-aware controller
(`controller/trust_balancer.py`) as an os-ken app and swapping it in for
`learning_switch_13.py` in the demo above.
