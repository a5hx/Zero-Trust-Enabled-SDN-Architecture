# Setup and Run Guide

How to install, run, experiment with and score the system on this project's machine: a
Windows laptop running **WSL2, Ubuntu 24.04, Python 3.12**. For the project overview see
[`README.md`](README.md). For the narrated, on-screen demo see [`final_run.md`](final_run.md).

**Contents**

1. [Environment](#1-environment)
2. [Install (once)](#2-install-once)
3. [After every restart (WSL2)](#3-after-every-restart-wsl2)
4. [Run the tests](#4-run-the-tests)
5. [One live run](#5-one-live-run)
6. [Interactive demo (separate terminals)](#6-interactive-demo-separate-terminals)
7. [Experiments: replicated live runs](#7-experiments-replicated-live-runs)
8. [Scoring](#8-scoring)
9. [Opt-in features and their config keys](#9-opt-in-features-and-their-config-keys)
10. [Dashboard: live and replay](#10-dashboard-live-and-replay)
11. [Offline models and simulations](#11-offline-models-and-simulations)
12. [The paper](#12-the-paper)
13. [Inspecting the network by hand](#13-inspecting-the-network-by-hand)
14. [Troubleshooting](#14-troubleshooting)

---

## 1. Environment

- **The SDN framework is os-ken, not Ryu.** os-ken is the maintained fork of Ryu, with the
  same API (`os_ken.*`). It comes from apt (`python3-os-ken`, 2.8.1 here).
  - The Ubuntu package has no `osken-manager` CLI and no example apps.
  - `controller/osken_manager.py` launches the apps, and
    `controller/learning_switch_13.py` is a plain L2 switch for connectivity checks.
- **Everything comes from apt.** No venv, and no `pip install`.
  - `requirements.txt` lists the same packages for other machines.
- **sudo is the user's.** Mininet needs root, and `sudo` asks for a password interactively.
  Every command marked **(sudo)** is run in your own terminal.
  - An assistant session prepares, stages and scores, but never runs those commands.
- **Git:** work happens on `feature/*` branches. You commit, push and merge yourself.

## 2. Install (once)

**(sudo)**

```bash
sudo apt update
```

```bash
sudo apt install -y mininet openvswitch-switch openvswitch-testcontroller iperf3 python3-os-ken python3-numpy python3-scipy python3-sklearn python3-matplotlib python3-seaborn python3-yaml python3-requests python3-pytest python3-joblib python3-cryptography
```

**Optional:**
- The eBPF work and the feasibility checks need `bpftrace bpfcc-tools python3-bpfcc`.
- A TPM-backed attestation quote needs `swtpm swtpm-tools tpm2-tools`.
- Packet capture needs `wireshark`.

Check the install:

```bash
mn --version
```

```bash
python3 -c "import os_ken, numpy, scipy, sklearn, matplotlib, yaml, requests, cryptography; print('deps OK', os_ken.__version__)"
```

To check which kernel features the later phases need (cgroup v2 `cpu.max`, eBPF, swtpm):

```bash
sudo tools/feasibility_check.sh
```

It installs nothing. The results from this machine are in
[`docs/FEASIBILITY.md`](docs/FEASIBILITY.md).

## 3. After every restart (WSL2)

WSL2 does not start Open vSwitch or keep the traffic-shaping modules loaded, and a crashed
run leaves stale bridges behind. Run this once after every laptop restart, and again after
any crash. **(sudo)**

```bash
scripts/wsl_preflight.sh
```

It does the same as these three commands, and checks that `netem` really works:

```bash
sudo service openvswitch-switch start
```

```bash
sudo modprobe -a sch_htb sch_netem sch_tbf sch_prio ifb
```

```bash
sudo mn -c
```

Note the `-a`: without it, `modprobe` loads only the first module.

**Before a recorded run**, check that the config does what the run is meant to show. It
needs no root:

```bash
python3 scripts/preflight_live_run.py --config config/params_trust_full.yaml
```

Exit code 0 means the run is safe to start.

## 4. Run the tests

No root and no Mininet are needed. The suite has about 1,460 tests and takes about 3 minutes:

```bash
python3 -m pytest tests/ base_model/tests/ -q
```

**Your working tree can pass while CI fails**, because it holds uncommitted files. To test
exactly what a commit contains, test an export of it:

```bash
rm -rf /tmp/ztsdn_head && mkdir /tmp/ztsdn_head && git archive HEAD | tar -x -C /tmp/ztsdn_head && (cd /tmp/ztsdn_head && python3 -m pytest tests/ base_model/tests/ -q)
```

A few tests skip in an export because they read recordings that only exist locally.

## 5. One live run

One command starts the controller, the Mininet network, the edge-server agents and the IoT
clients. It runs the configured length, then tears everything down. **(sudo)**

```bash
sudo python3 run_demo.py --mode mininet --config config/params_trust_full.yaml
```

- **`config/params_trust_full.yaml`** is the full-scale scenario:
  - 8 edge servers and 40 IoT devices, 300 s;
  - a load liar (srv3), a blackhole (srv6), a grayhole (srv1) and an on-off attacker (srv8);
  - a flooding device, a spoofing device and a wrong-key device.
- **Other configs:**
  - `config/params_trust_demo.yaml`: 4 servers, 12 devices, one liar;
  - `config/params_trust_raft.yaml`: the full scenario on a 3-replica Raft ledger;
  - `config/params_<arm>.yaml`: every experiment arm (§7).
- **While it runs**, the live dashboard is at <http://localhost:8081/>.
- **The recording** goes to the config's `controller.dashboard.record_path`
  (`data/events.jsonl` for the full config).
  - A leftover recording from an earlier run is moved to `data/archive/` at start-up, never
    deleted.
  - `data/` is not in git, so back recordings up yourself.
- **The NFR pass/fail report** goes to `data/nfr_report.txt`.
- **Per-host logs** go to `logs/` (`srvN_agent.log`, `iotN_client.log`, `controller.log`).
- **The control arm** (the same network, with detectors that publish but never act):

  ```bash
  sudo python3 -m base_model.run_base
  ```

  It records to `data/base_events.jsonl`.

**Keep the laptop plugged in and awake.** A sleep or a power loss ruins the run in progress.

## 6. Interactive demo (separate terminals)

To drive the network by hand from the Mininet CLI, start the controller and the topology
separately. **Start the controller first:** without it, the switches have no flows, and
Mininet's `pingAll` silently times out on every pair.

Terminal A, the controller (no sudo):

```bash
python3 -m controller.osken_manager controller.trust_balancer
```

Wait for `TrustBalancerApp started` and `NorthboundAPI listening on 0.0.0.0:8081`. Until the
agents come up, every server logs `/status poll failed`. That is expected.

**A controller started this way overwrites its recording.** Unlike `run_demo.py`, it does not
move an old one to `data/archive/` first. Copy anything you want to keep before starting it:

```bash
cp data/events.jsonl data/events_keep_$(date +%Y%m%d_%H%M).jsonl
```

To use a config other than the default, set `ZTSDN_CONFIG=config/params_<name>.yaml` in front
of the command.

Terminal B, the topology **(sudo)**:

```bash
sudo mn -c
```

```bash
sudo python3 -m simulation.topology --config config/params_trust_demo.yaml --interactive
```

The step-by-step script for a watched demo, including Wireshark, what to point at and the
narrative arc, is [`final_run.md`](final_run.md). §13 below lists the useful inspection
commands.

## 7. Experiments: replicated live runs

An **arm** is one configuration: `config/params_<arm>.yaml`. Each arm differs from its base
only in the keys its experiment varies, and a test pins that difference (for example
`tests/test_witness_hold_arms.py`). The runner runs every arm `REPS` times (default 5). The
arms are interleaved in rotating order, so slow drift on the machine spreads across arms.
**(sudo)**

```bash
sudo ARMS="wh3_control_hold wh3_forge_act wh3_forge_hold" tools/run_replicates.sh
```

**It is resumable.** Each arm is topped up to `REPS` complete runs, and nothing already
recorded is re-run or overwritten. After an interruption, run the same command again.

**Options:**

| Variable | Effect |
|---|---|
| `REPS=1` | A one-run pilot |
| `COOLDOWN_S=30` | Pause between runs |
| `ZTSDN_ALLOW_FORGERY=1` | Required by arms that set `controller.debug_forge_trust` (the forged-score and forged-evidence arms). Config validation refuses them otherwise. |

```bash
sudo REPS=1 ARMS="witfix_control" tools/run_replicates.sh
```

```bash
sudo ZTSDN_ALLOW_FORGERY=1 ARMS="lv_forge_score lv_forge_evidence" tools/run_replicates.sh
```

**Output** goes to `data/runs/<arm>/`:

| File | Contents |
|---|---|
| `rNN.jsonl` | The recording |
| `rNN.params.yaml` | The exact config used |
| `rNN.controller.log` | The controller's log |
| `rNN.console.log` | The run's console output |
| `rNN.nfr.txt` | The NFR report |

- A run shorter than 90% of its configured length is kept as `rNN.jsonl.short` and skipped
  by the scorers.
- `data/runs/manifest.csv` records every attempt, with its git commit (`+dirty` if the tree
  had uncommitted changes).

**Arm names:**

| Name | Runs |
|---|---|
| `base`, `scoreonly`, `treat` | The control arm, the gate computed but not enforced, and both rails (`params_trust_full.yaml`) |
| `<parent>_tNNN` (e.g. `scoreonly_t045`) | A θ-sweep arm, derived fresh by `tools/derive_config.py` |
| Any other name | `config/params_<name>.yaml`, as-is |

**Experiment families in `config/`:**

| Prefix | Experiment |
|---|---|
| `liar_*`, `liarfix*_*`, `ship_*`, `stealthy_treat` | The liar experiment (consistent, split-claim and adaptive liars) |
| `hw_*` | Heterogeneous hardware and honest throttling |
| `wit_*`, `witfix_*` | The switch witness, live |
| `att_*` | Attestation beside behaviour |
| `lv_*` | Ledger re-verification and forgery |
| `wa_*` | Witness verdicts acting |
| `wh_*`, `wh2_*`, `wh3_*` | The witness hold |
| `flood_*` | Flood throttle off and on |

**The working rule for a new experiment:**
1. Write its prediction to `docs/predictions/<exp>_<date>.txt`.
2. Commit it before the first run.
3. Run the arms.
4. Score them, and write `<exp>_<date>_OUTCOME.md` next to the prediction, including the
   predictions that failed.
5. A hole an experiment exposes is fixed only after it has been measured. Then re-run.

## 8. Scoring

None of this needs root or the controller stack.

**Replicated arms**, with between-run 95% intervals (t for continuous measures, Wilson for
yes/no outcomes):

```bash
python3 -m evaluation.replicates data/runs --arms wh3_control_hold,wh3_forge_hold --out-dir data/withold3_experiment_2026-10-25
```

**Always pass `--arms` and a new `--out-dir`.** The runner's generic hint,
`python3 -m evaluation.replicates data/runs --out-dir data/replicates`, re-scores every arm
and overwrites the original ablation summary.

**One report per experiment:**

| Experiment | Command |
|---|---|
| Liar (offline model) | `python3 -m evaluation.liar_sweep --seeds 5` |
| Switch witness, offline | `python3 -m evaluation.witness_offline data/runs` |
| Switch witness, live | `python3 -m evaluation.witness_report data/runs --arms witfix_control,witfix_drop` |
| Witness acting and hold | `python3 -m evaluation.witness_act_report data/runs --arms wh3_control_hold,wh3_forge_act,wh3_forge_hold,wh3_drop_act,wh3_drop_hold` |
| Attestation | `python3 -m evaluation.attestation_report data/runs --arms att_off_clean,att_on_clean,att_off_tampered,att_on_tampered,att_on_runtime` |
| Ledger re-verification | `python3 -m evaluation.ledger_report data/runs --arms lv_noverify,lv_honest,lv_forge_score,lv_forge_evidence` |

**A single recording:**

| Command | Reports |
|---|---|
| `python3 -m evaluation.nfr_report data/events.jsonl` | The four NFRs, pass/fail |
| `python3 -m evaluation.attack_report data/events.jsonl` | Confusion matrix and detection latency |
| `python3 -m evaluation.availability_report data/events.jsonl` | Honest availability vs containment |
| `python3 -m evaluation.interval_report data/events.jsonl` | Every metric vs time, in 10 s buckets |
| `python3 -m evaluation.topology_metrics data/events.jsonl` | Node degree and distance to the core switch |

`attack_report` and `availability_report` score against the ground truth carried on the
recording's `topology` event, so they need a recording that includes the start of its run.

**The analysis page** is one self-contained HTML file, with no CDN and no build step. The
controller serves it at `http://localhost:8081/analysis`, and it also opens straight from
disk:

```bash
python3 -m evaluation.build_analysis_page data/events.jsonl --run-sweeps --out dashboard/analysis.html
```

A section whose input is missing names the command that fills it.

## 9. Opt-in features and their config keys

Everything added after the shipped design is off unless a config turns it on. That way every
recorded config replays exactly. The arm configs in `config/` are working examples of each.

| Feature | Keys | Example config |
|---|---|---|
| Routing on the verified load claim (the default) | `edge_score.cpu_claim: verified` (`raw` is pinned by every config recorded before it became the default) | `params_ship_c_verified.yaml` |
| Selection strategy | `edge_score.selection: p2c` (or `argmax`), `d_choices`, `epsilon` | `params_trust_full.yaml` |
| Raft ledger | `ledger.backend: raft_remote`, `ledger.replicas`, `ledger.launch_local` (starts 3 local replicas) | `params_trust_raft.yaml` |
| Replica re-verification | `ledger.verify: true` | `params_lv_honest.yaml` |
| Forgery (test only) | `controller.debug_forge_trust: {node, mode: score\|evidence, start_s}`, plus `ZTSDN_ALLOW_FORGERY=1` | `params_lv_forge_*.yaml` |
| Switch witness | `controller.witness.enabled: true` (observes only) | `params_witfix_control.yaml` |
| Witness verdicts act | `controller.witness.act: {servers: true, clients: true}` | `params_wa_*_act.yaml` |
| Witness hold | `controller.witness.act.hold: {trial_interval_s: 10, passes: 3}` | `params_wh3_*_hold.yaml` |
| Server attestation | `security.attestation: {enabled: true, reattest_s, validity_s}` | `params_att_on_*.yaml` |
| Flood throttle | `controller.flood_response: {mode: meter, rate_factor, ...}` | `params_flood_on.yaml` |
| Hardware classes and throttling | `simulation.server_profiles: {srvN: {class, cpu_max}}`, `simulation.honest_throttle: [...]`, `controller.latency_baseline: class` | `params_hw_*.yaml` |
| Admin token on mutating endpoints | `controller.admin_token_env: <ENV VAR>`: the token is read from that variable, never from the file or argv | (deploy) |
| Device keys | `security.shared_key_env`, `security.key_derivation: per_device`; `ZTSDN_MASTER_KEY=... python3 tools/device_key.py iot1` prints a device's key | (deploy) |

**Raft leader-kill check.** While a Raft config runs, in a second terminal **(sudo)**:

```bash
sudo python3 tools/raft_failover_check.py --config config/params_trust_raft.yaml
```

The design and the results are in [`docs/RAFT.md`](docs/RAFT.md). To run on real machines
instead of Mininet, see [`deploy/README.md`](deploy/README.md).

## 10. Dashboard: live and replay

**Live:** during any run whose config has `controller.dashboard.enabled: true`, open
<http://localhost:8081/>. It is served by the same process as the REST API. It shows:
- the topology, with dots whose rate comes from the real packet counters on the flow rules;
- each routing decision, with its EdgeScore;
- claimed vs observed load;
- quarantines, drop rules with their dropped-packet counts, and re-steering;
- the UCB1 optimizer's arms;
- metric-vs-time charts.

The controller never sees individual packets once a rule is installed, so the dots show
measured rates, not every packet.

**Replay** a recording, with no Mininet and no sudo, at its original pace:

```bash
python3 -m dashboard.replay data/events.jsonl --loop
```

Then open <http://localhost:8082/>. `--speed 3` replays faster, and any `data/runs/<arm>/rNN.jsonl`
works too.

**A recording with no network at all** is generated by the real `TrustState`, `FlowMonitor`
and optimizer, driven by scripted telemetry. It is useful as a fallback on demo day, but it
is not a measurement:

```bash
python3 -m dashboard.generate_demo_recording --out data/demo_events.jsonl
```

## 11. Offline models and simulations

None of these needs root, and each finishes in seconds to a minute.

| Command | What it does |
|---|---|
| `python3 -m evaluation.liar_sweep --seeds 5` | Predicts liar traffic shares on the real selector and trust code |
| `python3 -m evaluation.scalability_sweep` | Throughput, PDR, delay and Jain index vs N, with real queueing |
| `python3 -m evaluation.scalability_sweep --load-factors 0.1,0.6` | The same, at low and high load |
| `python3 -m evaluation.starvation_sweep` | argmax vs p2c vs p2c+ε across N |
| `python3 -m evaluation.baseline --runs 30 --csv data/results.csv` | The 600-run seeded comparison (5 routers × 4 scenarios × 30 seeds) |
| `python3 -m evaluation.stats data/results.csv --metric slo_violation_rate` | Paired Wilcoxon with Holm–Bonferroni on that comparison |
| `python3 run_demo.py --mode standalone --duration 120 --attack both` | Trust-engine simulation; writes figures to `data/figures/` |

## 12. The paper

The paper lives in `paper-draft/`.
- `NUMBERS.md` maps every number to a file and a command.
- `CHECKLIST.md` lists the open items.

Re-score every number from the recordings:

```bash
paper-draft/tools/regenerate.sh
```

Build `paper.pdf`:

```bash
make -C paper-draft
```

## 13. Inspecting the network by hand

From the `mininet>` prompt of an interactive run (§6):

| Command | Shows |
|---|---|
| `dpctl dump-flows -O OpenFlow13` | Every switch's rules. Mininet has no `dump-flows` command of its own. |
| `dpctl dump-flows -O OpenFlow13 \| grep cookie=0x5a` | Per-connection VIP rewrite rules; the cookie's low byte is the server index |
| `dpctl dump-flows -O OpenFlow13 \| grep priority=400` | Quarantine drop rules; re-run it to watch `n_packets` climb |
| `iot1 curl -s http://10.0.99.254:8081/node/status \| python3 -m json.tool` | Trust, claims, in-flight counts, quarantine state |
| `iot1 curl -s http://10.0.99.254:8081/trust/score \| python3 -m json.tool` | Current trust scores |
| `iot1 ping -c 3 srv3` | Fails once srv3 is quarantined |
| `sh ovs-ofctl -O OpenFlow13 dump-meters s0` | Rate-limit meters |

The REST calls reach the controller through the `cx` routing node (`10.0.99.254`), the same
path the clients use for their `/report` calls.

**Rule priorities:**

| Priority | Rule |
|---|---|
| 460 | Probation and witness trial rewrite, on the client's ingress switch |
| 455 | Trial passage, on every switch |
| 450 | Health-check exemption |
| 400 | Quarantine drop |
| 300 | Ordinary per-connection VIP rewrite |

The full scheme is in [`docs/FLOW_RULES.md`](docs/FLOW_RULES.md).

**Wireshark.**
- **The OpenFlow control channel:** `sudo wireshark -i lo -k -f "tcp port 6653"`, with
  display filter `openflow_v4`.
- **A host's data plane:** run `xhost +si:localuser:root` first as your own user, then
  `iot1 wireshark &` from the Mininet CLI.
- **If no window appears:** capture to a file with
  `iot1 tcpdump -i iot1-eth0 -w /tmp/iot1.pcap`, and open it afterwards.

## 14. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Topology hangs; `pingAll` times out on every pair | Open vSwitch is not running, or no controller is listening on 6653. Run `scripts/wsl_preflight.sh`, and in §6 start the controller first. |
| `Specified qdisc kind is unknown` | The traffic-shaping modules are not loaded: `sudo modprobe -a sch_htb sch_netem sch_tbf sch_prio ifb` |
| `RTNETLINK answers: File exists` | Stale state from a crash: `sudo mn -c` |
| `Port 6653 (or 8081) is already in use` | A controller from an earlier run is still alive. Stop it (`ss -ltnp 'sport = :6653'` shows its PID). |
| `PermissionError ... data/events.jsonl` | A file left owned by root from an old sudo run: `sudo chown -R $USER data logs` |
| A batch stopped part-way (sleep, power loss) | Re-run the same `run_replicates.sh` command; it resumes. A half-written run leaves no `rNN.jsonl` and is not scored. |
| `rNN.jsonl.short` | That run recorded less than 90% of its length. It is kept but not scored, and the runner tops the arm up. |
| `sch_htb: quantum of class ... is big` | Harmless (the 1 Gbit core links) |
| `Unable to contact the remote controller` at start-up | Harmless; it clears once the controller is up |
| A switch shows a huge DPID | A stale bridge from an uncleaned run: `sudo mn -c` |
| A forgery arm refuses to start | It needs `ZTSDN_ALLOW_FORGERY=1` on the command |
