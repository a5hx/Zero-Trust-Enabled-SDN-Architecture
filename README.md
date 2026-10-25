# Zero Trust–Enabled SDN for Secure Load Balancing in Edge Networks

A trust-aware SDN load balancer for OpenFlow 1.3 networks.
- The controller scores every edge server.
- It routes IoT tasks through a virtual service IP, by an EdgeScore.
- It installs each decision as a real flow rule.
- It quarantines misbehaving servers in the data plane.

Every trust update is committed to a hash-chained, Merkle-rooted ledger, which can be
replicated over Raft.

The **product** is the controller application, its REST API and its live dashboard. It runs
against any OpenFlow 1.3 switch. Mininet, the edge-server agents and the IoT clients are its
**test harness**.

> **How to install and run everything: [`SETUP.md`](SETUP.md).** This README is the map.
> For the research story and every result in full, read the paper in
> [`paper-draft/`](paper-draft/).

---

## What the project found

The research question is **what catches a server that lies about its own load, but still
serves correctly**. Every result below comes from live Mininet runs, at least 5 per arm, with
a prediction registered before the runs. Predictions and outcomes are in
[`docs/predictions/`](docs/predictions/).

- **The trust score alone has a narrow, slow margin. The anomaly gate is wide and fast.**
  - In a 15-run ablation, the score never isolated the load liar or the on-off attacker at
    θ = 0.30.
  - The gate isolated both in every run, in a median of 7.6 s and 10.4 s.
  - A registered θ sweep showed that the score *can* isolate them at θ = 0.45, but
    3.4–20× slower, a few hundredths above honest servers under load.
- **Route on what you verify.** A *split-claim* liar reports a low instantaneous load and a
  truthful busy counter. It took +4.0 points of excess traffic and was never caught, because
  the router read one figure and the honesty check verified the other. Routing on the
  verified figure closes the hole, and is now the default.
- **Honest slowness is not mistaken for lying.** Mixed hardware classes and a 25% CPU
  throttle (cgroup v2) caused 0 false quarantines.
- **The switches are a third witness.** Comparing server, client and switch-counter
  evidence names the lying party (server, switch or badmouthing client) in 25/25 runs, and
  has never blamed an honest party (100+ runs).
  - When its verdicts act, honest task success under a controller that forges evidence
    rises from 82.2% to 97.5%.
- **Attestation and behaviour catch different things.**
  - A tampered agent is refused before it serves anything (5/5, 0 connections).
  - A run-time compromise passes attestation, and behaviour catches it.
- **Ledger replicas re-check the controller's arithmetic.** Forged trust scores are rejected
  in every run, and no honest record ever is. Forged *evidence* passes the replicas; only the
  switch witness exposes it.
- **Engineering figures:**
  - routing decisions take about 0.55 ms;
  - after a Raft leader kill, failover takes 0.47 s with no update lost;
  - a flood is throttled by a per-client OpenFlow meter, and honest p95 latency falls from
    178 to 139 ms.

The method itself is part of the contribution. Predictions are registered before runs,
offline models are checked against live runs, failed predictions are reported, and one
earlier finding was retracted. Every defect we found in our own system is written up in the
outcome that measured it (`docs/predictions/*_OUTCOME.md`).

**Paper:** [`paper-draft/`](paper-draft/), *"What Catches a Lie That Works? Trust Scores,
Anomaly Gates and Load-Misreporting Servers in Zero-Trust Edge Load Balancing"*. Every number
in it maps to a file and a command in [`paper-draft/NUMBERS.md`](paper-draft/NUMBERS.md).

---

## Components

| Part | What it does | Where |
|---|---|---|
| SDN controller (os-ken) | OpenFlow 1.3 load balancer behind a VIP: EdgeScore routing with power-of-two-choices + ε, quarantine drop rules, probation trials, re-steering, northbound REST API | `controller/trust_balancer.py`, `trust_state.py`, `edge_selector.py`, `northbound_api.py` |
| Trust model | `T = αR̄ + βB̄ + γH̄ − δĀ` with EMA decay | `trust_engine/trust_calculator.py` |
| Anomaly gate and detectors | Honesty (claimed vs observed load), latency, packet-drop, reachability and flood tells, with leaky-bucket persistence | `controller/flow_monitor.py`, `flood_detector.py` |
| Attack classifier | Names the attack (sybil/load liar, blackhole, grayhole, on-off, flood, spoof, bad credentials). The live controller and the offline scorer share one pure function. | `controller/attack_classifier.py` |
| Switch witness | Cross-checks client reports and server claims against switch flow and port counters. Optionally acts (`controller.witness.act`) and holds a blamed server until it serves trials. | `controller/switch_witness.py`, `flow_stats.py`, `port_stats.py` |
| Flood response | Per-client OpenFlow meter throttle (opt-in) | `controller/flood_response.py` |
| Ledger | SHA-256 blocks with Merkle roots, tamper localisation; Raft (3 replicas, TCP) with async commits; replica re-verification of every trust update (opt-in) | `blockchain/` |
| Device admission | PRESENT-80 challenge–response with a source-IP pin; per-device keys | `security/authenticator.py`, `present_cipher.py`, `tools/device_key.py` |
| Server attestation | Nonce challenge and Ed25519 software quote over the agent's code, with an allowlist and re-attestation (opt-in) | `security/attestation.py`, `simulation/attester.py` |
| Management security | Admin token for the mutating endpoints; keys read from the environment, never from argv | `security/admin_auth.py` |
| AI weight optimizer | UCB1 bandit over the EdgeScore weights (online); Random Forest (offline) | `trust_engine/ai_optimizer.py`, `rf_optimizer.py` |
| Dashboard | Live topology, packet animation from real flow counters, rules, trust, metric charts, over SSE; replay of any recording | `dashboard/` |
| Test harness | Mininet topology, edge-server agent with every attacker mode, IoT clients, cgroup v2 CPU profiles | `simulation/` |
| Control arm | The same network with no enforcement | `base_model/` |
| Evaluation | Replicate scorer with Wilson/t intervals, one report per experiment, offline models and sweeps, the seeded baseline comparison | `evaluation/` |

**os-ken, not Ryu.** The controller runs on [os-ken](https://opendev.org/openstack/os-ken),
the maintained fork of Ryu with the same API (`os_ken.*` instead of `ryu.*`). Ryu does not
run on current Python, and os-ken ships as an Ubuntu package. There is no `ryu` dependency
and no `ryu-manager`: `controller/osken_manager.py` is the launcher.

---

## Quick start

The full commands, including the one-time setup WSL2 needs after every restart, are in
[`SETUP.md`](SETUP.md). In brief:

```bash
python3 -m pytest tests/ base_model/tests/ -q
```

```bash
sudo python3 run_demo.py --mode mininet --config config/params_trust_full.yaml
```

```bash
python3 -m dashboard.replay data/events.jsonl --loop
```

- The **test suite** (about 1,460 tests, about 3 minutes) needs no sudo and no Mininet.
- The **live run** is the full-scale scenario: 8 servers, 40 devices, every attack,
  300 s. The live dashboard is at <http://localhost:8081/>.
- The **replay** shows a recorded run on the dashboard with no Mininet. Open
  <http://localhost:8082/>.

For **experiments**, the replicate runner runs each named arm (one config each, in
`config/`) 5 times, interleaved and resumable:

```bash
sudo ARMS="wh3_control_hold wh3_forge_hold" tools/run_replicates.sh
```

Score the result without sudo:

```bash
python3 -m evaluation.replicates data/runs --arms wh3_control_hold,wh3_forge_hold --out-dir data/my_experiment
```

---

## Repository map

```
controller/        the SDN application (routing, trust state, detectors, witness, API)
trust_engine/      trust calculator, UCB1 and Random-Forest weight optimizers
security/          PRESENT-80 admission, admin token and device keys, server attestation
blockchain/        blocks, Merkle tree, ledger, Raft, commit backends, replica verifier
contracts/         data contracts, thresholds, the address inventory
simulation/        Mininet topology, edge-server agent, IoT client, cgroup CPU profiles, attester
base_model/        the no-enforcement control arm
evaluation/        scorers, reports, offline models and sweeps
dashboard/         the browser dashboard, replay, demo-recording generator
config/            one YAML per experiment arm, each pinned by a test
tools/             replicate runner, Raft failover check, feasibility checks, device-key tool
scripts/           WSL preflight and per-run preflight
deploy/            systemd units and inventory for a real (non-Mininet) testbed
docs/              topic documents; predictions/ holds every registered prediction and outcome
paper-draft/       the paper (LaTeX), its evidence, NUMBERS.md and regenerate.sh
ppt/               Panel Review 1 deck and briefing (September, partly superseded)
tests/             the test suite (no root needed)
data/              recordings and scored outputs: local only, not in git
```

### Where to read what

| Document | For |
|---|---|
| [`SETUP.md`](SETUP.md) | Install, environment, every way to run, score and debug |
| [`docs/PROJECT_BRIEFING.md`](docs/PROJECT_BRIEFING.md) | A briefing for staff and reviewers: design, experiments, results, limits. As of 20 October, so it predates the live witness, attestation and ledger work. |
| [`docs/predictions/`](docs/predictions/) | Each experiment's registered prediction and its `_OUTCOME.md` |
| [`paper-draft/`](paper-draft/) | The paper, `NUMBERS.md`, `CHECKLIST.md`, `evidence/` |
| [`final_run.md`](final_run.md) | The narrated, four-terminal live demo |
| [`deploy/README.md`](deploy/README.md) | Running on real machines |
| `docs/` topic files | `RAFT.md`, `LIAR_BOUND.md`, `WITNESS_OFFLINE.md`, `FEASIBILITY.md`, `FLOW_RULES.md`, `AI_OPTIMIZER.md`, `LOAD_BALANCING_STARVATION.md`, `EVALUATION.md` |

`SOURCE_OF_TRUTH.md`, `DIRECTION.md`, `panel_fix.md` and the `plan*.md` / `explain*.md`
files record the state in August–September. They are kept for history; the paper
supersedes them.

---

## Status

| Area | State |
|---|---|
| Trust-aware routing, quarantine, probation, re-steering | Done, validated live |
| Anomaly gate and detectors; attack classification | Done, validated live |
| Liar experiment (consistent, split-claim, adaptive liars); verified routing | Done; in the paper |
| Heterogeneous hardware and throttling (cgroup v2) | Done; in the paper |
| Switch witness: offline, live, acting | Done; acting not yet in the paper |
| Witness hold (a blamed server stays held until it serves trials) | Re-run in progress (`wh3_*`, see `docs/predictions/withold3_2026-10-25.txt`) |
| Server attestation (software quote) | Done; in the paper. No TPM (swtpm feasibility passed) |
| Raft ledger, wired in (opt-in), live leader kill | Done |
| Replica re-verification of the controller | Done; in the paper |
| Flood throttle (per-client meter) | Done, opt-in |
| Management security (admin token, per-device keys) | Done |
| eBPF kernel witness | Not started (bpftrace/BCC feasibility passed) |
| Hardware testbed (Raspberry Pis) | Deploy kit ready, not yet run |

**Known limits.**
- The defence needs spare capacity, and detection takes 6–16 s from an attack's onset.
- With no attacks, it does slightly worse than round-robin in simulation.
- It does not cover an attacker that searches for the defence's blind spots, malicious Raft
  replicas, or all of one switch's clients colluding.
- The dashboard and the read-only API have no TLS.
- PRESENT-80 and the software quote demonstrate the architecture; they are not
  production-grade security.

The full list is in the paper's limitations section.
