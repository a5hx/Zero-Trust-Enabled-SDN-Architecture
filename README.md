# Zero Trust–Enabled SDN for Secure Load Balancing in Edge Networks

A trust-aware SDN load balancer for OpenFlow 1.3 networks. The controller
computes a per-node trust score, ranks edge servers by an EdgeScore, installs
routing decisions as real flow rules, and quarantines misbehaving nodes in the
data plane. Trust events are recorded in a tamper-evident (SHA-256 + Merkle)
ledger.

Final-year project. The **product** is the controller application, its REST
API, and the live dashboard — it runs against any OpenFlow 1.3 switch. Mininet,
the node agents, and the IoT clients are its **test harness**, not the product.

> **The authoritative run-book is [`SETUP.md`](SETUP.md).** It has the exact,
> environment-specific install and demo commands. Start there for anything
> hands-on. This README is the map; `SETUP.md` is the instructions.

---

## Overview

A Zero Trust security model drives trust-aware routing for IoT workloads at the
edge. Trust is computed continuously from task outcomes and node telemetry; an
independent anomaly gate quarantines nodes that lie about their load but keep
serving (a case the trust score alone provably cannot catch — see
[`DIRECTION.md`](DIRECTION.md) §3, Finding 1). Trust decisions are enforced as
OpenFlow rules, not simulated.

**Core components:**
- **SDN controller (os-ken)** — OpenFlow 1.3 trust-aware load balancer
  (`controller/trust_balancer.py`). See note on os-ken vs Ryu below.
- **Dynamic trust model** — normalised formula `T = αR̄+βB̄+γH̄−δĀ` with EMA
  decay, plus a load-bearing anomaly gate (`trust_engine/trust_calculator.py`,
  `controller/edge_selector.py`).
- **Live dashboard** — topology, packet animation from real `OFPFlowStats`
  counters, flow rules, and trust, over server-sent events (`dashboard/`).
- **Blockchain ledger** — SHA-256 + Merkle-tree trust record store
  (`blockchain/`).
- **PRESENT-80 cipher** — lightweight IoT device authentication *(planned;
  seam at `security/authenticator.py`)*.
- **RAFT consensus** — leader election + log replication, built and unit-tested
  in isolation (`blockchain/raft.py`) *(not yet wired to the ledger; TCP
  transport pending)*.
- **AI weight optimizer** — Random Forest (offline) + UCB1 bandit (online)
  *(planned)*.
- **Evaluation harness** — 4 baselines, seeded runs, Wilcoxon significance
  tests *(planned)*.

### os-ken, not Ryu

The deck specified Ryu. This project runs on **os-ken** — the actively
maintained fork of Ryu — because the target OS (Ubuntu 26.04) ships only
Python 3.14 and has no Ryu package, and Ryu cannot run on Python > 3.13. os-ken
has the same API (`os_ken.*` instead of `ryu.*`). This is an environment-driven
engineering decision, documented in `SETUP.md` §0. There is no `ryu` dependency
and no `ryu-manager` in this project.

---

## Repository structure

```
config/            params.yaml (full scale), params_demo.yaml, params_trust_demo.yaml
contracts/         data contracts (trust_update, block schema, thresholds)
trust_engine/      trust_calculator.py, ai_optimizer.py (planned)
controller/        trust_balancer.py, flow_monitor.py, edge_selector.py,
                   northbound_api.py, event_bus.py, flow_stats.py,
                   osken_manager.py (hand-written app launcher)
blockchain/        merkle.py, block.py, ledger.py, commit_backend.py, raft.py (isolated core)
security/          authenticator.py (HMAC seam), present_cipher.py (planned)
simulation/        topology.py, attack_simulator.py, node_agent.py, iot_client.py, addressing.py
evaluation/        metrics.py, plots.py, baseline.py (planned), stats.py (planned)
dashboard/         index.html, replay.py, generate_demo_recording.py
tests/             pytest suite (no sudo/Mininet required)
uml_diagrams/      class, sequence, DFD, ER, activity
```

---

## Prerequisites

- Ubuntu with Python 3.14 (system Python; no venv needed on the target box)
- Mininet + Open vSwitch
- os-ken (`python3-os-ken`) and the scientific stack, installed via `apt`

All dependencies install as apt packages — see `SETUP.md` §1 for the exact
command. There is no `pip install -r requirements.txt` step on the target
environment.

---

## Quick start

Full, environment-specific commands are in `SETUP.md`. In brief:

**Run the unit tests** (no sudo, no Mininet — works anywhere the deps are installed):

```bash
python3 -m pytest tests/ -v
```

**Standalone trust-engine simulation** (figures + routing CSV, no Mininet):

```bash
python3 run_demo.py --mode standalone --duration 120 --attack both
```

**Live trust-aware controller + Mininet demo** (three terminals, needs sudo for
Mininet) — see `SETUP.md` §3b.

**Live dashboard without Mininet** (replay a recorded run):

```bash
python3 -m dashboard.replay data/events.jsonl --loop   # then open localhost:8082
```

---

## Status

| Component | Status |
|-----------|--------|
| Repo structure & data contracts | ✅ Done |
| Trust formula & calculator | ✅ Done |
| Blockchain core (SHA-256 + Merkle) | ✅ Done (order-sensitive proofs) |
| Standalone trust-engine simulation | ✅ Done |
| Mininet topology + live controller connectivity | ✅ Done |
| Trust-aware controller (EdgeScore routing, quarantine drop rules, REST API) | ✅ Done |
| Live dashboard (topology, packets, rules, trust) | ✅ Done |
| PRESENT-80 authentication | 🔄 Planned (Sprint 2) |
| RAFT consensus | 🟡 Core built + tested in isolation (not wired in) |
| Evaluation harness (baselines + Wilcoxon) | 🔄 Planned (Sprint 2) |
| AI weight optimizer | 🔄 Planned (Sprint 2) |
| Full-scale integration (8 edge / 40 IoT / 3 malicious) | 🔄 Planned (Sprint 2) |

See [`DIRECTION.md`](DIRECTION.md) for the honest status assessment, the
legacy-vs-novelty analysis, and the Sprint 2+ roadmap.

---
