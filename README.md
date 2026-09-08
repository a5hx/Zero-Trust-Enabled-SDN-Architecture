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
- **Attack classification** — six attacks (sybil, blackhole, grayhole, on-off,
  DDoS/flood, identity spoof) plus bad-credentials devices, each named rather
  than merely flagged, by one pure function the live controller and the offline
  scorer both call (`controller/attack_classifier.py`,
  `controller/flood_detector.py`).
- **Live dashboard** — topology, packet animation from real `OFPFlowStats`
  counters, flow rules, trust, nine metric-vs-time charts and per-node
  structural metrics, over server-sent events (`dashboard/`).
- **Blockchain ledger** — SHA-256 + Merkle-tree trust record store
  (`blockchain/`). Tamper-evident: an edit is localised to the seam, not just
  reported as "chain invalid".
- **PRESENT-80 cipher** — lightweight IoT device authentication, wired into
  live device admission, extended with a provisioned source-IP pin so the
  fleet-wide key authenticates the *device* and not merely possession of the key
  (`security/present_cipher.py`, `security/authenticator.py`).
- **RAFT consensus** — leader election, log replication, TCP transport and a
  standalone 3-replica demo, all built and unit-tested
  (`blockchain/raft.py`, `raft_transport.py`, `raft_replica.py`, `raft_demo.py`)
  *(the live controller still runs a single local replica — not wired in)*.
- **AI weight optimizer** — UCB1 bandit (online), wired into the live monitor
  loop and dashboard (`trust_engine/ai_optimizer.py`) *(offline Random Forest
  planned)*.
- **Evaluation harness** — 4 baselines, 30 seeded runs/scenario, paired Wilcoxon
  signed-rank with Holm–Bonferroni correction — 14/16 comparisons favour the
  system (`evaluation/baseline.py`, `evaluation/stats.py`,
  [results](docs/EVALUATION.md)).
- **Live-run scorers** — NFR pass/fail, per-interval metrics, confusion matrix
  with detection latency, and service availability, all read the same recording
  and none needs the controller stack installed (`evaluation/nfr_report.py`,
  `interval_report.py`, `attack_report.py`, `availability_report.py`).

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
config/                  params.yaml (full scale), params_trust_full.yaml (the panel run),
                         params_demo.yaml, params_trust_demo.yaml, params_attacks_demo.yaml
contracts/               data contracts (trust_update, block schema, thresholds)
trust_engine/            trust_calculator.py, ai_optimizer.py (UCB1 online; RF offline planned)
controller/              trust_balancer.py, flow_monitor.py, edge_selector.py,
                         attack_classifier.py, flood_detector.py, trust_state.py,
                         northbound_api.py, event_bus.py, flow_stats.py,
                         osken_manager.py (hand-written app launcher)
blockchain/              merkle.py, block.py, ledger.py, commit_backend.py,
                         raft.py, raft_transport.py, raft_replica.py, raft_demo.py
security/                authenticator.py (PRESENT-80 + source-IP pin), present_cipher.py
simulation/              topology.py, attack_simulator.py, node_agent.py, iot_client.py, addressing.py
evaluation/              metrics.py, plots.py, baseline.py, stats.py, starvation_sweep.py,
                         interval_report.py, availability_report.py, attack_report.py,
                         nfr_report.py, topology_metrics.py
dashboard/               index.html, replay.py, generate_demo_recording.py
docs/paper/              the research paper (.docx) — built by tools/paper/
tools/paper/             paper build: figures, template, docx renderer (see its README)
trust_convergence_demo/  standalone demo proving trust base values are computed
wsl_gui/                 WSL packet-capture + dashboard integration utilities
tests/                   pytest suite, 669 tests (no sudo/Mininet required)
uml_diagrams/            class, sequence, DFD, ER, activity
```

### Where to read what

| Document | Role |
|---|---|
| [`SETUP.md`](SETUP.md) | **Start here for anything hands-on** — install, environment, per-feature deep dives |
| [`SOURCE_OF_TRUTH.md`](SOURCE_OF_TRUTH.md) | Consolidated state: what was built, what the live runs say, what is still open |
| [`final_run.md`](final_run.md) | The runbook — every command, in order |
| [`docs/paper/`](docs/paper/) | The research paper: findings, evaluation, limitations |
| [`docs/EVALUATION.md`](docs/EVALUATION.md) | The baseline experiment and its significance testing |
| [`DIRECTION.md`](DIRECTION.md) | Honest status assessment, novelty analysis, roadmap |
| [`PROBLEM_AND_IMPACT.md`](PROBLEM_AND_IMPACT.md) | What problem this solves, where it applies, what it does *not* claim |
| `docs/` | `AI_OPTIMIZER.md`, `FLOW_RULES.md`, `LOAD_BALANCING_STARVATION.md`, `RAFT.md` |

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
Mininet) — see `SETUP.md` §3b. The full-scale panel run is:

```bash
sudo python3 run_demo.py --mode mininet --config config/params_trust_full.yaml
```

> **Archive the recording before the next run.** `--mode mininet` unlinks
> `data/events.jsonl` at startup and `data/` is gitignored, so copy it to
> `data/events_runN.jsonl` the moment a run finishes or its numbers cannot be
> re-derived.

**Score a live run** (no sudo, no controller stack — all four read the same recording):

```bash
python3 -m evaluation.nfr_report          data/events.jsonl   # the four NFRs, pass/fail
python3 -m evaluation.attack_report       data/events.jsonl   # confusion matrix + detection latency
python3 -m evaluation.availability_report data/events.jsonl   # honest availability vs containment
python3 -m evaluation.interval_report     data/events.jsonl   # every metric vs time, 10 s buckets
```

**The statistical comparison** (5 strategies × 4 scenarios × 30 seeds = 600 runs, ~40 s):

```bash
python3 -m evaluation.baseline --runs 30 --csv results.csv
python3 -m evaluation.stats results.csv --metric slo_violation_rate
```

**Live dashboard without Mininet** (replay a recorded run):

```bash
python3 -m dashboard.replay data/events.jsonl --loop   # then open localhost:8082
```

**Rebuild the paper** — see [`tools/paper/README.md`](tools/paper/README.md).

**Trust convergence demonstration** (prove base values are computed, not referenced):

```bash
cd trust_convergence_demo
python3 simulate_network.py   # See START_HERE.md for details
```

---

## Status

**Test suite: 669 tests, all passing.**

| Component | Status |
|-----------|--------|
| Repo structure & data contracts | ✅ Done |
| Trust formula & calculator | ✅ Done |
| Blockchain core (SHA-256 + Merkle) | ✅ Done (order-sensitive proofs) |
| Standalone trust-engine simulation | ✅ Done |
| Mininet topology + live controller connectivity | ✅ Done |
| Trust-aware controller (EdgeScore routing, quarantine drop rules, REST API) | ✅ Done |
| Live dashboard (topology, packets, rules, trust, time-series, ledger) | ✅ Done |
| PRESENT-80 authentication | ✅ Done — live admission + provisioned source-IP pin |
| Six attacks + classifier (named, not just flagged) | ✅ Done — 8/8 detected, 8/8 right family |
| Live-run scorers (NFR, interval, confusion matrix, availability) | ✅ Done |
| Evaluation harness (baselines + Wilcoxon) | ✅ Done — 14/16 comparisons favour the system ([results](docs/EVALUATION.md)) |
| **Full-scale integration (8 edge / 40 IoT / 6 attack classes)** | ✅ **Done** — all four NFRs PASS, 100% honest-node availability |
| Research paper | ✅ Done — [`docs/paper/`](docs/paper/) |
| AI weight optimizer | 🟡 UCB1 (online) done and live, but this run could not separate its arms; Random Forest (offline) pending |
| RAFT consensus | 🟡 Core, TCP transport and 3-replica demo built + tested; **not wired into the live controller** (single local replica) |
| DDoS response | 🟡 Detected and classified, not throttled — needs a per-client-IP flow path |

See [`SOURCE_OF_TRUTH.md`](SOURCE_OF_TRUTH.md) for the consolidated state and the
live-run numbers, and [`DIRECTION.md`](DIRECTION.md) for the novelty analysis and
roadmap. Open limitations are listed in full in the paper (§9) and
`SOURCE_OF_TRUTH.md` §6.

### Headline results

From the full-scale live run (8 edge servers, 40 IoT devices, 6 armed attacks,
215 s) and the 600-run seeded comparison harness:

- **The trust score alone provably cannot isolate a competent liar.** A node that
  under-reports load while still serving correctly floors at `T = 0.44` against an
  isolation threshold of `0.30`. In the live run the sybil and on-off attackers
  were caught **only** by the anomaly gate, while the blackhole attacker was
  caught **only** by the trust score and raised no anomaly at all. Neither rail
  alone catches all four — this is why the gate is necessary, not belt-and-braces.
- **8/8 attacks detected, 8/8 in the right family, 0/40 honest nodes mislabelled**
  (95.8% over all 48 subjects).
- **100% honest-node availability**, zero route denials, no outage.
- **All four NFRs pass** — routing decision 2.02 ms mean, isolation re-dispatch
  51.29 ms mean, ledger overhead 0.130%.
- **19.7–68.8% fewer SLO violations** than incumbent load balancers and
  **15.1–29.8%** fewer than the same selector with trust removed
  (paired Wilcoxon, Holm–Bonferroni, p_adj = 6.94×10⁻⁶, r = +1.00).

---
