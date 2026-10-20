# Zero-Trust SDN for Secure Load Balancing at the Edge — Project Briefing

**Team 50 · 23CSE498 Project Phase 2 · Department of CSE, Amrita Vishwa Vidyapeetham, Coimbatore**
**Guide:** Dr. Radhika N
**Prepared:** 14 October 2026 for a faculty opinion meeting; **refreshed 20 October 2026**
**Repository state:** branch `feature/liar`, head `cf960f7`; all experiment code committed

This document explains everything done so far:
- what we built and how we tested it;
- what we found, including what turned out to be wrong;
- where the system works and where it does not;
- which parts of the repository are outdated;
- where the work can go next.

Every number comes from a recording, a script or a test run on this machine. Where a number is a simulation rather than a live measurement, the text says so.

**What changed since the 14 October version:**
- The Raft ledger is wired into the controller and survived a live leader kill.
- Flooding clients are now throttled in the switches, not only detected.
- The management API and device keys are secured.
- The controller can read a real deployment's addresses from a config inventory.
- The threshold sweep is in the paper.
- **The "pure liar" experiment ran: 80 live runs.** It found a real hole (the *split claim*), the fix for it, and a defect in our own honesty check.
- An offline study shows the switches' own counters can verify the clients' reports.
- The paper is at revision 4, retitled around the liar result.

---

## Contents

1. [Summary in twelve points](#1-summary-in-twelve-points)
2. [The problem](#2-the-problem)
3. [What we built](#3-what-we-built)
4. [How we evaluated it](#4-how-we-evaluated-it)
5. [Findings](#5-findings)
6. [Where the system works, and where it does not](#6-where-the-system-works-and-where-it-does-not)
7. [Open issues](#7-open-issues)
8. [What is outdated or superseded](#8-what-is-outdated-or-superseded)
9. [Honest assessment](#9-honest-assessment)
10. [Where we can go next](#10-where-we-can-go-next)
11. [Questions for the meeting](#11-questions-for-the-meeting)
- [Appendix A — Key numbers](#appendix-a--key-numbers)
- [Appendix B — Live-run history](#appendix-b--live-run-history)
- [Appendix C — Original commitments versus status](#appendix-c--original-commitments-versus-status)
- [Appendix D — Reproducing the results](#appendix-d--reproducing-the-results)
- [Appendix E — Repository map](#appendix-e--repository-map)
- [Appendix F — Glossary](#appendix-f--glossary)

---

## 1. Summary in twelve points

1. **We built a working Zero-Trust SDN load balancer.**
   - An OpenFlow 1.3 controller scores every edge server continuously.
   - It routes each client connection with a trust-aware selector.
   - It enforces quarantine as real flow rules on real Open vSwitch switches.
   - Servers do real work and clients make real TCP requests.
2. **The system has two independent decision rails.**
   - A *trust score* `T = 0.35·R + 0.25·B + 0.25·H − 0.15·A` ranks eligible servers.
   - An *anomaly gate* excludes a server outright when its smoothed anomaly level Ā ≥ 0.5.
   - A server is quarantined when `T < θ` (θ = 0.30) **or** `Ā ≥ 0.5`.
3. **We tested it live, with replication.** There are 120 archived live runs on an 8-server, 40-device emulated edge network. They cover:
   - the ablation (no enforcement / score only / both rails, five runs each);
   - a threshold sweep;
   - a heavy-flood experiment;
   - the liar experiment (80 runs in four batches);
   - a live Raft leader kill.
4. **Enforcement works.** Against the no-enforcement control:
   - delivery ratio 94.4% → 99.3%;
   - timeouts 378 → 43 per run;
   - honest-device availability 85.7% → 99.1%;
   - fairness across honest servers 0.68 → 0.996.
5. **The score alone has a narrow, slow margin.**
   - At θ = 0.30 it never isolated the two attackers that complete every task (0/5); the gate isolated both every time (5/5).
   - At θ = 0.45 the score alone did isolate both, but 3.4× and 20× more slowly.
   - Honest servers under load dip to within a few hundredths of where the liars sit.
6. **The original liar never tested the gate against a working lie.**
   - Our load-misreporting attacker burns CPU, so it is slow.
   - At the shipped ~1% load, its lie ranked *below* honest servers' truthful claims, so it drew less than its fair share of traffic (1.98% against a fair 12.5% under the score alone).
   - The gate caught a slow server, not a lie.
7. **A liar whose lie works exposed a real hole, now closed.** We built liars that serve at honest speed and ran them at 40% occupancy, where a lie can pay.
   - **A consistent lie doesn't pay:** 9.4–10.5% of traffic, and it is contained.
   - **The *split claim* pays and is never caught.** The server lies in the instantaneous load figure the router ranks on, but reports a truthful busy-time counter to the honesty check. It wins **+4.0 points** above fair share and is quarantined 0/5.
   - **Ranking on the verified figure closes it:** +0.01 points, at no measured cost to honest servers. This is now the default, by a decision rule written down before the run that decided it.
8. **The experiment found a defect in our own detector.**
   - At load, the honesty check quarantined 3–4 honest servers per run.
   - The cause was a completion-rate estimator that measured a burst over its own duration.
   - Two fixes cut false quarantines from 3.4 to 0.2 per run.
   - The defect is invisible at the shipped 1% load, so the earlier results stand.
9. **We found a defect specific to data-plane enforcement.** Quarantine tears down in-flight connections, and the resulting timeouts were charged to the innocent server that inherited the flow. The fix attributes only what a node actually received.
10. **Flooding is now throttled, and it helps honest devices.** A per-client OpenFlow meter under a heavy flood:
    - honest mean latency 105 → 92 ms;
    - p95 178 → 139 ms;
    - the flooder's served tasks cut by 97%;
    - no honest device throttled.
11. **The supporting pieces are integrated.**
    - **Raft:** the ledger runs on a 3-replica cluster in live runs. A live leader kill failed over in 0.47 s with 649/649 updates committed and none lost.
    - **Security:** management endpoints take a bearer token, and per-device keys are available.
    - **Deployment:** an address inventory lets the controller run outside Mininet.
12. **We report our own errors.**
    - A "containment versus attribution" trade-off we claimed did not survive replication and is retracted.
    - The "the score is blind" headline was replaced by the measured margin.
    - Every liar-experiment batch was scored against a prediction committed before it ran, including the two predictions that failed.

---

## 2. The problem

Edge computing places workloads on many small, physically exposed, heterogeneously owned servers. Three facts collide there:

- **The perimeter model fails.** A server inside the network can be compromised, rented out, misconfigured or simply selfish. Classical load balancers (round-robin, least-connections) assume every backend is honest about its state and does its work.
- **Schedulers trust self-reported telemetry.** Orchestrators route on what a server says about itself, so a server that under-reports its load attracts traffic.
- **Zero Trust is a policy, not a mechanism.** NIST SP 800-207 says "never trust, always verify, continuously". It does not say how a network control plane verifies *serving infrastructure* (as opposed to users), or how it acts on the verdict in the forwarding path.

**Our question:** can an SDN control plane continuously verify edge servers using what it *observes* rather than what they *claim*, and enforce the verdict in the data plane fast enough to matter?

**Closest prior work.** Load misreporting against SDN load balancers is an established attack, studied at the **switch**:
- Burke et al. 2023 show a compromised switch falsifying its statistics to draw load.
- Yu et al. 2024 add reconnaissance-tuned stealth.
- Saha et al. 2025 detect it with machine learning, without mitigating it.
- SPHINX (NDSS 2015) checks flow statistics between switches.

We study the **server-side** counterpart: a server lying in its own self-report, cross-checked against what the controller observes, with the verdict enforced in the data plane.

---

## 3. What we built

### 3.1 Architecture

```
   40 IoT clients ──► 8 OVS edge switches ──► core switch ──► 8 edge servers
        │                       ▲   OpenFlow 1.3 (flow rules, meters, stats)
        │ /auth  /report        │
        ▼                       │
  ┌───────────────── SDN controller (os-ken application) ─────────────────┐
  │  Northbound REST + Server-Sent Events API (admin endpoints: token)     │
  │  TrustState ── Rail 1: trust score T (EMA, λ = 0.85)                   │
  │            └─ Rail 2: anomaly gate Ā (4 detectors, 1 Hz polling)       │
  │  Edge selector (power-of-two-choices, verified load claim)             │
  │  Graduated response: full · rate-limited (meters) · quarantined        │
  │  Probation (circuit-breaker half-open)   Attack classifier             │
  │  Per-client flood throttle (OpenFlow meter / drop, backoff)            │
  │  PRESENT-80 admission + source-IP pin    UCB1 weight optimizer         │
  │  Ledger (SHA-256 + Merkle) ──► async commit ──► 3 Raft replicas         │
  └────────────────────────────────────────────────────────────────────────┘
                                │
                     Live dashboard (browser)
```

**How routing works.**
- A client never addresses a server directly. It connects to a virtual IP, and the controller rewrites the destination MAC and IP in the data plane. Every routing decision is therefore invisible to the client and revocable by the controller.
- The *request* path writes evidence into the trust state, and the 1 Hz *control* loop reads decisions out of it. The two never share a code path, which is what later made the ablation possible without touching the trust engine.

### 3.2 Components

| Component | Main file(s) | Status | What it does |
|---|---|---|---|
| SDN controller | `controller/trust_balancer.py` | Built, live | OpenFlow 1.3 app on os-ken (the maintained fork of Ryu). VIP rewrite and a two-table pipeline. One cookie per server, so a quarantine deletes all of a server's rules in one `OFPFC_DELETE`. Rule priorities: serving 300, client throttle 280, quarantine drop 400, probation 460. |
| Trust engine (rail 1) | `trust_engine/trust_calculator.py`, `controller/trust_state.py` | Built, live | Per task: R (1.0 success / 0.3 timeout / 0.0 failure); B = max(0, 1 − latency/500 ms); H = max(0, 1 − \|claimed − expected duty\|/0.5); A = anomaly flag. Each is smoothed with λ = 0.85. T is clipped to [0, 1] and starts at 0.5. |
| Anomaly gate (rail 2) | `controller/flow_monitor.py` | Built, live | Polls every server each second. Four detectors: latency tell; timeout-rate tell; CPU-honesty check (claimed busy time against the duty implied by completions the controller saw, abstaining when the controller lacks a full window of evidence); flood tell (keyed on the client). |
| Edge selector | `controller/edge_selector.py`, `controller/trust_state.py` | Built, live | EdgeScore = 0.50·T + 0.30·(1 − load claim) + 0.20·(1 − latency). Excludes ineligible servers *before* ranking, then picks by power-of-two-choices (d = 2) with 5% exploration. Ranks on the **verified** load claim (the busy-time duty the honesty check validates) by default since 20 October; `edge_score.cpu_claim: raw` restores the old behaviour. |
| Graduated response | `controller/trust_state.py` | Built, live | Full service (T ≥ 0.5 and Ā < 0.25); rate-limited via OpenFlow meters (T < 0.5 or Ā ≥ 0.25); quarantined (T < 0.3 or Ā ≥ 0.5). |
| Quarantine, re-steer, probation | `controller/trust_state.py` | Built, live | Quarantine installs drop rules and re-assigns in-flight work. A server quarantined on trust alone, with Ā below the gate, gets one trial task every 5 s. |
| Flood response | `controller/flood_response.py` | Built, live, opt-in | Throttles a flooding client's *new* connections in every switch: a per-client packets/s meter (falls back to drop). Backoff 10 s doubling to 300 s, forgiven after 600 s quiet. |
| Attack classifier | `controller/attack_classifier.py` | Built, live and offline | Names the attack (sybil, blackhole, grayhole, on-off, flood, spoof, bad credentials, or none) from an evidence *window*. The live controller and the offline scorer call the same function. |
| Device admission | `security/present_cipher.py`, `security/authenticator.py` | Built, live | PRESENT-80 challenge–response with single-use nonces, checked against published test vectors, plus a provisioned device-to-IP roster. Per-device keys (HMAC-derived from a master key) are available opt-in. Keys travel in the environment, never on a command line. |
| Management security | `security/admin_auth.py` | Built | Bearer token on `/register`, `/topology/links` and `/monitor/pause` in both arms. The controller refuses to start if a configured token is unset. |
| Trust ledger | `blockchain/ledger.py`, `blockchain/merkle.py` | Built, live | Trust updates batched 10 per block into a hash chain with a Merkle root per block. The dashboard recomputes the chain in the browser. |
| Raft replication | `blockchain/raft*.py`, `blockchain/commit_backend.py` | Built, **live, opt-in** | 3 replica processes with durable state (fsync'd log and vote). The controller is a client: it commits off the request path through an async committer that retries and never silently drops. Leader kill tested live (§5.10). |
| Inventory and deployment | `contracts/inventory.py`, `deploy/` | Built | Addresses come from a config inventory (generated for Mininet, configured for hardware). Per-hardware-class latency baseline. systemd templates. |
| AI weight optimizer | `trust_engine/ai_optimizer.py`, `trust_engine/rf_optimizer.py` | UCB1 live; Random Forest offline | UCB1 chooses among five weight presets online. The Random Forest prior does not beat static weights (§5.13). |
| Live dashboard | `dashboard/`, `controller/northbound_api.py` | Built | Topology, packet animation from real flow counters, flow rules, trust, time-series charts with attack onsets, the ledger with an in-browser tamper check, an analysis page. |
| Test harness | `simulation/topology.py`, `node_agent.py`, `iot_client.py` | Built | Mininet topology (1 core + 8 edge switches, 8 servers, 40 clients). Server agents support real hashing, worker-hold or fixed-work tasks, and optional worker slots. All attacks have a delayed onset, including the liar and stealthy (adaptive) liars. |
| Control arm | `base_model/` | Built, live | The same network and attacks with static routing. Detectors run and publish; nothing acts on them. |
| Evaluation tools | `evaluation/` | Built | 600-run simulation against 4 baselines; scalability sweep; liar model (`liar_sweep.py`); switch-witness study (`witness_offline.py`); NFR, attack, availability and interval reports; replicate aggregator with per-attacker route share. |
| Tests | `tests/`, `base_model/tests/` | **1,240 passing, 11 skipped** | About 2.6 minutes. No root or Mininet needed. |

### 3.3 The live test scenario

Every live run uses the same topology and attack schedule, launched by the same code.

- **Network:** 1 core switch + 8 edge switches (Open vSwitch, OpenFlow 1.3) under Mininet. 8 edge servers, 40 IoT clients, one 4-core host (WSL2, Ubuntu 24.04.4, Python 3.12.3).
- **Workload (ablation, sweep, flood):** each device reports every 2.0 s, with 15 ms of real CPU work per task and a 4.0 s client timeout. That is about 20 requests/s from honest devices, about **1% occupancy** per server.
- **Workload (liar experiment):** the same rate, but each task holds a worker for 320 ms on two workers per server, which is **40% occupancy** without loading the host (§5.11).
- **Run length:** about 310–320 s.

| Attacker | Attack | Starts at | What it does |
|---|---|---|---|
| srv3 | Load misreporting ("Sybil" in code) | 20 s | Burns CPU in the background while claiming 10% load. Completes every task. |
| srv6 | Blackhole | 30 s | Accepts tasks and never answers. |
| srv1 | Grayhole | 40 s | Drops 50% of tasks. |
| srv8 | On-off | 50 s | Alternates honest and lying phases (20 s period, 50% duty). Completes every task. |
| iot37 | Flood | 60 s | Sends far faster than other devices (12 workers at 0.1 s in the heavy-flood arms). |
| iot38 | Identity spoof | 15 s | Holds the fleet key and tries to authenticate as another device. |
| iot39, iot40 | Wrong credentials | at start | Attempt admission with the wrong key. |

In the liar experiment every one of these is removed and a single liar arms on srv3 at 20 s (§5.11).

### 3.4 Scale of the work

- About 52,000 lines of Python including tests; 93 commits since February 2026.
- 1,240 automated tests passing.
- **120 archived live runs (15 GB)** under `data/runs/`, plus the live Raft failover run, earlier single runs 5–13 and two long study runs.
- The paper draft (`paper-draft/`, 14 pages, revision 4), a panel deck and a 44-page panel briefing (`ppt/`).

---

## 4. How we evaluated it

| Level | What | Scale | Used for |
|---|---|---|---|
| Unit tests | Every component, including regression tests for each live-run defect | 1,240 tests | Correctness; pinning findings so they cannot silently regress |
| Simulation | Seeded discrete-event simulation driving the **real** selector, trust calculator and detectors | 600 runs (5 strategies × 4 scenarios × 30 seeds); scalability sweep to N = 64 | Comparison against baselines; scale beyond what the 4-core host can run live |
| Liar model | Discrete-event model of the liar experiment on the real selector and trust calculator | 360 cells | Predictions registered before the live liar runs; landed within ~1 point of live |
| Single live runs | Runs 1–13 (August–September) | 13 runs | Finding and fixing defects (Appendix B) |
| Replicated live runs | Ablation, θ sweep, heavy flood, liar experiment | **120 runs** | Every live claim in the paper |
| Live Raft failover | Leader killed mid-run, restarted, chain checked | 1 run, 649 commits | Raft wired into the controller |
| Offline switch-witness study | Switch counters re-read from every recording | 110 recordings | Whether the switches can verify the clients (§5.12) |

**Statistical method for the live runs.**
- The unit of replication is the run, never the task.
- Continuous metrics are reported as the mean with a 95% Student-t interval across runs.
- Yes/no outcomes are reported as k/n with a Wilson interval: for 5/5 that is [57%, 100%], for 0/5 [0%, 43%].
- With n = 5 per arm we call two arms different only when their intervals do not overlap.
- Arms run in rotating order, so machine drift doesn't land on one arm.

**Registered predictions.** The θ sweep and all four liar-experiment batches had a written prediction committed *before* the batch ran (`docs/predictions/`, and `data/theta_sweep_prediction_2026-09-29.txt`). Each was scored against it, failures included.

**The ablation design.** The *score-only* arm is the shipping controller with one switch changed (`trust.anomaly_rail_enforced: false`). Its config differs from the full system in exactly two keys, and a test pins this. We separated *computing* Ā from *acting* on it, so the score being measured is unchanged.

---

## 5. Findings

### 5.1 Enforcement helps, clearly

Five runs per arm, θ = 0.30, mean with 95% interval. Source: `paper-draft/evidence/replicates/summary.txt`.

| Metric | Control (no enforcement) | Score only | Both rails | Reading |
|---|---|---|---|---|
| Packet delivery ratio | 94.35% [94.15, 94.55] | 99.40% [99.29, 99.52] | 99.25% [99.06, 99.44] | Enforcement helps; rail choice does not |
| Tasks lost to timeout | 377.8 [375.0, 380.6] | 35.4 [26.8, 44.0] | 43.2 [31.0, 55.4] | Enforcement helps; rail choice does not |
| Throughput (tasks/s) | 20.15 [19.44, 20.86] | 19.53 [19.23, 19.84] | 19.72 [19.12, 20.31] | All overlap |
| Mean latency | 87.4 ms [80.0, 94.7] | 98.3 ms [93.7, 103.0] | 91.6 ms [86.8, 96.5] | All overlap |
| p95 latency | 317.8 ms [288.2, 347.3] | 175.6 ms [161.1, 190.2] | **137.2 ms** [128.5, 145.9] | The gate cuts the tail further |
| Honest-device availability | 85.72% [85.63, 85.82] | 99.29% [99.15, 99.43] | 99.13% [98.92, 99.34] | Enforcement helps; rail choice does not |
| Jain fairness, honest servers | 0.676 [0.643, 0.709] | 0.996 [0.994, 0.998] | 0.996 [0.991, 1.000] | Enforcement helps |
| Routes reaching attackers | 29.84% | 17.37% | **11.63%** | The gate's main effect |
| Attacker time isolated | — | 41.38% | **67.13%** | The gate's main effect |
| Honest servers ever quarantined | 0 | 0 | 0 | No false isolation |
| Honest subjects mislabelled | 0 | 0 | 0 | No false accusation |

"—" means *not measured*: the control arm has no quarantine mechanism, so it isn't scored as zero.

**Fairness needs two populations.** Jain's index over all 8 servers barely separates the arms (0.605 / 0.681 / 0.622):
- the control arm is uneven because the flooding device is statically bound to one server;
- the acting arms are uneven because they deliberately starve attackers.

Over the four honest servers the arms separate sharply (0.68 against 0.996).

### 5.2 The ablation at θ = 0.30

| Attacker | Score crossed θ (control / score-only / both) | Quarantined, score only | Quarantined, both rails | Trust at quarantine (both rails) |
|---|---|---|---|---|
| srv6 blackhole | 5/5 · 5/5 · 5/5 | **5/5** | 5/5 | 0.130 |
| srv1 grayhole | 5/5 · 5/5 · 5/5 | **5/5** | 5/5 | 0.220 |
| srv3 load misreporting | **0/5 · 0/5 · 0/5** | **0/5** | **5/5** | **0.710** |
| srv8 on-off | **0/5 · 0/5 · 0/5** | **0/5** | **5/5** | **0.709** |

- **Attackers that fail tasks** drive R down, and the score catches them unaided at the same speed as the gate.
- **The two that never fail a task** never crossed θ = 0.30 in 15 runs; their minimum trust settled at 0.399–0.411. The gate isolated them in every run (medians 7.6 s and 10.4 s) at trust 2.4× the threshold.

### 5.3 The threshold sweep: a narrow, slow band (in the paper)

A written prediction was registered on 29 September. Then the score-only arm ran live at θ = 0.40, 0.45 and 0.50, five runs each.

| Arm | Load-misreporting isolated | On-off isolated | Honest servers quarantined | Routes to attackers |
|---|---|---|---|---|
| Score only, θ 0.30 | 0/5 | 0/5 | 0/5 | 17.37% |
| Score only, θ 0.40 | 0/5 | 1/5 (228.9 s) | 0/5 | 16.56% |
| Score only, θ 0.45 | **5/5** (median 26.2 s) | **5/5** (median 207.3 s) | 0/5 | 13.47% |
| Score only, θ 0.50 | 5/5 (50.1 s) | 5/5 (76.1 s) | **1/5**, plus one attacker quarantined before its attack began | 11.27% |
| Both rails, θ 0.30 | 5/5 (7.6 s) | 5/5 (10.4 s) | 0/5 | 11.63% |

So the score is not blind, but it is slow (3.4× and 20× slower than the gate). Its usable band is a few hundredths wide: honest servers under load dipped to 0.417–0.421. The gate has a wide margin.

### 5.4 Why the score has a floor

For a server that never fails a task, the lowest possible score is `T ≥ α + β·b − δ` (reached only if H → 0 and Ā → 1). That is 0.44 at a 20 ms latency, above θ = 0.30. Two qualifications:
- **The bound is conservative.** The measured minimum was 0.399–0.409 against a predicted 0.302. The honesty term barely registered the lie: the claimed-versus-observed gap averaged 0.084, so H stayed near 0.83.
- **That attacker is not latency-faithful.** It is slow, and its slowness is what the gate's latency tell catches. §5.11 tests liars that are not slow.

A weighted sum is **compensatory** (good service offsets dishonesty); the gate is a **veto**.

### 5.5 Enforcement corrupts its own input

Quarantine installs drop rules, so in-flight TCP connections die. The client's timeout was charged to the healthy server that inherited the flow, which could quarantine it in turn, a positive feedback loop.
- **The fix has no tuned threshold.** An inherited dispatch is stamped at re-assignment, and trust attribution skips it.
- **How much it matters:** it affected 123 of 32,107 reports (0.38%), but that decides whether honest servers get quarantined.

**General lesson:** wherever a verdict is enforced in the data path, the enforcement action is itself an input to the detector.

### 5.6 Detection and classification quality

Over all 48 subjects (8 attackers, 40 honest), five runs per arm:

| | Control | Score only | Both rails |
|---|---|---|---|
| Overall accuracy | 91.67% | 97.92% | 97.50% [96.34, 98.66] |
| Attacks named exactly (of 8) | 4.0 | 7.0 | 6.8 |
| Attacks in the right family (of 8) | 4.0 | 8.0 | 8.0 |
| Honest subjects mislabelled (of 40) | 0 | 0 | 0 |
| Identity spoof admitted | 5/5 runs | 0/5 | 0/5 |

- **The recurring miss:** the blackhole is labelled *grayhole*. It's the right family, one step too mild, because once quarantined it gets too little traffic to accumulate a timeout rate.
- **Two classification limits are documented, not tuned away:**
  - blackhole versus grayhole differ only in magnitude;
  - load misreporting versus on-off differ only in intermittency.

### 5.7 Simulation against four baselines

Seeded simulation with the real selector, trust calculator and detectors; 30 seeds per cell; paired Wilcoxon tests with Holm–Bonferroni correction. Metric: SLO violation rate. Source: `paper-draft/evidence/stats_slo.txt`.

| Scenario | vs least-connections | vs no-trust ablation | vs random | vs round-robin |
|---|---|---|---|---|
| Clean (no attack) | 51.7% better | 6.0% better | **4.8% worse** | **10.7% worse** |
| Load misreporting | 64.6% better | 15.1% better | 29.6% better | 19.7% better |
| Drop | 61.8% better | 25.3% better | 49.4% better | 48.7% better |
| Both | 68.8% better | 29.8% better | 52.3% better | 48.5% better |

- **14 of 16 comparisons favour our system.**
- **The p-values need a caveat.** p_adj = 7.45 × 10⁻⁹ is the test's floor at n = 30, when every seed wins.
- **The two losses are real.** With no attack, stale load information (a 1 s poll against ~0.1 s tasks) costs us against random and round-robin.

### 5.8 Selection, starvation and scale

- **Argmax starves servers:** it routed to only about 2 servers regardless of fleet size. It was replaced by power-of-two-choices with 5% exploration.
- **p2c scales linearly (simulation):** 48 → 762 tasks/s from N = 4 to 64, with delivery 99.7–99.8%. Argmax saturates near 85 tasks/s.
- **p2c is not a CPU win:** both selectors cost 3–30 µs per decision.
- **The capacity cliff:** with 4 servers and 2 attackers, isolating half the fleet saturates the honest half. The defence needs spare capacity.

### 5.9 Non-functional requirements

Over the five both-rails runs (`paper-draft/evidence/nfr_replicates.txt`), and the live Raft run for the Raft row:

| Requirement | Target | Measured | Verdict |
|---|---|---|---|
| Routing decision (packet-in → flow-mod) | < 200 ms | mean 0.54–0.55 ms, p95 0.71–0.73 ms | Pass |
| Isolation (re-dispatch after decision) | < 3,000 ms | mean 12.9–23.5 ms | Pass |
| Ledger overhead | < 15% of task latency | 0.045–0.052% | Pass |
| Raft commit | < 500 ms | **live**: mean 14 ms, p95 20 ms over 649 blocks | Pass |

**Caveat:** isolation is measured from *decision* to re-dispatch. From *attack onset* to isolation is dominated by detection, with medians of 6–16 s.

### 5.10 Raft, wired and tested live

- **The controller commits off the request path** to a 3-replica cluster (`ledger.backend: raft_remote`), via an async committer that retries and never silently drops a batch. Replicas persist term, vote and log with fsync, so a restarted replica rejoins with its log.
- **Live leader kill (19 October):** the leader was killed with SIGKILL mid-run. Results:
  - failover in **0.47 s** (term 2 → 4);
  - **649/649** batches committed, with none dropped and one retry;
  - the killed replica restarted and caught up in **1.0 s**;
  - blocks were contiguous and correctly hash-linked across the change of term;
  - routing p95 stayed at 0.77 ms.

  Archived in `data/raft_failover_2026-10-19/`.
- **Still crash-fault only.** A malicious replica is not tolerated, and the controller is not re-verified by the replicas (§10).

### 5.11 Liars whose lie works (in the paper as §VII-E)

**Why.** Re-scoring the ablation showed the shipped load-misreporting attacker drew *less* than its fair share in every arm, 1.98% under the score alone, because:
- at ~1% occupancy an honest server truthfully reports ~0 load, so a lie of 0.1 ranks below the truth;
- its CPU burning makes it slow, so its trust drops.

**Design.**
- **New liars that burn no CPU:**
  - *consistent*: its busy-time counter is faked to agree with its claim of 0;
  - *split claim*: it lies only in the instantaneous load figure and reports a truthful busy-time counter;
  - *adaptive*: it reads its peers' claims from the controller and undercuts them inside the honesty threshold.
- **Occupancy raised to 40%** by holding workers rather than computing.
- **One liar on srv3** with every other attack removed.
- **An offline model** on the real selector predicted every arm first; it landed within ~1 point of live.
- **The ceiling:** under p2c with 5% exploration, a liar that wins every comparison is capped at 24.4% of traffic, however large the lie.

**Results** (5 runs per row, share of routing decisions after onset, fair share 12.5%):

| Liar | Routing, detector | Share | Quarantined |
|---|---|---|---|
| Consistent | raw, shipped | 9.37% [9.05, 9.68] | 5/5, median 8.2 s |
| Consistent | raw, fixed | 10.29% [9.99, 10.60] | 5/5, median 6.4 s |
| Adaptive | raw, fixed | 11.34% [10.97, 11.71] | 5/5, median 17.7 s |
| **Split claim** | **raw, fixed** | **16.50% [15.97, 17.02]: +4.00 points** | **0/5** |
| Split claim | **verified**, fixed | 12.51%: +0.01 [−0.28, +0.30] | — |
| Consistent at 1% load | raw, fixed | 10.14% [8.92, 11.36] | 0/5 |
| Consistent at 1% load | verified, fixed | 13.58% [11.97, 15.19]: +1.08 [−0.53, +2.69] | 0/5 |

**What this establishes.**
- **A consistent lie doesn't pay.** The honesty term costs it trust on every task, and p2c settles each comparison on score.
- **The split claim pays and evades both rails.** Routing ranked on the raw claim, while the honesty check verified the busy counter. Each code path was correct on its own; the hole was between them. No design review flagged it; a liar built to use it did.
- **Ranking on the verified figure closes it**, with honest latency unchanged (396.2 against 396.4 ms). At 1% load the verified ranking gives a consistent liar more than raw ranking does, but not measurably more than its fair share. By the pre-registered rule, `verified` is now the default, and every config behind a recorded run pins `raw` so it still replays.

**The defect it exposed in our own honesty check.**
- In the first batch, every arm, the control included, quarantined 3.0–4.4 honest servers per run, all through the honesty check.
- **Cause:** the completion rate was measured up to the *last* completion rather than to *now*, so a burst followed by quiet read as about 3× the real rate.
- **Evidence:** rebuilt at 119 firings, the expected duty was 0.81 as computed and 0.30 with the span ending now.
- **Second, smaller defect:** the check judged partial windows during the synchronized start of all forty clients.
- **Result:** honest false quarantines per run went 3.4 → 1.4 → **0.2** across the three batches.
- **Scope:** both defects are invisible at 1% load (the ablation recorded no honesty firing on an honest server), so the earlier results stand.

The full trail, predictions and outcomes, is in `docs/predictions/` and `paper-draft/evidence/liar/`.

### 5.12 The switches can verify the clients (offline; not yet live)

Every recording already holds OpenFlow counters for each connection's two VIP rules. Re-read from 110 recordings (`docs/WITNESS_OFFLINE.md`):
- **The switches and the clients agree.** Connections the switches saw a server answer, divided by the successes clients reported, per honest server per run: median **0.9992** (p5 0.9917).
- **The switches see dropped work without any client report.** The share of a server's connections that got no full response is 0.3% for honest servers, against 50% for the blackhole and 36% for the grayhole.
- **What a live check must handle:**
  - connections the controller itself re-steered look unanswered;
  - the switches' baseline traffic differs between workloads, so compare each server with the fleet, not a constant.

This is the basis for a live two-witness check (§10).

### 5.13 Flood response, the AI optimizer, and engineering lessons

**Flood response.** Heavy flood, throttle off (5 runs) against on (4 usable runs), measured over honest devices only:

| | Off | On |
|---|---|---|
| Honest mean latency | 105.0 ms [101.2, 108.9] | 91.7 ms [89.4, 94.0] |
| Honest p95 latency | 177.7 ms [160.9, 194.5] | 139.4 ms [132.9, 145.8] |
| Flooder's served tasks | 8,951 | 293 |

- The flooder's served tasks fell by 97%, and no honest device was throttled.
- Honest task success overlaps between the two arms.
- **Metric trap:** run-wide throughput and mean latency move the "wrong" way purely because the flooder's tasks dominate them. Always split honest from attacker.

**AI optimizer.** UCB1 chooses among five weight presets online. The Random Forest warm-start prior did not beat static weights.

**Engineering lessons.** Every serious live-run failure came from the controller's own bookkeeping feeding correct detectors with wrong input, never from the detectors themselves (Appendix B):
- start-up order;
- the stale-dispatch reaper;
- quarantine as an absorbing state;
- the dispatch-count leak;
- the honesty fallback;
- the spoof start-up race;
- re-steered timeouts;
- now the completion-rate span.

Two diagnostic methods came out of this:
- **Little's law:** comparing predicted with actual in-flight counts.
- **Replay versus re-run:** a defect inside a feedback loop needs a live re-run; a replay won't show it.

### 5.14 Corrections and retractions

| Earlier claim | What replication showed | Status |
|---|---|---|
| Faster containment costs attack-label accuracy | ρ = −0.52, p = 0.12, n = 10: not supported | Retracted in the paper |
| Enforcement costs mean latency / throughput | All three arms' intervals overlap | Withdrawn |
| "The score is blind to faithful liars" | The θ sweep shows a narrow, slow band | Rewritten in the paper |
| "The gate catches load liars" | The tested liar was slow and its lie repelled traffic; a working lie (split claim) evaded both rails | Qualified; hole found and closed (§5.11) |
| Honest servers are never falsely quarantined | True at 1% load; at 40% the honesty check had a defect | Defect fixed (§5.11) |
| Panel deck numbers (September) | Scored against a recording a later run overwrote | Superseded (§8) |

---

## 6. Where the system works, and where it does not

### 6.1 Validated in live emulation

| Situation | Evidence |
|---|---|
| Servers that fail tasks (blackhole, grayhole) | Isolated in every enforcing run, median 10–16 s |
| Servers that lie and slow down doing so | Isolated by the gate in 5/5 runs, median 7.6 s and 10.4 s |
| Servers that lie at honest speed with consistent claims | Below fair share; contained 5/5, median 6.4 s |
| Split-claim liars | Gain closed by verified-claim routing (+0.01 points), now the default |
| Honest servers under these attacks | 0 false quarantines at 1% load; 0.2 per run at 40% load after the fixes |
| Identity spoofing with the fleet key | Refused in every acting run |
| Flooding client | Throttled; honest p95 178 → 139 ms under a heavy flood |
| Ledger leader failure | Failover 0.47 s, no update lost |
| Recovering a wrongly quarantined server | Probation |
| Routing decision speed | Sub-millisecond mean |

### 6.2 Works, with conditions

- **Spare capacity is required.** The defence removes capacity.
- **The poll interval bounds detection:** 6–16 s from onset to isolation.
- **Without attacks the system pays a small price:** 5–11% more SLO violations than random or round-robin in simulation, from stale load information.
- **Score-only enforcement has a margin of a few hundredths** (§5.3).
- **Verified-claim routing** removes the split claim's gain at load. At 1% load it slightly favours a consistent liar relative to raw routing (not above fair share).

### 6.3 Not covered, or not working

| Gap | Why it matters |
|---|---|
| Adaptive attackers that search the defence | Our adaptive liar follows one rule (undercut peers inside the honesty threshold). An attacker that tunes its busy counter against the threshold across loads is not measured. |
| Badmouthing clients, misreporting switches, collusion | Trust still depends on client reports. The switch-witness study (§5.12) shows the switches could check them; the live check is not built. |
| Honest-but-slow servers on mixed hardware | Not tested. An idle honest server that is throttled matches the latency tell's "claims idle, answers slowly" rule. Next experiment (§10). |
| Controller compromise | The controller is fully trusted. Replicas could re-verify its trust arithmetic; not built. |
| Byzantine replicas | Raft tolerates crashes, not malicious replicas. |
| Dashboard and read-only API; no TLS | Admin endpoints take a token, but the dashboard and GET endpoints are open and traffic is plain HTTP. Keep the management network separate. |
| Device keys | PRESENT-80 is an architecture demonstration. Per-device keys exist but were not used in the experiments. |
| Drop tell on few samples | It judges on as few as 4 outcomes. In a synthetic replay with injected random timeouts this caused rare honest quarantines; no live run showed it. |
| Scale and realism | 8 servers on one 4-core host; larger scale is simulation only. No physical hardware yet. |
| Remote attestation | Real Zero Trust deployments verify infrastructure with hardware attestation first. Not built (feasibility checked: a software TPM works on this host). |

### 6.4 Real-world applicability

**The idea transfers; this implementation does not.**
- **The idea:** rank on one rail, exclude on a separate non-compensatory rail, verify claims against observations, enforce in the data path, and **route on what you verify**. Production service meshes already separate ranking from ejection: Envoy uses p2c, plus outlier detection on errors and success rates.
- **Part of the vulnerability is self-inflicted.** Our selector deliberately schedules on claimed load. Balancers that rank only on their own observations are not attracted by load lies.
- **The implementation is research-grade:** a single Python controller on OpenFlow, where industry uses proxies, service meshes and eBPF.

**Where it fits:** multi-access edge computing at 5G sites (following ETSI MEC 003); industrial and factory edge; smart-campus and smart-city gateway clusters; federated or volunteer edge compute.

**Where it doesn't:** public cloud data centres, inter-domain routing, consumer IoT products.

**Most likely software outcomes:**
1. An open-source attack-and-scoring benchmark (the `turncoat-sdn` effort).
2. A latency-aware ejection controller for Envoy or Kubernetes.
3. A teaching lab built from the Mininet scenario and dashboard.

---

## 7. Open issues

| Issue | Severity | Detail | Action |
|---|---|---|---|
| Recordings exist on one disk only | **High** | `data/` is gitignored and now holds **15 GB in 120 runs**, plus the Raft failover run. One earlier run (run 7) and the first 632-block Raft run were already lost. | External drive plus Zenodo (gives a DOI for the paper) |
| AI-use declaration has a broken sentence | **High** | The 19 October edit left "…evaluation tooling; of §VII-D came about." The narrowed wording also no longer matches the assistance given. | Fix the sentence; decide the scope of disclosure |
| Ledger: a rejected batch blocks the commit queue | Medium | `AsyncCommitter` retries a deterministically rejected batch forever, so every later batch waits. Not triggered today, because nothing rejects. | Fix in Phase 6 (replica verification) |
| Ledger: the local backend drops a failed batch silently | Medium | The flush clears pending updates even when the in-memory ledger refuses them. | Count as dropped; Phase 6 |
| Project portal is stale | Medium | The team website still shows the September headline, old test counts, "Raft not wired" and single-run numbers. | Update from the paper (critique sent to the team) |
| Paper details | Medium | Per-class recall missing; 14 pages against a typical 6–8 limit; venue and template not chosen; two reference page ranges to confirm | `paper-draft/CHECKLIST.md` |
| Repository clutter | Low | Three committed copies of `base_model` (.zip, .tar, "(2).zip"), Windows `Zone.Identifier` files, overlapping Markdown at the root | `git rm`; consolidate documents |
| Old README | Low | Still says 669 tests and points to the old paper | Update |

Resolved since 14 October:
- the run code is committed (but no `runs-2026-09-29` tag was ever made; `git tag` lists none);
- the AI declaration was restored (then edited, see above);
- the paper headline was rewritten;
- Raft is wired;
- the management endpoints are secured.

---

## 8. What is outdated or superseded

### 8.1 Documents

| Item | Date | Why it is outdated | Current source |
|---|---|---|---|
| `docs/paper/zero-trust-sdn-paper.docx` | 16 Aug | Earlier paper; the 0.44 "trust floor" headline from one run | `paper-draft/` (revision 4) |
| `ppt/sections_1_2_3.tex` / `.pdf` and `data/comparison/` | 7–8 Sep | Scored against a single-run recording a later run overwrote | `paper-draft/evidence/replicates/` |
| `ppt/PANEL_REVIEW_BRIEF.pdf` | 8 Sep | Predates the replicate campaign, the θ sweep and the liar experiment | This briefing |
| The team documentation portal | Sep | September headline and numbers | This briefing; the paper |
| `docs/study/trust-routing-study.html` / `.pdf` | July | Argmax selector, before the p2c fix | §5.8, `docs/LOAD_BALANCING_STARVATION.md` |
| `DIRECTION.md`, `PROBLEM_AND_IMPACT.md` | 17 Jul | Components "not started" that were built since; old test counts. The problem analysis is still valid. | §2, §3.2 |
| `SOURCE_OF_TRUTH.md` | 3 Sep | Predates the replicate campaign; run-by-run detail is still accurate | §5, Appendix B |
| `README.md` | 3 Sep | 669 tests; points to the old paper | §3.2 |
| `SETUP.md`, `final_run.md` platform notes | Aug–Sep | Say Ubuntu 26.04 / Python 3.14. Experiments ran on WSL2 Ubuntu 24.04.4, Python 3.12.3. | §3.3 |
| `explain*.md`, `plan*.md`, `panel_fix.md` | Jul–Sep | Working notes | This briefing |

### 8.2 Technology choices that are dated

| Choice | Why it is dated | What industry or research uses now |
|---|---|---|
| OpenFlow 1.3 server load balancing | Production load balancing moved to proxies, meshes and eBPF | Envoy, Istio, Linkerd, Cilium, Katran |
| os-ken / Ryu controller | Research-grade, single process | ONOS, OpenDaylight; xDS control planes |
| PRESENT-80 | 80-bit keys are below modern margins | Mutual TLS, SPIFFE/SPIRE, EDHOC/OSCORE for constrained IoT |
| "Blockchain" ledger | Crash-fault Raft plus a hash chain is a tamper-evident log, not a blockchain | Signed append-only logs; transparency logs |
| Weighted additive trust score | Compensatory | Veto rules / outlier ejection alongside ranking (our gate) |
| Behaviour-only verification | Zero Trust deployments verify infrastructure by attestation first | TPM remote attestation (Keylime, RFC 9334), behaviour as a second layer |

---

## 9. Honest assessment

| Dimension | Rating | Change since 14 Oct | Reasoning |
|---|---|---|---|
| Engineering and testing | 8.5 / 10 | — | Real OpenFlow enforcement, 1,240 tests, a regression test for every live-run defect, Raft wired and failover-tested, a security baseline |
| Experimental method | 8 / 10 | +0.5 | Run-level replication, Wilson intervals, a clean ablation, **four registered predictions scored including failures**, a model checked against live, a retraction. Still n = 5, one host, one topology. |
| Research novelty | 5 / 10 | +1 | The split claim (route on what you verify), positioned as the server-side counterpart of switch-misreporting work, is a concrete, measured finding with a fix. The two-rail idea itself is known. |
| Paper | 7 / 10 | +2 | Revision 4 leads with a real hole and its fix, cites the closest prior work, reports failures. Too long for most venues; venue not chosen. |
| Real-world readiness | 3 / 10 | +0.5 | Deployable outside Mininet in principle (inventory, tokens, Raft), but untested on hardware |

**As a final-year project** this is well above the typical "Zero Trust + blockchain + SDN + AI" project.

**As a publication** it is now a solid workshop paper and a credible short conference paper. A hardware testbed, the live switch-witness check, or an adaptive attacker would strengthen it further.

---

## 10. Where we can go next

### 10.1 Immediate plan (no hardware)

| Step | Effort | What |
|---|---|---|
| 1. Honest-slow versus lying | ~1 week + ~1.5 h of runs | Emulate slower hardware and thermal throttling with cgroup `cpu.max` (feasibility passed). Measure honest false quarantines with fleet versus per-class latency baselines, a throttled honest server, and a liar among mixed hardware. Prerequisite for the testbed. |
| 2. Live two-witness check | ~2–3 weeks + ~2 h of runs | Build the switch-witness signal (§5.12), a misreporting-switch emulation and a badmouthing client. Measure each single liar, and document collusion as a limitation. |
| 3. Attestation + behaviour | ~1.5 weeks | Software quote (or swtpm) at admission; show attestation catches tampered code and behaviour catches run-time compromise |
| 4. eBPF kernel witness | ~1.5 weeks | Per-server on-CPU and service time from the kernel (bpftrace and BCC work on this host) |
| 5. Replicas re-verify the controller | ~1.5 weeks | Replay the trust arithmetic on each replica and reject forged scores. Also fixes the two ledger issues in §7. |

Steps 3–5 are independent and fill the gaps while live runs are going. If the deadline is close, stop at a phase boundary.

**Hardware testbed (separate track).**
- **Stage A:** 2–3 lab PCs joined by VXLAN.
- **Stage B:** 8 Raspberry Pis (4 × Pi 5, 4 × Pi 4) with coolers, a managed gigabit switch with VLANs, a controller PC, 3 Raft hosts and 2 client laptops.

The deploy kit (`deploy/`) and inventory are ready. The agent has a fixed-work task mode, so hardware differences now show.

### 10.2 Six directions (unchanged; status updated)

| | Direction | Status |
|---|---|---|
| D1 | Safe ejection of slow servers (gray failure) | Next (step 1 above) |
| D2 | Adaptive adversaries | Partly done: the split claim and the rule-following adaptive liar. A searching attacker remains. |
| D3 | Self-reported telemetry elsewhere | Not started; the split claim generalises to any scheduler that ranks on one self-report and verifies another |
| D4 | Attestation plus behaviour | Planned (step 3) |
| D5 | eBPF/XDP | Planned (step 4) |
| D6 | Our evaluation method as a contribution | Strengthened: registered predictions, model-versus-live, the defect the experiment found |

### 10.3 Dead ends to avoid

- More attacks, panels or ledger features on the current stack.
- More "blockchain for trust".
- Tuning trust weights.
- ML intrusion detection on public datasets.
- A startup from this codebase.

---

## 11. Questions for the meeting

1. **Paper framing.** Is "what catches a lie that works: the split claim, and route on what you verify" the right headline, with the score-versus-gate ablation as the setting?
2. **Venue and timing.** IEEE NetSoft or CNSM workshops, IEEE ANTS, COMSNETS, IEEE CCNC, or ICC/Globecom workshops? The paper is 14 pages and must be cut.
3. **Verified routing as the default.** It was adopted by a pre-registered rule. Is changing a default in the middle of the project acceptable, given that every recorded experiment pins its old setting?
4. **Remaining semester.** Honest-slow servers first (needed for hardware), then the live two-witness check? Or the hardware testbed first?
5. **Hardware.** Can the department provide lab machines, Raspberry Pis or a managed switch?
6. **Authorship and AI disclosure.** What does the department expect for CRediT roles and for disclosing AI assistance?
7. **Scope of claims.** Raft is crash-fault only and the controller is trusted. Is that acceptable as stated?

---

## Appendix A — Key numbers

| Quantity | Value | Source |
|---|---|---|
| Tests | 1,240 passed, 11 skipped | `pytest tests/ base_model/tests/`, 20 Oct |
| Live runs archived | 120 (25 arms), ~310–320 s each, 15 GB | `data/runs/manifest.csv` |
| Delivery ratio, control → both rails | 94.35% → 99.25% | replicates summary |
| Honest-device availability, control → both rails | 85.72% → 99.13% | replicates summary |
| Attacker route share: control / score only / both rails | 29.84% / 17.37% / 11.63% | replicates summary |
| p95 latency: control / score only / both rails | 317.8 / 175.6 / 137.2 ms | replicates summary |
| Load-misreporting and on-off isolated at θ = 0.30, score only versus both rails | 0/5 versus 5/5 each | replicates summary |
| θ = 0.45 score only: isolated | 5/5 (26.2 s) / 5/5 (207.3 s) | θ-sweep summary |
| Shipped liar's post-onset route share, score only | 1.98% (fair 12.5%) | replicates summary |
| Split claim, raw routing | 16.50%, +4.00 [3.47, 4.52] points, quarantined 0/5 | `evidence/liar/batch2` |
| Split claim, verified routing | +0.01 [−0.28, +0.30] points | `evidence/liar/batch2` |
| Consistent liar | 9.4–10.5%, contained 5/5, median 6.4–8.2 s | `evidence/liar/` |
| Honest false quarantines at 40% load | 3.4 → 1.4 → 0.2 per run | `evidence/liar/` |
| Liar model against live | within ~1 point; p2c ceiling 24.4% | `docs/LIAR_BOUND.md` |
| Switch versus client agreement | median 0.9992 per honest server-run | `docs/WITNESS_OFFLINE.md` |
| Heavy flood, honest p95, throttle off → on | 177.7 → 139.4 ms; flooder −97% | `paper-draft/evidence/flood/` |
| Raft live failover | 0.47 s; 649/649 committed; rejoin 1.0 s; commit mean 14 ms | `data/raft_failover_2026-10-19/` |
| Routing decision | mean 0.54–0.55 ms | NFR report |
| Simulation | 14/16 comparisons favour the system | `stats_slo.txt` |
| Retracted trade-off | ρ = −0.52, p = 0.12, n = 10 | replicates summary |

## Appendix B — Live-run history

| Run | Date | What happened | What it led to |
|---|---|---|---|
| Study runs A, B | Jul | An honest server starved for 2,238.8 s | Power-of-two-choices + exploration |
| 1–4 | 1 Aug | Collapses: start-up order, reaper horizon, absorbing quarantine, dispatch-count leak | Each fixed and pinned by a test |
| 5 | 2 Aug | First clean full-scale run | Two-rail design confirmed live |
| 6–8 | 3–7 Aug | Honesty-term wiring; run 7's 175/175 false honesty firings (not archived) | Honesty fallback split; spoof keyed on source IP |
| 9–11 | 8–9 Aug | Spoof start-up race; first 8/8 exact labels; re-steer attribution fix | Provisioned roster; attribution fix |
| 12–13 | Sep | Dashboard runs | — |
| Control arm run 1 | 5 Sep | First run of `base_model/` | Load-window parity fix |
| Replicate campaign | 29 Sep | 15 runs: control / score only / both rails | The ablation |
| θ sweep | 29 Sep | 15 runs at θ 0.40 / 0.45 / 0.50 | §5.3 |
| Raft live run | 15 Oct | 632 blocks in term 2. **Recording later overwritten** | Recordings now archived automatically |
| Flood throttle run | 18 Oct | Meters work on WSL2 OVS; only the flooder throttled | Heavy-flood experiment |
| Heavy flood | 18 Oct | 10 runs, throttle off/on (one run invalid: host slept) | §5.13 |
| Raft leader kill | 19 Oct | Failover 0.47 s, 649/649 | §5.10 |
| Liar batch 1 | 20 Oct | 25 runs; split claim +4.5 points; honest false quarantines exposed | Completion-rate fix |
| Liar batch 2 | 20 Oct | 30 runs; split claim never caught; verified routing closes it | Warm-up fix |
| Liar batch 3 | 20 Oct | 15 runs; honest false quarantines 0.2 per run | Phase 1 complete |
| Shipped-load check | 20 Oct | 10 runs; no measurable liar gain from verified routing | Verified routing becomes the default |

## Appendix C — Original commitments versus status

| Commitment (project deck / SRS) | Status |
|---|---|
| Zero Trust continuous verification | Done: 1 Hz verification plus per-task scoring, enforced in the data plane |
| Trust formula T = αR̄ + βB̄ + γH̄ − δĀ, EMA λ = 0.85 | Done, unchanged; its limits are a finding (§5.2–5.4) |
| PRESENT-80 device authentication | Done, plus a source-IP pin; per-device keys available |
| Blockchain trust ledger (SHA-256 + Merkle) | Done |
| Raft replication, 3 replicas | **Done and wired** (opt-in); live leader kill passed |
| Ryu SDN controller | Replaced by os-ken (maintained fork, same API) |
| EdgeScore routing | Done; argmax → power-of-two-choices; now ranks on the verified load claim |
| AI weight optimizer (Random Forest offline + UCB1 online) | Both built; UCB1 live; the Random Forest does not beat static weights |
| Evaluation: 4 baselines, 30 runs per scenario, Wilcoxon | Done (600 runs, Holm–Bonferroni), plus 120 replicated live runs |
| Scale: 8 servers / 40 IoT / 3 malicious | Done live |

## Appendix D — Reproducing the results

All commands run from the repository root.

```bash
# Unit tests (no root, no Mininet), about 2.6 minutes
python3 -m pytest tests/ base_model/tests/ -q

# Re-score every number in the paper from the archived recordings
paper-draft/tools/regenerate.sh

# The liar model (the registered predictions) and the switch-witness study
python3 -m evaluation.liar_sweep --seeds 5
python3 -m evaluation.witness_offline data/runs

# Score one liar batch
python3 -m evaluation.replicates data/runs --arms liarfix_honest,liarfix_c_treat,liarfix_t_treat,liarfix_stealthy,liarfix_t_verified,liarfix_honest_verified

# Feasibility checks for the next phases (root; installs nothing)
sudo tools/feasibility_check.sh

# Build the paper
make -C paper-draft

# Live runs (root, Open vSwitch, Mininet; about 6 minutes per run)
sudo ARMS="liarfix3_honest liarfix3_c_treat" tools/run_replicates.sh
```

A single `run_demo.py` run now moves any previous recording into `data/archive/` instead of deleting it. `tools/run_replicates.sh` archives each run under `data/runs/<arm>/`. WSL2 prerequisites are in `SETUP.md`.

## Appendix E — Repository map

| Path | Contents |
|---|---|
| `controller/` | The SDN application: trust state, flow monitor (anomaly gate), edge selector, attack classifier, flood detector and response, northbound API, event bus, flow statistics |
| `trust_engine/` | Trust calculator; UCB1 and Random Forest weight optimizers |
| `security/` | PRESENT-80 cipher, device authenticator, admin token and per-device keys |
| `blockchain/` | Merkle tree, ledger, commit backends (local, remote Raft, async committer), Raft core, transport, replica |
| `contracts/` | Shared data contracts, thresholds, the address inventory |
| `simulation/` | Mininet topology, server agents (attacks, liars, work modes), IoT clients, addressing |
| `base_model/` | The no-enforcement control arm and its comparison tools |
| `evaluation/` | Baselines, statistics, scalability sweep, liar model, switch-witness study, NFR / attack / availability / interval reports, replicate aggregator |
| `dashboard/` | Live dashboard, replay tool, demo recording generator |
| `config/` | Run configurations: one per arm, each pinned by a test |
| `deploy/` | Testbed deployment kit: systemd templates, inventory example |
| `tools/` | Replicate runner, θ-sweep config derivation, Raft failover check, feasibility checks, device keys |
| `docs/` | Topic documents (Raft, liar bound, switch witness, feasibility), **`predictions/`** (every registered prediction and its outcome), and this briefing |
| `paper-draft/` | The paper, `NUMBERS.md` (every number → artifact → command), `CHECKLIST.md`, evidence |
| `ppt/` | Panel Review 1 deck, figures and the 44-page briefing |
| `tests/` | The test suite |
| `data/` | Recordings and derived outputs (gitignored, local only) |

## Appendix F — Glossary

| Term | Meaning |
|---|---|
| θ (theta) | The isolation threshold on the trust score; 0.30 as shipped |
| Ā | The smoothed anomaly level from the four detectors; the gate fires at 0.5 |
| Rail | An independent route to a quarantine decision; we have two (trust score and anomaly gate) |
| Ablation | Removing one mechanism and re-running everything else unchanged |
| Arm | One experimental condition |
| Occupancy | The fraction of a server's worker time spent on tasks; ~1% in the shipped workload, 40% in the liar experiment |
| Split claim | Lying in the load figure the router ranks on while reporting truthfully in the figure the honesty check verifies |
| Verified claim | Routing on the busy-time duty the honesty check validates, rather than the raw instantaneous claim; the default since 20 October |
| Registered prediction | A written prediction committed to the repository before the runs that test it |
| Quarantine | Installing drop rules for a server and re-assigning its in-flight work |
| Re-steer | Moving an in-flight client flow from a quarantined server to a healthy one |
| Probation | One trial task every 5 s for a server quarantined on trust alone |
| Power-of-two-choices (p2c) | Pick two candidates at random and send to the better one |
| Wilson interval | A confidence interval for a proportion that is accurate at small n |
| Gray failure / fail-slow | A partial failure where a component still responds, but slowly or incorrectly |
| Remote attestation | A machine proving, with a hardware-signed report, what software it booted |
| NFR | Non-functional requirement (latency, overhead and similar targets from the SRS) |
