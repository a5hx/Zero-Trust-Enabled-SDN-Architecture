# Zero-Trust SDN for Secure Load Balancing at the Edge — Project Briefing

**Team 50 · 23CSE498 Project Phase 2 · Department of CSE, Amrita Vishwa Vidyapeetham, Coimbatore**
**Guide:** Dr. Radhika N
**Prepared:** 14 October 2026, for a faculty opinion meeting
**Repository state:** branch `feature/ai-optimizer`, head `27ed08d` plus uncommitted changes (listed in §7)

This document explains everything done so far: what we built, how we tested it, what we found (including what turned out to be wrong), where the system works and where it does not, which parts of the repository are outdated, and where the work can go next. Every number comes from a recording, a script or a test run on this machine. Where a number is a simulation and not a live measurement, it says so.

---

## Contents

1. [Summary in ten points](#1-summary-in-ten-points)
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

## 1. Summary in ten points

1. **We built a working Zero-Trust SDN load balancer.** An OpenFlow 1.3 controller scores every edge server continuously, routes each client connection with a trust-aware selector, and enforces quarantine as real flow rules on real (Open vSwitch) switches. Servers do real CPU work and clients make real TCP requests.
2. **The system has two independent decision rails.** A *trust score* `T = 0.35·R + 0.25·B + 0.25·H − 0.15·A` ranks eligible servers, and an *anomaly gate* excludes servers outright when its smoothed anomaly level Ā ≥ 0.5. A server is quarantined when `T < θ` (θ = 0.30) **or** `Ā ≥ 0.5`.
3. **We tested it live, with replication.** 30 archived live runs on an 8-server, 40-device emulated edge network with six attacks armed in every run. The original three arms (no enforcement / score only / both rails) have five runs each, plus a threshold sweep (score only at θ = 0.40, 0.45, 0.50) with five runs each.
4. **Enforcement works.** Against the no-enforcement control: delivery ratio 94.4% → 99.3%, timeouts 378 → 43 per run, honest-device availability 85.7% → 99.1%, fairness across honest servers 0.68 → 0.996. No honest server was ever quarantined and no honest subject was ever labelled as an attacker, in any of the 15 runs at the shipped threshold.
5. **The score alone misses two attacks at the shipped threshold.** The two attackers that never fail a task (a load-misreporting "Sybil" and an on-off attacker) never crossed θ = 0.30 in 15 runs and were never isolated by the score alone (0/5). The gate isolated both in every run (5/5), while their trust was about 0.71.
6. **The threshold sweep qualifies finding 5.** At θ = 0.45 the score alone did isolate both (5/5) with no honest server quarantined, but 3.4× and 20× slower than the gate. Honest servers under load dipped to 0.417–0.421 in other runs, and at θ = 0.50 an honest server was quarantined. **So the score is not blind; its usable threshold band is narrow and slow, while the gate has a wide margin and is fast.** The paper draft has not yet been updated with this.
7. **The gate buys containment, not service.** Between score-only and both-rails, delivery, throughput, mean latency, availability and fairness all overlap. The gate's measured gains are attacker traffic share (17.4% → 11.6%), attacker time isolated (41% → 67%) and p95 latency (176 → 137 ms).
8. **We found a defect specific to data-plane enforcement.** Quarantine tears down in-flight TCP connections, and the resulting client timeouts were charged to the innocent server that inherited the flow. This drove honest servers into quarantine. The fix (attribute only what a node actually received) fires on 0.38% of reports and needs no tuned threshold.
9. **We retracted one of our own earlier claims.** A "containment versus attribution" trade-off we claimed from three single runs did not survive replication (ρ = −0.52, p = 0.12, n = 10).
10. **Supporting pieces are built but some are not integrated.** Raft consensus works standalone (0.21 s failover) but the live controller still commits to a single replica. PRESENT-80 device authentication works but uses one fleet-wide key. The UCB1 weight optimizer is live, and an offline Random Forest prior did not beat hand-set weights.

---

## 2. The problem

Edge computing places workloads on many small, physically exposed, heterogeneously owned servers. Three facts collide there:

- **The perimeter model fails.** A server inside the network can be compromised, rented out, misconfigured or simply selfish. Classical load balancers (round-robin, least-connections) assume every backend is honest about its state and does its work.
- **Schedulers trust self-reported telemetry.** Orchestrators route on what a server says about itself, so a server that under-reports its load attracts traffic.
- **Zero Trust is a policy, not a mechanism.** NIST SP 800-207 says "never trust, always verify, continuously", but does not say how a network control plane verifies *serving infrastructure* (as opposed to users) or how it acts on the verdict in the forwarding path.

**Our question:** can an SDN control plane continuously verify edge servers using what it *observes* rather than what they *claim*, and enforce the verdict in the data plane fast enough to matter?

---

## 3. What we built

### 3.1 Architecture

```
   40 IoT clients ──► 8 OVS edge switches ──► core switch ──► 8 edge servers
        │                       ▲   OpenFlow 1.3 (flow rules, meters, stats)
        │ /auth  /report        │
        ▼                       │
  ┌───────────────── SDN controller (os-ken application) ─────────────────┐
  │  Northbound REST + Server-Sent Events API                              │
  │  TrustState ── Rail 1: trust score T (EMA, λ = 0.85)                   │
  │            └─ Rail 2: anomaly gate Ā (4 detectors, 1 Hz polling)       │
  │  Edge selector (power-of-two-choices, deny by default)                 │
  │  Graduated response: full · rate-limited (meters) · quarantined        │
  │  Probation (circuit-breaker half-open)   Attack classifier             │
  │  PRESENT-80 admission + source-IP pin    Ledger (SHA-256 + Merkle)     │
  │  UCB1 weight optimizer                                                 │
  └────────────────────────────────────────────────────────────────────────┘
                                │
                     Live dashboard (browser)
```

A client never addresses a server directly. It connects to a virtual IP, and the controller rewrites the destination MAC and IP in the data plane, so every routing decision is invisible to the client and revocable by the controller. The *request* path writes evidence into the trust state, and the 1 Hz *control* loop reads decisions out of it; the two never share a code path. That separation is what later made the ablation possible without touching the trust engine.

### 3.2 Components

| Component | Main file(s) | Status | What it does |
|---|---|---|---|
| SDN controller | `controller/trust_balancer.py` | Built, live | OpenFlow 1.3 app on os-ken (the maintained fork of Ryu). VIP rewrite, two-table pipeline, one cookie per server so a quarantine deletes all of a server's rules in one `OFPFC_DELETE`. Rule priorities: serving 300, quarantine drop 400, probation 460. |
| Trust engine (rail 1) | `trust_engine/trust_calculator.py`, `controller/trust_state.py` | Built, live | Per task: R (1.0 success / 0.3 timeout / 0.0 failure), B = max(0, 1 − latency/500 ms), H = max(0, 1 − \|claimed − observed load\|/0.5), A = anomaly flag. Each smoothed with λ = 0.85; T clipped to [0, 1], starts at 0.5. |
| Anomaly gate (rail 2) | `controller/flow_monitor.py` | Built, live | Polls every server each second. Four detectors: latency tell (response time versus fleet median, 3 consecutive polls), timeout-rate tell, CPU-honesty check (claimed busy time versus the duty cycle implied by completions the controller saw; abstains when evidence is missing), flood tell (keyed on the client, not the server). |
| Edge selector | `controller/edge_selector.py` | Built, live | EdgeScore = 0.50·T + 0.30·(1 − claimed CPU) + 0.20·(1 − latency). Excludes ineligible servers *before* ranking, then picks by power-of-two-choices (d = 2) with 5% random exploration. If nothing is eligible the request is denied. |
| Graduated response | `controller/trust_state.py` | Built, live | Full service (T ≥ 0.5 and Ā < 0.25); rate-limited via OpenFlow meters (T < 0.5 or Ā ≥ 0.25); quarantined (T < 0.3 or Ā ≥ 0.5). |
| Quarantine, re-steer, probation | `controller/trust_state.py` | Built, live | Quarantine installs drop rules and re-assigns in-flight work. A server quarantined on trust alone, with Ā already below the gate, gets one trial task every 5 s (probation). A server the gate has flagged is never probed. |
| Attack classifier | `controller/attack_classifier.py` | Built, live and offline | Names the attack (sybil, blackhole, grayhole, on-off, flood, spoof, bad credentials, or none) from an evidence *window*, not a single cycle. The live controller and the offline scorer call the same function. |
| Device admission | `security/present_cipher.py`, `security/authenticator.py` | Built, live | PRESENT-80 challenge–response with 64-bit single-use nonces (TTL 30 s), checked against the cipher's published test vectors. A provisioned device-to-IP roster closes the gap that a fleet-wide key authenticates possession of the key, not the device. Denials return HTTP 403 and are published as events. |
| Trust ledger | `blockchain/ledger.py`, `blockchain/merkle.py` | Built, live | Trust updates batched 10 per block into a hash chain with a Merkle root per block. The dashboard recomputes the chain in the browser rather than trusting the controller's validity flag. |
| Raft consensus | `blockchain/raft.py`, `raft_transport.py`, `raft_replica.py` | Built, standalone only | Leader election, log replication, real TCP transport, a 3-process cluster with a real leader kill. **Not wired into the controller** (§7). |
| AI weight optimizer | `trust_engine/ai_optimizer.py`, `trust_engine/rf_optimizer.py` | UCB1 live; Random Forest offline | UCB1 bandit chooses among five weight presets online. It never touches the security thresholds. The Random Forest warm-start prior was built and evaluated; it does not beat static weights (§5.11). |
| Live dashboard | `dashboard/`, `controller/northbound_api.py` | Built | Topology, packet animation from real flow-stat counters, flow rules, trust, nine time-series charts with attack onsets shaded, per-cluster panels, a client-load panel, the ledger with an in-browser tamper check, and an analysis page built from the recording. |
| Test harness | `simulation/topology.py`, `node_agent.py`, `iot_client.py` | Built | Mininet topology (1 core + 8 edge switches, 8 servers, 40 clients). Server agents do real bounded hash work. All attacks implemented with delayed onset. |
| Control arm | `base_model/` | Built, live | The same network and attacks with static nearest-server routing. Detectors run and publish; nothing acts on them. |
| Evaluation tools | `evaluation/` | Built | 600-run simulation against 4 baselines with paired statistics; scalability sweep; NFR report; attack/confusion report; availability report; interval report; replicate aggregator with between-run intervals; θ what-if predictor. |
| Tests | `tests/`, `base_model/tests/` | 1,082 passing, 11 skipped | Run on 14 October 2026 in 2 min 29 s. No root or Mininet needed. |

### 3.3 The live test scenario

Every live run uses the same topology, workload and attack schedule, launched by the same code.

- **Network:** 1 core switch + 8 edge switches (Open vSwitch, OpenFlow 1.3) under Mininet, 8 edge servers, 40 IoT clients, one 4-core host (WSL2, Ubuntu 24.04, Python 3.12.3).
- **Workload:** each device reports every 2.0 s, 15 ms of real CPU work per task, 4.0 s client timeout. About 20 requests/s from honest devices plus about 12/s from the flooding device.
- **Run length:** about 320 s.

| Attacker | Attack | Starts at | What it does |
|---|---|---|---|
| srv3 | "Sybil" (load misreporting) | 20 s | Burns CPU in the background while claiming 10% load. Completes every task. |
| srv6 | Blackhole | 30 s | Accepts tasks and never answers. |
| srv1 | Grayhole | 40 s | Drops 50% of tasks. |
| srv8 | On-off | 50 s | Alternates honest and lying phases (20 s period, 50% duty). Completes every task. |
| iot37 | Flood | 60 s | Sends at a far higher rate than other devices. |
| iot38 | Identity spoof | 15 s | Holds the fleet key and tries to authenticate as another device. |
| iot39, iot40 | Wrong credentials | at start | Attempt admission with the wrong key. |

Four servers and 36 devices are honest and must not be flagged.

> **Naming note.** srv3's attack is called "Sybil" throughout the code and paper. A Sybil attack in the literature (Douceur, 2002) means one entity presenting many identities. srv3 is a load-misreporting node. We plan to rename it in the paper.

### 3.4 Scale of the work

- About 47,000 lines of Python including tests; 79 commits since February 2026.
- 1,082 automated tests passing.
- 30 archived live runs in the current campaign (3.6 GB), plus earlier single runs 5–13 and two long study runs.
- A paper draft (`paper-draft/`, 11 pages), a panel deck and a 44-page panel briefing (`ppt/`).

---

## 4. How we evaluated it

| Level | What | Scale | Used for |
|---|---|---|---|
| Unit tests | Every component, including regression tests for each live-run defect | 1,082 tests | Correctness; pinning findings so they cannot silently regress |
| Simulation | Seeded discrete-event simulation driving the **real** selector, trust calculator and detectors | 600 runs (5 strategies × 4 scenarios × 30 seeds); scalability sweep to N = 64 | Comparison against baselines; scale beyond what the 4-core host can run live |
| Single live runs | Runs 1–13 on the full 8/40 topology (August–September) | 13 runs | Finding and fixing defects (Appendix B) |
| Replicated live runs | Three arms × five runs, then a θ sweep of three arms × five runs | 30 runs | Every live claim in the paper |
| Standalone Raft | 3 processes over loopback TCP with a real leader kill | 45 s recorded timeline | Raft safety and failover |

**Statistical method for the live runs.** The unit of replication is the run, never the task. Continuous metrics are reported as the mean with a 95% Student-t interval across runs. Yes/no outcomes (was the attacker isolated? did its score cross θ?) are reported as k/n with a Wilson interval; for 5/5 that is [57%, 100%] and for 0/5 it is [0%, 43%]. Times are reported only over runs where the event happened. With n = 5 per arm we do not run significance tests between arms on service metrics; two arms are called different only when their intervals do not overlap. Arms run in rotating order so machine drift does not land on one arm.

**The ablation design.** The *score-only* arm is the shipping controller with one switch changed (`trust.anomaly_rail_enforced: false`). Its configuration differs from the full system in exactly two keys, and a test pins this. Disabling the gate by setting its threshold to infinity would also have removed Ā from the trust score and changed the thing being measured. We separated *computing* Ā from *acting* on it instead.

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
| Honest devices served < 50% | 5.0 | 0.0 | 0.0 | Enforcement helps |
| Jain fairness, honest servers | 0.676 [0.643, 0.709] | 0.996 [0.994, 0.998] | 0.996 [0.991, 1.000] | Enforcement helps |
| Routes reaching attackers | 29.84% | 17.37% | **11.63%** | The gate's main effect |
| Attacker time isolated | — | 41.38% | **67.13%** | The gate's main effect |
| Honest servers ever quarantined | 0 | 0 | 0 | No false isolation |
| Honest subjects mislabelled | 0 | 0 | 0 | No false accusation |

"—" means *not measured*: the control arm has no quarantine mechanism, so it is not scored as zero.

**Fairness needs two populations.** Jain's index over all 8 servers barely separates the arms (0.605 / 0.681 / 0.622) and on its own would say the load balancer made no difference. The control arm is uneven because the flooding device is statically bound to one server; the acting arms are uneven because they deliberately starve attackers. Over the four honest servers the arms separate sharply (0.68 versus 0.996). We report both, plus the attacker share.

### 5.2 The ablation: what the score alone cannot reach at θ = 0.30

| Attacker | Score crossed θ (control / score-only / both) | Quarantined, score only | Quarantined, both rails | Trust at quarantine (both rails) |
|---|---|---|---|---|
| srv6 blackhole | 5/5 · 5/5 · 5/5 | **5/5** | 5/5 | 0.130 |
| srv1 grayhole | 5/5 · 5/5 · 5/5 | **5/5** | 5/5 | 0.220 |
| srv3 "Sybil" | **0/5 · 0/5 · 0/5** | **0/5** | **5/5** | **0.710** |
| srv8 on-off | **0/5 · 0/5 · 0/5** | **0/5** | **5/5** | **0.709** |

- The two attackers that **fail tasks** drive R down; the score catches them unaided, at the same speed as the gate (blackhole median 10.7 s versus 10.1 s).
- The two attackers that **never fail a task** never crossed θ = 0.30 in any of 15 runs. Their minimum trust settled at 0.399–0.411. Without the gate they were never isolated; with it, they were isolated in every run (medians 7.6 s and 10.4 s), at trust 2.4× the threshold.
- Detection and response are effectively simultaneous: the gap between a server's first anomaly event and its quarantine was 3.5–12.5 ms.

### 5.3 The threshold sweep (new; not yet in the paper)

The obvious objection to §5.2 is that θ = 0.30 was our choice. We registered a written prediction on 29 September (`data/theta_sweep_prediction_2026-09-29.txt`), then ran the score-only arm live at θ = 0.40, 0.45 and 0.50, five runs each. Scored on 14 October.

| Arm | Sybil isolated | On-off isolated | Honest servers quarantined | Routes to attackers | p95 latency |
|---|---|---|---|---|---|
| Score only, θ 0.30 | 0/5 | 0/5 | 0/5 | 17.37% | 175.6 ms |
| Score only, θ 0.40 | 0/5 | 1/5 (228.9 s) | 0/5 | 16.56% | 172.5 ms |
| Score only, θ 0.45 | **5/5** (median 26.2 s) | **5/5** (median 207.3 s) | 0/5 | 13.47% | 157.2 ms |
| Score only, θ 0.50 | 5/5 (median 50.1 s) | 5/5 (median 76.1 s) | **1/5**, plus one attacker quarantined before its attack began | 11.27% | 148.5 ms |
| Both rails, θ 0.30 | 5/5 (median 7.6 s) | 5/5 (median 10.4 s) | 0/5 | 11.63% | 137.2 ms |

**What this means.**

- The prediction was confirmed: at θ = 0.45 the score crosses for both liars in every run.
- So the claim "a score of this form is structurally unable to isolate these attackers" is **too strong** and must change.
- What remains true and is better supported:
  - **The score is slow.** 3.4× slower than the gate for the Sybil and 20× slower for the on-off attacker.
  - **The usable band is narrow, possibly empty.** While they keep serving, the liars' trust bottoms out at about 0.40–0.41. Honest servers under load dipped to 0.417 and 0.420 (θ 0.40 runs) and 0.421 (a both-rails run). A threshold that catches the liars therefore sits within a few hundredths of where honest servers go. θ = 0.45 held in its five runs, but nothing guarantees it under more load.
  - **The ceiling is close.** Every server starts at T = 0.5, and at θ = 0.50 an honest server was quarantined.
  - **The gate has a wide margin.** It isolates while the attackers' trust is about 0.71.

### 5.4 Why the score has a floor

For a server that never fails a task (R → 1) and keeps its latency term at b, the lowest possible score is

```
T ≥ α + β·b − δ        (reached only if H → 0 and Ā → 1)
```

With our weights and a 20 ms service latency (b = 0.96) the floor is 0.44, above θ = 0.30. Isolating such a server by score needs either θ above the floor or δ > 0.29, nearly double the suspicion weight, taken from the service terms.

Two measured qualifications:

- **The bound is conservative.** Computed from each run's measured Sybil latency, the predicted floor averaged 0.302 (range 0.278–0.328); the measured minimum was 0.399–0.409. The gap is the honesty term: the Sybil's claimed-versus-observed load gap averaged only 0.084, so H stayed near 0.83. **The term designed to punish lying barely registered the lie**, because its normaliser (0.5) assumes a gap the attacker never needs to open.
- **The tested attacker is not latency-faithful.** A 0.302 floor implies the Sybil's mean latency was about 300 ms, far above the fleet. Its CPU burning makes it slow, and that slowness is exactly what the gate's latency tell catches. A liar that claims low load *without* slowing itself has not been tested yet (§10, "pure liar").

The insight underneath is a known one from decision theory: a weighted sum is **compensatory** (good service compensates for dishonesty), while the gate is a **veto** (no amount of good service compensates for being flagged).

### 5.5 Enforcement corrupts its own input

When quarantine installs drop rules, the in-flight TCP connections to that server die. The client waits out its own 4 s timeout on a dead socket, while the controller's dispatch record has already moved the flow to a healthy server. The timeout was then charged to the healthy server, which lowered its trust, which could quarantine it, which re-dispatched onto fewer servers, which produced real timeouts: a positive feedback loop.

- **How we proved the mechanism:** every affected report sat at the client timeout ceiling (4,031–4,085 ms). A first proposed fix ("excuse outcomes that arrived with little budget left") was tested against the recordings and would have excused **0 of 26** cases, because the median re-steered flow still had 2.86 s of its 4.0 s left. It was a wrong-server problem, not a short-budget problem.
- **The fix has no tuned threshold.** An inherited dispatch is stamped at re-assignment, and trust attribution is skipped for it. The report is still published, so availability and delivery figures keep counting the client's real loss.
- **Size:** 123 of 32,107 reports (0.38%) across the five both-rails runs. Small, but it decides whether honest servers get quarantined. In run 10, all 11 timeouts charged to the honest srv7 (which was quarantined twice) were inherited.

**General lesson:** in any system that enforces a verdict in the data path, the enforcement action is itself an input to the detector. The coupling must be made explicit, or it will be discovered as a cascade.

### 5.6 Detection and classification quality

Over all 48 subjects (8 attackers, 40 honest), five runs per arm:

| | Control | Score only | Both rails |
|---|---|---|---|
| Overall accuracy | 91.67% | 97.92% | 97.50% [96.34, 98.66] |
| Attacks named exactly (of 8) | 4.0 | 7.0 | 6.8 |
| Attacks in the right family (of 8) | 4.0 | 8.0 | 8.0 |
| Honest subjects mislabelled (of 40) | 0 | 0 | 0 |
| Identity spoof admitted | 5/5 runs | 0/5 | 0/5 |

- **Zero false accusations** of the 40 honest subjects across 15 runs, with "no attack" scored as a real class so it cannot be hidden.
- The recurring miss is the blackhole labelled *grayhole* (right family, one step too mild). Once quarantined at about 10 s it receives almost no traffic, so its timeout rate never accumulates.
- Accuracy is dominated by the 40 honest subjects; per-class recall would be a fairer headline, and we plan to add it.
- **Two classification limits are documented, not tuned away.** Blackhole and grayhole differ only in *magnitude*, and Sybil and on-off differ only in *intermittency*, so both pairs need an evidence window rather than a single cycle. An on-off attacker with a short good phase is still caught, but labelled Sybil.

### 5.7 Simulation against four baselines

Seeded simulation using the real selector, trust calculator and detectors. 30 seeds per cell, paired Wilcoxon signed-rank tests with Holm–Bonferroni correction. Metric: SLO violation rate (lower is better). Source: `paper-draft/evidence/stats_slo.txt`.

| Scenario | vs least-connections | vs no-trust ablation | vs random | vs round-robin |
|---|---|---|---|---|
| Clean (no attack) | 51.7% better | 6.0% better | **4.8% worse** | **10.7% worse** |
| Sybil | 64.6% better | 15.1% better | 29.6% better | 19.7% better |
| Drop | 61.8% better | 25.3% better | 49.4% better | 48.7% better |
| Both | 68.8% better | 29.8% better | 52.3% better | 48.5% better |

- **14 of 16 comparisons favour our system.**
- **The p-values need a caveat.** Every favouring comparison has p_adj = 7.45 × 10⁻⁹ with effect size r = +1.00. That is the *smallest value the test can return* at n = 30, because all 30 seeds won; it reflects a deterministic ordering, not a large sample. The effect sizes and medians carry the result.
- **The two losses are real.** With no attack, the system is worse than round-robin and random. The cause is stale load information (we poll at 1 s while tasks finish in about 0.1 s), a known result in the literature (Mitzenmacher 2000; Dahlin 2000). Freshening the poll improves every load-reading strategy, and ours is best at a 0.01 s poll.

### 5.8 Selection, starvation and scale

- **Argmax starves servers.** Our first selector picked the single best EdgeScore. Because trust only moves when a server completes tasks, it locked onto about 2 servers regardless of fleet size: in simulation 2 of 8, 2 of 32 and 3 of 64 servers were used. In the July study run, an honest server (srv2) received no traffic for 2,238.8 s. Replaced by power-of-two-choices with 5% exploration.
- **Power-of-two-choices scales linearly (simulation).** At 60% offered load: 48 / 95 / 192 / 382 / 762 tasks/s at N = 4 / 8 / 16 / 32 / 64, delivery 99.7–99.8%. Argmax saturates near 85 tasks/s, with delivery falling to 10.5%.
- **Argmax fails in two different ways.** At low load it starves (13 of 16 servers idle). At high load it is balanced *and* broken, because queues push load off the favoured servers.
- **p2c is not a CPU win.** Both selectors cost 3–30 µs per decision, because the selector ranks every eligible server either way to explain its decision.
- **The capacity cliff.** With 4 servers and 2 attackers, isolating half the fleet saturates the honest half and the latency gain disappears (while still giving 32× fewer outright failures). With 6 servers the cliff is gone. **The defence needs spare capacity to absorb what it isolates.**

### 5.9 Non-functional requirements

Over the five both-rails runs (`paper-draft/evidence/nfr_replicates.txt`):

| Requirement | Target | Measured | Verdict |
|---|---|---|---|
| Routing decision (packet-in → flow-mod) | < 200 ms | mean 0.54–0.55 ms, p95 0.71–0.73 ms, max 4.4–8.6 ms | Pass |
| Isolation (re-dispatch after decision) | < 3,000 ms | mean 12.9–23.5 ms, max 32.8 ms | Pass |
| Ledger overhead | < 15% of task latency | 0.045–0.052% over 625–661 blocks | Pass |
| Raft commit | < 500 ms | mean 4.3–4.8 ms (standalone cluster only) | Pass, standalone |

**A caveat to state honestly:** the isolation requirement as measured is the time from *decision* to re-dispatch. The time from *attack onset* to isolation is dominated by detection: medians of 7.6–15.5 s, bounded below by the 1 s poll and the 3-poll persistence that keeps healthy servers out of quarantine on a jitter blip. If the original requirement meant "< 3 s from attack start", it is not met.

### 5.10 Raft

Measured on a standalone 3-replica cluster (three processes, real TCP, real leader kill): failover in 0.21 s; 850 of 853 commits succeeded during a 45 s run with a kill at 15 s and a restart at 30 s; mean commit 4.3–4.8 ms. A restarted replica rejoins empty and is caught up by the leader (crash-fault only; state is in memory). **Every block of every live run carries Raft term 0 and a single proposer**: the live controller does not use Raft.

### 5.11 The AI weight optimizer

- **UCB1** (online) chooses among five weight presets for (trust, CPU, latency) during runs. It is classical UCB1, not deep reinforcement learning, and assumes the reward does not change over time.
- **Random Forest** (offline warm-start prior), 720 simulation runs. It did not beat hand-set static weights. It was slightly worse in the Sybil scenario (−1.2%) and the combined scenario (−0.8%) and no different elsewhere. Under p2c the weight presets barely differ in reward, so any bandit mostly adds switching noise.

### 5.12 Engineering lessons from the live-run history

Every serious live-run failure so far came from the controller's own bookkeeping feeding correct detectors with wrong input, never from the detectors themselves. The defects, in the order we found them (details in Appendix B):

| Defect | Effect | Fix |
|---|---|---|
| Connectivity test ran before server agents started | All 8 servers quarantined at t = 0.5 s for 168 s | Reordered start-up |
| Stale-dispatch reaper set to 30 s against a 2 s client timeout | Phantom load on idle servers → honesty check fired → cascade | Horizon derived from the client timeout |
| Re-steer reset the dispatch timestamp | Dispatches never aged out during quarantine churn | Keep the original timestamp |
| Servers scored before they had ever answered | Startup anomalies on servers that did not exist yet | "Never seen" is unknown, not anomalous |
| Quarantine as an absorbing state | Quarantine cut the traffic that produces evidence, so servers could never leave | Detectors abstain on stale evidence; probation |
| Dispatch-count leak on re-registration | A healthy server held at 0.50 phantom load for 976 s, 707 quarantines | Invariant `sum(inflight) == len(dispatches)`, pinned by tests |
| Honesty check fell back to a biased estimator | 175 of 175 CPU-honesty firings false; honest availability 48% | Abstain when the server reports but the controller lacks evidence |
| Identity spoof succeeded through a start-up race | Attacker ran 130 tasks under a stolen identity | Larger accept backlog, client retries on resets, provisioned identity roster |
| Spoof blamed on the victim | Classifier turned a successful defence into a false accusation | Key denials on source IP |
| Re-steered timeouts charged to the inheritor | Honest servers quarantined | §5.5 |
| Control arm used a different load window (5 s versus 3 s) | Occupancy not comparable across arms; invisible to config diffing | Pinned against the code default |

**Two methods that came out of this:**

- **Little's law as a diagnostic.** Predicted in-flight count (arrival rate × latency) against the actual counter told fabricated occupancy (0.01 predicted versus 2 actual) from real load.
- **Replay versus re-run.** Replaying a fixed recording measures only first-order effects. When the defect sits inside a feedback loop, only a new live run settles it. Run 8 showed this: a replay predicted a small improvement, and the live run went from 48% to 98.9% availability.

### 5.13 Corrections and retractions

| Earlier claim | What replication showed | Status |
|---|---|---|
| Faster containment costs attack-label accuracy | ρ = −0.52, p = 0.12, n = 10: not supported | Retracted in the paper |
| Enforcement costs mean latency | All three arms' intervals overlap | Withdrawn |
| Enforcement costs throughput | All three arms' intervals overlap | Withdrawn |
| Rail attribution in the scorer | Credited the gate in the arm where the gate was switched off | Fixed in `attribute_rail()` |
| "The score is blind to faithful liars" | The θ sweep shows a narrow, slow band exists | Must be rewritten (§5.3) |
| Panel deck numbers (September) | Scored against a recording a later run overwrote | Superseded (§8) |

---

## 6. Where the system works, and where it does not

### 6.1 Validated in live emulation

| Situation | Evidence |
|---|---|
| Servers that fail tasks (blackhole, grayhole) | Isolated in all 25 runs where enforcement was on (10 at θ = 0.30, 15 in the sweep), median 10–16 s |
| Servers that lie about load and slow down doing so (Sybil, on-off) | Isolated by the gate in 5/5 runs, median 7.6 s and 10.4 s |
| Honest servers under these attacks | Never quarantined in the 10 enforcing runs at θ = 0.30; eligible 100% of the time |
| Identity spoofing with the fleet key | Refused in 10/10 acting runs; admitted in 5/5 control runs |
| Wrong-key devices | Refused and recorded |
| Flooding client | Detected and attributed to the client (not throttled; §6.3) |
| Recovering a wrongly quarantined server | Probation; in run 7, 51 of 55 quarantines recovered |
| Routing decision speed | Sub-millisecond mean |
| Tamper evidence on trust records | Overhead 0.05% |

### 6.2 Works, with conditions

- **Spare capacity is required.** The defence removes capacity; with too few servers (4 servers, 2 attackers) the honest half saturates (§5.8).
- **The poll interval bounds detection.** About 10 s from attack onset to isolation, because of 1 s polling and 3-poll persistence.
- **Without attacks, the system pays a small price.** About 5–11% more SLO violations than random or round-robin in simulation, because of stale load information.
- **Score-only enforcement can catch liars, but with almost no margin and slowly.** The liars' trust bottoms out at about 0.40–0.41 while they keep serving, so θ must sit above that. Honest servers under load dipped to 0.417–0.421 in other runs. The gap between the two is a few hundredths at best: θ = 0.45 worked in its five runs, but a run with an honest dip like those would have quarantined an honest server.

### 6.3 Not covered, or not working

| Gap | Why it matters |
|---|---|
| Adaptive attackers | All attackers follow fixed scripts. An attacker that keeps each signal just under its threshold has not been tested. |
| A liar that does not slow itself | The gate catches the Sybil partly through its own slowness (§5.4). Untested. |
| Collusion between servers; bad-mouthing by clients | Outside the threat model. Trust depends on client reports, which a dishonest admitted client could falsify. |
| Flood response | Detection only. Per-client throttling would need per-client-IP rules; current rules are per server. |
| Controller compromise | The controller is fully trusted and a single point of failure. This is the standard SDN model, but it is in tension with Zero Trust. |
| Byzantine replicas | Raft tolerates crashes, not malicious replicas, and is not wired in anyway. |
| Management API security | `/monitor/pause`, `/register` and `/topology/links` accept unauthenticated requests. Fine for a testbed, not for deployment. |
| Device keys | PRESENT-80 with one fleet-wide 80-bit key is an architecture demonstration, not a security claim. |
| Scale and realism | Live results are 8 servers on one 4-core host. Larger scale is simulation only. Workloads are Poisson-like; bursty and heavy-tailed workloads are untested. No physical hardware. |
| Remote attestation | Real Zero Trust deployments verify infrastructure with hardware attestation (TPM, Keylime, IETF RATS). We do not, and the paper does not discuss it. |

### 6.4 Real-world applicability

**The idea transfers; this implementation does not.**

- **The idea.** Rank healthy servers on one rail, exclude misbehaving ones on a separate non-compensatory rail, verify claims against observations, and enforce in the data path. Production service meshes already work this way in a different form: Envoy uses power-of-two-choices for least-request balancing and ejects bad hosts through separate *outlier detection*. Envoy's documented ejection rules are based on errors and success rates, not latency.
- **Part of the vulnerability is self-inflicted.** Our selector schedules on *claimed* CPU on purpose, to create the attack surface. Balancers that rank only on their own observations (outstanding requests, measured latency) are not attracted by load lies.
- **The implementation is research-grade.** OpenFlow server load balancing has largely given way to proxies, service meshes and eBPF in industry. The controller is a single Python process, keys are fleet-wide, and management endpoints are open.

**Where it fits.** Multi-access edge computing at 5G sites (controller ↔ MEC orchestrator, edge servers ↔ MEC hosts, IoT devices ↔ user equipment, following ETSI MEC 003), industrial and factory edge, smart-campus and smart-city gateway clusters, and federated or volunteer edge compute.

**Where it does not.** Public cloud data centres, inter-domain internet routing, and consumer IoT products.

**Most likely software outcomes.**

1. An open-source attack-and-scoring benchmark built from our harness and scorers.
2. A latency-aware ejection controller for Envoy or Kubernetes, reusing our detection functions.
3. A teaching lab built from the Mininet scenario and dashboard.

A commercial product from this codebase is not realistic.

---

## 7. Open issues

| Issue | Severity | Detail | Action |
|---|---|---|---|
| Experiment code is uncommitted | **High** | The `anomaly_rail_enforced` switch, `evaluation/replicates.py`, the derived-config tool and the run script are not committed. Every run in `data/runs/manifest.csv` is stamped `27ed08d+dirty`. The controller files were last modified before the first run, so committing now captures the run code exactly. | Commit and tag (`runs-2026-09-29`) |
| Recordings exist on one disk only | **High** | `data/` is gitignored; 3.6 GB in `data/runs/`. One earlier run (run 7) has already been lost this way. | External drive plus Zenodo (gives a DOI for the paper) |
| AI-use declaration removed from the paper | **High** | Deleted from `paper-draft/paper.tex` on 5 October (an unstaged change); `CHECKLIST.md` still ticks it. IEEE and the university expect disclosure, and the assistance was substantial. | `git restore paper-draft/paper.tex`, then rebuild |
| Paper headline superseded | **High** | The θ sweep contradicts "structurally unable" / "blind" (§5.3). | Rewrite around margin and speed |
| Paper details | Medium | Fig. 1 is a slide with numbers from a superseded single run; test counts given as 1,059 and as 832 (actual 1,082); "Sybil" misnamed; per-class recall missing; the weight optimizer running in all arms is not mentioned in the method; 11 pages versus a typical 6–8 limit. | Edit list in the roadmap |
| Raft not wired | Medium | Three blockers: nothing drives the election clock in the controller; a commit could block an OpenFlow handler for up to 2 s; the flush path discards a failed commit, which under Raft would lose trust updates on every leadership change. | Wire it, or describe it honestly as standalone (the paper already does) |
| Unauthenticated management endpoints | Medium for deployment, low for research | `/monitor/pause` can switch off continuous verification. | Mutual TLS or tokens before any deployment |
| Repository clutter | Low | Three committed copies of `base_model` (.zip, .tar, "(2).zip"), Windows `Zone.Identifier` files, about 400 KB of overlapping Markdown at the root. | `git rm`; consolidate documents |

---

## 8. What is outdated or superseded

### 8.1 Documents

| Item | Date | Why it is outdated | Current source |
|---|---|---|---|
| `docs/paper/zero-trust-sdn-paper.docx` | 16 Aug | Earlier paper. Leads with the 0.44 "trust floor" from one 215 s run; says 669 tests. The README still points to it as "the research paper". | `paper-draft/` |
| `paper-draft/paper.tex` and `paper.pdf` | 5 Oct | Headline superseded by the θ sweep; Fig. 1 stale; inconsistent test counts; AI declaration removed. | This briefing, until the rewrite |
| `ppt/sections_1_2_3.tex` / `.pdf` (Panel Review 1 deck) and `data/comparison/` | 7–8 Sep | Scored against a single-run recording that a later run overwrote. For example, it says 39 quarantines and 99.43% delivery where the surviving recording gives 33 and 99.36%. | `paper-draft/evidence/replicates/` |
| `ppt/PANEL_REVIEW_BRIEF.pdf` | 8 Sep | Predates the replicate campaign and the θ sweep. | This briefing |
| `docs/study/trust-routing-study.html` / `.pdf` | July | Describes the argmax selector before the p2c fix. The PDF was printed from an even older version. | §5.8 and `docs/LOAD_BALANCING_STARVATION.md` |
| `DIRECTION.md` | 17 Jul | Says PRESENT-80, Raft, the optimizer and the evaluation harness are "not started"; all were built since. | §3.2 |
| `PROBLEM_AND_IMPACT.md` | 17 Jul | Says "64/64 tests" and "two attack models". The problem and application analysis is still valid. | §2, §6.4 |
| `SOURCE_OF_TRUTH.md` | 3 Sep | Runs 7–11, 669 tests; predates the replicate campaign and the θ sweep. Its run-by-run detail is still accurate. | §5, Appendix B |
| `README.md` | 3 Sep | Says 669 tests, says the Random Forest is "planned" (it is built), points to the old paper. | §3.2 |
| `SETUP.md`, `final_run.md`, `README.md` platform notes | Aug–Sep | Say Ubuntu 26.04 with Python 3.14. The machine that ran every experiment is WSL2 Ubuntu 24.04.4 with Python 3.12.3. | §3.3 |
| `explain.md`, `explain_adv.md`, `plan.md`, `plan_adv.md`, `panel_fix.md` | Jul–Sep | Working notes and plans. Useful history, but not current. | This briefing |

### 8.2 Technology choices that are dated

| Choice | Why it is dated | What industry or research uses now |
|---|---|---|
| OpenFlow 1.3 server load balancing | Production load balancing moved to L4/L7 proxies, service meshes and eBPF | Envoy, Istio, Linkerd, Cilium, Katran |
| os-ken / Ryu controller | Research-grade, single process | ONOS, OpenDaylight for SDN; xDS control planes for meshes |
| PRESENT-80 with a fleet-wide key | 80-bit keys are below modern margins; a shared key authenticates the key, not the device | Per-device credentials: mutual TLS, SPIFFE/SPIRE identities, EDHOC/OSCORE for constrained IoT |
| "Blockchain" ledger | Crash-fault Raft plus a hash chain is a tamper-evident log, not a blockchain; the label invites hard questions | Signed append-only logs; transparency logs |
| Weighted additive trust score | Compensatory: good service can mask dishonesty | Veto rules / outlier ejection alongside ranking (our gate) |
| Verifying servers by behaviour only | Zero Trust deployments verify infrastructure by hardware attestation first | TPM-based remote attestation (Keylime, IETF RATS RFC 9334), with behaviour as a second layer |
| P4 as the "next" data plane | Intel stopped developing new Tofino switch chips in 2023 | eBPF/XDP on Linux hosts |

### 8.3 Code defects listed in old documents that are now fixed

- The Merkle tree no longer sorts sibling hashes (proofs are position-ordered; `blockchain/merkle.py`).
- `run_demo.py` no longer records `score_before == score_after`.
- `evaluation/stats.py` scipy mismatch (8 failing tests in September) is resolved; the full suite passes.

---

## 9. Honest assessment

| Dimension | Rating | Reasoning |
|---|---|---|
| Engineering and testing | 8.5 / 10 | Real OpenFlow enforcement, real CPU work, 1,082 tests, regression tests for every live-run defect, offline scorers that share code with the live controller |
| Experimental method | 7.5 / 10 | Run-level replication, Wilson intervals, a clean ablation, a registered prediction, reported null results and a retraction. Held back by n = 5, one host and one topology |
| Research novelty | 4 / 10 | The core insight (an additive score is compensatory, so a separate veto rail is needed) is sound but known in concept, and production service meshes already separate ranking from ejection |
| Paper as currently written | 5 / 10 | Fixable. The headline is contradicted by our own θ sweep, the related work is thin (21 references) and the attacker is misnamed |
| Real-world readiness | 2–3 / 10 | Expected for a research prototype |

**As a final-year project** this is well above the typical "Zero Trust + blockchain + SDN + AI" project: the mechanisms are real, the measurements are replicated and the negative results are reported. **As a publication** it is workshop-level after the rewrite, and could reach a solid conference with an adaptive attacker, physical hardware and a comparison against service-mesh-style outlier detection.

---

## 10. Where we can go next

Two companion pages go into full detail (both private until shared from their Share menu):

- **Roadmap:** https://claude.ai/artifact/4XGRCVei6YNTrp48cF4aPE
- **Research directions:** https://claude.ai/artifact/HVzmGEzmLzgqc8EF2oFGUg

### 10.1 Immediate plan

| Phase | When | What |
|---|---|---|
| 0. Protect the work | This week | Restore the AI declaration; commit and tag the run code; archive the recordings to an external drive and Zenodo; point the README at the current paper |
| 1. Rewrite and submit the paper | Weeks 1–4 | Lead with margin and speed; add the θ sweep table and a θ-versus-outcome figure; rename "Sybil"; widen the related work; replace Fig. 1; fix test counts; fit 6–8 pages; switch to the IEEE template |
| 1a. One extra experiment | Within phase 1 | **The pure liar:** a server that claims low load without burning CPU, five runs each in score-only and both-rails, prediction written first. Answers the "your detector was built for your attacker" objection either way |
| 2. Literature kill tests | Week 3 | One week checking that the next two directions are not already solved |
| 3. Safe-ejection testbed | Months 1–3 after submission | Envoy, containers and fault injection (direction D1 below) |
| 4. Adaptive attacker and release | Months 3–6 | Direction D2 on the same testbed; open-source the harness |

### 10.2 Six directions

| | Direction | What it asks | Builds on our work | Novelty | Effort |
|---|---|---|---|---|---|
| D1 | **Safe ejection of slow servers** (gray failure) | When does removing a slow server improve tail latency, and when does it start a cascade? Can a capacity-aware rule avoid the cascade? | High (latency tell, capacity cliff, probation, honest-server dips) | Medium–high | ~3 months |
| D2 | **Adaptive adversaries** | How much harm can an attacker cause while staying under every threshold, and which detector designs shrink that? | High (harness, ground truth, attacker code) | High | 2–4 months |
| D3 | **Self-reported telemetry elsewhere** | Federated-learning client selection, volunteer compute, autoscaling: what does misreporting gain, and what cheap check catches it? | Medium | Medium | 3–5 months |
| D4 | **Attestation plus behaviour** | Combine TPM-based attestation with the behavioural gate; which failures does each catch? Can suspicion trigger re-attestation instead of quarantine? | Medium | Medium | 3–4 months |
| D5 | **eBPF/XDP enforcement** | Measure and enforce in the kernel data path: faster detection, per-client flood throttling | Medium | Low–medium | 2–4 months |
| D6 | **Our evaluation method as a contribution** | Package the ablation design, provenance, pre-registration and the pitfalls we measured as a reusable benchmark | Very high | Low–medium | 1–2 months |

**Recommendation:** D1 and D2 as the main line (one testbed, two papers, one tool), with D6 alongside. D3, D4 and D5 suit team members whose plans point that way.

### 10.3 Dead ends to avoid

- Adding more features to the current stack (attacks, panels, ledger features).
- More "blockchain for trust".
- Tuning the trust weights.
- ML intrusion detection on public datasets.
- OpenFlow-specific SDN security.
- A startup from this codebase.

---

## 11. Questions for the meeting

1. **Paper framing.** Is "the score has a narrow, slow band; the gate has a wide, fast margin" an acceptable central claim, or should we lead with something else, such as the enforcement-feedback finding (§5.5)?
2. **Venue and timing.** Which venue fits the semester calendar: IEEE NetSoft or CNSM workshops, IEEE ANTS, COMSNETS workshops or posters, IEEE CCNC, or ICC/Globecom workshops?
3. **The pure-liar experiment.** Should we run it before submitting (about one day of code and one hour of runs), or submit first?
4. **Direction for the rest of the semester.** D1 (safe ejection, more systems-oriented) or D2 (adaptive attacker, more security-oriented) as the main line?
5. **Original commitments.** How will the final evaluation treat deviations from the original deck: Ryu replaced by os-ken, Raft built but not wired, the Random Forest negative result, and the "blockchain" label?
6. **Hardware and testbed access.** Can the department provide lab machines, Raspberry Pis or managed switches for a physical testbed, or help with access to a shared research testbed?
7. **Authorship and AI disclosure.** What does the department expect for CRediT roles and for disclosing AI assistance in the report and the paper?
8. **Scope of claims.** Is it acceptable to describe Raft and the ledger as "built and tested standalone" in the final report, rather than wiring Raft in during the remaining time?

---

## Appendix A — Key numbers

| Quantity | Value | Source |
|---|---|---|
| Tests | 1,082 passed, 11 skipped | `pytest tests/ base_model/tests/`, 14 Oct |
| Live runs in the current campaign | 30 (6 arms × 5), ~320 s each, 3.6 GB | `data/runs/manifest.csv` |
| Delivery ratio, control → both rails | 94.35% → 99.25% | replicates summary |
| Timeouts per run, control → both rails | 377.8 → 43.2 | replicates summary |
| Honest-device availability, control → both rails | 85.72% → 99.13% | replicates summary |
| Jain fairness over honest servers, control → both rails | 0.676 → 0.996 | replicates summary |
| Attacker route share: control / score only / both rails | 29.84% / 17.37% / 11.63% | replicates summary |
| p95 latency: control / score only / both rails | 317.8 / 175.6 / 137.2 ms | replicates summary |
| Sybil and on-off isolated at θ = 0.30, score only versus both rails | 0/5 versus 5/5 each | replicates summary |
| Trust at quarantine for Sybil / on-off (both rails) | 0.710 / 0.709 | replicates summary |
| Containment medians (both rails): Sybil / blackhole / on-off / grayhole | 7.6 / 10.1 / 10.4 / 15.5 s | replicates summary |
| θ = 0.45 score only: Sybil / on-off isolated | 5/5 (26.2 s) / 5/5 (207.3 s) | θ-sweep scoring, 14 Oct |
| Lowest honest-server trust under load | 0.417, 0.420, 0.421 | θ-sweep and replicate recordings |
| Honest subjects mislabelled | 0 of 40, in all 15 runs at θ = 0.30 | replicates summary |
| Re-steer reports withheld from trust | 123 of 32,107 (0.38%) | both-rails recordings |
| Routing decision | mean 0.54–0.55 ms | NFR report |
| Ledger overhead | 0.045–0.052% | NFR report |
| Raft failover (standalone) | 0.21 s; 850/853 commits | `data/raft_timeline.jsonl` |
| Simulation | 14/16 comparisons favour the system; worse than round-robin by 10.7% with no attack | `stats_slo.txt` |
| p2c throughput at N = 64 (simulation) | 762 tasks/s versus argmax ~85 | scalability sweep |
| Retracted trade-off | ρ = −0.52, p = 0.12, n = 10 | replicates summary |

## Appendix B — Live-run history

| Run | Date | What happened | What it led to |
|---|---|---|---|
| Study run A | Jul | 498 s, 3,742 decisions; first trust-routing study | `docs/study/` |
| Study run B | 21 Jul | 2,832 s; an honest server starved for 2,238.8 s; honesty-term mismatch found | Power-of-two-choices + exploration; claimed-load averaging |
| 1 | 1 Aug | First full 8/40 run collapsed: all 8 servers quarantined, 91.7% of requests denied | Start-up order fix; reaper horizon fix |
| 2 | 1 Aug | 76.1% denial | Keep original dispatch timestamp; "never seen" is unknown |
| 3 | 1 Aug | Every server ended quarantined: quarantine was an absorbing state | Stale-evidence abstention; probation |
| 4 | 1 Aug | A healthy server quarantined 707 times by a phantom dispatch count | The dispatch invariant |
| 5 | 2 Aug | First clean full-scale run: 0 denials over 18,539 routes; 18,185 successes versus 19 timeouts; liars isolated by the gate while their trust stayed high | Confirmed the two-rail design live |
| 6 | 3 Aug | Partial effect of the honesty-term wiring fix | Second-layer fix: report busy time, compare like with like |
| 7 | 7 Aug | All six attacks; honest availability 48.05%; 175/175 honesty firings false; spoof blamed on its victim. **Recording not archived** | Honesty fallback split; denials keyed on source IP |
| 8 | 7 Aug | Availability 98.9%, 0% denial, accuracy 93.8% | Confirmed run 7's fixes; replay-versus-re-run lesson |
| 9 | 8 Aug | Availability 100%; **the identity spoof succeeded** through a start-up race; one server quarantined 4.9 s before its attack began | Accept backlog, client retries, provisioned roster |
| 10 | 8 Aug | All 8 attacks named exactly for the first time; 47/48 subjects correct; spoof refused | Classification headline |
| 11 | 9 Aug (archived) | 8/8 exact, 48/48 subjects, with the re-steer attribution fix. A separate, shorter "run 11" from 11 Aug in `SOURCE_OF_TRUTH.md` was not archived | Re-steer attribution confirmed |
| 12 | 3 Sep | 336.9 s on commit `710c80c`; 7/8 exact, 0/40 honest mislabelled | Dashboard work |
| 13 | Sep | Partial recording only | — |
| Control arm run 1 | 5 Sep | First run of `base_model/`; a successful spoof merged two devices' availability into one number | Spoof break-out in the comparison tool; load-window parity fix |
| Replicate campaign | 29 Sep | 15 runs: control / score only / both rails, five each | The paper's live results |
| θ sweep | 29 Sep | 15 runs: score only at θ 0.40 / 0.45 / 0.50, five each | §5.3 |

## Appendix C — Original commitments versus status

| Commitment (project deck / SRS) | Status |
|---|---|
| Zero Trust continuous verification | Done: 1 Hz verification plus per-task scoring, enforced in the data plane |
| Trust formula T = αR̄ + βB̄ + γH̄ − δĀ, EMA λ = 0.85 | Done, unchanged; its limits are a finding (§5.2–5.4) |
| PRESENT-80 device authentication | Done, plus a provisioned source-IP pin; fleet-wide key |
| Blockchain trust ledger (SHA-256 + Merkle) | Done; Merkle ordering bug fixed |
| Raft replication, 3 replicas | Built and demonstrated standalone; not wired into the controller |
| Ryu SDN controller | Replaced by os-ken (maintained fork, same API). The documented reason is that the target OS shipped only Python 3.14, which Ryu does not support; the experiments themselves ran on Python 3.12.3 (§8.1) |
| EdgeScore routing | Done, enforced as flow rules; selection changed from argmax to power-of-two-choices after the starvation finding |
| AI weight optimizer (Random Forest offline + UCB1 online) | Both built; UCB1 live; the Random Forest does not beat static weights |
| Evaluation: 4 baselines, 30 runs per scenario, Wilcoxon | Done (600 runs, Holm–Bonferroni), plus 30 replicated live runs |
| Scale: 8 servers / 40 IoT / 3 malicious | Done live; 4 malicious servers plus 4 malicious devices in the final scenario |

## Appendix D — Reproducing the results

All commands run from the repository root.

```bash
# Unit tests (no root, no Mininet), about 2.5 minutes
python3 -m pytest tests/ base_model/tests/ -q

# Score the three original arms into the paper's evidence folder
python3 -m evaluation.replicates data/runs --arms base,scoreonly,treat --out-dir paper-draft/evidence/replicates

# Score the threshold sweep, about 80 seconds
python3 -m evaluation.replicates data/runs --arms scoreonly,scoreonly_t040,scoreonly_t045,scoreonly_t050 --out-dir paper-draft/evidence/theta_sweep

# Simulation against four baselines, then the paired statistics
python3 -m evaluation.baseline --runs 30 --csv paper-draft/evidence/baseline_600runs.csv
python3 -m evaluation.stats paper-draft/evidence/baseline_600runs.csv

# Selector scalability sweep
python3 -m evaluation.scalability_sweep --ns 4,8,16,32,64 --load-factors 0.1,0.6 --seed 1 --csv paper-draft/evidence/scalability.csv

# NFR report for one live run
python3 -m evaluation.nfr_report data/runs/treat/r01.jsonl

# Build the paper
make -C paper-draft

# Live runs (needs root, Open vSwitch and Mininet; about 6 minutes per run)
sudo ARMS="scoreonly treat" tools/run_replicates.sh
```

Live runs overwrite `data/events.jsonl` at start-up; `tools/run_replicates.sh` archives each run before the next one starts. WSL2 prerequisites (OVS daemon, queueing-discipline modules, `mn -c`, controller first) are in `SETUP.md`.

## Appendix E — Repository map

| Path | Contents |
|---|---|
| `controller/` | The SDN application: trust state, flow monitor (anomaly gate), edge selector, attack classifier, flood detector, northbound API, event bus, flow statistics |
| `trust_engine/` | Trust calculator; UCB1 and Random Forest weight optimizers |
| `security/` | PRESENT-80 cipher and device authenticator |
| `blockchain/` | Merkle tree, blocks, ledger, commit backends, Raft core, transport, replica and demos |
| `contracts/` | Shared data contracts and threshold constants |
| `simulation/` | Mininet topology, server agents, IoT clients, attack simulator, addressing |
| `base_model/` | The no-enforcement control arm and its comparison and plotting tools |
| `evaluation/` | Simulation baselines, statistics, scalability sweep, NFR / attack / availability / interval reports, replicate aggregator, analysis page builder |
| `dashboard/` | Live dashboard, replay tool, demo recording generator |
| `config/` | Run configurations, including `params_trust_full.yaml` (both rails) and `params_trust_scoreonly.yaml` (ablation) |
| `tools/` | `run_replicates.sh` (live campaign runner), `derive_config.py` (θ-sweep configs), paper figure tools |
| `paper-draft/` | Current paper source, `NUMBERS.md` (every number → artifact → command), `CHECKLIST.md`, evidence |
| `ppt/` | Panel Review 1 deck, figures and the 44-page briefing |
| `docs/` | Topic documents (Raft, AI optimizer, evaluation, flow rules, starvation, live run 8/40/3), the older paper and study, and this briefing |
| `tests/` | The test suite |
| `data/` | Recordings and derived outputs (gitignored, local only) |

## Appendix F — Glossary

| Term | Meaning |
|---|---|
| θ (theta) | The isolation threshold on the trust score; 0.30 as shipped |
| Ā | The smoothed anomaly level from the four detectors, between 0 and 1; the gate fires at 0.5 |
| Rail | An independent route to a quarantine decision; we have two (trust score and anomaly gate) |
| Ablation | Removing one mechanism and re-running everything else unchanged |
| Arm | One experimental condition (control, score only, both rails, or a θ variant) |
| Quarantine | Installing drop rules for a server and re-assigning its in-flight work |
| Re-steer | Moving an in-flight client flow from a quarantined server to a healthy one |
| Probation | One trial task every 5 s for a server quarantined on trust alone (circuit-breaker half-open state) |
| Power-of-two-choices (p2c) | Pick two candidates at random and send to the better one |
| Wilson interval | A confidence interval for a proportion that is accurate at small n |
| Gray failure / fail-slow | A partial failure where a component still responds, but slowly or incorrectly |
| Outlier ejection | A load balancer temporarily removing a backend that behaves unlike the others |
| Remote attestation | A machine proving, with a hardware-signed report, what software it booted and runs |
| NFR | Non-functional requirement (latency, overhead and similar targets from the SRS) |
