# Panel Review 1 — Sections 1 → 2 → 3
### Zero Trust–Enabled SDN for Secure Load Balancing in Edge Networks · Team 50

Every figure is in `ppt/figures/` at 2400 × 1350 px (16:9) as PNG and SVG.
Every number is traceable: `data/comparison/comparison.txt`, `data/nfr_report.txt`,
`data/raft_timeline.jsonl`, `pytest -q`.

---
---

# SECTION 1 — Software Architecture & Module Design
**Rubric: UML diagrams, DB schema, APIs, module interaction & deployment (5 marks)**

## Slide 1.1 — Architecture & modular decomposition
**Figure: `fig1_software_architecture.png`**

Five layers, one operating-system process. The controller is a single os-ken
(Ryu-fork) OpenFlow 1.3 application; the trust engine and the ledger are
libraries it calls in-process, not network services.

**Table 1.1 — Modular decomposition and contracts**

| Layer | Modules | Responsibility |
|---|---|---|
| L5 Presentation & analysis | `dashboard/`, `evaluation/` (19 tools), `base_model/` | Live SSE panels; offline scoring; the no-zero-trust control arm |
| L4 Northbound API | `controller/northbound_api.py` | REST + Server-Sent Events on :8081, stdlib `ThreadingHTTPServer` |
| L3 SDN control plane | `controller/trust_balancer.py`, `edge_selector`, `trust_state`, `flow_monitor`, `flood_detector`, `attack_classifier`, `event_bus`, `learning_switch_13`, `flow_stats`, `port_stats` | Routing decisions, detection, enforcement, event publication |
| L2 Trust, security & consensus | `trust_engine/trust_calculator`, `trust_engine/ai_optimizer`, `security/authenticator` + `present_cipher`, `blockchain/ledger·block·merkle`, `blockchain/raft*` | Trust scoring, weight tuning, admission crypto, the hash-chained ledger |
| L1 Data plane | `simulation/topology`, `node_agent`, `iot_client` | 1 core switch, 8 edge switches, 8 edge servers, 40 IoT devices |

**Design rule carried through every layer:** the request path *writes* evidence
into `TrustState`; the 1-second control loop *reads* decisions out of it. The
two never share a code path, which is why the same trust code can run in the
control arm with enforcement removed.

## Slide 1.2 — Module interaction (UML component & call flow)
**Figure: `fig2_module_interaction.png`**

- **Request path (solid):** `IoTClient` → `NorthboundAPI` → `PRESENT80Authenticator` + `IdentityBinding` → `TrustBalancerApp` → `edge_selector` → OpenFlow flow-mod.
- **Control loop (dashed):** `flow_monitor` (1 s `/status` poll) and `flood_detector` → anomaly **A** → `TrustState` → `attack_classifier`.
- **Evidence path:** `TrustState` → `TrustCalculator.update()` → `CommitBackend.commit()` → `Ledger` → `Block`; every decision also published once through `EventBus`.
- `attack_classifier` is a **pure function over an evidence window** — the same implementation serves the live controller and the offline scorer, so the two cannot drift.

## Slide 1.3 — Core APIs and the data model
**Figures: `fig3_data_model_er.png`** (and API table below)

**Table 1.2 — Core API specification** (`controller/northbound_api.py`)

| Method | Path | Request | Response |
|---|---|---|---|
| POST | `/auth/challenge` | `{device_id}` | `{nonce}` — 64-bit, TTL 30 s |
| POST | `/auth/verify` | `{device_id, response}` | `{token}` · **403** + `auth_denied{kind}` |
| POST | `/report` | `{device_id, vip_src_port, status, latency_ms}` | task outcome; `client_ip` read from the socket |
| POST | `/register` | `{node_id, concurrency}` | agent start-up registration |
| POST | `/topology/links` | `{links:[{a,b,delay_ms,bw_mbps}]}` | link parameters the harness actually built |
| GET | `/trust/score` | `?node_id=` | `{node_id: score}` or all nodes |
| GET | `/node/status` | `?node_id=` | `TrustState.snapshot()` |
| GET | `/ledger/verify` | — | `{valid, chain_length, max_updates_per_block}` |
| GET | `/api/events` | — | Server-Sent Events stream (one-way, no third-party library) |

`auth_denied` kinds: `ip_pin` · `bad_response` · `nonce_expired`.

**Table 1.3 — Data model (no RDBMS — stated deliberately)**

| Entity | Defined in | Key fields | Integrity mechanism |
|---|---|---|---|
| `Block` | `contracts/block_schema.py` | `index` PK, `previous_hash` → `Block.hash`, `merkle_root`, `proposer_id`, `raft_term`, `hash` | SHA-256 header hash + Merkle root; genesis timestamp pinned to 0.0 |
| `TrustUpdate` | `contracts/trust_update.py` | `device_id`, `edge_node_id`, `task_status`, `cpu_usage`, `reported_cpu`, `latency_ms`, `anomaly_flag` | Merkle leaf; 10 batched per block |
| `NodeState` | `controller/trust_state.py` | `node_id` PK, `trust`, `observed_load`, `inflight`, `anomaly`, `quarantined`, `probation` | in-memory, invariant-checked (`sum(_inflight) == len(_dispatches)`) |
| `IdentityBinding` | `security/authenticator.py` | `device_id` PK, `expected_ip` (roster), `session_ip` (TOFU) | source-IP pin, checked on every admission |
| `EMA state` | `trust_engine/trust_calculator.py` | `node_id` PK, R, B, H, A | λ = 0.85 exponential decay |
| `Event` | `data/events.jsonl` | `type` (20 kinds), `ts`, `seq`, payload | append-only; the durable evidence log |

> **Why no relational database:** the ledger *is* the store of record for trust,
> and its integrity is cryptographic (hash chain + Merkle root, verified by
> `GET /ledger/verify` and re-verified independently in the browser) rather than
> referential. The JSONL recording is the durable evidence log every analysis
> tool reads back. Configuration is YAML under `config/`.

## Slide 1.4 — Deployment architecture
**Figure: `fig4_deployment.png`**

| Process group | What runs | Ports |
|---|---|---|
| 1 — SDN controller | `sudo python3 -m controller.osken_manager controller.trust_balancer` | :6653 OpenFlow 1.3 · :8081 REST + SSE |
| 2 — Mininet namespaces | `s0` core OVS, `s1..s8` edge OVS, 8 × `node_agent.py`, 40 × `iot_client.py`, `cx` control host | VIP 10.0.99.254:9000 |
| 3 — RAFT cluster (standalone) | 3 × `blockchain/raft_replica.py` | RAFT :9001–9003 · control API :9101–9103 |

- Host: WSL2 · Ubuntu 26.04 · **Python 3.14** · 4 cores · apt packages only, no venv/pip.
- A client never addresses a server: it connects to the VIP, and the controller
  rewrites destination MAC + IP in the data plane — so the routing decision is
  invisible to the client and **revocable** by the controller.
- Start-up order is enforced by `scripts/preflight_live_run.py` (controller first;
  a switch that connects to nothing installs no rules and the run is silently empty).
- Both arms bind the same ports, so the zero-trust arm and the `base_model`
  control arm are run one at a time, back to back on an idle machine.

---
---

# SECTION 2 — Implementation Progress (≈60%) & Module Functionality
**Rubric: backend, frontend, database & core modules functional (8 marks)**

## Slide 2.1 — Implementation status
**Table 2.1 — Software implementation status (≈60% complete)**

| Subsystem / layer | Current implementation state | Status |
|---|---|---|
| Data plane & topology | 1 core + 8 edge OVS switches, 8 edge servers, 40 IoT devices, TCLink delays/bandwidths, VIP service model | **Functional** |
| SDN control plane | os-ken OpenFlow 1.3 app; proxy-ARP, per-connection VIP rewrite, 5-band priority table, cookie-scoped deletes, OpenFlow meters | **Functional** |
| Trust engine | `T = αR + βB + γH − δA`, EMA λ = 0.85, isolation 0.30, anomaly gate 0.50, graduated response bands | **Functional** |
| Secure load balancing | EdgeScore + power-of-two-choices, eligibility filter, ε-greedy, UCB1 online weight tuning | **Functional** |
| Security / admission | PRESENT-80 challenge–response, nonce TTL 30 s + single-use, provisioned-roster and TOFU source-IP pinning | **Functional** |
| Attack simulation & detection | 6 attacks with delayed onset + wrong-key devices; latency, timeout, honesty and flood tells; windowed classifier | **Functional** |
| Blockchain ledger | SHA-256 hash chain, Merkle root per block, batch of 10, `GET /ledger/verify`, in-browser re-verification | **Functional** |
| Northbound API | 9 endpoints + SSE stream, stdlib only | **Functional** |
| Dashboard (frontend) | Live topology, flow tables, 6 time-series charts, per-cluster panel, client-load panel, tamper-testable ledger ribbon | **Functional** |
| Evaluation & control arm | 19 analysis tools; complete `base_model/` control arm; scored baseline-vs-treatment comparison | **Integrated** |
| RAFT consensus | Core + TCP transport + 3-replica live cluster, safety proven (R-01–R-18); **not wired into the controller** | **Partial** |
| DDoS response | Detected and classified; **throttling not built** (needs a per-client-IP OpenFlow path) | **Partial** |

## Slide 2.2 — System workflow and demonstration evidence
**Figure: `fig5_system_workflow.png`**

One task, end to end: admission (1–4, once per device) → routing (5–9, once per
TCP connection) → execution, trust update, ledger commit (10–14, once per task,
~20 per second across the fleet).

**Demonstration evidence available at the panel**
- Live Mininet run: `sudo python3 run_demo.py --mode mininet --config config/params_trust_full.yaml`
- Live dashboard at `http://localhost:8081/` — quarantine, re-steer and block commit visible as they happen
- Real flow tables: `mininet> dpctl dump-flows -O OpenFlow13 | grep cookie=0x5a`
- API by cURL: `iot1 curl -s http://10.0.99.254:8081/node/status`
- Recorded failover: `python3 -m blockchain.raft_timeline --duration-s 45 --kill-at-s 15 --restart-at-s 30`
- Repository: 993 passing tests, `python3 -m pytest -q` (50.7 s)

## Slide 2.3 — Measured functionality: the controlled comparison
**Figures: `fig8_results_comparison.png`, `fig10_trust_per_server.png`, `fig11_load_share.png`**

Two live runs on 2026-09-05 — same topology, same 40 devices, same six attacks
on the same schedule, launched by the same code. The arms differ in exactly two
things: **who decides where a connection goes**, and **what happens when a node
misbehaves**.

**Table 2.2 — Baseline (control arm) vs zero-trust (treatment arm)**

| Metric | Baseline | Zero-trust |
|---|---|---|
| Packet delivery ratio | 94.29 % | **99.10 %** |
| Mean per-device availability (honest) | 85.67 % | **99.00 %** |
| Honest devices served below 50 % | 5 | **0** |
| Tasks lost to timeout | 380 | **58** |
| p95 task latency | 260.0 ms | **134.3 ms** |
| Mean task latency | **83.7 ms** | 88.5 ms |
| Throughput | 20.74 task/s | 20.66 task/s |
| Jain fairness, honest servers only | 0.689 | **0.992** |
| Requests routed to attacker nodes | 30.5 % | **12.5 %** |
| Anomalies raised / acted on | 502 / 0 | 372 / **33** |
| Re-steers performed | 0 | 38 |
| Identity spoof (iot38 → iot1) | **ADMITTED** at t = 19.6 s | **REFUSED** (`ip_pin`) |
| Wrong-key devices admitted | 2 | **0** |
| Trust blocks committed | — (no ledger) | 649 |

**Table 2.3 — Containment: time from attack onset to isolation**

| Server | Attack | Baseline | Zero-trust |
|---|---|---|---|
| srv3 | sybil | never | **8.2 s** |
| srv6 | blackhole (drop) | never | **8.7 s** |
| srv8 | on-off | never | **9.9 s** |
| srv1 | grayhole | never | **11.3 s** |

> Stated honestly: **mean latency is 4.8 ms worse** in the zero-trust arm. That
> is the trade — a small cost in the mean to remove the long tail. p95 halves,
> timeouts fall 85 %, and throughput is unchanged, so the gain is not bought by
> serving less work.

---
---

# SECTION 3 — Technical Knowledge & Engineering Decisions
**Rubric: software architecture, implementation, integration & tech stack (5 marks)**

## Slide 3.1 — Architectural patterns and the technology stack
**Figures: `fig6_zero_trust_flow.png`, `fig7_load_balancing_flow.png`**

**Table 3.1 — Patterns actually used, and why**

| Pattern | Where | Justification |
|---|---|---|
| Layered architecture | L1–L5 above | The trust engine must be callable with enforcement removed; that is what makes the control arm a *controlled* experiment rather than a second codebase |
| Strategy | `edge_selector` (`argmax` / `p2c`), `base_model/static_router` | Routing policy is config (`selection: p2c`), so the arms differ by a key, not a fork |
| Protocol / interface (structural typing) | `CommitBackend`, `Transport`, `Authenticator` | `RaftBackend` is a drop-in for `LocalLedgerBackend`; `RaftNode` did not change at all to gain a TCP transport |
| Observer / pub-sub | `EventBus` → SSE + JSONL | Every decision is published exactly once; the dashboard and every analysis tool read the same stream |
| Pure function over an evidence window | `attack_classifier` | No I/O, no locks, no state — the live and offline verdicts come from one implementation |
| Decorator | `TimingCommitBackend(LocalLedgerBackend())` | Commit cost is measured without the ledger knowing it is being timed |
| Multi-armed bandit (UCB1) | `trust_engine/ai_optimizer` | Weight tuning is an exploration problem, not a training problem — no labelled data exists at runtime |

**Stack:** Python 3.14 · os-ken (Ryu fork, apt) · Mininet + Open vSwitch,
OpenFlow 1.3 · stdlib `ThreadingHTTPServer` + SSE · PRESENT-80 lightweight
cipher · SHA-256 / Merkle · matplotlib · pytest. **No pip, no venv, no
third-party web framework** — a deliberate constraint of the target box.

## Slide 3.2 — Data integrity, concurrency and error handling

**Table 3.2 — Integrity and concurrency mechanisms**

| Concern | Mechanism |
|---|---|
| Ledger integrity | SHA-256 chain + Merkle root per block; `verify()` walks the chain; the browser recomputes the hash itself rather than trusting the controller's `valid` flag |
| Deterministic replication | Log entries carry only *content* (`timestamp`, `proposer_id`, `raft_term`, updates); `index`, `previous_hash` and `merkle_root` are recomputed **per replica** at apply time — the fix for two real bugs (non-deterministic genesis, stale ledger snapshot at proposal) |
| Controller concurrency | One `RLock` guards all `RaftNode`/`Ledger` access (re-entrant because `apply_fn` re-enters); a second `_commit_lock` serialises whole `commit()` calls; `commit()` releases the first lock while waiting, or the driver thread deadlocks |
| Trust-state consistency | All mutation under one lock; the invariant `sum(_inflight) == len(_dispatches)` is asserted, after a register leak fabricated load on honest nodes |
| Replay resistance | Nonces are single-use (popped on first verification) and expire after 30 s |
| Identity integrity | The fleet key is shared, so PRESENT-80 authenticates *possession of the key*, not the device — closed by source-IP pinning against a provisioned roster, with TOFU as the fallback |
| Error handling | Structured `AuthError(kind=…)`; a 403 also **publishes** an event, so a refusal is visible to the recording and not only to the device refused; meters degrade to allow/quarantine on switches without meter support, logged once |
| Timeout coupling | The controller's dispatch reap horizon is tied to the client's task timeout — a larger horizon manufactures phantom load under saturation |

## Slide 3.3 — Preliminary testing and NFR validation
**Figures: `fig9_testing_evidence.png`, `fig12_raft_failover.png`**

**Table 3.3 — Non-functional requirements** (`data/nfr_report.txt`)

| NFR | Target | Measured | Verdict |
|---|---|---|---|
| Routing decision (packet-in → flow-mod) | < 200 ms | mean 0.53 ms · p95 0.71 ms · max 6.64 ms (n = 6 611) | **PASS** |
| Isolation (quarantine → re-dispatch) | < 3 000 ms | mean 25.6 ms · max 47.3 ms (n = 38) | **PASS** |
| Blockchain overhead | < 15 % | **0.049 %** — commit mean 0.437 ms over 649 blocks | **PASS** |
| RAFT commit latency | < 500 ms | mean 4.3–4.8 ms; failover 0.21 s (standalone cluster) | **PASS** |

**Test suite: 1 004 tests — 993 passing, 11 skipped, 0 failing** (50.7 s).
Unit (pure logic) · integration (real sockets, real processes, real SIGTERM) ·
parity (the control arm must match the treatment arm key for key).

**Recorded Raft failover** (`fig12`, 45 s run of 2026-09-07): 850/853 commits
succeeded (99.6 %), leader failover **0.21 s**, service gap 0.21 s, three
attempts refused while no leader existed. A degraded 2-of-3 cluster costs more
per commit (2.23 → 3.08 → 2.58 ms); the cause is observed, not yet established.

## Slide 3.4 — Engineering decisions defended, and what is not done

**Decisions we would defend under questioning**
1. **Power-of-two-choices over argmax.** Argmax is winner-take-all: it sends every request to one node until its load catches up. Measured to starve the fleet as N grows; p2c scales linearly.
2. **The flood tell is keyed on the requesting client, never the edge node it lands on.** A server drowning under a flood is telling the truth about being overwhelmed — blaming it repeats a mistake this project already made twice.
3. **A detector with no recent evidence abstains rather than re-asserting a stale verdict.** Without this, quarantine became an absorbing state: isolation starved the very evidence needed to leave it.
4. **Anomaly Ā is a separate gate, not a fourth term.** A node that lies about its load but serves tasks well holds T ≈ 0.44 and never crosses the isolation line; the formula alone cannot isolate it.
5. **No literal replay attack was built.** `verify_response` pops the nonce on first use, so replay was already structurally impossible — building a fake version of a defeated attack would have been dishonest. The real gap was fleet-wide key sharing, which source-IP pinning closes.

**Open limitations, stated rather than hidden**
- **RAFT is built, proven and demonstrated — but not wired into the controller.** Every live run committed single-replica (`raft_term = 0`, `proposer_id = "controller"` on all 649 blocks). Three runtime blockers: nobody drives the tick, `commit()` would block an OpenFlow handler thread for up to 2 s, and a `None` return is currently discarded silently.
- **DDoS is detection-only**; throttling needs a per-client-IP OpenFlow path, and today's rate-limit machinery is per-edge-node. Deferred as real scope rather than half-built.
- **One run per configuration** — no confidence intervals.
- **Detection latency is an upper bound**, bounded by the 1 s poll interval.
- **Scalability beyond 8 nodes is a queueing simulation**, not a live run.
- **Localhost, not multi-host**: three OS processes and real loopback TCP, not three separate machines. The RAFT code, sockets and process boundaries are real; only hardware separation is not.

---
---

# REFERENCES

Numbering **[1]–[13] is identical to Appendix B of the project report**
(`docs/paper/`, built from `tools/paper/paper_template.html`), so a citation
means the same thing in the deck, the report and the paper. **[14]–[21]** are
additions used by the deck. Rendered as three Beamer frames at the end of
`ppt/sections_1_2_3.tex`.

## Zero Trust and trust-aware edge computing

| # | Reference | What we took from it |
|---|---|---|
| [1] | S. Rose, O. Borchert, S. Mitchell, S. Connelly, "Zero Trust Architecture," *NIST SP 800-207*, NIST, Aug. 2020. | The doctrine we implement — **and the gap we claim**: it mandates continuous verification but specifies no mechanism for verifying the *serving infrastructure* |
| [11] | B. Ali, M. A. Gregory, S. Li, "Trust-aware task load balancing in multi-access edge computing based on blockchain and a zero trust security capability framework," *Trans. Emerging Telecom. Technologies*, 34(12), e4845, 2023. DOI 10.1002/ett.4845 | Closest prior work — same three ingredients (ZT + blockchain + MEC load balancing). We differ in **enforcing the verdict in the data plane** and in measuring against a control arm |
| [12] | "Securing edge based smart city networks with software defined networking and zero trust architecture (TREN)," *J. Network and Computer Applications*, 2025. DOI 10.1016/j.jnca.2025.104318 | The smart-city / SDN application domain |
| [13] | M. Huang, Z. Li, F. Xiao, S. Long, A. Liu, "Trust Mechanism-Based Multi-Tier Computing System for Service-Oriented Edge-Cloud Networks," *IEEE TDSC*, 21(4), 1639–1651, 2024. DOI 10.1109/TDSC.2023.3285927 | Trust scoring for edge task placement — the score-only design whose arithmetic ceiling our **Finding 1** characterises |
| [19] | ETSI GS MEC 003, "Multi-access Edge Computing (MEC); Framework and Reference Architecture," V3.1.1, 2022. | The deployment mapping: controller → MEC orchestrator, edge servers → MEC hosts, IoT clients → UE |

## Load balancing — why we replaced argmax with power-of-two-choices

| # | Reference | What we took from it |
|---|---|---|
| [2] | M. Mitzenmacher, "The Power of Two Choices in Randomized Load Balancing," *IEEE TPDS*, 12(10), 1094–1104, 2001. DOI 10.1109/71.963420 | **The fix.** Sample two candidates, take the better — exponentially better tail behaviour than picking the single best. This is the argmax → p2c switch |
| [14] | Y. Azar, A. Z. Broder, A. R. Karlin, E. Upfal, "Balanced Allocations," *SIAM J. Computing*, 29(1), 180–200, 1999. | The originating balanced-allocations result behind [2] |
| [3] | M. Mitzenmacher, "How Useful Is Old Information?," *IEEE TPDS*, 11(1), 6–20, 2000. DOI 10.1109/71.824633 | Herd behaviour from stale load information — our poll interval is 1 s while tasks finish in ~0.2 s, exactly this regime |
| [4] | M. Dahlin, "Interpreting Stale Load Information," *IEEE TPDS*, 11(10), 1033–1047, 2000. DOI 10.1109/71.888643 | **Explains the one place we lose:** stale least-loaded is worse than random — why least-connections is our weakest measured baseline, and why we sit 10.7% behind round-robin with no attacker present |
| [9] | R. Jain, D.-M. Chiu, W. Hawe, "A Quantitative Measure of Fairness and Discrimination for Resource Allocation in Shared Computer Systems," *DEC Research Report TR-301*, 1984. | The fairness index in Table 2.2 (0.689 → 0.992, honest servers only) |
| [20] | J. D. C. Little, "A Proof for the Queuing Formula L = λW," *Operations Research*, 9(3), 383–387, 1961. | The diagnostic that proved a live run's occupancy was **fabricated rather than real** (predicted in-flight 0.01 vs an actual counter of 2) |

## Lightweight cryptography, the ledger and consensus

| # | Reference | What we took from it |
|---|---|---|
| [5] | A. Bogdanov et al., "PRESENT: An Ultra-Lightweight Block Cipher," *CHES 2007*, LNCS 4727, 450–466, 2007. | The cipher behind device admission, and the **published test vectors** our implementation is checked against |
| [18] | ISO/IEC 29192-2:2019, *Information security — Lightweight cryptography — Part 2: Block ciphers*. | The standardisation that makes PRESENT-80 defensible for constrained devices — and the framing for its 80-bit key being below modern margins |
| [6] | R. C. Merkle, "A Digital Signature Based on a Conventional Encryption Function," *CRYPTO '87*, LNCS 293, 369–378, 1988. | The Merkle tree giving per-record proofs; `_hash_pair` was fixed to positional concatenation so proofs are **order-sensitive** as the construction requires |
| [7] | D. Ongaro, J. Ousterhout, "In Search of an Understandable Consensus Algorithm," *USENIX ATC*, 305–319, 2014. | RAFT. Safety properties R-01–R-18 are tested against this paper's statements. **Crash-fault, not Byzantine** — the distinction we state before being asked |

## SDN platform

| # | Reference | What we took from it |
|---|---|---|
| [8] | N. McKeown et al., "OpenFlow: Enabling Innovation in Campus Networks," *ACM SIGCOMM CCR*, 38(2), 69–74, 2008. | The protocol our decisions are installed as — and the source of **Finding 3**: once a rule is installed, matching packets never return to the controller |
| [10] | B. Lantz, B. Heller, N. McKeown, "A Network in a Laptop: Rapid Prototyping for Software-Defined Networks," *ACM SIGCOMM HotNets*, 2010. | Mininet — the emulation testbed. Grounds "demonstrated in an emulated network", never "proven in production" |

## Learning and statistical method

| # | Reference | What we took from it |
|---|---|---|
| [15] | P. Auer, N. Cesa-Bianchi, P. Fischer, "Finite-time Analysis of the Multiarmed Bandit Problem," *Machine Learning*, 47(2–3), 235–256, 2002. | UCB1, the online EdgeScore weight optimiser. **Classical bandit, not deep RL** — weight tuning is an exploration problem because no labelled data exists at runtime |
| [16] | F. Wilcoxon, "Individual Comparisons by Ranking Methods," *Biometrics Bulletin*, 1(6), 80–83, 1945. | The paired signed-rank test behind every p-value. Chosen over a paired t-test because our outcomes are bounded rates, skewed and zero-inflated |
| [17] | S. Holm, "A Simple Sequentially Rejective Multiple Test Procedure," *Scandinavian J. Statistics*, 6(2), 65–70, 1979. | The multiple-comparison correction. Four baselines = four tests, so family-wise false-positive risk is ~19%, not 5%. Holm over Bonferroni: uniformly more powerful, same guarantee |
| [21] | M. T. Nygard, *Release It!: Design and Deploy Production-Ready Software*, 2nd ed., Pragmatic Bookshelf, 2018. | The circuit-breaker pattern. Our **probation** mechanism is its half-open leg, and it is what stopped quarantine being an absorbing state |

## What is borrowed, what is reproduced, and what is ours

| Claim in this project | Source | Status |
|---|---|---|
| Continuous verification, never trust | [1] | **Borrowed doctrine.** We supply the missing mechanism for infrastructure nodes |
| Argmax starves the fleet as N grows | [2],[14] | **Predicted by theory, reproduced by us** on the real selector: N=8 → 2 nodes used, N=64 → 3 |
| p2c scales where argmax saturates | [2] | **Reproduced.** 48/95/192/382/762 tasks/s at N=4..64 vs argmax saturating at ~85 tasks/s |
| Stale load signals cause herding | [3],[4] | **Reproduced — and it explains our own loss** in the no-attack scenario; isolated by a poll-interval sweep |
| Fairness 0.689 → 0.992 | [9] | **Borrowed metric**, measured on our runs, reported over two populations because whole-roster Jain hides the result |
| Trust score alone cannot isolate a liar | — | **Ours (Finding 1).** T = 0.44 floor against a 0.30 threshold; not in the literature we reviewed |
| A Sybil lie is self-defeating | — | **Ours (Finding 2).** Emerges only because the testbed measures real work instead of injecting telemetry |
| Per-packet SDN animation is dishonest | [8] | **Ours (Finding 3)**, following directly from the OpenFlow forwarding model |
| RAFT failover 0.21 s, commit 4.3–4.8 ms | [7] | **Our measurement** of a standalone 3-replica cluster; the algorithm is [7]'s |
| p_adj = 7.45×10⁻⁹, r = +1.00 | [16],[17] | **Borrowed method**, our 600-run experiment |
| PRESENT-80 admission | [5],[18] | **Borrowed primitive**, checked against published test vectors; framed as architecture, not as strong security |

> **The honest summary:** the load-balancing and consensus results are established
> theory that we reproduce on a real system; the three findings in the middle of
> that table are ours, and they came from building and measuring rather than from
> the review.
