# Project Direction — Honest Assessment & Roadmap

*Zero Trust–Enabled SDN Architecture for Secure and Intelligent Load Balancing in Edge Networks*
*Written 2026-07-17, verified against the repo state on that date (`pytest tests/` 64/64 green, git head `7b401e9`).*

This document answers one question honestly: **what is the best direction from here**, balancing *legacy* (what the presentation deck and SRS committed to, which the rubric grades against) with *novelty* (what this project can genuinely claim as a contribution in the report and viva).

---

## 1. Where the project actually stands

Everything below was verified against the working tree, not recalled from notes.

### Done and tested
| Piece | Evidence |
|---|---|
| Environment (Mininet, OVS, os-ken, sci-stack on Ubuntu 26.04 / Python 3.14) | Phase A; `SETUP.md` is the run-book |
| Standalone trust-engine simulation | Phase B; isolates Sybil (T→0.00), degrades packet-drop node; figures + routing CSV |
| Plain Mininet demo through a live controller | Phase C; pingall 0 % loss, iperf ~9.4 Mbit/s on 10 Mbit links (re-run 2026-07-16) |
| **Trust-aware controller** (`TrustBalancerApp`): VIP dispatch, 2-table pipeline, `OFPFC_DELETE` on trust collapse, FlowMonitor anomaly detection, REST northbound API | Phase D Sprint 1; 64/64 tests; confirmed speaking real OpenFlow to a live switch |
| **Live dashboard** (topology, packet animation from real `OFPFlowStats` counters, rules, trust) + replay tool + honest demo recording | API layer verified against a live switch; SSE streams correct events |

### Built but **never verified by a human**
- The full 3-terminal live trust demo (`SETUP.md` §3b) — the controller has been exercised against a stale OVS bridge, but **you have never run the complete Mininet + agents + controller demo yourself**. The advisor demo is unproven end-to-end.
- The dashboard **in an actual browser** — the API is verified; whether the page renders correctly at `localhost:8082` has never been eyeballed.

### Not started at all (0-byte stubs)
- `security/present_cipher.py` — PRESENT-80 authentication
- `blockchain/raft.py` — RAFT consensus
- `trust_engine/ai_optimizer.py` — Random Forest + UCB1 weight optimizer
- `evaluation/baseline.py`, `evaluation/stats.py` — baselines + Wilcoxon statistics
- `tests/test_present.py`, `tests/test_raft.py`

That is **four of the deck's headline components** untouched. Being honest: right now this is a very good *engineering demo* of trust-aware SDN load balancing. The pieces that make it the *research project the deck describes* — cryptographic device auth, consensus-replicated ledger, learned weights, statistical evaluation — do not exist yet.

### Known defects inherited from earlier phases
1. **`blockchain/merkle.py::_hash_pair` sorts siblings before hashing.** The tree is order-agnostic, so Merkle proofs are weaker than claimed. An advisor who reads the blockchain code will find this. Must be fixed before RAFT replicates proofs.
2. **`run_demo.py:231`** records `score_before == score_after` for every honest event — silently corrupts the before/after deltas the evaluation harness will need.
3. **`README.md` is badly stale**: says trust/blockchain are "Pending" (done), documents `ryu-manager` (this project uses os-ken; Ryu is not installed and cannot be), and claims `requirements.txt` includes `ryu`. Anyone grading from the README gets a false picture — in both directions.
4. `run_demo.py` hardcodes `sybil_target='srv3'`, `pktdrop_target='srv5'` — breaks under reduced configs.

---

## 2. Legacy — what the deck committed to, and where each commitment stands

The deck (`project_presentation.pdf`) is rubric-graded. Deviating from it silently is a risk; deviating from it *openly, with a documented reason* is defensible and often reads as maturity.

| Deck commitment | Status | Honest position |
|---|---|---|
| Zero Trust continuous verification | **Partially real** | Continuous verification exists (FlowMonitor, 1 Hz) — but see §3: the published formula alone cannot deliver it; the anomaly gate does. |
| Trust formula `T = αR̄+βB̄+γH̄−δĀ`, EMA λ=0.85 | **Done, unchanged** | Kept byte-for-byte for deck fidelity. Its structural ceiling is a *finding*, not a secret. |
| PRESENT-80 device authentication | **Not started** | The `Authenticator` seam exists (`security/authenticator.py`), so this is a drop-in, not a rewrite. |
| Blockchain trust ledger (SHA-256 + Merkle) | **Built**, but Merkle proof bug weakens the claim | Fix before showing anyone the blockchain internals. |
| RAFT replication, 3 replicas | **Not started** | `CommitBackend` seam exists; `Block.raft_term` is already in the hash preimage, so RAFT can populate it without breaking hashes. SRS itself mandates building RAFT in isolation first. |
| Ryu SDN controller | **Substituted: os-ken** | Forced by Ubuntu 26.04 / Python 3.14 (no Ryu package, no Python ≤3.13). os-ken is the maintained fork with the same API. State this in the report as an environment-driven engineering decision — do not present it as Ryu. |
| EdgeScore routing `w1·T + w2·(1−cpu) + w3·(1−lat)` | **Done and enforced in the data plane** | Stronger than the deck required: decisions are installed as OpenFlow rules, not simulated. |
| AI weight optimizer (RF offline + UCB1 online) | **Not started** | Needs real routing data — which Sprint 1 now produces. Correctly sequenced *after* the live demo works. |
| Evaluation: 4 baselines, 30 runs/scenario, Wilcoxon p<0.05 | **Not started** | This is what separates "we built it" from "we showed it works better." Highest marks-per-hour of anything remaining. |
| Scale: 8 edge / 40 IoT / 3 malicious | **Demo runs at 4/12/1** | Full scale is an integration task at the end, not a blocker now. |
| Deck slide 8: "3 malicious nodes are IoT devices" | **Contradicts slide 13** (packet-drop defined as a node that *accepts tasks*) | Already resolved deliberately: malicious **edge servers** for the trust/routing story; malicious **IoT devices** become an *authentication* problem, which is exactly what PRESENT-80 addresses. Say this explicitly in the report — it turns a deck inconsistency into a design clarification. |

**Legacy verdict:** nothing committed in the deck needs to be abandoned. Two things need *open reframing* (Ryu→os-ken, and the detection claims below), and one thing needs a bug fix before scrutiny (Merkle).

---

## 3. Novelty — what this project can genuinely claim

This is the honest part that matters most for the viva. The project already holds **three defensible findings that did not come from the literature review — they came from building the thing**. They should be front and centre in the report, not buried.

### Finding 1 — the published trust formula cannot isolate a competent liar *(strongest claim)*
Replaying the real `TrustCalculator` against the deck's own attack scenarios shows the deck's "Ā→1 ⇒ T→0" claim is arithmetically unreachable. A node that lies about its load but still serves tasks holds R̄→1, B̄→0.96, so:

```
T = 0.35(1.0) + 0.25(0.96) + 0.25(0) − 0.15(1.0) = 0.44   (floor, never < 0.3)
```

δ can only ever subtract 0.15 — dishonesty alone cannot cross the isolation threshold. **Consequence:** score-based trust is insufficient for Zero Trust's continuous-verification requirement; an independent anomaly gate (`Ā ≥ 0.5 ⇒ quarantine regardless of T`) is *necessary*, not optional. This is proven in code by `test_f04_non_degrading_liar_needs_anomaly_gate`, which drives the real calculator, not a mock. The demo recording shows it live: srv3's trust never drops below ~0.60 and it is caught **only** by the gate.

*Framing:* "We found the published formula insufficient and characterised exactly why; we kept the formula intact and added a documented gate." That is a contribution. Quietly patching the formula would have destroyed it.

### Finding 2 — a Sybil lie is self-defeating when telemetry is real
Because the node agents do *real bounded work* (hash loops), a liar advertising "I'm idle" attracts traffic it cannot serve, genuinely degrades, times out, and its trust collapses to 0.00 on its own. This emergent self-punishment **only exists because the testbed measures real load instead of injecting synthetic telemetry** — most simulation papers in this space inject. The pathological case (a liar with spare capacity that never degrades) is precisely the case Finding 1's gate covers. The two findings together are a complete story.

### Finding 3 — honest packet visualisation in SDN is structurally hard
Once a flow rule is installed, matching packets are forwarded entirely in the data plane and **never reach the controller again** — so a controller cannot honestly animate per-packet flow from PacketIn. The dashboard therefore drives its animation from 1 Hz `OFPFlowStatsRequest` counter deltas and prints the measured pps on screen so the claim is checkable. This is a small but real observation about SDN observability, worth a paragraph in the report and a confident answer in the viva ("why doesn't your dashboard show every packet?").

### Supporting novelty (worth an implementation chapter, not headline claims)
- Trust decisions **enforced in the data plane** (VIP rewrite + `OFPFC_DELETE` on collapse, <3 s isolation NFR) rather than simulated.
- "Unreachable = anomalous": an unresponsive `/status` endpoint is itself an anomaly signal — a bug caught by writing tests, now a design rule.
- Running a full SDN research stack on Python 3.14 / os-ken with a hand-written app manager, where the standard tooling (Ryu, `os-ken-manager`, `os_ken.app.wsgi`) doesn't exist — documented in `SETUP.md`.

### Novelty still on the table (only earned by finishing Sprint 2+)
- **The evaluation harness is where the thesis-grade claim lives.** "Full ZT-SDN beats Round-Robin / Least-Connections / No-Trust baselines with p<0.05 over 30 seeded runs" is the sentence that makes this research. Nothing else remaining produces a sentence like it.
- The AI optimizer's honest question is: *does learning the weights actually beat hand-tuned weights?* Either answer is publishable in an FYP — a negative result honestly measured is fine — but only if the harness exists to measure it.

---

## 4. The best direction forward — ordered, with reasons

### Step 0 (this week, before anything else): close what's built
1. **Run the live trust demo yourself** (`SETUP.md` §3b, three terminals, `sudo mn -c` first — a stale OVS bridge from an earlier run is known to linger). Watch for `Routed <ip>:<port> -> srvN`, then `QUARANTINE: srv3`. Until this happens, Sprint 1 is "believed working," not "working."
2. **Open the dashboard in a browser** (`python3 -m dashboard.replay data/events.jsonl --loop`, then `localhost:8082`) and confirm it renders. It is demo-day insurance and the direct answer to the advisor's "rules + visual packet flow" ask — but only if it actually draws.
3. **Commit the untracked work** (`dashboard/generate_demo_recording.py`, new data files). The repo has git history now — keep it current, and push to a remote (GitHub private repo) as backup. A dead disk in the final semester is an unrecoverable project.
4. **Fix `README.md`** against `SETUP.md` (30 minutes). It currently misinforms anyone who grades from it.

### Step 1: PRESENT-80 (`security/present_cipher.py`) — first real Sprint 2 item
Small, pure-function, self-contained; published test vectors exist for PRESENT-80, so correctness is checkable against the literature. Slots into the existing `Authenticator` seam (challenge–response, 80-bit key, 64-bit nonce, 30 s replay TTL). This is also where **malicious IoT devices** finally enter the story, resolving the deck's slide 8/13 contradiction properly.

### Step 2: fix Merkle, then RAFT (`blockchain/raft.py`)
Fix `_hash_pair` to positional concatenation *first* — do not replicate broken proofs. Then build RAFT transport-agnostic, unit-test the safety properties through a deterministic in-memory transport (injectable loss/partition/delay), then a TCP transport so the demo can run 3 real replicas and you can kill one live in front of the advisor. Swap `LocalLedgerBackend → RaftBackend` last. The SRS itself mandates isolation-first; follow it.

### Step 3: evaluation harness (`evaluation/baseline.py`, `evaluation/stats.py`) — **pulled ahead of the AI optimizer, deliberately**
The original plan ordered optimizer → harness. Reverse it. Reasons:
- The harness needs only what already exists (Sprint 1 + standalone sim). The optimizer needs the harness to prove it did anything.
- The harness produces the single most rubric-valuable artifact (baseline comparison, significance tests). If time runs out, a project with a harness and no optimizer has results; a project with an optimizer and no harness has a component and no evidence.
- Also fix the `run_demo.py:231` before/after-score bug here, since the harness consumes those deltas.

Build it against the **standalone simulation first** (fast, seedable, 30 runs is minutes not hours), with the Mininet-in-the-loop variant as a stretch.

### Step 4: AI optimizer (`trust_engine/ai_optimizer.py`)
Random Forest offline on the harness's CSVs + UCB1 online (constraints: `w1+w2+w3=1`, each ≥0.05). Its evaluation question is now well-posed because Step 3 exists: *learned weights vs hand-tuned, same seeds, same statistics*. Report whichever answer is true.

**Open question to settle with the advisor (from the threshold discussion):** is the optimizer expected to tune only the EdgeScore weights, or also the two gate values (`isolation_threshold=0.3`, `anomaly_gate=0.5`)? Recommendation: keep the gates as fixed safety rails and state that choice — a learned safety threshold is hard to defend in a Zero-Trust framing — but it is the advisor's call and affects the harness design. Ask before building Step 4.

### Step 5: full-scale integration (8 edge / 40 IoT / 3 malicious)
Last, because it is an integration and performance task, not a design task. Validate the deck's NFRs at scale: blockchain overhead <15 %, RAFT commit <500 ms, routing decision <200 ms, isolation <3 s. `run_demo.py --mode mininet` (currently a stub that prints and exits) becomes the single entry point.

### If time runs short — what to cut, in order
1. Full-scale 8/40/3 → present at 4/12/1 with a scaling argument (topology and configs demonstrably scale; deterministic addressing already supports it).
2. Mininet-in-the-loop evaluation → standalone-sim evaluation only (statistically identical methodology; state the fidelity limitation).
3. UCB1 online adaptation → offline Random Forest only (still "AI weight optimizer", honestly scoped).
4. **Do not cut:** PRESENT-80 (small, deck-headline), RAFT-in-isolation (SRS-mandated, advisor will ask), or the evaluation harness (it is the thesis).

---

## 5. How to present this to the advisor

- **Lead with the working demo** (once Step 0 confirms it): live re-steering visible in `dpctl dump-flows` and Wireshark `OFPT_FLOW_MOD`s, plus the dashboard. This is her exact ask ("rules" + "visual flow of packets") answered.
- **Present Finding 1 as a finding**, with the arithmetic on one slide and the regression test named. It is simultaneously an honest limitation report and the project's strongest original claim — and it pre-empts the awkward version where *she* derives the 0.44 floor herself.
- **Disclose the two open reframings** (os-ken substitution; malicious-edge-servers vs malicious-IoT split) proactively, each with its one-line reason. Silent deviations from the deck are rubric risk; explained ones are engineering judgment.
- **Bring the Step 4 threshold question** (fixed gates vs learned gates) as a concrete decision for her — advisors respond well to being handed a well-posed choice rather than a status report.

---

## 6. Summary

The legacy is intact: every deck commitment is either done, seamed for drop-in, or openly reframed with a defensible reason — nothing needs to be walked back. The novelty is real but currently under-claimed: two findings (formula insufficiency + self-defeating lies) and one observation (SDN observability) already exist in code and tests, and the single highest-value remaining work is the **evaluation harness**, which converts a working system into a defended claim. The single highest-risk item is that **the flagship demo has never been run end-to-end by a human** — do that first, this week, before writing another line of new code.

---

## 7. Framing this as a *software project*

The FYP is graded as a software project, not a research thesis. The reframe costs little because the product already exists inside the repo:

**The product is the controller application + REST API + dashboard — a trust-aware load balancer for any OpenFlow 1.3 network. Mininet, the node agents, and the IoT clients are its test harness, not the project.** Nothing in `TrustBalancerApp` depends on Mininet; it has already been shown connecting to an arbitrary OVS switch. State this framing in the report's first chapter.

### Directions that cash the framing in

1. **Package it:** product name + CLI entry point (`ztlb run --config …`), config validation with readable errors, version, CHANGELOG, tagged `v1.0` for the demo build.
2. **Operator features** (the user is a network admin): manual quarantine/release via API + dashboard buttons — the dashboard graduates from visualization to **operator console**; webhook alert on quarantine; trust-state persistence across controller restarts; present the ledger as what it is in product terms, a **tamper-evident audit log** of routing/trust decisions.
3. **Requirements traceability matrix** — requirement (deck/SRS) → design element (UML, already in git) → test ID (64 tests, already green). All three artifacts exist; the matrix is a day's work and is the highest marks-per-hour software-process artifact available.
4. **Visible engineering process:** GitHub Actions CI running `pytest` (unit tests need no sudo/Mininet — works today), branches + PRs, issues/milestones per sprint. Sprint 2's components (PRESENT-80, RAFT, harness) sit behind existing seams and are naturally independent — a ready-made division of work across the 5-person team, whose contribution the git history currently does not show.
5. **Evaluation harness = acceptance-test suite.** The deck's NFRs (<200 ms routing, <3 s isolation, <15 % overhead) are acceptance criteria; the 30-seeded-run harness is simultaneously the research evaluation and the automated acceptance suite. One artifact, two chapters. This makes §4's "harness first" ordering the right call under *both* framings.
6. **Re-narrate the findings as software process:** Finding 1 = a defect discovered in testing, resolved via a documented requirement change (the anomaly gate) with a locked-in regression test; "unreachable = anomalous" = a defect caught by test-first development. Nothing is discarded — the research story and the engineering-process story are the same events told in the rubric's language.
