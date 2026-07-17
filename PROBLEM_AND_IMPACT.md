# Problem & Impact — Is This Project Actually Solving Something?

*Companion to `DIRECTION.md` (roadmap/status). This document answers four questions honestly: does the project solve a real problem, where would it apply, will it be a good project when finished, and which choices decide that.*
*Written 2026-07-17.*

---

## 1. Is this solving a real problem?

**Short answer: the problem class is real and well-documented; this project is a credible feasibility study of one answer to it — not a deployable product, and it should never claim to be one.**

### The real problem underneath

Edge computing pushes computation onto many small, physically exposed, heterogeneously-owned nodes (gateways, roadside units, factory-floor servers, campus racks). Three facts collide there:

1. **The perimeter model fails at the edge.** A node inside the network can be compromised, rented, misconfigured, or simply selfish. Classical load balancers (round-robin, least-connections) assume every backend is honest about its state and faithfully does its work. Neither assumption survives a compromised node.
2. **Self-reported telemetry is the industry norm and it is trivially gameable.** Almost every real orchestrator (Kubernetes metrics, cloud auto-scalers, MEC orchestration) schedules on what nodes *claim* about themselves. A node that under-reports load attracts traffic — whether to steal data, degrade service, or freeload. This project's own Finding 1 (the 0.44 trust floor — see `DIRECTION.md` §3) is a concrete demonstration of *why* naive trust scoring over self-reports fails.
3. **Zero Trust is policy, not implementation, at the network layer.** NIST SP 800-207 says "never trust, always verify, continuously" — but it is an architecture document. *How* a network control plane continuously verifies infrastructure nodes (not users) and *acts* on the result in the data path is genuinely under-specified. Most Zero-Trust products verify users and devices at access time; verifying the *serving infrastructure itself, continuously, with routing consequences* is much less settled.

So the honest problem statement is: **"Can an SDN control plane continuously verify edge servers using observed (not claimed) behaviour, and enforce the verdict in the data plane fast enough to matter?"** That is a real, current, unsolved-in-practice question. This project answers it at prototype scale: yes, with a <3 s isolation NFR, and with the important negative result that score-based trust alone is insufficient.

### What it is *not* solving — say this out loud

- It does not solve Zero Trust for edge networks in general; it demonstrates one mechanism (behavioural trust + SDN enforcement) under two attack models (Sybil-style load lying, packet dropping). Real adversaries have a much larger menu (collusion, slow-and-low degradation, on-off attacks timed against the EMA window, data-plane attacks the controller never sees).
- It does not solve the trust bootstrapping problem: a fresh node starts at neutral trust, and nothing prevents an attacker from cycling identities — *unless* PRESENT-80 authentication (Sprint 2) makes identities expensive. This is exactly why the auth layer is not decoration: without it, the trust system is vulnerable to the cheapest attack of all (rejoin as someone new). Build it and connect this dot explicitly in the report.
- The evaluation is simulation/emulation (Mininet), not a field deployment. That is normal and acceptable for an FYP — but claim "demonstrated in an emulated network," never "proven in production."

---

## 2. Where can this actually be applied?

Ranked by how honest the fit is.

### Strong fit
- **Multi-access edge computing (MEC / 5G edge).** Telco edge sites run third-party workloads on distributed nodes; the operator genuinely cannot fully trust every node, and MEC orchestrators route by self-reported load today. Trust-aware task steering with SDN enforcement maps almost one-to-one onto this project's architecture (controller = MEC orchestrator, edge servers = MEC hosts, IoT clients = UEs). If the report names one application domain, name this one.
- **Industrial IoT / factory edge.** OT networks increasingly use SDN-style central control; a compromised line controller that keeps "working" while lying about state is a top OT fear. The "quarantine on behavioural anomaly, not just on score" gate is directly relevant, and the <3 s isolation bound is the kind of number OT people ask for.
- **Smart campus / smart city gateways.** Many small operators, physically accessible nodes, no dedicated SOC watching them. An autonomous "detect-and-re-steer" control plane is precisely the unstaffed-operations story.

### Plausible fit (with caveats)
- **Federated / community edge (volunteer nodes, CDN-lite).** Nodes owned by strangers is exactly where behavioural trust matters most — but there, the controller itself becomes the trust bottleneck (who runs it?), which this project does not address.
- **Tactical / disconnected-operations networks.** Continuous verification with local enforcement suits contested environments; RAFT-replicated state suits partition tolerance. But the ledger's crash-fault (not Byzantine) model matters even more there — be careful with claims.

### Weak fit — do not claim
- **Public cloud data centers** (hyperscalers trust their own hardware and have vastly richer telemetry).
- **General internet routing / inter-domain** (no single control plane exists; trust between operators is a contractual problem, not an SDN one).
- **Consumer IoT security as a product** ("secure your smart home with blockchain" — this project's mechanisms target infrastructure operators, not consumers; stretching it there would smell like buzzword marketing and invite hostile viva questions).

---

## 3. When completed, will this be a *good* project?

**Yes, conditionally — and the conditions are specific.** Here is the honest scoring, both directions.

### What already makes it better than the typical FYP in this space
The median "Zero Trust + blockchain + SDN + AI" student project is four buzzwords glued together with injected data and no measurement. This project is already structurally different:

1. **Real mechanisms, not mocks:** the controller speaks actual OpenFlow to actual switches; trust decisions become actual flow rules; node agents burn real CPU; the anomaly detector reads real counters. The Sybil lie being *self-defeating* (Finding 2) emerged from that realism — it cannot be produced by injected telemetry.
2. **It found and kept a negative result.** The published trust formula provably cannot isolate a competent liar, and the project documents that instead of quietly retuning the weights until the demo worked. Examiners are trained to distrust projects where everything worked; a characterised failure mode with a tested fix is the strongest credibility signal available.
3. **Honest instrumentation:** the dashboard displays measured packets-per-second from flow counters and admits the controller cannot see data-plane packets (Finding 3), rather than animating a lie.
4. **Reproducibility:** seeded runs, deterministic addressing, a maintained run-book (`SETUP.md`), tests that replay the findings (64/64).

### What would make it a *mediocre* project despite all that
- **Shipping components without evidence.** If Sprint 2 produces PRESENT-80, RAFT, and an optimizer but the evaluation harness never runs, the project ends as "we built many things" — indistinguishable from the buzzword projects it currently outclasses. The harness is the difference between an artifact and a result.
- **Claiming what the architecture cannot deliver** (see §4's hard questions — especially the RAFT/Byzantine one). One overclaim discovered by an examiner taints every honest claim around it.
- **The demo failing live.** The flagship demo has still never been run end-to-end by a human (`DIRECTION.md` §1). A project whose demo collapses in front of the advisor is remembered for that, whatever the report says.

### The realistic ceiling
Completed per `DIRECTION.md` — live demo verified, PRESENT-80 + RAFT built and tested in isolation, evaluation showing statistically significant improvement over 4 baselines, findings presented as findings — this is a **top-band FYP with a workshop-paper-shaped core**: the anomaly-gate insufficiency result plus the real-telemetry evaluation is genuinely the kind of thing that appears at venues like NOMS/IM workshops or CCNC. Whether to actually attempt publication is a post-submission decision with the advisor, but *being publishable-shaped* is the right quality bar to aim at.

---

## 4. Which directions decide whether it ends up good

These are the live choices. Each has a "good project" branch and a "mediocre project" branch.

### 4.1 Evidence over inventory *(the single most important choice)*
**Choose:** evaluation harness before the AI optimizer; results over components; if time runs short, cut scale and cut the online bandit, never the harness (cut-list in `DIRECTION.md` §4).
**Because:** every question in §3 resolves the same way — measurement is what converts this from a demo into a defended claim.

### 4.2 Scope the blockchain claim honestly *(the most dangerous viva trap)*
The hard question you **will** get: *"RAFT is crash-fault tolerant, not Byzantine-fault tolerant. A malicious ledger replica can lie and RAFT will happily replicate it. So what does your 'blockchain' actually secure?"*

**The defensible position:** the ledger provides **tamper-evidence** (hash-chained, Merkle-proven history — after the `merkle.py` fix — so *retroactive* falsification of trust records is detectable) and **availability** (RAFT survives replica crashes), *within a controller cluster that is itself in the trusted computing base*. It is not a permissionless blockchain, does not tolerate Byzantine replicas, and does not need to: the threat model puts malicious behaviour at the **edge nodes**, not inside the controller cluster. Write exactly this in the report, one paragraph, before anyone asks.
**The trap branch:** implying the blockchain defends against malicious *controllers/replicas*. It does not, an examiner will know it does not, and the deck's "private blockchain" framing invites exactly this probe. Also be ready for the follow-up — *"then why not just a signed append-only log?"* — to which the honest answer is: a hash-chained Merkle log replicated by RAFT **is** essentially that, structured for per-record proofs (`/ledger/verify`) and batch commits; "private blockchain" is the deck's name for it. Conceding that gracefully costs nothing; defending the buzzword costs credibility.

### 4.3 Frame PRESENT-80 as lightweight-crypto engineering, not as strong security
80-bit keys are below modern security margins (and PRESENT-80 has published biclique/related-key analyses). **Choose:** frame it as "an ISO/IEC 29192-2 lightweight block cipher appropriate to severely constrained IoT devices, demonstrating the challenge–response *architecture*; a production deployment would use a 128-bit primitive behind the same `Authenticator` seam." The seam already exists — this sentence is nearly free, and it converts a weakness into evidence of good architecture. Also connect it to the identity-cycling problem (§1): authentication is what makes trust scores *stick to* an identity.
**The trap branch:** presenting PRESENT-80 as making the system "secure," full stop.

### 4.4 Admit the controller is a trusted single point — and say what that costs
Zero Trust purists will note the SDN controller itself is fully trusted and a single point of failure/compromise, which is in tension with "never trust." **Choose:** acknowledge it as the standard SDN trust model, note RAFT replication of ledger state is a *step* toward controller redundancy, and list full controller distribution as future work. One honest paragraph.
**The trap branch:** silence, hoping nobody notices. In a Zero-Trust-titled project, somebody will.

### 4.5 Name the adversary model's edges
The system detects two attack behaviours. It does not handle: collusion between edge nodes, on-off attacks tuned to the EMA decay window (λ=0.85 — an attacker who behaves for a while regains trust; is that a feature or a hole? measure it!), adaptive adversaries that keep |claimed−observed| just under 0.40, or attacks on the controller/dashboard themselves. **Choose:** a limitations table naming these explicitly, and — if any time remains — *one* small experiment probing one of them (the EMA on-off attack is cheap to run in the standalone sim and would make a genuinely interesting extra figure).
**The trap branch:** "the system detects malicious nodes" stated unqualified.

### 4.6 Keep the application story to one domain
**Choose:** MEC/5G edge as the single named application (§2), with industrial IoT as a secondary mention. A report that maps its architecture onto one real domain reads as engineering; one that lists eight domains reads as marketing.

---

## 5. One-paragraph summary

The project attacks a real and current gap — orchestrators trust self-reported node state, and Zero Trust doctrine says they shouldn't, but offers no mechanism — and demonstrates a working mechanism: behavioural trust computed from observed telemetry, enforced as OpenFlow rules within seconds, validated on real (emulated-network) traffic rather than injected data. Its strongest asset is honesty: it proved its own published formula insufficient and fixed it visibly. It becomes a genuinely good project on exactly four conditions: the live demo is verified by a human; the evaluation harness produces statistically defended results against baselines; the blockchain and cipher claims are scoped to what they actually provide (tamper-evidence + availability; lightweight-crypto architecture demo); and the limitations are named before an examiner names them. Every one of those is a choice, not a gamble — the directions in `DIRECTION.md` §4 and §4.1–4.6 above are how to choose them.
