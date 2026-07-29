# The Complete Project Guide
### Zero Trust–Enabled SDN Architecture for Secure and Intelligent Load Balancing in Edge Networks

*A top-to-bottom explanation of the whole project, written so someone with no
networking background can follow it, and detailed enough to be the single
reference for the report and the viva. Last updated 2026-07-17, after Sprint 2
Week 2 (105 tests passing).*

> **How to read this document.** Part 1 and Part 2 are pure background — read
> them if the words "SDN", "OpenFlow", or "controller" are new to you. Part 3
> onward is this specific project: architecture, every file, every config key,
> how to run it, and what is real vs planned. There is a glossary at the very
> end (Part 13) — jump there any time a term is unfamiliar.

---

## Table of contents

1. What this project is, in one page
2. Background concepts (the beginner foundation)
3. The architecture of *this* project
4. The trust model, in detail
5. How a single task flows through the system
6. Every directory and file
7. Every configuration file and setting
8. The environment and how it was set up
9. How to run everything
10. The data-plane flow rules
11. What is built vs what is planned
12. The engineering/development history (Sprints)
13. Glossary

---

## Part 1 — What this project is, in one page

Imagine a network of small computers ("edge servers") sitting close to where data
is produced — near factory sensors, 5G base stations, smart-city cameras. Little
"IoT devices" (sensors, phones, cameras) send them work to do: "process this
image", "run this reading". Because the edge servers are close by, answers come
back fast. This is **edge computing**.

Two problems arise:

1. **Which server should each job go to?** Some servers are busy, some are
   fast, some are far. Sending every job to the same one is wasteful. This is
   **load balancing**.
2. **Can you trust the servers?** In an open edge network, a server might be
   compromised, or malicious. It might *lie* — claim it is idle to attract jobs
   and then drop them, or quietly fail. Traditional networks assume everything
   inside is trustworthy. **Zero Trust** says the opposite: *never trust, always
   verify — continuously.*

This project builds a **smart traffic controller for such a network**. It:

- watches every edge server's behaviour and computes a **trust score** for each,
- routes each job to the best server using a formula that blends **trust +
  spare capacity + speed** (the "EdgeScore"),
- **enforces** those decisions as real forwarding rules inside the network
  switches (not just a simulation on paper),
- **contains** a server the instant it misbehaves (stops sending it traffic,
  drops traffic aimed at it, and re-routes its clients elsewhere),
- **rate-limits** servers that are merely *suspect* rather than fully bad,
- records every trust decision in a **tamper-evident ledger** (a mini
  blockchain),
- only lets **authenticated devices** onto the network (a lightweight cipher
  challenge), and
- shows all of this **live in a browser dashboard**.

**The key framing (important for the report):** the *product* is the controller
application + its REST API + the dashboard. It works against **any** standard
OpenFlow 1.3 network switch. The Mininet simulation, the fake servers, and the
fake IoT clients are just the **test harness** used to exercise the product —
they are not the project itself.

---

## Part 2 — Background concepts (the beginner foundation)

If you already know SDN and OpenFlow, skip to Part 3.

### 2.1 A network in 30 seconds

Computers talk by sending **packets** (small chunks of data). A **switch** is a
box that receives a packet on one of its ports and decides which port to send it
out of, so it reaches its destination. Every network card has a **MAC address**
(a hardware ID like `00:00:00:00:01:03`); every device has an **IP address**
(like `10.0.1.3`). A normal switch learns "MAC X is reachable via port 2" by
watching traffic, and forwards accordingly.

### 2.2 The big idea: SDN (Software-Defined Networking)

In a **traditional** switch, the "brain" (deciding where packets go) and the
"muscle" (actually moving packets) live together inside the same box, baked into
the vendor's firmware. You cannot easily program new behaviour.

**SDN splits these two apart:**

- **Data plane** = the muscle. The switches. They just move packets very fast
  according to a table of rules.
- **Control plane** = the brain. A separate program called the **controller**,
  running on a normal computer. It decides what the rules should be and installs
  them into the switches.

```
        ┌──────────────────────────────┐
        │   CONTROLLER  (control plane) │   <- our software; the "brain"
        │   decides the forwarding rules│
        └──────────────┬───────────────┘
                       │  OpenFlow protocol (TCP)
        ┌──────────────┴───────────────┐
        │   SWITCHES    (data plane)    │   <- move packets at line rate
        │   just follow the rules       │
        └──────────────────────────────┘
```

Why this matters here: because the brain is now *ordinary software we can
write*, we can make forwarding decisions based on **trust** — something no
traditional switch could ever do.

### 2.3 OpenFlow — the language between brain and muscle

**OpenFlow** is the standard protocol the controller uses to talk to switches.
This project uses **OpenFlow 1.3**. The core concept is the **flow rule** (or
"flow entry"), which lives in a **flow table** inside each switch. A flow rule
has three parts:

- **Match**: which packets it applies to (e.g. "TCP packets going to IP
  10.0.99.1 on port 9000").
- **Instructions/Actions**: what to do with them (e.g. "rewrite the destination
  to server 3, then send to the next table"). An **empty** action means **drop**
  the packet.
- **Priority**: when several rules match, the highest priority wins.

Each rule also keeps **counters** (how many packets and bytes it has matched) and
optional **timeouts** (auto-delete after N seconds idle or N seconds total).

**The single most important fact for this project:** once a flow rule is
installed, the switch handles matching packets **entirely by itself, in the data
plane. Those packets never reach the controller again.** The controller only
ever sees the *first* packet of a new connection (via a special "send this to the
controller" rule). This is what makes SDN fast — and it is *why* the dashboard
animates traffic from counters rather than from individual packets (see Part
3.4, "Finding 3").

A packet sent to the controller is called a **PacketIn** event. A rule the
controller installs is sent as a **FlowMod** message (`OFPT_FLOW_MOD`).

### 2.4 The controller software: Ryu → os-ken

To write a controller you use a framework. The project was designed for **Ryu**,
a popular Python SDN controller framework. But the development machine runs a
very new OS (Ubuntu 26.04) that only ships **Python 3.14**, and Ryu does not run
on Python that new. So the project uses **os-ken** instead — the actively
maintained fork of Ryu, with the same API (just `os_ken.*` instead of `ryu.*`).
This is an environment-forced engineering decision, documented honestly. There
is **no Ryu** anywhere in the project.

### 2.5 The test bed: Mininet + Open vSwitch

- **Open vSwitch (OVS)** is a real, software OpenFlow switch. It behaves like a
  hardware switch but runs as a program.
- **Mininet** is a tool that builds a whole fake network — many hosts and OVS
  switches, wired together with virtual links of a chosen bandwidth and delay —
  all on one computer. Each fake "host" runs in its own **network namespace**
  (an isolated networking sandbox), so `iot1` genuinely cannot see `iot2`'s
  network interfaces directly. This is why some commands must be run "inside" a
  host via Mininet's CLI (e.g. `iot1 ping srv3`).

So: Mininet builds the network, the OVS switches are the data plane, and our
os-ken controller connects to them over OpenFlow to be the brain.

### 2.6 Zero Trust

**Zero Trust** is a security model whose slogan is *"never trust, always
verify."* Instead of assuming everything inside the network is safe, every actor
must **continuously prove** it is behaving. In this project that means:

- Devices must **authenticate** before they can send traffic (PRESENT-80, Part
  2.9).
- Servers earn a **trust score** that is recomputed every second from their
  actual behaviour, and lose it the moment they misbehave.
- Trust is **enforced** — a distrusted server is physically cut off in the
  switches, not just flagged.

### 2.7 Trust score, reputation, EMA

A **trust score** is a single number in `[0, 1]` summarising how trustworthy a
server currently looks, based on its recent behaviour: does it complete tasks?
is it fast? does it tell the truth about its own load? has it triggered any
anomaly alarms? The exact formula is in Part 4.

Behaviour is smoothed over time with an **EMA (Exponential Moving Average)** — a
running average that weights recent events more than old ones, so a server's
score reacts quickly to new behaviour but is not thrown around by a single blip.

### 2.8 Load balancing and the VIP

**Load balancing** spreads incoming work across multiple servers. A common trick
is a **VIP (Virtual IP)**: clients send everything to one fake address (here
`10.0.99.1:9000`), and the load balancer secretly rewrites each connection to go
to a chosen real server. The client never learns which server served it — the
mapping lives only in the controller. This project does the rewrite **in the
switch**, as OpenFlow rules.

### 2.9 The other building blocks (each explained where it appears)

- **Blockchain / Merkle tree** (Part 4.5): a **tamper-evident log**. Trust
  decisions are batched into "blocks"; each block links to the previous one by a
  cryptographic hash, so altering any past record breaks the chain and is
  detectable. A **Merkle tree** lets you prove one record is in a block without
  revealing the whole block.
- **RAFT** (Part 11; consensus core built, not yet wired in): a **consensus**
  algorithm that keeps several
  copies of the ledger in agreement even if one copy's machine crashes. It gives
  *availability + tamper-evidence*, not protection against a lying majority
  (that's a different, harder property called Byzantine tolerance — stated
  honestly in the report).
- **PRESENT-80** (Part 4.6): a **lightweight block cipher** designed for tiny
  IoT hardware. Used here for device authentication: a device proves it knows a
  shared secret key by encrypting a random challenge.
- **AI weight optimizer** (planned, Part 11): machine learning (a Random Forest,
  offline; and a UCB1 "bandit", online) to *learn* the best blend of the
  EdgeScore weights instead of hand-tuning them.

---

## Part 3 — The architecture of *this* project

### 3.1 The components and how they fit together

```
   IoT devices (iot_client.py)                Edge servers (node_agent.py)
   - authenticate (PRESENT-80)                - do real work (hash loops)
   - send tasks to the VIP                    - answer /status (may lie)
        │                                            ▲
        │ tasks to VIP 10.0.99.1:9000                │ /status polled 1/sec
        ▼                                            │
   ┌─────────────────────────  OVS switches (data plane)  ──────────────────┐
   │  follow the flow rules the controller installs (rewrite, drop, meter)  │
   └───────────────────────────────┬────────────────────────────────────────┘
                                    │ OpenFlow 1.3 (port 6653)
                     ┌──────────────┴───────────────────────────────┐
                     │        CONTROLLER  (TrustBalancerApp)         │
                     │  - EdgeScore routing (edge_selector.py)       │
                     │  - trust engine (trust_calculator.py)         │
                     │  - anomaly detection (flow_monitor.py)        │
                     │  - trust ledger (blockchain/)                 │
                     │  - device auth (security/)                    │
                     │  - REST API + dashboard (northbound_api.py,   │
                     │    event_bus.py, flow_stats.py, port_stats.py)│
                     └──────────────┬───────────────────────────────┘
                                    │ REST + Server-Sent Events (port 8081)
                                    ▼
                      Browser dashboard (dashboard/index.html)
                      Operator via curl / any HTTP client
```

### 3.2 The product vs the harness (say this in Chapter 1 of the report)

| Part | Role | Files |
|------|------|-------|
| **The product** | A trust-aware load balancer for any OpenFlow 1.3 network | `controller/`, `security/`, `blockchain/`, `trust_engine/`, `dashboard/` |
| **The test harness** | A fake network + fake servers + fake clients to exercise the product | `simulation/` (Mininet topology, node agents, IoT clients), `config/` |
| **The evaluation** | Measures whether the product actually works better than baselines | `evaluation/` (partly planned), `run_demo.py` |

Nothing in the controller depends on Mininet — it has been shown talking real
OpenFlow to a plain OVS switch.

### 3.3 The two "planes" in this project

- **Data plane** = the OVS switches following flow rules. This is where routing
  is *enforced*: a VIP rewrite rule literally changes a packet's destination, a
  drop rule literally kills a quarantined server's traffic, a meter literally
  caps a suspect server's rate.
- **Control plane** = `TrustBalancerApp`. It watches, decides, and installs
  rules. It never touches individual data packets after the first one.

### 3.4 The three original findings (the "novelty" — front and centre in the viva)

These were discovered by *building* the system, not from the literature:

1. **The published trust formula alone cannot catch a competent liar.** A server
   that lies about its load but still completes tasks keeps a high reputation.
   Working through the arithmetic (Part 4.4), its trust *floors at 0.44* and
   never crosses the 0.3 isolation line, because the "attack suspicion" term can
   only ever subtract 0.15. **Conclusion:** an independent **anomaly gate** is
   *necessary*, not optional. This is proven by a test that drives the real
   calculator, not a mock.
2. **A Sybil lie is self-defeating when the telemetry is real.** Because the fake
   servers do *real* work (hash loops), a liar that advertises "I'm idle"
   attracts traffic it cannot serve, genuinely slows down, times out, and its
   trust collapses on its own. This only happens because the test bed measures
   real load instead of injecting fake numbers (which most simulation papers do).
3. **Honest per-packet visualisation in SDN is structurally impossible from the
   controller.** Once a rule is installed, packets never return to the
   controller (Part 2.3). So the dashboard animates traffic from **flow/port
   counter deltas** and prints the measured rate on screen, rather than
   pretending to see each packet.

---

## Part 4 — The trust model, in detail

### 4.1 The trust formula

Each server's trust `T` is a weighted sum of four EMA-smoothed components:

```
T = α·R̄ + β·B̄ + γ·H̄ − δ·Ā
```

with weights (which must sum to 1.0):

| Symbol | Name | Meaning | Weight (default) |
|--------|------|---------|------------------|
| `R̄` | Reputation | Did tasks succeed? success=1.0, timeout=0.3, failure=0.0 | α = 0.35 |
| `B̄` | Behaviour | Is it fast? `max(0, 1 − latency_ms/500)` | β = 0.25 |
| `H̄` | Honesty | Does its claimed CPU match reality? `max(0, 1 − |claimed−actual|/0.5)` | γ = 0.25 |
| `Ā` | Anomaly | Has an alarm fired? 1.0 if flagged, else 0.0 (this one is *subtracted*) | δ = 0.15 |

Code: `trust_engine/trust_calculator.py`. The raw values come from each
`TrustUpdate` (`contracts/trust_update.py`). The final score is clipped to
`[0, 1]`.

### 4.2 EMA smoothing (λ = 0.85)

Every component is smoothed:

```
X̄(now) = λ·X(this sample) + (1−λ)·X̄(previous)
```

With `λ = 0.85`, the newest sample dominates (85%) but history still matters
(15%). Higher λ = reacts faster / forgets faster.

### 4.3 EdgeScore — the routing decision

To pick a server for a job, the controller scores every **non-excluded** server
and takes the highest:

```
EdgeScore(n) = w1·T(n) + w2·(1 − cpu_load(n)) + w3·(1 − latency_norm(n))
n* = argmax EdgeScore(n)     over eligible nodes
```

Weights `w1=0.50, w2=0.30, w3=0.20` (sum to 1.0). Notes:

- `cpu_load` is the server's **claimed** load — deliberately, because lying about
  it is the attack we want to demonstrate.
- `latency_norm` uses the **controller-measured** round-trip time (added in
  Sprint 2), *not* the server's self-reported latency — a server can lie in its
  status message but cannot lie about how long its reply actually took to arrive.
- Ties (e.g. at start-up when all servers are equal) are broken round-robin so
  the routing chart isn't skewed by list order.

Code: `controller/edge_selector.py` (`edge_score`, `select_edge_node`).

### 4.4 The anomaly gate (Finding 1, proven)

A server is **excluded from routing entirely** ("quarantined") when **either**:

- its trust `T < 0.3` (the **isolation threshold**), **or**
- its smoothed anomaly `Ā ≥ 0.5` (the **anomaly gate**).

Why the gate is mandatory: consider a server that lies about its CPU but still
serves tasks. It holds R̄→1, B̄→0.96, H̄→0 (fully dishonest), Ā→1:

```
T = 0.35(1.0) + 0.25(0.96) + 0.25(0.0) − 0.15(1.0) = 0.44
```

0.44 never drops below 0.3, because δ can only ever subtract 0.15. **The score
alone can never quarantine this liar.** The anomaly gate — a separate check that
quarantines on `Ā ≥ 0.5` regardless of `T` — is what catches it. Code:
`contracts/thresholds.py`, `controller/edge_selector.py::is_quarantined`.

### 4.5 Graduated response — trust *bands* (Sprint 2)

Zero Trust is not simply on/off. A server between "fully trusted" and
"quarantined" is **suspect**, and gets a proportional response:

| Band | Condition | Treatment |
|------|-----------|-----------|
| **Full** | `T ≥ 0.5` and `Ā < 0.25` | Normal service |
| **Rate-limited** | `0.3 ≤ T < 0.5`, or `0.25 ≤ Ā < 0.5` | Still served, but its inbound flows are **rate-limited** by an OpenFlow **meter** (2 Mbps) |
| **Quarantined** | `T < 0.3` or `Ā ≥ 0.5` | Cut off: rules deleted, drop rules installed, clients re-routed |

The two hard gates (0.3, 0.5) stay as safety rails; the two new thresholds (0.5,
0.25) just carve the "suspect" band out of the healthy region. Code:
`controller/edge_selector.py::trust_band`, `controller/trust_state.py::band`,
enforcement in `controller/trust_balancer.py`.

### 4.6 The two anomaly signals (how misbehaviour is detected)

`controller/flow_monitor.py` polls every server's `/status` once a second and
raises an anomaly on **either** of two independent signals:

1. **CPU-honesty deviation**: `|claimed_cpu − observed_load| > 0.40`. The
   controller computes its *own* estimate of each server's load (from how many
   jobs it dispatched there), so a lying server cannot influence the number it is
   judged against. This catches the **Sybil** liar.
2. **Packet-drop tell**: the recent client-observed timeout rate is too high.
   This catches the **drop** attacker, who reports its own CPU honestly but
   silently never answers. It needs its own signal because signal (1) can't see
   it.

Also: a server whose `/status` is **unreachable** is treated as anomalous, not
merely skipped ("unreachable = anomalous" — a rule that came from a bug caught by
testing).

### 4.7 The tamper-evident ledger (blockchain)

Every trust update is batched (up to 10 per block) and committed to a chain of
**blocks**. Each `Block` (`contracts/block_schema.py`) contains the updates, a
**Merkle root** (a single hash summarising all updates in the block), the
previous block's hash, and its own hash. Changing any past record changes its
block's hash, which breaks every following block's `previous_hash` link — so
tampering is detectable (`Ledger.is_valid_chain()`).

- `blockchain/merkle.py` — builds the Merkle root and per-record proofs. **Fixed
  in Sprint 2** so the tree is *order-sensitive* (it previously sorted sibling
  hashes, which silently weakened proofs).
- `blockchain/block.py`, `blockchain/ledger.py` — block factory and the chain.
- `blockchain/commit_backend.py` — a seam (`CommitBackend`) so the storage can
  later be swapped from local (`LocalLedgerBackend`) to RAFT-replicated without
  touching callers.
- `blockchain/raft.py` — the consensus core behind that future swap: leader
  election, log replication, and the commit rule, transport-agnostic and driven
  by a virtual clock. Tested against an in-memory network with injectable loss,
  delay, and partitions. **Not connected to the ledger yet** — the controller
  still runs `LocalLedgerBackend`.
- In product terms this is a **tamper-evident audit log** of every routing/trust
  decision.

---

## Part 5 — How a single task flows through the system

Follow one job from an IoT device to completion:

1. **Admission.** `iot_client.py` runs the PRESENT-80 handshake with the
   controller (`POST /auth/challenge` → encrypt the returned nonce with the
   shared key → `POST /auth/verify`). If the key is wrong, it is denied and
   sends nothing. (Sprint 2.)
2. **First packet.** The client opens a *new* TCP connection to the VIP
   `10.0.99.1:9000` and sends `POST /task`. No per-connection rule exists yet, so
   the switch's "new connection" rule (priority 250) sends the first packet to
   the controller (**PacketIn**).
3. **Decision.** `TrustBalancerApp._handle_table_vip` calls
   `choose_edge_node()` → EdgeScore argmax over eligible servers → say `srv2`.
4. **Enforcement.** It installs a **VIP rewrite pair** (priority 300) into the
   switch: forward packets get their destination rewritten to `srv2`; reply
   packets get un-rewritten back to the VIP. If `srv2` is in the *rate-limited*
   band, the forward rule also carries a **meter** that caps its rate. It records
   the client→server mapping internally (the client is never told).
5. **Data plane takes over.** Every subsequent packet of that connection is
   rewritten by the switch itself; the controller no longer sees them.
6. **Work.** `node_agent.py` on `srv2` does a real bounded hash loop and replies.
7. **Report.** The client `POST /report`s the outcome (success/timeout, latency)
   to the controller. The controller resolves which server served it (from its
   mapping), builds a `TrustUpdate`, and updates `srv2`'s trust; the update is
   batched into the ledger.
8. **Continuous verification.** In parallel, `flow_monitor.py` polls `srv2`'s
   `/status` every second, updates the honesty/anomaly signals, and recomputes
   its band.
9. **If srv2 misbehaves.** The moment it crosses into quarantine, the controller
   (`_on_trust_collapse`) **deletes** srv2's rewrite rules, **installs drop
   rules** (priority 400) on srv2's MAC so even direct traffic dies, and
   **re-dispatches** srv2's active clients to the next-best server — all within
   the ~1-second poll cycle, well under the 3-second isolation target.
10. **Visibility.** Every step publishes an event on the internal **event bus**,
    which the dashboard streams live over Server-Sent Events, and which is also
    appended to `data/events.jsonl` for offline replay.

---

## Part 6 — Every directory and file

```
Zero-Trust-Enabled-SDN-Architecture/
├── controller/        THE PRODUCT — the SDN controller application
├── trust_engine/      the trust score maths + (planned) AI optimizer
├── blockchain/        the tamper-evident trust ledger
├── security/          device authentication (PRESENT-80)
├── contracts/         shared data shapes + thresholds (no logic)
├── simulation/        THE HARNESS — Mininet network, fake servers, fake clients
├── evaluation/        metrics, plots, (planned) baselines + statistics
├── dashboard/         the live browser view + replay tool
├── config/            YAML configs (full-scale, demo, trust-demo)
├── tests/             the pytest suite (105 tests, no sudo/Mininet needed)
├── docs/              FLOW_RULES.md, this guide
├── uml_diagrams/      class/sequence/DFD/ER/activity diagrams
├── run_demo.py        standalone (no-Mininet) trust-engine simulation
├── README.md          project overview
├── SETUP.md           the authoritative, step-by-step run-book
├── DIRECTION.md       honest status + roadmap + cut-list
└── PROBLEM_AND_IMPACT.md   problem validation + viva framings
```

### 6.1 `controller/` — the product

| File | What it does |
|------|--------------|
| `trust_balancer.py` | **The main app.** `TrustBalancerApp` (the real os-ken controller) + `TrustBalancerStandalone` (a no-OpenFlow version used by `run_demo.py`). Installs all flow rules, handles PacketIn, quarantine, meters, re-dispatch. |
| `trust_state.py` | Thread-safe shared state: dispatch tracking, quarantine/band logic, ledger batching. The single object every other part talks to. |
| `edge_selector.py` | The EdgeScore formula, `is_quarantined`, `trust_band`. Single source of truth for the routing decision. |
| `flow_monitor.py` | The 1 Hz `/status` polling loop and the two anomaly signals. Also measures round-trip latency. |
| `northbound_api.py` | The REST API + dashboard HTTP server (stdlib, no Flask). Auth, status, trust, offload, report, register, and the `/api/*` dashboard routes. |
| `event_bus.py` | Internal publish/subscribe. `publish()` never blocks the OpenFlow thread; `NullBus` is the inert version used when the dashboard is off. |
| `flow_stats.py` | Polls per-flow packet/byte counters (`OFPFlowStatsRequest`) for the "rules" panel and packet animation. |
| `port_stats.py` | Polls per-port byte counters (`OFPPortStatsRequest`) for the live link-load readout. (Sprint 2.) |
| `osken_manager.py` | A hand-written launcher, because Ubuntu's os-ken package omits the normal `os-ken-manager` CLI. |
| `learning_switch_13.py` | A plain OF1.3 learning switch, used only to verify basic connectivity before the real app. |

### 6.2 `trust_engine/`

| File | What it does |
|------|--------------|
| `trust_calculator.py` | The `T = αR̄+βB̄+γH̄−δĀ` formula with EMA smoothing. |
| `ai_optimizer.py` | **Planned (empty).** Will learn the EdgeScore weights (Random Forest + UCB1). |

### 6.3 `blockchain/`

| File | What it does |
|------|--------------|
| `merkle.py` | Merkle root + proofs (order-sensitive since Sprint 2). |
| `block.py` | `build_block()` — assembles a block and computes its hash. |
| `ledger.py` | The chain: `append`, `is_valid_chain`, `latest_trust_score`. |
| `commit_backend.py` | The `CommitBackend` seam + `LocalLedgerBackend`. |
| `raft.py` | RAFT core: leader election, log replication, commit rule, plus an in-memory test transport. **Isolated — not wired to the ledger yet.** |

### 6.4 `security/`

| File | What it does |
|------|--------------|
| `present_cipher.py` | The PRESENT-80 cipher, pinned to published test vectors. (Sprint 2.) |
| `authenticator.py` | The `Authenticator` seam + `NullAuthenticator`, `HmacAuthenticator`, `Present80Authenticator`. |

### 6.5 `contracts/` (pure data, no logic)

| File | What it does |
|------|--------------|
| `trust_update.py` | The `TrustUpdate` record (one task outcome + telemetry) and `honesty_delta()`. |
| `block_schema.py` | The `Block` dataclass and its hashing. |
| `thresholds.py` | All the default thresholds (isolation, anomaly gate, rate-limit band, anomaly warn) with the reasoning as comments. |

### 6.6 `simulation/` (the harness)

| File | What it does |
|------|--------------|
| `topology.py` | Builds the Mininet network (switches, servers, IoT hosts, the `cx` routing node) and launches the agents/clients. |
| `node_agent.py` | A fake edge server: `POST /task` does a **real** hash-loop; `GET /status` reports telemetry (and *lies* if malicious). Sybil = lie about CPU; drop = accept and never answer. |
| `iot_client.py` | A fake IoT device: authenticates, then sends tasks to the VIP on fresh connections and reports outcomes. |
| `addressing.py` | The single source of truth for IPs/MACs (`srv_ip`, `srv_mac`, `iot_ip`, `iot_mac`, `VIP_MAC`) so the controller and topology never disagree. |
| `attack_simulator.py` | Attack scheduling for the standalone `run_demo.py`. |
| `traffic_gen.py` | pingall + iperf traffic for the plain (non-trust) demo. |

### 6.7 `dashboard/`

| File | What it does |
|------|--------------|
| `index.html` | One self-contained page (vanilla JS + hand-drawn SVG, **no CDN** so it works offline on a projector). Topology, packet animation, rules, trust, live throughput. |
| `replay.py` | Replays a recorded `data/events.jsonl` with original timing — no Mininet, no sudo. Demo-day insurance. |
| `generate_demo_recording.py` | Produces a reproducible recording by driving the **real** components (seed 7). |

### 6.8 `evaluation/`

| File | What it does |
|------|--------------|
| `metrics.py` | Collects run metrics. |
| `plots.py` | Generates figures. |
| `baseline.py`, `stats.py` | **Planned (empty).** Baseline algorithms + Wilcoxon significance tests. |

### 6.9 `tests/` (105 tests, run with `python3 -m pytest tests/`)

No sudo and no Mininet required — the controller code is tested against os-ken's
OpenFlow parser with a *mocked* switch, so tests run anywhere. Notable files:
`test_trust*.py`, `test_edge_selector.py`, `test_flow_monitor.py`,
`test_quarantine_drop.py`, `test_present.py`, `test_authenticator.py`,
`test_graduated_response.py`, `test_port_stats.py`, `test_blockchain.py`,
`test_dashboard_api.py`.

---

## Part 7 — Every configuration file and setting

There are three config files. They share the same shape; they differ in scale
and in which features are turned on.

| File | Scale | Purpose |
|------|-------|---------|
| `config/params.yaml` | 8 edge / 40 IoT / 3 malicious | Full-scale evaluation config |
| `config/params_demo.yaml` | 2 edge / 6 IoT / 0 malicious | Fast plain-connectivity demo (no trust features) |
| `config/params_trust_demo.yaml` | 4 edge / 12 IoT / 1 malicious | **The main trust demo** — all Sprint 1 & 2 features on |

### 7.1 Every key in `params_trust_demo.yaml` (the important one)

```yaml
trust:
  alpha: 0.35            # weight of Reputation R̄ in T
  beta: 0.25             # weight of Behaviour/latency B̄
  gamma: 0.25            # weight of Honesty H̄
  delta: 0.15            # weight (subtracted) of Anomaly Ā   (α+β+γ+δ must = 1.0)
  lambda_decay: 0.85     # EMA factor: higher = react faster / forget faster
  initial_score: 0.5     # trust a brand-new server starts with

  isolation_threshold: 0.3   # T below this  -> quarantined
  anomaly_gate: 0.5          # Ā at/above this -> quarantined (regardless of T)
  rate_limit_trust: 0.5      # T below this (but ≥ isolation) -> rate-limited band
  anomaly_warn: 0.25         # Ā at/above this (but < gate)   -> rate-limited band

edge_score:
  w1_trust: 0.50         # weight of trust in EdgeScore
  w2_cpu: 0.30           # weight of spare CPU
  w3_latency: 0.20       # weight of low latency   (w1+w2+w3 must = 1.0)

simulation:
  num_edge_nodes: 4      # how many edge servers (srv1..srv4)
  num_iot_devices: 12    # how many IoT clients (iot1..iot12)
  num_malicious: 1       # how many misbehaving servers
  duration_s: 120        # run length
  malicious_edge_nodes:  # WHICH servers misbehave and how
    - node: srv3
      attack: sybil      # 'sybil' = lie about CPU; 'drop' = accept then never answer
      start_s: 20        # start attacking at t=20s

security:                # (Sprint 2) device authentication
  auth_scheme: present80 # present80 | hmac | null
  shared_key_hex: "00112233445566778899"   # 10 bytes = 80-bit key
  malicious_iot_devices: # devices given a WRONG key -> denied admission
    - iot12

blockchain:
  max_updates_per_block: 10   # batch size before a block is committed
  block_commit_timeout_s: 5.0 # commit a partial batch after this long

controller:
  vip: 10.0.99.1         # the Virtual IP clients send everything to
  vip_port: 9000
  api_host: 0.0.0.0      # the controller binds its REST API on all interfaces
  api_port: 8081         # REST API + dashboard port
  flow_idle_timeout_s: 10   # delete a VIP rule after 10s idle
  flow_hard_timeout_s: 30   # delete a VIP rule 30s after install regardless
  monitor_interval_s: 1.0   # how often /status is polled (the 1 Hz loop)
  rate_limit:            # (Sprint 2) graduated response meters
    enabled: true
    rate_kbps: 2000      # ~2 Mbps ceiling for a suspect server's inbound flows
    burst_kb: 200
  dashboard:
    enabled: true
    record_path: data/events.jsonl   # where the event recording is written
  honesty_deviation_threshold: 0.40  # |claimed−observed| CPU that triggers anomaly

agents:
  node_port: 8000        # port each node_agent listens on for /task and /status
  report_interval_s: 1.0 # how often each IoT client sends a task
  task_timeout_s: 2.0    # client task timeout (a drop attacker trips this)
  task_work_ms: 40       # real CPU work per task (the hash loop length)
```

`params_demo.yaml` has **no** `controller`/`security`/`agents` blocks — its
absence of a `controller:` block is exactly what makes `topology.py` run the
"plain" (non-trust) demo. `params.yaml` is the same shape at 8/40/3 scale.

---

## Part 8 — The environment and how it was set up

- **OS:** Ubuntu 26.04, which ships **only Python 3.14** (no 3.9–3.13, no
  pyenv/uv). This forced the **Ryu → os-ken** switch (Part 2.4).
- **os-ken quirk:** Ubuntu's `python3-os-ken` is a trimmed build — it omits the
  `os-ken-manager` CLI and the example apps, so the repo includes hand-written
  replacements (`controller/osken_manager.py`, `controller/learning_switch_13.py`).
- **OpenFlow port:** os-ken uses TCP **6653** (the modern IANA port), not the old
  6633.
- **No venv / no pip on the dev box:** everything installs as `apt` packages
  (`python3-os-ken`, `python3-numpy`, `python3-scipy`, `python3-sklearn`,
  `python3-matplotlib`, `python3-seaborn`, `python3-pytest`, `python3-joblib`,
  plus `mininet`, `openvswitch-switch`, `iperf`/`iperf3`, `wireshark`).
- **sudo is interactive-password-only:** an AI assistant session cannot type the
  password, so any root command (running Mininet, `ovs-vsctl`, apt) is handed to
  the human to run. Unit tests need no sudo.
- **CI:** `.github/workflows/ci.yml` runs the pytest suite on every push/PR on a
  GitHub runner (installs os-ken from PyPI + `requirements.txt` on Python 3.12).

Full, exact commands live in **`SETUP.md`** — that is the run-book; this guide is
the explanation.

---

## Part 9 — How to run everything

Three ways to see the system, in increasing realism. Exact commands are in
`SETUP.md`; here is what each one *is*.

### 9.1 Unit tests (no sudo, no Mininet — works anywhere)

```bash
python3 -m pytest tests/ -v      # expect 105 passing
```

### 9.2 Standalone trust-engine simulation (no Mininet)

```bash
python3 run_demo.py --mode standalone --duration 120 --attack both
```

Runs the trust maths against scripted attacks and writes figures + a routing CSV.
Fast and seedable. Good for showing the trust formula isolating a Sybil node
without any networking.

### 9.3 The live trust demo (three terminals, needs sudo for Mininet)

This is the flagship. Summarised (full block in `SETUP.md` §3b):

- **Terminal A — controller** (no sudo):
  `python3 -m controller.osken_manager controller.trust_balancer`
- **Terminal B — network** (sudo): `sudo mn -c` first (clears stale state),
  then `sudo python3 -m simulation.topology --config config/params_trust_demo.yaml --interactive`
- **Terminal C — watch** from the Mininet CLI: `dpctl dump-flows -O OpenFlow13`,
  `iot1 ping srv3`, `sh ovs-ofctl -O OpenFlow13 dump-meters s0`, etc.

What to look for (all documented in `SETUP.md` §3b-extra): `Routed …→ srvN`
lines, then `QUARANTINE: srv3`, priority-400 drop rules with climbing packet
counters, a failed `ping srv3` while `ping srv2` works, the `Re-dispatched …`
line, `AUTH DENIED` for `iot12`, and metered flows.

### 9.4 The dashboard (browser)

Live (during 9.3): open `http://localhost:8081/`. Or offline, no sudo:

```bash
python3 -m dashboard.replay data/events.jsonl --loop   # then open localhost:8082
```

Shows the topology, animated traffic (from real counters), the live flow rules,
each server's trust, and total link throughput.

---

## Part 10 — The data-plane flow rules

This is the heart of "enforced in the data plane". The controller uses a
**two-table pipeline** on every switch. Full spec with matches and priorities is
in `docs/FLOW_RULES.md`; the essentials:

- **Table 0 (`TABLE_VIP`)** handles the VIP: proxy-ARP for the VIP address,
  per-connection rewrite rules (the routing decision), quarantine drops, and the
  punts that create PacketIn events.
- **Table 1 (`TABLE_L2`)** is a plain MAC-learning switch for everything else.

Priority order (high wins): **400 quarantine-drop** > **350 ARP-punt** > **300
VIP-rewrite** > **250 new-connection-punt** > **0 table-miss**. This order is
load-bearing — e.g. the drop rule must out-rank a stale rewrite rule so a
quarantined server's traffic dies even before its old rules time out.

**Cookie scheme:** controller-installed rules carry a 64-bit "cookie" of
`0x5A000000000000NN` where `NN` is the server index. This lets one command delete
*all* of a server's rules on quarantine, and lets the dashboard colour rules by
server.

**Meters:** a separate table of rate-limiters. Each server has one meter (id =
its index) with a drop band at the configured kbps. A suspect server's VIP
forward rule carries an `OFPInstructionMeter` pointing at its meter. If a switch
doesn't support meters, the controller detects that on connect and silently
falls back to plain allow/quarantine.

---

## Part 11 — What is built vs what is planned

| Component | Status |
|-----------|--------|
| Environment (Mininet, OVS, os-ken, Python 3.14) | ✅ Done |
| Trust formula + calculator | ✅ Done |
| Standalone trust simulation (`run_demo.py`) | ✅ Done |
| Mininet topology + live controller connectivity | ✅ Done |
| Trust-aware controller (EdgeScore routing, quarantine, REST API) | ✅ Done, human-verified live |
| Data-plane drop rules on quarantine | ✅ Done (Sprint 2 W1) |
| Measured-RTT latency term | ✅ Done (Sprint 2 W1) |
| Post-quarantine client re-dispatch | ✅ Done (Sprint 2 W1) |
| Blockchain ledger (SHA-256 + order-sensitive Merkle) | ✅ Done (Merkle fixed Sprint 2 W1) |
| Live dashboard (topology, packets, rules, trust, throughput) | ✅ Done (browser-verified) |
| GitHub Actions CI | ✅ Done (Sprint 2 W1) |
| **PRESENT-80 authentication** (cipher + auth + live wiring + malicious-IoT) | ✅ Done (Sprint 2 W2) |
| **Link-load telemetry** (port stats) | ✅ Done (Sprint 2 W2) |
| **Graduated response** (rate-limit meters) | ✅ Done (Sprint 2 W2) |
| **Flow-rule specification** (`docs/FLOW_RULES.md`) | ✅ Done (Sprint 2 W2) |
| RAFT consensus (`blockchain/raft.py`) | 🟡 Core built + 26 tests in isolation; TCP transport and the `RaftBackend` swap still outstanding |
| Evaluation harness (baselines + Wilcoxon stats) | 🔲 Planned (Week 5–6) |
| AI weight optimizer (Random Forest + UCB1) | 🔲 Planned (Week 7) |
| Full-scale integration (8/40/3) | 🔲 Planned (Week 8) |

**Live verification still owed by a human:** the Sprint 2 observables in
`SETUP.md` §3b-extra (drop counters, meters, PRESENT-80 denial). Also, OVS meter
support on the specific dev machine is unverified — the capability probe will
report at runtime, and the code degrades gracefully if unsupported.

---

## Part 12 — The development history (Sprints)

- **Phase A** — environment set up (Mininet/OVS/os-ken/sci-stack).
- **Phase B** — verified the standalone trust simulation (isolates Sybil,
  degrades drop node).
- **Phase C** — the advisor's first ask: plain Mininet + live controller,
  pingall + iperf through it.
- **Phase D Sprint 1** — the trust-aware controller: EdgeScore routing enforced
  as flow rules, anomaly detection, REST API, then the live dashboard.
- **Phase D Sprint 2 — Week 1 (hygiene + traffic engineering):** committed &
  pushed all prior work + CI; fixed the Merkle order bug, the `run_demo` before/
  after-score bug, and the hardcoded attack targets; rewrote the stale README;
  added data-plane drop rules on quarantine, measured-RTT routing, and
  post-quarantine re-dispatch. (69 tests.)
- **Phase D Sprint 2 — Week 2 (this session):** PRESENT-80 (cipher + authenticator
  + live wiring + malicious-IoT device), link-load port-stats telemetry,
  graduated-response OpenFlow meters, and `docs/FLOW_RULES.md`. (105 tests.)

The honest roadmap, legacy-vs-novelty analysis, and cut-list are in
`DIRECTION.md`; the problem validation and viva "trap" framings are in
`PROBLEM_AND_IMPACT.md`.

---

## Part 13 — Glossary

| Term | Plain meaning |
|------|---------------|
| **SDN** | Software-Defined Networking — split the network "brain" (controller) from the "muscle" (switches). |
| **Data plane / control plane** | The muscle (switches moving packets) / the brain (the controller deciding rules). |
| **OpenFlow** | The protocol the controller uses to install rules in switches. This project uses v1.3. |
| **Flow rule / flow entry** | A match + action + priority stored in a switch's flow table. |
| **PacketIn** | A packet a switch sends up to the controller (only happens for packets no installed rule handles, e.g. a new connection's first packet). |
| **FlowMod** | A message from the controller that installs/changes/deletes a flow rule. |
| **Controller** | The program that is the SDN brain. Here: `TrustBalancerApp`, built on **os-ken**. |
| **os-ken** | The maintained fork of the **Ryu** SDN framework; used because Ryu doesn't run on Python 3.14. |
| **Mininet** | A tool that emulates a whole network (hosts + switches + links) on one machine. |
| **Open vSwitch (OVS)** | A real software OpenFlow switch. |
| **Network namespace** | An isolated networking sandbox; each Mininet host has its own, which is why you run per-host commands via the Mininet CLI. |
| **Zero Trust** | "Never trust, always verify" — continuously prove every actor is behaving. |
| **Trust score (T)** | A `[0,1]` number summarising a server's recent trustworthiness. |
| **EMA** | Exponential Moving Average — a running average that favours recent data. |
| **EdgeScore** | The routing score: blend of trust, spare CPU, and low latency. |
| **VIP (Virtual IP)** | One fake address all clients use; the load balancer secretly rewrites it to a real server. |
| **Quarantine** | Cutting a server off entirely (delete its rules, drop its traffic, re-route its clients). |
| **Anomaly gate** | A separate quarantine trigger on the anomaly signal, needed because the trust score alone can't catch a competent liar. |
| **Graduated response / band** | Full vs rate-limited vs quarantined — a proportional reaction to how suspect a server is. |
| **Meter** | An OpenFlow rate-limiter attached to a flow. |
| **Sybil attack** | A server lying about its load (e.g. "I'm idle") to attract traffic. |
| **Drop attack** | A server that accepts a task then silently never answers. |
| **Merkle tree / root** | A hash structure that summarises many records into one hash and lets you prove membership. |
| **RAFT** | A consensus algorithm keeping several ledger copies in agreement despite crashes. Core built in isolation; not yet replicating the live ledger. |
| **PRESENT-80** | A lightweight block cipher (64-bit block, 80-bit key) used for IoT device authentication. |
| **Northbound API** | The controller's REST API "above" it, for operators/dashboards (as opposed to the "southbound" OpenFlow toward switches). |
| **NFR** | Non-Functional Requirement — a performance target (e.g. isolate a bad node in < 3 s, routing decision < 200 ms). |

---

*This document explains the system as it stands after Sprint 2 Week 2. For
exact run commands see `SETUP.md`; for the rule table see `docs/FLOW_RULES.md`;
for the honest roadmap see `DIRECTION.md`.*
