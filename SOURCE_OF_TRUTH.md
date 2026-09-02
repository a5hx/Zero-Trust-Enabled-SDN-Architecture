# Source of Truth — everything built since `c3e6824`

*Covers commits `c3e6824..710c80c` (9 commits, 2026-08-06 → 2026-08-09), plus
the uncommitted live run 11 recording scored on 2026-08-11.*

This is the **single reference for the current state of the project**: what was
built, what it measures, what the live runs actually say, what is still broken,
and how to run every part of it. It consolidates `plan_adv.md` (the phase plan)
and `panel_fix.md` (the defect register) into one document and adds the
run-11 numbers, which appear in neither.

| Document | Role |
|---|---|
| **`SOURCE_OF_TRUTH.md`** (this file) | Consolidated state, results, and what's open |
| `final_run.md` | The runbook — every command, in order |
| `SETUP.md` | Install, environment, per-feature deep dives |
| `plan_adv.md` | Phase plan and per-phase status (long form) |
| `panel_fix.md` | Defect register — what was wrong, how we knew (long form) |
| `docs/` | `AI_OPTIMIZER.md`, `FLOW_RULES.md`, `LOAD_BALANCING_STARVATION.md`, `RAFT.md` |

---

## 1. Executive summary

Before `c3e6824` the system could **detect and isolate** two attacks (sybil,
blackhole) and report NFR pass/fail. Since then it can:

1. **Simulate six attacks** — sybil, blackhole, grayhole, on-off, DDoS/flooding,
   identity spoofing — plus bad-credentials devices as a seventh ground-truth
   class, all with **delayed onset** so each attack has a clean baseline before it.
2. **Name the attack**, not just flag it. `controller/attack_classifier.py`
   turns detector signals into one discrete label per subject, live and offline
   from the same implementation.
3. **Score itself against ground truth** — confusion matrix, per-class
   precision/recall/F1, detection latency, service availability, and a
   full-system scalability sweep to N=64.
4. **Draw six time-series charts** in the live dashboard (throughput, delay,
   PDR, Jain fairness, offered-vs-served load, packet drop) with attack onsets
   shaded from ground truth — plus a second panel splitting the same metrics
   **per cluster**, so an attack's damage can be seen to be localised rather
   than averaged away (§3.7), and a client-load panel comparing p2c against
   argmax across 20→40 IoT devices (§3.7b).
5. **Show the trust ledger, and let the browser check it.** A hash-linked block
   ribbon whose SHA-256 is recomputed **in the page** from the streamed block
   header rather than taken from the controller's own `valid` flag, anchored on
   a genesis block the page rebuilds itself, with a tamper control that breaks
   the chain locally and localises the break to the seam (§3.7c).
6. **Refuse an identity spoof** that previously succeeded, and stop charging an
   honest node for a task a quarantine tore off the wire before it ever arrived.

Five live runs (7 → 11) drove this. The measured trajectory:

| | run 7 | run 8 | run 9 | run 10 | **run 11** |
|---|---|---|---|---|---|
| Date | 08-07 | 08-07 | 08-08 | 08-08 | **08-11** |
| Length | 316.8 s | 311.7 s | 325 s | 320.5 s | **213.1 s** |
| Honest-node availability | 48.05% | 98.90% | 100.00% | 91.8% worst node | **100.00%** |
| Honest nodes never quarantined | — | 3/4 | 4/4 | 3/4 | **4/4** |
| Route denial | 28.3% | 0.0% | 0% | 0% | **0.0%** (0 / 3,927) |
| Total outage | 71.3 s | none | none | none | **none** |
| Time at/above 50% quorum | 26.4% | 100% | 100% | 98.5% | **100.0%** |
| Classification accuracy | 83.3% | 93.8% | 93.8% | **97.9%** | 95.8% |
| Attacks classified correctly | 5/8 | 6/8 | 5/8 | **8/8** | 6/8 |
| Attacks in the right family | 7/8 | 8/8 (est.) | 6/8 | **8/8** | **8/8** |
| Honest subjects wrongly labelled | 5/40 | 1/40 | 0/40 | 1/40 | **0/40** |
| All four NFRs | — | PASS | PASS | PASS | **PASS** |

**Run 10 is the best classification result. Run 11 is the best defence result** —
the first run with zero honest quarantines, zero honest mislabels, zero route
denials, and zero outage simultaneously. The two are not the same run, and §5.3
explains why that is not a contradiction.

**Test suite: 669 tests, 661 passing** (was 344 at `c3e6824`). The 8 failures are
a pre-existing scipy version mismatch in `evaluation/stats.py` — see §8.

---

## 2. Commit map

| Commit | Date | What landed |
|---|---|---|
| `804f03a` add/classification | 08-07 | Phases 0–2: delayed onset, 4 new attacks, `attack_classifier.py`, `flood_detector.py`, source-IP pinning, `attack_report.py`, `params_trust_full.yaml` |
| `34e1455` add/scalability-sweep | 08-07 | Phase 3: `evaluation/scalability_sweep.py` (M/M/c per node, real timeouts) |
| `a247ce4` add/service-availability | 08-07 | Phase 4: `evaluation/availability_report.py` |
| `80bce64` update/dashboard | 08-07 | Phase 5: six time-series charts in `dashboard/index.html`; three demo-recording fidelity bugs fixed |
| `8524d57` fix | 08-08 | Phase 7: on-off eagerness, the lying-vs-dropping weighing rule, trust-rail evidence; live-config preflight |
| `035a7d9` fix/run-9 | 08-08 | `DEFAULT_MIN_LYING_SHARE` 0.50 → 0.25 (run 9 regression) |
| `9f5c2c5` plan-9-postfix | 08-08 | Phase 8: accept-queue 5→128, retry-vs-403, provisioned identity roster, `identity_unclaimed` |
| `bbd6622` run10 | 08-08 | Run-10 write-up only |
| `710c80c` fix/resteer-attribution | 08-09 | Phase 9: re-steered dispatches are not chargeable |

**Totals:** 34 files, **+9,713 / −95 lines**. 11 new source modules, 12 new test
files.

---

## 3. What was built

### 3.1 Six attacks, all with delayed onset

`start_s` was in the config files all along and silently ignored; Phase 0 wired
it through `topology.py` → `node_agent.py --malicious-start-s`. Before arming, an
attacker is behaviorally **identical** to an honest node, so every attack has a
clean baseline interval before it.

| Attack | Where | Flags | How it's caught |
|---|---|---|---|
| **sybil** | `node_agent.py` | `--malicious sybil` | latency tell (claims idle, answers `/status` slowly) |
| **blackhole** | `node_agent.py` | `--malicious drop` | timeout-rate tell |
| **grayhole** | `node_agent.py` | `--malicious grayhole --grayhole-drop-rate` | timeout-rate tell, weaker per sample |
| **on-off** | `node_agent.py` | `--malicious onoff --onoff-period-s --onoff-duty` | latency tell + sustained intermittency |
| **DDoS / flood** | `iot_client.py` | `--malicious flood --flood-concurrency --flood-interval-s` | `flood_detector.py`, keyed on the **client** |
| **identity spoof** | `iot_client.py` | `--malicious spoof --spoof-target-device-id` | source-IP pin → `auth_denied kind=ip_pin` |
| *bad credentials* | `security.malicious_iot_devices` | (wrong key) | `auth_denied kind=bad_response` |

Two design decisions worth defending out loud:

- **The flood tell is keyed on the requesting client, never on the edge node it
  lands on.** A server drowning under a flood is not lying about its load — it
  is telling the truth about being overwhelmed. Blaming the node would repeat a
  mistake this project has already made twice.
- **A literal replay attack was already structurally impossible** (`verify_response`
  pops the nonce on first use). Building a fake version of an attack the system
  already defeats would have been dishonest. The real gap was that the shared key
  is **fleet-wide**, so PRESENT-80/HMAC authenticate *possession of the key*, not
  *the device* — which is what source-IP pinning closes.

**DDoS enforcement is deliberately not built.** Flooding is detected and
classified but not throttled; auto-dropping a flooding client needs a
per-client-IP OpenFlow path, and today's rate-limit/quarantine machinery is all
per-edge-node. Deferred as real scope rather than half-built (§6.1).

### 3.2 `controller/attack_classifier.py` — the label

A **pure function over an evidence window**. No I/O, no locks, no `TrustState`,
so the live controller and the offline scorer reach the same verdict from the
same evidence by calling one implementation rather than two that drift.

**A window, not a single cycle**, because two of the six pairs are not separable
from one cycle's signals: blackhole vs grayhole fire the *same* signal and differ
only in **magnitude**; sybil vs on-off fire the *same* signals and differ only in
**intermittency**.

Rules that survived contact with live data:

- **Lying beats dropping — by weight, not precedence.** The original rule promoted
  any node raising a lying signal into the sybil family, on the premise that a
  pure dropper never raises a lying signal. Run 7 disproved that premise. It is
  now a weighing rule: the lying signal must carry ≥ `DEFAULT_MIN_LYING_SHARE`
  (**0.25**, swept safe band 0.15–0.40) of family-bearing cycles.
- **Blackhole vs grayhole splits on the *median* timeout rate, not the max.** A
  grayhole's rate is a binomial sample over a 10-deep window and *will* touch 1.0
  by chance; a max-based rule relabels it on one unlucky draw.
- **On-off requires *sustained* intermittency** — qualifying off phases must
  account for ≥20% of the active span. Derived from an on-off attacker's duty
  cycle, not fitted. (The periodicity check originally proposed would **not** have
  worked: srv3's two false gaps were the same length, i.e. perfectly regular.)
- **`node_down` is kept strictly separate from the six attacks.** This project's
  blackhole answers `/status` fine and drops only `/task`, so "silent" is a
  liveness failure. Folding it in would inflate exactly the numbers this module
  exists to measure honestly.
- **Abstains on stale or absent evidence.** Auth verdicts latch, load/traffic
  verdicts do not — "presented another device's identity at t=5" is a historical
  fact, "is currently slow" is a condition.

**Two resolution limits, documented rather than tuned away.** Classifying on-off
*as* on-off requires observing a quiet stretch, so (1) the attacker's good phase
must outlast the detector's reaction time (`ONOFF_MIN_GOOD_PHASE_S` ≈ 4 s), and
(2) the evidence window must span a whole on-off period or it mostly holds one
phase and reports sybil. In both cases the attacker is **still caught and
quarantined** — only the label degrades. Both are pinned by tests so a future
"shrink the window" change fails loudly.

### 3.3 Three plumbing gaps closed before the classifier existed

A confusion matrix on the then-current event stream could not have been honest:

1. **Auth denials were never published.** `/auth/verify` returned 403 and told
   nobody, so a spoof left no trace. `AuthError` gained a structured `kind`
   (`ip_pin` / `bad_response` / `no_challenge` / `nonce_expired`) and
   `northbound_api.py` publishes `auth_denied`. **The kind is the only thing
   separating an insider spoofing with the fleet key from a device that never
   held it.**
2. **Ground truth was edge-node-only.** 2 of the 6 attacks (flood, spoof) had no
   confusion-matrix row and would have vanished rather than been scored. The
   `topology` event now carries `attack` + `attack_start_s` for IoT nodes too.
3. **Signals were free-text prose.** `anomaly` now carries a parallel
   machine-readable `signals` dict. `reasons` is untouched.

### 3.4 Four analysis tools

All read the same `data/events.jsonl` a live run writes; none needs the
controller stack installed.

| Tool | Answers |
|---|---|
| `evaluation/nfr_report.py` | The four NFRs, pass/fail, whole run |
| `evaluation/interval_report.py` | Every metric vs time, 10 s buckets |
| `evaluation/attack_report.py` | Confusion matrix, per-class P/R/F1, detection latency |
| `evaluation/availability_report.py` | Service availability / "network lifetime" |

**`attack_report.py` replays rather than tallies.** Live `classification` events
record label *changes* (rising edge only), so counting them would weight a
subject that flapped once the same as one that held a verdict all run. It
rebuilds the per-cycle evidence — using `node_status` as the heartbeat supplying
the clean cycles `anomaly` alone cannot — and re-runs the same classifier, which
also makes the offline number unable to silently disagree with the live one. The
run verdict is the **modal** label, not the final one. `NO_ATTACK` is scored as a
real class, because it is the one that catches false accusation of honest nodes.

**`availability_report.py` never prints a combined figure.** Quarantine downtime
means *opposite* things for the two groups — an isolated attacker is enforcement
working, an isolated honest node is the system's real cost — so the headline
counts **honest nodes only**, attacker downtime is reported separately as
*containment*, and absent groups report `None`, not `0.0`. It also surfaces two
failure modes this project has actually shipped: **stranded honest nodes**
(`never_recovered` — the absorbing-state defect) and **teardown misread as
collapse** (warned about, never silently trimmed; a knob that discards
inconvenient tail data is a knob that will eventually be used to flatter a
result).

**The WSN "network lifetime" metric was reframed, not faked.** No energy model
exists in this repo and inventing one for mains-powered edge servers would be a
fabricated number dressed as a measurement. Isolation stands in for death: time
to first death → time to first isolation; time to 50% dead → time below serving
quorum; network lifetime → time above it.

### 3.5 `evaluation/scalability_sweep.py` — full-system metrics vs N

A **new module, not an extension of `starvation_sweep.py`**, and the reason is
load-bearing: `starvation_sweep.py` models an **infinite-server** farm (an arrival
is served immediately, nothing queues, nothing times out). That is exactly right
for "who does the selector pick?" and is why its published tables are
trustworthy — but it makes delay flat in N *by construction*, PDR 1.0 *by
construction*, and throughput equal to the offered rate. Extending it in place
would also have silently invalidated those tables.

New model: **M/M/c per node** with an unbounded FIFO and real task timeouts. A
timed-out task is counted as loss but deliberately **not** removed from the node —
the client abandoned it, the node has no idea, the worker stays occupied. That
wasted capacity is what makes an overloaded fleet degrade instead of gracefully
shedding load. Trust is **composed** (`T = αR + β + γ`), not equated with the
reliability EMA, or a single timeout drops an honest node to 0.075 and quarantines
the fleet — a modelling artifact, since a merely-slow node still scores full marks
on behaviour and honesty.

**Results (seed 1, 120 s cells, N = 4..64):**

1. **p2c scales linearly; argmax saturates.** At 60% load p2c gives
   **48 / 95 / 192 / 382 / 762 tasks/s** for N = 4/8/16/32/64 — a clean doubling
   per doubling — at PDR 99.7–99.8% and ~266 ms mean delay throughout. argmax
   saturates at ~85 tasks/s from N=8 and its PDR falls
   **99.2% → 91.7% → 45.8% → 21.3% → 10.5%**, delay pinned at the ~2 s timeout ceiling.
2. **argmax fails two different ways at the two ends of offered load**, which is
   why load became a sweep axis. At **10%** it starves (13/16 nodes idle, Jain
   0.176; 23/32 at N=32). At **60%** almost nothing is starved (Jain 0.75–0.85)
   because queues finally push the CPU term away from the favoured nodes — the
   fleet ends up balanced *and* broken. Reporting either end alone makes argmax
   look merely unfair, or merely slow, instead of both.
3. **p2c is *not* a per-decision CPU win** — worth saying because it is the
   intuitive claim and it is wrong here. Both strategies cost the same and both
   grow ~linearly with N (3/5/9/16/30 µs at N=4/8/16/32/64), because
   `select_edge_node` scores and sorts **every** eligible node regardless of
   strategy — that ranking is returned as the *explanation* of the decision. A
   deliberate trade: explicability bought with CPU that is nowhere near a
   bottleneck. **Not to be "optimised" away without consciously giving up the
   ranking.**

### 3.6 Dashboard time-series charts

Six small-multiple line charts in a "Metrics over time" panel: throughput, task
delay (mean + p95), PDR, Jain fairness, offered-vs-served load, and packet drop.
Before this the dashboard had **no** time-series at all, so an attack's effect on
throughput/PDR/delay was invisible while it was happening. Attack onsets are
shaded from ground truth, labelled as *configured arming time* — not as a claim
about when the controller detected anything.

- **Binned in the browser with the same rules as `interval_report.py`.** They
  cannot share code (browser JS vs. Python that must run without the controller),
  so the coupling is **pinned** instead: `tests/test_dashboard_charts.py` asserts
  the bucket width against `DEFAULT_BUCKET_S` and the drop-rule priority across
  all three copies (dashboard → `interval_report` → `trust_balancer.PRIO_QUARANTINE_DROP`).
- **Task loss and OpenFlow quarantine drops stay separate series** — never summed
  into one "drops" line.
- **Redraw throttled to 2 Hz.** A sustained flood is hundreds of events/sec, and
  rebuilding six SVGs per event would let the attack traffic slow the dashboard
  down — a bad demo and a small self-inflicted DoS.
- Colour computed rather than eyeballed, via the `dataviz` palette validator
  against **this panel's** surface (`#161b22`): lightness band, chroma floor,
  adjacent CVD separation, normal-vision separation and 3:1 contrast all PASS.

**A flat line in a chart is a hypothesis about the data before it is one about
the chart** — and it was. Three demo-recording fidelity bugs fell out of actually
looking at the charts: the serving VIP rule was emitted at `priority: 400`
(= `PRIO_QUARANTINE_DROP`, so every consumer read serving traffic as drops), the
drop rule was marked `is_vip: False` (making the OpenFlow-drop series
unreachable), and serving/drop rules used different cookie bases (which no real
run produces — one cookie per node is the mechanism quarantine relies on). This
also means **`interval_report.py` had been reporting zero throughput and zero
OpenFlow drops for that recording** — the charts did not introduce the fault,
they made an existing one visible.

### 3.7 Dashboard: per-cluster time-series (2026-08-11)

A second "Metrics over time — by cluster" panel below the fleet one. Same
buckets, same metric definitions, but attributed **per serving node** and summed
into two clusters (halves of the server roster: srv1–4 and srv5–8).

**No controller change was needed.** Every event the panel bins already carries
the serving node — `route.chosen`, `report.node`, `flow_stats.rules[].node` —
so this is a different *aggregation* of existing evidence, not new
instrumentation. Verified against run 11's recording: cluster A + cluster B
equals the fleet series **exactly** in every bucket, for throughput, requests
routed (6,025), tasks lost (92) and quarantine drops (722). Nothing is lost or
double-counted.

Four constraints the design had to respect rather than route around:

1. **The split is positional, not physical, and the panel says so.** This
   topology gives every server its own edge switch off one core switch, so
   srv1–4 / srv5–8 are not two racks or two failure domains. Cluster membership
   is printed on the panel and the caption calls the split positional, so a
   reader cannot infer a locality that isn't there.
2. **One colour per cluster, held across every chart** — a hue that means
   "cluster A" on one plot and "p95" on the next is worse than no colour. That
   fixes the series budget at two, which is exactly the two validated palette
   slots this surface has. **A third cluster needs the validator re-run**, not a
   hand-picked hue; pinned by a test.
3. **Task loss and quarantine drops get a chart each.** Both series slots are
   spent on clusters, so they cannot share a plot — the packet-drop discipline
   held harder, never a summed "drops" line.
4. **No offered-load chart.** `route_denied` carries no chosen node, so offered
   traffic cannot honestly be attributed to a cluster. The chart plots requests
   *routed* and is titled that way.

Both panels draw through **one renderer** — a second implementation would drift,
the same argument the binning rules already answer that way. Delay is p95-only
here (the mean lives in the fleet panel above); binning stays per-node and
resolves to clusters at render time, so events arriving before the topology
event are not silently dropped.

**It shows real signal.** In run 11, srv6's blackhole arms at t=30 s and srv6
sits in cluster B: cluster B's PDR falls to **84.3%** with 14 tasks lost in that
bucket while cluster A holds **100%**. That separation is invisible in the
fleet-wide panel, which averages it to ~92%.

**Verification limit — narrowed on 2026-08-13.** This previously read "no JS
engine is installed on this box, so this panel's JS was not executed". A
`quickjs` interpreter was installed for the §3.7b work, and the cluster panel
was executed through it against a DOM stub: it renders all seven charts, 14
polylines (two series each), its attack bands, and a membership key reading
`cluster A (srv1–srv4) / cluster B (srv5–srv8)`. What remains unexecuted is real
browser DOM/SVG layout — the stub returns markup, not a rendered document. The
aggregation rules are separately mirrored in Python and run over run 11's real
recording, where all four conservation checks pass exactly.

### 3.7a Three chart defects found by looking at the panel (2026-08-11)

A screenshot of the live panel showed an x-axis reading **`16770s`** on a run
that was seconds old, and four charts where there should have been six. Three
separate defects, all of which had been shipping since Phase 5:

**1. The chart timeline was anchored to the page, not the run.** `CH.t0` was the
first event the *browser* ever saw. The controller is the same process that
serves the page, so it routinely outlives several topologies — a page left open
had `t0` hours in the past. Three consequences, and the second is the serious
one:
  - the x-axis read in absolute seconds since the page connected (`16770s`);
  - **the ground-truth attack bands never rendered.** They are drawn at bucket
    `attack_start_s / BUCKET_S`, i.e. buckets 2–6, which sat ~1,600 buckets left
    of the visible window. The shaded onsets are the panel's whole ground-truth
    device, and they were silently absent;
  - the previous run's state survived into the next: `vipBps` kept
    forward-filling throughput for flow rules that no longer existed (a flat
    line at a stale rate — visible in the screenshot as 10.0 kbps dead flat),
    and `prevDropPkts` held cumulative baselines for counters that had reset.

  Fixed by re-anchoring on the `topology` event, which fires exactly once per
  run and is the closest thing on the bus to "the network now exists" — which is
  what `attack_start_s` is relative to. **This makes the live panel agree with
  `interval_report.py` rather than diverge from it**: a recording's first event
  *is* its topology event, so the offline report already bins from that instant.
  Pinned by a test that fails if topology ever stops being emitted first.

  It also fixes an unrelated double-count: SSE backfill replays history on every
  reconnect, and without a reset those events were binned a second time on top
  of themselves.

**2. A chart with no data vanished from the grid.** `if (!flat.length) return ''`
dropped the whole element, so six charts silently became four and a reader could
not tell "nothing reported yet" from "this chart was removed". Task delay and
PDR are the two that hit it, since both come only from `report` events and a run
has none until its first task completes. Now renders the frame with an explicit
*no data in this window yet*, at the same height so the grid does not reflow.

**3. `topology` was evicted from the SSE backfill within seconds.**
`EventBus._history` is a 500-event ring, and the current recording runs at
**~66 events/s** — so the backfill window is about **7.5 seconds**. A browser
opened any later than that into a run received no `topology` at all, and with it
no server roster, no attack onsets and no cluster membership. Every panel built
on it then rendered *empty rather than erroring* — a silent failure, and the one
that makes "open the dashboard mid-run" unreliable as a demo step.

  Fixed with a sticky-type pin: the latest `topology` is retained outside the
  ring and prepended to `history()` when it has aged out, never duplicated when
  it has not, and always **first** — a `route` naming srv6 is not interpretable
  before the topology that says what srv6 is. Only the latest is kept, so a
  second run against the same controller replaces the roster rather than
  offering two.

**Verified by simulation** against the screenshot's own numbers: driving 4.67 h
of stale stats then a topology event reproduces the `16600–17190s` axis and an
attack band 1,600 buckets off-screen; with the re-anchor the axis restarts at
`0s` and the band lands in-window. 10 new tests.

### 3.7b Dashboard: client-load panel, 20→40 IoT devices (2026-08-13)

A third chart panel, **"Client load — 20→40 IoT devices"**. Six charts, x = the
IoT device count, p2c against argmax, with the roster held at
`config/params.yaml`'s **8 edge servers**. Generated by
`evaluation/scale_compare.py`, served over `/api/scale_compare`.

**It could not be a re-binning of the panels above**, and that is the design
constraint. A run has one device count and one roster; comparing five device
counts means five separate runs and one point per run. So this is a different
chart type (not a time series), on a different x quantity (a count, not elapsed
seconds), from pre-computed data (not the event stream). Each of those is a way
for a reader to be misled, which is what the constraints below answer.

**A fleet-size row was built and then removed the same day.** It swept 20→40
edge *servers*. The live topology has 8, no 40-server run has ever existed, and
that row projected five fleet sizes past anything ever instantiated on the
strength of a queueing model — a projection sitting on the same page as live
charts, which is not defensible under questioning. No capability was lost:
`scalability_sweep.py` has always swept N and still does on the CLI
(`--ns 20,25,30,35,40`), where the numbers read as a simulation harness's output
rather than as a dashboard panel. Its absence is pinned by a test so it is not
reintroduced from memory.

**What survives is bounded by the shipped topology at both ends.** 8 servers is
`num_edge_nodes`; 40 devices is `num_iot_devices`. The right-hand edge of the
chart *is* the demo configuration. That makes this interpolation inside the
deployed config rather than extrapolation beyond it — a real reduction in how
much the model is asked to carry, and **still not a live measurement**, which
the panel says in those words.

**What the panel shows.** 20→40 devices is 12.5%→25% of farm capacity, which is
argmax's *starvation* regime rather than its saturation one, so the failure is
quiet:

| metric | p2c (20→40 devices) | argmax (20→40 devices) |
|---|---|---|
| throughput | 19.4 → 39.7 tasks/s | 20.0 → 40.3 tasks/s |
| PDR | 99.7 → 99.9% | 99.9 → 99.4% |
| mean delay | **196 → 204 ms** (flat) | **300 → 670 ms** (climbing) |
| Jain fairness | 0.936 → 0.980 | 0.281 → 0.394 |
| servers actually serving | **8 / 8** | **3 / 8** (4/8 at 40) |

**Throughput and PDR do not separate the two strategies anywhere in this
range.** An evaluation reporting only those two would conclude the selectors are
equivalent; argmax is meanwhile running the entire workload on three machines,
and paying for it in a delay that more than doubles across the sweep while p2c's
stays flat. That is the panel's whole point, and it is why fairness and the
serving-node count sit next to throughput rather than in an appendix.

**Four constraints the design had to respect:**

1. **No new simulation model.** `scale_compare.py` contains none — it calls
   `scalability_sweep.run_sweep` with `ns=[8]` and a swept `load_factors`,
   which drives the real `select_edge_node`. A third model for what is only a
   different choice of axis is the drift `starvation_sweep.py` and
   `scalability_sweep.py` were split to avoid.
2. **Still one renderer.** `renderCharts` was **parameterised, not forked**:
   `opts.rows` supplies the row objects, `opts.xOf` maps a row to its numeric x,
   `opts.xLab` labels the end ticks. A second implementation would drift in
   units, tick precision and empty-state handling. Pinned by a test that counts
   the definitions.
3. **Attack bands are suppressed on a non-time axis.** They mark a moment in
   *time*; drawn against a device count they would shade some unrelated run's
   arming second at "30 devices" — nonsense carrying the authority of a shaded
   region. `bands: false`, pinned by a test.
4. **The panel states what is real and what is modelled, on the panel.** Not
   just "simulation": the note says the *selector* is the shipping
   `select_edge_node`, and that the servers are M/M/c queues and **the network
   is not modelled at all** — no OpenFlow round trips, no flow-rule
   installation, no propagation delay. "Simulation" alone invites a reader to
   assume the routing logic was modelled too, when it is the real function.
   Pinned by a test.

**Not calibrated against the live run, and it does not claim to be.** Device
count is converted to an offered rate with the live arithmetic
(`num_iot / report_interval_s`, `config/params_trust_full.yaml`), but that rate
is expressed against the *harness's* farm capacity, whose 200 ms service time is
not the live `task_work_ms` of 15–40 ms. The sweep at 8 servers therefore does
not reproduce live-at-8-servers, and no such agreement is asserted anywhere.
Live figures are in `docs/LIVE_RUN_8_40_3.md`.

`data/` is gitignored, so a fresh clone has no sweep. That is the normal case,
not an error: the route 404s with the command in the body and the panel prints
it, the same way `replay.py` handles a missing recording.

### 3.7c Dashboard: the trust ledger, verified in the browser (2026-08-13)

A **"Trust ledger"** panel, full width below the topology: a hash-linked ribbon
of the last 10 blocks, a pending-batch gauge, live commit cost against the
blockchain-overhead NFR, and a tamper control.

**The `block` event had been published and dropped since Phase 5.**
`trust_balancer._on_block_committed` has emitted one `block` event per commit
for months — `evaluation/nfr_report.py` consumes it for the overhead NFR, and
the dashboard had no `case 'block':` at all. The ledger, the one subsystem the
project is named for, was the only one with no visual representation while its
data was already on the wire.

**The panel re-derives the chain rather than displaying a verdict.** This is the
design decision everything else follows from. `GET /ledger/verify` already
answers "is the chain valid?", but that is *the controller auditing its own
ledger with the code that built it* — a panel rendering that flag could never
contradict it, and a tamper demonstration driven by it would be theatre. So the
block **header** is streamed and the SHA-256 is recomputed in the browser from
the preimage. Both verdicts are shown, side by side, deliberately not merged:

> `47 blocks` · `✓ browser: 6 recomputed, 6 link(s) checked` · `✓ controller: chain valid`

**Six header fields were added to the `block` event** — `timestamp`,
`previous_hash`, `merkle_root`, `proposer_id`, `raft_term`, `hash`. Not for
display: they *are* the hash preimage that `Block.compute_hash()` digests.
`timestamp` is deliberately unrounded, since a rounded copy hashes to something
else and would fail every check on a healthy chain. A test pins the published
set against `contracts/block_schema.py`'s header dict, so adding a field to the
hash without adding it to the event fails rather than silently reporting every
block as tampered.

**Three things this turned up that were worth the work:**

1. **Genesis is reproducible, so the chain anchors without trusting anyone.**
   `blockchain/ledger.py` pins genesis's timestamp to `0.0` (so RAFT replicas
   agree on it). The page therefore *builds genesis itself* and checks block 1's
   `previous_hash` against a digest it computed — the anchor is not taken on
   faith from the controller.
2. **Python renders that float as `0.0`, JavaScript as `0`.** A naive
   `JSON.stringify` reproduces every block's digest *except* the one anchoring
   the chain. `pyFloat()` handles integral floats — and negative zero, which
   `Number.isInteger(-0) && (-0).toFixed(1)` silently renders as `"0.0"` where
   Python writes `"-0.0"`. Caught by a test, not by reading.
3. **The link check compares against the RECOMPUTED predecessor hash, not the
   shipped one.** This is stricter than `Ledger.is_valid_chain()`, which
   compares `previous_hash` to `prev.hash` as stored. Against a block whose
   contents were edited without recomputing its `hash` field, the stored-hash
   comparison still passes and the damage never propagates — so the chain reads
   as "one bad block" rather than as broken linkage. Recomputing is what makes
   it tamper-*evident* instead of merely checksummed. Pinned by its own test.

**What the tamper control actually does.** It flips one hex digit of a block's
`merkle_root` **in this page's copy only** — nothing is sent anywhere, and a
test asserts the function contains no `fetch`/`XHR`/`sendBeacon`/`WebSocket`. A
demo that mutated real state to prove immutability would refute itself.
`merkle_root` is the field to corrupt because it commits to the batch of
`TrustUpdate`s, so editing it is what "somebody rewrote a trust record" looks
like.

The observed result, which is **more precise than "everything after goes red"**:
the edited block fails its own digest (`hash mismatch`) and its immediate
successor fails its link (`broken link`); blocks further right stay verified
because they chain correctly to an untouched predecessor. That localises the
tamper **to the seam**, which is the forensically useful outcome — the chain
does not just say "something is wrong", it says *where*.

**SHA-256 is hand-implemented rather than called through Web Crypto.**
`crypto.subtle` is async, and — the deciding reason — it **cannot be tested on
this box**, since there is no browser in the test path. A plain function runs
under the `quickjs` interpreter, so the JS digest is pinned against Python's
`hashlib` over real `build_block` output: plain strings across every padding
boundary, a full appended chain, genesis, and integral timestamps. An untestable
implementation of the one thing this panel claims to prove was not worth the
brevity. 21 new tests.

**RAFT is deliberately absent.** `docs/RAFT.md` states it outright: *"Nothing in
the running controller uses this yet."* The live path is
`TimingCommitBackend(LocalLedgerBackend())` — single replica, `raft_term` pinned
to 0. A leader/term/quorum display beside live charts would assert consensus
that is not running, the same failure mode as the removed fleet-size panel
(§3.7b). A test greps the panel for `leader`/`quorum`/`election`/`follower`/
`candidate` and fails if any appears. If RAFT is ever to be shown, it belongs in
a separate panel fed by `blockchain/raft_demo.py`'s standalone 3-replica
cluster, labelled as a separate experiment.

**Not built (deferred, not forgotten):** the Merkle tree expander — unfolding a
block into its leaves and lighting up one record's proof path to the root.
`blockchain/merkle.py` already has `_build_proof` and `verify_record`; it needs
an endpoint exposing block contents, which no route offers today.

### 3.8 `tests/test_live_config_preflight.py` — a live run costs sudo

Every live run in this project's history has surfaced at least one defect, and
several were pure config/wiring mistakes knowable beforehand. The preflight
drives the **real** `_launch_trust_agents` against a stub Mininet `net` that
records the command it would run on each host, then feeds every recorded command
to the **real** argparse of the module it invokes. A typo'd flag, an attack wired
into the topology but missing from `--malicious`, or a config key `topology.py`
silently ignores now fails in milliseconds instead of 300 s into a sudo run.

This required extracting `build_parser()` from `node_agent.main()` and
`build_parser()`/`parse_args()` from `iot_client.main()`, so the preflight checks
the real CLI rather than a copy of it.

**It has already earned its keep.** Phase 8's first `_device_roster` read
`cfg['topology']` when the block is `simulation:`. It returned `{}` — every
identity silently back on TOFU, a no-op fix indistinguishable from success in a
live run. The preflight test asserting the roster is *populated* caught it.
**A fix with a silent fallback needs a test that it is in effect, not just that
it is harmless.**

---

## 4. Defects found and fixed

| # | Defect | Found by | Fix |
|---|---|---|---|
| 3.1 | Auth denials never published | Phase 2 fact-check | `AuthError.kind` + `auth_denied` event |
| 3.2 | Ground truth covered only edge nodes | Phase 2 fact-check | `attack`/`attack_start_s` on IoT nodes |
| 3.3 | Detector output was free-text prose only | Phase 2 fact-check | machine-readable `signals` dict |
| 3.4 | Healthy node published a spurious empty verdict | a test | guard on first poll |
| 3.5 | Analysis tools read the wrong field names | Phase 2 | corrected |
| 3.6–3.8 | Demo recording: wrong priority, `is_vip`, split cookies | looking at the charts | pinned against the deriving function |
| 3.9 | Demo recording carried no attack onset | Phase 5 | onset added |
| **3.10** | **The honesty-check fallback caused every false quarantine** | **live run 7** | split the two causes of `None`: abstain when the *controller* lacks completions, keep the degraded comparison only when the *node* withholds `busy_seconds` |
| **3.11** | **Spoofing was blamed on the victim** | **live run 7** | auth denials keyed on source IP, not the claimed `device_id` |
| 3.12 | On-off named on incidental quiet | run-8 replay | sustained-intermittency rule (≥20% of active span) |
| 3.13 | "Lying beats dropping" precedence disproven | run 7 | replaced with a weighing rule |
| 3.14 | Trust-rail isolation left no evidence to classify | run 8 | `TrustState.isolation_evidence()` + `SIG_TRUST_COLLAPSE` |
| 5.14 | The weighing threshold was set too high | **live run 9** | `DEFAULT_MIN_LYING_SHARE` 0.50 → **0.25** |
| **3.16** | **The spoofing race — an identity nobody claimed was free to take** | **live run 9** | accept queue 5→128; reset ≠ denial; provisioned roster; `identity_unclaimed` |
| **3.17** | **A re-steered flow's timeout charged to the node that never got it** | runs 8/10 | `resteered_from` + `CompletedDispatch.chargeable` |

### 4.1 The three defects that mattered most

**§3.10 — the honesty fallback (run 7).** `expected_duty_cycle()` was available
in 70% of reports and is excellent where it engages (deviation 0.0006 against a
0.40 gate). But **175 of 175 CPU-honesty firings came from the fallback path** —
every false quarantine, none from the fixed path — and it was self-reinforcing:
quarantine → fewer completions → no fleet median → biased fallback → quarantine.

*The prediction about this fix was wrong, and why matters.* A static replay of
run 7 showed honest anomaly cycles dropping only 212 → 174, so the write-up said
the fix "should not be expected to restore availability on its own", reading the
remaining `packet_drop` false positives as an independent congestion problem.
They were not independent, they were **downstream**: false CPU-honesty →
quarantine → re-dispatch onto fewer nodes → real timeouts → drop tell → more
quarantine. Removing the first link collapsed the cascade — run 8 came in at
98.90% honest availability against run 7's 48.05%. **Replaying a fixed recording
measures only first-order effects**; when the suspected defect sits inside a
feedback loop, a replay estimate is a lower bound and only a re-run settles it.

**§3.16 — the spoofing race (run 9).** Three individually-minor defects composed
into a real one. `NorthboundAPI` inherited the stdlib `request_queue_size = 5`
while all 48 hosts connect within milliseconds of `net.start()`; past 5 pending
accepts the kernel resets. That reset knocked the *legitimate* iot1 off its
handshake at t+0.4 s. The client then treated a transport failure as a refusal
and sat out the whole run. And the source-IP pin was **trust-on-first-use**, so
"iot1" was now an identity nobody had claimed — free for the taking. iot38
authenticated as iot1 at t+15 s and ran **130 tasks under the stolen identity**.

Fixed at every link: backlog 128 (pinned against the configured fleet size); the
client retries transport failures (5 attempts, backoff) and **never** retries a
403 — retrying a real denial would turn a bad-credentials device into an auth
flood; and `security.IdentityBinding` takes a **provisioned** `device_id → source
IP` roster **derived from `simulation/addressing.py`** (already the shared source
of truth for addressing) rather than maintained separately in YAML where it could
drift. TOFU remains where no roster entry exists — right for an unknown
population, wrong for a known one. Verified end-to-end over a real socket:
run 9's spoof now gets **HTTP 403**, the legitimate owner gets **200**, and the
denial reaches the bus tagged `ip_pin` → classified `spoof` **on the attacker**.

> **Run 9 is the run where an attack succeeded.** Every previous run's misses
> were labelling failures on attacks that were contained. This one got in.

**§3.17 — re-steer attribution (Phase 9).** The defect register had the mechanism
**wrong**, and re-deriving it from the recordings is what found that. §6.9
proposed excusing a re-steered outcome that arrived with less than the node's
typical service time remaining. Matching every report to its exact flow
(`report.ts - latency_ms/1000` against `route` events, which carry the client port
`report` omits) across runs 8/9/10: the median re-steered flow still had **2.86 s
of its 4.0 s** at handover, min 0.15 s, against successful tasks completing in
103–437 ms. **That rule would have excused 0 of 26.**

The real mechanism was already in `reassign_dispatches`'s own docstring:
quarantine's drop rules **tear down the in-flight TCP connections**, so the client
waits out its own timeout on a dead socket while the dispatch map entry has
already moved to the survivor. **The receiving node was never asked.** Not a
partial-budget problem — a wrong-node problem.

Fixed structurally, with **no tuned threshold**: `_Dispatch` carries
`resteered_from`/`resteered_at`, stamped only by `reassign_dispatches`;
`complete_dispatch` returns a `CompletedDispatch` whose `chargeable` is false for
an inherited flow; `handle_client_report` skips `record_task_outcome` for those.
`dispatched_at` and the inflight release are deliberately untouched — the reaper
horizon and occupancy are different questions from blame. It **abstains without
going silent**: the `report` event still publishes so availability and PDR keep
counting the client's real loss, plus `charged: false` and `resteered_from` so the
abstention is re-derivable offline.

---

## 5. Live run results

### 5.1 Run 10 (2026-08-08, 320.5 s) — the classification headline

```
iot38   spoof            spoof            OK   +5.3s
iot39   bad_credentials  bad_credentials  OK   +5.6s
iot40   bad_credentials  bad_credentials  OK   +5.6s
iot37   flood            flood            OK   +9.1s
srv1    grayhole         grayhole         OK   +12.8s
srv3    sybil            sybil            OK   +9.6s
srv6    blackhole        blackhole        OK   +11.9s
srv8    onoff            onoff            OK   +37.1s
```

**8/8 correct, 8/8 detected, 8/8 right family, 47/48 = 97.9% overall.** All four
NFRs PASS, no outage, 98.5% above quorum, every attacker contained in 9.6–12.8 s.
The spoof was refused and the client says so itself. Zero `Connection reset by
peer` across all 40 client logs.

**What run 10 does NOT prove, and this matters.** iot1 authenticated at t+0.5 s,
so it already owned the TOFU pin when iot38 tried at t+15 s — **plain
trust-on-first-use would have refused this spoof too.** Fix (a) removed the
precondition, so fix (c) was not load-bearing here. The roster's unique
contribution — refusing a foreign host for an identity *nobody has claimed* — is
exercised only by the end-to-end socket test. Saying "8/8, therefore the roster
works" would claim more than the run shows.

**One honest node still mislabelled in run 10: srv7 → `grayhole`.** That is
§3.17, fixed after this run.

### 5.2 Run 11 (2026-08-11, 213.1 s) — first run on the Phase 9 fix

*Scored 2026-08-11 from the working-tree `data/events.jsonl`. This recording is
gitignored and its numbers appear in no other document.*

| Metric | Value |
|---|---|
| Honest-node availability | **100.00%** |
| Honest nodes never quarantined | **4 / 4** (srv2, srv4, srv5, srv7 all 100% eligible) |
| Honest subjects wrongly labelled | **0 / 40** |
| Route denial | **0.0%** (0 of 3,927 routes) |
| Total outage | **none** |
| Time at/above 50% quorum | **100.0%** (213.1 s) |
| Mean nodes serving | 6.34 / 8 (worst case 4 / 8) |
| Quarantine recoverability | 23 recoveries / 25 quarantines |
| Attacks detected at all | **8 / 8** |
| Attacks in the right family | **8 / 8** |
| Attacks classified correctly | 6 / 8 |
| Overall accuracy | 46 / 48 = **95.8%** |
| Mean detection latency | 23.3 s (upper bound — §6.2) |
| Attacker containment | srv6 +16.9 s, srv1 +17.9 s, srv3 +22.2 s, srv8 +50.0 s |
| All four NFRs | **PASS** |

NFR detail: routing decision **2.25 ms mean / 4.16 ms p95** (target < 200 ms);
isolation re-dispatch **63.81 ms mean / 92 ms max** over 34 re-steers (target
< 3000 ms); blockchain overhead **0.120%** (target < 15%); RAFT commit 4.3–4.8 ms
(target < 500 ms, measured standalone).

**§3.17 fired live for the first time: 31 of 3,849 reports (0.81%) were withheld
from trust attribution** (`charged: false`), against a replay estimate of 29
(0.46%) on run 10. srv7 — mislabelled `grayhole` in run 10 on 21 `packet_drop`
cycles and quarantined twice — came out **100% eligible, never quarantined,
correctly `none`**. That is the fix doing exactly what §3.17 predicted, in a live
run rather than a replay.

**The two misses are both FAMILY-correct, and both are known limits, not new
defects:**

- **srv3 `sybil` → `onoff`** — the on-off eagerness limit (§3.2 resolution limit 1).
  srv3 was quarantined **14 times** this run, and each quarantine produces a
  genuinely quiet stretch that looks like an off phase.
- **srv6 `blackhole` → `grayhole`** — the §4.7 magnitude tension. srv6 was
  isolated at +16.9 s and stayed isolated for 166.2 s of a 213 s run (22.0%
  eligible), so the drop tell never accumulated a measured rate and the family
  came from the trust rail, which cannot claim magnitude. Run 10 got `blackhole`
  because srv6 carried 31 `packet_drop` **and** 31 `trust_collapse` cycles there;
  here it did not.

### 5.3 Why run 11's classification is below run 10's, and why that is not a regression

Both misses are **magnitude/intermittency resolution limits that only appear when
the defence is fast**, and run 11's defence was faster and cleaner than run 10's.
The attackers were contained hard (srv6 isolated for 78% of the run, srv3
quarantined 14 times), which is precisely the condition that starves the anomaly
rail of the evidence needed to *name* the attack — the §4.7 tension, stated in the
register before this run happened:

> **Containment quality and magnitude evidence are in direct tension.** The faster
> an attacker is isolated, the less evidence exists to distinguish *how much* it
> was dropping.

The right reading: **run 11 traded two label-precision points for a perfect honest
side.** 0/40 honest mislabels, 4/4 honest nodes never quarantined, 0% route
denial, and 100% of the run above quorum. Both misses stay in the right family, so
the response would have been identical either way.

**Two caveats, stated rather than buried.** Run 11 is **213.1 s against a
configured 300 s** — the run was cut short, which costs the on-off attacker ~4
periods of evidence and is the likely reason srv8's detection latency is 50 s.
And this is a **single run at a single seed**, like every live figure in this
project (§6.5).

---

## 6. Open limitations

Honest list. Nothing here is hidden in a footnote elsewhere.

### 6.1 DDoS response is detection-only
Flooding is detected and classified but not throttled. Needs a per-client-IP
OpenFlow rule path; today's rate-limit and quarantine machinery is all
per-edge-node.

### 6.2 Detection latency is an upper bound
`start_s` is measured from agent launch; the recording's t0 is controller start,
which necessarily precedes it by the Mininet build. The reported figure includes
that gap and **overstates** the detector. Overstating is the safe direction;
quietly subtracting an estimate would not be.

### 6.3 Scalability beyond 8 nodes is simulation, not live
The box is 4 cores. N=64 live would measure the laptop, not the architecture. The
sweep drives the **real** `select_edge_node`, but it is not a live run and must
not be presented as one. **It is deliberately kept off the dashboard.** A
fleet-size panel (20→40 servers) was built on 2026-08-13 and removed the same
day: on a page where every other panel reports the running system, a projection
five fleet sizes past anything ever instantiated is not defensible under
questioning. The N sweep lives in `scalability_sweep.py`'s CLI output, where it
reads as the simulation result it is. What the dashboard carries instead is the
client-load panel (§3.7b), whose axes both stay inside the deployed topology —
and which still says "not live" on itself, because it is still a model.

The remaining honest claim about scale: **at 8 servers we measure; beyond that
we simulate the fleet while executing the real selector.** What the simulation
supports is that the *selection rule*, not the hardware, is what stops scaling
under argmax. It does not support a capacity figure for 40 real machines.

### 6.4 One false-positive flood tell
Honest iot29 tripped the flood detector once in run 7, plausibly retry pressure
under 28% route denial. Runs 8–11 (0% denial) produced no such false positive,
which supports that reading but does not prove it.

### 6.5 Single run per configuration
Every live figure comes from one run at one seed. No confidence intervals.
`evaluation/stats.py` already implements the paired-comparison machinery — but
it **does not currently run on this box**: it needs `scipy.stats.wilcoxon(method=)`
(scipy ≥ 1.9) and the installed scipy is 1.8.0, which spells that argument
`mode=`. So the honest statement is not "it has simply never been pointed at the
live runs" but "it cannot be until that call is made version-tolerant or scipy is
upgraded." One-line fix either way; flagged because a stale limitation entry that
says "just needs pointing" invites someone to promise multi-seed results in a
meeting.

### 6.6 The study document is stale
`docs/study/trust-routing-study.html` still describes pre-p2c routing, and its PDF
was printed from an even older version. Both of its open questions now have
answers (starvation closed by p2c + ε; the H-term mismatch closed by the
duty-cycle comparison plus §3.10's abstention rule).

### 6.7 The two detection rails' timing is not reconciled
Whether `_MIN_TIMEOUT_SAMPLES = 4` is right for **isolation** is still open. The
*classification* half is answered: unanimity on a small sample is **not** evidence
of magnitude (srv1's first two post-collapse outcomes were unanimously timeouts
and it is a grayhole).

### 6.8 Run length and topology size
300 s at 8/40 leaves the on-off attacker only ~12 periods and the classifier a
thin evidence base — run 11's 213 s leaves it fewer still. A longer run would firm
up the on-off numbers; a larger live topology needs hardware this project does not
have.

### 6.9 `DEFAULT_MIN_LYING_SHARE` needs one more re-check
0.25 was tuned against run 9 evidence that **partly consisted of inherited
timeouts** — run 9's srv8 loses all 6 of its drop-tell firings under §3.17. 0.25
sits mid-band in the swept safe range 0.15–0.40, so it does not need reverting; it
does need re-checking rather than being assumed still-calibrated. Run 11 named
srv8 `onoff` correctly, which is a point in its favour but not a sweep.

### 6.10 Closed, listed so they are not re-opened by accident
Signal precedence (§3.13), `onoff` as an absorbing label (§3.12), trust-rail
isolation outrunning the classifier (§3.14), the transport-layer refusal leaving
no trace (§3.16), identity spoofing against an unclaimed identity (§3.16), and
re-steer misattribution (§3.17).

---

## 7. Configuration

`config/params_trust_full.yaml` is the panel config: **8 edge servers, 40 IoT
devices, 6 attacks, 300 s**, p2c routing with ε=0.05, optimizer on, dashboard on,
PRESENT-80 auth, meters on.

| Subject | Attack | Onset | Notes |
|---|---|---|---|
| srv3 | sybil | 20 s | |
| srv6 | drop (→ `blackhole`) | 30 s | |
| srv1 | grayhole | 40 s | `grayhole_drop_rate: 0.5` |
| srv8 | onoff | 50 s | 20 s period / 0.5 duty = 10 s good phase |
| iot37 | flood | 60 s | 3 workers @ 0.25 s ≈ 12 Hz |
| iot38 | spoof | 15 s | targets iot1; holds the **real** fleet key |
| iot39, iot40 | bad credentials | — | wrong key, denied at admission |

Three config decisions that are load-bearing and easy to break:

- **4 of 8 malicious looks like it threatens the latency tell's fleet-median
  (honest-majority) assumption, and does not.** Only the two CPU-burning attacks
  make a node slow to answer `/status`; blackhole and grayhole answer at full
  speed. So at most 2 of 8 are ever slow and the median stays among the honest
  six. **A third CPU-burner would break this** and must not be added without
  re-checking `flow_monitor.py`'s baseline assumption.
- **The flood rate is chosen against the detector, not for maximum damage.**
  ~12 Hz is 24× the 0.5 Hz expected per-device rate — unambiguous to the tell
  while adding only ~12 req/s on top of the fleet's ~20. Deliberately not the
  unpaced default: this box is 4 cores, and every collapse in this project's live
  runs traces to offered load, not to the architecture.
- **iot38 must NOT appear in `security.malicious_iot_devices`.** That list hands
  out a *wrong* key; the spoofer needs the *real* fleet key, since the whole point
  is that possession of the key does not authenticate the device. Pinned by a
  preflight test.
- `simulation.num_malicious` is **vestigial** — it counts IoT devices, not edge
  servers, and drives no behaviour. Documented in the config rather than removed,
  since both entry points still read the key.

Workload sizing: 20 req/s honest + 12 req/s flood = **0.48 of 4 cores (12%)**,
fleet utilisation 1.5%, ~50 processes. `report_interval_s: 2.0`,
`task_work_ms: 15`, `task_timeout_s: 4.0`.

---

## 8. Test suite

**669 tests: 661 passing, 8 failing** (344 at `c3e6824`). The most recent
37 cover the client-load panel (§3.7b) and the trust-ledger panel (§3.7c).

The 8 failures are all in `tests/test_stats.py` and are **environmental, not a
regression**: `evaluation/stats.py` calls `scipy.stats.wilcoxon(method=...)`,
which was added in scipy 1.9, and this box has **scipy 1.8.0** (where the
argument is spelled `mode=`). Nothing else in the pipeline imports it, so every
live-run and analysis path is unaffected — but see §6.5, because this is the
module that was supposed to supply the statistical rigour.

| File | Tests | Covers |
|---|---|---|
| `test_attack_classifier.py` | 32+ | the label, both resolution limits, the weighing rule |
| `test_attack_report.py` | 33+ | confusion matrix, replay-not-tally, detection latency |
| `test_availability_report.py` | 27 | arithmetic against hand-computed timelines |
| `test_scalability_sweep.py` | 18 | including guards on the queueing invariant itself |
| `test_dashboard_charts.py` | 50 | bucket width / drop priority pinned across three copies; one-renderer and no-fleet-projection pins (§3.7b) |
| `test_dashboard_ledger.py` | 23 | browser SHA-256 vs Python `hashlib` over real blocks; tamper cascades; no RAFT claim (§3.7c) |
| `test_live_config_preflight.py` | 12+ | real `_launch_trust_agents` vs real argparse |
| `test_flood_detector.py` | 9 | pure-function tell |
| `test_iot_client_flood.py` | 3 | real-server control flow |
| `test_iot_client_spoof.py` | 4 | denial stops traffic, success sends it, delayed onset |
| `test_node_agent.py` | 6 | delayed onset, grayhole, on-off |
| `test_demo_recording.py` | 4 | generator fidelity pinned against `_is_vip_cookie()` |
| plus additions to | | `test_trust_state.py`, `test_authenticator.py`, `test_flow_monitor.py` |

Tests that exist specifically so a future change **fails loudly**:
`test_the_rule_carries_no_tuned_threshold` (§3.17 reads no clock),
`test_a_liar_that_also_drops_is_not_demoted_to_a_dropper` (§5.14), the
`ONOFF_MIN_GOOD_PHASE_S` and window-span pins, the `PRIO_QUARANTINE_DROP`
three-way pin, and the preflight's assertion that the identity roster is
*populated* rather than merely harmless.

---

## 9. Discipline rules carried through this work

Each was learned from a real defect in this repo, and each is worth keeping:

- **Separate "correctly isolated attacker" from "wrongly quarantined honest
  node" in every metric that touches quarantine.** Averaging them hides whichever
  one matters.
- **A detector with no recent evidence abstains; it does not re-assert a stale
  verdict.** Applied to the timeout tell, the classifier, and the honesty check.
- **Task-level loss and OpenFlow drop-rule hits are different things** and never
  share a series.
- **When a comparison keeps producing false signal, check both sides are the same
  physical quantity before smoothing either one** — service time vs residence time
  was a ~17× bias hiding behind a plausible-looking number.
- **Pin fixtures against the deriving function, not a copied literal.**
- **A flat line in a chart is a hypothesis about the data before it is one about
  the chart.**
- **Re-derive a finding from the recording before acting on it.** §5.2 was
  confidently misattributed; §6.9 was written *from that re-derivation* and still
  got the mechanism wrong, because it reasoned from the shape of the fix rather
  than measuring the flows.
- **"No effect on run N" means untested, not safe.** A latent fix should not carry
  a tuned threshold.
- **A replay measures only first-order effects.** When the defect sits inside a
  feedback loop, the replay is a lower bound and only a re-run settles it.
- **A fix with a silent fallback needs a test that it is in effect**, not just
  that it does no harm.

---

## 10. Running it

Full runbook with terminal layout, Wireshark, and the narrative arc:
**`final_run.md`**. The short version:

```bash
# ---- no root ----
python3 -m pytest tests/ -q                                   # 624 pass, 8 known scipy failures (§8)
python3 -m evaluation.scalability_sweep --ns 4,8,16,32,64 --load-factors 0.1,0.6

# ---- full-scale panel run (root) ----
sudo service openvswitch-switch start
sudo modprobe -a sch_htb sch_netem sch_tbf sch_prio ifb
sudo mn -c
sudo python3 run_demo.py --mode mininet --config config/params_trust_full.yaml

# ---- score it ----
python3 -m evaluation.nfr_report          data/events.jsonl
python3 -m evaluation.interval_report     data/events.jsonl
python3 -m evaluation.attack_report       data/events.jsonl
python3 -m evaluation.availability_report data/events.jsonl
```

> **Archive the recording before the next run.** `run_demo.py --mode mininet`
> **unlinks `data/events.jsonl` at startup**, and `data/` is gitignored. Copy it
> to `data/events_runN.jsonl` the moment a run finishes, or the numbers above
> cannot be re-derived.

---

## 11. Repository state

**Branch:** `feature/ai-optimizer`. **HEAD:** `710c80c` (fix/resteer-attribution).

**Untracked and gitignored:**
- `data/events.jsonl` — the run 11 recording scored in §5.2. **Not archived.**
- `logs/` — per-host agent and client logs from run 11.

**Untracked, not part of this work:** `demo_topo.py`, `draw_topo.py`,
`show_flows.py` — standalone helper scripts (a 7-switch chain topology, a static
`topology.png` generator, and an `ovs-ofctl` flow pretty-printer) predating this
phase. They are unrelated to the trust-aware controller and nothing in the
pipeline imports them.

**Next step named by the plan:** archive run 11, then a longer run (full 300 s) to
firm up the on-off evidence base and re-check `DEFAULT_MIN_LYING_SHARE` against
post-§3.17 telemetry (§6.9).
