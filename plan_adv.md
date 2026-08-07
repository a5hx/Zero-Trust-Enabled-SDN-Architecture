# Advisor-Driven Plan — Metrics, Iteration, Attack Classification

*Created 2026-08-06. Driven by mam's review of the current build: the panel
will not accept architecture claims without iterative, time-series proof, and
wants attacks classified by type, not just quarantined. This plan is scoped to
**2-3 weeks** before panel review — trim signal is noted per phase.*

This supplements `plan.md` (which covers the original Sprint 1-3 roadmap, now
closed). `plan.md` is not touched by this document; do not duplicate status
tracking between the two.

---

## 1. What was actually asked, decoded

Two asks from the advisor review:

1. **Iterative metrics.** Throughput, delay, packet delivery ratio,
   scalability, response time, network lifetime, load balancing, traffic
   load, packet-drop — each shown **as a function of simulation time**
   (metric-vs-time curves, standard AODV/DSR/LEACH-paper evaluation shape),
   not single end-of-run numbers. Confirmed with the user this is the
   intended reading of "iteratively."
2. **5 (now 6) classified attacks with measured per-interval impact.** Not
   "quarantined: yes/no" but "attack X detected on node Y at time T,
   classified as [type], here is what PDR/delay/throughput did around T."

---

## 2. Fact-check against the real codebase (verified 2026-08-06, not from docs)

| Metric | State found | What's missing |
|---|---|---|
| Throughput | Live only, real `OFPPortStats`/flow counters (`controller/flow_stats.py`), shown as instantaneous pps in the dashboard topbar. Nothing persisted. | Periodic sampling into the event log + interval binning. |
| Delay / response time | Real per-event data already logged: `decision_ms`, `resteer_ms`, `latency_ms` (read by `evaluation/nfr_report.py`). But collapsed to one mean/p95/max for the **whole run**. | Bucket the same data by time window — no new instrumentation needed. |
| PDR | Task-level analog exists (`report` events carry `status`). | Same binning gap. |
| Load balancing | Jain's fairness index computed **live, client-side only**, in dashboard JS (`dashboard/index.html:334`). Never logged or reported. | Port server-side, per interval, from the same routing-share tally. |
| Traffic load | Not logged as its own series anywhere. | New: log offered-vs-served rate per interval. |
| Packet drop | Two genuinely different things exist and must not be conflated (same discipline as `[[edgescore-fanout-starvation]]`): (a) task-level loss from timeouts/attacks, (b) real OpenFlow drop-rule hits on quarantined nodes (`PRIO_QUARANTINE_DROP`). Both measurable from existing counters. | Report both as distinct series. |
| Scalability | `evaluation/starvation_sweep.py` already sweeps N=4..64 for the load-balancing selector only, via a discrete-event harness driving the *real* selector code (not live Mininet). | Extend to full-system metrics; live Mininet scalability is **hardware-capped** (WSL2, 4 cores; the 8/40/3 live run already needed workload retuning to avoid collapse — see `[[live-run-cascading-quarantine]]`). Decision: simulation-harness sweep only, no larger live runs attempted. |
| Network lifetime | **Does not exist.** WSN metric (time to first battery-dead node); no energy model anywhere in the repo, and edge servers are mains-powered so a literal battery model would be dishonest for them. | Decision: reframe as **service availability** — time-to-first-permanent-isolation, fraction of run each node stayed eligible to serve. Derived entirely from existing quarantine/isolation event history. |

**Structural finding:** `evaluation/plots.py` already has the right plotting
machinery — `plot_attack_timeline()` draws trust-vs-time with the attack
window shaded, plus `plot_trust_evolution`/`plot_routing_distribution`. But
it is wired **only into `run_demo.py --mode standalone`**
(`run_demo.py:315-321`), the toy in-process simulation with a fake
`AttackSimulator`. The real `--mode mininet` run (real OVS, real os-ken — the
one actually credible to a panel) produces only a flat JSONL log and a
single-number NFR report. The iterative-plotting muscle exists; it's pointed
at the wrong run.

## 3. Fact-check against the real codebase: attacks and classification

- **Only 2 attack behaviors exist anywhere, consistently**:
  `simulation/node_agent.py --malicious {sybil, drop}` (used by the live
  Mininet path). The older `simulation/attack_simulator.py` (queue-injection,
  standalone-mode only) has the same two and nothing else.
- **Detection already distinguishes 4 signatures**, as free-text `reasons`
  strings (`controller/flow_monitor.py:265-413`): CPU-honesty deviation, the
  latency tell (sybil-style idle-but-slow), packet-drop timeout-rate tell,
  `/status unreachable`. Real and good, but never turned into a discrete
  label — today the event log says "anomaly" + a sentence, never
  `attack_type: sybil`.
- **Ground truth already exists but is siloed**: `topology.py` knows exactly
  which node runs which attack (`malicious_edge_nodes: [{node, attack,
  start_s}]`) — the labeled test set a classifier needs, sitting unused.
- **Doc/code mismatch found**: `docs/PROJECT_GUIDE.md:625` documents
  `start_s: 20 # start attacking at t=20s` as if delayed onset were
  supported. `topology.py:203-205`'s own comment says plainly it is **not**
  implemented — every attack currently starts at t=0. Without fixing this
  there is no clean baseline interval to compare "during attack" against.

## 4. Decisions made (2026-08-06)

- **Network lifetime** → reframed as service availability. No energy model.
- **New attacks (bringing the total to 6)**, in build-cost order:
  1. Sybil — existing.
  2. Blackhole / packet-drop — existing (rename to standard terminology in
     reporting; behavior unchanged).
  3. Grayhole / selective drop — new, cheap (extends existing `drop` mode
     with a probabilistic rate instead of always-never-respond).
  4. On-off / intermittent trust manipulation — new, cheap, high narrative
     value: behaves honestly long enough to rebuild trust via the EMA, then
     defects again. Directly stress-tests this project's own headline
     finding (anomaly gate catches what trust alone provably cannot).
  5. DDoS / flooding — new, more work: different attack surface
     (control-plane request-rate abuse, not node-side lying), needs a new
     detector signal.
  6. Identity spoofing / replay at the PRESENT-80 auth layer — new, separate
     subsystem from routing/trust, can be built independently of 3-5.
- **Scalability** → simulation-harness sweep only (extend
  `starvation_sweep.py`'s pattern), no attempt at larger live Mininet runs.
- **"Iteratively"** → confirmed: metric-vs-simulation-time plots, attack
  windows shaded, standard evaluation-paper shape.
- **Timeline** → 2-3 weeks to panel review. Trim signal: Phases 0-2 must be
  solid; Phases 3-4 can be basic; Phase 5-6 are the first things cut if time
  runs out (a correct-but-unplotted number beats a rushed chart).

## 5. Phase plan

Order is a real dependency chain, not a priority list — later phases read
data structures Phase 0 produces.

### Phase 0 — Foundations (**IN PROGRESS**, start here)
Everything downstream depends on this.
- [x] **Delayed attack onset (2026-08-06).** Wired
      `malicious_edge_nodes[].start_s` from config through `topology.py`
      into `node_agent.py --malicious-start-s`. Before arming, the agent is
      behaviorally identical to `--malicious none` (sybil: no background
      burner threads, real self-reported telemetry; drop: `/task` served
      normally). The sybil lie's synthetic `busy_seconds` is measured from
      `_attack_armed_at`, not process start, so a delayed attack doesn't
      backdate its claimed duty cycle. Config files already carried
      `start_s: 20` (documented in `docs/PROJECT_GUIDE.md`, silently
      ignored before this) — no config changes needed, just the wiring.
      6 new tests in `tests/test_node_agent.py` (real HTTP server on
      loopback, same pattern as `test_run_demo_mininet.py`); full suite
      344/344 green.
- [x] ~~Periodic snapshot events~~ **Turned out unnecessary — checked before
      building it.** Traced every one of the 9 metrics back to the existing
      event stream: `route`/`route_denied` (offered/served/decision_ms),
      `report` (task status/latency_ms — PDR, delay), `quarantine`/
      `recovered` (service availability), `flow_stats` (VIP-flow bps for
      throughput, and the *same* quarantine-drop rules' cumulative packet
      counters for OpenFlow-level drops — they share the per-node cookie, so
      `priority == PRIO_QUARANTINE_DROP` picks them out of the existing
      dump), `port_stats` (link-level bps). All of it is already written to
      the JSONL. Also found the `topology` event already carries **ground
      truth `attack` per server node** (`trust_balancer.py:1300`,
      surfaced deliberately for post-hoc marking, never fed forward) — reuse
      this in Phase 2 instead of re-deriving it from config. Building new
      events here would have duplicated data already on the bus, against
      this project's own reuse-real-counters discipline
      (`flow_stats.py`/`port_stats.py`'s own docstrings make the same
      argument). Folded into the binning module below.
- [x] **Interval-binning module (2026-08-06):** `evaluation/interval_report.py`
      — reads the same JSONL `nfr_report.py` does, buckets every event by a
      configurable time window (default 10s), and computes throughput
      (VIP-serving flow bps), decision/response delay (mean + p95),
      task-level PDR, Jain's Fairness Index (Jain/Chiu/Hawe 1984) over
      per-node routing share against the *full* server roster (from the
      `topology` event, so a starved-for-the-whole-run node still counts
      against fairness instead of silently not appearing), offered-traffic
      rate, and both packet-drop series (task-level timeouts/failures vs.
      OpenFlow quarantine-drop-rule packet counts, kept separate per the
      packet-drop discipline in §"Notes / rules" below). Cumulative counters
      (flow byte/packet counts) are diffed between sightings, not summed
      fresh, so a bucket's number is *that bucket's* traffic, not
      running-total noise. Throughput and the quarantine roster forward-fill
      into buckets with no events of their own, matching how a live
      dashboard reads (a quiet bucket isn't a zero-throughput bucket).
      Feeds text/CSV output now; the same `IntervalMetrics` list is what
      Phase 5's charts and Phase 4's service-availability metric will
      consume. 19 new tests in `tests/test_interval_report.py`, including a
      pin against the real `PRIO_QUARANTINE_DROP` constant so the two files
      can't drift silently. Smoke-tested end to end against a hand-built
      JSONL through the CLI (`python3 -m evaluation.interval_report`).
      **Full suite: 363/363 green** (pre-existing repo suite + 6
      `test_node_agent.py` + 19 `test_interval_report.py`).

**Phase 0 status: all three items done (2026-08-06). 363/363 tests passing.**
Ready for Phase 1.

### Phase 1 — New attack behaviors
Grayhole → On-off → DDoS/flooding → Spoofing/replay (cost order; spoofing can
run in parallel with the others since it's a separate subsystem).

- [x] **Grayhole (2026-08-06).** `node_agent.py --malicious grayhole
      --grayhole-drop-rate`: same "accept and never respond" behavior as
      blackhole/drop, but only for a random fraction of tasks. Self-reports
      CPU honestly (the tell is purely the timeout rate, same signal as
      blackhole, just weaker per-sample) — this is what lets Phase 2 test
      whether the existing threshold catches a partial dropper or only an
      always-dropper.
- [x] **On-off / intermittent trust manipulation (2026-08-06).**
      `node_agent.py --malicious onoff --onoff-period-s --onoff-duty`: a
      dedicated toggle thread alternates BAD (sybil-style CPU lie, real
      background burners) and GOOD (fully honest, burners stopped) phases.
      Deliberately targets the trust EMA's memory rather than any one
      telemetry check — see module docstring for why this is the sharpest
      available test of the anomaly-gate-vs-trust-alone claim. The lie's
      synthetic `busy_seconds` is measured from the *current bad phase's*
      start, not from when the attack armed, so it can't claim duty cycle
      for earlier good phases (or earlier bad ones) it wasn't lying through.
      6 new tests total (3 grayhole, 3 onoff) in `tests/test_node_agent.py`.
      `topology.py` wired to pass both new attacks' parameters through from
      `malicious_edge_nodes[]` config entries, defaults matching on both
      sides so omitting them is always safe. **369/369 tests green.**
- [x] **DDoS / flooding (2026-08-06).** Different attack surface from the
      other four -- request-rate abuse of the fleet's/controller's capacity,
      not any one edge node's honesty -- so it needed a genuinely new
      detector, not just a new node_agent.py mode:
      - Attacker: `iot_client.py --malicious flood` (new
        `--flood-concurrency` parallel workers, `--flood-interval-s`
        pacing, default 0.0 = unpaced). Same delayed-onset design as
        node_agent.py, same reason. The honest single-worker path is
        byte-for-byte untouched -- the new complexity lives entirely in a
        separate `_run_flood` helper, only entered when `--malicious flood`
        is set, to keep risk to the non-malicious common case at zero.
      - Detector: `controller/flood_detector.py`'s `evaluate_flood_tell`,
        same leaky-bucket persistence shape as `evaluate_latency_tell`.
        Keyed on the requesting **client**, never on whichever edge node
        the flood happens to land on — see the module's docstring for why
        blaming the node would repeat a mistake this project has already
        made twice (memory/edgescore-fanout-starvation,
        memory/live-run-cascading-quarantine). `TrustState` gained
        `record_client_request`/`client_request_rate` (per-client-IP
        timestamp tracking, mirroring how it already owns dispatch/occupancy
        bookkeeping); `trust_balancer.py._check_flood` calls it on every VIP
        PacketIn and publishes a `'flood'` event **only on the rising edge**
        (crossing into `flood_persist` strikes), not every packet — a
        sustained flood is itself hundreds of PacketIns/sec, and publishing
        one dashboard event per packet would let the attack DoS the event
        bus too.
      - **Enforcement deliberately deferred.** This ships detection +
        classification-ready signal only; auto-throttling/dropping a
        flooding client's traffic would need a new per-client-IP OpenFlow
        rule path (today's `rate_limit`/quarantine machinery is all
        per-edge-node), which is real additional scope. Documented here as
        a known limitation rather than half-building it under time pressure.
      - 17 new tests (9 `test_flood_detector.py` pure-function, 5
        `test_trust_state.py::TestClientRequestRate`, 3
        `test_iot_client_flood.py`, real-server style like
        `test_node_agent.py`). `topology.py` wired via a new
        `malicious_flood_devices[]` config list (parallel to
        `malicious_edge_nodes[]`, but IoT-side). **386/386 tests green.**
- [x] **Identity spoofing / replay (2026-08-06).** Fact-check before
      building anything: a literal *replay* of a captured (device_id,
      response) pair was already structurally impossible --
      `verify_response` pops the nonce on first use regardless of outcome,
      so resubmitting it hits "no outstanding challenge". Building a fake
      version of an attack the system already defeats would have been
      dishonest. The **real** gap, found by reading
      `security/authenticator.py` closely: the shared key is **fleet-wide**
      (`topology.py` hands every legitimate device the identical
      `shared_key_hex`), so PRESENT-80/HMAC on their own authenticate
      *possession of the key*, not *the device* — anyone holding the key can
      compute a correct response for any device_id string. `/report`
      already binds identity to the request's own socket
      (`self.client_address[0]`, never the JSON body — see its own
      docstring); `/auth/challenge` and `/auth/verify` didn't have that.
      - Fix: **source-IP pinning**. `Authenticator.verify_response` gained
        an optional `source_ip` param; the first successful auth for a
        device_id pins it to that IP (all three implementations —
        `NullAuthenticator`, `Present80Authenticator`, `HmacAuthenticator`).
        A later request with a cryptographically *correct* response for
        that device_id from a *different* IP is refused. Safe in this
        closed topology specifically because every real device's IP is
        static for the whole run (`simulation/addressing.py`) — no
        legitimate roaming to accommodate. `northbound_api.py` passes
        `self.client_address[0]` through, mirroring `/report`'s existing
        discipline.
      - Attacker: `iot_client.py --malicious spoof
        --spoof-target-device-id`. Waits `malicious_start_s` (long enough
        for the real target to have already authenticated — default 5.0s),
        then attempts to authenticate AS the target from its own host. On
        denial (expected/correct outcome), logs and sends nothing; on
        success (the bug case, defence failed), sends real task traffic
        under the stolen identity. `run()`'s new spoof branch sits *before*
        normal admission, since a spoofer never authenticates as itself.
      - This is enforcement, not just detection-and-log like the DDoS
        case — cheap and safe to deny outright here because the closed
        topology makes false positives structurally impossible (no
        legitimate reason for a device_id's IP to change mid-run).
      - 9 new tests: 5 in `tests/test_authenticator.py::TestSourceIpPinning`
        (the real crypto/pinning logic), 4 in `tests/test_iot_client_spoof.py`
        (iot_client.py's control flow against a canned fake server — denial
        stops traffic, success sends it, delayed onset waits, missing
        `--spoof-target-device-id` is rejected at the CLI). `topology.py`
        wired via a new `malicious_spoof_devices[]` config list (`device`,
        `target`, optional `start_s`). **395/395 tests green.**

**Phase 1 status: all 6 attacks (2 pre-existing + 4 new) done (2026-08-06).**
Sybil, blackhole, grayhole, on-off, DDoS/flooding, identity spoofing — one
more than mam's "5". Ready for Phase 2 (classification).

### Phase 2 — Classification
- [x] **Three plumbing gaps closed first (2026-08-07).** Fact-check before
      building the classifier found that a confusion matrix built on the
      then-current event stream could not have been honest:
      - **Auth denials were never published.** `/auth/verify` returned 403 and
        told nobody — the controller did the right thing and forgot it, so a
        spoofing attempt left no trace in the JSONL and was structurally
        invisible to any scorer. `AuthError` gained a structured `kind`
        (`ip_pin` / `bad_response` / `no_challenge` / `nonce_expired`) and
        `northbound_api.py` now publishes `auth_denied`. The kind is what
        separates *identity spoofing* (correct key, wrong source) from *a
        device that never held the key* — two different attacks distinguished
        by nothing but the reason the denial fired.
      - **Ground truth was edge-node-only.** The `topology` event carried
        `attack` for servers but nothing for the IoT side, so 2 of the 6
        attacks (flooding, spoofing) had no confusion-matrix row and would
        have vanished rather than been scored. Added `attack` +
        `attack_start_s` to both server and IoT nodes, with the same
        spoof-beats-flood precedence `topology.py` itself uses.
      - **Signals were free-text prose.** Classifying by regexing sentences
        written for a dashboard is fragile, so `anomaly` now carries a
        parallel machine-readable `signals` dict. `reasons` is untouched.
- [x] **`controller/attack_classifier.py` (2026-08-07)** — pure functions over
      an evidence *window*, no I/O, shared by the live controller and the
      offline scorer (same one-implementation discipline as
      `evaluate_latency_tell`). A window rather than a single cycle because
      **two of the six pairs are not separable from one cycle's signals**:
      blackhole vs. grayhole fire the *same* signal and differ only in
      magnitude; sybil vs. on-off fire the *same* signals and differ only in
      intermittency. Rules: lying signals (CPU honesty / latency tell) beat
      drop signals, because a CPU-burning liar really is slow and so raises the
      drop tell too while a pure dropper never raises a lying signal —
      asymmetric evidence, so the more specific one wins. Blackhole vs grayhole
      splits on the **median** timeout rate over flagged cycles, not the max: a
      grayhole's rate is a binomial sample over a 10-deep window and *will*
      touch 1.0 by chance, which a max-based rule would relabel on one unlucky
      draw. `node_down` is kept strictly separate from the six attacks (this
      project's blackhole answers `/status` fine and drops only `/task`, so
      "silent" is a liveness failure — folding it in would inflate exactly the
      numbers this module exists to measure honestly). Abstains on stale or
      absent evidence, per `[[quarantine-absorbing-state]]`; auth verdicts
      latch and load/traffic verdicts do not, because "presented another
      device's identity at t=5" is a historical fact while "is currently slow"
      is a condition.
- [x] **Live wiring (2026-08-07).** `flow_monitor.py` records every cycle
      (including clean ones — an off phase is only visible because the quiet
      cycles were recorded) and publishes `classification` on **label change
      only**; `trust_balancer.py` does the same for clients from the flood
      tell and auth denials, in a separate subject namespace so a flooding
      client can never be scored against the node it overwhelmed. A test
      caught a real bug here: a healthy node published a spurious empty
      verdict on its first poll.
- [x] **`evaluation/attack_report.py` (2026-08-07)** — confusion matrix,
      per-class precision/recall/F1, and detection latency. **Replays rather
      than tallies:** the live `classification` events record label *changes*,
      so counting them would weight a subject that flapped once the same as one
      that held a verdict all run. Instead it rebuilds the per-cycle evidence
      (using `node_status` as the heartbeat that supplies the clean cycles
      `anomaly` alone cannot) and re-runs the same classifier, which also makes
      the offline number unable to silently disagree with the live one. The run
      verdict is the **modal** label, not the final one — an on-off attacker is
      correctly abstained on mid-good-phase, so the last label says more about
      where the recording was cut than about what the system concluded.
      `NO_ATTACK` is scored as a real class, because it is the one that catches
      false accusation of honest nodes — this project's historically dangerous
      failure mode (`[[live-run-cascading-quarantine]]`).

**Two resolution limits found and documented rather than tuned away.**
Classifying on-off *as* on-off requires observing a quiet stretch, so:
  1. the attacker's good phase must outlast the detector's own reaction time
     (`ONOFF_MIN_GOOD_PHASE_S` ≈ 4 s: the latency tell's leaky bucket keeps
     flagging ~1 poll after the switch, then needs 3 clean polls); and
  2. the evidence window must span a whole on-off *period*, or it mostly holds
     one phase at a time and reports sybil — measured, not assumed: a 10-cycle
     window over a 12-cycle period yields sybil for most of a run.
In both cases the attacker is **still caught and quarantined** — only the label
degrades. `topology.py`'s on-off default was raised 8 s → 20 s to clear limit
(1) with margin, and both limits are pinned by tests so a future "shrink the
window" change fails loudly instead of silently turning every on-off result
into a sybil result. A deliberately faster attacker is now a valid experiment
to *measure* against, not something to hide.

**Config:** `params_trust_full.yaml` now carries all six attacks + wrong-key
devices in one run, so the matrix is exercisable end to end. 4 of 8 edge nodes
are malicious, which looks like it threatens the latency tell's fleet-median
(honest-majority) assumption and does not — only the 2 CPU-burning attacks make
a node slow to answer `/status`; blackhole and grayhole answer at full speed.
That reasoning is written into the config, because a third CPU-burner *would*
break it. Config self-consistency is pinned by tests (a spoofer accidentally
listed as a wrong-key device would be denied at admission and silently remove
an attack from the run).

**Phase 2 status: done (2026-08-07). 395 → 472 tests green** (77 new:
`test_attack_classifier.py` 32, `test_attack_report.py` 33, +7 in
`test_authenticator.py`, +5 in `test_flow_monitor.py`). Smoke-tested end to end
through the CLI against a hand-built JSONL. **Not yet run against real live
telemetry — the numbers are only meaningful after Phase 6.**

### Phase 3 — Scalability sweep
- [x] **`evaluation/scalability_sweep.py` (2026-08-07).** Same *pattern* as
      `starvation_sweep.py` — discrete-event harness driving the **real**
      `select_edge_node` — but a **new module, not an extension**, for a
      reason found by reading the old one: `starvation_sweep.py` models an
      **infinite-server** farm (an arrival is served immediately at
      `now + service`, `inflight` may exceed `concurrency` without bound,
      nothing ever times out). That is exactly right for "who does the
      selector pick?", and it is why its published tables in
      `docs/LOAD_BALANCING_STARVATION.md` are trustworthy — but it makes delay
      flat in N *by construction*, PDR 1.0 *by construction*, and throughput
      equal to the offered rate. Extending it in place would also have
      silently invalidated those tables. New model: **M/M/c per node** with an
      unbounded FIFO and real task timeouts. A timed-out task is counted as
      loss but deliberately **not** removed from the node — the client
      abandoned it, the node has no idea, and the worker stays occupied. That
      wasted capacity is what makes an overloaded fleet degrade instead of
      gracefully shedding load.
- [x] **Trust is composed, not equated with reliability.** `starvation_sweep.py`
      can treat trust *as* the reliability EMA because there trust only ever
      rises and only the ordering matters. Here it decides **eligibility**
      (`select_edge_node` drops anything under `isolation_threshold` 0.30), so
      collapsing T to R alone put an honest-but-overloaded node at 0.075 after
      a single timeout and quarantined the whole fleet — a modelling artifact,
      since a merely-slow node still scores full marks on behaviour and
      honesty. Modelling `T = αR + β + γ` floors honest trust at 0.50 and keeps
      saturation showing up where it genuinely does: in latency and PDR.
      Pinned by a test asserting zero route denials under 200% load.

**Results (seed 1, 120s cells, N=4..64).**
1. **p2c scales linearly; argmax saturates.** Offered load rises with N, so
   keeping up means linear throughput and flat delay/PDR. At 60% load p2c gives
   **48/95/192/382/762 tasks/s** for N=4/8/16/32/64 — a clean doubling per
   doubling — at PDR 99.7–99.8% and ~266 ms mean delay throughout. argmax
   saturates at ~85 tasks/s from N=8 and its PDR falls **99.2% → 91.7% →
   45.8% → 21.3% → 10.5%**, delay pinned at the ~2 s timeout ceiling.
2. **argmax fails in two different ways at the two ends of offered load**,
   which is why load became a sweep axis rather than a fixed setting. At **10%**
   it starves (13/16 nodes idle, Jain 0.176; 23/32 at N=32) — the same effect
   as `docs/LOAD_BALANCING_STARVATION.md` and the starved-for-2238 s live node.
   At **60%** almost nothing is starved (Jain 0.75–0.85) because queues finally
   push the CPU term away from the favoured nodes — the fleet ends up balanced
   *and* broken. Reporting either end alone makes argmax look merely unfair, or
   merely slow, instead of both. The crossover is visible in a single row:
   argmax at 10% load and N=64 offers 128 tasks/s against the ~40 tasks/s two
   favoured nodes can serve, so it tips out of starvation (0/64) into loss
   (PDR 73.5%).
3. **p2c does not make decisions cheaper** — and this is worth saying because
   it is the intuitive claim to make and it is wrong here. Both strategies cost
   the same and both grow ~linearly with N (3/5/9/16/30 µs at N=4/8/16/32/64).
   `select_edge_node` scores and sorts **every** eligible node regardless of
   strategy, because that ranking is returned as the *explanation* of the
   decision (`trust_balancer.py` publishes it as `ranked`). p2c's O(d) sampling
   rides on an O(N log N) base rather than replacing it. A deliberate trade —
   explicability bought with CPU that is nowhere near a bottleneck at these
   sizes — and **not** to be "optimised" away without consciously giving up the
   ranking. The p2c win is real in fairness, throughput and delay; it is not a
   CPU win.

**Phase 3 status: done (2026-08-07). 472 → 490 tests green** (18 new in
`tests/test_scalability_sweep.py`, including guards on the queueing invariant
itself — if that broke, this harness would quietly become `starvation_sweep.py`
with extra columns and report perfect scaling for everything). Live Mininet
scalability remains out of scope and hardware-capped, per §4.

### Phase 4 — Service-availability metric
- [x] **`evaluation/availability_report.py` (2026-08-07).** No new
      instrumentation, as planned: everything is derived from the `quarantine`
      / `recovered` events the controller already publishes plus Phase 2's
      ground truth. The WSN metric maps over cleanly with **isolation standing
      in for death** — time to first node death → time to first isolation;
      time to 50% dead → time below a serving quorum; network lifetime → time
      the fleet stayed above it; per-node lifetime → per-node eligible fraction.
      No energy model was invented; for mains-powered edge servers a battery
      curve would be a fabricated number dressed as a measurement.
- [x] **The attacker/honest split is the point of the module, not a
      presentation choice.** Quarantine downtime means *opposite* things for
      the two groups: an isolated attacker is zero-trust enforcement working,
      and counting it as lost availability penalises the defence for
      defending; an isolated honest node is the system's real cost, and this
      project has twice shipped a defect whose entire signature was honest
      nodes wrongly quarantined (`[[live-run-cascading-quarantine]]`,
      `[[quarantine-absorbing-state]]`). A single fleet-wide "availability:
      94%" would be an average over two quantities that should move in
      opposite directions, so the headline number counts **honest nodes
      only**, attacker downtime is reported separately as *containment*, and
      `format_report` never prints a combined figure. Absent groups report
      `None`, not `0.0` — "no attackers configured" must not read as "total
      enforcement failure".
- [x] **Two failure modes this project has actually shipped are surfaced
      explicitly**, because both are invisible in an availability average:
      - **Stranded honest nodes** (`never_recovered`): entered quarantine and
        never left. That is the absorbing-state defect exactly, and a fleet
        full of them can still average 90% uptime. Called out by name with a
        pointer to probation.
      - **Teardown misread as collapse**: a recording whose final seconds show
        most of the fleet quarantining is almost certainly capturing agents
        being killed while the controller still polls. Detected and **warned
        about, never silently trimmed** — a knob that discards inconvenient
        tail data is a knob that will eventually be used to flatter a result.
        The tail still counts as real downtime; the reader is told why it is
        probably an artifact and pointed at `POST /monitor/pause`.
- [x] Also reports containment latency per attacker (configured onset → first
      isolation), which complements Phase 2's detection latency: Phase 2
      measures how fast the attack was *named*, this measures how fast it was
      *stopped*. Same stated upper-bound caveat.

**Phase 4 status: done (2026-08-07). 490 → 517 tests green** (27 new in
`tests/test_availability_report.py`, arithmetic checked against hand-computed
timelines — every figure here is a time integral, so an off-by-one in segment
attribution would give a plausible wrong number rather than a crash). All four
analysis tools now documented together in `SETUP.md`.

### Phase 5 — Dashboard time-series charts
Wire Phase 0's binned data into real line charts (currently the dashboard has
zero time-series — only live snapshots and one-shot animations). `dataviz`
skill territory when reached.

### Phase 6 — Fresh full live run
Produce the real panel-facing numbers/plots on current code; likely also what
finally unsticks the stale study doc (`[[study-runs-and-data]]`).

---

## Notes / rules to not lose while building this

- Keep the packet-drop discipline: task-level loss and OpenFlow drop-rule
  hits are different things and both matter — don't let one absorb the
  other in reporting.
- Keep the "correctly isolated attacker" vs. "wrongly starved/quarantined
  honest node" distinction alive in every new metric that touches
  quarantine — this project has been burned by conflating the two twice
  already (`[[edgescore-fanout-starvation]]`, `[[live-run-cascading-quarantine]]`).
- A detector with no recent evidence abstains, it does not re-assert a stale
  verdict (`[[quarantine-absorbing-state]]`) — any new detector added for
  DDoS/on-off must follow the same rule or it reintroduces the absorbing-state
  bug in a new shape.
