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

### Phase 2 — Classification
Turn detector `reasons` (+ Phase 1's new signals) into a discrete
`attack_type` label; score against `topology.py`'s ground truth for a real
confusion matrix. This is the concrete "proof" behind the classification ask.

### Phase 3 — Scalability sweep
Extend `starvation_sweep.py`'s pattern from fan-out-only to full metrics,
N=4..64+.

### Phase 4 — Service-availability metric
Derived from existing quarantine/isolation event history; no new
instrumentation needed.

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
