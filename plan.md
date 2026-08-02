# Project Plan — Zero Trust–Enabled SDN Architecture

*Last updated: 2026-08-02. Verified against working tree on `feature/ai-optimizer`
(commit `248feca`): **325/325 tests passing** — 22 new for the offline Random
Forest in Step 1, 33 new for RAFT wiring in Step 2, 31 new for the Step 3 NFR
instrumentation/orchestration below, and 16 new for the escape-from-quarantine
work (stale-evidence abstention + probation) and the inflight-invariant fix
that live runs 1–4 drove out. **Five live 8/40/3 runs are done; run 5
(2026-08-02) is the confirming one and Step 3 is closed** — zero routing
denials, 99.87% task success, all 3 attackers isolated, all 5 honest nodes
serving throughout.*

This is the working roadmap from here to submission. It supersedes the
"Not started at all" section of `DIRECTION.md` (2026-07-17), which is now
stale — four of the five items it lists as 0-byte stubs are built.

---

## Verified state (re-check before trusting old docs)

`pytest tests/` → **325 passed** (15.3s). Status vs. the deck's headline components:

| Deck component | Real status |
|---|---|
| PRESENT-80 auth | ✅ Built + wired into live device admission (`security/present_cipher.py`) |
| Evaluation harness | ✅ Done — 600 runs, Wilcoxon + Holm–Bonferroni, 14/16 favour the system (`docs/EVALUATION.md`) |
| AI optimizer | ✅ Done — UCB1 online (`TrustState` + dashboard) + offline Random Forest warm-start prior, both with a measured result (`docs/AI_OPTIMIZER.md`) |
| RAFT | ✅ Done (not yet wired to the live controller) — TCP transport + `RaftBackend` + a 3-process live demo with measured commit latency (`docs/RAFT.md`) |

Also fixed since `DIRECTION.md` / earlier memory notes were written: Merkle
order-sensitivity, EdgeScore starvation (p2c + ε-exploration), the Sybil
latency tell, and the run-B trust H-term mismatch (`TrustState.claimed_load()`
in `controller/trust_state.py` now time-averages the node's claim over the
same window the controller integrates occupancy over).

## Two real gaps left (offline Random Forest and RAFT wiring closed — see below)

1. ~~RAFT wiring~~ — **done**, see Step 2 below and `docs/RAFT.md`. Not yet
   swapped into the live controller (`trust_balancer.py` still constructs
   `LocalLedgerBackend`) — that swap is now a one-line, one-call-site change
   whenever it's wanted, per the seam `RaftBackend` was built to match.
2. ~~Offline Random Forest~~ — **done.** `evaluation/baseline.py`'s harness did
   *not* actually produce training data on its own (that line above was
   aspirational, corrected in `docs/AI_OPTIMIZER.md`) — fixed by running a live
   UCB1 bandit inside the simulator across seeds/scenarios
   (`evaluation/generate_optimizer_dataset.py`), training a
   `RandomForestRegressor` on the result (`trust_engine/rf_optimizer.py`), and
   comparing the RF-warm-started bandit (`zt_sdn_rf`, `evaluation/rf_comparison.py`)
   against the same 5 strategies on the same seeds. **Measured result: no, it
   does not beat hand-tuned static weights** — significantly *worse* in
   `sybil`/`both` (≈1% relative, medium effect size), no difference in
   `clean`/`drop`. Reported as the honest finding, not chased further.
3. ~~Full-scale 8/40/3 live~~ — **done.** Five runs (2026-08-01/02) drove out
   seven defects, every one of them the controller's own bookkeeping feeding a
   working detector bad input — never the detectors themselves. Run 5 confirms
   all seven fixed: zero routing denials, 99.87% task success, attackers
   isolated, honest nodes serving throughout. See Step 3 and
   `docs/LIVE_RUN_8_40_3.md`. Two non-blocking items left (teardown artifact,
   `pingAll` wall-clock) — both listed in Step 3.
4. **Study run C** — `docs/study/trust-routing-study.html` sections 6–8 still
   narrate the H-term/starvation defects as open; both are now fixed in code.
   Needs a fresh live run to confirm in real telemetry (or reopen the finding).

---

## Step 0 — Housekeeping (in progress)

- [x] Merge `origin/main` into `feature/ai-optimizer` (brought in a teammate's
      `trust_convergence_demo/` + `wsl_gui/` additions; resolved the README
      repo-structure conflict in favour of the accurate Sprint-2 status).
- [x] Re-run full test suite post-merge — 216/216 still green.
- [x] Fix `run_demo.py`'s mininet-mode message (said "Ryu", now says
      "Mininet/Open vSwitch/os-ken").
- [x] Fix README Status table: PRESENT-80 ✅, AI optimizer 🟡 (UCB1 done / RF
      pending), commit `045683b`.
- [x] **Push `feature/ai-optimizer` to `origin`** — done outside this session;
      branch is up to date with `origin/feature/ai-optimizer` at `045683b`.
- [x] Open PR `feature/ai-optimizer` → `main` — done and merged outside this
      session: `origin/main` is `cddb788`, "Merge pull request #5 from
      a5hx/feature/ai-optimizer". `main` has nothing this branch lacks other
      than that merge commit itself.

Step 0 is fully complete.

## Step 1 — Offline Random Forest weight optimizer — DONE

- [x] Correct the plan's premise: `evaluation/baseline.py` did **not** already
      produce `(conditions → arm, reward)` training data — its 5 strategies
      never touched the optimizer. Fixed by adding a 6th, non-default strategy
      `zt_sdn_rf` that drives a live `UCB1WeightOptimizer` inside the same
      simulator (`_Router.choose` now takes `weights`; `simulate()` gained a
      `window`-event bandit loop mirroring `TrustState.optimizer_tick`).
- [x] `evaluation/generate_optimizer_dataset.py` — runs the cold bandit across
      seeds × scenarios, writes `data/optimizer_dataset.csv`.
- [x] `trust_engine/rf_optimizer.py` — trains a `RandomForestRegressor`
      (features: conditions + arm's own weight triple), joblib-persisted;
      `UCB1WeightOptimizer.seed_values()` is the warm-start seam (no protocol
      change, no controller change).
- [x] `evaluation/rf_comparison.py` — runs `zt_sdn_rf` (RF-warm-started)
      alongside the original 5 strategies on the same seeds;
      `evaluation/stats.py` needed no changes (`--system zt_sdn_rf`).
- [x] Tests: `tests/test_ai_optimizer.py` (`seed_values`),
      `tests/test_rf_optimizer.py`, `tests/test_generate_optimizer_dataset.py`,
      `TestOptimizerStrategy` in `tests/test_baseline.py`. 238/238 passing.
- [x] Ran the real 720-run comparison (8 nodes, 120s, 30 seeds × 4 scenarios ×
      6 strategies). **Measured answer: no, the learned prior does not beat
      hand-tuned static weights** — significantly worse in `sybil`/`both`
      (~1% relative, medium effect size), no significant difference in
      `clean`/`drop`. Full table and reproduction command in
      `docs/AI_OPTIMIZER.md` Part 2. This is reported as the honest result,
      not treated as a defect to fix.

**Why before RAFT:** cheapest remaining item (sklearn already a dependency,
training data already produced, no new transport/networking code), and it
closes a deck row with a *measured* result rather than a built-but-unproven
component.

## Step 2 — RAFT wiring — DONE

- [x] `blockchain/raft_transport.py` — `TcpTransport` satisfying `raft.py`'s
      `Transport` Protocol (JSON over length-prefixed TCP frames, not pickle —
      these sockets face the network). `blockchain/raft.py` itself is
      untouched. Tested in `tests/test_raft_transport.py` (codec round-trips +
      real-socket delivery) — RAFT's safety properties are not re-proven
      against it, per the plan; that stays in `tests/test_raft.py`.
- [x] `RaftBackend(CommitBackend)` in `blockchain/commit_backend.py` — turns
      RAFT's async commit into the synchronous `commit()` the Protocol
      promises. Found and fixed two real bugs building this (see
      `docs/RAFT.md` for the full writeup): (1) `Ledger`'s genesis block used
      `time.time()` as its default timestamp, so every independently-built
      replica started from a *different* genesis hash — fixed by pinning it
      to `0.0` (`blockchain/ledger.py`); (2) a newly-elected leader can
      propose against a *stale* local ledger snapshot (it's guaranteed to have
      every entry in its RAFT log, not to have already applied every earlier
      one) — fixed by replicating only entry *content* (timestamp,
      proposer_id, raft_term, trust_updates) and having each replica compute
      its own `index`/`previous_hash`/`merkle_root` at apply time, which
      RAFT's strict in-order apply guarantees is safe.
- [x] `blockchain/raft_replica.py` (standalone replica process + HTTP control
      API) and `blockchain/raft_demo.py` (spawns 3, commits, kills the leader,
      measures recovery) — run live, not simulated: 3 real OS processes, real
      loopback TCP, real `SIGTERM`.
- [x] Tests: `tests/test_raft_transport.py`, `tests/test_commit_backend.py`,
      `tests/test_raft_replica.py`, `tests/test_raft_demo.py`. 271/271 passing.
- [x] Measured commit latency (`python3 -m blockchain.raft_demo --commits 50
      --commit-interval-s 0.02`, 2 runs): mean 4.3–4.8ms, max 29–42ms, both
      well under the 500ms NFR. Leader failover: 0.22s to a new leader both
      runs. Full table in `docs/RAFT.md`.
- [ ] **Not done, and deliberately deferred**: swapping `LocalLedgerBackend →
      RaftBackend` inside the live controller (`controller/trust_balancer.py`).
      `RaftBackend` matches `LocalLedgerBackend`'s constructor shape closely
      enough that this is a one-call-site change whenever it's wanted; doing
      it needs a decision on the "no client-side leader redirect" limitation
      in `docs/RAFT.md` first (who retries against `leader_id` when the
      active controller isn't the current leader).

## Step 3 — Full-scale integration, 8 edge / 40 IoT / 3 malicious — CODE DONE, LIVE RUN PENDING

- [x] `run_demo.py --mode mininet` is a real entry point, not a stub: root +
      Mininet-availability + config-shape checks, spawns the os-ken controller
      as a subprocess (`ZTSDN_CONFIG` env var), polls the REST API until it's
      up (`_wait_for_controller`, avoids the fail-secure-switches race), runs
      `simulation.topology.run_topology(cfg, interactive=False)` for the
      configured duration, tears the controller down, then computes and
      prints/saves the NFR report.
- [x] `config/params_trust_full.yaml` — the 8/40/3 live config
      (`params_trust_demo.yaml`'s 4/12/1 scaled up): 3 malicious edge servers
      spread through the fleet (srv3 sybil, srv6 drop, srv8 sybil) + 2
      malicious IoT devices (wrong-key, auth-deny path). "3 malicious" = edge
      servers, matching the evaluation harness's own convention
      (`num_malicious` in `config/params.yaml`) — the malicious-edge vs.
      malicious-IoT split stays an openly disclosed reframing (Step 6), not
      silently resolved.
- [x] `evaluation/nfr_report.py` — computes 3 of the 4 NFRs from a live run's
      `data/events.jsonl`: routing decision (`route` events' `decision_ms`),
      isolation (`reroute` events' `resteer_ms`, folded together with one
      `monitor_interval_s` poll bound), blockchain overhead (`report` events'
      `report_ms` split by a new `committed` flag — the relative slowdown a
      `/report` call suffers when it happens to trigger a block commit vs.
      one that doesn't). RAFT commit is reported from the already-measured
      isolated figure (`docs/RAFT.md`), not computed live — RAFT stays
      unwired into the live controller per Step 2.
- [x] New instrumentation to make blockchain overhead measurable at all:
      `TimingCommitBackend` (`blockchain/commit_backend.py`) wraps the
      controller's commit backend, timing every real `commit()` call;
      `handle_client_report` (`controller/trust_balancer.py`) times its own
      `record_task_outcome` call and tags the existing `bus.publish('report',
      ...)` event with `report_ms` + `committed`. Nothing on the OpenFlow
      packet-in path (the <200ms NFR) was touched.
- [x] Tests: `tests/test_commit_backend.py` (`TestTimingCommitBackend`),
      `tests/test_nfr_report.py` (pure-function tests against synthetic
      events, no Mininet needed), `tests/test_run_demo_mininet.py` (guard
      clauses, config-default resolution, controller-readiness poll).
      293 -> 302 tests, all green.
- [x] **Live run 1 done (2026-08-01) — it collapsed, and that was useful.**
      All four NFRs came out PASS on real data (routing mean 0.62ms / p95
      0.91ms; isolation mean 28.6ms / max 42.0ms; blockchain overhead 0.018%;
      RAFT from `docs/RAFT.md`), but all 8 servers ended quarantined with
      91.7% of routing attempts denied. Full write-up, timelines and
      before/after evidence: **`docs/LIVE_RUN_8_40_3.md`**. Two real defects
      found and fixed:
      1. `simulation/topology.py` ran `net.pingAll()` *before*
         `_launch_trust_agents()`. O(hosts²) — 2,352 pings at 8/40 = 163s
         during which the controller quarantined all 8 servers for not
         answering polls on agents that did not exist yet (44% of the run).
         Fixed by reordering; this was also the "laggy dashboard at startup".
      2. `TrustState._dispatch_reap_after_s` was hardcoded to 30.0s against a
         2.0s client `task_timeout_s`. A timed-out client never sends
         `/report`, so its dispatch kept counting toward `observed_load` for
         15 more cycles — honest, genuinely-idle nodes read as 0.75 loaded
         against a truthful 0.00 claim, tripped the honesty check, and each
         quarantine re-dispatched load onto the next survivor until all 8
         fell. **The detectors were right the whole time** (the 3 real
         attackers were caught first); the load signal feeding them was
         wrong. Fixed by deriving the reap horizon from `task_timeout_s`
         (`contracts/thresholds.DEFAULT_TASK_TIMEOUT_S`), so they cannot
         drift apart again.
      Also fixed a defect in the harness itself: `nfr_report.py`'s
      blockchain-overhead denominator was an uncommitted `/report`'s handling
      time (tens of µs), which reported a 0.42ms commit as 2155% overhead.
      Now amortises over batch size and divides by end-to-end task latency.
      307/307 tests green, with regression tests for all three.
- [x] **Live runs 2 and 3 done (2026-08-01).** Run 2 found two more defects
      (`reassign_dispatches` resetting the abandonment clock; the controller
      scoring nodes that had never existed) — both fixed, see
      `docs/LIVE_RUN_8_40_3.md`. Run 3 then **confirmed every structural fix
      from runs 1–2**: no startup quarantine at all, first route 1.2s after
      switch-up (vs 163s in run 1), 9 `/status unreachable` anomalies in the
      whole run, and final `inflight` 0 / `observed_load` 0.00 on all 8
      against truthful claims. The phantom-load cascade is gone.
- [x] **Run 3 exposed the real root cause: quarantine was an absorbing
      state.** All 8 still ended quarantined, but for a reason unrelated to
      the load signal: quarantine cuts service traffic, and service traffic is
      the only thing that produces task outcomes, so every detector reading
      outcomes goes blind the moment it fires and every term of T that
      outcomes feed stops moving. Two expressions, both fixed:
      1. **Detectors latched on frozen evidence.** `_recent_statuses` was a
         count-based `deque(maxlen=10)` of bare statuses, so it only turns
         over when tasks arrive. srv5's last real outcome was t=9.2s and the
         controller was still asserting `timeout rate 0.60 > 0.40` against it
         at t=240.9s — 231s of Ā=1.0 from a sample that had stopped being
         observed. Entries now carry timestamps and `recent_timeout_rate()`
         returns `None` past `3 × task_timeout_s`: a detector with no recent
         evidence must abstain, not re-assert its last verdict.
      2. **Trust could not climb without traffic.** srv1/srv4/srv7 ended at
         anomaly 0.0, ~29ms RTT, inflight 0 — provably healthy — and isolated
         for the whole run at trust 0.18–0.21 vs a 0.3 threshold, because R
         and B only move on outcomes quarantine prevents. Added **probation**,
         the half-open leg of a circuit breaker: a node quarantined on the
         trust rail *only*, with Ā already under the gate, gets one trial task
         per `probation_interval_s` (5.0s). The anomaly gate stays an absolute
         bar — a flagged node is never probed — and exposure is capped at one
         task per node per interval, inert when nothing is quarantined. Trial
         flows install at `PRIO_PROBATION = 460`, above the quarantine drops,
         or they would be black-holed by the rules they exist to escape.
      Again: **the detectors were right.** Run 3's initial quarantines fired
      on true evidence (real timeouts at mean 341ms / p95 1609ms task latency
      while 40 clients and 8 agents came up on 4 cores). What was missing was
      any path back. 309 → 321 tests, all green.
- [x] **Live run 4 done (2026-08-01).** Both Defect 6 escapes worked — 143
      probation trials, 22 continuous recoveries, 0.0% denial for the first
      55s — and then the run degraded to 46.9% denial via **Defect 7**:
      `register_dispatch` overwrote an already-present key while keeping its
      inflight count, orphaning it permanently (no dict entry for the reaper,
      no completion report to release it). srv1 — zero probation trials, so
      nothing new could be blamed — sat at exactly 2 orphaned dispatches for
      976s, pinning `observed_load` 0.50 against a truthful `claimed_cpu`
      0.00, one tick over the 0.40 gate, producing 707 quarantines of a
      healthy node. Little's Law is what proved the occupancy was fabricated
      (0.01 predicted vs 2 actual). Fixed; four tests assert the invariant
      `sum(_inflight) == len(_dispatches)` directly.
- [x] **Live run 5 done (2026-08-02) — the confirming run. Step 3 is closed.**
      1,720s at 8/40/3 with **zero `route_denied` events** across 18,539
      routes, **18,185 task successes against 19 timeouts** (99.87%), and flat
      ~640 routes/min service from t=5.6s to t=1,717.9s with no degradation in
      any 60s bin. All four NFRs PASS (routing mean 0.68ms; isolation mean
      13.5ms; blockchain overhead 0.056%; RAFT per `docs/RAFT.md`).
      - **Defect 7 confirmed fixed on the measurement that found it**:
        `inflight` oscillates — 487–535 changes over 1,309 polls per honest
        node, longest constant non-zero run 4–16 polls, vs run 4's 976s
        freeze. CPU-honesty firings fell from 3,563 to **8** (4 honest / 4
        attacker).
      - **Detection is carried entirely by the latency tell**: 2,198 firings,
        every one on a sybil, **zero on honest nodes**. srv6 (drop) completed
        0 tasks; srv3/srv8 completed 43/36 (probation trials) vs ~3,200–3,800
        each for the honest five.
      - **Finding 1 confirmed live**: both sybils ended at trust 0.742/0.693 —
        *higher* than honest srv4 at 0.400 — and were isolated purely by the
        anomaly gate. Good material for the viva.
      - **Probation measured**: 330 trials, one per 5.6s against a 5.0s
        interval (cap holds); 301 went to srv6 and correctly re-confirmed its
        verdict, while srv4 recovered on its 23 after a genuine startup
        congestion quarantine.
- [ ] **Teardown quarantines all 8 nodes (cosmetic, but fix it).** `run_demo.py`
      kills the agents while the controller is still polling, so 16 `/status
      unreachable` anomalies land in the last 2s and the final `node_status` —
      the frame anyone would screenshot — shows all 8 quarantined at anomaly
      0.98–1.00. Every honest node was serving normally until t=1,717.9s. Stop
      the monitor (or mark teardown in the recording) before stopping agents.
- [ ] **`pingAll` costs 82% of the run.** `net.pingAll()` sits at
      `simulation/topology.py:280`, between agent launch and the
      `time.sleep(duration)` at line 294, so its cost is *additive* to
      `duration_s`: run 5 was configured for 300s and took 1,720s, ~1,415s of
      it the 2,352-ping sweep. Not a correctness problem (first route at
      t=5.6s, service flat throughout) but it makes every live run 5.7× longer
      than it needs to be. Sample reachability, or skip it in `trust_mode`.

Note the evaluation harness already defaults to 8 edge nodes
(`config/params.yaml`), so scale is already proven *statistically* — this step
is the live-fidelity half of that same claim.

## Step 4 — Regenerate the study with a fresh run (~half day)

Run C on current head (after Steps 1–3, or standalone if time-constrained).
Rewrite `docs/study/trust-routing-study.html` sections 6–8 from "open defect"
to "found, characterised, fixed — here's the before/after evidence", which is
a stronger story than what's currently written. Reprint the PDF via the
in-page "Print / Save as PDF" button (no chromium/weasyprint/wkhtmltopdf
installed on this WSL box to do it headlessly).

## Step 5 — Software-project artifacts (~1 day)

- Requirements traceability matrix: requirement (deck/SRS) → design element
  (UML, already in git under `uml_diagrams/`) → test ID (216 tests, already
  green). All three artifacts already exist; this is assembly, not new work.
- CLI entry point (`ztlb run --config …`), config validation with readable
  errors, version string.
- Manual quarantine/release buttons on the dashboard (operator-console framing
  from `DIRECTION.md` §7).
- `CHANGELOG.md` + tag `v1.0` for the demo build.

## Step 6 — Report + viva prep

Lead with the working live demo. Present Finding 1 (published trust formula
cannot isolate a competent liar without the anomaly gate — see `DIRECTION.md`
§3) as a finding, with the regression test named
(`test_f04_non_degrading_liar_needs_anomaly_gate`). Disclose the two open
reframings proactively (os-ken substitution; malicious-edge-servers vs.
malicious-IoT-devices split). Bring the fixed-vs-learned-gates question
(`DIRECTION.md` §4 Step 4 note) to the advisor as a concrete decision if not
already settled.

---

## Notes / decisions carried over

- **Do not conflate the two zero-traffic cases** when discussing load
  balancing: sybil/malicious getting 0 traffic is correct isolation; a
  healthy node getting 0 traffic was the starvation bug (now fixed by p2c +
  ε — see memory `edgescore-fanout-starvation`).
- **`data/` is gitignored** — `data/events.jsonl` (source for the study
  figures) is not in git; only the derived JSON pasted into the study HTML
  survives. Re-derive via streaming `json.loads` per line if a fresh run is
  needed (~400 MB file).
- **WSL run prerequisites** (needed every session before Mininet works): OVS
  daemon (`sudo service openvswitch-switch start`), qdisc modules
  (`sudo modprobe -a sch_htb sch_netem sch_tbf sch_prio ifb`), `sudo mn -c`
  between runs, controller started before topology. Full detail in memory
  `wsl-run-prerequisites` / `final_run.md`.
