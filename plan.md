# Project Plan — Zero Trust–Enabled SDN Architecture

*Last updated: 2026-08-01. Verified against working tree at commit `045683b`
on `feature/ai-optimizer` (271/271 tests passing — 22 new for the offline
Random Forest in Step 1, 33 new for RAFT wiring in Step 2).*

This is the working roadmap from here to submission. It supersedes the
"Not started at all" section of `DIRECTION.md` (2026-07-17), which is now
stale — four of the five items it lists as 0-byte stubs are built.

---

## Verified state (re-check before trusting old docs)

`pytest tests/` → **216 passed**. Status vs. the deck's headline components:

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
3. **Full-scale 8/40/3 live** — `run_demo.py --mode mininet` is still a stub
   that exits with a message (now says os-ken, not Ryu — fixed today).
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

## Step 3 — Full-scale integration, 8 edge / 40 IoT / 3 malicious (~1 day)

Turn `run_demo.py --mode mininet` into a real entry point (currently exits
immediately — see the message fixed in Step 0). Validate all four deck NFRs in
one table:
- routing decision <200 ms
- isolation <3 s
- blockchain overhead <15 %
- RAFT commit <500 ms (once Step 2 lands)

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
