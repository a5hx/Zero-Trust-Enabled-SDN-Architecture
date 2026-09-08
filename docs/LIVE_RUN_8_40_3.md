# Live full-scale run — 8 edge / 40 IoT / 3 malicious

First end-to-end live run of `run_demo.py --mode mininet` at the deck's full
scale, 2026-08-01, on the WSL2 box (4 cores). Config:
`config/params_trust_full.yaml`. Source events (`data/events.jsonl`, 137 MB)
are gitignored; everything below is derived from them and reproducible with
`python3 -m evaluation.nfr_report data/events.jsonl --poll-interval-s 1.0`.

The run **collapsed** — all 8 edge servers ended quarantined and 91.7% of
routing attempts were denied. It also produced clean numbers for three of the
four NFRs, and two genuine defects. Both defects are fixed; this document is
the before/after evidence.

> **Read the ending first.** This document is chronological across five runs
> and eight defects. Runs 1–4 each collapsed and each exposed a different one —
> seven in all, every one of them the controller's own bookkeeping feeding a
> *working* detector bad input. **Run 5 (2026-08-02) is the confirming run**:
> zero routing denials across 18,539 routes, 18,185 task successes against 19
> timeouts, all three attackers isolated, all five honest nodes serving
> throughout. Jump to "Run 5" for the closing evidence.
>
> **Defect 8 is different in kind** and worth reading on its own: run 5 passed,
> and analysing its recording afterwards showed a fix from *weeks* earlier had
> only ever been wired into one of its two consumers. It quarantined nothing
> and failed no test — it was hidden by a workload retune. See "Defect 8".

---

## NFR results (run 1, from the recording)

| NFR | target | measured | verdict |
|---|---|---|---|
| Routing decision | < 200 ms | mean 0.62 ms / p95 0.91 ms / max 12.90 ms (n=417) | **PASS** |
| Isolation (re-dispatch) | < 3000 ms | mean 28.56 ms / max 42.02 ms (n=30), + 1 s detection poll | **PASS** |
| Blockchain overhead | < 15 % | 0.018 % — 0.0428 ms per task vs 243.7 ms task latency | **PASS** |
| RAFT commit | < 500 ms | mean 4.3–4.8 ms (measured separately, `docs/RAFT.md`) | **PASS** |

Routing and isolation are measured on the real OpenFlow path and hold with
three and two orders of magnitude of headroom respectively. They were measured
*during the collapse*, which if anything is the harder case.

---

## Defect 1 — the controller judged nodes that had not been started yet

`simulation/topology.py` ran `net.pingAll()` **before** `_launch_trust_agents()`.
pingAll is O(hosts²): 272 pings at the 4/12 demo scale (seconds), but **2,352
pings at 8/40 — 163.5 s** (10:27:39.6 → 10:30:23.1).

Throughout those 163 s the controller was already polling `/status` every
second on 8 servers whose `node_agent.py` processes did not exist yet. An
unanswered poll scores anomaly 1.0 — correctly, an unreachable node is
indistinguishable from a failed one — and the EMA (λ=0.85) puts a single such
observation at 0.85, past the 0.5 quarantine gate:

```
t=  0.5s  Q srv1..srv8  -> 8/8 quarantined     (agents not launched yet)
t=168.0s  R srv1..srv8  -> 0/8 quarantined     (agents up; instant recovery)
```

**44% of a 300 s run** was spent quarantining processes that did not exist.
This is also the "dashboard is laggy at startup" symptom: the same ping storm,
plus 49 host namespaces on 4 cores.

**Fix:** `_launch_trust_agents()` now runs before `net.pingAll()`. pingAll's
reachability check is unaffected by the agents running, and the switches are up
either way, so the reorder costs nothing.

---

## Defect 2 — the dispatch reaper out-lived the client timeout 15:1

This is the one that caused the collapse.

| | value | where |
|---|---|---|
| client gives up after | **2.0 s** | `agents.task_timeout_s` (config) |
| controller forgot the dispatch after | **30.0 s** | `_dispatch_reap_after_s` (hardcoded) |

A client that times out never sends `/report` at all. Its dispatch therefore
kept counting toward `_inflight` — and so toward `observed_load` — for 30 s
after the client had already walked away. The run recorded **3,427 timeouts
against 356 successes** (90.6%), so every node accumulated roughly 15 cycles of
phantom inflight.

`flow_monitor`'s honesty check compares the controller's `observed_load`
against the node's self-reported `claimed_cpu`, and fires above a 0.40 gap.
With phantom load it fired on nodes that were genuinely idle:

```
srv2: honesty deviation 0.750 (claimed=0.000 observed=0.750) > 0.400
```

srv2 is honest, and at that moment had real inflight 0 and an RTT of 31 ms.
The controller's own stale bookkeeping declared it a liar.

Then it cascaded — each quarantine re-dispatches that node's clients onto a
survivor, which pushes the survivor over the same threshold:

```
t=169.6s  Q srv6, srv8      -> 2/8      <- genuinely malicious (drop, sybil)
t=170.8s  Q srv2            -> 3/8      <- honest
t=172.1s  Q srv5            -> 3/8      <- honest
t=174.5s  Q srv3            -> 4/8      <- genuinely malicious (sybil)
t=177.2s  Q srv1            -> 5/8      <- honest
t=178.3s  Q srv7            -> 7/8      <- honest
t=179.7s  Q srv4            -> 8/8      <- honest
```

Final tally: **4,634 `route_denied` vs 417 `route`** — 91.7% denial.

**The detectors were correct throughout.** Note the ordering: the three actual
attackers (srv6 drop, srv8 sybil, srv3 sybil) were caught *first*, and fast.
The five honest nodes fell only afterwards, as they absorbed redistributed
load. What was wrong was the load signal being fed to a working detector, not
the detector.

**Fix:** `_dispatch_reap_after_s` is now derived from the client's own
`task_timeout_s` (`max(1.0, task_timeout_s * 1.5)`, wired from
`agents.task_timeout_s`), so the two cannot drift apart again. Regression
tests: `test_reap_horizon_tracks_the_client_task_timeout` and
`test_abandoned_dispatches_do_not_pin_observed_load_on_an_idle_node` in
`tests/test_trust_state.py`.

### Contributing factor, not a defect: host saturation

4 cores hosted ~50 Python processes (8 agents + 40 clients + controller + OVS)
with 40 ms of real hash work per task. Successful-task latency was 243.7 ms
against the 2,000 ms client timeout. The box was genuinely oversubscribed, which
is what generated the timeouts the reaper then amplified. The fix removes the
amplification; it does not make a 4-core box able to serve 40 concurrent IoT
clients at 1 Hz. A re-run should either drop `task_work_ms`, lower
`report_interval_s`, or be read as a saturation experiment on purpose.

---

## Defect 3 (in the harness, not the system) — wrong overhead denominator

`evaluation/nfr_report.py`'s first cut divided block-commit cost by the
handling time of a `/report` that triggered *no* commit. That path only
computes a trust score and appends to a list — tens of microseconds — so it
reported a 0.424 ms commit as **2155% overhead**, a FAIL on a system that
spends 0.018% of a task in the ledger.

The metric now amortises commit cost over the actual batch size and divides by
end-to-end task latency, which is what "<15% overhead" is a claim about.
Regression test: `test_a_tiny_uncommitted_baseline_does_not_inflate_the_result`.

---

---

# Run 2 (same day, after the run-1 fixes) — still collapsed, two more defects

| | run 1 | run 2 |
|---|---|---|
| startup all-8 quarantine | 168 s (44% of run) | **5 s** |
| `/status unreachable` window | 163 s | ~3 s (controller starts before Mininet) |
| denial rate | 91.7% | **76.1%** |
| recoveries | monotonic slide to 8/8 | real churn, 22 recoveries |

Both run-1 fixes worked. The run was still unusable, for two further reasons.

## Defect 4 — re-dispatch reset the abandonment clock

`TrustState.reassign_dispatches()` rebuilt each moved entry as
`_Dispatch(to_node_id, time.time())` — **stamping `now`**. But `dispatched_at`
answers "has the client given up on this task yet?", and re-steering does not
restart the *client's* timer: it dispatched at T and abandons at
T + `task_timeout_s` however many times the controller re-points its flow.

Because this path only runs during quarantine churn, dispatches were
rejuvenated exactly when they most needed to age out. Run 2 held
`inflight = 7` on srv1 for its entire length (t=28 s → t=134 s, never
draining) with only 50 reaps, which pinned `observed_load` at **1.00** against
a truthful `claimed_cpu` of **0.00** — 220 honesty trips at exactly that
signature. Each re-dispatch then carried the phantom load onto the survivor,
which is what made it contagious.

**Fix:** carry the original `dispatched_at` across a reassignment. Regression
test: `test_reassigned_dispatches_keep_their_original_age`.

## Defect 5 — the controller scored nodes that had never existed

Run 1's fix reordered agent launch *within* `topology.py`, but the controller
is a **separate process that must be listening before any switch can connect**,
so it necessarily comes up seconds before Mininet builds the network. Run 2
still quarantined all 8 servers at t=0.5 s on `/status unreachable` — three
seconds before the network existed.

**Fix:** `FlowMonitor` now tracks `_ever_seen`. A node that has never answered
a single poll is **unknown**, not anomalous, and does not score. This does not
weaken the original Sprint 1 "unreachable = anomalous" finding — a node that
has been seen and *then* goes silent still scores 1.0 immediately, which is
the actual security property. Both halves are pinned:
`test_unreachable_agent_treated_as_anomalous` (seen, then dark → anomalous)
and `test_never_seen_agent_is_unknown_not_anomalous`.

## Workload tuning (config, not code)

Run 2 still showed 1,226 timeouts vs 483 successes because the offered load
genuinely exceeds the host:

```
offered task CPU = num_iot / report_interval_s x task_work_ms
                 = 40 / 1.0s x 40ms = 1.60 cores
```

40% of a 4-core box in pure task work, before the 40 client + 8 agent +
controller + OVS processes are scheduled at all. `config/params_trust_full.yaml`
now uses `report_interval_s: 2.0`, `task_work_ms: 15` (**0.30 cores, 8%**) and
`task_timeout_s: 4.0`. The topology stays 8/40/3 — what changed is how hard
each device pushes, which is a property of the host, not of the architecture.

---

## What a re-run should show

1. No quarantines at startup at all (never-seen nodes no longer score).
2. Startup to first traffic in seconds rather than ~3 minutes.
3. `inflight` that actually drains, and `observed_load` tracking `claimed_cpu`
   on honest nodes.
4. Honest nodes staying up, with srv3/srv6/srv8 still caught.
5. A denial rate near zero rather than 76–92%.

1–3 are structural and follow from the fixes. 4–5 additionally depend on the
retuned workload leaving enough headroom, which the arithmetic above says it
should by roughly 5x.

---

---

# Run 3 — predictions 1–3 held, 4–5 did not, for a new reason

Predictions 1–3 came true exactly. Predictions 4–5 did not, and the reason
turned out to have nothing to do with the load signal that broke runs 1 and 2.

| | run 1 | run 2 | run 3 |
|---|---|---|---|
| startup quarantine storm | 168 s | 5 s | **none** |
| first route after switch-up | after 163 s pingAll | ~3 s | **1.2 s** (switch up t=2.3 s, first route t=3.5 s) |
| `/status unreachable` anomalies | flood | flood | **9, total** |
| final `inflight` | — | pinned at 7 | **0 on all 8** |
| final `observed_load` vs truthful `claimed 0.00` | 0.75–1.00 | 1.00 | **0.00 on all 8** |
| dominant anomaly reason | CPU honesty (phantom load) | CPU honesty (phantom load) | **packet-drop tell (239 of ~250)** |

The phantom-load cascade is gone. `observed_load` now tracks reality, honest
idle nodes read idle, and the CPU-honesty check has stopped firing on them.
Traffic flowed from the first seconds: 153 routes and 136 successful tasks in
the first 15 s, where run 1 had none for 163 s.

All eight servers were nonetheless quarantined by t=20.3 s and only one ever
came back.

## Defect 6 — quarantine is an absorbing state

This is one root cause with two independent expressions, and it is a design
gap rather than a coding slip: **quarantine cuts service traffic, and service
traffic is the only thing that produces task outcomes.** Every detector that
reads task outcomes goes blind the moment it fires, and every term of
T = 0.35R + 0.25B + 0.25H − 0.15A that task outcomes feed stops moving. The
system could enter quarantine but had no evidence-generating path out of it.

The `reap_stale_dispatches` docstring already names this shape — "a terminal
state nothing can leave" — for the inflight counter, and run 2's fix closed
that one instance. Run 3 exposed the two others.

### 6a — the packet-drop tell fired forever on frozen evidence

`TrustState._recent_statuses` was a `deque(maxlen=10)` of bare status strings.
It is count-based, so it only turns over when tasks arrive — and a quarantined
node receives none. Its last verdict therefore stood forever:

```
srv5:  last real task outcome   t =   9.2 s
       still asserting          t = 240.9 s   'timeout rate 0.60 > 0.40'
```

231 seconds of Ā = 1.0 derived from a sample that had stopped being observed.
srv2 and srv6 were held the same way. The packet-drop tell accounted for 239
of roughly 250 anomaly reasons in the whole run — almost all of them replays
of evidence from the first 30 seconds.

**Fix:** entries are `(timestamp, status)`, and `recent_timeout_rate()` returns
`None` — "no opinion" — when the newest outcome is older than
`3 × task_timeout_s`. A detector with no recent evidence must abstain, not
re-assert its last verdict. Under live traffic a node's outcomes arrive far
inside that horizon, so a real drop attacker is still caught immediately;
`test_a_node_still_receiving_tasks_never_abstains` pins that half.

### 6b — trust could not climb without traffic

The other three nodes were not anomalous at all. Final snapshot:

```
srv1  trust 0.1843  anomaly 0.0  inflight 0  latency  29.50 ms  quarantined
srv4  trust 0.2102  anomaly 0.0  inflight 0  latency  29.37 ms  quarantined
srv7  trust 0.1822  anomaly 0.0  inflight 0  latency  29.27 ms  quarantined
```

Idle, honest, responsive, Ā fully decayed — and isolated for the rest of the
run, because trust sat below `isolation_threshold: 0.3` and R and B only move
on task outcomes that quarantine prevents. There was no mechanism by which
these nodes could ever be re-tested.

**Fix:** a probation state, the half-open leg of a circuit breaker. A node
quarantined on the trust rail *only*, with Ā already back under the gate, is
offered a single trial task at most once per `probation_interval_s` (default
5 s). Successful trials raise trust until it crosses back over the threshold
and the node rejoins ordinary routing.

Two properties keep this from being a hole in the model:

- **The anomaly gate stays absolute.** A node the anomaly rail has flagged is
  never probed. Probation re-tests a stale *trust* verdict; it does not
  second-guess active suspicion.
- **The exposure is bounded and self-limiting.** One task per node per
  interval, capped at `|nodes| / probation_interval_s` decisions per second
  regardless of offered load. When nothing is quarantined there are no
  candidates and the path is inert, so ordinary routing is unchanged.

Trial flows install at `PRIO_PROBATION = 460`, above `PRIO_QUARANTINE_DROP`,
for the same reason the health-check carve-out does — below it, every trial
would be black-holed by the drop rules it exists to escape and would read as a
timeout, making probation a machine for confirming the verdict it is meant to
re-test. They carry a short `hard_timeout` (~one task) so the carve-out closes
on its own. `test_probation_trial_flows_out_rank_the_quarantine_drops` pins
both the ordering and the expiry.

### What triggered it in the first place

Worth separating from the defect: the initial quarantines were not spurious.
Successful-task latency was mean 341 ms / p95 1609 ms / max 3488 ms, so real
timeouts did occur while 40 client processes and 8 agents came up together on
4 cores. The detectors fired on true evidence. What was broken is that nothing
could ever rescind the verdict once the evidence stopped arriving — the same
distinction as runs 1 and 2, one layer further in.

### Still outstanding: pingAll got slower, not faster

Run 1's fix (launch agents before `net.pingAll()`) removed the false
quarantines, but it also means the 2,352 pings now run *concurrently with the
live workload* instead of on an idle box. Run 1 measured 163 s for that sweep
with nothing else running; run 3 took **1,255 s end to end** against a
configured `duration_s: 300`, with the last 60 s showing zero routes and zero
reports — the extra ~700 s is pingAll competing with 48 busy processes for 4
cores.

This is wasted wall-clock, not a correctness problem: the reachability check
still passes and nothing is misjudged during it. But it dominates the run, and
at this scale it is not earning its cost — a future change should sample
reachability (or skip it in `trust_mode`) rather than doing all 2,352 pings.
Keep the ordering either way; run 1 is what happens without it.

---

---

# Run 4 — both escapes work; a counter leak underneath them does not

Run 4 is the first run with the Defect 6 fixes in. Both worked, and both are
measurable:

| | run 3 | run 4 |
|---|---|---|
| worst stale-evidence firing | **231.7 s** old | **11.4 s** old (inside the 12 s horizon) |
| packet-drop tell firings | 239 | 49 |
| probation trials | n/a (did not exist) | **143** across 6 nodes |
| recoveries | 8 (only 1 after t=24 s) | **22**, continuous |
| denial rate, first 55 s | 88.5% | **0.0%** |

For the first 55 seconds the system did exactly what it is supposed to do: 553
routes, zero denials, 516 successes against 18 timeouts, honest nodes serving
and attackers being caught. Then it degraded to a 46.9% denial rate, and the
cause was neither of the things runs 1–3 had trained us to look for.

## Defect 7 — `register_dispatch` leaked the inflight counter

`TrustState` maintains two structures that must agree:

```
sum(_inflight.values()) == len(_dispatches)
```

Each count is *owned* by exactly one dict entry. Every decrement in the class
is paired with a `_dispatches.pop()` — `complete_dispatch`, the reaper — or
with a matching increment (`reassign_dispatches`). One path broke it:

```python
self._dispatches[(client_ip, client_port)] = _Dispatch(node_id, time.time())
self._inflight[node_id] = self._inflight.get(node_id, 0) + 1
```

If that key was **already present**, the assignment drops the previous entry on
the floor while its count stays behind. Nothing can ever release it: no dict
entry survives for the reaper to sweep, and no completion report will ever
reference it. It is not merely wrong, it is *unreachable* — a permanent
addition to the node's occupancy.

Re-registration is a normal event. A PacketIn means a new connection, clients
reuse ephemeral ports, and the re-steer path reinstalls flow rules that draw
fresh PacketIns. Run 4 recorded **57 re-registrations of a still-outstanding
key**, including three for the same flow inside one poll cycle:

```
t=38.6s  10.0.0.1:40778  held by srv1 -> re-registered to srv2
t=38.6s  10.0.0.1:40778  held by srv2 -> re-registered to srv1
t=38.6s  10.0.0.1:40778  held by srv1 -> re-registered to srv1
```

### The evidence that isolates it

srv1 is the clean case, because it received **zero probation trials** — so
nothing about the new code can be implicated:

```
srv1:  2 orphaned dispatches
       inflight frozen at exactly 2 from t=52s to t=1028s  (976 s, never once decrementing)
       observed_load pinned at 0.50 against a truthful claimed_cpu of 0.00
       707 CPU-honesty anomalies -> quarantined
```

Frozen, not oscillating: a real workload's inflight moves. And 0.50 against
0.00 is a deviation of exactly 0.50, one decisive tick over the 0.40 honesty
gate, on every poll, forever.

Fleet-wide the CPU-honesty check fired **2,937 times on the 5 honest nodes**
against 626 on the 3 attackers — it had become almost entirely a false-positive
generator, and the leading cause of quarantine in the run.

### Why Little's Law proves it was not real load

`observed_load` is a Little's-Law estimate, `inflight ≈ λ · L`. Using only
measured quantities:

| node | λ (tasks/s) | L (ms) | predicted inflight | actual |
|---|---|---|---|---|
| srv1 | 0.10 | 105.0 | **0.01** | **2** |
| srv2 | 0.20 | 96.3 | 0.02 | 2 |
| srv4 | 0.37 | 96.2 | 0.04 | 2 |

Two orders of magnitude apart. No arrival rate and no latency in this run can
produce an inflight of 2 — the occupancy was fabricated by the leak, not
observed.

The confirming measurement is run 4's own first 30 seconds, before the leak had
accrued:

```
t=24s  srv1  inflight 0  load 0.06  claimed 0.00  dev 0.06
t=24s  srv2  inflight 1  load 0.12  claimed 0.00  dev 0.12
t=24s  srv4  inflight 0  load 0.07  claimed 0.00  dev 0.07
```

0.06–0.12 against a 0.40 gate — comfortable headroom, and within rounding of
the 0.059 that λ·L/concurrency predicts. The check is correctly calibrated. It
was being fed a corrupted input.

**Fix:** `register_dispatch` releases the superseded entry's count before
overwriting the key. Pinned by four tests in `tests/test_trust_state.py` that
assert the invariant directly (`_assert_invariant`) rather than the symptom,
including a replay of the t=38.6 s triple and a check that an orphaned count
survives the reaper.

## A hypothesis that the data killed

Worth recording, because it was wrong in an instructive way. The first reading
of `claimed 0.00 / observed 0.50` was that the two sides measure different
*intervals*: the controller counts a dispatch for the whole end-to-end latency
L (handshake, packet-in, flow install, transit, service, the client's own
report), while the agent's `active/concurrency` counts only in-handler time S.
At `task_work_ms: 15` against ~282 ms mean end-to-end latency that is an 18.8×
ratio, which looked like more than enough to explain a 0.50 deviation, and it
suggested raising `task_work_ms` as the fix.

Little's Law refuted it: an 18.8× ratio on a predicted inflight of 0.01 is still
0.2, nowhere near 2. The discrepancy was ~100×, not 18.8×, so the interval
mismatch could not be the mechanism. Raising `task_work_ms` would have changed
nothing and cost headroom.

The interval mismatch is nonetheless real, and worth knowing as a *latency*
sensitivity rather than a workload one: at λ ≈ 2.4 tasks/s/node it stays under
the gate up to roughly L ≈ 850 ms, and only trips above that. That is a
saturated system, where a node genuinely is backed up — but the delay is being
attributed to the node rather than to the network and control plane in front of
it. If a future run trips the honesty check on healthy nodes at high latency
with the invariant holding, this is the thing to fix, and the fix is to
estimate service time rather than residence time — not to retune the workload.

---

---

# Run 5 — the confirming run: no collapse, no denials, no leak

Run 5 (2026-08-02) is the first run with the Defect 7 fix in, and the first
that ends the way the architecture claims it should. All four NFRs PASS — but
so did they in runs 1–4, so the NFR table is not the evidence. These are:

| | run 3 | run 4 | **run 5** |
|---|---|---|---|
| `route_denied` events | 88.5% of attempts | 46.9% | **0** (18,539 routes, none denied) |
| task successes : timeouts | 356 : 3,427 | — | **18,185 : 19** (+5 failures) |
| CPU-honesty firings, honest nodes | — | 2,937 | **4** |
| CPU-honesty firings, attackers | — | 626 | 4 |
| worst frozen `inflight` | — | 976 s at 2 | **4–16 polls, all values transient** |
| honest nodes serving at end of workload | 0 | degrading | **5 of 5** |
| mean end-to-end task latency | 341 ms | 282 ms | **91.7 ms** |

Service was continuous from t=5.6 s to t=1,717.9 s at a flat ~640 routes/min
with no degradation in any 60 s bin. Nothing in the run resembles the
positive-feedback cascades of runs 1–4.

## Defect 7 is closed, on the measurement that found it

`inflight` now moves. Over 1,309 status polls the five honest nodes changed
value 487–535 times each, ranging 0–8, and the longest run at a constant
non-zero value was 4–16 polls. Compare run 4's srv1: frozen at exactly 2 for
976 s, never once decrementing. The distinction from
`inflight-dispatch-invariant` — *frozen means a leak, oscillating means real
load* — is the test, and run 5 passes it directly rather than by proxy.

The consequence shows up exactly where predicted. The CPU-honesty check fired
**8 times in the whole run** (4 on honest nodes, 4 on srv6), against run 4's
3,563. It has stopped being a false-positive generator, which is what it was
when fed a corrupted occupancy input. Final observed loads are 0.00–0.38
against truthful claims of 0.00, all comfortably under the 0.40 gate.

## What actually caught the attackers

Detection has moved entirely onto the latency tell:

| reason | firings | honest | attackers |
|---|---|---|---|
| latency tell (claims idle, RTT is a multiple of fleet median, sustained) | 2,198 | **0** | 2,198 (srv8 1,128 / srv3 1,070) |
| `/status` unreachable | 25 | 10 | 15 |
| CPU honesty | 8 | 4 | 4 |

The latency tell has **perfect precision in this run**: 2,198 firings, every
one on a sybil, none on an honest node. That is the detector added in
`4f63d40` / `a9bad07` doing the whole job.

Isolation held. srv6 (drop) completed **zero** tasks in 1,720 s; srv3 and srv8
(sybil) completed 43 and 36 against ~3,200–3,800 each for the five honest
nodes — and those are probation trials being consumed, not service.

## Finding 1, confirmed in live telemetry

The two sybils ended the run at **trust 0.742 and 0.693** — higher than srv4,
an honest node, at 0.400. They were isolated solely by the anomaly gate
(anomaly 1.00 on both). This is the deck's Finding 1 measured on the real
OpenFlow path rather than in the simulator: *the published trust formula
cannot isolate a competent liar; the anomaly gate is what does it.* A sybil
that fabricates plausible reports keeps climbing the T rail indefinitely.
Regression test: `test_f04_non_degrading_liar_needs_anomaly_gate`.

## Probation, measured

330 trial routes across 6 nodes, or one per 5.6 s against
`probation_interval_s: 5.0` — the exposure cap holds. The split is the
interesting part: **301 went to srv6**, the drop attacker, which failed every
one and stayed quarantined. srv4 took 23 and recovered with them, having been
quarantined at t=18.4 s on genuine early-startup congestion and released at
t=128.6 s. Probation is doing exactly what the half-open leg of a circuit
breaker should: cheaply re-testing a stale verdict, cheaply re-confirming a
true one.

## Two things that are still not right

Neither affects the result above, and neither is a detector or trust-engine
defect.

### The teardown quarantines all 8 nodes

The final `node_status` shows all 8 nodes quarantined at anomaly 0.98–1.00,
which reads like another collapse and is not one. 16 of the 25 `/status
unreachable` anomalies land at t=1,718 s and t=1,720 s — 8 nodes each, one
sweep apiece — because `run_demo.py` kills the agents while the controller is
still polling every second. Every honest node was serving normally until
t=1,717.9 s. srv2 and srv7 have exactly one quarantine each for the entire
run, both at t=1,719 s.

It is cosmetic, but it poisons the last frame of the dashboard and the final
state anyone would quote from the recording. The fix is ordering: stop the
monitor (or mark teardown in the recording) before stopping agents.

### `pingAll` now costs 82% of the run

`simulation/topology.py` runs `net.pingAll()` at line 280, between agent launch
and the `time.sleep(duration)` at line 294 — so its cost is **additive** to
`duration_s`, not overlapped with it. Run 5 was configured for `duration_s:
300` and took **1,720 s**, of which roughly 1,415 s was the 2,352-ping sweep
running against the live workload.

The workload does not care — service ran flat throughout, and the first route
was at t=5.6 s, so the reachability sweep is not blocking startup. But the run
is 5.7× its configured length for a check that could be satisfied by sampling.
Run 1 measured 163 s for the same sweep on an idle box; the growth is
contention, not topology. Sample it, or skip it in `trust_mode`.

## Verdict

Step 3 is closed. The 8/40/3 topology runs to completion with zero routing
denials, a 99.87% task success rate, all three attackers isolated, all five
honest nodes serving throughout, and every one of the seven defects found in
runs 1–4 confirmed fixed against the specific measurement that exposed it.

---

## Defect 8 — the honesty fix was wired into one of its two consumers

Found on 2026-08-02 by analysing run 5's recording for the *study's* Finding 6,
not by a failure in the run itself. It is the first defect in this document
that never quarantined anything.

`claimed_load()` exists precisely to stop the honesty comparison putting an
instantaneous sample next to a windowed integral. It is wired into the anomaly
gate and nowhere else:

| consumer | claim used | |
|---|---|---|
| anomaly gate, `flow_monitor.py:297` | `claimed_load()` — time-averaged | correct |
| trust H term, `trust_balancer.py:1177` | `get_claimed_cpu()` — **raw instant** | **wrong** |

The raw value flows `TrustUpdate.reported_cpu` → `honesty_delta()`
(`contracts/trust_update.py:20`) → `h_raw = max(0, 1 - delta/0.5)`
(`trust_engine/trust_calculator.py:107`) → the `γ·H̄` term of
`T = 0.35R̄ + 0.25B̄ + 0.25H̄ − 0.15Ā`.

### Why run 5 hid it and also proves it

The agent samples `active/concurrency` the instant its `/status` handler runs.
At `task_work_ms: 15` it is genuinely idle at that instant almost every time,
so it truthfully claims 0.00 — in **98.49% of the 6,545 honest samples**. When
the claim is zero the deviation *is* the occupancy:

| occupancy | n | mean claimed | mean \|dev\| | dev/occ |
|---|---|---|---|---|
| 0.00–0.05 | 1,794 | 0.0067 | 0.0343 | 1.226 |
| 0.05–0.10 | 3,578 | 0.0034 | 0.0752 | 1.019 |
| 0.10–0.15 | 1,004 | 0.0050 | 0.1166 | 1.005 |
| 0.15–0.20 | 62 | 0.0121 | 0.1635 | 0.982 |
| 0.25–0.30 | 48 | 0.0000 | 0.2665 | 1.000 |
| 0.30–0.40 | 45 | 0.0000 | 0.3202 | 1.000 |

`dev/occ = 1.000` at every load. So `h_raw = 1 − 2·occupancy`: H is 0.74 at 13%
occupancy and 0.50 at 25%. That is the study's §7 "honesty tax" — *a busy
honest node loses trust for being busy* — running at full strength, and it is
the run-B mechanism that `claimed_load()` was written to remove.

It never trips the 0.40 gate here (0.367% of samples) only because the retuned
workload keeps occupancy under ~0.15. **The finding was masked by the workload,
not fixed by the code.** Any return to run 1's intensity brings it back.

**A correction to the record:** `plan.md` and the project memory both asserted
this mismatch was closed by `claimed_load()`. Half of it was. Both have been
corrected.

**Fix:** `trust_balancer.py` passes `claimed_load()` into `TrustUpdate`,
matching the gate. Pinned by
`test_trust_path_uses_the_windowed_claim_not_the_raw_one`, which drives the
real `handle_client_report` and fails with `0.5 < 0.1` against the old line.
326 tests green.

**Not yet confirmed live** — needs a run 6. The expected signature: trust on
busy honest nodes stops drifting down with occupancy, and mean ΔT per poll
stops going negative in the modal 0.05–0.10 occupancy bin (run 5: −0.00323).

---

## Defect 8, second layer — the two sides were never the same quantity

Run 6 (2026-08-02) confirmed the one-line fix worked *and* that it was not
enough. Measured on the `report` events, which carry the value that actually
reaches `honesty_delta`:

| | run 5 (before) | run 6 (after one-line fix) |
|---|---|---|
| claimed non-zero reaching H | 0.47% | **4.16%** |
| mean \|deviation\| | 0.0804 | **0.0701** |
| mean `h_raw` | 0.8392 | **0.8598** |
| mean ΔT, modal 0.05–0.10 bin | −0.00323 | **−0.00201** |
| **`dev/occ`** | ~1.000 | **~1.000 — unchanged** |

Time-averaging did exactly what it was built to do (8.8× more non-zero claim
reaching the formula, 13% off the tax) and `dev/occ` did not move, because
**time-averaging a series that is genuinely ~0 still gives ~0.**

The residual was never a wiring bug. The node can only measure *service* time S
— seconds inside its `/task` handler. `observed_load()` measures *residence*
time L — dispatch to report, including flow install, transit and the client's
own reporting. Run 6 put S/L at roughly 1:6. No smoothing closes a gap between
two different quantities.

### The fix: both sides become duty cycles

The agent now reports **`busy_seconds`**, a cumulative monotonic counter of
in-handler time. Differencing two polls gives a duty cycle over exactly the
controller's window:

```
claimed_duty  = (B(t1) - B(t0)) / ((t1 - t0) * concurrency)
expected_duty = completions_per_s * fleet_median_service_time / concurrency
```

Both are "fraction of available worker-time spent working". The controller owns
the completion count, so the honesty check no longer needs to trust anything
the node said about its load — and a node that under-reports busy time while
completing tasks normally shows an implausibly small implied service time
(`busy_seconds / completions`) against the fleet median. That is a *stronger*
sybil tell than the one it replaces, and it uses the median for the same reason
the latency tell does: it survives the 3-of-8 threat model.

Three design points worth not simplifying away:

- **The sybil fabricates `busy_seconds` consistently** with its `cpu_load` lie
  (`node_agent.py`). A liar that reported truthful busy time next to a false
  load would be caught by a trivial internal contradiction, making it a weaker
  attacker than the one runs 1–6 were measured against.
- **The estimator abstains** (returns `None`) when the span is under
  `DEFAULT_MIN_BUSY_SPAN_S` or fewer than `DEFAULT_MIN_FLEET_SERVICE_SAMPLES`
  nodes have usable evidence — poll jitter otherwise lands straight on the
  quotient.
- **Abstention falls back, it does not skip the check.** The first cut abstained
  outright and deleted sybil detection for any agent that simply declines to
  report `busy_seconds` — a hole the attacker controls. Caught by
  `test_sybil_liar_deviation_triggers_anomaly_and_quarantine`. The fallback is
  the old residence-time comparison: imperfect, but never absent.

Pinned by five tests in `tests/test_trust_state.py`, notably
`test_honest_busy_node_is_not_taxed_for_being_busy` and
`test_sybil_under_reporting_busy_time_is_caught_by_implied_service_time`.

**Prediction for run 7:** mean |deviation| falls from 0.0701 to near zero,
`h_raw` rises from 0.86 toward 1.0, and `dev/occ` finally stops tracking
occupancy. The `report` events now carry `expected_duty` and
`honesty_reference` so this is checkable directly from the recording.

## Two harness items, fixed in the same batch

- **Teardown no longer quarantines the fleet.** `topology.py` POSTs
  `/monitor/pause` before killing agents, so the last sweeps do not score eight
  just-killed nodes as unreachable. This does **not** weaken "seen-then-dark is
  anomalous" — polling stops entirely rather than any verdict being softened.
  Best-effort: an already-dead controller just restores the old artefact.
- **`pingAll` is sampled.** `_sampled_reachability_check` probes O(hosts)
  pairs — every client against a server, every server against a client — rather
  than all 2,352. `simulation.full_pingall: true` restores the exhaustive
  sweep. Run 7 should take roughly 5–6 minutes instead of 29.
