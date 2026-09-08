# `base_model/` — the control arm

A second, complete Mininet SDN that runs **the same network, the same workload
and the same attackers** as this project's zero-trust controller, with none of
its defences. It exists so the project's results can be stated as a difference
against something rather than asserted on their own.

Same 1 core switch, 8 edge switches, 8 edge servers, 40 IoT devices. Same four
server-side attacks on the same schedule, the same flooding device, the same
identity spoofer, the same two wrong-key devices. Same task rate, same work per
task, same timeouts.

**What differs is exactly two things:**

| | treatment (`controller/trust_balancer.py`) | control (`base_model/`) |
|---|---|---|
| **who decides where a connection goes** | `EdgeScore = w₁T + w₂(1−cpu) + w₃(1−lat)`, p2c over non-quarantined nodes | a fixed map from the client's address |
| **what happens when a node misbehaves** | quarantine, rate-limit, re-steer, refuse admission | nothing |

Trust is still **computed** here — by the same code, from the same evidence,
with the same weights — and never acted on. That is what puts both arms' trust
curves on one axis.

---

## 1. Running it

Both arms need root (Mininet) and, on WSL2, the usual once-per-session setup:

```bash
sudo service openvswitch-switch start
sudo modprobe -a sch_htb sch_netem sch_tbf sch_prio ifb
sudo mn -c
```

Then, from the repo root:

```bash
# 1. the control arm  -> data/base_events.jsonl
sudo -E python3 -m base_model.run_base --duration 300

# 2. the treatment arm -> data/events.jsonl   (unchanged, existing command)
sudo python3 run_demo.py --mode mininet --config config/params_trust_full.yaml

# 3. score them against each other
python3 -m base_model.compare \
    --baseline  data/base_events.jsonl \
    --treatment data/events.jsonl \
    --out-dir   data/comparison

# 4. per-server trust-vs-time figures -> base_model/trust/
python3 -m base_model.plot_trust --treatment data/events.jsonl

# 5. per-server load + fairness figures -> base_model/load/
python3 -m base_model.plot_load  --treatment data/events.jsonl
```

(Both plotters take `--treatment` to overlay the arms, or run baseline-alone
without it.)

`-E` on the first command matters: it preserves the environment `sudo` would
otherwise strip. **Run one arm at a time** — both bind OpenFlow 6653 and the
northbound API 8081, and both need the same Mininet namespaces.

Run them back to back on the same idle machine. This box is 4 cores and every
collapse in this project's history traces to offered load, not to architecture
(`docs/LIVE_RUN_8_40_3.md`); an arm that ran while a browser was compiling
something is not comparable to one that did not.

### Other strategies

```bash
sudo -E python3 -m base_model.run_base --strategy round_robin
```

Writes the effective config to `logs/params_base_effective.yaml`, so the
recording can always be traced to the config that produced it.

### Live view

There is no dashboard here — that is a treatment feature. `GET /api/status`,
`GET /api/bindings` and the `GET /api/events` SSE stream are the whole surface.
For panels, replay the recording afterwards through `dashboard/replay.py`,
which reads the JSONL both arms write.

---

## 2. What the outputs are

`base_model/compare.py` writes four files into `--out-dir`:

| file | what it is for |
|---|---|
| `comparison.txt` | the table to read and quote |
| `comparison.json` | the same numbers, machine-readable |
| `trust_series.csv` | **the trust-curve figure's data.** Long format: `arm,node,role,attack_start_s,t_s,trust,anomaly,samples` |
| `per_node.csv` | per-arm, per-server end-of-run summary |

`trust_series.csv` is long format, not wide, because the two arms will not have
identical bucket counts — a run interrupted a few seconds early would silently
misalign a wide table, and the misalignment would be invisible in the plot.

Every existing analysis tool also reads a baseline recording unchanged, because
the event schema is the same one:

```bash
python3 -m evaluation.interval_report     data/base_events.jsonl
python3 -m evaluation.availability_report data/base_events.jsonl
python3 -m evaluation.attack_report       data/base_events.jsonl
python3 -m evaluation.topology_metrics    data/base_events.jsonl
python3 -m evaluation.nfr_report          data/base_events.jsonl
```

(The recording path is positional for all of these — no `--events` flag.)

`nfr_report.py` reports the routing-decision NFR and prints **`[NO DATA]`** for
isolation and blockchain overhead. That is correct and must be quoted that way:
the baseline has no isolation path and no ledger, so those are absent
mechanisms, not mechanisms that scored zero.

---

## 3. What is in here

| file | what it does |
|---|---|
| `config/params_base_full.yaml` | the run. Everything above its `baseline:` block is copied verbatim from `config/params_trust_full.yaml` |
| `static_router.py` | the routing policy. Pure, ~60 lines of logic, cannot see node state |
| `trust_observer.py` | trust as a measurement. Wraps `TrustState`; exposes no enforcement |
| `baseline_controller.py` | the os-ken app: OpenFlow 1.3, VIP, proxy-ARP, per-connection rewrite, L2 learning, a passive monitor loop |
| `baseline_api.py` | northbound HTTP. Same wire contract, no admission control |
| `run_base.py` | the runner. Reuses `simulation/topology.py`'s launcher |
| `compare.py` | the scorer |
| `figure_style.py` | the one visual system both figure families use |
| `plot_trust.py` | per-server trust-vs-time figures -> `trust/` |
| `plot_load.py` | per-server load + fairness figures -> `load/` |
| `tests/` | 160 tests, all of which run without root, Mininet or a network |

### The trust figures

`plot_trust.py` writes into `base_model/trust/`:

| file | what it is |
|---|---|
| `srvN_trust.png` / `.svg` | one figure per server — seconds since start (x) against trust score (y). SVG is the one to put in the paper |
| `all_servers_trust.png` / `.svg` | the same eight as one 2×4 grid |
| `trust_data.csv` | exactly the points plotted, so the figures have a table view and a reader can check them against numbers |

Four choices in there are not cosmetic:

- **The y-axis is fixed to [0, 1] on every figure.** Auto-scaling per server
  would give an honest node that sat between 0.79 and 0.81 a chart that looks
  like a rollercoaster, and put it beside a blackhole's collapse at apparently
  the same amplitude.
- **x is seconds since the run's `topology` event**, the same instant
  `attack_start_s` is relative to, so the shaded onset band and the curve share
  one clock. (This is the anchoring bug the live dashboard had — §3.7a.)
- **Points are raw, not smoothed.** Trust is already an EMA over
  `lambda_decay`; smoothing it again would flatten the transitions the figure
  exists to show.
- **The shaded band is labelled as the *configured arming time*, never as a
  detection.** It is ground truth from the recording. Labelling it otherwise
  would let the figure imply the controller knew something at that instant —
  which is the claim the detection-latency numbers exist to establish
  separately.

Colours are two slots from the project's validated palette (blue `#2a78d6`
baseline, orange `#eb6834` zero-trust), checked with the dataviz validator
against the `#fcfcfb` surface under `--pairs all`: lightness band, chroma
floor, CVD separation (worst ΔE 24.7 protan), normal-vision separation (ΔE
33.6) and 3:1 contrast all PASS. The isolation threshold is drawn in muted ink
because it is a constant, not data. Don't substitute hues without re-running
the validator.

### The load figures

`plot_load.py` writes into `base_model/load/`:

| file | what it is |
|---|---|
| `srvN_load.png` / `.svg` | requests routed to that server per second, over time, per arm |
| `all_servers_load.png` / `.svg` | the same eight as one 2×4 grid |
| `load_share.png` / `.svg` | total requests per server — the headline figure |
| `fairness_over_time.png` / `.svg` | Jain over the full roster **and** over honest servers only |
| `load_data.csv` | the points plotted |

**"Load" here means requests routed, not occupancy.** Requests routed is the
quantity the router *controls*, counted straight off the `route` events, so it
is the honest subject of a load-balancing comparison. Occupancy
(`observed_load`) is a consequence, measured over `load_window_s`, and it is
deliberately not plotted — see the caveat in §5 below.

**The trap this tool exists to avoid.** Jain over the full roster is nearly
identical in the two arms — measured **0.622 baseline vs 0.627 zero-trust**.
Reported alone that reads as *"the load balancer made no difference"*, and it is
wrong. The two numbers are low for opposite reasons:

- the **baseline** is uneven because a flooding device is statically pinned to
  one server (srv5 took 2,545 of 6,773 requests) and nothing can move it;
- the **zero-trust arm** is uneven because it *deliberately withheld* traffic
  from four attackers (srv3 took 44).

One is a failure to spread load. The other is the enforcement working. A single
whole-roster index cannot tell them apart, so this tool always reports two
populations side by side plus the share of traffic that reached an attacker:

| | Jain (all 8) | Jain (honest 4) | share to attackers |
|---|---|---|---|
| baseline | 0.622 | **0.689** | **30.5%** |
| zero-trust | 0.627 | **0.992** | **12.5%** |

`test_plot_load.py::test_whole_roster_jain_hides_the_difference` pins this: any
change that makes the tool report a single whole-roster index fails.

---

## 4. The four design decisions, and why each is defensible

These are the questions a reviewer will ask. Each has an answer in code and a
test that keeps it true.

### 4.1 The control is still an SDN

It keeps OpenFlow 1.3, OVS, the two-table pipeline, the VIP, proxy-ARP, the
per-connection rewrite, and the same flow/port stats polling.

If the control were a non-SDN network, every measured difference would confound
*SDN vs. not* with *zero trust vs. not* — and the claim is about the second.
The fabric is held constant so exactly one variable moves.

### 4.2 The binding is uniform by construction, and still loses

`static_nearest` serves `iotJ` from `srv[((J−1) mod 8) + 1]` — the server on the
client's own edge switch. It is the conventional non-adaptive edge assignment:
no measurement, no controller state, no feedback.

40 devices over 8 servers is **exactly 5 each, for the whole run**. That is
deliberate. An unfair static map would let a reader attribute the treatment
arm's advantage to fairness alone. This control is *a priori perfectly
balanced* — Jain 1.000 on request count — and it still loses, for the one
reason that matters: five devices are bound to a blackhole and stay bound to it.

`test_static_router.py::test_static_map_is_exactly_uniform` fails if that stops
being true, so the sentence above cannot quietly become false.

If a reviewer objects that this conflates *no load balancing* with *no
failover*, run `--strategy round_robin`: naive balancing, still no failover, and
a blackhole receives precisely its 1/n share of every client's traffic forever.

### 4.3 Trust is computed but not enforced — and the anomaly rail is a choice

The baseline needs a trust value per node per instant or there is nothing to
plot. `trust_observer.py` produces one by **wrapping `controller/trust_state.py`**
and calling only its observation surface. It does not reimplement the trust
formula, the occupancy estimator, the busy-time duty cycle, or the tells.

That is the strongest available guarantee that both curves measure the same
thing. A reimplementation would drift, and "were the two trust curves produced
by the same estimator?" is the first question anyone will ask about the figure.

`BaselineTrustObserver.check_no_enforcement()` runs at controller start-up and
in the test suite, and asserts the wrapper exposes none of
`choose_edge_node`, `poll_quarantine_transitions`, `quarantined`,
`probation_due`, `trust_band`.

**The anomaly rail is on by default** (`baseline.observe_anomaly: true`). The
baseline runs the same two evidence-only tells and feeds `A` into `T`, and acts
on none of it. This is the sharper control: it separates *detection* from
*response*, so the treatment arm's advantage cannot be dismissed as "it simply
had a detector". The count of gate crossings that produced no response is
reported as **detections with NO response**.

Setting it `false` pins `A` at 0 and makes this a blind legacy controller — a
legitimate third arm, but then `T = αR + βB + γH` in one arm and
`T = αR + βB + γH − δA` in the other, and a paper reporting it **must say so**.
Every `node_status` row carries `anomaly_observed` so a recording can never be
misread as the other configuration.

### 4.4 Admission is recorded, not checked

`/auth/verify` always returns 200. Nothing is compared and nothing is refused.

The findings are still measurable, because they are derived from *recorded
facts* rather than from a verification step:

- **iot38's spoof succeeds.** It authenticates as `iot1` from `10.0.0.38`. The
  controller admits it and writes down both values. `compare.py` reads the
  mismatch against the ground truth already in the `topology` event and reports
  `identity spoof outcome: SUCCEEDED`. In the treatment arm the same instant
  produces `auth_denied kind=ip_pin`, and it reports `REFUSED`. From t=15 s the
  baseline recording contains two devices reporting as iot1.
- **iot39/iot40 hold the wrong key and are admitted anyway**, and generate real
  traffic all run.

The nonce issued is real and freshly random, so the client's PRESENT-80 path
runs identically in both arms — the device spends the same CPU and the
handshake costs the same two round trips. Only the verdict is absent. The
baseline is not faster here because it skipped work the client still did.

---

## 5. How drift between the arms is prevented

A controlled comparison is only controlled while the controlled variables are
actually held. Four mechanisms, all of them tests:

1. **`tests/test_base_config_parity.py`** diffs 35 shared config keys — the
   trust weights, the topology, the whole attack schedule, the credentials, the
   workload intensity, the detector knobs — against
   `config/params_trust_full.yaml` and fails on any difference. It also asserts
   the two arms record to *different* files, so running one cannot destroy the
   other's recording.

2. **Both arms are launched by the same function.** `run_base.py` imports
   `simulation.topology._launch_trust_agents` rather than copying it. That
   function builds every agent and client command line; two copies would be two
   workloads. `tests/test_launcher_parity.py` drives the real launcher with the
   real baseline config against a fake Mininet and asserts the exact attacker
   argv — sybil at t=20, blackhole at t=30, grayhole at t=40 at rate 0.5, on-off
   at t=50, flood at concurrency 3, spoof targeting iot1, and the byte-flipped
   key going to exactly iot39 and iot40.

3. **`tests/test_observer_parity.py`** pins the shared constants across the two
   arms (`_MIN_TIMEOUT_SAMPLES`, `_STATUS_TIMEOUT_S`, the VIP cookie base), that
   the latency tell is the treatment arm's own imported function rather than a
   copy, and that the honesty reference is computed by the same call chain in
   the same order.

4. **`tests/test_baseline_controller.py`** asserts the enforcement priorities
   and methods are absent, and pins the complete set of event types this arm can
   publish. Adding one has to be a deliberate act.

---

## 6. Things this arm must not be "fixed" into

Each of these looks like a bug and is a measurement.

- **Five clients keep hammering a blackhole for the rest of the run.** No
  failover exists. This is the availability finding.
- **`route_denied` is never emitted.** There is no eligibility check, so a
  request is always routed somewhere — including to a node that has been
  dropping every task for four minutes. `interval_report.py` reads
  `route_denied` as offered-but-unserved load, a concept this arm does not have.
- **The ledger row is `--`, not 0.** `NoLedgerBackend.commit_count` stays 0 all
  run, which is what makes the blockchain-overhead NFR report *no data* rather
  than 0.0 % overhead. A reader skimming would score 0 % as *better*.
- **A failed `/status` poll raises no anomaly.** The treatment arm scores
  seen-then-dark as anomalous because it is about to act on it. A control arm
  that never acts has no reason to turn silence into an accusation, and doing so
  would inflate this arm's own false-positive count against nodes that are
  merely unreachable.

## 7. Three honest limitations to state in the paper

- **The first baseline recording (2026-09-05) ran a 5 s occupancy window**
  against the treatment arm's 3 s. `load_window_s` has no counterpart in the
  treatment *config* — that arm never overrides `TrustState`'s default — so it
  sat outside `test_base_config_parity.py`'s reach. Now fixed to 3.0 and pinned
  by `test_observer_parity.py::test_load_window_matches_the_treatment_arm`.
  It feeds four estimators (`observed_load`'s integral, `claimed_load`'s
  time-average, the completion rate behind `expected_duty_cycle`, and the
  packet-drop tell's staleness horizon), so **occupancy from that first
  recording is not comparable across arms** and `plot_load.py` does not plot
  it. The trust curves are affected only second-order — H is one of four terms
  and both sides of its comparison were integrated over the same window within
  each arm — but re-run the baseline before quoting occupancy or claiming
  window parity.

- **`observed_load` here is the controller's own dispatch accounting**, exactly
  as in the treatment arm — the baseline knows which server each connection went
  to because it installed the rewrite rule. That is bookkeeping, not a defence,
  but it does mean the control arm is instrumented in a way a truly legacy
  controller would not be. It has to be, or there would be no H term to compare.
- **The `/status` poll loop here is serial**, not the treatment arm's thread
  pool. At 8 nodes and a 0.5 s timeout the worst case is 4 s against a 1 s
  interval, so a fleet that goes fully dark would skew this arm's poll cadence.
  It has not been observed at this scale; parallelise it before running the
  baseline at a larger N.
