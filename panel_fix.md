# Panel Review — Findings, Fixes and Evidence

*Compiled 2026-08-07. Covers the work driven by `plan_adv.md` Phases 2–6:
attack classification, the scalability sweep, the service-availability metric,
the dashboard time-series, and live runs 7 and 8.*

This is the defect and finding register. `plan_adv.md` holds the phase plan and
status; this document holds **what was actually wrong, how we knew, and what
the evidence says now**. Numbers quoted as results come from live run 8 unless
stated otherwise.

---

## 1. Headline results (live run 8, 311.7 s, 8 servers / 40 devices / 6 attacks)

| Metric | Value |
|---|---|
| Honest-node availability | **98.90%** |
| Route denial | **0.0%** (0 of 5,692 routes) |
| Total outage (0 nodes serving) | **none** |
| Time at/above 50% serving quorum | **100%** of the run |
| Mean nodes serving | 5.30 / 8 (worst case 4 / 8) |
| Attack classification accuracy | **95.8%** (46 / 48 subjects) |
| Attacks classified correctly | 7 / 8 |
| Attacks detected at all | 7 / 8 measured; 8 / 8 with §3.14 (see §5.11) |
| Honest subjects wrongly labelled | **1 / 40** |
| Mean detection latency | 11.1 s (upper bound — see §5.6) |
| Attacker containment | srv8 +8.1 s, srv6 +9.7 s, srv1 +12.9 s, srv3 +14.6 s |
| Quarantine recoverability | 37 recoveries / 41 quarantines |

**Six attacks are implemented and scored**: sybil, blackhole, grayhole, on-off
(intermittent trust manipulation), DDoS/flooding, and identity spoofing — plus
bad-credentials devices as a seventh ground-truth class.

### Run 7 → run 8, after the fixes in §3.10 and §3.11

| Metric | Run 7 | Run 8 |
|---|---|---|
| Route denial | 28.3% | **0.0%** |
| Honest availability | 48.05% | **98.90%** |
| Total outage | 71.3 s (22.5%) | **none** |
| Mean nodes serving | 2.74 / 8 | **5.30 / 8** |
| Time above quorum | 26.4% | **100%** |
| Classification accuracy | 83.3% | **93.8%** |
| Honest nodes mislabelled | 5 / 40 | **1 / 40** |
| Anomaly events | 589 | 315 |
| CPU-honesty false firings | 175 | **0** |

### Run 8's telemetry, re-scored after the classifier fixes in §3.12–§3.14

The classifier is a pure function over recorded evidence, so re-running it over
run 8's own events is a real measurement, not a projection — with the one
exception noted in §5.11.

| Metric | as run | re-scored | source |
|---|---|---|---|
| Classification accuracy | 93.8% (45/48) | **95.8% (46/48)** | measured |
| Attacks classified correctly | 6 / 8 | **7 / 8** | measured |
| `sybil` precision | 0.000 | **1.000** | measured |
| `onoff` precision | 0.500 | **1.000** | measured |
| Attacks detected at all | 7 / 8 | **8 / 8** | replay estimate (§5.11) |
| Attacks in the right family | 7 / 8 | **8 / 8** | replay estimate (§5.11) |
| Honest nodes mislabelled | 1 / 40 | 1 / 40 | unchanged — see §5.12 |
| Mean detection latency | 11.1 s | 11.1 s | unchanged |

Remaining misses: **srv6** `blackhole` → `grayhole` (right family, magnitude
unresolvable — §4.7) and **srv4** honest → `grayhole` (a re-dispatch attribution
transient, not a classifier fault — §5.12).

### Live run 9 (2026-08-08, 325 s, same config) — validation

Run 9 exists to confirm §3.14 in real telemetry. **It did** — and it found two
things the re-score could not.

| Metric | Run 8 | Run 9 |
|---|---|---|
| Honest-node availability | 98.90% | **100.00%** |
| Honest nodes never quarantined | 3 / 4 | **4 / 4** |
| Honest subjects wrongly labelled | 1 / 40 | **0 / 40** |
| Time at/above quorum | 100% | 100% |
| Total outage | none | none |
| Attackers contained | 4 / 4 | 4 / 4 |
| All four NFRs | PASS | PASS |
| Classification accuracy | 95.8% | 93.8% |
| Attacks classified correctly | 7 / 8 | 5 / 8 |
| Attacks in the right family | 8 / 8 (est.) | **6 / 8 (measured)** |

**The defence got better; the classification numbers got worse, and the two are
unrelated.** Both regressions are on the IoT side and neither is a Phase 7
fault:

- **srv6 `blackhole → grayhole  FAMILY` — §3.14 confirmed.** The replay
  estimate held exactly (§5.11).
- **srv8 `onoff → grayhole` — a real regression from §3.13**, caught and fixed:
  the weighing threshold was too high (§5.14). Re-scored, srv8 is `onoff` again
  and run 8 is unchanged.
- **iot38 `spoof → none` — the spoof SUCCEEDED (§5.13).** Not a classification
  failure: there was nothing to classify, because the attack was never refused.
- **iot40 `bad_credentials → none` — §5.5**, the transport-layer refusal,
  recurring (it also hit in run 7 and was absent in run 8).

Test suite: **599 passing** (561 before this work).

### After run 9: the spoofing race closed (§3.16)

Run 9's two IoT misses were never classification failures — one attack was
never refused (§5.13) and one denial never reached the bus (§5.5). Both are now
fixed at the source, and the fix is verified end-to-end against the real
`/auth/verify` endpoint over a real socket, replaying run 9's exact scenario:

| | run 9 | after §3.16 |
|---|---|---|
| Spoof of an identity nobody claimed | **succeeded**, 130 tasks | **HTTP 403** |
| Legitimate owner admitted | — | HTTP 200 |
| Denial reaches the bus | no event at all | `auth_denied`, `kind=ip_pin` → `spoof` |
| Controller accept backlog | 5 (stdlib default) | 128 |
| A reset during the handshake | permanent self-eviction | retried, 5 attempts |
| An identity nobody claimed | silent | `identity_unclaimed` event |

**Live run 10 confirms this in situ.** Until then the honest claim is "refused
in an end-to-end test of the real endpoint", not "refused in a live run".

---

## 2. How to reproduce

```bash
# Live run (needs root; WSL2 needs OVS + qdisc modules once per session)
sudo service openvswitch-switch start
sudo modprobe -a sch_htb sch_netem sch_tbf sch_prio ifb
sudo mn -c
sudo python3 run_demo.py --mode mininet --config config/params_trust_full.yaml

# Analysis of the resulting data/events.jsonl
python3 -m evaluation.nfr_report          data/events.jsonl   # NFR pass/fail
python3 -m evaluation.interval_report     data/events.jsonl   # metrics vs time
python3 -m evaluation.attack_report       data/events.jsonl   # confusion matrix
python3 -m evaluation.availability_report data/events.jsonl   # availability

# No root required
python3 -m evaluation.scalability_sweep --ns 4,8,16,32,64 --load-factors 0.1,0.6
python3 -m pytest -q
```

---

## 3. Defects found and fixed

### 3.1 Auth denials were never published to the event bus
**Symptom:** identity spoofing was structurally invisible to any recording.
**Cause:** `/auth/verify` returned 403 and told nobody — the controller did the
right thing and then forgot it.
**Fix:** `AuthError` gained a structured `kind`
(`ip_pin` / `bad_response` / `no_challenge` / `nonce_expired`) and
`northbound_api.py` publishes an `auth_denied` event.
**Why the tag matters:** it is the *only* thing separating an insider spoofing
with the fleet key (`ip_pin`) from a device that never held the key
(`bad_response`) — two different attacks in the adversary model.

### 3.2 Ground truth covered only edge nodes
**Symptom:** two of the six attacks (flooding, spoofing) had no confusion-matrix
row and would have vanished rather than being scored.
**Fix:** the `topology` event now carries `attack` and `attack_start_s` for IoT
devices as well as servers, with the same spoof-beats-flood precedence
`topology.py` itself uses.

### 3.3 Detector output was free-text prose only
**Symptom:** classification would have depended on regexing sentences written
for a human to read on a dashboard.
**Fix:** `anomaly` events carry a parallel machine-readable `signals` dict.
`reasons` is unchanged and still drives the UI.

### 3.4 A healthy node published a spurious empty verdict
**Symptom:** every healthy node emitted one meaningless `classification` event
on its first poll.
**Cause:** "no previous label" and "label is None" were distinguishable when
they should not have been.
**Found by:** a test asserting a clean node publishes nothing.

### 3.5 Analysis tools read the wrong field names
**Symptom:** `attack_report.py` and `availability_report.py` would have found
**nothing at all** in a real recording.
**Cause:** the event bus records `type`/`ts`; both modules read `event`/`t`.
**Why it survived:** every hand-built test fixture agreed with the mistake, so
the suite passed while the tools were broken — the worst kind of green.
**Fix + guard:** corrected, and pinned by tests that read a file the **real**
`EventBus` produced, which is the only check that cannot make the same mistake
alongside the code.

### 3.6 Demo recording: serving rule advertised at the drop priority
**Symptom:** dashboard throughput was a flat zero.
**Cause:** `generate_demo_recording.py` emitted the **serving** VIP rule at
`priority: 400` — which is `PRIO_QUARANTINE_DROP`. Every consumer that separates
serving from dropped traffic by priority read it backwards: the bps was
discarded and the serving rule's packets were tallied as quarantine drops.
Real serving rules use `PRIO_CONNECTION = 300`.
**Scope:** this also meant **`evaluation/interval_report.py` had been silently
reporting zero throughput** for this recording. The charts did not introduce the
fault; they made an existing one visible.

### 3.7 Demo recording: drop rules marked `is_vip: False`
**Symptom:** the OpenFlow-drop series was flat zero even with a node quarantined.
**Cause:** every consumer filters on `is_vip` first. In a real run those rules
carry the node's own `0x5A` cookie and `flow_stats._is_vip_cookie()` marks them
VIP.

### 3.8 Demo recording: split cookie bases
**Cause:** serving and drop rules used different bases (`0x51` / `0x5A`). No real
run produces that — `_cookie_for(node_id)` gives **one** cookie per node covering
both, which is precisely how quarantine deletes all of a node's rules with a
single cookie-matched `OFPFC_DELETE`.

> **Guard for 3.6–3.8:** four tests now pin the generator against the real
> constants. The strongest asserts the hand-set `is_vip` equals what the real
> `FlowStatsPoller._is_vip_cookie()` derives from the rule's own cookie.
> **Rule worth reusing: when a fixture hand-writes data that production normally
> derives, pin the fixture against the deriving function, not a copied literal.**

### 3.9 Demo recording carried no attack onset
**Symptom:** detection latency was permanently unknown in the demo.
**Fix:** the generator publishes `attack_start_s`. Detection latency now reads
+3.0 s there — which is exactly the latency tell's 3-strike floor at a 1 Hz poll,
not noise.

### 3.10 The honesty-check fallback caused every false quarantine *(live run 7)*
**Symptom:** 28% route denial, 48% honest availability, 22.5% total outage.

**Cause.** The H-term fix (comparing *service*-time duty cycle rather than
*residence* time) **works** — `expected_duty_cycle()` was available in 70% of
reports and is excellent where it engages: deviation **0.0006** against a 0.40
gate, while `observed_load` reads **~17× higher** on the same samples. But
`flow_monitor` fell back to `observed_load` whenever the estimate was
unavailable, and **175 of 175 CPU-honesty firings came from that fallback** —
every false quarantine, none from the fixed path.

It was self-reinforcing: quarantine → fewer completions → no fleet median →
biased fallback → quarantine.

**Fix.** The fallback conflated two different causes of "no estimate":

| Cause | Correct response |
|---|---|
| The **node** withholds `busy_seconds` | Keep the degraded comparison — going quiet would let a liar disable the check by omission |
| The **controller** lacks completions | **Abstain** — our missing evidence is not the node's misbehaviour |

`TrustState.reports_busy_seconds()` picks the branch and is **recency-based**, so
reporting once and then stopping cannot buy permanent abstention. The degraded
basis is named in the reason text, so a reader is never shown a residence-time
number labelled as a duty cycle.

**Result (run 8):** CPU-honesty fired **zero** times, and no attacker escaped —
srv3/srv8 are carried by the latency tell, srv1 by the drop tell, srv6 by the
trust rail.

### 3.11 Spoofing was blamed on the victim *(live run 7)*
**Symptom:** iot38 impersonated iot1; the source-IP pin correctly refused it —
and the `spoof` label landed on **iot1, the victim**, while iot38 scored clean.
**Cause:** auth denials were keyed on the *claimed* `device_id`. A spoofer's
whole method is to present someone else's identity, so keying on the claim files
the attempt under the impersonated party.
**Fix:** keyed on **source IP** — the host that actually acted — with the
impersonated `device_id` retained in the payload as evidence and folded back to a
device name via `subject_aliases`.
**Impact:** accuracy 79.2% → 83.3% on run 7's own data.
**Framing:** a classifier that blames the impersonated party is worse than no
classifier — it manufactures a false accusation out of a *successful defence*.

### 3.12 On-off was named on incidental quiet, not sustained intermittency
*(found and fixed 2026-08-08, on run 8's telemetry)*

`classify_node` promoted a subject to `onoff` on `off_phases >= 1` — a single
clean run of `DEFAULT_MIN_CLEAN_RUN` cycles. srv3, a **steady sybil** flagged on
198 of 250 cycles, had almost all its clean runs at a single poll of jitter, but
two of them happened to land exactly on the floor. That was enough: it was
reported `onoff` for 165 of its 220 classified cycles.

Counting off phases harder does not separate the cases — srv3 had exactly two,
so a "two gaps make a rhythm" rule fires on it as well. What separates them is
how much of the active span is actually **quiet**, and the margin is not close:

| subject | truth | qualifying quiet | active span | quiet fraction |
|---|---|---|---|---|
| srv3 | sybil | 6 cycles | 250 | **2.4%** |
| srv8 | onoff | ~145 cycles | 227 | **64%** |

**Fix:** on-off additionally requires `quiet_fraction >= 0.20`, derived rather
than fitted — an attacker with duty cycle `d` is quiet for `(1 - d)` of its
period less the detector's own reaction lag, which at topology.py's defaults
(d = 0.5, period 20 s, 1 Hz) is 0.30. The bar accepts attackers up to d ≈ 0.6
while sitting an order of magnitude above the incidental-gap case. Gaps shorter
than `min_clean_run` count toward neither the tally nor the quiet time, so a
subject with a hundred single-poll gaps cannot accumulate its way over the bar.
**Impact:** srv3 → `sybil` on all 220 classified cycles; sybil and on-off
precision both 0.500 → **1.000**; accuracy 93.8% → **95.8%**, attacks correct
6/8 → **7/8**. No change to srv8, and **every one of the 71 pre-existing
classifier tests passed unchanged** — the rule tightens without re-fitting any
invariant they encoded.

### 3.13 The "lying beats dropping" precedence, replaced with a weighing rule
*(fixed 2026-08-08)*

§5.1's disproven premise, now closed. Any lying signal used to promote a subject
out of the drop family outright. The asymmetry behind it is real — a CPU-burning
liar genuinely times tasks out too, so it raises both families — but treating it
as absolute meant one spurious cycle overruled dozens of true ones.

A real liar lies on essentially **every** cycle it is flagged on (run 8: srv3
188/198 = 95%, srv8 55/57 = 96%); a dropper with contaminated telemetry lies on
a minority. The lying signal must now carry at least half the family-bearing
cycles, which sits ≈0.45 clear of both measured populations. Cycles that carry
neither family's evidence (an `unreachable`-only cycle) are excluded from the
denominator so they cannot dilute either side.

**Impact on run 8: none — this is a latent robustness fix.** Run 8 had no
contaminated dropper, because §3.10 had already removed the source of the
spurious signals. It is pinned by a test built from run 7's actual failure shape
so the premise cannot quietly return.

### 3.14 A trust-rail isolation left no evidence to classify
*(fixed 2026-08-08 — closes §5.3)*

srv6 was a blackhole quarantined at t=39.7 s, 9.7 s after onset, on the **trust
rail**, with anomaly exactly **0.0** and **not one flagged cycle in 250**. Only
3 timeouts were ever reported against it — below the drop tell's
`_MIN_TIMEOUT_SAMPLES = 4` — so the anomaly rail never fired, and the classifier,
which read only anomaly signals, correctly abstained on a perfectly contained
attack.

**Fix:** `TrustState.isolation_evidence()` hands the classifier the evidence the
trust rail acted on, as a new `trust_collapse` signal. Two properties are
load-bearing:

- **It adds no isolation power.** Nothing about it reaches `anomaly_raw`, the
  gate, or a flow rule. It is only ever consulted about a node the trust rail
  has *already* condemned, so the worst a wrong answer costs is a wrong label in
  a report — never an outage. Pinned by
  `test_trust_rail_evidence_adds_no_isolation_power`.
- **Outcomes are counted from the collapse, not from the last 10.**
  `_recent_statuses` is era-blind, and at the moment srv6's trust collapsed it
  held nine pre-onset successes and one timeout — a 0.10 failure rate for a node
  that was by then dropping everything. The question being asked is not "how has
  this node behaved" but "what has it done since we decided it was bad".

**Impact (replay estimate):** srv6 `none` → `grayhole`. **Attacks detected at
all 7/8 → 8/8**, right family 7/8 → 8/8; exact label stays 7/8. See §4.7 for why
the magnitude does not follow, and §5.11 for the validation status.

### 3.16 The spoofing race, closed *(2026-08-08 — closes §5.13, §5.5)*

Three defects in one chain, fixed at each link. The chain matters more than any
single link: **each part was individually minor and the composition was not.**

**(a) A five-deep accept queue evicted a legitimate device.**
`NorthboundAPI` inherited the stdlib `request_queue_size = 5`.
`ThreadingHTTPServer` spawns a thread per connection, so the *serving* side
scales — but threads are only spawned after `accept()`, and all 48 hosts open
their first connection within milliseconds of `net.start()`. Past 5 pending
accepts the kernel resets, which is the `Connection reset by peer` of §5.5.
Run 9 reset iot1 and iot40 inside the same 20 ms window. Now **128**, which is
a queue bound rather than a preallocation and costs nothing. Pinned by a test
asserting the backlog exceeds the configured host count.

**(b) The client treated a reset as a denial.** One transport failure and iot1
logged "AUTH DENIED, sending no traffic" and sat out the entire run. A reset
means *the question never got asked*; a 403 means *the answer was no*. The
client now retries transport failures (5 attempts, exponential backoff) and
never retries a 403 — retrying a real denial would turn a bad-credentials
device into an auth flood. Pinned in both directions.

**(c) The pin was trust-on-first-use.** The actual security fix.
`security.IdentityBinding` takes a **provisioned** `device_id -> source IP`
roster; where an entry exists it is authoritative whether or not that device
has ever authenticated, so an unclaimed identity is no longer up for grabs.
Where no entry exists, TOFU is unchanged — right for an unknown population,
wrong for a known one, and keeping both means this needs no deployment to
enumerate its devices. The roster is **derived** from
`simulation/addressing.py`, already the shared source of truth for addressing,
rather than maintained separately in YAML where it could drift.

The denial kind stays `ip_pin`, so a roster catch is reported exactly like a
TOFU catch and the classifier maps it to `spoof` with no downstream change.
The three duplicated copies of the pin check are now one.

**Verified end-to-end over a real socket** (source IP from the kernel, not a
test argument), replaying run 9 exactly — an identity nobody has claimed:

```
spoof of an identity NOBODY claimed -> HTTP 403      (run 9: succeeded)
legitimate owner of iot1            -> HTTP 200
auth_denied on bus: [('iot38', 'ip_pin', ...)]       -> classified `spoof`
still unclaimed: ['iot38']
```

**(d) An unclaimed identity is now reported.** `FlowMonitor` audits the roster
once, 45 s in, and publishes `identity_unclaimed` for provisioned devices that
never authenticated. This gates nothing — the race is closed in (c); this
exists so that an eviction leaves a trace instead of looking like a device that
simply never started. A refused spoof deliberately does **not** mark the victim
claimed, or the attack would mask the eviction it exploited.

**A near-miss worth recording:** the first version of `_device_roster` read
`cfg['topology']`, but the block is `simulation:`. It returned `{}` — every
identity silently back on TOFU, a no-op fix shipped into a live run and
indistinguishable from success. The preflight test that asserts the roster is
*populated* for the real config caught it. **A fix with a silent fallback needs
a test that the fix is actually in effect, not just that it does no harm.**

### 3.15 Two documentation defects
- `config/params_attacks_demo.yaml` claimed `start_s` was "advisory only". It has
  been honoured since Phase 0.
- `num_malicious` is **vestigial**: `topology.py` uses it only to build a
  `malicious_ids` list nothing reads, plus a log line; `run_demo.py` assigns it to
  an unused local. It counts **IoT devices**, not edge servers, despite sitting
  with the edge settings. Documented in the config rather than removed, since both
  entry points still read the key.

---

## 4. Findings that are not defects

These are measurements and limits worth stating rather than things to fix.

### 4.1 p2c scales linearly; argmax saturates
Offered load rises with N, so a system that keeps up shows **linear throughput
and flat delay/PDR**. At 60% load:

| N | 4 | 8 | 16 | 32 | 64 |
|---|---|---|---|---|---|
| p2c throughput (tasks/s) | 48 | 95 | 192 | 382 | **762** |
| argmax throughput (tasks/s) | 48 | 89 | 87 | 82 | **80** |
| p2c PDR | 99.7% | 99.8% | 99.7% | 99.8% | **99.8%** |
| argmax PDR | 99.2% | 91.7% | 45.8% | 21.3% | **10.5%** |

p2c holds ~266 ms mean delay at every size; argmax pins at the ~2 s timeout
ceiling (a ceiling, not a measurement of service).

### 4.2 argmax fails two *different* ways at the two ends of offered load
- **Low load (10%):** classic starvation — 13 of 16 nodes idle, Jain 0.176.
- **High load (60%):** almost nothing starved (Jain 0.75–0.85) because queues
  finally push the CPU term off the favoured nodes — the fleet ends up balanced
  *and* broken.

Reporting either end alone makes argmax look merely unfair, or merely slow,
instead of both. The crossover is visible in one row: argmax at 10% load and
N=64 offers 128 tasks/s against ~40 tasks/s of favoured-node capacity, so it
tips out of starvation (0/64) into loss (PDR 73.5%).

### 4.3 p2c is **not** a per-decision CPU win
Both strategies cost the same and both grow ~linearly with N: 3/5/9/16/30 µs at
N=4/8/16/32/64. `select_edge_node` scores and sorts **every** eligible node
regardless of strategy, because that ranking is returned as the *explanation* of
the decision (published as `ranked`). p2c's O(d) sampling rides on an O(N log N)
base rather than replacing it. A deliberate trade — explicability for CPU that is
nowhere near a bottleneck — and **the p2c win should be claimed in fairness,
throughput and delay, never in CPU.**

### 4.4 Two on-off resolution limits
Naming an on-off attacker *as* on-off requires observing a quiet stretch:
1. the good phase must outlast the detector's reaction time (~4 s: the latency
   tell's bucket keeps flagging ~1 poll after the switch, then needs 3 clean
   polls);
2. the evidence window must span a whole on-off *period*, or it mostly holds one
   phase and reports sybil — measured, not assumed: a 10-cycle window over a
   12-cycle period yields sybil for most of a run.

**In both cases the attacker is still caught and quarantined; only the label
degrades.** `topology.py`'s on-off default was raised 8 s → 20 s to clear limit
(1) with margin.

### 4.5 A model simplification stops being one when it feeds a gate
`starvation_sweep.py` can treat trust *as* the reliability EMA because trust only
rises there and only ordering matters. In a model with timeouts, trust decides
**eligibility** — so `T = R` put an honest-but-overloaded node at 0.075 after a
single timeout and quarantined the whole fleet. Modelling `T = αR + β + γ` floors
honest trust at 0.50 and puts saturation where it belongs: in latency and PDR.

### 4.6 Replaying a recording measures only first-order effects
Asked to predict the impact of the §3.10 fix, a static replay of run 7 showed
honest anomaly cycles dropping only 212 → 174, which was read as "the
`packet_drop` false positives are an independent congestion problem; do not
expect availability to recover."

**That prediction was wrong.** Run 8 restored availability from 48% to 98.9%.
The `packet_drop` false positives were not independent — they were **downstream**:
false CPU-honesty → quarantine → re-dispatch onto fewer nodes → real timeouts →
drop tell → more quarantine. Cutting the first link collapsed the cascade.

**The counterfactual run has different traffic, so a feedback loop is invisible
to replay by construction.** When the suspected defect sits inside a loop, a
replay estimate is a *lower bound* and only a re-run settles it.

**The converse is also worth stating, because §3.14 relies on it.** A replay is
sound exactly when the change cannot alter the traffic. The trust-collapse
signal never reaches `anomaly_raw`, the gate, or a flow rule, so there is no
loop for a replay to miss and the estimate is not merely a lower bound. The test
is not "is this a replay?" but "can this change feed back into what gets
measured?"

### 4.7 Containment quality and magnitude evidence are in direct tension
The obvious way to finish §3.14 is to let the trust rail's own post-collapse
failure rate decide blackhole-vs-grayhole. Measured on run 8, it does name srv6
correctly — **and it renames srv1, a true grayhole, a blackhole**, because
srv1's first two post-collapse outcomes were both timeouts and 2/2 = 1.00, a
reading identical to srv6's. Every sample bar that keeps srv1 right excludes
srv6 entirely:

| min samples | srv6 (blackhole) | srv1 (grayhole) |
|---|---|---|
| 2 | blackhole ✓ | blackhole ✗ |
| 4 | no evidence, abstains ✗ | grayhole ✓ |

This is not a threshold to be tuned. It is the shape of the evidence:

> A blackhole fails **everything**, so it is isolated fastest, so it yields the
> fewest outcomes with which to characterise it. srv6 produced 3 task outcomes
> in a 312 s run; srv1, which kept partially working and so stayed in
> circulation, produced 24 after its collapse alone.

**The better the containment, the weaker the forensics.** So the trust rail
establishes the *family* and is never consulted on the magnitude, and with no
measured rate available the call degrades to `grayhole` — the weaker of the two
claims. Understating the attack is the same safe direction as reporting
detection latency as an upper bound: it never flatters the system.

---

## 5. Known limitations (open and honest)

### 5.1 The classifier's signal precedence is disproven — **CLOSED by §3.13**
It promoted any node raising a "lying" signal into the sybil family, on the
premise that *a pure dropper never raises a lying signal*. Live run 7 disproved
that premise. §3.10 removed the trigger; §3.13 has now replaced the rule itself
with a weighing rule, so the disproven premise is no longer load-bearing.

### 5.2 `onoff` was an absorbing label — **CLOSED by §3.12**
Any subject whose signals came and went looked intermittent; precision was 0.167
in run 7 and 0.500 in run 8. Now 1.000, via the sustained-intermittency rule.

**This entry previously misattributed run 8's misses**, and the correction is
worth recording. It claimed on-off eagerness caused "2 of run 8's 3 misses
(srv3 sybil→onoff, srv4 honest→grayhole)". Only srv3 was on-off eagerness.
srv4→grayhole is a `packet_drop` false positive with nothing to do with
intermittency — see §5.12. The entry was written from the *shape* of the two
misses rather than from their evidence, and re-deriving each from the recording
before fixing anything is what caught it. **Reading a defect register is not a
substitute for re-reading the data it was written from.**

### 5.3 Trust-rail isolation can outrun the classifier — **CLOSED by §3.14**
srv6 (blackhole) was quarantined at t=39.7 s with **trust 0.2085 and anomaly
0.0**: only 3 timeouts had been reported, below `_MIN_TIMEOUT_SAMPLES = 4`, so
the drop tell never fired. The classifier reads only anomaly signals, had no
evidence, and correctly abstained.

**An attacker isolated on the trust rail faster than the anomaly rail reaches its
minimum sample count is never labelled**, and quarantine then starves any later
evidence — the absorbing-state shape applied to *labels* rather than trust.
This is a **reporting** gap, not a security one: the defence contained srv6 in
9.7 s and never released it.

### 5.4 DDoS response is detection-only
Flooding is detected and classified, but not throttled. Auto-dropping a flooding
client needs a per-client-IP OpenFlow rule path; today's rate-limit and
quarantine machinery is all per-edge-node.

### 5.13 **SECURITY: identity spoofing succeeds against an identity never claimed**
*(found by live run 9, 2026-08-08 — the most important thing that run produced)*

In run 9 **iot38's spoof succeeded outright.** It authenticated as iot1, was
issued a session, and ran 130 tasks as iot1 for the rest of the run. No
`auth_denied`, no anomaly, no classification — it scored `none` and so did its
victim.

The chain, from the logs:

```
08:04:23,779  iot1  starts, begins handshake
08:04:24,194  iot1  Auth handshake failed (network): [Errno 104] Connection reset by peer
08:04:24,194  iot1  AUTH DENIED -- refused admission, sending no traffic     <- victim is out
08:04:40,578  iot38 attempting to authenticate AS iot1 from this host
08:04:40,681  iot38 SPOOFING SUCCEEDED -- now sending traffic as iot1
```

**Root cause: the source-IP pin is trust-on-first-use.**
`security/authenticator.py` pins "the *first* source IP to successfully
authenticate as a device_id", and the check is skipped entirely when
`self._session_ip.get(device_id)` is None. An identity that has never been
claimed is free for the taking. Normally the legitimate device wins the race —
it starts at t=0 while the spoofer waits until t+15 s — so this never showed.
In run 9 the real iot1 was knocked out at t+0.4 s by §5.5's
`Connection reset by peer`, leaving "iot1" unclaimed, and the spoofer's
t+15 s attempt became the first success.

**This reclassifies §5.5.** It was recorded as a *reporting* gap — "a device
refused below the HTTP layer leaves no trace". It is also a **security** gap:
the same transport-layer failure that hides a denial can evict a legitimate
device, and eviction is what makes the spoof land. Two known-minor issues
compose into a real one.

**Neither defence was wrong on its own terms** — the same discipline as run 3's
"the detectors were right". PRESENT-80 verified a correct response; the pin had
no prior binding to compare against. What is missing is that **identity
ownership is established by a race**, and nothing notices when the wrong party
wins it.

**FIXED 2026-08-08 — see §3.16.**

### 5.5 A transport-layer refusal leaves no trace — **CLOSED by §3.16**
In run 7, iot40's handshake died with `Connection reset by peer` rather than a
403, so no `auth_denied` was published and the device scored as undetected. It
succeeded in run 8, so the behaviour is load-dependent and not yet understood.

### 5.6 Detection latency is an upper bound
`start_s` is measured from agent launch, but the recording's t0 is controller
start, which necessarily precedes it by the Mininet build. The reported figure
includes that gap and **overstates** the detector. Overstating is the safe
direction; quietly subtracting an estimate would not be.

### 5.7 Scalability beyond 8 nodes is simulation, not live
The box is 4 cores. N=64 live would measure the laptop, not the architecture.
The sweep drives the **real** `select_edge_node` through a discrete-event
harness with real per-node queueing and timeouts, but it is not a live run and
should not be presented as one.

### 5.8 One false-positive flood tell
Honest iot29 tripped the flood detector once in run 7, plausibly retry pressure
under 28% route denial. Run 8 (0% denial) produced no such false positive,
which supports that reading but does not prove it.

### 5.9 Single run per configuration
Every live figure here comes from one run at one seed. No confidence intervals.

### 5.10 The study document is stale
`docs/study/trust-routing-study.html` still describes code that no longer ships
(pre-p2c routing), and its PDF was printed from an even older version.

### 5.14 The weighing rule was set too high, and live run 9 caught it
`DEFAULT_MIN_LYING_SHARE` shipped at 0.50 — "the lying signal must dominate".
Run 8 was indifferent to the value, so nothing objected. Run 9 was not: srv8, a
true on-off attacker, raised the drop tell on 30 cycles that run (its CPU burn
genuinely does time tasks out), the rolling window sat in the drop family for
the first 150 s, and the run verdict came out **`grayhole`** — 121 grayhole
cycles against 100 on-off. §3.13 had broken the very case the precedence it
replaced existed to protect.

**The error was treating two asymmetric claims as one.** "A pure dropper never
raises a lying signal" is false (run 7). "A liar that burns CPU also raises the
drop tell" is *true*, and srv8 is exactly it. A bar high enough to punish the
first also demotes the second while it is still accumulating evidence.

Swept against both runs, the safe band is **0.15–0.40**; 0.25 is now the
default, ~0.15 clear on each side. Pinned by
`test_a_liar_that_also_drops_is_not_demoted_to_a_dropper`. Fixed 2026-08-08.

**A latent fix that changed nothing on the run it was written against was
tuned on no evidence at all** — "no effect on run 8" was read as "safe", when
it only meant "untested". §3.13's own write-up called it latent and that should
have been the signal to withhold a threshold, not to pick a round one.

### 5.11 The trust-rail fix is a replay estimate, not live telemetry
§3.12 and §3.13 are measured on run 8's **own recording** and need no caveat —
the classifier is a pure function over recorded evidence, so re-running it over
the same events is the real result. §3.14 is different: run 8 predates the
`trust_collapse` signal, so its effect is measured by synthesising the signal
from the recorded trust series and task outcomes, replaying the exact rule
`isolation_evidence()` implements. That estimate is sound rather than merely a
lower bound (§4.6), but live run 9 is what confirms it.

**CONFIRMED by live run 9 (2026-08-08).** srv6 came out
`blackhole → grayhole  FAMILY`, exactly as the replay predicted — the drop
family established from trust-rail evidence, the magnitude correctly not
claimed. The §4.6 reasoning held: an estimate for a change that cannot feed
back into the traffic is not merely a lower bound.

### 5.12 One honest node is still mislabelled, and it is a re-dispatch transient
srv4 (honest) → `grayhole`, the last honest-subject miss. Its root cause is not
the classifier and not intermittency:

- srv4's **only** clustered timeouts are 5 in a 0.9 s burst at t = 40.1–41.0 s.
  Its other 4 all run are isolated singletons.
- That burst lands immediately after srv6 was quarantined (39.7 s) and srv3 was
  flapping — i.e. exactly when their in-flight work was re-steered onto the
  survivors.
- `reassign_dispatches` correctly carries the **original** `dispatched_at`
  across, because re-steering does not restart the client's abandonment timer.
  So a re-steered task can arrive at srv4 with most of its 4 s budget already
  spent on another node, time out at the ceiling, and be **charged to srv4**.
- 5 such timeouts in a 10-deep window clear the drop tell, and srv4 was
  quarantined for 13.6 s before recovering.

So the drop tell fired on true evidence, and the classifier faithfully reported
it — the run-3 framing again. The defect is one of **attribution**: srv4 is
blamed for a timeout it never had the budget to satisfy.

**This is the last surviving trace of the run-7 cascade**, and in run 8 it is
self-limiting: one honest node, 13.6 s, recovered, with no onward effect. The
fix belongs in outcome attribution, not in the classifier — see §6.9. It is
*not* bundled with §3.12–3.14 deliberately: it would change quarantine
behaviour, and mixing an unvalidated behaviour change into run 9 would muddy
what that run measures.

**Run 9 did not reproduce it**: 0/40 honest subjects mislabelled, 4/4 honest
nodes never quarantined, 100.00% honest availability. That is *not* evidence
the defect is gone — nothing was changed — only that the re-dispatch burst that
triggers it did not line up this time. It is timing-dependent by nature, which
is an argument for fixing it rather than for waiting to see it again.

---

## 6. Future scope

Ordered by value per unit of effort.

### 6.1 Close the remaining 3 classification misses — **DONE 2026-08-08** (§3.12–§3.13)
Both changes landed. The predictions here were half right, and the half that was
wrong is on the record:

- **The weighing rule** (§3.13) went in as described — and changed nothing on
  run 8, because §3.10 had already removed the spurious signals that made the
  precedence bite. It is a latent robustness fix, not a scoring one.
- **The on-off rule** (§3.12) was *not* fixed by the periodicity check proposed
  here. srv3's two incidental gaps were the same length, so they are perfectly
  "regular" and a periodicity test passes them. What separates a sybil from an
  on-off is the **share of the active span spent quiet** — 2.4% vs 64% — not the
  regularity of the gaps.
- **"6/8 to 8/8" was optimistic.** The result is 7/8, because one of the three
  misses (srv4) was misattributed to on-off eagerness in the first place (§5.2)
  and the other (srv6) runs into §4.7.

### 6.2 Feed trust-rail quarantines into classification — **DONE 2026-08-08** (§3.14)
Landed, and it closes §5.3's blind spot: srv6 goes from unlabelled to the right
family, taking attacks-detected to 8/8.

**The prediction that it "would have labelled srv6 `blackhole`" was wrong**, and
§4.7 is why: the trust rail's own post-collapse rate does name srv6 correctly
but simultaneously renames the true grayhole srv1 a blackhole, and no sample bar
separates them. Naming the family is what this can honestly deliver.

### 6.3 Rewrite the study document from live run 8
`docs/study/trust-routing-study.html` (§5.10) should be rebuilt on run 8's
telemetry. Both of its open questions now have answers: starvation is closed by
p2c + ε-exploration, and the H-term mismatch is closed by the duty-cycle
comparison plus §3.10's abstention rule.

### 6.4 Statistical rigour for the panel
Multiple seeds per configuration with confidence intervals (§5.9).
`evaluation/stats.py` already implements the paired comparison machinery; it
simply has not been pointed at the live runs.

### 6.5 DDoS enforcement
Add the per-client-IP OpenFlow path (§5.4) so a detected flood can be throttled
rather than only logged. Deliberately deferred as real additional scope, not
half-built under time pressure.

### 6.6 Reconcile the two detection rails' timing — **partly answered by §4.7**
§5.3 exposed that the trust rail can act before the anomaly rail has its
minimum samples, and asked whether the drop tell should act on fewer samples
when they are unanimous. §4.7 answers the *classification* half: no —
srv1's first two post-collapse outcomes were unanimously timeouts and it is a
grayhole, so unanimity on a small sample is not evidence of magnitude. Whether
`_MIN_TIMEOUT_SAMPLES = 4` is right for **isolation** is still open, and is now
a much lower-stakes question since §3.14 removed the reporting blind spot that
motivated it.

### 6.7 Make transport-layer auth refusals observable
Understand and instrument the `Connection reset by peer` path (§5.5) so a device
refused below the HTTP layer still leaves a trace.

### 6.8 Longer runs and larger topologies
300 s at 8/40 leaves the on-off attacker only ~12 periods and the classifier a
thin evidence base. A longer run would firm up the on-off numbers; a larger live
topology needs hardware this project does not have (§5.7).

### 6.10 Close the spoofing race — **DONE 2026-08-08** (§3.16)
All three parts landed: the accept-queue root cause, the client's
reset-is-not-a-denial distinction, and provisioned roster pinning. Verified
end-to-end over a real socket; **live run 10 is what confirms it in situ**, and
until then the honest statement is "refused in an end-to-end test of the real
endpoint", not "refused in a live run".

The original plan text is kept below because part 3 was written as an
alternative to part 2 ("if (2) is judged too rigid") and both were built —
part 2 closes the race, part 3 makes the eviction that enabled it visible.
They turned out to be complements, not alternatives.

<details><summary>original plan text</summary>

An identity that has never been claimed is free for the taking, and a
transport-layer failure can vacate one. Three parts, in order:

1. **Make transport-layer refusals impossible to confuse with absence.** This is
   §6.7, promoted from a reporting nicety to a prerequisite: the controller
   cannot tell "iot1 has not started yet" from "iot1 was knocked off the socket"
   because both look like silence. Instrument the `Connection reset by peer`
   path first — everything else depends on knowing which case you are in.
2. **Pin identities from configuration, not from first contact.** The fleet
   roster is known ahead of time (`topology.py` assigns `iot<N>` → `10.0.0.<N>`),
   so device→IP can be a *provisioned* binding rather than trust-on-first-use.
   That removes the race entirely rather than narrowing it. TOFU is the right
   default when the population is unknown; here it is not unknown.
3. **Alarm on a late first claim.** If (2) is judged too rigid, then at minimum
   a device_id claimed for the first time well after fleet start is a suspicious
   event and should reach the bus as one, rather than being indistinguishable
   from an ordinary registration.

</details>

Worth stating plainly for the panel: run 9 is the run where **an attack
succeeded**. Every previous run's misses were labelling failures on attacks
that were contained. This one got in — and it is now closed.

### 6.9 Do not charge a node for a re-steered task's spent budget
Closes §5.12, the last honest-node mislabel. When `reassign_dispatches` moves an
in-flight dispatch to a survivor, the receiving node inherits a task whose
client-side deadline is already partly spent — and is then charged with the
timeout. srv4 took 5 such tasks in a 0.9 s burst and was quarantined for 13.6 s
for it.

The attribution and the reaper horizon must be separated. Carrying the original
`dispatched_at` is **correct** for the reaper and for `observed_load` (run 2's
defect 3: re-steering does not restart the client's abandonment timer) and must
not be undone. What should change is *blame*: an outcome for a re-steered
dispatch that arrived with less than the node's typical service time remaining
says nothing about the receiving node, and should not reach `record_task_outcome`
as a timeout against it.

**Deliberately not bundled with §3.12–3.14.** Unlike those, this one changes
quarantine behaviour, so it needs its own live run to validate, and folding it
into run 9 would make run 9 unable to tell which change produced which effect.

---

## 7. Discipline notes carried through this work

Recurring rules that shaped the fixes above, kept because each was learned from a
real defect:

- **Separate "correctly isolated attacker" from "wrongly quarantined honest
  node" in every metric that touches quarantine.** Availability is reported
  split by ground truth for exactly this reason: attacker downtime is the system
  working, honest downtime is its cost, and averaging them hides whichever one
  matters.
- **A detector with no recent evidence abstains; it does not re-assert a stale
  verdict.** Applied to the timeout tell, to the classifier, and now to the
  honesty check (§3.10).
- **Task-level loss and OpenFlow drop-rule hits are different things** and never
  share a series.
- **When a comparison keeps producing false signal, check both sides are the
  same physical quantity before smoothing either one** — service time vs
  residence time was a ~17× bias hiding behind a plausible-looking number.
- **Pin fixtures against the deriving function, not a copied literal** (§3.6–3.8).
- **A flat line in a chart is a hypothesis about the data before it is one about
  the chart.**
- **Re-derive a finding from the recording before acting on it.** §5.2 had
  confidently attributed srv4's miss to on-off eagerness; the evidence says it is
  a `packet_drop` transient with no connection to intermittency. A defect
  register is a summary, and summaries drift from the data they came from.
- **When two fixes both work but only one is needed, ship the derived one.** A
  minimum off-phase *count* and a minimum quiet *fraction* each sounded right;
  only the fraction follows from what on-off means, and the count would have
  cost a 50% wider evidence window for nothing.
- **Ask whether a change can feed back into what you are measuring.** That, not
  "is it a replay?", is what decides whether an offline estimate is trustworthy
  (§4.6) — and it is why §3.14's estimate stands where §3.10's did not.
- **A reporting improvement must not become a new way to quarantine.** §3.14
  touches nothing that gates, and has a test whose only job is to keep it that
  way. Every cascade in this project's live-run history began with something
  that could isolate a node acting on evidence it should not have.
