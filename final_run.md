# Final Run — Full Live Demo, End to End

A single, ordered walkthrough that brings up **everything built so far** at once
and drives it live: the trust-aware SDN controller, the Mininet network with real
IoT traffic, Wireshark on both the OpenFlow control channel and the data plane,
and the **live** browser dashboard (not the pre-recorded replay) showing routing,
trust, packet drops, and the AI weight optimizer learning in real time. Routing
now spreads load across **all** healthy servers via power-of-two-choices, not just
the top two — the starvation fix (§5b).

> This is the demo-day runbook. For the consolidated state of the project — what
> was built, what the live runs measured, and what is still open — see
> **`SOURCE_OF_TRUTH.md`**. For install/environment details and per-feature deep
> dives see **`SETUP.md`**; for the optimizer design see **`docs/AI_OPTIMIZER.md`**;
> for the flow-rule scheme see **`docs/FLOW_RULES.md`**; for the load-balancing
> starvation fix see **`docs/LOAD_BALANCING_STARVATION.md`**.
>
> **Platform note:** this box ships only Python 3.14, so the controller uses
> **os-ken** (a maintained Ryu fork), and `sudo` needs an interactive password —
> every **(sudo)** step must be run by you, in your own terminal. No venv/pip.

**Two runs, two purposes — pick one before you start:**

| | **Narrated demo** (§1–§8) | **Full-scale panel run** (§10) |
|---|---|---|
| Config | `params_trust_demo.yaml` | `params_trust_full.yaml` |
| Scale | 4 servers / 12 devices / 1 attack | **8 servers / 40 devices / 6 attacks** |
| Terminals | 4 + browser, driven by hand | **1 command**, unattended |
| For | showing the mechanism live, on screen | producing the numbers you quote |

Do the narrated demo when someone is watching, and the full-scale run when you
need measurements. §9 is the no-Mininet fallback if the network misbehaves in
front of an examiner. **Everything, in one place: §12.**

The narrated demo uses **four terminals** plus a browser. Keep them in this layout:

| Terminal | Role | sudo? |
|----------|------|-------|
| **A** | Trust-aware controller (also serves REST + dashboard on `:8081`) | no |
| **C** | Wireshark on the OpenFlow control channel (`lo:6653`) | yes |
| **B** | Mininet topology + the `mininet>` CLI | yes |
| Browser | Live dashboard at `http://localhost:8081/` | — |

The order matters: **A → C → B**. The controller must be listening before the
switches connect, and Wireshark should be capturing before the switches connect
so you catch the OpenFlow handshake and the first flow installs.

---

## 0. Pre-flight (once)

From the repo root `Zero-Trust-Enabled-SDN-Architecture/`:

```bash
# Dependencies installed and services up? (see SETUP.md §1 if not)
mn --version                                            # 2.3.0
python3 -c "import os_ken; print(os_ken.__version__)"   # 4.1.1

# Everything green before you demo anything live:
python3 -m pytest tests/ -q     # expect: 624 pass, 8 fail in test_stats.py
#   Those 8 are a known scipy-version mismatch (needs >=1.9, box has 1.8.0)
#   in evaluation/stats.py. Nothing in the live path imports it. Any OTHER
#   failure means stop and fix before spending a sudo run.

# Confirm the demo config has the features on (they are, by default):
grep -E "enabled|auth_scheme|rate_limit|selection|epsilon" config/params_trust_demo.yaml
```

**Once per WSL2 session** (the kernel modules and OVS daemon do not survive a
reboot, and Mininet's `tc` shaping fails without them):

```bash
sudo service openvswitch-switch start
sudo modprobe -a sch_htb sch_netem sch_tbf sch_prio ifb
```

**Archive the previous recording before you run anything.** `data/` is
gitignored and `run_demo.py --mode mininet` **unlinks `data/events.jsonl` at
startup** — once it is gone, the run's numbers cannot be re-derived:

```bash
cp data/events.jsonl data/events_runN.jsonl     # do this FIRST, every time
```

`config/params_trust_demo.yaml` is the demo scenario: **4 edge servers, 12 IoT
devices, 1 malicious edge server (`srv3`, Sybil/CPU-lie), 1 malicious IoT
(`iot12`, wrong key), 120 s**. It has the dashboard, PRESENT-80 auth, meters, and
the AI optimizer all enabled, and routes with **`selection: p2c`** (+ `epsilon:
0.05`) so healthy load is shared across all four servers instead of starving two
(§5b, `docs/LOAD_BALANCING_STARVATION.md`).

**One-time display permission for Wireshark** (Mininet runs as root, so GUI apps
launched from inside it draw as root and need this — run as your **normal** user):

```bash
xhost +si:localuser:root
```

---

## 1. Terminal A — start the controller

No sudo. This one process is the SDN controller **and** the northbound REST API
**and** the dashboard web server (all on `:8081`).

```bash
python3 -m controller.osken_manager controller.trust_balancer
```

Wait for:
```
TrustBalancerApp started: vip=10.0.99.1:9000 ...
NorthboundAPI listening on 0.0.0.0:8081
```

You will immediately see `QUARANTINE: srvN ... /status poll failed` for every
node — **this is expected**: no edge agents exist yet, and an unreachable node is
treated as suspicious, not merely idle. It clears the moment Terminal B brings the
agents up. Leave this terminal visible; it's where routing/quarantine/optimizer
decisions are logged.

---

## 2. Terminal C — capture the OpenFlow control channel (Wireshark)

The controller↔switch channel is plain TCP on loopback port **6653**. Start this
**before** Mininet so you catch the `OFPT_HELLO` handshake and the first
`OFPT_FLOW_MOD` rule installs:

```bash
sudo wireshark -i lo -k -f "tcp port 6653" &
```

In Wireshark's display-filter bar, type **`openflow_v4`** and press Enter. This
isolates and decodes the OpenFlow 1.3 messages. What to point out to your advisor:
- `OFPT_HELLO` / `OFPT_FEATURES_REQUEST/REPLY` — the switch connecting.
- `OFPT_FLOW_MOD` — **the "rules" being installed**, live and decoded on the wire.
  When `srv3` is quarantined you'll see a burst of these (VIP-rule deletes + the
  priority-400 drop-rule adds).
- `OFPT_MULTIPART_REQUEST/REPLY` (Flow/Port Stats) — the 1 Hz stats polls that
  feed the dashboard's counters.

---

## 3. Terminal B — start the Mininet network (sudo)

Always clean up leftover state first — a stale OVS bridge still pointed at
`127.0.0.1:6653` will reconnect to Terminal A and confuse what you see:

```bash
sudo mn -c
sudo python3 -m simulation.topology --config config/params_trust_demo.yaml --interactive
```

This builds the topology, launches a real `node_agent.py` per edge server and a
real `iot_client.py` per IoT device (continuous traffic through the VIP), runs the
initial connectivity/traffic pass, then drops you at the `mininet>` prompt.

Back in **Terminal A** you'll now see the story begin:
```
Routed 10.0.0.4:41xxx -> srv2   (EdgeScore ...)
...
OPTIMIZER: window closed reward=0.83 (37 outcomes) weights [0.5,0.3,0.2] -> [0.7,0.2,0.1]
...
QUARANTINE: srv3 ... deleting VIP rules, installing drop rules
Re-dispatched N client(s) from quarantined srv3 to srvM (X.XXms after collapse; NFR isolation < 3000ms)
```

---

## 4. Browser — open the LIVE dashboard

```
http://localhost:8081/
```

Same port as the controller — it **is** the controller, serving the live event
stream over SSE. The header pill should read **live** (green dot), not replay.
(If it says replay, you accidentally opened `:8082` — that's the recording.)

Keep this on screen next to Wireshark. It is the plain-English view of exactly the
same events Wireshark shows at the protocol level.

**The "Trust ledger" panel sits directly under the topology.** Every trust
update is batched (10 per block) into a hash-linked block; the ribbon shows the
last 10. Two things to point at:

- **The hash chips line up.** Each block's `prev` chip carries the same eight
  characters as the previous block's `hash` chip. Read it left to right — that
  is the chain, on screen, not asserted in a slide.
- **Two verdicts, not one.** `✓ controller: chain valid` is the controller
  auditing its own ledger. `✓ browser: N recomputed` is **this page** having
  recomputed every SHA-256 itself from the block header, anchored on a genesis
  block it built locally. They are independent, which is the whole point.

**The demo move:** click **tamper with a block**. It flips one hex digit of a
block's `merkle_root` *in the browser's copy only* — the controller's ledger is
untouched and nothing is sent anywhere. That block immediately reads `hash
mismatch` and the next one reads `broken link`, with a red arrow at the seam.
Say this precisely: **the break localises to where the edit happened** — blocks
further right still chain correctly to their own untouched predecessors. That is
better than "everything goes red": the chain tells you *where* it was altered.
Click **restore** to put it back.

The footer carries the live blockchain-overhead NFR (commit cost amortised over
the batch, against task latency, target <15%) and a pending gauge showing the
batch filling toward 10.

**Three chart panels sit below that.** The first two are live time-series on
10 s buckets; the third is not live and is labelled so on the panel:

- **Metrics over time** — the whole fleet: throughput, task delay (mean + p95),
  PDR, Jain fairness, offered-vs-served load, packet drop. Shaded bands mark the
  *configured* attack onsets, so the gap between a band's left edge and the line
  reacting is your detection latency, visually.
- **Metrics over time — by cluster** — the same buckets split into two halves of
  the server roster (srv1–4, srv5–8), attributed by serving node. Use it to show
  that an attack's damage is **localised**: when a blackhole arms in cluster B,
  B's PDR drops while A holds flat — a separation the fleet panel averages away.
  Membership is printed on the panel; the split is positional, not physical
  (every server has its own edge switch here), so say so if asked.
- **Client load — 20→40 IoT devices** — six charts, x = the device count, with
  the roster held at the deployed 8 servers. **Say "this one is not live"
  before you point at it**; the panel says so too, and says what *is* real (the
  selector) versus modelled (the servers, the network).

  The point to make, in one sentence: **throughput and PDR are identical for
  both strategies across the whole sweep, and argmax is running the entire
  workload on 3 of the 8 servers.** Then show why that costs something —
  argmax's mean delay climbs 300→670 ms as devices are added while p2c holds
  ~200 ms flat, because every new device piles onto the same three queues.
  Fairness is the leading indicator here; PDR is the lagging one, and it has
  not moved yet.

  The right-hand edge (40 devices, 8 servers) is exactly the topology you just
  ran live, which is the reason to trust the shape of it more than a projection.

  If the panel says "no scaling sweep generated yet", run
  `python3 -m evaluation.scale_compare` (~20 s) and reload — `data/` is
  gitignored, so a fresh clone never ships one.

---

## 5. Terminal B (Mininet CLI) — data-plane Wireshark + rule inspection

With the network up, from the same `mininet>` prompt:

**Watch real packets on a host interface** (each host is its own namespace, so you
must scope the capture to the host):
```
mininet> iot1 wireshark &
```
Pick `iot1-eth0` as the interface. Generate a burst to watch live:
```
mininet> iot1 ping -c 20 srv1
```
*(GUI won't appear? Capture to a file instead: `iot1 tcpdump -i iot1-eth0 -w /tmp/iot1.pcap`, Ctrl-C, then `wireshark /tmp/iot1.pcap`.)*

**Inspect the live flow rules** (the same rules Wireshark shows as `FLOW_MOD`, and
the dashboard shows in its rules panel). Every controller-installed rule carries
the cookie high byte **`0x5A`** with the low byte = server index; they're told
apart by **priority** (VIP forward/reverse = 300, quarantine drop = 400 — see
`docs/FLOW_RULES.md`):
```
mininet> dpctl dump-flows -O OpenFlow13 | grep cookie=0x5a     # all controller rules (VIP + drop), by node
mininet> dpctl dump-flows -O OpenFlow13 | grep priority=400    # quarantine drop rules (n_packets = dropped)
mininet> dpctl dump-flows -O OpenFlow13 | grep meter           # metered (rate-limited) flows
```
Run the `priority=400` dump twice a couple of seconds apart — `n_packets` on
those entries should climb: that's exactly how many packets the switch is killing
on the quarantined node's behalf.

**Query the northbound API** (through the `cx` routing node, the same path the IoT
clients use):
```
mininet> iot1 curl -s http://10.0.99.254:8081/node/status  | python3 -m json.tool
mininet> iot1 curl -s http://10.0.99.254:8081/trust/score  | python3 -m json.tool
mininet> iot1 curl -s http://10.0.99.254:8081/api/optimizer | python3 -m json.tool
```
The last one is the AI optimizer's live state: `active_weights` and every arm's
pull count + mean reward — the same numbers the dashboard's Optimizer panel draws.

---

## 5b. Show the load-balancing fix (all healthy servers share load)

The router used to be winner-take-all `argmax`: it sent everything to the single
best node, so once trust entrenched two servers the other two got **zero** traffic
— a healthy server starved, not a security decision. The demo config now routes
with **power-of-two-choices** (`selection: p2c`), so healthy load is shared across
all of `srv1`, `srv2`, `srv4` (and `srv3` until it's caught). Full analysis and
IEEE references: `docs/LOAD_BALANCING_STARVATION.md`.

**On the dashboard:** the routing pulses fan out to *all* healthy servers, not two.

**From the Mininet CLI** — every healthy node shows non-zero `inflight` (current
load); with `argmax` two of them would sit pinned at `0`:
```
mininet> iot1 curl -s http://10.0.99.254:8081/node/status | python3 -m json.tool
```

**Hard per-server counts** — the controller records every decision to
`data/events.jsonl` (dashboard is on). Tally the share so far (run it in the repo
root, in Terminal A or a spare shell):
```bash
python3 -m evaluation.tally_route_share data/events.jsonl
```
Under `p2c` all four servers appear with a comparable share; the `starved` line is
empty. Keep this number for the before/after point below.

**The before/after (optional, off the live clock).** Reproduce the contrast with
no Mininet — this drives the *real* selector:
```bash
python3 -m evaluation.starvation_sweep          # argmax: 2 used / N-2 starved; p2c: all used
```
Or, for a true live before/after, run the whole demo once with `selection: argmax`
in the config and once with `p2c`, saving `data/events.jsonl` between runs and
tallying each (see `SETUP.md` §3b-routing). Those two tallies are exactly the
before/after of **Figure 11** in `docs/study/trust-routing-study.html`.

> Security is unchanged by this: quarantine excludes a malicious node **before**
> selection, so `srv3` still gets zero traffic once caught — p2c only changes which
> *healthy* node wins.

---

## 5c. Optional: show the drop attack too (second, independent detector)

The base demo has one attacker (`srv3`, Sybil). To show **both** detection paths in
one run, launch the opt-in scenario instead — same everything, plus a **packet-drop**
attacker (`srv4`):

```bash
# Terminal A (controller) and Terminal B (topology), both with this config:
ZTSDN_CONFIG=config/params_attacks_demo.yaml python3 -m controller.osken_manager controller.trust_balancer
sudo python3 -m simulation.topology --config config/params_attacks_demo.yaml --interactive
```

Two attackers, caught by two **different** signals — a good point to make explicitly:

| node | attack | how it's caught | what you'll see in Terminal A |
|------|--------|-----------------|-------------------------------|
| `srv3` | Sybil — claims idle, burns CPU | **latency tell** (claims idle but slow `/status`) | `latency tell: claims idle … x fleet median … (sustained)` |
| `srv4` | drop — accepts task, never replies | **timeout-rate tell** (clients time out) | `recent timeout rate … > 0.40 — packet-drop tell` |

`srv4` answers its `/status` poll perfectly normally and reports honest CPU — so the
Sybil checks never fire on it; only its clients' **timeouts** give it away. Watch the
dashboard: `srv3` and `srv4` both go red, `srv1`/`srv2` carry all the load, and the
**Load balancing** panel's `starved` stays 0 (two quarantined ≠ starved). Detection
takes a few seconds longer than the Sybil — the client task timeout is 2 s, so `srv4`
needs a handful of timed-out tasks before `recent_timeout_rate` crosses the line.

> This is the whole Zero-Trust argument in one screen: two independent misbehaviours,
> two independent detectors, and healthy load spread the entire time.

---

## 6. The narrative arc — what to watch, on every surface at once

The demo tells one story. Here's the same story across all four surfaces so you
can narrate it:

| ~Time | What happens | Dashboard (`:8081`) | Wireshark | Terminal A / CLI |
|-------|--------------|---------------------|-----------|------------------|
| 0–10 s | Switches connect, traffic starts, routing by EdgeScore | Blue dots flow IoT→switch→server, fanning out across **all four** servers (p2c, §5b); labelled pulses `→ srv2 (0.81)`; trust bars fill | `HELLO`, `FEATURES`, first `FLOW_MOD`s | `Routed ... -> srvN` (all healthy srvN, not just two) |
| 0–120 s | **AI optimizer** tunes weights every 10 s | **AI Optimizer panel**: active-weights bar shifts, arm rows accrue pulls/reward (`◀` active, `★` best); header `EdgeScore =` formula updates live | `MULTIPART` stat polls | `OPTIMIZER: window closed reward=...` |
| ~5 s | `iot12` (wrong key) tries to join | (no traffic ever appears from iot12) | 403 on its `/register` | `grep "AUTH DENIED" logs/iot12_client.log` |
| ~20 s | `srv3` starts **lying** about CPU | Trust panel: srv3's **claimed CPU** bar separates from **observed load**; `CPU LIE` tag | data-plane traffic still flowing to srv3 | honesty-deviation logs |
| mid-band | A node dips below full trust | that node's new flows carry a **meter** (rate-limited) | `FLOW_MOD` with meter instruction | `dpctl ... | grep meter` |
| ~catch | `srv3` tripped by the **anomaly gate** | srv3 struck out red, link dashed, VIP rules vanish; **`dropped N pkts`** pill climbs; red drop-rule rows | burst of `FLOW_MOD`: VIP deletes + `priority=400` drop adds | `QUARANTINE: srv3 ...` |
| ~catch+ε | srv3's clients re-steered | traffic re-appears on a healthy server | new `FLOW_MOD` rewrite rules | `Re-dispatched N client(s) ... < 3000ms` |
| after | srv3 stays isolated | `iot1 ping -c 3 srv3` → 100% loss; drop-rule `n_packets` keeps rising | drops, no replies | `dpctl ... | grep priority=400` (counter climbing) |

**Two points to make explicitly:**

1. **The malicious node is caught by the anomaly gate, not the trust threshold.**
   `srv3` is tripped by **Ā ≥ 0.5**, not by trust falling below the isolation line
   — it keeps completing tasks so its trust never drops far enough on its own.
   That's the core Zero-Trust finding
   (`tests/test_trust_state.py::test_f04_non_degrading_liar_needs_anomaly_gate`):
   trust alone is not enough; an independent anomaly signal is what makes it real.
   Under **p2c** the trigger is the **latency tell** — `srv3` claims idle
   (`cpu 0.1`) but answers `/status` far slower than its peers because it's
   burning CPU. (This matters: p2c stops the Sybil attracting concentrated load,
   which is what the *older* CPU-honesty deviation check needed to fire — so a
   load-independent tell was added to catch it anyway. See
   `docs/LOAD_BALANCING_STARVATION.md` §7.) Watch Terminal A for
   `latency tell: claims idle … but rtt …x fleet baseline`, and the Events panel
   for the same reason on the `anomaly` line.
2. **Healthy load is shared, not starved.** All four servers carry traffic (§5b),
   because routing is power-of-two-choices, not winner-take-all. Zero traffic to a
   server now means exactly one thing — it was **quarantined** (`srv3`) — never
   that a healthy node was starved by the scorer.

---

## 7. Teardown

```
mininet> exit
```
Then in Terminal A press `Ctrl-C`. Close the Wireshark windows. If you plan to run
again, start the next run with `sudo mn -c` (Terminal B) to clear bridges.

---

## 8. If something misbehaves

- **Dashboard says "controller unreachable" / blank:** Terminal A isn't up, or you
  opened it before the controller started. Refresh once A prints
  `NorthboundAPI listening`.
- **Switch logs a huge numeric DPID / rules look wrong:** you're talking to a stale
  bridge from a previous run. `mininet> exit`, `sudo mn -c`, start over.
- **Wireshark GUI never appears (root/Wayland):** you skipped `xhost +si:localuser:root`,
  or the display is locked down — use the `tcpdump -w file.pcap` fallback (§5).
- **No `AUTH DENIED` for iot12:** confirm `security.auth_scheme: present80` and
  `security.malicious_iot_devices: [iot12]` in the config.
- **Optimizer panel empty:** it fills on the first 10 s window; confirm
  `optimizer.enabled: true` in the config, or hit `/api/optimizer` (§5) to check.
- **`sch_htb: quantum ...` warnings at startup:** harmless `tc` tuning notices.

---

## 9. No-Mininet fallback (demo-day insurance)

If the live network misbehaves in front of your examiner, the **exact same
dashboard** replays a recorded run with no root and no Mininet — see `SETUP.md`
§5 "Replay". Generate a fresh recording (drives the real components, seed-fixed)
and loop it:

```bash
python3 -m dashboard.generate_demo_recording --out data/events.jsonl
python3 -m dashboard.replay data/events.jsonl --loop        # open http://localhost:8082/
```

Keep this ready in a spare terminal as a safety net. Prefer the **live** run
(§1–6) when the network cooperates.

> Careful: this **overwrites `data/events.jsonl`**. If a real run is sitting
> there unarchived, copy it out first (§0).

---

## 10. The full-scale panel run (8 servers / 40 devices / 6 attacks)

This is the run that produces the numbers in `SOURCE_OF_TRUTH.md` — every attack
the system implements, in one 300 s run, scored against ground truth afterwards.
Unlike §1–6 it is **one command in one terminal**: `run_demo.py` launches the
controller as a subprocess itself, then builds the network, then tears both down.
Nothing to narrate live; you read the result from the four reports in §11.

```bash
# 1. Archive the previous recording (data/ is gitignored, and this run deletes it)
cp data/events.jsonl data/events_runN.jsonl

# 2. Clean state
sudo service openvswitch-switch start
sudo modprobe -a sch_htb sch_netem sch_tbf sch_prio ifb
sudo mn -c

# 3. Run it (~5 minutes; needs root; the controller starts itself)
sudo python3 run_demo.py --mode mininet --config config/params_trust_full.yaml
```

**Let it finish.** The configured length is `simulation.duration_s: 300` and the
run tears itself down; interrupting it early costs the on-off attacker (`srv8`,
20 s period) most of its evidence, which is exactly what shortened run 11 to
213 s and pushed srv8's detection latency to 50 s.

While it runs, the live dashboard is still on **`http://localhost:8081/`** and
the controller's own log is **`logs/controller.log`**; per-host logs land in
`logs/srvN_agent.log` and `logs/iotN_client.log`.

**What is attacking, and when** (all from `config/params_trust_full.yaml`):

| Subject | Attack | Onset | Caught by |
|---|---|---|---|
| `iot38` | identity spoof (targets `iot1`) | 15 s | source-IP pin → `auth_denied kind=ip_pin` |
| `srv3` | sybil — claims idle, burns CPU | 20 s | latency tell |
| `srv6` | blackhole — accepts, never replies | 30 s | timeout-rate tell |
| `srv1` | grayhole — drops 50% | 40 s | timeout-rate tell (weaker) |
| `srv8` | on-off — 20 s period, 0.5 duty | 50 s | latency tell + sustained intermittency |
| `iot37` | DDoS flood — 3 workers @ 0.25 s | 60 s | client-keyed flood tell |
| `iot39`, `iot40` | bad credentials (wrong key) | at admission | `auth_denied kind=bad_response` |

Spot-checks while it runs or straight after:

```bash
grep "SPOOFING DENIED"  logs/iot38_client.log      # the spoof was refused
grep -c "Connection reset by peer" logs/*_client.log | grep -v ":0"   # expect nothing
grep "QUARANTINE\|Re-dispatched" logs/controller.log | head -40
grep -c '"charged": false' data/events.jsonl       # re-steered timeouts not charged (§3.17)
```

---

## 11. Analysing a finished run

All four read the same `data/events.jsonl` and **none of them needs root, Mininet,
or the controller stack**. Run them from the repo root:

```bash
python3 -m evaluation.nfr_report          data/events.jsonl   # the four NFRs, pass/fail
python3 -m evaluation.interval_report     data/events.jsonl   # every metric vs time, 10s buckets
python3 -m evaluation.attack_report       data/events.jsonl   # confusion matrix + detection latency
python3 -m evaluation.availability_report data/events.jsonl   # availability / "network lifetime"
```

Each also takes options worth knowing:

```bash
python3 -m evaluation.interval_report     data/events.jsonl --bucket-s 5 --csv buckets.csv
python3 -m evaluation.attack_report       data/events.jsonl --window-cycles 120 --csv subjects.csv
python3 -m evaluation.availability_report data/events.jsonl --quorum 0.5 --csv nodes.csv
python3 -m evaluation.nfr_report          data/events.jsonl --out data/nfr_report.txt
```

`attack_report` and `availability_report` score against the ground truth carried
on the run's `topology` event, so they need a recording that **includes the start
of the run** — they will tell you so rather than guess.

**Read the two reports together, and read them the right way round:**
- `availability_report` splits **honest** nodes from **attackers** and never
  prints a combined figure. An isolated attacker is enforcement working; an
  isolated honest node is the system's real cost. The headline is honest-only.
- `attack_report`'s detection latency is an **upper bound** — it is measured from
  controller start, which precedes agent launch by the Mininet build.
- A `FAMILY` row means the attack was caught and placed in the right family but
  the magnitude/intermittency was not resolved. The response was identical; only
  the label degraded.

**Route-denial and re-steer counts**, which no report prints directly:

```bash
echo "routes: $(grep -c '\"type\": \"route\"' data/events.jsonl)  denied: $(grep -c '\"type\": \"route_denied\"' data/events.jsonl)"
grep -c '"type": "quarantine"' data/events.jsonl
grep -c '"type": "recovered"'  data/events.jsonl
```

**No root required, and no live run needed** — the two simulation sweeps that
drive the *real* selector:

```bash
python3 -m evaluation.starvation_sweep                                  # argmax starves, p2c does not
python3 -m evaluation.scalability_sweep --ns 4,8,16,32,64 --load-factors 0.1,0.6
python3 -m evaluation.scalability_sweep --csv scaling.csv --seed 1      # same, to CSV
python3 -m evaluation.tally_route_share data/events.jsonl               # per-server share of a real run
```

Sweep the **load factor** as well as N: argmax *starves* nodes at 10% load and
*loses tasks* at 60%, and either end alone tells only half the story.

---

## 12. Command index — everything, in one place

**Checks (no root):**
```bash
python3 -m pytest tests/ -q                                  # 624 pass, 8 known scipy fails
python3 -m pytest tests/test_live_config_preflight.py -q      # config sound before you spend sudo
mn --version && python3 -c "import os_ken; print(os_ken.__version__)"
```

**Once per WSL2 session (root):**
```bash
sudo service openvswitch-switch start
sudo modprobe -a sch_htb sch_netem sch_tbf sch_prio ifb
xhost +si:localuser:root                                     # as your normal user, for Wireshark
```

**Narrated demo — 4 servers / 12 devices / 1 attack (§1–§8):**
```bash
# Terminal A (no sudo)
python3 -m controller.osken_manager controller.trust_balancer
# Terminal C (sudo)
sudo wireshark -i lo -k -f "tcp port 6653" &                 # filter: openflow_v4
# Terminal B (sudo)
sudo mn -c
sudo python3 -m simulation.topology --config config/params_trust_demo.yaml --interactive
# Browser
#   http://localhost:8081/
```

**Two-attacker variant (§5c):**
```bash
ZTSDN_CONFIG=config/params_attacks_demo.yaml python3 -m controller.osken_manager controller.trust_balancer
sudo python3 -m simulation.topology --config config/params_attacks_demo.yaml --interactive
```

**Full-scale panel run — 8 / 40 / 6 attacks (§10):**
```bash
cp data/events.jsonl data/events_runN.jsonl                  # archive first
sudo mn -c
sudo python3 run_demo.py --mode mininet --config config/params_trust_full.yaml
```

**Standalone, no Mininet and no root** (the trust engine on its own):
```bash
python3 run_demo.py --mode standalone --attack both --duration 120
```

**Analysis (no root, §11):**
```bash
python3 -m evaluation.nfr_report          data/events.jsonl
python3 -m evaluation.interval_report     data/events.jsonl
python3 -m evaluation.attack_report       data/events.jsonl
python3 -m evaluation.availability_report data/events.jsonl
python3 -m evaluation.scalability_sweep --ns 4,8,16,32,64 --load-factors 0.1,0.6
python3 -m evaluation.starvation_sweep
python3 -m evaluation.tally_route_share   data/events.jsonl
```

**Replay fallback (§9):**
```bash
python3 -m dashboard.generate_demo_recording --out data/events.jsonl --seed 7
python3 -m dashboard.replay data/events.jsonl --speed 8 --loop        # http://localhost:8082/
```

**From the `mininet>` prompt (§5):**
```
mininet> dpctl dump-flows -O OpenFlow13 | grep cookie=0x5a
mininet> dpctl dump-flows -O OpenFlow13 | grep priority=400
mininet> dpctl dump-flows -O OpenFlow13 | grep meter
mininet> iot1 curl -s http://10.0.99.254:8081/node/status   | python3 -m json.tool
mininet> iot1 curl -s http://10.0.99.254:8081/trust/score   | python3 -m json.tool
mininet> iot1 curl -s http://10.0.99.254:8081/api/optimizer | python3 -m json.tool
mininet> iot1 wireshark &
mininet> exit
```

**Teardown:**
```bash
mininet> exit          # then Ctrl-C in Terminal A
sudo mn -c             # before the next run, always
```
