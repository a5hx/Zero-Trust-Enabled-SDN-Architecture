# Final Run — Full Live Demo, End to End

A single, ordered walkthrough that brings up **everything built so far** at once
and drives it live: the trust-aware SDN controller, the Mininet network with real
IoT traffic, Wireshark on both the OpenFlow control channel and the data plane,
and the **live** browser dashboard (not the pre-recorded replay) showing routing,
trust, packet drops, and the AI weight optimizer learning in real time. Routing
now spreads load across **all** healthy servers via power-of-two-choices, not just
the top two — the starvation fix (§5b).

> This is the demo-day runbook. For install/environment details and per-feature
> deep dives see **`SETUP.md`**; for the optimizer design see
> **`docs/AI_OPTIMIZER.md`**; for the flow-rule scheme see **`docs/FLOW_RULES.md`**;
> for the load-balancing starvation fix see **`docs/LOAD_BALANCING_STARVATION.md`**.
>
> **Platform note:** this box ships only Python 3.14, so the controller uses
> **os-ken** (a maintained Ryu fork), and `sudo` needs an interactive password —
> every **(sudo)** step must be run by you, in your own terminal. No venv/pip.

You will use **four terminals** plus a browser. Keep them in this layout:

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
python3 -m pytest tests/ -q                             # expect: all passing

# Confirm the demo config has the features on (they are, by default):
grep -E "enabled|auth_scheme|rate_limit|selection|epsilon" config/params_trust_demo.yaml
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
   trust alone is not enough; the independent load-honesty check is what makes it
   real.
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
