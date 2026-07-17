# Flow-Rule Specification

Every OpenFlow 1.3 rule `TrustBalancerApp` installs, what it matches, what it
does, and the code path that installs it. This is the reference behind the
advisor's "show me the rules" ask: what you see in
`dpctl dump-flows -O OpenFlow13` should correspond, line for line, to a row
here.

The controller uses a **two-table pipeline**:

- **Table 0 — `TABLE_VIP`**: proxy-ARP for the virtual service IP, per-connection
  VIP rewrite (the load-balancing decision, enforced in the data plane),
  quarantine drops, and the punts that create PacketIn events. Everything that
  is not terminal here falls through to table 1.
- **Table 1 — `TABLE_L2`**: a plain MAC-learning switch.

Constants: `config/params_trust_demo.yaml` sets the VIP (`10.0.99.1:9000`), the
flow timeouts (`idle 10s / hard 30s`), and the meter rate. Priorities and table
ids are class constants in `controller/trust_balancer.py`.

---

## Table 0 — `TABLE_VIP`

| Prio | Purpose | Match | Instructions (in order) | Cookie | Timeouts | Installed by |
|------|---------|-------|-------------------------|--------|----------|--------------|
| 400 | **Quarantine drop** (2 entries per node: source and destination MAC) | `eth_src=srvN_mac` / `eth_dst=srvN_mac` | *(empty instruction set = drop)* | `0x5A..0N` | none | `_on_trust_collapse` |
| 350 | **Proxy-ARP punt** for the VIP | `eth_type=ARP, arp_tpa=VIP` | `output:CONTROLLER` | 0 | none | `switch_features_handler` |
| 300 | **VIP forward** (client → server rewrite; the routing decision) | `ip,tcp, ipv4_src=client, tcp_src=cport, ipv4_dst=VIP, tcp_dst=9000` | `[meter N]`?, `set eth_dst=srvN_mac`, `set ipv4_dst=srvN_ip`, `goto TABLE_L2` | `0x5A..0N` | idle 10 / hard 30 | `_install_vip_pair` |
| 300 | **VIP reverse** (server → client un-rewrite) | `ip,tcp, ipv4_src=srvN_ip, tcp_src=9000, ipv4_dst=client, tcp_dst=cport` | `set eth_src=VIP_MAC`, `set ipv4_src=VIP`, `goto TABLE_L2` | `0x5A..0N` | idle 10 / hard 30 | `_install_vip_pair` |
| 250 | **New-connection punt** (first packet of a new VIP flow) | `ip,tcp, ipv4_dst=VIP, tcp_dst=9000` | `output:CONTROLLER` | 0 | none | `switch_features_handler` |
| 0 | **Table-miss** → L2 | `*` | `goto TABLE_L2` | 0 | none | `switch_features_handler` |

`[meter N]?` — the VIP forward rule carries an `OFPInstructionMeter(N)` **only**
when the destination node is in the rate-limited band (graduated response); at
full trust the meter is absent. `N` is the server index. See the meter table
below.

## Table 1 — `TABLE_L2`

| Prio | Purpose | Match | Actions | Cookie | Timeouts | Installed by |
|------|---------|-------|---------|--------|----------|--------------|
| 1 | **Learned unicast** | `in_port=<p>, eth_dst=<mac>` | `output:<learned port>` | 0 | none | `_handle_table_l2` (on PacketIn) |
| 0 | **Table-miss** → controller (learn) | `*` | `output:CONTROLLER` | 0 | none | `switch_features_handler` |

## Meter table

| Meter id | Type | Band | Installed by |
|----------|------|------|--------------|
| `N` (= server index, one per edge server) | `KBPS` | drop band, `rate = rate_kbps`, `burst = burst_kb` (config `controller.rate_limit`) | `_install_meters`, after the `OFPMeterFeaturesStatsRequest` probe confirms support |

If a switch reports no meter support, no meters are installed and VIP forward
rules never reference one — graduated response degrades to binary
allow/quarantine on that switch, logged once.

---

## Cookie scheme

Controller-installed VIP and quarantine rules carry a cookie of
`0x5A00000000000000 | srvN_index` (`_cookie_for`):

- **High byte `0x5A`** tags a rule as controller-installed (VIP dispatch or
  quarantine), distinguishing it from L2-learning noise. `FlowStatsPoller` uses
  this to label rules and colour them by server in the dashboard.
- **Low byte = server index** lets a single cookie-scoped `OFPFC_DELETE` remove
  every rule for one node the instant it is quarantined (`_on_trust_collapse`),
  and lets the quarantine drop rules be identified for a future release path.

## Priority ordering, and why

`400 > 350 > 300 > 250 > 0`. The order is load-bearing:

- **400 quarantine drop** outranks everything so a quarantined node's traffic
  dies even if one of its own per-connection rewrite rules (300) is still
  present and has not yet timed out.
- **350 ARP punt** sits above the connection rules so an ARP request for the VIP
  is always answered by the controller's proxy-ARP, regardless of any installed
  flow.
- **300 connection** rules outrank the **250 new-connection punt** so that once
  a flow's rewrite pair is installed, its packets are rewritten in the data
  plane and stop punting to the controller — the controller only ever sees the
  *first* packet of each connection (this is why the dashboard animates from
  counter deltas, not per-packet PacketIn; see `controller/flow_stats.py`).
- **0 table-miss** falls through to the L2 table.

## Lifecycle of one VIP connection

1. Client sends SYN to `VIP:9000`. No 300-rule matches yet, so the **250** punt
   fires PacketIn.
2. `_handle_table_vip` runs `choose_edge_node()` (EdgeScore argmax over
   non-quarantined nodes) and calls `_install_vip_pair`, installing the **300**
   forward/reverse pair (metered if the node is in the rate-limited band).
3. Subsequent packets of that connection match the **300** rules and are
   rewritten entirely in the data plane.
4. If the node is later quarantined, `_on_trust_collapse` deletes its **300**
   rules by cookie, installs the **400** drops, and re-dispatches the client's
   next connection to the next-best node.
5. Idle/hard timeouts (10s/30s) reap the **300** rules when a connection ends.
