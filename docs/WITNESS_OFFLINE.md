# Phase 2a: the switch as a witness, measured offline (2026-10-20)

Novelty plan, direction 2. The question is whether the OpenFlow counters the
controller already collects (`flow_stats`, `port_stats`) can verify the
**clients'** account of each server, and therefore whether building the live
check (Phase 2b, about 2–3 weeks) is worth it. It was answered from the
existing recordings, with no new run:

```bash
python3 -m evaluation.witness_offline data/runs --out data/witness_2026-10-20
```

The run covered 110 recordings across 22 arms, with 675 honest server-runs.
Tests are in `tests/test_witness_offline.py`.

## What one connection looks like to the switch

Every task is one TCP connection with its own VIP rule pair on the client's
ingress switch, keyed by the client's IP and source port. On every honest
server the switch sees **6 packets / 548 bytes in, 6 packets / 598 bytes
back**. A connection is classed:

| Class | Bytes back |
|---|---|
| served | at least 400 (a full response) |
| unanswered | 0 |
| partial | anything else, e.g. a client gave up after 4 s and only its close was acknowledged |

## Findings

**1. The switch and the clients agree, tightly.** Switch-served connections
divided by client-reported successes, per honest server per run:
**median 0.9992**, p5 0.9917, p95 1.0000 (n = 675).
- A client that misreported even a few percent of a server's tasks would
  stand out over a run.
- Per 10 s window the noise is wider (p1 0.77, p99 1.25, n = 21,143), so a
  live check needs cumulative or roughly 60 s windows, not 10 s ones.

**2. The switch sees drops without any client report.** This is measured as
the fraction of connections with **no full response** (unanswered + partial),
in the trust-controller arms:

| Ground truth | n | Median | Range |
|---|---|---|---|
| honest | 655 | **0.003** | 0.000–0.154 |
| blackhole (`drop`) | 35 | **0.504** | 0.395–0.841 |
| grayhole | 35 | **0.364** | 0.230–0.625 |
| liar / on-off / stealthy | 80 | 0.01–0.05 | — |
| sybil | 35 | 0.069 | 0.000–0.500 |

"Zero bytes back" alone is the wrong test. A client that times out closes the
connection, and the server's acknowledgement of that close flows back, which
is why a grayhole looked almost clean on that definition in the flood arms.

**3. Flow conservation between switches holds within a workload, not across
workloads.** The share of a server's own edge-switch port-1 bytes not
accounted for by its VIP rules (the controller's `/status` polls, ARP) is:
- 0.16–0.17 at the shipped workload;
- about 0.33 in the 40%-occupancy liar arms;
- 0.11–0.20 in the flood arms.

Each arm's range is tight. A live check must therefore compare each server
with the fleet median at the same time, as the latency tell does, never with
a fixed constant.

## Confounders a live check must handle (found here)

- **Re-steered connections.** When the controller quarantines a server it
  moves that server's in-flight tasks. The old rule pair keeps request bytes
  but gets no response. This is why the sybil in the θ = 0.45 and 0.50 arms
  shows 17–40% "unanswered" with zero client timeouts, and part of why honest
  servers reach 0.154. Exclude connections the controller re-steered (the
  `reroute` events).
- **The baseline arm's rule layout** doesn't show its dropped connections the
  same way: successes still match the clients exactly, but no unserved
  connections appear. The drop finding above is for the trust controller;
  the baseline needs its own parse.
- **Client reports lost after a successful response** push agreement above 1
  (at most 1.045, in the 40%-occupancy arms).

## Decision

**Phase 2b is worth building.** The switch account agrees with the clients to
better than 1% per run, and it separates droppers from honest servers without
using any client report. A badmouthing client and a misreporting switch are
both visible as disagreements between independent witnesses.

The live check should:
1. use about 60 s or cumulative windows;
2. exclude re-steered connections;
3. compare conservation residuals with the fleet median;
4. start classifier-only, as planned.
