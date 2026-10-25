# Outcome: the witness hold re-run on the fixed trial path (wh2_*): stopped at 8 of 25 runs

Prediction `withold2_2026-10-24.txt` was committed before any run (`284ecf4`). The batch
stopped about 4 minutes into its 10th run (`wh2_drop_hold` r02), when the machine went down
on 2026-10-23 at about 22:45 UTC. That run left only a console log and a partial recording,
and neither is scored. The 8 complete runs are all at `284ecf4`, and all completed cleanly:

| Arm | Runs |
|---|---|
| `wh2_control_hold` | 1 |
| `wh2_forge_act` | 2 |
| `wh2_forge_hold` | 2 |
| `wh2_drop_act` | 2 |
| `wh2_drop_hold` | 1 |

They were scored on 2026-10-25:

```bash
python3 -m evaluation.witness_act_report data/runs --arms wh2_control_hold,wh2_forge_act,wh2_forge_hold,wh2_drop_act,wh2_drop_hold
python3 -m evaluation.replicates data/runs --arms wh2_control_hold,wh2_forge_act,wh2_forge_hold,wh2_drop_act,wh2_drop_hold --out-dir data/withold2_experiment_2026-10-25
```

The outputs are `withold2_2026-10-24_live_withold.txt` and `_live_summary.txt`.

**The batch is not being completed.** The 8 runs already expose a second defect on the
trial path, in all three runs of the holding arms. Every remaining run would measure that
same defect again. It is fixed below, and the five arms are re-run as `wh3_*` (prediction
`withold3_2026-10-25.txt`). K1–K5 are scored on the 8 runs only as an interim reading. None
of them is claimed as held or failed at n ≤ 2.

## Interim reading of K1–K5

| # | Predicted | Measured (8 runs) | |
|---|---|---|---|
| K1 | ≥ 80% of witness trials judged | forge 21/46, drop 28/44: **54%** (batch 1: 8%) | Below; cause found, see below |
| K2 | `wh2_forge_hold`: held 5/5, released 0; ≥ 95% quarantined; honest success ≥ 98.5%, disjoint above act | held 2/2, released 0; **95.5%**; **99.00%** [97.96, 100] vs act 97.72% [97.46, 97.99] | On track (n = 2) |
| K3 | srv1 (grayhole) released ≥ 1 in ≥ 3/5; srv6 held, never released | srv1 **released 2× in 1/1** (3 holds); srv6 held, 0 releases | On track (n = 1) |
| K4 | control: no honest server held or blamed; honest success ≥ 99.9% | 0 held, 0 blamed; **99.98%** | On track (n = 1) |
| K5 | no honest server quarantined by the witness signal | **0 in 8 runs** | On track |

**The fix of 2026-10-24 works.** Trials now reach the held server: 54% are judged, against
8% in batch 1. srv1, a 50% grayhole, now passes 3 trials in a row and is released, then
re-held about 36 s later. That is the hold's weakness, registered before batch 1, and now
observed for the first time.

## The second defect: a trial's own timeout report is charged to an honest server

**What happens to a trial connection:**
1. The trial's rules (rewrite pair and passage) carry `hard_timeout = task_timeout_s = 4 s`.
2. Against a dropper, the client gives up at about 4.04 s and closes its socket.
3. By then the rules have expired, so the client's FIN misses them and reaches the
   controller as a PacketIn on the VIP.
4. The controller treated every VIP PacketIn as a new connection. It routed the FIN to a
   fresh server and re-registered that `(client_ip, client_port)` key there.
5. The client's timeout report for the trial arrived about 20 ms later. It was attributed to
   the fresh, honest server and charged as an ordinary timeout.

**Example** (`wh2_forge_hold` r01):
- At 110.4 s the trial `10.0.0.20:59628` was routed to srv3.
- At 114.51 s the same key was routed to srv1.
- At 114.53 s a `timeout` (4077 ms) was charged to srv1, whose trust fell to 0.42.

**Measured** (`trial tails re-routed / charged elsewhere`, now in `witness_act_report`):

| Arm | Trial tails re-routed | Charged to an honest server |
|---|---|---|
| `wh2_forge_hold` (2 runs) | 35 | **25** |
| `wh2_drop_hold` (1 run) | 26 | **16** |
| batch 1 `wh_forge_hold` / `wh_drop_hold` (10 runs) | 4 + 11 | 1 + 3 |

**Two consequences:**
- **K1's shortfall.** The witness judges a trial by its key, and its report went to another
  server, so the trial was never judged.
- **The honest-trust floor of the holding arms.** With λ = 0.85, one charged timeout takes a
  steady honest server to about 0.42. The lowest honest trust was 0.419 in `wh2_forge_hold`
  and 0.420 in `wh2_drop_hold`, against 0.50 in the control.

In the tails where the report arrived *before* the FIN, the stray re-route instead opened a
dispatch that no report would ever close. That is a phantom in-flight count on an honest
server, held until the reaper clears it.

No honest server was quarantined by it in these 8 runs. But two such charges close together
would do what two real failures did in batch 1's `wh_control_hold` r01: push an honest server
below θ = 0.30.

**Why batch 1 hid it:** almost every trial was black-holed. A client whose `connect()` never
completes sends no report, so there was nothing to misattribute. Fixing the black hole
exposed this defect.

**Older recordings.** Trust-rail probation trials have the same 4 s rules. Across the
recorded arms with probation trials (`treat`, `scoreonly`, `scoreonly_t040/45/50`,
`flood_off`/`flood_on`), 3–7 timeouts per 5 runs were charged to an honest server this way.
That is small, because most trials there were black-holed too, and it points the same way as
the black hole: honest servers lose a little trust they should not have lost.

**A cost the black hole also hid.** Batch 1's `wh_forge_hold` honest success, 99.40%, was
flattered by the defect: a black-holed trial produced no report, so it never counted as a
failure. With trials reaching the dropper, every trial costs an honest client one task
(about 23 per run). Honest success reads **99.00%**, still above acting alone (97.72%).
This is the price of re-testing a real dropper, and it is now visible.

## Fix (`controller/trust_balancer.py`, `_handle_table_vip`)

Only a SYN opens a connection. A VIP PacketIn without SYN, or with SYN+ACK, is the tail of a
connection whose rules have expired. It is no longer routed: no dispatch, no rules, no
packet-out. A `route_ignored` event (reason `not_syn`) is published instead. The dispatch it
belongs to keeps its report.

- The flood tell still counts the packet, as before.
- The baseline controller is unchanged (it has no trials).
- `tests/test_non_syn_packet_in.py` drives the real PacketIn path with packets built by the
  os-ken packet library:
  - a SYN is routed;
  - FIN+ACK, ACK, RST and SYN+ACK leave the trial's dispatch, its in-flight count and its
    report attribution untouched;
  - a stray tail opens no dispatch.
- Removing the guard fails 5 of the 6 tests.

## Next

Run `wh3_*`: the same five arms, with only the recording path changed. The prediction
`withold3_2026-10-25.txt` was registered before any run.
