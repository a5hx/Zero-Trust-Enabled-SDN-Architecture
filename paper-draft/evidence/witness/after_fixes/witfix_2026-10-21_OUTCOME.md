# Outcome: Phase 2d re-run on the fixed switch witness (X1–X6)

- Prediction: `witfix_2026-10-21.txt`, committed in 15728ac before any run.
- Runs: 25 live runs, all at 15728ac, none short.
- Verdicts: `witfix_2026-10-21_live_verdicts.txt`. Service: `witfix_2026-10-21_live_summary.txt`.

| | Prediction | Batch 1 (before the fixes) | Re-run | Verdict |
|---|---|---|---|---|
| X1 | Control: nobody blamed (≥ 4/5) | 0 in 5/5 | **0 in 5/5** | **Held** |
| X2 | srv6 and srv1 blamed 5/5, median ≤ 20 s; no honest party | 4/5 and 5/5, 54–61 s | **5/5 and 5/5, medians 12.9 s and 14.1 s; 0 honest** | **Held** |
| X3 | Lying switch blamed 5/5 ≤ 20 s; no client or server (≥ 4/5) | 5/5 in 14.1 s; clients wrongly blamed in 3/5 | **5/5 in 5.2 s; 0 clients, 0 servers in 5/5** | **Held** |
| X4 | Badmouthers blamed 5/5 ≤ 30 s; no switch or server | 5/5, ~14 s | **5/5 each, 12.0 s; nobody else** | **Held** |
| X5 | Covered dropper srv6 blamed 5/5; no client behind dpid 4 | 5/5 | **5/5, 16.2 s; covering switch 0/5; nobody else** | **Held** |
| X6 | Control honest mean latency within wit_control's interval (87.9–92.2 ms) | 90.1 ms | **93.6 ms [89.0, 98.3]** | **Failed as worded** |

**On X6.** The two intervals overlap, but the mean is above the earlier
interval, so the prediction as written failed. The witness is observe-only:
it routes, delays and quarantines nothing. The difference is between-batch
variation in the host, not an effect of the fixes. The honest-latency means
across the re-run's five arms are 90.2–93.6 ms, and 0 honest servers were
quarantined in any arm.

## Result

**Across 25 runs:**
- every lying party was blamed in every run: two dropping servers, a lying
  switch, two badmouthing clients, and a dropper covered by a colluding
  switch;
- **no honest server, switch or client was blamed for even one second.**

**The two fixes did what they were for:**
- dropping servers are now blamed in 13–14 s, against 54–61 s;
- the lying switch in 5.2 s, against 14.1 s;
- the transient client misattribution is gone (0/5, against 3/5).

**The covering switch was not blamed in any live run (0/5).** In the live
system the gate quarantines the dropper ~12 s after onset, so the covering
switch gets too few covered connections to cross the threshold. The
synthetic test, where the dropper is never quarantined, can blame it.
Covering a server that the gate isolates anyway buys the switch nothing.
That remains a stated limitation, and is not a false accusation.

**What the three-witness check now shows:** with the server's, the
switch's and the client's accounts of every task, the controller can name
which party is lying:
- a server dropping work;
- a switch hiding responses;
- a client badmouthing servers;
- collusion through one switch (still seen through the other switches).

It is observe-only. The step after this is letting its verdicts act: for
example, discounting a blamed client's reports, or excluding a blamed
switch's counters. That should come only now that its false-blame rate has
been measured at 0 in 25 runs.
