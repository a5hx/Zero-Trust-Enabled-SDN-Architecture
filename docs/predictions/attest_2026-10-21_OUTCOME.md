# Phase 4 outcome: admission by attestation, alongside behaviour

Prediction `attest_2026-10-21.txt` was committed and pushed before any run (`840c58f`).
The 25 runs took place 2026-10-21 17:56 to 20:20 UTC, all at `840c58f`, and all completed
cleanly (307.7–308.9 s recorded). Scored 2026-10-22:

```bash
python3 -m evaluation.attestation_report data/runs --arms att_off_clean,att_on_clean,att_off_tampered,att_on_tampered,att_on_runtime
python3 -m evaluation.replicates data/runs --arms att_off_clean,att_on_clean,att_off_tampered,att_on_tampered,att_on_runtime --out-dir data/attest_experiment_2026-10-22
```

The full outputs are `attest_2026-10-21_live_attestation.txt` and
`attest_2026-10-21_live_summary.txt`.

## Verdict: A1–A6 all held

| # | Predicted | Measured | |
|---|---|---|---|
| A1 | `att_on_clean`: 8/8 admitted 5/5; last ≤ 3 s after first; < 56 denied before, none after | 5/5; last admitted 0.11–0.50 s after the first; 0–3 denied (mean 0.6), none after | **Held** |
| A2 | No genuine server refused or expired in any of the 15 attestation-on runs | **0** refusals, **0** expirations; 88 quotes per run in clean and tampered arms | **Held** |
| A3 | Tampered srv6 refused 5/5, only `simulation/node_agent.py` named; never admitted; 0 connections | refused **5/5**, every refusal `not_in_allowlist ['simulation/node_agent.py']`; admitted **0/5**; **0** connections in every run | **Held** |
| A4 | Attestation off: srv6 contained 5/5, median ≤ 20 s; > 0 connections before containment in every run | 5/5, median **10.9 s** (8.8–32.3); **25, 17, 6, 18, 17** connections before containment | **Held** |
| A5 | Runtime compromise passes attestation 5/5, never refused; behaviour contains it; intervals overlap A4's | passed **5/5**, refused 0; contained **5/5**, median **9.9 s** (8.9–10.5); exposure 20 [15, 24] vs 17 [8, 25]; containment 9.7 [8.9, 10.5] vs 14.9 [2.6, 27.1] | **Held** |
| A6 | Honest latency intervals overlap; median verify < 5 ms | 90.6 [88.8, 92.3] vs 88.5 [87.2, 89.7] ms (overlap 0.9 ms); verify median **0.20 ms**, p95 0.30 ms | **Held**, narrowly |

## What the experiment shows

**Attestation and behaviour catch different things.** The same dropping srv6 was run
three ways:
- **Tampered image, attestation off:** behaviour caught it in a median 10.9 s, after it had
  been handed 6–25 connections.
- **Tampered image, attestation on:** it never received a single connection.
- **Genuine image compromised at run time, attestation on:** every one of its 42
  post-onset quotes passed. Behaviour caught it as fast as before (9.9 s, 20
  connections). Attestation bought nothing here, as predicted.

**The service difference was measurable**, though it was not predicted (the registration
said the gap might sit inside run-to-run noise):

| | Honest timeouts per run | Honest task success |
|---|---|---|
| `att_off_tampered` | 24.6 [16.4, 32.8] | 99.52% [99.36, 99.69] |
| `att_on_tampered` | **0.0** | **99.98% [99.95, 100]** |
| `att_on_runtime` | 27.6 [22.8, 32.4] | 99.48% [99.39, 99.57] |

The intervals for the two tampered arms are disjoint. Runtime compromise costs honest
devices the same as an unattested tampered server.

**Cost:**
- Admission adds about 4 s from controller start to the whole fleet admitted (4.1 [3.9, 4.5] s).
  This is about when clients send their first task anyway: the first route came 3–8 s after
  the first event in the earlier arms.
- 0–4 connections are denied per run, all before the fleet is in.
- Verification takes 0.2 ms per quote.
- Honest mean latency was +2.1 ms (+2.4%) with attestation on. The intervals overlap by
  only 0.9 ms, so a small cost cannot be ruled out. p95 was 130.9 against 126.3 ms, also
  overlapping narrowly.

## Two things not predicted

**1. Quarantine also cuts the attestation channel.** In `att_on_runtime`, srv6 completed
9–10 attestation rounds instead of 11.
- Of its 42 post-onset quotes, **0** fell inside one of its quarantine intervals, although it
  was quarantined for 48.6% of that time. Reproduced by `evaluation.attestation_report`, line
  `quotes after onset` (added 2026-10-22, after this outcome was first written). If timing were independent, that would happen
  with probability about 0.514^42 ≈ 10⁻¹².
- Each round that fell due while it was isolated arrived 0.2–2 s after the release instead
  (for example: release 71.7 s, quote 73.3 s; release 128.1 s, quote 128.4 s).
- Cause: OpenFlow isolation drops the server's traffic to the controller, and the attester
  shares that path.
- Harmless here: the quarantine intervals are about 12 s, the admission lasts 75 s, and a
  quarantined server gets no traffic anyway.
- It matters for any design that relies on attestation to re-admit a quarantined server, or
  that quarantines for longer than `validity_s`. Then the server's admission expires and it
  cannot renew it while isolated. Attestation should travel on an out-of-band management path
  or be exempt from quarantine.
- This is the same coupling the paper's §VIII-A names: *the enforcement action is itself an
  input to the detector*.

**2. Staggered admission can concentrate the start-up burst.**
- In 1 of 15 runs (`att_on_tampered` r01), srv4 was admitted 56 ms before the next server and
  took 9 connections alone, then 28 of the first 40.
- Its task latency reached 0.95 s, 2 tasks failed, and its trust fell to **0.354** (θ = 0.30).
  It was not quarantined.
- In the other 14 runs the first-admitted server took 1–13 of the first 40 connections.
- A second start-up dip (r05, srv2 0.462 at 4.3 s) is *not* explained by admission order:
  srv3 was admitted first there.
- Possible fixes (not tested): hold routing until a quorum of servers is admitted, or admit
  the first round as a batch.

## What this does not show

- **No hardware root of trust.** The key and the measurement live in a root process on the
  same host as the agent.
- **A crude tampered image.** It differs by one appended line, so it shows the mechanism
  works, not that any particular real-world tampering is caught.
- **Measurement scope.** It covers the interpreter and the agent's two source files, not the
  standard library, the kernel or the configuration (command-line flags are not measured).
  Runtime compromise passing is therefore by construction; the experiment shows behaviour
  still catches it, not that attestation could.
