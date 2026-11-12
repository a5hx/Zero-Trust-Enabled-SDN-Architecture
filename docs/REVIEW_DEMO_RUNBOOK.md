# Final-review demo runbook (16 Nov)

What runs where, in what order, and what to fall back to. Every command
here has been run at least as far as this document says. The **Status**
section at the end records what has and has not been verified.

**The framing to say out loud:** the data plane is emulated (Mininet on
laptop A), and the control plane is distributed across laptops: three ledger
replicas, a read-only second controller, and remote viewers.

## Configs

| File | Scene | Notes |
|---|---|---|
| `config/params_review_demo.yaml` | main demo, 240 s | every attack of `params_trust_full`, verified routing, meter throttle, witness act + hold, `raft_remote` + replica re-verification; replicas launched locally |
| `config/params_review_demo_forge.yaml` | auditor scene, 180 s | srv3 drops from 30 s, the primary forges its evidence from 30 s with its own witness off; auditor attached and launched locally. Needs `ZTSDN_ALLOW_FORGERY=1` |
| `deploy/demo/*_remote.yaml` | the multi-laptop variants | **generated** by `tools/demo_hosts.py`; never edit by hand |

Attestation is off in all of them: its allow-list measures this machine's
interpreter.

## 1. Single-laptop rehearsal (laptop A, WSL)

The features in the main config have never all run together. Rehearse twice
before involving any other laptop.

```bash
sudo scripts/wsl_preflight.sh
```

```bash
python3 scripts/preflight_live_run.py --config config/params_review_demo.yaml
```

```bash
sudo python3 run_demo.py --mode mininet --config config/params_review_demo.yaml
```

Open `http://localhost:8081/` in Windows. **Pass** when:

- no honest server (srv2, srv4, srv5, srv7) is quarantined;
- every attack gets a label in the Security panel: srv3 sybil, srv6 blackhole, srv1 grayhole, srv8 onoff, 10.0.0.38 spoof, 10.0.0.39/40 bad_credentials, 10.0.0.37 flood;
- the witness holds and then releases at least one server;
- the ledger strip reads "Raft cluster, 3 replicas", a leader is shown, and "0 record(s) refused".

Then score the recording:

```bash
python3 -m evaluation.nfr_report data/events_review_demo.jsonl
```

Auditor scene, same laptop (`run_demo.py` starts the auditor on port 6654 itself):

```bash
ZTSDN_ALLOW_FORGERY=1 python3 scripts/preflight_live_run.py --config config/params_review_demo_forge.yaml
```

```bash
sudo ZTSDN_ALLOW_FORGERY=1 python3 run_demo.py --mode mininet --config config/params_review_demo_forge.yaml
```

**Pass** when:

- the Controllers panel shows **9/9** switches confirmed read-only;
- from about 40 s, srv3 reads "not serving · DISAGREE — primary still routes to it", while the primary's trust row shows srv3 healthy;
- the other seven servers read "agree".

The auditor log is `logs/auditor.log`; its recording is `data/events_review_demo_forge_auditor.jsonl`.

**If a feature combination fails on rehearsal:** drop that combination
from the config, not the demo, and note it here.

## 2. Multi-laptop

All laptops join the **phone hotspot** (college Wi-Fi may isolate clients).

1. Collect each laptop's hotspot address, then:
   ```bash
   cp deploy/demo_hosts.example.yaml deploy/demo_hosts.yaml
   ```
   Fill in `deploy/demo_hosts.yaml`. To add the Mac as auditor, uncomment its line.
2. On laptop A, generate everything:
   ```bash
   python3 tools/demo_hosts.py
   ```
   This writes `deploy/demo/`: the derived configs, `ledger_token.txt`, `replica_bundle.zip`, `auditor_bundle.zip`, `run_controller_A.sh` and `portproxy_A.ps1`. It is gitignored.
3. **Replica laptops (B, C: Windows):** copy `replica_bundle.zip` over and unzip it. Once, in an **Administrator** PowerShell, run `powershell -ExecutionPolicy Bypass -File replica_n1.ps1` (`n2` on C); this adds the firewall rule. Needs Python 3 and `py -3 -m pip install pyyaml`.
4. **Replica laptop D (Linux, no sudo):** unzip, then `python3 -m pip install --user pyyaml` and `sh replica_n3.sh`.
5. **Auditor laptop E (Mac):** copy `auditor_bundle.zip` and unzip it. Run `sh auditor_mac.sh`, or `sh auditor_mac.sh forge` for the auditor scene. The first run needs internet (it builds a venv with os-ken). Click **Allow** when macOS asks about incoming connections. Restart it for every run.
6. **Laptop A, Windows side, Administrator PowerShell** (this lets other laptops view the dashboard). Re-run it after any reboot:
   ```
   powershell -ExecutionPolicy Bypass -File \\wsl$\<distro>\home\<user>\Zero-Trust-Enabled-SDN-Architecture\deploy\demo\portproxy_A.ps1
   ```
7. **Laptop A, WSL.** First check every replica and wait for a leader:
   ```bash
   python3 tools/demo_hosts.py --check --wait-leader 30
   ```
   Then start the main demo:
   ```bash
   sh deploy/demo/run_controller_A.sh
   ```
   Or the auditor scene:
   ```bash
   sh deploy/demo/run_controller_A.sh forge
   ```
8. Viewers open `http://<laptop A hotspot IP>:8081/`.

**Lid scene:** close replica laptop B's lid mid-run. In the ledger strip, B's chip
loses "leader" if it held it, the term on the newest block rises, the
retries count may tick, and the block count keeps rising.

## Scenes, in order

1. Normal routing: the Load balancing panel, 8/8 serving.
2. Wrong key and spoof refused: Security → Admission refusals (from 4 s / 15 s).
3. Liar caught by the gate: srv3 sybil from 20 s, "QUARANTINED · anomaly gate".
4. Droppers caught and held by the witness: srv6 and srv1, the Switch witness panel, "held by witness", the trial streak.
5. Flood throttled: iot37 from 60 s, the "throttled N client(s)" header pill.
6. Close B's lid: the ledger keeps committing.
7. Auditor scene (only if it passed the 14 Nov cutoff).

Use **alerts only** on the Events panel during the talk: it hides the
route/report traffic.

## Fallback ladder

1. Full multi-laptop live.
2. Live on laptop A with **local** replicas (section 1's commands), with remote viewers via `portproxy_A.ps1`.
3. Live on laptop A alone.
4. **Replay** of the best rehearsal recording. Replay serves port 8082; replay-mode panels say "n/a in replay" where there is no live endpoint:
   ```bash
   python3 -m dashboard.replay data/events_review_demo.jsonl --loop
   ```
   Recorded single-feature runs:
   ```bash
   python3 -m dashboard.replay data/runs/wh3_forge_hold/r01.jsonl
   ```
   ```bash
   python3 -m dashboard.replay data/runs/flood_on/r01.jsonl
   ```
   ```bash
   python3 -m dashboard.replay data/runs/att_on_tampered/r01.jsonl
   ```
5. Slides with recorded screenshots.

Copy the best rehearsal recordings somewhere safe on the 15th:
`run_demo.py` archives the previous recording on every start, but a full
disk or a wrong `--config` still loses evidence.

## Claims to avoid on stage

- Detection is not instant: the recorded times are 6–16 s.
- Say "emulated data plane", never "real network".
- No adaptive adversary was tested.
- The ledger **detects** a tampered record; it does not prevent the controller from routing on it (§VII-I).
- The auditor **observes**; it cannot take over yet. Takeover is the next milestone.

## Status (12 Nov)

Verified here, without root:

- the dashboard: every published event type is dispatched or logged (tests/test_dashboard_events.py); real recordings replayed through the page under node and screenshotted in headless Chromium;
- a late-joining viewer rebuilds quarantines, holds, refusals and labels from the event-bus backfill;
- `tools/demo_hosts.py`: a 3-replica cluster started from the unzipped bundle's own `.sh` scripts elects a leader, enforces the token, and re-elects after its leader is killed (tests/test_demo_hosts.py);
- the generated `.ps1` replica scripts parse under Windows PowerShell, and three of them ran natively on Windows Python 3.14 and elected a leader;
- the auditor: role handshake, read-only property, server derivation from the real installed FlowMods, verdicts (tests/test_auditor.py); it starts and listens on `--ofp-port`;
- preflight passes on both review configs.

**Not yet verified, because it needs root or other laptops:**

- either config under Mininet;
- the auditor against real OVS (role reply, multipart flow stats);
- os-ken installing on the Mac;
- portproxy;
- hotspot reachability.
