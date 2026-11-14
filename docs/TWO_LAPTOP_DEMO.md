# Two-laptop demo: Windows+WSL and a Mac

`REVIEW_DEMO_RUNBOOK.md` is written for five laptops. This is the same demo
on the two laptops available now:

| Laptop | Runs |
|---|---|
| **A**: Windows + WSL | WSL: Mininet, the primary controller, the dashboard. Windows side: ledger replica **n1** |
| **M**: Mac | ledger replicas **n2** and **n3**, the **auditor**, and a dashboard viewer |

The RAFT cluster still needs three replicas (`tools/demo_hosts.py` refuses
fewer, or any even number). Two of them run on the Mac on separate ports, so
**most of the ledger is on a different machine from the controller**. Say
that out loud: the data plane is emulated on laptop A, and the ledger
majority and the auditor are on the Mac.

Read the runbook's single-laptop rehearsal (section 1) first and pass it
before you start here. Nothing below helps if the config fails on one machine.

## 0. Network

Put both laptops on the **phone hotspot**, not college Wi-Fi, which may stop
laptops from reaching each other. Note both addresses:

- **A**: in Windows `cmd` or PowerShell, run `ipconfig` and take the Wi-Fi
  adapter's IPv4 address. Use the **Windows** address here, not the WSL one
  (`hostname -I` inside WSL gives a different, internal address).
- **M**: `ipconfig getifaddr en0`

The examples below use `192.168.43.10` for A and `192.168.43.20` for M.
Hotspot addresses change from session to session, so check them again on the
day.

## 1. Hosts file (laptop A, WSL)

```bash
cp deploy/demo_hosts.example.yaml deploy/demo_hosts.yaml
```

Replace its `controller`, `replicas` and `auditor` entries with:

```yaml
controller:
  host: 192.168.43.10          # A's Windows hotspot address

replicas:
  n1: {host: 192.168.43.10, os: windows}                              # A, Windows side
  n2: {host: 192.168.43.20, os: mac}                                  # Mac
  n3: {host: 192.168.43.20, os: mac, http_port: 9102, raft_port: 9002} # Mac, own ports

auditor: {host: 192.168.43.20, os: mac}
```

n3 needs its own `http_port` and `raft_port` because it shares the Mac with
n2. Leave the `ports:` block as it is.

## 2. Generate (laptop A, WSL)

```bash
python3 tools/demo_hosts.py
```

This writes `deploy/demo/`, which contains `replica_bundle.zip` (holding
`replica_n1.ps1`, `replica_n2.sh` and `replica_n3.sh`), `auditor_bundle.zip`,
`run_controller_A.sh`, `portproxy_A.ps1`, the derived configs and
`ledger_token.txt`.

**Re-run this whenever an address changes**, then copy the bundles over
again. The token is kept across regenerations, but the replica scripts carry
the addresses.

Copy the bundles out of WSL:

```bash
mkdir -p /mnt/c/ztsdn
cp deploy/demo/replica_bundle.zip deploy/demo/auditor_bundle.zip /mnt/c/ztsdn/
```

Leave one `replica_bundle.zip` in `C:\ztsdn` for n1, and move both zips to
the Mac. Without a USB stick, serve them from the Windows side of A and
download them with `curl`. In an Administrator PowerShell on A:

```
cd C:\ztsdn
New-NetFirewallRule -DisplayName "ztsdn-transfer" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow -Profile Any
py -3 -m http.server 8000 --bind 0.0.0.0
```

On the Mac:

```bash
cd ~/Downloads
curl -fO http://192.168.43.10:8000/replica_bundle.zip
curl -fO http://192.168.43.10:8000/auditor_bundle.zip
unzip -o replica_bundle.zip -d replica_bundle
unzip -o auditor_bundle.zip -d auditor_bundle
```

Then stop the server on A at once (Ctrl+C), because `replica_bundle.zip`
holds the ledger token, and remove the rule:

```
Remove-NetFirewallRule -DisplayName "ztsdn-transfer"
```

## 3. Replica n1 (laptop A, Windows side)

You need Python 3 installed **on Windows**, not just in WSL (from python.org
or the Microsoft Store), then:

```
py -3 -m pip install pyyaml
```

Unzip `C:\ztsdn\replica_bundle.zip`. In an **Administrator** PowerShell:

```
cd C:\ztsdn\replica_bundle
powershell -ExecutionPolicy Bypass -File replica_n1.ps1
```

The first run adds the firewall rule for ports 9001 and 9101. Leave the
window open: it is the replica.

## 4. Replicas n2 and n3 (Mac)

Unzip `replica_bundle.zip`. PyYAML is the only dependency. Homebrew's Python
refuses `pip install --user` ("externally-managed-environment"), so use a
venv:

```bash
cd ~/Downloads/replica_bundle          # wherever it unzipped
python3 -m venv .venv && .venv/bin/pip install pyyaml
```

Open **two Terminal windows** in that folder. In each one, activate the venv
so the script's `python3` is the venv's, then start one replica:

```bash
source .venv/bin/activate && sh replica_n2.sh
```

```bash
source .venv/bin/activate && sh replica_n3.sh
```

Click **Allow** when macOS asks whether Python may accept incoming
connections. Both replicas share `raft_data/` and each wipes only its own
subfolder.

**Keep the Mac awake** for the whole demo. In a third window:

```bash
caffeinate -dims
```

## 5. Auditor (Mac)

Unzip `auditor_bundle.zip` somewhere else, then:

```bash
cd ~/Downloads/auditor_bundle
sh auditor_mac.sh            # main demo
sh auditor_mac.sh forge      # or: the auditor scene
```

The first run needs internet because it builds a venv with os-ken. Click
**Allow** again. **Restart the auditor for every run**, and use the `forge`
argument only together with `run_controller_A.sh forge`.

## 6. Dashboard access (laptop A, Windows side)

In an Administrator PowerShell, run this once per boot so the Mac can open
the dashboard:

```
powershell -ExecutionPolicy Bypass -File \\wsl$\<distro>\home\<user>\Zero-Trust-Enabled-SDN-Architecture\deploy\demo\portproxy_A.ps1
```

Find `<distro>` with `wsl -l`.

## 7. Check, then run (laptop A, WSL)

Before **every** run, clear any Mininet state a killed run left behind, and
make sure nothing else holds the dashboard or OpenFlow ports. Docker Desktop
containers are the usual culprit: one publishing 8081 makes the dashboard
answer `ERR_EMPTY_RESPONSE`.

```bash
sudo mn -c
ss -ltn | grep -E ":8081|:6653"      # must print nothing
docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep -E ":(8081|6653)->"   # stop any it prints
```

```bash
python3 tools/demo_hosts.py --check --wait-leader 30
```

**Pass** when all three replicas print `OK`, every RAFT port is reachable,
and it prints `OK    leader is nX`. The auditor lines only read `OK` once
`auditor_mac.sh` is running. Then start the demo:

```bash
sh deploy/demo/run_controller_A.sh          # main demo, 240 s
sh deploy/demo/run_controller_A.sh forge    # auditor scene, 180 s
```

Open `http://localhost:8081/` on A and `http://192.168.43.10:8081/` on the
Mac. The pass criteria are the runbook's: the ledger strip reads "Raft
cluster, 3 replicas" with a leader and "0 record(s) refused", and in the
forge scene the Controllers panel shows 9/9 switches read-only.

**Start order every run:** replicas (n1, n2, n3), then the auditor, then
`--check`, then `run_controller_A.sh`.

## Replica-loss scene (replaces "close B's lid")

Closing the Mac's lid stops **two** of the three replicas. The ledger then
has no majority, so it **stalls**, which is the correct RAFT behaviour but the
wrong scene. Instead, mid-run:

- press **Ctrl+C in n3's Terminal window** on the Mac, or
- close **n1's PowerShell window** on laptop A.

The ledger strip should then show that replica's chip drop out. If it was the
leader, the term on the newest block rises. The block count keeps rising
because two of three replicas are still a majority. If the audience asks,
stopping two replicas stalls commits, and that is RAFT refusing to commit
without a majority.

## If something fails

| Symptom | Fix |
|---|---|
| `--check`: n1 unreachable from WSL, but the Mac can reach it | WSL cannot reach its own host's hotspot address (Hyper-V firewall). Switch WSL to mirrored networking: add `[wsl2]` / `networkingMode=mirrored` to `%UserProfile%\.wslconfig`, run `wsl --shutdown`, and reopen WSL. In mirrored mode, **skip `portproxy_A.ps1`**, because WSL already listens on the Windows address; just allow inbound TCP 8081 in the firewall. |
| `--check`: n2/n3 unreachable | The Mac's firewall blocked Python. Open System Settings → Network → Firewall and allow Python, or turn the firewall off for the demo. Check the address with `ipconfig getifaddr en0` again. |
| `HTTP 401 (wrong or missing token?)` | The bundles are from an older `deploy/demo/`. Copy the current zips and unzip them again. |
| No leader after 30 s | One replica has old addresses. Regenerate, copy and restart **all three**. |
| Mac cannot open the dashboard | Re-run `portproxy_A.ps1` (WSL's address changes at every reboot). The dashboard only exists while `run_controller_A.sh` is running. |
| Dashboard gives `ERR_EMPTY_RESPONSE` | Another program holds 8081 inside WSL, usually a Docker container (`docker ps`). Stop it, or quit Docker Desktop for the demo. |
| `Error creating interface pair (…): RTNETLINK answers: File exists` | `sudo mn -c`, then run again. (On 14 Nov this was also a code defect: with an auditor configured, the topology was built twice. Fixed in `simulation/topology.py`.) |
| RAFT commit fails the 500 ms target in `nfr_report` | Hotspot latency spikes force leader elections (14 Nov: mean 46 ms, p95 154 ms, max 1.04 s across two elections). Keep the phone close to both laptops and nothing else on the hotspot. No record is lost. |
| Auditor lines WARN | `auditor_mac.sh` is not running yet, or its first-run os-ken install failed (it needs internet). |

## Fallback ladder (two-laptop version)

1. Everything above.
2. Replicas local on A, with the Mac as a viewer only: on A, run the
   runbook's section 1 commands (`config/params_review_demo.yaml` starts
   all three replicas itself) plus `portproxy_A.ps1`, and open
   `http://192.168.43.10:8081/` on the Mac.
3. Laptop A alone.
4. Replay: `python3 -m dashboard.replay data/events_review_demo.jsonl --loop`
   (port 8082).

## Status (14 Nov)

**Main demo, run across the two real laptops on the phone hotspot: passed**
(recording `data/events_review_demo_remote.jsonl`):

- the ledger ran as a Raft cluster of n1 (A, Windows) and n2/n3 (Mac), all
  three on the same chain and leader, 336 blocks, 0 records refused; WSL
  reached n1 on its own Windows host address without mirrored networking;
- no honest server (srv2, srv4, srv5, srv7) was ever quarantined; all four
  attacking servers were; the witness held srv6 and srv1 and released srv1;
- the auditor on the Mac held all 9 switches as SLAVE and named the same
  droppers (srv1, srv6) as the primary;
- labels: srv1 grayhole, srv6 blackhole (marginal: median timeout rate at
  the 0.85 cutoff), srv8 onoff and every device label correct. **srv3 is
  labelled onoff, not sybil**: once quarantined it gets almost no traffic to
  misreport on, and the classifier counts those quiet cycles as an off
  phase. Detection and isolation are unaffected;
- NFR report: routing, isolation and ledger overhead pass; the Raft commit
  target fails on its maximum (see "If something fails").

**Not yet run on two laptops:** the auditor scene (`forge`) and the
replica-loss scene.
