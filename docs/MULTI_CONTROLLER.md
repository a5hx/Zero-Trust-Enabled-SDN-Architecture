# Multi-Controller: a Standby That Can Take Over

Branch `feature/multi-controller` (from 62179b1, after the 16 Nov review demo).
Today the controller is the one component whose failure, or whose lying, the
system can **detect** but not **survive**: the auditor (`controller/auditor.py`)
sees a forged score or a missing quarantine, the ledger replicas keep the
record, but nobody can take over routing. This work adds a second controller
that can take over, while only one controller ever acts at a time.

**Status:** step 1 (fencing) is built and unit-tested; nothing is run live yet.
Off by default: with `controller.fencing.enabled` unset, the controller sends
no role request and behaves exactly as on `feature/review-demo`.

---

## 1. What the literature already covers

| Work | What it does | Cost / assumption |
|---|---|---|
| Ravana (Katta et al., SOSR 2015) | Crash-tolerant replicated controller; exactly-once events and commands | Crash faults only; needs switch-side changes (buffers, acks) |
| Rama (Mantas & Ramos, arXiv 1902.01669) | Ravana's guarantees with unmodified OpenFlow switches (bundles, role messages) | Crash faults only |
| AR2C2 (NOMS 2016) | Actively replicated controllers | Crash faults |
| MORPH (Sakic, Đerić, Kellerer, IEEE JSAC 2018, arXiv 1902.02560) | Byzantine-tolerant: replicas compute every config, switches accept what enough agree on | 2F_M + F_A + 1 controllers, all computing in parallel |
| P4BFT (Sakic et al., arXiv 1905.04064) | Compares controller outputs inside P4 switches | Programmable switches; still replicas voting |
| SDBFT (Gardiner, Lancaster thesis 2024) | BFT controller replication | 3f+1 replicas |
| SPHINX (NDSS 2015) | Detects data-plane attacks from flow graphs | Assumes the controller is trusted |
| Fencing tokens (Kleppmann, *Designing Data-Intensive Applications*, ch. 8) | A monotonically increasing token a storage service checks, so a stale lock holder cannot write | Needs the *resource* to check the token |

**The gap.** Byzantine work makes the controller trustworthy by **replication
and voting**: many controllers compute the same output and the switch (or a
P4 stage) accepts the majority. Crash work (Ravana, Rama) assumes controllers
fail by stopping. Nothing found uses a **second, independent controller that
audits the acting one from data-plane evidence** (switch counters, the
ledger's replayable record) and takes over only when the evidence says the
acting one is wrong. That is cheaper (one controller acts; the other only
reads) and it reuses what this project already has: the auditor, the switch
witness, and `TrustReplay`. The claim to test is that independent evidence plus
a single fenced takeover catches the lies we measure (score forgery, evidence
forgery, dropped quarantines) with one standby, where voting needs 3f+1.

What it does **not** claim: tolerance of a lie the evidence cannot see (a
controller that routes subtly badly but within every audited bound), or of two
colluding controllers.

---

## 2. Design: one writer per generation

### 2.1 The generation register (in the ledger's Raft log)

A **generation** is a counter replicated by the ledger cluster that already
exists (`blockchain/commit_backend.py`, `blockchain/raft_replica.py`). A
controller claims it with a compare-and-set entry:

```
{"kind": "controller_claim", "controller_id": "primary", "expect": 3, "timestamp": ...}
```

Applied on every replica in log order: granted iff the current generation
equals `expect`; then generation = expect + 1 and holder = controller_id. Two
controllers racing for the same `expect` cannot both win, because the log
orders them. The replica API:

| Endpoint | Does |
|---|---|
| `GET /controller` | `{generation, holder}` (leader only; others answer 409 with a leader hint) |
| `POST /controller/claim` `{controller_id, expect}` | 200 with `{granted, generation, holder}`, 409 off-leader, 400 on a bad body |

`RemoteRaftBackend.claim_generation(controller_id, takeover=False)` refuses,
without writing, when another controller holds the generation; a restart under
the same id takes a fresh generation (so the old process's token dies with it).
Only `takeover=True` claims over another holder; that is what the standby will
call (step 3).

### 2.2 Fencing at the ledger

Every trust batch carries the generation (`commit_ex(..., generation=g)`).
Once any generation has been claimed, a replica refuses a batch whose
generation is missing (`no_generation`), older than current
(`stale_generation`), or newer / not an integer (`unknown_generation`). The
check runs before the trust verifier, and a refusal is **not** cached, so the
same rows resent under the current generation commit normally. A deposed
controller therefore cannot rewrite the trust record, whatever it does to the
switches.

### 2.3 Fencing at the switches (OpenFlow roles)

The controller asks each switch for `ROLE_MASTER` with `generation_id = g`
(`controller/fencing.py`, `controller/trust_balancer.py`). OpenFlow 1.3 §6.3.5
and Open vSwitch then do the rest:

* a request with an older generation_id is refused `OFPRRFC_STALE`
  (comparison is a signed 64-bit difference, so it survives wrap-around);
* a new MASTER demotes the previous MASTER to SLAVE;
* a SLAVE's FlowMods are refused `OFPBRC_IS_SLAVE`.

The primary installs **nothing** on a switch until the switch has confirmed it
as MASTER (`Fence.may_write`); packet-ins from an unconfirmed switch are
ignored. Any STALE reply, SLAVE reply, or IS_SLAVE error marks the controller
*fenced*: it drops every datapath and publishes `controller_fenced` to the
dashboard. The auditor asks for SLAVE under the current generation (read from
`GET /controller`), and re-reads it when a switch refuses.

### 2.4 The EQUAL hole

Every OpenFlow connection starts in role **EQUAL**, and EQUAL can write. A new
MASTER demotes only other MASTERs, so an EQUAL controller is never demoted,
and a stale request leaves the connection EQUAL. An honest controller that has
been fenced stops; a **dishonest** one can stay EQUAL and keep writing. Roles
alone cannot close this. Closing it needs the switch's management plane:
removing the deposed controller's target from the bridge
(`ovs-vsctl set-controller <br> <remaining targets>` or the OVSDB equivalent),
done by the takeover path through an agent on the switch host. Until that is
built the takeover protects against a crashed or honest-but-stale primary
fully, and against a lying one at the ledger only.

`tools/role_fencing_check.py` confirms each of these behaviours on the real
Open vSwitch, including step 9, which shows whether EQUAL writes go through.

---

## 3. What is built (step 1)

| Piece | File |
|---|---|
| Generation register, claim entries, ledger fencing | `blockchain/commit_backend.py` (`CONTROLLER_CLAIM`, `ClaimResult`, `RaftBackend.claim_generation`, `_generation_check`, `RemoteRaftBackend.claim_generation`, `find_remote`) |
| Replica endpoints | `blockchain/raft_replica.py` (`GET /controller`, `POST /controller/claim`, `generation` on `/commit`) |
| Role state machine | `controller/fencing.py` (`FencingConfig`, `Fence`) |
| Primary: claim at start, MASTER handshake, fenced shutdown | `controller/trust_balancer.py` |
| Auditor: SLAVE under the current generation | `controller/auditor.py` |
| Dashboard log lines (`controller_generation`, `controller_role`, `controller_fenced`) | `dashboard/index.html` |
| Tests | `tests/test_fencing.py` |
| Live OVS probe | `tools/role_fencing_check.py` |

Config, in the controller block (needs `ledger.backend: raft_remote`; the
controller refuses to start with fencing on and any other ledger):

```yaml
controller:
  fencing:
    enabled: true
    controller_id: primary
```

Test suite: 1564 passed, 23 skipped, 0 failed (`tests/` + `base_model/tests/`).

### How to verify it

1. **Unit tests** (no root): `python3 -m pytest -q tests/test_fencing.py`.
2. **The switch behaves as assumed** (root, no Mininet):
   `sudo python3 tools/role_fencing_check.py`. Checks 1–8 must PASS; step 9
   is reported for the record (the EQUAL hole, 2.4).
3. **Live run** with `config/params_mc_fencing.yaml` (the review-demo config
   plus fencing and the local auditor, 120 s):
   `sudo python3 run_demo.py --mode mininet --config config/params_mc_fencing.yaml`.
   Expected:
   * dashboard log: "primary holds controller generation 1", then one
     "this controller is master (generation 1)" line per switch;
   * `sudo python3 tools/fencing_status.py` in a second terminal:
     `generation 1 held by 'primary'`, and on every switch
     `tcp:127.0.0.1:6653=master  tcp:127.0.0.1:6654=slave`;
   * routing, quarantines and ledger blocks as on an unfenced run.
4. **Ledger fencing, live:** during the run,
   `python3 tools/fencing_status.py --claim standby` takes generation 2. From
   then on the dashboard shows "replica … refused the trust record …
   stale_generation" for every batch the primary sends, and the ledger stops
   growing. The switches still list the primary as master: nothing has asked
   them for MASTER under generation 2 yet (that is the standby, step 2).

### Results, 15 Nov 2026 (laptop A, WSL2, Mininet 9 switches)

* `role_fencing_check.py`: checks 1–8 PASS. Step 9: after being demoted and
  refused as stale, controller A asked for EQUAL, was granted it, and **its
  FlowMod was accepted**. The EQUAL hole (2.4) is real on this OVS.
* Live run (`data/events_mc_fencing.jsonl`): `primary` claimed generation 1;
  all 9 switches confirmed it MASTER (18 `controller_role` events: pending,
  then master, per switch) and the auditor SLAVE.
* Takeover at 22 s (`fencing_status.py --claim standby`, generation 2): 28
  blocks committed before it, **0 after**; 580 trust records refused, every
  one `stale_generation`. No `controller_fenced`: the primary kept routing and
  kept sending batches, because nothing told it about the new generation.
  An honest primary should treat its first `stale_generation` refusal as
  being fenced and stop (next steps, item 0).

---

## 4. Next steps

0. **Stand down on a ledger refusal.** A primary whose batch is refused as
   `stale_generation` marks itself fenced (`controller_fenced`) and stops
   writing to the switches, as it already does on a switch's STALE reply.
1. **Standby mode.** A second TrustBalancerApp started with
   `controller.role: standby`: connects as SLAVE under the current generation,
   reads switches and the ledger, writes nothing. In practice the auditor
   grows into it.
2. **Takeover triggers.**
   * *Crash:* the primary heartbeats into the ledger (or holds a lease); the
     standby takes over after N missed beats.
   * *Caught lying:* the auditor's disagreement (score forgery, evidence
     forgery, missing quarantine) beyond a threshold triggers takeover.
3. **State restore on takeover.** Trust from the ledger (`TrustReplay` over the
   committed batches, which the standby verifies anyway); quarantines from
   the switches' flow tables; meters re-probed. Then
   `claim_generation(takeover=True)` and MASTER under the new generation, which
   demotes the old primary everywhere at once.
4. **Close the EQUAL hole.** A switch-host agent removes the deposed
   controller's target on takeover (2.4).
5. **Client report mirror.** Client load reports go to both controllers, so the
   standby's witness has the same inputs without trusting the primary.
6. **Experiments**, each with its prediction registered in `docs/predictions/`
   before the run:
   * `mc_control` – fencing on, no fault: overhead against the single-controller run;
   * `mc_crash` – kill the primary mid-run: time to takeover, requests lost;
   * `mc_forge_score` – primary forges trust scores: detection and takeover time;
   * `mc_forge_evidence` – primary forges witness evidence: same.
7. **Dashboard.** Both controllers' roles, the current generation, and a
   takeover timeline.
