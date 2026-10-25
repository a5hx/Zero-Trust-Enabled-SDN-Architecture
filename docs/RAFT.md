# RAFT Consensus for the Trust Ledger

The trust ledger (`blockchain/`) started single-replica: `LocalLedgerBackend`
appends straight to an in-memory `Ledger`, no consensus, no fault tolerance.
`blockchain/raft.py` built and unit-tested a transport-agnostic RAFT core
(Ongaro & Ousterhout, "In Search of an Understandable Consensus Algorithm,"
USENIX ATC 2014) in isolation, against a virtual-clock `InMemoryNetwork`, to
prove the paper's five safety properties (`tests/test_raft.py`, R-01–R-18)
before anything touched a socket. This document covers the second half: a
real TCP transport, a `RaftBackend` that turns RAFT's async commit into the
synchronous `CommitBackend` the controller already expects, and a live
3-replica demo with measured commit latency.

**Wired into the controller (October 2026), opt-in.** With a `ledger:` block
set to `backend: raft_remote` (see `config/params_trust_raft.yaml`), the
controller commits every trust-update batch to a separate 3-replica cluster.
Without that block it uses `LocalLedgerBackend`, exactly as every earlier live
run did. See "Controller integration" below.

---

## What's built

| Piece | File |
|---|---|
| Consensus core (leader election, log replication, safety) | `blockchain/raft.py` — unchanged by this work |
| TCP `Transport` | `blockchain/raft_transport.py` |
| `RaftBackend(CommitBackend)` | `blockchain/commit_backend.py` |
| Standalone replica process + HTTP control API | `blockchain/raft_replica.py` |
| 3-replica live demo (spawn / commit / kill / recover) | `blockchain/raft_demo.py` |

## TCP Transport

`RaftNode` only needs one method from its transport: `send(src, dst,
message) -> None`, fire-and-forget (`blockchain/raft.py`'s `Transport`
Protocol). `TcpTransport` implements it over persistent TCP connections
(one per peer, opened lazily, reused), with a small length-prefixed JSON wire
format for the four RPC dataclasses (`RequestVote`, `RequestVoteReply`,
`AppendEntries`, `AppendEntriesReply`).

**JSON, not pickle.** These sockets face the network, and pickle
deserializes arbitrary code on load — an unacceptable attack surface for a
project whose whole thesis is zero trust. Every RPC round-trips through
plain dicts cleanly.

`RaftNode` did not change at all to use this transport — that is the point
of the seam its own module docstring commits to. Only the transport's own
contract is tested (`tests/test_raft_transport.py`): it delivers what was
sent to whoever asked to receive it, over real sockets. RAFT's safety
properties are not re-proven against it; that would just be re-running
`tests/test_raft.py` against a slower, flakier transport for no new
information.

## RaftBackend

`RaftBackend` owns a `RaftNode` and turns its asynchronous, log-index-based
commit signal into the synchronous `commit(updates) -> Optional[Block]` the
`CommitBackend` Protocol promises. `commit()` blocks on a `threading.Event`
until the entry it just proposed is actually applied (majority-replicated),
or `commit_timeout_s` elapses.

**Only the leader can commit** — mirrors `RaftNode.client_append`'s
leader-only contract. A follower's `commit()` returns `None` immediately,
same as a timed-out or rejected commit.

### The bug that shaped the design: what gets replicated

The first version replicated the whole `Block` — leader builds it, log entry
payload *is* the finished block, every replica just deserializes and
`Ledger.append()`s the identical object. Two real bugs came out of testing
that against a live 3-replica cluster (`tests/test_commit_backend.py`):

1. **Non-deterministic genesis.** `Ledger.__init__` built its genesis block
   with `Block`'s default `timestamp=time.time()`. Every replica constructs
   its own `Ledger()` independently, at a slightly different wall-clock
   moment, so every replica started from a *different* genesis hash — and
   `timestamp` is inside `Block.compute_hash()`'s preimage, so every block
   after it diverged too. Fixed by pinning genesis's timestamp to `0.0`
   (`blockchain/ledger.py`) — it carries no real data, so a fixed anchor
   costs nothing.

2. **Stale ledger snapshot at proposal time.** A newly-elected leader is only
   guaranteed to have every entry in its RAFT *log* (Election Safety) — not
   to have already *applied* every earlier entry to its own `Ledger`.
   Entries commit indirectly, in a batch, once a higher-term entry above them
   commits (`RaftNode._advance_commit_index`'s current-term restriction). So
   a fresh leader's `_ledger.get_chain_length()` can be stale exactly when it
   proposes its first block, and two replicas built colliding
   `index`/`previous_hash` values for what RAFT correctly ordered as two
   distinct log entries. `tests/test_commit_backend.py`'s
   `test_killing_the_leader_lets_the_cluster_recover_and_keep_committing`
   catches this directly.

**The fix:** the log entry payload carries only *content* the leader
uniquely decides — `timestamp`, `proposer_id`, `raft_term`, `trust_updates`
(`blockchain/commit_backend.py::_entry_payload`) — never a chain *position*.
`index`, `previous_hash`, and `merkle_root` are computed independently by
*each* replica inside `RaftBackend._on_apply`, at the moment that specific
entry is applied. That's safe because `RaftNode._apply_committed` always
applies entries one at a time, in strict log order — by the time entry N is
applied on a given replica, entry N-1's block (if it had one) is already in
that same replica's ledger. `merkle_root` doesn't need to travel at all: it's
a pure function of `trust_updates`, which does. `timestamp` is the one
exception with no other canonical source, so it must travel — a replica that
stamped its own wall clock at apply time would again hash the "same" block
differently on every node.

### Thread safety

`drive_tick`/`drive_receive` run on a driver thread (the replica process's
`Ticker`, or a test's driver) while `commit()` is called from a controller
thread. A single `RLock` guards all `RaftNode`/`Ledger` access — RLock,
because `_on_apply` (RAFT's own `apply_fn` callback) re-enters it from inside
whatever call is already holding it (`tick`, `receive`, or `client_append`).
`commit()` releases that lock while it waits for its entry to commit —
holding it there would deadlock the driver thread trying to process the very
`AppendEntriesReply` that completes that commit — so a second lock,
`_commit_lock`, serializes whole `commit()` calls end-to-end; without it, two
interleaved proposals could each build against the same stale ledger tip
before either committed.

## Live demo: 3 replicas, real TCP, real kill

`blockchain/raft_demo.py` spawns three `blockchain.raft_replica` **processes**
on localhost — real OS process boundaries, real loopback TCP sockets, real
`SIGTERM` — waits for a leader, submits commits over each replica's HTTP
control API (`POST /commit`), measures wall-clock latency (HTTP round trip
included, so it's what a real client observes), kills the leader outright,
waits for the survivors to elect a new one, and keeps committing.

Disclosed plainly, the same way `evaluation/baseline.py` discloses it is a
simulation and not a Mininet run: this is three processes on one machine, not
three physically separate hosts. The RAFT code, the sockets, and the process
boundaries are all real; only the hardware separation is not.

```
python3 -m blockchain.raft_demo --commits 50 --commit-interval-s 0.02
```

### Measured result

Two runs, 50 commits each phase, on the WSL2 box this project runs on:

| phase | commits | mean | median | max | NFR (<500ms) |
|---|---:|---:|---:|---:|---|
| before kill | 50/50 | 4.8ms | 3.9ms | 41.5ms | PASS |
| after recovery | 50/50 | 4.3ms | 3.8ms | 29.4ms | PASS |

Leader failover took **0.22s** (new leader elected, both runs) — inside the
deck's separate <3s isolation NFR too, for reference, though that NFR was
written about attacker isolation, not RAFT recovery specifically.

Commit latency sits two orders of magnitude under the 500ms NFR because the
cluster is 3 processes on one loopback interface with no real network
latency; a WAN-deployed cluster would see this number dominated by the
majority round trip instead of local scheduling overhead. The number is
still an honest measurement of the built system, not a simulation — same
caveat `evaluation/baseline.py` states about its own results, the same
discipline applied here.

## Controller integration

The controller is a **client** of the cluster rather than a replica in it. The
replicas are separate `blockchain/raft_replica.py` processes (on a real
testbed, separate machines), each with its own ticker, so nothing in the
controller drives elections. Three pieces, all in `blockchain/commit_backend.py`:

- **`RemoteRaftBackend`** posts each batch to the replica it believes is
  leader (`POST /commit`), follows the `leader_id` hint in a 409, and moves on
  to the next replica on a connection error. Every committed block comes back
  in full and is appended to a local **mirror** `Ledger`, which re-validates
  index, previous hash, Merkle root and hash itself. The mirror backs
  `/ledger/verify` and the dashboard; if it ever disagrees with the cluster it
  is rebuilt from `GET /blocks?from=1`.
- **`AsyncCommitter`** takes commits off the report path:
  `TrustState._flush_pending_locked` hands it the batch and returns at once,
  and one worker commits batches in order, retrying with backoff until the
  cluster accepts each one. A leadership change delays trust records; it no
  longer loses them. A full queue drops explicitly and counts it.
- **Idempotent commits.** Each batch carries a content hash (`batch_key`).
  A replica that has already applied a batch returns the existing block, and
  a batch that reached the log twice is applied once, on every replica alike.
  This is what makes the client's retries safe.

Replicas persist term, vote and log under `--data-dir` (`raft.FileStorage`),
so a killed replica rejoins with its log. `--auth-token-env` makes every
replica endpoint require a bearer token.

`run_demo.py --mode mininet` starts the replicas itself when the config has
`ledger.launch_local`, waits for a leader, then starts the controller.
`GET /ledger/status` on the controller reports queue depth, retries, the
leader last used and the last error.

**Measured (localhost, 3 replica processes, real TCP, 15 Oct 2026):** 60
batches submitted 50 ms apart, leader killed after batch 25. Two attempts
failed during the election and were retried; all 60 batches committed exactly
once, in order, on a valid chain, across terms 2 and 3 (proposers n2, then
n3). Handing a batch to the queue took at most 0.08 ms.

**Acceptance check for a live run:** every `block` event in the recording has
`raft_term > 0` and a replica id as `proposer_id`; killing the leader mid-run
leaves submitted = committed in `/ledger/status`.

---

## Re-verification: the replicas check the controller's arithmetic (Phase 6)

With `ledger.verify: true`, every replica is started with `--verify-config`
(the run's config) and replays the trust formula from the evidence carried in
each committed record (`blockchain/verifier.py`). For each record it checks
that `trust_score_before` equals the score its own replay holds for that node,
and that `trust_score_after` equals what its replay computes from the record's
evidence. Records that fail are not appended; they come back to the
controller and are published as `ledger_rejected` events.

- **Deterministic.** Entries apply in log order on every replica, the floats
  round-trip exactly through JSON, and the replay always advances on the
  evidence, so every replica reaches the same verdict and appends the same
  block. One forged score costs at most two records (its own, and the next
  record's `before`), never a cascade.
- **A batch with a different trust configuration** (the controller sends the
  hash of its `trust:` block with every batch) is rejected whole and does not
  advance the replay.
- **A batch rejected whole** gets HTTP 422 from `/commit`;
  `RemoteRaftBackend` raises `BatchRejected` and `AsyncCommitter` drops it from
  the queue. Before this, a batch the cluster refused would have been retried
  forever and blocked every later one.
- **What it cannot catch:** forged *evidence*. A controller that reports a
  timeout as a success writes a record whose arithmetic is honest. Only an
  independent witness of the evidence (the switch witness, the clients) can
  contradict it. And routing reads the controller's in-memory score, so a
  rejection detects a forgery after the fact; it does not prevent it.
- **Test-only forgery:** `controller.debug_forge_trust` (`controller/forgery.py`),
  refused unless `ZTSDN_ALLOW_FORGERY=1`. Arms: `config/params_lv_*.yaml`;
  prediction: `docs/predictions/ledger_2026-10-22.txt`; scorer:
  `python3 -m evaluation.ledger_report`.

---

## Known limitations

- **Redirect lives in the client.** A follower's `commit()` (and
  `POST /commit`) still returns `None`/`409` rather than forwarding.
  `RemoteRaftBackend` does the redirect (following `leader_id`) and
  `AsyncCommitter` the retry, so the controller survives a leadership change;
  any *other* client must do the same.
- **Opt-in, and not yet run live under Mininet.** The default is still
  `LocalLedgerBackend`; no recorded Mininet run uses the replicated ledger yet.
  Run `config/params_trust_raft.yaml` to produce the first one.
- **Crash-fault, not Byzantine**, matching `PROBLEM_AND_IMPACT.md` §4. A
  malicious replica could lie. Persistence is opt-in (`--data-dir`); without
  it a restarted replica still rejoins empty. No log compaction yet: the log
  file grows with the run.
- **Localhost demo, not multi-host.** See the disclosure above.
