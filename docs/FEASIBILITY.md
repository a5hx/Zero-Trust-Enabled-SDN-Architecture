# Feasibility of the planned mechanisms on the development host

Run with `sudo tools/feasibility_check.sh`, which installs nothing. Its report
goes to `logs/feasibility_<UTC>.txt`. Host: WSL2, kernel
6.18.54.1-microsoft-standard-WSL2, Ubuntu 24.04, cgroup v2 only.

## Result of 2026-10-19 18:04 UTC: all three PASS

| Check | Needed by | Result |
|---|---|---|
| cgroup v2 `cpu.max` | Phase 3, emulated hardware classes and thermal throttling | **PASS.** A 3 s busy loop capped at `25000 100000` used 0.776 s of CPU (0.26 of one core) and was throttled for 31 periods. |
| bpftrace on `tracepoint:sched:sched_switch` | Phase 5, kernel witness | **PASS.** 883 context switches counted in 2 s. |
| BCC kprobe on `tcp_v4_connect` | Phase 5, kernel witness | **PASS.** Compiled and attached. |
| swtpm (socket mode) + tpm2-tools | Phase 4, optional TPM-backed quote | **PASS.** Startup, PCR read (sha256 PCR 0 and 10) and RNG all worked. |

## What this settles

- **Phase 3 uses cgroup v2 directly**, writing `/sys/fs/cgroup/ztsdn/<srv>/cpu.max`
  for each agent PID. Mininet's `CPULimitedHost` is not used: it calls `cgcreate`
  with the v1 controllers `cpu,cpuacct,cpuset` and writes v1 `tasks` files, and
  this host has neither.
  - Because Mininet hosts share the root PID namespace, the harness (running as
    root) can place each agent in its own group.
  - Unlike a work multiplier, a CPU cap also slows the agent's `/status` replies,
    which is what real throttling does to the latency tell.
- **Phase 5 can use BCC from Python**, and bpftrace for quick probes.
  `unprivileged_bpf_disabled=2`, so both need root, as the live runs already do.
- **Phase 4 can offer a TPM-backed quote** through swtpm in socket mode
  (`TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=2321`). There is no `/dev/tpm0`,
  because the kernel lacks `TCG_VTPM_PROXY`. Each server needs its own swtpm
  instance and port.
  - The pure-software Ed25519 quote remains the default and the fallback.
  - Neither is a hardware root of trust. Keylime is not packaged for this
    distribution and is out of scope.
