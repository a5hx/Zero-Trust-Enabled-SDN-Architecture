#!/usr/bin/env python3
"""Preflight for a recorded live run. Complements scripts/wsl_preflight.sh.

That script gets the *box* ready (OVS, qdisc modules, stale namespaces). This
one gets the *run* ready, and its main job is the lesson from panel_fix.md
§3.16: a fix that can silently fall back needs a check that it is actually in
effect, not merely that it does no harm. The first `_device_roster` returned
`{}` and would have shipped into a live run looking exactly like success.

So this exercises the real controller entry point under the real config and
asserts the behaviour a run is meant to demonstrate, rather than trusting that
the code is present.

    python3 scripts/preflight_live_run.py [--config config/params_trust_full.yaml]

Exit code 0 means the run is safe to start. No root required.
"""

from __future__ import annotations

import argparse
import shutil
import socket
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml  # noqa: E402

DEFAULT_CONFIG = 'config/params_trust_full.yaml'
MIN_FREE_MB = 2048

_problems: list[str] = []
_warnings: list[str] = []


def ok(msg: str) -> None:
    print(f"    \033[32mOK\033[0m    {msg}")


def bad(msg: str) -> None:
    print(f"    \033[31mFAIL\033[0m  {msg}")
    _problems.append(msg)


def warn(msg: str) -> None:
    print(f"    \033[33mWARN\033[0m  {msg}")
    _warnings.append(msg)


# --------------------------------------------------------------------------- #
def check_recording_is_archived(events_path: str) -> None:
    """run_demo.py unlinks the recording at startup. If the file sitting there
    is not byte-identical to one of the data/events_run*.jsonl archives, that
    unlink destroys the only copy -- and the archives are the whole evidence
    base every finding in panel_fix.md is re-derived from."""
    print("==> Recording safety")
    live = Path(events_path)
    if not live.exists():
        ok(f"{events_path} absent — nothing to lose")
        return

    archives = sorted(live.parent.glob('events_run*.jsonl'))
    size = live.stat().st_size
    for arc in archives:
        if arc.stat().st_size == size and _same_bytes(live, arc):
            ok(f"{events_path} is byte-identical to {arc.name} — already archived")
            return
    bad(f"{events_path} ({size/1e6:.0f} MB) matches no archive in data/. "
        f"Starting a run DELETES it. Archive it first: "
        f"cp {events_path} data/events_runN.jsonl")


def _same_bytes(a: Path, b: Path, chunk: int = 1 << 20) -> bool:
    with a.open('rb') as fa, b.open('rb') as fb:
        while True:
            ba, bb = fa.read(chunk), fb.read(chunk)
            if ba != bb:
                return False
            if not ba:
                return True


def check_disk(events_path: str) -> None:
    print("==> Disk")
    free_mb = shutil.disk_usage(Path(events_path).parent).free / 1e6
    if free_mb < MIN_FREE_MB:
        bad(f"only {free_mb:.0f} MB free; a 300 s run records ~130 MB "
            f"and the NFR report re-reads all of it")
    else:
        ok(f"{free_mb/1000:.0f} GB free")


def check_ports(cfg: dict) -> None:
    print("==> Ports")
    api_port = int(cfg['controller']['api_port'])
    for port, what in ((6653, 'OpenFlow'), (api_port, 'northbound API + dashboard')):
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(('127.0.0.1', port))
            except OSError:
                bad(f"port {port} ({what}) is already bound — a previous "
                    f"controller is still running; kill it or the run silently "
                    f"records against the wrong process")
            else:
                ok(f"port {port} free ({what})")


def check_inventory(cfg: dict) -> None:
    """Every address the controller will install into a rule must be real.

    Under Mininet the inventory is generated (simulation/addressing.py) and
    there is nothing to probe before the network exists. A configured
    inventory is a real testbed: each server must answer /status from this
    machine, and controller_ip must be one of this machine's addresses, or the
    health-check carve-out in the quarantine rules matches nothing.
    """
    import http.client
    from contracts.inventory import Inventory, InventoryError

    print("==> Inventory")
    try:
        inv = Inventory.from_config(cfg)
    except InventoryError as exc:
        bad(f"inventory does not load: {exc}")
        return
    if inv.source == 'mininet':
        ok(f"generated from simulation/addressing.py: {len(inv.servers)} servers, "
           f"{len(inv.devices)} devices (Mininet)")
        if not inv.devices:
            warn("no devices in the roster -- every identity falls back to trust-on-first-use")
        return

    ok(f"configured: {len(inv.servers)} servers, {len(inv.devices)} devices")
    try:
        with socket.socket() as s:
            s.bind((inv.controller_ip, 0))
        ok(f"controller_ip {inv.controller_ip} is an address of this machine")
    except OSError:
        bad(f"controller_ip {inv.controller_ip} is not an address of this machine -- "
            f"/status polls will come from elsewhere and quarantine will drop them")
    port = int((cfg.get('agents') or {}).get('node_port', 8000))
    for nid in inv.server_ids:
        ip = inv.server_ip(nid)
        try:
            conn = http.client.HTTPConnection(ip, port, timeout=1.5)
            conn.request('GET', '/status')
            status = conn.getresponse().status
            conn.close()
        except OSError as exc:
            bad(f"{nid} ({ip}:{port}) unreachable: {exc}")
            continue
        (ok if status == 200 else bad)(f"{nid} ({ip}:{port}) /status -> HTTP {status}")
    if not inv.devices:
        warn("inventory.devices is empty -- every identity falls back to trust-on-first-use")


def check_ledger(cfg: dict) -> None:
    """The replicated ledger: replicas up (external cluster) or their ports
    free (run_demo.py will start them)."""
    import http.client
    from blockchain.commit_backend import parse_replicas

    ledger = cfg.get('ledger') or {}
    print("==> Ledger")
    if ledger.get('backend', 'local') == 'local':
        ok("local single-replica ledger (no ledger: block)")
        return
    replicas = parse_replicas(ledger['replicas'])
    if ledger.get('launch_local'):
        raft_ports = parse_replicas(ledger['launch_local']['raft_peers'])
        for rid, addrs in (('control', replicas), ('raft', raft_ports)):
            for nid, (host, port) in addrs.items():
                with socket.socket() as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    try:
                        s.bind((host, port))
                    except OSError:
                        bad(f"replica {nid} {rid} port {host}:{port} already bound -- "
                            f"a replica from an earlier run is still alive")
                        continue
                ok(f"replica {nid} {rid} port {port} free (run_demo.py starts it)")
        return
    leaders = []
    for nid, (host, port) in replicas.items():
        try:
            conn = http.client.HTTPConnection(host, port, timeout=1.5)
            conn.request('GET', '/status')
            body = conn.getresponse().read()
            conn.close()
            import json as _json
            role = _json.loads(body or b'{}').get('role', '?')
        except (OSError, ValueError) as exc:
            bad(f"replica {nid} ({host}:{port}) unreachable: {exc}")
            continue
        ok(f"replica {nid} ({host}:{port}) is {role}")
        if role == 'leader':
            leaders.append(nid)
    if len(leaders) != 1:
        bad(f"expected exactly one leader, found {leaders or 'none'}")


def describe_run(cfg: dict) -> None:
    print("==> Run shape")
    sim = cfg['simulation']
    agents = cfg.get('agents', {})
    ok(f"{sim['num_edge_nodes']} edge / {sim['num_iot_devices']} IoT, "
       f"duration {sim['duration_s']} s")
    attacks = sim.get('malicious_edge_nodes') or []
    names = [f"{a.get('node', '?')}:{a.get('attack', '?')}@{a.get('start_s', '?')}s"
             for a in attacks] if isinstance(attacks, list) else [str(attacks)]
    ok(f"edge attacks: {', '.join(names) or '(none)'}")
    ok(f"flood={sim.get('malicious_flood_devices')} "
       f"spoof={sim.get('malicious_spoof_devices')} "
       f"bad-creds={cfg.get('security', {}).get('malicious_iot_devices')}")
    ok(f"task_timeout_s={agents.get('task_timeout_s')} "
       f"report_interval_s={agents.get('report_interval_s')} "
       f"task_work_ms={agents.get('task_work_ms')}")

    dash = cfg['controller'].get('dashboard', {})
    if not dash.get('enabled'):
        bad("controller.dashboard.enabled is false — the run records NOTHING "
            "and every evaluation/ report will have no input")
    else:
        ok(f"recording to {dash.get('record_path', 'data/events.jsonl')}")


# --------------------------------------------------------------------------- #
def check_resteer_attribution_is_live() -> None:
    """panel_fix.md §3.17. Drives the real handle_client_report, not a mock of
    it, and asserts both halves: an inherited outcome is withheld from trust
    and from the drop tell's window, and a routed one is still charged in full.

    The second half is the one that matters most here -- a fix that made the
    controller stop charging anything would also pass the first."""
    print("==> §3.17 re-steer attribution is in effect")
    from controller.trust_balancer import TrustBalancerApp
    from controller.trust_state import TrustState

    published: list[tuple] = []

    class _Bus:
        def publish(self, topic, **kw):
            published.append((topic, kw))

    class _Backend:
        commit_count = 0

    state = TrustState(node_ids=['srv1', 'srv2'])
    stub = types.SimpleNamespace(state=state, bus=_Bus(), _commit_backend=_Backend())

    # (a) a flow re-steered off a quarantined node
    state.register_dispatch('10.0.0.5', 5000, 'srv1')
    state.reassign_dispatches('srv1', 'srv2')
    before = state.trust_calc.get_score('srv2')
    score = TrustBalancerApp.handle_client_report(
        stub, '10.0.0.5', 5000, 'iot5', 'timeout', 4040.0)

    if score is not None:
        bad("an inherited timeout was still charged — §3.17 is NOT in effect")
    elif state.trust_calc.get_score('srv2') != before:
        bad("an inherited timeout moved the receiving node's trust")
    elif state._recent_statuses['srv2']:
        bad("an inherited timeout entered the packet-drop tell's window — "
            "this is what quarantined srv7 twice in run 10")
    else:
        ok("inherited outcome withheld from trust and from the drop tell")

    if not published:
        bad("nothing published for the inherited outcome — the client's real "
            "loss vanished, which would inflate every availability figure")
    else:
        ev = published[-1][1]
        if ev.get('charged') is not False or ev.get('resteered_from') != 'srv1':
            bad(f"report event lacks the abstention evidence: {ev}")
        elif ev.get('status') != 'timeout' or ev.get('latency_ms') != 4040.0:
            bad("report event lost the fields availability/PDR are measured from")
        else:
            ok("client's loss still published with charged=false, "
               "attribution=resteer_inherited")

    # (b) the anti-evasion half: work the node was actually routed
    published.clear()
    state.register_dispatch('10.0.0.5', 5001, 'srv2')
    before = state.trust_calc.get_score('srv2')
    score = TrustBalancerApp.handle_client_report(
        stub, '10.0.0.5', 5001, 'iot5', 'timeout', 4040.0)
    if score is None or score >= before:
        bad("a ROUTED timeout was not charged — abstention has leaked beyond "
            "re-steered flows and the drop tell is now blind")
    elif [s for _, s in state._recent_statuses['srv2']] != ['timeout']:
        bad("a routed timeout did not reach the drop tell's window")
    else:
        ok("routed outcome still charged in full (anti-evasion half)")

    # (c) occupancy must be untouched by an attribution change
    counted, held = sum(state._inflight.values()), len(state._dispatches)
    if counted != held:
        bad(f"inflight invariant broken: {counted} counted vs {held} held")
    else:
        ok("sum(_inflight) == len(_dispatches) preserved")


def check_ground_truth_is_recorded(cfg: dict) -> None:
    """Without per-node `attack` on the topology event there is no confusion
    matrix -- one of the three event-bus gaps Phase 2 had to close first."""
    print("==> Scoring inputs")
    sim = cfg['simulation']
    attacks = sim.get('malicious_edge_nodes') or []
    if not attacks:
        warn("no edge attacks configured — attack_report will score an "
             "all-honest run")
    else:
        missing = [a for a in attacks if not a.get('attack')]
        if missing:
            bad(f"{len(missing)} malicious_edge_nodes entries have no `attack` "
                f"key — ground truth would be unscorable")
        else:
            ok(f"{len(attacks)} edge attacks carry ground-truth labels")
    starts = [a.get('start_s') for a in attacks if isinstance(a, dict)]
    if starts and all(s is not None for s in starts):
        ok(f"staggered onsets at {sorted(set(starts))} s")


# --------------------------------------------------------------------------- #
def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--config', default=DEFAULT_CONFIG)
    args = p.parse_args()

    cfg = yaml.safe_load(Path(args.config).read_text())
    events_path = cfg['controller'].get('dashboard', {}).get(
        'record_path', 'data/events.jsonl')

    print(f"Preflight for a live run with {args.config}\n")
    check_recording_is_archived(events_path)
    check_disk(events_path)
    check_ports(cfg)
    check_inventory(cfg)
    check_ledger(cfg)
    describe_run(cfg)
    check_ground_truth_is_recorded(cfg)
    check_resteer_attribution_is_live()

    print()
    if _problems:
        print(f"\033[31m{len(_problems)} problem(s) — do not start the run:\033[0m")
        for m in _problems:
            print(f"  - {m}")
        return 1
    if _warnings:
        print(f"\033[33m{len(_warnings)} warning(s):\033[0m")
        for m in _warnings:
            print(f"  - {m}")
    print("\033[32mPreflight clean. Start the run with:\033[0m")
    print("  sudo scripts/wsl_preflight.sh")
    print(f"  sudo python3 run_demo.py --mode mininet --config {args.config}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
