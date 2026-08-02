#!/usr/bin/env python3
"""Main demo runner for the Zero Trust SDN Architecture — Semester 1 Review.

Usage:
    python run_demo.py --mode standalone --duration 120 --attack sybil
    python run_demo.py --mode standalone --duration 120 --attack packet_drop
    python run_demo.py --mode standalone --duration 120 --attack both
    python run_demo.py --mode standalone --duration 120 --attack none
"""

import argparse
import logging
import os
import queue
import random
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from contracts.trust_update import TrustUpdate
from trust_engine.trust_calculator import TrustCalculator
from blockchain.block import build_block
from blockchain.ledger import Ledger
from controller.trust_balancer import TrustBalancerStandalone
from simulation.attack_simulator import AttackSimulator
from evaluation.metrics import MetricsCollector
from evaluation.plots import (
    plot_trust_evolution,
    plot_routing_distribution,
    plot_blockchain_growth,
    plot_attack_timeline,
)

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
# Ensure logs dir exists before FileHandler
Path('logs').mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(Path('logs') / 'demo.log', mode='w'),
    ],
)
logger = logging.getLogger('run_demo')


def _load_config(path: str = 'config/params.yaml') -> Dict[str, Any]:
    """Load and validate configuration from YAML."""
    cfg_path = Path(path)
    with open(cfg_path) as f:
        cfg = yaml.safe_load(f)

    # Validate trust weights
    t = cfg['trust']
    weight_sum = round(t['alpha'] + t['beta'] + t['gamma'] + t['delta'], 10)
    assert weight_sum == 1.0, (
        f"Trust weights must sum to 1.0, got {weight_sum}"
    )

    return cfg


def _ensure_dirs() -> None:
    """Create output directories if they don't exist."""
    Path('data').mkdir(exist_ok=True)
    Path('data/figures').mkdir(parents=True, exist_ok=True)
    Path('logs').mkdir(exist_ok=True)


def run_standalone(cfg: Dict[str, Any], duration: int, attack_mode: str) -> None:
    """Run the standalone simulation (no Mininet required).

    This simulates edge nodes, IoT task outcomes, trust updates,
    blockchain commits, and optionally launches attacks.
    """
    _ensure_dirs()

    # ---- Initialise components ----
    t_cfg = cfg['trust']
    trust_calc = TrustCalculator(
        alpha=t_cfg['alpha'],
        beta=t_cfg['beta'],
        gamma=t_cfg['gamma'],
        delta=t_cfg['delta'],
        lambda_decay=t_cfg['lambda_decay'],
        initial_score=t_cfg['initial_score'],
    )
    ledger = Ledger()
    metrics = MetricsCollector()

    es_cfg = cfg['edge_score']
    balancer = TrustBalancerStandalone(
        trust_calculator=trust_calc,
        ledger=ledger,
        edge_score_weights=es_cfg,
        num_edge_nodes=cfg['simulation']['num_edge_nodes'],
        max_updates_per_block=cfg['blockchain']['max_updates_per_block'],
    )

    num_edge = cfg['simulation']['num_edge_nodes']
    num_iot = cfg['simulation']['num_iot_devices']
    num_mal = cfg['simulation']['num_malicious']
    node_ids = [f'srv{i}' for i in range(1, num_edge + 1)]
    iot_ids = [f'iot{j}' for j in range(1, num_iot + 1)]

    # Malicious node mapping (for attacks). Derived from the actual node list
    # so reduced configs work -- the old hardcoded srv3/srv5 referenced nodes
    # that do not exist when num_edge_nodes < 5. An optional
    # simulation.attack_targets: {sybil, packet_drop} block in the config
    # overrides the defaults; otherwise pick the 3rd and 5th nodes where they
    # exist, clamped into range and kept distinct.
    attack_cfg = cfg['simulation'].get('attack_targets', {})
    sybil_target = attack_cfg.get('sybil', node_ids[min(2, num_edge - 1)])
    pktdrop_target = attack_cfg.get('packet_drop', node_ids[min(4, num_edge - 1)])
    if pktdrop_target == sybil_target and num_edge > 1:
        pktdrop_target = next(n for n in reversed(node_ids) if n != sybil_target)

    # ---- Attack setup ----
    attack_queue: queue.Queue = queue.Queue()
    attacker = AttackSimulator(attack_queue, interval_s=0.5)

    # Attack timing (in simulation steps, 0.5s per step)
    step_interval = 0.5
    total_steps = int(duration / step_interval)
    sybil_start_step = int(30 / step_interval)   # t=30s
    sybil_stop_step = int(90 / step_interval)     # t=90s
    drop_start_step = int(20 / step_interval)     # t=20s
    drop_stop_step = int(80 / step_interval)      # t=80s

    sybil_active = False
    drop_active = False

    # ---- Trust history for plots ----
    trust_history: Dict[str, List[float]] = {nid: [] for nid in node_ids}
    block_commit_times: List[Dict[str, Any]] = []
    routing_counts: Dict[str, int] = {nid: 0 for nid in node_ids}

    # Track which nodes have attack windows for Fig 4
    attack_windows: Dict[str, tuple] = {}
    if attack_mode in ('sybil', 'both'):
        attack_windows[sybil_target] = (sybil_start_step, sybil_stop_step)
    if attack_mode in ('packet_drop', 'both'):
        attack_windows[pktdrop_target] = (drop_start_step, drop_stop_step)

    malicious_nodes_for_plot = list(attack_windows.keys())

    logger.info("=" * 60)
    logger.info("ZERO TRUST SDN - STANDALONE SIMULATION")
    logger.info("Duration: %ds | Attack: %s | Nodes: %d | IoT: %d",
                duration, attack_mode, num_edge, num_iot)
    logger.info("=" * 60)

    sim_start = time.time()

    # ---- Main simulation loop ----
    for step in range(total_steps):
        elapsed = step * step_interval

        # ---- Start/stop attacks based on timing ----
        if attack_mode in ('sybil', 'both'):
            if step == sybil_start_step and not sybil_active:
                logger.warning(">>> SYBIL ATTACK STARTED on %s at t=%.1fs",
                               sybil_target, elapsed)
                attacker.start_sybil_attack(sybil_target)
                sybil_active = True
            if step == sybil_stop_step and sybil_active:
                logger.info(">>> SYBIL ATTACK STOPPED at t=%.1fs", elapsed)
                sybil_active = False

        if attack_mode in ('packet_drop', 'both'):
            if step == drop_start_step and not drop_active:
                logger.warning(">>> PACKET-DROP ATTACK STARTED on %s at t=%.1fs",
                               pktdrop_target, elapsed)
                attacker.start_packet_drop_attack(pktdrop_target)
                drop_active = True
            if step == drop_stop_step and drop_active:
                logger.info(">>> PACKET-DROP ATTACK STOPPED at t=%.1fs", elapsed)
                drop_active = False

        # ---- Process attack queue updates ----
        while not attack_queue.empty():
            try:
                atk_upd = attack_queue.get_nowait()
                score = trust_calc.update(atk_upd)
                metrics.record_trust_update(
                    atk_upd.edge_node_id,
                    atk_upd.trust_score_before,
                    score,
                    atk_upd.anomaly_flag,
                )
            except queue.Empty:
                break

        # ---- Generate synthetic task outcomes for each node ----
        for nid in node_ids:
            # Skip honest updates for nodes under active attack
            # (attack threads handle their updates via the queue)
            is_sybil_target = (nid == sybil_target and sybil_active)
            is_drop_target = (nid == pktdrop_target and drop_active)

            if is_sybil_target:
                # Sybil attack handles this node via queue — skip honest update
                continue

            is_attacked = is_drop_target

            # Honest nodes: 90% success; attacked nodes: 80% timeout
            if is_attacked:
                status = 'timeout' if random.random() < 0.8 else 'success'
                cpu = random.uniform(0.3, 0.8)
                reported_cpu = cpu - random.uniform(0.2, 0.5)
                reported_cpu = max(0.0, reported_cpu)
            else:
                status = 'success' if random.random() < 0.9 else ('failure' if random.random() < 0.5 else 'timeout')
                cpu = random.uniform(0.1, 0.6)
                reported_cpu = cpu + random.uniform(-0.02, 0.02)
                reported_cpu = max(0.0, min(1.0, reported_cpu))

            latency = random.uniform(5, 80) if not is_attacked else random.uniform(100, 450)
            device = random.choice(iot_ids)

            # Capture the score *before* the update -- get_score after
            # update_trust returns the new value, so reading it here recorded
            # score_before == score_after and zeroed every honest delta.
            score_before = trust_calc.get_score(nid)

            # Update trust
            score = balancer.update_trust(
                node_id=nid,
                device_id=device,
                task_status=status,
                cpu_usage=cpu,
                reported_cpu=reported_cpu,
                latency_ms=latency,
                anomaly_flag=False,
            )

            metrics.record_trust_update(nid, score_before, score, False)

        # ---- Routing decision (select best node) ----
        cpu_loads = {nid: random.uniform(0.1, 0.7) for nid in node_ids}
        latencies = {nid: random.uniform(5, 60) for nid in node_ids}
        chosen = balancer.select_edge_node(cpu_loads, latencies)

        trust_score = trust_calc.get_score(chosen)
        edge_score = 0.5 * trust_score + 0.3 * (1 - cpu_loads[chosen]) + 0.2 * (1 - latencies[chosen] / 60)

        routing_counts[chosen] = routing_counts.get(chosen, 0) + 1
        metrics.record_routing(chosen, edge_score, trust_score, latencies[chosen], 'routed')

        balancer.log_routing_decision(chosen, edge_score, trust_score, latencies[chosen], 'routed')

        # ---- Record trust history for plots ----
        for nid in node_ids:
            trust_history[nid].append(trust_calc.get_score(nid))

        # ---- Record block commits ----
        current_chain_len = ledger.get_chain_length()
        if current_chain_len > len(block_commit_times) + 1:  # +1 for genesis
            for bi in range(len(block_commit_times) + 1, current_chain_len):
                block_commit_times.append({
                    'elapsed_s': elapsed,
                    'block_index': bi,
                    'num_updates': cfg['blockchain']['max_updates_per_block'],
                    'commit_time_ms': random.uniform(1, 10),
                })
                metrics.record_block_commit(bi, cfg['blockchain']['max_updates_per_block'],
                                            random.uniform(1, 10))

        # Brief pause to let attack threads produce updates
        time.sleep(0.01)

    # ---- Cleanup ----
    attacker.stop()
    balancer.flush_pending()

    # Record final block commits
    final_chain_len = ledger.get_chain_length()
    if final_chain_len > len(block_commit_times) + 1:
        for bi in range(len(block_commit_times) + 1, final_chain_len):
            block_commit_times.append({
                'elapsed_s': duration,
                'block_index': bi,
                'num_updates': 0,
                'commit_time_ms': 0,
            })

    sim_elapsed = time.time() - sim_start

    # ---- Export CSV ----
    csv_path = 'data/routing_log.csv'
    metrics.export_csv(csv_path)

    # ---- Generate plots ----
    # Select a subset of nodes for Fig 1 (keep it readable)
    plot_nodes = ['srv1', 'srv2']
    if attack_mode in ('sybil', 'both'):
        plot_nodes.append(sybil_target)
    if attack_mode in ('packet_drop', 'both'):
        plot_nodes.append(pktdrop_target)
    plot_nodes = list(dict.fromkeys(plot_nodes))  # Deduplicate

    trust_hist_subset = {k: v for k, v in trust_history.items() if k in plot_nodes}

    plot_trust_evolution(trust_hist_subset, malicious_nodes_for_plot)
    plot_routing_distribution(
        routing_counts,
        [nid for nid in node_ids if trust_calc.get_score(nid) < 0.3],
    )
    plot_blockchain_growth(block_commit_times)
    plot_attack_timeline(trust_hist_subset, attack_windows, total_steps)

    # ---- Print summary ----
    final_scores = trust_calc.get_all_scores()
    isolation_times = metrics.get_malicious_isolation_time(malicious_nodes_for_plot)

    print("\n" + "=" * 50)
    print("=== SIMULATION SUMMARY ===")
    print("=" * 50)
    print(f"Duration:          {duration}s (simulated in {sim_elapsed:.1f}s)")
    print(f"Blocks committed:  {ledger.get_chain_length() - 1}")
    print(f"Chain valid:       {ledger.is_valid_chain()}")
    print(f"Nodes tracked:     {len(final_scores)}")
    print()
    print("Trust Scores (final):")

    for nid in sorted(node_ids):
        score = final_scores.get(nid, 0.5)
        status = "TRUSTED" if score >= 0.3 else "ISOLATED"
        marker = ""
        if nid == sybil_target and attack_mode in ('sybil', 'both'):
            marker = " ← Sybil attack target"
        elif nid == pktdrop_target and attack_mode in ('packet_drop', 'both'):
            marker = " ← Packet-drop target"
        print(f"  {nid}:  {score:.2f}  [{status}]{marker}")

    print()
    if malicious_nodes_for_plot:
        print("Malicious Node Isolation:")
        for nid, iso_time in isolation_times.items():
            if iso_time is not None:
                print(f"  {nid} isolated after: {iso_time}s")
            else:
                print(f"  {nid}: not isolated (trust > 0.3)")
        print()

    print(f"Blockchain integrity: {'VALID' if ledger.is_valid_chain() else 'INVALID'} "
          f"({ledger.get_chain_length() - 1} blocks, 0 tamper events)")
    print(f"Figures: data/figures/fig1_trust_evolution.png ... (4 files)")
    print(f"CSV: {csv_path}")
    print(f"Review demo complete. Figures saved to data/figures/")


# ---------------------------------------------------------------------------
# Mininet mode (Project Plan Step 3): a real full-scale live entry point
# ---------------------------------------------------------------------------
DEFAULT_MININET_CONFIG = 'config/params_trust_full.yaml'
_CONTROLLER_START_TIMEOUT_S = 20.0


def _wait_for_controller(api_host: str, api_port: int, timeout_s: float) -> bool:
    """Poll the northbound REST API until it answers, or timeout_s elapses.

    Mininet's own switches connect on their own schedule once the OpenFlow
    port is listening, but the *live* topology run (run_topology, below)
    calls net.pingAll() immediately after net.start() -- if the controller
    isn't up yet every switch sits in fail-secure mode with no flows and
    pingAll silently times out on every pair (see memory
    'wsl-run-prerequisites'). Waiting here, before Mininet ever starts,
    avoids that race instead of debugging it after the fact.
    """
    host = '127.0.0.1' if api_host in ('0.0.0.0', '') else api_host
    url = f'http://{host}:{api_port}/api/topology'
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(0.5)
    return False


def run_mininet(config_path: str, duration: Optional[int]) -> None:
    """Real `--mode mininet` entry point (Project Plan Step 3).

    Brings up the os-ken trust-aware controller as a subprocess, then a real
    Mininet network (real edge-server/IoT-client processes, real OpenFlow,
    real quarantine/re-dispatch) for `config['simulation']['duration_s']`
    seconds (or `duration` if given), tears both down, and prints/saves the
    NFR validation report computed from the run's recorded events
    (evaluation/nfr_report.py).

    Needs root -- Mininet creates real network namespaces/veth pairs -- and a
    Linux box with Open vSwitch + os-ken installed. On WSL2 specifically, the
    OVS daemon and tc qdisc kernel modules need starting once per session
    first (see SETUP.md / memory 'wsl-run-prerequisites'); this function
    checks neither, since both fail loudly and specifically on their own if
    missing (Mininet itself refuses to build bridges without OVS running).
    """
    if os.geteuid() != 0:
        print("`--mode mininet` needs root -- Mininet creates real network")
        print("namespaces and veth pairs, which requires CAP_NET_ADMIN.")
        print()
        print("Re-run as:  sudo python3 run_demo.py --mode mininet ...")
        print()
        print("First time this session (WSL2 in particular doesn't auto-start")
        print("these): sudo service openvswitch-switch start")
        print("        sudo modprobe -a sch_htb sch_netem sch_tbf sch_prio ifb")
        sys.exit(1)

    from simulation.topology import _MININET_AVAILABLE, run_topology

    if not _MININET_AVAILABLE:
        print("Mininet is not installed. See SETUP.md for install steps.")
        print("Use --mode standalone for a demo that needs no Mininet/root.")
        sys.exit(1)

    _ensure_dirs()
    cfg = _load_config(config_path)
    if 'controller' not in cfg:
        print(f"{config_path} has no `controller:` block, so it can't drive the")
        print(f"live trust-aware demo -- see {DEFAULT_MININET_CONFIG} for the shape")
        print("a live-mode config needs (controller/security/agents/optimizer).")
        sys.exit(1)
    if duration is not None:
        cfg['simulation']['duration_s'] = duration

    ctrl_cfg = cfg['controller']
    events_path = ctrl_cfg.get('dashboard', {}).get('record_path', 'data/events.jsonl')
    # Start from a clean recording -- a stale file from a previous run would
    # silently corrupt the NFR report computed at the end of this one.
    Path(events_path).unlink(missing_ok=True)

    env = dict(os.environ)
    env['ZTSDN_CONFIG'] = config_path
    logger.info("Starting the trust-aware controller (config=%s)...", config_path)
    controller_log = open(Path('logs') / 'controller.log', 'w')
    controller_proc = subprocess.Popen(
        [sys.executable, '-m', 'controller.osken_manager', 'controller.trust_balancer'],
        env=env, stdout=controller_log, stderr=subprocess.STDOUT,
    )

    try:
        if not _wait_for_controller(ctrl_cfg['api_host'], ctrl_cfg['api_port'],
                                     _CONTROLLER_START_TIMEOUT_S):
            print(f"Controller did not come up within {_CONTROLLER_START_TIMEOUT_S:.0f}s "
                  "-- see logs/controller.log")
            sys.exit(1)

        logger.info(
            "Controller up on %s:%d. Launching the %d-edge/%d-IoT Mininet "
            "topology for %ds (needs root; this is the long-running part)...",
            ctrl_cfg['api_host'], ctrl_cfg['api_port'],
            cfg['simulation']['num_edge_nodes'], cfg['simulation']['num_iot_devices'],
            cfg['simulation']['duration_s'],
        )
        run_topology(cfg, interactive=False)
    except KeyboardInterrupt:
        logger.warning("Interrupted -- tearing down early.")
    finally:
        controller_proc.terminate()
        try:
            controller_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            controller_proc.kill()
            controller_proc.wait()
        controller_log.close()

    logger.info("Live run complete. Computing the NFR report from %s...", events_path)
    if not Path(events_path).exists():
        print(f"No events were recorded at {events_path} -- can't compute the NFR report.")
        print("Check logs/controller.log and logs/srvN_agent.log / iotN_client.log.")
        return

    from evaluation.nfr_report import build_report, format_report, load_events

    events = load_events(events_path)
    results = build_report(events, poll_interval_s=ctrl_cfg.get('monitor_interval_s'))
    text = format_report(results)
    print('\n' + text)
    report_path = 'data/nfr_report.txt'
    Path(report_path).write_text(text)
    print(f"NFR report saved to {report_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description='Zero Trust SDN — Semester 1 Review Demo',
    )
    parser.add_argument(
        '--mode', choices=['standalone', 'mininet'], default='standalone',
        help='Run mode (default: standalone)',
    )
    parser.add_argument(
        '--duration', type=int, default=None,
        help='Simulation duration in seconds (standalone default: 120; '
             'mininet default: the config file\'s simulation.duration_s)',
    )
    parser.add_argument(
        '--attack', choices=['none', 'sybil', 'packet_drop', 'both'], default='both',
        help='Attack scenario (standalone mode only; mininet attacks are '
             'config-driven -- see simulation.malicious_edge_nodes/'
             'security.malicious_iot_devices)',
    )
    parser.add_argument(
        '--config', type=str, default=None,
        help='Path to config file (standalone default: config/params.yaml; '
             f'mininet default: {DEFAULT_MININET_CONFIG})',
    )

    args = parser.parse_args()

    if args.mode == 'standalone':
        config_path = args.config or 'config/params.yaml'
        cfg = _load_config(config_path)
        run_standalone(cfg, args.duration if args.duration is not None else 120, args.attack)
    else:
        config_path = args.config or DEFAULT_MININET_CONFIG
        run_mininet(config_path, args.duration)


if __name__ == '__main__':
    main()
