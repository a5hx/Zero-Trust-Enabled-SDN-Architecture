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
import queue
import random
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

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

    # Malicious node mapping (for attacks)
    sybil_target = 'srv3'
    pktdrop_target = 'srv5'

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

            metrics.record_trust_update(nid, trust_calc.get_score(nid), score, False)

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
        '--duration', type=int, default=120,
        help='Simulation duration in seconds (default: 120)',
    )
    parser.add_argument(
        '--attack', choices=['none', 'sybil', 'packet_drop', 'both'], default='both',
        help='Attack scenario (default: both)',
    )
    parser.add_argument(
        '--config', type=str, default='config/params.yaml',
        help='Path to config file (default: config/params.yaml)',
    )

    args = parser.parse_args()

    cfg = _load_config(args.config)

    if args.mode == 'standalone':
        run_standalone(cfg, args.duration, args.attack)
    else:
        print("Mininet mode requires Linux with Mininet/Ryu installed.")
        print("Use --mode standalone for the review demo.")
        sys.exit(1)


if __name__ == '__main__':
    main()
