"""Publication-quality matplotlib figures for the Zero Trust SDN evaluation.

Generates 4 figures saved to data/figures/:
  1. Trust Score Evolution (convergence under attack)
  2. Routing Distribution (per-node bar chart)
  3. Blockchain Growth (blocks over time)
  4. Trust vs Attack Timeline (dual-axis with attack shading)
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import numpy as np

logger = logging.getLogger(__name__)

# IEEE-style appearance
try:
    import seaborn as sns
    sns.set_style('whitegrid')
    sns.set_context('paper', font_scale=1.2)
except ImportError:
    logger.info("Seaborn not available - using default matplotlib style")

FIGURE_DIR = Path('data') / 'figures'
DPI = 150
FIGSIZE = (8, 5)


def _ensure_dir() -> None:
    FIGURE_DIR.mkdir(parents=True, exist_ok=True)


def plot_trust_evolution(
    trust_history: Dict[str, List[float]],
    malicious_nodes: List[str],
    output_path: Optional[Path] = None,
) -> Path:
    """Figure 1 — Trust Score Convergence Under Attack.

    Args:
        trust_history: {node_id: [score_at_step_0, score_at_step_1, …]}
        malicious_nodes: Node IDs that are under attack.
        output_path: Override default save path.

    Returns:
        Path to saved figure.
    """
    _ensure_dir()
    path = output_path or FIGURE_DIR / 'fig1_trust_evolution.png'

    fig, ax = plt.subplots(figsize=FIGSIZE)

    for node_id, scores in trust_history.items():
        style = '--' if node_id in malicious_nodes else '-'
        color = 'red' if node_id in malicious_nodes else None
        label = f"{node_id} {'(attacked)' if node_id in malicious_nodes else '(honest)'}"
        ax.plot(scores, linestyle=style, color=color, label=label, linewidth=1.5)

    ax.axhline(y=0.5, color='gray', linestyle=':', linewidth=1, label='Neutral threshold')
    ax.axhline(y=0.3, color='orange', linestyle=':', linewidth=1, alpha=0.7, label='Isolation threshold')
    ax.set_xlabel('Interaction Number')
    ax.set_ylabel('Trust Score')
    ax.set_title('Trust Score Convergence Under Attack')
    ax.set_ylim(-0.05, 1.05)
    ax.legend(loc='best', fontsize=8, ncol=2)
    fig.tight_layout()
    fig.savefig(path, dpi=DPI, bbox_inches='tight')
    plt.close(fig)

    logger.info("Saved figure: %s", path)
    return path


def plot_routing_distribution(
    routing_counts: Dict[str, int],
    low_trust_nodes: List[str],
    output_path: Optional[Path] = None,
) -> Path:
    """Figure 2 — Routing Distribution by Edge Node.

    Args:
        routing_counts: {node_id: count_of_routing_decisions}.
        low_trust_nodes: Nodes whose trust dropped below 0.3.
        output_path: Override default save path.

    Returns:
        Path to saved figure.
    """
    _ensure_dir()
    path = output_path or FIGURE_DIR / 'fig2_routing_distribution.png'

    fig, ax = plt.subplots(figsize=FIGSIZE)

    nodes = sorted(routing_counts.keys())
    counts = [routing_counts[n] for n in nodes]
    colors = ['#e74c3c' if n in low_trust_nodes else '#2ecc71' for n in nodes]

    bars = ax.bar(nodes, counts, color=colors, edgecolor='white', linewidth=0.5)

    # Legend patches
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor='#2ecc71', label='Trusted node'),
        Patch(facecolor='#e74c3c', label='Low-trust node (T < 0.3)'),
    ]
    ax.legend(handles=legend_elements, loc='upper right')

    ax.set_xlabel('Edge Node')
    ax.set_ylabel('Routing Decisions')
    ax.set_title('Routing Distribution by Edge Node (Trust-Aware)')
    fig.tight_layout()
    fig.savefig(path, dpi=DPI, bbox_inches='tight')
    plt.close(fig)

    logger.info("Saved figure: %s", path)
    return path


def plot_blockchain_growth(
    block_events: List[Dict[str, Any]],
    output_path: Optional[Path] = None,
) -> Path:
    """Figure 3 — Blockchain Ledger Growth Over Simulation.

    Args:
        block_events: List of dicts with 'elapsed_s' and 'block_index'.
        output_path: Override default save path.

    Returns:
        Path to saved figure.
    """
    _ensure_dir()
    path = output_path or FIGURE_DIR / 'fig3_blockchain_growth.png'

    fig, ax = plt.subplots(figsize=FIGSIZE)

    if block_events:
        times = [e['elapsed_s'] for e in block_events]
        indices = [e['block_index'] for e in block_events]
        ax.step(times, indices, where='post', color='#3498db', linewidth=2)
        ax.fill_between(times, indices, step='post', alpha=0.15, color='#3498db')
    else:
        ax.text(0.5, 0.5, 'No blocks committed', transform=ax.transAxes,
                ha='center', va='center', fontsize=14, color='gray')

    ax.set_xlabel('Time (seconds)')
    ax.set_ylabel('Blocks Committed')
    ax.set_title('Blockchain Ledger Growth Over Simulation')
    fig.tight_layout()
    fig.savefig(path, dpi=DPI, bbox_inches='tight')
    plt.close(fig)

    logger.info("Saved figure: %s", path)
    return path


def plot_attack_timeline(
    trust_history: Dict[str, List[float]],
    attack_windows: Dict[str, tuple],
    total_steps: int,
    output_path: Optional[Path] = None,
) -> Path:
    """Figure 4 — Trust Score Response to Sybil and Packet-Drop Attacks.

    Args:
        trust_history: {node_id: [score_at_each_step]}.
        attack_windows: {node_id: (start_step, stop_step)} for attacked nodes.
        total_steps: Total number of simulation steps.
        output_path: Override default save path.

    Returns:
        Path to saved figure.
    """
    _ensure_dir()
    path = output_path or FIGURE_DIR / 'fig4_attack_timeline.png'

    fig, ax1 = plt.subplots(figsize=FIGSIZE)
    ax2 = ax1.twinx()

    # Plot trust scores on left axis
    for node_id, scores in trust_history.items():
        if node_id in attack_windows:
            ax1.plot(scores, label=f'{node_id} (trust)', linewidth=1.5, color='red')
        else:
            ax1.plot(scores, label=f'{node_id} (trust)', linewidth=1.0, alpha=0.4)

    # Shade attack windows on right axis
    x = np.arange(total_steps)
    for node_id, (start, stop) in attack_windows.items():
        attack_active = np.zeros(total_steps)
        attack_active[start:stop] = 1.0
        ax2.fill_between(
            x, attack_active, alpha=0.15, color='orange',
            label=f'{node_id} attack active',
        )

    ax1.set_xlabel('Simulation Step')
    ax1.set_ylabel('Trust Score')
    ax2.set_ylabel('Attack Active (0/1)')
    ax2.set_ylim(-0.1, 1.5)

    ax1.set_title('Trust Score Response to Sybil and Packet-Drop Attacks')

    # Combined legend
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='best', fontsize=7, ncol=2)

    fig.tight_layout()
    fig.savefig(path, dpi=DPI, bbox_inches='tight')
    plt.close(fig)

    logger.info("Saved figure: %s", path)
    return path
