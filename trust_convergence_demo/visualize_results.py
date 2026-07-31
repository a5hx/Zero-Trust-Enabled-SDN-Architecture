#!/usr/bin/env python3
"""
Generates visualization plots for trust convergence demonstration.
Shows how trust scores evolve over time and component contributions.
"""

import json
import sys
from collections import defaultdict

try:
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend for WSL
    import matplotlib.pyplot as plt
    import numpy as np
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("Warning: matplotlib not available. Install with: pip3 install matplotlib")


class TrustVisualizer:
    """Creates visualizations of trust evolution."""
    
    def __init__(self, history_file: str = 'trust_evolution.json'):
        with open(history_file, 'r') as f:
            self.data = json.load(f)
        
        self.params = self.data['parameters']
        self.history = self.data['history']
        self.final_states = self.data['final_states']
        
        # Organize by node
        self.node_data = defaultdict(lambda: {'time': [], 'trust': [], 'R': [], 'B': [], 'H': [], 'A': []})
        for entry in self.history:
            node = entry['node_id']
            self.node_data[node]['time'].append(entry['timestamp'])
            self.node_data[node]['trust'].append(entry['trust_score'])
            self.node_data[node]['R'].append(entry['components']['R'])
            self.node_data[node]['B'].append(entry['components']['B'])
            self.node_data[node]['H'].append(entry['components']['H'])
            self.node_data[node]['A'].append(entry['components']['A'])
    
    def plot_trust_convergence(self, output_file: str = 'trust_convergence.png'):
        """Plot trust score evolution over time for all nodes."""
        if not HAS_MATPLOTLIB:
            print("Skipping plot: matplotlib not available")
            return None
        
        fig, ax = plt.subplots(figsize=(12, 6))
        
        for node_id in sorted(self.node_data.keys()):
            data = self.node_data[node_id]
            ax.plot(data['time'], data['trust'], marker='o', markersize=3, 
                   label=f'{node_id} (final={data["trust"][-1]:.3f})', linewidth=2)
        
        ax.axhline(y=0.5, color='gray', linestyle='--', alpha=0.5, label='Initial Score (0.5)')
        ax.axhline(y=0.3, color='red', linestyle='--', alpha=0.5, label='Isolation Threshold (0.3)')
        
        ax.set_xlabel('Time (seconds)', fontsize=12)
        ax.set_ylabel('Trust Score', fontsize=12)
        ax.set_title('Trust Score Convergence Over Time\n(Computed from Network Events)', fontsize=14, fontweight='bold')
        ax.legend(loc='best', fontsize=9)
        ax.grid(True, alpha=0.3)
        ax.set_ylim([0, 1])
        
        plt.tight_layout()
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        print(f"✓ Trust convergence plot saved to {output_file}")
        plt.close()
        
        return output_file
    
    def plot_component_breakdown(self, output_file: str = 'component_breakdown.png'):
        """Plot R, B, H, A components for each node."""
        if not HAS_MATPLOTLIB:
            print("Skipping plot: matplotlib not available")
            return None
        
        nodes = sorted(self.node_data.keys())
        n_nodes = len(nodes)
        
        fig, axes = plt.subplots(n_nodes, 1, figsize=(12, 3*n_nodes), sharex=True)
        if n_nodes == 1:
            axes = [axes]
        
        for idx, node_id in enumerate(nodes):
            ax = axes[idx]
            data = self.node_data[node_id]
            
            ax.plot(data['time'], data['R'], label='Reputation (R)', linewidth=2)
            ax.plot(data['time'], data['B'], label='Behavior (B)', linewidth=2)
            ax.plot(data['time'], data['H'], label='Honesty (H)', linewidth=2)
            ax.plot(data['time'], data['A'], label='Anomaly (A)', linewidth=2, linestyle='--')
            
            ax.set_ylabel(f'{node_id}\nComponent Value', fontsize=10)
            ax.legend(loc='right', fontsize=8)
            ax.grid(True, alpha=0.3)
            ax.set_ylim([0, 1])
            
            final_trust = data['trust'][-1]
            ax.set_title(f'Final Trust: {final_trust:.4f}', fontsize=9, loc='left')
        
        axes[-1].set_xlabel('Time (seconds)', fontsize=12)
        fig.suptitle('Trust Component Evolution (R, B, H, A)', fontsize=14, fontweight='bold')
        
        plt.tight_layout()
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        print(f"✓ Component breakdown plot saved to {output_file}")
        plt.close()
        
        return output_file
    
    def plot_final_comparison(self, output_file: str = 'final_comparison.png'):
        """Bar chart comparing final trust scores and components."""
        if not HAS_MATPLOTLIB:
            print("Skipping plot: matplotlib not available")
            return None
        
        nodes = sorted(self.final_states.keys())
        trust_scores = [self.final_states[n]['trust_score'] for n in nodes]
        R_vals = [self.final_states[n]['reputation'] for n in nodes]
        B_vals = [self.final_states[n]['behavior'] for n in nodes]
        H_vals = [self.final_states[n]['honesty'] for n in nodes]
        A_vals = [self.final_states[n]['anomaly'] for n in nodes]
        
        x = np.arange(len(nodes))
        width = 0.15
        
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))
        
        # Final trust scores
        bars = ax1.bar(x, trust_scores, width=0.5, color='steelblue', alpha=0.8)
        ax1.axhline(y=0.5, color='gray', linestyle='--', alpha=0.5, label='Initial (0.5)')
        ax1.axhline(y=0.3, color='red', linestyle='--', alpha=0.5, label='Threshold (0.3)')
        ax1.set_ylabel('Trust Score', fontsize=12)
        ax1.set_title('Final Trust Scores (Computed from Network Behavior)', fontsize=13, fontweight='bold')
        ax1.set_xticks(x)
        ax1.set_xticklabels(nodes)
        ax1.legend()
        ax1.grid(axis='y', alpha=0.3)
        ax1.set_ylim([0, 1])
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height:.3f}', ha='center', va='bottom', fontsize=9)
        
        # Component breakdown
        ax2.bar(x - 1.5*width, R_vals, width, label='Reputation (R)', alpha=0.8)
        ax2.bar(x - 0.5*width, B_vals, width, label='Behavior (B)', alpha=0.8)
        ax2.bar(x + 0.5*width, H_vals, width, label='Honesty (H)', alpha=0.8)
        ax2.bar(x + 1.5*width, A_vals, width, label='Anomaly (A)', alpha=0.8, color='red')
        ax2.set_ylabel('Component Value', fontsize=12)
        ax2.set_title('Trust Component Breakdown', fontsize=13, fontweight='bold')
        ax2.set_xticks(x)
        ax2.set_xticklabels(nodes)
        ax2.legend()
        ax2.grid(axis='y', alpha=0.3)
        ax2.set_ylim([0, 1])
        
        plt.tight_layout()
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        print(f"✓ Final comparison plot saved to {output_file}")
        plt.close()
        
        return output_file
    
    def generate_all_plots(self):
        """Generate all visualization plots."""
        print("\n" + "="*70)
        print(" GENERATING VISUALIZATIONS ".center(70, "="))
        print("="*70 + "\n")
        
        if not HAS_MATPLOTLIB:
            print("matplotlib is not installed. Install with:")
            print("  pip3 install matplotlib")
            print("\nSkipping visualization generation.")
            return []
        
        plots = []
        plots.append(self.plot_trust_convergence())
        plots.append(self.plot_component_breakdown())
        plots.append(self.plot_final_comparison())
        
        print("\n" + "="*70)
        print(" VISUALIZATION COMPLETE ".center(70, "="))
        print("="*70)
        print(f"\nGenerated {len([p for p in plots if p])} plots")
        print("\nView the PNG files to see trust convergence results.\n")
        
        return plots


def main():
    if len(sys.argv) > 1:
        history_file = sys.argv[1]
    else:
        history_file = 'trust_evolution.json'
    
    try:
        visualizer = TrustVisualizer(history_file)
        visualizer.generate_all_plots()
    except FileNotFoundError:
        print(f"Error: {history_file} not found.")
        print("Run simulate_network.py first to generate the data.")
        sys.exit(1)


if __name__ == '__main__':
    main()
