#!/usr/bin/env python3
"""
Main simulation script that ties everything together.
Runs packet simulation and computes trust from scratch.
"""

import sys
import argparse
from trust_compute import TrustComputeEngine
from packet_simulator import PacketSimulator


def run_simulation(duration: int = 60, event_rate: float = 2.0, verbose: bool = True):
    """
    Run the complete trust convergence simulation.
    
    Args:
        duration: Simulation duration in seconds
        event_rate: Packet events per second
        verbose: Print detailed output
    """
    print("\n" + "="*70)
    print(" TRUST CONVERGENCE DEMONSTRATION ".center(70, "="))
    print("="*70)
    print("\nThis simulation demonstrates that trust values are COMPUTED")
    print("from actual network behavior, not referenced from external sources.\n")
    
    # Define switches (edge nodes we'll track)
    switches = ['s1', 's2', 's3', 's4', 's5']
    
    # Initialize trust engine with default parameters
    print("\n" + "-"*70)
    print("STEP 1: Initialize Trust Engine")
    print("-"*70)
    trust_engine = TrustComputeEngine(
        alpha=0.35,      # Reputation weight
        beta=0.25,       # Behavior weight
        gamma=0.25,      # Honesty weight
        delta=0.15,      # Anomaly weight
        lambda_decay=0.85,
        initial_score=0.5  # Starting point - NO external reference
    )
    
    # Generate packet events with edge cases
    print("\n" + "-"*70)
    print("STEP 2: Generate Packet Events")
    print("-"*70)
    simulator = PacketSimulator(switches, duration=duration)
    events = simulator.generate_events(events_per_second=event_rate)
    
    # Process each event and compute trust
    print("\n" + "-"*70)
    print("STEP 3: Process Events and Compute Trust")
    print("-"*70)
    print("\nProcessing packet events (trust computed in real-time)...\n")
    
    if not verbose:
        print("(Set --verbose to see detailed event processing)")
    
    for i, event in enumerate(events):
        if verbose or event.details.startswith("EDGE CASE"):
            trust_engine.process_event(event)
        else:
            # Process silently for normal events
            import sys
            import os
            # Suppress output temporarily
            devnull = open(os.devnull, 'w')
            old_stdout = sys.stdout
            sys.stdout = devnull
            trust_engine.process_event(event)
            sys.stdout = old_stdout
            devnull.close()
        
        # Progress indicator
        if (i + 1) % 20 == 0:
            print(f"\n[Progress: {i+1}/{len(events)} events processed]")
    
    # Display final results
    print("\n" + "="*70)
    print(" FINAL TRUST SCORES ".center(70, "="))
    print("="*70)
    
    states = trust_engine.get_all_states()
    for node_id in sorted(states.keys()):
        state = states[node_id]
        print(f"\n{node_id} ({simulator.node_profiles[node_id]}):")
        print(f"  Final Trust Score: {state.trust_score:.4f}")
        print(f"  Components:")
        print(f"    Reputation (R): {state.reputation:.3f}")
        print(f"    Behavior (B):   {state.behavior:.3f}")
        print(f"    Honesty (H):    {state.honesty:.3f}")
        print(f"    Anomaly (A):    {state.anomaly:.3f}")
        print(f"  Events Processed: {state.event_count}")
    
    # Export results
    print("\n" + "-"*70)
    print("STEP 4: Export Results")
    print("-"*70)
    output_file = trust_engine.export_history('trust_evolution.json')
    
    print("\n" + "="*70)
    print(" SIMULATION COMPLETE ".center(70, "="))
    print("="*70)
    print(f"\nResults saved to: {output_file}")
    print("\nNext steps:")
    print("  1. Run: python3 convergence_analyzer.py")
    print("  2. Run: python3 visualize_results.py")
    print("\nThese will generate convergence analysis and graphs.\n")
    
    return trust_engine, events


def main():
    parser = argparse.ArgumentParser(
        description='Trust Convergence Demonstration Simulation'
    )
    parser.add_argument(
        '--duration', 
        type=int, 
        default=60,
        help='Simulation duration in seconds (default: 60)'
    )
    parser.add_argument(
        '--event-rate',
        type=float,
        default=2.0,
        help='Packet events per second (default: 2.0)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show detailed event processing'
    )
    
    args = parser.parse_args()
    
    try:
        run_simulation(
            duration=args.duration,
            event_rate=args.event_rate,
            verbose=args.verbose
        )
    except KeyboardInterrupt:
        print("\n\nSimulation interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nError: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
