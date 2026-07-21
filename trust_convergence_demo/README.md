# Trust Convergence Demonstration

## Purpose
This standalone simulation demonstrates that the trust formula's base values are **computed from actual network behavior**, not referenced from external sources. It shows how trust scores converge based on real packet-level events.

## What This Proves
1. **Initial Trust Values**: All nodes start at 0.5 (no external reference)
2. **Event-Driven Updates**: Trust changes based on actual packet success/failure
3. **Convergence Analysis**: Shows how trust stabilizes over time
4. **Edge Cases**: Demonstrates various failure scenarios:
   - Packet delivery failures
   - Wrong destination routing
   - Timeout events
   - Resource misreporting
   - Anomalous behavior

## Files
- `topology.py` - Custom Mininet network (5 nodes, various paths)
- `packet_simulator.py` - Generates realistic traffic with edge cases
- `trust_compute.py` - Standalone trust calculator (no external deps)
- `convergence_analyzer.py` - Tracks and visualizes trust evolution
- `run_demo.sh` - Main execution script for WSL
- `visualize_results.py` - Generates convergence graphs

## Usage (WSL)

### One-Command Run
```bash
sudo bash run_demo.sh
```

### Step-by-Step
```bash
# 1. Start the simulation
sudo python3 simulate_network.py

# 2. Analyze results
python3 convergence_analyzer.py

# 3. Generate plots
python3 visualize_results.py
```

## Output
- `trust_evolution.json` - Raw trust data over time
- `convergence_report.txt` - Statistical analysis
- `trust_convergence.png` - Graph showing trust evolution
- `event_impact.png` - How different events affect trust

## Key Metrics Shown
1. **Time to Convergence** - When trust scores stabilize
2. **Event Sensitivity** - How each event type changes trust
3. **Component Breakdown** - R, B, H, A evolution over time
4. **Statistical Validation** - Mean, std dev, convergence rate
