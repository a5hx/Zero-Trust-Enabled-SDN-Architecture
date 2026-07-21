# Trust Convergence Demo - Usage Guide

## Purpose
Demonstrate to your mentor that trust base values are **computed from network events**, not referenced from external sources.

## What This Proves
✓ All nodes start at 0.5 (initial_score) - NO external reference  
✓ Trust evolves based on actual packet behavior  
✓ Formula handles edge cases (failures, wrong dest, resource lies)  
✓ Convergence shows the formula is stable and reliable  

---

## Quick Start (WSL)

### One-Command Run
```bash
cd trust_convergence_demo
sudo bash run_demo.sh
```

### Custom Configuration
```bash
# Longer simulation with more events
sudo bash run_demo.sh --duration 120 --event-rate 3.0

# Verbose mode (see every event)
sudo bash run_demo.sh --verbose
```

---

## Step-by-Step Execution

### 1. Run the Simulation
```bash
python3 simulate_network.py
```

**What happens:**
- Initializes 5 switches with trust=0.5
- Simulates packet events (success, failure, timeouts, wrong destinations)
- Computes trust in real-time using the formula
- Exports data to `trust_evolution.json`

### 2. Analyze Convergence
```bash
python3 convergence_analyzer.py
```

**Output:**
- Convergence times for each node
- Event impact analysis
- Statistical summary
- Saves to `convergence_report.txt`

### 3. Generate Visualizations
```bash
python3 visualize_results.py
```

**Creates:**
- `trust_convergence.png` - Trust evolution over time
- `component_breakdown.png` - R, B, H, A components
- `final_comparison.png` - Final trust scores

---

## Node Behavioral Profiles

The simulation includes 5 nodes with different behaviors:

| Node | Profile | Behavior |
|------|---------|----------|
| s1 | Normal | Well-behaved, high success rate |
| s2 | Intermittent | Occasional failures (20%) |
| s3 | Malicious | Wrong destinations + resource lies |
| s4 | Overloaded | High latency but honest |
| s5 | Liar | Good performance but under-reports CPU |

---

## Edge Cases Demonstrated

The simulation includes specific edge cases at key times:

**t=10s** - Packet failure (s2)
- Buffer overflow causing packet drop
- Shows R (Reputation) component decrease

**t=20s** - Wrong destination routing (s3)
- Packet sent to wrong IP
- Shows anomaly detection (A component)

**t=30s** - Resource misreporting (s5)
- Reports CPU=0.1, actual=0.8
- Shows H (Honesty) component decrease

**t=40s** - Timeout event (s4)
- Latency > 500ms threshold
- Shows B (Behavior) component impact

---

## Output Files

### trust_evolution.json
Complete history of trust computation:
```json
{
  "parameters": {
    "alpha": 0.35,
    "beta": 0.25,
    "gamma": 0.25,
    "delta": 0.15,
    "lambda_decay": 0.85,
    "initial_score": 0.5
  },
  "history": [...],
  "final_states": {...}
}
```

### convergence_report.txt
Statistical analysis showing:
- Convergence times
- Event impact metrics
- Component breakdown
- Key findings

### Visualization PNGs
Graphs showing trust evolution and convergence

---

## Presenting to Your Mentor

### Key Points to Highlight

1. **No External References**
   - Open `trust_compute.py`, line 45: `initial_score=0.5`
   - Show that ALL nodes start at 0.5
   - No database, no config file lookups

2. **Event-Driven Computation**
   - Open `trust_evolution.json`
   - Show timestamp-by-timestamp changes
   - Each event causes computed trust update

3. **Formula Components**
   - R (Reputation): Task success/failure
   - B (Behavior): Latency performance
   - H (Honesty): Resource reporting accuracy
   - A (Anomaly): Suspicious behavior detection

4. **Convergence Proof**
   - Show `trust_convergence.png`
   - Point out where each node stabilizes
   - Explain variance threshold method

5. **Edge Case Handling**
   - Walk through t=10s, 20s, 30s, 40s events
   - Show how trust responds appropriately
   - Demonstrate formula robustness

---

## Troubleshooting

### matplotlib not installed
```bash
pip3 install matplotlib numpy
```

### Permission denied on run_demo.sh
```bash
chmod +x run_demo.sh
sudo bash run_demo.sh
```

### WSL Python issues
```bash
# Install Python 3 if needed
sudo apt update
sudo apt install python3 python3-pip

# Install dependencies
pip3 install -r requirements.txt
```

---

## Advanced Options

### Modify Trust Parameters

Edit `simulate_network.py`, line 29-35:
```python
trust_engine = TrustComputeEngine(
    alpha=0.35,      # Change reputation weight
    beta=0.25,       # Change behavior weight
    gamma=0.25,      # Change honesty weight
    delta=0.15,      # Change anomaly weight
    lambda_decay=0.85,  # Change EMA smoothing
    initial_score=0.5   # Change starting point
)
```

### Add More Nodes

Edit `simulate_network.py`, line 22:
```python
switches = ['s1', 's2', 's3', 's4', 's5', 's6', 's7']
```

Edit `packet_simulator.py` to add profiles for new nodes.

### Longer Simulation

```bash
python3 simulate_network.py --duration 300 --event-rate 5.0
```

---

## Questions Your Mentor Might Ask

**Q: How do I know you didn't hard-code these values?**  
A: Check `trust_compute.py` - the only hard-coded value is `initial_score=0.5`. Everything else is computed from packet events in `process_event()` method.

**Q: What if a node has no traffic initially?**  
A: It stays at 0.5 until first event. See `_init_node()` method.

**Q: How do you ensure convergence?**  
A: EMA smoothing with λ=0.85 provides stability. Analysis in `convergence_analyzer.py` detects when variance < threshold.

**Q: Can you show the raw calculations?**  
A: Run with `--verbose` flag to see every event and its trust impact.

**Q: What about real Mininet integration?**  
A: The topology in `topology.py` can be used. Current version simulates for speed and reproducibility.

---

## Next Steps

After showing this to your mentor:

1. Integrate with main project's trust calculator
2. Use computed base values in production
3. Reference this demo in documentation
4. Add to thesis/paper methodology section

**Success Criteria:** Your mentor sees that trust values are computed, not assumed.
