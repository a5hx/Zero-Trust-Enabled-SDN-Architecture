# Trust Convergence Demo - START HERE

## What Is This?

A **standalone simulation** that proves your trust formula's base values are **computed from actual network behavior**, not referenced from external sources.

This folder contains everything your mentor needs to see.

---

## For the Impatient (30 seconds)

```bash
cd trust_convergence_demo
python3 simulate_network.py
python3 convergence_analyzer.py
python3 visualize_results.py
```

Done! Show your mentor the generated PNG files.

---

## What You Get

### Input
- 5 network switches with different behaviors
- Packet events: success, failure, timeout, wrong destination, resource lies
- Various edge cases at specific timestamps

### Output
- `trust_evolution.json` - Complete trust computation history
- `convergence_report.txt` - Statistical analysis
- `trust_convergence.png` - Trust evolution graph
- `component_breakdown.png` - R, B, H, A components
- `final_comparison.png` - Final trust scores

### What It Proves
✓ All trust values start at 0.5 (no external reference)  
✓ Trust changes based only on packet events  
✓ Formula handles edge cases properly  
✓ Trust converges to stable values  
✓ Everything is traceable and auditable  

---

## File Guide

| File | Purpose |
|------|---------|
| **START_HERE.md** | This file - start here |
| **QUICKSTART.md** | Fastest way to run the demo |
| **USAGE.md** | Detailed usage instructions |
| **MENTOR_PRESENTATION.md** | Script for presenting to mentor |
| **README.md** | Technical overview |
| `simulate_network.py` | Main simulation script |
| `trust_compute.py` | Trust calculation engine |
| `packet_simulator.py` | Event generator with edge cases |
| `convergence_analyzer.py` | Statistical analysis |
| `visualize_results.py` | Graph generation |
| `run_demo.sh` | One-command runner (WSL/Linux) |
| `run_demo.bat` | One-command runner (Windows) |
| `topology.py` | Mininet topology (optional) |
| `requirements.txt` | Python dependencies |

---

## Quick Start Options

### Option 1: Automated (Recommended)
**WSL/Linux:**
```bash
sudo bash run_demo.sh
```

**Windows:**
- Double-click `run_demo.bat`
- Or from WSL: `sudo bash run_demo.sh`

### Option 2: Step by Step
```bash
# 1. Simulate network and compute trust
python3 simulate_network.py

# 2. Analyze convergence
python3 convergence_analyzer.py

# 3. Generate graphs
python3 visualize_results.py
```

### Option 3: Custom Settings
```bash
# Longer simulation, more events, verbose output
python3 simulate_network.py --duration 120 --event-rate 3.0 --verbose
```

---

## System Requirements

### Minimum (Will work anywhere)
- Python 3.7+
- No additional packages needed (uses built-in `json`)
- Generates JSON and text reports

### Recommended (For visualizations)
- Python 3.7+
- matplotlib (for graphs)
- numpy (for graphs)

Install with:
```bash
pip3 install -r requirements.txt
```

### Optional (For Mininet topology)
- WSL (Windows) or Linux
- Mininet installed
- sudo privileges

---

## 5-Minute Demo for Mentor

1. **Show the code** (2 min)
   - Open `trust_compute.py`
   - Point to line 60: "See? Only initial_score=0.5"
   - Point to line 76: "This is where trust is computed from events"

2. **Run simulation** (1 min)
   ```bash
   python3 simulate_network.py
   ```

3. **Show results** (2 min)
   - Open `trust_convergence.png`
   - "All nodes start at 0.5, trust computed from behavior"
   - Point to edge cases at t=10s, 20s, 30s, 40s

**Done!** Your mentor sees the proof.

---

## Edge Cases Demonstrated

The simulation includes specific scenarios to prove robust computation:

| Time | Event | Node | Impact |
|------|-------|------|--------|
| t=10s | Packet failure | s2 | R (Reputation) drops |
| t=20s | Wrong destination | s3 | A (Anomaly) increases |
| t=30s | Resource lying | s5 | H (Honesty) drops |
| t=40s | Timeout | s4 | B (Behavior) drops |

Plus continuous traffic with various success rates, latencies, and accuracy levels.

---

## Node Behavioral Profiles

| Node | Profile | Behavior | Expected Trust |
|------|---------|----------|----------------|
| s1 | Normal | Well-behaved, high success | ~0.72 (high) |
| s2 | Intermittent | 20% failure rate | ~0.59 (medium) |
| s3 | Malicious | Wrong dest + lies | ~0.28 (low, quarantined) |
| s4 | Overloaded | High latency, honest | ~0.45 (medium-low) |
| s5 | Liar | Good perf, lies about CPU | ~0.44 (medium-low) |

---

## Troubleshooting

### "python3: command not found"
Install Python 3:
```bash
# Ubuntu/Debian (WSL)
sudo apt update && sudo apt install python3 python3-pip

# Already have Python? Try 'python' instead of 'python3'
python --version
```

### "matplotlib not available"
Visualizations will be skipped. Install with:
```bash
pip3 install matplotlib numpy
```
Or just use the JSON and text reports.

### "Permission denied: run_demo.sh"
Make it executable:
```bash
chmod +x run_demo.sh
```

### WSL not working?
Use the Python scripts directly (no WSL needed):
```bash
python3 simulate_network.py
python3 convergence_analyzer.py
```

---

## What to Show Your Mentor

### Primary Evidence
1. **`trust_compute.py`** - The code (line 60, 76)
2. **`trust_evolution.json`** - Complete computation history
3. **`trust_convergence.png`** - Visual proof of convergence
4. **`convergence_report.txt`** - Statistical validation

### Supporting Evidence
5. **`component_breakdown.png`** - Component analysis
6. **`final_comparison.png`** - Final trust comparison
7. Console output from verbose run

### Key Points to Emphasize
- Initial trust = 0.5 for ALL nodes (no external reference)
- Trust changes only based on packet events
- Every update is computed using: T = αR + βB + γH - δA
- Convergence proves formula stability
- Edge cases handled correctly

---

## Next Steps After Demo

1. ✓ Mentor reviews and approves approach
2. Document this in your thesis/paper methodology section
3. Reference this demo when explaining base values
4. Optionally integrate with main project for production
5. Add to GitHub/GitLab for reproducibility

---

## Questions?

### "Can I modify the trust formula?"
Yes! Edit `trust_compute.py`, line 27-35.

### "Can I add more nodes?"
Yes! Edit `packet_simulator.py` to add node profiles.

### "Can I run longer simulations?"
Yes! Use `--duration 300` for 5 minutes, etc.

### "Can this run on real Mininet?"
Yes! `topology.py` defines the actual topology. Current version simulates for speed.

### "Where's the actual network code?"
This is a **standalone demo**. Your main project has the production version. This just proves the computation concept.

---

## Success Criteria

Your mentor should be able to say:

> "I see that trust values are computed from network events, not referenced from external sources. The simulation shows proper convergence and edge case handling. The approach is valid."

✓ Mission accomplished!

---

## Need Help?

1. Read **QUICKSTART.md** for fastest run
2. Read **USAGE.md** for detailed instructions
3. Read **MENTOR_PRESENTATION.md** for presentation script
4. Check troubleshooting section above
5. Run with `--verbose` to see detailed computation

**Good luck with your mentor meeting! 🚀**
