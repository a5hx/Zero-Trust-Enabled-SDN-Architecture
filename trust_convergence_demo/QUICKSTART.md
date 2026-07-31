# Quick Start Guide - Trust Convergence Demo

## For Your Mentor Meeting

### Option 1: From Windows (Easiest)
1. Open this folder in Windows Explorer
2. Double-click `run_demo.bat`
3. Choose option 1 (Quick run)
4. Wait ~2 minutes for completion
5. Show generated files to mentor

### Option 2: From WSL Terminal
```bash
cd /mnt/c/Users/Arjun/Desktop/Zero-Trust-Enabled-SDN-Architecture/trust_convergence_demo
sudo bash run_demo.sh
```

### Option 3: Manual Steps
```bash
# 1. Run simulation
python3 simulate_network.py

# 2. Analyze
python3 convergence_analyzer.py

# 3. Visualize
python3 visualize_results.py
```

---

## What Gets Generated

✓ **trust_evolution.json** - Complete trust computation history  
✓ **convergence_report.txt** - Statistical analysis  
✓ **trust_convergence.png** - Trust over time graph  
✓ **component_breakdown.png** - R, B, H, A components  
✓ **final_comparison.png** - Final trust comparison  

---

## 3-Minute Demo for Mentor

1. **Show the code** (`trust_compute.py`)
   - Point to line 60: "See? Only initial_score=0.5"
   - Point to line 76: "This is where trust is computed"

2. **Run the simulation**
   ```bash
   python3 simulate_network.py --verbose
   ```
   - "Watch trust change in real-time based on packets"

3. **Show results**
   - Open `trust_convergence.png`
   - "All start at 0.5, converge based on behavior"

4. **Explain edge cases**
   - "At t=10s, packet fails → trust drops"
   - "At t=20s, wrong destination → anomaly detected"
   - "At t=30s, resource lie → honesty drops"

**Done! Your mentor now sees trust is computed, not referenced.**

---

## Troubleshooting

### "sudo: command not found"
You need WSL with Linux installed. Run from WSL terminal.

### "python3: command not found"
Install Python in WSL:
```bash
sudo apt update
sudo apt install python3 python3-pip
```

### "matplotlib not available"
Visualizations will be skipped. Install with:
```bash
pip3 install matplotlib numpy
```

### Still stuck?
Run the manual version without WSL/Mininet:
```bash
python3 simulate_network.py
python3 convergence_analyzer.py
```

This works on any system with Python 3.

---

## Key Points for Mentor

1. ✅ **No external references** - Only `initial_score=0.5`
2. ✅ **Event-driven computation** - Trust calculated from packets
3. ✅ **Edge cases handled** - Failures, timeouts, lies, anomalies
4. ✅ **Convergence proven** - Trust stabilizes after ~30s
5. ✅ **Fully traceable** - Every calculation logged in JSON

Your base values are **computed**, not assumed. ✓
