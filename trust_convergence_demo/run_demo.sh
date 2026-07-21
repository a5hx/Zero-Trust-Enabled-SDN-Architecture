#!/bin/bash
# Main execution script for trust convergence demonstration
# Runs in WSL environment

set -e  # Exit on error

echo "========================================================================"
echo "          TRUST CONVERGENCE DEMONSTRATION - WSL RUNNER"
echo "========================================================================"
echo ""
echo "This script will:"
echo "  1. Run network simulation with packet events"
echo "  2. Compute trust scores from scratch (no external references)"
echo "  3. Analyze convergence behavior"
echo "  4. Generate visualization plots"
echo ""

# Check if running with sudo (needed for Mininet)
if [ "$EUID" -ne 0 ]; then 
    echo "Error: This script must be run with sudo"
    echo "Usage: sudo bash run_demo.sh"
    exit 1
fi

# Check Python version
echo "Checking Python environment..."
python3 --version

# Check for required packages
echo ""
echo "Checking dependencies..."

MISSING_DEPS=()

python3 -c "import json" 2>/dev/null || MISSING_DEPS+=("json (built-in)")

if ! python3 -c "import matplotlib" 2>/dev/null; then
    echo "  Warning: matplotlib not found (optional, for plots)"
    echo "  Install with: pip3 install matplotlib"
fi

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    echo "Error: Missing required dependencies:"
    for dep in "${MISSING_DEPS[@]}"; do
        echo "  - $dep"
    done
    exit 1
fi

echo "  ✓ All required dependencies found"
echo ""

# Parse arguments
DURATION=60
EVENT_RATE=2.0
VERBOSE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --event-rate)
            EVENT_RATE="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE="--verbose"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: sudo bash run_demo.sh [--duration SECONDS] [--event-rate RATE] [--verbose]"
            exit 1
            ;;
    esac
done

echo "Configuration:"
echo "  Simulation Duration: ${DURATION}s"
echo "  Event Rate: ${EVENT_RATE} events/sec"
echo "  Verbose: ${VERBOSE:-no}"
echo ""

# Step 1: Run simulation
echo "========================================================================"
echo "STEP 1: Running Network Simulation"
echo "========================================================================"
echo ""

python3 simulate_network.py --duration $DURATION --event-rate $EVENT_RATE $VERBOSE

if [ $? -ne 0 ]; then
    echo ""
    echo "Error: Simulation failed"
    exit 1
fi

echo ""
echo "Press Enter to continue to analysis..."
read

# Step 2: Analyze convergence
echo ""
echo "========================================================================"
echo "STEP 2: Analyzing Convergence"
echo "========================================================================"
echo ""

python3 convergence_analyzer.py

if [ $? -ne 0 ]; then
    echo ""
    echo "Error: Convergence analysis failed"
    exit 1
fi

echo ""
echo "Press Enter to continue to visualization..."
read

# Step 3: Generate plots
echo ""
echo "========================================================================"
echo "STEP 3: Generating Visualizations"
echo "========================================================================"
echo ""

python3 visualize_results.py

if [ $? -ne 0 ]; then
    echo ""
    echo "Warning: Visualization generation failed (matplotlib may not be installed)"
    echo "Continuing anyway..."
fi

# Summary
echo ""
echo "========================================================================"
echo "                        DEMONSTRATION COMPLETE"
echo "========================================================================"
echo ""
echo "Generated Files:"
echo "  - trust_evolution.json     (Raw trust computation data)"
echo "  - convergence_report.txt   (Statistical analysis)"
echo "  - trust_convergence.png    (Trust evolution over time)"
echo "  - component_breakdown.png  (R, B, H, A components)"
echo "  - final_comparison.png     (Final trust comparison)"
echo ""
echo "Key Points for Your Mentor:"
echo "  1. All trust values start at 0.5 (initial_score)"
echo "  2. Trust is computed purely from packet-level events"
echo "  3. NO external references used"
echo "  4. Convergence demonstrates formula stability"
echo "  5. Edge cases (failures, wrong dest, lies) are handled"
echo ""
echo "Next Steps:"
echo "  - Review convergence_report.txt for statistics"
echo "  - Open PNG files to see trust evolution graphs"
echo "  - Show trust_evolution.json to demonstrate computation"
echo ""
