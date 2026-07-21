#!/bin/bash
# Stop the dashboard services

echo "🛑 Stopping Zero-Trust SDN Dashboard..."

# Get the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Read PIDs from file
if [ -f .dashboard_pids ]; then
    PIDS=$(cat .dashboard_pids)
    for PID in $PIDS; do
        if ps -p $PID > /dev/null 2>&1; then
            kill $PID 2>/dev/null
            echo "✓ Killed process $PID"
        fi
    done
    rm -f .dashboard_pids
else
    # Try to find and kill by port
    echo "No PID file found. Searching for processes..."
    
    # Kill process on port 8080 (API server)
    PID_8080=$(lsof -ti:8080 2>/dev/null)
    if [ ! -z "$PID_8080" ]; then
        kill $PID_8080 2>/dev/null
        echo "✓ Killed packet capture server (port 8080)"
    fi
    
    # Kill process on port 8000 (HTTP server)
    PID_8000=$(lsof -ti:8000 2>/dev/null)
    if [ ! -z "$PID_8000" ]; then
        kill $PID_8000 2>/dev/null
        echo "✓ Killed HTTP server (port 8000)"
    fi
fi

echo "✅ Dashboard services stopped"
