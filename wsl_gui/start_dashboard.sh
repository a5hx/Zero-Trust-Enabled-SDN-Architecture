#!/bin/bash
# Startup script for Packet Tracer Dashboard
# Run this in WSL terminal

echo "🚀 Starting Zero-Trust SDN Packet Tracer Dashboard"
echo ""

# Get the script directory (works even if called from elsewhere)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3."
    exit 1
fi

# Check if port 8080 is already in use
if lsof -Pi :8080 -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "⚠️  Port 8080 is already in use."
    echo "   Kill existing process? [y/N]"
    read -r response
    if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        lsof -ti:8080 | xargs kill -9
        echo "✓ Killed process on port 8080"
    else
        echo "❌ Aborted. Please free port 8080 manually."
        exit 1
    fi
fi

# Start packet capture server in background
echo "📡 Starting packet capture server on port 8080..."
python3 packet_capture_server.py --port 8080 --host 0.0.0.0 &
SERVER_PID=$!
sleep 2

# Check if server started successfully
if ! ps -p $SERVER_PID > /dev/null; then
    echo "❌ Failed to start packet capture server"
    exit 1
fi

echo "✓ Packet capture server started (PID: $SERVER_PID)"

# Start HTTP file server for dashboard on port 8000
echo "🌐 Starting dashboard web server on port 8000..."
python3 -m http.server 8000 &
HTTP_PID=$!
sleep 2

if ! ps -p $HTTP_PID > /dev/null; then
    echo "❌ Failed to start HTTP server"
    kill $SERVER_PID
    exit 1
fi

echo "✓ Dashboard web server started (PID: $HTTP_PID)"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Dashboard is ready!"
echo ""
echo "📊 Open this URL in your Windows browser:"
echo "   http://localhost:8000/packet_tracer_dashboard.html"
echo ""
echo "🔌 API Server: http://localhost:8080"
echo ""
echo "📝 To stop the dashboard:"
echo "   kill $SERVER_PID $HTTP_PID"
echo "   Or press Ctrl+C in this terminal"
echo ""
echo "💡 Next steps:"
echo "   1. Open the URL above in Chrome/Firefox/Edge"
echo "   2. In another terminal, start your SDN controller"
echo "   3. Watch packets flow in real-time!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Save PIDs to file for easy cleanup
echo "$SERVER_PID $HTTP_PID" > .dashboard_pids

# Wait for user interrupt
trap "echo ''; echo '🛑 Shutting down...'; kill $SERVER_PID $HTTP_PID 2>/dev/null; rm -f .dashboard_pids; echo '✓ Dashboard stopped'; exit 0" INT TERM

# Keep script running
wait
