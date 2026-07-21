#!/bin/bash
# Test script to verify dashboard connectivity

echo "🧪 Testing Packet Tracer Dashboard Connection"
echo ""

# Test 1: Check if server is running
echo "Test 1: Checking if API server is running on port 8080..."
if curl -s http://localhost:8080/api/stats > /dev/null 2>&1; then
    echo "✅ API server is running"
    curl -s http://localhost:8080/api/stats | python3 -m json.tool
else
    echo "❌ API server is NOT running"
    echo "   Start it with: python3 packet_capture_server.py --port 8080"
    exit 1
fi

echo ""

# Test 2: Check topology endpoint
echo "Test 2: Fetching topology..."
if curl -s http://localhost:8080/api/topology > /dev/null 2>&1; then
    echo "✅ Topology endpoint working"
else
    echo "⚠️  Topology endpoint not responding"
fi

echo ""

# Test 3: Send test packet
echo "Test 3: Sending test packet..."
RESPONSE=$(curl -s -X POST http://localhost:8080/api/packet \
  -H "Content-Type: application/json" \
  -d '{
    "eth_src": "00:00:00:00:00:01",
    "eth_dst": "00:00:00:00:01:01",
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.1.1",
    "tcp_src": 54321,
    "tcp_dst": 80,
    "protocol": "TCP",
    "length": 66,
    "info": "Test packet from script"
  }')

if echo "$RESPONSE" | grep -q "created"; then
    echo "✅ Test packet sent successfully"
else
    echo "❌ Failed to send test packet"
    echo "   Response: $RESPONSE"
fi

echo ""

# Test 4: Verify packet was captured
echo "Test 4: Checking if packet was captured..."
sleep 1
PACKETS=$(curl -s http://localhost:8080/api/packets?limit=1)
if echo "$PACKETS" | grep -q "10.0.0.1"; then
    echo "✅ Packet captured and stored"
    echo "$PACKETS" | python3 -m json.tool
else
    echo "⚠️  Packet not found in capture"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ All tests passed!"
echo ""
echo "📊 Open dashboard in browser:"
echo "   http://localhost:8000/dashboard_test.html"
echo ""
echo "   Or direct file:"
echo "   file:///C:/Users/Arjun/Desktop/Zero-Trust-Enabled-SDN-Architecture/wsl_gui/dashboard_test.html"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
