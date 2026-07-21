# 🔌 Integration Guide - Connect Dashboard to Live SDN Controller

## Current Status
✅ Dashboard working standalone  
⏳ Need to connect to real Mininet packets

## Option 1: Quick Integration (Recommended)

### Step 1: Start Backend Server in WSL

```bash
cd /mnt/c/Users/Arjun/Desktop/Zero-Trust-Enabled-SDN-Architecture/wsl_gui
python3 packet_capture_server.py --port 8080 --event-bus ../data/events.jsonl &
```

This will:
- Start API server on port 8080
- Read from existing event bus file
- No code changes needed!

### Step 2: Refresh Dashboard

Reload `dashboard_test.html` in your browser. Status should change to "Connected" in green.

### Step 3: Run Your SDN Demo

In another WSL terminal:
```bash
cd /mnt/c/Users/Arjun/Desktop/Zero-Trust-Enabled-SDN-Architecture
sudo python3 run_demo.py
```

Packets should now appear in real-time! 🎉

---

## Option 2: Direct Controller Integration (More Features)

For full packet capture with protocol parsing, modify `controller/trust_balancer.py`:

### Step 1: Add Import

Add at top of `trust_balancer.py`:
```python
from wsl_gui.controller_integration import PacketCaptureIntegration
```

### Step 2: Initialize in `__init__`

In `TrustBalancerApp.__init__()`, after `self.bus = EventBus(...)`:
```python
# Initialize packet capture for dashboard
self.packet_capture = PacketCaptureIntegration(self.bus)
logger.info("Packet capture integration enabled")
```

### Step 3: Capture PacketIn Events

In `packet_in_handler()`, after parsing the packet:

```python
@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
def packet_in_handler(self, ev):
    msg = ev.msg
    dp = msg.datapath
    
    pkt = packet.Packet(msg.data)
    eth = pkt.get_protocol(ethernet.ethernet)
    
    if eth is None:
        return
    
    # ✨ Add this line to capture packets for dashboard
    if hasattr(self, 'packet_capture'):
        self.packet_capture.capture_packet_in(msg, pkt, eth, dp)
    
    # ... rest of your existing handler code ...
```

### Step 4: Test

```bash
# Terminal 1: Start packet server
python3 wsl_gui/packet_capture_server.py --port 8080

# Terminal 2: Start controller with integration
sudo python3 run_demo.py

# Terminal 3: Generate traffic (if needed)
# Mininet CLI: pingall
```

---

## Option 3: Automatic Integration (Easiest)

Use the auto-integration wrapper:

### Modify `controller/osken_manager.py`

After creating the TrustBalancerApp:

```python
from controller.trust_balancer import TrustBalancerApp
from wsl_gui.controller_integration import integrate_into_controller

# Create app
app = TrustBalancerApp(...)

# ✨ Add this single line
integrate_into_controller(app)

# Continue with manager setup...
```

That's it! The integration will automatically hook into packet_in_handler.

---

## Verification

Once integrated, you should see:

1. **In Terminal**: 
   ```
   [INFO] PacketCaptureIntegration initialized
   [INFO] packet_in: eth_src=00:00:00:00:00:01, eth_dst=00:00:00:00:01:01, protocol=TCP
   ```

2. **In Dashboard**:
   - Status changes to "Connected" (green)
   - Packets appear in real-time
   - Blue dots animate across the topology
   - Packet count increases

3. **In Browser Console (F12)**:
   ```
   SSE connected to http://localhost:8080/api/events
   Received packet: {src_ip: "10.0.0.1", dst_ip: "10.0.1.1", protocol: "TCP", ...}
   ```

---

## Troubleshooting

### Dashboard shows "Standalone Mode"
**Cause**: Backend server not running  
**Fix**: Start packet_capture_server.py in WSL

### "Connection failed" in browser
**Cause**: CORS or port blocked  
**Fix**: 
```bash
# Check if server is running
curl http://localhost:8080/api/stats

# Should return: {"total_packets": 0, ...}
```

### No packets appearing
**Cause**: Controller not integrated  
**Fix**: Add packet_capture.capture_packet_in() call (see Option 2)

### Packets appearing but not animating
**Cause**: IP addresses don't match topology  
**Fix**: Check browser console for "Unknown device" warnings

---

## Testing Without Full Controller

Send test packets via API:

```bash
curl -X POST http://localhost:8080/api/packet \
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
    "info": "Test SYN packet"
  }'
```

You should see this packet immediately in the dashboard!

---

## What Gets Captured

- ✅ **PacketIn events**: First packet of each new flow
- ✅ **ARP requests/replies**: MAC address discovery
- ✅ **TCP SYN**: Connection establishment to VIP
- ✅ **Protocol details**: Full L2/L3/L4 header parsing
- ✅ **Timestamps**: Millisecond precision
- ✅ **Switch info**: Which datapath received the packet

## What Doesn't Get Captured

- ❌ Packets switched in data plane (after flow rule installed)
- ❌ Packets between already-learned MAC addresses
- ❌ Payload data (only headers)

For data-plane traffic, use flow stats (already polled by `flow_stats.py`).

---

## Next Steps

Once working:
1. ✅ Verify packets appear for new connections
2. ✅ Test with `pingall` in Mininet
3. ✅ Start IoT clients sending tasks to VIP
4. ✅ Watch quarantine events trigger
5. ✅ Export packet capture for analysis

Happy packet hunting! 🦈
