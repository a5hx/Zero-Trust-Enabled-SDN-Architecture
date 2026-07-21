# 🚀 Quick Start Guide - Packet Tracer Dashboard

## ✅ What You Have Now

The dashboard is **already working** in standalone mode! You can:
- ✅ See the network topology (IoT devices, edge servers, switches)
- ✅ Click "🧪 Send Test Packet" to inject packets
- ✅ Watch packets appear in the capture table
- ✅ See packet animations (blue dots) moving across the network

---

## 📁 File Structure

```
wsl_gui/
├── dashboard_test.html          ← Main dashboard (WORKING NOW!)
├── packet_capture_server.py     ← Backend API server
├── controller_integration.py    ← Hooks for SDN controller
├── start_dashboard.sh           ← Quick start script
├── stop_dashboard.sh            ← Stop all services
├── test_connection.sh           ← Test backend connectivity
├── QUICKSTART.md               ← This file
├── INTEGRATION_GUIDE.md        ← Advanced integration
└── README.md                    ← Full documentation
```

---

## 🎯 Three Ways to Use the Dashboard

### Mode 1: Standalone (Current - No Setup Needed) ✅

**What it does**: Mock topology with test packet injection  
**How to use**: Just open the HTML file

```
File: file:///C:/Users/Arjun/Desktop/Zero-Trust-Enabled-SDN-Architecture/wsl_gui/dashboard_test.html
```

Click **"🧪 Send Test Packet"** → Packets appear instantly!

---

### Mode 2: With Backend Server (Recommended Next Step) 🔥

**What it does**: Real-time packet streaming via API  
**How to use**:

#### Step 1: Start Backend Server (WSL Terminal)

```bash
cd /mnt/c/Users/Arjun/Desktop/Zero-Trust-Enabled-SDN-Architecture/wsl_gui

# Start the packet capture server
python3 packet_capture_server.py --port 8080
```

**Expected output:**
```
INFO: Starting Packet Capture Server on 0.0.0.0:8080
INFO: Server ready. Dashboard URL: http://localhost:8080
INFO: API endpoints:
  GET  /api/events      - SSE stream of real-time events
  GET  /api/packets     - Get recent packets
  GET  /api/topology    - Get network topology
```

Leave this terminal running.

#### Step 2: Test the Connection

In **another WSL terminal**:

```bash
cd /mnt/c/Users/Arjun/Desktop/Zero-Trust-Enabled-SDN-Architecture/wsl_gui

# Make test script executable
chmod +x test_connection.sh

# Run the test
./test_connection.sh
```

**Expected output:**
```
✅ API server is running
✅ Topology endpoint working
✅ Test packet sent successfully
✅ Packet captured and stored
```

#### Step 3: Reload Dashboard

Refresh `dashboard_test.html` in your browser. Status should change from:
- ❌ **"Standalone Mode"** (yellow)
- ✅ **"Connected"** (green)

#### Step 4: Send Packets via API

```bash
# In WSL terminal, send a test packet
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
    "info": "Hello from curl!"
  }'
```

Watch the dashboard → Packet appears + blue dot animates! ✨

---

### Mode 3: With Live SDN Controller (Full Integration) 🚀

**What it does**: Captures real packets from Mininet network  
**How to use**: See `INTEGRATION_GUIDE.md` for details

**Quick version:**

1. **Start backend server** (from Mode 2 above)
2. **Start your SDN controller** with integration:

```bash
# Option A: Read from event bus file (easiest)
cd /mnt/c/Users/Arjun/Desktop/Zero-Trust-Enabled-SDN-Architecture
python3 packet_capture_server.py --port 8080 --event-bus data/events.jsonl &

# Then start your controller
sudo python3 run_demo.py
```

3. **Watch real packets flow!**
   - Every PacketIn from Mininet appears in dashboard
   - ARP requests, TCP SYNs, ICMP pings
   - Real-time trust score updates

---

## 🔧 Common Commands

### Start Dashboard (All-in-One)

```bash
cd /mnt/c/Users/Arjun/Desktop/Zero-Trust-Enabled-SDN-Architecture/wsl_gui

# Make scripts executable (first time only)
chmod +x *.sh

# Start everything
./start_dashboard.sh
```

This starts:
- ✅ Packet capture server (port 8080)
- ✅ HTTP file server (port 8000)
- ✅ Opens dashboard at `http://localhost:8000/dashboard_test.html`

### Stop Dashboard

```bash
# Press Ctrl+C in the terminal where start_dashboard.sh is running

# Or manually:
./stop_dashboard.sh
```

### Check if Server is Running

```bash
curl http://localhost:8080/api/stats
```

Should return: `{"total_packets": 0, "subscribers": 0, ...}`

---

## 🎮 Dashboard Controls

| Button | Function |
|--------|----------|
| **▶ Start Capture** | Begin capturing packets to table |
| **🧪 Send Test Packet** | Inject a test packet (standalone mode) |
| **Clear** | Clear captured packets |
| **Status Indicator** | Green = Connected, Yellow = Standalone |

---

## 🐛 Troubleshooting

### Dashboard shows "Standalone Mode"
**Cause**: Backend server not running  
**Fix**: Start `packet_capture_server.py` in WSL

### "No packets captured"
**Cause**: "Start Capture" not clicked  
**Fix**: Click **"▶ Start Capture"** button at bottom

### Browser console errors
**Cause**: CORS issues with `file://`  
**Fix**: Use HTTP server:
```bash
cd wsl_gui
python3 -m http.server 8000
# Open: http://localhost:8000/dashboard_test.html
```

### Port 8080 already in use
**Fix**:
```bash
# Find and kill process
lsof -ti:8080 | xargs kill -9
```

### Nothing visible in dashboard
**Cause**: Incomplete HTML file  
**Fix**: Use `dashboard_test.html` (not `packet_tracer_dashboard.html`)

---

## 📊 What You'll See

### Left Panel: Devices
- 💡 **IoT Devices**: Purple circles (iot1, iot2, iot3)
- 🖥️ **Edge Servers**: Green circles with trust scores (srv1, srv2)
- ⚡ **Switches**: Blue rectangle (s0)

### Center: Topology Canvas
- Network diagram with animated packet flow
- Blue dots = TCP packets moving between nodes
- Orange dots = ARP packets

### Right Panel: Recent Packets
- Last 10 packets captured
- Protocol, source → destination
- Timestamp

### Bottom: Capture Table
- Wireshark-style packet list
- Click "Start Capture" to begin logging
- Columns: No., Time, Source, Destination, Protocol, Info

---

## ⏭️ Next Steps

1. ✅ **Current**: Dashboard working standalone
2. 🔄 **Next**: Start backend server (Mode 2 above)
3. 🚀 **Final**: Integrate with SDN controller (Mode 3)

**Ready to proceed?**  
Start with **Mode 2** to see real-time packet streaming! 🎉

---

## 📚 More Resources

- **Full documentation**: `README.md`
- **Controller integration**: `INTEGRATION_GUIDE.md`
- **Test connectivity**: `./test_connection.sh`

---

**Questions? Issues?**  
Check browser console (F12) for error messages.
