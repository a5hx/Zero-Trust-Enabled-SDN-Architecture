# 📋 Dashboard Cheat Sheet

## 🎯 Quick Access

**Dashboard URL (works now!):**
```
file:///C:/Users/Arjun/Desktop/Zero-Trust-Enabled-SDN-Architecture/wsl_gui/dashboard_test.html
```

---

## 🚀 3-Step Setup for Live Mode

### 1️⃣ Start Backend (WSL)
```bash
cd /mnt/c/Users/Arjun/Desktop/Zero-Trust-Enabled-SDN-Architecture/wsl_gui
python3 packet_capture_server.py --port 8080
```

### 2️⃣ Test Connection (WSL)
```bash
./test_connection.sh
```

### 3️⃣ Reload Dashboard (Browser)
Refresh `dashboard_test.html` → Status turns green ✅

---

## 📡 Send Test Packets

### Via Dashboard UI
Click **"🧪 Send Test Packet"** button

### Via API (WSL)
```bash
curl -X POST http://localhost:8080/api/packet \
  -H "Content-Type: application/json" \
  -d '{"src_ip":"10.0.0.1","dst_ip":"10.0.1.1","protocol":"TCP","info":"Test"}'
```

---

## 🎮 Dashboard Buttons

| Button | Action |
|--------|--------|
| **▶ Start Capture** | Begin logging packets to table |
| **🧪 Send Test Packet** | Inject test packet (standalone) |
| **Clear** | Clear all captured packets |

---

## ✅ Status Indicators

| Status | Meaning |
|--------|---------|
| 🟢 **Connected** | Backend server running, live mode |
| 🟡 **Standalone Mode** | No backend, test packets only |
| 🔴 **Reconnecting...** | Lost connection, retrying |

---

## 🛠️ Useful Commands

```bash
# Check if backend is running
curl http://localhost:8080/api/stats

# Kill port 8080
lsof -ti:8080 | xargs kill -9

# Make scripts executable
chmod +x wsl_gui/*.sh

# Start everything at once
./start_dashboard.sh

# Stop everything
./stop_dashboard.sh
```

---

## 📂 Important Files

| File | Purpose |
|------|---------|
| `dashboard_test.html` | ⭐ Main dashboard (use this!) |
| `packet_capture_server.py` | Backend API server |
| `QUICKSTART.md` | Full setup guide |
| `INTEGRATION_GUIDE.md` | SDN controller integration |

---

## 🐛 Quick Fixes

**Nothing visible?** → Use `dashboard_test.html` (not `packet_tracer_dashboard.html`)

**No packets?** → Click "▶ Start Capture" button first

**Port in use?** → `lsof -ti:8080 | xargs kill -9`

**CORS error?** → Serve via HTTP: `python3 -m http.server 8000`

---

## 📞 Support

1. Check browser console (F12) for errors
2. Read `QUICKSTART.md` for detailed steps
3. See `INTEGRATION_GUIDE.md` for SDN integration
