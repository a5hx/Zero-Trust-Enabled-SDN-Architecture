#!/usr/bin/env python3
"""
Packet Capture Server for Zero-Trust SDN Dashboard

This server integrates with the Osken controller to capture real-time packet
events and stream them to the Packet Tracer dashboard via SSE.

Features:
- Captures PacketIn events from OpenFlow controller
- Parses Ethernet/IP/TCP/ARP/ICMP headers
- Provides REST API + Server-Sent Events (SSE)
- Integrates with existing event bus
"""

import argparse
import json
import logging
import queue
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from controller.event_bus import EventBus

logger = logging.getLogger(__name__)


class PacketCapture:
    """Captures and stores packet events from the controller."""
    
    def __init__(self, max_packets: int = 1000):
        self.packets: List[Dict[str, Any]] = []
        self.max_packets = max_packets
        self.lock = threading.Lock()
        self.packet_id = 0
        
    def add_packet(self, packet: Dict[str, Any]) -> None:
        """Add a captured packet."""
        with self.lock:
            self.packet_id += 1
            packet['packet_id'] = self.packet_id
            packet['timestamp'] = packet.get('timestamp', time.time() * 1000)
            
            self.packets.append(packet)
            if len(self.packets) > self.max_packets:
                self.packets.pop(0)  # FIFO
    
    def get_packets(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent packets."""
        with self.lock:
            return self.packets[-limit:]
    
    def get_packet(self, packet_id: int) -> Optional[Dict[str, Any]]:
        """Get specific packet by ID."""
        with self.lock:
            for pkt in reversed(self.packets):
                if pkt['packet_id'] == packet_id:
                    return pkt
        return None
    
    def clear(self) -> None:
        """Clear all captured packets."""
        with self.lock:
            self.packets.clear()


class SSEManager:
    """Manages Server-Sent Events subscriptions."""
    
    def __init__(self):
        self.subscribers: List[queue.Queue] = []
        self.lock = threading.Lock()
    
    def subscribe(self) -> queue.Queue:
        """Subscribe to SSE events."""
        q = queue.Queue(maxsize=50)
        with self.lock:
            self.subscribers.append(q)
        return q
    
    def unsubscribe(self, q: queue.Queue) -> None:
        """Unsubscribe from SSE events."""
        with self.lock:
            if q in self.subscribers:
                self.subscribers.remove(q)
    
    def broadcast(self, event_type: str, data: Dict[str, Any]) -> None:
        """Broadcast event to all subscribers."""
        with self.lock:
            dead = []
            for q in self.subscribers:
                try:
                    q.put_nowait({'event': event_type, 'data': data})
                except queue.Full:
                    # Drop oldest event
                    try:
                        q.get_nowait()
                        q.put_nowait({'event': event_type, 'data': data})
                    except:
                        pass
            # Clean up dead subscribers
            for q in dead:
                self.subscribers.remove(q)


# Global instances
packet_capture = PacketCapture()
sse_manager = SSEManager()


class PacketCaptureHandler(BaseHTTPRequestHandler):
    """HTTP request handler for packet capture API."""
    
    def log_message(self, format, *args):
        """Override to use logger."""
        logger.debug(format % args)
    
    def _send_cors_headers(self):
        """Send CORS headers for cross-origin requests."""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
    
    def _send_json(self, code: int, data: Any) -> None:
        """Send JSON response."""
        self.send_response(code)
        self._send_cors_headers()
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))
    
    def _send_sse(self, q: queue.Queue) -> None:
        """Send Server-Sent Events stream."""
        self.send_response(200)
        self._send_cors_headers()
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Connection', 'keep-alive')
        self.end_headers()
        
        try:
            while True:
                try:
                    event = q.get(timeout=30)  # 30s keepalive
                    if event is None:
                        break
                    
                    # Format as SSE
                    self.wfile.write(f"event: {event['event']}\n".encode('utf-8'))
                    self.wfile.write(f"data: {json.dumps(event['data'])}\n\n".encode('utf-8'))
                    self.wfile.flush()
                except queue.Empty:
                    # Send keepalive comment
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            sse_manager.unsubscribe(q)
    
    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()
    
    def do_GET(self):
        """Handle GET requests."""
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)
        
        try:
            if path == '/api/events':
                # SSE stream
                q = sse_manager.subscribe()
                self._send_sse(q)
            
            elif path == '/api/packets':
                # Get recent packets
                limit = int(params.get('limit', ['100'])[0])
                packets = packet_capture.get_packets(limit)
                self._send_json(200, {'packets': packets})
            
            elif path.startswith('/api/packet/'):
                # Get specific packet
                packet_id = int(path.split('/')[-1])
                packet = packet_capture.get_packet(packet_id)
                if packet:
                    self._send_json(200, packet)
                else:
                    self._send_json(404, {'error': 'Packet not found'})
            
            elif path == '/api/topology':
                # Get topology (mock for now, should integrate with controller)
                topology = self._get_topology()
                self._send_json(200, topology)
            
            elif path == '/api/stats':
                # Get statistics
                stats = {
                    'total_packets': len(packet_capture.packets),
                    'subscribers': len(sse_manager.subscribers),
                    'uptime': time.time()
                }
                self._send_json(200, stats)
            
            else:
                self._send_json(404, {'error': 'Not found'})
        
        except Exception as e:
            logger.exception("GET request failed")
            self._send_json(500, {'error': str(e)})
    
    def do_POST(self):
        """Handle POST requests."""
        parsed = urlparse(self.path)
        path = parsed.path
        
        try:
            # Read request body
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(body) if body else {}
            
            if path == '/api/packet':
                # Manual packet injection (for testing)
                packet_capture.add_packet(data)
                sse_manager.broadcast('packet', data)
                self._send_json(201, {'status': 'created'})
            
            elif path == '/api/clear':
                # Clear all packets
                packet_capture.clear()
                self._send_json(200, {'status': 'cleared'})
            
            else:
                self._send_json(404, {'error': 'Not found'})
        
        except Exception as e:
            logger.exception("POST request failed")
            self._send_json(500, {'error': str(e)})
    
    def _get_topology(self) -> Dict[str, Any]:
        """Get network topology (should be populated by controller integration)."""
        # This is a mock - in real implementation, this would come from
        # the controller's TrustState or topology configuration
        return {
            'iot': [
                {'id': 'iot1', 'ip': '10.0.0.1', 'mac': '00:00:00:00:00:01', 'type': 'iot'},
                {'id': 'iot2', 'ip': '10.0.0.2', 'mac': '00:00:00:00:00:02', 'type': 'iot'},
                {'id': 'iot3', 'ip': '10.0.0.3', 'mac': '00:00:00:00:00:03', 'type': 'iot'},
            ],
            'edge': [
                {'id': 'srv1', 'ip': '10.0.1.1', 'mac': '00:00:00:00:01:01', 'type': 'edge', 'trust_score': 0.95},
                {'id': 'srv2', 'ip': '10.0.1.2', 'mac': '00:00:00:00:01:02', 'type': 'edge', 'trust_score': 0.85},
                {'id': 'srv3', 'ip': '10.0.1.3', 'mac': '00:00:00:00:01:03', 'type': 'edge', 'trust_score': 0.75},
            ],
            'switches': [
                {'id': 's0', 'type': 'switch', 'name': 'Core Switch'},
            ],
            'links': []
        }


def integrate_with_event_bus(event_bus_file: Optional[Path] = None) -> None:
    """
    Integrate with existing event bus by reading from recorded events.
    In production, this would subscribe to the live event bus.
    """
    if not event_bus_file or not event_bus_file.exists():
        logger.warning("No event bus file found, running in standalone mode")
        return
    
    def reader_thread():
        """Read events from file and broadcast them."""
        try:
            with open(event_bus_file, 'r') as f:
                f.seek(0, 2)  # Seek to end
                while True:
                    line = f.readline()
                    if line:
                        try:
                            event = json.loads(line)
                            # Convert controller events to packet format
                            if event.get('type') == 'packet_in':
                                packet = convert_event_to_packet(event)
                                packet_capture.add_packet(packet)
                                sse_manager.broadcast('packet', packet)
                            elif event.get('type') == 'flow_stats':
                                sse_manager.broadcast('flow_stats', event)
                            elif event.get('type') == 'trust_update':
                                sse_manager.broadcast('trust_update', event)
                        except json.JSONDecodeError:
                            pass
                    else:
                        time.sleep(0.1)  # Wait for new events
        except Exception as e:
            logger.exception("Event bus reader failed")
    
    thread = threading.Thread(target=reader_thread, daemon=True)
    thread.start()
    logger.info("Integrated with event bus: %s", event_bus_file)


def convert_event_to_packet(event: Dict[str, Any]) -> Dict[str, Any]:
    """Convert controller event to packet format for dashboard."""
    packet = {
        'timestamp': event.get('ts', time.time()) * 1000,
        'eth_src': event.get('eth_src', 'unknown'),
        'eth_dst': event.get('eth_dst', 'unknown'),
        'src_ip': event.get('ipv4_src'),
        'dst_ip': event.get('ipv4_dst'),
        'tcp_src': event.get('tcp_src'),
        'tcp_dst': event.get('tcp_dst'),
        'protocol': event.get('protocol', 'TCP'),
        'length': event.get('length', 0),
        'info': event.get('info', ''),
        'dpid': event.get('dpid'),
        'in_port': event.get('in_port'),
    }
    
    # Generate info string
    if packet['src_ip'] and packet['dst_ip']:
        if packet['tcp_src'] and packet['tcp_dst']:
            packet['info'] = f"{packet['tcp_src']} → {packet['tcp_dst']}"
    
    return packet


def run_server(host: str = '0.0.0.0', port: int = 8080, event_bus_file: Optional[Path] = None):
    """Run the packet capture server."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    )
    
    logger.info("Starting Packet Capture Server on %s:%d", host, port)
    
    # Integrate with event bus if available
    integrate_with_event_bus(event_bus_file)
    
    # Start HTTP server
    server = HTTPServer((host, port), PacketCaptureHandler)
    
    logger.info("Server ready. Dashboard URL: http://%s:%d", 
                'localhost' if host == '0.0.0.0' else host, port)
    logger.info("API endpoints:")
    logger.info("  GET  /api/events      - SSE stream of real-time events")
    logger.info("  GET  /api/packets     - Get recent packets")
    logger.info("  GET  /api/topology    - Get network topology")
    logger.info("  POST /api/packet      - Inject test packet")
    logger.info("  POST /api/clear       - Clear captured packets")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.shutdown()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Packet Capture Server for SDN Dashboard')
    parser.add_argument('--host', default='0.0.0.0', help='Server host (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8080, help='Server port (default: 8080)')
    parser.add_argument('--event-bus', type=Path, help='Path to event bus JSONL file')
    
    args = parser.parse_args()
    run_server(args.host, args.port, args.event_bus)
