#!/usr/bin/env python3
"""
Controller Integration for Packet Capture Dashboard

This module hooks into the TrustBalancerApp to capture real-time PacketIn events
and publish them to the packet capture server.

Usage:
    Add this to your controller startup (or modify trust_balancer.py):
    
    from wsl_gui.controller_integration import PacketCaptureIntegration
    
    # In TrustBalancerApp.__init__():
    self.packet_capture = PacketCaptureIntegration(self.bus)
    
    # In packet_in_handler(), after parsing:
    self.packet_capture.capture_packet_in(msg, pkt, eth, dp)
"""

import logging
import struct
import time
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class PacketCaptureIntegration:
    """Captures PacketIn events and publishes them to event bus."""
    
    def __init__(self, event_bus: Any):
        self.bus = event_bus
        self.enabled = True
        logger.info("PacketCaptureIntegration initialized")
    
    def capture_packet_in(self, msg: Any, pkt: Any, eth: Any, dp: Any) -> None:
        """
        Capture an OpenFlow PacketIn event and parse it.
        
        Args:
            msg: OFPPacketIn message
            pkt: Parsed packet from packet.Packet
            eth: Ethernet header
            dp: Datapath (switch)
        """
        if not self.enabled:
            return
        
        try:
            # Extract timestamp
            timestamp = time.time()
            
            # Basic ethernet info
            packet_data = {
                'timestamp': timestamp,
                'dpid': dp.id,
                'in_port': msg.match['in_port'] if hasattr(msg, 'match') else None,
                'eth_src': eth.src,
                'eth_dst': eth.dst,
                'eth_type': hex(eth.ethertype),
                'length': len(msg.data) if hasattr(msg, 'data') else 0,
                'buffer_id': msg.buffer_id if hasattr(msg, 'buffer_id') else None,
            }
            
            # Parse layer 3+
            from os_ken.lib.packet import packet, ethernet, ipv4, ipv6, arp, icmp, tcp, udp
            
            # Try to find IP layer
            ip4 = pkt.get_protocol(ipv4.ipv4)
            ip6 = pkt.get_protocol(ipv6.ipv6)
            arp_pkt = pkt.get_protocol(arp.arp)
            
            if ip4:
                packet_data['protocol'] = 'IPv4'
                packet_data['src_ip'] = ip4.src
                packet_data['dst_ip'] = ip4.dst
                packet_data['ip_proto'] = ip4.proto
                packet_data['ttl'] = ip4.ttl
                packet_data['tos'] = ip4.tos
                
                # Parse transport layer
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                udp_pkt = pkt.get_protocol(udp.udp)
                icmp_pkt = pkt.get_protocol(icmp.icmp)
                
                if tcp_pkt:
                    packet_data['protocol'] = 'TCP'
                    packet_data['tcp_src'] = tcp_pkt.src_port
                    packet_data['tcp_dst'] = tcp_pkt.dst_port
                    packet_data['tcp_flags'] = self._format_tcp_flags(tcp_pkt)
                    packet_data['tcp_seq'] = tcp_pkt.seq
                    packet_data['tcp_ack'] = tcp_pkt.ack
                    packet_data['info'] = f"{tcp_pkt.src_port} → {tcp_pkt.dst_port} [{packet_data['tcp_flags']}]"
                
                elif udp_pkt:
                    packet_data['protocol'] = 'UDP'
                    packet_data['udp_src'] = udp_pkt.src_port
                    packet_data['udp_dst'] = udp_pkt.dst_port
                    packet_data['info'] = f"{udp_pkt.src_port} → {udp_pkt.dst_port}"
                
                elif icmp_pkt:
                    packet_data['protocol'] = 'ICMP'
                    packet_data['icmp_type'] = icmp_pkt.type
                    packet_data['icmp_code'] = icmp_pkt.code
                    packet_data['info'] = f"Type {icmp_pkt.type} Code {icmp_pkt.code}"
            
            elif ip6:
                packet_data['protocol'] = 'IPv6'
                packet_data['src_ip'] = ip6.src
                packet_data['dst_ip'] = ip6.dst
                packet_data['info'] = 'IPv6 packet'
            
            elif arp_pkt:
                packet_data['protocol'] = 'ARP'
                packet_data['arp_op'] = arp_pkt.opcode
                packet_data['src_ip'] = arp_pkt.src_ip
                packet_data['dst_ip'] = arp_pkt.dst_ip
                op_str = 'Request' if arp_pkt.opcode == 1 else 'Reply'
                packet_data['info'] = f"ARP {op_str}: Who has {arp_pkt.dst_ip}? Tell {arp_pkt.src_ip}"
            
            else:
                packet_data['protocol'] = 'Unknown'
                packet_data['info'] = f"Ethertype {packet_data['eth_type']}"
            
            # Publish to event bus
            self.bus.publish('packet_in', **packet_data)
            
        except Exception as e:
            logger.exception("Failed to capture packet: %s", e)
    
    def _format_tcp_flags(self, tcp_pkt: Any) -> str:
        """Format TCP flags as string (e.g., 'SYN', 'ACK', 'PSH,ACK')."""
        flags = []
        if tcp_pkt.bits & 0x01:  # FIN
            flags.append('FIN')
        if tcp_pkt.bits & 0x02:  # SYN
            flags.append('SYN')
        if tcp_pkt.bits & 0x04:  # RST
            flags.append('RST')
        if tcp_pkt.bits & 0x08:  # PSH
            flags.append('PSH')
        if tcp_pkt.bits & 0x10:  # ACK
            flags.append('ACK')
        if tcp_pkt.bits & 0x20:  # URG
            flags.append('URG')
        return ','.join(flags) if flags else 'None'
    
    def enable(self):
        """Enable packet capture."""
        self.enabled = True
        logger.info("Packet capture enabled")
    
    def disable(self):
        """Disable packet capture."""
        self.enabled = False
        logger.info("Packet capture disabled")


def integrate_into_controller(trust_balancer_app: Any) -> PacketCaptureIntegration:
    """
    Convenience function to integrate packet capture into TrustBalancerApp.
    
    Usage:
        from wsl_gui.controller_integration import integrate_into_controller
        
        # After TrustBalancerApp is created:
        packet_capture = integrate_into_controller(app)
    
    Args:
        trust_balancer_app: Instance of TrustBalancerApp
    
    Returns:
        PacketCaptureIntegration instance
    """
    capture = PacketCaptureIntegration(trust_balancer_app.bus)
    
    # Hook into packet_in_handler
    original_handler = trust_balancer_app.packet_in_handler
    
    def wrapped_handler(ev):
        # Call original handler
        result = original_handler(ev)
        
        # Capture packet
        try:
            msg = ev.msg
            dp = msg.datapath
            
            from os_ken.lib.packet import packet, ethernet
            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocol(ethernet.ethernet)
            
            if eth:
                capture.capture_packet_in(msg, pkt, eth, dp)
        except Exception as e:
            logger.exception("Packet capture wrapper failed: %s", e)
        
        return result
    
    trust_balancer_app.packet_in_handler = wrapped_handler
    logger.info("Packet capture integrated into controller")
    
    return capture
