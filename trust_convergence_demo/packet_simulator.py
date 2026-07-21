#!/usr/bin/env python3
"""
Packet-level event simulator with edge cases for trust convergence demo.
Generates realistic traffic patterns including failures and anomalies.
"""

import random
import time
from typing import List
from trust_compute import PacketEvent


class PacketSimulator:
    """Simulates packet events with various edge cases."""
    
    def __init__(self, switches: List[str], duration: int = 60):
        self.switches = switches
        self.duration = duration
        self.events: List[PacketEvent] = []
        
        # Simulate different node behaviors
        self.node_profiles = {
            's1': 'normal',      # Well-behaved node
            's2': 'intermittent',  # Sometimes fails
            's3': 'malicious',   # Wrong destinations + lies about resources
            's4': 'overloaded',  # High latency, honest about it
            's5': 'liar',        # Good performance but lies about CPU
        }
        
        print(f"\nPacket Simulator Initialized:")
        print(f"  Duration: {duration}s")
        print(f"  Switches: {len(switches)}")
        print("\n  Node Profiles:")
        for switch, profile in self.node_profiles.items():
            print(f"    {switch}: {profile}")
    
    def generate_events(self, events_per_second: float = 2.0) -> List[PacketEvent]:
        """
        Generate packet events over the simulation duration.
        Includes various edge cases to demonstrate trust computation.
        """
        print(f"\n{'='*60}")
        print("Generating Packet Events with Edge Cases")
        print(f"{'='*60}")
        
        total_events = int(self.duration * events_per_second)
        events = []
        
        for i in range(total_events):
            t = i / events_per_second
            switch = random.choice(self.switches)
            profile = self.node_profiles.get(switch, 'normal')
            
            event = self._generate_event_by_profile(t, switch, profile, i)
            events.append(event)
            
            # Add some specific edge cases at key times
            if t == 10.0:
                # Packet failure at t=10s for s2
                events.append(PacketEvent(
                    timestamp=t,
                    switch_id='s2',
                    event_type='failure',
                    latency_ms=0.0,
                    reported_cpu=0.3,
                    actual_cpu=0.3,
                    details="EDGE CASE: Packet drop due to buffer overflow"
                ))
            
            if t == 20.0:
                # Wrong destination routing at t=20s for s3
                events.append(PacketEvent(
                    timestamp=t,
                    switch_id='s3',
                    event_type='wrong_dest',
                    latency_ms=50.0,
                    reported_cpu=0.2,
                    actual_cpu=0.5,
                    details="EDGE CASE: Packet routed to wrong destination (10.0.0.3 → 10.0.0.1)"
                ))
            
            if t == 30.0:
                # Resource lying at t=30s for s5
                events.append(PacketEvent(
                    timestamp=t,
                    switch_id='s5',
                    event_type='resource_lie',
                    latency_ms=25.0,
                    reported_cpu=0.1,  # Claims low usage
                    actual_cpu=0.8,    # Actually heavily loaded
                    details="EDGE CASE: Node lying about CPU load (reported=0.1, actual=0.8)"
                ))
            
            if t == 40.0:
                # Timeout at t=40s for s4
                events.append(PacketEvent(
                    timestamp=t,
                    switch_id='s4',
                    event_type='timeout',
                    latency_ms=600.0,  # Exceeds threshold
                    reported_cpu=0.9,
                    actual_cpu=0.9,
                    details="EDGE CASE: Packet timeout (latency > 500ms)"
                ))
        
        self.events = sorted(events, key=lambda e: e.timestamp)
        
        print(f"\n✓ Generated {len(self.events)} packet events")
        print(f"  Event types breakdown:")
        event_types = {}
        for e in self.events:
            event_types[e.event_type] = event_types.get(e.event_type, 0) + 1
        for etype, count in sorted(event_types.items()):
            print(f"    {etype}: {count}")
        
        return self.events
    
    def _generate_event_by_profile(
        self, 
        timestamp: float, 
        switch: str, 
        profile: str,
        event_num: int
    ) -> PacketEvent:
        """Generate an event based on the node's behavioral profile."""
        
        if profile == 'normal':
            # Well-behaved: mostly success, low latency, honest
            event_type = 'success' if random.random() > 0.05 else 'failure'
            latency = random.uniform(10, 50)
            cpu = random.uniform(0.2, 0.5)
            reported_cpu = cpu + random.uniform(-0.05, 0.05)
            details = "Normal operation"
        
        elif profile == 'intermittent':
            # Occasionally fails (20% failure rate)
            event_type = 'success' if random.random() > 0.2 else 'failure'
            latency = random.uniform(20, 80)
            cpu = random.uniform(0.3, 0.6)
            reported_cpu = cpu + random.uniform(-0.05, 0.05)
            details = "Intermittent failures due to congestion"
        
        elif profile == 'malicious':
            # Wrong destinations + lies about resources
            if random.random() < 0.15:
                event_type = 'wrong_dest'
                details = "Malicious routing to wrong destination"
            else:
                event_type = 'success' if random.random() > 0.1 else 'failure'
                details = "Malicious node behavior"
            latency = random.uniform(30, 100)
            cpu = random.uniform(0.4, 0.8)
            reported_cpu = cpu - random.uniform(0.2, 0.4)  # Under-reports CPU
        
        elif profile == 'overloaded':
            # High latency but honest
            event_type = 'success' if random.random() > 0.15 else 'timeout'
            latency = random.uniform(100, 400)
            cpu = random.uniform(0.7, 0.95)
            reported_cpu = cpu + random.uniform(-0.05, 0.05)
            details = "Overloaded node, high latency"
        
        elif profile == 'liar':
            # Good performance but lies about resources
            event_type = 'success' if random.random() > 0.05 else 'failure'
            latency = random.uniform(20, 60)
            cpu = random.uniform(0.5, 0.9)
            reported_cpu = random.uniform(0.1, 0.3)  # Always reports low
            details = "Node consistently under-reports CPU usage"
        
        else:
            # Default
            event_type = 'success'
            latency = random.uniform(20, 60)
            cpu = random.uniform(0.3, 0.6)
            reported_cpu = cpu
            details = "Default behavior"
        
        return PacketEvent(
            timestamp=timestamp,
            switch_id=switch,
            event_type=event_type,
            latency_ms=latency,
            reported_cpu=cpu,
            actual_cpu=cpu if 'liar' not in profile and 'malicious' not in profile else cpu,
            details=details
        )


def main():
    """Test the packet simulator."""
    switches = ['s1', 's2', 's3', 's4', 's5']
    simulator = PacketSimulator(switches, duration=60)
    events = simulator.generate_events(events_per_second=1.0)
    
    print(f"\n{'='*60}")
    print("Sample Events:")
    print(f"{'='*60}")
    for event in events[:10]:
        print(f"t={event.timestamp:.2f}s | {event.switch_id} | "
              f"{event.event_type} | latency={event.latency_ms:.1f}ms")


if __name__ == '__main__':
    main()
