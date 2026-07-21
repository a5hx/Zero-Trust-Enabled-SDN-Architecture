#!/usr/bin/env python3
"""
Custom Mininet topology for trust convergence demonstration.
Simple 5-node topology with multiple paths for realistic routing scenarios.
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSController
from mininet.cli import CLI
from mininet.log import setLogLevel


class TrustDemoTopology(Topo):
    """
    Topology:
        h1 --- s1 --- s2 --- h2
               |  \   /  |
               |   X X   |
               |  /   \  |
               s3 ----- s4
               |         |
               h3       h4
    
    5 switches, 4 hosts, multiple paths between nodes
    """
    
    def build(self):
        # Add hosts (IoT devices)
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')
        
        # Add switches (edge nodes that we'll compute trust for)
        s1 = self.addSwitch('s1', dpid='0000000000000001')
        s2 = self.addSwitch('s2', dpid='0000000000000002')
        s3 = self.addSwitch('s3', dpid='0000000000000003')
        s4 = self.addSwitch('s4', dpid='0000000000000004')
        s5 = self.addSwitch('s5', dpid='0000000000000005')
        
        # Add links - host to switch
        self.addLink(h1, s1)
        self.addLink(h2, s2)
        self.addLink(h3, s3)
        self.addLink(h4, s4)
        
        # Add links - switch to switch (multiple paths)
        self.addLink(s1, s2)  # Primary path
        self.addLink(s1, s3)  # Alternative path 1
        self.addLink(s1, s5)  # Alternative path 2
        self.addLink(s2, s4)  # Primary path
        self.addLink(s2, s5)  # Cross link
        self.addLink(s3, s4)  # Alternative path
        self.addLink(s3, s5)  # Cross link
        self.addLink(s4, s5)  # Alternative path


def create_network():
    """Create and return the Mininet network instance."""
    topo = TrustDemoTopology()
    net = Mininet(
        topo=topo,
        controller=OVSController,
        autoSetMacs=True,
        autoStaticArp=True
    )
    return net


def test_topology():
    """Test the topology interactively."""
    setLogLevel('info')
    net = create_network()
    net.start()
    print("\n" + "="*60)
    print("Trust Convergence Demo Topology Started")
    print("="*60)
    print("\nHosts:")
    for host in net.hosts:
        print(f"  {host.name}: {host.IP()}")
    print("\nSwitches:")
    for switch in net.switches:
        print(f"  {switch.name}: {switch.dpid}")
    print("\nTest connectivity:")
    net.pingAll()
    print("\nStarting CLI (type 'exit' to quit)...")
    CLI(net)
    net.stop()


if __name__ == '__main__':
    test_topology()
