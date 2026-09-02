#!/usr/bin/env python3
"""
Minimal demo topology: 7 switches, 1 host each, chained together,
controlled by a remote Ryu controller. Auto-launches an xterm for
each host so the simulation is visually "live" without manual CLI steps.

    h1--s1--s2--s3--s4--s5--s6--s7--h7
         |   |   |   |   |   |
         h2  h3  h4  h5  h6

Run:
    Terminal 1 (Ryu venv):
        source ~/ryu-env/bin/activate
        ryu-manager ryu.app.simple_switch_13

    Terminal 2 (system python, needs root):
        sudo python3 demo_topo.py
"""
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel


def build():
    net = Mininet(switch=OVSSwitch, controller=None, autoSetMacs=True)
    c0 = net.addController('c0', controller=RemoteController,
                            ip='127.0.0.1', port=6653)

    switches = [net.addSwitch(f's{i}', protocols='OpenFlow13')
                for i in range(1, 8)]
    hosts = [net.addHost(f'h{i}', ip=f'10.0.0.{i}/24')
             for i in range(1, 8)]

    # one host per switch
    for sw, h in zip(switches, hosts):
        net.addLink(sw, h)

    # chain the switches: s1-s2-s3-...-s7
    for i in range(len(switches) - 1):
        net.addLink(switches[i], switches[i + 1])

    net.start()

    print("\n*** Launching a live terminal window for each host")
    for h in hosts:
        h.cmd('xterm -hold -e bash &')

    print("\n*** Testing full connectivity (this triggers rule installs)")
    net.pingAll()

    print("\n*** Dropping into CLI. Try:")
    print("    pingall   (run again to see cached rules in action)")
    print("    net       (see full topology)")
    print("(Open a separate terminal for: sudo ovs-ofctl -O OpenFlow13 dump-flows s4)")

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    build()
