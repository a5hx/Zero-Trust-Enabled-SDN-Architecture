#!/usr/bin/env python3
"""
Generates a static diagram image (topology.png) of the demo topology:
7 switches chained together, 1 host per switch.

Run:
    pip3 install networkx matplotlib
    python3 draw_topo.py
"""
import networkx as nx
import matplotlib.pyplot as plt

G = nx.Graph()

switches = [f's{i}' for i in range(1, 8)]
hosts = [f'h{i}' for i in range(1, 8)]

G.add_nodes_from(switches)
G.add_nodes_from(hosts)

# chain the switches
for i in range(len(switches) - 1):
    G.add_edge(switches[i], switches[i + 1])

# one host per switch
for sw, h in zip(switches, hosts):
    G.add_edge(sw, h)

pos = {}
for i, s in enumerate(switches):
    pos[s] = (i * 2, 0)
for i, h in enumerate(hosts):
    pos[h] = (i * 2, -1)

plt.figure(figsize=(14, 5))
nx.draw_networkx_nodes(G, pos, nodelist=switches, node_color='lightblue', node_shape='s', node_size=1800)
nx.draw_networkx_nodes(G, pos, nodelist=hosts, node_color='lightgreen', node_shape='o', node_size=1200)
nx.draw_networkx_edges(G, pos)
nx.draw_networkx_labels(G, pos, font_size=10, font_weight='bold')

plt.title("Zero Trust SDN Demo Topology — 7 Switches, 1 Controller, 7 Hosts")
plt.axis('off')
plt.tight_layout()
plt.savefig('topology.png', dpi=200)
print("Saved topology.png")
