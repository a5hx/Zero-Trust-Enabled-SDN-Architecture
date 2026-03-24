"""Mininet topology for the Zero Trust SDN edge network.

All Mininet imports are conditional so that unit tests and standalone
simulation can run without Mininet installed.
"""

import logging
import random
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------- conditional Mininet imports ----------
try:
    from mininet.topo import Topo
    from mininet.net import Mininet
    from mininet.node import OVSSwitch, RemoteController
    from mininet.link import TCLink

    _MININET_AVAILABLE = True
except ImportError:
    # Provide a stub base so the class definition doesn't crash
    Topo = object  # type: ignore[misc,assignment]
    _MININET_AVAILABLE = False
    logger.info("Mininet not available - topology will work in metadata-only mode")


class ZeroTrustTopo(Topo):  # type: ignore[misc]
    """3-tier SDN topology: core switch → edge switches → IoT devices.

    Tier 0: 1 core OVSSwitch (s0)
    Tier 1: num_edge_nodes edge switches (s1..sN), each with one edge server
    Tier 2: num_iot_devices IoT hosts, round-robin attached to edge switches
    """

    malicious_ids: List[str] = []

    def build(self, cfg: Dict[str, Any]) -> None:  # type: ignore[override]
        """Build the topology from config parameters."""
        n_edge: int = cfg['simulation']['num_edge_nodes']
        n_iot: int = cfg['simulation']['num_iot_devices']
        n_mal: int = cfg['simulation']['num_malicious']

        edge_switches: List[Any] = []
        self.edge_servers: List[Any] = []

        # Core switch
        core = self.addSwitch('s0', cls=OVSSwitch, protocols='OpenFlow13')

        # Edge switches + servers
        for i in range(1, n_edge + 1):
            sw = self.addSwitch(f's{i}', cls=OVSSwitch, protocols='OpenFlow13')
            srv = self.addHost(f'srv{i}', ip=f'10.0.1.{i}')
            self.addLink(sw, srv, cls=TCLink, delay='2ms', bw=100)
            self.addLink(core, sw, cls=TCLink, delay='5ms', bw=1000)
            edge_switches.append(sw)
            self.edge_servers.append(srv)

        # IoT devices — last n_mal are malicious
        self.malicious_ids = []
        for j in range(1, n_iot + 1):
            is_mal = j > (n_iot - n_mal)
            h = self.addHost(f'iot{j}', ip=f'10.0.0.{j}')
            sw_idx = (j - 1) % n_edge
            delay = f'{random.randint(1, 10)}ms'
            self.addLink(h, edge_switches[sw_idx], cls=TCLink, delay=delay, bw=10)
            if is_mal:
                self.malicious_ids.append(f'iot{j}')

        logger.info(
            "Topology built: %d edge nodes, %d IoT devices (%d malicious)",
            n_edge, n_iot, n_mal,
        )


def run_topology(cfg: Dict[str, Any]) -> None:
    """Launch the Mininet network with a remote Ryu controller.

    Each edge server runs a simple HTTP status endpoint. The network
    runs for cfg['simulation']['duration_s'] seconds and then cleans up.

    Args:
        cfg: Parsed params.yaml configuration dict.

    Raises:
        RuntimeError: If Mininet is not installed.
    """
    if not _MININET_AVAILABLE:
        raise RuntimeError(
            "Mininet is not installed. Use --mode standalone for demo."
        )

    import time
    import subprocess

    topo = ZeroTrustTopo()
    topo.build(cfg)

    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633),
        switch=OVSSwitch,
        link=TCLink,
    )
    net.start()
    logger.info("Mininet network started")

    # Start HTTP status servers on each edge server
    http_procs = []
    for i, srv_name in enumerate(
        [f'srv{j}' for j in range(1, cfg['simulation']['num_edge_nodes'] + 1)]
    ):
        srv = net.get(srv_name)
        port = 8080
        cmd = (
            f'python3 -m http.server {port} &'
        )
        srv.cmd(cmd)
        logger.info("Started HTTP server on %s:%d", srv_name, port)

    duration = cfg['simulation']['duration_s']
    logger.info("Running topology for %d seconds...", duration)
    time.sleep(duration)

    net.stop()
    logger.info("Mininet network stopped")
