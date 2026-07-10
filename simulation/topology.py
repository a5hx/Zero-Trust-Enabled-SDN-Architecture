"""Mininet topology for the Zero Trust SDN edge network.

All Mininet imports are conditional so that unit tests and standalone
simulation can run without Mininet installed.
"""

import logging
import random
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Allow running this file directly (`python3 simulation/topology.py`) as
# well as as a module (`python3 -m simulation.topology`) by ensuring the
# repo root is on sys.path for the `simulation.traffic_gen` import below.
_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

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
        self.iot_to_edge: Dict[str, int] = {}

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
            self.iot_to_edge[f'iot{j}'] = sw_idx + 1
            if is_mal:
                self.malicious_ids.append(f'iot{j}')

        logger.info(
            "Topology built: %d edge nodes, %d IoT devices (%d malicious)",
            n_edge, n_iot, n_mal,
        )


def run_topology(cfg: Dict[str, Any], interactive: bool = False) -> None:
    """Launch the Mininet network with a remote Ryu/os-ken controller.

    Each edge server runs a simple HTTP status endpoint, and pingAll +
    iperf traffic is generated between IoT hosts and their edge server.
    If interactive, drops into the Mininet CLI afterwards (so pingall /
    ovs-ofctl dump-flows can be run by hand); otherwise sleeps out the
    remainder of cfg['simulation']['duration_s'] and tears down.

    Args:
        cfg: Parsed params.yaml configuration dict.
        interactive: drop into the Mininet CLI instead of sleeping.

    Raises:
        RuntimeError: If Mininet is not installed.
    """
    if not _MININET_AVAILABLE:
        raise RuntimeError(
            "Mininet is not installed. Use --mode standalone for demo."
        )

    import time
    import subprocess

    topo = ZeroTrustTopo(cfg=cfg)

    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653),
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

    from simulation.traffic_gen import generate_traffic

    duration = cfg['simulation']['duration_s']
    logger.info("Running topology for %d seconds...", duration)

    traffic_start = time.time()
    summary = generate_traffic(net, topo.iot_to_edge)
    logger.info("Traffic summary: pingAll loss=%s%%, flows=%d",
                summary['ping_loss_percent'], len(summary['flows']))

    if interactive:
        from mininet.cli import CLI
        logger.info("Dropping into Mininet CLI (try: pingall, dump-flows, exit)")
        CLI(net)
    else:
        remaining = duration - (time.time() - traffic_start)
        if remaining > 0:
            time.sleep(remaining)

    net.stop()
    logger.info("Mininet network stopped")


if __name__ == '__main__':
    import argparse

    import yaml

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
    )

    parser = argparse.ArgumentParser(description='Zero Trust SDN Mininet topology')
    parser.add_argument('--config', default='config/params.yaml',
                         help='Path to YAML config (default: config/params.yaml)')
    parser.add_argument('--interactive', action='store_true',
                         help='Drop into the Mininet CLI instead of running for a fixed duration')
    args = parser.parse_args()

    with open(args.config) as f:
        run_cfg = yaml.safe_load(f)

    run_topology(run_cfg, interactive=args.interactive)
