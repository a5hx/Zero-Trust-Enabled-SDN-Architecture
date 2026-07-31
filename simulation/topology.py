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

from simulation.addressing import CX_IP, iot_ip, iot_mac, srv_ip, srv_mac

logger = logging.getLogger(__name__)

# ---------- conditional Mininet imports ----------
try:
    from mininet.topo import Topo
    from mininet.net import Mininet
    from mininet.node import Node, OVSSwitch, RemoteController
    from mininet.link import TCLink

    _MININET_AVAILABLE = True
except ImportError:
    # Provide a stub base so the class definition doesn't crash
    Topo = object  # type: ignore[misc,assignment]
    _MININET_AVAILABLE = False
    logger.info("Mininet not available - topology will work in metadata-only mode")

# The root-namespace routing node (design fact #3, Sprint 1 memory): a plain
# Node (not addNAT() -- no iptables MASQUERADE needed) linked to the core
# switch, deliberately kept on a narrower /24 than the emulated hosts'
# default /8 so it doesn't widen the blast radius. It exists so the
# controller process itself (which runs directly in the root namespace, not
# inside any Mininet host) can route into the emulated 10.0.0.0/24 (IoT) and
# 10.0.1.0/24 (server) subnets -- required for FlowMonitor's /status polling
# and for iot_client's /report calls to the northbound API.
CX_NAME = 'cx'
CX_PREFIX = 24  # CX_IP comes from addressing.py -- the controller needs it too


class ZeroTrustTopo(Topo):  # type: ignore[misc]
    """3-tier SDN topology: core switch → edge switches → IoT devices.

    Tier 0: 1 core OVSSwitch (s0)
    Tier 1: num_edge_nodes edge switches (s1..sN), each with one edge server
    Tier 2: num_iot_devices IoT hosts, round-robin attached to edge switches

    Every switch gets an explicit, distinct, nonzero DPID -- s0 defaults to
    dpid=0 otherwise, which some OVS versions reject or mishandle (see
    SETUP.md's DPID quirk note). Every host gets a deterministic MAC from
    simulation/addressing.py, the same scheme controller/trust_balancer.py
    uses to build VIP rewrite rules with no runtime ARP/discovery -- if the
    two ever computed addresses differently, the rewrite would silently
    target a MAC nothing owns.
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

        # Core switch. dpid=1 (not the Mininet default of 0).
        core = self.addSwitch('s0', cls=OVSSwitch, protocols='OpenFlow13', dpid='%016x' % 1)

        # Edge switches + servers
        for i in range(1, n_edge + 1):
            sw = self.addSwitch(
                f's{i}', cls=OVSSwitch, protocols='OpenFlow13', dpid='%016x' % (i + 1),
            )
            srv = self.addHost(f'srv{i}', ip=f'{srv_ip(i)}/8', mac=srv_mac(i))
            self.addLink(sw, srv, cls=TCLink, delay='2ms', bw=100)
            self.addLink(core, sw, cls=TCLink, delay='5ms', bw=1000)
            edge_switches.append(sw)
            self.edge_servers.append(srv)

        # IoT devices — last n_mal are malicious
        self.malicious_ids = []
        for j in range(1, n_iot + 1):
            is_mal = j > (n_iot - n_mal)
            h = self.addHost(f'iot{j}', ip=f'{iot_ip(j)}/8', mac=iot_mac(j))
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


def _add_cx_node(net: Any, core_switch: Any) -> Any:
    """Add the root-namespace `cx` routing node (see CX_NAME docstring above)
    and give it explicit routes into the emulated 10.0.0.0/24 (IoT) and
    10.0.1.0/24 (server) subnets. Those routes are only needed on cx itself:
    every Mininet host already has a /8 netmask by Mininet's default IP
    scheme, so from *their* side, cx's 10.0.99.0/24 is already on-link.

    Must be called after net.start() -- cx.cmd() needs its shell/interface
    to already exist, which only happens once Mininet has configured links.
    """
    cx = net.addHost(CX_NAME, cls=Node, ip=None, inNamespace=False)
    link = net.addLink(cx, core_switch, cls=TCLink, bw=1000)
    # addLink() after net.start() builds the veth pair but does *not* add the
    # switch end to the OVS bridge -- that only happens inside start(). Without
    # this attach the link looks perfectly healthy from the host (cx-eth0 is up,
    # peered to s0-eth5, routes resolve) while the datapath never sees the port,
    # so every controller->agent poll and every device auth handshake times out.
    core_switch.attach(link.intf2)
    cx_intf = cx.intfNames()[-1]
    cx.cmd(f'ip link set {cx_intf} up')
    cx.cmd(f'ip addr add {CX_IP}/{CX_PREFIX} dev {cx_intf}')
    cx.cmd(f'ip route add 10.0.0.0/24 dev {cx_intf}')
    cx.cmd(f'ip route add 10.0.1.0/24 dev {cx_intf}')
    logger.info("cx routing node up: %s/%d on %s", CX_IP, CX_PREFIX, cx_intf)
    return cx


def _launch_trust_agents(net: Any, cfg: Dict[str, Any]) -> None:
    """Start node_agent.py on every edge server and iot_client.py on every
    IoT host, backgrounded inside each Mininet host's own namespace. Reads
    --malicious from cfg['simulation']['malicious_edge_nodes'] (delayed
    onset via that list's start_s is not implemented by node_agent.py --
    malicious nodes misbehave from the moment they start)."""
    Path('logs').mkdir(exist_ok=True)

    n_edge = cfg['simulation']['num_edge_nodes']
    n_iot = cfg['simulation']['num_iot_devices']
    ctrl_cfg = cfg['controller']
    agents_cfg = cfg.get('agents', {})
    agent_port = agents_cfg.get('node_port', 8000)
    work_ms = agents_cfg.get('task_work_ms', 40.0)
    report_interval = agents_cfg.get('report_interval_s', 1.0)
    task_timeout = agents_cfg.get('task_timeout_s', 2.0)

    mal_by_node = {m['node']: m for m in cfg['simulation'].get('malicious_edge_nodes', [])}

    for i in range(1, n_edge + 1):
        node_id = f'srv{i}'
        srv = net.get(node_id)
        mal = mal_by_node.get(node_id)
        attack = mal['attack'] if mal else 'none'
        cmd = (
            f'python3 -u -m simulation.node_agent --node-id {node_id} '
            f'--port {agent_port} --work-ms {work_ms} --malicious {attack} '
            f'> logs/{node_id}_agent.log 2>&1 &'
        )
        srv.cmd(cmd)
        logger.info("Started node_agent on %s (malicious=%s)", node_id, attack)

    # Device authentication (Sprint 2). Legit devices get the shared key from
    # the config's security block; devices named in malicious_iot_devices get a
    # deliberately wrong key (correct key with every byte flipped), so the
    # controller denies them at admission and they generate no VIP traffic.
    sec_cfg = cfg.get('security', {})
    auth_scheme = sec_cfg.get('auth_scheme', 'present80')
    good_key_hex = sec_cfg.get('shared_key_hex')
    malicious_iot = set(sec_cfg.get('malicious_iot_devices', []))
    wrong_key_hex = (
        bytes(b ^ 0xFF for b in bytes.fromhex(good_key_hex)).hex()
        if good_key_hex else None
    )

    for j in range(1, n_iot + 1):
        device_id = f'iot{j}'
        host = net.get(device_id)
        auth_args = ''
        if good_key_hex:
            key_hex = wrong_key_hex if device_id in malicious_iot else good_key_hex
            auth_args = f'--auth-scheme {auth_scheme} --auth-key-hex {key_hex} '
        cmd = (
            f'python3 -u -m simulation.iot_client --device-id {device_id} '
            f'--vip {ctrl_cfg["vip"]} --vip-port {ctrl_cfg["vip_port"]} '
            f'--controller {CX_IP} --controller-port {ctrl_cfg["api_port"]} '
            f'--interval-s {report_interval} --timeout-s {task_timeout} '
            f'{auth_args}'
            f'> logs/{device_id}_client.log 2>&1 &'
        )
        host.cmd(cmd)
    logger.info(
        "Started iot_client on %d IoT host(s) (%d malicious/wrong-key)",
        n_iot, len(malicious_iot),
    )


def _stop_trust_agents(net: Any, cfg: Dict[str, Any]) -> None:
    """Explicitly kill backgrounded agent/client processes before net.stop()
    (mirrors traffic_gen.py's own `kill %iperf` cleanup) rather than relying
    on namespace teardown to reap them."""
    n_edge = cfg['simulation']['num_edge_nodes']
    n_iot = cfg['simulation']['num_iot_devices']
    for i in range(1, n_edge + 1):
        net.get(f'srv{i}').cmd('pkill -f simulation.node_agent 2>/dev/null')
    for j in range(1, n_iot + 1):
        net.get(f'iot{j}').cmd('pkill -f simulation.iot_client 2>/dev/null')


def run_topology(cfg: Dict[str, Any], interactive: bool = False) -> None:
    """Launch the Mininet network with a remote os-ken controller.

    Two modes, selected by whether cfg has a `controller:` block (i.e. was
    loaded from config/params_trust_demo.yaml or config/params.yaml, not
    config/params_demo.yaml):

    Trust mode (cfg has `controller:`): adds the cx routing node, starts a
        real node_agent.py per edge server (malicious ones per
        cfg['simulation']['malicious_edge_nodes']) and a real iot_client.py
        per IoT host generating continuous traffic through the VIP, so
        TrustBalancerApp (run separately -- see SETUP.md) has genuine
        traffic to route and re-steer. No iperf/http.server traffic in this
        mode; the point is the VIP-routed task traffic itself.
    Plain mode (no `controller:` block, e.g. params_demo.yaml): unchanged
        Phase C behaviour -- plain HTTP status servers + pingAll/iperf via
        simulation.traffic_gen, for connectivity verification against
        learning_switch_13.py rather than the trust-aware controller.

    If interactive, drops into the Mininet CLI afterwards (so pingall /
    `dpctl dump-flows -O OpenFlow13` can be run by hand); otherwise sleeps
    out the remainder of cfg['simulation']['duration_s'] and tears down.

    Args:
        cfg: Parsed params YAML configuration dict.
        interactive: drop into the Mininet CLI instead of sleeping.

    Raises:
        RuntimeError: If Mininet is not installed.
    """
    if not _MININET_AVAILABLE:
        raise RuntimeError(
            "Mininet is not installed. Use --mode standalone for demo."
        )

    import time

    trust_mode = 'controller' in cfg

    topo = ZeroTrustTopo(cfg=cfg)

    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653),
        switch=OVSSwitch,
        link=TCLink,
    )
    net.start()
    logger.info("Mininet network started")

    if trust_mode:
        _add_cx_node(net, net.get('s0'))
        loss = net.pingAll()
        logger.info("pingAll loss: %s%% (reachability check before agents start)", loss)
        _launch_trust_agents(net, cfg)

        duration = cfg['simulation']['duration_s']
        logger.info("Trust-aware demo running for %d seconds (Ctrl-C / exit to stop early)...", duration)

        if interactive:
            from mininet.cli import CLI
            logger.info(
                "Dropping into Mininet CLI (try: pingall, dpctl dump-flows -O "
                "OpenFlow13, iot1 wireshark &, exit)"
            )
            CLI(net)
        else:
            time.sleep(duration)

        _stop_trust_agents(net, cfg)
    else:
        # Start HTTP status servers on each edge server
        for i, srv_name in enumerate(
            [f'srv{j}' for j in range(1, cfg['simulation']['num_edge_nodes'] + 1)]
        ):
            srv = net.get(srv_name)
            port = 8080
            cmd = f'python3 -m http.server {port} &'
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
