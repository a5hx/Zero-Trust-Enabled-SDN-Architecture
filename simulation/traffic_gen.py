"""Traffic generation for the Mininet Zero Trust SDN demo.

Drives representative edge traffic (reachability + throughput) over a
running Mininet network so the SDN controller has real flows to route
and the demo has measurable output to show an advisor: pingall results,
per-flow iperf throughput, and installed OpenFlow rules.
"""
import logging
import time
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger(__name__)

IPERF_SERVER_PORT = 5001
IPERF_CLIENT_SECONDS = 3


def generate_traffic(
    net: Any,
    iot_to_edge: Dict[str, int],
    log_path: str = 'data/mininet_traffic.log',
) -> Dict[str, Any]:
    """Run pingAll + iperf flows between IoT hosts and their edge server.

    Args:
        net: a started mininet.net.Mininet instance.
        iot_to_edge: mapping of iot host name -> edge server index
            (e.g. {'iot1': 1} means iot1's traffic targets srv1),
            as built by simulation.topology.ZeroTrustTopo.
        log_path: where to write the raw iperf/ping output for the report.

    Returns:
        Summary dict with ping loss percentage and per-flow throughput.
    """
    Path(log_path).parent.mkdir(parents=True, exist_ok=True)
    log_lines = []
    summary: Dict[str, Any] = {'flows': []}

    logger.info("Running pingAll for reachability...")
    loss = net.pingAll()
    summary['ping_loss_percent'] = loss
    log_lines.append(f"pingAll loss: {loss}%")
    logger.info("pingAll loss: %s%%", loss)

    edge_servers = sorted(set(iot_to_edge.values()))
    for edge_idx in edge_servers:
        srv = net.get(f'srv{edge_idx}')
        srv.cmd(f'iperf -s -p {IPERF_SERVER_PORT} > /tmp/iperf_srv{edge_idx}.log 2>&1 &')
    time.sleep(1)

    for iot_name, edge_idx in iot_to_edge.items():
        client = net.get(iot_name)
        srv = net.get(f'srv{edge_idx}')
        logger.info("iperf: %s -> srv%d (%s)", iot_name, edge_idx, srv.IP())
        out = client.cmd(
            f'iperf -c {srv.IP()} -p {IPERF_SERVER_PORT} -t {IPERF_CLIENT_SECONDS}'
        )
        log_lines.append(f"--- {iot_name} -> srv{edge_idx} ---\n{out}")
        summary['flows'].append({'src': iot_name, 'dst': f'srv{edge_idx}', 'raw': out.strip()})

    for edge_idx in edge_servers:
        srv = net.get(f'srv{edge_idx}')
        srv.cmd('kill %iperf 2>/dev/null')

    with open(log_path, 'w') as f:
        f.write('\n'.join(log_lines))
    logger.info("Traffic log written to %s", log_path)

    return summary
