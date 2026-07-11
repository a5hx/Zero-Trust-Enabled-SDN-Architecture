#!/usr/bin/env python3
"""IoT client agent for the Zero Trust SDN trust-aware demo.

Runs on each iotN Mininet host. Sends real task requests to the controller's
virtual service IP (VIP) at >=1 Hz, measures latency, classifies the outcome,
and reports it to the controller's northbound REST API — so trust updates are
driven by genuine, observed traffic rather than injected/synthetic events.

Each task uses a FRESH TCP connection, never a pooled/reused one. This is not
a style choice: the controller only re-evaluates EdgeScore on a new PacketIn,
which only happens for a new (client_ip, client_port) flow. A persistent or
pooled connection would pin this client to whichever server it first reached
and silently defeat trust-driven re-steering — the demo would look like the
controller is ignoring trust entirely, with no error to explain why.

This client never learns which edge server actually served it — that mapping
lives only in the controller (see controller/trust_state.py's dispatch
tracking), which is what makes the routing decision genuinely enforced in the
data plane rather than just advisory.
"""

import argparse
import http.client
import json
import logging
import socket
import time
from typing import Optional, Tuple

logger = logging.getLogger('iot_client')


def _send_task(vip: str, vip_port: int, timeout_s: float) -> Tuple[str, float, Optional[int]]:
    """POST /task to the VIP over a brand-new connection.

    Returns:
        (status, latency_ms, local_port) where status is one of
        'success' / 'timeout' / 'failure', and local_port is the ephemeral
        source port this connection used — the only handle the controller has
        to resolve which of its own dispatch records this task belongs to.
    """
    conn = http.client.HTTPConnection(vip, vip_port, timeout=timeout_s)
    start = time.monotonic()
    local_port: Optional[int] = None
    try:
        conn.connect()
        local_port = conn.sock.getsockname()[1]
        conn.request(
            'POST', '/task', body=b'{}',
            headers={'Content-Type': 'application/json', 'Connection': 'close'},
        )
        resp = conn.getresponse()
        resp.read()
        latency_ms = (time.monotonic() - start) * 1000.0
        status = 'success' if resp.status == 200 else 'failure'
    except (socket.timeout, TimeoutError):
        latency_ms = (time.monotonic() - start) * 1000.0
        status = 'timeout'
    except OSError:
        latency_ms = (time.monotonic() - start) * 1000.0
        status = 'failure'
    finally:
        conn.close()

    return status, latency_ms, local_port


def _report(
    controller: str, controller_port: int, device_id: str,
    vip_src_port: Optional[int], status: str, latency_ms: float, timeout_s: float,
) -> None:
    """POST /report to the controller. Best-effort: re-steering itself does not
    depend on this succeeding (only the VIP data-plane path does), but trust
    scoring does, so a failure here is logged, not silently swallowed."""
    if vip_src_port is None:
        return  # connect() to the VIP never even succeeded; nothing to attribute

    payload = json.dumps({
        'device_id': device_id,
        'vip_src_port': vip_src_port,
        'status': status,
        'latency_ms': round(latency_ms, 2),
    }).encode()

    try:
        conn = http.client.HTTPConnection(controller, controller_port, timeout=timeout_s)
        conn.request(
            'POST', '/report', body=payload,
            headers={'Content-Type': 'application/json', 'Connection': 'close'},
        )
        conn.getresponse().read()
        conn.close()
    except OSError as exc:
        logger.warning("Failed to report outcome to controller: %s", exc)


def run(
    device_id: str, vip: str, vip_port: int, controller: str, controller_port: int,
    interval_s: float, timeout_s: float,
) -> None:
    logger.info(
        "iot_client %s -> VIP %s:%d, reporting to %s:%d",
        device_id, vip, vip_port, controller, controller_port,
    )
    while True:
        status, latency_ms, local_port = _send_task(vip, vip_port, timeout_s)
        logger.info("%s task -> %s (%.1f ms)", device_id, status, latency_ms)
        _report(controller, controller_port, device_id, local_port, status, latency_ms, timeout_s)
        time.sleep(interval_s)


def main() -> None:
    parser = argparse.ArgumentParser(description='Zero Trust SDN IoT client')
    parser.add_argument('--device-id', required=True)
    parser.add_argument('--vip', required=True)
    parser.add_argument('--vip-port', type=int, default=9000)
    parser.add_argument('--controller', required=True)
    parser.add_argument('--controller-port', type=int, default=8081)
    parser.add_argument('--interval-s', type=float, default=1.0)
    parser.add_argument('--timeout-s', type=float, default=2.0)
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
    )

    try:
        run(
            args.device_id, args.vip, args.vip_port,
            args.controller, args.controller_port,
            args.interval_s, args.timeout_s,
        )
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
