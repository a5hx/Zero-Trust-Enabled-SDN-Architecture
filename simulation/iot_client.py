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

--malicious flood: ignores --interval-s's pacing and hammers the VIP from
                   --flood-concurrency parallel workers instead of one,
                   each looping as fast as --flood-interval-s allows
                   (default 0.0 -- no pacing at all). A different attack
                   SURFACE from every node_agent.py --malicious kind: this
                   targets the fleet's/controller's capacity to absorb
                   requests, not any one edge node's honesty. Caught by
                   controller/flood_detector.py's request-rate tell, keyed
                   on the requesting client, never on whichever node the
                   flood happens to land on -- see that module's docstring
                   for why blaming the node would be the wrong target.
                   Supports the same delayed-onset design as
                   node_agent.py's --malicious-start-s, for the same reason
                   (a clean pre-attack baseline interval).
"""

import argparse
import http.client
import json
import logging
import socket
import threading
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


def _compute_auth_response(scheme: str, key: bytes, device_id: str, nonce: bytes) -> bytes:
    """The response a legitimate device returns for an auth challenge.

    Pure and side-effect free so it can be unit-tested against the controller's
    Authenticator without any HTTP. present80 encrypts the nonce under the
    shared 80-bit key; hmac matches HmacAuthenticator's device_id||nonce MAC.
    """
    if scheme == 'present80':
        from security.present_cipher import encrypt_bytes
        return encrypt_bytes(key, nonce)
    if scheme == 'hmac':
        import hashlib
        import hmac
        return hmac.new(key, device_id.encode() + nonce, hashlib.sha256).digest()
    raise ValueError(f"unsupported auth scheme: {scheme!r}")


def _authenticate(
    controller: str, controller_port: int, device_id: str,
    scheme: str, key: bytes, timeout_s: float,
) -> Optional[str]:
    """Run the challenge-response handshake with the controller.

    Returns the session token on success, or None if the controller denied the
    device (wrong key -> 403) or the handshake could not be completed. A None
    return is the signal for the caller to not join the fleet.
    """
    try:
        conn = http.client.HTTPConnection(controller, controller_port, timeout=timeout_s)
        conn.request(
            'POST', '/auth/challenge',
            body=json.dumps({'device_id': device_id}).encode(),
            headers={'Content-Type': 'application/json', 'Connection': 'close'},
        )
        resp = conn.getresponse()
        nonce = bytes.fromhex(json.loads(resp.read())['nonce'])
        conn.close()

        response = _compute_auth_response(scheme, key, device_id, nonce)

        conn = http.client.HTTPConnection(controller, controller_port, timeout=timeout_s)
        conn.request(
            'POST', '/auth/verify',
            body=json.dumps({'device_id': device_id, 'response': response.hex()}).encode(),
            headers={'Content-Type': 'application/json', 'Connection': 'close'},
        )
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        if resp.status == 200:
            return json.loads(body).get('token')
        return None  # 403 -- denied admission
    except OSError as exc:
        logger.warning("Auth handshake failed (network): %s", exc)
        return None


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


def _worker_loop(
    vip: str, vip_port: int, controller: str, controller_port: int,
    device_id: str, timeout_s: float, interval_s: float, stop_event: threading.Event,
) -> None:
    """Send tasks and report outcomes until stopped. `interval_s` paces
    between requests; 0 means no pacing at all (a flood worker). Shared body
    for the honest single-worker loop and every one of a flood's parallel
    workers -- same request, different concurrency and pacing."""
    while not stop_event.is_set():
        status, latency_ms, local_port = _send_task(vip, vip_port, timeout_s)
        logger.info("%s task -> %s (%.1f ms)", device_id, status, latency_ms)
        _report(controller, controller_port, device_id, local_port, status, latency_ms, timeout_s)
        if interval_s > 0:
            stop_event.wait(interval_s)


def _arm_flood(
    vip: str, vip_port: int, controller: str, controller_port: int,
    device_id: str, timeout_s: float, flood_concurrency: int, flood_interval_s: float,
    stop_normal: threading.Event, stop_flood: threading.Event,
) -> None:
    """Stop the paced single-worker loop and start flood_concurrency
    parallel workers hammering the VIP right now. Split from
    _arm_flood_after_delay (mirrors node_agent.py's _arm_malicious /
    _arm_after_delay split) so tests can arm synchronously without waiting
    out a real delay."""
    if stop_normal.is_set():
        return  # already torn down (e.g. process shutting down mid-delay)
    logger.warning(
        "%s: FLOOD mode ARMED -- %d parallel workers, interval=%.3fs",
        device_id, flood_concurrency, flood_interval_s,
    )
    stop_normal.set()
    for _ in range(flood_concurrency):
        threading.Thread(
            target=_worker_loop,
            args=(vip, vip_port, controller, controller_port, device_id,
                  timeout_s, flood_interval_s, stop_flood),
            daemon=True,
        ).start()


def _arm_flood_after_delay(delay_s: float, *args) -> None:
    """Daemon-thread target: wait out the onset delay, then arm the flood."""
    time.sleep(delay_s)
    _arm_flood(*args)


def _run_flood(
    device_id: str, vip: str, vip_port: int, controller: str, controller_port: int,
    interval_s: float, timeout_s: float,
    malicious_start_s: float, flood_concurrency: int, flood_interval_s: float,
) -> None:
    """--malicious flood's run loop: honestly paced (interval_s, single
    worker) until malicious_start_s elapses -- 0 arms immediately -- then
    flood_concurrency parallel workers take over. Kept as a separate
    function from run()'s honest path so that path is untouched
    byte-for-byte for every non-malicious device, which is the overwhelming
    common case."""
    stop_normal = threading.Event()
    stop_flood = threading.Event()

    threading.Thread(
        target=_worker_loop,
        args=(vip, vip_port, controller, controller_port, device_id,
              timeout_s, interval_s, stop_normal),
        daemon=True,
    ).start()

    arm_args = (
        vip, vip_port, controller, controller_port, device_id, timeout_s,
        flood_concurrency, flood_interval_s, stop_normal, stop_flood,
    )
    if malicious_start_s > 0:
        logger.warning(
            "%s: MALICIOUS MODE flood -- honest until t+%.1fs, then ARMS",
            device_id, malicious_start_s,
        )
        threading.Thread(
            target=_arm_flood_after_delay, args=(malicious_start_s, *arm_args), daemon=True,
        ).start()
    else:
        _arm_flood(*arm_args)

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        stop_normal.set()
        stop_flood.set()
        raise


def _run_spoof(
    device_id: str, vip: str, vip_port: int, controller: str, controller_port: int,
    interval_s: float, timeout_s: float,
    auth_scheme: Optional[str], auth_key: Optional[bytes],
    malicious_start_s: float, spoof_target_id: str,
    stop_event: Optional[threading.Event] = None,
) -> None:
    """--malicious spoof: after malicious_start_s (should be long enough for
    the real spoof_target_id to have already authenticated normally), attempt
    to authenticate AS spoof_target_id from this host's own source IP, using
    the fleet-shared key.

    This is possible at all only because the key is fleet-wide (topology.py
    hands every legitimate device the identical shared_key_hex) -- see
    security/authenticator.py's source-IP pinning, which is exactly what
    this attack is built to test. Denial is the expected/correct outcome; on
    the (bug) case where it isn't denied, the spoofer proceeds to send task
    traffic under the stolen identity, same as any authenticated device.
    """
    if malicious_start_s > 0:
        logger.warning(
            "%s: MALICIOUS MODE spoof -- waiting t+%.1fs before impersonating %s",
            device_id, malicious_start_s, spoof_target_id,
        )
        time.sleep(malicious_start_s)

    logger.warning(
        "%s: attempting to authenticate AS %s from this host", device_id, spoof_target_id,
    )
    token = _authenticate(
        controller, controller_port, spoof_target_id, auth_scheme, auth_key, timeout_s,
    )
    if token is None:
        logger.error(
            "%s: SPOOFING DENIED -- %s's identity is pinned to a different "
            "source IP", device_id, spoof_target_id,
        )
        return

    logger.warning(
        "%s: SPOOFING SUCCEEDED -- now sending traffic as %s (session %s...)",
        device_id, spoof_target_id, token[:8],
    )
    if stop_event is None:
        stop_event = threading.Event()
    try:
        _worker_loop(
            vip, vip_port, controller, controller_port, spoof_target_id,
            timeout_s, interval_s, stop_event,
        )
    except KeyboardInterrupt:
        stop_event.set()
        raise


def run(
    device_id: str, vip: str, vip_port: int, controller: str, controller_port: int,
    interval_s: float, timeout_s: float,
    auth_scheme: Optional[str] = None, auth_key: Optional[bytes] = None,
    malicious: str = 'none', malicious_start_s: float = 0.0,
    flood_concurrency: int = 20, flood_interval_s: float = 0.0,
    spoof_target_id: Optional[str] = None,
) -> None:
    logger.info(
        "iot_client %s -> VIP %s:%d, reporting to %s:%d",
        device_id, vip, vip_port, controller, controller_port,
    )

    if malicious == 'spoof':
        _run_spoof(
            device_id, vip, vip_port, controller, controller_port,
            interval_s, timeout_s, auth_scheme, auth_key,
            malicious_start_s, spoof_target_id,
        )
        return

    # Admission control: authenticate before generating any traffic. A device
    # given the wrong key is denied here and never joins the fleet -- the
    # malicious-IoT case. Skipped only when no key is supplied (plain runs).
    if auth_key is not None:
        token = _authenticate(
            controller, controller_port, device_id, auth_scheme, auth_key, timeout_s,
        )
        if token is None:
            logger.error(
                "AUTH DENIED for %s -- refused admission, sending no traffic", device_id,
            )
            return
        logger.info("AUTH OK for %s (session %s...)", device_id, token[:8])

    if malicious == 'flood':
        _run_flood(
            device_id, vip, vip_port, controller, controller_port,
            interval_s, timeout_s, malicious_start_s, flood_concurrency, flood_interval_s,
        )
        return

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
    parser.add_argument(
        '--auth-scheme', default='present80', choices=['present80', 'hmac'],
        help='challenge-response scheme the controller expects',
    )
    parser.add_argument(
        '--auth-key-hex', default=None,
        help='shared key as hex. If omitted, the device skips authentication '
             '(plain runs). A wrong key is refused at admission.',
    )
    parser.add_argument('--malicious', choices=['none', 'flood', 'spoof'], default='none')
    parser.add_argument(
        '--malicious-start-s', type=float, default=0.0,
        help='Delay (s) after start before --malicious flood/spoof arms. 0 '
             '(default) arms immediately. Before arming the device behaves '
             'normally (flood: paces normally; spoof: sends no traffic at '
             'all, since it has no identity of its own to authenticate as).',
    )
    parser.add_argument(
        '--flood-concurrency', type=int, default=20,
        help='--malicious flood only: number of parallel request workers.',
    )
    parser.add_argument(
        '--flood-interval-s', type=float, default=0.0,
        help='--malicious flood only: pacing between requests per worker. '
             '0 (default) = no pacing, as fast as the network allows.',
    )
    parser.add_argument(
        '--spoof-target-device-id', default=None,
        help='--malicious spoof only: device_id to impersonate. Requires '
             '--auth-key-hex (the attacker must hold the fleet-wide key).',
    )
    args = parser.parse_args()

    if args.malicious == 'spoof' and not args.spoof_target_device_id:
        parser.error('--malicious spoof requires --spoof-target-device-id')

    auth_key = bytes.fromhex(args.auth_key_hex) if args.auth_key_hex else None

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
    )

    try:
        run(
            args.device_id, args.vip, args.vip_port,
            args.controller, args.controller_port,
            args.interval_s, args.timeout_s,
            auth_scheme=args.auth_scheme, auth_key=auth_key,
            malicious=args.malicious, malicious_start_s=args.malicious_start_s,
            flood_concurrency=args.flood_concurrency, flood_interval_s=args.flood_interval_s,
            spoof_target_id=args.spoof_target_device_id,
        )
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
