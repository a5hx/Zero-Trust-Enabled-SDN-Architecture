"""Tests for simulation/iot_client.py's --malicious flood mode (plan_adv.md
Phase 1). Runs a real fake HTTP server on loopback standing in for both the
VIP (/task) and the controller (/report) endpoints -- same real-server
pattern as tests/test_node_agent.py -- so the request-rate behavior this
attack depends on is exercised for real, not mocked."""

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from simulation import iot_client


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class _CountingHandler(BaseHTTPRequestHandler):
    """Answers every POST with 200; counts only /task hits (with a
    timestamp), which is the flood's actual target -- /report hits are
    incidental bookkeeping traffic and not what this test measures."""

    task_hits: list = []

    def log_message(self, *a) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get('Content-Length', 0) or 0)
        if length:
            self.rfile.read(length)
        if self.path == '/task':
            type(self).task_hits.append(time.monotonic())
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def fake_server():
    """One fake server standing in for both the VIP and the controller
    (both /task and /report land here); returns its port. Resets the hit
    counter first since it's class-level, shared state."""
    _CountingHandler.task_hits = []
    port = _free_port()
    server = ThreadingHTTPServer(('127.0.0.1', port), _CountingHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()


class TestArmFlood:
    def test_arm_stops_the_normal_worker_and_starts_flood_workers(self, fake_server):
        stop_normal = threading.Event()
        stop_flood = threading.Event()
        normal_thread = threading.Thread(
            target=iot_client._worker_loop,
            args=('127.0.0.1', fake_server, '127.0.0.1', fake_server,
                  'iotT', 2.0, 0.05, stop_normal),
            daemon=True,
        )
        normal_thread.start()
        try:
            time.sleep(0.2)  # let a handful of paced requests land
            normal_count = len(_CountingHandler.task_hits)
            assert normal_count > 0

            iot_client._arm_flood(
                '127.0.0.1', fake_server, '127.0.0.1', fake_server, 'iotT',
                2.0, 10, 0.0, stop_normal, stop_flood,
            )
            assert stop_normal.is_set()  # the paced worker was told to stop

            time.sleep(0.3)
            flood_count = len(_CountingHandler.task_hits) - normal_count
            # 10 unpaced workers hammering for 0.3s on loopback must clearly
            # outrun what the single 20 Hz paced worker produced in the same
            # style of window -- generous bounds to avoid flakiness on a
            # loaded CI box while still proving the flood is real traffic,
            # not a no-op.
            assert flood_count > 5
            assert flood_count > normal_count
        finally:
            stop_normal.set()
            stop_flood.set()

    def test_delayed_arm_stays_honest_until_the_delay_elapses(self, fake_server):
        stop_normal = threading.Event()
        stop_flood = threading.Event()
        normal_thread = threading.Thread(
            target=iot_client._worker_loop,
            args=('127.0.0.1', fake_server, '127.0.0.1', fake_server,
                  'iotT', 2.0, 0.05, stop_normal),
            daemon=True,
        )
        normal_thread.start()
        try:
            arm_thread = threading.Thread(
                target=iot_client._arm_flood_after_delay,
                args=(0.15, '127.0.0.1', fake_server, '127.0.0.1', fake_server,
                      'iotT', 2.0, 10, 0.0, stop_normal, stop_flood),
                daemon=True,
            )
            arm_thread.start()

            time.sleep(0.05)
            assert not stop_normal.is_set()  # still inside the delay window

            arm_thread.join(timeout=2.0)
            assert stop_normal.is_set()
        finally:
            stop_normal.set()
            stop_flood.set()

    def test_arm_is_a_no_op_if_already_torn_down(self, fake_server):
        # A race between shutdown and a pending delayed arm must not resurrect
        # workers after the process has been told to stop.
        stop_normal = threading.Event()
        stop_flood = threading.Event()
        stop_normal.set()  # already torn down before arming ever runs

        iot_client._arm_flood(
            '127.0.0.1', fake_server, '127.0.0.1', fake_server, 'iotT',
            2.0, 10, 0.0, stop_normal, stop_flood,
        )
        time.sleep(0.1)
        assert len(_CountingHandler.task_hits) == 0
        assert not stop_flood.is_set()
