"""Tests for simulation/iot_client.py's --malicious spoof mode (plan_adv.md
Phase 1). Runs a fake /auth + /task server on loopback that returns canned
responses -- this exercises iot_client.py's own control flow (does a denial
stop traffic, does a success send it under the stolen identity), not
security/authenticator.py's real crypto/pinning logic, which
tests/test_authenticator.py already covers directly."""

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from simulation import iot_client

_KEY_HEX = '00112233445566778899'  # 10 bytes = 80-bit


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class _FakeAuthHandler(BaseHTTPRequestHandler):
    """Canned /auth/challenge + /auth/verify + /task + /report responses.
    Class-level `deny_verify` controls whether /auth/verify succeeds; the
    crypto is never actually checked (that's test_authenticator.py's job)."""

    deny_verify = True
    task_hits: list = []  # (path, device_id_claimed_via_report) not tracked -- just counts

    def log_message(self, *a) -> None:
        pass

    def _write_json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        length = int(self.headers.get('Content-Length', 0) or 0)
        body = self.rfile.read(length) if length else b'{}'

        if self.path == '/auth/challenge':
            self._write_json(200, {'nonce': '00' * 8})
            return
        if self.path == '/auth/verify':
            if type(self).deny_verify:
                self._write_json(403, {'error': 'denied (test)'})
            else:
                self._write_json(200, {'token': 'stolen-token-abc123'})
            return
        if self.path == '/task':
            type(self).task_hits.append(time.monotonic())
            self._write_json(200, {'ok': True})
            return
        if self.path == '/report':
            self._write_json(200, {'accepted': True})
            return
        self._write_json(404, {'error': 'not found'})


@pytest.fixture
def fake_server():
    _FakeAuthHandler.deny_verify = True
    _FakeAuthHandler.task_hits = []
    port = _free_port()
    server = ThreadingHTTPServer(('127.0.0.1', port), _FakeAuthHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()


class TestRunSpoof:
    def test_denied_spoof_sends_no_task_traffic(self, fake_server):
        _FakeAuthHandler.deny_verify = True
        # No stop_event needed -- a denial returns immediately, no loop entered.
        iot_client._run_spoof(
            'iotAttacker', '127.0.0.1', fake_server, '127.0.0.1', fake_server,
            interval_s=0.05, timeout_s=2.0,
            auth_scheme='present80', auth_key=bytes.fromhex(_KEY_HEX),
            malicious_start_s=0.0, spoof_target_id='iot3',
        )
        assert _FakeAuthHandler.task_hits == []

    def test_successful_spoof_sends_task_traffic(self, fake_server):
        _FakeAuthHandler.deny_verify = False
        stop_event = threading.Event()
        thread = threading.Thread(
            target=iot_client._run_spoof,
            args=(
                'iotAttacker', '127.0.0.1', fake_server, '127.0.0.1', fake_server,
                0.02, 2.0, 'present80', bytes.fromhex(_KEY_HEX),
                0.0, 'iot3', stop_event,
            ),
            daemon=True,
        )
        thread.start()
        try:
            time.sleep(0.3)
            assert len(_FakeAuthHandler.task_hits) > 0
        finally:
            stop_event.set()
            thread.join(timeout=2.0)

    def test_delayed_spoof_waits_before_attempting_auth(self, fake_server):
        _FakeAuthHandler.deny_verify = True
        start = time.monotonic()
        iot_client._run_spoof(
            'iotAttacker', '127.0.0.1', fake_server, '127.0.0.1', fake_server,
            interval_s=0.05, timeout_s=2.0,
            auth_scheme='present80', auth_key=bytes.fromhex(_KEY_HEX),
            malicious_start_s=0.2, spoof_target_id='iot3',
        )
        elapsed = time.monotonic() - start
        assert elapsed >= 0.2

    def test_missing_target_id_is_rejected_at_the_cli(self):
        import sys

        argv = [
            'iot_client', '--device-id', 'iotX', '--vip', '10.0.99.1',
            '--controller', '10.0.0.1', '--malicious', 'spoof',
        ]
        old_argv = sys.argv
        sys.argv = argv
        try:
            with pytest.raises(SystemExit):
                iot_client.main()
        finally:
            sys.argv = old_argv
