"""Tests for blockchain/raft_replica.py -- the standalone RAFT replica
process's wiring and HTTP control API (Step 2 live demo).

The multi-process, real-kill scenario is exercised manually via
`python3 -m blockchain.raft_demo` (see docs/RAFT.md for a recorded run) rather
than in the automated suite -- spawning real subprocesses and racing real
election timeouts is exactly the kind of thing that is fine to run once by
hand and flaky to assert on in CI. What's tested here instead: the pure
parsing helper, and the HTTP control API wired to a real (single-node, no
subprocess) RaftBackend running `run()` on a background thread -- the same
code path a live replica process runs, just without the process boundary.
"""

import json
import threading
import time
from http.client import HTTPConnection

import pytest

from blockchain.raft_replica import _parse_peers, run


def _free_port() -> int:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class TestParsePeers:
    def test_parses_multiple_entries(self) -> None:
        peers = _parse_peers('n1=127.0.0.1:9001,n2=127.0.0.1:9002')
        assert peers == {'n1': ('127.0.0.1', 9001), 'n2': ('127.0.0.1', 9002)}

    def test_single_entry(self) -> None:
        assert _parse_peers('n1=10.0.0.5:9001') == {'n1': ('10.0.0.5', 9001)}


@pytest.fixture
def running_replica():
    """A single-node 'cluster' (no peers) driven by the real run() entry
    point, on a background thread, with its HTTP control API reachable."""
    raft_port = _free_port()
    http_port = _free_port()
    node_id = 'solo'
    peers = {node_id: ('127.0.0.1', raft_port)}

    thread = threading.Thread(
        target=run, args=(node_id, peers, '127.0.0.1', http_port), daemon=True,
    )
    thread.start()
    # run() binds its HTTP server before serve_forever(); give it a moment.
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        try:
            conn = HTTPConnection('127.0.0.1', http_port, timeout=0.2)
            conn.request('GET', '/status')
            conn.getresponse()
            conn.close()
            break
        except OSError:
            time.sleep(0.02)
    else:
        pytest.fail("replica's HTTP control API never came up")
    yield http_port


def _get(http_port: int, path: str) -> dict:
    conn = HTTPConnection('127.0.0.1', http_port, timeout=2.0)
    conn.request('GET', path)
    resp = conn.getresponse()
    body = json.loads(resp.read())
    conn.close()
    return body


def _post(http_port: int, path: str, payload) -> tuple:
    conn = HTTPConnection('127.0.0.1', http_port, timeout=2.0)
    body = json.dumps(payload).encode()
    conn.request('POST', path, body=body, headers={'Content-Type': 'application/json'})
    resp = conn.getresponse()
    return resp.status, json.loads(resp.read())


class TestControlApi:
    def test_status_reports_a_solo_node_becoming_leader(self, running_replica) -> None:
        http_port = running_replica
        deadline = time.monotonic() + 2.0
        role = None
        while time.monotonic() < deadline:
            role = _get(http_port, '/status').get('role')
            if role == 'leader':
                break
            time.sleep(0.02)
        assert role == 'leader'

    def test_commit_via_http_returns_block_info(self, running_replica) -> None:
        http_port = running_replica
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and _get(http_port, '/status')['role'] != 'leader':
            time.sleep(0.02)

        rows = [{
            'device_id': 'demo_iot', 'edge_node_id': 'srv1', 'task_status': 'success',
            'cpu_usage': 0.3, 'reported_cpu': 0.3, 'latency_ms': 15.0,
            'trust_score_after': 0.8,
        }]
        status_code, body = _post(http_port, '/commit', rows)
        assert status_code == 200
        assert body['ok'] is True
        assert body['block_index'] == 1
        assert 'block_hash' in body

    def test_commit_with_malformed_row_returns_400(self, running_replica) -> None:
        http_port = running_replica
        status_code, body = _post(http_port, '/commit', [{'not_a_real_field': 1}])
        assert status_code == 400

    def test_unknown_path_returns_404(self, running_replica) -> None:
        http_port = running_replica
        conn = HTTPConnection('127.0.0.1', http_port, timeout=2.0)
        conn.request('GET', '/nope')
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 404
