"""Tests for simulation/node_agent.py -- specifically the --malicious-start-s
delayed-onset gate (plan_adv.md Phase 0). Runs the real AgentHandler over a
real HTTP server on a loopback port (same pattern as
tests/test_run_demo_mininet.py's _free_port helper); no Mininet/root needed.

AgentHandler's class attributes and the module's globals are process-wide
state, so every test resets them via the `agent_server` fixture rather than
relying on import order or test order.
"""

import http.client
import socket
import threading
import time
from http.server import ThreadingHTTPServer

import pytest

from simulation import node_agent
from simulation.node_agent import AgentHandler


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def _wait_until(condition, timeout: float = 2.0, interval: float = 0.01) -> bool:
    """Poll `condition` (a zero-arg callable) until it's true or timeout.
    Returns the final truth value -- callers still assert on it, this just
    avoids a hardcoded sleep racing a background thread's first tick."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(interval)
    return condition()


@pytest.fixture
def agent_server():
    """Reset all node_agent process-wide state and serve a fresh AgentHandler
    on a free loopback port. Yields the port; the test configures
    AgentHandler.* attributes before making requests."""
    node_agent._active_tasks = 0
    node_agent._busy_seconds_total = 0.0
    node_agent._recent_latencies_ms.clear()
    node_agent._attack_armed_at = None
    node_agent._onoff_bad_phase_started_at = None

    AgentHandler.node_id = 'srvT'
    AgentHandler.concurrency = 4
    AgentHandler.work_ms = 1.0  # tiny -- keep tests fast
    AgentHandler.malicious = 'none'
    AgentHandler.claimed_cpu_lie = 0.1
    AgentHandler.armed = False
    AgentHandler.grayhole_drop_rate = 0.5
    AgentHandler.onoff_period_s = 8.0
    AgentHandler.onoff_duty = 0.5
    AgentHandler.onoff_bad = False

    port = _free_port()
    server = ThreadingHTTPServer(('127.0.0.1', port), AgentHandler)
    # Daemon handler threads: a --malicious drop request that never gets a
    # reply parks its handler thread in time.sleep(); without this the
    # process (and the test session) would not exit cleanly.
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()


def _get_status(port: int) -> dict:
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5.0)
    try:
        conn.request('GET', '/status')
        resp = conn.getresponse()
        import json
        return json.loads(resp.read())
    finally:
        conn.close()


def _post_task(port: int, timeout: float = 5.0) -> http.client.HTTPResponse:
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=timeout)
    conn.request('POST', '/task', body=b'')
    return conn.getresponse()


class TestSybilBeforeArming:
    def test_unarmed_sybil_reports_honest_cpu_load_not_the_lie(self, agent_server):
        AgentHandler.malicious = 'sybil'
        AgentHandler.claimed_cpu_lie = 0.1
        # concurrency=4 -> honest cpu_load in {0, .25, .5, .75, 1.0}, which
        # can never coincide with the 0.1 lie -- a deterministic distinguisher.
        status = _get_status(agent_server)
        assert status['cpu_load'] != 0.1
        assert status['cpu_load'] == 0.0  # idle, no in-flight tasks
        assert status['busy_seconds'] == 0.0

    def test_unarmed_sybil_does_the_real_work_a_task_asks_for(self, agent_server):
        AgentHandler.malicious = 'sybil'
        resp = _post_task(agent_server)
        assert resp.status == 200
        status = _get_status(agent_server)
        # Real work was done and accrued honestly -- not the synthetic
        # uptime * lie * concurrency formula the armed branch would report.
        assert status['busy_seconds'] > 0.0


class TestSybilAfterArming:
    def test_armed_sybil_reports_the_fixed_lie(self, agent_server):
        AgentHandler.malicious = 'sybil'
        AgentHandler.claimed_cpu_lie = 0.1
        stop_event = threading.Event()
        try:
            node_agent._arm_malicious('srvT', 'sybil', concurrency=1, stop_event=stop_event)
            status = _get_status(agent_server)
            assert status['cpu_load'] == 0.1
        finally:
            stop_event.set()  # stop the background CPU burner thread


class TestDelayedOnset:
    def test_agent_is_honest_before_the_delay_elapses_and_lies_after(self, agent_server):
        AgentHandler.malicious = 'sybil'
        AgentHandler.claimed_cpu_lie = 0.1
        stop_event = threading.Event()
        try:
            t = threading.Thread(
                target=node_agent._arm_after_delay,
                args=(0.15, 'srvT', 'sybil', 1, stop_event),
                daemon=True,
            )
            t.start()

            # Immediately: still within the delay window, must be honest.
            assert AgentHandler.armed is False
            status = _get_status(agent_server)
            assert status['cpu_load'] != 0.1

            t.join(timeout=2.0)
            assert AgentHandler.armed is True
            status = _get_status(agent_server)
            assert status['cpu_load'] == 0.1
        finally:
            stop_event.set()

    def test_drop_mode_serves_normally_before_arming(self, agent_server):
        AgentHandler.malicious = 'drop'
        resp = _post_task(agent_server, timeout=5.0)
        assert resp.status == 200

    def test_drop_mode_blocks_once_armed(self, agent_server, monkeypatch):
        # Shrink the hang so the parked handler thread exits quickly instead
        # of sitting in time.sleep() for a simulated hour.
        monkeypatch.setattr(node_agent, '_DROP_HANG_S', 1.0)
        AgentHandler.malicious = 'drop'
        stop_event = threading.Event()
        node_agent._arm_malicious('srvT', 'drop', concurrency=1, stop_event=stop_event)

        # A client with a much shorter patience than the (shrunk) hang must
        # time out rather than get a reply -- this is the exact behavior
        # controller/flow_monitor.py's timeout-rate tell depends on.
        with pytest.raises((TimeoutError, OSError)):
            _post_task(agent_server, timeout=0.3)


class TestGrayhole:
    def test_unarmed_grayhole_serves_normally(self, agent_server):
        AgentHandler.malicious = 'grayhole'
        resp = _post_task(agent_server, timeout=5.0)
        assert resp.status == 200

    def test_armed_grayhole_drops_when_the_roll_is_under_the_rate(
        self, agent_server, monkeypatch,
    ):
        monkeypatch.setattr(node_agent, '_DROP_HANG_S', 1.0)
        monkeypatch.setattr(node_agent.random, 'random', lambda: 0.1)
        AgentHandler.malicious = 'grayhole'
        AgentHandler.grayhole_drop_rate = 0.5
        stop_event = threading.Event()
        try:
            node_agent._arm_malicious('srvT', 'grayhole', concurrency=1, stop_event=stop_event)
            with pytest.raises((TimeoutError, OSError)):
                _post_task(agent_server, timeout=0.3)
        finally:
            stop_event.set()

    def test_armed_grayhole_serves_when_the_roll_is_over_the_rate(
        self, agent_server, monkeypatch,
    ):
        monkeypatch.setattr(node_agent.random, 'random', lambda: 0.9)
        AgentHandler.malicious = 'grayhole'
        AgentHandler.grayhole_drop_rate = 0.5
        stop_event = threading.Event()
        try:
            node_agent._arm_malicious('srvT', 'grayhole', concurrency=1, stop_event=stop_event)
            resp = _post_task(agent_server, timeout=5.0)
            assert resp.status == 200
        finally:
            stop_event.set()


class TestOnOff:
    def test_unarmed_onoff_is_honest(self, agent_server):
        AgentHandler.malicious = 'onoff'
        status = _get_status(agent_server)
        assert status['cpu_load'] != 0.1

    def test_bad_phase_lies_then_good_phase_is_honest_again(self, agent_server):
        AgentHandler.malicious = 'onoff'
        AgentHandler.claimed_cpu_lie = 0.1
        AgentHandler.onoff_period_s = 0.3
        AgentHandler.onoff_duty = 0.5  # bad=0.15s, good=0.15s
        stop_event = threading.Event()
        try:
            node_agent._arm_malicious('srvT', 'onoff', concurrency=1, stop_event=stop_event)

            assert _wait_until(lambda: AgentHandler.onoff_bad is True)
            status = _get_status(agent_server)
            assert status['cpu_load'] == 0.1

            assert _wait_until(lambda: AgentHandler.onoff_bad is False, timeout=2.0)
            status = _get_status(agent_server)
            assert status['cpu_load'] != 0.1
        finally:
            stop_event.set()

    def test_onoff_before_arming_ignores_onoff_bad_leftover_state(self, agent_server):
        # Regression guard: onoff_bad is a separate flag from `armed`. A node
        # must never lie just because onoff_bad happens to be True while
        # still unarmed (e.g. leftover class state from a prior test/run).
        AgentHandler.malicious = 'onoff'
        AgentHandler.armed = False
        AgentHandler.onoff_bad = True
        status = _get_status(agent_server)
        assert status['cpu_load'] != 0.1
