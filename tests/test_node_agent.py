"""Tests for simulation/node_agent.py -- specifically the --malicious-start-s
delayed-onset gate (plan_adv.md Phase 0). Runs the real AgentHandler over a
real HTTP server on a loopback port (same pattern as
tests/test_run_demo_mininet.py's _free_port helper); no Mininet/root needed.

AgentHandler's class attributes and the module's globals are process-wide
state, so every test resets them via the `agent_server` fixture rather than
relying on import order or test order.
"""

import http.client
import http.server
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
    node_agent._slots = None
    node_agent._lie_busy_base = 0.0
    node_agent._lie_busy_at = None
    node_agent._stealth_last_busy = None
    AgentHandler.work_mode = 'burn'
    AgentHandler.work_ops = 20000
    AgentHandler.liar_busy = 'consistent'
    AgentHandler.stealth_rho = 0.25
    AgentHandler.stealth_margin = 0.8
    AgentHandler.stealth_honesty_threshold = 0.40
    AgentHandler.stealth_interval_s = 2.0
    AgentHandler.stealth_observe_url = 'http://127.0.0.1:1/node/status'
    AgentHandler.stealth_claim_now = 0.0

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


# --------------------------------------------------------------------------- #
# Phase 1 (2026-10-19): work models, worker slots, and the liars whose lie
# works. The shipped sybil burns CPU (so it is slow) and its 0.1 claim sits
# above an honest server's truthful ~0 at the shipped ~1% duty, so it repels
# traffic; these are the attackers that test whether the gate catches the LIE.

def _post_tasks_concurrently(port: int, n: int) -> list:
    out, threads = [], []
    for _ in range(n):
        t = threading.Thread(target=lambda: out.append(_post_task(port).status))
        threads.append(t)
        t.start()
    for t in threads:
        t.join(timeout=10)
    return out


class TestWorkModes:
    def test_hold_occupies_a_worker_for_work_ms(self, agent_server):
        AgentHandler.work_mode = 'hold'
        AgentHandler.work_ms = 120.0
        t0 = time.monotonic()
        assert _post_task(agent_server).status == 200
        assert time.monotonic() - t0 >= 0.12
        assert _get_status(agent_server)['busy_seconds'] >= 0.12

    def test_hold_uses_no_cpu(self, agent_server):
        AgentHandler.work_mode = 'hold'
        AgentHandler.work_ms = 200.0
        cpu0 = time.process_time()
        _post_task(agent_server)
        assert time.process_time() - cpu0 < 0.1     # a sleep, not a spin

    def test_ops_is_a_fixed_amount_of_work(self, agent_server, monkeypatch):
        calls = []
        monkeypatch.setattr(node_agent, '_burn_ops', lambda n: calls.append(n))
        AgentHandler.work_mode = 'ops'
        AgentHandler.work_ops = 777
        _post_task(agent_server)
        assert calls == [777]

    def test_burn_is_still_the_default(self):
        args = node_agent.build_parser().parse_args(['--node-id', 'srv1'])
        assert args.work_mode == 'burn' and args.enforce_concurrency is False


class TestWorkerSlots:
    def test_unbounded_by_default(self, agent_server):
        AgentHandler.work_mode = 'hold'
        AgentHandler.work_ms = 300.0
        AgentHandler.concurrency = 1
        t0 = time.monotonic()
        assert _post_tasks_concurrently(agent_server, 2) == [200, 200]
        assert time.monotonic() - t0 < 0.55          # served side by side

    def test_enforced_slots_make_excess_work_queue(self, agent_server):
        AgentHandler.work_mode = 'hold'
        AgentHandler.work_ms = 300.0
        AgentHandler.concurrency = 1
        node_agent._slots = threading.BoundedSemaphore(1)
        t0 = time.monotonic()
        assert _post_tasks_concurrently(agent_server, 2) == [200, 200]
        assert time.monotonic() - t0 >= 0.6          # one after the other
        # Queueing is not service: busy time is ~2 x 0.3 s, not more.
        assert _get_status(agent_server)['busy_seconds'] == pytest.approx(0.6, abs=0.1)


def _arm(kind):
    node_agent._arm_malicious('srvT', kind, concurrency=AgentHandler.concurrency,
                              stop_event=threading.Event())


class TestLiar:
    def test_claims_the_lie_and_burns_nothing(self, agent_server):
        AgentHandler.malicious = 'liar'
        AgentHandler.claimed_cpu_lie = 0.0
        before = threading.active_count()
        _arm('liar')
        assert threading.active_count() == before     # no burner threads
        assert _get_status(agent_server)['cpu_load'] == 0.0

    def test_consistent_busy_counter_continues_from_the_real_one(self, agent_server):
        AgentHandler.malicious = 'liar'
        AgentHandler.claimed_cpu_lie = 0.0
        AgentHandler.work_mode = 'hold'
        AgentHandler.work_ms = 100.0
        _post_task(agent_server)                       # honest work before onset
        real_at_arm = _get_status(agent_server)['busy_seconds']
        _arm('liar')
        _post_task(agent_server)                       # real work, hidden
        busy = _get_status(agent_server)['busy_seconds']
        # Claimed duty 0: the counter stops where the real one was at arming.
        # It never jumps backwards (the sybil's restarts from 0).
        assert busy == pytest.approx(real_at_arm, abs=1e-6)
        assert node_agent._busy_seconds_total > real_at_arm + 0.09

    def test_truthful_busy_counter_is_the_split_claim(self, agent_server):
        AgentHandler.malicious = 'liar'
        AgentHandler.claimed_cpu_lie = 0.0
        AgentHandler.liar_busy = 'truthful'
        AgentHandler.work_mode = 'hold'
        AgentHandler.work_ms = 100.0
        _arm('liar')
        _post_task(agent_server)
        status = _get_status(agent_server)
        assert status['cpu_load'] == 0.0               # what routing reads
        assert status['busy_seconds'] >= 0.1           # what the honesty check reads

    def test_unarmed_liar_is_honest(self, agent_server):
        AgentHandler.malicious = 'liar'
        AgentHandler.claimed_cpu_lie = 0.0
        AgentHandler.work_mode = 'hold'
        AgentHandler.work_ms = 100.0
        _post_task(agent_server)
        assert _get_status(agent_server)['busy_seconds'] >= 0.1


class TestStealthClaim:
    def test_undercuts_to_the_peer_quantile(self):
        peers = [0.2, 0.4, 0.6, 0.8]
        assert node_agent.stealth_claim(peers, true_duty=0.3, rho=0.0,
                                        margin=0.8, honesty_threshold=0.4) == 0.2

    def test_never_below_the_honesty_floor(self):
        # True duty 0.9; floor 0.9 - 0.8*0.4 = 0.58, above every peer's claim.
        c = node_agent.stealth_claim([0.1, 0.2], true_duty=0.9, rho=0.25,
                                     margin=0.8, honesty_threshold=0.4)
        assert c == pytest.approx(0.58)

    def test_blind_falls_back_to_the_floor(self):
        assert node_agent.stealth_claim([], true_duty=0.5, rho=0.25, margin=1.0,
                                        honesty_threshold=0.4) == pytest.approx(0.1)
        assert node_agent.stealth_claim([], true_duty=0.1, rho=0.25, margin=1.0,
                                        honesty_threshold=0.4) == 0.0

    def test_quantile_interpolates(self):
        assert node_agent._quantile([0.0, 1.0], 0.25) == pytest.approx(0.25)


class TestStealthyAgent:
    def test_reads_the_controller_and_claims_the_quantile(self, agent_server):
        import json as _json

        class _Snap(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = _json.dumps({
                    'srvT': {'claimed_cpu': 0.0},          # itself: excluded
                    'srv1': {'claimed_cpu': 0.30}, 'srv2': {'claimed_cpu': 0.50},
                    'srv3': {'claimed_cpu': 0.70}}).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        port = _free_port()
        ctrl = http.server.HTTPServer(('127.0.0.1', port), _Snap)
        threading.Thread(target=ctrl.serve_forever, daemon=True).start()
        try:
            AgentHandler.malicious = 'stealthy'
            AgentHandler.stealth_observe_url = f'http://127.0.0.1:{port}/node/status'
            AgentHandler.stealth_interval_s = 0.05
            AgentHandler.stealth_rho = 0.0
            stop = threading.Event()
            node_agent._arm_malicious('srvT', 'stealthy', concurrency=4, stop_event=stop)
            assert _wait_until(lambda: _get_status(agent_server)['cpu_load'] == 0.3)
            stop.set()
        finally:
            ctrl.shutdown()
            ctrl.server_close()
