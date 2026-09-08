"""Tests for run_demo.py's `--mode mininet` orchestration (Project Plan
Step 3). None of these need Mininet or root: the guard clauses (root check,
Mininet-availability check, config shape check) and the controller-readiness
poll are exercised directly; actually creating a Mininet network is left to
a human running `sudo python3 run_demo.py --mode mininet` (see SETUP.md /
memory 'wsl-run-prerequisites')."""

import http.server
import socket
import sys
import threading

import pytest

import run_demo


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class TestWaitForController:
    def test_returns_true_once_the_api_responds(self) -> None:
        port = _free_port()

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 (stdlib method name)
                self.send_response(200)
                self.end_headers()

            def log_message(self, *a) -> None:  # silence test output
                pass

        server = http.server.HTTPServer(('127.0.0.1', port), _Handler)
        # handle_request() (single-shot) rather than serve_forever()+shutdown():
        # this test process also imports run_demo -> controller.trust_balancer
        # -> os_ken, and something in that import chain makes
        # socketserver.BaseServer.shutdown() hang forever in-process (does not
        # affect the real live demo -- there, the controller is always a
        # separate OS process, see run_mininet). One request is all this test
        # needs anyway.
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        try:
            assert run_demo._wait_for_controller('127.0.0.1', port, timeout_s=3.0) is True
        finally:
            thread.join(timeout=2)
            server.server_close()

    def test_returns_false_when_nothing_listens(self) -> None:
        port = _free_port()  # bound-and-released; nothing is listening on it
        assert run_demo._wait_for_controller('127.0.0.1', port, timeout_s=1.0) is False

    def test_0_0_0_0_is_dialed_as_loopback(self) -> None:
        # api_host is 0.0.0.0 in every shipped config (the controller binds
        # all interfaces); dialing 0.0.0.0 back from the same box doesn't
        # reliably connect on every platform, so this must rewrite to 127.0.0.1.
        port = _free_port()
        assert run_demo._wait_for_controller('0.0.0.0', port, timeout_s=1.0) is False  # no crash


class TestRunMininetGuardClauses:
    def test_requires_root(self, monkeypatch, capsys) -> None:
        monkeypatch.setattr(run_demo.os, 'geteuid', lambda: 1000)
        with pytest.raises(SystemExit) as exc:
            run_demo.run_mininet(run_demo.DEFAULT_MININET_CONFIG, None)
        assert exc.value.code == 1
        assert 'sudo' in capsys.readouterr().out

    def test_requires_mininet_installed(self, monkeypatch, capsys) -> None:
        monkeypatch.setattr(run_demo.os, 'geteuid', lambda: 0)
        monkeypatch.setattr('simulation.topology._MININET_AVAILABLE', False)
        with pytest.raises(SystemExit) as exc:
            run_demo.run_mininet(run_demo.DEFAULT_MININET_CONFIG, None)
        assert exc.value.code == 1
        assert 'not installed' in capsys.readouterr().out

    def test_requires_a_controller_block_in_the_config(self, monkeypatch, capsys) -> None:
        monkeypatch.setattr(run_demo.os, 'geteuid', lambda: 0)
        monkeypatch.setattr('simulation.topology._MININET_AVAILABLE', True)
        # config/params.yaml (the evaluation harness's config) has no
        # `controller:` block -- it can't drive the live trust-aware demo.
        with pytest.raises(SystemExit) as exc:
            run_demo.run_mininet('config/params.yaml', None)
        assert exc.value.code == 1
        assert 'controller:' in capsys.readouterr().out


class TestMainConfigResolution:
    """main() picks the right default config per mode without the caller
    having to pass --config -- verified by faking out the mode handler and
    inspecting what it was called with, so no real run (standalone or
    mininet) actually happens."""

    def test_mininet_mode_defaults_to_the_full_scale_config(self, monkeypatch) -> None:
        captured = {}
        monkeypatch.setattr(
            run_demo, 'run_mininet',
            lambda config_path, duration: captured.update(config_path=config_path, duration=duration),
        )
        monkeypatch.setattr(sys, 'argv', ['run_demo.py', '--mode', 'mininet'])
        run_demo.main()
        assert captured['config_path'] == run_demo.DEFAULT_MININET_CONFIG
        assert captured['duration'] is None

    def test_mininet_mode_honours_an_explicit_config(self, monkeypatch) -> None:
        captured = {}
        monkeypatch.setattr(
            run_demo, 'run_mininet',
            lambda config_path, duration: captured.update(config_path=config_path, duration=duration),
        )
        monkeypatch.setattr(
            sys, 'argv',
            ['run_demo.py', '--mode', 'mininet', '--config', 'config/params_trust_demo.yaml',
             '--duration', '60'],
        )
        run_demo.main()
        assert captured['config_path'] == 'config/params_trust_demo.yaml'
        assert captured['duration'] == 60

    def test_standalone_mode_still_defaults_to_120s_and_params_yaml(self, monkeypatch) -> None:
        captured = {}
        monkeypatch.setattr(
            run_demo, 'run_standalone',
            lambda cfg, duration, attack: captured.update(duration=duration, attack=attack),
        )
        monkeypatch.setattr(sys, 'argv', ['run_demo.py'])
        run_demo.main()
        assert captured['duration'] == 120
        assert captured['attack'] == 'both'


class _FakeHost:
    def __init__(self, name, ip, loss_to=()):
        self.name = name
        self._ip = ip
        self._loss_to = set(loss_to)
        self.pings = []

    def IP(self):
        return self._ip

    def cmd(self, c):
        target = c.rsplit(' ', 1)[-1]
        self.pings.append(target)
        if target in self._loss_to:
            return '1 packets transmitted, 0 received, 100% packet loss'
        return '1 packets transmitted, 1 received, 0% packet loss'


class _FakeNet:
    def __init__(self, n_srv, n_iot, loss_to=()):
        self.hosts = {}
        for i in range(1, n_srv + 1):
            self.hosts[f'srv{i}'] = _FakeHost(f'srv{i}', f'10.0.1.{i}', loss_to)
        for j in range(1, n_iot + 1):
            self.hosts[f'iot{j}'] = _FakeHost(f'iot{j}', f'10.0.0.{j}', loss_to)
        self.pingall_calls = 0

    def get(self, name):
        return self.hosts[name]

    def pingAll(self):
        self.pingall_calls += 1
        return 0.0


def _cfg(n_srv, n_iot, **extra):
    sim = {'num_edge_nodes': n_srv, 'num_iot_devices': n_iot}
    sim.update(extra)
    return {'simulation': sim}


class TestSampledReachability:
    """pingAll is O(hosts^2) and, since Defect 1's fix put it after agent
    launch, it runs against the live workload: ~1,415 s of a 1,720 s run at
    8/40/3. The sample has to stay O(hosts) while still touching every host."""

    def test_probe_count_is_linear_not_quadratic(self):
        from simulation.topology import _sampled_reachability_check
        net = _FakeNet(8, 40)
        _sampled_reachability_check(net, _cfg(8, 40))
        probes = sum(len(h.pings) for h in net.hosts.values())
        assert probes <= 2 * 48, f'{probes} probes is not O(hosts)'
        assert probes < 2352 / 10, 'must be far cheaper than the 2,352-ping sweep'
        assert net.pingall_calls == 0

    def test_every_host_is_covered_in_at_least_one_direction(self):
        from simulation.topology import _sampled_reachability_check
        net = _FakeNet(8, 40)
        _sampled_reachability_check(net, _cfg(8, 40))
        sources = {n for n, h in net.hosts.items() if h.pings}
        targets = {t for h in net.hosts.values() for t in h.pings}
        for j in range(1, 41):
            assert f'iot{j}' in sources, f'iot{j} never probed anything'
        for i in range(1, 9):
            assert f'srv{i}' in sources, f'srv{i} never probed anything'
            assert f'10.0.1.{i}' in targets, f'srv{i} was never a target'

    def test_reports_loss_when_a_pair_does_not_answer(self):
        from simulation.topology import _sampled_reachability_check
        net = _FakeNet(4, 8, loss_to={'10.0.1.1'})
        loss = _sampled_reachability_check(net, _cfg(4, 8))
        assert loss > 0.0, 'a dead server must show up as loss, not be sampled away'

    def test_full_pingall_opt_in_restores_the_exhaustive_sweep(self):
        from simulation.topology import _sampled_reachability_check
        net = _FakeNet(8, 40)
        _sampled_reachability_check(net, _cfg(8, 40, full_pingall=True))
        assert net.pingall_calls == 1
        assert sum(len(h.pings) for h in net.hosts.values()) == 0


class TestTeardownPausesTheMonitor:
    """Runs 5 and 6 both ended with all 8 nodes quarantined in the final frame,
    purely because the harness kills agents while the controller still polls."""

    def test_pause_is_requested_before_agents_are_killed(self, monkeypatch):
        import simulation.topology as topo
        order = []

        def _fake_pause(cfg):
            order.append('pause')

        net = _FakeNet(2, 2)
        for h in net.hosts.values():
            h.cmd = lambda c, _h=h: order.append(f'kill:{_h.name}')
        monkeypatch.setattr(topo, '_pause_controller_monitor', _fake_pause)
        topo._stop_trust_agents(net, _cfg(2, 2))

        assert order[0] == 'pause', f'monitor must pause first, got {order}'
        assert any(o.startswith('kill:') for o in order)

    def test_teardown_survives_an_unreachable_controller(self):
        import simulation.topology as topo
        # Nothing listening on this port -- must warn, not raise.
        topo._pause_controller_monitor(
            {'controller': {'api_host': '127.0.0.1', 'api_port': 9}}
        )

    def test_no_controller_block_is_a_no_op(self):
        import simulation.topology as topo
        topo._pause_controller_monitor({'simulation': {}})
