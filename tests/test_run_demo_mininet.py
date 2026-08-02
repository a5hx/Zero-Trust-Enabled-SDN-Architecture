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
