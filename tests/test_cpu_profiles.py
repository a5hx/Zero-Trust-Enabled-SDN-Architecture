"""simulation/cpu_profiles.py -- Phase 3, honest-slow servers on demand.

No root needed: the cgroup filesystem is faked under tmp_path, which is a
plain directory tree with the same file names. What is pinned here is what
the harness writes where, and that the shipped configs are untouched."""

import threading
import time
from pathlib import Path

import pytest
import yaml

from simulation import cpu_profiles as cp


def _cfg(**sim):
    base = {'num_edge_nodes': 8, 'num_iot_devices': 4, 'malicious_edge_nodes': []}
    base.update(sim)
    return {'simulation': base}


def _fake_root(tmp_path):
    root = tmp_path / 'cgroup'
    root.mkdir()
    (root / 'cgroup.controllers').write_text('cpuset cpu io memory pids\n')
    (root / 'cgroup.subtree_control').write_text('memory pids\n')
    return root


PROFILED = _cfg(
    server_profiles={'srv1': {'class': 'fast'}, 'srv5': {'class': 'slow', 'cpu_max': '5000 10000'}},
    honest_throttle=[{'node': 'srv4', 'start_s': 0.05, 'duration_s': 0.1, 'cpu_max': '2500 10000'}],
)


class TestConfig:
    def test_profiles_and_classes(self):
        assert cp.server_classes(PROFILED) == {'srv1': 'fast', 'srv5': 'slow'}
        assert cp.parse_profiles(PROFILED)['srv1'].cpu_max is None

    def test_only_capped_or_throttled_servers_get_a_group(self):
        assert cp.capped_nodes(PROFILED) == ['srv4', 'srv5']

    @pytest.mark.parametrize('bad', ['half', '5000', '0 10000', '5000 10000 1'])
    def test_cpu_max_is_validated(self, bad):
        with pytest.raises(cp.ProfileError):
            cp.parse_profiles(_cfg(server_profiles={'srv1': {'cpu_max': bad}}))

    def test_unknown_server_is_refused(self):
        with pytest.raises(cp.ProfileError):
            cp.parse_profiles(_cfg(server_profiles={'srv9': {'class': 'x'}}))

    def test_an_attacker_cannot_be_an_honest_throttle(self):
        cfg = _cfg(malicious_edge_nodes=[{'node': 'srv3', 'attack': 'liar'}],
                   honest_throttle=[{'node': 'srv3', 'start_s': 1, 'duration_s': 1,
                                     'cpu_max': '2500 10000'}])
        with pytest.raises(cp.ProfileError):
            cp.parse_throttles(cfg)

    def test_schedule_restores_the_profile_cap_not_full_speed(self):
        cfg = _cfg(server_profiles={'srv5': {'class': 'slow', 'cpu_max': '5000 10000'}},
                   honest_throttle=[{'node': 'srv5', 'start_s': 120, 'duration_s': 60,
                                     'cpu_max': '1000 10000'}])
        assert cp.schedule(cfg) == [(120.0, 'srv5', '1000 10000'), (180.0, 'srv5', '5000 10000')]

    def test_an_unprofiled_throttle_ends_uncapped(self):
        assert cp.schedule(PROFILED)[-1] == (0.15000000000000002, 'srv4', cp.UNCAPPED)


class TestCgroupFilesystem:
    def test_setup_creates_groups_with_initial_caps(self, tmp_path):
        root = _fake_root(tmp_path)
        assert cp.setup(PROFILED, root) == ['srv4', 'srv5']
        assert '+cpu' in (root / 'cgroup.subtree_control').read_text()
        assert (root / 'ztsdn' / 'srv5' / 'cpu.max').read_text() == '5000 10000'
        assert (root / 'ztsdn' / 'srv4' / 'cpu.max').read_text() == cp.UNCAPPED

    def test_setup_refuses_without_a_cpu_controller(self, tmp_path):
        root = _fake_root(tmp_path)
        (root / 'cgroup.controllers').write_text('memory pids\n')
        with pytest.raises(cp.ProfileError):
            cp.setup(PROFILED, root)

    def test_nothing_to_do_touches_nothing(self, tmp_path):
        root = _fake_root(tmp_path)
        assert cp.setup(_cfg(), root) == []
        assert not (root / 'ztsdn').exists()

    def test_the_schedule_applies_and_restores(self, tmp_path):
        root = _fake_root(tmp_path)
        cp.setup(PROFILED, root)
        stop = threading.Event()
        th = cp.start_schedule(PROFILED, stop, root)
        cpu = root / 'ztsdn' / 'srv4' / 'cpu.max'
        deadline = time.monotonic() + 2
        seen = set()
        while time.monotonic() < deadline and th.is_alive():
            seen.add(cpu.read_text())
            time.sleep(0.005)
        assert '2500 10000' in seen
        assert cpu.read_text() == cp.UNCAPPED

    def test_teardown_removes_empty_groups(self, tmp_path):
        root = _fake_root(tmp_path)
        cp.setup(PROFILED, root)
        # A real cgroup directory with no processes is removable even though
        # its interface files are listed; the fake one needs them gone.
        for node in ('srv4', 'srv5'):
            (root / 'ztsdn' / node / 'cpu.max').unlink()
        (root / 'ztsdn' / 'cgroup.subtree_control').unlink()
        cp.teardown(PROFILED, root)
        assert not (root / 'ztsdn').exists()


class TestLaunch:
    """The first pilot (2026-10-20) showed an agent cannot join its group from
    inside a Mininet host ("Directory nonexistent": the host's /sys is not the
    root's). Agents now launch unchanged and the harness attaches them."""

    def _commands(self, cfg):
        from tests.test_live_config_preflight import launch_commands
        return dict(launch_commands(cfg))

    def _full(self):
        with open('config/params_trust_full.yaml') as fh:
            return yaml.safe_load(fh)

    def test_profiles_never_change_a_launch_command(self):
        cfg = self._full()
        before = self._commands(cfg)
        cfg['simulation']['server_profiles'] = {'srv5': {'class': 'slow', 'cpu_max': '5000 10000'}}
        assert self._commands(cfg) == before

    def test_attach_moves_each_capped_agent_into_its_group(self, tmp_path):
        root = _fake_root(tmp_path)
        cp.setup(PROFILED, root)
        pids = {'srv4': [111], 'srv5': [222]}
        moved = cp.attach(PROFILED, root, find_pids=lambda n: pids.get(n, []))
        assert moved == {'srv4': [111], 'srv5': [222]}
        assert (root / 'ztsdn' / 'srv5' / 'cgroup.procs').read_text() == '222'
        assert cp.unjoined(PROFILED, root) == []

    def test_an_agent_that_is_not_running_is_reported(self, tmp_path):
        root = _fake_root(tmp_path)
        cp.setup(PROFILED, root)
        cp.attach(PROFILED, root, find_pids=lambda n: [333] if n == 'srv5' else [])
        assert cp.unjoined(PROFILED, root) == ['srv4']


class TestClassesReachTheController:
    def test_generated_inventory_takes_classes_from_profiles(self):
        from contracts.inventory import Inventory
        cfg = _cfg(server_profiles={'srv1': {'class': 'fast'}, 'srv2': {'class': 'fast'},
                                    'srv5': {'class': 'slow', 'cpu_max': '5000 10000'}})
        inv = Inventory.from_config(cfg)
        assert inv.server_class('srv5') == 'slow' and inv.server_class('srv1') == 'fast'
        assert inv.server_class('srv3') == 'default'
        assert inv.source == 'mininet'

    def test_topology_event_marks_throttled_honest_servers(self):
        pytest.importorskip('os_ken')
        from controller.trust_balancer import TrustBalancerApp
        from controller.trust_state import TrustState
        cfg = self._full_cfg()

        class FakeApp:
            def __init__(self):
                self.cfg = cfg
                self.state = TrustState(node_ids=[f'srv{i}' for i in range(1, 9)])
                self.vip_ip = '10.0.99.1'
                self.vip_port = 9000

        g = TrustBalancerApp.topology_graph(FakeApp())
        srv = {n['id']: n for n in g['nodes'] if n.get('kind') == 'server'}
        assert srv['srv4']['attack'] == 'none'
        assert srv['srv4']['throttle'] == [{'start_s': 0.05, 'duration_s': 0.1,
                                            'cpu_max': '2500 10000'}]
        assert srv['srv5']['hw_class'] == 'slow' and srv['srv5']['cpu_max'] == '5000 10000'
        assert 'hw_class' not in srv['srv2'] and 'throttle' not in srv['srv2']

    def _full_cfg(self):
        with open('config/params_trust_full.yaml') as fh:
            cfg = yaml.safe_load(fh)
        cfg['simulation']['malicious_edge_nodes'] = []
        cfg['simulation'].update({k: v for k, v in PROFILED['simulation'].items()
                                  if k in ('server_profiles', 'honest_throttle')})
        return cfg


def test_a_capped_group_with_no_process_is_reported(tmp_path):
    root = _fake_root(tmp_path)
    cp.setup(PROFILED, root)
    (root / 'ztsdn' / 'srv5' / 'cgroup.procs').write_text('4242\n')
    (root / 'ztsdn' / 'srv4' / 'cgroup.procs').write_text('')
    assert cp.unjoined(PROFILED, root) == ['srv4']
