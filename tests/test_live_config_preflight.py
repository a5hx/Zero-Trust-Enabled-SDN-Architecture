"""Preflight for the live-run configs. plan_adv.md Phase 6.

A live run costs sudo, a few minutes, and a terminal the user has to babysit --
and every live run in this project's history has surfaced at least one defect,
several of them pure config/wiring mistakes that were knowable beforehand
(see memory/live-run-cascading-quarantine). `config/params_trust_full.yaml` now
carries all six Phase 1 attacks and had never been run when these were written.

So this exercises the REAL launch path without root: `_launch_trust_agents` is
driven against a stub Mininet `net` that records the shell command it would run
on each host instead of running it, and every recorded command is then fed to
the actual argparse of the module it invokes. A typo'd flag, an attack kind the
agent does not accept, or a config key topology.py silently ignores fails here
in milliseconds instead of 300 seconds into a sudo run.

It deliberately does NOT check anything that needs the network to exist --
that is what the live run is for.
"""

import re
import shlex
import unittest
from pathlib import Path

import yaml

CONFIGS = ['config/params_trust_full.yaml', 'config/params_attacks_demo.yaml']


class _FakeHost:
    def __init__(self, name, sink):
        self.name = name
        self._sink = sink

    def cmd(self, cmd):
        self._sink.append((self.name, cmd))
        return ''


class _FakeNet:
    """Enough of a Mininet net for _launch_trust_agents to run against."""

    def __init__(self):
        self.commands = []

    def get(self, name):
        return _FakeHost(name, self.commands)


def launch_commands(cfg):
    from simulation.topology import _launch_trust_agents

    net = _FakeNet()
    _launch_trust_agents(net, cfg)
    return net.commands


def load(path):
    with open(path) as f:
        return yaml.safe_load(f)


def argv_for(cmd):
    """Strip `python3 -u -m module` and the shell redirection off a command."""
    body = cmd.split('>')[0].strip()
    parts = shlex.split(body)
    assert parts[0] == 'python3', parts[0]
    m = parts.index('-m')
    return parts[m + 1], parts[m + 2:]


class TestLaunchCommandsParse(unittest.TestCase):
    """Every command topology.py builds must be accepted by its own module.

    This is the check that would have caught a new attack kind wired into
    topology.py but never added to node_agent.py's `--malicious` choices.
    """

    def _commands(self, path):
        if not Path(path).exists():
            self.skipTest(f'{path} not present')
        return launch_commands(load(path))

    def test_every_agent_and_client_command_parses(self):
        from simulation import iot_client, node_agent

        # iot_client exposes parse_args() because it has a cross-field rule
        # (spoof requires a target) that a bare parser would skip -- and that
        # rule guards a real config mistake.
        parsers = {
            'simulation.node_agent': lambda a: node_agent.build_parser().parse_args(a),
            'simulation.iot_client': iot_client.parse_args,
        }
        for path in CONFIGS:
            for host, cmd in self._commands(path):
                module, argv = argv_for(cmd)
                self.assertIn(module, parsers, f'{path}: {host} -> {module}')
                # SystemExit here means argparse rejected the command line the
                # topology would really have run.
                try:
                    parsers[module](argv)
                except SystemExit:
                    self.fail(f'{path}: {host} command rejected by {module}:\n  {cmd}')

    def test_every_server_and_device_gets_launched(self):
        for path in CONFIGS:
            cfg = load(path)
            cmds = self._commands(path)
            hosts = {h for h, _ in cmds}
            n_edge = cfg['simulation']['num_edge_nodes']
            n_iot = cfg['simulation']['num_iot_devices']
            for i in range(1, n_edge + 1):
                self.assertIn(f'srv{i}', hosts, f'{path}: srv{i} never launched')
            for j in range(1, n_iot + 1):
                self.assertIn(f'iot{j}', hosts, f'{path}: iot{j} never launched')


class TestConfiguredAttacksReachTheAgents(unittest.TestCase):
    """A config entry that topology.py silently ignores is the failure mode
    here: the run looks fine, the attack never happens, and the classifier is
    scored against an attack that was not present."""

    def setUp(self):
        path = 'config/params_trust_full.yaml'
        if not Path(path).exists():
            self.skipTest(f'{path} not present')
        self.cfg = load(path)
        self.cmds = dict(launch_commands(self.cfg))

    def test_each_malicious_edge_node_is_launched_with_its_attack(self):
        for m in self.cfg['simulation'].get('malicious_edge_nodes', []):
            cmd = self.cmds[m['node']]
            self.assertIn(f"--malicious {m['attack']}", cmd,
                          f"{m['node']} not armed with {m['attack']}")
            self.assertIn(f"--malicious-start-s {float(m.get('start_s', 0.0))}", cmd)

    def test_honest_nodes_are_launched_with_no_attack(self):
        mal = {m['node'] for m in self.cfg['simulation'].get('malicious_edge_nodes', [])}
        n_edge = self.cfg['simulation']['num_edge_nodes']
        for i in range(1, n_edge + 1):
            if f'srv{i}' in mal:
                continue
            self.assertIn('--malicious none', self.cmds[f'srv{i}'])

    def test_attack_specific_parameters_are_passed_through(self):
        for m in self.cfg['simulation'].get('malicious_edge_nodes', []):
            cmd = self.cmds[m['node']]
            if 'grayhole_drop_rate' in m:
                self.assertIn(f"--grayhole-drop-rate {m['grayhole_drop_rate']}", cmd)
            if 'onoff_period_s' in m:
                self.assertIn(f"--onoff-period-s {m['onoff_period_s']}", cmd)
            if 'onoff_duty' in m:
                self.assertIn(f"--onoff-duty {m['onoff_duty']}", cmd)

    def test_flood_devices_are_armed(self):
        for m in self.cfg['simulation'].get('malicious_flood_devices', []):
            cmd = self.cmds[m['device']]
            self.assertIn('--malicious flood', cmd)
            self.assertIn(f"--flood-concurrency {m.get('concurrency', 20)}", cmd)

    def test_spoof_devices_are_armed_against_their_target(self):
        for m in self.cfg['simulation'].get('malicious_spoof_devices', []):
            cmd = self.cmds[m['device']]
            self.assertIn('--malicious spoof', cmd)
            self.assertIn(f"--spoof-target-device-id {m['target']}", cmd)

    def test_a_spoofer_is_given_the_real_fleet_key(self):
        """A spoofer holding the WRONG key is refused for bad credentials and
        never gets far enough to impersonate anyone -- the run would then
        contain five attacks while the report expects six."""
        good = self.cfg['security']['shared_key_hex']
        for m in self.cfg['simulation'].get('malicious_spoof_devices', []):
            self.assertIn(f'--auth-key-hex {good}', self.cmds[m['device']])

    def test_wrong_key_devices_really_get_a_different_key(self):
        good = self.cfg['security']['shared_key_hex']
        for device in self.cfg['security'].get('malicious_iot_devices', []) or []:
            cmd = self.cmds[device]
            self.assertIn('--auth-key-hex', cmd)
            self.assertNotIn(f'--auth-key-hex {good}', cmd)


class TestGroundTruthMatchesWhatIsLaunched(unittest.TestCase):
    """The `topology` event's ground truth must describe the run that actually
    happens. If they disagree, the confusion matrix scores the wrong thing and
    every number downstream inherits the error."""

    def setUp(self):
        path = 'config/params_trust_full.yaml'
        if not Path(path).exists():
            self.skipTest(f'{path} not present')
        try:
            import os_ken  # noqa: F401
        except ImportError:
            self.skipTest('os-ken not installed')
        self.cfg = load(path)
        self.cmds = dict(launch_commands(self.cfg))

    def _graph(self):
        from controller.trust_balancer import TrustBalancerApp
        from controller.trust_state import TrustState

        cfg = self.cfg
        n_edge = cfg['simulation']['num_edge_nodes']

        class FakeApp:
            def __init__(self):
                self.cfg = cfg
                self.state = TrustState(
                    node_ids=[f'srv{i}' for i in range(1, n_edge + 1)])
                self.vip_ip = cfg['controller']['vip']
                self.vip_port = cfg['controller']['vip_port']

        return TrustBalancerApp.topology_graph(FakeApp())

    def test_every_node_marked_as_attacking_is_really_launched_attacking(self):
        from controller.attack_classifier import (
            ATTACK_BAD_CREDENTIALS, GROUND_TRUTH_ALIASES, NO_ATTACK,
        )

        for node in self._graph()['nodes']:
            if node.get('kind') not in ('server', 'iot'):
                continue
            truth = GROUND_TRUTH_ALIASES.get(node.get('attack', 'none'), 'none')
            cmd = self.cmds.get(node['id'], '')
            # An edge agent is always launched with an explicit --malicious;
            # an honest IoT client is launched with the flag omitted entirely
            # (it defaults to none). So read the effective value rather than
            # assuming either spelling.
            armed = re.search(r'--malicious (\w+)', cmd)
            armed = armed.group(1) if armed else 'none'

            if truth == NO_ATTACK:
                self.assertEqual(
                    armed, 'none',
                    f"{node['id']} is ground-truthed honest but launched as {armed}",
                )
            elif truth == ATTACK_BAD_CREDENTIALS:
                # The one attack with no --malicious mode: it is expressed
                # purely as being handed the wrong key.
                self.assertEqual(armed, 'none')
                self.assertIn('--auth-key-hex', cmd)
            else:
                self.assertNotEqual(
                    armed, 'none',
                    f"{node['id']} is ground-truthed as {truth} but launched honest",
                )

    def test_onsets_in_ground_truth_match_the_launched_start(self):
        for node in self._graph()['nodes']:
            if node.get('attack', 'none') in ('none', 'bad_credentials'):
                continue
            cmd = self.cmds.get(node['id'], '')
            self.assertIn(
                f"--malicious-start-s {float(node['attack_start_s'])}", cmd,
                f"{node['id']}: ground-truth onset disagrees with launch",
            )

    def test_all_six_attacks_plus_bad_credentials_are_present(self):
        """The confusion matrix is only meaningful if the run contains the
        attacks it claims to score."""
        kinds = {n.get('attack') for n in self._graph()['nodes']}
        for expected in ('sybil', 'drop', 'grayhole', 'onoff', 'flood', 'spoof',
                         'bad_credentials'):
            self.assertIn(expected, kinds, f'{expected} missing from the run')


if __name__ == '__main__':
    unittest.main()
