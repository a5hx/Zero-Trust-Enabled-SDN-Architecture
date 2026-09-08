"""Both arms are launched by the same code. This pins that.

`base_model/run_base.py` imports four private helpers out of
`simulation/topology.py` rather than copying them. The reason is in that file's
docstring: `_launch_trust_agents` builds every `node_agent.py` and
`iot_client.py` command line -- work-ms, report interval, task timeout, which
server is a sybil and when it arms, which device floods at what concurrency,
which device spoofs whom, which two get the wrong key. Two copies of that
function is two workloads, and the arms would drift apart while still being
reported as a controlled comparison.

The cost of importing private names is that a rename breaks the baseline at
run time -- after `sudo`, after the network is up, minutes into a run. These
tests move that failure to the test suite.

The last test is the important one: it drives the real launcher against the
real config with a fake Mininet and asserts the attacker command lines the
baseline arm will actually issue. That is the check that the two arms arm the
same attackers at the same second.
"""

import inspect

import pytest

yaml = pytest.importorskip('yaml')

from simulation import topology as topo_mod  # noqa: E402

BASELINE_CONFIG = 'base_model/config/params_base_full.yaml'

#: (name, required parameters) for every private helper run_base.py imports.
REQUIRED_HELPERS = (
    ('_add_cx_node', ('net', 'core_switch')),
    ('_launch_trust_agents', ('net', 'cfg')),
    ('_publish_link_table', ('cfg', 'topo')),
    ('_sampled_reachability_check', ('net', 'cfg')),
    ('_stop_trust_agents', ('net', 'cfg')),
)


@pytest.mark.parametrize('name,params', REQUIRED_HELPERS)
def test_helper_exists_with_the_expected_signature(name, params):
    fn = getattr(topo_mod, name, None)
    assert fn is not None, (
        f'simulation.topology.{name} is gone. base_model/run_base.py imports it '
        f'so both arms share one launcher -- update run_base.py, do not copy '
        f'the function into base_model/'
    )
    assert tuple(inspect.signature(fn).parameters) == params


def test_run_base_imports_the_launcher_rather_than_defining_one():
    from base_model import run_base
    src = inspect.getsource(run_base)
    assert '_launch_trust_agents' in src
    # The launch INVOCATION, not the bare module name -- run_base.py's own
    # docstring names both agents when explaining why it does not launch them.
    for invocation in ('-m simulation.node_agent', '-m simulation.iot_client'):
        assert invocation not in src, (
            f'run_base.py builds {invocation!r} itself -- that is a second '
            f'launcher, and the two arms would drift'
        )


def test_baseline_topology_uses_the_shared_topo_class():
    from base_model import run_base
    src = inspect.getsource(run_base.run_baseline_topology)
    assert 'ZeroTrustTopo' in src, (
        'the baseline must build the SAME topology class as the treatment arm; '
        'a second topology would confound shape with policy'
    )


class _FakeHost:
    def __init__(self, name):
        self.name = name
        self.commands = []

    def cmd(self, command):
        self.commands.append(command)
        return ''


class _FakeNet:
    def __init__(self):
        self.hosts = {}

    def get(self, name):
        return self.hosts.setdefault(name, _FakeHost(name))


def test_the_launcher_arms_the_same_attackers_from_the_baseline_config(tmp_path, monkeypatch):
    """Drive the real launcher with the baseline config and read the argv.

    This is the test that actually proves the arms run the same workload: the
    same function, given the baseline config, must produce the attack schedule
    the treatment config also specifies (`test_base_config_parity.py` proves
    the two configs agree; this proves the launcher consumes it).
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / 'logs').mkdir(exist_ok=True)
    with open(_repo_path(BASELINE_CONFIG)) as f:
        cfg = yaml.safe_load(f)

    net = _FakeNet()
    topo_mod._launch_trust_agents(net, cfg)

    joined = {name: ' '.join(h.commands) for name, h in net.hosts.items()}

    # Four server-side attacks, each with its configured onset.
    assert '--malicious sybil --malicious-start-s 20.0' in joined['srv3']
    assert '--malicious drop --malicious-start-s 30.0' in joined['srv6']
    assert '--malicious grayhole --malicious-start-s 40.0' in joined['srv1']
    assert '--grayhole-drop-rate 0.5' in joined['srv1']
    assert '--malicious onoff --malicious-start-s 50.0' in joined['srv8']
    assert '--onoff-period-s 20.0 --onoff-duty 0.5' in joined['srv8']

    # Honest servers are launched with no attack at all.
    for name in ('srv2', 'srv4', 'srv5', 'srv7'):
        assert '--malicious none' in joined[name]

    # Two device-side attacks.
    assert '--malicious flood' in joined['iot37']
    assert '--flood-concurrency 3' in joined['iot37']
    assert '--malicious spoof' in joined['iot38']
    assert '--spoof-target-device-id iot1' in joined['iot38']

    # ...and the two wrong-key devices. The key handed out must be the fleet
    # key with every byte flipped, exactly as the treatment arm hands it out --
    # the baseline differs in ADMITTING them, never in what they hold.
    good = cfg['security']['shared_key_hex']
    wrong = bytes(b ^ 0xFF for b in bytes.fromhex(good)).hex()
    for name in ('iot39', 'iot40'):
        assert f'--auth-key-hex {wrong}' in joined[name]
    assert f'--auth-key-hex {good}' in joined['iot1']
    # The spoofer holds the REAL key -- that is what makes it an insider rather
    # than a device that never had credentials.
    assert f'--auth-key-hex {good}' in joined['iot38']

    # Workload intensity reaches the agents from the baseline config.
    assert '--work-ms 15' in joined['srv1']
    assert '--interval-s 2.0' in joined['iot1']
    assert '--timeout-s 4.0' in joined['iot1']


def _repo_path(relative: str) -> str:
    from pathlib import Path
    return str(Path(__file__).resolve().parents[2] / relative)
