#!/usr/bin/env python3
"""Run the control arm end to end.

    sudo -E python3 -m base_model.run_base --duration 300

Brings up `base_model/baseline_controller.py` as a subprocess, then the SAME
Mininet topology and the SAME agent/client processes the treatment arm uses,
for the configured duration, then tears both down and writes the reports.

WHY THIS FILE IMPORTS PRIVATE HELPERS FROM simulation/topology.py
----------------------------------------------------------------
It calls `_launch_trust_agents`, `_sampled_reachability_check`,
`_publish_link_table` and `_stop_trust_agents` — all underscore-prefixed, all
belonging to another module. That is a deliberate trade and the alternative is
worse.

`_launch_trust_agents` is the function that builds every `node_agent.py` and
`iot_client.py` command line: work-ms, report interval, task timeout, which
server is a sybil and when it arms, which device floods at what concurrency,
which device spoofs whom, and which two devices get the deliberately wrong key.
Copying it here would give the two arms two launchers, and the first time
someone tuned one the arms would be running different workloads while still
being reported as a controlled comparison. Reusing it makes that class of drift
impossible: **both arms are driven by the same launcher, byte for byte.**

The cost is a coupling to private names, which `base_model/tests/
test_launcher_parity.py` pins — it fails loudly if any of them is renamed or
its signature changes, rather than letting the import break at 3am mid-run.

WHAT DIFFERS FROM run_demo.py --mode mininet
--------------------------------------------
Exactly three things: the config file, the controller module launched, and the
NFR report's interpretation (two of the four NFRs are not applicable to an arm
that has no isolation path and no ledger — they are reported as N/A, never as
a pass or a zero).
"""

import argparse
import logging
import os
import pwd
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict

import yaml

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

logger = logging.getLogger('base_model.run_base')

DEFAULT_CONFIG = 'base_model/config/params_base_full.yaml'
CONTROLLER_MODULE = 'base_model.baseline_controller'
_CONTROLLER_START_TIMEOUT_S = 20.0


def _setup_logging() -> None:
    Path('logs').mkdir(exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(Path('logs') / 'base_demo.log', mode='w'),
        ],
    )


def _give_back_to_invoking_user(*paths: Path) -> None:
    """Hand root-owned artefacts back to whoever ran sudo.

    Mininet forces the whole run to be root, so the recording, the logs and the
    reports all land owned by root. The next non-sudo command in the project
    then trips over them -- including, in this project's history, the event
    bus itself failing to open its own recording on the following run.
    """
    sudo_user = os.environ.get('SUDO_USER')
    if not sudo_user or os.geteuid() != 0:
        return
    try:
        entry = pwd.getpwnam(sudo_user)
    except KeyError:
        return
    for path in paths:
        if not path.exists():
            continue
        try:
            os.chown(path, entry.pw_uid, entry.pw_gid)
            if path.is_dir():
                for child in path.rglob('*'):
                    os.chown(child, entry.pw_uid, entry.pw_gid)
        except OSError as exc:  # noqa: PERF203 -- never fatal to a finished run
            logger.warning("Could not chown %s back to %s: %s", path, sudo_user, exc)


def _wait_for_controller(api_host: str, api_port: int, timeout_s: float) -> bool:
    """Poll the baseline API until it answers.

    Controller first, Mininet second -- never the other way round. If the
    switches come up with no controller listening they sit in fail-secure mode
    with no flows at all, and the reachability check then times out on every
    pair while looking like a broken data plane. This is the same race
    documented in the treatment arm's runner and in SETUP.md.
    """
    host = '127.0.0.1' if api_host in ('0.0.0.0', '') else api_host
    url = f'http://{host}:{api_port}/health'
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(0.5)
    return False


def _load_config(path: str) -> Dict[str, Any]:
    with open(path) as f:
        return yaml.safe_load(f)


def run_baseline_topology(cfg: Dict[str, Any], interactive: bool = False) -> None:
    """Build the network, start the workload, wait it out, tear it down.

    Structurally identical to `simulation.topology.run_topology`'s trust-mode
    branch, and the ordering constraints it encodes are load-bearing here too:

      * agents BEFORE the reachability check. The controller starts polling
        /status the moment it has datapaths and an unanswered poll is
        indistinguishable from a dead node. In the treatment arm that
        mis-ordering quarantined all eight servers for 163 s while pingAll
        ran. This arm cannot quarantine anything -- but it would still record
        eight nodes' worth of anomalies against processes that did not exist
        yet, and those would land in the comparison as baseline false
        positives. Same fix, different failure.

      * `_pause_controller_monitor` (inside `_stop_trust_agents`) BEFORE the
        agents are killed, so the final recorded frame is not eight
        just-killed nodes read as a collapse.
    """
    from mininet.link import TCLink
    from mininet.net import Mininet
    from mininet.node import OVSSwitch, RemoteController

    from simulation.topology import (
        ZeroTrustTopo,
        _add_cx_node,
        _launch_trust_agents,
        _publish_link_table,
        _sampled_reachability_check,
        _stop_trust_agents,
    )

    topo = ZeroTrustTopo(cfg=cfg)
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653),
        switch=OVSSwitch,
        link=TCLink,
    )
    net.start()
    logger.info("Mininet network started (baseline arm)")

    try:
        _add_cx_node(net, net.get('s0'))
        _publish_link_table(cfg, topo)
        _launch_trust_agents(net, cfg)
        loss = _sampled_reachability_check(net, cfg)
        logger.info("Reachability sample loss: %s%%", loss)

        duration = cfg['simulation']['duration_s']
        logger.info(
            "Baseline arm running for %ds. Expect NO quarantine events: the "
            "attackers arm on schedule and nothing stops them.", duration,
        )
        if interactive:
            from mininet.cli import CLI
            CLI(net)
        else:
            time.sleep(duration)
    finally:
        _stop_trust_agents(net, cfg)
        net.stop()
        logger.info("Mininet network stopped")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description='Zero Trust SDN -- BASELINE (control) arm',
    )
    parser.add_argument('--config', default=DEFAULT_CONFIG)
    parser.add_argument(
        '--duration', type=int, default=None,
        help='Override simulation.duration_s (seconds).',
    )
    parser.add_argument(
        '--strategy', default=None,
        choices=['static_nearest', 'round_robin', 'random'],
        help='Override baseline.strategy for this run.',
    )
    parser.add_argument(
        '--interactive', action='store_true',
        help='Drop into the Mininet CLI instead of sleeping out the duration.',
    )
    args = parser.parse_args(argv)

    _setup_logging()

    if os.geteuid() != 0:
        print("The baseline arm needs root -- Mininet creates real network")
        print("namespaces and veth pairs, which requires CAP_NET_ADMIN.")
        print()
        print("Re-run as:  sudo -E python3 -m base_model.run_base")
        print()
        print("First time this session (WSL2 does not auto-start these):")
        print("  sudo service openvswitch-switch start")
        print("  sudo modprobe -a sch_htb sch_netem sch_tbf sch_prio ifb")
        print("  sudo mn -c")
        return 1

    try:
        from simulation.topology import _MININET_AVAILABLE
    except ImportError:
        _MININET_AVAILABLE = False
    if not _MININET_AVAILABLE:
        print("Mininet is not installed. See SETUP.md.")
        return 1

    Path('data').mkdir(exist_ok=True)
    Path('logs').mkdir(exist_ok=True)

    cfg = _load_config(args.config)
    if args.duration is not None:
        cfg['simulation']['duration_s'] = args.duration

    # Strategy overrides are written into a scratch config rather than passed
    # as a flag, because the controller reads its config from a file and the
    # recording must be able to say which config produced it. A run whose
    # recorded config does not match the run is worse than no record at all.
    config_path = args.config
    if args.strategy:
        cfg.setdefault('baseline', {})['strategy'] = args.strategy
        config_path = str(Path('logs') / 'params_base_effective.yaml')
        Path(config_path).write_text(yaml.safe_dump(cfg, sort_keys=False))
        logger.info("Strategy overridden to %s; effective config at %s",
                    args.strategy, config_path)

    ctrl_cfg = cfg['controller']
    events_path = ctrl_cfg.get('dashboard', {}).get(
        'record_path', 'data/base_events.jsonl',
    )
    # A stale recording would be silently mixed into this run's reports.
    Path(events_path).unlink(missing_ok=True)

    env = dict(os.environ)
    env['ZTSDN_BASE_CONFIG'] = config_path
    logger.info("Starting the BASELINE controller (config=%s)...", config_path)
    controller_log = open(Path('logs') / 'base_controller.log', 'w')
    controller_proc = subprocess.Popen(
        [sys.executable, '-m', 'controller.osken_manager', CONTROLLER_MODULE],
        env=env, stdout=controller_log, stderr=subprocess.STDOUT,
    )

    try:
        if not _wait_for_controller(
            ctrl_cfg['api_host'], ctrl_cfg['api_port'], _CONTROLLER_START_TIMEOUT_S,
        ):
            print(f"Baseline controller did not come up within "
                  f"{_CONTROLLER_START_TIMEOUT_S:.0f}s -- see logs/base_controller.log")
            return 1
        logger.info(
            "Controller up. Launching the %d-edge/%d-IoT topology for %ds...",
            cfg['simulation']['num_edge_nodes'],
            cfg['simulation']['num_iot_devices'],
            cfg['simulation']['duration_s'],
        )
        run_baseline_topology(cfg, interactive=args.interactive)
    except KeyboardInterrupt:
        logger.warning("Interrupted -- tearing down early.")
    finally:
        controller_proc.terminate()
        try:
            controller_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            controller_proc.kill()
            controller_proc.wait()
        controller_log.close()
        _give_back_to_invoking_user(Path(events_path), Path('logs'), Path('data'))

    if not Path(events_path).exists():
        print(f"No events recorded at {events_path} -- check "
              f"logs/base_controller.log and logs/srvN_agent.log.")
        return 1

    print()
    print(f"Baseline run complete. Recording: {events_path}")
    print()
    print("Next:")
    print(f"  python3 -m base_model.compare --baseline {events_path} \\")
    print("      --treatment data/events.jsonl")
    print(f"  python3 -m evaluation.interval_report --events {events_path}")
    print(f"  python3 -m evaluation.availability_report --events {events_path}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
