"""Emulated hardware classes and thermal throttling, with cgroup v2 cpu.max.

Novelty plan, Phase 3 ("honest-slow versus lying"). A real edge fleet is
mixed: Pi 4s next to Pi 5s, a box throttling in a hot cabinet. An honest
server that is slow looks, to the latency tell, like a liar that is slow --
"claims idle, answers slowly" (controller/flow_monitor.py). Before any
hardware is bought this module lets the Mininet harness produce honest
slowness on purpose, so the false-quarantine rate can be measured.

Why cgroups and not a work multiplier. A multiplier inside the agent would
slow its tasks but not its /status replies, and the latency tell reads the
/status round trip. A CPU cap slows the whole process, the way frequency
scaling slows a real machine. Mininet's own CPULimitedHost cannot be used on
this host: it assumes the cgroup v1 layout (`cgcreate`, `tasks` files) and
WSL2 here is cgroup v2 only (docs/FEASIBILITY.md). Mininet hosts share the
root PID namespace, so the harness, already root, places each agent directly.

Mechanism. Every server with a profile or a scheduled throttle gets its own
group `/sys/fs/cgroup/ztsdn/<srvN>`. Agents are launched exactly as always;
the harness, root in the ROOT mount namespace, then finds each capped agent's
PID and writes it into the group (moving the whole process, all threads).
Joining from inside the Mininet host does not work: the first pilot
(2026-10-20) failed with "cannot create /sys/fs/cgroup/ztsdn/srv5/cgroup.procs:
Directory nonexistent", because a Mininet host's /sys is not the root's.
Hosts do share the root PID namespace, which is what makes attaching from
outside possible. The cost is ~2 s uncapped at start-up. `cpu.max` is
"QUOTA PERIOD" in microseconds; use a short period (10 ms) so a cap behaves
like a slower CPU rather than as 100 ms bursts of full speed.

Config (`simulation:` block). These are deliberately OUTSIDE
`malicious_edge_nodes`: every server here is honest, and the ground truth the
scorers read must say so.

    server_profiles:
      srv5: {class: slow, cpu_max: "5000 10000"}    # half a core
      srv1: {class: fast}                           # class only, uncapped
    honest_throttle:
      - {node: srv4, start_s: 120, duration_s: 60, cpu_max: "2500 10000"}

`class` also feeds the generated inventory, so `controller.latency_baseline:
class` can judge each server against its own hardware class in Mininet.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

CGROUP_ROOT = Path('/sys/fs/cgroup')
GROUP = 'ztsdn'
UNCAPPED = 'max 10000'
_CPU_MAX_RE = re.compile(r'^(max|\d+) \d+$')


class ProfileError(ValueError):
    pass


@dataclass(frozen=True)
class ServerProfile:
    node: str
    hw_class: str
    cpu_max: Optional[str] = None          # None = uncapped


@dataclass(frozen=True)
class Throttle:
    node: str
    start_s: float
    duration_s: float
    cpu_max: str


def _check_cpu_max(value: Any, where: str) -> str:
    v = str(value).strip()
    if not _CPU_MAX_RE.match(v):
        raise ProfileError(f'{where}: cpu_max must be "QUOTA PERIOD" in microseconds '
                           f'(or "max PERIOD"), not {value!r}')
    quota, period = v.split()
    if quota != 'max' and (int(quota) <= 0 or int(period) <= 0):
        raise ProfileError(f'{where}: cpu_max quota and period must be positive')
    return v


def _check_node(node: Any, n_edge: int, where: str) -> str:
    m = re.match(r'^srv(\d+)$', str(node))
    if not m or not 1 <= int(m.group(1)) <= n_edge:
        raise ProfileError(f'{where}: {node!r} is not one of srv1..srv{n_edge}')
    return str(node)


def parse_profiles(cfg: Dict[str, Any]) -> Dict[str, ServerProfile]:
    sim = cfg.get('simulation') or {}
    n_edge = int(sim.get('num_edge_nodes') or 0)
    out = {}
    for node, entry in (sim.get('server_profiles') or {}).items():
        where = f'simulation.server_profiles.{node}'
        node = _check_node(node, n_edge, where)
        entry = entry or {}
        cpu = entry.get('cpu_max')
        out[node] = ServerProfile(node, str(entry.get('class', 'default')),
                                  _check_cpu_max(cpu, where) if cpu is not None else None)
    return out


def parse_throttles(cfg: Dict[str, Any]) -> List[Throttle]:
    sim = cfg.get('simulation') or {}
    n_edge = int(sim.get('num_edge_nodes') or 0)
    malicious = {m.get('node') for m in sim.get('malicious_edge_nodes') or []}
    out = []
    for i, entry in enumerate(sim.get('honest_throttle') or []):
        where = f'simulation.honest_throttle[{i}]'
        node = _check_node(entry.get('node'), n_edge, where)
        if node in malicious:
            raise ProfileError(f'{where}: {node} is an attacker; honest_throttle is for honest '
                               f'servers, so the ground truth stays honest')
        start, dur = float(entry.get('start_s', 0.0)), float(entry.get('duration_s', 0.0))
        if start < 0 or dur <= 0:
            raise ProfileError(f'{where}: need start_s >= 0 and duration_s > 0')
        out.append(Throttle(node, start, dur, _check_cpu_max(entry.get('cpu_max'), where)))
    return out


def server_classes(cfg: Dict[str, Any]) -> Dict[str, str]:
    """srvN -> hardware class, for the generated (Mininet) inventory."""
    return {n: p.hw_class for n, p in parse_profiles(cfg).items()}


def capped_nodes(cfg: Dict[str, Any]) -> List[str]:
    """Servers that need their own cgroup: a cap, or a scheduled throttle."""
    nodes = {n for n, p in parse_profiles(cfg).items() if p.cpu_max}
    nodes |= {t.node for t in parse_throttles(cfg)}
    return sorted(nodes, key=lambda s: int(s[3:]))


def group_dir(node: str, root: Path = CGROUP_ROOT) -> Path:
    return root / GROUP / node


def agent_pids(node: str) -> List[int]:
    """PIDs of `node`'s agent, found from the root PID namespace."""
    import os
    import subprocess
    out = subprocess.run(['pgrep', '-f', f'simulation.node_agent --node-id {node} '],
                         capture_output=True, text=True).stdout.split()
    return [int(p) for p in out if int(p) != os.getpid()]


def attach(cfg: Dict[str, Any], root: Path = CGROUP_ROOT,
           find_pids: Callable[[str], List[int]] = agent_pids) -> Dict[str, List[int]]:
    """Move each capped server's agent into its group. Returns node -> PIDs
    moved; a node with none is left for unjoined() to report."""
    moved: Dict[str, List[int]] = {}
    for node in capped_nodes(cfg):
        pids = find_pids(node)
        for pid in pids:
            try:
                _write(group_dir(node, root) / 'cgroup.procs', str(pid))
            except OSError as exc:
                logger.error('%s: could not move pid %d into its cgroup: %s', node, pid, exc)
        moved[node] = pids
    return moved


def schedule(cfg: Dict[str, Any]) -> List[Tuple[float, str, str]]:
    """(t, node, cpu_max) events: each throttle's cap at its start, and the
    node's profile cap (or uncapped) restored at its end."""
    profiles = parse_profiles(cfg)
    events = []
    for t in parse_throttles(cfg):
        base = profiles.get(t.node)
        events.append((t.start_s, t.node, t.cpu_max))
        events.append((t.start_s + t.duration_s, t.node,
                       base.cpu_max if base and base.cpu_max else UNCAPPED))
    return sorted(events)


def _write(path: Path, text: str) -> None:
    path.write_text(text)


def setup(cfg: Dict[str, Any], root: Path = CGROUP_ROOT) -> List[str]:
    """Create the groups and set each node's initial cap. Raises ProfileError
    with the reason if the host cannot do it, before any agent is launched."""
    nodes = capped_nodes(cfg)
    if not nodes:
        return []
    controllers = (root / 'cgroup.controllers')
    if not controllers.exists() or 'cpu' not in controllers.read_text().split():
        raise ProfileError(f'no cgroup v2 cpu controller at {root} (see docs/FEASIBILITY.md)')
    try:
        if 'cpu' not in (root / 'cgroup.subtree_control').read_text().split():
            _write(root / 'cgroup.subtree_control', '+cpu')
        (root / GROUP).mkdir(exist_ok=True)
        _write(root / GROUP / 'cgroup.subtree_control', '+cpu')
        profiles = parse_profiles(cfg)
        for node in nodes:
            d = group_dir(node, root)
            d.mkdir(exist_ok=True)
            p = profiles.get(node)
            _write(d / 'cpu.max', p.cpu_max if p and p.cpu_max else UNCAPPED)
    except OSError as exc:
        raise ProfileError(f'cannot configure cgroups under {root}: {exc} (needs root)') from exc
    logger.info('cgroup CPU profiles ready for %s', ', '.join(nodes))
    return nodes


def unjoined(cfg: Dict[str, Any], root: Path = CGROUP_ROOT) -> List[str]:
    """Capped servers whose group holds no process -- their agent did not
    join, so it would run uncapped. The harness aborts on any: an uncapped
    run recorded as a capped one is worse than no run."""
    out = []
    for node in capped_nodes(cfg):
        try:
            procs = (group_dir(node, root) / 'cgroup.procs').read_text().split()
        except OSError:
            procs = []
        if not procs:
            out.append(node)
    return out


def apply(node: str, cpu_max: str, root: Path = CGROUP_ROOT) -> None:
    _write(group_dir(node, root) / 'cpu.max', cpu_max)
    logger.warning('%s: cpu.max -> %s', node, cpu_max)


def start_schedule(cfg: Dict[str, Any], stop: threading.Event, root: Path = CGROUP_ROOT,
                   clock: Callable[[], float] = time.monotonic) -> Optional[threading.Thread]:
    """Run the throttle schedule in a daemon thread, t = 0 being now (the
    agents' launch, the same reference as every attack's start_s)."""
    events = schedule(cfg)
    if not events:
        return None
    t0 = clock()

    def run() -> None:
        for t, node, cpu_max in events:
            if stop.wait(max(0.0, t0 + t - clock())):
                return
            try:
                apply(node, cpu_max, root)
            except OSError as exc:
                logger.error('%s: could not set cpu.max %s: %s', node, cpu_max, exc)

    th = threading.Thread(target=run, name='cpu-throttle-schedule', daemon=True)
    th.start()
    return th


def teardown(cfg: Dict[str, Any], root: Path = CGROUP_ROOT) -> None:
    """Remove the groups once their agents have exited. Best effort."""
    for node in capped_nodes(cfg):
        try:
            group_dir(node, root).rmdir()
        except OSError:
            pass
    try:
        (root / GROUP).rmdir()
    except OSError:
        pass
