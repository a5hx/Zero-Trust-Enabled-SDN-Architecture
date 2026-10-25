"""The switch as a third witness: who is lying -- server, switch or client?

Novelty plan, Phase 2b. Until now the controller had two accounts of every
task: the server's self-report and the client's report. Each OpenFlow switch
keeps a third, independent one for free: the packet and byte counters on the
connection's two VIP rules (installed on the client's ingress switch). The
offline study (docs/WITNESS_OFFLINE.md) showed that account is precise: an
honest task is 6 packets / 548 bytes in and 6 packets / 598 bytes back, and
the connections the switches saw served match the clients' reported successes
to a median of 0.9992 per honest server-run.

Per connection, keyed by (client IP, client source port) -- exactly what a
client's /report carries -- the witness joins the switch's verdict with the
client's:

    client says  switch says   pattern            points at
    failed       no response   AGREE_FAILED       the server (both agree it dropped)
    succeeded    served        AGREE_SERVED       nobody
    failed       served        CLIENT_FAIL_SERVED a lying client, or a switch covering a dropper
    succeeded    no response   CLIENT_OK_UNSERVED a lying switch hiding responses

Attribution takes the smallest explanation, in scope order:

1. Switches first. A client only ever uses its own ingress switch, so a lying
   switch and the clients behind it produce the same pattern. If at least
   `switch_majority` of the clients seen behind a switch disagree with it,
   the switch is blamed and those clients are not. (All clients of one switch
   colluding is indistinguishable from the switch lying -- a stated limit.)
2. Then clients: a client whose disagreement rate is high, behind a switch
   that is not blamed.
3. Then servers: corroborated failures (client AND switch agree it failed) on
   connections whose client and switch are both unblamed.

Connections the controller re-steered are never judged: their timeouts are
the controller's doing (paper §VIII-A), and the switch counters of the
quarantined node's rules are deleted with them.

This module is pure bookkeeping -- no OpenFlow, no I/O -- so it is tested on
its own. `TrustBalancerApp` feeds it flow-stats replies and client reports and
publishes its verdicts as `witness` events. It is OBSERVE-ONLY: nothing it
says quarantines anyone, until its false-positive rate has been measured.
"""

from __future__ import annotations

import re
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, Iterable, List, Optional, Set, Tuple

AGREE_SERVED = 'agree_served'
AGREE_FAILED = 'agree_failed'
CLIENT_FAIL_SERVED = 'client_fail_served'
CLIENT_OK_UNSERVED = 'client_ok_unserved'
UNSEEN = 'unseen'

_MATCH_KV = re.compile(r'(\w+)=([^,]+)')


@dataclass
class _Conn:
    node: Optional[str] = None
    by_dpid: Dict[int, Tuple[int, int]] = field(default_factory=dict)   # dpid -> (fwd_bytes, rev_bytes)
    first_seen: float = 0.0
    report: Optional[Tuple[float, str, str, str]] = None              # (t, node, device, status)

    def ingress(self) -> Optional[int]:
        """The switch the client actually used: the one whose forward rule
        carried bytes (re-steers install the pair on every switch)."""
        best = max(self.by_dpid.items(), key=lambda kv: kv[1][0], default=None)
        return best[0] if best and best[1][0] > 0 else None


@dataclass(frozen=True)
class Judged:
    t: float
    node: str
    dpid: Optional[int]
    device: str
    client_ip: str
    pattern: str


@dataclass(frozen=True)
class WitnessConfig:
    served_min_bytes: int = 400       # a full response; an honest one is 598
    settle_s: float = 2.0             # wait this long after the report for the next poll
    give_up_s: float = 20.0           # a reported connection never seen by a switch
    window_s: float = 60.0
    min_judged: int = 10              # per party, within the window
    threshold: float = 0.20           # disagreement rate that marks a party
    switch_majority: float = 0.5      # share of a switch's clients that must disagree
    # Fix 1 (2026-10-21): judge each party on its MOST RECENT connections, not
    # on everything in the window. With a 60 s window a dropping server's
    # pre-attack successes diluted its failures for ~50 s (blamed at a median
    # 54-61 s after onset, and once never, while the gate quarantined it in
    # ~10 s and so starved the witness of new failures). The timeout tell
    # already works on the last 10 outcomes for the same reason.
    recent_party: int = 20            # servers and switches
    recent_client: int = 10           # a client sends ~1 task per 2 s
    # Fix 2 (2026-10-21): blame a client on its own only if the OTHER clients
    # behind its switch look clean (mean rate < mates_clean x threshold).
    # While a lying switch's lie ramps up, its clients cross the threshold one
    # by one; the first one or two used to be blamed for 1-4 s before the
    # switch-majority rule caught up (3 of 5 hide runs).
    mates_clean: float = 0.5

    @classmethod
    def from_config(cls, ctrl_cfg: Dict[str, Any]) -> 'WitnessConfig':
        b = (ctrl_cfg or {}).get('witness') or {}
        return cls(**{k: type(getattr(cls, k))(b[k]) for k in cls.__dataclass_fields__ if k in b})


class SwitchWitness:
    def __init__(self, vip_ip: str, cfg: Optional[WitnessConfig] = None) -> None:
        self.vip_ip = vip_ip
        self.cfg = cfg or WitnessConfig()
        self._conns: Dict[Tuple[str, str], _Conn] = {}
        self._judged: Deque[Judged] = deque()
        self.voided = 0
        self.unseen = 0
        # Flow-stats replies and client reports arrive on different threads.
        self._lock = threading.RLock()

    # -- thread-safe public surface ---------------------------------------- #
    def on_flow_stats(self, dpid: int, rules: Iterable[Dict[str, Any]], t: float) -> None:
        with self._lock:
            self._on_flow_stats(dpid, rules, t)

    def on_report(self, client_ip: str, client_port: int, node: str, device: str,
                  status: str, chargeable: bool, t: float) -> None:
        with self._lock:
            self._on_report(client_ip, client_port, node, device, status, chargeable, t)

    def tick(self, t: float) -> List['Judged']:
        with self._lock:
            return self._tick(t)

    def verdicts(self) -> Dict[str, Any]:
        with self._lock:
            return self._verdicts()

    # -- input --------------------------------------------------------------- #
    def _on_flow_stats(self, dpid: int, rules: Iterable[Dict[str, Any]], t: float) -> None:
        """`rules`: dicts with node, priority, match (k=v,... string or dict),
        bytes -- the shape controller/flow_stats.py publishes."""
        for r in rules:
            if r.get('priority') not in (300, 460) or not r.get('node'):
                continue
            m = r['match'] if isinstance(r['match'], dict) else dict(_MATCH_KV.findall(r['match']))
            if m.get('ipv4_dst') == self.vip_ip:
                key, fwd = (m.get('ipv4_src'), str(m.get('tcp_src'))), True
            else:
                key, fwd = (m.get('ipv4_dst'), str(m.get('tcp_dst'))), False
            if not key[0]:
                continue
            c = self._conns.get(key)
            if c is None:
                c = self._conns[key] = _Conn(node=r['node'], first_seen=t)
            f, b = c.by_dpid.get(dpid, (0, 0))
            nbytes = int(r.get('bytes', 0))
            c.by_dpid[dpid] = (max(f, nbytes), b) if fwd else (f, max(b, nbytes))

    def _on_report(self, client_ip: str, client_port: int, node: str, device: str,
                  status: str, chargeable: bool, t: float) -> None:
        key = (client_ip, str(client_port))
        if not chargeable:
            self._conns.pop(key, None)        # re-steered: the controller's doing
            self.voided += 1
            return
        c = self._conns.setdefault(key, _Conn(node=node, first_seen=t))
        c.node = node
        c.report = (t, node, device, status)

    # -- judging ------------------------------------------------------------- #
    def _tick(self, t: float) -> List[Judged]:
        """Judge every reported connection whose switch counters have had time
        to settle; expire connections no report ever came for."""
        out = []
        for key in list(self._conns):
            c = self._conns[key]
            if c.report is None:
                if t - c.first_seen > 3 * self.cfg.give_up_s:
                    del self._conns[key]
                continue
            rt, node, device, status = c.report
            if t - rt < self.cfg.settle_s:
                continue
            dpid = c.ingress()
            if dpid is None:
                if t - rt < self.cfg.give_up_s:
                    continue
                self.unseen += 1
                pattern = UNSEEN
            else:
                served = c.by_dpid[dpid][1] >= self.cfg.served_min_bytes
                ok = status == 'success'
                pattern = (AGREE_SERVED if ok and served else
                           AGREE_FAILED if not ok and not served else
                           CLIENT_FAIL_SERVED if served else CLIENT_OK_UNSERVED)
            j = Judged(t, node, dpid, device, key[0], pattern)
            self._judged.append(j)
            out.append(j)
            del self._conns[key]
        while self._judged and self._judged[0].t < t - self.cfg.window_s:
            self._judged.popleft()
        return out

    def _verdicts(self) -> Dict[str, Any]:
        """Who the current window's disagreements point at, smallest
        explanation first. Rates are over judged connections in the window."""
        cfg = self.cfg
        judged = [j for j in self._judged if j.pattern != UNSEEN]
        disagree = (CLIENT_FAIL_SERVED, CLIENT_OK_UNSERVED)

        def rate(items: List[Judged], patterns: Tuple[str, ...],
                 recent: int = 0) -> Optional[float]:
            if recent:
                items = items[-recent:]          # the deque is in time order
            if len(items) < min(cfg.min_judged, recent or cfg.min_judged):
                return None
            return sum(1 for j in items if j.pattern in patterns) / len(items)

        by_device: Dict[str, List[Judged]] = {}
        by_dpid: Dict[int, List[Judged]] = {}
        for j in judged:
            by_device.setdefault(j.device, []).append(j)
            if j.dpid is not None:
                by_dpid.setdefault(j.dpid, []).append(j)

        client_rate = {d: rate(js, disagree, cfg.recent_client) for d, js in by_device.items()}
        disputing = {d for d, r in client_rate.items() if r is not None and r >= cfg.threshold}

        switches: Set[int] = set()
        switch_rate: Dict[int, Optional[float]] = {}
        devices_on: Dict[int, Set[str]] = {}
        for dpid, js in by_dpid.items():
            devices = {j.device for j in js}
            devices_on[dpid] = devices
            switch_rate[dpid] = rate(js, disagree, cfg.recent_party)
            if devices and len(devices & disputing) / len(devices) > cfg.switch_majority:
                switches.add(dpid)

        def home(d: str) -> Optional[int]:
            dp = [j.dpid for j in by_device[d] if j.dpid is not None]
            return max(set(dp), key=dp.count) if dp else None

        def mates_clean(d: str) -> bool:
            k = home(d)
            rates = [client_rate[m] for m in devices_on.get(k, set())
                     if m != d and client_rate.get(m) is not None]
            return not rates or sum(rates) / len(rates) < cfg.mates_clean * cfg.threshold

        clients = {d for d in disputing
                   if home(d) not in switches and mates_clean(d)}

        clean = [j for j in judged if j.dpid not in switches and j.device not in clients]
        by_node: Dict[str, List[Judged]] = {}
        for j in clean:
            by_node.setdefault(j.node, []).append(j)
        server_rate = {n: rate(js, (AGREE_FAILED,), cfg.recent_party) for n, js in by_node.items()}
        servers = {n for n, r in server_rate.items() if r is not None and r >= cfg.threshold}

        def rounded(d):
            return {str(k): round(v, 4) for k, v in d.items() if v is not None}

        return {
            'servers': sorted(servers), 'switches': sorted(switches), 'clients': sorted(clients),
            'server_rate': rounded(server_rate), 'switch_rate': rounded(switch_rate),
            'client_rate': rounded(client_rate),
            'judged': len(judged), 'voided': self.voided, 'unseen': self.unseen,
        }


# --------------------------------------------------------------------------- #
# Emulated misreporting switch (Phase 2c). OVS cannot be made to lie without
# patching it, so the lie is injected where the controller receives the
# switch's statistics -- which is exactly the point an adversary controlling
# the switch's OpenFlow agent would occupy. Modes after Burke et al.:
#   hide   -- report no response bytes on every VIP reverse rule: frames every
#             server reached through this switch as a dropper;
#   cover  -- report a full response on `node`'s reverse rules: covers for a
#             dropping server (collusion).

@dataclass(frozen=True)
class SwitchLie:
    dpid: int
    mode: str
    start_s: float = 0.0
    node: Optional[str] = None


def parse_switch_lies(cfg: Dict[str, Any]) -> List[SwitchLie]:
    out = []
    for i, e in enumerate((cfg.get('simulation') or {}).get('malicious_switches') or []):
        mode = str(e.get('mode'))
        if mode not in ('hide', 'cover'):
            raise ValueError(f'simulation.malicious_switches[{i}].mode must be hide or cover')
        if mode == 'cover' and not e.get('node'):
            raise ValueError(f'simulation.malicious_switches[{i}]: cover needs a node')
        out.append(SwitchLie(int(e['dpid']), mode, float(e.get('start_s', 0.0)), e.get('node')))
    return out


def falsify(stats: Iterable[Any], lie: SwitchLie, vip_ip: str,
            node_of_cookie, served_bytes: int = 598, served_packets: int = 6) -> None:
    """Rewrite an os-ken OFPFlowStats list in place, as the lying switch would
    report it. Only VIP reverse rules (task traffic back to a client) change."""
    for st in stats:
        if getattr(st, 'priority', None) not in (300, 460):
            continue
        try:
            items = dict(st.match.items())
        except (AttributeError, TypeError):
            continue
        if items.get('ipv4_dst') == vip_ip or 'ipv4_src' not in items:
            continue                           # a forward rule, or not a VIP pair
        node = node_of_cookie(getattr(st, 'cookie', 0))
        if node is None:
            continue
        if lie.mode == 'hide':
            st.byte_count, st.packet_count = 0, 0
        elif lie.mode == 'cover' and node == lie.node and getattr(st, 'packet_count', 0) >= 0:
            st.byte_count = max(st.byte_count, served_bytes)
            st.packet_count = max(st.packet_count, served_packets)
