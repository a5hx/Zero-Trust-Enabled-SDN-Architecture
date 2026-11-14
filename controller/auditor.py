"""The auditor: a second controller that watches the switches and cannot act.

First step to multi-controller (plan for the 16 Nov review). The primary
controller decides and enforces; the auditor connects to the SAME switches as
an OpenFlow SLAVE -- read-only by the protocol, not by our promise -- and
judges every edge server from the switches' own counters alone:

    a connection whose forward rule carried request bytes and whose reverse
    rule never carried a full response (>= 400 B; an honest one is 598 B)
    was not served.

That is the switch-only half of the Phase 2 witness ("no full response",
docs/WITNESS_OFFLINE.md: it separates droppers cleanly). It needs no client
report and nothing the primary says, which is the point: a primary that
forges trust evidence (controller/forgery.py, Phase 6) can keep a dropping
server looking healthy on its own dashboard, but it cannot make the switches
count response bytes that were never sent.

What the auditor trusts and what it does not
---------------------------------------------
* The server behind a connection is read off the forward rule's own
  set_field ipv4_dst/eth_dst -- the rewrite the switch actually applies --
  mapped through the inventory. Never the cookie: the cookie is the primary's
  label for its rule, and a lying primary could label anything.
* A forward rewrite whose ip and mac name different servers is counted as a
  `rewrite_mismatch` and not judged.
* A connection whose server changes (the primary re-steered it) is voided,
  as the witness voids re-steered connections: its loss is the primary's
  doing, not the server's.
* A connection whose rules vanish before it can be judged (deleted by a
  quarantine) is voided too -- unjudgeable, not a failure.

What it cannot do
-----------------
It sends OFPRoleRequest(SLAVE) to each switch on connect and reads flow
statistics only from switches that have CONFIRMED the slave role; a slave's
FlowMod, PacketOut, GroupMod or MeterMod is refused by the switch with
OFPET_BAD_REQUEST/IS_SLAVE. It never builds one anyway (pinned by
tests/test_auditor.py with an AST scan of this module), and every PacketIn
that reaches it is counted and dropped. Takeover is the next milestone.

Run (the primary is unaffected; OVS connects to both):
    ZTSDN_CONFIG=config/params_review_demo.yaml \\
        python3 -m controller.osken_manager --ofp-port 6654 controller.auditor
and set controller.auditor.address in the config, so simulation/topology.py
gives every switch the second controller.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

SERVED = 'served'
UNANSWERED = 'unanswered'
PARTIAL = 'partial'

VERDICT_SERVING = 'serving'
VERDICT_DROPPING = 'dropping'
VERDICT_INSUFFICIENT = 'insufficient'
VERDICT_IDLE = 'no recent traffic'


@dataclass(frozen=True)
class AuditConfig:
    served_min_bytes: int = 400     # a full response (honest: 598 B)
    judge_after_s: float = 6.0      # task_timeout_s (4 s) + margin: no response by now = none
    forget_after_s: float = 3.0     # rules absent this long are gone (polled every 1 s)
    recent: int = 20                # judge each server on its most recent connections
    min_judged: int = 8
    threshold: float = 0.25         # unanswered+partial share that marks a dropper
    stale_s: float = 60.0           # no judged connection for this long: idle

    @classmethod
    def from_config(cls, block: Optional[Dict[str, Any]]) -> 'AuditConfig':
        b = block or {}
        return cls(**{k: type(getattr(cls, k))(b[k]) for k in cls.__dataclass_fields__ if k in b})


@dataclass
class _Conn:
    node: str
    first_seen: float
    last_seen: float
    fwd: int = 0
    rev: int = 0
    first_fwd: Optional[float] = None
    judged: bool = False


@dataclass(frozen=True)
class Judgement:
    t: float
    node: str
    client_ip: str
    client_port: str
    outcome: str


@dataclass
class _NodeTally:
    recent: Deque[Judgement] = field(default_factory=deque)
    totals: Dict[str, int] = field(default_factory=lambda: {SERVED: 0, UNANSWERED: 0, PARTIAL: 0})
    last_t: Optional[float] = None


class SwitchAudit:
    """Per-connection bookkeeping over flow-stats replies. No OpenFlow, no I/O.

    `observe()` takes one switch's rules as plain dicts:
        {'priority', 'match': {field: value}, 'set_fields': {field: value},
         'bytes'}
    -- `set_fields` being the SetField actions the rule applies.
    """

    def __init__(self, servers: Dict[str, Tuple[str, str]], vip_ip: str, vip_port: int,
                 node_port: int, cfg: AuditConfig = AuditConfig()) -> None:
        self.cfg = cfg
        self.vip_ip = vip_ip
        self.vip_port = int(vip_port)
        self.node_port = int(node_port)
        self.servers = dict(servers)
        self._by_ip = {ip: node for node, (ip, _mac) in servers.items()}
        self._by_mac = {mac.lower(): node for node, (_ip, mac) in servers.items()}
        self._conns: Dict[Tuple[str, str], _Conn] = {}
        self._tally: Dict[str, _NodeTally] = {n: _NodeTally() for n in servers}
        self.voided = 0
        self.rewrite_mismatch = 0
        self.judged = 0
        self._lock = threading.Lock()

    # -- input --------------------------------------------------------------- #
    def classify(self, rule: Dict[str, Any]) -> Optional[Tuple[str, Tuple[str, str], str]]:
        """('fwd'|'rev', (client_ip, client_port), node) for a VIP rewrite
        rule, None for anything else (L2, ARP, drops, trial passages)."""
        m, sf = rule.get('match') or {}, rule.get('set_fields') or {}
        if m.get('ipv4_dst') == self.vip_ip and int(m.get('tcp_dst', -1)) == self.vip_port:
            node = self._by_ip.get(sf.get('ipv4_dst'))
            if node is None:
                return None
            mac_node = self._by_mac.get(str(sf.get('eth_dst', '')).lower())
            if mac_node is not None and mac_node != node:
                return ('mismatch', (str(m.get('ipv4_src')), str(m.get('tcp_src'))), node)
            return ('fwd', (str(m.get('ipv4_src')), str(m.get('tcp_src'))), node)
        # The reverse rule un-rewrites the reply to look like the VIP. A trial
        # passage matches the same 5-tuple but rewrites nothing, so the
        # set_field is what tells them apart.
        if sf.get('ipv4_src') == self.vip_ip and m.get('ipv4_src') in self._by_ip:
            return ('rev', (str(m.get('ipv4_dst')), str(m.get('tcp_dst'))),
                    self._by_ip[m['ipv4_src']])
        return None

    def observe(self, dpid: int, rules: Iterable[Dict[str, Any]], now: float) -> None:
        with self._lock:
            seen_mismatch = set()
            for r in rules:
                kind = self.classify(r)
                if kind is None:
                    continue
                direction, key, node = kind
                if direction == 'mismatch':
                    if key not in seen_mismatch:
                        seen_mismatch.add(key)
                        self.rewrite_mismatch += 1
                    continue
                c = self._conns.get(key)
                if c is not None and c.node != node and not c.judged:
                    # Re-steered by the primary: void, start over on the new server.
                    self.voided += 1
                    c = None
                if c is None or (c.judged and c.node != node):
                    c = self._conns[key] = _Conn(node=node, first_seen=now, last_seen=now)
                c.last_seen = now
                if c.judged:
                    continue
                nbytes = int(r.get('bytes', 0))
                if direction == 'fwd':
                    if nbytes > c.fwd:
                        c.fwd = nbytes
                        if c.first_fwd is None:
                            c.first_fwd = now
                else:
                    c.rev = max(c.rev, nbytes)

    # -- judging ------------------------------------------------------------- #
    def tick(self, now: float) -> List[Judgement]:
        out: List[Judgement] = []
        cfg = self.cfg
        with self._lock:
            for key, c in list(self._conns.items()):
                gone = now - c.last_seen > cfg.forget_after_s
                if c.judged:
                    if gone:
                        del self._conns[key]
                    continue
                outcome = None
                if c.rev >= cfg.served_min_bytes:
                    outcome = SERVED
                elif c.first_fwd is not None and now - c.first_fwd >= cfg.judge_after_s:
                    outcome = UNANSWERED if c.rev == 0 else PARTIAL
                elif gone:
                    if c.first_fwd is not None:
                        self.voided += 1       # deleted before it could be judged
                    del self._conns[key]
                    continue
                if outcome is None:
                    continue
                c.judged = True
                j = Judgement(t=now, node=c.node, client_ip=key[0], client_port=key[1],
                              outcome=outcome)
                tally = self._tally.setdefault(c.node, _NodeTally())
                tally.recent.append(j)
                while len(tally.recent) > cfg.recent:
                    tally.recent.popleft()
                tally.totals[outcome] += 1
                tally.last_t = now
                self.judged += 1
                out.append(j)
        return out

    def verdicts(self, now: float) -> Dict[str, Any]:
        cfg = self.cfg
        nodes: Dict[str, Any] = {}
        flagged: List[str] = []
        with self._lock:
            for node in sorted(self._tally, key=lambda n: (len(n), n)):
                t = self._tally[node]
                n = len(t.recent)
                bad = sum(1 for j in t.recent if j.outcome != SERVED)
                rate = round(bad / n, 4) if n else None
                if t.last_t is None or now - t.last_t > cfg.stale_s:
                    verdict = VERDICT_IDLE
                elif n < cfg.min_judged:
                    verdict = VERDICT_INSUFFICIENT
                elif rate is not None and rate >= cfg.threshold:
                    verdict = VERDICT_DROPPING
                else:
                    verdict = VERDICT_SERVING
                if verdict == VERDICT_DROPPING:
                    flagged.append(node)
                nodes[node] = {
                    'verdict': verdict, 'rate': rate, 'window': n,
                    'served': t.totals[SERVED], 'unanswered': t.totals[UNANSWERED],
                    'partial': t.totals[PARTIAL],
                    'last_judged_s_ago': None if t.last_t is None else round(now - t.last_t, 1),
                }
            return {
                'nodes': nodes, 'dropping': flagged, 'judged': self.judged,
                'voided': self.voided, 'rewrite_mismatch': self.rewrite_mismatch,
                'open_connections': sum(1 for c in self._conns.values() if not c.judged),
                'threshold': cfg.threshold, 'min_judged': cfg.min_judged,
            }


def rules_from_stats(body: Iterable[Any]) -> List[Dict[str, Any]]:
    """OFPFlowStats entries -> the dicts SwitchAudit.observe() takes."""
    out = []
    for stat in body:
        try:
            match = dict(stat.match.items())
        except (AttributeError, TypeError):
            match = {}
        set_fields: Dict[str, Any] = {}
        for inst in getattr(stat, 'instructions', None) or []:
            for a in getattr(inst, 'actions', None) or []:
                key = getattr(a, 'key', None)
                if key is not None and hasattr(a, 'value'):
                    set_fields[key] = a.value
        out.append({'priority': stat.priority, 'match': match, 'set_fields': set_fields,
                    'bytes': stat.byte_count, 'packets': stat.packet_count})
    return out


# --------------------------------------------------------------------------- #
# The os-ken application                                                       #
# --------------------------------------------------------------------------- #
try:                                     # the bookkeeping above needs no os-ken
    from os_ken.base import app_manager
    from os_ken.controller import ofp_event
    from os_ken.controller.handler import (CONFIG_DISPATCHER, DEAD_DISPATCHER,
                                           MAIN_DISPATCHER, set_ev_cls)
    from os_ken.lib import hub
    from os_ken.ofproto import ofproto_v1_3
    _OSKEN = True
except ImportError:                      # pragma: no cover - env dependent
    _OSKEN = False

ROLE_PENDING = 'pending'
ROLE_SLAVE = 'slave'
ROLE_REFUSED = 'refused'


def _load_config() -> Dict[str, Any]:
    import yaml
    path = os.environ.get('ZTSDN_CONFIG', 'config/params_review_demo.yaml')
    with open(path) as fh:
        return yaml.safe_load(fh)


def auditor_block(cfg: Dict[str, Any]) -> Dict[str, Any]:
    return dict((cfg.get('controller') or {}).get('auditor') or {})


def _generation_reader(cfg: Dict[str, Any]) -> Any:
    """A RemoteRaftBackend used only to read the controller generation (it
    never commits). Fencing needs ledger.backend: raft_remote."""
    from blockchain.commit_backend import RemoteRaftBackend, parse_replicas
    ledger = cfg.get('ledger') or {}
    if ledger.get('backend') != 'raft_remote':
        raise ValueError('controller.fencing needs ledger.backend: raft_remote')
    token_env = ledger.get('auth_token_env')
    token = os.environ.get(token_env) or None if token_env else None
    return RemoteRaftBackend(parse_replicas(ledger['replicas']), auth_token=token,
                             request_timeout_s=float(ledger.get('request_timeout_s', 3.0)),
                             deadline_s=float(ledger.get('commit_deadline_s', 5.0)))


if _OSKEN:
    class AuditorApp(app_manager.OSKenApp):
        """Read-only second controller. See the module docstring."""

        OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            from contracts.inventory import Inventory
            from controller.event_bus import EventBus

            self.cfg = _load_config()
            ctrl = self.cfg.get('controller') or {}
            block = auditor_block(self.cfg)
            inv = Inventory.from_config(self.cfg)
            self.audit = SwitchAudit(
                servers=inv.servers, vip_ip=ctrl.get('vip', '10.0.99.1'),
                vip_port=int(ctrl.get('vip_port', 9000)),
                node_port=int((self.cfg.get('agents') or {}).get('node_port', 8000)),
                cfg=AuditConfig.from_config(block),
            )
            self.poll_interval_s = float(block.get('poll_interval_s', 1.0))
            self.bus = EventBus(record_path=block.get('record_path', 'data/events_auditor.jsonl'))
            self._datapaths: Dict[int, Any] = {}
            self.roles: Dict[int, str] = {}
            self.packet_ins_ignored = 0
            self.replies_before_slave = 0
            self.polls = 0
            self.started = time.time()
            self._last_flagged: Optional[Tuple[str, ...]] = None
            # With controller.fencing on, a switch refuses a SLAVE request
            # whose generation_id is older than the primary's MASTER claim
            # (OFPRRFC_STALE), so the auditor asks under the cluster's
            # current generation, and asks again after a refusal.
            self._fencing = bool(((ctrl.get('fencing') or {}).get('enabled')))
            self._generation_reader = _generation_reader(self.cfg) if self._fencing else None
            self.generation = self._read_generation()
            self.bus.publish('auditor_start', requested_role='slave', vip=self.audit.vip_ip,
                             servers=sorted(self.audit.servers),
                             config={k: getattr(self.audit.cfg, k)
                                     for k in AuditConfig.__dataclass_fields__})
            hub.spawn(self._poll_loop)
            self._start_http(block.get('http_host', '0.0.0.0'),
                             int(block.get('http_port', 8083)))

        # -- switches ---------------------------------------------------------- #
        @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
        def _on_state(self, ev: Any) -> None:
            dp = ev.datapath
            if ev.state == MAIN_DISPATCHER:
                self._datapaths[dp.id] = dp
                self.roles[dp.id] = ROLE_PENDING
                self.request_slave(dp)
            elif ev.state == DEAD_DISPATCHER and dp.id is not None:
                self._datapaths.pop(dp.id, None)
                self.roles.pop(dp.id, None)

        def _read_generation(self) -> int:
            """The cluster's current controller generation, or the last one
            known (0 before any). Without fencing nothing is ever claimed and
            0 is always accepted."""
            if self._generation_reader is None:
                return getattr(self, 'generation', 0)
            state = self._generation_reader.current_generation()
            if state is None:
                logger.warning('auditor: ledger cluster unreachable; keeping generation %s',
                               getattr(self, 'generation', 0))
                return getattr(self, 'generation', 0)
            return int(state.get('generation', 0))

        def request_slave(self, dp: Any) -> None:
            """Ask to be read-only, under the current controller generation:
            a SLAVE request carries one too, and the switch refuses a stale
            one. This auditor never competes for MASTER."""
            ofp = dp.ofproto
            dp.send_msg(dp.ofproto_parser.OFPRoleRequest(dp, ofp.OFPCR_ROLE_SLAVE,
                                                         self.generation))

        @set_ev_cls(ofp_event.EventOFPRoleReply, MAIN_DISPATCHER)
        def _on_role_reply(self, ev: Any) -> None:
            dp, msg = ev.msg.datapath, ev.msg
            role = ROLE_SLAVE if msg.role == dp.ofproto.OFPCR_ROLE_SLAVE else f'role {msg.role}'
            self.roles[dp.id] = role
            logger.info('switch %s: auditor role confirmed: %s', dp.id, role)
            self.bus.publish('auditor_role', dpid=dp.id, role=role,
                             generation_id=msg.generation_id)

        @set_ev_cls(ofp_event.EventOFPErrorMsg, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
        def _on_error(self, ev: Any) -> None:
            dp, msg = ev.msg.datapath, ev.msg
            if msg.type == dp.ofproto.OFPET_ROLE_REQUEST_FAILED:
                self.roles[dp.id] = ROLE_REFUSED
                logger.warning('switch %s refused the SLAVE role (code %s)', dp.id, msg.code)
                self.bus.publish('auditor_role', dpid=dp.id, role=ROLE_REFUSED, code=msg.code)

        @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
        def _on_packet_in(self, ev: Any) -> None:
            # A slave is normally sent no PacketIns; any that arrive (before the
            # role is confirmed, or from a switch that refused it) are counted
            # and dropped. The auditor never decides anything.
            self.packet_ins_ignored += 1

        @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
        def _on_flow_stats(self, ev: Any) -> None:
            dp = ev.msg.datapath
            if self.roles.get(dp.id) != ROLE_SLAVE:
                self.replies_before_slave += 1
                return
            self.audit.observe(dp.id, rules_from_stats(ev.msg.body), time.monotonic())

        # -- loop -------------------------------------------------------------- #
        def _poll_loop(self) -> None:
            while True:
                hub.sleep(self.poll_interval_s)
                try:
                    self.poll_once()
                except Exception:
                    logger.exception('auditor poll failed')

        def poll_once(self) -> None:
            refused = [dp for dpid, dp in self._datapaths.items()
                       if self.roles.get(dpid) == ROLE_REFUSED]
            if refused and self._fencing:
                # Most likely stale: the primary claimed a newer generation
                # after we asked. Re-read it and ask again.
                self.generation = self._read_generation()
                for dp in refused:
                    self.roles[dp.id] = ROLE_PENDING
                    self.request_slave(dp)
            for dpid, dp in list(self._datapaths.items()):
                if self.roles.get(dpid) == ROLE_SLAVE:
                    dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(
                        datapath=dp, table_id=dp.ofproto.OFPTT_ALL))
            now = time.monotonic()
            self.audit.tick(now)
            self.polls += 1
            v = self.audit.verdicts(now)
            flagged = tuple(v['dropping'])
            if flagged != self._last_flagged or self.polls % 5 == 0:
                self.bus.publish('auditor_verdict', **v)
                if flagged != self._last_flagged and flagged:
                    logger.warning('auditor: switches show %s not serving', ', '.join(flagged))
                self._last_flagged = flagged

        def status(self) -> Dict[str, Any]:
            v = self.audit.verdicts(time.monotonic())
            return {
                'role': 'auditor (OpenFlow SLAVE, read-only)',
                'switches': {str(k): r for k, r in sorted(self.roles.items())},
                'switches_slave': sum(1 for r in self.roles.values() if r == ROLE_SLAVE),
                'packet_ins_ignored': self.packet_ins_ignored,
                'replies_before_slave': self.replies_before_slave,
                'polls': self.polls,
                'uptime_s': round(time.time() - self.started, 1),
                **v,
            }

        # -- status API ---------------------------------------------------------- #
        def _start_http(self, host: str, port: int) -> None:
            from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
            app = self

            class Handler(BaseHTTPRequestHandler):
                def log_message(self, *a: Any) -> None:     # quiet
                    pass

                def do_GET(self) -> None:
                    if self.path.split('?')[0] != '/auditor/status':
                        self._send(404, {'error': 'not found'})
                        return
                    self._send(200, app.status())

                def _send(self, code: int, body: Dict[str, Any]) -> None:
                    data = json.dumps(body).encode()
                    self.send_response(code)
                    self.send_header('Content-Type', 'application/json')
                    # The dashboard is served by the primary, from another origin.
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.send_header('Cache-Control', 'no-store')
                    self.send_header('Content-Length', str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)

            server = ThreadingHTTPServer((host, port), Handler)
            server.daemon_threads = True
            hub.spawn(server.serve_forever)
            logger.info('auditor status on http://%s:%d/auditor/status', host, port)
