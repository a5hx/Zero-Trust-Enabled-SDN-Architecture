"""os-ken SDN controller for trust-aware load balancing.

Two classes live here:
    TrustBalancerStandalone -- no os-ken dependency, used by run_demo.py.
        Untouched by the Sprint 1 os-ken work below: it has its own routing
        logic (no quarantine gate) that run_demo.py and its tests depend on
        exactly as-is.
    TrustBalancerApp -- the real os-ken OSKenApp driving the Mininet demo,
        using controller/edge_selector.py + controller/trust_state.py as its
        single source of truth for the EdgeScore/quarantine logic.
"""

import csv
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from contracts.trust_update import TrustUpdate
from trust_engine.trust_calculator import TrustCalculator
from blockchain.block import build_block
from blockchain.commit_backend import LocalLedgerBackend
from blockchain.ledger import Ledger

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib import hub
from os_ken.lib.packet import arp, ethernet, ether_types, ipv4, packet, tcp
from os_ken.ofproto import inet, ofproto_v1_3

from contracts.thresholds import DEFAULT_ANOMALY_WARN, DEFAULT_RATE_LIMIT_TRUST
from controller.edge_selector import BAND_RATE_LIMITED, EdgeWeights
from controller.event_bus import EventBus, NullBus
from controller.trust_state import TrustState
from security.authenticator import (
    HmacAuthenticator, NullAuthenticator, Present80Authenticator,
)
from simulation.addressing import VIP_MAC, iot_ip, srv_index, srv_ip, srv_mac

logger = logging.getLogger(__name__)


class TrustBalancerStandalone:
    """Standalone trust-aware load balancer (no Ryu dependency).

    Provides the same EdgeScore routing logic used by the full Ryu
    controller so that run_demo.py can work without Ryu/Mininet.
    """

    def __init__(
        self,
        trust_calculator: TrustCalculator,
        ledger: Ledger,
        edge_score_weights: Dict[str, float],
        num_edge_nodes: int = 8,
        max_updates_per_block: int = 10,
    ) -> None:
        self.trust_calc = trust_calculator
        self.ledger = ledger
        self.w1 = edge_score_weights.get('w1_trust', 0.50)
        self.w2 = edge_score_weights.get('w2_cpu', 0.30)
        self.w3 = edge_score_weights.get('w3_latency', 0.20)
        self.num_edge_nodes = num_edge_nodes
        self.max_updates_per_block = max_updates_per_block

        # Pending trust updates waiting for block commit
        self._pending_updates: List[TrustUpdate] = []

        # Routing log path
        self._log_path = Path('data') / 'routing_log.csv'
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._log_initialised = False

    def _ensure_log_header(self) -> None:
        """Write CSV header if the file doesn't exist yet."""
        if not self._log_initialised:
            with open(self._log_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 'node_id', 'edge_score', 'trust_score',
                    'routing_latency_ms', 'task_status',
                ])
            self._log_initialised = True

    def select_edge_node(
        self,
        cpu_loads: Dict[str, float],
        latencies: Dict[str, float],
    ) -> str:
        """Select the best edge node using the EdgeScore formula.

        EdgeScore(n) = w1*T(n) + w2*(1 - cpu_load(n)) + w3*(1 - lat_norm(n))

        Args:
            cpu_loads: {node_id: cpu_load} where cpu_load ∈ [0, 1].
            latencies: {node_id: latency_ms}.

        Returns:
            The node_id with the highest EdgeScore.
        """
        best_node: str = f'srv1'
        best_score: float = -1.0

        # Normalise latencies to [0, 1]
        max_lat = max(latencies.values()) if latencies else 1.0
        max_lat = max(max_lat, 1.0)  # Avoid division by zero

        for i in range(1, self.num_edge_nodes + 1):
            nid = f'srv{i}'
            t_score = self.trust_calc.get_score(nid)
            cpu = cpu_loads.get(nid, 0.5)
            lat = latencies.get(nid, 50.0)
            lat_norm = lat / max_lat

            edge_score = (
                self.w1 * t_score
                + self.w2 * (1.0 - cpu)
                + self.w3 * (1.0 - lat_norm)
            )

            if edge_score > best_score:
                best_score = edge_score
                best_node = nid

        return best_node

    def update_trust(
        self,
        node_id: str,
        device_id: str,
        task_status: str,
        cpu_usage: float,
        reported_cpu: float,
        latency_ms: float,
        anomaly_flag: bool = False,
    ) -> float:
        """Create a TrustUpdate, compute the new score, and batch for block commit.

        Returns:
            The new trust score for the node.
        """
        upd = TrustUpdate(
            device_id=device_id,
            edge_node_id=node_id,
            task_status=task_status,
            cpu_usage=cpu_usage,
            reported_cpu=reported_cpu,
            latency_ms=latency_ms,
            anomaly_flag=anomaly_flag,
        )
        upd.trust_score_before = self.trust_calc.get_score(node_id)
        score = self.trust_calc.update(upd)

        self._pending_updates.append(upd)

        # Commit block when batch is full
        if len(self._pending_updates) >= self.max_updates_per_block:
            self._commit_block()

        return score

    def _commit_block(self) -> Optional[Any]:
        """Commit pending updates as a new block on the ledger."""
        if not self._pending_updates:
            return None

        block = build_block(
            index=self.ledger.get_chain_length(),
            previous_hash=self.ledger._chain[-1].hash,
            updates=list(self._pending_updates),
        )
        accepted = self.ledger.append(block)
        if accepted:
            logger.info("Block %d committed with %d updates", block.index, len(self._pending_updates))
        else:
            logger.error("Block %d REJECTED", block.index)

        self._pending_updates.clear()
        return block if accepted else None

    def flush_pending(self) -> None:
        """Force-commit any remaining pending updates."""
        if self._pending_updates:
            self._commit_block()

    def log_routing_decision(
        self,
        node_id: str,
        edge_score: float,
        trust_score: float,
        routing_latency_ms: float,
        task_status: str,
    ) -> None:
        """Append a routing decision to the CSV log."""
        self._ensure_log_header()
        with open(self._log_path, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                time.time(), node_id, f'{edge_score:.4f}',
                f'{trust_score:.4f}', f'{routing_latency_ms:.2f}', task_status,
            ])


# --------------------------------------------------------------------------- #
# TrustBalancerApp -- the real os-ken controller for the Mininet demo         #
# --------------------------------------------------------------------------- #

# Demo-only pre-shared key for HmacAuthenticator (security/authenticator.py).
# Used only when the config selects auth_scheme: hmac (or leaves security
# unset). PRESENT-80 is the Sprint 2 default and carries its own 80-bit key.
_DEMO_HMAC_KEY = b'zero-trust-sdn-demo-shared-key'


def _build_authenticator(cfg: Dict[str, Any]):
    """Select the device authenticator from the config's `security:` block.

    security:
      auth_scheme: present80 | hmac | null   (default present80)
      shared_key_hex: "00010203...."         (10 bytes for present80)

    All three satisfy the same Authenticator protocol, so nothing downstream
    (TrustState, the /auth endpoints) changes with the choice. Absent config ->
    HMAC with the demo key, preserving Sprint 1 behaviour for older config
    files that have no security block.
    """
    sec = cfg.get('security')
    if not sec:
        return HmacAuthenticator(shared_key=_DEMO_HMAC_KEY)

    scheme = sec.get('auth_scheme', 'present80')
    if scheme == 'null':
        return NullAuthenticator()
    if scheme == 'hmac':
        key_hex = sec.get('shared_key_hex')
        key = bytes.fromhex(key_hex) if key_hex else _DEMO_HMAC_KEY
        return HmacAuthenticator(shared_key=key)
    if scheme == 'present80':
        key_hex = sec.get('shared_key_hex')
        if not key_hex:
            raise ValueError("security.auth_scheme=present80 requires shared_key_hex (10 bytes)")
        return Present80Authenticator(shared_key=bytes.fromhex(key_hex))
    raise ValueError(f"unknown security.auth_scheme: {scheme!r}")

# Overridable so tests / alternate demo scales can point at a different file
# without editing code.
_CONFIG_ENV_VAR = 'ZTSDN_CONFIG'
_DEFAULT_CONFIG_PATH = 'config/params_trust_demo.yaml'


class TrustBalancerApp(app_manager.OSKenApp):
    """Trust-aware OpenFlow 1.3 controller.

    Two-table pipeline per switch:
        TABLE_VIP (0): proxy-ARP for the virtual service IP (VIP), punts new
            TCP connections to the VIP to the controller, and holds the
            per-connection rewrite rules the controller installs dynamically.
            Miss -> goto TABLE_L2.
        TABLE_L2 (1): ordinary MAC-learning switch, identical logic to
            learning_switch_13.py, just relocated to table_id=1 so it never
            competes with the VIP rules in table 0.

    Routing itself is enforced entirely in the data plane (the rewrite rules
    installed in TABLE_VIP): an IoT client only ever addresses the VIP and is
    never told which real edge server answered. TrustState.choose_edge_node()
    decides who that is at the moment of the first PacketIn for a new
    (client_ip, client_port) flow.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    TABLE_VIP = 0
    TABLE_L2 = 1

    PRIO_QUARANTINE_DROP = 400
    PRIO_ARP_PUNT = 350
    PRIO_CONNECTION = 300
    PRIO_NEW_TASK = 250
    PRIO_MISS = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        cfg_path = os.environ.get(_CONFIG_ENV_VAR, _DEFAULT_CONFIG_PATH)
        with open(cfg_path) as f:
            cfg = yaml.safe_load(f)
        self.cfg = cfg

        n = cfg['simulation']['num_edge_nodes']
        node_ids = [f'srv{i}' for i in range(1, n + 1)]

        trust_cfg = cfg['trust']
        trust_calc = TrustCalculator(
            alpha=trust_cfg['alpha'],
            beta=trust_cfg['beta'],
            gamma=trust_cfg['gamma'],
            delta=trust_cfg['delta'],
            lambda_decay=trust_cfg['lambda_decay'],
            initial_score=trust_cfg['initial_score'],
        )

        blockchain_cfg = cfg.get('blockchain', {})

        self.state = TrustState(
            node_ids=node_ids,
            trust_calculator=trust_calc,
            commit_backend=LocalLedgerBackend(),
            authenticator=_build_authenticator(cfg),
            edge_weights=EdgeWeights.from_config(cfg['edge_score']),
            isolation_threshold=trust_cfg['isolation_threshold'],
            anomaly_gate=trust_cfg['anomaly_gate'],
            rate_limit_trust=trust_cfg.get('rate_limit_trust', DEFAULT_RATE_LIMIT_TRUST),
            anomaly_warn=trust_cfg.get('anomaly_warn', DEFAULT_ANOMALY_WARN),
            anomaly_lambda=trust_cfg['lambda_decay'],
            max_updates_per_block=blockchain_cfg.get('max_updates_per_block', 10),
            block_commit_timeout_s=blockchain_cfg.get('block_commit_timeout_s', 5.0),
        )

        ctrl_cfg = cfg['controller']

        # Graduated response: flows to a mid-band ("suspect") node are metered
        # to this rate. Disabled if the config omits the rate_limit block, or if
        # a switch turns out not to support OpenFlow meters (capability probe in
        # switch_features_handler -> _meters_ok).
        rl_cfg = ctrl_cfg.get('rate_limit', {})
        self.rate_limit_enabled: bool = bool(rl_cfg.get('enabled', False))
        self.rate_limit_kbps: int = int(rl_cfg.get('rate_kbps', 1000))
        self.rate_limit_burst_kb: int = int(rl_cfg.get('burst_kb', 100))
        # dpid -> bool: does this switch support meters (set by the features probe)
        self._meters_ok: Dict[int, bool] = {}
        # dpids on which per-node meters have already been installed
        self._meters_installed: set = set()
        self.vip_ip: str = ctrl_cfg['vip']
        self.vip_port: int = ctrl_cfg['vip_port']
        self.api_host: str = ctrl_cfg['api_host']
        self.api_port: int = ctrl_cfg['api_port']
        self.flow_idle_timeout: int = ctrl_cfg['flow_idle_timeout_s']
        self.flow_hard_timeout: int = ctrl_cfg['flow_hard_timeout_s']
        self.monitor_interval_s: float = ctrl_cfg['monitor_interval_s']
        self.honesty_deviation_threshold: float = ctrl_cfg['honesty_deviation_threshold']

        self._datapaths: Dict[int, Any] = {}
        self._mac_to_port: Dict[int, Dict[str, int]] = {}
        self._cookie_base = 0x5A00000000000000

        # Dashboard event bus. Absent/disabled config -> NullBus, so every
        # self.bus.publish() below is a no-op and the controller behaves
        # bit-for-bit as it did before the dashboard existed.
        dash_cfg = ctrl_cfg.get('dashboard', {})
        self.dashboard_enabled: bool = bool(dash_cfg.get('enabled', False))
        if self.dashboard_enabled:
            self.bus: Any = EventBus(
                record_path=dash_cfg.get('record_path', 'data/events.jsonl'),
            )
        else:
            self.bus = NullBus()

        # Imported here (not at module scope) because FlowMonitor is built and
        # wired in the same Sprint 1 pass as this class -- avoids a hard
        # top-level dependency ordering requirement between the two files.
        from controller.flow_monitor import FlowMonitor

        agents_cfg = cfg.get('agents', {})
        self.flow_monitor = FlowMonitor(
            state=self.state,
            node_ids=node_ids,
            agent_port=agents_cfg.get('node_port', 8000),
            poll_interval_s=self.monitor_interval_s,
            honesty_deviation_threshold=self.honesty_deviation_threshold,
            on_quarantine=self._on_trust_collapse,
            bus=self.bus,
        )

        # Set in start() when the dashboard is enabled -- polls OFPFlowStats so
        # the packet animation and rule hit-counters are driven by real switch
        # counters rather than anything the controller makes up.
        self.flow_stats: Any = None
        # Likewise polls OFPPortStats for the dashboard's link-load view.
        self.port_stats: Any = None

        self._http_server = None  # set in start(), from northbound_api.py

    def start(self):
        super().start()
        hub.spawn(self._run_http_server)
        hub.spawn(self.flow_monitor.run)

        if self.dashboard_enabled:
            from controller.flow_stats import FlowStatsPoller
            from controller.port_stats import PortStatsPoller

            # First event in every recording, so dashboard/replay.py can rebuild
            # the exact graph this run used instead of guessing it back from the
            # traffic (a run where a server never got traffic would otherwise
            # replay with that server missing from the map).
            self.bus.publish('topology', graph=self.topology_graph())

            self.flow_stats = FlowStatsPoller(
                datapaths=self._datapaths,
                bus=self.bus,
                poll_interval_s=self.monitor_interval_s,
            )
            hub.spawn(self.flow_stats.run)

            self.port_stats = PortStatsPoller(
                datapaths=self._datapaths,
                bus=self.bus,
                poll_interval_s=self.monitor_interval_s,
            )
            hub.spawn(self.port_stats.run)
            logger.info(
                "Dashboard enabled -- open http://localhost:%d/ in a browser",
                self.api_port,
            )

        logger.info(
            "TrustBalancerApp started: vip=%s:%d, api=%s:%d, nodes=%s",
            self.vip_ip, self.vip_port, self.api_host, self.api_port,
            self.state.node_ids,
        )

    def _run_http_server(self) -> None:
        # Imported lazily for the same reason as FlowMonitor above.
        from controller.northbound_api import NorthboundAPI

        self._http_server = NorthboundAPI(
            app=self, state=self.state, host=self.api_host, port=self.api_port,
        )
        self._http_server.serve_forever()

    # ------------------------------------------------------------------ #
    # OpenFlow event handlers                                             #
    # ------------------------------------------------------------------ #
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        self._datapaths[dp.id] = dp
        self._mac_to_port.setdefault(dp.id, {})

        # TABLE_VIP: default miss -> goto TABLE_L2 (no other action).
        self._install_goto_l2(dp, self.TABLE_VIP, self.PRIO_MISS, parser.OFPMatch(), [])

        # TABLE_VIP: proxy-ARP punt for the VIP (terminal, never reaches L2).
        arp_match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_tpa=self.vip_ip)
        arp_actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self._install_terminal(dp, self.TABLE_VIP, self.PRIO_ARP_PUNT, arp_match, arp_actions)

        # TABLE_VIP: new TCP connection to the VIP -> punt to controller
        # (terminal; a per-connection rewrite rule at PRIO_CONNECTION takes
        # over for the rest of that flow once installed).
        tcp_match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP,
            ipv4_dst=self.vip_ip, tcp_dst=self.vip_port,
        )
        tcp_actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self._install_terminal(dp, self.TABLE_VIP, self.PRIO_NEW_TASK, tcp_match, tcp_actions)

        # TABLE_L2: miss -> controller (same rule learning_switch_13.py used,
        # just relocated to table_id=1).
        l2_miss_actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self._install_terminal(dp, self.TABLE_L2, self.PRIO_MISS, parser.OFPMatch(), l2_miss_actions)

        # Graduated response capability probe: ask whether this switch supports
        # OpenFlow meters. The reply (meter_features_handler) records support and
        # installs the per-node meters; until then VIP flows are unmetered. If
        # the switch has no meter table, metering silently degrades to the
        # binary allow/quarantine behaviour -- never a crash.
        if self.rate_limit_enabled:
            dp.send_msg(parser.OFPMeterFeaturesStatsRequest(dp))

        logger.info("Switch connected: dpid=%016x", dp.id)
        self.bus.publish('switch_up', dpid=dp.id)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """OFPFlowStats replies arrive as os-ken events on this app, not on the
        poller that requested them (FlowStatsPoller is a plain object, not an
        OSKenApp, so it can't register handlers of its own) -- forward them."""
        if self.flow_stats is not None:
            self.flow_stats.handle_reply(ev)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        """OFPPortStats replies, forwarded to PortStatsPoller for the same
        reason as flow stats above (plain object, can't self-register)."""
        if self.port_stats is not None:
            self.port_stats.handle_reply(ev)

    @set_ev_cls(ofp_event.EventOFPMeterFeaturesStatsReply, MAIN_DISPATCHER)
    def meter_features_handler(self, ev):
        """Result of the graduated-response capability probe. If the switch has
        a usable meter table, record support and install the per-node meters;
        otherwise flag it unsupported so VIP installs never attach a meter (the
        rate-limit band degrades to full service on that switch, logged once)."""
        dp = ev.msg.datapath
        body = ev.msg.body
        feat = body[0] if isinstance(body, (list, tuple)) else body
        max_meter = getattr(feat, 'max_meter', 0) or 0
        supported = max_meter > 0
        self._meters_ok[dp.id] = supported
        if supported:
            self._install_meters(dp)
        else:
            logger.warning(
                "dpid=%016x reports no meter support (max_meter=%s) -- graduated "
                "response degrades to binary allow/quarantine here", dp.id, max_meter,
            )

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        if msg.table_id == self.TABLE_VIP:
            self._handle_table_vip(dp, msg, pkt, eth, in_port)
        else:
            self._handle_table_l2(dp, msg, pkt, eth, in_port)

    # ------------------------------------------------------------------ #
    # TABLE_VIP handling                                                  #
    # ------------------------------------------------------------------ #
    def _handle_table_vip(self, dp, msg, pkt, eth, in_port) -> None:
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocols(arp.arp)[0]
            if arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip == self.vip_ip:
                self._send_arp_reply(dp, in_port, arp_pkt, eth)
            return

        if eth.ethertype != ether_types.ETH_TYPE_IP:
            return

        ip_pkt = pkt.get_protocols(ipv4.ipv4)[0]
        if ip_pkt.proto != inet.IPPROTO_TCP:
            return
        tcp_pkt = pkt.get_protocols(tcp.tcp)[0]
        if ip_pkt.dst != self.vip_ip or tcp_pkt.dst_port != self.vip_port:
            # Shouldn't happen given the installed match, but stay defensive.
            return

        decision_start = time.monotonic()
        client_ip = ip_pkt.src
        client_port = tcp_pkt.src_port

        chosen = self.state.choose_edge_node()
        if chosen is None:
            logger.warning(
                "No eligible edge node for %s:%d -- all quarantined, denying",
                client_ip, client_port,
            )
            self.bus.publish(
                'route_denied', client_ip=client_ip, client_port=client_port,
                reason='all candidates quarantined',
            )
            return

        self.state.register_dispatch(client_ip, client_port, chosen)
        self._install_vip_pair(dp, client_ip, client_port, chosen)
        self._resend_packet(dp, msg, in_port)

        decision_ms = (time.monotonic() - decision_start) * 1000.0
        logger.info(
            "Routed %s:%d -> %s (decision took %.2fms)",
            client_ip, client_port, chosen, decision_ms,
        )

        # The ranked list is what makes the decision explicable on screen: the
        # dashboard can show not just who won but the EdgeScore of everyone who
        # lost, which is the whole point of the trust-aware routing claim.
        last = self.state.last_routing_decision() or {}
        self.bus.publish(
            'route',
            client_ip=client_ip, client_port=client_port, chosen=chosen,
            edge_score=last.get('score'), ranked=last.get('ranked'),
            decision_ms=round(decision_ms, 2), dpid=dp.id,
        )

    def _send_arp_reply(self, dp, in_port, arp_pkt, eth) -> None:
        parser = dp.ofproto_parser
        ofproto = dp.ofproto

        reply = packet.Packet()
        reply.add_protocol(ethernet.ethernet(
            dst=eth.src, src=VIP_MAC, ethertype=ether_types.ETH_TYPE_ARP,
        ))
        reply.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY, src_mac=VIP_MAC, src_ip=self.vip_ip,
            dst_mac=arp_pkt.src_mac, dst_ip=arp_pkt.src_ip,
        ))
        reply.serialize()

        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port,
            actions=[parser.OFPActionOutput(in_port)], data=reply.data,
        )
        dp.send_msg(out)

    def _install_vip_pair(self, dp, client_ip: str, client_port: int, node_id: str) -> None:
        parser = dp.ofproto_parser
        idx = srv_index(node_id)
        s_ip = srv_ip(idx)
        s_mac = srv_mac(idx)
        cookie = self._cookie_for(node_id)

        forward_match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP,
            ipv4_src=client_ip, ipv4_dst=self.vip_ip,
            tcp_src=client_port, tcp_dst=self.vip_port,
        )
        forward_actions = [
            parser.OFPActionSetField(eth_dst=s_mac),
            parser.OFPActionSetField(ipv4_dst=s_ip),
        ]
        # Graduated response: a node in the rate-limited band gets its inbound
        # (client -> server) flow metered. The reverse path is left unmetered --
        # rate-limiting the *load offered to* a suspect node is the point.
        meter_id = self._meter_for_node(dp, node_id)
        self._install_goto_l2(
            dp, self.TABLE_VIP, self.PRIO_CONNECTION, forward_match, forward_actions,
            cookie=cookie, idle_timeout=self.flow_idle_timeout,
            hard_timeout=self.flow_hard_timeout, meter_id=meter_id,
        )

        # Reverse direction is installed on the SAME datapath (the client's
        # ingress switch), not the server's. The server's OS replies using the
        # client's real ip/mac untouched, so the reply travels as ordinary
        # learned L2 traffic all the way to the client's own edge switch --
        # it only needs un-rewriting at that very last hop before delivery.
        reverse_match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP,
            ipv4_src=s_ip, ipv4_dst=client_ip,
            tcp_src=self.vip_port, tcp_dst=client_port,
        )
        reverse_actions = [
            parser.OFPActionSetField(eth_src=VIP_MAC),
            parser.OFPActionSetField(ipv4_src=self.vip_ip),
        ]
        self._install_goto_l2(
            dp, self.TABLE_VIP, self.PRIO_CONNECTION, reverse_match, reverse_actions,
            cookie=cookie, idle_timeout=self.flow_idle_timeout,
            hard_timeout=self.flow_hard_timeout,
        )

        # Rendered as text here rather than in the browser: this is the exact
        # rewrite the advisor wants to see ("rules"), and building the string
        # next to the OFPMatch it describes is the only way it can't drift from
        # what was actually installed.
        self.bus.publish(
            'flow_install', dpid=dp.id, node=node_id, cookie=cookie,
            table=self.TABLE_VIP, priority=self.PRIO_CONNECTION,
            idle_timeout=self.flow_idle_timeout,
            hard_timeout=self.flow_hard_timeout,
            rate_limited=meter_id is not None,
            rate_limit_kbps=self.rate_limit_kbps if meter_id is not None else None,
            rules=[
                {
                    'dir': 'forward',
                    'match': f'ipv4_src={client_ip},tcp_src={client_port},'
                             f'ipv4_dst={self.vip_ip},tcp_dst={self.vip_port}',
                    'actions': (
                        (f'meter {meter_id} ({self.rate_limit_kbps} kbps), '
                         if meter_id is not None else '')
                        + f'set eth_dst={s_mac}, set ipv4_dst={s_ip} -> goto table {self.TABLE_L2}'
                    ),
                },
                {
                    'dir': 'reverse',
                    'match': f'ipv4_src={s_ip},tcp_src={self.vip_port},'
                             f'ipv4_dst={client_ip},tcp_dst={client_port}',
                    'actions': f'set eth_src={VIP_MAC}, set ipv4_src={self.vip_ip} -> goto table {self.TABLE_L2}',
                },
            ],
        )

    def _resend_packet(self, dp, msg, in_port) -> None:
        """Resubmit the just-punted packet through the pipeline from table 0,
        so it now matches the higher-priority per-connection rule just
        installed instead of falling into the punt rule again (no loop), and
        the very first SYN isn't dropped waiting for a TCP retransmit."""
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
            actions=[parser.OFPActionOutput(ofproto.OFPP_TABLE)], data=data,
        )
        dp.send_msg(out)

    # ------------------------------------------------------------------ #
    # TABLE_L2 handling -- straight port of learning_switch_13.py         #
    # ------------------------------------------------------------------ #
    def _handle_table_l2(self, dp, msg, pkt, eth, in_port) -> None:
        parser = dp.ofproto_parser
        ofproto = dp.ofproto

        dst = eth.dst
        src = eth.src
        dpid = dp.id
        self._mac_to_port.setdefault(dpid, {})
        self._mac_to_port[dpid][src] = in_port

        out_port = self._mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            buffer_id = msg.buffer_id if msg.buffer_id != ofproto.OFP_NO_BUFFER else None
            self._install_goto_l2_flow_mod(
                dp, self.TABLE_L2, 1, match, actions, buffer_id=buffer_id,
            )
            if buffer_id is not None:
                return

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data,
        )
        dp.send_msg(out)

    def _install_goto_l2_flow_mod(self, dp, table_id, priority, match, actions, buffer_id=None) -> None:
        """Table-1 rule with no goto (nothing after L2) -- named for symmetry
        with the TABLE_VIP installers below, but is really just a terminal
        apply-actions rule installed directly into table_id=1."""
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=dp, table_id=table_id, priority=priority, match=match,
            instructions=inst, buffer_id=buffer_id if buffer_id is not None else dp.ofproto.OFP_NO_BUFFER,
        )
        dp.send_msg(mod)

    # ------------------------------------------------------------------ #
    # Flow-mod helpers                                                    #
    # ------------------------------------------------------------------ #
    def _install_terminal(self, dp, table_id, priority, match, actions, cookie: int = 0) -> None:
        """Apply-actions only, no goto -- used for the controller-punt rules
        and the TABLE_L2 miss rule."""
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=dp, cookie=cookie, table_id=table_id, priority=priority,
            match=match, instructions=inst,
        )
        dp.send_msg(mod)

    def _install_goto_l2(
        self, dp, table_id, priority, match, actions, cookie: int = 0,
        idle_timeout: int = 0, hard_timeout: int = 0, meter_id: Optional[int] = None,
    ) -> None:
        """Apply-actions (if any) + GotoTable(TABLE_L2) -- used for the
        TABLE_VIP default-miss rule (actions=[]) and the per-connection VIP
        rewrite rules. When meter_id is given, a Meter instruction is prepended
        so matching packets are metered (rate-limited) before being rewritten
        and forwarded -- the graduated-response middle band."""
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        inst = []
        if meter_id is not None:
            inst.append(parser.OFPInstructionMeter(meter_id, ofproto.OFPIT_METER))
        if actions:
            inst.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions))
        inst.append(parser.OFPInstructionGotoTable(self.TABLE_L2))
        mod = parser.OFPFlowMod(
            datapath=dp, cookie=cookie, table_id=table_id, priority=priority,
            match=match, instructions=inst,
            idle_timeout=idle_timeout, hard_timeout=hard_timeout,
        )
        dp.send_msg(mod)

    def _cookie_for(self, node_id: str) -> int:
        return self._cookie_base | srv_index(node_id)

    # ------------------------------------------------------------------ #
    # Graduated response: OpenFlow meters                                 #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _meter_id_for(node_id: str) -> int:
        """One meter per edge server, id = server index (>=1; 0 is reserved)."""
        return srv_index(node_id)

    def _install_meters(self, dp) -> None:
        """Install one drop-band KBPS meter per edge server on this switch, so
        a rate-limited node's flows can point at its meter. Idempotent per dpid.
        Only called for switches whose features probe confirmed meter support."""
        if dp.id in self._meters_installed:
            return
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        for node_id in self.state.node_ids:
            mid = self._meter_id_for(node_id)
            band = parser.OFPMeterBandDrop(
                rate=self.rate_limit_kbps, burst_size=self.rate_limit_burst_kb,
            )
            dp.send_msg(parser.OFPMeterMod(
                datapath=dp, command=ofproto.OFPMC_ADD, flags=ofproto.OFPMF_KBPS,
                meter_id=mid, bands=[band],
            ))
        self._meters_installed.add(dp.id)
        logger.info(
            "Installed %d per-node meters on dpid=%016x (%d kbps drop band)",
            len(self.state.node_ids), dp.id, self.rate_limit_kbps,
        )

    def _meter_for_node(self, dp, node_id: str) -> Optional[int]:
        """The meter id to attach to a new VIP flow for this node, or None for
        full-rate service. Returns a meter only when graduated response is
        enabled, this switch supports meters, and the node is currently in the
        rate-limited band."""
        if not self.rate_limit_enabled or not self._meters_ok.get(dp.id):
            return None
        if self.state.band(node_id) != BAND_RATE_LIMITED:
            return None
        return self._meter_id_for(node_id)

    # ------------------------------------------------------------------ #
    # Quarantine enforcement                                              #
    # ------------------------------------------------------------------ #
    def _on_trust_collapse(self, node_id: str) -> None:
        """Called by FlowMonitor the instant a node crosses into quarantine.
        Two-step containment on every switch: (1) delete every VIP rewrite
        rule for this node by cookie, so no further traffic is steered to it;
        (2) install top-priority drop rules on the node's MAC, so traffic
        addressed to it directly dies in the data plane too; then (3) re-steer
        the node's still-active clients onto the next-best node so their retry
        reconnects immediately instead of waiting out a flow timeout."""
        collapse_start = time.monotonic()
        t = self.state.trust_calc.get_score(node_id)
        a = self.state.get_anomaly(node_id)
        logger.warning(
            "QUARANTINE: %s trust=%.4f anomaly=%.4f -- deleting VIP rules, "
            "installing drop rules",
            node_id, t, a,
        )
        cookie = self._cookie_for(node_id)
        dpids = []
        for dp in list(self._datapaths.values()):
            parser = dp.ofproto_parser
            ofproto = dp.ofproto
            mod = parser.OFPFlowMod(
                datapath=dp, cookie=cookie, cookie_mask=0xFFFFFFFFFFFFFFFF,
                table_id=self.TABLE_VIP, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                match=parser.OFPMatch(),
            )
            dp.send_msg(mod)
            dpids.append(dp.id)

        # The deletes stop the controller *steering* traffic at the node, but
        # any host could still reach it directly. A flow entry with an empty
        # instruction set is OpenFlow's drop: matching packets die in the
        # switch, and the entry's packet counter records exactly how many it
        # killed (`dpctl dump-flows -O OpenFlow13`, the priority=400 entries).
        # Matching the MAC as source *and* destination covers every ethertype,
        # including the node's ARP replies -- an IP-only match would not.
        node_mac = srv_mac(srv_index(node_id))
        for dp in list(self._datapaths.values()):
            parser = dp.ofproto_parser
            ofproto = dp.ofproto
            for match in (
                parser.OFPMatch(eth_src=node_mac),
                parser.OFPMatch(eth_dst=node_mac),
            ):
                dp.send_msg(parser.OFPFlowMod(
                    datapath=dp, cookie=cookie, table_id=self.TABLE_VIP,
                    command=ofproto.OFPFC_ADD,
                    priority=self.PRIO_QUARANTINE_DROP,
                    match=match, instructions=[],
                ))
            self.bus.publish(
                'flow_install', dpid=dp.id, node=node_id, cookie=cookie,
                table=self.TABLE_VIP, priority=self.PRIO_QUARANTINE_DROP,
                idle_timeout=0, hard_timeout=0,
                rules=[
                    {'dir': 'quarantine', 'match': f'eth_src={node_mac}',
                     'actions': 'drop'},
                    {'dir': 'quarantine', 'match': f'eth_dst={node_mac}',
                     'actions': 'drop'},
                ],
            )

        self.bus.publish(
            'quarantine', node=node_id, trust=round(t, 4), anomaly=round(a, 4),
            isolation_threshold=self.state.isolation_threshold,
            anomaly_gate=self.state.anomaly_gate,
        )
        self.bus.publish('flow_delete', node=node_id, cookie=cookie, dpids=dpids)

        # (3) Proactively re-steer this node's active clients. Done after the
        # drops so the dead node is already excluded from re-selection.
        self._redispatch_after_quarantine(node_id, collapse_start)

    def _redispatch_after_quarantine(self, node_id: str, collapse_start: float) -> None:
        """Re-point every client the quarantined node was serving at the
        next-best eligible node, installing fresh VIP rewrite rules so the
        client's retry re-connects with no PacketIn round trip.

        All moved clients go to a single re-selected target: the current
        EdgeScore argmax already excludes the quarantined node, and re-running
        the selection per client returns the same winner under the present
        score (which does not factor in-flight load), so one selection is both
        correct and cheaper. If every other node is also quarantined, there is
        nowhere to send them -- their retry will PacketIn and be denied, which
        is the correct deny-by-default behaviour."""
        target = self.state.choose_edge_node()
        if target is None:
            logger.warning(
                "Re-dispatch after %s quarantine: no eligible node, "
                "affected clients will be denied on retry", node_id,
            )
            return

        moved = self.state.reassign_dispatches(node_id, target)
        if not moved:
            return

        # Fresh VIP pair on every switch, same as the drop rules: only the
        # client's real ingress switch will ever match, the rest expire idle.
        for dp in list(self._datapaths.values()):
            for client_ip, client_port in moved:
                self._install_vip_pair(dp, client_ip, client_port, target)

        resteer_ms = (time.monotonic() - collapse_start) * 1000.0
        for client_ip, client_port in moved:
            self.bus.publish(
                'reroute', client_ip=client_ip, client_port=client_port,
                from_node=node_id, to_node=target, resteer_ms=round(resteer_ms, 2),
            )
        logger.info(
            "Re-dispatched %d client(s) from quarantined %s to %s "
            "(%.2fms after collapse; NFR isolation < 3000ms)",
            len(moved), node_id, target, resteer_ms,
        )

    # ------------------------------------------------------------------ #
    # Called by northbound_api.py                                         #
    # ------------------------------------------------------------------ #
    def handle_client_report(
        self, client_ip: str, vip_src_port: int, device_id: str,
        status: str, latency_ms: float,
    ) -> Optional[float]:
        """POST /report: a client's task-completion outcome. Resolves which
        node actually served it via the dispatch map (the client is never
        told), then feeds a real TrustUpdate through the shared TrustState.

        Returns the node's new trust score, or None if this report can't be
        attributed to any known dispatch (stale, duplicate, or reaped)."""
        node_id = self.state.complete_dispatch(client_ip, vip_src_port)
        if node_id is None:
            logger.warning(
                "Unattributable /report from %s:%d (device=%s) -- stale or duplicate",
                client_ip, vip_src_port, device_id,
            )
            return None

        claimed_cpu = self.state.get_claimed_cpu(node_id)
        observed = self.state.observed_load(node_id)
        upd = TrustUpdate(
            device_id=device_id, edge_node_id=node_id, task_status=status,
            cpu_usage=observed, reported_cpu=claimed_cpu, latency_ms=latency_ms,
        )
        score = self.state.record_task_outcome(upd)
        logger.info(
            "Report: %s task=%s from %s -> %s trust=%.4f",
            device_id, status, node_id, node_id, score,
        )
        self.bus.publish(
            'report', device=device_id, node=node_id, status=status,
            latency_ms=round(latency_ms, 2), trust=round(score, 4),
            claimed_cpu=round(claimed_cpu, 4), observed_load=round(observed, 4),
        )
        return score

    # ------------------------------------------------------------------ #
    # Called by northbound_api.py -- dashboard                            #
    # ------------------------------------------------------------------ #
    def topology_graph(self) -> Dict[str, Any]:
        """The node/link graph the dashboard draws.

        Derived from the same config and the same round-robin attachment rule
        (`sw_idx = (j - 1) % n_edge`) that ZeroTrustTopo.build() in
        simulation/topology.py uses to build the real Mininet network. Computed
        from the shared config rather than read back off the switches so the
        dashboard can draw the topology before any switch has connected -- but
        it does mean this formula must track topology.py's if that ever changes.
        """
        n_edge = self.cfg['simulation']['num_edge_nodes']
        n_iot = self.cfg['simulation']['num_iot_devices']
        mal = {
            m['node']: m.get('attack', 'none')
            for m in self.cfg['simulation'].get('malicious_edge_nodes', [])
        }

        nodes: List[Dict[str, Any]] = [
            {'id': 's0', 'kind': 'core_switch', 'dpid': 1, 'label': 's0 (core)'},
        ]
        links: List[Dict[str, Any]] = []

        for i in range(1, n_edge + 1):
            nodes.append({
                'id': f's{i}', 'kind': 'edge_switch', 'dpid': i + 1,
                'label': f's{i}',
            })
            nodes.append({
                'id': f'srv{i}', 'kind': 'server', 'ip': srv_ip(i),
                'mac': srv_mac(i), 'label': f'srv{i}',
                # Surfaced only so the dashboard can mark ground truth *after*
                # the controller catches it -- never used to pre-emptively
                # colour a node, which would give the detection away for free.
                'attack': mal.get(f'srv{i}', 'none'),
            })
            links.append({'a': f's{i}', 'b': f'srv{i}', 'kind': 'server_link'})
            links.append({'a': 's0', 'b': f's{i}', 'kind': 'core_link'})

        for j in range(1, n_iot + 1):
            sw_idx = (j - 1) % n_edge          # matches ZeroTrustTopo.build()
            nodes.append({
                'id': f'iot{j}', 'kind': 'iot', 'ip': iot_ip(j),
                'label': f'iot{j}',
            })
            links.append({'a': f'iot{j}', 'b': f's{sw_idx + 1}', 'kind': 'iot_link'})

        return {
            'nodes': nodes,
            'links': links,
            'vip': f'{self.vip_ip}:{self.vip_port}',
            'weights': {
                'w1_trust': self.state.edge_weights.w1_trust,
                'w2_cpu': self.state.edge_weights.w2_cpu,
                'w3_latency': self.state.edge_weights.w3_latency,
            },
            'thresholds': {
                'isolation': self.state.isolation_threshold,
                'anomaly_gate': self.state.anomaly_gate,
            },
        }

    def flow_table(self) -> List[Dict[str, Any]]:
        """Current flow rules with live counters, for the dashboard's rules
        panel. Empty until the flow-stats poller has completed a cycle (or
        always, if the dashboard is disabled)."""
        if self.flow_stats is None:
            return []
        return self.flow_stats.snapshot()

    def port_table(self) -> List[Dict[str, Any]]:
        """Current per-port link load (measured bps), for the dashboard's
        link-load view. Empty until the port-stats poller has run a cycle (or
        always, if the dashboard is disabled)."""
        if self.port_stats is None:
            return []
        return self.port_stats.snapshot()

    def handle_offload_advisory(self) -> Dict[str, Any]:
        """POST /offload/request: advisory only -- returns what node *would*
        be chosen, without installing anything. The real routing decision
        already happens on the VIP data-plane path in _handle_table_vip; this
        exists so evaluation/baseline.py has a comparable read-only hook."""
        chosen = self.state.choose_edge_node()
        return {'chosen': chosen, 'snapshot': self.state.snapshot()}
