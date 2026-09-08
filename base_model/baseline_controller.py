"""The control arm's OpenFlow controller: an SDN with no zero trust in it.

Launch:

    ZTSDN_BASE_CONFIG=base_model/config/params_base_full.yaml \\
        python3 -m controller.osken_manager base_model.baseline_controller

WHY THIS IS STILL AN SDN
------------------------
The baseline keeps OpenFlow 1.3, OVS, the two-table pipeline, the VIP, the
proxy-ARP, the per-connection rewrite and the same flow/port stats polling. It
has to. If the control arm were a non-SDN network, every difference measured
would confound "SDN vs. not" with "zero trust vs. not", and the paper's claim is
about the second one. So the fabric is held constant and exactly one thing
changes: what decides where a connection goes, and what happens when a node
misbehaves.

WHAT IS MISSING, BY NAME
------------------------
Read the priority constants below against
`controller/trust_balancer.py::TrustBalancerApp`. That arm has seven; this one
has four, and the three absentees are the entire enforcement mechanism:

    PRIO_PROBATION        (460)  gone -- nothing is ever isolated, so nothing
                                 ever needs a trial task to earn its way back
    PRIO_HEALTH_CHECK     (450)  gone -- it exists only to carve the /status
                                 poll out of the quarantine drop rules
    PRIO_QUARANTINE_DROP  (400)  gone -- this arm installs no drop rules

Also absent: OpenFlow meters (no rate-limit band), cookie-matched flow deletes
(nothing to tear down), re-steering (`_redispatch_after_quarantine`), the
blockchain commit path, the AI optimiser, the flood detector, and the source-IP
pin. None of them is present-but-disabled. They are not here.

WHAT REMAINS, AND WHY
---------------------
Routing goes through `base_model/static_router.py`, which cannot see node
state. Trust goes through `base_model/trust_observer.py`, which cannot act.
`FlowStatsPoller` / `PortStatsPoller` are reused unchanged because they are
instrumentation, not defence — and reusing them is what lets
`evaluation/interval_report.py` read a baseline recording and a treatment
recording with the same code. The cookie scheme is deliberately identical
(`0x5A00000000000000 | srv_index`) for the same reason: FlowStatsPoller
resolves a rule to a server from the cookie, and a different base would make
every baseline throughput series silently unattributable.

THE ONE THING TO WATCH WHEN READING A BASELINE RUN
--------------------------------------------------
Under `static_nearest`, the five clients bound to a blackholing server keep
being bound to it. Their tasks time out for the rest of the run. That is not a
bug in this file and must not be "fixed" — it is the measurement.
"""

import logging
import os
import time
from typing import Any, Dict, List, Optional

import yaml
from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib import hub
from os_ken.lib.packet import arp, ethernet, ipv4, packet, tcp
from os_ken.lib.packet import ether_types
from os_ken.ofproto import inet, ofproto_v1_3

from base_model.static_router import STRATEGY_STATIC_NEAREST, StaticRouter
from base_model.trust_observer import BaselineTrustObserver, StatusSample
from controller.event_bus import EventBus, NullBus
from simulation.addressing import VIP_MAC, iot_ip, srv_index, srv_ip, srv_mac

logger = logging.getLogger('base_model.baseline_controller')

_CONFIG_ENV_VAR = 'ZTSDN_BASE_CONFIG'
_DEFAULT_CONFIG_PATH = 'base_model/config/params_base_full.yaml'

#: /status poll timeout. Same as controller/flow_monitor.py's, so a node reads
#: as unreachable at the same instant in both arms.
_STATUS_TIMEOUT_S = 0.5


class BaselineControllerApp(app_manager.OSKenApp):
    """Static-binding OpenFlow controller with a passive trust meter."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    TABLE_VIP = 0
    TABLE_L2 = 1

    # Four priorities. See the module docstring for the three that are absent
    # and what each of them was for.
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
        self.cfg_path = cfg_path

        sim = cfg['simulation']
        ctrl = cfg['controller']
        agents = cfg.get('agents', {})
        base = cfg.get('baseline', {})

        self.n_edge = int(sim['num_edge_nodes'])
        self.n_iot = int(sim['num_iot_devices'])
        self.node_ids = [f'srv{i}' for i in range(1, self.n_edge + 1)]

        self.vip_ip = ctrl['vip']
        self.vip_port = int(ctrl['vip_port'])
        self.api_host = ctrl.get('api_host', '0.0.0.0')
        self.api_port = int(ctrl.get('api_port', 8081))
        self.node_port = int(agents.get('node_port', 8000))
        self.flow_idle_timeout = int(ctrl.get('flow_idle_timeout_s', 10))
        self.flow_hard_timeout = int(ctrl.get('flow_hard_timeout_s', 30))
        self.monitor_interval_s = float(ctrl.get('monitor_interval_s', 1.0))
        self.task_timeout_s = float(agents.get('task_timeout_s', 4.0))

        # Same base as controller/trust_balancer.py. Not a coincidence and not
        # free to change: FlowStatsPoller reads the server index out of the low
        # byte, so a different base makes every baseline throughput series
        # unattributable to a node while still looking fine.
        self._cookie_base = 0x5A00000000000000

        self.router = StaticRouter(
            n_edge=self.n_edge,
            strategy=base.get('strategy', 'static_nearest'),
            seed=int(base.get('seed', 1)),
        )

        self.observer = BaselineTrustObserver(
            node_ids=self.node_ids,
            trust_cfg=cfg.get('trust', {}),
            observe_anomaly=bool(base.get('observe_anomaly', True)),
            load_window_s=float(base.get('load_window_s', 5.0)),
            latency_tell_cfg=ctrl,
            honesty_deviation_threshold=float(
                ctrl.get('honesty_deviation_threshold', 0.40)
            ),
            task_timeout_s=self.task_timeout_s,
        )
        BaselineTrustObserver.check_no_enforcement()

        dash = ctrl.get('dashboard', {})
        self.dashboard_enabled = bool(dash.get('enabled', True))
        record_path = dash.get('record_path', 'data/base_events.jsonl')
        self.bus = EventBus(record_path=record_path) if self.dashboard_enabled else NullBus()

        self._datapaths: Dict[int, Any] = {}
        self._mac_to_port: Dict[int, Dict[str, int]] = {}
        self._link_params: List[Dict[str, Any]] = []
        self._link_params_by_pair: Dict[Any, Dict[str, Any]] = {}
        self._monitor_paused = False
        self._admitted: Dict[str, str] = {}
        self.flow_stats = None
        self.port_stats = None

        logger.info(
            "BaselineControllerApp configured from %s: %d servers, %d IoT, "
            "strategy=%s, observe_anomaly=%s -- NO quarantine, NO rate limit, "
            "NO re-steer, NO admission control",
            cfg_path, self.n_edge, self.n_iot, self.router.strategy,
            self.observer.observe_anomaly,
        )

    # ------------------------------------------------------------------ #
    # Lifecycle                                                           #
    # ------------------------------------------------------------------ #
    def start(self):
        super().start()
        hub.spawn(self._run_http_server)
        hub.spawn(self._monitor_loop)

        if self.dashboard_enabled:
            from controller.flow_stats import FlowStatsPoller
            from controller.port_stats import PortStatsPoller

            # First event in the recording, exactly as in the treatment arm --
            # every offline tool anchors its clock and its ground truth on it,
            # and dashboard/replay.py rebuilds the graph from it.
            self.bus.publish('topology', graph=self.topology_graph())
            # Written down immediately after, so a recording carries the arm it
            # came from. Nothing downstream should ever have to infer "this was
            # the baseline" from the absence of quarantine events.
            self.bus.publish(
                'arm',
                arm='baseline',
                strategy=self.router.strategy,
                observe_anomaly=self.observer.observe_anomaly,
                config=self.cfg_path,
                enforcement=[],
                absent=[
                    'quarantine', 'rate_limit', 'resteer', 'probation',
                    'admission_control', 'source_ip_pin', 'blockchain',
                    'ai_optimizer', 'flood_detector', 'trust_aware_routing',
                ],
            )

            self.flow_stats = FlowStatsPoller(
                datapaths=self._datapaths, bus=self.bus,
                poll_interval_s=self.monitor_interval_s,
            )
            hub.spawn(self.flow_stats.run)
            self.port_stats = PortStatsPoller(
                datapaths=self._datapaths, bus=self.bus,
                poll_interval_s=self.monitor_interval_s,
            )
            hub.spawn(self.port_stats.run)

        logger.info(
            "BaselineControllerApp started: vip=%s:%d api=%s:%d nodes=%s",
            self.vip_ip, self.vip_port, self.api_host, self.api_port, self.node_ids,
        )

    def _run_http_server(self) -> None:
        from base_model.baseline_api import BaselineAPI

        self._http_server = BaselineAPI(
            app=self, host=self.api_host, port=self.api_port,
        )
        self._http_server.serve_forever()

    # ------------------------------------------------------------------ #
    # OpenFlow                                                            #
    # ------------------------------------------------------------------ #
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        self._datapaths[dp.id] = dp
        self._mac_to_port.setdefault(dp.id, {})

        self._install_goto_l2(dp, self.TABLE_VIP, self.PRIO_MISS, parser.OFPMatch(), [])

        arp_match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_tpa=self.vip_ip)
        self._install_terminal(
            dp, self.TABLE_VIP, self.PRIO_ARP_PUNT, arp_match,
            [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)],
        )

        tcp_match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP,
            ipv4_dst=self.vip_ip, tcp_dst=self.vip_port,
        )
        self._install_terminal(
            dp, self.TABLE_VIP, self.PRIO_NEW_TASK, tcp_match,
            [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)],
        )

        self._install_terminal(
            dp, self.TABLE_L2, self.PRIO_MISS, parser.OFPMatch(),
            [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)],
        )

        # No meter-features probe here. The treatment arm asks every switch
        # whether it supports OpenFlow meters so it can rate-limit a suspect
        # node; this arm has no suspect band to enforce, so it never asks and
        # never installs a meter.

        logger.info("Switch connected: dpid=%016x", dp.id)
        self.bus.publish('switch_up', dpid=dp.id)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        if self.flow_stats is not None:
            self.flow_stats.handle_reply(ev)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        if self.port_stats is not None:
            self.port_stats.handle_reply(ev)

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
    # TABLE_VIP -- the routing decision, such as it is                    #
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
            return

        decision_start = time.monotonic()
        client_ip = ip_pkt.src
        client_port = tcp_pkt.src_port

        # The whole decision. No candidate scoring, no eligibility filter, no
        # deny path -- `bind` cannot return None, so unlike the treatment arm
        # there is no `route_denied` event this controller is able to emit.
        chosen = self.router.bind(client_ip, client_port)

        self.observer.register_dispatch(client_ip, client_port, chosen)
        self._install_vip_pair(dp, client_ip, client_port, chosen)
        self._resend_packet(dp, msg, in_port)

        decision_ms = (time.monotonic() - decision_start) * 1000.0
        self.bus.publish(
            'route',
            client_ip=client_ip, client_port=client_port, chosen=chosen,
            # Null rather than 0.0: this arm computes no EdgeScore and ranks
            # nothing. A zero here would be read by every downstream tool as a
            # measured score of zero, which is a different and false claim.
            edge_score=None, ranked=[],
            decision_ms=round(decision_ms, 2), dpid=dp.id,
            probation=False, strategy=self.router.strategy,
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
        # OFPP_IN_PORT, not the literal port number: OpenFlow silently drops an
        # output action naming the packet's own ingress port, and the failure
        # mode is a VIP nothing can ever resolve while the ARP punt counter
        # climbs on retries.
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port,
            actions=[parser.OFPActionOutput(ofproto.OFPP_IN_PORT)], data=reply.data,
        ))

    def _install_vip_pair(self, dp, client_ip: str, client_port: int, node_id: str) -> None:
        parser = dp.ofproto_parser
        idx = srv_index(node_id)
        s_ip, s_mac = srv_ip(idx), srv_mac(idx)
        cookie = self._cookie_base | idx

        forward_match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP,
            ipv4_src=client_ip, ipv4_dst=self.vip_ip,
            tcp_src=client_port, tcp_dst=self.vip_port,
        )
        forward_actions = [
            parser.OFPActionSetField(eth_dst=s_mac),
            parser.OFPActionSetField(ipv4_dst=s_ip),
            # The port must be translated too: the VIP is published on
            # vip_port while agents bind node_port. Without it the rewritten
            # packet lands where nothing listens, the server's kernel RSTs, and
            # the flow counters look healthy while no agent sees a request.
            parser.OFPActionSetField(tcp_dst=self.node_port),
        ]
        # No meter instruction: this arm has no rate-limited band.
        self._install_goto_l2(
            dp, self.TABLE_VIP, self.PRIO_CONNECTION, forward_match, forward_actions,
            cookie=cookie, idle_timeout=self.flow_idle_timeout,
            hard_timeout=self.flow_hard_timeout,
        )

        reverse_match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP,
            ipv4_src=s_ip, ipv4_dst=client_ip,
            tcp_src=self.node_port, tcp_dst=client_port,
        )
        reverse_actions = [
            parser.OFPActionSetField(eth_src=VIP_MAC),
            parser.OFPActionSetField(ipv4_src=self.vip_ip),
            parser.OFPActionSetField(tcp_src=self.vip_port),
        ]
        self._install_goto_l2(
            dp, self.TABLE_VIP, self.PRIO_CONNECTION, reverse_match, reverse_actions,
            cookie=cookie, idle_timeout=self.flow_idle_timeout,
            hard_timeout=self.flow_hard_timeout,
        )

        self.bus.publish(
            'flow_install', dpid=dp.id, node=node_id, cookie=cookie,
            table=self.TABLE_VIP, priority=self.PRIO_CONNECTION,
            idle_timeout=self.flow_idle_timeout,
            hard_timeout=self.flow_hard_timeout,
            probation=False, rate_limited=False, rate_limit_kbps=None,
            rules=[
                {
                    'dir': 'forward',
                    'match': f'ipv4_src={client_ip},tcp_src={client_port},'
                             f'ipv4_dst={self.vip_ip},tcp_dst={self.vip_port}',
                    'actions': f'set eth_dst={s_mac}, set ipv4_dst={s_ip}, '
                               f'set tcp_dst={self.node_port} -> goto table {self.TABLE_L2}',
                },
                {
                    'dir': 'reverse',
                    'match': f'ipv4_src={s_ip},tcp_src={self.node_port},'
                             f'ipv4_dst={client_ip},tcp_dst={client_port}',
                    'actions': f'set eth_src={VIP_MAC}, set ipv4_src={self.vip_ip}, '
                               f'set tcp_src={self.vip_port} -> goto table {self.TABLE_L2}',
                },
            ],
        )

    def _resend_packet(self, dp, msg, in_port) -> None:
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
            actions=[parser.OFPActionOutput(ofproto.OFPP_TABLE)], data=data,
        ))

    # ------------------------------------------------------------------ #
    # TABLE_L2 -- plain MAC learning                                      #
    # ------------------------------------------------------------------ #
    def _handle_table_l2(self, dp, msg, pkt, eth, in_port) -> None:
        parser = dp.ofproto_parser
        ofproto = dp.ofproto

        dpid = dp.id
        self._mac_to_port.setdefault(dpid, {})
        self._mac_to_port[dpid][eth.src] = in_port
        out_port = self._mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst)
            buffer_id = msg.buffer_id if msg.buffer_id != ofproto.OFP_NO_BUFFER else None
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, table_id=self.TABLE_L2, priority=1, match=match,
                instructions=inst,
                buffer_id=buffer_id if buffer_id is not None else ofproto.OFP_NO_BUFFER,
            ))
            if buffer_id is not None:
                return

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data,
        ))

    # ------------------------------------------------------------------ #
    # Flow-mod helpers                                                    #
    # ------------------------------------------------------------------ #
    def _install_terminal(self, dp, table_id, priority, match, actions, cookie: int = 0) -> None:
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, cookie=cookie, table_id=table_id, priority=priority,
            match=match, instructions=inst,
        ))

    def _install_goto_l2(
        self, dp, table_id, priority, match, actions,
        cookie: int = 0, idle_timeout: int = 0, hard_timeout: int = 0,
    ) -> None:
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        inst = []
        if actions:
            inst.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions))
        inst.append(parser.OFPInstructionGotoTable(self.TABLE_L2))
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, cookie=cookie, table_id=table_id, priority=priority,
            match=match, instructions=inst,
            idle_timeout=idle_timeout, hard_timeout=hard_timeout,
        ))

    # ------------------------------------------------------------------ #
    # Monitoring -- observation only                                      #
    # ------------------------------------------------------------------ #
    def _monitor_loop(self) -> None:
        """Poll every agent's /status, feed the observer, publish, repeat.

        Structurally the treatment arm's `FlowMonitor.run`, with its last step
        deleted. There, a cycle ends by calling
        `state.poll_quarantine_transitions()` and acting on the result. Here it
        ends by publishing `node_status` and going back to sleep.
        """
        logger.info(
            "Baseline monitor: polling %d agents every %.1fs (observation only)",
            len(self.node_ids), self.monitor_interval_s,
        )
        while True:
            if not self._monitor_paused:
                try:
                    self._poll_once()
                except Exception:
                    logger.exception("Baseline poll cycle failed")
            hub.sleep(self.monitor_interval_s)

    def _poll_once(self) -> None:
        # Abandoned tasks stop counting as inflight at about the moment their
        # client stopped waiting. Without this the occupancy estimate inflates
        # under load and the H term drifts for a reason that has nothing to do
        # with either architecture -- which would corrupt the comparison in the
        # baseline's disfavour.
        self.observer.reap_stale_dispatches()

        samples = [self._fetch_status(nid) for nid in self.node_ids]
        for sample in samples:
            self.observer.record_status(sample)

        for verdict in self.observer.evaluate_cycle(samples):
            if verdict.reasons:
                self.bus.publish(
                    'anomaly', node=verdict.node_id, reasons=verdict.reasons,
                    signals=verdict.signals, anomaly=round(verdict.anomaly, 4),
                    gate=self.observer._state.anomaly_gate,  # noqa: SLF001
                    # The field that makes this arm's central claim countable:
                    # evidence was gathered, a gate was crossed, and nothing
                    # happened. The treatment arm has no equivalent because
                    # there, crossing the gate IS the action.
                    actioned=False,
                )

        self.bus.publish('node_status', nodes=self.observer.snapshot())

    def _fetch_status(self, node_id: str) -> StatusSample:
        """GET /status from one agent, timing the round trip ourselves.

        Serial, not the treatment arm's thread pool. At eight nodes and a 0.5 s
        timeout the worst case is 4 s against a 1 s interval, which would skew
        the poll cadence — so if a run is ever made larger than this, or the
        fleet goes dark, this loop is the first thing to parallelise. It is
        left serial here because the fleet is eight nodes and a control arm
        with fewer moving parts is easier to defend.
        """
        import http.client

        host = srv_ip(srv_index(node_id))
        start = time.monotonic()
        try:
            conn = http.client.HTTPConnection(host, self.node_port, timeout=_STATUS_TIMEOUT_S)
            conn.request('GET', '/status')
            resp = conn.getresponse()
            body = resp.read()
            rtt_ms = (time.monotonic() - start) * 1000.0
            conn.close()
            if resp.status != 200:
                return StatusSample(node_id=node_id, ok=False, rtt_ms=rtt_ms)
            import json as _json
            payload = _json.loads(body)
            return StatusSample(
                node_id=node_id, ok=True,
                claimed_cpu=float(payload.get('cpu_load', 0.0)),
                rtt_ms=rtt_ms,
                latency_ms=float(payload.get('latency_ms', rtt_ms)),
                busy_seconds=(
                    float(payload['busy_seconds'])
                    if payload.get('busy_seconds') is not None else None
                ),
                concurrency=int(payload.get('concurrency', 4)),
            )
        except Exception:
            rtt_ms = (time.monotonic() - start) * 1000.0
            return StatusSample(node_id=node_id, ok=False, rtt_ms=rtt_ms)

    # ------------------------------------------------------------------ #
    # API surface                                                         #
    # ------------------------------------------------------------------ #
    def admit(self, device_id: str, source_ip: str) -> str:
        """Admit any device that asks. Records the pair; compares nothing.

        `claimed_by` is how a spoof shows up in the recording without anything
        having detected it: iot38 authenticates as iot1, so this arm records
        device_id='iot1' from source_ip='10.0.0.38' and carries on. The mismatch
        is a fact in the file; noticing it is `compare.py`'s job, offline, after
        the run has already been damaged by it.
        """
        token = f'baseline-{device_id}-{int(time.time() * 1000)}'
        previous = self._admitted.get(device_id)
        self._admitted[device_id] = source_ip
        expected_ip = self._expected_ip(device_id)
        self.bus.publish(
            'auth_admitted', device_id=device_id, source_ip=source_ip,
            expected_ip=expected_ip,
            # Computed for the recording, never consulted for the verdict --
            # the token above was already issued unconditionally.
            source_matches_identity=(expected_ip is None or expected_ip == source_ip),
            reclaimed_from=previous if previous and previous != source_ip else None,
            verified=False,
        )
        logger.info("ADMITTED %s from %s (no verification performed)", device_id, source_ip)
        return token

    @staticmethod
    def _expected_ip(device_id: str) -> Optional[str]:
        if device_id.startswith('iot'):
            try:
                return iot_ip(int(device_id[3:]))
            except ValueError:
                return None
        return None

    def handle_client_report(
        self, client_ip: str, vip_src_port: int, device_id: str,
        status: str, latency_ms: float,
    ) -> Optional[Dict[str, Any]]:
        payload = self.observer.record_report(
            device_id=device_id, client_ip=client_ip, vip_src_port=vip_src_port,
            status=status, latency_ms=latency_ms,
        )
        if payload is None:
            return None
        # `source_ip` rides along on every report so a spoofed device's traffic
        # stays attributable to the host that actually sent it, even though the
        # controller admitted it under someone else's name.
        self.bus.publish('report', source_ip=client_ip, **payload)
        return payload

    def set_node_concurrency(self, node_id: str, concurrency: int) -> None:
        self.observer._state.set_concurrency(node_id, concurrency)  # noqa: SLF001

    def pause_monitor(self) -> bool:
        self._monitor_paused = True
        logger.info("Baseline monitor paused for teardown")
        return True

    def record_link_params(self, links: List[Dict[str, Any]]) -> int:
        """What the harness reports it actually wired up.

        Descriptive, never a control. The per-IoT link delay is drawn from an
        unseeded RNG inside `ZeroTrustTopo.build()`, so it cannot be
        re-derived from config -- this is the only record of it, and without it
        "distance to sink" on a baseline run would be hop counts dressed up as
        measured delays. Keyed by unordered endpoint pair, matching the way
        `topology_graph()` looks them up.
        """
        self._link_params = list(links or [])
        self._link_params_by_pair = {
            frozenset((lk['a'], lk['b'])): {
                k: v for k, v in lk.items() if k not in ('a', 'b')
            }
            for lk in self._link_params
            if 'a' in lk and 'b' in lk
        }
        if self._link_params:
            self.bus.publish('topology_links', links=self._link_params)
        return len(self._link_params)

    # ------------------------------------------------------------------ #
    # Topology graph -- ground truth for the offline scorers              #
    # ------------------------------------------------------------------ #
    def topology_graph(self) -> Dict[str, Any]:
        """The same `topology` event shape the treatment arm publishes.

        Shape parity is not cosmetic. `evaluation/topology_metrics.py`,
        `attack_report.py` and `dashboard/replay.py` all read this event, and
        they key on `links` entries shaped `{a, b, kind}` -- so a baseline
        recording that used `{source, target}` would parse, produce an empty
        graph, and report a plausible-looking nothing.

        Carries the attack ground truth for BOTH tiers, servers and IoT
        devices, because two of the six attacks (flood, spoof) live on the
        client side and would otherwise have no row in any confusion matrix.
        Attack precedence follows `simulation/topology.py`'s own wiring: spoof
        beats flood for the same device, and the wrong-key devices in
        `security.malicious_iot_devices` are a third mechanism again.

        Hand-duplicates `ZeroTrustTopo.build()`'s `sw_idx = (j - 1) % n_edge`
        attachment rule, exactly as `trust_balancer.topology_graph()` does and
        with the same caveat: if that rule changes, all three copies must.
        """
        sim = self.cfg['simulation']
        mal = {
            m['node']: m.get('attack', 'none')
            for m in sim.get('malicious_edge_nodes', []) or []
        }
        onset = {
            m['node']: float(m.get('start_s', 0.0))
            for m in sim.get('malicious_edge_nodes', []) or []
        }
        iot_mal: Dict[str, str] = {
            d: 'bad_credentials'
            for d in self.cfg.get('security', {}).get('malicious_iot_devices', []) or []
        }
        iot_onset: Dict[str, float] = {}
        for m in sim.get('malicious_flood_devices', []) or []:
            iot_mal[m['device']] = 'flood'
            iot_onset[m['device']] = float(m.get('start_s', 0.0))
        for m in sim.get('malicious_spoof_devices', []) or []:
            iot_mal[m['device']] = 'spoof'
            iot_onset[m['device']] = float(m.get('start_s', 5.0))

        nodes: List[Dict[str, Any]] = [
            {'id': 's0', 'kind': 'core_switch', 'dpid': 1, 'label': 's0 (core)'},
        ]
        links: List[Dict[str, Any]] = []

        for i in range(1, self.n_edge + 1):
            nodes.append({
                'id': f's{i}', 'kind': 'edge_switch', 'dpid': i + 1, 'label': f's{i}',
            })
            nodes.append({
                'id': f'srv{i}', 'kind': 'server', 'ip': srv_ip(i), 'mac': srv_mac(i),
                'label': f'srv{i}',
                # Ground truth for post-hoc marking only. This arm never acts on
                # it -- and unlike the treatment arm, it never acts on anything
                # it derives either, so the field cannot leak into a decision.
                'attack': mal.get(f'srv{i}', 'none'),
                'attack_start_s': onset.get(f'srv{i}', 0.0),
            })
            links.append({'a': f's{i}', 'b': f'srv{i}', 'kind': 'server_link'})
            links.append({'a': 's0', 'b': f's{i}', 'kind': 'core_link'})

        static = self.router.strategy == STRATEGY_STATIC_NEAREST
        for j in range(1, self.n_iot + 1):
            sw_idx = (j - 1) % self.n_edge      # matches ZeroTrustTopo.build()
            node = {
                'id': f'iot{j}', 'kind': 'iot', 'ip': iot_ip(j), 'label': f'iot{j}',
                'attack': iot_mal.get(f'iot{j}', 'none'),
                'attack_start_s': iot_onset.get(f'iot{j}', 0.0),
            }
            # Baseline-only, and the most useful field here for reading a run:
            # which server this device is nailed to for the duration. Emitted
            # ONLY under static_nearest -- under the rotating strategies there
            # is no fixed binding, and writing one down would be a claim the
            # run does not support. The `route` events are the authority then.
            if static:
                node['bound_to'] = f'srv{sw_idx + 1}'
            nodes.append(node)
            links.append({'a': f'iot{j}', 'b': f's{sw_idx + 1}', 'kind': 'iot_link'})

        measured_links = getattr(self, '_link_params_by_pair', None) or {}
        for lk in links:
            measured = measured_links.get(frozenset((lk['a'], lk['b'])))
            if measured:
                lk.update(measured)

        return {
            'nodes': nodes,
            'links': links,
            'vip': f'{self.vip_ip}:{self.vip_port}',
            # No `weights` key. The treatment arm reports w1/w2/w3 because it
            # has an EdgeScore to weight; emitting zeros or nulls here would
            # invite a reader to plot "the baseline's trust weight" against the
            # treatment arm's. There is no such quantity.
            'thresholds': {
                # Reported so both arms are read against the same ruler, and
                # explicitly marked as unenforced so the pair cannot be
                # mistaken for active gates.
                'isolation': self.observer._state.isolation_threshold,  # noqa: SLF001
                'anomaly_gate': self.observer._state.anomaly_gate,      # noqa: SLF001
                'enforced': False,
            },
            'selection': {
                'strategy': self.router.strategy,
                'adaptive': False,
            },
        }
