"""Per-flow packet/byte counter polling, for the dashboard's packet animation.

Why this file exists at all:

    In OpenFlow, once a flow rule is installed the switch forwards matching
    packets entirely in the data plane -- they never reach the controller
    again. That is the whole point of SDN, and it means the controller *cannot*
    see individual packets and therefore cannot honestly animate them from
    PacketIn events alone (it only ever sees the first packet of each new
    connection).

    What the switch *does* keep is a packet/byte counter on every flow rule.
    OFPFlowStatsRequest reads them. Diffing those counters between two polls
    gives the real packets-per-second carried by each rule, which is what the
    dashboard uses to set how fast dots travel along each link. So the
    animation is driven by genuine switch counters, not by anything the
    controller invents -- and the measured pps is printed on screen next to it.

Runs as its own os-ken hub greenthread (`hub.spawn(poller.run)`), same pattern
as controller/flow_monitor.py. The replies come back as os-ken events on
TrustBalancerApp (this is a plain object, not an OSKenApp, so it cannot
register its own handlers), which forwards them to handle_reply().
"""

import logging
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from os_ken.lib import hub

logger = logging.getLogger(__name__)

# Rules with a cookie in this range were installed by TrustBalancerApp's VIP
# dispatch (see _cookie_base there); everything else is L2-learning noise the
# dashboard's rules panel labels differently.
_VIP_COOKIE_BASE = 0x5A00000000000000
_VIP_COOKIE_MASK = 0xFF00000000000000

# A rule seen in a poll but absent from the next N polls is dropped from the
# table. Rules expire on their own idle/hard timeout (10s/30s in the demo
# config), and the panel should reflect that rather than showing a rule that no
# longer exists on the switch.
_MISSING_POLLS_BEFORE_EVICT = 2


def _match_to_str(match: Any) -> str:
    """Render an OFPMatch as the compact `k=v,k=v` form used by ovs-ofctl, so a
    rule in the dashboard's panel reads the same as it does in
    `dpctl dump-flows -O OpenFlow13` -- the two must be recognisably the same
    thing when the advisor compares them side by side."""
    try:
        items = sorted(match.items())
    except (AttributeError, TypeError):
        return str(match)
    if not items:
        return '*'
    return ','.join(f'{k}={v}' for k, v in items)


class FlowStatsPoller:
    """Polls every connected switch for flow counters at a fixed interval."""

    def __init__(
        self,
        datapaths: Dict[int, Any],
        bus: Any,
        poll_interval_s: float = 1.0,
    ) -> None:
        # Shared reference to TrustBalancerApp._datapaths, deliberately not a
        # copy: switches connect after this object is built, and the poller must
        # pick them up without being rebuilt.
        self._datapaths = datapaths
        self.bus = bus
        self.poll_interval_s = poll_interval_s
        self._stop = False

        self._lock = threading.Lock()
        # (dpid, table, priority, cookie, match) -> last seen counters
        self._prev: Dict[Tuple, Dict[str, Any]] = {}
        self._current: Dict[Tuple, Dict[str, Any]] = {}
        self._missing: Dict[Tuple, int] = {}

    def run(self) -> None:
        logger.info("FlowStatsPoller started: interval=%.2fs", self.poll_interval_s)
        while not self._stop:
            try:
                self._request_all()
            except Exception:
                logger.exception("FlowStatsPoller request cycle failed")
            hub.sleep(self.poll_interval_s)

    def stop(self) -> None:
        self._stop = True

    def _request_all(self) -> None:
        for dp in list(self._datapaths.values()):
            parser = dp.ofproto_parser
            ofproto = dp.ofproto
            dp.send_msg(parser.OFPFlowStatsRequest(datapath=dp, table_id=ofproto.OFPTT_ALL))

    def handle_reply(self, ev: Any) -> None:
        """One switch's full flow table. Diff it against the previous poll to
        turn cumulative counters into a rate."""
        dp = ev.msg.datapath
        dpid = dp.id
        now = time.time()

        rules: List[Dict[str, Any]] = []

        with self._lock:
            seen_keys = set()

            for stat in ev.msg.body:
                match_str = _match_to_str(stat.match)
                key = (dpid, stat.table_id, stat.priority, stat.cookie, match_str)
                seen_keys.add(key)

                prev = self._prev.get(key)
                pps = 0.0
                bps = 0.0
                if prev is not None:
                    dt = now - prev['ts']
                    if dt > 0:
                        # max(0, ...) because a rule can be deleted and
                        # reinstalled with the same key between polls, resetting
                        # its counter to zero -- a negative "rate" is nonsense.
                        pps = max(0.0, (stat.packet_count - prev['packets']) / dt)
                        bps = max(0.0, (stat.byte_count - prev['bytes']) / dt)

                entry = {
                    'ts': now,
                    'packets': stat.packet_count,
                    'bytes': stat.byte_count,
                }
                self._prev[key] = entry

                rules.append({
                    'dpid': dpid,
                    'table': stat.table_id,
                    'priority': stat.priority,
                    'cookie': stat.cookie,
                    'node': self._node_for_cookie(stat.cookie),
                    'match': match_str,
                    'actions': self._actions_to_str(stat.instructions),
                    'packets': stat.packet_count,
                    'bytes': stat.byte_count,
                    'pps': round(pps, 2),
                    'bps': round(bps, 2),
                    'is_vip': self._is_vip_cookie(stat.cookie),
                })

            self._evict_stale_locked(dpid, seen_keys)
            for rule in rules:
                self._current[self._key_of(rule)] = rule

        self.bus.publish('flow_stats', dpid=dpid, rules=rules)

    @staticmethod
    def _key_of(rule: Dict[str, Any]) -> Tuple:
        return (
            rule['dpid'], rule['table'], rule['priority'],
            rule['cookie'], rule['match'],
        )

    def _evict_stale_locked(self, dpid: int, seen_keys: set) -> None:
        """Forget rules this switch no longer reports (they hit their idle/hard
        timeout, or were deleted by a quarantine). Requires a couple of
        consecutive misses so a dropped reply doesn't clear the panel."""
        for key in [k for k in self._current if k[0] == dpid and k not in seen_keys]:
            self._missing[key] = self._missing.get(key, 0) + 1
            if self._missing[key] >= _MISSING_POLLS_BEFORE_EVICT:
                self._current.pop(key, None)
                self._prev.pop(key, None)
                self._missing.pop(key, None)

        for key in seen_keys:
            self._missing.pop(key, None)

    @staticmethod
    def _is_vip_cookie(cookie: int) -> bool:
        return (cookie & _VIP_COOKIE_MASK) == _VIP_COOKIE_BASE

    @classmethod
    def _node_for_cookie(cls, cookie: int) -> Optional[str]:
        """VIP rules encode the edge server they route to in the low byte of
        their cookie (TrustBalancerApp._cookie_for) -- that is how a quarantine
        can delete every rule for one node with a single cookie-matched
        OFPFC_DELETE, and it is how the dashboard colours each rule by server."""
        if not cls._is_vip_cookie(cookie):
            return None
        idx = cookie & 0xFF
        return f'srv{idx}' if idx else None

    @staticmethod
    def _actions_to_str(instructions: Any) -> str:
        parts: List[str] = []
        for inst in instructions or []:
            actions = getattr(inst, 'actions', None)
            if actions is not None:
                for act in actions:
                    cls_name = type(act).__name__
                    if cls_name == 'OFPActionOutput':
                        port = act.port
                        # OFPP_CONTROLLER (0xfffffffd) is the punt-to-controller
                        # rule; spelling it out matters because those are the
                        # rules that make PacketIn happen at all.
                        parts.append(
                            'output:CONTROLLER' if port == 0xfffffffd
                            else f'output:{port}'
                        )
                    elif cls_name == 'OFPActionSetField':
                        parts.append(f'set {act.key}={act.value}')
                    else:
                        parts.append(cls_name)
            table_id = getattr(inst, 'table_id', None)
            if table_id is not None and actions is None:
                parts.append(f'goto table {table_id}')
        return ', '.join(parts) if parts else 'drop'

    def snapshot(self) -> List[Dict[str, Any]]:
        """Current flow table across all switches, for GET /api/flows."""
        with self._lock:
            return sorted(
                self._current.values(),
                key=lambda r: (r['dpid'], r['table'], -r['priority']),
            )
