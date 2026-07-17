"""Per-port byte-counter polling, for the dashboard's link-load view.

Companion to controller/flow_stats.py, same design and for the same reason: the
controller never sees data-plane packets after a rule is installed, but every
switch keeps cumulative byte/packet counters per *port*. OFPPortStatsRequest
reads them; diffing between two polls gives the real bits-per-second crossing
each link, which the dashboard uses to colour/weight links by load.

Honesty note (worth a line in the report, same spirit as flow_stats.py): this
reports the *measured* throughput in bits per second, not a percentage of link
capacity. On Mininet's TCLink over OVS the tc-imposed link rate is not something
the switch reports back reliably (the port's advertised speed reflects the veth,
not the tc qdisc), so turning bps into a "% utilised" would mean inventing a
capacity the controller cannot actually observe. The dashboard therefore scales
link load relative to the busiest link in view and prints the measured bps -- a
checkable number, not a fabricated ratio. This is display/telemetry only; it
does not feed the EdgeScore (deck fidelity -- see DIRECTION.md).

Runs as its own os-ken hub greenthread. Replies arrive as os-ken events on
TrustBalancerApp (a plain object can't register handlers) which forwards them to
handle_reply().
"""

import logging
import threading
import time
from typing import Any, Dict, List, Tuple

from os_ken.lib import hub

logger = logging.getLogger(__name__)

# Ports at or above this number are OpenFlow reserved ports (LOCAL, CONTROLLER,
# etc.), not physical links -- skip them in the link-load view.
_OFPP_MAX = 0xffffff00


class PortStatsPoller:
    """Polls every connected switch for per-port counters at a fixed interval."""

    def __init__(
        self,
        datapaths: Dict[int, Any],
        bus: Any,
        poll_interval_s: float = 1.0,
    ) -> None:
        # Shared reference to TrustBalancerApp._datapaths (not a copy): switches
        # connect after this object is built and must be picked up live.
        self._datapaths = datapaths
        self.bus = bus
        self.poll_interval_s = poll_interval_s
        self._stop = False

        self._lock = threading.Lock()
        # (dpid, port_no) -> last seen {ts, tx_bytes, rx_bytes}
        self._prev: Dict[Tuple[int, int], Dict[str, Any]] = {}
        # (dpid, port_no) -> latest computed rates, for GET /api/ports
        self._current: Dict[Tuple[int, int], Dict[str, Any]] = {}

    def run(self) -> None:
        logger.info("PortStatsPoller started: interval=%.2fs", self.poll_interval_s)
        while not self._stop:
            try:
                self._request_all()
            except Exception:
                logger.exception("PortStatsPoller request cycle failed")
            hub.sleep(self.poll_interval_s)

    def stop(self) -> None:
        self._stop = True

    def _request_all(self) -> None:
        for dp in list(self._datapaths.values()):
            parser = dp.ofproto_parser
            ofproto = dp.ofproto
            dp.send_msg(parser.OFPPortStatsRequest(datapath=dp, port_no=ofproto.OFPP_ANY))

    def handle_reply(self, ev: Any) -> None:
        """One switch's per-port counters. Diff against the previous poll to turn
        cumulative byte counts into a live rate."""
        dpid = ev.msg.datapath.id
        now = time.time()

        ports: List[Dict[str, Any]] = []
        with self._lock:
            for stat in ev.msg.body:
                port_no = stat.port_no
                if port_no >= _OFPP_MAX:
                    continue  # reserved port, not a physical link

                key = (dpid, port_no)
                prev = self._prev.get(key)
                tx_bps = rx_bps = 0.0
                if prev is not None:
                    dt = now - prev['ts']
                    if dt > 0:
                        # max(0, ...) guards a counter reset (port flap / switch
                        # reconnect) from producing a nonsensical negative rate.
                        tx_bps = max(0.0, (stat.tx_bytes - prev['tx_bytes']) * 8 / dt)
                        rx_bps = max(0.0, (stat.rx_bytes - prev['rx_bytes']) * 8 / dt)

                self._prev[key] = {
                    'ts': now, 'tx_bytes': stat.tx_bytes, 'rx_bytes': stat.rx_bytes,
                }
                entry = {
                    'dpid': dpid, 'port': port_no,
                    'tx_bps': round(tx_bps, 1), 'rx_bps': round(rx_bps, 1),
                    'total_bps': round(tx_bps + rx_bps, 1),
                    'tx_bytes': stat.tx_bytes, 'rx_bytes': stat.rx_bytes,
                }
                self._current[key] = entry
                ports.append(entry)

        self.bus.publish('port_stats', dpid=dpid, ports=ports)

    def snapshot(self) -> List[Dict[str, Any]]:
        """Current per-port rates across all switches, for GET /api/ports."""
        with self._lock:
            return sorted(self._current.values(), key=lambda p: (p['dpid'], p['port']))
