"""PortStatsPoller: turning cumulative per-port byte counters into live bps.

No switch and no os-ken event loop -- handle_reply is fed a faked reply whose
shape (ev.msg.datapath.id, ev.msg.body[*].{port_no,tx_bytes,rx_bytes}) matches a
real OFPPortStatsReply, and time is controlled so the rate is exact.
"""

from types import SimpleNamespace

import controller.port_stats as ps
from controller.port_stats import PortStatsPoller, _OFPP_MAX


class _CapturingBus:
    def __init__(self):
        self.events = []

    def publish(self, topic, **kw):
        self.events.append((topic, kw))


def _reply(dpid, port_counters):
    """port_counters: list of (port_no, tx_bytes, rx_bytes)."""
    body = [
        SimpleNamespace(port_no=p, tx_bytes=tx, rx_bytes=rx)
        for p, tx, rx in port_counters
    ]
    return SimpleNamespace(msg=SimpleNamespace(datapath=SimpleNamespace(id=dpid), body=body))


def test_first_poll_has_no_rate_second_poll_computes_bps(monkeypatch):
    bus = _CapturingBus()
    poller = PortStatsPoller(datapaths={}, bus=bus)

    t = [1000.0]
    monkeypatch.setattr(ps.time, 'time', lambda: t[0])

    # First poll: no previous sample, so rates are zero (baseline only).
    poller.handle_reply(_reply(1, [(1, 0, 0)]))
    assert bus.events[-1][1]['ports'][0]['tx_bps'] == 0.0

    # 1 second later, port 1 has sent 1250 bytes and received 2500 bytes.
    t[0] = 1001.0
    poller.handle_reply(_reply(1, [(1, 1250, 2500)]))
    port = bus.events[-1][1]['ports'][0]
    assert port['tx_bps'] == 1250 * 8      # 10000 bps
    assert port['rx_bps'] == 2500 * 8      # 20000 bps
    assert port['total_bps'] == (1250 + 2500) * 8


def test_reserved_ports_are_skipped(monkeypatch):
    bus = _CapturingBus()
    poller = PortStatsPoller(datapaths={}, bus=bus)
    monkeypatch.setattr(ps.time, 'time', lambda: 5.0)

    poller.handle_reply(_reply(1, [(1, 0, 0), (_OFPP_MAX, 999, 999)]))
    ports = bus.events[-1][1]['ports']
    assert [p['port'] for p in ports] == [1]  # the reserved port is filtered out


def test_counter_reset_does_not_produce_negative_rate(monkeypatch):
    bus = _CapturingBus()
    poller = PortStatsPoller(datapaths={}, bus=bus)
    t = [0.0]
    monkeypatch.setattr(ps.time, 'time', lambda: t[0])

    poller.handle_reply(_reply(1, [(1, 10_000, 10_000)]))
    t[0] = 1.0
    # Port flapped: counters reset to a smaller value.
    poller.handle_reply(_reply(1, [(1, 5, 5)]))
    port = bus.events[-1][1]['ports'][0]
    assert port['tx_bps'] == 0.0 and port['rx_bps'] == 0.0


def test_snapshot_sorted_by_dpid_then_port(monkeypatch):
    bus = _CapturingBus()
    poller = PortStatsPoller(datapaths={}, bus=bus)
    monkeypatch.setattr(ps.time, 'time', lambda: 1.0)

    poller.handle_reply(_reply(2, [(3, 0, 0), (1, 0, 0)]))
    poller.handle_reply(_reply(1, [(2, 0, 0)]))
    snap = poller.snapshot()
    assert [(p['dpid'], p['port']) for p in snap] == [(1, 2), (2, 1), (2, 3)]
