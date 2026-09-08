"""Client request-rate flood/DDoS tell. plan_adv.md Phase 1.

controller/trust_balancer.py's `_handle_table_vip` calls this on every new
VIP PacketIn. Deliberately NOT part of flow_monitor.py's per-node 1Hz poll
loop: flooding is a property of the CLIENT (source IP) issuing requests, not
of whichever edge node ends up trying (and maybe failing) to serve them.
Feeding this into an edge node's own anomaly score would repeat the mistake
this project has already been burned by twice on the other side of a
request -- see memory/edgescore-fanout-starvation and
memory/live-run-cascading-quarantine's "correctly isolated attacker vs.
wrongly blamed honest party" discipline: a server drowning under a flood is
not lying about its load, it is telling the truth about being overwhelmed.

Same leaky-bucket persistence shape as evaluate_latency_tell
(controller/flow_monitor.py) on purpose, for the same reason: a source has
to be fast on most of a recent run of samples to trip, one busy-but-legitimate
burst can't flag it, and a genuinely sustained flood can't hide behind one
quiet sample either.
"""

from typing import NamedTuple, Optional


class FloodTell(NamedTuple):
    tripped: bool
    strikes: int
    ratio: Optional[float]  # measured rate as a multiple of expected, or None


def evaluate_flood_tell(
    rate_hz: float,
    expected_rate_hz: float,
    strikes: int,
    flood_ratio: float = 5.0,
    flood_floor_hz: float = 3.0,
    flood_persist: int = 3,
) -> FloodTell:
    """Pure function -- no I/O, no locks -- so it's testable standalone and
    shareable if another caller ever needs the same check.

    Args:
        rate_hz: measured request rate from one source over the current
            window (TrustState.client_request_rate).
        expected_rate_hz: the fleet's normal per-device rate, e.g. derived
            from agents.report_interval_s -- what one honest device is
            configured to send.
        strikes: leaky-bucket level carried over from the previous call.
        flood_ratio: how many multiples of expected_rate_hz counts as "fast".
        flood_floor_hz: absolute floor as well, so a fleet configured with a
            very low expected rate doesn't make ordinary jitter look like a
            multiple (mirrors latency_liar_floor_ms's role in the latency
            tell).
        flood_persist: strikes required before flagging.
    """
    is_fast = (
        expected_rate_hz > 0
        and rate_hz > expected_rate_hz * flood_ratio
        and rate_hz >= flood_floor_hz
    )
    if is_fast:
        strikes = min(flood_persist + 1, strikes + 1)
    else:
        strikes = max(0, strikes - 1)

    ratio = (rate_hz / expected_rate_hz) if expected_rate_hz > 0 else None
    return FloodTell(
        tripped=strikes >= flood_persist, strikes=strikes, ratio=ratio,
    )
