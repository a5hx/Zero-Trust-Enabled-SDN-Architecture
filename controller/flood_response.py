"""Responding to a flooding client: throttle its NEW connections in the switch.

`controller/flood_detector.py` decides *that* a client is flooding. Until this
module existed that was the end of it -- the paper's "DDoS response is
detection-only" limitation. This is the policy for *what to do*, kept pure (no
I/O, no OpenFlow) so it is testable on its own; `TrustBalancerApp` turns a
`Throttle` into flow rules.

Where the throttle bites. A client's new TCP connection to the virtual IP
misses every per-connection rule and is punted to the controller by the
"new task" rule (priority 250). A throttle installs a per-client rule just
above it (`TrustBalancerApp.PRIO_CLIENT_THROTTLE`, 280), matching only that
client's new connections to the VIP. Connections already admitted keep their
own priority-300 rules and finish normally. Two modes:

* ``meter`` -- new connections pass through a per-client packets-per-second
  meter (``rate_factor`` x an honest device's expected rate), so the client is
  slowed to a fair share rather than cut off. A wrongly judged honest client
  keeps working; a flooder loses everything above its share, and the
  controller is spared the PacketIn storm. A switch without meter support
  falls back to ``drop`` for that switch.
* ``drop`` -- new connections are dropped in the switch for the duration.

Each throttle is a rule with a hard timeout: the switch lifts it on its own. A
client caught again soon after is a repeat offender and is throttled for
twice as long (``initial_s`` doubling up to ``max_s``); after ``forgive_after_s``
without an offence the count resets. ``mode: off`` (the default) keeps the
old detection-only behaviour, so every earlier run's config is unchanged.
"""

import math
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

MODES = ('off', 'meter', 'drop')


@dataclass(frozen=True)
class FloodResponseConfig:
    mode: str = 'off'
    rate_factor: float = 2.0       # meter rate, in multiples of the expected per-device rate
    min_rate_pps: float = 1.0      # never meter below this
    initial_s: float = 10.0        # first throttle
    max_s: float = 300.0           # cap for a repeat offender
    forgive_after_s: float = 600.0  # quiet time after which the offence count resets

    @classmethod
    def from_config(cls, ctrl_cfg: Dict[str, Any]) -> 'FloodResponseConfig':
        block = (ctrl_cfg or {}).get('flood_response') or {}
        cfg = cls(
            mode=str(block.get('mode', 'off')),
            rate_factor=float(block.get('rate_factor', 2.0)),
            min_rate_pps=float(block.get('min_rate_pps', 1.0)),
            initial_s=float(block.get('initial_s', 10.0)),
            max_s=float(block.get('max_s', 300.0)),
            forgive_after_s=float(block.get('forgive_after_s', 600.0)),
        )
        if cfg.mode not in MODES:
            raise ValueError(f"controller.flood_response.mode must be one of {MODES}, not {cfg.mode!r}")
        if cfg.initial_s < 1 or cfg.max_s < cfg.initial_s:
            raise ValueError("flood_response: need 1 <= initial_s <= max_s")
        if cfg.rate_factor <= 0 or cfg.min_rate_pps <= 0:
            raise ValueError("flood_response: rate_factor and min_rate_pps must be positive")
        return cfg


@dataclass(frozen=True)
class Throttle:
    client_ip: str
    mode: str                  # 'meter' or 'drop' (what was asked for)
    rate_pps: Optional[int]    # meter rate; None in drop mode
    duration_s: int            # the rules' hard timeout
    offence: int               # 1 for a first offence, 2 for the next, ...
    until: float               # when the switch lifts it


class FloodResponder:
    """Decides, per tripped flood tell, whether and how hard to throttle."""

    def __init__(self, cfg: FloodResponseConfig, expected_rate_hz: float) -> None:
        self.cfg = cfg
        self.expected_rate_hz = expected_rate_hz
        # client_ip -> (offence count, time of last offence)
        self._offences: Dict[str, Tuple[int, float]] = {}
        self._active: Dict[str, Throttle] = {}

    @property
    def enabled(self) -> bool:
        return self.cfg.mode != 'off'

    def rate_pps(self) -> int:
        return int(math.ceil(max(self.cfg.min_rate_pps, self.expected_rate_hz * self.cfg.rate_factor)))

    def is_throttled(self, client_ip: str, now: float) -> bool:
        t = self._active.get(client_ip)
        return t is not None and t.until > now

    def active(self, now: float) -> Dict[str, Throttle]:
        return {ip: t for ip, t in self._active.items() if t.until > now}

    def on_tripped(self, client_ip: str, now: float) -> Optional[Throttle]:
        """A new throttle for this client, or None (off, or already throttled)."""
        if not self.enabled or self.is_throttled(client_ip, now):
            return None
        count, last = self._offences.get(client_ip, (0, 0.0))
        if count and now - last > self.cfg.forgive_after_s:
            count = 0
        count += 1
        duration = int(min(self.cfg.max_s, self.cfg.initial_s * 2 ** (count - 1)))
        throttle = Throttle(
            client_ip=client_ip, mode=self.cfg.mode,
            rate_pps=self.rate_pps() if self.cfg.mode == 'meter' else None,
            duration_s=max(1, duration), offence=count, until=now + max(1, duration),
        )
        self._offences[client_ip] = (count, now)
        self._active[client_ip] = throttle
        return throttle
