"""A test-only dishonest controller, for measuring the replicas' re-verification
(Phase 6, blockchain/verifier.py).

The replicas can only be shown to catch a forged trust record if the controller
can be made to write one. `controller.debug_forge_trust` does that for one
server from `start_s` seconds after the controller starts:

* ``mode: score`` -- inflate the server's trust by `delta` after each honest
  update, in the record AND in the score routing reads: a controller shielding
  or favouring a server. Every record's arithmetic is now wrong, so the
  replicas should reject every one of them, and only them.
* ``mode: evidence`` -- rewrite the server's task outcomes as fast successes
  with no anomaly before the formula runs. The arithmetic is honest, so the
  replicas cannot see it: the stated limit of re-verification, measured.

Refused unless the environment sets ZTSDN_ALLOW_FORGERY=1, so no ordinary
config can turn a controller dishonest by accident.
"""

import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from contracts.trust_update import TrustUpdate

ENV_GATE = 'ZTSDN_ALLOW_FORGERY'
MODES = ('score', 'evidence')


@dataclass
class TrustForgery:
    node: str
    mode: str
    delta: float = 0.3
    start_s: float = 0.0

    @classmethod
    def from_config(cls, controller_cfg: Optional[Dict[str, Any]],
                    environ: Optional[Dict[str, str]] = None) -> Optional['TrustForgery']:
        spec = (controller_cfg or {}).get('debug_forge_trust')
        if not spec:
            return None
        env = os.environ if environ is None else environ
        if env.get(ENV_GATE) != '1':
            raise ValueError(f'controller.debug_forge_trust makes the controller forge trust '
                             f'records; refusing unless {ENV_GATE}=1 is set')
        unknown = set(spec) - {'node', 'mode', 'delta', 'start_s'}
        if unknown:
            raise ValueError(f'controller.debug_forge_trust: unknown keys {sorted(unknown)}')
        f = cls(node=str(spec['node']), mode=str(spec.get('mode', 'score')),
                delta=float(spec.get('delta', 0.3)), start_s=float(spec.get('start_s', 0.0)))
        if f.mode not in MODES:
            raise ValueError(f'controller.debug_forge_trust.mode must be one of {MODES}')
        return f

    def ground_truth(self) -> Dict[str, Any]:
        return {'node': self.node, 'mode': self.mode, 'delta': self.delta,
                'start_s': self.start_s}


class Forger:
    """Applies a TrustForgery around TrustCalculator.update()."""

    def __init__(self, forgery: TrustForgery, now: Callable[[], float] = time.monotonic) -> None:
        self.forgery = forgery
        self._now = now
        self._t0 = now()
        self.forged = 0

    def _active(self, upd: TrustUpdate) -> bool:
        return (upd.edge_node_id == self.forgery.node
                and self._now() - self._t0 >= self.forgery.start_s)

    def before(self, upd: TrustUpdate) -> None:
        """Evidence mode: rewrite the outcome the formula is about to see."""
        if self.forgery.mode == 'evidence' and self._active(upd):
            upd.task_status = 'success'
            upd.latency_ms = min(upd.latency_ms, 20.0)
            upd.anomaly_flag = False
            upd.cpu_usage = upd.reported_cpu
            self.forged += 1

    def after(self, upd: TrustUpdate, score: float) -> Optional[float]:
        """Score mode: the inflated score to record and route on, or None."""
        if self.forgery.mode != 'score' or not self._active(upd):
            return None
        self.forged += 1
        return min(1.0, score + self.forgery.delta)
