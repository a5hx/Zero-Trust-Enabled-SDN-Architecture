"""Replicas re-verify the controller's trust arithmetic (Phase 6).

The ledger made trust records tamper-evident *after* they were written: a
retroactive edit breaks the hash chain. It said nothing about whether a record
was honest when it was written. The controller computes every score and the
replicas, until now, stored whatever it sent.

A replica can do better without trusting the controller's arithmetic. Every
TrustUpdate carries the evidence its score was computed from (task status,
latency, claimed and expected load, the anomaly flag) and the score before
and after. The trust weights are static, so a replica holding the same trust
configuration can replay the formula from genesis and check, per record:

    before == the score its own replay holds for that node
    after  == the score its own replay computes from this record's evidence

A record that fails either check is rejected; the rest of the batch is
committed. The replay always advances on the evidence, rejected or not: the
evidence is all a replica has, and skipping it would desynchronise every
later record of that node.

What this cannot catch, by construction: forged *evidence*. A controller that
reports a timeout as a success produces a record whose arithmetic is honest.
Only an independent witness of the evidence (the switches, Phase 2; the
clients) can contradict that. And routing reads the controller's in-memory
score, so a rejection detects a forgery after the fact; it does not stop the
controller acting on it.

Determinism: every replica applies committed entries in the same log order,
runs the same float operations on values that round-trip exactly through
JSON, and so reaches the same verdict.
"""

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Sequence

from contracts.trust_update import TrustUpdate
from trust_engine.trust_calculator import TrustCalculator

#: Recomputed and recorded scores must agree to this. Replay is the same float
#: arithmetic on the same values, so the honest difference is exactly zero;
#: the tolerance only absorbs a different platform's last-bit rounding.
TOLERANCE = 1e-9

#: TrustCalculator's parameters, with its own defaults.
_DEFAULTS = {'alpha': 0.35, 'beta': 0.25, 'gamma': 0.25, 'delta': 0.15,
             'lambda_decay': 0.85, 'initial_score': 0.5}

BEFORE = 'before_mismatch'
AFTER = 'after_mismatch'
CONFIG = 'config_mismatch'


def trust_params(trust_cfg: Optional[Dict[str, Any]]) -> Dict[str, float]:
    """The six numbers the trust formula depends on, from a `trust:` block."""
    cfg = trust_cfg or {}
    return {k: float(cfg.get(k, d)) for k, d in _DEFAULTS.items()}


def config_hash(trust_cfg: Optional[Dict[str, Any]]) -> str:
    """Identifies the trust formula a record was computed under. The
    controller sends it with every batch; a replica with a different one
    rejects the whole batch rather than judge it by the wrong formula."""
    canonical = json.dumps(trust_params(trust_cfg), sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass
class Rejection:
    position: int            # index of the record within its batch
    node: str
    reason: str
    recorded_before: float
    recorded_after: float
    expected_before: Optional[float]
    expected_after: Optional[float]
    timestamp: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class TrustReplay:
    """One replica's independent replay of the trust formula."""

    def __init__(self, trust_cfg: Optional[Dict[str, Any]]) -> None:
        self.params = trust_params(trust_cfg)
        self.hash = config_hash(trust_cfg)
        self._calc = TrustCalculator(**self.params)
        self.checked = 0
        self.rejected = 0

    def score(self, node: str) -> float:
        return self._calc.get_score(node)

    def check(self, updates: Sequence[TrustUpdate],
              batch_config_hash: Optional[str]) -> List[Rejection]:
        """Judge a committed batch, in order, and advance the replay.

        A batch computed under another trust configuration is rejected whole
        and does not advance the replay: its scores mean nothing here.
        """
        if batch_config_hash != self.hash:
            self.checked += len(updates)
            self.rejected += len(updates)
            return [Rejection(i, u.edge_node_id, CONFIG, u.trust_score_before,
                              u.trust_score_after, None, None, u.timestamp)
                    for i, u in enumerate(updates)]
        out: List[Rejection] = []
        for i, u in enumerate(updates):
            expected_before = self._calc.get_score(u.edge_node_id)
            probe = TrustUpdate(**u.to_dict())
            expected_after = self._calc.update(probe)
            reason = None
            if abs(u.trust_score_before - expected_before) > TOLERANCE:
                reason = BEFORE
            if abs(u.trust_score_after - expected_after) > TOLERANCE:
                reason = AFTER          # the score itself is wrong: say so
            if reason is not None:
                out.append(Rejection(i, u.edge_node_id, reason, u.trust_score_before,
                                     u.trust_score_after, expected_before,
                                     expected_after, u.timestamp))
        self.checked += len(updates)
        self.rejected += len(out)
        return out


class BatchRejected(Exception):
    """Every record of a committed batch failed verification. Retrying cannot
    help -- every replica reaches the same verdict -- so the caller must drop
    the batch, not retry it."""

    def __init__(self, rejections: List[Dict[str, Any]]) -> None:
        super().__init__(f'{len(rejections)} trust record(s) rejected by the replicas')
        self.rejections = rejections
