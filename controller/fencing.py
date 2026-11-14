"""Multi-controller fencing: one writing controller per generation.

Step 1 of the post-review multi-controller plan (docs/MULTI_CONTROLLER.md).
With fencing on, the controller that routes and enforces is the one holding
the current *generation*, a number issued by the ledger's Raft cluster
(blockchain/commit_backend.py, CONTROLLER_CLAIM entries). The generation is
enforced at the two places the controller writes:

* the switches -- the controller claims OpenFlow ROLE_MASTER with the
  generation as its generation_id. A switch refuses a MASTER or SLAVE request
  whose generation_id is older than the newest it has seen (OFPRRFC_STALE),
  and a new MASTER demotes the old one to SLAVE, whose FlowMods the switch
  then refuses (OFPBRC_IS_SLAVE);
* the ledger -- every trust batch carries the generation, and the replicas
  refuse batches from any other generation once one has been claimed.

What the protocol does NOT do, and this module therefore must
----------------------------------------------------------------
* A controller starts every switch connection in role EQUAL, which can write
  and which a new MASTER does not demote (OpenFlow 1.3, 6.3.5: only other
  MASTERs become SLAVE). So the primary installs nothing on a switch until
  that switch has CONFIRMED it as MASTER: until then the datapath is held
  here, not registered for writes.
* A stale role request is refused but leaves the connection EQUAL. An honest
  controller that is told it is stale stops writing (that is what `fenced`
  records); a dishonest one could keep writing as EQUAL. Cutting that off
  needs the switch's management plane (removing the controller target),
  which is out of this module's reach -- see docs/MULTI_CONTROLLER.md.

The state machine here is plain Python, so tests drive it without os-ken.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, Optional

PENDING = 'pending'      # role request sent, no answer yet: do not write
MASTER = 'master'        # confirmed: this controller may write to the switch
SLAVE = 'slave'          # demoted (or asked to be): read-only
STALE = 'stale'          # the switch has seen a newer generation: fenced
REFUSED = 'refused'      # any other role-request failure


@dataclasses.dataclass(frozen=True)
class FencingConfig:
    """`controller.fencing` in the config. Off by default: with it off no
    role request is sent, every switch stays EQUAL, and the controller
    behaves exactly as it did before multi-controller work began."""
    enabled: bool = False
    controller_id: str = 'primary'

    @classmethod
    def from_config(cls, ctrl_cfg: Optional[Dict[str, Any]]) -> 'FencingConfig':
        block = (ctrl_cfg or {}).get('fencing') or {}
        return cls(enabled=bool(block.get('enabled', False)),
                   controller_id=str(block.get('controller_id', 'primary')))


class Fence:
    """Per-switch role state for one controller and one generation."""

    def __init__(self, generation: int) -> None:
        if generation < 1:
            raise ValueError('a fencing generation is issued by the cluster and starts at 1')
        self.generation = int(generation)
        self.roles: Dict[int, str] = {}
        self.codes: Dict[int, int] = {}
        #: Set once any switch says this controller is stale or demotes it:
        #: from then on this controller writes nothing anywhere.
        self.fenced = False
        self.fenced_reason: Optional[str] = None

    # -- transitions -------------------------------------------------------- #
    def requested(self, dpid: int) -> None:
        self.roles[dpid] = PENDING

    def on_role_reply(self, dpid: int, role: str, generation_id: Optional[int]) -> bool:
        """Record a RoleReply. True when this switch is now writable. A reply
        naming a newer generation than ours means someone else already holds
        the switch, so we are fenced even if the role reads MASTER."""
        if generation_id is not None and _is_newer(int(generation_id), self.generation):
            self._fence(dpid, STALE, f'switch {dpid} reports generation {generation_id}')
            return False
        self.roles[dpid] = role
        if role == MASTER and not self.fenced:
            return True
        if role == SLAVE:
            self._fence(dpid, SLAVE, f'switch {dpid} has this controller as SLAVE')
        return False

    def on_role_failed(self, dpid: int, stale: bool, code: int) -> None:
        self.codes[dpid] = int(code)
        self._fence(dpid, STALE if stale else REFUSED,
                    f'switch {dpid} refused the MASTER request '
                    f'({"stale generation" if stale else f"code {code}"})')

    def on_is_slave_error(self, dpid: int) -> None:
        """The switch refused a write because this controller is SLAVE: a
        newer controller has claimed MASTER since our role was confirmed."""
        self._fence(dpid, SLAVE, f'switch {dpid} refused a write: controller demoted to SLAVE')

    def forget(self, dpid: int) -> None:
        self.roles.pop(dpid, None)
        self.codes.pop(dpid, None)

    def _fence(self, dpid: int, role: str, reason: str) -> None:
        self.roles[dpid] = role
        if not self.fenced:
            self.fenced = True
            self.fenced_reason = reason

    # -- queries ------------------------------------------------------------ #
    def may_write(self, dpid: int) -> bool:
        return not self.fenced and self.roles.get(dpid) == MASTER

    def status(self) -> Dict[str, Any]:
        return {
            'generation': self.generation,
            'fenced': self.fenced,
            'fenced_reason': self.fenced_reason,
            'switches': {str(k): v for k, v in sorted(self.roles.items())},
            'masters': sum(1 for r in self.roles.values() if r == MASTER),
        }


def _is_newer(a: int, b: int) -> bool:
    """`a` is a newer generation than `b` under OpenFlow's rule: the signed
    64-bit difference, so the comparison survives wrap-around."""
    diff = (a - b) & 0xFFFFFFFFFFFFFFFF
    return 0 < diff < (1 << 63)


def role_name(ofp: Any, role: int) -> str:
    """OpenFlow role constant -> this module's name."""
    if role == ofp.OFPCR_ROLE_MASTER:
        return MASTER
    if role == ofp.OFPCR_ROLE_SLAVE:
        return SLAVE
    if role == ofp.OFPCR_ROLE_EQUAL:
        return 'equal'
    return f'role {role}'
