"""Block schema data contract for the Zero Trust blockchain ledger."""

from dataclasses import dataclass, field
from typing import Any, Dict, List
from contracts.trust_update import TrustUpdate
import hashlib
import json
import time


@dataclass
class Block:
    """Represents a single block in the trust-update blockchain.

    Each block contains a batch of TrustUpdate records, a Merkle root
    computed over those records, and a SHA-256 hash linking it to the
    previous block in the chain.
    """

    index: int
    timestamp: float = field(default_factory=time.time)
    previous_hash: str = '0' * 64
    merkle_root: str = ''
    proposer_id: str = 'controller'
    raft_term: int = 0  # Placeholder — RAFT added in Semester 2
    trust_updates: List[TrustUpdate] = field(default_factory=list)
    hash: str = ''

    def compute_hash(self) -> str:
        """Compute SHA-256 hash over the block header fields."""
        header = {
            'index': self.index,
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
            'merkle_root': self.merkle_root,
            'proposer_id': self.proposer_id,
            'raft_term': self.raft_term,
        }
        return hashlib.sha256(
            json.dumps(header, sort_keys=True).encode()
        ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """The whole block as plain JSON-able data: header, hash and updates.

        Used to ship a committed block from a RAFT replica to the controller
        (blockchain/raft_replica.py -> RemoteRaftBackend), which rebuilds it
        with `from_dict` and re-validates it with its own `Ledger.append` --
        so the controller never takes a replica's word that a block is sound.
        """
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
            'merkle_root': self.merkle_root,
            'proposer_id': self.proposer_id,
            'raft_term': self.raft_term,
            'trust_updates': [u.to_dict() for u in self.trust_updates],
            'hash': self.hash,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Block':
        """Inverse of `to_dict`. Takes `hash` as given -- it is *checked*, not
        recomputed, by whoever appends the block (`Ledger.append`)."""
        return cls(
            index=int(data['index']),
            timestamp=float(data['timestamp']),
            previous_hash=data['previous_hash'],
            merkle_root=data['merkle_root'],
            proposer_id=data['proposer_id'],
            raft_term=int(data['raft_term']),
            trust_updates=[TrustUpdate(**u) for u in data['trust_updates']],
            hash=data['hash'],
        )
