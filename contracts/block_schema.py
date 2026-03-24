"""Block schema data contract for the Zero Trust blockchain ledger."""

from dataclasses import dataclass, field
from typing import List
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
