"""Trust-ledger commit seam.

The controller batches TrustUpdate records and hands them to this interface. Sprint 1
runs `LocalLedgerBackend`, which appends directly to the in-memory chain. Sprint 3
implements RAFT in `blockchain/raft.py` and drops in a `RaftBackend` — the controller
does not change.

`Block.raft_term` already exists in the schema and is already inside the block's hash
preimage (see contracts/block_schema.py::compute_hash), so a RAFT backend can populate
the term without altering how blocks hash.
"""

import logging
import threading
from typing import List, Optional, Protocol

from blockchain.block import build_block
from blockchain.ledger import Ledger
from contracts.block_schema import Block
from contracts.trust_update import TrustUpdate

logger = logging.getLogger(__name__)


class CommitBackend(Protocol):
    """What the controller needs from any ledger backend."""

    def commit(self, updates: List[TrustUpdate]) -> Optional[Block]:
        """Durably record a batch of trust updates as a block.

        Returns:
            The committed Block, or None if the commit was rejected.
        """
        ...

    def latest_score(self, node_id: str) -> Optional[float]:
        """Most recent trust score recorded for a node, or None if never seen."""
        ...

    def verify(self) -> bool:
        """Full-chain integrity check (backs GET /ledger/verify)."""
        ...

    def chain_length(self) -> int:
        ...


class LocalLedgerBackend:
    """Single-replica backend: append straight to the in-memory Ledger.

    Thread-safe, because the controller commits from OpenFlow event handlers while
    the REST API reads from its own HTTP threads (os-ken's hub is `native`, i.e.
    real OS threads).
    """

    def __init__(self, ledger: Optional[Ledger] = None, proposer_id: str = 'controller') -> None:
        self._ledger = ledger if ledger is not None else Ledger()
        self._proposer_id = proposer_id
        self._lock = threading.Lock()

    @property
    def ledger(self) -> Ledger:
        return self._ledger

    def commit(self, updates: List[TrustUpdate]) -> Optional[Block]:
        if not updates:
            return None

        with self._lock:
            block = build_block(
                index=self._ledger.get_chain_length(),
                previous_hash=self._ledger.head_hash(),
                updates=list(updates),
                proposer_id=self._proposer_id,
            )
            if not self._ledger.append(block):
                logger.error("Block %d REJECTED by ledger", block.index)
                return None

        logger.info("Block %d committed (%d updates)", block.index, len(updates))
        return block

    def latest_score(self, node_id: str) -> Optional[float]:
        with self._lock:
            return self._ledger.latest_trust_score(node_id)

    def verify(self) -> bool:
        with self._lock:
            return self._ledger.is_valid_chain()

    def chain_length(self) -> int:
        with self._lock:
            return self._ledger.get_chain_length()
