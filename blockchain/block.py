"""Block factory for the Zero Trust blockchain ledger."""

import logging
import time
from typing import List, Optional

from contracts.block_schema import Block
from contracts.trust_update import TrustUpdate
from blockchain.merkle import build_merkle_root

logger = logging.getLogger(__name__)


def build_block(
    index: int,
    previous_hash: str,
    updates: List[TrustUpdate],
    proposer_id: str = 'controller',
    raft_term: int = 0,
    timestamp: Optional[float] = None,
) -> Block:
    """Create a fully-formed Block with Merkle root and hash computed.

    Args:
        index: Block sequence number.
        previous_hash: Hash of the previous block in the chain.
        updates: List of TrustUpdate records to include.
        proposer_id: ID of the node proposing this block.
        raft_term: The RAFT term this block was proposed in (0 for the
            single-replica `LocalLedgerBackend`, which has no term). Must be
            set here, before `compute_hash()`, since it is inside the header
            hashed by `Block.compute_hash()` -- see `blockchain/commit_backend.py`'s
            `RaftBackend` for why this makes replication hash-stable.
        timestamp: Explicit block timestamp. Defaults to `time.time()`
            (matching `Block`'s own default) when omitted -- the
            single-replica path. `RaftBackend` always passes the timestamp
            the leader chose at proposal time: it is inside the hash
            preimage, so every replica must use the identical value or they
            compute different hashes for what is supposed to be the same
            block.

    Returns:
        A complete Block with merkle_root and hash fields set.
    """
    merkle_root = build_merkle_root(updates)

    block = Block(
        index=index,
        timestamp=timestamp if timestamp is not None else time.time(),
        previous_hash=previous_hash,
        merkle_root=merkle_root,
        proposer_id=proposer_id,
        raft_term=raft_term,
        trust_updates=updates,
    )
    block.hash = block.compute_hash()

    logger.info(
        "Built block %d with %d updates, merkle_root=%s..., hash=%s...",
        index, len(updates), merkle_root[:12], block.hash[:12],
    )

    return block
