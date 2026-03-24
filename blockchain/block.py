"""Block factory for the Zero Trust blockchain ledger."""

import logging
from typing import List

from contracts.block_schema import Block
from contracts.trust_update import TrustUpdate
from blockchain.merkle import build_merkle_root

logger = logging.getLogger(__name__)


def build_block(
    index: int,
    previous_hash: str,
    updates: List[TrustUpdate],
    proposer_id: str = 'controller',
) -> Block:
    """Create a fully-formed Block with Merkle root and hash computed.

    Args:
        index: Block sequence number.
        previous_hash: Hash of the previous block in the chain.
        updates: List of TrustUpdate records to include.
        proposer_id: ID of the node proposing this block.

    Returns:
        A complete Block with merkle_root and hash fields set.
    """
    merkle_root = build_merkle_root(updates)

    block = Block(
        index=index,
        previous_hash=previous_hash,
        merkle_root=merkle_root,
        proposer_id=proposer_id,
        trust_updates=updates,
    )
    block.hash = block.compute_hash()

    logger.info(
        "Built block %d with %d updates, merkle_root=%s..., hash=%s...",
        index, len(updates), merkle_root[:12], block.hash[:12],
    )

    return block
