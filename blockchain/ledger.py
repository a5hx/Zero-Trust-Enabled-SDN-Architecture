"""Blockchain ledger for immutable trust-update storage."""

import logging
from typing import Dict, Optional, List

from contracts.block_schema import Block
from contracts.trust_update import TrustUpdate
from blockchain.merkle import build_merkle_root
from blockchain.block import build_block

logger = logging.getLogger(__name__)


class Ledger:
    """Append-only blockchain ledger storing batches of TrustUpdate records.

    The ledger begins with a genesis block and validates every appended
    block for index continuity, hash chaining, and Merkle-root integrity.
    """

    def __init__(self) -> None:
        """Create a new ledger with a genesis block."""
        genesis = Block(
            index=0,
            previous_hash='0' * 64,
            merkle_root='GENESIS',
            proposer_id='genesis',
        )
        genesis.hash = genesis.compute_hash()
        self._chain: List[Block] = [genesis]
        logger.info("Ledger initialised with genesis block, hash=%s...", genesis.hash[:12])

    def append(self, block: Block) -> bool:
        """Validate and append a block to the chain.

        Validation checks:
            1. Block index is correct (sequential).
            2. previous_hash matches the hash of the last block.
            3. Merkle root matches recomputed root from trust_updates.
            4. Block hash matches recomputed hash.

        Args:
            block: The Block to append.

        Returns:
            True if the block was accepted, False if rejected.
        """
        last = self._chain[-1]

        # Check 1: correct index
        if block.index != last.index + 1:
            logger.warning(
                "Block rejected: expected index %d, got %d",
                last.index + 1, block.index,
            )
            return False

        # Check 2: correct previous_hash
        if block.previous_hash != last.hash:
            logger.warning(
                "Block %d rejected: previous_hash mismatch (expected %s..., got %s...)",
                block.index, last.hash[:12], block.previous_hash[:12],
            )
            return False

        # Check 3: Merkle root integrity
        expected_merkle = build_merkle_root(block.trust_updates)
        if block.merkle_root != expected_merkle:
            logger.warning(
                "Block %d rejected: merkle_root mismatch (expected %s..., got %s...)",
                block.index, expected_merkle[:12], block.merkle_root[:12],
            )
            return False

        # Check 4: hash integrity
        expected_hash = block.compute_hash()
        if block.hash != expected_hash:
            logger.warning(
                "Block %d rejected: hash mismatch (expected %s..., got %s...)",
                block.index, expected_hash[:12], block.hash[:12],
            )
            return False

        self._chain.append(block)
        logger.info(
            "Block %d appended (%d updates), chain length=%d",
            block.index, len(block.trust_updates), len(self._chain),
        )
        return True

    def latest_trust_score(self, node_id: str) -> Optional[float]:
        """Walk the chain newest-first and return the first matching trust_score_after.

        Args:
            node_id: The edge node ID to look up.

        Returns:
            The latest trust score, or None if the node has never been recorded.
        """
        for block in reversed(self._chain):
            for update in reversed(block.trust_updates):
                if update.edge_node_id == node_id:
                    return update.trust_score_after
        return None

    def is_valid_chain(self) -> bool:
        """Validate the entire chain from genesis to tip.

        Returns:
            True if every block passes all validation checks.
        """
        for i in range(1, len(self._chain)):
            block = self._chain[i]
            prev = self._chain[i - 1]

            if block.index != prev.index + 1:
                logger.error("Chain invalid at block %d: bad index", i)
                return False

            if block.previous_hash != prev.hash:
                logger.error("Chain invalid at block %d: previous_hash mismatch", i)
                return False

            expected_merkle = build_merkle_root(block.trust_updates)
            if block.merkle_root != expected_merkle:
                logger.error("Chain invalid at block %d: merkle_root mismatch", i)
                return False

            expected_hash = block.compute_hash()
            if block.hash != expected_hash:
                logger.error("Chain invalid at block %d: hash mismatch", i)
                return False

        return True

    def get_chain_length(self) -> int:
        """Return the number of blocks in the chain (including genesis)."""
        return len(self._chain)

    def get_all_scores(self) -> Dict[str, float]:
        """Return the latest trust score for every node ever recorded.

        Returns:
            Dictionary mapping node_id → latest trust_score_after.
        """
        scores: Dict[str, float] = {}
        for block in self._chain:
            for update in block.trust_updates:
                scores[update.edge_node_id] = update.trust_score_after
        return scores
