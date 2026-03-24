"""Unit tests for the blockchain ledger, Merkle tree, and block operations.

Tests B-01 through B-05 as specified in the Semester 1 review requirements.
"""

import sys
import os
import hashlib
import pytest

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from blockchain.merkle import build_merkle_root, _build_proof, verify_record
from blockchain.block import build_block
from blockchain.ledger import Ledger
from contracts.trust_update import TrustUpdate


def _make_update(
    node_id: str = 'srv1',
    score_after: float = 0.7,
) -> TrustUpdate:
    """Helper to create a TrustUpdate with minimal fields."""
    return TrustUpdate(
        device_id='iot_test',
        edge_node_id=node_id,
        task_status='success',
        cpu_usage=0.3,
        reported_cpu=0.3,
        latency_ms=20.0,
        trust_score_after=score_after,
    )


class TestBlockchain:
    """B-01 through B-05: Blockchain test suite."""

    def test_b01_append_five_blocks(self) -> None:
        """B-01: Append 5 valid blocks → chain length = 6 (including genesis)."""
        ledger = Ledger()
        for i in range(1, 6):
            updates = [_make_update(f'srv{j}') for j in range(1, 4)]
            block = build_block(
                index=i,
                previous_hash=ledger._chain[-1].hash,
                updates=updates,
            )
            accepted = ledger.append(block)
            assert accepted, f"Block {i} should be accepted"

        assert ledger.get_chain_length() == 6, (
            f"Expected 6 blocks (genesis + 5), got {ledger.get_chain_length()}"
        )
        assert ledger.is_valid_chain()

    def test_b02_tamper_detection(self) -> None:
        """B-02: Tamper trust_score_after in block 3 → is_valid_chain() returns False."""
        ledger = Ledger()
        for i in range(1, 5):
            updates = [_make_update(f'srv{j}', score_after=0.8) for j in range(1, 3)]
            block = build_block(
                index=i,
                previous_hash=ledger._chain[-1].hash,
                updates=updates,
            )
            ledger.append(block)

        # Tamper with block at index 3
        ledger._chain[3].trust_updates[0].trust_score_after = 0.99
        assert not ledger.is_valid_chain(), (
            "Chain should be invalid after tampering trust_score_after"
        )

    def test_b03_wrong_previous_hash(self) -> None:
        """B-03: Block with wrong previous_hash → append() returns False."""
        ledger = Ledger()
        updates = [_make_update()]
        block = build_block(
            index=1,
            previous_hash='bad_hash_' + '0' * 55,  # Wrong hash
            updates=updates,
        )
        accepted = ledger.append(block)
        assert not accepted, "Block with wrong previous_hash should be rejected"

    def test_b04_empty_updates(self) -> None:
        """B-04: Empty updates list → Merkle root = sha256('EMPTY'), block still valid."""
        expected_root = hashlib.sha256(b'EMPTY').hexdigest()
        root = build_merkle_root([])
        assert root == expected_root, f"Empty root mismatch: {root} != {expected_root}"

        # Block with empty updates should still be appendable
        ledger = Ledger()
        block = build_block(
            index=1,
            previous_hash=ledger._chain[-1].hash,
            updates=[],
        )
        accepted = ledger.append(block)
        assert accepted, "Block with empty updates should be accepted"
        assert ledger.is_valid_chain()

    def test_b05_latest_trust_score(self) -> None:
        """B-05: latest_trust_score for known and unknown node → score / None."""
        ledger = Ledger()

        # Add a block with a known node
        updates = [_make_update('srv1', score_after=0.85)]
        block = build_block(
            index=1,
            previous_hash=ledger._chain[-1].hash,
            updates=updates,
        )
        ledger.append(block)

        # Known node
        score = ledger.latest_trust_score('srv1')
        assert score == 0.85, f"Expected 0.85, got {score}"

        # Unknown node
        score = ledger.latest_trust_score('srv_unknown')
        assert score is None, f"Expected None for unknown node, got {score}"
