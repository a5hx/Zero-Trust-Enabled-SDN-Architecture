"""Merkle tree construction and verification for trust-update records."""

import hashlib
import json
from typing import List, Tuple, Optional

from contracts.trust_update import TrustUpdate


def _hash_leaf(update: TrustUpdate) -> str:
    """Hash a single TrustUpdate leaf using SHA-256."""
    payload = json.dumps(update.to_dict(), sort_keys=True, default=str).encode()
    return hashlib.sha256(payload).hexdigest()


def _hash_pair(left: str, right: str) -> str:
    """Hash two sibling nodes — sort before concatenation for determinism."""
    pair = ''.join(sorted([left, right]))
    return hashlib.sha256(pair.encode()).hexdigest()


def build_merkle_root(updates: List[TrustUpdate]) -> str:
    """Build a Merkle root from a list of TrustUpdate records.

    Args:
        updates: List of TrustUpdate objects to hash into a tree.

    Returns:
        Hex-encoded SHA-256 Merkle root string.
        If updates is empty, returns sha256('EMPTY').
    """
    if not updates:
        return hashlib.sha256(b'EMPTY').hexdigest()

    # Hash all leaves
    layer: List[str] = [_hash_leaf(u) for u in updates]

    # Build tree bottom-up
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])  # Duplicate last if odd
        next_layer: List[str] = []
        for i in range(0, len(layer), 2):
            next_layer.append(_hash_pair(layer[i], layer[i + 1]))
        layer = next_layer

    return layer[0]


def _build_proof(updates: List[TrustUpdate], target_index: int) -> List[Tuple[str, str]]:
    """Build a Merkle proof path for the record at target_index.

    Returns:
        List of (sibling_hash, position) tuples where position is 'left' or 'right'.
    """
    if not updates or target_index < 0 or target_index >= len(updates):
        return []

    layer: List[str] = [_hash_leaf(u) for u in updates]
    proof: List[Tuple[str, str]] = []
    idx = target_index

    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])

        # Determine sibling
        if idx % 2 == 0:
            sibling = layer[idx + 1]
            proof.append((sibling, 'right'))
        else:
            sibling = layer[idx - 1]
            proof.append((sibling, 'left'))

        # Build next layer
        next_layer: List[str] = []
        for i in range(0, len(layer), 2):
            next_layer.append(_hash_pair(layer[i], layer[i + 1]))
        layer = next_layer
        idx = idx // 2

    return proof


def verify_record(update: TrustUpdate, proof: List[Tuple[str, str]], root: str) -> bool:
    """Verify that a TrustUpdate record belongs to the tree with the given root.

    Args:
        update: The TrustUpdate to verify.
        proof: Sibling-hash proof path from _build_proof().
        root: Expected Merkle root.

    Returns:
        True if the record can be verified against the root.
    """
    current = _hash_leaf(update)

    for sibling_hash, position in proof:
        current = _hash_pair(current, sibling_hash)

    return current == root
