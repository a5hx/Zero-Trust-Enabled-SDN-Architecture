"""PRESENT-80 lightweight block cipher (Bogdanov et al., CHES 2007).

A pure-Python, dependency-free implementation of the 64-bit-block, 80-bit-key
variant the project committed to for IoT device authentication. It is the
cryptographic primitive behind security.authenticator.Present80Authenticator.

Scope and honesty (state this in the report / viva): this is a *reference*
implementation used to demonstrate a lightweight-crypto authentication
architecture on constrained edge/IoT devices. It is not constant-time and makes
no side-channel guarantees -- PRESENT-80's own 80-bit key is below modern
key-length recommendations regardless. The contribution is the architecture
(challenge-response device admission behind a swappable Authenticator seam), not
a production cipher.

Correctness is pinned to the four published PRESENT-80 test vectors in
tests/test_present.py, so this file is checkable against the literature rather
than trusted.

Structure per the specification:
    - 64-bit block, 80-bit key, 31 rounds.
    - Each round: addRoundKey -> sBoxLayer (16x 4-bit S-box) -> pLayer (bit
      permutation). A final addRoundKey follows the 31st round.
    - Key schedule produces 32 round keys from the 80-bit key register.
"""

from typing import List

# 4-bit S-box, S[x] (PRESENT specification, Table 1).
_SBOX: List[int] = [
    0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2,
]

_ROUNDS = 31
_MASK64 = (1 << 64) - 1
_MASK80 = (1 << 80) - 1


def _sbox_layer(state: int) -> int:
    """Apply the 4-bit S-box to each of the 16 nibbles of the 64-bit state."""
    out = 0
    for i in range(16):
        out |= _SBOX[(state >> (4 * i)) & 0xF] << (4 * i)
    return out


def _p_layer(state: int) -> int:
    """Bit permutation: input bit i moves to output position P(i), where
    P(i) = (16*i) mod 63 for 0 <= i < 63, and P(63) = 63."""
    out = 0
    for i in range(64):
        if (state >> i) & 1:
            pos = 63 if i == 63 else (16 * i) % 63
            out |= 1 << pos
    return out


def _round_keys(key: int) -> List[int]:
    """Derive the 32 round keys from the 80-bit key register.

    Round key i is the leftmost 64 bits of the register. Between extractions the
    register is: rotated left 61 bits, its top nibble passed through the S-box,
    and a 5-bit round counter XORed into bits 19..15.
    """
    keys: List[int] = []
    reg = key & _MASK80
    for rnd in range(1, 33):
        keys.append(reg >> 16)                       # leftmost 64 bits
        reg = ((reg << 61) | (reg >> 19)) & _MASK80  # rotate left 61
        reg = (reg & ~(0xF << 76)) | (_SBOX[reg >> 76] << 76)  # S-box top nibble
        reg ^= rnd << 15                             # XOR round counter
    return keys


def encrypt_block(key: int, plaintext: int) -> int:
    """Encrypt one 64-bit block under an 80-bit key. Both are big-endian ints.

    Args:
        key: 80-bit key as an integer (bits above 80 are ignored).
        plaintext: 64-bit block as an integer.

    Returns:
        The 64-bit ciphertext block as an integer.
    """
    round_keys = _round_keys(key)
    state = plaintext & _MASK64
    for r in range(_ROUNDS):
        state = _sbox_layer((state ^ round_keys[r]) & _MASK64)
        state = _p_layer(state)
    return (state ^ round_keys[_ROUNDS]) & _MASK64


def encrypt_bytes(key: bytes, block: bytes) -> bytes:
    """Byte-oriented wrapper over encrypt_block.

    Args:
        key: exactly 10 bytes (80 bits), big-endian.
        block: exactly 8 bytes (64 bits), big-endian.

    Returns:
        8 ciphertext bytes, big-endian.
    """
    if len(key) != 10:
        raise ValueError(f"PRESENT-80 key must be 10 bytes (80 bits), got {len(key)}")
    if len(block) != 8:
        raise ValueError(f"PRESENT block must be 8 bytes (64 bits), got {len(block)}")
    ct = encrypt_block(int.from_bytes(key, 'big'), int.from_bytes(block, 'big'))
    return ct.to_bytes(8, 'big')
