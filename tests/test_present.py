"""PRESENT-80 correctness, pinned to the published test vectors.

The four vectors below are the canonical ones from the PRESENT specification
(Bogdanov et al., CHES 2007, Appendix). If any of these fail, the cipher is
wrong -- they are the literature's own ground truth, not values we invented.
"""

import pytest

from security.present_cipher import encrypt_block, encrypt_bytes

# (key80, plaintext64, expected_ciphertext64)
_VECTORS = [
    (0x00000000000000000000, 0x0000000000000000, 0x5579C1387B228445),
    (0xFFFFFFFFFFFFFFFFFFFF, 0x0000000000000000, 0xE72C46C0F5945049),
    (0x00000000000000000000, 0xFFFFFFFFFFFFFFFF, 0xA112FFC72F68417B),
    (0xFFFFFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x3333DCD3213210D2),
]


@pytest.mark.parametrize("key,plaintext,expected", _VECTORS)
def test_published_vectors(key, plaintext, expected):
    assert encrypt_block(key, plaintext) == expected


def test_encrypt_bytes_matches_int_api():
    key = 0xFFFFFFFFFFFFFFFFFFFF
    pt = 0x0000000000000000
    ct = encrypt_bytes(key.to_bytes(10, 'big'), pt.to_bytes(8, 'big'))
    assert ct == (0xE72C46C0F5945049).to_bytes(8, 'big')


def test_encrypt_bytes_rejects_wrong_key_length():
    with pytest.raises(ValueError):
        encrypt_bytes(b'\x00' * 8, b'\x00' * 8)  # 8-byte key, not 10


def test_encrypt_bytes_rejects_wrong_block_length():
    with pytest.raises(ValueError):
        encrypt_bytes(b'\x00' * 10, b'\x00' * 4)  # 4-byte block, not 8


def test_single_bit_plaintext_change_avalanches():
    """A one-bit change in the plaintext should flip many ciphertext bits --
    a sanity check on diffusion, not a formal property."""
    key = 0x0123456789ABCDEF0123
    a = encrypt_block(key, 0x0000000000000000)
    b = encrypt_block(key, 0x0000000000000001)
    flipped = bin(a ^ b).count('1')
    assert flipped >= 16  # well over half the 64 bits typically flip
