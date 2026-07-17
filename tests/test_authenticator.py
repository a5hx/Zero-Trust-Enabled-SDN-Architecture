"""Present80Authenticator: challenge-response device admission.

Covers the accept path, the malicious-device reject path (wrong key), and the
replay/lifecycle edges. Uses the real PRESENT-80 cipher, not a mock.
"""

import time

import pytest

from security.authenticator import AuthError, Present80Authenticator
from security.present_cipher import encrypt_bytes

_KEY = bytes(range(10))          # 10 bytes = 80-bit shared key
_WRONG_KEY = bytes(range(10, 20))


def _legitimate_response(key: bytes, nonce: bytes) -> bytes:
    """What a device holding `key` computes for the challenge."""
    return encrypt_bytes(key, nonce)


def test_legitimate_device_is_admitted():
    auth = Present80Authenticator(shared_key=_KEY)
    nonce = auth.issue_challenge('iot1')
    token = auth.verify_response('iot1', _legitimate_response(_KEY, nonce))
    assert token and auth.is_authenticated('iot1')


def test_wrong_key_device_is_denied():
    """The malicious-IoT case: a device without the shared key cannot produce
    the response and is refused before any trust/routing logic runs."""
    auth = Present80Authenticator(shared_key=_KEY)
    nonce = auth.issue_challenge('rogue')
    with pytest.raises(AuthError):
        auth.verify_response('rogue', _legitimate_response(_WRONG_KEY, nonce))
    assert not auth.is_authenticated('rogue')


def test_response_without_challenge_is_denied():
    auth = Present80Authenticator(shared_key=_KEY)
    with pytest.raises(AuthError):
        auth.verify_response('iot1', b'\x00' * 8)


def test_expired_nonce_is_rejected(monkeypatch):
    auth = Present80Authenticator(shared_key=_KEY)
    nonce = auth.issue_challenge('iot1')
    # Jump time forward past the 30s TTL.
    import security.authenticator as mod
    real_time = time.time()
    monkeypatch.setattr(mod.time, 'time', lambda: real_time + mod.NONCE_TTL_S + 1)
    with pytest.raises(AuthError):
        auth.verify_response('iot1', _legitimate_response(_KEY, nonce))


def test_nonce_is_single_use():
    """A consumed challenge cannot be replayed even with the correct response."""
    auth = Present80Authenticator(shared_key=_KEY)
    nonce = auth.issue_challenge('iot1')
    auth.verify_response('iot1', _legitimate_response(_KEY, nonce))
    with pytest.raises(AuthError):
        auth.verify_response('iot1', _legitimate_response(_KEY, nonce))


def test_key_must_be_80_bits():
    with pytest.raises(ValueError):
        Present80Authenticator(shared_key=b'\x00' * 8)


def test_fresh_nonce_each_challenge():
    auth = Present80Authenticator(shared_key=_KEY)
    nonces = {auth.issue_challenge('iot1') for _ in range(20)}
    assert len(nonces) == 20  # 64-bit random, collisions astronomically unlikely
