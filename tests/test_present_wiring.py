"""PRESENT-80 wiring: config-driven authenticator selection, and agreement
between the iot_client's response computation and the controller's verifier.

No HTTP and no Mininet -- the client's _compute_auth_response is pure, so it can
be checked directly against the server-side Present80Authenticator.
"""

import pytest

from controller.trust_balancer import _build_authenticator
from security.authenticator import (
    AuthError, HmacAuthenticator, NullAuthenticator, Present80Authenticator,
)
from simulation.iot_client import _compute_auth_response

_KEY_HEX = "00112233445566778899"


def test_build_authenticator_selects_present80():
    auth = _build_authenticator({'security': {
        'auth_scheme': 'present80', 'shared_key_hex': _KEY_HEX,
    }})
    assert isinstance(auth, Present80Authenticator)


def test_build_authenticator_present80_requires_key():
    with pytest.raises(ValueError):
        _build_authenticator({'security': {'auth_scheme': 'present80'}})


def test_build_authenticator_hmac_and_null():
    assert isinstance(
        _build_authenticator({'security': {'auth_scheme': 'hmac'}}), HmacAuthenticator)
    assert isinstance(
        _build_authenticator({'security': {'auth_scheme': 'null'}}), NullAuthenticator)


def test_build_authenticator_defaults_to_hmac_when_absent():
    # Older configs with no security block keep Sprint 1 behaviour.
    assert isinstance(_build_authenticator({}), HmacAuthenticator)


def test_build_authenticator_rejects_unknown_scheme():
    with pytest.raises(ValueError):
        _build_authenticator({'security': {'auth_scheme': 'rot13'}})


def test_client_and_server_agree_on_present80_handshake():
    """The response the iot_client computes must be exactly what the controller
    verifies -- the real cross-component contract."""
    key = bytes.fromhex(_KEY_HEX)
    server = Present80Authenticator(shared_key=key)

    nonce = server.issue_challenge('iot1')
    client_response = _compute_auth_response('present80', key, 'iot1', nonce)
    token = server.verify_response('iot1', client_response)
    assert token and server.is_authenticated('iot1')


def test_wrong_key_client_is_denied_by_server():
    key = bytes.fromhex(_KEY_HEX)
    wrong = bytes(b ^ 0xFF for b in key)   # exactly how topology.py builds it
    server = Present80Authenticator(shared_key=key)

    nonce = server.issue_challenge('iot12')
    bad_response = _compute_auth_response('present80', wrong, 'iot12', nonce)
    with pytest.raises(AuthError):
        server.verify_response('iot12', bad_response)


def test_client_hmac_scheme_matches_hmac_authenticator():
    key = b'zero-trust-sdn-demo-shared-key'
    server = HmacAuthenticator(shared_key=key)
    nonce = server.issue_challenge('iot1')
    client_response = _compute_auth_response('hmac', key, 'iot1', nonce)
    assert server.verify_response('iot1', client_response)
