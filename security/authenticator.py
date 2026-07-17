"""Device authentication seam.

The controller talks to this interface, never to a cipher directly. Sprint 1 runs
`NullAuthenticator` (accept-all) so the trust-aware routing demo can be built and
shown without waiting on the cipher. Sprint 2 implements PRESENT-80 in
`security/present_cipher.py` and drops in a `Present80Authenticator` here — the
controller and the `POST /auth/challenge` endpoint do not change.

The five-step challenge–response the project committed to:
    1. device  -> controller : HELLO(device_id)
    2. controller -> device  : CHALLENGE(nonce)          64-bit nonce
    3. device  -> controller : RESPONSE(PRESENT80(key, nonce))
    4. controller            : verify + replay check     nonce TTL 30 s
    5. controller -> device  : SESSION(token) | DENY
"""

import hashlib
import hmac
import logging
import secrets
import time
from typing import Dict, Optional, Protocol

logger = logging.getLogger(__name__)

# Nonces are rejected after this many seconds — the deck's replay-protection TTL.
NONCE_TTL_S = 30.0


class AuthError(Exception):
    """Raised when a device fails authentication."""


class Authenticator(Protocol):
    """What the controller needs from any authentication scheme."""

    def issue_challenge(self, device_id: str) -> bytes:
        """Step 2. Return a fresh nonce for this device."""
        ...

    def verify_response(self, device_id: str, response: bytes) -> str:
        """Steps 4–5. Verify the device's response and return a session token.

        Raises:
            AuthError: if the response is wrong, the nonce is unknown, or the
                nonce has expired (replay).
        """
        ...

    def is_authenticated(self, device_id: str) -> bool:
        """True if this device currently holds a valid session."""
        ...


class NullAuthenticator:
    """Accept-all placeholder. Sprint 1 only.

    Still tracks nonces and sessions with the real lifecycle, so that swapping in
    PRESENT-80 changes only how the response is *checked*, not how the controller
    drives the handshake.
    """

    def __init__(self) -> None:
        self._nonces: Dict[str, tuple[bytes, float]] = {}
        self._sessions: Dict[str, str] = {}
        logger.warning(
            "NullAuthenticator active — all devices are accepted without "
            "verification. Replace with Present80Authenticator in Sprint 2."
        )

    def issue_challenge(self, device_id: str) -> bytes:
        nonce = secrets.token_bytes(8)  # 64-bit, per the SRS
        self._nonces[device_id] = (nonce, time.time())
        return nonce

    def verify_response(self, device_id: str, response: bytes) -> str:
        entry = self._nonces.pop(device_id, None)
        if entry is None:
            raise AuthError(f"No outstanding challenge for {device_id}")

        _nonce, issued_at = entry
        if time.time() - issued_at > NONCE_TTL_S:
            raise AuthError(f"Nonce for {device_id} expired (replay protection)")

        # A real authenticator checks `response` here. This one does not.
        token = secrets.token_hex(16)
        self._sessions[device_id] = token
        return token

    def is_authenticated(self, device_id: str) -> bool:
        return device_id in self._sessions


class Present80Authenticator:
    """Challenge-response device admission using the PRESENT-80 cipher.

    This is the Sprint 2 realisation of the deck's five-step handshake (see the
    module docstring). The response a device must return is the challenge nonce
    encrypted under the shared 80-bit key with PRESENT-80:

        RESPONSE = PRESENT80(key, nonce)          (step 3)

    The controller re-derives the same value and compares in constant time. A
    device that does not hold the key -- the "malicious IoT device" case in the
    adversary model -- cannot produce it and is denied at admission, before any
    trust/routing logic ever sees it. Device binding comes from the per-device
    nonce map: verify_response only accepts the response to the exact nonce this
    controller issued to that device_id.

    Drop-in for HmacAuthenticator: same Authenticator protocol, same 64-bit
    nonce and 30 s replay TTL, so nothing in the controller or the
    /auth endpoints changes when this replaces it. See security.present_cipher
    for the cipher itself (pinned to published test vectors).
    """

    def __init__(self, shared_key: bytes) -> None:
        if len(shared_key) != 10:
            raise ValueError(
                f"PRESENT-80 key must be 10 bytes (80 bits), got {len(shared_key)}"
            )
        self._key = shared_key
        self._nonces: Dict[str, tuple[bytes, float]] = {}
        self._sessions: Dict[str, str] = {}

    def issue_challenge(self, device_id: str) -> bytes:
        nonce = secrets.token_bytes(8)  # 64-bit, per the SRS
        self._nonces[device_id] = (nonce, time.time())
        return nonce

    def expected_response(self, nonce: bytes) -> bytes:
        """What a legitimate device holding the shared key must send back:
        the nonce encrypted under PRESENT-80."""
        from security.present_cipher import encrypt_bytes
        return encrypt_bytes(self._key, nonce)

    def verify_response(self, device_id: str, response: bytes) -> str:
        entry = self._nonces.pop(device_id, None)
        if entry is None:
            raise AuthError(f"No outstanding challenge for {device_id}")

        nonce, issued_at = entry
        if time.time() - issued_at > NONCE_TTL_S:
            raise AuthError(f"Nonce for {device_id} expired (replay protection)")

        if not hmac.compare_digest(self.expected_response(nonce), response):
            raise AuthError(f"Bad auth response from {device_id}")

        token = secrets.token_hex(16)
        self._sessions[device_id] = token
        return token

    def is_authenticated(self, device_id: str) -> bool:
        return device_id in self._sessions


class HmacAuthenticator:
    """Real (if lightweight) challenge–response, used until PRESENT-80 lands.

    A working trivial auth beats a stubbed sophisticated one: this is genuine
    HMAC-SHA256 verification with real replay protection, not a placeholder. Every
    device shares one pre-shared key (fine for a simulated IoT fleet; a real
    per-device key store is one dict away when needed). Sprint 2 swaps this class
    for `Present80Authenticator` — callers only ever depend on `Authenticator`.
    """

    def __init__(self, shared_key: bytes) -> None:
        self._key = shared_key
        self._nonces: Dict[str, tuple[bytes, float]] = {}
        self._sessions: Dict[str, str] = {}

    def issue_challenge(self, device_id: str) -> bytes:
        nonce = secrets.token_bytes(8)
        self._nonces[device_id] = (nonce, time.time())
        return nonce

    def expected_response(self, device_id: str, nonce: bytes) -> bytes:
        """What a legitimate device holding the shared key must send back."""
        return hmac.new(self._key, device_id.encode() + nonce, hashlib.sha256).digest()

    def verify_response(self, device_id: str, response: bytes) -> str:
        entry = self._nonces.pop(device_id, None)
        if entry is None:
            raise AuthError(f"No outstanding challenge for {device_id}")

        nonce, issued_at = entry
        if time.time() - issued_at > NONCE_TTL_S:
            raise AuthError(f"Nonce for {device_id} expired (replay protection)")

        expected = self.expected_response(device_id, nonce)
        if not hmac.compare_digest(expected, response):
            raise AuthError(f"Bad auth response from {device_id}")

        token = secrets.token_hex(16)
        self._sessions[device_id] = token
        return token

    def is_authenticated(self, device_id: str) -> bool:
        return device_id in self._sessions
