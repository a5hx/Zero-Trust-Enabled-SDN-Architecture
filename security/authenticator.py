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
from typing import Dict, Optional, Protocol, Set

logger = logging.getLogger(__name__)

# Nonces are rejected after this many seconds — the deck's replay-protection TTL.
NONCE_TTL_S = 30.0


# AuthError.kind values. A denial's *reason* is what tells an identity-spoofing
# attempt (correct crypto, wrong source) apart from a device that simply does
# not hold the key -- two different attacks in this project's adversary model
# (plan_adv.md Phase 1: identity spoofing vs. malicious_iot_devices). The
# human-readable message stays exactly as it was; this is a parallel machine-
# readable tag, added because classification must not depend on regexing prose.
AUTH_DENY_NO_CHALLENGE = 'no_challenge'
AUTH_DENY_NONCE_EXPIRED = 'nonce_expired'
AUTH_DENY_BAD_RESPONSE = 'bad_response'
AUTH_DENY_IP_PIN = 'ip_pin'


class AuthError(Exception):
    """Raised when a device fails authentication.

    Carries a structured `kind` (one of the AUTH_DENY_* constants above)
    alongside the message. Defaults to AUTH_DENY_BAD_RESPONSE so any existing
    or third-party raiser that passes only a message still produces a valid
    tag rather than None.
    """

    def __init__(self, message: str, kind: str = AUTH_DENY_BAD_RESPONSE) -> None:
        super().__init__(message)
        self.kind = kind


class IdentityBinding:
    """Which source IP is entitled to a device_id, and how we know.

    WHY THIS IS NOT TRUST-ON-FIRST-USE ANY MORE
    --------------------------------------------
    Live run 9 (2026-08-08) is the first run in this project where an attack
    SUCCEEDED rather than being contained-but-mislabelled, and this class is
    where it succeeded. The rule was "the first source IP to successfully
    authenticate as a device_id is pinned to it", with the check skipped
    entirely when no prior binding existed. That is TOFU, and TOFU gives the
    identity to whoever gets there first:

        08:04:24,194  iot1  handshake dies, Connection reset by peer
        08:04:24,194  iot1  AUTH DENIED -- sending no traffic     <- victim out
        08:04:40,578  iot38 authenticating AS iot1 from this host
        08:04:40,681  iot38 SPOOFING SUCCEEDED -- 130 tasks as iot1

    The real iot1 never claimed "iot1", so there was nothing for the pin to
    compare against and the spoofer's response -- cryptographically correct,
    because the PRESENT-80 key is fleet-wide -- was accepted. Normally the
    legitimate device wins the race by 15 s and none of this shows.

    So identity ownership must not be decided by a race. When the fleet roster
    is known ahead of time -- and here it is, `simulation/addressing.py` assigns
    `iot<N>` -> `10.0.0.<N>` and both topology.py and the controller already
    depend on that being the single source of truth -- the binding is
    PROVISIONED and an unclaimed identity is not up for grabs.

    Semantics, deliberately narrow:
      * device_id IS in the roster -> the provisioned IP is the only one
        accepted, whether or not the device has ever authenticated.
      * device_id is NOT in the roster -> fall back to TOFU, unchanged.
        TOFU is the right default for a population you do not know in advance;
        it is the wrong one for a population you do. Keeping both means this
        can be adopted without requiring every deployment to enumerate devices.

    The denial kind stays AUTH_DENY_IP_PIN either way: it is the same attack
    and the classifier already maps ip_pin -> spoof, so a roster catch is
    reported identically to a TOFU catch with no downstream change.
    """

    def __init__(self, expected_ips: Optional[Dict[str, str]] = None) -> None:
        #: Provisioned device_id -> source IP. Authoritative where present.
        self._expected_ips: Dict[str, str] = dict(expected_ips or {})
        #: Observed device_id -> source IP, for identities with no roster entry.
        self._session_ip: Dict[str, str] = {}
        #: Every device_id that has completed a handshake at least once.
        self._authenticated: Set[str] = set()

    def check(self, device_id: str, source_ip: Optional[str]) -> None:
        """Raise AuthError(AUTH_DENY_IP_PIN) if this host may not be device_id.

        A caller that cannot supply source_ip (unit tests, non-socket
        transports) gets no identity binding at all -- the same as before.
        """
        if source_ip is None:
            return

        provisioned = self._expected_ips.get(device_id)
        if provisioned is not None:
            if provisioned != source_ip:
                raise AuthError(
                    f"{device_id} is provisioned to {provisioned}, request came "
                    f"from {source_ip} (identity spoofing -- correct key, wrong "
                    f"host; the roster binding does not depend on {device_id} "
                    f"ever having authenticated)",
                    AUTH_DENY_IP_PIN,
                )
            return

        pinned = self._session_ip.get(device_id)
        if pinned is not None and pinned != source_ip:
            raise AuthError(
                f"{device_id} is pinned to {pinned}, request came from "
                f"{source_ip} (possible identity spoofing -- correct key, "
                f"wrong source)",
                AUTH_DENY_IP_PIN,
            )

    def bind(self, device_id: str, source_ip: Optional[str]) -> None:
        """Record the observed owner. A no-op for provisioned identities --
        their binding is configuration, not observation."""
        if source_ip is not None and device_id not in self._expected_ips:
            self._session_ip[device_id] = source_ip

    def owner(self, device_id: str) -> Optional[str]:
        return self._expected_ips.get(device_id) or self._session_ip.get(device_id)

    def roster(self) -> Dict[str, str]:
        return dict(self._expected_ips)

    def mark_authenticated(self, device_id: str) -> None:
        self._authenticated.add(device_id)

    def unclaimed(self) -> Dict[str, str]:
        """Roster identities nobody has successfully authenticated as.

        The controller previously could not tell "iot1 has not started yet"
        from "iot1 was knocked off its socket and is out of the run" -- both
        are silence. With a roster it can at least name which identities are
        vacant, which is the precondition for noticing an eviction at all.
        """
        return {d: ip for d, ip in self._expected_ips.items()
                if d not in self._authenticated}


class Authenticator(Protocol):
    """What the controller needs from any authentication scheme."""

    def issue_challenge(self, device_id: str) -> bytes:
        """Step 2. Return a fresh nonce for this device."""
        ...

    def verify_response(
        self, device_id: str, response: bytes, source_ip: Optional[str] = None,
    ) -> str:
        """Steps 4–5. Verify the device's response and return a session token.

        Args:
            source_ip: the request's actual source address, if the caller has
                it (northbound_api.py's self.client_address[0]). Used to pin
                a device_id to the IP that first successfully authenticated
                as it -- see Present80Authenticator's docstring for why this
                matters given the fleet-wide shared key.

        Raises:
            AuthError: if the response is wrong, the nonce is unknown, the
                nonce has expired (replay), or device_id is already pinned to
                a different source_ip (identity spoofing).
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

    def __init__(self, expected_ips: Optional[Dict[str, str]] = None) -> None:
        self._nonces: Dict[str, tuple[bytes, float]] = {}
        self._sessions: Dict[str, str] = {}
        self.binding = IdentityBinding(expected_ips)
        logger.warning(
            "NullAuthenticator active — all devices are accepted without "
            "verification. Replace with Present80Authenticator in Sprint 2."
        )

    def issue_challenge(self, device_id: str) -> bytes:
        nonce = secrets.token_bytes(8)  # 64-bit, per the SRS
        self._nonces[device_id] = (nonce, time.time())
        return nonce

    def verify_response(
        self, device_id: str, response: bytes, source_ip: Optional[str] = None,
    ) -> str:
        entry = self._nonces.pop(device_id, None)
        if entry is None:
            raise AuthError(
                f"No outstanding challenge for {device_id}", AUTH_DENY_NO_CHALLENGE,
            )

        _nonce, issued_at = entry
        if time.time() - issued_at > NONCE_TTL_S:
            raise AuthError(
                f"Nonce for {device_id} expired (replay protection)",
                AUTH_DENY_NONCE_EXPIRED,
            )

        # A real authenticator checks `response` here. This one does not --
        # so the IP-pinning check below is the only identity-spoofing defence
        # NullAuthenticator has.
        self.binding.check(device_id, source_ip)

        token = secrets.token_hex(16)
        self._sessions[device_id] = token
        self.binding.bind(device_id, source_ip)
        self.binding.mark_authenticated(device_id)
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

    Source-IP pinning (plan_adv.md Phase 1's spoofing/replay attack): the
    shared key is fleet-wide, not per-device (see topology.py -- every
    legitimate device gets the identical `good_key_hex`), so PRESENT-80 on
    its own authenticates possession of *the key*, not *the device*. Anyone
    who holds the key can produce a correct response for ANY device_id. The
    simulated fleet's device IPs are static for the whole run (no legitimate
    DHCP/roaming in this topology -- see simulation/addressing.py), so the
    first source IP to successfully authenticate as a device_id is pinned to
    it; a later request presenting a correct response for that device_id
    from a DIFFERENT IP is refused, even though the crypto passed. This is
    the same identity-binding discipline northbound_api.py's /report
    endpoint already applies (client_ip from the socket, never the body) --
    /auth just didn't have it until now.
    """

    def __init__(
        self, shared_key: bytes,
        expected_ips: Optional[Dict[str, str]] = None,
    ) -> None:
        if len(shared_key) != 10:
            raise ValueError(
                f"PRESENT-80 key must be 10 bytes (80 bits), got {len(shared_key)}"
            )
        self._key = shared_key
        self._nonces: Dict[str, tuple[bytes, float]] = {}
        self._sessions: Dict[str, str] = {}
        self.binding = IdentityBinding(expected_ips)

    def issue_challenge(self, device_id: str) -> bytes:
        nonce = secrets.token_bytes(8)  # 64-bit, per the SRS
        self._nonces[device_id] = (nonce, time.time())
        return nonce

    def expected_response(self, nonce: bytes) -> bytes:
        """What a legitimate device holding the shared key must send back:
        the nonce encrypted under PRESENT-80."""
        from security.present_cipher import encrypt_bytes
        return encrypt_bytes(self._key, nonce)

    def verify_response(
        self, device_id: str, response: bytes, source_ip: Optional[str] = None,
    ) -> str:
        entry = self._nonces.pop(device_id, None)
        if entry is None:
            raise AuthError(
                f"No outstanding challenge for {device_id}", AUTH_DENY_NO_CHALLENGE,
            )

        nonce, issued_at = entry
        if time.time() - issued_at > NONCE_TTL_S:
            raise AuthError(
                f"Nonce for {device_id} expired (replay protection)",
                AUTH_DENY_NONCE_EXPIRED,
            )

        if not hmac.compare_digest(self.expected_response(nonce), response):
            raise AuthError(
                f"Bad auth response from {device_id}", AUTH_DENY_BAD_RESPONSE,
            )

        self.binding.check(device_id, source_ip)

        token = secrets.token_hex(16)
        self._sessions[device_id] = token
        self.binding.bind(device_id, source_ip)
        self.binding.mark_authenticated(device_id)
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

    def __init__(
        self, shared_key: bytes,
        expected_ips: Optional[Dict[str, str]] = None,
    ) -> None:
        self._key = shared_key
        self._nonces: Dict[str, tuple[bytes, float]] = {}
        self._sessions: Dict[str, str] = {}
        self.binding = IdentityBinding(expected_ips)

    def issue_challenge(self, device_id: str) -> bytes:
        nonce = secrets.token_bytes(8)
        self._nonces[device_id] = (nonce, time.time())
        return nonce

    def expected_response(self, device_id: str, nonce: bytes) -> bytes:
        """What a legitimate device holding the shared key must send back."""
        return hmac.new(self._key, device_id.encode() + nonce, hashlib.sha256).digest()

    def verify_response(
        self, device_id: str, response: bytes, source_ip: Optional[str] = None,
    ) -> str:
        entry = self._nonces.pop(device_id, None)
        if entry is None:
            raise AuthError(
                f"No outstanding challenge for {device_id}", AUTH_DENY_NO_CHALLENGE,
            )

        nonce, issued_at = entry
        if time.time() - issued_at > NONCE_TTL_S:
            raise AuthError(
                f"Nonce for {device_id} expired (replay protection)",
                AUTH_DENY_NONCE_EXPIRED,
            )

        expected = self.expected_response(device_id, nonce)
        if not hmac.compare_digest(expected, response):
            raise AuthError(
                f"Bad auth response from {device_id}", AUTH_DENY_BAD_RESPONSE,
            )

        # Same source-IP pinning as Present80Authenticator -- see its
        # docstring. The shared key here is fleet-wide too.
        self.binding.check(device_id, source_ip)

        token = secrets.token_hex(16)
        self._sessions[device_id] = token
        self.binding.bind(device_id, source_ip)
        self.binding.mark_authenticated(device_id)
        return token

    def is_authenticated(self, device_id: str) -> bool:
        return device_id in self._sessions
