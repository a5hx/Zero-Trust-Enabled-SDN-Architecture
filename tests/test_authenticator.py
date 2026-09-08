"""Present80Authenticator: challenge-response device admission.

Covers the accept path, the malicious-device reject path (wrong key), and the
replay/lifecycle edges. Uses the real PRESENT-80 cipher, not a mock.
"""

import time

import pytest

from security.authenticator import (
    AUTH_DENY_BAD_RESPONSE,
    AUTH_DENY_IP_PIN,
    AUTH_DENY_NO_CHALLENGE,
    AUTH_DENY_NONCE_EXPIRED,
    NONCE_TTL_S,
    AuthError,
    IdentityBinding,
    Present80Authenticator,
)
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


class TestSourceIpPinning:
    """plan_adv.md Phase 1's spoofing/replay attack: the shared key is
    fleet-wide (topology.py gives every legitimate device the identical
    key), so PRESENT-80 alone authenticates the KEY, not the DEVICE. A
    second host presenting a cryptographically correct response for a
    device_id already pinned to a different source IP must be refused."""

    def test_first_successful_auth_pins_the_device_to_its_source_ip(self):
        auth = Present80Authenticator(shared_key=_KEY)
        nonce = auth.issue_challenge('iot1')
        token = auth.verify_response(
            'iot1', _legitimate_response(_KEY, nonce), source_ip='10.0.1.11',
        )
        assert token and auth.is_authenticated('iot1')

    def test_same_device_reauthenticating_from_the_same_ip_is_fine(self):
        auth = Present80Authenticator(shared_key=_KEY)
        nonce1 = auth.issue_challenge('iot1')
        auth.verify_response('iot1', _legitimate_response(_KEY, nonce1), source_ip='10.0.1.11')

        nonce2 = auth.issue_challenge('iot1')
        token2 = auth.verify_response(
            'iot1', _legitimate_response(_KEY, nonce2), source_ip='10.0.1.11',
        )
        assert token2

    def test_correct_key_wrong_source_ip_is_refused(self):
        # The attacker HOLDS the real shared key (it's fleet-wide) and can
        # compute a perfectly valid response -- the crypto check alone
        # cannot catch this, only the IP pin can.
        auth = Present80Authenticator(shared_key=_KEY)
        nonce1 = auth.issue_challenge('iot1')
        auth.verify_response('iot1', _legitimate_response(_KEY, nonce1), source_ip='10.0.1.11')

        nonce2 = auth.issue_challenge('iot1')  # the spoofer's own HELLO
        with pytest.raises(AuthError, match='spoofing'):
            auth.verify_response(
                'iot1', _legitimate_response(_KEY, nonce2), source_ip='10.0.1.99',
            )

    def test_no_source_ip_supplied_skips_the_pin_check(self):
        # Callers that don't know the source IP (or tests) get the old
        # behaviour back -- the pin is a defence-in-depth addition, not a
        # required parameter that breaks every other caller.
        auth = Present80Authenticator(shared_key=_KEY)
        nonce1 = auth.issue_challenge('iot1')
        auth.verify_response('iot1', _legitimate_response(_KEY, nonce1), source_ip='10.0.1.11')

        nonce2 = auth.issue_challenge('iot1')
        token2 = auth.verify_response('iot1', _legitimate_response(_KEY, nonce2))
        assert token2

    def test_different_devices_pin_independently(self):
        auth = Present80Authenticator(shared_key=_KEY)
        nonce1 = auth.issue_challenge('iot1')
        auth.verify_response('iot1', _legitimate_response(_KEY, nonce1), source_ip='10.0.1.11')

        nonce2 = auth.issue_challenge('iot2')
        token2 = auth.verify_response(
            'iot2', _legitimate_response(_KEY, nonce2), source_ip='10.0.1.12',
        )
        assert token2  # iot2's own IP, no conflict with iot1's pin


class TestAuthErrorKinds:
    """plan_adv.md Phase 2: denials carry a structured `kind` alongside the
    message, because classification must not depend on regexing prose.

    The distinction that matters is 'ip_pin' vs 'bad_response' -- those are two
    different attacks in this project's adversary model (identity spoofing by
    an insider holding the fleet key, vs. a device that never held it), and
    they are told apart by nothing but the reason the denial fired.
    """

    def test_wrong_key_is_tagged_bad_response(self):
        auth = Present80Authenticator(shared_key=_KEY)
        nonce = auth.issue_challenge('iot1')
        with pytest.raises(AuthError) as exc:
            auth.verify_response('iot1', _legitimate_response(_WRONG_KEY, nonce))
        assert exc.value.kind == AUTH_DENY_BAD_RESPONSE

    def test_correct_key_from_the_wrong_host_is_tagged_ip_pin(self):
        auth = Present80Authenticator(shared_key=_KEY)
        nonce1 = auth.issue_challenge('iot1')
        auth.verify_response(
            'iot1', _legitimate_response(_KEY, nonce1), source_ip='10.0.1.11',
        )
        nonce2 = auth.issue_challenge('iot1')
        with pytest.raises(AuthError) as exc:
            auth.verify_response(
                'iot1', _legitimate_response(_KEY, nonce2), source_ip='10.0.1.99',
            )
        # Crypto PASSED -- only the source disagreed. That is what makes this
        # spoofing rather than a device without credentials.
        assert exc.value.kind == AUTH_DENY_IP_PIN

    def test_missing_challenge_is_tagged_separately(self):
        auth = Present80Authenticator(shared_key=_KEY)
        with pytest.raises(AuthError) as exc:
            auth.verify_response('iot1', b'\x00' * 8)
        assert exc.value.kind == AUTH_DENY_NO_CHALLENGE

    def test_expired_nonce_is_tagged_separately(self, monkeypatch):
        auth = Present80Authenticator(shared_key=_KEY)
        nonce = auth.issue_challenge('iot1')
        # Same time-jump technique as test_expired_nonce_is_rejected above.
        import security.authenticator as mod
        real_time = time.time()
        monkeypatch.setattr(
            mod.time, 'time', lambda: real_time + NONCE_TTL_S + 1,
        )
        with pytest.raises(AuthError) as exc:
            auth.verify_response('iot1', _legitimate_response(_KEY, nonce))
        assert exc.value.kind == AUTH_DENY_NONCE_EXPIRED

    def test_kind_defaults_so_a_bare_raise_still_tags_validly(self):
        # Nothing should construct AuthError without a kind, but if something
        # does it must not produce a None tag that silently drops a denial out
        # of classification.
        assert AuthError('boom').kind == AUTH_DENY_BAD_RESPONSE

    def test_message_is_unchanged_by_the_added_tag(self):
        assert str(AuthError('boom', AUTH_DENY_IP_PIN)) == 'boom'

    def test_every_kind_maps_to_a_classifier_signal_or_is_deliberately_inert(self):
        from controller.attack_classifier import (
            SIG_AUTH_BAD_RESPONSE, SIG_AUTH_IP_PIN,
        )

        mapped = {
            AUTH_DENY_IP_PIN: SIG_AUTH_IP_PIN,
            AUTH_DENY_BAD_RESPONSE: SIG_AUTH_BAD_RESPONSE,
        }
        # The other two are protocol-sequencing failures, not evidence of
        # either modelled auth attack, and are deliberately not mapped.
        inert = {AUTH_DENY_NO_CHALLENGE, AUTH_DENY_NONCE_EXPIRED}
        assert set(mapped) | inert == {
            AUTH_DENY_IP_PIN, AUTH_DENY_BAD_RESPONSE,
            AUTH_DENY_NO_CHALLENGE, AUTH_DENY_NONCE_EXPIRED,
        }


class TestProvisionedRosterClosesTheSpoofingRace:
    """LIVE RUN 9: the first run in this project where an attack SUCCEEDED.

    iot38 authenticated AS iot1, was issued a session, and ran 130 tasks under
    the stolen identity -- no denial, no anomaly, scored `none`. The pin was
    trust-on-first-use, so it had nothing to compare against for an identity
    that had never been claimed:

        08:04:24,194  iot1  handshake dies, Connection reset by peer
        08:04:24,194  iot1  AUTH DENIED -- sending no traffic
        08:04:40,578  iot38 authenticating AS iot1 from this host
        08:04:40,681  iot38 SPOOFING SUCCEEDED

    A provisioned roster removes the race rather than narrowing it: ownership
    is configuration, so it does not matter who gets there first.
    """

    ROSTER = {'iot1': '10.0.0.1', 'iot38': '10.0.0.38'}

    def test_the_run_9_spoof_is_refused_even_though_the_victim_never_showed_up(self):
        auth = Present80Authenticator(shared_key=_KEY, expected_ips=self.ROSTER)
        # iot1 never authenticates -- it was reset off its socket at t+0.4s.
        # iot38 then attempts the identity from its own host, with a
        # cryptographically PERFECT response (the key is fleet-wide).
        nonce = auth.issue_challenge('iot1')
        with pytest.raises(AuthError, match='spoofing') as exc:
            auth.verify_response(
                'iot1', _legitimate_response(_KEY, nonce), source_ip='10.0.0.38',
            )
        assert exc.value.kind == AUTH_DENY_IP_PIN
        assert not auth.is_authenticated('iot1')

    def test_the_legitimate_owner_is_still_admitted_whenever_it_arrives(self):
        # The point is to bind the identity, not to require punctuality: a
        # device delayed past every other host must still get its own name.
        auth = Present80Authenticator(shared_key=_KEY, expected_ips=self.ROSTER)
        nonce = auth.issue_challenge('iot1')
        assert auth.verify_response(
            'iot1', _legitimate_response(_KEY, nonce), source_ip='10.0.0.1',
        )

    def test_a_device_not_in_the_roster_still_uses_first_use_pinning(self):
        # TOFU is right when the population is unknown and wrong when it is
        # known. Both must remain available, or adopting this would require
        # every deployment to enumerate its devices up front.
        auth = Present80Authenticator(shared_key=_KEY, expected_ips=self.ROSTER)
        n1 = auth.issue_challenge('sensorX')
        assert auth.verify_response(
            'sensorX', _legitimate_response(_KEY, n1), source_ip='10.9.9.9',
        )
        n2 = auth.issue_challenge('sensorX')
        with pytest.raises(AuthError, match='spoofing'):
            auth.verify_response(
                'sensorX', _legitimate_response(_KEY, n2), source_ip='10.9.9.10',
            )

    def test_a_roster_binding_is_not_overwritten_by_observation(self):
        """The provisioned IP must not be replaceable by a successful auth.

        Otherwise the roster is only advisory: whoever authenticates first
        would still end up owning the binding, which is the bug.
        """
        binding = IdentityBinding({'iot1': '10.0.0.1'})
        binding.bind('iot1', '10.0.0.1')
        assert binding.owner('iot1') == '10.0.0.1'
        assert binding.roster()['iot1'] == '10.0.0.1'
        with pytest.raises(AuthError):
            binding.check('iot1', '10.0.0.38')


class TestUnclaimedIdentitiesAreVisible:
    """The controller could not tell "not started yet" from "evicted" --
    both are silence, and silence is what the spoofer exploited."""

    def test_roster_identities_start_unclaimed_and_clear_when_claimed(self):
        binding = IdentityBinding({'iot1': '10.0.0.1', 'iot2': '10.0.0.2'})
        assert set(binding.unclaimed()) == {'iot1', 'iot2'}
        binding.mark_authenticated('iot1')
        assert set(binding.unclaimed()) == {'iot2'}

    def test_a_refused_spoof_does_not_mark_the_victim_as_claimed(self):
        # If it did, an eviction would be masked by the very attack that
        # exploited it -- the report would say iot1 turned up fine.
        auth = Present80Authenticator(
            shared_key=_KEY, expected_ips={'iot1': '10.0.0.1'},
        )
        nonce = auth.issue_challenge('iot1')
        with pytest.raises(AuthError):
            auth.verify_response(
                'iot1', _legitimate_response(_KEY, nonce), source_ip='10.0.0.38',
            )
        assert set(auth.binding.unclaimed()) == {'iot1'}
