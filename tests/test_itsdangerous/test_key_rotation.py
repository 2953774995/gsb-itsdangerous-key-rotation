from __future__ import annotations

import hashlib
import os
from datetime import datetime
from datetime import timedelta
from datetime import timezone

import pytest
from freezegun import freeze_time

from itsdangerous import BadHeader
from itsdangerous import BadKeyIdentifier
from itsdangerous import BadSignature
from itsdangerous import Key
from itsdangerous import KeyExpired
from itsdangerous import KeyRevoked
from itsdangerous import KeyRing
from itsdangerous import Signer
from itsdangerous import TimestampSigner
from itsdangerous import UnknownKeyIdentifier
from itsdangerous import URLSafeTimedSerializer
from itsdangerous.encoding import base64_encode
from itsdangerous.encoding import int_to_bytes


def make_secret() -> bytes:
    return os.urandom(32)


def make_ring(*, revoked: bool = False) -> KeyRing:
    now = datetime.now(timezone.utc)
    return KeyRing(
        [
            Key.verification_only(
                make_secret(),
                "old",
                expires_at=now + timedelta(days=30),
                revoked=revoked,
            ),
            Key.signing(make_secret(), "current"),
        ]
    )


def test_duplicate_traditional_secret_keys_are_deduplicated():
    secret = make_secret()
    ring = KeyRing.from_secret_keys([secret, secret])

    assert ring.secret_keys == [secret]
    assert ring.key_ids == [hashlib.sha256(secret).hexdigest()]


class TestVersionedEnvelope:
    def test_signer_round_trip_and_header(self):
        ring = make_ring()
        signer = Signer(key_ring=ring)

        assert signer.signing_kid == "current"
        signed = signer.sign(b"payload")

        assert signed.startswith(b"v1-current.")
        assert signer.unsign(signed) == b"payload"

    def test_timestamped_round_trip(self):
        ring = make_ring()
        signer = TimestampSigner(key_ring=ring)
        signed = signer.sign(b"payload")

        assert signed.startswith(b"v1-current.")
        assert signer.unsign(signed, max_age=10) == b"payload"

    def test_legacy_timestamped_token_remains_valid(self):
        ring = make_ring()
        old_signer = TimestampSigner(ring.secret_keys)
        old_signed = self._legacy_timestamp_sign(old_signer, b"payload")

        assert not old_signed.startswith(b"v1-")
        assert (
            TimestampSigner(key_ring=ring).unsign(old_signed, max_age=10) == b"payload"
        )

    def test_url_safe_full_stack_with_compression_and_max_age(self):
        serializer = URLSafeTimedSerializer(key_ring=make_ring())
        value = {"message": "x" * 1000}
        token = serializer.dumps(value)

        assert token.startswith("v1-current.")
        assert all(char.isascii() and char not in "?#" for char in token)
        assert serializer.loads(token, max_age=10) == value

    def test_unsafe_load_retains_payload_on_bad_signature(self):
        serializer = URLSafeTimedSerializer(key_ring=make_ring())
        value = {"id": 42}
        token = serializer.dumps(value)

        assert serializer.loads_unsafe(token[:-1]) == (False, value)

    def test_kid_selects_exact_key(self):
        ring = make_ring()
        signer = Signer(key_ring=ring)
        signed = signer.sign(b"payload")
        original_signer = signer

        class OneKeyAlgorithm:
            calls = 0

            def get_signature(self, key, value):
                self.calls += 1
                return original_signer.algorithm.get_signature(key, value)

            def verify_signature(self, key, value, sig):
                self.calls += 1
                return original_signer.algorithm.verify_signature(key, value, sig)

        algorithm = OneKeyAlgorithm()
        verifier = Signer(key_ring=ring, algorithm=algorithm)

        assert verifier.unsign(signed) == b"payload"

        assert algorithm.calls == 1

    @pytest.mark.parametrize("position", (0, 1))
    def test_tampered_kid_fails(self, position):
        signer = Signer(key_ring=make_ring())
        signed = bytearray(signer.sign(b"payload"))
        signed[position] = ord("x")

        with pytest.raises((BadHeader, BadSignature)):
            signer.unsign(bytes(signed))

    def test_version_downgrade_fails(self):
        signer = Signer(key_ring=make_ring())
        signed = signer.sign(b"payload")
        downgraded = signed.replace(b"v1-", b"v0-", 1)

        with pytest.raises(BadHeader):
            signer.unsign(downgraded)

    def test_unsupported_version_is_header_error(self):
        signer = Signer(key_ring=make_ring())

        with pytest.raises(BadHeader):
            signer.unsign(b"v2-current.payload.sig")

    def test_unknown_kid_is_header_error(self):
        signer = Signer(key_ring=make_ring())
        signed = signer.sign(b"payload").replace(b"v1-current", b"v1-missing", 1)

        with pytest.raises(UnknownKeyIdentifier) as exc_info:
            signer.unsign(signed)

        assert isinstance(exc_info.value, BadHeader)

    def test_malformed_kid_is_header_error(self):
        signer = Signer(key_ring=make_ring())
        token = signer.sign(b"payload")
        value, sig = token.rsplit(b".", 1)
        malformed = value.replace(b"v1-current", b"v1-bad kid", 1) + b"." + sig

        with pytest.raises(BadKeyIdentifier):
            signer.unsign(malformed)

    def test_malformed_versioned_header_is_not_ambiguous(self):
        signer = Signer(key_ring=make_ring())

        with pytest.raises(BadKeyIdentifier):
            signer.unsign(b"v1-.payload.sig")

    def test_empty_kid_with_nested_separator_is_rejected(self):
        signer = Signer(key_ring=make_ring())

        with pytest.raises(BadKeyIdentifier):
            signer.unsign(b"v1-.extra.payload.sig")

    def test_invalid_signature_encoding(self):
        signer = Signer(key_ring=make_ring())
        signed = signer.sign(b"payload")
        value, _sig = signed.rsplit(b".", 1)

        for invalid_sig in (b"bad/sig", b"bad=sig"):
            with pytest.raises(BadSignature):
                signer.unsign(value + b"." + invalid_sig)

    def test_kid_cannot_contain_separator(self):
        with pytest.raises(ValueError):
            Key(make_secret(), "bad.kid")

    def test_custom_separator_round_trip(self):
        signer = Signer(key_ring=make_ring(), sep=b"!")

        assert signer.unsign(signer.sign(b"payload")) == b"payload"

    def test_legacy_token_remains_valid(self):
        ring = make_ring()
        old_signer = Signer(ring.secret_keys)
        old_signed = self._legacy_sign(old_signer, b"payload")

        assert not old_signed.startswith(b"v1-")
        assert Signer(key_ring=ring).unsign(old_signed) == b"payload"

    def test_legacy_looking_token_is_not_confused_with_new_format(self):
        ring = make_ring()
        old_signer = Signer(ring.secret_keys)
        old_payload = b"legacy.current.actual-payload"
        old_signed = self._legacy_sign(old_signer, old_payload)

        assert Signer(key_ring=ring).unsign(old_signed) == old_payload

    @staticmethod
    def _legacy_sign(signer: Signer, value: bytes) -> bytes:
        key = signer.derive_key(signer.secret_keys[-1])
        signature = signer.algorithm.get_signature(key, value)

        return value + signer.sep + base64_encode(signature)

    @staticmethod
    def _legacy_timestamp_sign(signer: TimestampSigner, value: bytes) -> bytes:
        timestamp = base64_encode(int_to_bytes(signer.get_timestamp()))
        timed_value = value + signer.sep + timestamp
        key = signer.derive_key(signer.secret_keys[-1])
        signature = signer.algorithm.get_signature(key, timed_value)

        return timed_value + signer.sep + base64_encode(signature)


class TestKeyLifecycle:
    def test_expired_key_is_rejected_with_distinct_error(self):
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        ring = KeyRing(
            [
                Key.verification_only(
                    make_secret(), "old", expires_at=now - timedelta(seconds=1)
                ),
                Key.signing(make_secret(), "current"),
            ]
        )
        old_ring = KeyRing(
            [
                Key.signing(ring.keys[0].secret_key, "old"),
                Key.verification_only(ring.keys[1].secret_key, "current"),
            ]
        )
        token = Signer(key_ring=old_ring).sign(b"payload")

        with freeze_time(now):
            with pytest.raises(KeyExpired):
                Signer(key_ring=ring).unsign(token)

    def test_revoked_key_is_rejected_with_distinct_error(self):
        ring = make_ring()
        active_ring = KeyRing(
            [
                Key.signing(ring.keys[0].secret_key, "old"),
                Key.verification_only(ring.keys[1].secret_key, "current"),
            ]
        )
        token = Signer(key_ring=active_ring).sign(b"payload")
        revoked_ring = make_ring(revoked=True)

        with pytest.raises(KeyRevoked):
            Signer(key_ring=revoked_ring).unsign(token)

    def test_verification_only_key_cannot_sign(self):
        with pytest.raises(ValueError):
            Key(make_secret(), "current", can_sign=True, can_verify=False)

    def test_expiration_requires_timezone(self):
        with pytest.raises(ValueError):
            Key(make_secret(), "kid", expires_at=datetime(2026, 1, 1))

    def test_duplicate_kid_is_rejected(self):
        with pytest.raises(ValueError):
            KeyRing(
                [
                    Key.verification_only(make_secret(), "same"),
                    Key.signing(make_secret(), "same"),
                ]
            )
