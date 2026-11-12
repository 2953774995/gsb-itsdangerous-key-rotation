from __future__ import annotations

import collections.abc as cabc
import hashlib
import hmac
import re
import typing as t
from dataclasses import dataclass
from datetime import datetime
from datetime import timezone

from .encoding import want_bytes
from .exc import KeyExpired
from .exc import KeyRevoked
from .exc import KeySigningError
from .exc import KeyStatusError
from .exc import UnknownKeyIdentifier

if t.TYPE_CHECKING:
    from .signer import _SecretKeyInput

# Key identifiers are public. Restricting them to the URL-safe base64
# alphabet without padding means they can never contain the envelope
# separator and need no percent-encoding in URLs or HTTP headers.
_KID_RE = re.compile(rb"[A-Za-z0-9_-]{1,128}$")


def validate_kid(kid: str) -> bytes:
    """Validate and encode a public key identifier."""
    value = want_bytes(kid, encoding="ascii")

    if _KID_RE.fullmatch(value) is None:
        raise ValueError(
            "A key id must be 1 to 128 URL-safe base64 characters"
            " (letters, digits, '_', or '-')."
        )

    return value


@dataclass(frozen=True)
class Key:
    """Metadata and secret material for one versioned signing key.

    :param secret_key: The HMAC secret key. It is never included in a
        token; only the public :attr:`kid` is emitted.
    :param kid: A stable public key identifier.
    :param can_sign: Whether this key may produce new signatures.
    :param can_verify: Whether this key may verify existing signatures.
    :param expires_at: Optional timezone-aware expiration time.
    :param revoked: Whether the key has been permanently retired.
    """

    secret_key: str | bytes
    kid: str
    can_sign: bool = False
    can_verify: bool = True
    expires_at: datetime | None = None
    revoked: bool = False

    def __post_init__(self) -> None:
        validate_kid(self.kid)

        if self.can_sign and not self.can_verify:
            raise ValueError("A signing key must also be allowed to verify.")

        if self.expires_at is not None and self.expires_at.tzinfo is None:
            raise ValueError("'expires_at' must be a timezone-aware datetime.")

    @property
    def secret(self) -> bytes:
        return want_bytes(self.secret_key)

    @classmethod
    def signing(
        cls,
        secret_key: str | bytes,
        kid: str,
        expires_at: datetime | None = None,
    ) -> Key:
        """Create a key that may sign and verify."""
        return cls(
            secret_key=secret_key,
            kid=kid,
            can_sign=True,
            can_verify=True,
            expires_at=expires_at,
        )

    @classmethod
    def verification_only(
        cls,
        secret_key: str | bytes,
        kid: str,
        expires_at: datetime | None = None,
        revoked: bool = False,
    ) -> Key:
        """Create a key that may verify but may not produce new tokens."""
        return cls(
            secret_key=secret_key,
            kid=kid,
            can_sign=False,
            can_verify=True,
            expires_at=expires_at,
            revoked=revoked,
        )


class KeyRing:
    """A collection of keys with explicit signing and verification
    lifecycle metadata.
    """

    def __init__(self, keys: cabc.Iterable[Key]):
        keys = tuple(keys)

        if not keys:
            raise ValueError("A key ring must contain at least one key.")

        kids: set[bytes] = set()
        signing_count = 0

        for key in keys:
            kid = validate_kid(key.kid)

            if kid in kids:
                raise ValueError(f"Duplicate key id {key.kid!r}.")

            kids.add(kid)

            if key.can_sign:
                signing_count += 1

        if signing_count != 1:
            raise ValueError("A key ring must have exactly one signing key.")

        self.keys: tuple[Key, ...] = keys
        self._kids = tuple(validate_kid(key.kid) for key in keys)

    @classmethod
    def from_secret_keys(
        cls,
        secret_keys: _SecretKeyInput,
    ) -> KeyRing:
        """Build a ring from the traditional single key or key list.

        The last key is the signing key. Each stable identifier is the
        SHA-256 digest of the corresponding secret material, so reordering
        or removing a verification-only key does not change its ``kid``.
        Duplicate secret material is ignored to preserve unique identifiers.
        Explicit :class:`Key` metadata should be used for production
        rotation policies.
        """
        from .signer import _make_keys_list

        raw_keys = _make_keys_list(secret_keys)
        unique_raw_keys: list[bytes] = []
        keys = []

        for secret in raw_keys:
            if secret not in unique_raw_keys:
                unique_raw_keys.append(secret)

        for index, secret in enumerate(unique_raw_keys):
            kid = hashlib.sha256(secret).hexdigest()
            keys.append(
                Key(
                    secret_key=secret,
                    kid=kid,
                    can_sign=index == len(unique_raw_keys) - 1,
                    can_verify=True,
                )
            )

        return cls(keys)

    @property
    def secret_keys(self) -> list[bytes]:
        return [key.secret for key in self.keys]

    @property
    def key_ids(self) -> list[str]:
        return [key.kid for key in self.keys]

    def _index_for_kid(self, kid: bytes) -> int:
        # kid is a public identifier, but keep the lookup independent of
        # dictionary hash behavior and avoid short-circuiting on the first
        # mismatch. MAC verification remains the actual security boundary.
        match_index = -1

        for index, configured_kid in enumerate(self._kids):
            matched = hmac.compare_digest(kid, configured_kid)
            match_index += (index - match_index) * int(matched)

        return match_index

    def get_signing_key(self, now: datetime | None = None) -> Key:
        for key in self.keys:
            if key.can_sign:
                self._check_status(key, now=now)
                if not key.can_verify:
                    raise KeySigningError(
                        f"Key id {key.kid!r} is not allowed for verification."
                    )
                return key

        # Construction rejects rings without a signing key.
        raise KeySigningError("No signing key is configured.")

    def get_verification_key(
        self, kid: str | bytes, now: datetime | None = None
    ) -> Key:
        if isinstance(kid, str):
            kid = kid.encode("ascii")

        index = self._index_for_kid(kid)

        if index < 0:
            raise UnknownKeyIdentifier(f"Unknown key id {kid!r}.", header=kid)

        key = self.keys[index]
        self._check_status(key, now=now)

        if not key.can_verify:
            raise KeyStatusError(
                f"Key id {key.kid!r} is not allowed for verification.",
                header=kid,
            )

        return key

    def verification_keys(self, now: datetime | None = None) -> cabc.Iterator[Key]:
        for key in self.keys:
            try:
                self._check_status(key, now=now)
            except KeyStatusError:
                continue

            if key.can_verify:
                yield key

    @staticmethod
    def _check_status(key: Key, now: datetime | None = None) -> None:
        if key.revoked:
            raise KeyRevoked(f"Key id {key.kid!r} has been revoked.")

        if key.expires_at is not None:
            current = now or datetime.now(timezone.utc)

            if current >= key.expires_at:
                raise KeyExpired(
                    f"Key id {key.kid!r} expired at {key.expires_at.isoformat()}."
                )
