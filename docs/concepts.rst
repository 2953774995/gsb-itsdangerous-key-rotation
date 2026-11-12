General Concepts
================


Serializer vs Signer
--------------------

ItsDangerous provides two levels of data handling. The :doc:`/signer` is
the basic system that signs a given ``bytes`` value based on the given
signing parameters. The :doc:`/serializer` wraps a signer to enable
serializing and signing other data besides ``bytes``.

Typically, you'll want to use a serializer, not a signer. You can
configure the signing parameters through the serializer, and even
provide fallback signers to upgrade old tokens to new parameters.


The Secret Key
--------------

Signatures are secured by the ``secret_key``. Typically one secret key
is used with all signers, and the salt is used to distinguish different
contexts. Changing the secret key will invalidate existing tokens.

It should be a long random string of bytes. This value must be kept
secret and should not be saved in source code or committed to version
control. If an attacker learns the secret key, they can change and
resign data to look valid. If you suspect this happened, change the
secret key to invalidate existing tokens.

One way to keep the secret key separate is to read it from an
environment variable. When deploying for the first time, generate a key
and set the environment variable when running the application. All
process managers (like systemd) and hosting services have a way to
specify environment variables.

.. code-block:: python

    import os
    from itsdangerous.serializer import Serializer
    SECRET_KEY = os.environ.get("SECRET_KEY")
    s = Serializer(SECRET_KEY)

.. code-block:: text

    $ export SECRET_KEY="base64 encoded random bytes"
    $ python application.py

One way to generate a key is to use :func:`os.urandom`.

.. code-block:: text

    $ python3 -c 'import os; print(os.urandom(16).hex())'


The Salt
--------

The salt is combined with the secret key to derive a unique key for
distinguishing different contexts. Unlike the secret key, the salt
doesn't have to be random, and can be saved in code. It only has to be
unique between contexts, not private.

For example, you want to email activation links to activate user
accounts, and upgrade links to upgrade users to a paid accounts. If all
you sign is the user id, and you don't use different salts, a user could
reuse the token from the activation link to upgrade the account. If you
use different salts, the signatures will be different and will not be
valid in the other context.

.. code-block:: python

    from itsdangerous.url_safe import URLSafeSerializer

    s1 = URLSafeSerializer("secret-key", salt="activate")
    s1.dumps(42)
    'NDI.MHQqszw6Wc81wOBQszCrEE_RlzY'

    s2 = URLSafeSerializer("secret-key", salt="upgrade")
    s2.dumps(42)
    'NDI.c0MpsD6gzpilOAeUPra3NShPXsE'

The second serializer can't load data dumped with the first because the
salts differ.

.. code-block:: python

    s2.loads(s1.dumps(42))
    Traceback (most recent call last):
      ...
    BadSignature: Signature does not match

Only the serializer with the same salt can load the data.

.. code-block:: python

    s2.loads(s2.dumps(42))
    42


Key Rotation
------------

Key rotation can provide an extra layer of mitigation against an
attacker discovering a secret key. A rotation system will keep a list of
valid keys, generating a new key and removing the oldest key
periodically. If it takes four weeks for an attacker to crack a key, but
the key is rotated out after three weeks, they will not be able to use
any keys they crack. However, if a user doesn't refresh their token
within three weeks it will be invalid too.

The system that generates and maintains keys is outside the scope of
ItsDangerous, but the library now supports explicit key lifecycle metadata
through :class:`Key` and :class:`KeyRing`.

Version 1 envelopes use this layout::

    v1-<kid>.<payload>[.<timestamp>].<signature>

``kid`` is public and limited to the unpadded URL-safe base64 alphabet, so
it cannot contain the envelope separator. The HMAC input is the complete
value before the final signature, including ``v1`` and ``kid``. Changing
the version or key identifier therefore changes the bytes that the MAC
covers and causes verification to fail. This prevents an attacker from
downgrading an envelope or moving a valid signature onto another key.

A token without a versioned header is handled by the legacy parser. A token
that merely looks like version 1 still has to authenticate before the
version-1 path accepts it, which keeps legacy payloads that may contain dots
from being misclassified. An unsupported numeric version is rejected as a
header error rather than being treated as a downgrade target.

Configure one key with ``can_sign=True``. Retired keys remain available for
verification only, optionally with an expiration time or a revocation flag.

.. code-block:: python

    import os
    from datetime import datetime, timedelta, timezone
    from itsdangerous import Key, KeyRing, URLSafeTimedSerializer

    previous_key = os.urandom(32)
    current_key = os.urandom(32)
    now = datetime.now(timezone.utc)
    ring = KeyRing(
        [
            Key.verification_only(
                previous_key,
                "2026-a",
                expires_at=now + timedelta(days=30),
            ),
            Key.signing(current_key, "2026-b"),
        ]
    )
    serializer = URLSafeTimedSerializer(key_ring=ring)

To add a key, keep the current key as verification-only and add the new key
with signing enabled. To terminate a retired key before its natural cutoff,
set ``revoked=True`` or remove it from the ring. Removing a key rejects
future verification for all tokens carrying that ``kid``; revocation gives
you a distinct :exc:`~itsdangerous.exc.KeyRevoked` exception for audit
logging. An expired key raises
:exc:`~itsdangerous.exc.KeyExpired`, while a ``kid`` that is not configured
raises :exc:`~itsdangerous.exc.UnknownKeyIdentifier`.

The traditional single-key and key-list constructors remain supported. They
generate a stable SHA-256-based ``kid`` for each key, use the last key for
signing, and retain the legacy verification path for tokens created before
this feature.


Digest Method Security
----------------------

A signer is configured with a ``digest_method``, a hash function that
is used as an intermediate step when generating the HMAC signature. The
default method is :func:`hashlib.sha1`. Occasionally, users are
concerned about this default because they have heard about hash
collisions with SHA-1.

When used as the intermediate, iterated step in HMAC, SHA-1 is not
insecure. In fact, even MD5 is still secure in HMAC. The security of the
hash alone doesn't apply when used in HMAC.

If a project considers SHA-1 a risk anyway, they can configure the
signer with a different digest method such as :func:`hashlib.sha512`.
A fallback signer for SHA-1 can be configured so that old tokens will be
upgraded. SHA-512 produces a longer hash, so tokens will take up more
space, which is relevant in cookies and URLs.
