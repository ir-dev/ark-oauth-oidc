"""
The small cryptographic primitives the protocol is built out of.

Everything unguessable comes from :mod:`secrets`, and every digest from :mod:`hashlib` — both in
the standard library, so nothing in the chain that mints a PKCE verifier or compares a ``state``
can be replaced by a typosquatted package on install. Signature verification is the one thing that
needs more than the standard library offers, and it lives in :mod:`ark_oauth_client.jwt`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from typing import Union

__all__ = [
    "base64url_encode",
    "base64url_decode",
    "random_token",
    "sha256",
    "fixed_time_equal",
    "left_half_hash",
]

BytesLike = Union[bytes, bytearray, str]


def _to_bytes(value: BytesLike) -> bytes:
    return value.encode("utf-8") if isinstance(value, str) else bytes(value)


def base64url_encode(value: BytesLike) -> str:
    """base64url without padding (RFC 7515 §2)."""
    return base64.urlsafe_b64encode(_to_bytes(value)).rstrip(b"=").decode("ascii")


def base64url_decode(value: BytesLike) -> bytes:
    """Decodes base64url to bytes, tolerating the padding some encoders leave on."""
    raw = _to_bytes(value)
    return base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))


def random_token(num_bytes: int = 32) -> str:
    """
    Cryptographically random bytes as base64url.

    Every unguessable value in the protocol — ``state``, ``nonce``, the PKCE verifier, a session id
    — comes from here and only from here. The .NET client this one mirrors exists because its
    predecessor derived the PKCE verifier from a timestamp, which made it predictable and meant
    PKCE protected nothing at all.
    """
    return base64url_encode(secrets.token_bytes(num_bytes))


def sha256(value: BytesLike) -> bytes:
    return hashlib.sha256(_to_bytes(value)).digest()


def fixed_time_equal(a: object, b: object) -> bool:
    """
    Constant-time string comparison.

    Used for ``state`` and for the session cookie signature. A length-dependent early return would
    leak how much of a guess was right, which is enough to reconstruct a value one character at a
    time; hashing both sides first keeps the compared buffers equal-length so the comparison itself
    cannot be timed either.
    """
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    return hmac.compare_digest(sha256(a), sha256(b))


def left_half_hash(value: BytesLike) -> str:
    """
    The left-most half of the SHA-256 of a value, base64url encoded — the construction OIDC Core
    §3.1.3.6 uses for ``at_hash`` and ``c_hash``.
    """
    digest = sha256(value)
    return base64url_encode(digest[: len(digest) // 2])
