"""
PKCE (RFC 7636), ``state`` and ``nonce``.

The Ark server requires PKCE for every public client and accepts ``S256`` only — ``plain`` is not
implemented, because a plain challenge is the verifier and protects nothing once the authorization
request has been observed.
"""

from __future__ import annotations

from typing import NamedTuple

from .crypto import base64url_encode, random_token, sha256

__all__ = [
    "PkcePair",
    "create_code_verifier",
    "code_challenge_for",
    "create_pkce_pair",
    "create_state",
    "create_nonce",
]


class PkcePair(NamedTuple):
    """Verifier, challenge and method in one object, for callers driving the flow by hand."""

    code_verifier: str
    code_challenge: str
    code_challenge_method: str


def create_code_verifier() -> str:
    """
    A code verifier: 32 random bytes as base64url, which lands at 43 characters — the minimum
    RFC 7636 §4.1 allows, and entirely within its unreserved character set.
    """
    return random_token(32)


def code_challenge_for(verifier: str) -> str:
    """BASE64URL(SHA256(verifier)) — the ``code_challenge`` for ``code_challenge_method=S256``."""
    return base64url_encode(sha256(verifier))


def create_state() -> str:
    """CSRF protection for the authorization response, and the key a login transaction is stored under."""
    return random_token(24)


def create_nonce() -> str:
    """Binds the ID token to this authorization request so a captured one cannot be replayed."""
    return random_token(24)


def create_pkce_pair() -> PkcePair:
    verifier = create_code_verifier()
    return PkcePair(verifier, code_challenge_for(verifier), "S256")
