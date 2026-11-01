"""
Carries the refused identity from the callback to the access-denied page.

The denial happens before any session is written — that is the point of it — so there is no signed-in
user on the next request to read the account off. A short-lived, encrypted, HttpOnly cookie carries
just enough to name it, and is spent on first read.

The .NET client uses ASP.NET Core Data Protection for this. The equivalent here is AES-GCM under a
key derived from the application secret and a purpose string, which gives the same three properties:
the contents are unreadable to the browser, tampering is detected rather than parsed, and a cookie
minted for one purpose cannot be replayed into another.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional

from ..crypto import base64url_decode, base64url_encode
from .options import ArkDeniedAccount

__all__ = ["ArkAccessDeniedState", "protect", "unprotect"]

COOKIE_NAME = "ark_denied"
PURPOSE = b"Ark.oAuth.Client.AccessDenied.v1"
MAX_AGE_SECONDS = 300


def _key(secret: Any) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    material = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=PURPOSE).derive(material)


def protect(secret: Any, payload: Dict[str, Any]) -> str:
    """Encrypts a small JSON payload for a cookie. The nonce travels with the ciphertext."""
    import os

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    body = dict(payload)
    body["_iat"] = int(time.time())
    nonce = os.urandom(12)
    sealed = AESGCM(_key(secret)).encrypt(nonce, json.dumps(body).encode("utf-8"), PURPOSE)
    return base64url_encode(nonce + sealed)


def unprotect(secret: Any, value: str, max_age: int = MAX_AGE_SECONDS) -> Optional[Dict[str, Any]]:
    """Decrypts and age-checks a cookie written by :func:`protect`, or returns ``None``."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        raw = base64url_decode(value)
        opened = AESGCM(_key(secret)).decrypt(raw[:12], raw[12:], PURPOSE)
        payload = json.loads(opened)
    except Exception:
        # Tampered, or protected by a key this instance no longer holds. Either way the page falls
        # back to the unnamed wording rather than failing.
        return None
    if not isinstance(payload, dict):
        return None
    issued = payload.pop("_iat", 0)
    if max_age and (not issued or time.time() - issued > max_age):
        return None
    return payload


class ArkAccessDeniedState:
    """
    Reads and writes the ``ark_denied`` cookie.

    ``response`` and ``request`` are duck-typed: anything with Werkzeug's ``set_cookie`` /
    ``delete_cookie`` and a ``cookies`` mapping will do, which covers Flask and Quart.
    """

    @staticmethod
    def write(response: Any, secret: Any, account: ArkDeniedAccount, *, secure: bool = True) -> None:
        if not secret:
            return  # no secret: the page still works, just unnamed
        response.set_cookie(
            COOKIE_NAME,
            protect(secret, account.to_dict()),
            max_age=MAX_AGE_SECONDS,
            httponly=True,
            secure=secure,
            samesite="Lax",
            path="/",
        )

    @staticmethod
    def read(request: Any, secret: Any) -> Optional[ArkDeniedAccount]:
        value = (getattr(request, "cookies", None) or {}).get(COOKIE_NAME)
        if not value or not secret:
            return None
        payload = unprotect(secret, value)
        return ArkDeniedAccount.from_dict(payload) if payload else None

    @staticmethod
    def clear(response: Any) -> None:
        response.delete_cookie(COOKIE_NAME, path="/")
