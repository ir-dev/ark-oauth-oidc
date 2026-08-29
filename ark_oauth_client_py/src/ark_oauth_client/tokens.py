"""
One token endpoint response, with the parts an application actually asks for.

``expires_in`` is converted to an absolute ``expires_at`` the moment the response arrives. A
relative lifetime is only meaningful at the instant it is received, and a token set that has sat in
a session store for six minutes cannot answer "are you still valid" from a number that was relative
to a moment nobody recorded.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Iterable, List, Mapping, Optional

from .jwt import decode_jwt

__all__ = ["TokenSet"]


def _as_list(value: Any) -> List[str]:
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)] if value else []


class TokenSet:
    """The tokens from one grant, plus the validated ID token claims when there was one."""

    def __init__(
        self,
        response: Optional[Mapping[str, Any]] = None,
        *,
        issued_at: Optional[int] = None,
        claims: Optional[Mapping[str, Any]] = None,
    ) -> None:
        response = dict(response or {})
        self.access_token: Optional[str] = response.get("access_token")
        self.token_type: str = response.get("token_type") or "Bearer"
        self.refresh_token: Optional[str] = response.get("refresh_token")
        self.id_token: Optional[str] = response.get("id_token")
        self.scope: Optional[str] = response.get("scope")
        self.issued_at: int = int(time.time()) if issued_at is None else int(issued_at)

        expires_in = response.get("expires_in")
        self.expires_at: Optional[int] = (
            self.issued_at + int(expires_in)
            if isinstance(expires_in, (int, float))
            else response.get("expires_at")
        )

        #: Validated ID token claims — who the user is. ``None`` for a client credentials or API token.
        self.claims: Optional[Dict[str, Any]] = dict(claims) if claims else None

        #: Anything else the server returned, so a provider extension is never silently dropped.
        self.raw: Dict[str, Any] = response

    def expires_in(self, now: Optional[int] = None) -> Optional[int]:
        """Seconds until expiry; negative once it has passed. ``None`` when the server gave no lifetime."""
        if self.expires_at is None:
            return None
        return int(self.expires_at) - (int(time.time()) if now is None else now)

    def expired(self, leeway_seconds: int = 0, now: Optional[int] = None) -> bool:
        """
        Whether the access token should be treated as spent.

        ``leeway_seconds`` exists so a token is renewed *before* it dies rather than after: a token
        with four seconds left will not survive the downstream call it is about to be attached to.
        """
        if self.expires_at is None:
            return False
        now = int(time.time()) if now is None else now
        return now >= int(self.expires_at) - leeway_seconds

    def scopes(self) -> List[str]:
        """The granted scopes, as a list."""
        return [s for s in (self.scope or "").split(" ") if s]

    def has_scope(self, *wanted: Any) -> bool:
        granted = set(self.scopes())
        return all(s in granted for s in _flatten(wanted))

    def ark_claims(self) -> List[str]:
        """
        The tenant's authorization claims from the access token — Ark's ``ark_claims``.

        These, not the scopes, are what an application authorises against: scopes say what the
        client asked for, ``ark_claims`` says what this user may do in this client.
        """
        if not self.access_token:
            return []
        try:
            return _as_list(decode_jwt(self.access_token).payload.get("ark_claims"))
        except Exception:
            # A non-JWT access token (another provider's opaque token) simply carries no ark_claims.
            return []

    def access_token_claims(self) -> Optional[Dict[str, Any]]:
        """The access token's own claims, unverified — for logging and for reading ``sub``, never for authorising."""
        if not self.access_token:
            return None
        try:
            return decode_jwt(self.access_token).payload
        except Exception:
            return None

    @property
    def subject(self) -> Optional[str]:
        if self.claims and self.claims.get("sub"):
            return self.claims["sub"]
        payload = self.access_token_claims()
        return payload.get("sub") if payload else None

    def authorization_header(self) -> str:
        """The value for an ``Authorization`` header."""
        return f"{self.token_type} {self.access_token}"

    def to_dict(self) -> Dict[str, Any]:
        """JSON-safe, and round-trips through a session store without losing the absolute expiry."""
        return {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "refresh_token": self.refresh_token,
            "id_token": self.id_token,
            "scope": self.scope,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "claims": self.claims,
        }

    @classmethod
    def from_dict(cls, data: Any) -> Optional["TokenSet"]:
        if not data:
            return None
        if isinstance(data, TokenSet):
            return data
        return cls(
            data,
            issued_at=data.get("issued_at"),
            claims=data.get("claims"),
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"TokenSet(sub={self.subject!r}, scope={self.scope!r}, "
            f"expires_in={self.expires_in()!r})"
        )


def _flatten(values: Iterable[Any]) -> List[str]:
    out: List[str] = []
    for value in values:
        if isinstance(value, (list, tuple, set)):
            out.extend(_flatten(value))
        elif value is not None:
            out.append(str(value))
    return out
