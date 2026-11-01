"""
What the application knows about the caller of the current request.

The .NET client registers ``ArkAuthContext`` per request and reads the identity off the
authenticated principal, falling back to the legacy claims cookie. The same object is built here
from the Flask session, so a view can ask "who is this, which client are they in, and what may they
do" without touching tokens.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence

from .auth_config import ArkAuthConfig, AUser, AUserInfo

__all__ = ["ArkAuthContext"]


class ArkAuthContext:
    """One request's view of the signed-in user. Cheap to build; do not cache across requests."""

    def __init__(
        self,
        config: ArkAuthConfig,
        *,
        claims: Optional[Mapping[str, Any]] = None,
        ark_claims: Sequence[str] = (),
        client_id: Optional[str] = None,
        ip: Optional[str] = None,
        is_authenticated: bool = False,
    ) -> None:
        self.auth_client_config = config
        self.client_id = (client_id or config.client_id or "").lower()
        self.tenant_id = config.tenant_id
        self.ip = ip
        self.is_authenticated = is_authenticated
        self.user_id: Optional[str] = None
        self.user_info: Optional[AUserInfo] = None
        self._set_user_info(claims, ark_claims)

    @property
    def claims(self) -> List[str]:
        """The Ark authorization claims for this user in this client."""
        return list(self.user_info.claims) if self.user_info else []

    def has_claim(self, *wanted: str) -> bool:
        held = set(self.claims)
        return all(claim in held for claim in wanted)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "client_id": self.client_id,
            "tenant_id": self.tenant_id,
            "user_id": self.user_id,
            "ip": self.ip,
            "is_authenticated": self.is_authenticated,
            "user_info": self.user_info.to_dict() if self.user_info else None,
        }

    # ------------------------------------------------------------------

    def _set_user_info(
        self, claims: Optional[Mapping[str, Any]], ark_claims: Sequence[str]
    ) -> None:
        if not claims:
            return

        def first(*names: str) -> Optional[str]:
            for name in names:
                value = claims.get(name)
                if value:
                    return str(value)
            return None

        email = first("email", "preferred_username")
        subject = first("sub")
        self.user_id = email or subject
        self.user_info = AUserInfo(
            claims=list(ark_claims),
            client_id=self.client_id,
            client_name=self.client_id,
            user=AUser(
                email=email or subject or "",
                name=first("name") or "",
                type="user",
            ),
        )
