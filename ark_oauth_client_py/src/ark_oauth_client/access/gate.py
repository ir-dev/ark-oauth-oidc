"""
Decides, once per sign-in, whether the account the provider authenticated is entitled to this
application.

The check belongs at the callback rather than at each protected view. An entitlement failure is not
"this user may not open that page", it is "this user may not use this application at all", and the
difference is visible in what happens next: refuse at the callback and no session cookie is ever
written, so the person at the keyboard is not left holding somebody else's session while every page
they open answers 403.
"""

from __future__ import annotations

from typing import Any, List, Mapping, Optional, Sequence

from ..diagnostics import ArkClaimReader
from .options import (
    ArkAccessDeniedContext,
    ArkAccessEvaluationContext,
    ArkAccountSwitchOptions,
    ArkClientEvents,
    ArkDeniedAccount,
)

__all__ = ["ArkAccessGate"]


class ArkAccessGate:
    """The entitlement decision and the shape of the denial that follows it."""

    @staticmethod
    def allowed(
        options: ArkAccountSwitchOptions,
        events: Optional[ArkClientEvents],
        claims: Optional[Mapping[str, Any]],
        ark_claims: Sequence[str],
        *,
        tokens: Any = None,
    ) -> bool:
        required = options.required_claims or []
        allowed = (not options.require_ark_claims) or (
            any(c.lower() in {r.lower() for r in required} for c in ark_claims)
            if required
            else len(ark_claims) > 0
        )

        if events is None or events.on_evaluate_access is None:
            return allowed

        # The host's rule replaces the configured one outright rather than being ANDed with it — a
        # handler that wants both can read allowed_by_configuration and say so.
        return bool(
            events.on_evaluate_access(
                ArkAccessEvaluationContext(
                    claims=dict(claims or {}),
                    ark_claims=list(ark_claims),
                    allowed_by_configuration=allowed,
                    tokens=tokens,
                )
            )
        )

    @staticmethod
    def describe(
        reason: str,
        claims: Optional[Mapping[str, Any]],
        ark_claims: Sequence[str],
        return_url: Optional[str],
    ) -> ArkAccessDeniedContext:
        """Builds the denial context, reading the account off whatever identity we do have."""

        def first(*names: str) -> Optional[str]:
            for name in names:
                value = (claims or {}).get(name)
                if value:
                    return str(value)
            return None

        return ArkAccessDeniedContext(
            reason=reason,
            subject=first("sub"),
            email=first("email", "preferred_username"),
            name=first("name"),
            ark_claims=list(ark_claims),
            return_url=return_url,
        )

    @staticmethod
    def to_account(denied: ArkAccessDeniedContext) -> ArkDeniedAccount:
        return ArkDeniedAccount(
            subject=denied.subject,
            email=denied.email,
            name=denied.name,
            reason=denied.reason,
            return_url=denied.return_url,
        )

    @staticmethod
    def read_claims(access_token: Optional[str]) -> List[str]:
        """The authorization claims Ark issued for this client, read off the access token."""
        return ArkClaimReader.read_ark_claims(access_token)

    @staticmethod
    def denied_url(options: ArkAccountSwitchOptions, return_url: Optional[str]) -> str:
        from urllib.parse import quote

        path = options.access_denied_path or "/ark/no-access"
        if not return_url:
            return path
        separator = "&" if "?" in path else "?"
        return f"{path}{separator}returnUrl={quote(return_url, safe='')}"