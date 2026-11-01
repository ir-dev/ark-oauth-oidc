"""
The ``ark_oauth_client`` configuration section, as the .NET client binds it.

In practice only ``authority`` and ``client_id`` are needed — everything else is discovered from the
provider's ``/.well-known/openid-configuration`` document at startup. The legacy properties
(``issuer``, ``audience``, ``rsa_public``, the per-tenant certificate table) are kept so an existing
``appsettings.json`` can be loaded unchanged by :meth:`ArkAuthConfig.from_mapping`, which accepts
both the C# spelling (``AuthServerUrl``, ``authServerUrl``) and Python's (``auth_server_url``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional

from .access.options import ArkAccountSwitchOptions

__all__ = ["ArkAuthConfig", "ArkCert", "AUserInfo", "AUser"]


@dataclass
class ArkCert:
    """One tenant's pinned signing certificate. Legacy flow only."""

    kid: str = ""
    rsa_public: str = ""
    audience: str = ""
    issuer: str = ""


@dataclass
class AUser:
    email: str = ""
    name: str = ""
    type: str = "user"

    def to_dict(self) -> Dict[str, Any]:
        return {"email": self.email, "name": self.name, "type": self.type}


@dataclass
class AUserInfo:
    """What the application knows about the signed-in user, in the shape the .NET client returns."""

    claims: List[str] = field(default_factory=list)
    client_guid: str = ""
    client_id: str = ""
    client_name: str = ""
    user: AUser = field(default_factory=AUser)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "claims": list(self.claims),
            "client_guid": self.client_guid,
            "client_id": self.client_id,
            "client_name": self.client_name,
            "user": self.user.to_dict(),
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "AUserInfo":
        user = data.get("user") or {}
        return cls(
            claims=list(data.get("claims") or []),
            client_guid=data.get("client_guid") or "",
            client_id=data.get("client_id") or "",
            client_name=data.get("client_name") or "",
            user=AUser(
                email=user.get("email") or "",
                name=user.get("name") or "",
                type=user.get("type") or "user",
            ),
        )


def _snake(name: str) -> str:
    """``AuthServerUrl`` / ``authServerUrl`` / ``auth_server_url`` all arrive as the same key."""
    out: List[str] = []
    for index, char in enumerate(name):
        if char.isupper() and index > 0 and not name[index - 1].isupper():
            out.append("_")
        out.append(char.lower())
    return "".join(out)


@dataclass
class ArkAuthConfig:
    """The bound ``ark_oauth_client`` section."""

    # ---- legacy properties, kept so existing appsettings files still bind ----------------

    issuer: str = ""
    audience: str = ""
    rsa_public: str = ""
    logout_uri: str = ""
    redirect_uri: str = ""
    redirect_relative: str = ""
    auth_server_url: str = ""
    client_id: str = ""
    #: Client route or querystring key the client id is read from, e.g. ``["client_id"]``.
    route_key: List[str] = field(default_factory=list)
    tenant_id: str = ""
    domain: str = ""
    #: Suffix after the client id: ``lh`` for localhost, ``azd`` for an Azure dev deployment.
    suffix: str = ""
    expire_mins: int = 480
    tenants: Dict[str, ArkCert] = field(default_factory=dict)

    # ---- standard OIDC client settings ---------------------------------------------------

    #: The issuer URL of the authorization server, e.g. ``https://idp.example.com/my_tenant``.
    #: Left unset, it is derived from ``auth_server_url`` + ``tenant_id``, so existing
    #: configuration files pick up the standard flow without being rewritten.
    authority: Optional[str] = None

    #: Set for confidential clients. Public clients (SPAs, native apps) leave this empty.
    client_secret: Optional[str] = None

    #: Defaults to openid, profile, email, offline_access.
    scopes: Optional[List[str]] = None

    callback_path: Optional[str] = None
    signed_out_callback_path: Optional[str] = None
    signed_out_redirect_uri: Optional[str] = None

    #: Where to land when the sign-in callback fails. Receives ``?auth_error=…``.
    auth_error_path: Optional[str] = None

    #: Where an unauthenticated user is sent to start a sign-in.
    login_path: str = "/login"

    #: Where a sign-out is initiated.
    logout_path: str = "/logout"

    cookie_name: Optional[str] = None

    #: Claim type Ark authorization claims are projected onto. Defaults to ``role``.
    role_claim_type: Optional[str] = None

    #: Only turn this off for local development against a plain-http provider.
    require_https_metadata: bool = True

    #: Account switching on a shared browser, and the page shown to a user who is signed in as
    #: somebody without access to this application.
    account_switch: ArkAccountSwitchOptions = field(default_factory=ArkAccountSwitchOptions)

    #: Opt back in to the original cookie/bearer middleware. Provided for deployments that cannot
    #: move to the standard callback path yet; the legacy flow does not verify ``state`` or
    #: ``nonce`` and derives its PKCE verifier predictably.
    use_legacy_flow: bool = False

    def resolve_authority(self) -> str:
        if self.authority and self.authority.strip():
            return self.authority.rstrip("/")
        if self.auth_server_url and self.tenant_id:
            return f"{self.auth_server_url.rstrip('/')}/{self.tenant_id}"
        return ""

    def resolve_scopes(self) -> List[str]:
        return (
            list(self.scopes)
            if self.scopes
            else ["openid", "profile", "email", "offline_access"]
        )

    def resolve_callback_path(self) -> str:
        return self.callback_path or "/signin-oidc"

    def resolve_signed_out_callback_path(self) -> str:
        return self.signed_out_callback_path or "/signout-callback-oidc"

    def resolve_cookie_name(self) -> str:
        return self.cookie_name or "ark_auth"

    def resolve_role_claim_type(self) -> str:
        return self.role_claim_type or "role"

    @classmethod
    def from_mapping(cls, data: Optional[Mapping[str, Any]]) -> "ArkAuthConfig":
        """
        Binds a configuration dict, accepting the C# key spellings.

        ``{"ark_oauth_client": {...}}`` and the inner section are both accepted, so an
        ``appsettings.json`` loaded with :func:`json.load` can be handed over whole.
        """
        data = dict(data or {})
        if "ark_oauth_client" in data and isinstance(data["ark_oauth_client"], Mapping):
            data = dict(data["ark_oauth_client"])

        normalized = {_snake(str(k)): v for k, v in data.items()}
        config = cls()

        tenants = normalized.pop("tenants", None) or {}
        switch = normalized.pop("account_switch", None)

        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        for key, value in normalized.items():
            if key in known:
                setattr(config, key, value)

        config.tenants = {
            str(kid): (
                cert
                if isinstance(cert, ArkCert)
                else ArkCert(**{_snake(str(k)): v for k, v in dict(cert).items()})
            )
            for kid, cert in dict(tenants).items()
        }
        if switch is not None:
            config.account_switch = (
                switch
                if isinstance(switch, ArkAccountSwitchOptions)
                else ArkAccountSwitchOptions(
                    **{
                        _snake(str(k)): v
                        for k, v in dict(switch).items()
                        if _snake(str(k)) in ArkAccountSwitchOptions.__dataclass_fields__
                    }
                )
            )
        if config.route_key and isinstance(config.route_key, str):
            config.route_key = [config.route_key]
        return config
