"""
Reads the provider's discovery document and pairs it with this application's own configuration.

Fetching discovery here is not duplicated work — it is exactly what the sign-in path does on its
first challenge, done somewhere the failure can be read. Without it the first symptom of a wrong
port, a stopped provider or an untrusted development certificate is an exception thrown out of the
sign-in redirect, which says nothing about which of the three it was.

The values on the left are read from local configuration; the values on the right come from the
provider's own discovery document. Registration problems are almost always a mismatch between the
two — a redirect URI that was typed slightly differently, an Authority pointing at the wrong tenant
— and holding both halves in one object turns a generic ``invalid_client`` into something an
operator can act on.

This lives in the client library rather than in one sample application because every Ark client
hits the same three or four registration mistakes. Build it with :class:`ArkSetupProbe` and render
it however the application likes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .auth_config import ArkAuthConfig
from .diagnostics import ArkJson
from .errors import ArkOAuthError
from .http import get_json

__all__ = ["ArkSetupProbe", "ArkSetupModel", "ArkProviderMetadata"]


@dataclass
class ArkProviderMetadata:
    """
    The parts of an OpenID Provider Metadata document (RFC 8414 / OIDC Discovery §3) that a client
    actually uses.

    Deliberately a plain object: this is for showing an operator what the provider advertises,
    including fields the sign-in path ignores, and it must survive a document that is missing half
    of them.
    """

    issuer: Optional[str] = None
    authorization_endpoint: Optional[str] = None
    token_endpoint: Optional[str] = None
    userinfo_endpoint: Optional[str] = None
    end_session_endpoint: Optional[str] = None
    jwks_uri: Optional[str] = None
    registration_endpoint: Optional[str] = None
    device_authorization_endpoint: Optional[str] = None
    pushed_authorization_request_endpoint: Optional[str] = None
    introspection_endpoint: Optional[str] = None
    revocation_endpoint: Optional[str] = None

    scopes_supported: List[str] = field(default_factory=list)
    grant_types_supported: List[str] = field(default_factory=list)
    response_types_supported: List[str] = field(default_factory=list)
    response_modes_supported: List[str] = field(default_factory=list)
    code_challenge_methods_supported: List[str] = field(default_factory=list)
    token_endpoint_auth_methods_supported: List[str] = field(default_factory=list)
    claims_supported: List[str] = field(default_factory=list)

    #: The document exactly as served, for the "show me the raw JSON" case.
    raw: Optional[str] = None

    @classmethod
    def parse(cls, document: Dict[str, Any]) -> "ArkProviderMetadata":
        def text(name: str) -> Optional[str]:
            value = document.get(name)
            return value if isinstance(value, str) else None

        def array(name: str) -> List[str]:
            value = document.get(name)
            return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []

        return cls(
            issuer=text("issuer"),
            authorization_endpoint=text("authorization_endpoint"),
            token_endpoint=text("token_endpoint"),
            userinfo_endpoint=text("userinfo_endpoint"),
            end_session_endpoint=text("end_session_endpoint"),
            jwks_uri=text("jwks_uri"),
            registration_endpoint=text("registration_endpoint"),
            device_authorization_endpoint=text("device_authorization_endpoint"),
            pushed_authorization_request_endpoint=text("pushed_authorization_request_endpoint"),
            introspection_endpoint=text("introspection_endpoint"),
            revocation_endpoint=text("revocation_endpoint"),
            scopes_supported=array("scopes_supported"),
            grant_types_supported=array("grant_types_supported"),
            response_types_supported=array("response_types_supported"),
            response_modes_supported=array("response_modes_supported"),
            code_challenge_methods_supported=array("code_challenge_methods_supported"),
            token_endpoint_auth_methods_supported=array("token_endpoint_auth_methods_supported"),
            claims_supported=array("claims_supported"),
            raw=ArkJson.prettify(json.dumps(document)),
        )


@dataclass
class ArkSetupModel:
    """What an operator needs in order to tell whether an application is correctly registered."""

    # ---- what this application is configured with -------------------------------------

    authority: str = ""
    client_id: str = ""
    is_confidential: bool = False
    scopes: List[str] = field(default_factory=list)
    role_claim_type: str = "role"

    #: The absolute redirect URI this app will send. Register it exactly.
    redirect_uri: str = ""
    post_logout_redirect_uri: str = ""

    #: This application's own origin, i.e. what it presents as an ``Origin`` header.
    origin: str = ""

    # ---- what the provider says about itself ------------------------------------------

    discovery_ok: bool = False
    discovery_error: Optional[str] = None
    discovery_url: str = ""
    provider: ArkProviderMetadata = field(default_factory=ArkProviderMetadata)

    # ---- current session ---------------------------------------------------------------

    is_authenticated: bool = False
    signed_in_as: Optional[str] = None

    #: Populated from ``?auth_error=`` when a sign-in callback failed.
    auth_error: Optional[str] = None

    # ---- provider values, forwarded ------------------------------------------------------

    @property
    def issuer(self) -> Optional[str]:
        return self.provider.issuer

    @property
    def authorization_endpoint(self) -> Optional[str]:
        return self.provider.authorization_endpoint

    @property
    def token_endpoint(self) -> Optional[str]:
        return self.provider.token_endpoint

    @property
    def userinfo_endpoint(self) -> Optional[str]:
        return self.provider.userinfo_endpoint

    @property
    def end_session_endpoint(self) -> Optional[str]:
        return self.provider.end_session_endpoint

    @property
    def jwks_uri(self) -> Optional[str]:
        return self.provider.jwks_uri

    @property
    def registration_endpoint(self) -> Optional[str]:
        return self.provider.registration_endpoint

    @property
    def scopes_supported(self) -> List[str]:
        return self.provider.scopes_supported

    @property
    def grant_types_supported(self) -> List[str]:
        return self.provider.grant_types_supported

    # ---- the checks worth making --------------------------------------------------------

    @property
    def issuer_mismatch(self) -> bool:
        """Set when the issuer in the discovery document is not the configured Authority."""
        if not self.discovery_ok:
            return False
        return (self.issuer or "").rstrip("/").lower() != self.authority.rstrip("/").lower()

    @property
    def unsupported_scopes(self) -> List[str]:
        """Scopes this app asks for that the provider does not advertise."""
        if not self.discovery_ok or not self.scopes_supported:
            return []
        published = {s.lower() for s in self.scopes_supported}
        return [s for s in self.scopes if s.lower() not in published]

    @property
    def supports_dynamic_registration(self) -> bool:
        """Whether the provider offers RFC 7591 dynamic client registration."""
        return bool(self.registration_endpoint)

    @property
    def supports_client_credentials(self) -> bool:
        """Whether the provider offers the client_credentials grant."""
        return any(g.lower() == "client_credentials" for g in self.grant_types_supported)

    # ---- convenience links --------------------------------------------------------------

    @property
    def tenant_id(self) -> str:
        """The tenant segment of the Authority, used to build admin console links."""
        trimmed = self.authority.rstrip("/")
        slash = trimmed.rfind("/")
        return trimmed[slash + 1 :] if 0 < slash < len(trimmed) - 1 else ""

    @property
    def admin_console_url(self) -> str:
        trimmed = self.authority.rstrip("/")
        slash = trimmed.rfind("/")
        if slash > 0:
            return f"{trimmed[:slash]}/{self.tenant_id}/admin"
        return trimmed + "/admin"

    @property
    def integration_page_url(self) -> str:
        return f"{self.authority.rstrip('/')}/oauth2/integrate/{self.client_id}"

    def to_dict(self) -> Dict[str, Any]:
        """A JSON-safe view, for a health endpoint or a template that prefers plain data."""
        return {
            "authority": self.authority,
            "client_id": self.client_id,
            "is_confidential": self.is_confidential,
            "scopes": list(self.scopes),
            "role_claim_type": self.role_claim_type,
            "redirect_uri": self.redirect_uri,
            "post_logout_redirect_uri": self.post_logout_redirect_uri,
            "origin": self.origin,
            "discovery_ok": self.discovery_ok,
            "discovery_error": self.discovery_error,
            "discovery_url": self.discovery_url,
            "is_authenticated": self.is_authenticated,
            "signed_in_as": self.signed_in_as,
            "auth_error": self.auth_error,
            "issuer_mismatch": self.issuer_mismatch,
            "unsupported_scopes": self.unsupported_scopes,
            "supports_dynamic_registration": self.supports_dynamic_registration,
            "supports_client_credentials": self.supports_client_credentials,
            "tenant_id": self.tenant_id,
            "admin_console_url": self.admin_console_url,
            "integration_page_url": self.integration_page_url,
            "provider": {
                "issuer": self.provider.issuer,
                "authorization_endpoint": self.provider.authorization_endpoint,
                "token_endpoint": self.provider.token_endpoint,
                "userinfo_endpoint": self.provider.userinfo_endpoint,
                "end_session_endpoint": self.provider.end_session_endpoint,
                "jwks_uri": self.provider.jwks_uri,
                "registration_endpoint": self.provider.registration_endpoint,
                "device_authorization_endpoint": self.provider.device_authorization_endpoint,
                "pushed_authorization_request_endpoint": (
                    self.provider.pushed_authorization_request_endpoint
                ),
                "introspection_endpoint": self.provider.introspection_endpoint,
                "revocation_endpoint": self.provider.revocation_endpoint,
                "scopes_supported": self.provider.scopes_supported,
                "grant_types_supported": self.provider.grant_types_supported,
                "response_types_supported": self.provider.response_types_supported,
                "response_modes_supported": self.provider.response_modes_supported,
                "code_challenge_methods_supported": self.provider.code_challenge_methods_supported,
                "token_endpoint_auth_methods_supported": (
                    self.provider.token_endpoint_auth_methods_supported
                ),
                "claims_supported": self.provider.claims_supported,
            },
        }


class ArkSetupProbe:
    """
    Builds an :class:`ArkSetupModel` from local configuration plus the provider's live metadata.

    Registered for you by ``add_ark_oidc_client``; construct it directly for a CLI check.
    """

    def __init__(self, config: ArkAuthConfig, **http: Any) -> None:
        self._config = config
        self._http = http or {"timeout": 15.0}

    @staticmethod
    def discovery_url(authority: str) -> str:
        return f"{authority.rstrip('/')}/.well-known/openid-configuration"

    def probe(
        self,
        *,
        origin: str = "",
        is_authenticated: bool = False,
        signed_in_as: Optional[str] = None,
        auth_error: Optional[str] = None,
    ) -> ArkSetupModel:
        """
        Builds the full picture: configured values, the provider's metadata, and who is signed in.

        ``origin`` is this application's own scheme + host + path base, which is what the absolute
        redirect URI is derived from. The Flask integration fills it in from the request.
        """
        config = self._config
        authority = config.resolve_authority()

        model = ArkSetupModel(
            authority=authority,
            client_id=config.client_id or "",
            is_confidential=bool(config.client_secret),
            scopes=config.resolve_scopes(),
            role_claim_type=config.role_claim_type or "role",
            origin=origin,
            redirect_uri=origin + (config.callback_path or "/signin-oidc"),
            post_logout_redirect_uri=origin
            + (config.signed_out_callback_path or "/signout-callback-oidc"),
            discovery_url=self.discovery_url(authority) if authority else "",
            is_authenticated=is_authenticated,
            signed_in_as=signed_in_as,
            auth_error=auth_error,
        )

        if not authority:
            model.discovery_error = "ark_oauth_client: 'authority' is not set."
            return model

        try:
            model.provider = self.read_metadata(authority)
            model.discovery_ok = True
        except Exception as error:
            model.discovery_error = str(error)

        return model

    def read_metadata(self, authority: Optional[str] = None) -> ArkProviderMetadata:
        """
        Fetches and parses the provider metadata document.

        Raises rather than returning a null-ish object, because every caller has to say something
        different about the failure and swallowing it here would hide the only diagnostic there is.
        """
        authority = authority or self._config.resolve_authority()
        if not authority:
            raise ArkOAuthError(
                "invalid_request", "ark_oauth_client: 'authority' is not set.", endpoint=""
            )
        document = get_json(self.discovery_url(authority), **self._http)
        return ArkProviderMetadata.parse(document)
