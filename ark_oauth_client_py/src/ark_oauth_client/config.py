"""
Normalises and checks what the application configured.

Everything that can be caught without talking to the network is caught here, at construction,
because the alternative is finding out from a user's failed sign-in. A ``redirect_uri`` with a
fragment, an authority that is really a base URL with the tenant id missing, ``private_key_jwt``
with no key: all of those produce an ``invalid_request`` page hours later and half a day of reading
server logs, or one sentence here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from .errors import ArkConfigError

__all__ = ["ArkConfig", "normalize_config", "DEFAULT_SCOPES", "AUTH_METHODS"]

DEFAULT_SCOPES: Tuple[str, ...] = ("openid", "profile", "email", "offline_access")

AUTH_METHODS = ("client_secret_basic", "client_secret_post", "private_key_jwt", "none")

_LOOPBACK = {"localhost", "127.0.0.1", "::1", "[::1]"}


def _is_loopback(url: Any) -> bool:
    return (url.hostname or "") in _LOOPBACK or url.netloc.split(":")[0] in _LOOPBACK


def _require_absolute_url(value: str, setting: str):
    url = urlsplit(value)
    if not url.scheme or not url.netloc:
        raise ArkConfigError(
            f"ark_oauth_client: '{setting}' must be an absolute URL, but is '{value}'."
        )
    if url.scheme not in ("http", "https"):
        raise ArkConfigError(
            f"ark_oauth_client: '{setting}' must be an http or https URL, but is '{value}'."
        )
    return url


@dataclass(frozen=True)
class PrivateKeyJwt:
    """The signing key for the ``private_key_jwt`` client assertion (OIDC Core §9)."""

    private_key: Any
    kid: Optional[str] = None
    alg: str = "RS256"
    lifetime_seconds: int = 60


@dataclass(frozen=True)
class ArkConfig:
    """The validated configuration of one client. Immutable once built."""

    authority: str
    client_id: str
    client_secret: Optional[str] = None
    token_endpoint_auth_method: str = "none"
    private_key_jwt: Optional[PrivateKeyJwt] = None
    redirect_uri: Optional[str] = None
    post_logout_redirect_uri: Optional[str] = None
    scopes: Tuple[str, ...] = DEFAULT_SCOPES
    audience: Optional[str] = None
    response_mode: str = "query"
    use_par: bool = False
    prompt: Optional[str] = None
    acr_values: Optional[str] = None
    extra_authorization_params: Mapping[str, str] = field(default_factory=dict)
    clock_tolerance_seconds: int = 60
    require_https: bool = True
    require_token_hashes: bool = True
    id_token_signing_algorithms: Optional[Tuple[str, ...]] = None
    timeout: float = 10.0
    metadata_ttl: float = 300.0
    jwks_ttl: float = 300.0
    jwks_min_refresh_interval: float = 10.0
    transport: Optional[Callable[..., Any]] = None
    role_claim: str = "role"

    @property
    def is_confidential(self) -> bool:
        return self.token_endpoint_auth_method != "none"

    @property
    def discovery_url(self) -> str:
        return f"{self.authority}/.well-known/openid-configuration"


def normalize_config(
    *,
    authority: Optional[str] = None,
    auth_server_url: Optional[str] = None,
    tenant_id: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    token_endpoint_auth_method: Optional[str] = None,
    private_key_jwt: Any = None,
    redirect_uri: Optional[str] = None,
    post_logout_redirect_uri: Optional[str] = None,
    scopes: Optional[Sequence[str]] = None,
    audience: Optional[str] = None,
    response_mode: str = "query",
    use_par: bool = False,
    prompt: Optional[str] = None,
    acr_values: Optional[str] = None,
    extra_authorization_params: Optional[Mapping[str, str]] = None,
    clock_tolerance_seconds: int = 60,
    require_https: bool = True,
    require_token_hashes: bool = True,
    id_token_signing_algorithms: Optional[Sequence[str]] = None,
    timeout: float = 10.0,
    metadata_ttl: float = 300.0,
    jwks_ttl: float = 300.0,
    jwks_min_refresh_interval: float = 10.0,
    transport: Optional[Callable[..., Any]] = None,
    role_claim: str = "role",
) -> ArkConfig:
    """Validates and freezes the options an :class:`~ark_oauth_client.client.ArkOAuthClient` takes."""

    # The .NET client accepts AuthServerUrl + TenantId as well as Authority; the same two-part form
    # is honoured here so a Python app can be configured from the values already in appsettings.json.
    resolved = (authority or "").strip()
    if not resolved and auth_server_url and tenant_id:
        resolved = f"{str(auth_server_url).rstrip('/')}/{tenant_id}"
    if not resolved:
        raise ArkConfigError(
            "ark_oauth_client: set 'authority' to the issuer URL of your Ark tenant — "
            "{BaseUrl}/{TenantId}, e.g. https://idp.example.com/my_idp. "
            "(Or set auth_server_url + tenant_id and it will be joined for you.)"
        )
    resolved = resolved.rstrip("/")
    authority_url = _require_absolute_url(resolved, "authority")
    if require_https and authority_url.scheme != "https" and not _is_loopback(authority_url):
        raise ArkConfigError(
            f"ark_oauth_client: 'authority' is {resolved}, which is plain http. Tokens would cross "
            "the network in the clear. Use https, or set require_https=False — only ever for local "
            "development."
        )

    if not client_id or not isinstance(client_id, str):
        raise ArkConfigError(
            "ark_oauth_client: 'client_id' is required — the client id registered with the tenant."
        )

    key_jwt: Optional[PrivateKeyJwt] = None
    if private_key_jwt is not None:
        key_jwt = (
            private_key_jwt
            if isinstance(private_key_jwt, PrivateKeyJwt)
            else PrivateKeyJwt(**dict(private_key_jwt))
        )

    method = token_endpoint_auth_method
    if not method:
        # Match what the server expects by default: a client with a secret authenticates with it, a
        # public client (SPA, native, CLI) has nothing to present and says so.
        method = "private_key_jwt" if key_jwt else "client_secret_basic" if client_secret else "none"
    if method not in AUTH_METHODS:
        raise ArkConfigError(
            f"ark_oauth_client: 'token_endpoint_auth_method' is '{method}'; the server supports "
            f"{', '.join(AUTH_METHODS)}."
        )
    if method in ("client_secret_basic", "client_secret_post") and not client_secret:
        raise ArkConfigError(f"ark_oauth_client: '{method}' needs a 'client_secret'.")
    if method == "private_key_jwt" and not (key_jwt and key_jwt.private_key):
        raise ArkConfigError(
            "ark_oauth_client: 'private_key_jwt' needs private_key_jwt.private_key (a PEM string, "
            "a JWK dict, or a cryptography private key object) and the matching public key "
            "published at the jwks_uri registered for this client."
        )
    if method == "none" and client_secret:
        raise ArkConfigError(
            "ark_oauth_client: a 'client_secret' was given but token_endpoint_auth_method is 'none'. "
            "The server matches the registered method exactly, so pick the one this client is "
            "registered for."
        )

    redirect: Optional[str] = None
    if redirect_uri:
        url = _require_absolute_url(redirect_uri, "redirect_uri")
        # The server validates all three of these at registration and matches the value exactly at
        # /authorize, so a mismatch here can never be recovered from at runtime.
        if url.fragment:
            raise ArkConfigError(
                f"ark_oauth_client: 'redirect_uri' must not contain a fragment: {redirect_uri}"
            )
        if url.scheme != "https" and not _is_loopback(url):
            raise ArkConfigError(
                f"ark_oauth_client: 'redirect_uri' is {redirect_uri}. The server accepts http only "
                "for loopback addresses (RFC 8252 §7.3)."
            )
        redirect = redirect_uri

    if post_logout_redirect_uri:
        _require_absolute_url(post_logout_redirect_uri, "post_logout_redirect_uri")

    if response_mode not in ("query", "fragment", "form_post"):
        raise ArkConfigError(
            f"ark_oauth_client: 'response_mode' is '{response_mode}'; the server supports query, "
            "fragment and form_post."
        )

    extras: Dict[str, str] = dict(extra_authorization_params or {})

    return ArkConfig(
        authority=resolved,
        client_id=client_id,
        client_secret=client_secret,
        token_endpoint_auth_method=method,
        private_key_jwt=key_jwt,
        redirect_uri=redirect,
        post_logout_redirect_uri=post_logout_redirect_uri,
        scopes=tuple(scopes) if scopes else DEFAULT_SCOPES,
        audience=audience,
        response_mode=response_mode,
        use_par=use_par,
        prompt=prompt,
        acr_values=acr_values,
        extra_authorization_params=extras,
        clock_tolerance_seconds=clock_tolerance_seconds,
        require_https=require_https,
        require_token_hashes=require_token_hashes,
        id_token_signing_algorithms=tuple(id_token_signing_algorithms)
        if id_token_signing_algorithms
        else None,
        timeout=timeout,
        metadata_ttl=metadata_ttl,
        jwks_ttl=jwks_ttl,
        jwks_min_refresh_interval=jwks_min_refresh_interval,
        transport=transport,
        role_claim=role_claim,
    )
