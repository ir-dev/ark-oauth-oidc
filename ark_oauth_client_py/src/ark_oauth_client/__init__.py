"""
ark-oauth-client — the OAuth 2.1 / OpenID Connect client for Python applications talking to an Ark
identity server.

There is one URL to configure: the issuer, ``{BaseUrl}/{TenantId}``. Every endpoint, signing key and
capability is read from the provider's discovery document, so an application does not need to be
redeployed when the provider rotates a key or moves an endpoint.

    from flask import Flask
    from ark_oauth_client.flask import add_ark_oidc_client, current_ark

    app = Flask(__name__)
    app.secret_key = os.environ["ARK_SESSION_SECRET"]

    auth = add_ark_oidc_client(app, {
        "authority": "https://idp.example.com/my_idp",
        "client_id": "my-app",
    })

    @app.get("/billing")
    @auth.require_claims("billing.admin")
    def billing():
        return f"hello {current_ark.user['name']}"

The Flask integration is one way in; :class:`ArkOAuthClient` is the whole protocol on its own, for
CLIs, workers, Django, FastAPI and every flow without a browser.
"""

from .access import (
    ArkAccessDeniedContext,
    ArkAccessDeniedPage,
    ArkAccessDeniedReasons,
    ArkAccessDeniedState,
    ArkAccessEvaluationContext,
    ArkAccessGate,
    ArkAccountSwitchOptions,
    ArkChallengeProperties,
    ArkClientEvents,
    ArkClientOptions,
    ArkDeniedAccount,
    local_or_default,
)
from .auth_config import ArkAuthConfig, ArkCert, AUser, AUserInfo
from .client import ArkOAuthClient, AuthorizationRequest, create_ark_client
from .config import ArkConfig, DEFAULT_SCOPES, PrivateKeyJwt, normalize_config
from .context import ArkAuthContext
from .crypto import base64url_decode, base64url_encode, left_half_hash, random_token
from .diagnostics import ArkClaimReader, ArkJson, ArkJwt
from .discovery import ArkDiscoveryCache, MetadataResolver, discovery_urls
from .errors import (
    ArkCallbackError,
    ArkConfigError,
    ArkError,
    ArkNetworkError,
    ArkOAuthError,
    ArkTokenError,
)
from .flows import ArkClientCredentials, ArkRegistration, ArkRegistrationResult, ArkTokenResult
from .helper import AuthClientHelper
from .jwks import JwksCache
from .jwt import (
    decode_jwt,
    sign_jwt,
    validate_claims,
    validate_token_hashes,
    verify_jwt,
    verify_signature,
)
from .pkce import (
    PkcePair,
    code_challenge_for,
    create_code_verifier,
    create_nonce,
    create_pkce_pair,
    create_state,
)
from .probe import ArkProviderMetadata, ArkSetupModel, ArkSetupProbe
from .session import (
    MemorySessionStore,
    SessionStore,
    create_session_id,
    sign_session_id,
    unsign_session_id,
)
from .tokens import TokenSet

__version__ = "2.0.5"

#: The PKCE helpers under the name the .NET package gives them.
PkceHelper = type(
    "PkceHelper",
    (),
    {
        "generate_code_verifier": staticmethod(create_code_verifier),
        "generate_code_challenge": staticmethod(code_challenge_for),
        "__doc__": "PKCE helpers, under the .NET client's name for them.",
    },
)

__all__ = [
    "__version__",
    # protocol client
    "ArkOAuthClient",
    "AuthorizationRequest",
    "create_ark_client",
    "TokenSet",
    # configuration
    "ArkConfig",
    "ArkAuthConfig",
    "ArkCert",
    "AUser",
    "AUserInfo",
    "PrivateKeyJwt",
    "normalize_config",
    "DEFAULT_SCOPES",
    # discovery and keys
    "MetadataResolver",
    "ArkDiscoveryCache",
    "discovery_urls",
    "JwksCache",
    # tokens
    "decode_jwt",
    "verify_jwt",
    "verify_signature",
    "validate_claims",
    "validate_token_hashes",
    "sign_jwt",
    # pkce
    "PkcePair",
    "PkceHelper",
    "create_code_verifier",
    "code_challenge_for",
    "create_pkce_pair",
    "create_state",
    "create_nonce",
    "base64url_encode",
    "base64url_decode",
    "left_half_hash",
    "random_token",
    # sessions
    "SessionStore",
    "MemorySessionStore",
    "create_session_id",
    "sign_session_id",
    "unsign_session_id",
    # diagnostics
    "ArkSetupProbe",
    "ArkSetupModel",
    "ArkProviderMetadata",
    "ArkJwt",
    "ArkJson",
    "ArkClaimReader",
    "ArkAuthContext",
    # flows
    "ArkClientCredentials",
    "ArkTokenResult",
    "ArkRegistration",
    "ArkRegistrationResult",
    "AuthClientHelper",
    # account switching
    "ArkAccountSwitchOptions",
    "ArkAccessDeniedReasons",
    "ArkAccessDeniedContext",
    "ArkAccessEvaluationContext",
    "ArkAccessDeniedPage",
    "ArkAccessDeniedState",
    "ArkAccessGate",
    "ArkChallengeProperties",
    "ArkClientEvents",
    "ArkClientOptions",
    "ArkDeniedAccount",
    "local_or_default",
    # errors
    "ArkError",
    "ArkConfigError",
    "ArkOAuthError",
    "ArkTokenError",
    "ArkCallbackError",
    "ArkNetworkError",
]
