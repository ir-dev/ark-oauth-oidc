<!--
  API-GUIDE.md — ark-oauth-client (Python)
  Audience: AI coding agents needing exact, non-fabricated signatures.
  Every member below is from src/ark_oauth_client/. If it is not here, read the module.
-->

# ark-oauth-client (Python) — API guide

Exact public API (import root `ark_oauth_client`, Flask helpers `ark_oauth_client.flask`, PyPI
`ark-oauth-client` v2.0.9, Python `>=3.9`). Verified against source.

## Flask integration (`ark_oauth_client.flask`)

| Signature | Purpose |
|---|---|
| `add_ark_oidc_client(app, config=None, configure=None, **options) -> ArkFlask` | Register interactive sign-in. `config` = the `ark_oauth_client` section (an `ArkAuthConfig`, a dict in any spelling, or omit and use kwargs). `configure(ArkClientOptions)` adjusts config + attaches events. |
| `ark_flask(app=None, **options) -> ArkFlask` | Friendlier constructor for apps configured in Python. |
| `add_ark_oidc_api(app=None, prefix="", **options) -> ArkBearer` | Register bearer-token API protection under `prefix`. |
| `ark_bearer(**options) -> ArkBearer` | An `ArkBearer` to use as a decorator without registering on an app. |
| `use_ark_account_endpoints(app) -> app` | Ensure the account endpoints are served (idempotent; `add_ark_oidc_client` already does it). |

**`ArkFlask` methods:** `require_auth(claims=(), scopes=())`, `require_claims(*claims)`,
`require_scopes(*scopes)`, `switch_user(return_url=None, login_hint=None)`,
`sign_out_everywhere(return_url=None)`, `sign_out_locally(return_url=None)`,
`denied_account() -> ArkDeniedAccount | None`, `setup_model() -> ArkSetupModel`. Properties:
`client -> ArkOAuthClient`, `login_path`, `callback_path`, `logout_path`, `store`, `config`, `switch`,
`events`, `probe`, `client_credentials`, `registration`, `onboarding`.

**`ArkFlask` constructor options** (also accepted as kwargs to `add_ark_oidc_client`):

| Option | Default | Notes |
|---|---|---|
| `secret` | `app.secret_key` | **>=16 chars**, same on every instance. Signs the session cookie. |
| `store` | `MemorySessionStore()` | Shared store for multi-instance (see `SessionStore`). |
| `cookie_secure` | `SESSION_COOKIE_SECURE` else `True` | `False` only for local http. |
| `cookie_samesite` / `cookie_domain` / `cookie_name` | `Lax` / config / `ark_auth` | |
| `session_ttl_seconds` | `expire_mins × 60` | |
| `refresh_leeway_seconds` | `120` | Refresh this long before access-token expiry. |
| `fetch_user_info` | `False` | Also call `/userinfo` at sign-in, merge into `current_ark.user`. |
| `return_to_param` | `returnTo` | |
| `default_return_to` | `/` | |
| `trust_proxy` | `True` | Honour `X-Forwarded-Proto`/`-Host` for this app's origin. |
| `service_token` | — | `auth_service_tkn` for `AuthClientHelper` onboarding calls. |

### `current_ark` (session request view; `LocalProxy`)

`is_authenticated: bool`, `user: dict | None` (ID token claims [+ UserInfo if `fetch_user_info`]),
`sub: str | None`, `claims: list[str]` (**Ark authorization claims — authorize on these**),
`scopes: list[str]`, `tokens: TokenSet | None`, `id_token: str | None`. Methods:
`access_token() -> str | None` (refreshed first if near expiry), `authorize(headers=None) -> dict`
(adds `Authorization: Bearer …`), `has_claim(*c) -> bool`, `has_scope(*s) -> bool`,
`context() -> ArkAuthContext`, `login(**opts)`, `logout(**opts)`.

Module-level accessors (mirror .NET `ArkTokenAccessors`): `get_ark_access_token() -> str | None`,
`get_ark_id_token()`, `get_ark_refresh_token()`, `with_ark_token(headers=None) -> dict`.

Account operations (mirror `ArkAccountExtensions`): `ark_switch_user(return_url=None, login_hint=None)`,
`ark_sign_out_everywhere(return_url=None)`, `ark_sign_out_locally(return_url=None)`,
`ark_denied_account() -> ArkDeniedAccount | None`.

### `ArkBearer` (resource server)

`ArkBearer(client=None, *, scopes=(), claims=(), audience=None, optional=False, require_type_header=True, **client_options)`.
Methods: `protect(app, prefix="") -> ArkBearer`, `require(scopes=(), claims=()) -> decorator`,
`__call__(view)` (decorator with construction-time scopes/claims). Request view **`g.ark`**:
`is_authenticated`, `sub`, `client_id`, `session_id`, `scopes`, `claims`, `payload`, `token`, `user`,
`has_claim(*c)`, `has_scope(*s)`. Failures follow RFC 6750 (401 missing/bad, 403 valid-but-forbidden).

## Configuration (`ArkAuthConfig`, section `ark_oauth_client`)

`ArkAuthConfig.from_mapping(dict)` binds any spelling (snake_case, camelCase, PascalCase) — an
existing `appsettings.json` loads unchanged.

| Field | Default | Notes |
|---|---|---|
| `authority` | — | **Required.** Issuer `{BaseUrl}/{TenantId}`. Or `auth_server_url` + `tenant_id`. |
| `client_id` | — | **Required.** |
| `client_secret` | — | Omit for public clients (SPA/native/CLI); PKCE is always sent. |
| `scopes` | `openid profile email offline_access` | `offline_access` earns the refresh token. |
| `callback_path` | `/signin-oidc` | Do not add a view here. |
| `signed_out_callback_path` | `/signout-callback-oidc` | |
| `signed_out_redirect_uri` | — | |
| `login_path` / `logout_path` | `/login` / `/logout` | |
| `auth_error_path` | — | Failed sign-in redirects here with `?auth_error=…`; else a plain 400. |
| `cookie_name` | `ark_auth` | |
| `expire_mins` | `480` | Session lifetime. |
| `domain` | — | Cookie domain; `localhost` ignored. |
| `role_claim_type` | `role` | Claim type Ark claims are projected onto. |
| `require_https_metadata` | `True` | `False` only for local dev. |
| `account_switch` | see below | `ArkAccountSwitchOptions`. |
| `use_legacy_flow` | `False` | Accepted for parity; **not implemented** in Python. |

Resolvers: `resolve_authority()`, `resolve_scopes()`, `resolve_callback_path()`,
`resolve_signed_out_callback_path()`, `resolve_cookie_name()`, `resolve_role_claim_type()`.

## Account switch (`ArkAccountSwitchOptions`, section `ark_oauth_client.account_switch`)

`enabled` (True), `auto_register_endpoints` (True), `require_ark_claims` (**False** — the switch),
`required_claims` (None), `access_denied_path` (`/ark/no-access`), `switch_user_path`
(`/ark/switch-user`), `sign_out_path` (`/ark/sign-out`), `serve_default_page` (True),
`app_display_name` (client id), `show_signed_in_account` (True), `allow_full_sign_out` (True),
`end_provider_session_on_switch` (False), `prompt` (`login`), `home_path` (`/`), `support_url`,
`support_email`.

**Events & options:** `ArkClientOptions(config, events)`; `ArkClientEvents.on_evaluate_access:
Callable[[ArkAccessEvaluationContext], bool]` (runs only when `require_ark_claims` on; returning
`True` allows sign-in; **replaces** the configured check), `ArkClientEvents.on_access_denied:
Callable[[ArkAccessDeniedContext], response | None]` (return a Flask response to render your own page,
or set `ctx.handled`). `ArkAccessDeniedReasons.NO_APP_ACCESS` / `.FORBIDDEN`.
`ArkChallengeProperties.switch_user(return_url=None, login_hint=None, prompt="login") -> dict`,
`.select_account(return_url=None)`. `ArkDeniedAccount`: `subject`, `email`, `name`, `reason`,
`return_url`. Helper `local_or_default(url, fallback)` keeps return URLs local (no open redirect).

## Protocol client (`ArkOAuthClient`)

`ArkOAuthClient(authority, client_id, client_secret=None, *, scopes=None, redirect_uri=None,
post_logout_redirect_uri=None, token_endpoint_auth_method=None, private_key_jwt=None, audience=None,
use_par=False, response_mode=None, prompt=None, acr_values=None, extra_authorization_params=None,
role_claim="role", clock_tolerance_seconds=60, require_https=True, require_token_hashes=True,
id_token_signing_algorithms=None, timeout=10, metadata_ttl=300, jwks_ttl=300,
jwks_min_refresh_interval=10, transport=None)`. Also `create_ark_client(config, **options)`.

Bad configuration raises `ArkConfigError` at construction (fragment in `redirect_uri`, plain-http
authority, `private_key_jwt` with no key, `client_secret` with `token_endpoint_auth_method="none"`).

| Method | Returns / notes |
|---|---|
| `create_authorization_url(*, redirect_uri=None, return_to=None, prompt=None, login_hint=None, scopes=None, max_age=None, ...)` | `AuthorizationRequest` (`.url`, `.state`, `.nonce`, `.to_dict()`/`from_dict`). |
| `handle_callback(params, transaction, *, redirect_uri=None) -> TokenSet` | Validates `iss`, `state`, `nonce`, `at_hash`, signature; exchanges the code. |
| `exchange_code(code, code_verifier, *, redirect_uri=None) -> TokenSet` | Lower-level exchange. |
| `refresh(refresh_token, *, scopes=None) -> TokenSet` | Rotation-aware. **Persist the result.** |
| `client_credentials(*, scopes=None) -> TokenSet` | Cached near expiry; uses the client's configured auth method. |
| `device_authorization(*, scopes=None) -> dict` | RFC 8628. |
| `poll_device_token(authorization) -> TokenSet` | Handles `authorization_pending` / `slow_down`. |
| `user_info(access_token) -> dict` | |
| `introspect(token, *, token_type_hint=None) -> dict` | RFC 7662. |
| `revoke(token, *, token_type_hint="refresh_token") -> bool` | RFC 7009. |
| `end_session_url(*, id_token_hint=None, post_logout_redirect_uri=None, state=None) -> str` | RP-initiated logout. |
| `verify_id_token(id_token, *, nonce=None, ...) -> dict` | Local verification. |
| `verify_access_token(token, *, audience=None, scopes=(), ark_claims=(), require_type_header=True) -> dict` | Enforces `typ: at+jwt`. |
| `push_authorization_request(params) -> dict` | RFC 9126. |
| `register_client(metadata, initial_access_token=None) -> dict` | RFC 7591. |
| `read_registration(client_id, registration_access_token) -> dict` | RFC 7592. |
| `delete_registration(client_id, registration_access_token) -> bool` | RFC 7592. |
| `check_setup(*, origin=None) -> dict` | `problems` list reads as sentences. |
| `metadata(*, force=False) -> dict`, `jwks -> JwksCache`, `config -> ArkConfig`, `authority -> str` | |

**`TokenSet`:** `access_token`, `id_token`, `refresh_token`, `claims` (validated ID-token claims),
`scopes() -> list[str]`, `has_scope(*s)`, `ark_claims() -> list[str]`, `subject`, `expired(leeway=0)`,
`to_dict()`/`from_dict()`.

## Non-browser helpers

**`ArkSetupProbe(config, **http)`**: `probe(*, origin, is_authenticated=False, signed_in_as=None,
auth_error=None) -> ArkSetupModel`; `read_metadata(authority=None) -> ArkProviderMetadata`; static
`discovery_url(authority)`. **`ArkSetupModel`** signals: `discovery_ok`, `discovery_error`,
`issuer_mismatch`, `unsupported_scopes`, `redirect_uri`, `post_logout_redirect_uri`,
`supports_dynamic_registration`, `supports_client_credentials`, `is_authenticated`, `signed_in_as`,
`tenant_id`, `admin_console_url`, `integration_page_url`, endpoint properties, `to_dict()`.
**`ArkProviderMetadata`** mirrors the discovery document (`issuer`, endpoints, `*_supported`, `.parse`).

**`ArkClientCredentials(config, probe, **http)`**: `get_token(client_id, client_secret, scopes=None,
authority=None) -> ArkTokenResult` (cached per client+scope, renewed ~60s early); `request_token(...)`
(bypasses cache; full exchange); classmethod `clear_cache()`. Authenticates with `client_secret_post`.
**`ArkTokenResult`**: `access_token`, `token_type`, `scope`, `expires_in`, `expires_at`,
`token_endpoint`, `status_code`, `error`, `error_description`, `request_form` (secret redacted),
`raw_response`, `succeeded`, `access_token_payload` (decoded, display only), `to_dict()`.

**`ArkRegistration(probe, **http)`**: `register(metadata, initial_access_token=None, authority=None)`,
`read(client_id, registration_access_token, ...)`, `delete(client_id, registration_access_token, ...)`
→ **`ArkRegistrationResult`**: `client_id`, `client_name`, `client_secret` (**once**),
`registration_access_token` (**once**), `registration_client_uri`, `endpoint`, `status_code`, `error`,
`error_description`, `succeeded`, `to_dict()`.

**`AuthClientHelper(config, service_token=None, **http)`**: `onboard_user(...)`, `onboard_customer(...)`
— wraps the provisioning API; treats "already exists in tenant" as success (safe to run twice).

**`ArkAuthContext`**: the per-request identity shape (`client_id`, `tenant_id`, `user_id`, `ip`,
`user_info: AUserInfo`) mirroring the .NET scoped service.

## Sessions (`SessionStore` protocol)

Implement four methods: `get(session_id) -> dict | None`, `set(session_id, data, ttl_seconds)`,
`destroy(session_id)`, `touch(session_id, ttl_seconds)`. `MemorySessionStore` is the per-process
default. `create_session_id()`, `sign_session_id(id, secret)`, `unsign_session_id(signed, secret)`.

## Errors (all subclass `ArkError`)

| Class | Meaning | Response |
|---|---|---|
| `ArkConfigError` | This app is misconfigured | Fix + redeploy (raised at construction where possible). |
| `ArkOAuthError` | Server refused; `.error` (RFC 6749 code), `.status`, `.endpoint` | Branch on `.error`. |
| `ArkTokenError` | A token failed validation | Never retry. |
| `ArkCallbackError` | Response not tied to a request this client started | Treat as CSRF / mix-up. |
| `ArkNetworkError` | Call did not complete | Retry with backoff. |

## Low-level (rarely needed)

`decode_jwt`, `verify_jwt`, `verify_signature`, `validate_claims`, `validate_token_hashes`, `sign_jwt`;
`PkcePair`, `PkceHelper` (`.generate_code_verifier()`/`.generate_code_challenge()`),
`create_pkce_pair`, `create_state`, `create_nonce`, `code_challenge_for`, `base64url_encode/decode`,
`left_half_hash`, `random_token`; `MetadataResolver`, `ArkDiscoveryCache`, `discovery_urls`,
`JwksCache`; `ArkJwt.decode_payload`, `ArkJson.prettify`, `ArkClaimReader`; `ArkConfig`,
`normalize_config`, `DEFAULT_SCOPES`, `PrivateKeyJwt`; `ArkCert`, `AUser`, `AUserInfo`.

> Note: `use_legacy_flow` is accepted for configuration parity with .NET but the legacy cookie/bearer
> middleware is **not implemented** here — the standard flow is the only supported one.
