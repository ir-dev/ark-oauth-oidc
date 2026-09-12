<!--
  AI-PROMPT.md — ark-oauth-client (Python)
  Audience: AI coding agents generating Python / Flask integration code.
  Source of truth: the code under src/ark_oauth_client/. Do not add APIs not listed here.
-->

# ark-oauth-client (Python) — AI coding instructions

Compact, source-verified instructions for an AI coding agent integrating the **`ark-oauth-client`**
PyPI package. Task recipes: [`AI-RECIPES.md`](AI-RECIPES.md); full API: [`API-GUIDE.md`](API-GUIDE.md);
failures: [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md); versions: [`MIGRATION.md`](MIGRATION.md). This is
the Python port of the .NET `Ark.oAuth.Client`, feature for feature.

## 1. Library identity

| | |
|---|---|
| **Package** | `ark-oauth-client` (PyPI) |
| **Current version** | `2.0.9` (moves in lockstep with `Ark.oAuth.Client` / npm `ark-oauth-client`) |
| **Import name** | `ark_oauth_client` (Flask helpers under `ark_oauth_client.flask`) |
| **Python** | `>=3.9` |
| **Install** | `pip install "ark-oauth-client[flask]"` (omit `[flask]` for the protocol client only) |
| **Purpose** | OAuth 2.1 / OIDC **client** (relying party) for Python. One call + `authority` + `client_id`, and `@auth.require_auth()` works. |
| **Problem solved** | A correct, self-contained OIDC client with `state`/`nonce`/`iss`/`at_hash` checks, JWKS rotation, silent refresh, and the shared-browser account-switch — without hand-rolling any of it. |
| **Runtime dependency** | `cryptography>=41` (signature verification). Everything else is stdlib. `flask>=2.2` is optional (the Flask integration). |
| **Config section** | `ark_oauth_client` (binds the same keys as .NET; accepts snake_case, camelCase, or PascalCase) |

Two ways in:
- **`ark_oauth_client.flask`** — `add_ark_oidc_client` / `add_ark_oidc_api` for Flask apps.
- **`ArkOAuthClient`** — the whole protocol on its own, for CLIs, workers, Django, FastAPI.

## 2. AI usage instructions

```text
When using ark-oauth-client:
1. Prefer the library's public APIs over custom OAuth/OIDC code. Never hand-roll the flow.
2. Flask: the entire integration is auth = add_ark_oidc_client(app, {authority, client_id}). It
   claims /login, /signin-oidc, /logout, /ark/no-access, /ark/switch-user, /ark/sign-out via a
   before_request hook. Do NOT add routes at those paths.
3. app.secret_key (or secret=) MUST be set, >=16 chars, and identical across every instance behind a
   load balancer — it signs the opaque session cookie. Tokens never reach the browser.
4. Only authority ({BaseUrl}/{TenantId}) and client_id are required; every endpoint/key comes from
   /.well-known/openid-configuration.
5. Do NOT invent APIs, config keys, or methods. If unsure, read src/ark_oauth_client/ (flask.py,
   client.py, config.py, access/*, flows/*, probe.py).
6. Authorize on Ark claims: @auth.require_claims("x") checks current_ark.claims (ark_claims), NOT
   OAuth scopes. Use @auth.require_scopes(...) for scopes.
7. Read the access token per request via current_ark.access_token() / get_ark_access_token(); it is
   refreshed automatically shortly before expiry. Never cache it.
8. For a downstream call: headers = current_ark.authorize(headers) (or with_ark_token(headers)).
9. Behind a load balancer / across restarts, pass a shared store= (get/set/destroy/touch), because
   the default MemorySessionStore is per-process.
10. Refresh tokens ROTATE: always persist what a refresh returns; replaying a retired one revokes the
    whole family. Add a cross-process lock in a shared store if two instances can refresh at once.
11. Errors are typed (ArkConfigError/ArkOAuthError/ArkTokenError/ArkCallbackError/ArkNetworkError) —
    branch on the class and on ArkOAuthError.error, never on message text.
```

## 3. Capability map

```text
Flask interactive sign-in
 ├── Purpose        Sign a browser user in; keep tokens server-side behind an opaque session cookie
 ├── Import         from ark_oauth_client.flask import add_ark_oidc_client, current_ark
 ├── Entry point    auth = add_ark_oidc_client(app, config, configure=None, **options) -> ArkFlask
 ├── Config         ark_oauth_client: authority, client_id, client_secret?, scopes, callback_path,
 │                  login_path, logout_path, auth_error_path, cookie_name, expire_mins,
 │                  role_claim_type, require_https_metadata, account_switch, use_legacy_flow
 ├── Options        secret, store, cookie_secure/samesite/domain, session_ttl_seconds,
 │                  refresh_leeway_seconds, fetch_user_info, default_return_to, trust_proxy, service_token
 ├── Served paths   /login /signin-oidc /logout /ark/no-access /ark/switch-user /ark/sign-out
 ├── Request view   current_ark (is_authenticated, user, sub, claims, scopes, tokens, access_token(),
 │                  authorize(headers), has_claim/has_scope, context(), login/logout)
 ├── Guards         @auth.require_auth(claims=[],scopes=[]), @auth.require_claims(*c), @auth.require_scopes(*s)
 └── Anti-patterns  routes at claimed paths; caching the token; per-process store behind a load balancer

API protection (resource server)
 ├── Purpose        Verify incoming bearer JWTs locally against the cached JWKS (no round trip)
 ├── Entry point    bearer = add_ark_oidc_api(app, prefix, authority=, client_id=, audience=?) -> ArkBearer
 ├── Per route      @bearer.require(claims=[], scopes=[]) ; @bearer as a decorator ; optional=True
 ├── Request view   g.ark (sub, client_id, scopes, claims, payload, has_claim/has_scope)
 └── Anti-patterns  statically configured keys; skipping the at+jwt type check

Account switch / shared-browser recovery
 ├── Purpose        Recover from SSO signing the wrong person in on a shared browser
 ├── Config         ark_oauth_client.account_switch (ArkAccountSwitchOptions)
 ├── Key setting    require_ark_claims (default False) — entitlement check moved to the callback
 ├── Events         events.on_evaluate_access(ctx)->bool, events.on_access_denied(ctx)->response|None
 ├── Views          ark_switch_user(), ark_sign_out_everywhere(), ark_sign_out_locally(), ark_denied_account()
 │                  ArkChallengeProperties.switch_user(...); auth.switch_user()/sign_out_everywhere()
 └── Anti-patterns  building your own "wrong account" page from scratch; open-redirect returnTo

Protocol client (no browser)
 ├── Purpose        The whole protocol for CLIs, workers, Django, FastAPI
 ├── Class          ArkOAuthClient(authority, client_id, client_secret?, redirect_uri?, ...)
 ├── Methods        create_authorization_url, handle_callback, exchange_code, refresh,
 │                  client_credentials, device_authorization, poll_device_token, user_info,
 │                  introspect, revoke, end_session_url, verify_access_token, verify_id_token,
 │                  push_authorization_request, register_client/read_registration/delete_registration,
 │                  check_setup
 └── Anti-patterns  storing state/nonce/code_verifier where the user can read/edit them

Non-browser flow helpers (parity with .NET services)
 ├── Setup probe    ArkSetupProbe(config).probe(...) -> ArkSetupModel ; .read_metadata() -> ArkProviderMetadata
 ├── Client creds   ArkClientCredentials(config, probe).get_token(id, secret, scopes) -> ArkTokenResult (cached)
 ├── Registration   ArkRegistration(probe).register/read/delete(...) -> ArkRegistrationResult (RFC 7591/7592)
 └── Onboarding     AuthClientHelper(config, service_token).onboard_user/onboard_customer(...)
```

## 4. API decision guide

```text
Flask app, sign users in?                    -> add_ark_oidc_client(app, {authority, client_id})
Protect a Flask view (must be signed in)?    -> @auth.require_auth()
Authorize by Ark claim?                       -> @auth.require_claims("billing.admin")
Authorize by OAuth scope?                     -> @auth.require_scopes("reports.read")
Call a downstream API as the user?            -> headers = current_ark.authorize(headers)
Get the raw access token?                     -> current_ark.access_token()  (or get_ark_access_token())
Build a resource-server API?                  -> add_ark_oidc_api(app, "/api", authority=, client_id=, audience=)
Public client (SPA/native/CLI)?               -> omit client_secret (PKCE is always sent)
Confidential client (server-side web)?        -> set client_secret (from env, not source)
Not Flask (CLI/worker/Django/FastAPI)?        -> ArkOAuthClient(...) directly
Machine-to-machine, no user?                  -> client.client_credentials(scopes=[...]) or ArkClientCredentials.get_token
Device with no browser/keyboard?              -> client.device_authorization() + client.poll_device_token(...)
Register a client programmatically?           -> client.register_client(metadata, initial_access_token) / ArkRegistration.register
Diagnose "invalid_client"/setup?              -> auth.setup_model() or client.check_setup()
Shared browser, wrong account, no way out?    -> account_switch.require_ark_claims = True
Custom entitlement rule?                      -> configure: options.events.on_evaluate_access = lambda ctx: ...
Behind a load balancer / multi-instance?      -> pass store=<shared store> and a same session secret

AVOID:
- use_legacy_flow (accepted for parity; the legacy middleware is NOT implemented in Python).
- Reading/validating the access token's contents in the client app (it is for the API).
- Storing state/nonce/code_verifier in a hidden field or plain cookie (that is the whole security).
```

## 5. Anti-patterns (do NOT generate)

```text
DO NOT:
- Hand-roll the authorization-code/PKCE/refresh flow. add_ark_oidc_client / ArkOAuthClient do it.
- Add a route at /login, /signin-oidc, /logout, or the /ark/* paths — the before_request hook owns
  them; a routed view shadows the hook.
- Cache the access token. Call current_ark.access_token() / get_ark_access_token() per request; the
  library refreshes ~120s before expiry.
- Use MemorySessionStore behind a load balancer or across restarts. Pass a shared store=; without it
  a callback that lands on a different instance fails with "could not be matched to a request".
- Store or return what a refresh replaced without persisting it. Refresh tokens rotate; presenting a
  retired one revokes the whole family (invalid_grant). Always save client.refresh(...)'s result.
- Put state/nonce/code_verifier anywhere the user can read or edit (hidden form field, plain cookie).
- Set require_https_metadata=False (or cookie_secure=False) anywhere but local http development.
- Request scopes the client record does not whitelist — rejected outright. offline_access earns the
  refresh token.
- Register only one redirect URI, or one that differs by a character. Matching is byte-for-byte
  (loopback ports excepted); register both the sign-in and post-logout callbacks.
- Assume a signed-in user is entitled. On a shared browser SSO can sign in the wrong account with a
  valid token and no ark_claims. Use account_switch.require_ark_claims to refuse at the callback.
- Grep error message text. Branch on the exception class and ArkOAuthError.error (the RFC 6749 code).
- Set use_legacy_flow=True expecting old behaviour — it is accepted but not implemented in Python.
```

## 6. Version & compatibility

- Python `>=3.9`; runtime dependency `cryptography>=41`; `flask>=2.2` optional.
- Current version **2.0.9**; ships with `Ark.oAuth.Client 2.0.9` and npm `ark-oauth-client 2.0.9`.
- Feature parity with the .NET client (plus device grant, PAR, introspection, revocation and
  `private_key_jwt` exposed on `ArkOAuthClient`). Full detail: [`MIGRATION.md`](MIGRATION.md).

## 7. AI context block (inject into a system/developer prompt)

```text
LIBRARY: ark-oauth-client (Python, v2.0.9, import ark_oauth_client)

PURPOSE:
OAuth 2.1 / OpenID Connect client for Python. Flask integration (add_ark_oidc_client / add_ark_oidc_api)
plus ArkOAuthClient for any framework. One dependency (cryptography). Port of .NET Ark.oAuth.Client.

USE WHEN:
- A Python app must sign users in against an Ark (or OIDC-compliant) provider, protect an API with
  bearer JWTs, do machine-to-machine tokens, the device grant, or programmatic client registration.

DO NOT USE WHEN:
- The app is the identity provider (that is the .NET Ark.oAuth.Oidc server).
- You want to hand-roll OAuth.

PRIMARY APIS:
- from ark_oauth_client.flask import add_ark_oidc_client, add_ark_oidc_api, current_ark
- auth = add_ark_oidc_client(app, {"authority": ..., "client_id": ...})
- @auth.require_auth() / @auth.require_claims("x") / @auth.require_scopes("y")
- current_ark.user / .claims / .scopes / .access_token() / .authorize(headers)
- bearer = add_ark_oidc_api(app, "/api", authority=, client_id=, audience=); @bearer.require(claims=[])
- from ark_oauth_client import ArkOAuthClient; client.create_authorization_url/handle_callback/refresh/
  client_credentials/device_authorization/poll_device_token/verify_access_token/verify_id_token/
  register_client/end_session_url/check_setup
- ArkClientCredentials / ArkRegistration / ArkSetupProbe (non-browser helpers)

CONFIGURATION ("ark_oauth_client"):
authority (required, {BaseUrl}/{TenantId}), client_id (required), client_secret (omit for public),
scopes (default openid profile email offline_access), callback_path (/signin-oidc),
login_path (/login), logout_path (/logout), role_claim_type (role), require_https_metadata (True),
account_switch.require_ark_claims (False), use_legacy_flow (False, not implemented).
Options: secret (>=16 chars, same across instances), store (shared for multi-instance), fetch_user_info.

PREFERRED PATTERNS:
Discovery-driven config; opaque session cookie + server-side store; per-request token read;
ark_claims -> require_claims; register both redirect URIs byte-for-byte; typed error handling.

ANTI-PATTERNS:
Hand-rolled flow; routes at claimed paths; cached token; per-process store behind a load balancer;
not persisting rotated refresh tokens; state/nonce/verifier in client-readable storage; unregistered
scopes; trusting a signed-in user without ark_claims; grepping error text; use_legacy_flow.

IMPORTANT CONSTRAINTS:
- Provider maps users to clients explicitly; no mapping => sign-in fails like a wrong password.
- authority is the FULL issuer including the tenant segment.
- Refresh tokens rotate; replay revokes the family.
- Tokens never reach the browser; the cookie is an opaque signed id.

ERROR HANDLING:
Typed: ArkConfigError (fix+redeploy), ArkOAuthError (.error/.status/.endpoint; branch on .error),
ArkTokenError (never retry), ArkCallbackError (treat as CSRF/mix-up), ArkNetworkError (retry w/ backoff).
Failed sign-in -> auth_error_path?auth_error=... else 400. ArkTokenResult/ArkRegistrationResult carry
.succeeded, .error, .error_description, and the raw exchange.

PERFORMANCE:
Discovery + JWKS cached (300s TTL; JWKS refetched on an unseen kid, min 10s apart). API verification is
local (no round trip). Client-credentials tokens cached per client+scope. Refresh ~120s before expiry.

EXAMPLE:
  from flask import Flask
  from ark_oauth_client.flask import add_ark_oidc_client, current_ark
  app = Flask(__name__); app.secret_key = os.environ["ARK_SESSION_SECRET"]
  auth = add_ark_oidc_client(app, {"authority": "https://idp/tenant", "client_id": "app"})
  @app.get("/billing")
  @auth.require_claims("billing.admin")
  def billing(): return current_ark.user["name"]
```
