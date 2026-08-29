# ark-oauth-client

The OAuth 2.1 / OpenID Connect client for **Python** applications talking to an
[ARK Identity Server](../README.md) — the Python counterpart of the
[`Ark.oAuth.Client`](../Ark.oAuth.Oidc/Ark.oAuth.Client) NuGet package, feature for feature.

There is one URL to configure — the issuer, `{BaseUrl}/{TenantId}`. Endpoints, signing keys and
capabilities are read from the provider's discovery document, so the application does not have to be
redeployed when a key rotates or an endpoint moves.

One dependency: `cryptography`, for signature verification. Everything else — the HTTP layer, the
random values, the digests — is the standard library.

```bash
pip install ark-oauth-client
```

---

## Contents

- [Quick start](#quick-start)
- [What it implements](#what-it-implements)
- [Configuration](#configuration)
- [The Flask integration](#the-flask-integration)
- [Protecting an API](#protecting-an-api)
- [Account switching on a shared browser](#account-switching-on-a-shared-browser)
- [Sessions](#sessions)
- [Using the client directly](#using-the-client-directly)
- [The non-browser flows](#the-non-browser-flows)
- [Checking the setup](#checking-the-setup)
- [Errors](#errors)
- [Registering the client](#registering-the-client)
- [Coming from the .NET package](#coming-from-the-net-package)
- [Security notes](#security-notes)
- [Troubleshooting](#troubleshooting)
- [Development](#development)

---

## Quick start

```python
import os
from flask import Flask
from ark_oauth_client.flask import add_ark_oidc_client, current_ark

app = Flask(__name__)
app.secret_key = os.environ["ARK_SESSION_SECRET"]      # signs the session cookie

auth = add_ark_oidc_client(app, {
    "authority": "https://idp.example.com/my_idp",     # {BaseUrl}/{TenantId}
    "client_id": "my-app",
    "client_secret": os.environ.get("ARK_CLIENT_SECRET"),   # omit for public clients
})

@app.get("/")
def home():
    if not current_ark.is_authenticated:
        return '<a href="/login">Sign in</a>'
    return f"Hello {current_ark.user['name']}"

@app.get("/billing")
@auth.require_claims("billing.admin")
def billing():
    return "billing"
```

That is the whole integration. `/login`, `/signin-oidc` and `/logout` are served for you, along with
the account-switch endpoints. Authorization code + PKCE, `state`, `nonce`, `iss`, `at_hash`, JWKS
rotation, silent token refresh and sign-out are handled underneath.

Runnable versions of this and every other flow are in [`examples/`](examples/).

---

## What it implements

| Specification | What the client does |
|---|---|
| OpenID Connect Discovery 1.0 | Reads and caches `/.well-known/openid-configuration`; verifies `issuer` matches the configured authority |
| RFC 8414 metadata | Falls back to the `oauth-authorization-server` spelling for other providers |
| Authorization code (RFC 6749) | The only interactive flow; implicit and hybrid are gone in OAuth 2.1 and are not offered |
| PKCE (RFC 7636) | Always sent, `S256` only, verifier from `secrets` |
| OpenID Connect Core 1.0 | ID token verification: signature, `iss`, `aud`, `azp`, `exp`, `nbf`, `iat`, `nonce`, `at_hash`, `c_hash`, `auth_time`/`max_age` |
| RFC 7517 JWKS | Cached, and refetched on an unseen `kid`, so a two-phase key rotation needs no restart |
| RFC 9068 access tokens | `typ: at+jwt` enforced, so an ID token cannot be presented to an API in its place |
| Refresh (RFC 6749 §6) | Rotation-aware, scope narrowing, one refresh per session at a time |
| Client credentials | With per-client-and-scope caching |
| Device grant (RFC 8628) | Polling that handles `authorization_pending` and `slow_down` |
| PAR (RFC 9126) | `use_par=True`, or automatically when the tenant requires it |
| Introspection (RFC 7662) | With client authentication |
| Revocation (RFC 7009) | Called on sign-out, so the refresh-token family really ends |
| RP-Initiated Logout 1.0 | `id_token_hint`, `post_logout_redirect_uri`, `state` |
| RFC 9207 `iss` | Checked on every authorization response |
| Dynamic registration (RFC 7591/7592) | Register, read and delete |
| Client authentication | `client_secret_basic`, `client_secret_post`, `private_key_jwt`, `none` |

Ark's per-user-per-client authorization claims (`ark_claims` in the access token) are surfaced as
`current_ark.claims`, and are what `require_claims()` checks.

---

## Configuration

Only `authority` and `client_id` are required.

`add_ark_oidc_client` binds the same `ark_oauth_client` section the .NET package does, and accepts
either spelling of every key — `AuthServerUrl`, `authServerUrl` and `auth_server_url` are the same
setting — so an existing `appsettings.json` can be loaded with `json.load` and handed straight over.

| Setting | Default | Meaning |
|---|---|---|
| `authority` | — | The issuer URL: `{BaseUrl}/{TenantId}` |
| `auth_server_url` + `tenant_id` | — | Alternative to `authority`; joined for you |
| `client_id` | — | The client id registered with the tenant |
| `client_secret` | — | Confidential clients only. Omit for SPA, native and CLI clients |
| `scopes` | `openid profile email offline_access` | `offline_access` is what earns a refresh token |
| `callback_path` | `/signin-oidc` | Where the provider returns to |
| `signed_out_callback_path` | `/signout-callback-oidc` | |
| `login_path`, `logout_path` | `/login`, `/logout` | |
| `auth_error_path` | — | Where a failed sign-in lands, with `?auth_error=…`. Otherwise a plain 400 |
| `cookie_name` | `ark_auth` | |
| `expire_mins` | `480` | Session lifetime, matching the server's default |
| `domain` | — | Cookie domain; `localhost` is ignored |
| `role_claim_type` | `role` | Claim type Ark authorization claims are projected onto |
| `require_https_metadata` | `True` | Only ever `False` for local development |
| `account_switch` | see [below](#account-switching-on-a-shared-browser) | The shared-browser case |
| `use_legacy_flow` | `False` | Present for parity; the standard flow is the only supported one |

`ArkOAuthClient` — used directly — takes the protocol-level options as keyword arguments:
`token_endpoint_auth_method`, `private_key_jwt`, `redirect_uri`, `post_logout_redirect_uri`,
`audience`, `use_par`, `response_mode`, `prompt`, `acr_values`, `extra_authorization_params`,
`clock_tolerance_seconds` (60), `require_https` (True), `require_token_hashes` (True),
`id_token_signing_algorithms`, `timeout` (10s), `metadata_ttl` / `jwks_ttl` (300s),
`jwks_min_refresh_interval` (10s), and `transport` for injecting your own HTTP layer.

Mistakes are caught at construction, not at a user's sign-in: a `redirect_uri` with a fragment, a
plain-http authority, `private_key_jwt` with no key, a `client_secret` alongside
`token_endpoint_auth_method="none"`.

---

## The Flask integration

`add_ark_oidc_client(app, config, configure=None, **options)` is the counterpart of
`AddArkOidcClient` in `Program.cs`. It claims six paths and passes everything else through:

| Path | Purpose |
|---|---|
| `/login` | Starts a sign-in. `?returnTo=/somewhere` comes back to that page — same-origin paths only |
| `/signin-oidc` | Completes it |
| `/logout` | Revokes the refresh token, destroys the session, clears the cookie, then redirects to the provider's `end_session_endpoint` |
| `/ark/no-access` | The built-in access-denied page |
| `/ark/switch-user` | POST: abandon this account and ask for the sign-in form |
| `/ark/sign-out` | POST: end this application's session and the provider's |

They are served from a `before_request` hook rather than as routed views, exactly as the .NET client
serves them as middleware ahead of routing. The access-denied page has to render for a user who is
not signed in and may not be allowed to be, so it must not sit behind the application's own
authentication guard.

### `current_ark`

| Member | |
|---|---|
| `is_authenticated` | |
| `user` | ID token claims, plus UserInfo when `fetch_user_info=True` |
| `sub` | |
| `claims` | Ark authorization claims — **what to authorise on** |
| `scopes` | Granted scopes |
| `tokens` | The `TokenSet` |
| `access_token()` | The access token, renewed first if it is close to expiring |
| `authorize(headers)` | Returns headers with `Authorization: Bearer …` set, for a downstream call |
| `has_claim(...)`, `has_scope(...)` | |
| `context()` | An `ArkAuthContext`, the shape the .NET client's per-request service returns |
| `login(...)`, `logout(...)` | Drive the flows from your own views |

Module-level `get_ark_access_token()`, `get_ark_id_token()`, `get_ark_refresh_token()` and
`with_ark_token(headers)` mirror `ArkTokenAccessors`.

### Guards

```python
@auth.require_auth()                                       # signed in
@auth.require_claims("billing.admin")                      # Ark authorization claims
@auth.require_scopes("reports.read")                       # granted scopes
@auth.require_auth(claims=["tenant.root"], scopes=["admin"])
```

An unauthenticated **browser** request is redirected to the login page with a `returnTo`. Anything
else — `fetch`, XHR, a mobile client — gets `401` with an RFC 6750 challenge, because redirecting a
background request to a sign-in page produces a CORS error rather than anything the caller can act
on. A signed-in user missing a claim gets the access-denied page (403), never a redirect loop.

### Integration options

| Option | Default | |
|---|---|---|
| `secret` | `app.secret_key` | 16+ characters. Signs the session cookie. Same value on every instance |
| `store` | `MemorySessionStore` | See [Sessions](#sessions) |
| `cookie_secure` | `SESSION_COOKIE_SECURE`, else `True` | `False` only for local http |
| `cookie_samesite`, `cookie_domain`, `cookie_name` | `Lax`, from config, `ark_auth` | |
| `session_ttl_seconds` | `expire_mins × 60` | |
| `refresh_leeway_seconds` | `120` | Renew the access token this long before it expires |
| `fetch_user_info` | `False` | Also call `/userinfo` at sign-in and merge it into `current_ark.user` |
| `default_return_to` | `/` | |
| `trust_proxy` | `True` | Honour `X-Forwarded-Proto` / `X-Forwarded-Host` when deriving this app's origin |
| `service_token` | — | The `auth_service_tkn` for `AuthClientHelper` onboarding calls |

---

## Protecting an API

```python
from flask import Flask, g, jsonify
from ark_oauth_client.flask import add_ark_oidc_api

app = Flask(__name__)
bearer = add_ark_oidc_api(app, "/api",
    authority="https://idp.example.com/my_idp",
    client_id="my-api",
    audience="my_idp_api")          # omit to skip the audience check

@app.get("/api/me")
def me():
    return jsonify({"sub": g.ark.sub, "claims": g.ark.claims})

@app.get("/api/reports")
@bearer.require(claims=["reports.read"])
def reports():
    return jsonify({"reports": []})
```

Verification is local, against the cached JWKS, so a request costs no round trip to the identity
server. `optional=True` lets anonymous requests through with `g.ark.is_authenticated == False`.

---

## Account switching on a shared browser

The problem: single sign-on is browser-wide. Once one person has signed in anywhere, the provider's
session answers the authorize request of every other client in that browser. The second person opens
a different application, is silently signed in as the first, is told they do not have access — and
has no way back, because the sign-in link returns to the same session and gives the same answer.

Breaking that loop needs two things, and the package provides both:

```python
def configure(options):
    options.config.account_switch.require_ark_claims = True
    options.config.account_switch.app_display_name = "Billing Portal"
    options.config.account_switch.support_email = "help@example.com"

    # A rule of your own instead of the configured one.
    options.events.on_evaluate_access = lambda ctx: "tenant.root" in ctx.ark_claims
    # Log a denial, raise a ticket, or return a response to render your own page.
    options.events.on_access_denied = lambda ctx: print(ctx.email, ctx.reason)

auth = add_ark_oidc_client(app, config, configure)
```

**`require_ark_claims` moves the entitlement check to the callback.** An account with no `ark_claims`
for this client is refused *before* the session cookie is written, so the browser never holds a
session for somebody who cannot use the application.

**The page at `/ark/no-access` names the account that is signed in** and offers "Sign in as a
different user", which challenges with `prompt=login` so the provider draws its sign-in form instead
of answering from its session. It also catches ordinary 403s, which most applications never provide
a page for and which therefore render as a 404.

| Option | Default | |
|---|---|---|
| `enabled` | `True` | Serve the endpoints |
| `auto_register_endpoints` | `True` | Register them without an edit to your app factory |
| `require_ark_claims` | `False` | Refuse a sign-in with no `ark_claims` for this client |
| `required_claims` | — | Narrow it further: the user must hold at least one of these |
| `access_denied_path` | `/ark/no-access` | Point at your own view to take the UI over |
| `switch_user_path`, `sign_out_path` | `/ark/switch-user`, `/ark/sign-out` | |
| `serve_default_page` | `True` | Set `False` when `access_denied_path` is one of your routes |
| `app_display_name` | client id | Name of this application as the user knows it |
| `show_signed_in_account` | `True` | Print whose session it is — what makes the page make sense |
| `allow_full_sign_out` | `True` | Offer "sign out completely" as well |
| `end_provider_session_on_switch` | `False` | On: signs the previous user out of everything. For a kiosk |
| `prompt` | `login` | The one parameter every provider must honour |
| `home_path` | `/` | |
| `support_url`, `support_email` | — | The "who can give me access" link |

`ark_switch_user()`, `ark_sign_out_everywhere()`, `ark_sign_out_locally()` and
`ark_denied_account()` are importable for driving all of this from your own views.

Every part is **off or unchanged by default**: a host that sets nothing behaves exactly as before,
except that a 403 now reaches an explanation instead of a 404.

---

## Sessions

Tokens never reach the browser. The cookie carries an opaque session id and an HMAC over it; the
access token, refresh token and claims stay server-side in a store.

`MemorySessionStore` is the default and is fine for one process. Behind a load balancer, or across a
restart, supply a shared store — any object with these four methods:

```python
class RedisSessionStore:
    def get(self, session_id):                     ...   # -> dict | None
    def set(self, session_id, data, ttl_seconds):  ...
    def destroy(self, session_id):                 ...
    def touch(self, session_id, ttl_seconds):      ...

auth = add_ark_oidc_client(app, config, store=RedisSessionStore())
```

One thing to know when you do. This server **rotates refresh tokens**, and presenting a retired one
is treated as theft of the whole family. Concurrent refreshes within a process are serialised for
you; across processes they are not, so a shared store should also carry a short lock around the
refresh if your traffic can put two requests for the same session on two instances at the same
instant.

---

## Using the client directly

For CLIs, workers, Django, FastAPI, or any flow the Flask integration does not cover.

```python
from ark_oauth_client import ArkOAuthClient

client = ArkOAuthClient(
    authority="https://idp.example.com/my_idp",
    client_id="my-app",
    client_secret=...,
    redirect_uri="https://app.example.com/signin-oidc",
)
```

### Authorization code by hand

```python
# 1. starting a sign-in
tx = client.create_authorization_url(return_to="/dashboard")
save_somewhere_server_side(tx.to_dict())      # state, nonce, code_verifier
redirect(tx.url)

# 2. on the callback
tokens = client.handle_callback(request.args, tx)
tokens.access_token, tokens.id_token, tokens.refresh_token
tokens.claims          # validated ID token claims
tokens.ark_claims()    # Ark authorization claims
```

`state`, `nonce` and `code_verifier` are the entire security of the flow. Keep them somewhere the
user cannot read or edit — a hidden form field or a plain cookie hands an attacker exactly the three
values the checks are made of.

### The rest

```python
client.refresh(refresh_token)              # store what comes back: the old one is now dead
client.client_credentials(scopes=[...])    # cached until near expiry
client.device_authorization(scopes=[...]); client.poll_device_token(authorization)
client.user_info(access_token)
client.introspect(token, token_type_hint="refresh_token")
client.revoke(refresh_token)
client.end_session_url(id_token_hint=tokens.id_token, state=...)
client.verify_access_token(token, scopes=["reports.read"], ark_claims=["billing.admin"])
client.verify_id_token(id_token, nonce=...)
client.push_authorization_request(params)
client.register_client(metadata, initial_access_token)
```

---

## The non-browser flows

The three services `AddArkOidcClient` registers in the .NET package are here too, with the same
result objects — request form, HTTP status and response body — so a failure can be read rather than
guessed at.

```python
from ark_oauth_client import ArkAuthConfig, ArkClientCredentials, ArkRegistration, ArkSetupProbe

config = ArkAuthConfig.from_mapping({"authority": ..., "client_id": ...})
probe = ArkSetupProbe(config)

result = ArkClientCredentials(config, probe).get_token(client_id, client_secret, ["reports.read"])
result.succeeded, result.access_token, result.request_form   # the secret is redacted
result.access_token_payload                                  # decoded for display only

registration = ArkRegistration(probe)
created = registration.register({"client_name": "…", "redirect_uris": [...]}, initial_access_token)
created.client_secret, created.registration_access_token     # both shown exactly once
registration.read(created.client_id, created.registration_access_token)
registration.delete(created.client_id, created.registration_access_token)
```

`ArkClientCredentials` authenticates with `client_secret_post`, as the .NET class does, so the client
it is used with must be registered for that method. For a client registered any other way, use
`ArkOAuthClient.client_credentials`, which applies whichever method the client is configured for.

`AuthClientHelper` wraps the provisioning API (`onboard_user`, `onboard_customer`), and treats
"already exists in tenant" as success so an installer is safe to run twice.

---

## Checking the setup

```python
model = auth.setup_model()      # inside a request
model.discovery_ok, model.issuer_mismatch, model.unsupported_scopes
model.redirect_uri              # register this exactly
model.admin_console_url, model.integration_page_url
```

Or, without a request, `client.check_setup()` returns a plain dict whose `problems` list reads as
sentences. Render it on a health page, or run `python examples/setup_check.py` in CI — it exits
non-zero when something is wrong, so it fails a pipeline rather than a sign-in.

---

## Errors

Every error carries what is needed to decide what to do next, rather than a string to grep.

| Class | Meaning | Usual response |
|---|---|---|
| `ArkConfigError` | This application is misconfigured | Fix and redeploy; raised at construction where possible |
| `ArkOAuthError` | The server refused. `.error` is the RFC 6749 code, `.status` the HTTP status, `.endpoint` the URL | Branch on `.error` |
| `ArkTokenError` | A token failed validation — signature, issuer, audience, expiry, `nonce`, `at_hash` | Never retry. The answer cannot be trusted |
| `ArkCallbackError` | The authorization response does not belong to a request this client started | Treat as CSRF or a mix-up attempt |
| `ArkNetworkError` | The call did not complete: refused, DNS, timeout | Retry with backoff |

```python
from ark_oauth_client import ArkOAuthError

try:
    client.refresh(token)
except ArkOAuthError as error:
    if error.error == "invalid_grant":
        sign_in_again()
    else:
        raise
```

---

## Registering the client

In the admin console at `/{tenant}/admin`, or from the generated setup page at
`/{tenant}/oauth2/integrate/{client_id}`:

| Field | Value |
|---|---|
| Redirect URI | Exactly your `redirect_uri`, e.g. `https://app.example.com/signin-oidc` |
| Post-logout redirect URI | Your `post_logout_redirect_uri` |
| Grant types | `authorization_code`, `refresh_token` |
| Scopes | `openid`, `profile`, `email`, `offline_access` |
| Auth method | `none` for a public client, `client_secret_basic` for a confidential one |

Then **give each user access to the client**. Ark maps users to clients explicitly, and without a
mapping sign-in fails in a way that looks exactly like a wrong password.

A server-side Python application needs nothing in the tenant's `CorsOrigins` — that list is for
browser clients redeeming their own codes.

---

## Coming from the .NET package

The names carry over; only the casing changes.

| `Ark.oAuth.Client` | `ark_oauth_client` |
|---|---|
| `services.AddArkOidcClient(configuration)` | `add_ark_oidc_client(app, config)` |
| `services.AddArkOidcClient(configuration, options => …)` | `add_ark_oidc_client(app, config, configure)` |
| `builder.AddArkOidcApi(config)` | `add_ark_oidc_api(app, prefix, …)` |
| `app.UseArkOidcClient()` | not needed — registration happens in `add_ark_oidc_client` |
| `app.UseArkAccountEndpoints()` | `use_ark_account_endpoints(app)` |
| `ArkAuthConfig` | `ArkAuthConfig` — `from_mapping` binds either spelling |
| `ArkAccountSwitchOptions` | `ArkAccountSwitchOptions` |
| `ArkClientEvents.OnEvaluateAccess` / `OnAccessDenied` | `events.on_evaluate_access` / `on_access_denied` |
| `ArkChallengeProperties.SwitchUser(...)` | `ArkChallengeProperties.switch_user(...)` |
| `HttpContext.ArkSwitchUserAsync()` | `ark_switch_user()` |
| `HttpContext.ArkSignOutEverywhereAsync()` | `ark_sign_out_everywhere()` |
| `HttpContext.ArkSignOutLocallyAsync()` | `ark_sign_out_locally()` |
| `HttpContext.ArkDeniedAccount()` | `ark_denied_account()` |
| `HttpContext.GetArkAccessTokenAsync()` | `get_ark_access_token()` |
| `request.WithArkTokenAsync(context)` | `with_ark_token(headers)` |
| `ArkSetupProbe` / `ArkSetupModel` / `ArkProviderMetadata` | same names |
| `ArkClientCredentials` / `ArkTokenResult` | same names |
| `ArkRegistration` / `ArkRegistrationResult` | same names |
| `AuthClientHelper` | `AuthClientHelper` |
| `ArkAuthContext` / `AUserInfo` / `AUser` | same names |
| `ArkJwt.DecodePayload` / `ArkJson.Prettify` | `ArkJwt.decode_payload` / `ArkJson.prettify` |
| `PkceHelper.GenerateCodeVerifier()` | `PkceHelper.generate_code_verifier()` |
| `[Authorize(Roles = "billing.admin")]` | `@auth.require_claims("billing.admin")` |

Two differences worth stating. The .NET package configures ASP.NET Core's own OIDC and cookie
handlers; there is no equivalent to configure in Python, so the protocol is implemented here and
tested against a stub that mirrors the server. And `use_legacy_flow` is accepted for configuration
parity but the legacy cookie/bearer middleware is not reimplemented — it never validated `state` or
`nonce` and was a migration aid in the .NET package, not a supported configuration.

---

## Security notes

- **Tokens never reach the browser.** The cookie is an opaque id plus a signature; it is `HttpOnly`,
  `Secure` and `SameSite=Lax`.
- **The session id is replaced at sign-in**, so an id planted before authentication is never the one
  that ends up authenticated.
- **`state` is compared in constant time**, and `iss` is checked on every authorization response.
- **A missing `nonce` or `at_hash` fails as hard as a wrong one.** Absence is the easiest check to
  skip and the easiest one to attack.
- **`alg: none` is refused**, and the accepted algorithms are decided before the token's own header
  is read.
- **JWKS refetching is rate-limited**, and a `kid` already known to be absent never triggers another
  fetch — otherwise a stream of forged tokens turns this client into a request amplifier pointed at
  your identity server.
- **A POST is never redirected.** A GET of metadata or keys may follow a redirect; a POST carries a
  client secret or an authorization code and must not.
- **`returnTo` accepts same-origin paths only**, so the login route cannot become an open redirect.
- **The switch and sign-out endpoints require a same-origin POST**, so a cross-site page cannot end
  a user's session.
- **The denial cookie is encrypted and spent on first read**, so a stale one cannot name the wrong
  account on a later visit.
- **Sign-out revokes the refresh token** before ending the local session.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `redirect_uri does not match a registered value` | The registered value differs by a character — scheme, port, trailing slash. Matching is exact, with one carve-out for loopback ports |
| Sign-in fails as though the password were wrong | The user has no access mapping to this client |
| Signed in as somebody else on a shared machine | SSO answered from the other person's session. Turn on `require_ark_claims` and use `/ark/no-access` |
| `this sign-in could not be matched to a request from this browser` | The login expired (10 minutes), or the process restarted with the in-memory store |
| `invalid_grant` on the second refresh | A retired refresh token was presented; the family is revoked. Always store what a refresh returns |
| `the provider … identifies itself as '…'` | `authority` is not the issuer. It is `{BaseUrl}/{TenantId}`, tenant id included |
| `no key with kid '…' is published` | A token from a different provider — or a rotation less than `jwks_min_refresh_interval` ago that has not been refetched yet |
| `this client is registered for … not …` | The client's registered `token_endpoint_auth_method` differs from the one being sent |
| `CERTIFICATE_VERIFY_FAILED` in development | The provider's development certificate is not trusted. Trust it, or point at `http://localhost` with `require_https_metadata=False` **locally only** |
| A `Secure` cookie is not stored | Plain http in local development. Pass `cookie_secure=False` |

---

## Development

```bash
pip install -e ".[dev]"
pytest
```

The tests run against `tests/stub_idp.py`, a stand-in for the Ark server that mirrors what it
actually does rather than what the specs merely permit: the same paths, RS256 with a `kid` and two
published keys across a rotation, `at+jwt` access tokens carrying `ark_claims`, ID tokens with
`at_hash`/`c_hash`, `iss` on the authorization response, refresh-token rotation where replaying a
retired token revokes the family, and RFC 6749 §5.2 error bodies with the right status codes.

Building for PyPI:

```bash
python -m build
twine check dist/*
twine upload dist/*
```

---

## Licence

MIT — see [LICENSE](LICENSE).
