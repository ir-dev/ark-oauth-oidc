<!--
  AI-RECIPES.md — ark-oauth-client (Python)
  Audience: AI coding agents. Each recipe = a reusable prompt + a verified example.
  Every API used below exists in src/ark_oauth_client/. Do not add others.
-->

# ark-oauth-client (Python) — AI recipes

Task-oriented prompts and canonical, source-verified examples. Pair with
[`AI-PROMPT.md`](AI-PROMPT.md) (rules) and [`API-GUIDE.md`](API-GUIDE.md) (full API).

Install `pip install "ark-oauth-client[flask]"` · config section `ark_oauth_client` · version `2.0.9`.
Runnable versions of most of these are in [`examples/`](examples/).

---

## Recipe 1 — Basic Flask sign-in

> **PROMPT:** "Use ark-oauth-client to add OAuth 2.1 / OIDC sign-in to a Flask app with only
> `authority` and `client_id`. Set a session secret. Do not add routes at the claimed paths."

```python
import os
from flask import Flask
from ark_oauth_client.flask import add_ark_oidc_client, current_ark

app = Flask(__name__)
app.secret_key = os.environ["ARK_SESSION_SECRET"]      # >=16 chars; signs the session cookie

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
```

- **Served for you:** `/login`, `/signin-oidc`, `/logout`, and the `/ark/*` account endpoints.
- **Register on the provider:** the client, **both** redirect URIs (`…/signin-oidc` and
  `…/signout-callback-oidc`) byte-for-byte, and a user→client access mapping.
- **Mistake:** defining a view at `/login` or `/signin-oidc` — the `before_request` hook owns them.

---

## Recipe 2 — Authorize by Ark claim (and by scope)

> **PROMPT:** "Guard a view by Ark authorization claim. Ark issues `ark_claims`; authorize on those,
> not on OAuth scopes."

```python
@app.get("/billing")
@auth.require_claims("billing.admin")           # checks current_ark.claims (ark_claims)
def billing():
    return f"hello {current_ark.user['name']}"

@app.get("/reports")
@auth.require_scopes("reports.read")            # checks granted OAuth scopes
def reports():
    return "reports"

@app.get("/root")
@auth.require_auth(claims=["tenant.root"], scopes=["admin"])   # both
def root():
    return "root"
```

- **Behaviour:** an unauthenticated **browser** GET is redirected to `/login?returnTo=…`; a
  `fetch`/XHR/API request gets `401` + an RFC 6750 challenge (redirecting XHR would be a CORS error).
  A signed-in user missing a claim gets the access-denied page (`403`), never a redirect loop.

---

## Recipe 3 — Call a downstream API as the user

> **PROMPT:** "Call a downstream API on behalf of the signed-in user. Read the token per request
> (never cache) and attach it with the library helper."

```python
import requests
from ark_oauth_client.flask import current_ark   # or: from ark_oauth_client.flask import with_ark_token

@app.get("/things")
@auth.require_auth()
def things():
    headers = current_ark.authorize({"Accept": "application/json"})   # adds Authorization: Bearer …
    r = requests.get("https://api.example.com/things", headers=headers)
    return r.json()
```

- `current_ark.access_token()` (or `get_ark_access_token()`) returns the current token, refreshed
  first if it is about to expire.
- **Mistake:** caching the token in a module global; it goes stale and the API returns 401.

---

## Recipe 4 — Protect an API (resource server)

> **PROMPT:** "Protect a Flask API with bearer JWTs from the Ark provider. Verify locally against the
> cached JWKS; validate audience only if configured."

```python
from flask import Flask, g, jsonify
from ark_oauth_client.flask import add_ark_oidc_api

app = Flask(__name__)
bearer = add_ark_oidc_api(app, "/api",
    authority="https://idp.example.com/my_idp",
    client_id="my-api",
    audience="my_idp_api")            # omit to skip the audience check

@app.get("/api/me")
def me():
    return jsonify({"sub": g.ark.sub, "claims": g.ark.claims})

@app.get("/api/reports")
@bearer.require(claims=["reports.read"])
def reports():
    return jsonify({"reports": []})
```

- **Local verification:** no round trip to the IdP per request. `optional=True` lets anonymous
  requests through with `g.ark.is_authenticated == False`.
- **Mistake:** configuring a static signing key — keys come from the JWKS and rotate automatically.

---

## Recipe 5 — Shared-browser account switch (the "wrong account" fix)

> **PROMPT:** "On a shared browser SSO can sign the next person in as the previous one with a valid
> token but no access. Enable the account-switch fix so the callback is refused and the built-in page
> offers `prompt=login`. Use the `configure` callback."

```python
def configure(options):
    options.config.account_switch.require_ark_claims = True     # check moves to the callback
    options.config.account_switch.app_display_name = "Billing Portal"
    options.config.account_switch.support_email = "help@example.com"

auth = add_ark_oidc_client(app, config, configure)
```

- **Effect:** an account with no `ark_claims` for this client never gets a session; the user lands on
  `/ark/no-access`, which names the signed-in account and offers **Sign in as a different user**
  (challenges with `prompt=login`).
- **Left at default (`False`):** behaviour unchanged, except the built-in page now also serves
  ordinary `403`s (which most apps otherwise 404).
- **Kiosk variant:** `options.config.account_switch.end_provider_session_on_switch = True`.

---

## Recipe 6 — Account-switch / sign-out from your own views

> **PROMPT:** "Add a 'Not you?' action and a full sign-out using the importable helpers. Keep returnTo
> local."

```python
from ark_oauth_client.flask import ark_switch_user, ark_sign_out_everywhere, ark_sign_out_locally

@app.post("/not-you")                 # POST + same-origin (the built-in endpoints enforce this too)
def not_you():
    return ark_switch_user(return_url="/")      # drop local session, challenge prompt=login

@app.post("/sign-out")
def sign_out():
    return ark_sign_out_everywhere(return_url="/")   # local + provider (RP-initiated logout)
```

- Also: `ark_sign_out_locally(return_url)` (local session only), `ark_denied_account()` (who was
  refused). Or build challenge properties with `ArkChallengeProperties.switch_user(return_url, login_hint, prompt)`.

---

## Recipe 7 — Custom entitlement rule + your own denied page

> **PROMPT:** "Decide access with my own rule and render my own access-denied page. Use the
> `configure` events and point `access_denied_path` at my route."

```python
def configure(options):
    options.config.account_switch.require_ark_claims = True      # on_evaluate_access runs only when on
    options.config.account_switch.access_denied_path = "/no-access"
    options.config.account_switch.serve_default_page = False     # your route renders it

    options.events.on_evaluate_access = lambda ctx: "tenant.root" in ctx.ark_claims   # True = allow
    options.events.on_access_denied = lambda ctx: app.logger.warning("no access: %s", ctx.email)

auth = add_ark_oidc_client(app, config, configure)

@app.get("/no-access")
def no_access():
    from ark_oauth_client.flask import ark_denied_account
    refused = ark_denied_account()     # subject/email/name/reason/return_url, or None
    return render_template("no_access.html", refused=refused), 403
```

- `on_access_denied` may **return a Flask response** to render your own page (or set `ctx.handled`).
- `on_evaluate_access` **replaces** the configured `require_ark_claims` check; combine in your lambda
  if you want both.

---

## Recipe 8 — Shared session store (behind a load balancer)

> **PROMPT:** "Run multiple instances behind a load balancer. Provide a shared session store and the
> same secret everywhere. Guard the rotating refresh."

```python
class RedisSessionStore:
    def get(self, session_id):                    ...   # -> dict | None
    def set(self, session_id, data, ttl_seconds): ...
    def destroy(self, session_id):                ...
    def touch(self, session_id, ttl_seconds):     ...

auth = add_ark_oidc_client(app, config, store=RedisSessionStore(), secret=SHARED_SECRET)
```

- **Same `secret` on every instance** (it signs the cookie).
- **Refresh tokens rotate.** In-process refreshes are serialised for you; across instances they are
  not — add a short per-session lock around the refresh in your store if two requests for one session
  can hit two instances at the same instant, or a retired token gets replayed and the family is
  revoked.

---

## Recipe 9 — Use the protocol client directly (CLI / worker / Django / FastAPI)

> **PROMPT:** "Drive the authorization code flow by hand with ArkOAuthClient. Store state/nonce/
> verifier server-side only."

```python
from ark_oauth_client import ArkOAuthClient

client = ArkOAuthClient(
    authority="https://idp.example.com/my_idp",
    client_id="my-app",
    client_secret=...,                       # omit for public clients
    redirect_uri="https://app.example.com/signin-oidc",
)

# 1. start
tx = client.create_authorization_url(return_to="/dashboard")
save_server_side(tx.to_dict())               # state, nonce, code_verifier — never client-readable
# redirect the user to tx.url

# 2. callback
tokens = client.handle_callback(request_params, tx)   # validates iss, state, nonce, at_hash, signature
tokens.access_token, tokens.id_token, tokens.refresh_token
tokens.claims          # validated ID token claims
tokens.ark_claims()    # Ark authorization claims
```

- **Never** put `state`/`nonce`/`code_verifier` in a hidden field or plain cookie — those three
  values are the entire security of the flow.

---

## Recipe 10 — Refresh, client-credentials, device, introspect, revoke

> **PROMPT:** "Use the other ArkOAuthClient methods. Persist rotated refresh tokens."

```python
tokens = client.refresh(refresh_token)               # store what comes back — the old one is now dead
m2m    = client.client_credentials(scopes=["reports.read"])   # cached until near expiry
auth   = client.device_authorization(scopes=["openid"])       # show auth["user_code"]/verification_uri
tokens = client.poll_device_token(auth)                       # handles authorization_pending / slow_down
info   = client.user_info(access_token)
state  = client.introspect(token, token_type_hint="refresh_token")
client.revoke(refresh_token)                                  # ends the family
url    = client.end_session_url(id_token_hint=tokens.id_token, state="...")
```

- `client.verify_access_token(token, scopes=[...], ark_claims=[...])` and
  `client.verify_id_token(id_token, nonce=...)` validate locally against the cached JWKS.

---

## Recipe 11 — Machine-to-machine via the helper (cached)

> **PROMPT:** "A worker needs a token as itself. Use ArkClientCredentials (cached). It authenticates
> with client_secret_post."

```python
from ark_oauth_client import ArkAuthConfig, ArkClientCredentials, ArkSetupProbe

config = ArkAuthConfig.from_mapping({"authority": "https://idp/my_idp", "client_id": "svc"})
creds = ArkClientCredentials(config, ArkSetupProbe(config))

result = creds.get_token("my_machine_client", secret, ["reports.read"])   # cached per client+scope
if not result.succeeded:
    raise RuntimeError(f"{result.error}: {result.error_description}")
token = result.access_token
# result.request_form has the secret redacted; result.access_token_payload is decoded for display only
```

- `ArkClientCredentials` always uses `client_secret_post`. For a client registered any other way, use
  `ArkOAuthClient(...).client_credentials(...)`, which applies the client's configured method.

---

## Recipe 12 — Dynamic client registration (RFC 7591 / 7592)

> **PROMPT:** "Register a client dynamically. Persist the returned credentials — they are shown once."

```python
from ark_oauth_client import ArkRegistration, ArkSetupProbe, ArkAuthConfig

probe = ArkSetupProbe(ArkAuthConfig.from_mapping({"authority": "https://idp/my_idp", "client_id": "x"}))
reg = ArkRegistration(probe)

created = reg.register(
    {"client_name": "New App", "redirect_uris": ["https://new.example.com/signin-oidc"]},
    initial_access_token,                       # needs the client.register scope (via client_credentials)
)
# PERSIST NOW — shown once: created.client_id, created.client_secret, created.registration_access_token
reg.read(created.client_id, created.registration_access_token)
reg.delete(created.client_id, created.registration_access_token)
```

- Registration is **not** access: a user must still be mapped to the new client to sign in.

---

## Recipe 13 — Setup check in a request and in CI

> **PROMPT:** "Add a health check that compares config to the provider's live metadata, and a CI gate."

```python
# inside a request:
model = auth.setup_model()
model.discovery_ok, model.issuer_mismatch, model.unsupported_scopes
model.redirect_uri            # register this exactly
model.admin_console_url, model.integration_page_url

# without a request (e.g. CI): client.check_setup() returns a dict whose "problems" read as sentences.
# examples/setup_check.py exits non-zero when something is wrong, so it fails a pipeline, not a sign-in.
```

---

## Recipe 14 — Typed error handling

> **PROMPT:** "Handle errors by type, not by message text."

```python
from ark_oauth_client import ArkOAuthError, ArkTokenError, ArkNetworkError

try:
    tokens = client.refresh(refresh_token)
except ArkOAuthError as e:
    if e.error == "invalid_grant":     # refresh token spent/revoked -> sign in again
        start_sign_in()
    else:
        raise
except ArkTokenError:
    abort(401)                          # token failed validation — never retry
except ArkNetworkError:
    retry_with_backoff()
```

- `ArkConfigError` is raised at construction where possible (bad redirect_uri, plain-http authority,
  `private_key_jwt` with no key, secret alongside `token_endpoint_auth_method="none"`).
- `ArkCallbackError` — the response does not match a request this client started (treat as CSRF/mix-up).
