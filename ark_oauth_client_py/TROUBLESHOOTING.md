<!--
  TROUBLESHOOTING.md — ark-oauth-client (Python)
  Audience: AI coding agents diagnosing failures. Causes/fixes from src/ark_oauth_client/ and README.
  Do not invent error strings.
-->

# ark-oauth-client (Python) — troubleshooting matrix

Diagnose against the package's actual behaviour. The fastest general diagnostic is `auth.setup_model()`
in a request, or `client.check_setup()` / `python examples/setup_check.py` (exits non-zero in CI).

## Sign-in / configuration

| Symptom | Likely cause | Diagnosis | Correct solution | Avoid |
|---|---|---|---|---|
| Sign-in fails as though the password were wrong | The user has no access mapping to this client | Provider: is there a user→client mapping? | Map the user to the client (console / provisioning) | Resetting the password |
| `the provider … identifies itself as '…'` | `authority` is not the issuer | It must be `{BaseUrl}/{TenantId}`, tenant included | Set the full issuer incl. tenant segment | Using just `{BaseUrl}` |
| `redirect_uri does not match a registered value` | Registered value differs by a character (scheme/port/slash) | `auth.setup_model().redirect_uri` — register that exactly | Register both `/signin-oidc` and `/signout-callback-oidc` byte-for-byte | Wildcards (only loopback ports are excepted) |
| `invalid_scope` | Requesting a scope the client does not whitelist | `setup_model().unsupported_scopes` | Add the scope to the client, or drop it from `scopes` | Assuming unknown scopes are dropped |
| `this client is registered for … not …` | Registered `token_endpoint_auth_method` ≠ what is sent | Compare the client record | Match the method (`none`/basic/post/private_key_jwt) | Guessing the method |
| `ArkConfigError` at startup | Bad config caught at construction | Message names it (fragment in `redirect_uri`, plain-http authority, `private_key_jwt` with no key, secret with `auth_method="none"`) | Fix and redeploy | Deferring the check to a user's sign-in |
| `a session secret of at least 16 characters is required` | `app.secret_key`/`secret=` missing or short | — | Set a 16+ char secret, same on every instance | A per-instance random secret behind a load balancer |
| Failed sign-in shows a plain 400 | No `auth_error_path` set | Sign-in errors go to `auth_error_path?auth_error=…` else 400 | Set `auth_error_path` and read `?auth_error` | Expecting an exception page |
| A route at `/login` or `/signin-oidc` never runs | The `before_request` hook owns those paths | Search for views at claimed paths | Remove the view; drive flows via `current_ark.login()` if needed | Mapping the claimed paths |

## Sessions / tokens

| Symptom | Likely cause | Diagnosis | Correct solution | Avoid |
|---|---|---|---|---|
| `this sign-in could not be matched to a request from this browser` | Login expired (10 min), or the process restarted with the in-memory store | Are you behind a load balancer / did the app restart? | Provide a shared `store=`; keep the login within 10 min | `MemorySessionStore` in multi-instance / across restarts |
| `invalid_grant` on the second refresh | A retired (rotated) refresh token was presented; family revoked | Are you persisting `client.refresh(...)`'s result? | Always store what a refresh returns; add a per-session lock in a shared store | Reusing the old refresh token |
| User bounced to the IdP mid-session | No refresh token (missing `offline_access`) | Is `offline_access` in `scopes` and whitelisted? | Add `offline_access` — refresh then happens silently | Extending `expire_mins` instead |
| Downstream API returns 401 after a while | The access token was cached and went stale | Are you storing the token? | Read per request: `current_ark.access_token()` / `authorize(headers)` | Caching the token in a global |
| A `Secure` cookie is not stored (login loops) | Plain http in local dev | Cookie is `Secure` by default | Pass `cookie_secure=False` locally only | Shipping `cookie_secure=False` |
| Tokens visible in the browser | (They are not) the cookie is an opaque signed id | — | Nothing — tokens stay server-side | Trying to read tokens from the cookie |

## API (resource server)

| Symptom | Likely cause | Diagnosis | Correct solution | Avoid |
|---|---|---|---|---|
| Valid ID token rejected on the API | `verify_access_token` enforces `typ: at+jwt` | An ID token is not an access token | Send the access token to the API | Presenting the ID token to an API |
| `no key with kid '…' is published` | Token from another provider, or a rotation less than `jwks_min_refresh_interval` (10s) ago | Which provider issued it? | Point at the right provider; a fresh rotation refetches shortly | Lowering `jwks_min_refresh_interval` to 0 |
| 401 with `insufficient_scope` mislabeled | Missing scope vs missing claim | 403 `insufficient_scope` = valid token, not allowed | Grant the scope/claim on the client + mapping | Treating 403 as an auth failure |
| Anonymous requests rejected when they should pass | `optional` not set | — | `add_ark_oidc_api(..., optional=True)`; check `g.ark.is_authenticated` | Custom anonymous handling |

## Shared browser / account switch

| Symptom | Likely cause | Diagnosis | Correct solution | Avoid |
|---|---|---|---|---|
| Signed in as somebody else on a shared machine | SSO answered from the other person's session | Is `account_switch.require_ark_claims` on? | Set it `True` — the callback is refused and `/ark/no-access` offers `prompt=login` | Telling users to clear cookies |
| A `403` renders as a `404` | No access-denied page in the app | — | Leave `account_switch` at defaults — the built-in page serves 403s | A bespoke error page just for this |
| `on_evaluate_access` never runs | `require_ark_claims` is off | It runs only when on | Turn `require_ark_claims` on | Expecting the event to gate access alone |
| `/ark/switch-user` or `/ark/sign-out` returns 405/400 | Not a POST, or cross-site | Method + `Sec-Fetch-Site`/`Origin` | POST from the same origin | GET links to these endpoints |
| Denied page can't name the account | `show_signed_in_account=False`, or no denial cookie | The name comes from a spent, encrypted cookie | Keep `show_signed_in_account=True`; ensure the same `secret` | Reading the name after another request (it is spent on first read) |

## Machine-to-machine / registration

| Symptom | Likely cause | Diagnosis | Correct solution | Avoid |
|---|---|---|---|---|
| `ArkTokenResult.succeeded` False, `invalid_client` | Wrong id/secret, or the client is not registered for `client_secret_post` | `request_token(...)` → `raw_response` | Register the client for `client_secret_post`, or use `ArkOAuthClient.client_credentials` | Using `ArkClientCredentials` for a `basic`-auth client |
| Client-credentials call slow / rate-limited | `request_token` per call | — | Use `get_token` (cached, renewed ~60s early) | Requesting a token every call |
| `registration_not_supported` | Provider advertises no `registration_endpoint` | `setup_model().supports_dynamic_registration` | Enable dynamic registration on the server | Guessing the URL |
| Registered a client but sign-in still fails | Registration ≠ access mapping | — | Map a user to the new client | Assuming registration grants access |
| Lost `registration_access_token` | Shown once | — | Re-create the registration (operator cleans up the old one) | Expecting to re-derive it |

## Network / TLS

| Symptom | Likely cause | Diagnosis | Correct solution | Avoid |
|---|---|---|---|---|
| `CERTIFICATE_VERIFY_FAILED` in development | The provider's dev certificate is untrusted | — | Trust it, or use `http://localhost` with `require_https_metadata=False` **locally only** | Disabling TLS verification in production |
| `ArkNetworkError` | Refused / DNS / timeout | Is the provider reachable? | Retry with backoff | Retrying an `ArkTokenError` (never valid) |
| A POST seems to follow a redirect | (It does not) POSTs are never redirected | — | Nothing — a GET of metadata/keys may follow one, a POST may not | Assuming POST redirects are honoured |
