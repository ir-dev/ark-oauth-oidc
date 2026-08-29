# ARK OAuth / OIDC — repository guide

Guidance for Claude Code (and anyone reading) working in this repository. It is checked in, so it
travels with the public repo: if you cloned this, this file applies to your session too.

## What this repository is

An **OAuth 2.1 / OpenID Connect identity provider** and its **client libraries in three languages**.
The provider is multi-tenant; administration is not (one operator tenant administers all).

| Path | What it is | Ships as |
|---|---|---|
| `Ark.oAuth.Oidc/Ark.oAuth.Oidc` | The IdP / authorization server | NuGet `Ark.oAuth.Oidc` |
| `Ark.oAuth.Oidc/Ark.oAuth.Client` | ASP.NET Core client | NuGet `Ark.oAuth.Client` |
| `ark_oauth_client_py` | Python client (Flask + framework-agnostic) | PyPI `ark-oauth-client` |
| `ark_oauth_client_nodejs` | Node client (Express/Connect) | npm `ark-oauth-client` |
| `Ark.oAuth.Oidc/Ark.Client.Web` | Reference client app — the shape to copy | not published |
| `Ark.oAuth.Oidc/Ark.oAuth.Oidc.Host` | Runnable IdP host | not published |
| `Ark.oAuth.Oidc/Ark.Auth.Client.Web` | **Legacy v1 client. Do not copy it.** | not published |

The three client packages are **ports of each other and carry the same version number**. A change to
one is usually owed to the other two. An integration written in one translates almost line for line.

## Using a client library (the common case)

Only two settings are ever required: the **authority** (the issuer, `{BaseUrl}/{TenantId}`) and the
**client_id**. Endpoints, signing keys and capabilities come from the provider's
`/.well-known/openid-configuration`, so nothing needs redeploying when a key rotates or an endpoint
moves. `client_secret` is omitted for public clients (SPA, native, CLI), which then use PKCE.

```python
# Python — ark_oauth_client_py/README.md has the full reference
from ark_oauth_client.flask import add_ark_oidc_client, current_ark
auth = add_ark_oidc_client(app, {"authority": "https://<host>/<tenant>", "client_id": "<id>"})

@app.get("/billing")
@auth.require_claims("billing.admin")      # Ark authorization claims, not scopes
def billing(): return current_ark.user["name"]
```

```csharp
// .NET — Ark.oAuth.Oidc/Ark.oAuth.Client/README.md has the full reference
builder.Services.AddArkOidcClient(builder.Configuration);    // "ark_oauth_client" config section
app.UseRouting();            // MUST precede the next two
app.UseAuthentication();
app.UseAuthorization();
```

```js
// Node — ark_oauth_client_nodejs/README.md has the full reference
import { arkExpress } from 'ark-oauth-client';
const auth = arkExpress({ authority, clientId, redirectUri, secret });
app.use(auth);
app.get('/billing', auth.requireClaims('billing.admin'), handler);
```

## Things that cost real time to rediscover

These apply in every language and are the source of most "it just says the password is wrong":

* **Register the user against the client.** Ark maps users to clients explicitly. With no mapping,
  sign-in fails with an error indistinguishable from a wrong password.
* **Redirect URIs are matched byte for byte**, and *both* must be registered — the sign-in callback
  (`/signin-oidc`) and the sign-out callback (`/signout-callback-oidc`).
* **Scopes on a client record are a whitelist.** An unregistered scope is rejected outright, not
  dropped. `offline_access` is what produces a refresh token.
* **Never add a route at the callback path** — it shadows the handler.
* **Read the access token per call**, never cache it; the client refreshes it underneath you.
* **Sign out of both the local session and the provider's**, or the provider session survives and
  the next sign-in is silent.
* **On a shared browser, SSO signs the next person in as the previous one**, and the resulting "no
  access" page has no way out, because the sign-in link returns to the same session. Every client
  ships the fix and it is **off by default**: `AccountSwitch:RequireArkClaims` (.NET),
  `account_switch.require_ark_claims` (Python). It moves the entitlement check to the callback so no
  session is written for an account that cannot use the app, and serves a page offering
  `prompt=login`.
* **.NET only:** keep the `Microsoft.IdentityModel.*` package graph on one version. A mixed graph
  fails only at runtime, on the first challenge, with a message that names none of this.
* **Python only:** `ArkClientCredentials` always authenticates with `client_secret_post`. The server
  matches the *registered* method exactly, so use `ArkOAuthClient.client_credentials` for a client
  registered any other way.

## Working in this repo

* **Never copy `Ark.Auth.Client.Web`.** It is the v1 shape — a pasted RSA public key, a custom
  callback route, no `state`/`nonce` validation. `Ark.Client.Web` is its replacement.
* **This repository is public.** Never commit a token, key or secret — not in a test, an example, a
  runbook or a commit message. A live signing key had to be purged from this history once already.
* **Release runbooks are checked in and kept current**, with commands verified on the release
  machine: `nuget_deploy.txt` and `ark_oauth_client_py/pip_deploy.txt`. Read the runbook before
  publishing; versions are immutable on all three registries once pushed.
* **Tests:** `pytest` in `ark_oauth_client_py` (129 tests) and `npm test` in
  `ark_oauth_client_nodejs`. Both run against a stub IdP (`tests/stub_idp.py`, `test/stub-idp.js`)
  that mirrors the real server's wire behaviour — prefer it to a live server when changing a client.
  **The .NET side has no automated tests**: `Test.Csle` is a console sample, not a test project, so
  `dotnet test` finds nothing. Verify .NET changes against a running `Ark.oAuth.Oidc.Host`.
* Getting started end to end, including running the IdP locally: `GETTINGSTARTED.md`.
