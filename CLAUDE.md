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
| `ark_oauth_client_nodejs` | Node client (Express/Connect) | npm `ark-oauth-client-node` (`ark-oauth-client` up to 2.1.8) |
| `ark_oauth_client_js` | Browser/SPA client (public client; React, Next, Vue, Angular adapters) | npm `ark-oauth-client-js` |
| `Ark.oAuth.Oidc/Ark.Client.Web` | Reference client app — the shape to copy | not published |
| `Samples/client-js/react-client` | React SPA sample (browser only) on `ark-oauth-client-js`, with a guided QuickStart setup page | not published |
| `Ark.oAuth.Oidc/Ark.oAuth.Oidc.Host` | Runnable IdP host, configured through appsettings | not published |
| `Ark.oAuth.Oidc/Ark.oAuth.Oidc.QuickStart` | Zero-config IdP host: `AddArkIdp()` + `UseArkIdp()`, setup wizard on first run | not published |

The three client packages are **ports of each other and carry the same version number**. A change to
one is usually owed to the other two. An integration written in one translates almost line for line.
The browser client (`ark_oauth_client_js`) is a fourth port at the same version, using the same names
wherever a concept is shared, so a change to one of those is owed to it too.

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
import { arkExpress } from 'ark-oauth-client-node';
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
* **A new IdP needs no configuration.** `builder.AddArkIdp()` + `app.UseArkIdp()`; unconfigured, it
  serves the setup wizard at `/ark-idp/setup` and writes `ark-idp-data/settings.json` (a config
  source below user secrets / env). A host with `TenantId` + a connection string never sees it.
  In a container, point `Setup:DataPath` at persistent storage before the first start (App Service:
  under `/home`), and read the setup code from the container log: nothing there is loopback.
  Wizard code: `Code/ArkSetup.cs`, `Code/ArkIdpHosting.cs`, `wwwroot/setup/`.
* **A second IdP instance needs PostgreSQL or MySQL and nothing else.** The data-protection key
  ring (sign-in form anti-forgery token, console cookie) is kept in the IdP's own database unless the
  provider is SQLite or the host configured its own store (`ark_oauth_server:DataProtectionKeys`).
  Before that, a form drawn by one instance was refused by the next with a bare 400.
* **Look users and access mappings up through `ArkLookup`, never with `x.ToLower() == y.ToLower()`.**
  That comparison reads the whole table; with 30,000 accounts it was most of the server's load.
  Tenants, clients, scopes and the signing key come from `ArkIdpCache` (30 s, reset on any save that
  touches them); nothing about a user is ever cached. Before refusing a request for what a cached
  client says (secret, redirect URI, scope, grant, inactive), call `ArkIdpCache.ClientIfChangedAsync`:
  nothing may be refused on a stale copy.
* **.NET only:** keep the `Microsoft.IdentityModel.*` package graph on one version. A mixed graph
  fails only at runtime, on the first challenge, with a message that names none of this.
* **Python only:** `ArkClientCredentials` always authenticates with `client_secret_post`. The server
  matches the *registered* method exactly, so use `ArkOAuthClient.client_credentials` for a client
  registered any other way.

## Working in this repo

* **Never recreate the v1 client shape** (the removed `Ark.Auth.Client.Web`, still in git history):
  a pasted RSA public key, a custom callback route, no `state`/`nonce` validation.
  `Ark.Client.Web` is its replacement.
* **This repository is public.** Never commit a token, key or secret — not in a test, an example, a
  runbook or a commit message. A live signing key had to be purged from this history once already.
* **Release runbooks are checked in and kept current**, with commands verified on the release
  machine: `nuget_deploy.txt` and `ark_oauth_client_py/pip_deploy.txt`. Read the runbook before
  publishing; versions are immutable on all three registries once pushed.
* **Releases go through `.github/workflows/release.yml`** (manual dispatch): all five packages at
  one version, Trusted Publishing on every registry, then a `vX.Y.Z` GitHub release. The two npm
  packages are separate libraries with separate jobs and separate trusted publishers
  (`build-node`/`publish-npm-node`, `build-js`/`publish-npm-js`). The version is automatic
  (`scripts/version.sh next`): the highest `vX.Y.Z` tag with the patch number raised, or minor or
  major if the run asks; typing an exact version overrides it. Each runner stamps it into every
  manifest and over the "Next release" heading of the notes (`scripts/version.sh stamp`), and
  nothing is committed, so git lags until `stamp X.Y.Z` is run locally and committed. Do that
  before writing notes for the release after. Change versions with `set` or `stamp`, never by hand:
  the Python `__version__` and the browser client's `src/version.js` hold the version as literals,
  and the Python one has drifted more than once. Plain `X.Y.Z` only: npm rejects a fourth number.
* **Tests:** `pytest` in `ark_oauth_client_py` (142 tests), `npm test` in
  `ark_oauth_client_nodejs`, and `npm ci && npm test && npm run typecheck` in `ark_oauth_client_js`.
  All run against a stub IdP (`tests/stub_idp.py`, `test/stub-idp.js`)
  that mirrors the real server's wire behaviour — prefer it to a live server when changing a client.
  **The .NET side has no automated tests**, so `dotnet test` finds nothing. Verify .NET changes
  against a running `Ark.oAuth.Oidc.Host`.
* **Webhooks are an opt-in module** (`AddArkWebhooks()`, code in `Ark.oAuth.Oidc/Webhooks/`, spec in
  `WEBHOOKS.md`). Keep it that way: its tables live in its own two contexts, never in
  `ArkDataContext`, and the IdP raises events only through `ArkWebhookEvents.Raise(HttpContext, …)` —
  one call beside an existing audit line, which must never throw, block or touch the database.
  A host without the call must see no tables, no link and 404s.
* **Agent-to-agent (A2A) is built in and inert until a client lists a caller** (spec in
  `Ark.oAuth.Oidc/Ark.oAuth.Oidc/A2A.md`, logic in `Protocol/ArkAgentTokens.cs`). An agent is an
  ordinary confidential client, and the *target* names who may call it in `ArkClient.a2a_callers`.
  Keep these true: a token is addressed to one client (`aud` = its client_id, never the tenant
  audience as well); a delegated token carries the *user's* claims at the target and never outlives
  its subject token; a subject token is exchangeable only by the client it was issued to or
  addressed to; and a save that does not carry `a2a_callers_` leaves the list alone. The three
  server-side clients each ship `agent_token` / `verify_agent_token` / `agent_actors` under their
  own spelling; the browser client has none, because a public client cannot be an agent.
  `ArkClient.is_agent` is a label for the console badge and the audit trail: never read it to allow
  or refuse anything.
* **The server is an MCP server** (spec in `Ark.oAuth.Oidc/Ark.oAuth.Oidc/MCP.md`, code in `Mcp/`):
  setup at `/ark-idp/mcp` while unconfigured (setup code = bearer token, served by
  `ArkSetupMiddleware`), then host, `/{tenant}/mcp` and `/{tenant}/mcp/{client_id}`
  (`ArkMcpController`). Keep these true: an endpoint accepts only a token whose one `aud` is its own
  address (`ArkMcpAuth`), never a cookie and never a tenant-audience token; authority is read from the
  database per call, scopes only say look or change; a caller that is not the operator changes nothing
  outside its tenant, and an account only when `users.home_tenant_id` is that tenant; the `ark.*` claims
  are handed out only from the same level or above; in the operator tenant the tenant level *is* the
  operator's. A tool and its argument check come from one `ArkMcpParams`. Setup tools use the wizard's
  own validators, and setup secrets that never reach `settings.json` never reach the draft file either.
  The protocol is hand-written (no MCP SDK dependency): test it against the official Python, TypeScript
  and C# clients, in both the 2026-07-28 and the `initialize` era.
* **The audit trail to ARK-RAPID Watch is optional and must cost nothing when it is off**
  (`ark_oauth_server:Watch`, `Code/ArkWatch.cs`, package `Ark.Watch.Client`). No client, thread or
  file exists until an endpoint and a key are configured. Every `DataAccess.Log` / `Record` /
  `LogError` line is forwarded through `ArkWatchMap`; a new audit key needs a row there or it is
  filed as a generic event. A site that knows more passes its own `ArkWatchEvent`: the A2A paths do,
  through `Protocol/ArkAgentAudit.cs`. Keep these true: recording never throws or blocks; a token is
  named by its `jti`, never carried; and a refused A2A request is recorded with what was
  established before the refusal (`AgentTokenTrace`). Test against a scratch node built from the
  `Ark.Watch.Server` package, never a real one; on a laptop with a nearly full disk it answers 429
  until `ArkWatch__Wal__SoftDiskLimit` / `HardDiskLimit` are raised.
* **Load test:** `scripts/loadtest` (seed + generator) against a scratch host and database, never a
  real one. Results are published as a dated page under `site/performance/`. On a laptop, wrap a
  long run in `caffeinate -dimsu`: on battery the machine sleeps after a minute idle and the run
  reports a stall that never happened.
* Getting started end to end, including running the IdP locally: `GETTINGSTARTED.md`.
