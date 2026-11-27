# Ark.oAuth.Oidc

A self-contained OAuth 2.1 and OpenID Connect provider for ASP.NET Core. Add two lines to
`Program.cs`, point any standard OIDC library at the issuer URL, and it configures itself from the
discovery document.

Multi-tenant, runs on SQLite / MySQL / PostgreSQL / SQL Server, and ships its own sign-in, consent
and admin UI. The matching client package is [`Ark.oAuth.Client`](https://www.nuget.org/packages/Ark.oAuth.Client).

**Project website:** <https://ir-dev.github.io/ark-oauth-oidc/>

> **For AI coding agents** — prompt-oriented, source-verified docs live beside this README:
> [`AI-PROMPT.md`](AI-PROMPT.md) (rules + capability map + injectable context block),
> [`AI-RECIPES.md`](AI-RECIPES.md) (task → code recipes), [`API-GUIDE.md`](API-GUIDE.md) (host APIs,
> endpoints, settings, management routes + decision guide), [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md)
> (symptom → cause → fix), [`MIGRATION.md`](MIGRATION.md) (versions, schema scripts, upgrading). The
> C# in this directory is authoritative; do not invent APIs, endpoints, or settings.

## Install and run: nothing to configure first

```bash
dotnet new web -n MyIdp
cd MyIdp
dotnet add package Ark.oAuth.Oidc
```

```csharp
using Ark.oAuth.Oidc;

var builder = WebApplication.CreateBuilder(args);
builder.AddArkIdp();          // the identity provider, and sign-in for its own admin console

var app = builder.Build();
app.UseHttpsRedirection();
app.UseArkIdp();              // routing, CORS, setup wizard, bootstrap, auth, endpoints, in order
app.Run();
```

`dotnet run` and open the app. With no tenant and no database configured, every page goes to the
**setup wizard** at `/ark-idp/setup`, which collects everything the server needs:

| Step | What it captures |
|---|---|
| Organization & branding | organization and product name, website / terms / privacy URLs, your logo and a default app logo (uploaded, with a live sign-in page preview) |
| Server address | public URL, operator tenant id and display name, optional base path, and the landing page after sign-in (the public URL unless you choose another page). Shows the issuer and discovery URL it will produce |
| Database | SQLite, PostgreSQL or MySQL, built from fields or a raw connection string, with **Test connection** |
| Signing key | **Generate** an RSA key pair (2048 / 3072 / 4096) or import an existing PEM. Shows the kid and public key; the private key can be revealed or downloaded |
| Administrator | username, name and password (with a generator) |
| Users & email | how new users get their first password, a default password, SMTP with **Send test** |
| Protocol & security | device flow, PAR, dynamic registration, consent, back-channel logout, session and lockout limits, CORS origins, and a generated secret for the machine client |
| Review & install | everything on one page, then **Install** |

Install writes the settings, creates and seeds the database, and reloads configuration. **The same
running process is now the IdP**, with no restart. `/` leads to the sign-in page, and from there to
the landing page: the admin console, unless the wizard was given another page. Anyone who signed in
on the way to a particular page goes back to that page instead, and a host page's "Sign in" link
can do the same with `/ark-idp/signin?returnUrl=/that/page`. Every later start skips the wizard.

### Configuring through appsettings instead

A server that already has `ark_oauth_server:TenantId` and `ConnectionStrings:ArkAuthConnection`
(from appsettings, user secrets, the environment, anything) never sees the wizard. That is the
route for pipeline-built deployments, and every setting below still applies. To bring your own
console sign-in, `Ark.oAuth.Client` in this example, use the lower-level calls:

```csharp
using Ark.oAuth;
using Ark.oAuth.Oidc;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddArkOidcServer(builder.Environment);   // the identity provider
builder.Services.AddArkOidcClient(builder.Configuration); // the admin console is itself a client
builder.Services.AddControllersWithViews();

var app = builder.Build();

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();        // must come before UseAuthentication / UseAuthorization
app.UseArkOidcCors();    // only needed if browser-based clients call the token endpoint
app.UseArkAuthData();    // setup wizard (if unconfigured), then the one-time database bootstrap
app.UseArkOidcClient();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(name: "default", pattern: "{controller=Home}/{action=Index}/{id?}");
app.Run();
```

`builder.AddArkIdp(o => o.ConsoleSignIn = false)` is the middle ground: the wizard and the
pipeline, with the console's sign-in left to you.

`UseRouting()` has to run before `UseAuthentication()` / `UseAuthorization()`. Without a selected
endpoint the authorization middleware cannot see the `[Authorize]` metadata it is meant to enforce.

## appsettings.json

```jsonc
{
  "ark_oauth_server": {
    "TenantId": "my_idp",              // a client named "<TenantId>_client" is seeded for the admin console
    "BasePath": "",                    // set only if the app is hosted under a sub-path
    "BaseUrl": "https://idp.example.com",
    "Provider": "sqlite",              // sqlite (default) | mysql | postgres
    "UploadPath": "./wwwroot/{0}/",
    "DefaultPw": "<initial password for new users>",
    "UserPasswordMode": "admin_managed", // admin_managed | email_based | auto (legacy behaviour)
    "DataProtectionKeys": "auto",      // auto | database | off - see "Running at scale"
    "AdminUser": {                     // the account seeded when the database is first created
      "Username": "admin",             // optional, defaults to "admin"; need not be an email address
      "Password": "<required>",        // no default - see below
      "Name": "Admin User"
    },
    "Admin": {
      "SignOutUrl": "/Home/SignOutAll", // where the console's Sign out link goes; see below
      "LandingUrl": ""                  // AddArkIdp's sign-in only: where it lands when started at /; empty = the console
    },
    "Oidc": {
      "EnableA2A": true,                // agent-to-agent tokens; inert until a client lists a caller (A2A.md)
      "A2ATokenLifetimeSeconds": 300,
      "A2AMaxDelegationDepth": 4,
      "EnableDeviceFlow": true,
      "EnablePushedAuthorizationRequests": true,
      "RequirePushedAuthorizationRequests": false,
      "EnableDynamicRegistration": false,
      "RequireRegistrationAccessToken": true,
      "AlwaysRequireConsent": false,
      "SessionLifetimeMinutes": 480,
      "MaxFailedSignIns": 10,
      "LockoutMinutes": 15,
      "EnableBackChannelLogout": true,       // see "Signing out"
      "BackChannelLogoutTimeoutSeconds": 5,
      "LogoutTokenLifetimeSeconds": 120,
      "SignOutAllBrowserSessions": true,     // sign-out covers every session in the browser
      "SignOutAcrossTenants": true,
      "CorsOrigins": [],               // exact origins of any single-page-application clients
      "CleanupIntervalMinutes": 60,    // expired codes, tokens and sessions are purged this often
      "AuditRetentionDays": 0,         // 0 keeps the audit trail for ever
      "ReferenceCacheSeconds": 30,     // see "Running at scale"
      "ClientSecretCacheSeconds": 300,
      "MaxConcurrentPasswordHashes": 0, // 0 = half the cores
      "MaxPasswordHashWaitSeconds": 0   // 0 = a sign-in waits its turn however long; set to shed load instead
    }
  },
  "ConnectionStrings": {
    "ArkAuthConnection": "Data Source=./data/ark_auth.db"
  }
}
```

On first run the server creates its schema, generates an RSA signing key in-process, seeds the OIDC
scope catalogue and creates the administrator account from `AdminUser`.

`AdminUser:Password` is **required and has no default** — the server used to compile in
`admin` / `admin`, which put the same credentials on the account that administers every tenant of
every deployment. It falls back to `DefaultPw`, and a value left as a `<<placeholder>>` counts as
unset; with neither configured, the first request fails with a message naming the setting and no
database is created. Supply it out of band rather than in `appsettings.json`:

```bash
dotnet user-secrets set "ark_oauth_server:AdminUser:Password" "…"   # development
export ark_oauth_server__AdminUser__Password="…"                    # environment
```

The section is only read while the database is being created. Changing it afterwards renames
nothing and resets no password — use the console.

`UserPasswordMode` lets the host choose one password-onboarding flow for newly created accounts.
Use `admin_managed` when operators set or communicate passwords out of band, or `email_based`
when email-address accounts should be parked in reset mode and sent an activation link. `auto`
keeps the older mixed behaviour, where the caller decides.

Your issuer is `{BaseUrl}/{TenantId}`, and discovery lives at
`{BaseUrl}/{TenantId}/.well-known/openid-configuration`.

## What's supported

| Specification | Status |
|---|---|
| OAuth 2.0 (RFC 6749) | Authorization code, refresh token, client credentials |
| PKCE (RFC 7636) | **Required** for public clients, `S256` only |
| OpenID Connect Core 1.0 | ID tokens, UserInfo, `nonce`, `at_hash`/`c_hash`, `auth_time`, `sid` |
| OIDC Discovery 1.0 | `/.well-known/openid-configuration` |
| AS Metadata (RFC 8414) | `/.well-known/oauth-authorization-server` |
| JWKS (RFC 7517) | `/.well-known/jwks.json`, two-phase key rotation |
| JWT Access Tokens (RFC 9068) | `typ: at+jwt`, `client_id`, `jti`, `scope` |
| Introspection (RFC 7662) | Access and refresh tokens |
| Revocation (RFC 7009) | Revokes the whole refresh-token family |
| Device Grant (RFC 8628) | With `verification_uri_complete` |
| PAR (RFC 9126) | Optional, can be made mandatory |
| Dynamic Registration (RFC 7591/7592) | Optional, off by default |
| RP-Initiated Logout 1.0 | `end_session_endpoint`, browser-wide by default |
| Back-Channel Logout 1.0 | Signed `logout_token` POSTed to each client that took part |
| Issuer Identification (RFC 9207) | `iss` in the authorization response |
| Native Apps (RFC 8252) | Loopback redirect URIs with variable ports |
| Token Exchange (RFC 8693) | For agent-to-agent calls on behalf of a user: `act` chain, audience-bound, never outlives the token exchanged |
| Agent-to-agent (A2A) | Tokens addressed to one agent (`aud` = its client_id), a caller list per agent, the Agent Card security section — see [A2A.md](A2A.md) |
| Model Context Protocol | The server's own MCP endpoints, for setup, host, tenant and application — see [MCP.md](MCP.md) |
| Resource Indicators (RFC 8707), Protected Resource Metadata (RFC 9728) | For those endpoints |

Deliberately **not** supported: the implicit grant, the hybrid flow, and the resource owner password
credentials grant — all three are removed in OAuth 2.1.

## Endpoints

All paths are relative to the issuer, `{BaseUrl}/{TenantId}`.

| Purpose | Path |
|---|---|
| Discovery | `/.well-known/openid-configuration` |
| JWKS | `/.well-known/jwks.json` |
| Authorization | `/oauth2/authorize` |
| Token | `/oauth2/token` |
| UserInfo | `/oauth2/userinfo` |
| Introspection | `/oauth2/introspect` |
| Revocation | `/oauth2/revoke` |
| End session | `/oauth2/logout` |
| Device authorization | `/oauth2/device_authorization` |
| Pushed authorization request | `/oauth2/par` |
| Dynamic registration | `/oauth2/register` |
| MCP server of the tenant, of one application | `/mcp`, `/mcp/{client_id}` |
| Client setup page | `/oauth2/integrate/{client_id}` |

Signed in to the admin console, every registered client has a generated setup page at
`/{tenant_id}/oauth2/integrate/{client_id}` carrying its exact issuer, client ID, scopes, redirect
URIs and copy-paste snippets for the Ark client package, the raw ASP.NET Core handler,
`oidc-client-ts`, Authlib and `go-oidc`.

That page will also **run the flow for you**. Pick one of the client's redirect URIs and press
*Start the flow*: the page generates a real `code_verifier` and `S256` `code_challenge` in your
browser and runs the authorization request in an embedded iframe, ending on the redirect URI with
the code and state in its query string. Nothing is simulated — it is the same request your
application makes — and the verifier is shown alongside the `curl` that redeems the code, which is
the fastest way to prove PKCE end to end before writing any client code. The frame ends up on the
application's own origin, so if the application refuses to be framed, *Open in a new tab* runs the
identical flow.

## Signing out

`end_session_endpoint` is `/{tenant_id}/oauth2/logout`, and two things about it are worth knowing
before pointing a client at it.

**It signs out the whole browser, not one session.** The session cookie holds a single `sid`, but a
browser accumulates sessions: each sign-in creates one and overwrites the cookie, so every earlier
session stays live — with its refresh tokens — while becoming unreachable from the browser. On a
shared machine that is a different person, and ending only the session the cookie names leaves them
signed in everywhere they had been. A second cookie, `ark_idp_bid`, identifies the **browser**
rather than the sign-in; every session records the browser it was created in, and logout ends all
of them. It is a random value that means nothing without those session rows, and it is deliberately
kept across sign-out — it identifies the user agent, not the user.

**Clients are told, if they ask to be.** Register a `backchannel_logout_uri` and the client is
POSTed a signed `logout_token` whenever a session it took part in ends —
`application/x-www-form-urlencoded`, one `logout_token` parameter, answer 200 or 204. The token is
`typ: logout+jwt`, carries the `http://schemas.openid.net/event/backchannel-logout` event and,
unless the client turns `backchannel_logout_session_required` off, the `sid` to end. It never
carries a `nonce`, so it cannot be replayed into an ID token validator. Verify it against the same
JWKS as an ID token. Set the URI in the console's client editor, at `/oauth2/register` (RFC 7591)
or in the provisioning call; a client without one is simply never contacted, which is where every
existing client starts.

The clients notified are the ones that were logged in under the session — recorded when the
authorization code is issued, rather than derived from live refresh tokens, which would miss every
client that never asked for `offline_access`. Sessions are revoked before the first notification
goes out and each delivery has its own timeout, so **a client that is down cannot stop a user
signing out**; the failure is logged as a warning and named on the signed-out page.

| Setting | Default | |
|---|---|---|
| `Oidc:EnableBackChannelLogout` | `true` | Notifies nobody until a client registers a URI |
| `Oidc:BackChannelLogoutTimeoutSeconds` | `5` | Per client; deliveries run in parallel |
| `Oidc:LogoutTokenLifetimeSeconds` | `120` | |
| `Oidc:SignOutAllBrowserSessions` | `true` | Off ends only the session the cookie names |
| `Oidc:SignOutAcrossTenants` | `true` | Off keeps a sign-out inside the tenant it was asked of |

Front-channel logout is **not** implemented, and discovery no longer claims otherwise.

## Provisioning API

Standing up a new application is four operations in a fixed order: register the client, register
its redirect URIs, create the account, and add the per-user-per-client access mapping. The last is
the one that gets forgotten, and its absence looks exactly like a wrong password on the sign-in
page. This does all four in one call.

```http
POST /api/oauth/v1/provision/client
Content-Type: application/json

{
  "client_name": "Billing Portal",          // required
  "user_name":   "jane@example.com",        // required - an email address or a plain username
  "tenant_id":   "my_idp",                  // defaults to ark_oauth_server:TenantId
  "client_id":   "billing_portal",          // derived from client_name when omitted
  "client_logo": "https://…/logo.png",      // or a data: URI; shown on the sign-in page
  "redirect_uris": [ "https://billing.example.com/signin-oidc" ],
  "claims": [ "sub", "name", "email", "email_verified" ],
  "send_activation_email": false
}
```

```jsonc
// 200
{ "error": false, "code": "provisioned",
  "msg": "client 'billing_portal' created in tenant 'my_idp' - the new user signs in with the configured default password.",
  "data": { "client_id": "billing_portal", "client_created": true,
            "user_name": "jane@example.com", "user_created": true,
            "user_credential": "default_password", "mapping_created": true,
            "issuer": "…", "discovery": "…", "setup_url": "…" } }

// 409 - the name is taken. Nothing was written.
{ "error": true, "code": "client_exists", "msg": "an application named 'Billing Portal' …" }
```

Collisions are handled asymmetrically on purpose. An existing **client name** is refused and
nothing is written — quietly rewriting the redirect URIs of a live application would turn an
onboarding script into a way to redirect somebody else's authorization codes. An existing **user**
is reused and mapped to the new client, because that is exactly what happens when a person is
given their second application.

A user this call creates gets `ark_oauth_server:DefaultPw` and can sign in immediately unless the
host's `ark_oauth_server:UserPasswordMode` requires the email activation flow. In `auto` mode,
set `send_activation_email` to email a link instead; the account then cannot sign in until it is
used.

The console's **Provision an application** panel — on the administrator's *Provisioning* page,
linked from the console's own navigation — is this endpoint with a form in front of it. Fill the
form in and the page shows the same call as a `curl` command, with the values you typed already
in it.

## Deactivating a user or a client

Both an account and an application can be switched off without being deleted, and the sign-in
screen says which of the two it was — an application names itself, an account is told it has been
deactivated and who to ask. Neither message is reachable without the correct password, so the one
deliberately-vague message shown for every credentials failure still holds and the form cannot be
used to enumerate accounts.

```http
POST /api/oauth/v1/activation/client   { "tenant_id": "my_idp", "client_id": "billing_portal", "is_active": false }
POST /api/oauth/v1/activation/user     { "user_name": "jane@example.com", "is_active": false }
```

Deactivating revokes what has already been handed out — a client loses its refresh tokens, a user
loses their sessions *and* their refresh tokens — because otherwise the switch would not take
effect until they expired, up to fourteen days later. Access tokens already issued are
self-contained and remain valid until they expire, which is the usual bound on revoking a JWT.

The console's **Activation** panel — on the same *Provisioning* page — states the request as a
form and lists every client and account with its current state below it. Both endpoints need the
same authorization as the rest of the management API, below; the page itself is restricted to the
administrator account (`AdminUser:Username`, or a principal carrying an `admin` claim).

### Who may call the management API

Everything under `/api/oauth/v1/…` answers to the operator only, and the package decides that itself
— the host registers nothing and keeps its own default scheme. A caller is admitted if it is either

* the console session of the operator: the `AdminUser:Username` account, or an account carrying an
  `admin` claim on its mapping to the console client; or
* a bearer token this server issued to the machine client `{TenantId}_machine` with the
  `client.register` scope — which is how a pipeline provisions.

Anyone else gets `401` or `403` with a JSON body, never the sign-in page. A token with
`client.register` issued to any other client is refused: holding the scope does not make a client
the operator. `client.register` cannot be requested through provisioning or dynamic registration;
only an operator grants it, in the console.

The machine client ships without a secret. Give it one in the console (**Regenerate secret**), or
from configuration, so a fresh deployment can be provisioned without anyone signing in:

```bash
ark_oauth_server__Management__MachineClientSecret="$(openssl rand -base64 32)"   # env / key vault
```

It is applied on start-up and rotated by changing it. While it is set, the console will not
regenerate that client's secret, because the next restart would put the configured one back.
Whoever can read this setting is the operator, so keep it out of `appsettings.json`.
`Management:OperatorDeviceClients` admits device-code tokens approved by the operator, for a CLI;
it is empty by default and best left so.

### The machine client's secret, end to end

Most "registration fails with `invalid_client`" reports come down to this, so here is the whole
process.

1. **Know which secret is which.** A client app has its *own* `ark_oauth_client:ClientSecret`
   (`null` for a public client). The machine client `{TenantId}_machine` is a *different* client
   with its own secret. A caller that registers clients or calls the management API needs the
   second one.
2. **Expect it to be missing.** The machine client is seeded with **no secret**: on first run, and
   again whenever the database is recreated (deleted `data/`, factory reset, a `replace` import).
   The IdP stores only a PBKDF2 hash, so any secret a caller already holds stops working with no
   sign on the caller's side. "Configured" in a caller means only that it has *a* value.
3. **Diagnose by trying it.** `invalid_client: client authentication failed.` means the secret
   doesn't match. That includes the case where the IdP has none.
   ```bash
   curl -s -X POST https://<host>/<tenant>/oauth2/token -d grant_type=client_credentials \
     -d client_id=<tenant>_machine --data-urlencode client_secret="$SECRET" -d scope=client.register
   ```
4. **Give it one**, either way:
   * *Console:* **Clients → `{TenantId}_machine` → Regenerate secret**. It is shown once, so copy it
     then.
   * *Configuration:* `ark_oauth_server:Management:MachineClientSecret`, at least 16 characters. It
     is applied during the bootstrap, so a recreated database gets it back automatically. Rotate it
     by changing the setting; the console then refuses to regenerate it.
5. **Hand it to the caller out of source control:** an environment variable, a key vault
   reference, or pasted for a single use. Never `appsettings.json`. Whoever holds it is the
   operator.
6. **Verify:** step 3's command returns an `access_token`, and
   `GET /api/oauth/v1/client/list` with `Authorization: Bearer <access_token>` answers 200.

## Admin console

The console ships in this package. Referencing it is all the wiring there is:

| Purpose | Path |
|---|---|
| Console | `/{tenant_id}/admin` (`/admin` redirects to the configured tenant) |
| Its stylesheet and script | `/ark-admin/asset/ark-admin.css`, `/ark-admin/asset/ark-admin.js` |

Tenants, clients, users, scopes, claims, the per-user-per-client access mapping, one-call
provisioning and the two activation switches — all over the management API at
`/api/oauth/v1/…`. The page is self-contained — no layout, `_ViewStart`, tag
helper or `wwwroot` entry is required of the host, because the view brings its own shell and the
two assets are served straight out of the assembly. Tabulator is its one external dependency,
loaded pinned from unpkg.

Two things are worth knowing:

* **Sign out.** The console's session is the host application's authentication cookie, and only the
  host can drop it, so point `ark_oauth_server:Admin:SignOutUrl` at a route of your own that signs
  out of both the cookie and the OIDC scheme. Left unset, the link falls back to the tenant's
  `end_session_endpoint`, which ends the session at the IdP but leaves the local cookie in place.
* **Overriding it.** Application views win over package views: put your own
  `Views/Admin/Manage.cshtml` in the host to replace the page and keep the routes and API.

`AddArkOidcServer` also unpacks the assets to the host's content root in Development, so they can
be read and edited on disk; the served copies always come from the assembly.

The v1 console at `/oauth/{tenant}/v1/server/{client_id}/manage` is still served for existing
deployments and is no longer developed.

## Webhooks

Opt-in, with one line beside the server's own registration:

```csharp
builder.Services.AddArkWebhooks();
```

The console then has a **Webhooks** page (operator only) where endpoints are configured: the URL,
which events (`user.signed_in`, `token.issued`, `client.*`, …), how to authenticate (Basic, a static
token, a JWT minted per request with HS256 or the tenant's RS256 key, or an OAuth 2.0 access token
from a refresh token or client credentials), custom headers, the retry policy, the
consecutive-failure threshold that disables the endpoint for its tenant, and its **shard plan** —
shared, dedicated, hashed over one or more databases, or monthly tables. Deliveries are stored
before they are sent, signed per Standard Webhooks, retried with back-off, dead-lettered when they
cannot be delivered, and replayable; the page shows delivery history and analytics. A database-backed
dispatcher runs on every instance with bounded concurrency and compare-and-swap claims, so several
instances share the work safely.

Without the line nothing of it runs: no tables, no background work, no link, and its routes answer
404. Everything — events, payload, signature verification, configuration, the API — is in
[WEBHOOKS.md](WEBHOOKS.md).

## Agent-to-agent (A2A)

Agents are ordinary confidential clients, and a token for calling one is addressed to it alone: its
`aud` is that agent's client_id, so it is refused everywhere else. The agent being called decides
who may call it — open its client in the console, **Agent-to-agent (A2A)** → **Add calling
client** — and with nothing listed, which is how every client starts, nobody can.

```bash
# the agent as itself
curl -s {issuer}/oauth2/token -u agent-a:$SECRET -d grant_type=client_credentials -d audience=agent-b

# on behalf of a signed-in user (RFC 8693): sub stays the user, act records each agent on the way
curl -s {issuer}/oauth2/token -u agent-a:$SECRET \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token=$USER_TOKEN -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d audience=agent-b
```

A token issued for a user carries that user's own claims at the target, requires that the user has
access there, ends when their session does, and never outlives the token it was exchanged for.
`{issuer}/a2a/agent-card-security` serves the security section of an A2A Agent Card. It is on by
default and inert until a caller is listed; `Oidc:EnableA2A = false` removes it. Setup, the token
contents, every refusal and the client-library calls are in [A2A.md](A2A.md).

Tick **This client is an agent** in the same section and the client list shows it with an `agent`
badge and how many clients it may call and be called by; **agents only** narrows the list. The mark
is a label (`is_agent` on the client record): it grants nothing, the caller list decides.

## MCP: an agent sets the server up and runs it

The server is an MCP server itself, at four levels: setup (the setup code is the bearer token), the
operator's, a tenant's, and one application's.

```json
{ "mcpServers": { "ark-idp-setup": {
    "type": "http", "url": "https://id.example.com/ark-idp/mcp",
    "headers": { "Authorization": "Bearer ${ARK_SETUP_CODE}" } } } }
```

An agent with that collects what setup needs from the people who have it, shows the plan for
agreement, and installs it. `setup_complete` hands over the machine credential and the tenant's own
endpoint, where the agent goes on with a token addressed to it:

```bash
curl -s {issuer}/oauth2/token -d grant_type=client_credentials -d client_id=acme_machine \
  -d client_secret=$SECRET -d resource={issuer}/mcp -d scope='mcp.read mcp.manage'
```

`tenant_overview` is where it starts: the state of the tenant and the next steps, each with the tool
and arguments. The tools, who may call them, people as administrators, and the settings are in
[MCP.md](MCP.md). `ark_oauth_server:Mcp:Enabled = false` removes all of it; `Mcp:ReadOnly` leaves only
the tools that look.

The operator account finds every endpoint of the server on the console's **MCP** page
(`/{tenant_id}/admin/mcp`), with its address to copy and its documents to open in a new tab.

## Audit trail (ARK-RAPID Watch)

Optional. The server can send a structured record of everything it does to an
[ARK-RAPID Watch](https://github.com/ir-dev/ark-net-audit) audit server, through the
`Ark.Watch.Client` package this one now references: sign-ins and refusals, tokens, revocations,
sign-outs, every change made in the console or through the management API, and every
agent-to-agent event in full (see [A2A.md](A2A.md#the-audit-trail)). The record lives outside this
server, is tamper evident and can be searched by who, what, which client and which user.

**Nothing is sent until it is configured.** With no endpoint or no key, no client is created, no
thread is started and no file is written. Configure it in the setup wizard (the **Audit trail**
step, which tests the address and the key before saving), or as settings:

```json
"ark_oauth_server": {
  "Watch": {
    "Endpoint": "https://audit.example.com/",
    "Application": "ark-idp",
    "Environment": "Production"
  }
}
```

and the key from the environment or a vault, never a file: `ark_oauth_server__Watch__ApiKey`. Use a
**secret** key of the node (`arkw_sk_…`), created there under Admin → Applications.

| `ark_oauth_server:Watch` | Default | |
|---|---|---|
| `Enabled` | `true` | `false` stops sending without removing the settings. |
| `Endpoint` | none | The node's address. Required. |
| `ApiKey` | none | A secret key of the node. Required. |
| `Application` | `ark-idp` | What the events are filed under. A key created for one application only accepts that name. |
| `Environment` | the host's environment name | |
| `SpoolDirectory` | `watch-spool/{machine}` in the setup data directory | Where events wait while the node is away. `none` keeps them in memory only. Each instance needs a folder of its own, which the default gives it. |
| `IncludeProtocolTrace` | `true` | `false` leaves out the high-volume lines (each authorization request, pushed request, device code and ordinary token) and keeps who-did-what: sign-ins, refusals, agent tokens, revocations, changes. |
| `AllowConsoleChanges` | `true` | `false` pins the trail to configuration: the console's **Audit trail** page only shows it, and a destination saved there is ignored. Set it where the operator cannot, such as the environment, when the audit destination is a compliance control. |

**It never slows a request or fails one.** An event is written to an in-memory ring and the request
goes on; a background worker sends it. While the node cannot be reached, events are kept on disk
and sent in order when it is back, including across a restart of this server. A change to these
settings takes effect without a restart.

**Changing it while the server runs.** The operator account has an **Audit trail** page in the
console (`/{tenant_id}/admin/audit`) that shows where events go, where that setting comes from and
this instance's counters, and changes the destination: turn it on or off, and set the address, key,
application, environment and protocol trace. Saving tests the destination first (the wizard's test)
and refuses one that fails, unless you choose to save it anyway for a node that is down for now.

- **No restart, on every instance.** What the page saves is kept in the server's database (table
  `server_settings`), applies on the instance that saved it at once and on every other instance
  within the reference-cache window (`Oidc:ReferenceCacheSeconds`, 30 s). It survives a restart and
  a redeploy, and an instance that starts reads it before it records its own start.
- **It replaces configuration** (`ark_oauth_server:Watch`, from the settings file, appsettings or
  the environment) as a whole, apart from `SpoolDirectory`, which stays each instance's own, until
  **Use the configuration instead** removes it. The page shows both.
- **The change is itself on the record**, in the trail that stops (before its client is flushed and
  closed), as the first event of the trail that starts, and in this server's `audit_trace`, with who
  made it: `audit_trail.update`, `audit_trail.disable` or `audit_trail.revert`, with `from_*`
  and `to_*` attributes. Turning the trail off is the last thing the old destination receives.
- **A key is only sent to its own server.** Left blank, the key in use is kept, but only for an
  address on the same scheme, host and port as the one it was saved for; pointing the trail
  anywhere else needs the key entered again. No page or response carries a key, only a hint
  (`arkw_sk_…9f2c`). A key saved here is stored in the database, like the signing keys.
- Events still waiting to be sent when the destination changes are sent to the new one, under the
  application name they were recorded with.
- Export, import and factory reset leave `server_settings` alone: it belongs to the deployment, and
  an export of production loaded into a test server must not send the test server's trail to
  production.
- Scripts use the same API with the machine client's `client.register` token:
  `GET /api/oauth/v1/watch/settings`, `POST …/watch/test`, `POST …/watch/settings`,
  `POST …/watch/settings/remove` (see API-GUIDE.md).

**Is it working?** The console's footer shows *Audit trail: host, sending* (or *waiting for the
node*, or *losing events*), with the counters in its tooltip and, for the operator, a link to the
page; `GET /api/oauth/v1/watch/status` returns them: `logged`, `sent`, `spooled`, `replayed`, `rejected`,
`dropped`, `send_failures`, `health`, and `source` (`console`, `configuration` or `none`). `rejected`
above zero usually means the key belongs to another application name. The key is never returned.

It is independent of `EnableLogTrace`, which is about the trace this server keeps in its own
database: either can be on without the other.

## Export, import and factory reset

The operator account gets a **Data** page at `/{tenant_id}/admin/data`, over an API at
`/api/oauth/v1/data/…`:

* **Export** — every table and column (including password hashes, client secret hashes and
  private signing keys) plus the app settings, as one JSON file. Give it a passphrase and it is
  encrypted with AES-256-GCM; it carries a checksum either way. Treat it like a database backup:
  whoever holds it can sign tokens as this server.
* **Import** — analyse first. The server works out all three modes against the database as it is —
  `replace` (empty this server, load the file exactly), `merge_skip` (add what is missing, keep what
  is here) and `merge_overwrite` (add what is missing, take the file's version of the rest) — and
  says, row by row, what each would do. A row that cannot be loaded safely is excluded by a named
  rule (a tenant that differs only by letter case, a mapping to a missing client, a duplicate client
  name, a `javascript:` redirect URI, a signing key that would collide…) together with everything
  that depends on it; the rest loads, in one transaction. Same file and same database, same plan.
* **Factory reset** — empties every table and runs the same first-run seed a new install gets,
  after checking that an administrator password is configured, so it can never leave a server
  nobody can sign in to.

Configuration is compared on import, never applied. All three can be switched off under
`ark_oauth_server:Admin:DataTools` (`Enabled`, `AllowReset`, `AllowImport`, `AllowReplace`,
`MaxImportMegabytes`). The modes, every exclusion rule and the file format are specified in
[API-GUIDE.md](API-GUIDE.md#data-tools-api--export-import-factory-reset-datatoolscontroller-base-apioauth).

## Branding

The sign-in, consent and device pages show two marks in the header: the **host logo**, which says
who is asking for the password, and the **client logo**, which says what is being signed in to.

| Where it comes from | Setting |
|---|---|
| Host logo | `ark_oauth_server:EmailConfig:host_logo` |
| Default client logo | `ark_oauth_server:EmailConfig:client_logo` |
| Per-client logo | `client_logo` on the client — set it in the console's client editor, at provisioning time, or as `logo_uri` through dynamic registration |

A client's own logo wins; the configured one is the fallback for every client that has not set
one. Uploads through the console are inlined as a `data:` URI, so a logo needs no upload
directory, no static file route and nothing extra to back up — keep them under 256 KB, since the
value travels in every page that renders it.

The header lays itself out for whichever marks exist: two get a divider between them, one gets the
room both would have shared, and none promotes the host name to being the thing itself rather than
a caption under an empty space. The admin console's top bar draws the same lockup.

Under the card, and in the console's footer, sits a quiet **"Powered by Ark Identity Server"**
mark. `ark_oauth_server:ShowPoweredBy` (default `true`; the setup wizard asks) set to `false`
removes it, leaving only your brand on the pages users see. The console footer still names the
package version.

## The setup wizard

**Where it writes.** One directory, `ark-idp-data/` under the content root unless
`ark_oauth_server:Setup:DataPath` says otherwise:

| File | Contents |
|---|---|
| `settings.json` | the `ark_oauth_server` section and `ConnectionStrings:ArkAuthConnection`, mode 0600 |
| `ark-idp-{tenant}-keys.json` | written at install, whether by the wizard, Ark Pilot or an agent over MCP: the same file as the last screen's **Download JSON** (issuer, signing key pair, machine client id and secret), mode 0600. One from an earlier setup is renamed `ark-idp-{tenant}-keys.{time}.json`, not overwritten. Not written when attaching to an existing database, or with `Setup:SaveKeysFile=false` |
| `branding/` | the uploaded logos, served at `/ark-idp/branding/…` (as files, so activation emails can show them) |
| `ark_idp.db` | the SQLite database, when SQLite is chosen with the default path |
| `.gitignore` | `*`: the directory ignores itself, because `dotnet run` puts it inside your project |

**Or by conversation.** The **Welcome** step links to the agent view, `/ark-agent`: Ark Pilot, the
onboarding agent in this package, collects the same answers in a chat and files them for you. Sections you
do not know go to the colleague who does, by a link that reaches only those sections. The view shows every
value with who supplied it, who has been asked and has not answered, and what is waiting for you to
confirm; the card on the wizard's first page says the same in short. Install is a button, and only yours.
The same people may open it as may run the wizard, and the setup code is asked for once for both.
The wizard and the agent do not fill each other in: whichever installs, its values are used.

It uses no language model until `ark_onboarding_agent:Llm` names one (guided mode: it asks one question at
a time). It exists only while the server is unconfigured, and `ark_onboarding_agent:Enabled=false` removes
it. While it is at it, `agent-state.json` (the conversation) and `setup-draft.json` (the values) appear beside
the settings, both 0600 and deleted when setup finishes. Run one instance until then. Settings and the model
providers: [the agent's README](https://github.com/ir-dev/ark-oauth-oidc/tree/main/agents/agent-001-tenant-onboarding).

An agent of your own can do all of this too, over MCP; see [MCP.md](MCP.md).

The optional **Audit trail** step asks for an ARK-RAPID Watch address and key, tests them — the
address, the key, then one real event — and writes them to `settings.json` as
`ark_oauth_server:Watch`. Skipped, the section is not written and nothing is sent. A folder
`watch-spool/` appears beside the settings once it is on. Either way it can be set or changed later
on the console's **Audit trail** page, with no restart.

`settings.json` is read as configuration on every start. It is inserted **after appsettings.json and
before user secrets, environment variables and the command line**, so any value it holds can still
be overridden the usual way, for example `ark_oauth_server__EmailConfig__pw` from a key vault.

**What it never writes to `settings.json`.** The administrator's password and the machine client's
secret go into the database as hashes; the signing key's private half goes into `signing_keys`. None
of them is in `settings.json`, and the administrator's password is in no file at all. The machine
secret is shown once, on the last screen, which also offers **Download JSON** and **Download Excel
(.xlsx)**: the issuer, discovery and console addresses, the signing key pair (kid, public and private
PEM) and the machine client's id and secret, in one file made in the browser. It is the only time the
server hands them out over the network.

**The keys file.** The server also writes that same JSON into the data directory at install, as
`ark-idp-{tenant}-keys.json`, whichever route completed setup: the wizard, Ark Pilot, or an agent over
MCP (which is never sent the private key; `setup_complete` answers with the file's path). The private
key in it can sign tokens as this server and the secret administers it, so keep the directory as safe
as the database, and back it up with it. A key rotated or a secret regenerated later is not written
back. `ark_oauth_server:Setup:SaveKeysFile=false` turns it off, for a host whose data directory is
shared storage that should hold no key; nothing is offered either way when attaching to an existing
database, which creates neither.

**Who may run it.** Whoever finishes setup becomes the administrator, so an unconfigured server on
a network is a race to the first visitor. The wizard asks for a **setup code**, printed in the log
at start-up and saved as `setup-code.txt` beside the settings:

```
warn: Ark.oAuth.Oidc.Setup[0]
      Ark IdP is not configured yet. Open /ark-idp/setup on this server in a browser to run the setup
      wizard. Enter the setup code N9VL-VTVB-2T5N.
```

The one exception is a developer at `dotnet run`: in the **Development** environment, from a loopback
address and under a loopback name, with no forwarding header (`X-Forwarded-*`, `Forwarded`,
`X-Real-IP`, or the `X-Original-*` that ASP.NET Core's forwarded-headers middleware leaves), no code
is needed and the log says so. In any other environment the code is always asked for, on the server's
own machine too: a proxy on the same host makes every visitor look local.

**The setup link: no log access needed.** Whoever deploys the server can let someone else set it up
without reading any log. Set `ark_oauth_server:Setup:AccessKey` to a random value of at least 16
characters, in the platform's settings or a secret store, never in a committed file. Then send them
the link:

```
https://id.example.com/ark-idp/setup#key=<AccessKey>
```

Opening it, the wizard trades the key for the setup code, shows the code (with **Copy**, for an agent
that connects over MCP) and carries on as if it had been typed. The key travels after the `#`, so
it is never part of a request address and no server or proxy log records it. The wizard also
removes it from the address bar at once.

* With a key, the setup code is **derived from it** rather than random. It is the same on every
  instance and after every restart, even without persistent storage, and `setup-code.txt` and the
  log carry that code as before.
* A wrong key is answered after a second, one at a time for the whole server, and past 20 waiting
  the rest get `429`. The right key is never slowed. Each code handed out is logged with the
  caller's address.
* Once setup is finished the link answers `404`, `setup-code.txt` is deleted, and the log asks for
  the key to be removed. A key shorter than 16 characters is ignored, with an error in the log, and
  the setup code still works.
* Use letters and digits, so the link survives being pasted anywhere: `openssl rand -hex 16`, or
  `[guid]::NewGuid().ToString("N")` in PowerShell.

Every wizard call is a JSON POST with a custom header, which a browser will not send cross-site.
Once setup is done, `/ark-idp/setup` is gone (404) and the setup code is deleted. It does not come
back while the process runs: settings that go missing, or a `settings.json` that cannot be read, are
answered with `503` `configuration_unavailable` and reported in the log. Put the file right and the
server carries on; to set it up from the beginning, move the file away and restart.

**An existing database.** Point the wizard at a database that already holds Ark tenants and it
attaches instead of seeding: the tenant id must be one the database has, and no key, client or
account is created. Enter that database's administrator as the username; it is who the console
treats as the operator.

**Settings** (`ark_oauth_server:Setup`, from appsettings or the environment):

| Setting | Default | |
|---|---|---|
| `Enabled` | `true` | `false` removes the wizard; an unconfigured server then fails naming the missing setting |
| `RequireToken` | `false` | ask for the setup code in Development on localhost too; everywhere else it always is |
| `DataPath` | `ark-idp-data` | in a container, a mounted volume, e.g. `ark_oauth_server__Setup__DataPath=/home/data/ark-idp`. The .NET 8+ images run as a non-root user that cannot write to `/app` |
| `AccessKey` | — | opens the setup link `/ark-idp/setup#key=…` for someone without log access; at least 16 characters; the setup code is then derived from it. Platform settings or a secret store only |
| `SaveKeysFile` | `true` | write `ark-idp-{tenant}-keys.json` (signing key pair, machine credential) into `DataPath` at install; `false` leaves the browser download as the only copy |

### Running the wizard on a hosted server

A hosted server runs in Production unless it is told otherwise, so the wizard **always** asks for the
setup code.

**Easiest, on every host: the setup link.** Set `ark_oauth_server__Setup__AccessKey` in the same
settings page as `DataPath` below, then open (or send) `https://<public address>/ark-idp/setup#key=<AccessKey>`.
Nobody needs the log, and the code is the same on every instance and after every restart. See
*The setup link* above.

Without a key, the code is kept in two places, and every host lets you reach at least one of them:

* **the log**: the `Ark.oAuth.Oidc.Setup` warning shown above, written once at start-up. A restart
  prints it again;
* **`{DataPath}/setup-code.txt`**, until setup is finished.

| Host | From the log | From the file |
|---|---|---|
| Docker | `docker logs <container> 2>&1 \| grep "setup code"` | `docker exec <container> cat <DataPath>/setup-code.txt` |
| Azure App Service, Linux (custom container or code) | `az webapp log tail`, once container logging is on; Portal → **Log stream** | Kudu → **Bash**, or **SSH**: `cat /home/data/ark-idp/setup-code.txt` |
| Azure App Service, Windows (code) | not there: IIS discards console output | Kudu → **Debug console**: `type %HOME%\data\ark-idp\setup-code.txt` |
| Azure Container Apps | `az containerapp logs show`; Portal → **Log stream**; Log Analytics | `az containerapp exec`, or the Azure Files share itself |
| AWS Elastic Beanstalk, Linux (.NET or Docker platform) | `eb logs`; Console → **Logs** | `eb ssh`, then `sudo cat <DataPath>/setup-code.txt` |
| AWS Elastic Beanstalk, Windows | not there: IIS discards console output | RDP to the instance |

`exec` needs a shell or `cat` in the image. The chiseled .NET images have neither, so with those use
the log or read the volume from outside.

**Before the first start, on every host:**

1. **Put `DataPath` on storage that outlives the process.** The wizard's directory *is* the server's
   configuration. If it is on the container's or instance's own disk, a restart, redeploy or
   replaced instance loses `settings.json`, the wizard comes back, and every start makes a new code.
   Where the host has no such storage, see *Without a persistent volume* below.
2. **Run one instance until setup is finished**, then restart before scaling out. The install and
   Ark Pilot's conversation happen in one process, and other instances may not notice the new
   settings on a network share until they restart. Without an access key each instance also holds its own code, so with two the code
   is refused whenever a request lands on the other one.
3. **Let the app see the forwarded scheme.** All of these hosts end TLS in front of the app. Set
   `ASPNETCORE_FORWARDEDHEADERS_ENABLED=true`. Without it the app sees `http`, the wizard pre-fills an
   `http://` public URL, and the console's sign-in sends an `http://` callback that does not match
   the registered one. In the wizard, enter the `https://` address users will use (the custom domain,
   if there is one).

Setting names take `__` where configuration has `:`, on every host: `ark_oauth_server__Setup__DataPath`.

**Docker.** Mount a volume the container's user can write (the .NET 8+ images do not run as root),
set `ark_oauth_server__Setup__DataPath` to it, and read the code with
`docker logs <container> 2>&1 | grep "setup code"`.

**Azure App Service, custom container (Linux).**

1. `/home` is the only path App Service keeps, so point `DataPath` into it:

   ```bash
   az webapp config appsettings set -g <rg> -n <app> --slot <slot> --settings \
     WEBSITES_ENABLE_APP_SERVICE_STORAGE=true \
     ark_oauth_server__Setup__DataPath=/home/data/ark-idp \
     ASPNETCORE_FORWARDEDHEADERS_ENABLED=true
   ```

2. Read the setup code from the container log:

   ```bash
   az webapp log config -g <rg> -n <app> --slot <slot> --docker-container-logging filesystem
   az webapp log tail   -g <rg> -n <app> --slot <slot>   # restart the slot if the line has scrolled past
   ```

   Or Portal → the slot → **Monitoring → Log stream**; or **Advanced Tools** (Kudu) → **Bash** →
   `cat /home/data/ark-idp/setup-code.txt`. Kudu sees only `/home`, so it cannot find the file under
   the default `DataPath`. `az webapp ssh` reaches the container only if the image runs sshd on port
   2222.

3. Keep the slot at **one instance**, and run the wizard at the slot's `https://` address +
   `/ark-idp/setup`.

**Azure App Service, code deploy (no container), Linux or Windows.** The app runs from `site/wwwroot`
under the slot's home directory, and the default `DataPath` (`ark-idp-data` under the content root)
lands inside it. That directory survives a restart but not a redeploy. `az webapp deploy --type zip`
cleans the target by default. An app that runs from a package (`WEBSITE_RUN_FROM_PACKAGE=1`) cannot
write there at all and gets `cannot_write`. So put `DataPath` beside `site` instead:

```bash
# Linux
az webapp config appsettings set -g <rg> -n <app> --slot <slot> --settings \
  ark_oauth_server__Setup__DataPath=/home/data/ark-idp \
  ASPNETCORE_FORWARDEDHEADERS_ENABLED=true

# Windows: the home directory is D:\home on most plans; `echo %HOME%` in the Kudu console says which
az webapp config appsettings set -g <rg> -n <app> --slot <slot> --settings \
  'ark_oauth_server__Setup__DataPath=D:\home\data\ark-idp' \
  ASPNETCORE_FORWARDEDHEADERS_ENABLED=true
```

* **Linux:** read the code as for a custom container. Turn on container logging, then use
  `az webapp log tail` or **Log stream**. Or use **SSH** (Portal → Development Tools; the built-in
  images run sshd, so `az webapp ssh` works) or Kudu → **Bash**, then
  `cat /home/data/ark-idp/setup-code.txt`.
* **Windows:** IIS discards the app's console output, so the log stream never shows the code. The
  file does. The code is made when the app starts, which on Windows is usually its first request, so
  open the site once. Then go to **Advanced Tools** (Kudu) → **Debug console → CMD** and run
  `type %HOME%\data\ark-idp\setup-code.txt`.

**Azure Container Apps.** A replica's filesystem lasts only as long as the replica. Every change to
the template creates a new revision, which means a new replica, an empty directory and a new code.
Scaling to zero has the same effect.

1. Give the app an Azure Files share. Register it with the environment, then mount it through the
   app's YAML. The CLI has no flag for volume mounts; the Portal does it under **Volumes** when you
   create a new revision.

   ```bash
   az containerapp env storage set -g <rg> -n <environment> --storage-name arkidp \
     --azure-file-account-name <account> --azure-file-account-key <key> \
     --azure-file-share-name <share> --access-mode ReadWrite
   az containerapp show -g <rg> -n <app> -o yaml > app.yaml
   ```

   In `app.yaml`, under `properties.template`, add the volume, and add `volumeMounts` to the existing
   container entry (keep its image and everything else):

   ```yaml
       volumes:
         - name: ark-idp
           storageType: AzureFile
           storageName: arkidp
       containers:
         - name: <container>
           volumeMounts:
             - volumeName: ark-idp
               mountPath: /mnt/ark-idp
   ```

   ```bash
   az containerapp update -g <rg> -n <app> --yaml app.yaml
   az containerapp update -g <rg> -n <app> --min-replicas 1 --max-replicas 1 \
     --set-env-vars ark_oauth_server__Setup__DataPath=/mnt/ark-idp ASPNETCORE_FORWARDEDHEADERS_ENABLED=true
   ```

   If the wizard then says it cannot write to `/mnt/ark-idp`, the share is mounted for root only.
   Add `mountOptions: uid=1654,gid=1654` (the .NET images' `app` user) to the volume.

2. Read the code from the replica's console log:

   ```bash
   az containerapp logs show -g <rg> -n <app> --tail 300 | grep -i "setup code"
   ```

   Or Portal → the app → **Monitoring → Log stream**. With Log Analytics, run
   `ContainerAppConsoleLogs_CL | where Log_s has "setup code"` (the table is `ContainerAppConsoleLogs`,
   column `Log`, when logs go through diagnostic settings). From the file:
   `az containerapp exec -g <rg> -n <app>` opens a shell in the replica (not in chiseled images), then
   `cat /mnt/ark-idp/setup-code.txt`. Or download `setup-code.txt` from the share (Portal → the
   storage account → **File shares**).

3. Run the wizard at the app's ingress address + `/ark-idp/setup`. Scale out again once setup is
   finished.

**AWS Elastic Beanstalk.** Each deploy replaces `/var/app/current`, the content root, which takes the
default `DataPath` with it. Elastic Beanstalk also replaces instances, with their disks, when it
scales, heals or updates the platform.

1. Either mount an EFS file system on the instances (AWS's `storage-efs-mountfilesystem.config`
   sample does it in `.ebextensions`), writable by the user the app runs as (`webapp` on the .NET
   platform), and point `DataPath` into it. Or run the wizard on the instance's disk and then move
   its result into environment properties (*Without a persistent volume*, below). Either way, run a
   single instance while you set it up (`eb create --single`, or `eb scale 1`):

   ```bash
   eb setenv ark_oauth_server__Setup__DataPath=/mnt/efs/ark-idp ASPNETCORE_FORWARDEDHEADERS_ENABLED=true
   ```

2. Read the code. On the Linux platforms the app's console output is kept on the instance:

   ```bash
   eb logs | grep -i "setup code"        # last 100 lines of every log, from every instance
   eb ssh
   sudo grep -h  "setup code" /var/log/web.stdout.log                          # .NET platform
   sudo grep -rh "setup code" /var/log/eb-docker/containers/eb-current-app/    # Docker platform
   sudo cat /mnt/efs/ark-idp/setup-code.txt                                     # the file
   ```

   Or Console → the environment → **Logs → Request logs → Last 100 lines**. With log streaming on,
   the .NET platform's log is in CloudWatch under `/aws/elasticbeanstalk/<environment>/var/log/web.stdout.log`.
   On the Windows Server platforms IIS discards console output, so the code is only in
   `{DataPath}/setup-code.txt` on the instance (RDP).

3. Run the wizard at the environment's `https://` address + `/ark-idp/setup`.

**Without a persistent volume.** The wizard's result can survive without one, because everything it
collected apart from `settings.json` is in the database: the administrator, the signing key and the
machine secret. With a server database (PostgreSQL or MySQL, not SQLite on the instance), after
**Install**:

1. Read `{DataPath}/settings.json` the same way as the setup code, and turn it into settings:

   ```bash
   jq -r '{ConnectionStrings, ark_oauth_server}
     | paths(type | IN("object","array","null") | not) as $p
     | "\($p | map(tostring) | join("__"))=\(getpath($p))"' settings.json
   # ConnectionStrings__ArkAuthConnection=Host=…
   # ark_oauth_server__TenantId=ark_idp
   # ark_oauth_server__Oidc__CorsOrigins__0=https://app.example.com
   ```

2. Set those as the host's environment properties, app settings or environment variables. Put the
   connection string and `ark_oauth_server__EmailConfig__pw` in its secret store (Container Apps
   `secretref:`, App Service Key Vault references).

3. From then on the server starts configured on any instance and never shows the wizard. `DataPath`
   no longer matters, except for uploaded logos: they are files in `{DataPath}/branding/`. Host them
   anywhere on `https` and set `ark_oauth_server__EmailConfig__host_logo` / `client_logo` to their URLs.
   Copy `{DataPath}/ark-idp-{tenant}-keys.json` into a secret store as well before the instance goes:
   the database has the key, but nowhere else has the machine secret in the clear.

SQLite under `/home` (App Service) or on an Azure Files share (Container Apps) sits on a network
share, where its file locking is not reliable: fine for a trial, but use PostgreSQL or MySQL for a
server people depend on. A deployment driven by a pipeline can skip the wizard, the setup code and
`DataPath` altogether: set `ark_oauth_server__TenantId`, `ark_oauth_server__BaseUrl`,
`ConnectionStrings__ArkAuthConnection` and `ark_oauth_server__AdminUser__Password` as app settings
(Key Vault references for the secrets). The forwarded-headers setting still applies.

## Upgrading an existing database

Schema changes ship as numbered scripts, and **they now run themselves**: on start-up the server
applies every script the database has not had yet and records it in `ark_schema_history`.

```
00003_sql.sql   # 2.0.0 - protocol tables, RFC 7591 metadata
00004_sql.sql   # 2.0.2 - users.is_active
00005_sql.sql   # 2.0.3 - back-channel logout metadata, sessions.browser_id, session_clients
```

Nothing is ever replayed. A database that predates the history table is measured rather than
replayed — each script is checked against the live schema, and one whose tables and columns are all
present is recorded as a baseline without executing. That matters because 00003 rewrites every
client that holds no secret, which is right for a 2.0.0 upgrade and wrong for anything else.

Skipping this used to be silent and specific: without 00004 the entity carried `users.is_active`
and the table did not, so `/api/oauth/v1/user/list` answered a bare 500 and the console's Users
grid came up empty with nothing saying why.

Indexes are kept current the same way. An index the entity model declares and an existing
database lacks is created on start-up, along with the `lower(email)` indexes behind the
case-insensitive lookups. This is never fatal: an index that cannot be built — no privilege, or a
column type the provider will not index — is written to the log as `Ark IdP: index not created`
and the server starts without it. Unique indexes are never added this way.

Only the SQLite scripts ship in this package, so after them, on every provider, the updater
compares the entity model with the live database and adds whatever table or column is missing —
with DDL from the provider's own EF migrations generator, and with each entity's initialiser
(`is_active = true`, `access_token_lifetime_seconds = 3600`) as the value existing rows receive. It
is additive only. On MySQL and PostgreSQL this is what replaces hand-written `ALTER TABLE`s; before
it, a missed one surfaced as `42703: column c.backchannel_logout_session_required does not exist` on
the first request. `POST /api/migration/v1/sql?action=up|down&name=00005_sql.sql` is still there to
run or roll back one SQLite script by hand, and reports whether it actually worked. It is off — 404 —
unless `ark_oauth_server:Management:AllowMigrationEndpoint` is `true`, and operator-only when on.

## Running at scale

Measured with 30,000 accounts on PostgreSQL: all 30,000 signed in with no errors, and with their
30,000 sessions live a single instance answered a refresh in 5 ms and a single-sign-on hop in 7 ms at
the median. As two instances behind a TLS-terminating load balancer, with the database a network hop
away, the same 30,000 people were carried through 804,332 requests of every kind in 25 minutes without
an error. Sign-in under step load, from 100 to 10,000 people at once, completed 204,254 sign-ins
without one being refused. The dated report, with the method and every number, is on the project site:
<https://ir-dev.github.io/ark-oauth-oidc/#reviews>.

What decides whether a deployment holds up, in the order it matters:

1. **Use PostgreSQL or MySQL, not SQLite, beyond one small instance.** SQLite takes one writer at a
   time and its file cannot be shared between machines. Set `Provider` and the connection string;
   nothing else changes. Size the connection pool for your peak (`Maximum Pool Size`, 100 by default
   on both providers) and keep it under the database's own connection limit across all instances.
2. **Let the upgrade build its indexes.** The first start on this version adds the indexes the hot
   paths need to an existing database (see "Upgrading an existing database"). It reads each table
   once; on a database with millions of rows allow that start a little longer.
3. **More than one instance needs nothing more than a shared database.** The sign-in form's
   anti-forgery token and the console's cookie are protected with the ASP.NET Core data-protection
   key ring, which lives in a folder on each machine by default — so a form drawn by one instance is
   refused by the next. `DataProtectionKeys: auto` keeps the ring in the server's database on every
   provider except SQLite, so all instances share it. `database` does so on SQLite too; `off` leaves
   it to the host. A host that calls `PersistKeysTo…` itself always wins. The keys the machine was
   already using are copied into the database the first time, so the move signs nobody out and a
   sign-in form already open still posts. Set `BaseUrl` to the public
   address, and no session affinity is required. On a brand-new database, bring one instance up and
   let it answer a request before starting the others, so the schema and the first key are created
   once.
4. **Sign-in is the expensive request, by design.** A password is verified with PBKDF2 at 210,000
   iterations: about 40 ms of one core, which no setting should make cheaper. At most
   `MaxConcurrentPasswordHashes` run at once — half the cores by default — and the rest queue without
   holding a thread, so a few thousand people signing in together slow each other down and leave
   people who are already signed in alone. Budget roughly 25 sign-ins a second per hashing core;
   30,000 people arriving over fifteen minutes is 33 a second, so plan for at least two hashing
   cores across the deployment — four cores in total at the default — and more for a sharper peak.
   By default nobody is turned away: a sign-in waits its turn however long that takes, as it always
   has. Set `MaxPasswordHashWaitSeconds` (20 is reasonable) to answer "the server is busy, try
   again" after that long instead, which sheds load in an attack; such an attempt is not counted
   as a failed one.

Three things this version keeps in memory, and what that means when an operator changes something:

| Kept | For | A change is seen |
|---|---|---|
| Tenants, clients, scopes, the signing key | `ReferenceCacheSeconds` (30) | At once on the instance that made it. On the others: a change that allows something — a new secret, redirect URI, scope or grant, a reactivated client — at once too, because nothing is refused without reading the database first; a change that takes something away, within that time. `0` turns it off. |
| A client secret that verified | `ClientSecretCacheSeconds` (300) | At once: replacing the secret retires the entry. A wrong secret is never remembered. |
| The `ark_oauth_server` configuration | Until configuration reloads | On reload, as before. |

Nothing about a user is kept: accounts, access mappings and sessions are read from the database —
by index — on every request, so deactivating someone or ending a session takes effect immediately
on every instance. `/jwks.json` is always read from the database too.

Housekeeping runs every `CleanupIntervalMinutes`. It removes what has expired, and with it the
refresh tokens issued under sessions that have ended, which is what keeps that table to the size of
the signed-in population instead of a fortnight of rotations. The audit trail is written in batches,
off the request path, and is kept for ever unless `AuditRetentionDays` says otherwise; with
`EnableLogTrace` on, a busy server writes several rows per sign-in, so set one or the other.

## Before production

1. Set `AdminUser:Password` before the first run, out of band, and change it after first sign-in.
   With the wizard: run it from the server itself, or with the setup code, before the server is
   reachable by anyone else, and back up `ark-idp-data/`.
2. Set a strong `DefaultPw`.
3. Keep `RequireHttpsMetadata` at `true` on clients.
4. Leave `EnableDynamicRegistration` off unless you need it, and keep
   `RequireRegistrationAccessToken` on if you do.
   Decide who may hold a machine credential: it also opens the MCP endpoints. `Mcp:ReadOnly` or
   `Mcp:Enabled` limit that.
5. Give confidential clients real secrets and set `token_endpoint_auth_method` accordingly.
6. If anything provisions through the API, set `Management:MachineClientSecret` from a key vault
   or environment variable — never a settings file under source control — and leave
   `Management:AllowMigrationEndpoint` off.

## Documentation

The project website is <https://ir-dev.github.io/ark-oauth-oidc/>.

Full documentation, flow walkthroughs, the configuration reference and the v1 migration guide are
in the repository: <https://github.com/ir-dev/ark-oauth-oidc>

## License

MIT
