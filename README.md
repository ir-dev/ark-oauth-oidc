# ARK Identity Server

A self-contained OAuth 2.1 and OpenID Connect provider for ASP.NET Core, distributed as two
NuGet packages: `Ark.oAuth.Oidc` (the server) and `Ark.oAuth.Client` (the client).

It is multi-tenant, runs on SQLite / MySQL / PostgreSQL, and ships its own sign-in,
consent and admin UI. Point any standard OpenID Connect library at the issuer URL and it will
configure itself.

> **New here? Start with [GETTINGSTARTED.md](GETTINGSTARTED.md).** It takes a fresh clone to a
> working sign-in with one command — `./run.sh` (macOS/Linux) or `run.bat` (Windows) — and then
> explains every setting you passed on the way: the issuer formula, how a port turns into a
> redirect URI, and the four registrations that make the end-to-end sample work.
>
> This README is the reference: what the server supports, every endpoint and every setting.

---

## Contents

- [Getting started](GETTINGSTARTED.md) — the guided walkthrough, and `run.sh` / `run.bat`
- [What's supported](#whats-supported)
- [Quick start](#quick-start)
- [Integrating an application](#integrating-an-application)
- [The client package](#the-client-package)
- [Endpoints](#endpoints)
- [Admin console](#admin-console)
- [Flows](#flows)
- [Configuration reference](#configuration-reference)
- [Registering clients](#registering-clients)
- [Key management](#key-management)
- [Upgrading from the v1 endpoints](#upgrading-from-the-v1-endpoints)
- [Security notes](#security-notes)

---

## What's supported

| Specification | Status |
|---|---|
| OAuth 2.0 Authorization Framework (RFC 6749) | Authorization code, refresh token, client credentials |
| PKCE (RFC 7636) | **Required** for public clients, `S256` only |
| OpenID Connect Core 1.0 | ID tokens, UserInfo, `nonce`, `at_hash`/`c_hash`, `auth_time`, `sid` |
| OpenID Connect Discovery 1.0 | `/.well-known/openid-configuration` |
| OAuth 2.0 Authorization Server Metadata (RFC 8414) | `/.well-known/oauth-authorization-server` |
| JSON Web Key Set (RFC 7517) | `/.well-known/jwks.json`, with two-phase key rotation |
| JWT Profile for Access Tokens (RFC 9068) | `typ: at+jwt`, `client_id`, `jti`, `scope` |
| Token Introspection (RFC 7662) | Access and refresh tokens |
| Token Revocation (RFC 7009) | Revokes the whole refresh-token family |
| Device Authorization Grant (RFC 8628) | With `verification_uri_complete` |
| Pushed Authorization Requests (RFC 9126) | Optional, can be made mandatory |
| Dynamic Client Registration (RFC 7591/7592) | Optional, off by default |
| RP-Initiated Logout 1.0 | `end_session_endpoint`, browser-wide by default |
| Back-Channel Logout 1.0 | Signed `logout_token` POSTed to each client that took part |
| Authorization Server Issuer Identification (RFC 9207) | `iss` in the authorization response |
| Native Apps (RFC 8252) | Loopback redirect URIs with variable ports |

Deliberately **not** supported: the implicit grant, the hybrid flow, and the resource owner
password credentials grant. All three are removed in OAuth 2.1.

---

## Quick start

This builds a **new** host from the published packages. To run the sample already in this
repository instead — provider, client and admin console, with readiness checks — use `./run.sh`
or `run.bat` and follow [GETTINGSTARTED.md](GETTINGSTARTED.md).

### 1. Create a host project

```bash
dotnet new mvc -n MyIdp
cd MyIdp
dotnet add package Ark.oAuth.Oidc
dotnet add package Ark.oAuth.Client
```

### 2. `Program.cs`

```csharp
using Ark.oAuth;
using Ark.oAuth.Oidc;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddArkOidcServer(builder.Environment);   // the identity provider
builder.Services.AddArkOidcClient(builder.Configuration); // the admin console is itself a client
builder.Services.AddControllersWithViews();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();        // must come before UseAuthentication / UseAuthorization
app.UseArkAuthData();    // one-time database bootstrap
app.UseArkOidcClient();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(name: "default", pattern: "{controller=Home}/{action=Index}/{id?}");
app.Run();
```

> **Middleware order matters.** `UseRouting()` has to run before `UseAuthentication()` and
> `UseAuthorization()`. Without a selected endpoint, the authorization middleware cannot see the
> `[Authorize]` metadata it is supposed to enforce.

### 3. `appsettings.json`

```jsonc
{
  "ark_oauth_server": {
    "TenantId": "my_idp",              // a client named "<TenantId>_client" is created for the admin console
    "BasePath": "",                    // set if the app is hosted under a sub-path
    "BaseUrl": "https://idp.example.com",
    "Provider": "sqlite",              // sqlite (default) | mysql | postgres
    "EnableLogTrace": true,
    "UploadPath": "./wwwroot/{0}/",
    "DefaultPw": "<initial password for new users>",
    "UserPasswordMode": "admin_managed", // admin_managed | email_based | auto (legacy behaviour)
    "AdminUser": {                     // the account seeded when the database is first created
      "Username": "admin",             // optional, defaults to "admin"; need not be an email address
      "Password": "<required, no default>",
      "Name": "Admin User"
    },
    "Admin": {
      "SignOutUrl": "/Home/SignOutAll" // where the admin console's Sign out link goes
    },
    "EmailConfig": {
      "email": "idp@example.com",
      "pw": "<smtp password>",
      "from": "idp@example.com",
      "display": "Example (IdP)",
      "subject": "Example IdP: ",
      "smtp": "smtp.example.com",
      "port": 25,
      "host_logo": "https://idp.example.com/img/logo.png",
      "activation_link": "https://idp.example.com/oauth/{0}/v1/password/reset/{1}",
      "host_company_display": "Example Identity Provider",
      "privacy_policy_url": "https://example.com/privacy",
      "terms_url": "https://example.com/terms"
    }
  },
  "ConnectionStrings": {
    "ArkAuthConnection": "Data Source=./data/ark_auth.db"
  }
}
```

### 4. Run

```bash
dotnet user-secrets set "ark_oauth_server:AdminUser:Password" "<a real password>"
mkdir -p data && dotnet run
```

On first run the server creates its schema, generates an RSA signing key **locally**, seeds the
OIDC scope catalogue, and creates the administrator account described by `AdminUser`.

`AdminUser:Password` is **required and has no default**. It was `admin` / `admin`, compiled in —
the same credentials on every deployment, for the one account that administers every tenant. It
falls back to `DefaultPw`, and a value left as a `<<placeholder>>` counts as unset; with neither
configured the first request fails with a message naming the setting, and no database is created,
so nothing half-built is left behind to be mistaken for an initialised server later. Keep the real
value in a secret store or an environment variable (`ark_oauth_server__AdminUser__Password`) rather
than in `appsettings.json`.

The section is read only while the database is being created. Changing it afterwards renames
nothing and resets no password — use the console.

`UserPasswordMode` makes the host choose one password-onboarding flow for newly created accounts.
Use `admin_managed` when operators set or communicate passwords out of band, or `email_based`
when email-address accounts should be parked in reset mode and sent an activation link. `auto`
keeps the older mixed behaviour, where the caller decides.

Your issuer is now:

```
https://idp.example.com/my_idp
```

and the discovery document is at:

```
https://idp.example.com/my_idp/.well-known/openid-configuration
```

---

## Integrating an application

There is one URL to know — the **issuer**. Everything else is discovered.

A complete, runnable client is in **`Ark.oAuth.Oidc/Ark.Client.Web`** — a client-only ASP.NET Core
app whose [README](Ark.oAuth.Oidc/Ark.Client.Web/README.md) walks the whole process: registering
the client, granting a user access to it, configuring the app, and using the result (protected
pages, role claims, calling a downstream API, sign-out). Its home page checks its own registration
against the live discovery document, so setup mistakes surface as a sentence rather than an
`invalid_request` page. Start from it for new client applications.

Signed in to the admin console, each client has a generated setup page at:

```
/{tenant_id}/oauth2/integrate/{client_id}
```

It renders the exact values and copy-paste config for that client: issuer, client ID, scopes,
redirect URIs, and working snippets for the Ark client package, the raw ASP.NET Core handler,
`oidc-client-ts`, Authlib and `go-oidc`. Because it is generated from the client's own
registration, it cannot drift out of date.

---

## The client package

`Ark.oAuth.Client` configures ASP.NET Core's own OpenID Connect and cookie handlers. It is not a
hand-rolled protocol implementation, so PKCE, `state`, `nonce`, JWKS rollover and token refresh
are handled by the framework.

```csharp
builder.Services.AddArkOidcClient(builder.Configuration);
```

```jsonc
{
  "ark_oauth_client": {
    "Authority": "https://idp.example.com/my_idp",
    "ClientId": "my-app",
    "ClientSecret": null,                 // omit for public clients (SPA, native, browser apps)
    "Scopes": ["openid", "profile", "email", "offline_access"],
    "CallbackPath": "/signin-oidc",
    "SignedOutCallbackPath": "/signout-callback-oidc",
    "RequireHttpsMetadata": true
  }
}
```

Then use `[Authorize]` as normal. Reading tokens:

```csharp
var accessToken = await HttpContext.GetArkAccessTokenAsync();

// or attach it to a downstream call
var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/things");
await request.WithArkTokenAsync(HttpContext);
```

Ark authorization claims (`ark_claims` in the access token) are projected onto the principal as
role claims, so they work with policies directly:

```csharp
[Authorize(Roles = "billing.admin")]
public IActionResult Billing() => View();
```

### Protecting an API

```csharp
builder.Services
    .AddAuthentication()
    .AddArkOidcApi(arkConfig);
```

### The flows the handler does not cover

`AddArkOidcClient` also registers three services for the cases outside interactive sign-in. All
three read the provider's discovery document, so they need the issuer and nothing else.

| Service | For |
|---|---|
| `ArkSetupProbe` | Pairs local configuration with the provider's metadata and returns `ArkSetupModel` — issuer mismatch, unregistered scopes, the exact redirect URI this app will send. Render it and a registration mistake reads as a sentence instead of `invalid_client`. |
| `ArkClientCredentials` | The client credentials grant, with `GetTokenAsync` caching until shortly before expiry and `RequestTokenAsync` for a live exchange. |
| `ArkRegistration` | Dynamic client registration (RFC 7591) and management (RFC 7592). |

```csharp
var model  = await setup.ProbeAsync(HttpContext);
var token  = await credentials.GetTokenAsync(clientId, secret, new[] { "reports.read" });
var client = await registration.RegisterAsync(metadata, token.AccessToken);
```

### Talking to a different provider

Because this is the standard handler, changing `Authority` and `ClientId` is enough to point the
same application at Entra ID, Okta, Auth0 or Keycloak.

---

## Endpoints

All paths are relative to the issuer, `{BaseUrl}/{TenantId}`.

| Purpose | Path |
|---|---|
| Discovery | `/.well-known/openid-configuration` |
| Discovery (RFC 8414 name) | `/.well-known/oauth-authorization-server` |
| JWKS | `/.well-known/jwks.json` |
| Authorization | `/oauth2/authorize` |
| Token | `/oauth2/token` |
| UserInfo | `/oauth2/userinfo` |
| Introspection | `/oauth2/introspect` |
| Revocation | `/oauth2/revoke` |
| End session | `/oauth2/logout` |
| Device authorization | `/oauth2/device_authorization` |
| Device verification (user-facing) | `/oauth2/device` |
| Pushed authorization request | `/oauth2/par` |
| Dynamic registration | `/oauth2/register` |
| Client setup page | `/oauth2/integrate/{client_id}` |

---

## Signing out

`end_session_endpoint` is `/{tenant_id}/oauth2/logout`. Two things about it are worth knowing
before you point a client at it.

### It signs out the whole browser, not one session

The IdP session cookie holds a single `sid`, but a browser accumulates sessions: each sign-in
creates one and overwrites the cookie, so every earlier session stays live — with its refresh
tokens — while becoming unreachable from the browser. On a shared machine that is a different
person. Ending only the session the cookie names is a sign-out that leaves the previous user signed
in everywhere they had been, and it looks like it worked.

So a second cookie, `ark_idp_bid`, identifies the **browser** rather than the sign-in, every
session records the browser it was created in, and `end_session_endpoint` ends all of them. The
signed-out page says how many, and for how many accounts, because "you have been signed out"
understates it when it was three people.

`ark_idp_bid` is a random value that means nothing on its own, it is kept across sign-out — it
identifies the user agent, not the user — and dropping it would only leave the next sign-out unable
to find the sessions before it.

### Clients are told, if they ask to be

Register a `backchannel_logout_uri` on a client and it is POSTed a signed `logout_token` whenever a
session it took part in ends — `application/x-www-form-urlencoded`, one `logout_token` parameter,
answer 200 or 204. The token is `typ: logout+jwt`, carries the
`http://schemas.openid.net/event/backchannel-logout` event and, unless the client turns
`backchannel_logout_session_required` off, the `sid` to end. It never carries a `nonce`, so it
cannot be replayed into an ID token validator. Verify it against the same JWKS as an ID token.

Set it in the client editor, at `/oauth2/register` (RFC 7591), or in the provisioning call. A
client with no URI registered is simply never contacted, which is where every existing client
starts.

The clients to notify are the ones that were logged in under the session — recorded when the
authorization code is issued, not derived from live refresh tokens, which would miss every client
that never asked for `offline_access`. Sessions are revoked before the first notification goes out
and each delivery has its own timeout, so **a client that is down cannot stop a user signing out**;
the failure is logged as a warning and named on the signed-out page.

| Setting | Default | |
|---|---|---|
| `Oidc:EnableBackChannelLogout` | `true` | Notifies nobody until a client registers a URI |
| `Oidc:BackChannelLogoutTimeoutSeconds` | `5` | Per client; deliveries run in parallel |
| `Oidc:LogoutTokenLifetimeSeconds` | `120` | |
| `Oidc:SignOutAllBrowserSessions` | `true` | Off ends only the session the cookie names |
| `Oidc:SignOutAcrossTenants` | `true` | Off keeps a sign-out inside the tenant it was asked of |

Front-channel logout is **not** implemented. Discovery previously advertised
`frontchannel_logout_supported: true` anyway; it now reports `false`, which is what the server can
actually back.

---

## Admin console

The console ships **inside the server package**, so referencing `Ark.oAuth.Oidc` is all the wiring
there is. It used to live in the sample host, which meant getting a console from a NuGet reference
alone meant copying a controller, a view, a stylesheet and 800 lines of JavaScript out of this
repository and keeping them in step by hand.

| Purpose | Path |
|---|---|
| Console | `/{tenant_id}/admin` — `/admin` redirects to the tenant in `ark_oauth_server:TenantId` |
| Stylesheet and script | `/ark-admin/asset/ark-admin.css`, `/ark-admin/asset/ark-admin.js` |
| Management API it calls | `/api/oauth/v1/…` |

It manages tenants, clients, users, scopes, claims and the per-user-per-client access mapping.
Clients are edited in a form rather than a generated grid — the grid rendered every column of the
client record, the tenant's `rsa_private` included, as an editable text box.

The page is self-contained: it sets `Layout = null` and brings its own shell, and the two assets
are served straight out of the assembly, so no layout, `_ViewStart`, tag helper or `wwwroot` entry
is required of the host. Tabulator is its single external dependency, loaded pinned from unpkg. The
assets are also unpacked to the host's content root in Development, where they can be read and
edited on disk; the served copies always come from the assembly.

Two things are worth knowing:

* **Sign out.** The console's session is the host application's authentication cookie, and only the
  host can drop it. Point `ark_oauth_server:Admin:SignOutUrl` at a route of your own that signs out
  of both the cookie and the OIDC scheme — the sample host's `/Home/SignOutAll` is three lines.
  Left unset, the link falls back to the tenant's `end_session_endpoint`, which ends the session at
  the IdP but leaves the local cookie in place until it expires.
* **Overriding it.** Application views win over package views, so a host that wants a different
  page puts its own `Views/Admin/Manage.cshtml` in the application and keeps the routes and the API.

The v1 console at `/oauth/{tenant}/v1/server/{client_id}/manage` is still served for existing
deployments and is no longer developed.

---

## Flows

### Authorization code + PKCE

The default for web, SPA and native applications.

```
GET /{tenant}/oauth2/authorize
      ?response_type=code
      &client_id=my-app
      &redirect_uri=https://app.example.com/signin-oidc
      &scope=openid%20profile%20email%20offline_access
      &state=<random>
      &nonce=<random>
      &code_challenge=<BASE64URL(SHA256(verifier))>
      &code_challenge_method=S256
```

```
POST /{tenant}/oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=<code>
&redirect_uri=https://app.example.com/signin-oidc
&client_id=my-app
&code_verifier=<verifier>
```

```json
{
  "access_token": "eyJ…",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "…",
  "id_token": "eyJ…",
  "scope": "openid profile email offline_access"
}
```

A `refresh_token` is issued only when `offline_access` is granted.

### Refresh token

Rotation is on by default: each refresh returns a new refresh token and retires the old one.
Presenting an already-used token is treated as theft and **revokes the entire token family**.

```
grant_type=refresh_token&refresh_token=<token>&client_id=my-app
```

Scope may be narrowed on refresh, never widened.

### Client credentials

For service-to-service calls. Requires client authentication — a public client cannot use it.

```bash
curl -X POST https://idp.example.com/my_idp/oauth2/token \
  -u 'my-service:<secret>' \
  -d 'grant_type=client_credentials' \
  -d 'scope=reports.read'
```

### Device authorization grant

For TVs, CLIs and other input-constrained devices.

```bash
curl -X POST https://idp.example.com/my_idp/oauth2/device_authorization \
  -u 'my-device:<secret>' -d 'scope=openid profile'
```

```json
{
  "device_code": "…",
  "user_code": "WDJB-MJHT",
  "verification_uri": "https://idp.example.com/my_idp/oauth2/device",
  "verification_uri_complete": "https://idp.example.com/my_idp/oauth2/device?user_code=WDJB-MJHT",
  "expires_in": 600,
  "interval": 5
}
```

The device then polls the token endpoint with
`grant_type=urn:ietf:params:oauth:grant-type:device_code`, receiving `authorization_pending`
until the user approves, and `slow_down` if it polls faster than `interval`.

### Pushed authorization requests

Submit the authorization parameters over the back channel first:

```bash
curl -X POST https://idp.example.com/my_idp/oauth2/par \
  -u 'my-app:<secret>' \
  -d 'response_type=code' -d 'redirect_uri=https://app.example.com/cb' \
  -d 'scope=openid' -d 'code_challenge=<challenge>' -d 'code_challenge_method=S256'
```

Then send the browser to `/oauth2/authorize?client_id=my-app&request_uri=<request_uri>`.

Set `Oidc:RequirePushedAuthorizationRequests` to reject plain authorization requests entirely.

---

## Configuration reference

Two sections of `ark_oauth_server` sit outside `Oidc`:

| Key | Default | Meaning |
|---|---|---|
| `AdminUser:Username` | `admin` | Login identifier of the seeded administrator; need not be an email address |
| `AdminUser:Password` | **none** | Its initial password. Required — falls back to `DefaultPw`, and a `<<placeholder>>` counts as unset. Read only while the database is created |
| `AdminUser:Name` | `Admin User` | Its display name |
| `Admin:SignOutUrl` | `end_session_endpoint` | Where the admin console's **Sign out** link goes |

Everything below sits under `ark_oauth_server:Oidc` and is optional; defaults are shown.

| Key | Default | Meaning |
|---|---|---|
| `EnableDeviceFlow` | `true` | Serve the device authorization grant |
| `EnablePushedAuthorizationRequests` | `true` | Serve `/oauth2/par` |
| `RequirePushedAuthorizationRequests` | `false` | Refuse authorization requests that did not arrive via PAR |
| `EnableDynamicRegistration` | `false` | Serve `/oauth2/register` — it lets callers create clients |
| `RequireRegistrationAccessToken` | `true` | Require an initial access token to register |
| `AlwaysRequireConsent` | `false` | Show the consent screen even for first-party clients |
| `SessionLifetimeMinutes` | `480` | IdP session lifetime |
| `MaxFailedSignIns` | `10` | Consecutive failures before lockout; `0` disables |
| `LockoutMinutes` | `15` | Lockout duration |
| `DeviceCodeLifetimeSeconds` | `600` | Device code validity |
| `DevicePollIntervalSeconds` | `5` | Minimum device polling interval |
| `ParLifetimeSeconds` | `90` | `request_uri` validity |
| `CorsOrigins` | `[]` | Browser origins allowed to call the token, userinfo, discovery and JWKS endpoints — see below |

### Browser clients and `CorsOrigins`

A single-page application redeems its authorization code from the browser, so the token endpoint is
called cross-origin. Empty by default, which means no cross-origin call succeeds; list the exact
origins of your SPAs (scheme, host and port — there is no wildcard, because these endpoints hand
out tokens):

```jsonc
"ark_oauth_server": { "Oidc": { "CorsOrigins": [ "https://app.example.com" ] } }
```

The policy applies only to `/oauth2/token`, `/oauth2/userinfo`, discovery and JWKS, and never
allows credentials — a browser client authenticates with a bearer token, not a cookie. The host
enables it with `app.UseArkOidcCors()` between `UseRouting()` and `UseAuthorization()`.
Server-side clients need none of this.

A working example, including the JavaScript, is at `/flows/spa` in
[`Ark.Client.Web`](Ark.oAuth.Oidc/Ark.Client.Web/README.md#the-other-flows).

Per-client settings live on the client record: `access_token_lifetime_seconds`,
`id_token_lifetime_seconds`, `refresh_token_lifetime_seconds`,
`authorization_code_lifetime_seconds`, `require_pkce`, `require_par`, `require_consent`,
`refresh_token_rotation`, `token_endpoint_auth_method` and `is_active`.

---

## Registering clients

Through the admin console at `/{tenant}/admin`, or with dynamic registration when it is enabled:

```bash
curl -X POST https://idp.example.com/my_idp/oauth2/register \
  -H 'Authorization: Bearer <initial access token>' \
  -H 'Content-Type: application/json' \
  -d '{
        "client_name": "My Service",
        "grant_types": ["client_credentials"],
        "token_endpoint_auth_method": "client_secret_basic",
        "scope": "reports.read"
      }'
```

The response carries the `client_secret` **once** — it is stored only as a PBKDF2 hash and
cannot be retrieved later. It also returns a `registration_access_token` for reading or deleting
the registration through `/oauth2/register/{client_id}` (RFC 7592).

The server mints a random `c_<16>` as the `client_id` unless the request names one. A `client_id`
in the metadata is honoured when it has the shape of a login id — lowercase, starting with a
letter or digit, 2 to 64 characters of `[a-z0-9._-]`, so it survives the URL path segment it
becomes — and is not already registered in the tenant; otherwise the registration is refused with
`invalid_client_metadata` (`409` for a taken id, like a duplicate `client_name`) rather than
silently given another id. A host that registers one client per tenant of its own uses this to
make the id read as the tenant (`acme`) instead of an opaque token.

Redirect URIs are validated at registration: they must be absolute, carry no fragment, and use
`https` unless they are loopback addresses.

Supported `token_endpoint_auth_method` values: `client_secret_basic`, `client_secret_post`,
`private_key_jwt`, `none`.

The initial access token must carry the `client.register` scope. That token comes from the client
credentials grant, so registration is a two-step chain: a machine client obtains a token, and that
token authorises the registration. The server seeds a machine client for this — `<tenant>_machine`,
registered for `client_credentials` and `client.register`, and deliberately created **without a
secret** so that no deployment ships with a well-known one. Give it a secret with **Regenerate
secret** in the admin console before using it.

`Ark.oAuth.Client` provides both halves (`ArkClientCredentials`, `ArkRegistration`), and
[`Ark.Client.Web`](Ark.oAuth.Oidc/Ark.Client.Web/README.md#the-other-flows) drives them from
`/flows/register`.

---

## Key management

Each tenant has a signing key published at `/.well-known/jwks.json`. Rotation is two-phase, so it
never invalidates tokens still in flight:

1. The new key becomes `active` and starts signing.
2. The previous key moves to `rollover` and stays published, so clients that cached JWKS keep
   validating tokens signed with it.
3. Once the longest-lived token signed by the old key has expired, retire it.

Keys are generated in-process. Nothing is fetched from an external key service.

---

## Upgrading from the v1 endpoints

The original `/oauth/{tenant}/v1/…` routes still work and keep their original request and
response shapes. What changed underneath is that they now delegate to the standard protocol
core, so codes issued there are single-use, expire, and **have their PKCE verifier checked** —
that check did not previously exist.

For existing databases, run migration `00003`:

```
GET /api/migration/v1/sql?action=up&name=00003_sql.sql
```

It adds the protocol state tables and the RFC 7591 metadata columns, seeds the scope catalogue,
and adopts each tenant's existing RSA key as its active signing key with `kid = tenant_id`, so
tokens already issued keep validating.

To migrate an application:

| v1 | Standard |
|---|---|
| Paste `rsaPublic` into config | Discovered from `jwks_uri` |
| `authServerUrl` + `tenantId` | `Authority` (the two joined) |
| `/oauth/{t}/v1/connect/authorize` | `/{t}/oauth2/authorize` |
| `/oauth/{t}/v1/token` | `/{t}/oauth2/token` |
| `/oauth/{t}/v1/.well-known/{c}/openid-configuration` | `/{t}/.well-known/openid-configuration` |
| Custom `redirect_relative` handling | Standard `CallbackPath` |

Set `ark_oauth_client:UseLegacyFlow` to `true` to keep the old client middleware during the
transition. It does not validate `state` or `nonce`; treat it as a migration aid.

---

## Security notes

Behaviour worth knowing about when operating this server:

- **PKCE is enforced.** A public client must send `code_challenge`, and the verifier is checked
  against it at the token endpoint. The `plain` method is not accepted.
- **Codes and refresh tokens are stored as SHA-256 hashes.** Read access to the database does not
  yield redeemable credentials.
- **Replay is treated as compromise.** Reusing an authorization code revokes the tokens derived
  from that session; reusing a refresh token revokes its whole family.
- **Redirect URIs are matched exactly.** No wildcards or prefix matching. The one exception is
  the port of a loopback address, for native apps (RFC 8252 §7.3).
- **Errors before `redirect_uri` is validated render as a page**, never as a redirect — otherwise
  the authorization endpoint would be an open redirect.
- **The introspection endpoint requires client authentication**, so it cannot be used as an
  oracle to test captured tokens.
- **Client authentication failures are constant-time**, and an unknown `client_id` costs the same
  as a bad secret.
- **Sign-in failures return a single message** regardless of cause, so the login form cannot be
  used to enumerate accounts. Repeated failures trigger lockout.
- **The sign-in and consent pages load no third-party resources.** Their CSS is inlined, so they
  work offline and under a strict Content-Security-Policy. The only external requests are the
  logo and policy URLs you configure yourself.

Before going to production:

1. Set `AdminUser:Password` out of band before the first run, and change it after first sign-in.
2. Set a strong `DefaultPw`.
3. Keep `RequireHttpsMetadata` at `true`.
4. Leave `EnableDynamicRegistration` off unless you need it, and keep
   `RequireRegistrationAccessToken` on if you do.
5. Give confidential clients real secrets and set `token_endpoint_auth_method` accordingly.

---

## License

MIT.
