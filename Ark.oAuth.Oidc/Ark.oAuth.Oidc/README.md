# Ark.oAuth.Oidc

A self-contained OAuth 2.1 and OpenID Connect provider for ASP.NET Core. Add two lines to
`Program.cs`, point any standard OIDC library at the issuer URL, and it configures itself from the
discovery document.

Multi-tenant, runs on SQLite / MySQL / PostgreSQL / SQL Server, and ships its own sign-in, consent
and admin UI. The matching client package is [`Ark.oAuth.Client`](https://www.nuget.org/packages/Ark.oAuth.Client).

## Install

```bash
dotnet new mvc -n MyIdp
cd MyIdp
dotnet add package Ark.oAuth.Oidc
dotnet add package Ark.oAuth.Client
```

## Program.cs

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
app.UseArkAuthData();    // one-time database bootstrap
app.UseArkOidcClient();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(name: "default", pattern: "{controller=Home}/{action=Index}/{id?}");
app.Run();
```

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
    "AdminUser": {                     // the account seeded when the database is first created
      "Username": "admin",             // optional, defaults to "admin"; need not be an email address
      "Password": "<required>",        // no default - see below
      "Name": "Admin User"
    },
    "Admin": {
      "SignOutUrl": "/Home/SignOutAll" // where the console's Sign out link goes; see below
    },
    "Oidc": {
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
      "CorsOrigins": []                // exact origins of any single-page-application clients
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
same authorization as the rest of the management API; the page itself is restricted to the
administrator account (`AdminUser:Username`, or a principal carrying an `admin` claim).

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

Only the SQLite scripts ship in this package. On MySQL or PostgreSQL there is nothing to run
automatically and the `ALTER TABLE` is still yours to apply. `GET
/api/migration/v1/sql?action=up|down&name=00005_sql.sql` is still there to run or roll back one by
hand, and now reports whether it actually worked instead of always answering "executed".

## Before production

1. Set `AdminUser:Password` before the first run, out of band, and change it after first sign-in.
2. Set a strong `DefaultPw`.
3. Keep `RequireHttpsMetadata` at `true` on clients.
4. Leave `EnableDynamicRegistration` off unless you need it, and keep
   `RequireRegistrationAccessToken` on if you do.
5. Give confidential clients real secrets and set `token_endpoint_auth_method` accordingly.

## Documentation

Full documentation, flow walkthroughs, the configuration reference and the v1 migration guide are
in the repository: <https://github.com/ir-dev/ark-oauth-oidc>

## License

MIT
