<!--
  AI-RECIPES.md — Ark.oAuth.Oidc
  Audience: AI coding agents. Reusable prompts + verified examples for hosting/operating the IdP.
  Every API, endpoint, and setting used below exists in this directory's source.
-->

# Ark.oAuth.Oidc — AI recipes

Task-oriented prompts and canonical, source-verified examples. Pair with
[`AI-PROMPT.md`](AI-PROMPT.md) (rules), [`API-GUIDE.md`](API-GUIDE.md) (full surface),
[`TROUBLESHOOTING.md`](TROUBLESHOOTING.md).

Config section `ark_oauth_server` · issuer = `{BaseUrl}/{TenantId}` · version `2.0.9`.

---

## Recipe 1 — Stand up the identity provider

> **PROMPT:** "Host Ark.oAuth.Oidc as an OAuth 2.1 / OIDC provider in an ASP.NET Core MVC app.
> Register both server and client (the admin console is a client), put the middleware in the exact
> required order, and configure only TenantId + BaseUrl. Supply the admin password out of band."

```bash
dotnet new mvc -n MyIdp && cd MyIdp
dotnet add package Ark.oAuth.Oidc
dotnet add package Ark.oAuth.Client
dotnet user-secrets set "ark_oauth_server:AdminUser:Password" "<strong-password>"
```

**Program.cs**
```csharp
using Ark.oAuth;
using Ark.oAuth.Oidc;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddArkOidcServer(builder.Environment);    // the identity provider
builder.Services.AddArkOidcClient(builder.Configuration);  // the admin console is itself a client
builder.Services.AddControllersWithViews();

var app = builder.Build();

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();          // MUST precede UseAuthentication/UseAuthorization
app.UseArkOidcCors();      // only needed if browser (SPA) clients call the token endpoint
app.UseArkAuthData();      // one-time DB bootstrap (create/seed/upgrade), latched
app.UseArkOidcClient();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(name: "default", pattern: "{controller=Home}/{action=Index}/{id?}");
app.Run();
```

**appsettings.json**
```jsonc
{
  "ark_oauth_server": {
    "TenantId": "my_idp",
    "BaseUrl": "https://idp.example.com",
    "Provider": "sqlite",
    "DefaultPw": "<initial password for new users>",
    "AdminUser": { "Username": "admin", "Name": "Admin User" }  // Password comes from user-secrets/env
  },
  "ConnectionStrings": { "ArkAuthConnection": "Data Source=./data/ark_auth.db" }
}
```

- **Expected:** first request creates the schema, generates an RSA signing key in-process, seeds the
  scope catalogue and the admin account. Issuer = `https://idp.example.com/my_idp`; discovery at
  `…/my_idp/.well-known/openid-configuration`.
- **Order matters:** `UseRouting` before auth; `UseArkOidcCors` after routing, before authorization.
- **Mistake:** leaving `AdminUser:Password` (and `DefaultPw`) unset or as `<<placeholder>>` — seeding
  refuses with a message naming the setting, and no database is created.

---

## Recipe 2 — Onboard an application in one call (provisioning)

> **PROMPT:** "Provision a new application with `POST /api/oauth/v1/provision/client`. It must create
> the client, register the redirect URIs, create the user, AND add the user-client access mapping in
> one call. Authenticate with a bearer token."

```http
POST /api/oauth/v1/provision/client
Authorization: Bearer <token>
Content-Type: application/json

{
  "client_name": "Billing Portal",
  "user_name":   "jane@example.com",
  "tenant_id":   "my_idp",
  "client_id":   "billing_portal",
  "redirect_uris": [ "https://billing.example.com/signin-oidc" ],
  "post_logout_redirect_uris": [ "https://billing.example.com/signout-callback-oidc" ],
  "claims": [ "sub", "name", "email", "email_verified" ],
  "send_activation_email": false
}
```

```jsonc
// 200 — created
{ "error": false, "code": "provisioned",
  "data": { "client_id": "billing_portal", "client_created": true,
            "user_name": "jane@example.com", "user_created": true,
            "user_credential": "default_password", "mapping_created": true,
            "issuer": "…", "discovery": "…", "setup_url": "…" } }

// 409 — name taken; NOTHING written (a live app's redirect URIs are never silently rewritten)
{ "error": true, "code": "client_exists", "msg": "an application named 'Billing Portal' …" }
```

- **Why one call:** the four manual steps end with the user-client **access mapping**, which is the
  step people forget — and its absence looks exactly like a wrong password.
- **Collision semantics:** an existing **client name** → 409, nothing written; an existing **user** →
  reused and mapped (that is how someone gets their second app). `user_credential` is one of
  `default_password | activation_email | existing_account`.
- **Console equivalent:** `/{tenant}/admin/provisioning` is this endpoint with a form that also
  writes the `curl` for you.

---

## Recipe 3 — Register a client for the Ark client package (browser web app)

> **PROMPT:** "After provisioning, tell me what the client app needs. It uses Ark.oAuth.Client."

The client app needs only two settings; everything else is discovered:
```jsonc
"ark_oauth_client": {
  "Authority": "https://idp.example.com/my_idp",   // = issuer from the provisioning result
  "ClientId": "billing_portal"
}
```
- Register **both** callbacks on the client record: `…/signin-oidc` and `…/signout-callback-oidc`
  (byte-for-byte). Provisioning does this from `redirect_uris`/`post_logout_redirect_uris`.
- The generated setup page `…/my_idp/oauth2/integrate/billing_portal` shows copy-paste config and can
  **run the flow live** (real `code_verifier`/S256 in the browser, ending on your redirect URI).

---

## Recipe 4 — Deactivate / reactivate a user or a client

> **PROMPT:** "Switch an application or an account off without deleting it. Deactivation must revoke
> what was already handed out."

```http
POST /api/oauth/v1/activation/client
{ "tenant_id": "my_idp", "client_id": "billing_portal", "is_active": false, "reason": "offboarding" }

POST /api/oauth/v1/activation/user
{ "user_name": "jane@example.com", "is_active": false }
```

- **Effect:** a deactivated **client** loses its refresh tokens; a deactivated **user** loses their
  sessions *and* refresh tokens. Already-issued **access tokens** stay valid until they expire
  (self-contained JWTs — the usual bound on revoking a JWT).
- **Sign-in messaging:** a deactivated app names itself; a deactivated account is told it is
  deactivated — but only **after** the password verifies, so the form still resists account
  enumeration.

---

## Recipe 5 — Enable SPA (browser) clients to call the token endpoint

> **PROMPT:** "A single-page app redeems its code from the browser. Allow its origin for the token/
> userinfo endpoints via CORS."

```jsonc
"ark_oauth_server": {
  "Oidc": { "CorsOrigins": [ "https://app.example.com", "https://localhost:7255" ] }
}
```
and ensure `app.UseArkOidcCors();` sits **after** `UseRouting()` and **before** `UseAuthorization()`.

- **Expected:** listed origins can `fetch`/XHR the token, userinfo, discovery and JWKS endpoints.
- **No wildcard:** an empty `CorsOrigins` means cross-origin is **off**, not open. Server-side
  clients (web app code flow, client_credentials) do not go through a browser and need nothing here.
- **Mistake:** ordering `UseArkOidcCors()` after `UseAuthorization()` — a rejected preflight never
  gets its headers, and the browser reports a misconfigured client.

---

## Recipe 6 — Machine-to-machine (client credentials)

> **PROMPT:** "A backend service needs a token as itself. Use the seeded machine client after giving
> it a secret."

1. In the console's client editor for `{tenant}_machine`, press **Regenerate secret** (it ships
   secret-less on purpose and cannot mint tokens until it has one).
2. Exchange:
```http
POST /my_idp/oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=my_idp_machine&client_secret=<secret>&scope=client.register
```
- **`client.register`** is the scope an initial access token needs to create clients via `/oauth2/register`.
- On the client side use `ArkClientCredentials.GetTokenAsync(...)` from `Ark.oAuth.Client`.
- **Mistake:** expecting `{tenant}_machine` to work immediately — regenerate its secret first.

---

## Recipe 7 — Turn on dynamic client registration (RFC 7591)

> **PROMPT:** "Allow programmatic client registration, but keep it gated behind an initial access
> token."

```jsonc
"ark_oauth_server": {
  "Oidc": { "EnableDynamicRegistration": true, "RequireRegistrationAccessToken": true }
}
```
- Discovery then advertises `registration_endpoint` at `…/oauth2/register`.
- Callers register with an initial access token carrying the `client.register` scope (see Recipe 6);
  from the client library use `ArkRegistration.RegisterAsync(...)`.
- **Off by default** because it creates clients. Keep `RequireRegistrationAccessToken` on.

---

## Recipe 8 — Password onboarding modes

> **PROMPT:** "Choose how new-user passwords are set."

```jsonc
"ark_oauth_server": { "UserPasswordMode": "email_based" }   // admin_managed | email_based | auto
```
- `admin_managed` — always create on `DefaultPw`; operators set/communicate passwords out of band.
- `email_based` — email-address accounts are parked in reset mode and emailed an activation link;
  plain usernames still fall back to `DefaultPw`.
- `auto` (or unset) — legacy behaviour: the caller decides (`send_activation_email`).
- Requires a working `EmailConfig` for the email flow.

---

## Recipe 9 — Sign-out that clears the whole shared machine

> **PROMPT:** "On a shared machine, signing out should end every session in the browser and notify
> the apps that were signed in."

- Keep the defaults: `Oidc:SignOutAllBrowserSessions = true`, `Oidc:SignOutAcrossTenants = true`.
- Point clients at `end_session_endpoint` = `…/my_idp/oauth2/logout`. A long-lived `ark_idp_bid`
  cookie identifies the **browser**; every session records the browser it was created in, and logout
  ends all of them.
- For each app that wants its own cookie dropped when the IdP session ends, register a
  `backchannel_logout_uri` (console client editor, `/oauth2/register`, or the provisioning body). The
  app is POSTed a signed `logout_token` (`typ: logout+jwt`, `sid`, no `nonce`); validate against the
  same JWKS as an ID token and answer 200/204.
- **A down client cannot block sign-out** — deliveries run in parallel behind
  `Oidc:BackChannelLogoutTimeoutSeconds` and a failure is logged, not raised.

---

## Recipe 10 — Wire the admin console's Sign out to the host

> **PROMPT:** "Make the admin console Sign out end the host session too."

```jsonc
"ark_oauth_server": { "Admin": { "SignOutUrl": "/Home/SignOutAll" } }
```
```csharp
// The host route it points at — only the host can drop its own cookie:
public async Task SignOutAll()
{
    await HttpContext.SignOutAsync(ArkOidcClient.CookieScheme);
    await HttpContext.SignOutAsync(ArkOidcClient.OidcScheme,
        new AuthenticationProperties { RedirectUri = "/" });
}
```
- Left unset, the console's Sign out falls back to the tenant's `end_session_endpoint`, which ends the
  IdP session but leaves the host cookie in place until it expires.

---

## Recipe 11 — Run on MySQL or PostgreSQL

> **PROMPT:** "Point the IdP at PostgreSQL."

```jsonc
"ark_oauth_server": { "Provider": "postgres" },   // or "mysql"
"ConnectionStrings": { "ArkAuthConnection": "Host=…;Database=…;Username=…;Password=…" }
```
- **Only the SQLite migration scripts self-apply.** On MySQL/PostgreSQL you must apply the equivalent
  `ALTER TABLE`/`CREATE TABLE` for each schema version (00003/00004/00005) yourself — otherwise the
  entities carry columns the tables lack and the management API answers a bare 500. See
  [`MIGRATION.md`](MIGRATION.md).
- **Never `Provider: "sqlserver"`** — it is not wired and leaves the context with no provider.

---

## Recipe 12 — Upgrade an existing database

> **PROMPT:** "Upgrade a live SQLite deployment; what happens to the schema?"

- On start-up `UseArkAuthData()` applies every script the DB has not had yet and records it in
  `ark_schema_history`. Nothing is replayed; a DB predating the history table is *measured* (each
  script checked against the live schema) and recorded as a baseline if already present.
- Scripts: `00003` (2.0.0 — protocol tables, RFC 7591 metadata), `00004` (2.0.2 — `users.is_active`),
  `00005` (2.0.3 — back-channel logout metadata, `sessions.browser_id`, `session_clients`).
- To run/rollback one by hand: `GET /api/migration/v1/sql?action=up|down&name=00005_sql.sql`.

---

## Recipe 13 — Before production checklist

> **PROMPT:** "Harden the IdP before going live."

1. Set `AdminUser:Password` out of band (secret store/env), then change it after first sign-in.
2. Set a strong `DefaultPw`.
3. Keep `RequireHttpsMetadata=true` on clients; use an https `BaseUrl`.
4. Leave `Oidc:EnableDynamicRegistration` off unless needed; keep `RequireRegistrationAccessToken` on.
5. Give confidential clients real secrets and set `token_endpoint_auth_method` accordingly.
6. Regenerate the `{tenant}_machine` client secret (it ships without one).
7. List exact SPA origins in `Oidc:CorsOrigins`; leave it empty if there are none.
