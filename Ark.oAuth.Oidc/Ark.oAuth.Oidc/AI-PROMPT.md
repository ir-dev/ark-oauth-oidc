<!--
  AI-PROMPT.md — Ark.oAuth.Oidc
  Audience: AI coding agents standing up / operating the identity provider.
  Source of truth: the C# in this directory. Do not add APIs, endpoints, or settings not listed here.
-->

# Ark.oAuth.Oidc — AI coding instructions

Compact, source-verified instructions for an AI coding agent hosting or operating the
**`Ark.oAuth.Oidc`** NuGet package (the identity provider / authorization server). Task recipes are in
[`AI-RECIPES.md`](AI-RECIPES.md); the full endpoint/API surface is in [`API-GUIDE.md`](API-GUIDE.md);
failures in [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md); upgrades in [`MIGRATION.md`](MIGRATION.md).

## 1. Library identity

| | |
|---|---|
| **Package** | `Ark.oAuth.Oidc` (nuget.org) |
| **Current version** | `2.0.9` (moves in lockstep with `Ark.oAuth.Client`) |
| **Root namespace** | `Ark.oAuth.Oidc`. Host also uses `Ark.oAuth` for the client extension. |
| **Target framework** | `net9.0` |
| **Purpose** | A self-contained OAuth 2.1 / OpenID Connect **provider** (IdP) for ASP.NET Core. Add two lines to `Program.cs`; standard OIDC clients configure themselves from discovery. |
| **Problem solved** | Run your own multi-tenant IdP without stitching together a protocol stack. Ships sign-in, consent, device and admin UI. |
| **Multi-tenancy** | The protocol is multi-tenant (issuer = `{BaseUrl}/{TenantId}`). **Administration is not** — one operator tenant administers all. |
| **Databases** | SQLite (default), MySQL, PostgreSQL. (SQL Server is *not* wired — do not select `Provider: "sqlserver"`.) |
| **Config section** | `ark_oauth_server` (+ `ConnectionStrings:ArkAuthConnection`) |

**Key dependencies:** EF Core `9.0.x` (+ Sqlite/MySQL/PostgreSQL providers), `Microsoft.IdentityModel.*`
`8.8.0` (kept on one version deliberately — see anti-patterns), `ark.net.util`.

## 2. AI usage instructions

```text
When using Ark.oAuth.Oidc:
1. The host wiring is exactly: AddArkOidcServer(env) + AddArkOidcClient(configuration) (the admin
   console is itself a client) in ConfigureServices; then in the pipeline, in ORDER:
     UseRouting(); UseArkOidcCors(); UseArkAuthData(); UseArkOidcClient();
     UseAuthentication(); UseAuthorization();  then MapControllerRoute.
2. Configure via "ark_oauth_server". Only TenantId + BaseUrl (+ a connection string) are structurally
   required; AdminUser:Password (or DefaultPw) is required to seed. Everything under Oidc has defaults.
3. Do NOT hard-code endpoint URLs into clients. Clients read {BaseUrl}/{TenantId}/.well-known/
   openid-configuration. The issuer is {BaseUrl}/{TenantId}.
4. Do NOT invent endpoints, settings, or management routes. Read the source (Code/ArkExtn.cs,
   Model/ArkModel.cs, Protocol/ArkOidcEndpoints.cs, Endpoints/*, Api/*).
5. Provisioning a new app = ONE call: POST /api/oauth/v1/provision/client. It creates the client,
   registers redirect URIs, creates/reuses the user, AND adds the user-client access mapping (the
   step people forget). Prefer it over four manual steps.
6. Secrets: AdminUser:Password has NO safe default (never "admin"/"admin"). The machine client is
   seeded WITHOUT a secret and cannot mint tokens until an operator regenerates one.
7. Signing keys are generated in-process on first run and rotate via JWKS (two-phase). Nothing needs
   redeploying on rotation.
8. Schema updates self-apply on start-up on SQLite. On MySQL/PostgreSQL the ALTER TABLE is yours.
9. Preserve OAuth 2.1 posture: PKCE S256 is required for public clients; implicit, hybrid and ROPC
   are deliberately unsupported. Do not try to re-enable them.
10. Point the admin console's Sign out at your OWN route (ark_oauth_server:Admin:SignOutUrl) that
    drops the host cookie AND the OIDC scheme.
```

## 3. Capability map

```text
Host bootstrap
 ├── Purpose        Turn an ASP.NET Core app into the IdP; create/seed/upgrade the database
 ├── Namespace      Ark.oAuth.Oidc
 ├── Entry points   services.AddArkOidcServer(IWebHostEnvironment)
 │                  app.UseArkAuthData()  (one-time DB bootstrap, latched)
 │                  app.UseArkOidcCors()  (only if SPA clients call token/userinfo)
 ├── Config         ark_oauth_server: TenantId, BaseUrl, BasePath, Provider, DefaultPw,
 │                  UserPasswordMode, AdminUser{Username,Password,Name}, Admin{SignOutUrl},
 │                  Oidc{...}, EmailConfig{...}; ConnectionStrings:ArkAuthConnection
 └── Anti-patterns  Provider "sqlserver"; running requests before UseArkAuthData; seeding with a
                    <<placeholder>> password

OAuth 2.1 / OIDC protocol core  (endpoints under the issuer {BaseUrl}/{TenantId})
 ├── Discovery      /.well-known/openid-configuration  (+ /oauth-authorization-server, RFC 8414)
 ├── JWKS           /.well-known/jwks.json             (two-phase key rotation, RS256)
 ├── Authorize      /oauth2/authorize                  (code + PKCE S256; response_type=code only)
 ├── Token          /oauth2/token                      (authorization_code, refresh_token, client_credentials, device_code)
 ├── UserInfo       /oauth2/userinfo
 ├── Introspect     /oauth2/introspect (RFC 7662)      Revoke /oauth2/revoke (RFC 7009)
 ├── End session    /oauth2/logout     (RP-initiated; browser-wide by default)
 ├── Device         /oauth2/device_authorization (RFC 8628)   PAR /oauth2/par (RFC 9126)
 ├── Register       /oauth2/register (RFC 7591/7592; OFF by default)
 ├── Setup page     /oauth2/integrate/{client_id}      (copy-paste config + a live PKCE run)
 └── Anti-patterns  implicit/hybrid/ROPC; plain PKCE; hard-coded endpoint URLs in clients

Provisioning & activation API   (/api/oauth/v1/... , [Authorize] — needs a valid token)
 ├── Provision      POST /provision/client   -> client + user + redirect URIs + access mapping (1 call)
 ├── Activate       POST /activation/client, POST /activation/user  (is_active on/off; revokes tokens)
 ├── Collision      client name taken => 409 client_exists, nothing written; existing user => reused+mapped
 └── Anti-patterns  four manual steps; forgetting the access mapping (looks like a wrong password)

Management API   (/api/oauth/v1/... , [Authorize])
 ├── Tenants        v1/tenant/list, v1/tenant/upsert
 ├── Clients        v1/client/list|upsert|delete, v1/client/secret/reset
 ├── Users          v1/user/list|upsert, v1/user/pw/reset/init, v1/user/pw/set
 ├── Access map     v1/user/client/claims/upsert|delete, v1/user/list/client/claims/mapping/{email}/{ten}
 ├── Scopes/Claims  v1/scope/*, v1/claim/*
 ├── Service token  v1/service/pw/reset
 └── Anti-patterns  editing rows directly in the DB instead of the API

Admin console (UI)
 ├── Path           /{tenant_id}/admin  (/admin redirects to the configured tenant)
 ├── Provisioning   /{tenant_id}/admin/provisioning  (forms + generated curl; admin-only)
 ├── Assets         /ark-admin/asset/ark-admin.css|.js  (served from the assembly)
 ├── Sign out       ark_oauth_server:Admin:SignOutUrl  (host route; only the host can drop its cookie)
 └── Anti-patterns  copying views into the host; expecting the console to end the host session itself

Migration API
 ├── Run/rollback   GET /api/migration/v1/sql?action=up|down&name=00005_sql.sql
 ├── List embeds    GET /api/migration/v1/embeded/list
 └── Note           SQLite scripts self-apply on start-up; MySQL/PostgreSQL ALTERs are manual
```

## 4. API / configuration decision guide

```text
Standing up a new IdP?                     -> AddArkOidcServer(env) + AddArkOidcClient(cfg); set TenantId+BaseUrl+AdminUser:Password
Onboarding a new application?              -> POST /api/oauth/v1/provision/client (one call, includes the access mapping)
Turning an app or account off temporarily? -> POST /api/oauth/v1/activation/client | /activation/user (is_active=false; revokes tokens)
SPA client can't reach /token from browser?-> add its exact origin to Oidc:CorsOrigins, then UseArkOidcCors()
Need machine-to-machine tokens?            -> use the seeded {tenant}_machine client; regenerate its secret in the console first
Need dynamic client registration?          -> Oidc:EnableDynamicRegistration=true (keep RequireRegistrationAccessToken on)
Want mandatory PAR?                         -> Oidc:RequirePushedAuthorizationRequests=true
Onboarding passwords via email links?       -> UserPasswordMode="email_based" (email accounts parked in reset mode)
Shared-machine sign-out should clear all?   -> keep Oidc:SignOutAllBrowserSessions=true (default)
Different DB?                               -> Provider="mysql"|"postgres"; set ConnectionStrings:ArkAuthConnection
Upgrading an existing DB?                   -> SQLite: automatic on start-up; MySQL/PG: apply the ALTERs (see MIGRATION.md)

AVOID:
- Provider="sqlserver" (falls through every branch; no provider configured).
- Re-enabling implicit/hybrid/ROPC (removed by OAuth 2.1; unsupported here).
- Seeding with AdminUser:Password left as "<<placeholder>>" (treated as unset; seeding refuses).
- Putting AdminUser:Password in appsettings.json (use a secret store / env var).
```

## 5. Anti-patterns (do NOT generate)

```text
DO NOT:
- Set Provider to "sqlserver". OnConfiguring has no branch for it; the context ends up with no
  provider and fails. Use sqlite (default), mysql, or postgres.
- Compile in or default the admin password. AdminUser:Password has no default; a "<<placeholder>>"
  counts as unset and seeding stops with a message. Never re-introduce "admin"/"admin".
- Seed the machine client with a secret in source. It ships secret-less on purpose; an operator
  regenerates one per deployment.
- Hard-code endpoint URLs into clients. Clients configure from discovery; the issuer is {BaseUrl}/{TenantId}.
- Provision an app in four manual steps and forget the user-client access mapping — its absence looks
  exactly like a wrong password. Use POST /provision/client.
- Try to re-enable the implicit grant, hybrid flow, or resource-owner password credentials.
- Accept plain PKCE. Only S256 is advertised/accepted; PKCE is mandatory for public clients.
- Mix Microsoft.IdentityModel.* versions. MySql.Data pulls Protocols 7.5.0; the graph is pinned to
  8.8.0 so the OIDC challenge does not die with a MethodAccessException. Keep it aligned.
- Add a plain http BaseUrl in production, or turn RequireHttpsMetadata off on clients.
- Expect the admin console's Sign out to end the host session — only the host can drop its cookie;
  point Admin:SignOutUrl at a host route that signs out of the cookie AND the OIDC scheme.
- Skip a MySQL/PostgreSQL schema script. The entities will carry columns the tables lack and the
  management API answers a bare 500. Only SQLite self-applies.
- Run app requests before UseArkAuthData() has bootstrapped the database.
```

## 6. Version & compatibility

- Target framework `net9.0`; EF Core `9.0.x`.
- Current version **2.0.9**; ships with `Ark.oAuth.Client 2.0.9`.
- **Unsupported by design:** implicit grant, hybrid flow, ROPC, plain PKCE, SQL Server.
- Schema history is tracked in `ark_schema_history`; scripts `00003` (2.0.0), `00004` (2.0.2),
  `00005` (2.0.3). Full detail: [`MIGRATION.md`](MIGRATION.md).

## 7. AI context block (inject into a system/developer prompt)

```text
LIBRARY: Ark.oAuth.Oidc (v2.0.9, net9.0, namespace Ark.oAuth.Oidc)

PURPOSE:
Self-contained multi-tenant OAuth 2.1 / OpenID Connect provider for ASP.NET Core. Two lines in
Program.cs give discovery, JWKS, code+PKCE, refresh, client credentials, device grant, PAR,
introspection, revocation, dynamic registration, RP-initiated + back-channel logout, and sign-in/
consent/admin UI. Runs on SQLite/MySQL/PostgreSQL.

USE WHEN:
- You need to RUN an identity provider (issue tokens), not consume one.
- You need self-hosted, multi-tenant OIDC with an admin console and a one-call provisioning API.

DO NOT USE WHEN:
- The app only needs to sign users IN against an existing provider (use Ark.oAuth.Client).
- You need SQL Server, or the implicit/hybrid/ROPC grants.

PRIMARY APIS:
- services.AddArkOidcServer(env); services.AddArkOidcClient(configuration);
- pipeline: UseRouting(); UseArkOidcCors(); UseArkAuthData(); UseArkOidcClient(); UseAuthentication(); UseAuthorization();
- POST /api/oauth/v1/provision/client        (client + user + redirects + access mapping)
- POST /api/oauth/v1/activation/client|user  (is_active on/off; revokes tokens)
- Management API under /api/oauth/v1/... ([Authorize])
- Protocol endpoints under {BaseUrl}/{TenantId}/oauth2/... and /.well-known/...

CONFIGURATION ("ark_oauth_server"):
TenantId (required), BaseUrl (required), BasePath, Provider (sqlite|mysql|postgres),
DefaultPw, UserPasswordMode (admin_managed|email_based|auto), AdminUser{Username,Password(required),Name},
Admin{SignOutUrl}, Oidc{EnableDynamicRegistration=false, RequireRegistrationAccessToken=true,
EnableDeviceFlow=true, EnablePushedAuthorizationRequests=true, RequirePushedAuthorizationRequests=false,
AlwaysRequireConsent=false, SessionLifetimeMinutes=480, MaxFailedSignIns=10, LockoutMinutes=15,
EnableBackChannelLogout=true, BackChannelLogoutTimeoutSeconds=5, LogoutTokenLifetimeSeconds=120,
SignOutAllBrowserSessions=true, SignOutAcrossTenants=true, CorsOrigins=[]}.
ConnectionStrings:ArkAuthConnection.

PREFERRED PATTERNS:
Discovery-driven clients; issuer = {BaseUrl}/{TenantId}; one-call provisioning (never forget the
access mapping); in-process signing keys with JWKS rotation; secret out of band; SQLite auto-migrate.

ANTI-PATTERNS:
Provider "sqlserver"; defaulted/compiled admin password; secret-seeded machine client; hard-coded
client endpoints; implicit/hybrid/ROPC; plain PKCE; mixed IdentityModel versions; skipping a MySQL/
PostgreSQL schema script.

IMPORTANT CONSTRAINTS:
- Administration is single-tenant (one operator tenant administers all); the protocol is multi-tenant.
- Access token = at+jwt (RFC 9068). Codes & refresh tokens stored as SHA-256; replay revokes the family.
- Sign-out is browser-wide by default (ark_idp_bid cookie). Back-channel logout notifies only clients
  that registered a backchannel_logout_uri.
- Deactivating revokes already-issued refresh tokens/sessions; issued access tokens live until expiry.

ERROR HANDLING:
Standard OAuth error bodies. Management/list endpoints return { error, msg }. Provisioning: 200
{error:false,...}, 409 {error:true, code:"client_exists"}. A vague single sign-in message resists
account enumeration; deactivation messages only show after the password is verified.

PERFORMANCE:
DB bootstrap runs once (latched). Discovery is cacheable (max-age=300). Back-channel logout deliveries
run in parallel behind a per-client timeout; a down client cannot block sign-out.

EXAMPLE:
  builder.Services.AddArkOidcServer(builder.Environment);
  builder.Services.AddArkOidcClient(builder.Configuration);
  var app = builder.Build();
  app.UseRouting(); app.UseArkOidcCors(); app.UseArkAuthData(); app.UseArkOidcClient();
  app.UseAuthentication(); app.UseAuthorization();
  // "ark_oauth_server": { "TenantId":"my_idp", "BaseUrl":"https://idp.example.com", "Provider":"sqlite" }
  // issuer  = https://idp.example.com/my_idp
  // discovery = https://idp.example.com/my_idp/.well-known/openid-configuration
```
