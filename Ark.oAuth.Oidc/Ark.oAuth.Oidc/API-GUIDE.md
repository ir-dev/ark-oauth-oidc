<!--
  API-GUIDE.md — Ark.oAuth.Oidc
  Audience: AI coding agents needing exact host APIs, endpoints, settings and management routes.
  Every item is copied from this directory's source. If it is not here, read the .cs file.
-->

# Ark.oAuth.Oidc — API guide

Exact host-facing surface (namespace **`Ark.oAuth.Oidc`**, package `Ark.oAuth.Oidc` v2.0.9, `net9.0`).
Verified against the source. The provider is consumed by *hosting* it (three extension methods +
configuration) and by *calling* its HTTP endpoints (protocol + management APIs).

## Host extension methods (`ArkExtn`)

| Signature | Purpose | Order |
|---|---|---|
| `void IServiceCollection.AddArkOidcServer(IWebHostEnvironment environment)` | Register the DbContext, protocol services, CORS configurator, controllers/views, antiforgery. Unpacks embedded assets to the content root in Development. | in `ConfigureServices` |
| `void IApplicationBuilder.UseArkAuthData()` | One-time DB bootstrap: create + seed on first run, apply pending schema scripts, reconcile the admin/machine clients and scope catalogue. Latched (runs once per process). | after `UseRouting` |
| `void IApplicationBuilder.UseArkOidcCors()` | Enables the CORS middleware for endpoints marked `[EnableCors(ArkCors.PolicyName)]`. | after `UseRouting`, **before** `UseAuthorization` |

The host also calls **`AddArkOidcClient(configuration)`** and **`UseArkOidcClient()`** from
`Ark.oAuth.Client` (the admin console is itself an OIDC client). Full pipeline order:

```csharp
app.UseRouting();
app.UseArkOidcCors();     // only if SPA clients call token/userinfo cross-origin
app.UseArkAuthData();
app.UseArkOidcClient();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllerRoute("default", "{controller=Home}/{action=Index}/{id?}");
```

## Configuration (`ArkAuthServerConfig`, section `ark_oauth_server`)

| Property | Type | Default | Notes |
|---|---|---|---|
| `TenantId` | `string` | — | **Required.** A client `{TenantId}_client` is seeded for the console. |
| `BaseUrl` | `string` | — | **Required in practice.** Issuer = `{BaseUrl}/{TenantId}`. |
| `BasePath` | `string` | `""` | Set only if hosted under a sub-path. |
| `Provider` | `string` | `sqlite` | `sqlite` \| `mysql` \| `postgres`. **Not** `sqlserver`. |
| `UploadPath` | `string` | — | e.g. `./wwwroot/{0}/`. |
| `DefaultPw` | `string` | — | Initial password for new users; fallback for `AdminUser:Password`. |
| `UserPasswordMode` | `string` | `auto` | `admin_managed` \| `email_based` \| `auto`. |
| `AdminUser` | `ArkAdminUserConfig` | — | Seed account. `Username` (default `admin`), **`Password` (required, no safe default)**, `Name`. |
| `Admin` | `ArkAdminConsoleConfig` | — | `SignOutUrl` — host route the console's Sign out uses. |
| `Oidc` | `ArkOidcOptions` | see below | Protocol switches; every value has a default. |
| `EmailConfig` | `ArkEmailConfig` | — | SMTP + branding (`host_logo`, `client_logo`, links, …). |
| `ConnectionStrings:ArkAuthConnection` | `string` | — | The database connection string. |

**`ArkOidcOptions`** (section `ark_oauth_server:Oidc`):

| Property | Default | Notes |
|---|---|---|
| `EnableDynamicRegistration` | `false` | RFC 7591 `/register`. Off — it creates clients. |
| `RequireRegistrationAccessToken` | `true` | Require an initial access token on `/register`. |
| `EnableDeviceFlow` | `true` | RFC 8628. |
| `EnablePushedAuthorizationRequests` | `true` | RFC 9126 `/par`. |
| `RequirePushedAuthorizationRequests` | `false` | Refuse plain `/authorize` not via PAR. |
| `DeviceCodeLifetimeSeconds` | `600` | |
| `DevicePollIntervalSeconds` | `5` | |
| `ParLifetimeSeconds` | `90` | |
| `SessionLifetimeMinutes` | `480` | |
| `MaxFailedSignIns` | `10` | 0 disables lockout. |
| `LockoutMinutes` | `15` | |
| `AlwaysRequireConsent` | `false` | |
| `EnableBackChannelLogout` | `true` | Notifies only clients with a `backchannel_logout_uri`. |
| `BackChannelLogoutTimeoutSeconds` | `5` | Per client; deliveries run in parallel. |
| `LogoutTokenLifetimeSeconds` | `120` | |
| `SignOutAllBrowserSessions` | `true` | Off ends only the session the cookie names. |
| `SignOutAcrossTenants` | `true` | Off keeps sign-out inside the tenant. |
| `CorsOrigins` | `[]` | Exact SPA origins; empty = cross-origin off (no wildcard). |

**`ArkUserPasswordMode`** enum: `Auto`, `AdminManaged`, `EmailBased`. Helper:
`ArkAuthServerConfig.EffectiveUserPasswordMode`, `ShouldUseEmailPasswordFlow(loginId, requestedByCaller)`.

## Protocol endpoints (relative to the issuer `{BaseUrl}/{TenantId}`)

Built by `Protocol.ArkOidcEndpoints`. All advertised in discovery.

| Purpose | Path |
|---|---|
| Discovery | `/.well-known/openid-configuration` (also `/.well-known/oauth-authorization-server`, RFC 8414) |
| JWKS | `/.well-known/jwks.json` (also `/oauth2/jwks`) |
| Authorization | `/oauth2/authorize` |
| Token | `/oauth2/token` |
| UserInfo | `/oauth2/userinfo` |
| Introspection | `/oauth2/introspect` (RFC 7662) |
| Revocation | `/oauth2/revoke` (RFC 7009) |
| End session | `/oauth2/logout` (RP-initiated; browser-wide) |
| Device authorization | `/oauth2/device_authorization` (RFC 8628) · verification `/oauth2/device` |
| Pushed authorization request | `/oauth2/par` (RFC 9126) |
| Dynamic registration | `/oauth2/register` (RFC 7591/7592; only if enabled) |
| Client setup page | `/oauth2/integrate/{client_id}` |

**Discovery advertises** (verified in `OidcDiscoveryController`):
`response_types_supported: [code]`; `grant_types_supported: authorization_code, refresh_token,
client_credentials` (+ `urn:ietf:params:oauth:grant-type:device_code` if device flow on);
`code_challenge_methods_supported: [S256]`; `id_token_signing_alg_values_supported: [RS256]`;
`subject_types_supported: [public]`;
`token_endpoint_auth_methods_supported: client_secret_basic, client_secret_post, private_key_jwt, none`;
`authorization_response_iss_parameter_supported: true` (RFC 9207);
`backchannel_logout_supported: true`, `backchannel_logout_session_supported: true`;
`frontchannel_logout_supported: false` (front-channel logout is **not** implemented);
`scopes_supported`/`claims_supported` from the catalogue. Access tokens are `at+jwt` (RFC 9068) with
`client_id`, `jti`, `scope`.

**Not supported (by design):** implicit grant, hybrid flow, resource-owner password credentials,
plain PKCE, SQL Server.

## Provisioning & activation API (`ProvisionController`, `[Authorize]`, base `/api/oauth`)

| Method + route | Body | Result |
|---|---|---|
| `POST /v1/provision/client` | `ArkProvisionRequest` | 200 `{error:false, code:"provisioned", data: ArkProvisionResult}`; 409 `{error:true, code:"client_exists"}` (nothing written) |
| `POST /v1/activation/client` | `ArkActivationRequest` | client `is_active` on/off; deactivation revokes its refresh tokens |
| `POST /v1/activation/user` | `ArkActivationRequest` | user `is_active` on/off; deactivation revokes sessions + refresh tokens |

**`ArkProvisionRequest`**: `client_name` (**required**), `user_name` (**required**), `tenant_id`
(default `TenantId`), `client_id` (derived from name), `client_logo`, `redirect_uris`,
`post_logout_redirect_uris`, `backchannel_logout_uri`, `scopes` (default openid/profile/email/
offline_access), `application_type` (web|spa|native|service, default web), `token_endpoint_auth_method`
(default `none`), `user_display_name`, `claims` (default identity claims), `send_activation_email`
(default false).

**`ArkProvisionResult`**: `tenant_id`, `client_id`, `client_name`, `client_created`, `user_name`,
`user_created`, `user_credential` (`default_password`|`activation_email`|`existing_account`),
`mapping_created`, `claims`, `redirect_uris`, `issuer`, `discovery`, `setup_url`.

**`ArkActivationRequest`**: `tenant_id`, `client_id`, `user_name`, `is_active`, `reason`.

## Management API (`ManageController`, `[Authorize]`, base `/api/oauth`)

All `v1/...`; list endpoints are GET, mutations are POST with the entity in the body. On failure they
return `{ error, msg }`.

| Area | Routes |
|---|---|
| Tenants | `v1/tenant/list`, `v1/tenant/upsert` |
| Clients | `v1/client/list`, `v1/client/upsert`, `v1/client/delete`, `v1/client/secret/reset` |
| Claims | `v1/claim/list`, `v1/claim/upsert`, `v1/claim/delete` |
| Scopes | `v1/scope/list`, `v1/scope/upsert`, `v1/scope/delete` |
| Users | `v1/user/list`, `v1/user/upsert`, `v1/user/pw/reset/init`, `v1/user/pw/set` |
| Access mapping | `v1/user/list/client/claims/mapping/{email}/{ten_id}`, `v1/user/client/claims/upsert`, `v1/user/client/claims/delete` |
| Service token | `v1/service/pw/reset` |
| Legacy onboarding | `onboard/full`, `onboard/user` (superseded by provisioning) |

## Migration API (`MigrationController`, base `/api/migration`)

| Method + route | Purpose |
|---|---|
| `GET /v1/sql?action=up\|down&name=00005_sql.sql` | Run or roll back one script by hand (reports whether it worked). |
| `GET /v1/embeded/list` | List embedded migration resources. |

> Note: `MigrationController` has no class-level `[Authorize]`; protect `/api/migration` at the
> network/gateway layer, or do not expose it publicly.

## Admin console (UI)

| Purpose | Path |
|---|---|
| Console | `/{tenant_id}/admin` (`/admin` → configured tenant) |
| Provisioning page (admin-only) | `/{tenant_id}/admin/provisioning` |
| Assets (from assembly) | `/ark-admin/asset/ark-admin.css`, `/ark-admin/asset/ark-admin.js` |

Restricted to the administrator account (`AdminUser:Username`, or a principal carrying an `admin`
claim). Override a page by placing your own `Views/Admin/Manage.cshtml` in the host. The v1 console at
`/oauth/{tenant}/v1/server/{client_id}/manage` is still served but no longer developed.

## Seeded on first run

- Tenant `{TenantId}` with an in-process RSA signing key (`kid == tenant_id`, `RS256`).
- Admin console client `{TenantId}_client` (public, PKCE, `authorization_code`+`refresh_token`,
  redirect URIs include `/signin-oidc` and the v1 callback).
- Machine client `{TenantId}_machine` (`client_credentials`, `client_secret_post`, scope
  `client.register`) — **without a secret**; regenerate one before use.
- The default scope catalogue, identity claims, the admin user, and a default service account.

## Public types (for reference)

- `Protocol.ArkOidcOptions`, `Protocol.ArkCors.PolicyName = "ark-oidc-browser"`,
  `Protocol.ArkOidcEndpoints` (issuer/endpoint builder).
- `ArkAuthServerConfig`, `ArkAdminUserConfig`, `ArkAdminConsoleConfig`, `ArkEmailConfig`,
  `ArkUserPasswordMode`.
- `ArkProvisioning` (DI-registered), `ArkProvisionRequest`/`ArkProvisionResult`/`ArkProvisionException`.
- `ArkActivationLevel`, `ArkAccountInactiveException` (`FriendlyMessage`).
- `EmbeddedResourceUnpacker` (Development asset unpacking).
