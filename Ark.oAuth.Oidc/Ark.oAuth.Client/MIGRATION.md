<!--
  MIGRATION.md — Ark.oAuth.Client
  Audience: AI coding agents planning an upgrade. Facts from the .csproj release notes and source.
-->

# Ark.oAuth.Client — versions, compatibility & migration

## Current version

- **`2.0.9`** (`<Version>` in `Ark.oAuth.Client.csproj`), `net9.0`.
- Ships in lockstep with **`Ark.oAuth.Oidc 2.0.9`** — the client and server packages deliberately
  carry the **same version number**. Upgrade both together.
- The Python (`ark-oauth-client` / PyPI) and Node (`ark-oauth-client` / npm) clients are ports of
  this one and carry the same version; an integration translates almost line-for-line.

> **Version-number vs changelog note (flagged discrepancy):** the `PackageReleaseNotes` in the
> `.csproj` are written under the heading of the version a feature *landed in*. The client's newest
> heading is **"2.1.0 — account switching on a shared browser"**, but the package's actual
> `<Version>` is **`2.0.9`**. The account-switching feature described under that heading **is present
> and compiled** in the 2.0.9 assembly (`Access/ArkAccountSwitch.cs` etc.). Treat the shipped
> assembly as the source of truth: the feature exists in 2.0.9 and is **off by default**.

## Framework & dependency compatibility

| Requirement | Value |
|---|---|
| Target framework | `net9.0` (host app must be ASP.NET Core, `Microsoft.NET.Sdk.Web`) |
| OIDC handler | `Microsoft.AspNetCore.Authentication.OpenIdConnect` |
| Bearer | `Microsoft.AspNetCore.Authentication.JwtBearer` |
| IdentityModel graph | **All on `8.8.0`** — `JsonWebTokens`, `Protocols.OpenIdConnect`, `System.IdentityModel.Tokens.Jwt` |

**Hard rule:** keep the `Microsoft.IdentityModel.*` graph on one major/version. A mixed graph
(Protocols 7.x with Tokens 8.x) restores and compiles, then fails at the **first challenge** with
"Cannot redirect to the authorization endpoint, the configuration may be missing or invalid." The
package pins these as direct references so consumers inherit the aligned graph — do not override them
downward.

## Changelog (from the .csproj, newest first)

- **"2.1.0" — account switching on a shared browser** (present in 2.0.9): `AccountSwitch:RequireArkClaims`
  moves the entitlement check to the callback; a built-in `/ark/no-access` page offers "Sign in as a
  different user" (`prompt=login`) and replaces the framework's `/Account/AccessDenied` for `[Authorize]`
  403s; `HttpContext.ArkSwitchUserAsync`/`ArkSignOutEverywhereAsync`/`ArkSignOutLocallyAsync`;
  `ArkChallengeProperties.SwitchUser`; the `AddArkOidcClient(configuration, options)` overload with
  `ArkClientEvents` (`OnEvaluateAccess`, `OnAccessDenied`). **All off/unchanged by default** — an
  upgrade changes nothing except that a 403 now reaches an explanation instead of a 404.
- **2.0.3** — version alignment with `Ark.oAuth.Oidc 2.0.3`. No API change over 2.0.2. Note the server
  added back-channel logout; this package does **not** host the receiving endpoint (see below).
- **2.0.2 / 2.0.1** — version alignment + packaging fixes (icon + readme at the `.nupkg` root, SPDX
  license, symbol package). No API change.
- **2.0.0 — the standards release.** `AddArkOidcClient` now configures ASP.NET Core's OIDC + cookie
  handlers against discovery (real PKCE/`state`/`nonce`/JWKS rollover/silent refresh). `Authority` +
  `ClientId` are the only required settings. Added `AddArkOidcApi`, `ark_claims`→role projection,
  `GetArkAccessTokenAsync`/`WithArkTokenAsync`, and the `ArkSetupProbe`/`ArkClientCredentials`/
  `ArkRegistration` services. **Breaking:** the standard flow is the default; `UseLegacyFlow=true`
  keeps the old middleware while migrating.

## Migrating from the v1 client (pasted `rsaPublic` key)

The v1 client validated neither `state` nor `nonce`, used a custom callback route, and pasted a
base64 RSA public key into config. To migrate:

1. **Upgrade the package** to 2.x.
2. **(Optional, day one)** set `"ark_oauth_client": { "UseLegacyFlow": true }` to keep the old
   callback routes working while you register the standard ones. This preserves compilation
   (`UseArkOidcClient` still exists) but **does not validate `state`/`nonce`** and derives PKCE
   predictably — a migration aid only.
3. **Register the standard redirect URIs** on the provider: `https://<host>/signin-oidc` and
   `https://<host>/signout-callback-oidc` (byte-for-byte).
4. **Switch to the standard flow:** remove `UseLegacyFlow` (or set `false`). Delete legacy config
   (`RsaPublic`, `Issuer`, `Audience`, `RedirectUri`, `RouteKey`, `tenants`). Keep only `Authority`
   (`{BaseUrl}/{TenantId}`) and `ClientId` (+ `ClientSecret` for confidential clients).
5. **Remove any route at the callback path** and any code that copies a bearer token out of a cookie.
6. **Verify** with an `ArkSetupProbe` page and a real sign-in.

## `UseLegacyFlow` — what it is and is not

- **Is:** a bridge so an existing `Program.cs` compiles and its old callback routes keep working
  during a migration.
- **Is not:** a supported configuration. It skips `state`/`nonce` validation and derives its PKCE
  verifier from a timestamp. Never enable it for new code, and remove it as soon as the standard
  redirect URIs are registered.

## Interop with `Ark.oAuth.Oidc 2.0.3+` back-channel logout

The server can POST a signed `logout_token` to a client's `backchannel_logout_uri`. **This package
does not host that endpoint.** If you want the app's cookie dropped when the IdP session ends
elsewhere, register a `backchannel_logout_uri` and implement the endpoint yourself: validate the
posted token against the provider's JWKS (`typ: logout+jwt`, matching `iss`/`aud`, an `events` claim,
**no** `nonce`), sign out the session it names, and answer `200`/`204`. Register nothing and the app
is simply never notified (its prior behaviour).

## Deprecated / do-not-use

- `Ark.oAuth.Client.ClientController` (v1 callback controller).
- `AuthClientHelper` (legacy onboarding wrapper) — use the provider's provisioning API.
- Legacy `ArkAuthConfig` properties: `RsaPublic`, `Issuer`, `Audience`, `RedirectUri`,
  `RedirectRelative`, `AuthServerUrl`, `RouteKey`, `Domain`, `Suffix`, `tenants`.
