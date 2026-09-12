<!--
  AI-PROMPT.md — Ark.oAuth.Client
  Audience: AI coding agents generating ASP.NET Core integration code.
  Source of truth: the C# in this directory. Do not add APIs that are not listed here.
-->

# Ark.oAuth.Client — AI coding instructions

Compact, source-verified instructions for an AI coding agent integrating the **`Ark.oAuth.Client`**
NuGet package. Everything here is validated against the source in this directory. If you need a
task-oriented walkthrough see [`AI-RECIPES.md`](AI-RECIPES.md); for the full API surface see
[`API-GUIDE.md`](API-GUIDE.md); for failures see [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md).

## 1. Library identity

| | |
|---|---|
| **Package** | `Ark.oAuth.Client` (nuget.org) |
| **Current version** | `2.0.9` (moves in lockstep with `Ark.oAuth.Oidc`) |
| **Root namespace** | `Ark.oAuth` — **not** `Ark.oAuth.Client`. `using Ark.oAuth;` |
| **Target framework** | `net9.0` |
| **Purpose** | Turns an ASP.NET Core app into an OAuth 2.1 / OIDC **relying party** (client). One call in `Program.cs` + two settings and `[Authorize]` works. |
| **Problem solved** | Replaces hand-rolled OAuth flows and the v1 "paste an `rsaPublic` key" client that validated neither `state` nor `nonce`. |
| **How it works** | A thin configuration layer over ASP.NET Core's **own** OpenID Connect + cookie handlers. PKCE, `state`, `nonce`, JWKS rollover and silent token refresh come from the framework, not from this package. |
| **Built for** | `Ark.oAuth.Oidc`, but works against any compliant provider (Entra ID, Okta, Auth0, Keycloak) by changing `Authority`. |
| **Config section** | `ark_oauth_client` |

**Key dependencies** (pinned, must stay on one `Microsoft.IdentityModel.*` major — see anti-patterns):
`Microsoft.AspNetCore.Authentication.OpenIdConnect`, `Microsoft.AspNetCore.Authentication.JwtBearer`,
`Microsoft.IdentityModel.JsonWebTokens 8.8.0`, `Microsoft.IdentityModel.Protocols.OpenIdConnect 8.8.0`,
`System.IdentityModel.Tokens.Jwt 8.8.0`, `ark.net.util`.

## 2. AI usage instructions

```text
When using Ark.oAuth.Client:
1. Prefer the library's public APIs over custom OAuth/OIDC code. Never hand-roll the flow.
2. The entire integration is: AddArkOidcClient(configuration) in ConfigureServices, then
   UseAuthentication()/UseAuthorization() after UseRouting(). Do not add token middleware.
3. Configure via the "ark_oauth_client" section. Only Authority and ClientId are required;
   every endpoint and signing key is discovered from /.well-known/openid-configuration.
4. Do NOT invent APIs, config keys, schemes, or overloads. If unsure, read the source in this
   directory (ArkExtn.cs, ArkOidcClient.cs, Access/*, Flows/*, Diagnostics/*).
5. Read the access token per request with HttpContext.GetArkAccessTokenAsync(); never cache it.
   The cookie handler refreshes it underneath you (ArkTokenRefresher).
6. Ark authorization claims arrive as `ark_claims` and are projected onto the principal as role
   claims (RoleClaimType, default "role"). Author policies against roles, not raw scopes.
7. Never add a controller action/route at CallbackPath (/signin-oidc) — it shadows the handler.
8. Sign out of BOTH schemes (ArkOidcClient.CookieScheme and ArkOidcClient.OidcScheme), or the
   provider session survives and the next sign-in is silent.
9. Do not enable UseLegacyFlow for new code — it does not validate state/nonce (migration aid only).
10. Preserve existing app architecture; this package only adds authentication wiring.
```

## 3. Capability map

```text
Interactive sign-in (authorization code + PKCE)
 ├── Purpose        Sign a browser user in and issue an encrypted auth cookie
 ├── Namespace      Ark.oAuth
 ├── Entry point    IServiceCollection.AddArkOidcClient(IConfiguration[, Action<ArkClientOptions>])
 ├── Under the hood ArkOidcClient.AddArkOidcInteractive -> AddCookie + AddOpenIdConnect
 ├── Config         ark_oauth_client: Authority, ClientId, ClientSecret?, Scopes, CallbackPath,
 │                  SignedOutCallbackPath, SignedOutRedirectUri, AuthErrorPath, CookieName,
 │                  RoleClaimType, RequireHttpsMetadata, ExpireMins
 ├── Schemes        ArkOidcClient.CookieScheme="ArkCookie", ArkOidcClient.OidcScheme="ArkOidc"
 ├── Output         Authenticated ClaimsPrincipal; [Authorize] works; ark_claims -> role claims
 ├── Typical usage  [Authorize] / [Authorize(Roles="billing.admin")]
 └── Anti-patterns  Route at CallbackPath; caching the access token; hand-rolled PKCE

Token access
 ├── Purpose        Get the current tokens the OIDC handler stored in the cookie
 ├── Class          ArkTokenAccessors (extension methods on HttpContext / HttpRequestMessage)
 ├── Methods        GetArkAccessTokenAsync(), GetArkIdTokenAsync(), GetArkRefreshTokenAsync(),
 │                  HttpRequestMessage.WithArkTokenAsync(HttpContext)
 ├── Output         Task<string?> (token) / the same HttpRequestMessage with a Bearer header
 └── Anti-patterns  Caching the token in a field; reading it once at startup

API protection (resource server / bearer)
 ├── Purpose        Validate incoming JWT access tokens on an API
 ├── Entry point    AuthenticationBuilder.AddArkOidcApi(ArkAuthConfig[, scheme])
 ├── Config         Authority (issuer), Audience (optional; validated only if set)
 ├── Keys           From the provider's JWKS, not a configured public key
 └── Anti-patterns  Statically configured signing keys; validating audience you never set

Account switch / shared-browser recovery
 ├── Purpose        Recover from SSO signing the wrong person in on a shared browser
 ├── Namespace      Ark.oAuth
 ├── Config         ark_oauth_client:AccountSwitch (ArkAccountSwitchOptions)
 ├── Key setting    RequireArkClaims (default false) — moves the entitlement check to the callback
 ├── Endpoints      Self-registering: /ark/no-access, /ark/switch-user, /ark/sign-out
 ├── Methods        HttpContext.ArkSwitchUserAsync/ArkSignOutEverywhereAsync/ArkSignOutLocallyAsync,
 │                  ArkChallengeProperties.SwitchUser/SelectAccount, HttpContext.ArkDeniedAccount()
 ├── Events         ArkClientEvents.OnEvaluateAccess, OnAccessDenied (via the options overload)
 └── Anti-patterns  Building your own "wrong account" page from scratch; open-redirect return URLs

Setup diagnostics
 ├── Purpose        Compare local config against the provider's live metadata
 ├── Service        ArkSetupProbe (DI singleton) -> ArkSetupModel / ArkProviderMetadata
 ├── Methods        ProbeAsync(HttpContext), ReadMetadataAsync(authority?), DiscoveryUrl(authority)
 ├── Signals        IssuerMismatch, UnsupportedScopes, RedirectUri, SupportsDynamicRegistration
 └── Use            Render on a /setup page to turn "invalid_client" into a readable sentence

Client credentials grant (machine-to-machine)
 ├── Purpose        A service authenticating as itself (no user, no browser)
 ├── Service        ArkClientCredentials (DI singleton) -> ArkTokenResult
 ├── Methods        GetTokenAsync(clientId, secret, scopes?) [cached], RequestTokenAsync(...) [live]
 ├── Caching        Per clientId+scope, renewed 60s before expiry; static ClearCache()
 └── Anti-patterns  Using it to act on behalf of a signed-in user; calling RequestTokenAsync per request

Dynamic client registration (RFC 7591 / 7592)
 ├── Purpose        Register / read / delete a client programmatically
 ├── Service        ArkRegistration (DI singleton) -> ArkRegistrationResult
 ├── Methods        RegisterAsync(JsonObject, initialAccessToken?), ReadAsync(id, rat), DeleteAsync(id, rat)
 ├── Note           registration_access_token & client_secret are returned ONCE
 └── Anti-patterns  Discarding the registration_access_token; assuming registration == user access
```

## 4. API decision guide

```text
Need a browser user signed in?                 -> AddArkOidcClient(configuration); [Authorize]
Need role-based authorization?                 -> [Authorize(Roles="<ark_claim>")] (ark_claims map to roles)
Need to call a downstream API as the user?     -> await request.WithArkTokenAsync(HttpContext)
Need the raw token?                            -> await HttpContext.GetArkAccessTokenAsync()  (per call)
Building an API (resource server)?             -> AddAuthentication().AddArkOidcApi(arkConfig)
Public client (SPA/native/CLI)?                -> leave ClientSecret null (PKCE is automatic)
Confidential client (server-side web app)?     -> set ClientSecret
Machine-to-machine, no user?                   -> ArkClientCredentials.GetTokenAsync(...)
Register a client programmatically?            -> ArkRegistration.RegisterAsync(...)
"invalid_client" / setup unclear?              -> ArkSetupProbe.ProbeAsync(HttpContext) and render it
Shared browser, wrong account, no way out?     -> AccountSwitch.RequireArkClaims = true
Custom entitlement rule (group/licence/db)?    -> AddArkOidcClient(cfg, o => o.Events.OnEvaluateAccess = ...)
Want your own access-denied page?              -> AccessDeniedPath + ServeDefaultPage=false + ArkDeniedAccount()
"Not you?" link in your header?                -> HttpContext.ArkSwitchUserAsync(returnUrl)
Full sign-out (local + provider)?              -> HttpContext.ArkSignOutEverywhereAsync(returnUrl)
Migrating off v1 endpoints, can't move yet?    -> UseLegacyFlow=true (temporary; no state/nonce)

AVOID:
- UseLegacyFlow for anything new.
- Reading/validating the access token's contents in the client app (it is for the API).
- prompt=login omitted when switching accounts — the provider answers from its existing session.
```

## 5. Anti-patterns (do NOT generate)

```text
DO NOT:
- Hand-roll the authorization-code/PKCE/token-refresh flow. AddArkOidcClient configures the
  framework handlers; adding your own middleware duplicates and breaks it.
- Add a controller action or route at CallbackPath (/signin-oidc) or SignedOutCallbackPath — the
  OIDC handler owns those paths; a route shadows it and sign-in fails.
- Cache the access token in a field/singleton. Call GetArkAccessTokenAsync() per request; the
  cookie handler rotates it (ArkTokenRefresher refreshes ~2 min before expiry).
- Mix Microsoft.IdentityModel.* versions. A split graph (Protocols 7.x + Tokens 8.x) compiles and
  restores fine, then dies on the FIRST challenge: "Cannot redirect to the authorization endpoint,
  the configuration may be missing or invalid." Keep the whole graph on 8.8.0.
- Set UseLegacyFlow=true for new apps. It skips state/nonce validation and derives PKCE predictably.
- Sign out of only the cookie scheme. Sign out of BOTH ArkOidcClient.CookieScheme AND OidcScheme
  (or call ArkSignOutEverywhereAsync) or the IdP session survives and re-signs the user in silently.
- Set RequireHttpsMetadata=false anywhere except local http development.
- Request scopes the client record does not whitelist — they are rejected outright, not dropped.
  offline_access is required to get a refresh token.
- Register only one redirect URI. Register BOTH /signin-oidc and /signout-callback-oidc, byte-for-byte.
- Assume a signed-in user is entitled. On a shared browser SSO can sign in the wrong account with a
  valid token and no ark_claims. Use AccountSwitch.RequireArkClaims to refuse at the callback.
- Echo an arbitrary returnUrl. The library keeps return URLs local (LocalOrDefault); do the same.
```

## 6. Version & compatibility

- Target framework `net9.0`; the app must be an ASP.NET Core (`Microsoft.NET.Sdk.Web`) app.
- Current version **2.0.9**; ships alongside `Ark.oAuth.Oidc 2.0.9`.
- **2.0.0** made the standards flow the default (was hand-rolled). `UseLegacyFlow` preserves the old
  cookie/bearer middleware for migration only.
- **Account switching** (the changelog's "2.1.0" heading) is present in 2.0.9 and is **off by default**.
- Full version/migration detail: [`MIGRATION.md`](MIGRATION.md).

## 7. AI context block (inject into a system/developer prompt)

```text
LIBRARY: Ark.oAuth.Client (v2.0.9, net9.0, namespace Ark.oAuth)

PURPOSE:
OAuth 2.1 / OpenID Connect client for ASP.NET Core. Configures the framework's own OIDC + cookie
handlers. One call + Authority + ClientId, then [Authorize] works.

USE WHEN:
- An ASP.NET Core app must sign users in via an Ark (or any OIDC-compliant) provider.
- You need role-based auth from Ark claims, downstream API calls with the user's token, an API
  resource server, machine-to-machine tokens, or programmatic client registration.

DO NOT USE WHEN:
- The app is the identity provider itself (that is Ark.oAuth.Oidc).
- You want to hand-roll OAuth, or the app is not ASP.NET Core.

PRIMARY APIS:
- services.AddArkOidcClient(configuration) [+ Action<ArkClientOptions> overload]
- app.UseAuthentication(); app.UseAuthorization();  (after UseRouting)
- HttpContext.GetArkAccessTokenAsync(); HttpRequestMessage.WithArkTokenAsync(HttpContext)
- AuthenticationBuilder.AddArkOidcApi(arkConfig)   (resource server)
- ArkClientCredentials.GetTokenAsync(id, secret, scopes)   (M2M)
- ArkRegistration.RegisterAsync(metadata, initialAccessToken)   (RFC 7591)
- ArkSetupProbe.ProbeAsync(HttpContext)   (diagnostics)
- HttpContext.ArkSwitchUserAsync / ArkSignOutEverywhereAsync; ArkChallengeProperties.SwitchUser
- Schemes: ArkOidcClient.CookieScheme="ArkCookie", ArkOidcClient.OidcScheme="ArkOidc"

CONFIGURATION ("ark_oauth_client"):
Authority (required, = {BaseUrl}/{TenantId}), ClientId (required), ClientSecret (null = public+PKCE),
Scopes (default openid profile email offline_access), CallbackPath (/signin-oidc),
SignedOutCallbackPath (/signout-callback-oidc), RoleClaimType (role), RequireHttpsMetadata (true),
AccountSwitch:RequireArkClaims (false), UseLegacyFlow (false).

PREFERRED PATTERNS:
Discovery-driven config; per-request token read; ark_claims -> role claims -> [Authorize(Roles=...)];
register both redirect URIs byte-for-byte; sign out of both schemes.

ANTI-PATTERNS:
Hand-rolled flow; route at callback path; cached token; mixed IdentityModel versions; UseLegacyFlow
for new code; unregistered scopes; single redirect URI; trusting a signed-in user without ark_claims.

IMPORTANT CONSTRAINTS:
- Provider maps users to clients explicitly; no mapping => sign-in fails like a wrong password.
- Scopes are a whitelist on the client record; offline_access yields the refresh token.
- Redirect URIs matched byte-for-byte; register sign-in AND sign-out callbacks.
- Keep Microsoft.IdentityModel.* on one version (8.8.0).

ERROR HANDLING:
Failed callbacks redirect to AuthErrorPath?auth_error=... (not an exception page). Use ArkSetupProbe
to diagnose invalid_client/discovery issues. ArkTokenResult/ArkRegistrationResult carry .Succeeded,
.Error, .ErrorDescription and the raw exchange.

PERFORMANCE:
Discovery is cached (30 min). Client-credentials tokens are cached per client+scope, renewed 60s
before expiry. Token refresh is silent, ~2 min before access-token expiry.

EXAMPLE:
  // Program.cs
  builder.Services.AddArkOidcClient(builder.Configuration);
  var app = builder.Build();
  app.UseRouting(); app.UseAuthentication(); app.UseAuthorization();
  // appsettings.json -> "ark_oauth_client": { "Authority": "https://idp/tenant", "ClientId": "app" }
  // Controller:
  [Authorize(Roles = "billing.admin")] public IActionResult Billing() => View();
```
