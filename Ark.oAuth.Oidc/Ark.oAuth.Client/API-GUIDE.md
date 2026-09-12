<!--
  API-GUIDE.md — Ark.oAuth.Client
  Audience: AI coding agents needing exact, non-fabricated signatures.
  Every member below is copied from the source in this directory. If a member is not here, do not
  assume it exists — read the .cs file.
-->

# Ark.oAuth.Client — API guide

Exact public API surface (namespace **`Ark.oAuth`**, package `Ark.oAuth.Client` v2.0.9, `net9.0`).
Signatures are verified against the source. Members marked *internal* are listed for understanding
only — do not call them.

## Registration & pipeline extension methods (`ArkExtn`, `ArkOidcClient`)

| Signature | Purpose |
|---|---|
| `void IServiceCollection.AddArkOidcClient(IConfiguration configuration)` | Register the client from the `ark_oauth_client` section. Standard flow by default. |
| `void IServiceCollection.AddArkOidcClient(IConfiguration configuration, Action<ArkClientOptions>? configure)` | As above, plus mutate bound config and attach `ArkClientEvents`. |
| `AuthenticationBuilder IServiceCollection.AddArkOidcInteractive(ArkAuthConfig config)` | Wire the cookie + OIDC handlers directly (advanced). |
| `AuthenticationBuilder IServiceCollection.AddArkOidcInteractive(ArkAuthConfig config, ArkClientEvents? events)` | As above with events. |
| `AuthenticationBuilder AuthenticationBuilder.AddArkOidcApi(ArkAuthConfig config, string scheme = JwtBearerDefaults.AuthenticationScheme)` | Add JWT bearer validation for an API; keys from JWKS. |
| `void IApplicationBuilder.UseArkOidcClient()` | Registers the account endpoints; a no-op for the standard flow otherwise (legacy token middleware only under `UseLegacyFlow`). Optional — the endpoints self-register. |
| `IApplicationBuilder IApplicationBuilder.UseArkAccountEndpoints()` | Manually place the account/switch/sign-out endpoints (idempotent). Only needed if `AccountSwitch:AutoRegisterEndpoints = false`. |

**Constants** (`ArkOidcClient`): `CookieScheme = "ArkCookie"`, `OidcScheme = "ArkOidc"`,
`static readonly string Version` (read off the assembly).

**Middleware order (required):**
```csharp
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
```

## Token accessors (`ArkTokenAccessors` — extensions on `HttpContext` / `HttpRequestMessage`)

| Signature | Returns |
|---|---|
| `Task<string?> HttpContext.GetArkAccessTokenAsync()` | Current access token from the auth cookie. |
| `Task<string?> HttpContext.GetArkIdTokenAsync()` | Current ID token. |
| `Task<string?> HttpContext.GetArkRefreshTokenAsync()` | Current refresh token. |
| `Task<HttpRequestMessage> HttpRequestMessage.WithArkTokenAsync(HttpContext context)` | Attaches `Authorization: Bearer <access token>` and returns the same message. |

> Always call per request. `ArkTokenRefresher` (internal) refreshes the token ~2 minutes before
> expiry via the cookie handler's `OnValidatePrincipal`.

## Configuration POCO (`ArkAuthConfig`, section `ark_oauth_client`)

Standard-flow properties (the ones you set):

| Property | Type | Default | Notes |
|---|---|---|---|
| `Authority` | `string?` | — | **Required.** Issuer `{BaseUrl}/{TenantId}`. Falls back to `AuthServerUrl` + `TenantId`. |
| `ClientId` | `string` | — | **Required.** |
| `ClientSecret` | `string?` | `null` | `null` = public client + PKCE. Set for confidential clients. |
| `Scopes` | `List<string>?` | `openid profile email offline_access` | `offline_access` yields a refresh token. |
| `CallbackPath` | `string?` | `/signin-oidc` | Do not add a route here. |
| `SignedOutCallbackPath` | `string?` | `/signout-callback-oidc` | Register it too. |
| `SignedOutRedirectUri` | `string?` | `/` | |
| `AuthErrorPath` | `string?` | `/` | Failed callbacks redirect here with `?auth_error=…`. |
| `RequireHttpsMetadata` | `bool` | `true` | Only relax for local http dev. |
| `CookieName` | `string?` | `ark_auth` | |
| `RoleClaimType` | `string?` | `role` | `ark_claims` are projected onto this claim type. |
| `ExpireMins` | `int` | `480` | Cookie lifetime. |
| `AccountSwitch` | `ArkAccountSwitchOptions` | see below | Shared-browser recovery. |
| `UseLegacyFlow` | `bool` | `false` | Legacy cookie/bearer middleware. **Migration aid only.** |

**Methods:** `string ResolveAuthority()`, `List<string> ResolveScopes()`.

Legacy-only properties (present for old appsettings; ignore for new code): `Issuer`, `Audience`,
`RsaPublic`, `LogoutUri`, `RedirectUri`, `RedirectRelative`, `AuthServerUrl`, `RouteKey`, `TenantId`,
`Domain`, `Suffix`, `tenants` (`Dictionary<string, ArkCert>`).

## Account switch (`ArkAccountSwitchOptions`, section `ark_oauth_client:AccountSwitch`)

| Property | Type | Default | Notes |
|---|---|---|---|
| `Enabled` | `bool` | `true` | Serve the endpoints. Off still leaves the extension methods usable. |
| `AutoRegisterEndpoints` | `bool` | `true` | Place endpoints in the pipeline automatically. |
| `RequireArkClaims` | `bool` | `false` | **The switch.** Refuse the callback when there are no `ark_claims`. |
| `RequiredClaims` | `List<string>?` | `null` | Narrow the check to at least one of these values. |
| `AccessDeniedPath` | `string` | `/ark/no-access` | |
| `SwitchUserPath` | `string` | `/ark/switch-user` | POST, same-origin. |
| `SignOutPath` | `string` | `/ark/sign-out` | POST, same-origin. |
| `ServeDefaultPage` | `bool` | `true` | Set `false` to render `AccessDeniedPath` yourself. |
| `AppDisplayName` | `string?` | client id | How the page names the app. |
| `ShowSignedInAccount` | `bool` | `true` | Show the currently-signed-in account. |
| `AllowFullSignOut` | `bool` | `true` | Offer "sign out completely". |
| `EndProviderSessionOnSwitch` | `bool` | `false` | `true` = full RP-logout on switch (kiosk). |
| `Prompt` | `string` | `login` | Sent as `prompt` when switching (`select_account` where a picker exists). |
| `HomePath` | `string` | `/` | Return-URL fallback (kept local). |
| `SupportUrl` / `SupportEmail` | `string?` | `null` | "Request access" link. |

## Account operations (extensions on `HttpContext`, `ArkAccountExtensions`)

| Signature | Effect |
|---|---|
| `Task HttpContext.ArkSwitchUserAsync(string? returnUrl = null, string? loginHint = null)` | Drop the local cookie and challenge with `prompt=login` (or full RP-logout if `EndProviderSessionOnSwitch`). |
| `Task HttpContext.ArkSignOutEverywhereAsync(string? returnUrl = null)` | RP-initiated logout: local session + provider session. |
| `Task HttpContext.ArkSignOutLocallyAsync(string? returnUrl = null)` | End the local session only. |
| `ArkDeniedAccount? HttpContext.ArkDeniedAccount()` | The last refused account (`subject`, `email`, `name`, `reason`, `return_url`) or `null`. |

## Challenge properties (`ArkChallengeProperties`)

| Signature | Purpose |
|---|---|
| `AuthenticationProperties SwitchUser(string? returnUrl = null, string? loginHint = null, string prompt = "login")` | Build props that force `prompt=login`. Use with `Challenge(props, ArkOidcClient.OidcScheme)`. |
| `AuthenticationProperties SelectAccount(string? returnUrl = null)` | `prompt=select_account`. |
| `AuthenticationProperties AuthenticationProperties.WithArkPrompt(string prompt)` | Fluent prompt. |
| `AuthenticationProperties AuthenticationProperties.WithArkLoginHint(string loginHint)` | Fluent `login_hint`. |
| `AuthenticationProperties AuthenticationProperties.WithArkMaxAge(int seconds)` | Fluent `max_age` (0 = re-auth now). |

Constants: `PromptItem = "ark:prompt"`, `LoginHintItem = "ark:login_hint"`, `MaxAgeItem = "ark:max_age"`.

## Events & options (`ArkClientEvents`, `ArkClientOptions`)

- `ArkClientOptions.Config` → the mutable bound `ArkAuthConfig`.
- `ArkClientOptions.Events` → `ArkClientEvents`.
- `ArkClientEvents.OnEvaluateAccess : Func<ArkAccessEvaluationContext, Task<bool>>?` — return `true`
  to allow sign-in. Runs **only** when `RequireArkClaims` is on. Replaces the configured check
  (read `AllowedByConfiguration` to combine).
- `ArkClientEvents.OnAccessDenied : Func<ArkAccessDeniedContext, Task>?` — log / raise a ticket /
  write your own response (set `ArkAccessDeniedContext.Handled = true`).
- `ArkAccessEvaluationContext`: `HttpContext`, `Principal`, `ArkClaims`, `AllowedByConfiguration`.
- `ArkAccessDeniedContext`: `HttpContext`, `Reason`, `Subject`, `Email`, `Name`, `ArkClaims`,
  `ReturnUrl`, `Handled`.
- `ArkAccessDeniedReasons`: `NoAppAccess = "no_app_access"`, `Forbidden = "forbidden"`.

## Setup diagnostics (`ArkSetupProbe` — DI singleton)

| Signature | Returns |
|---|---|
| `Task<ArkSetupModel> ProbeAsync(HttpContext context, CancellationToken = default)` | Local config + provider metadata + session state. |
| `Task<ArkProviderMetadata> ReadMetadataAsync(string? authority = null, CancellationToken = default)` | Parsed discovery doc. **Throws** on failure. |
| `static string DiscoveryUrl(string authority)` | `{authority}/.well-known/openid-configuration`. |

**`ArkSetupModel`** signals: `DiscoveryOk`, `DiscoveryError`, `IssuerMismatch`, `UnsupportedScopes`
(`List<string>`), `RedirectUri`, `PostLogoutRedirectUri`, `SupportsDynamicRegistration`,
`SupportsClientCredentials`, `IsAuthenticated`, `SignedInAs`, `TenantId`, `AdminConsoleUrl`,
`IntegrationPageUrl`, plus the provider fields (`Issuer`, `TokenEndpoint`, …).

**`ArkProviderMetadata`**: `Issuer`, `AuthorizationEndpoint`, `TokenEndpoint`, `UserInfoEndpoint`,
`EndSessionEndpoint`, `JwksUri`, `RegistrationEndpoint`, `DeviceAuthorizationEndpoint`,
`PushedAuthorizationRequestEndpoint`, `IntrospectionEndpoint`, `RevocationEndpoint`,
`ScopesSupported`, `GrantTypesSupported`, `ResponseTypesSupported`, `ResponseModesSupported`,
`CodeChallengeMethodsSupported`, `TokenEndpointAuthMethodsSupported`, `ClaimsSupported`, `Raw`.

## Client credentials (`ArkClientCredentials` — DI singleton)

| Signature | Notes |
|---|---|
| `Task<ArkTokenResult> GetTokenAsync(string clientId, string clientSecret, IEnumerable<string>? scopes = null, string? authority = null, CancellationToken = default)` | **Use this in production.** Cached per `clientId+scope`, renewed 60s before expiry. |
| `Task<ArkTokenResult> RequestTokenAsync(...same...)` | Bypasses the cache; returns the full exchange for diagnostics. |
| `static void ClearCache()` | Clears the token cache. |

Authenticates with `client_secret_post`. **`ArkTokenResult`**: `AccessToken`, `TokenType`, `Scope`,
`ExpiresIn`, `ExpiresAt`, `TokenEndpoint`, `StatusCode`, `Error`, `ErrorDescription`, `RequestForm`
(secret redacted), `RawResponse`, `bool Succeeded`, `AccessTokenPayload` (decoded, display only).

## Dynamic registration (`ArkRegistration` — DI singleton)

| Signature | RFC |
|---|---|
| `Task<ArkRegistrationResult> RegisterAsync(JsonObject metadata, string? initialAccessToken = null, string? authority = null, CancellationToken = default)` | 7591 §3.1 |
| `Task<ArkRegistrationResult> ReadAsync(string clientId, string registrationAccessToken, string? authority = null, CancellationToken = default)` | 7592 §2.1 |
| `Task<ArkRegistrationResult> DeleteAsync(string clientId, string registrationAccessToken, string? authority = null, CancellationToken = default)` | 7592 §2.3 |

**`ArkRegistrationResult`**: `ClientId`, `ClientName`, `ClientSecret` (**once**),
`RegistrationAccessToken` (**once**, only credential that can read/update/delete the registration),
`RegistrationClientUri`, `Endpoint`, `StatusCode`, `Error`, `ErrorDescription`, `RequestBody`,
`RawResponse`, `bool Succeeded`. Error `registration_not_supported` = provider has no
`registration_endpoint`.

## Display helpers (`ArkJwt`, `ArkJson`) — not security boundaries

- `string? ArkJwt.DecodePayload(string? jwt)` — decode a JWT payload for a page/log. Does **not**
  validate. A client must not reason about its own access token's contents.
- `string ArkJson.Prettify(string? json)` — indent JSON, or return input unchanged if not JSON.

## Legacy / not for new code

- `ArkAuthContext` (scoped) — bridges the legacy cookie identity; under the standard flow it reads
  the authenticated principal. `client_id`, `tenant_id`, `user_id`, `ip`, `user_info` (`AUserInfo`).
- `PkceHelper.GenerateCodeVerifier()` / `GenerateCodeChallenge(verifier)` — used internally by the
  legacy path.
- `Ark.oAuth.Client.ClientController` (namespace `Ark.oAuth.Client`) — v1 callback controller at
  `/oauth/{tenant}/v1/client/{client}/...`. Do not wire new apps to it.
- Cookie helpers `StoreCookie`/`ReadCookie`/`DeleteCookie`/`ArkUser`, route helpers
  `ReadRoute`/`IsApi` on `HttpRequest`/`HttpResponse`.
- `AuthClientHelper` — legacy onboarding HTTP wrapper (`OnboardUser`, `OnboardCustomer`); superseded
  by the provider's provisioning API.
