<!--
  TROUBLESHOOTING.md — Ark.oAuth.Client
  Audience: AI coding agents diagnosing failures. Every cause/fix is derived from this directory's
  source and the README. Do not invent error strings.
-->

# Ark.oAuth.Client — troubleshooting matrix

Diagnose against the actual behaviour of this package. The fastest general diagnostic is a
`ArkSetupProbe.ProbeAsync(HttpContext)` page (see [`AI-RECIPES.md`](AI-RECIPES.md) recipe 8).

## Sign-in / configuration

| Symptom | Likely cause | Diagnosis | Correct solution | Avoid |
|---|---|---|---|---|
| Sign-in says the password is wrong for a correct password | The user is not mapped to this client on the provider | Provisioning: is there a user→client access mapping? | Map the user to the client (provider admin console / provisioning API) | Resetting the user's password — it is not the problem |
| `invalid_client` on the authorize/token request | Wrong `ClientId`, or wrong `Authority`/tenant | `ProbeAsync` → `IssuerMismatch`; compare `ClientId` to the provider | Fix `Authority` (`{BaseUrl}/{TenantId}`) and `ClientId` | Guessing endpoints — they come from discovery |
| `redirect_uri does not match a registered value` | Redirect URI not registered byte-for-byte, or only one of the two registered | `ProbeAsync` → `RedirectUri` / `PostLogoutRedirectUri`; compare to the provider | Register **both** `/signin-oidc` and `/signout-callback-oidc` exactly (scheme, host, port, path) | Wildcards / prefix matching — not supported |
| `invalid_scope` | Requesting a scope not whitelisted on the client record | `ProbeAsync` → `UnsupportedScopes` | Add the scope to the client on the provider, or remove it from `Scopes` | Assuming unknown scopes are silently dropped — they are rejected |
| "Cannot redirect to the authorization endpoint, the configuration may be missing or invalid" | Mixed `Microsoft.IdentityModel.*` versions (Protocols 7.x + Tokens 8.x) | `dotnet list package --include-transitive \| grep IdentityModel` | Pin the whole graph to `8.8.0` (as the package does) | Letting a transitive dep pull IdentityModel 7.x |
| Sign-in redirect throws an exception page | Provider unreachable / wrong port / untrusted dev cert | `ProbeAsync` → `DiscoveryError` names which | Fix the provider URL/cert; for local http set `RequireHttpsMetadata=false` | Leaving `RequireHttpsMetadata=false` in production |
| The callback path 404s or loops | A controller action/route was added at `CallbackPath` | Search for a route at `/signin-oidc` | Remove the route — the OIDC handler owns that path | Mapping anything at the callback path |
| Failed callback shows a raw error instead of a page | No `AuthErrorPath` handling | Failed callbacks redirect to `AuthErrorPath` with `?auth_error=…` | Read `?auth_error` on the `AuthErrorPath` page | Assuming an exception is thrown |

## Tokens / downstream calls

| Symptom | Likely cause | Diagnosis | Correct solution | Avoid |
|---|---|---|---|---|
| Downstream API returns 401 after a while | The access token was cached and went stale | Are you storing the token anywhere? | Read it per request: `await HttpContext.GetArkAccessTokenAsync()` / `WithArkTokenAsync` | Caching the token in a field/`static` |
| User is bounced to the IdP mid-session | No refresh token, so the session dies with the first access token | Is `offline_access` in `Scopes` and whitelisted? | Add `offline_access`; the cookie handler then refreshes silently | Extending cookie lifetime instead of enabling refresh |
| Refresh silently signs the user out | Refresh token revoked, expired, or replayed (family revoked) | Server logs; token replay revokes the family | Expected — the user re-signs-in. Investigate replay if frequent | Retrying refresh in a loop |
| API rejects the token (audience) | `AddArkOidcApi` validating an audience you never set | Check `ArkAuthConfig.Audience` | Audience is validated **only** if `Audience` is set — leave it null or set it correctly | Setting `Audience` to a value the token does not carry |

## Sign-out

| Symptom | Likely cause | Diagnosis | Correct solution | Avoid |
|---|---|---|---|---|
| Next sign-in is silent / no credentials prompt | Only the local cookie was dropped; the provider session survives | Did you sign out of both schemes? | `HttpContext.ArkSignOutEverywhereAsync()`, or `SignOutAsync` on **both** `CookieScheme` and `OidcScheme` | Signing out of the cookie scheme only |
| `/ark/switch-user` or `/ark/sign-out` returns 405/400 | Not a POST, or cross-site | Method + `Sec-Fetch-Site`/`Origin` | POST from the same origin | GET links to these endpoints |

## Shared browser / wrong account

| Symptom | Likely cause | Diagnosis | Correct solution | Avoid |
|---|---|---|---|---|
| Second user on a shared browser is signed in as the first and sees "no access" with no way out | SSO answered the authorize request from the first person's provider session | Is `AccountSwitch:RequireArkClaims` on? | Set `RequireArkClaims=true` — the callback is refused, and `/ark/no-access` offers `prompt=login` | Telling users to clear cookies |
| `[Authorize]` 403s render as a 404 | Framework default `/Account/AccessDenied` does not exist | — | Leave `AccountSwitch` at defaults — the built-in page serves 403s too | Creating a bespoke `/Account/AccessDenied` just for this |
| Custom `OnEvaluateAccess` never runs | `RequireArkClaims` is off | It runs only when `RequireArkClaims=true` | Turn `RequireArkClaims` on | Expecting the event to gate access on its own |
| The denied page can't name the account | No Data Protection configured | The name comes from a protected cookie | Configure ASP.NET Core Data Protection (persisted keys) | Relying on the name in a stateless/multi-instance deploy without shared keys |

## Machine-to-machine / registration

| Symptom | Likely cause | Diagnosis | Correct solution | Avoid |
|---|---|---|---|---|
| `ArkTokenResult.Succeeded == false`, `invalid_client` | Wrong client id/secret, or client not confidential / wrong auth method | `RequestTokenAsync` → `RawResponse` | Register the machine client with a secret and matching `token_endpoint_auth_method` | Using a public client for client credentials |
| Client-credentials call is slow / rate-limited | `RequestTokenAsync` called per request | — | Use `GetTokenAsync` (cached, renewed 60s before expiry) | Requesting a token on every outbound call |
| `registration_not_supported` from `ArkRegistration` | Provider does not advertise a `registration_endpoint` | `ProbeAsync` → `SupportsDynamicRegistration` | Enable `ark_oauth_server:Oidc:EnableDynamicRegistration` on the server | Guessing the registration URL |
| Registered a client but sign-in still fails | Registration ≠ user access | — | Map a user to the new client | Assuming registration grants access |
| Lost the `registration_access_token` | It is shown once | — | Re-create the registration (an operator with DB access must clean up the old one) | Expecting to re-derive it |

## Startup / DI

| Symptom | Likely cause | Diagnosis | Correct solution | Avoid |
|---|---|---|---|---|
| `ApplicationException: set 'Authority' …` at startup | No `Authority`/`AuthServerUrl`+`TenantId` | `ResolveAuthority()` returned empty | Set `ark_oauth_client:Authority` | Leaving the section empty |
| `[Authorize]` never challenges | `UseAuthentication`/`UseAuthorization` missing or before `UseRouting` | Middleware order | `UseRouting()` → `UseAuthentication()` → `UseAuthorization()` | Ordering auth before routing |
| Behaviour matches the old insecure client | `UseLegacyFlow=true` | Check the config | Remove it — the standard flow validates `state`/`nonce` | Shipping `UseLegacyFlow` |
