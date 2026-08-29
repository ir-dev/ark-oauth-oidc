# Ark.oAuth.Client

The OAuth 2.1 / OpenID Connect **client** for ASP.NET Core applications. One call in `Program.cs`,
two required settings, and `[Authorize]` works.

It configures ASP.NET Core's own OpenID Connect and cookie handlers rather than hand-rolling the
protocol, so PKCE, `state`, `nonce`, JWKS rollover and token refresh all come from the framework.

Built for [`Ark.oAuth.Oidc`](https://www.nuget.org/packages/Ark.oAuth.Oidc), but because it is the
stock handler underneath, changing `Authority` and `ClientId` is enough to point the same
application at Entra ID, Okta, Auth0 or Keycloak.

## Install

```bash
dotnet add package Ark.oAuth.Client
```

## Program.cs

```csharp
using Ark.oAuth;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddArkOidcClient(builder.Configuration);
builder.Services.AddControllersWithViews();

var app = builder.Build();

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();          // MUST precede the next two
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(name: "default", pattern: "{controller=Home}/{action=Index}/{id?}");
app.Run();
```

## appsettings.json

`Authority` and `ClientId` are the only required keys — every endpoint is read from the provider's
discovery document.

```jsonc
{
  "ark_oauth_client": {
    "Authority": "https://idp.example.com/my_idp",  // the issuer
    "ClientId": "my-app",
    "ClientSecret": null,                           // null = public client + PKCE
    "Scopes": [ "openid", "profile", "email", "offline_access" ],
    "CallbackPath": "/signin-oidc",
    "SignedOutCallbackPath": "/signout-callback-oidc",
    "SignedOutRedirectUri": "/",
    "AuthErrorPath": "/",                           // failed callbacks land here with ?auth_error=...
    "RequireHttpsMetadata": true,
    "CookieName": "my_app_auth",
    "RoleClaimType": "role",                        // ark_claims from the access token map onto this
    "ExpireMins": 480
  }
}
```

## Using the result

```csharp
[Authorize]
public IActionResult Secure() => View();

// Ark authorization claims (ark_claims) are projected as roles, so policies work directly
[Authorize(Roles = "billing.admin")]
public IActionResult Billing() => View();
```

Reading the access token — always per call, never cached; the cookie handler refreshes it
underneath you:

```csharp
var accessToken = await HttpContext.GetArkAccessTokenAsync();

var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/things");
await request.WithArkTokenAsync(HttpContext);
```

## Protecting an API

```csharp
builder.Services
    .AddAuthentication()
    .AddArkOidcApi(arkConfig);
```

## The flows outside interactive sign-in

`AddArkOidcClient` also registers three services. All three work off the provider's discovery
document, so they need the issuer and nothing else.

| Service | For |
|---|---|
| `ArkSetupProbe` | Pairs local configuration against the provider's live metadata and returns `ArkSetupModel` — issuer mismatch, unregistered scopes, the exact redirect URI this app will send. Render it and a registration mistake reads as a sentence instead of `invalid_client`. |
| `ArkClientCredentials` | The client credentials grant. `GetTokenAsync` caches until shortly before expiry; `RequestTokenAsync` forces a live exchange. |
| `ArkRegistration` | Dynamic client registration (RFC 7591) and management (RFC 7592). |

```csharp
var model  = await setup.ProbeAsync(HttpContext);
var token  = await credentials.GetTokenAsync(clientId, secret, new[] { "reports.read" });
var client = await registration.RegisterAsync(metadata, token.AccessToken);
```

## Registering the application

Three things have to line up on the provider, not one:

1. Create the client.
2. Register **both** redirect URIs — `{host}/signin-oidc` and `{host}/signout-callback-oidc` —
   matched byte for byte. No wildcards, no prefix matching.
3. Grant each user access to that client. Without the mapping, sign-in fails with a message that
   looks like a wrong password.

Scopes on a client record are a whitelist: an unregistered scope is rejected, not dropped.
`offline_access` is what produces a refresh token. Never add a controller action at `CallbackPath` —
it shadows the handler. Sign out of both `ArkOidcClient.CookieScheme` and `ArkOidcClient.OidcScheme`,
or the provider session survives and the next sign-in is silent.

Optionally, register a `backchannel_logout_uri` as well. Ark.oAuth.Oidc 2.0.3 and later POSTs a
signed `logout_token` there when a session this application took part in ends elsewhere — someone
signing out at another application, or an account being deactivated. This package does not host
that endpoint for you: write an action that validates the posted token against the provider's JWKS
(`typ: logout+jwt`, matching `iss` and `aud`, an `events` claim, never a `nonce`), signs out the
session it names, and answers 200 or 204. Register nothing and the application is simply never
notified, which is how it behaved before.

## Legacy flow

`ark_oauth_client:UseLegacyFlow` keeps the original cookie/bearer middleware for deployments
migrating off the v1 endpoints. It does not validate `state` or `nonce` — treat it as a migration
aid, not a supported configuration.

## Documentation

A complete, runnable client application and the full walkthrough are in the repository:
<https://github.com/ir-dev/ark-oauth-oidc>

## License

MIT
