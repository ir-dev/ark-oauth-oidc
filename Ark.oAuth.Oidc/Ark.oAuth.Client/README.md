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

## Shared browsers: the wrong account, and no way out

Single sign-on is a property of the browser, not of the tab. Once one person signs in to
*client-a*, the provider's session cookie answers the authorize request of every other client in
that browser. So when a second person opens *client-b*, the challenge is satisfied silently by the
first person's session: *client-b* receives a valid token for an account with no mapping to it,
shows "you do not have access to this application", and offers nothing that helps — the sign-in
link goes back to the same session and returns the same answer. The loop ends when somebody knows
to clear cookies.

Two settings break it.

```jsonc
"ark_oauth_client": {
  "AccountSwitch": {
    "RequireArkClaims": true,               // refuse the callback, do not write the cookie
    "AppDisplayName": "Client B"            // how the page names this application
  }
}
```

`RequireArkClaims` moves the entitlement check to the callback, where it belongs. An account with
no `ark_claims` for this client never gets a session here at all — instead of being signed in as
the wrong person and meeting 403 on every page, the user lands on a page that names the account
that is signed in and offers **Sign in as a different user**. That button challenges the provider
with `prompt=login`, the one parameter it must honour by ignoring its session and drawing the
sign-in form (OIDC Core §3.1.2.1), so the person at the keyboard can enter their own credentials.

Nothing needs adding to `Program.cs`: the page and its two POST endpoints register themselves.
Left at its default (`false`), `RequireArkClaims` changes no behaviour — but the page still serves
the 403s that `[Authorize]` produces, in place of the framework's `/Account/AccessDenied`, which
most applications never create.

### From your own pages

The same two operations, for a "Not you?" link in your header or an action of your own:

```csharp
await HttpContext.ArkSwitchUserAsync(returnUrl);        // drop the local cookie, prompt=login
await HttpContext.ArkSignOutEverywhereAsync(returnUrl); // RP-initiated logout, ends the IdP session too
var refused = HttpContext.ArkDeniedAccount();           // who was refused, for your own page
```

Or on any challenge you issue yourself:

```csharp
return Challenge(ArkChallengeProperties.SwitchUser("/", loginHint: "someone@example.com"),
                 ArkOidcClient.OidcScheme);
```

### Everything else it takes

| Setting | Default | |
|---|---|---|
| `Enabled` | `true` | Serve the endpoints. Off still leaves the extension methods usable. |
| `AutoRegisterEndpoints` | `true` | Place them in the pipeline for you. Off to call `UseArkAccountEndpoints()` where you want it. |
| `RequiredClaims` | — | Narrow the check: the user must hold at least one of these values. |
| `AccessDeniedPath` | `/ark/no-access` | Point at your own route, with `ServeDefaultPage: false`, to render it yourself. |
| `SwitchUserPath` / `SignOutPath` | `/ark/switch-user`, `/ark/sign-out` | POST, same-origin. |
| `ShowSignedInAccount` | `true` | Naming the account is what makes the page make sense; off if you would rather not print somebody else's address. |
| `EndProviderSessionOnSwitch` | `false` | `false` re-prompts and leaves the other person's other applications alone. `true` signs them out everywhere — right for a kiosk. |
| `Prompt` | `login` | What the switch sends. `select_account` where the provider has a picker. |
| `SupportUrl` / `SupportEmail` | — | A "request access" link on the page. |

For rules the settings do not cover — a licence lookup, a group claim, your own denial page or an
access-request ticket — use the events overload:

```csharp
builder.Services.AddArkOidcClient(builder.Configuration, o =>
{
    o.Events.OnEvaluateAccess = ctx => Task.FromResult(ctx.ArkClaims.Count > 0 && Licensed(ctx.Principal));
    o.Events.OnAccessDenied  = ctx => { logger.LogWarning("no access: {Email}", ctx.Email); return Task.CompletedTask; };
});
```

Worth knowing: switching accounts is a client-side remedy. The provider still issued a token for
an account that has no mapping to this client — only the client refuses it. Ending that at the
source means the authorization endpoint declining to satisfy an SSO session with no mapping for
the client it is being used against.

## Legacy flow

`ark_oauth_client:UseLegacyFlow` keeps the original cookie/bearer middleware for deployments
migrating off the v1 endpoints. It does not validate `state` or `nonce` — treat it as a migration
aid, not a supported configuration.

## Documentation

A complete, runnable client application and the full walkthrough are in the repository:
<https://github.com/ir-dev/ark-oauth-oidc>

## License

MIT
