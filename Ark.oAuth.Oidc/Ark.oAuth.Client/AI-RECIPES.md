<!--
  AI-RECIPES.md — Ark.oAuth.Client
  Audience: AI coding agents. Each recipe = a reusable prompt + a verified canonical example.
  Every API used below exists in this directory's source. Do not add others.
-->

# Ark.oAuth.Client — AI recipes

Task-oriented prompts and canonical, source-verified examples. Pair with
[`AI-PROMPT.md`](AI-PROMPT.md) (rules) and [`API-GUIDE.md`](API-GUIDE.md) (full API).

Namespace for every snippet: `using Ark.oAuth;` · Config section: `ark_oauth_client` · Version `2.0.9`.

---

## Recipe 1 — Basic interactive sign-in

> **PROMPT:** "Use Ark.oAuth.Client to add OAuth 2.1 / OIDC sign-in to an ASP.NET Core MVC app.
> Configure via the `ark_oauth_client` section with only Authority and ClientId. Register both
> redirect URIs. Do not invent APIs, do not hand-roll the flow, and place the middleware in the
> correct order."

**Program.cs**
```csharp
using Ark.oAuth;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddArkOidcClient(builder.Configuration);   // the whole integration
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

**appsettings.json**
```jsonc
{
  "ark_oauth_client": {
    "Authority": "https://idp.example.com/my_idp",   // issuer = {BaseUrl}/{TenantId}
    "ClientId": "my-app",
    "ClientSecret": null,                             // null => public client + PKCE
    "Scopes": [ "openid", "profile", "email", "offline_access" ]
  }
}
```

**A protected action**
```csharp
[Authorize]
public IActionResult Secure() => View();
```

- **Expected:** unauthenticated requests to `Secure` redirect to the IdP, complete the code+PKCE flow,
  and return with an encrypted auth cookie.
- **Register on the provider:** the client, **both** `https://<host>/signin-oidc` and
  `https://<host>/signout-callback-oidc` (byte-for-byte), and a user→client mapping.
- **Common mistake:** adding a `HomeController` action at `/signin-oidc` — it shadows the handler.

---

## Recipe 2 — Role-based authorization from Ark claims

> **PROMPT:** "Authorize by Ark authorization claim. Ark issues `ark_claims`; the client projects
> them onto the principal as role claims. Author `[Authorize(Roles=...)]` against them."

```csharp
[Authorize(Roles = "billing.admin")]           // "billing.admin" is an ark_claim value
public IActionResult Billing() => View(User.Identity!.Name);
```

- **Expected:** only users whose token carries `ark_claims: billing.admin` reach the action.
- **Note:** the claim type is `RoleClaimType` (default `"role"`). To use a different type set it in
  config and in your policies.
- **Mistake:** authorizing on OAuth *scopes* — Ark authorization is by **claims**, not scopes.

---

## Recipe 3 — Call a downstream API with the user's token

> **PROMPT:** "Call a downstream API on behalf of the signed-in user. Read the access token per
> request (never cache it) and attach it as a Bearer header using the library helper."

```csharp
public class ThingsController(IHttpClientFactory factory) : Controller
{
    [Authorize]
    public async Task<IActionResult> Index()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/things");
        await request.WithArkTokenAsync(HttpContext);          // adds "Authorization: Bearer <token>"

        var http = factory.CreateClient();
        var response = await http.SendAsync(request);
        return Content(await response.Content.ReadAsStringAsync());
    }
}
```

- **Or** the raw token: `var token = await HttpContext.GetArkAccessTokenAsync();`
- **Expected:** the token is always current — the cookie handler refreshes it ~2 min before expiry.
- **Mistake:** storing the token in a field or `static`; it goes stale and the API returns 401.

---

## Recipe 4 — Protect an API (resource server)

> **PROMPT:** "Protect a Web API with bearer JWTs from the Ark provider. Take signing keys from the
> provider's JWKS, not a configured key. Validate audience only if one is configured."

```csharp
using Ark.oAuth;

var arkConfig = builder.Configuration.GetSection("ark_oauth_client").Get<ArkAuthConfig>()!;

builder.Services
    .AddAuthentication()
    .AddArkOidcApi(arkConfig);        // JwtBearer; Authority from config, keys from JWKS

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
```

- **Config:** `Authority` (issuer) required; `Audience` optional — audience is validated **only** if set.
- **Expected:** requests with a valid `at+jwt` access token authenticate; `ark_claims` map to roles.
- **Mistake:** setting a static signing key — `AddArkOidcApi` uses the JWKS and rotates automatically.

---

## Recipe 5 — Shared-browser account switch (the "wrong account" fix)

> **PROMPT:** "On a shared browser, SSO can sign the next person in as the previous one with a valid
> token but no access. Enable the account-switch fix: refuse the callback when there are no
> `ark_claims`, and let the built-in page offer `prompt=login`. It self-registers — no Program.cs
> change."

**appsettings.json**
```jsonc
"ark_oauth_client": {
  "Authority": "https://idp.example.com/my_idp",
  "ClientId": "client-b",
  "AccountSwitch": {
    "RequireArkClaims": true,          // moves the entitlement check to the callback
    "AppDisplayName": "Client B"       // how the page names this app
  }
}
```

- **Expected:** an account with no `ark_claims` for this client never gets a cookie; the user lands on
  `/ark/no-access`, which names the signed-in account and offers **Sign in as a different user**
  (challenges with `prompt=login`).
- **Self-registering endpoints:** `/ark/no-access`, `/ark/switch-user`, `/ark/sign-out`.
- **Left at the default (`false`):** behaviour is unchanged, except the built-in page now also serves
  ordinary `[Authorize]` 403s (which otherwise 404 at the framework's `/Account/AccessDenied`).
- **Kiosk variant:** add `"EndProviderSessionOnSwitch": true` to end the previous user everywhere.

---

## Recipe 6 — Account-switch / sign-out from your own pages

> **PROMPT:** "Add a 'Not you?' link and a full sign-out to my own layout using the library's
> HttpContext extensions. Keep the return URL local."

```csharp
[HttpPost]                                  // POST + same-origin (the library guards its own too)
public async Task<IActionResult> NotYou(string? returnUrl)
{
    await HttpContext.ArkSwitchUserAsync(returnUrl);        // drop local cookie, challenge prompt=login
    return new EmptyResult();
}

[HttpPost]
public async Task SignOut(string? returnUrl)
    => await HttpContext.ArkSignOutEverywhereAsync(returnUrl);   // local + provider (RP-initiated logout)
```

Or on a challenge you issue yourself:
```csharp
return Challenge(
    ArkChallengeProperties.SwitchUser("/", loginHint: "someone@example.com"),
    ArkOidcClient.OidcScheme);
```

- **Also available:** `HttpContext.ArkSignOutLocallyAsync(returnUrl)` (local cookie only).
- **Mistake:** GET endpoints for these — the built-in endpoints require POST from the same origin.

---

## Recipe 7 — Custom entitlement rule + your own denied page

> **PROMPT:** "Decide access with my own rule (a licence lookup / group claim / DB row) and render my
> own access-denied page. Use the options overload with ArkClientEvents and point AccessDeniedPath at
> my route."

```csharp
builder.Services.AddArkOidcClient(builder.Configuration, o =>
{
    o.Config.AccountSwitch.RequireArkClaims = true;      // OnEvaluateAccess runs only when this is on
    o.Config.AccountSwitch.AccessDeniedPath = "/no-access";
    o.Config.AccountSwitch.ServeDefaultPage = false;     // your route renders it

    o.Events.OnEvaluateAccess = ctx =>
        Task.FromResult(ctx.ArkClaims.Count > 0 && Licensed(ctx.Principal));   // true = allow sign-in
    o.Events.OnAccessDenied = ctx =>
    {
        logger.LogWarning("no access: {Email}", ctx.Email);
        return Task.CompletedTask;                        // set ctx.Handled=true if you write the response
    };
});
```

Your page reads who was refused:
```csharp
[HttpGet("/no-access")]
public IActionResult NoAccess()
{
    var refused = HttpContext.ArkDeniedAccount();          // subject/email/name/reason/return_url, or null
    return View(refused);
}
```

- **Semantics:** `OnEvaluateAccess` **replaces** the configured check (read `AllowedByConfiguration`
  to AND them). Returning `false` denies at the callback — no cookie is written.

---

## Recipe 8 — Setup diagnostics page (turn "invalid_client" into a sentence)

> **PROMPT:** "Add a /setup page that compares local config to the provider's live discovery document
> using ArkSetupProbe and shows issuer mismatch, unsupported scopes and the exact redirect URI."

```csharp
public class SetupController(ArkSetupProbe probe) : Controller
{
    [HttpGet("/setup")]
    public async Task<IActionResult> Index()
    {
        ArkSetupModel model = await probe.ProbeAsync(HttpContext);
        // model.DiscoveryOk, model.IssuerMismatch, model.UnsupportedScopes,
        // model.RedirectUri (register this exactly), model.PostLogoutRedirectUri,
        // model.SupportsDynamicRegistration, model.AdminConsoleUrl, model.IntegrationPageUrl
        return View(model);
    }
}
```

- **Expected:** if discovery fails, `model.DiscoveryError` names the reason (wrong port, stopped
  provider, untrusted dev cert) instead of an exception thrown from the sign-in redirect.
- **`probe.ReadMetadataAsync()`** returns `ArkProviderMetadata` (throws on failure — each caller says
  something different about it).

---

## Recipe 9 — Machine-to-machine (client credentials)

> **PROMPT:** "A background worker needs to call an API as itself (no user). Use ArkClientCredentials;
> prefer the cached GetTokenAsync. Register the machine client as confidential with a secret and
> whitelist the scopes."

```csharp
public class ReportWorker(ArkClientCredentials credentials, IHttpClientFactory factory)
{
    public async Task RunAsync()
    {
        ArkTokenResult token = await credentials.GetTokenAsync(
            "my_machine_client", secret, new[] { "reports.read" });   // cached until ~60s before expiry

        if (!token.Succeeded)
            throw new InvalidOperationException($"{token.Error}: {token.ErrorDescription}");

        var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/reports");
        request.Headers.Authorization = new("Bearer", token.AccessToken);
        await factory.CreateClient().SendAsync(request);
    }
}
```

- **Cached vs live:** `GetTokenAsync` caches per `clientId+scope`; `RequestTokenAsync` bypasses the
  cache and returns the full exchange (`RequestForm` with the secret redacted, `RawResponse`) for a
  diagnostics screen. `ArkClientCredentials.ClearCache()` clears it.
- **Never** use client-credentials tokens to act for a signed-in user — they carry the service's
  authority, and nothing downstream can tell the difference.

---

## Recipe 10 — Dynamic client registration (RFC 7591 / 7592)

> **PROMPT:** "Register a client dynamically. Get an initial access token via client credentials
> (needs the `client.register` scope), register, and persist the returned credentials — they are
> shown once."

```csharp
public class Onboarding(ArkClientCredentials creds, ArkRegistration registration)
{
    public async Task<ArkRegistrationResult> RegisterAsync()
    {
        var initial = await creds.GetTokenAsync("my_machine_client", secret, new[] { "client.register" });

        var metadata = new System.Text.Json.Nodes.JsonObject
        {
            ["client_name"] = "New App",
            ["redirect_uris"] = new System.Text.Json.Nodes.JsonArray("https://new.example.com/signin-oidc"),
            ["grant_types"] = new System.Text.Json.Nodes.JsonArray("authorization_code", "refresh_token"),
            ["scopes"] = "openid profile email offline_access"
        };

        var result = await registration.RegisterAsync(metadata, initial.AccessToken);
        // PERSIST NOW — shown once: result.ClientId, result.ClientSecret, result.RegistrationAccessToken
        return result;
    }
}
```

- **`registration_not_supported`** in the result means the provider does not advertise a
  `registration_endpoint` (set `ark_oauth_server:Oidc:EnableDynamicRegistration` on the server).
- **Registration is not authentication:** a user still has to be mapped to the new client to sign in.

---

## Recipe 11 — Confidential (server-side) client

> **PROMPT:** "Configure a confidential client that authenticates with a client secret."

```jsonc
"ark_oauth_client": {
  "Authority": "https://idp.example.com/my_idp",
  "ClientId": "server-app",
  "ClientSecret": "<from a secret store, not appsettings.json>"
}
```
Supply the secret out of band: `dotnet user-secrets set "ark_oauth_client:ClientSecret" "..."`.
Set the client's `token_endpoint_auth_method` accordingly on the provider.

---

## Recipe 12 — Testing the integration

> **PROMPT:** "Write an integration test that a protected endpoint 401/redirects when anonymous."

- The `.NET side has no automated test project` in this repo — verify against a running
  `Ark.oAuth.Oidc.Host`.
- For your own app, use `WebApplicationFactory<Program>` and assert that `[Authorize]` endpoints
  redirect (302 to the IdP) when unauthenticated; inject a test cookie for the authenticated case.
- Do not point tests at the live provider for the sign-in redirect assertion — assert the 302 target
  is the discovered `authorization_endpoint`.

---

## Recipe 13 — Migrating from the v1 client

> **PROMPT:** "Upgrade an app that used the v1 rsaPublic client without changing callback routes on
> day one, then move to the standard flow."

1. Upgrade the package. Temporarily set `"ark_oauth_client": { "UseLegacyFlow": true }` to keep the
   old cookie/bearer middleware and existing callback routes.
2. Register the standard redirect URIs (`/signin-oidc`, `/signout-callback-oidc`) on the provider.
3. Remove `UseLegacyFlow` (or set `false`) and remove any pasted `RsaPublic`/`Issuer`/`Audience`
   config — only `Authority` + `ClientId` are needed.

- **UseLegacyFlow does not validate `state`/`nonce`** and derives PKCE predictably — a migration aid,
  never a destination. See [`MIGRATION.md`](MIGRATION.md).
