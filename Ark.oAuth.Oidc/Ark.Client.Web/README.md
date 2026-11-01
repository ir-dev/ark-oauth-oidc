# Ark client sample — registering and using an OAuth 2.1 / OIDC client

A client-only ASP.NET Core web application. It has no database, no identity provider and no
protocol code of its own: sign-in, PKCE, `state`, `nonce`, JWKS rollover and silent token refresh
all come from ASP.NET Core's OpenID Connect handler, configured by `AddArkOidcClient`.

Use it two ways:

* **as a walkthrough** — run it and open `/`, which prints the exact values to register and checks
  them live against the provider's discovery document;
* **as a template** — copy `Program.cs`, the `ark_oauth_client` section of `appsettings.json` and
  `Controllers/AccountController.cs` into a new project. That is the whole integration.

---

## Contents

- [The short version](#the-short-version)
- [Step 1 — Run the identity provider](#step-1--run-the-identity-provider)
- [Step 2 — Register the client](#step-2--register-the-client)
- [Step 3 — Grant a user access](#step-3--grant-a-user-access)
- [Step 4 — Configure the application](#step-4--configure-the-application)
- [Step 5 — Run and verify](#step-5--run-and-verify)
- [The other flows](#the-other-flows)
- [Using it from application code](#using-it-from-application-code)
- [Confidential clients](#confidential-clients)
- [Porting this into a new project](#porting-this-into-a-new-project)
- [Troubleshooting](#troubleshooting)
- [Before production](#before-production)

---

## The short version

| | |
|---|---|
| Identity provider | `https://localhost:7233` (`Ark.oAuth.Oidc.Host`) |
| Tenant | `ark_idp` |
| Issuer / Authority | `https://localhost:7233/ark_idp` |
| This app | `https://localhost:7255` |
| client_id | `ark_sample_web` |
| Redirect URI | `https://localhost:7255/signin-oidc` |
| Post-logout redirect URI | `https://localhost:7255/signout-callback-oidc` |
| Scopes | `openid profile email offline_access` |
| Client type | public (no secret) + PKCE |
| Test credentials | `admin` / `admin` (seeded on the provider's first run) |

```bash
dotnet run --project Ark.oAuth.Oidc.Host   # terminal 1 — the provider
dotnet run --project Ark.Client.Web        # terminal 2 — this app
```

---

## Step 1 — Run the identity provider

```bash
dotnet run --project Ark.oAuth.Oidc.Host
```

On first run it creates its SQLite database, generates an RSA signing key, seeds the scope
catalogue and creates an `admin` / `admin` account.

Confirm the discovery document is served:

```bash
curl -s https://localhost:7233/ark_idp/.well-known/openid-configuration | jq .issuer
# "https://localhost:7233/ark_idp"
```

**This URL is the only thing this application needs to know about the provider.** The authorize,
token, userinfo, jwks and end-session endpoints are all read from it, so there is no public key
to paste and nothing to change when a signing key rotates.

---

## Step 2 — Register the client

Sign in to the admin console at `https://localhost:7233/ark_idp/admin` (as `admin`), open
**Clients**, and add a client:

| Field | Value | Why |
|---|---|---|
| `client_id` | `ark_sample_web` | Must match `ark_oauth_client:ClientId`. |
| `client_name` | `Ark Client Sample` | Shown on the sign-in and consent screens. |
| `application_type` | `web` | Server-side rendered application. |
| `token_endpoint_auth_method` | `none` | No secret — this is a public client. See [Confidential clients](#confidential-clients). |
| `redirect_uris` | `https://localhost:7255/signin-oidc` | Matched **exactly**. No wildcards, no prefix matching, no trailing-slash tolerance. |
| `post_logout_redirect_uris` | `https://localhost:7255/signout-callback-oidc` | Required for RP-initiated logout to return the user. |
| `grant_types` | `authorization_code`, `refresh_token` | `refresh_token` is what lets a session outlive the first access token. |
| `scopes` | `openid profile email offline_access` | A scope the client is not registered for is **rejected**, not silently dropped. |
| `require_pkce` | `true` | Mandatory for public clients; `S256` only. |
| `is_active` | `true` | |

The redirect URIs come from `CallbackPath` and `SignedOutCallbackPath` plus the app's own origin.
Change the port in `launchSettings.json` and both registrations have to change with it — the
home page prints the current values so there is nothing to work out by hand.

> Registration is also available over the wire as RFC 7591 dynamic client registration
> (`POST /{tenant}/oauth2/register`), but it is off by default. With it on, `/flows/register` does
> Steps 2 and 3 for this app from forms — see [below](#flowsregister--dynamic-client-registration).

---

## Step 3 — Grant a user access

**Not optional, and the easiest step to miss.** Ark authorizes per user *per client*: a user with
no mapping to this client cannot sign in to it at all, and the sign-in page reports only that the
credentials were not recognised — deliberately, so the form cannot be used to enumerate accounts.

In the admin console open **Access mapping** and add: user `admin`, client `ark_sample_web`, with
claims:

```
sub  name  email  email_verified  sample.admin
```

Two kinds of claim live in that one list:

* **Identity claims** (`name`, `email`, `email_verified`, …) — filtered by the granted scopes and
  returned in the ID token and from UserInfo.
* **Authorization claims** (anything else, e.g. `sample.admin`) — delivered in the access token as
  `ark_claims` and projected by the client onto `ark_oauth_client:RoleClaimType` (default `role`),
  so `[Authorize(Roles = "sample.admin")]` works against them.

Claims are written into tokens when they are issued, so a change takes effect at the user's next
sign-in, not immediately.

---

## Step 4 — Configure the application

`Program.cs` — two lines, plus middleware in the right order:

```csharp
builder.Services.AddArkOidcClient(builder.Configuration);
...
app.UseRouting();        // must come before the two below
app.UseAuthentication();
app.UseAuthorization();
```

`appsettings.json`:

```jsonc
"ark_oauth_client": {
  "Authority": "https://localhost:7233/ark_idp",
  "ClientId": "ark_sample_web",
  "ClientSecret": null,
  "Scopes": [ "openid", "profile", "email", "offline_access" ],
  "CallbackPath": "/signin-oidc",
  "SignedOutCallbackPath": "/signout-callback-oidc",
  "SignedOutRedirectUri": "/",
  "AuthErrorPath": "/",
  "RequireHttpsMetadata": true,
  "CookieName": "ark_sample_web_auth",
  "RoleClaimType": "role"
}
```

`Authority` and `ClientId` are the only required keys. Everything else has a working default.

`CallbackPath` and `SignedOutCallbackPath` are served by the handler itself — **do not add
controller actions for them.** An action at `/signin-oidc` shadows the handler and the callback
never completes.

---

## Step 5 — Run and verify

```bash
dotnet run --project Ark.Client.Web
```

Open <https://localhost:7255>. The home page re-derives every value above from configuration and
checks it against the live discovery document — reachability, issuer match, unsupported scopes —
so a registration mistake shows up as a sentence rather than an `invalid_request` page.

Then walk the pages:

| Page | Shows |
|---|---|
| `/home/secure` | `[Authorize]` and nothing else — reaching it means the whole flow completed. |
| `/home/profile` | Claims on the principal, plus the decoded access and ID tokens. |
| `/home/roles` | `ark_claims` → role projection, granted or not. |
| `/home/downstream` | Calling an API with the user's access token. |
| `/flows/spa` | The same flow run by JavaScript in a public client — see below. |
| `/flows/machine` | The client credentials grant, live. |
| `/flows/register` | Dynamic client registration (RFC 7591) and management (RFC 7592). |
| Sign out | RP-initiated logout through the provider's `end_session_endpoint`. |

What happens on the wire, for reference:

```
GET  /account/login
  302 → {authority}/oauth2/authorize?client_id=…&redirect_uri=…&response_type=code
        &scope=openid%20profile%20email%20offline_access&code_challenge=…&code_challenge_method=S256
        &state=…&nonce=…
POST {authority}/oauth2/authorize            (credentials, then consent)
  302 → https://localhost:7255/signin-oidc?code=…&state=…
  ↳ the handler exchanges the code with code_verifier, validates the ID token against JWKS,
    and writes the encrypted authentication cookie
  302 → /home/profile
```

---

## The other flows

Everything above is one flow: the authorization code flow through a server-side web application,
where the OpenID Connect handler does the work. Three cases it does not cover have their own
pages, each running live against the provider.

### `/flows/spa` — single-page application

The same authorization code flow with PKCE, run entirely by the browser. The page is its own
`redirect_uri`, the exchange happens in `fetch`, and the tokens live in a JavaScript variable that
a reload discards.

Two things have to be set up, and both fail outside the application if they are not:

1. **Register a second client.** It is a public client whose redirect URI is the page itself:

   | | |
   |---|---|
   | client_id | `ark_sample_spa` (`sample:Spa:ClientId`) |
   | redirect_uris | `https://localhost:7255/flows/spa` |
   | token_endpoint_auth_method | `none` |
   | grant_types | `authorization_code` |
   | scopes | `openid profile email` |

   Register it in the admin console, or create it from `/flows/register`.

2. **Allow this origin on the provider.** A SPA calls the token endpoint cross-origin, so the
   browser sends a preflight first and blocks the real request if the server does not answer it —
   with a console error and no server-side trace:

   ```jsonc
   // Ark.oAuth.Oidc.Host/appsettings.json
   "ark_oauth_server": { "Oidc": { "CorsOrigins": [ "https://localhost:7255" ] } }
   ```

   Exact origins only; there is no wildcard, because these endpoints hand out tokens. The policy
   covers the token, userinfo, discovery and JWKS endpoints. The authorization endpoint is a
   browser redirect and needs nothing.

No `offline_access`: a refresh token is a long-lived credential and a browser has nowhere safe to
keep one. Tokens are held in memory rather than `localStorage`, which any script on the page can
read. An application that needs durable browser sessions should put a backend in front of the flow
— which is what the rest of this sample is.

### `/flows/machine` — client credentials

A service authenticating as itself: no user, no browser, no redirect. Use it for scheduled jobs
and service-to-service calls; never to act on behalf of a signed-in user, because the token then
carries the service's authority rather than theirs and every audit record downstream says so.

The provider seeds a machine client, `<tenant>_machine`, with **no secret** — a secret committed to
source would be the same secret on every deployment. Give it one:

1. Admin console → **Clients** → `ark_idp_machine` → **Regenerate secret** (shown once).
2. Paste it on `/flows/register` (**machine client_secret** in Step 1; **View** shows it). Each
   form on the page sends it along; it is stored nowhere. To keep it across restarts, export it before starting the app:
   `export sample__Machine__ClientSecret='<the secret>'`. Don't write it into `appsettings.json`,
   which is in source control.

`/flows/register` tries the stored secret against the IdP on every load and shows *accepted*,
*rejected* or *not set*. A secret goes stale silently when the IdP's database is recreated, because
the new database seeds the machine client without one.

### `/flows/register` — dynamic client registration

Creating a client at runtime over RFC 7591 instead of by hand, then reading and deleting it over
RFC 7592. Registration is itself an authorized operation, so the page chains the two flows: it
obtains an initial access token with the client credentials grant above, then registers with it.

The provider must have it switched on — it is off by default, since an open registration endpoint
lets anyone create clients:

```jsonc
// Ark.oAuth.Oidc.Host/appsettings.json
"ark_oauth_server": {
  "Oidc": {
    "EnableDynamicRegistration": true,
    "RequireRegistrationAccessToken": true   // the initial access token needs scope client.register
  }
}
```

The `client_secret` and `registration_access_token` in the response are shown **once** — the server
keeps only hashes. The registration access token is not the client's access token and cannot be
re-derived; lose it and the registration can only be removed by an operator with database access.

Registering a client is also not the same as authorizing anyone to use it: on Ark a user still has
to be mapped to the new client under **Access mapping**, or their sign-in fails in a way that looks
like a wrong password.

**The form registers this app itself.** `client_id` and `client_name` are prefilled with
`ark_oauth_client:ClientId` (`ark_sample_web`), and the redirect URIs, scopes and
`token_endpoint_auth_method` with this app's own. Ark honours a requested `client_id` when it is
free, so the client created is the one the app already signs in as: nothing to reconfigure, nothing
to restart. Clear `client_id` to have the IdP mint one, and Step 4 prints the user-secrets to switch.

The machine client's token also drives the IdP's management API, which the rest of the page uses:

* it checks whether the client already exists, and offers **Remove** when it does — RFC 7592's
  delete needs the registration access token, which is gone once the page is reloaded;
* Step 3, **Grant access**, calls `POST /api/oauth/v1/provision/user`. An account that exists is
  left untouched and only mapped; one that does not is created with the IdP's default password and
  the display name from the form (the user id when blank). The mapping keeps any claims the user
  already has on the client, always carries `sub name email email_verified`, and adds the ones in
  the form (by default `name email email_verified sample.admin`).

That works only when `Authority` names the IdP's operator tenant: the management API accepts tokens
issued to that tenant's `<tenant>_machine` and nothing else.

---

## Using it from application code

**Require sign-in**

```csharp
[Authorize]
public IActionResult Secure() => View();
```

**Require an authorization claim**

```csharp
[Authorize(Roles = "sample.admin")]
public IActionResult Billing() => View();
```

**Read the user**

```csharp
var subject = User.FindFirst("sub")?.Value;
var email   = User.FindFirst("email")?.Value;
var roles   = User.FindAll("role").Select(c => c.Value);
```

**Call a downstream API**

```csharp
var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/things");
await request.WithArkTokenAsync(HttpContext);
using var response = await httpClient.SendAsync(request);
```

Read the token at call time — never cache it. The cookie handler refreshes it roughly two minutes
before expiry, and a captured copy goes stale.

**Sign in / sign out explicitly**

```csharp
// challenge
Challenge(new AuthenticationProperties { RedirectUri = "/" }, ArkOidcClient.OidcScheme);

// sign out locally *and* at the provider
SignOut(new AuthenticationProperties { RedirectUri = "/" },
        ArkOidcClient.CookieScheme, ArkOidcClient.OidcScheme);
```

**Protect an API instead of a UI**

```csharp
builder.Services.AddAuthentication().AddArkOidcApi(arkConfig);
```

**Check this app's own registration**

`AddArkOidcClient` also registers `ArkSetupProbe`, which pairs local configuration with the
provider's discovery document. `ArkSetupModel` is what the home page renders — it is in the client
library, not in this sample, so any Ark client can show the same check.

```csharp
public HomeController(ArkSetupProbe setup) => _setup = setup;

public async Task<IActionResult> Index() => View(await _setup.ProbeAsync(HttpContext));
// model.IssuerMismatch, model.UnsupportedScopes, model.RedirectUri, model.DiscoveryError …
```

**Get a token as the service itself**

```csharp
public class ReconciliationJob(ArkClientCredentials credentials)
{
    public async Task RunAsync()
    {
        // cached until shortly before expiry; RequestTokenAsync always hits the network
        var token = await credentials.GetTokenAsync(clientId, clientSecret, new[] { "jobs.run" });
        if (!token.Succeeded) throw new InvalidOperationException(token.ErrorDescription);

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.AccessToken);
    }
}
```

**Register a client at runtime**

```csharp
var initial = await credentials.GetTokenAsync(machineId, machineSecret, new[] { "client.register" });

var result = await registration.RegisterAsync(new JsonObject
{
    ["client_name"] = "My new client",
    ["redirect_uris"] = new JsonArray("https://app.example.com/signin-oidc"),
    ["grant_types"] = new JsonArray("authorization_code", "refresh_token"),
    ["token_endpoint_auth_method"] = "none",
    ["scope"] = "openid profile email offline_access"
}, initial.AccessToken);

// result.ClientSecret and result.RegistrationAccessToken are returned once — store them here.
// registration.ReadAsync / DeleteAsync manage it afterwards with that token.
```

---

## Confidential clients

A server-side web application can hold a secret, and should where the deployment allows it.

1. Set `token_endpoint_auth_method` to `client_secret_post` (or `client_secret_basic`) on the
   client record.
2. Press **Regenerate secret** in the admin console. The value is shown **once** — only a PBKDF2
   hash is stored, so it cannot be read back.
3. Put it somewhere other than `appsettings.json`:

```bash
dotnet user-secrets init
dotnet user-secrets set "ark_oauth_client:ClientSecret" "<the secret>"
```

Nothing in the code changes. PKCE stays on: it protects the authorization code regardless of
client authentication.

---

## Porting this into a new project

```bash
dotnet new mvc -n MyApp
cd MyApp
dotnet add package Ark.oAuth.Client
```

Then:

1. Copy the `ark_oauth_client` section into `appsettings.json`; change `ClientId` and, if the
   provider differs, `Authority`.
2. Add `builder.Services.AddArkOidcClient(builder.Configuration);` and make sure `UseRouting()`
   precedes `UseAuthentication()` / `UseAuthorization()`.
3. Copy `Controllers/AccountController.cs` for the sign-in and sign-out endpoints.
4. Register the new `client_id` and its two redirect URIs on the provider (Step 2), and add the
   access mapping (Step 3).
5. If the installed `Ark.oAuth.Client` package predates the dependency pins, keep the
   `Microsoft.IdentityModel.*` `PackageReference` lines from `Ark.Client.Web.csproj` — see below.

Because this is the standard ASP.NET Core handler underneath, pointing the same application at
Entra ID, Okta, Auth0 or Keycloak is a change of `Authority` and `ClientId` alone.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `Cannot redirect to the authorization endpoint, the configuration may be missing or invalid.` | Either the provider is unreachable, **or** a split `Microsoft.IdentityModel` graph — `Protocols[.OpenIdConnect]` at 7.x against `Tokens` at 8.x. Check with `dotnet list package --include-transitive`; every `Microsoft.IdentityModel.*` must be the same major version. Nothing warns at build time. |
| Sign-in page says the credentials were not recognised, and they are correct | No access mapping for that user *and* this client — Step 3. |
| `invalid_request` / `unauthorized_client` at `/oauth2/authorize` | The `client_id` is not registered in that tenant, is inactive, or is missing the `authorization_code` grant. |
| `invalid_request` naming `redirect_uri` | The registered URI does not match byte for byte — scheme, host, port, path, trailing slash. |
| `invalid_scope` | The client is not registered for a scope it asked for. Registered scopes are a whitelist, not a filter. |
| Callback returns to `/?auth_error=…` | The handler's remote failure hook. The message names the failing check — usually a correlation cookie lost to a scheme or host change mid-flow. |
| No `refresh_token` | `offline_access` was not requested or not granted. |
| Signed out locally but signing in again asks nothing | Only the cookie scheme was signed out. Sign out of both schemes to end the provider session too. |
| Callback loops or 404s | A controller action is shadowing `/signin-oidc`. |
| `RequireHttpsMetadata` errors on a plain-http provider | Development only: set it to `false`. Never in production. |

---

## Before production

1. Change the seeded `admin` / `admin` password on the provider.
2. Keep `RequireHttpsMetadata` at `true`.
3. Give confidential clients real secrets, kept outside source control, and set
   `token_endpoint_auth_method` to match.
4. Register production redirect URIs explicitly; they are matched exactly, so a staging URI is not
   a substring away from working.
5. Leave dynamic client registration off unless it is deliberately needed.
