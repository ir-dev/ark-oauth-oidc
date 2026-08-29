# Getting started

From a fresh clone to a working sign-in, and an explanation of every setting you passed on the
way.

Two applications are involved and they are deliberately kept apart:

| Project | What it is | Address |
|---|---|---|
| [`Ark.oAuth.Oidc.Host`](Ark.oAuth.Oidc/Ark.oAuth.Oidc.Host/) | The identity provider. Serves the protocol and the admin console. | `https://localhost:7233` |
| [`Ark.Client.Web`](Ark.oAuth.Oidc/Ark.Client.Web/) | A sample application that signs its users in through it. No database, no protocol code. | `https://localhost:7255` |

---

## Contents

- [1. The short version](#1-the-short-version)
- [2. What you are actually running](#2-what-you-are-actually-running)
- [3. Prerequisites](#3-prerequisites)
- [4. First run](#4-first-run)
- [5. How the configuration works](#5-how-the-configuration-works)
- [6. Making the end-to-end sample ready](#6-making-the-end-to-end-sample-ready)
- [7. What the readiness checks mean](#7-what-the-readiness-checks-mean)
- [8. Take the tour](#8-take-the-tour)
- [9. Troubleshooting](#9-troubleshooting)
- [10. Where to go next](#10-where-to-go-next)

---

## 1. The short version

```bash
git clone <this repo> && cd ark-oauth-oidc

# macOS / Linux
./run.sh

# Windows
run.bat
```

The script builds the solution, starts both applications, waits for each to answer, verifies that
the sample client registrations exist, and prints what is ready and what is not. On the very first
run it asks you to choose a password for the administrator account, because that account is created
once and has no default.

```
==> Checking prerequisites
  ✔ .NET SDK 10.0.101
  ✔ https development certificate is trusted
  ✔ ports free

==> Starting the identity provider
  ✔ the identity provider is up at https://localhost:7233

==> Checking the end-to-end sample
  ✔ discovery served, issuer is https://localhost:7233/ark_idp
  ✔ signing key published at /.well-known/jwks.json
  ✔ client 'ark_sample_web' is registered — the sign-in page renders
  ! client 'ark_sample_spa' is not registered — /flows/spa will fail
  ✔ https://localhost:7255 is allowed to call the token endpoint from the browser
  ✔ 'ark_idp_machine' can obtain a token
```

Useful flags, on both scripts:

| Flag | Effect |
|---|---|
| `--check-only` | Run the readiness checks against an already-running pair and start nothing. Exit code 0 means ready. |
| `--no-build` | Skip `dotnet build` and run what is already compiled. |
| `--no-browser` | Do not open the sample client when it comes up. |
| `--verbose` | Show full build output. |
| `--stop` | *(run.bat only)* Close the two windows it opened. On `run.sh`, Ctrl-C stops both. |

`run.sh` runs both applications as children of your terminal and writes their logs to `.run-logs/`.
`run.bat` opens one console window per application, so each log is in front of you.

Prefer two terminals? That works too — the scripts do nothing you cannot do by hand:

```bash
dotnet run --project Ark.oAuth.Oidc/Ark.oAuth.Oidc.Host   # terminal 1
dotnet run --project Ark.oAuth.Oidc/Ark.Client.Web        # terminal 2
```

---

## 2. What you are actually running

```
   Browser
      │
      │  1. GET /home/secure  ──► not signed in
      ▼
┌─────────────────────────┐                    ┌──────────────────────────────────┐
│  Ark.Client.Web         │  2. redirect to    │  Ark.oAuth.Oidc.Host             │
│  localhost:7255         │  ───────────────►  │  localhost:7233                  │
│                         │     /oauth2/       │                                  │
│  client_id              │     authorize      │  issuer                          │
│    ark_sample_web       │                    │    https://localhost:7233/ark_idp│
│                         │  ◄───────────────  │                                  │
│  ASP.NET Core's own     │  3. ?code=…        │  sign-in page, consent,          │
│  OpenID Connect handler │                    │  admin console, database         │
│                         │  4. POST /oauth2/  │                                  │
│  AddArkOidcClient()     │     token  ──────► │  AddArkOidcServer()              │
│                         │  ◄─── id + access  │                                  │
└─────────────────────────┘      + refresh     └──────────────────────────────────┘
```

Two things are worth internalising before you touch any settings.

**The client knows exactly one URL.** `Authority` — the issuer. Everything else (authorize, token,
userinfo, jwks, end-session) is read from `{Authority}/.well-known/openid-configuration` at
startup. There is no public key to paste anywhere and nothing to update when a signing key rotates.

**Neither application implements the protocol by hand.** The provider is `Ark.oAuth.Oidc`; the
client is ASP.NET Core's own OpenID Connect handler, configured by `Ark.oAuth.Client`. PKCE,
`state`, `nonce`, JWKS rollover and silent refresh are the framework's job, not yours.

---

## 3. Prerequisites

| | |
|---|---|
| **.NET SDK** | 9.0 or later. Both projects target `net9.0`, so you also need the ASP.NET Core **9** runtime — or `DOTNET_ROLL_FORWARD=Major` to run them on a newer one. |
| **A trusted https dev certificate** | `dotnet dev-certs https --trust`. Sign-in is a chain of https redirects; an untrusted certificate breaks it in the browser, where neither application can report it. |
| **curl** | Used by the readiness checks. Ships with macOS, Linux and Windows 10 1803+. |

`run.sh` / `run.bat` check all three and tell you what to do about each.

---

## 4. First run

### The administrator account

The provider seeds one administrator when it creates its database, from
`ark_oauth_server:AdminUser`. **The password is required and has no default.** It used to be a
compiled-in `admin` / `admin` — the same credentials on every deployment, on the one account that
administers every tenant. Now, with nothing configured, the first request fails with a message
naming the setting and **no database is created**, so you never end up with a half-built server
that looks initialised.

`appsettings.json` ships the placeholder `"<<set-before-first-run>>"`, and a value still in
`<<…>>` counts as unset. Supply a real one in whichever way suits you:

```bash
# the scripts prompt for this on the first run and pass it to the child process only
export ark_oauth_server__AdminUser__Password='a-real-password'

# or store it, out of source control (the host project has no UserSecretsId yet, hence init)
dotnet user-secrets init --project Ark.oAuth.Oidc/Ark.oAuth.Oidc.Host
dotnet user-secrets set "ark_oauth_server:AdminUser:Password" 'a-real-password' \
  --project Ark.oAuth.Oidc/Ark.oAuth.Oidc.Host
```

The section is read **only while the database is being created**. Changing it later renames nothing
and resets no password — use the admin console.

### What the first run creates

On the first request the provider builds its schema in `Ark.oAuth.Oidc.Host/data/ark_idp.db`
(SQLite, gitignored) and seeds:

| | |
|---|---|
| the tenant | `ark_idp`, with an RSA signing key generated in-process, `kid = ark_idp` |
| `ark_idp_client` | the admin console, which is itself an OIDC client of this same server |
| `ark_idp_machine` | a `client_credentials` client for `client.register`, deliberately **without a secret**, so no deployment ships a well-known one |
| the administrator | the `AdminUser` above, with its user-client access mapping |
| the scope catalogue | `openid`, `profile`, `email`, `offline_access`, … |

Starting over is a file delete:

```bash
rm -rf Ark.oAuth.Oidc/Ark.oAuth.Oidc.Host/data/     # everything: users, clients, keys, tokens
```

---

## 5. How the configuration works

Three files carry everything. Nothing is discovered by convention and nothing is hidden.

| File | Section | Read by |
|---|---|---|
| `Ark.oAuth.Oidc.Host/appsettings.json` | `ark_oauth_server` | the identity provider |
| `Ark.oAuth.Oidc.Host/appsettings.json` | `ark_oauth_client` | the host, as a client of *itself* — that is how the admin console signs you in |
| `Ark.Client.Web/appsettings.json` | `ark_oauth_client` | the sample application |
| `Ark.Client.Web/appsettings.json` | `sample` | the sample's own demo pages; **not** read by the client library |
| both `Properties/launchSettings.json` | `applicationUrl` | Kestrel — which ports each application listens on |

### Step 1 — the issuer is a formula

```
issuer = BaseUrl + BasePath + TenantId
```

```jsonc
// Ark.oAuth.Oidc.Host/appsettings.json
"ark_oauth_server": {
  "TenantId": "ark_idp",                    // also seeds a client named "<TenantId>_client"
  "BasePath":  "",                          // only if the app is hosted under a sub-path
  "BaseUrl":  "https://localhost:7233",     // must match the address the server is reached on
  "Provider": "sqlite"                      // sqlite | mysql | postgres
}
```

giving

```
https://localhost:7233/ark_idp                                        ← the issuer
https://localhost:7233/ark_idp/.well-known/openid-configuration       ← everything else
```

Two rules follow from that single line:

* **`BaseUrl` must match reality.** It is what the discovery document advertises and what ends up
  in the `iss` claim of every token. Point it at the wrong host and every client rejects every
  token, correctly.
* **If you set `BasePath`, add `app.UsePathBase` to match.** They have to agree, or the redirect
  URIs you registered will not be the ones actually sent.

### Step 2 — the client knows only that issuer

```jsonc
// Ark.Client.Web/appsettings.json
"ark_oauth_client": {
  "Authority": "https://localhost:7233/ark_idp",   // ← the issuer from step 1. Required.
  "ClientId":  "ark_sample_web",                   // ← must exist on the server. Required.
  "ClientSecret": null,                            // null = public client, PKCE only
  "Scopes": [ "openid", "profile", "email", "offline_access" ],
  "CallbackPath":          "/signin-oidc",
  "SignedOutCallbackPath": "/signout-callback-oidc",
  "RequireHttpsMetadata": true,                    // only ever false against a plain-http provider
  "RoleClaimType": "role"                          // ark_claims are projected onto this
}
```

`Authority` and `ClientId` are the only required keys. Everything else has a working default.

Because this is the standard ASP.NET Core handler underneath, changing those two values points the
same application at Entra ID, Okta, Auth0 or Keycloak instead.

### Step 3 — follow one port through the whole system

This is the part that catches people, so it is worth tracing once. The sample client's port
appears in **four** places, and they all have to agree:

```
Ark.Client.Web/Properties/launchSettings.json
   "applicationUrl": "https://localhost:7255;…"                  ← ① where it listens
                              │
        ┌─────────────────────┴──────────────────────┐
        ▼                                            ▼
② appsettings.json                        ③ the client record on the server
   "CallbackPath": "/signin-oidc"     ─►      redirect_uris
                                                https://localhost:7255/signin-oidc
   "SignedOutCallbackPath":                   post_logout_redirect_uris
       "/signout-callback-oidc"       ─►        https://localhost:7255/signout-callback-oidc
        │
        ▼
④ Ark.oAuth.Oidc.Host/appsettings.json
   "Oidc": { "CorsOrigins": [ "https://localhost:7255" ] }        ← browser-side flows only
```

The redirect URI the client sends is *derived* — origin + `CallbackPath` — and the server matches
what it receives against the registration **exactly**: scheme, host, port, path, trailing slash. No
wildcards, no prefix matching. So changing the port in ① means editing ③ and ④ as well.

You never have to work this out by hand: `https://localhost:7255` prints the exact values it is
about to send and checks them against the live discovery document.

### Step 4 — what a client record controls

Registration is a whitelist, not a filter. A scope the client is not registered for is **rejected**
with `invalid_scope`, not quietly dropped.

| Field | For the web sample | Why |
|---|---|---|
| `client_id` | `ark_sample_web` | matches `ark_oauth_client:ClientId` |
| `token_endpoint_auth_method` | `none` | public client — no secret. See [Confidential clients](Ark.oAuth.Oidc/Ark.Client.Web/README.md#confidential-clients) |
| `redirect_uris` | `https://localhost:7255/signin-oidc` | matched byte for byte |
| `post_logout_redirect_uris` | `https://localhost:7255/signout-callback-oidc` | required for logout to return the user |
| `grant_types` | `authorization_code`, `refresh_token` | `refresh_token` is what lets a session outlive the first access token |
| `scopes` | `openid profile email offline_access` | `offline_access` is what produces a refresh token |
| `require_pkce` | `true` | mandatory for public clients, `S256` only |
| `is_active` | `true` | switching it off also revokes that client's refresh tokens |

### Step 5 — the setting with no config file: access mapping

Ark authorizes **per user, per client**. A user with no mapping to a client cannot sign in to it at
all — and the sign-in page reports only that the credentials were not recognised, deliberately, so
the form cannot be used to enumerate accounts.

This is the single most common "it does not work" and it looks exactly like a wrong password.
There is no setting for it: it lives in the database, edited in the admin console under **Access
mapping**.

The claims on a mapping are two kinds in one list:

| Kind | Example | Where it ends up |
|---|---|---|
| Identity claims | `sub`, `name`, `email`, `email_verified` | filtered by the granted scopes, into the ID token and UserInfo |
| Authorization claims | `sample.admin` | into the access token as `ark_claims`, projected by the client onto `RoleClaimType`, so `[Authorize(Roles = "sample.admin")]` works |

Claims are written into tokens when tokens are issued, so a change takes effect at the user's
**next sign-in**.

### Change-this / change-that

| If you change… | …also change |
|---|---|
| the host's port in `launchSettings.json` | `ark_oauth_server:BaseUrl`, and `Authority` in **both** `appsettings.json` files |
| `TenantId` | `Authority` in both `appsettings.json` files (the issuer contains it) |
| the client's port in `launchSettings.json` | the client's `redirect_uris` and `post_logout_redirect_uris` on the server, and `Oidc:CorsOrigins` |
| `CallbackPath` / `SignedOutCallbackPath` | the same two registered URIs |
| `ClientId` | the client record on the server, and its access mapping |
| a client's registered `scopes` | the `Scopes` the application asks for — unregistered scopes are rejected |

---

## 6. Making the end-to-end sample ready

Four registrations make every page of the sample work. Only the first two are needed to sign in;
the rest unlock the extra flow pages.

Sign in to the admin console at **`https://localhost:7233/ark_idp/admin`** as `admin`, with the
password from step 4.

### a. The web client — required

**Clients → add**, with the values from [Step 4](#step-4--what-a-client-record-controls) above.

### b. The access mapping — required

**Access mapping → add**: user `admin`, client `ark_sample_web`, claims

```
sub  name  email  email_verified  sample.admin
```

`sample.admin` is what `/home/roles` checks; the rest are the identity claims.

### c. The SPA client — for `/flows/spa`

A second, separate public client whose redirect URI is the page itself:

| | |
|---|---|
| `client_id` | `ark_sample_spa` |
| `redirect_uris` | `https://localhost:7255/flows/spa` |
| `token_endpoint_auth_method` | `none` |
| `grant_types` | `authorization_code` |
| `scopes` | `openid profile email` — **no** `offline_access`; a refresh token has nowhere safe to live in a browser |

It also needs `https://localhost:7255` in `ark_oauth_server:Oidc:CorsOrigins` (already there in
this repo), because the page redeems its code from the browser, cross-origin. Without it the
browser blocks the request before it reaches the server, with a console error and no server-side
trace.

### d. The machine client's secret — for `/flows/machine` and `/flows/register`

`ark_idp_machine` is seeded **without** a secret on purpose. Give it one:

1. **Clients → `ark_idp_machine` → Regenerate secret.** The value is shown once — only a PBKDF2
   hash is stored.
2. ```bash
   dotnet user-secrets set "sample:Machine:ClientSecret" "<the secret>" \
     --project Ark.oAuth.Oidc/Ark.Client.Web
   ```

Then re-run the checks:

```bash
./run.sh --check-only
```

> There is also a one-call provisioning endpoint — `POST /api/oauth/v1/provision/client` — that
> does the client, the user and the access mapping together, and an operator-only console page at
> `/ark_idp/admin/provisioning` that writes the equivalent `curl` for you. It is authorized by the
> host's browser session, so it is a console-and-script tool rather than something `run.sh` can
> call unattended.

---

## 7. What the readiness checks mean

Each check the scripts run maps to one thing that can be wrong, and each is verifiable without
credentials.

| Check | How it is tested | If it fails |
|---|---|---|
| **discovery served, issuer matches** | `GET {issuer}/.well-known/openid-configuration`, compare `issuer` | `ark_oauth_server:BaseUrl` does not match the address the server is reached on. Every token would carry the wrong `iss`. |
| **signing key published** | `GET /.well-known/jwks.json` contains a `kid` | The tenant has no active signing key — usually a database that was created but not seeded. |
| **client registered** | `GET /oauth2/authorize?client_id=…` answers `200` (the sign-in page) rather than `400 unknown client_id` | The `client_id` is not registered in this tenant, or is inactive. Register it (§6a). |
| **CORS origin allowed** | `OPTIONS /oauth2/token` with an `Origin` header returns a matching `access-control-allow-origin` | The SPA page cannot redeem its authorization code. Add the origin to `Oidc:CorsOrigins` and restart the provider. |
| **machine client can get a token** | `client_credentials` with `scope=client.register` returns an `access_token` | No secret, or a stale one. Regenerate it (§6d). |

Two things the scripts deliberately **cannot** check, because both need a signed-in session:

* **the access mapping** — its absence is indistinguishable from a wrong password, by design;
* **whether the registered redirect URI matches** — that is validated when the code is redeemed,
  not when the sign-in page is drawn. `https://localhost:7255` shows you the comparison instead.

---

## 8. Take the tour

Open <https://localhost:7255> and sign in.

| Page | What it demonstrates |
|---|---|
| `/` | A live setup check: this app's configuration paired with the provider's discovery document. |
| `/home/secure` | `[Authorize]` and nothing else — reaching it means the whole flow completed. |
| `/home/profile` | The claims on the principal, plus the decoded access and ID tokens. |
| `/home/roles` | `ark_claims` → role projection, granted or not. |
| `/home/downstream` | Calling an API with the user's access token. |
| `/flows/spa` | The same flow run entirely by JavaScript in the browser. |
| `/flows/machine` | The client credentials grant — a service authenticating as itself. |
| `/flows/register` | Dynamic client registration (RFC 7591) and management (RFC 7592). |
| Sign out | RP-initiated logout, which ends the session at the provider too. |

And on the provider, `https://localhost:7233/ark_idp/admin` manages tenants, clients, users,
scopes and access mapping. Each client also has a generated setup page at
`/ark_idp/oauth2/integrate/{client_id}` with copy-paste configuration for that specific client —
for the Ark client package, the raw ASP.NET Core handler, `oidc-client-ts`, Authlib and `go-oidc`.

---

## 9. Troubleshooting

| Symptom | Cause |
|---|---|
| Sign-in says the credentials were not recognised, and they are correct | No access mapping for that user *and* that client — §6b. |
| `unable to open database file` | The `data/` directory does not exist. SQLite will not create it; the scripts do. |
| First request fails naming `AdminUser:Password` | No admin password configured — §4. No database is created, so nothing is left half-built. |
| `invalid_request` / `unknown client_id` at `/oauth2/authorize` | The `client_id` is not registered in that tenant, or is inactive. |
| `invalid_request` naming `redirect_uri` | The registered URI does not match byte for byte — scheme, host, port, path, trailing slash. |
| `invalid_scope` | The client is not registered for a scope it asked for. Registrations are a whitelist. |
| `Cannot redirect to the authorization endpoint, the configuration may be missing or invalid.` | The provider is unreachable, **or** a split `Microsoft.IdentityModel` graph — `Protocols` at 7.x against `Tokens` at 8.x. Check `dotnet list package --include-transitive`; nothing warns at build time. |
| The callback loops or 404s | A controller action is shadowing `/signin-oidc`. Never add one at `CallbackPath` — the handler serves it. |
| The browser refuses the certificate | `dotnet dev-certs https --trust`. |
| No `refresh_token` | `offline_access` was not requested, or not granted on the client record. |
| `/flows/spa` fails in the browser console with no server-side trace | The origin is missing from `Oidc:CorsOrigins`. |
| Signed out locally but signing in again asks nothing | Only the cookie scheme was signed out. Sign out of both schemes to end the provider session too. |
| A port is already in use | Something from a previous run survived. `./run.sh --check-only` tests what is there. |

---

## 10. Where to go next

* **[README.md](README.md)** — the specifications supported, every endpoint, the full
  configuration reference, key management, and the security notes worth reading before production.
* **[Ark.Client.Web/README.md](Ark.oAuth.Oidc/Ark.Client.Web/README.md)** — the client walkthrough
  in depth: registering, granting access, reading tokens, calling a downstream API, confidential
  clients, and porting the sample into a new project.
* **Building your own client** — copy `Program.cs`, the `ark_oauth_client` section and
  `Controllers/AccountController.cs` from `Ark.Client.Web`. That is the whole integration.
* **Building your own provider host** — `dotnet add package Ark.oAuth.Oidc`, then the three
  extension methods in [`Ark.oAuth.Oidc.Host/Program.cs`](Ark.oAuth.Oidc/Ark.oAuth.Oidc.Host/Program.cs).
  Middleware order matters: `UseRouting()` before `UseAuthentication()` / `UseAuthorization()`.

Before any of it reaches production, read
[Security notes](README.md#security-notes) — in particular: change the seeded administrator
password, keep `RequireHttpsMetadata` on, and leave dynamic client registration off unless you
deliberately need it.
