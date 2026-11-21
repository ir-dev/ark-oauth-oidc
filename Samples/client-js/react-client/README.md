# Team Library: a React client for Ark, browser only

A React single-page app that signs in against an **Ark identity provider** with
[`ark-oauth-client-js`](../../../ark_oauth_client_js). There is no server of its own: the browser
does the whole OpenID Connect flow as a **public client** (authorization code + PKCE, no secret).

Start it and the landing page walks you through the rest. It describes the sample scenario, gives a
step-by-step guide to start the [QuickStart IdP](../../../Ark.oAuth.Oidc/Ark.oAuth.Oidc.QuickStart),
register this app on it as a client and connect the two, and ends with a live setup check.

- [Run it](#run-it)
- [The scenario](#the-scenario)
- [The setup guide, in short](#the-setup-guide-in-short)
- [How it is wired](#how-it-is-wired)
- [What "no server" means here](#what-no-server-means-here)
- [Build and host it](#build-and-host-it)
- [Troubleshooting](#troubleshooting)
- [Prompt: add Ark sign-in to a React app against a hosted IdP](#prompt-add-ark-sign-in-to-a-react-app-against-a-hosted-idp)

## Run it

Needs Node 20.19+ (or 22.12+). The IdP side needs the .NET 10 SDK.

```bash
cd Samples/client-js/react-client
npm install
npm run dev          # http://localhost:5173, then follow the guide on the page
```

The port is pinned (`strictPort`). The app's address is part of its registration on the IdP, because
redirect URIs and the CORS origin are matched byte for byte. If 5173 is busy, Vite stops rather than
moving to 5174. Open the app at `http://localhost:5173`, not `127.0.0.1`, which is a different origin.

## The scenario

A team's shared bookshelf, with the three levels of access most single-page apps need:

| Page | Who | How |
|---|---|---|
| **Shelf** (`/shelf`) | everyone | a public route; a signed-out visitor is offered a sign-in to borrow |
| **My loans** (`/loans`), **Session** (`/session`) | any signed-in user | `<RequireArk>`: a signed-out visitor goes to the IdP and comes back to the same page |
| **Librarian desk** (`/desk`) | users holding the Ark claim `library.librarian` | `<RequireArk claims={['library.librarian']}>`; anyone else gets "You do not have access", with **Sign in as a different user** (`prompt=login`) |

Loans are stored against the ID token's `sub` in `localStorage`. That stands in for an API, since
the sample has none. The Session page shows the ID token claims, the Ark claims, a live call to the
IdP's userinfo endpoint (a real bearer-protected API), and a token refresh.

## The setup guide, in short

The landing page has the full guide. Its values are computed from the page's own origin and the
settings in effect, each with a copy button. Here is the same in brief, for the defaults:

1. **Start the IdP**, from the repository root:
   ```bash
   dotnet dev-certs https --trust          # the app calls the IdP with fetch(); an untrusted cert fails silently
   cd Ark.oAuth.Oidc/Ark.oAuth.Oidc.QuickStart
   dotnet run                              # https://localhost:7300 → setup wizard
   ```
2. **Setup wizard:** Public URL `https://localhost:7300`, Tenant id `ark_idp` (issuer
   `https://localhost:7300/ark_idp`), SQLite. On the Signing key step click **Generate key pair**.
   Set an administrator, and under *Protocol & security* add the CORS origin `http://localhost:5173`.
   Install, then sign in to the console.
   *Wizard already done?* Add the origin to `ark_oauth_server.Oidc.CorsOrigins` in
   `ark-idp-data/settings.json`. It is read without a restart.
3. **Register the app:** console → **Provisioning**. Application name `Team Library`, client_id
   `team-library`, application_type `spa`, user = your admin username, redirect_uris
   `http://localhost:5173/signin-oidc`, claims `sub, name, email, email_verified, library.librarian`.
   **Provision.** This creates a public client (`token_endpoint_auth_method: none`, grants
   `authorization_code` + `refresh_token`, scopes `openid profile email offline_access`, PKCE) and
   **maps the user to it**. Without a mapping, sign-in fails as if the password were wrong.
4. **Sign-out address:** console → **Manage** → Clients → **Edit** on `team-library` →
   post_logout_redirect_uris `http://localhost:5173/signout-callback-oidc` → **Save client**.
5. **Connect the app:** `cp .env.example .env.local` (values below) and restart `npm run dev`. Or,
   for this sample only, paste the two values into the form on the landing page.
   ```bash
   VITE_ARK_AUTHORITY=https://localhost:7300/ark_idp
   VITE_ARK_CLIENT_ID=team-library
   ```
6. **Run the setup check** on the landing page (discovery, signing keys, CORS, client), then **Sign in**.

This exact sequence was run end to end in Chrome against a fresh QuickStart.

## How it is wired

The integration is four files. Everything else is the sample's own UI.

| File | What it does |
|---|---|
| [`src/ark.js`](src/ark.js) | The **one** `ArkBrowserClient`, created at module scope. Only `authority` and `clientId` are required; the rest are the library defaults, spelled out. Also `signOut()` / `switchAccount()` (see below). |
| [`src/main.jsx`](src/main.jsx) | `<ArkProvider>` **inside** `<BrowserRouter>`, with `onRedirectCallback` set to the router's `navigate`. |
| [`src/App.jsx`](src/App.jsx) | The routes, including the two callback routes a SPA must have: `/signin-oidc` (`<ArkCallback>`) and `/signout-callback-oidc`. |
| [`src/components/Guard.jsx`](src/components/Guard.jsx) | `<RequireArk>` with a loading view, an error view with the likely fix, and the "no access" page. |
| [`src/config.js`](src/config.js) | Reads `VITE_ARK_AUTHORITY` / `VITE_ARK_CLIENT_ID`. The fallback to values saved from the landing page is a **sample-only** convenience; a real app reads build-time env only. |

**Sign-out and account switch go through `signOut()` / `switchAccount()` in `src/ark.js`.** Both
drop the local session a moment before the browser leaves for the IdP. A page inside
`<RequireArk>` sees "signed out" in that moment and starts a sign-in of its own, which races the
redirect. If the guard's sign-in wins, single sign-on signs the same user straight back in, and an
account switch loses its `prompt=login`. The helpers raise a flag first, and `<Guard>` renders
"Signing you out…" instead of `<RequireArk>` while it is up. For the same reason, the "no access"
page is the sample's own, with buttons wired to those helpers, rather than `<ArkAccessDenied>`.

## What "no server" means here

- **Public client.** No `clientSecret`: anything in a bundle is readable by every visitor, and the
  constructor refuses one. PKCE protects the authorization code instead.
- **CORS on the IdP.** The browser redeems the code and refreshes tokens itself, so the IdP must list
  the app's origin in `ark_oauth_server:Oidc:CorsOrigins`. Server-side apps never need this.
- **Tokens in `sessionStorage`** (the default): they survive a reload, stay private to the tab, and go
  when it closes. Storage changes how long a stolen token is good for, not whether XSS can reach it.
  A strict Content-Security-Policy is what stops XSS.
- **Renewal by refresh token** (`offline_access`), rotated on every use and serialised across tabs.
  Hidden-iframe renewal is not possible against Ark (`frame-ancestors 'self'`).
- **Authorisation belongs to the API.** Hiding the librarian desk is UI. An API behind the app
  validates the access token and its `ark_claims` itself, for example with `verifyAccessToken` in
  the Node client or `RequireArkClaims` in .NET.

## Build and host it

```bash
npm run build        # dist/
npm run preview      # serves dist/ on the same http://localhost:5173, so the registration still matches
```

On any other host: serve `dist/` with **history fallback**, so `/signin-oidc` and
`/signout-callback-oidc` return `index.html`. Set the two `VITE_ARK_*` variables at build time.
Register the production origin as well: both URIs on the client, and the origin in `CorsOrigins`.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `Failed to fetch`, or the setup check says CORS | The origin is not in `CorsOrigins`, the IdP is not running, or its certificate is not trusted. |
| The password is right but sign-in says it is wrong | The user is not mapped to `team-library` (Provisioning does it; or **Manage → Access mapping**). |
| `redirect_uri` error on the IdP | The registered URI differs by a character, or the app is open at `127.0.0.1` instead of `localhost`. |
| `invalid_scope` | The client lacks one of `openid profile email offline_access`. Scopes are a whitelist. |
| Sign-out stops on the IdP's own "signed out" page | `post_logout_redirect_uris` is missing or differs (step 4). You are signed out either way. |
| The desk says "no access" | The mapping lacks `library.librarian`. Add it, then sign out and in: claims are read at sign-in. |

---

## Prompt: add Ark sign-in to a React app against a hosted IdP

For a coding agent (Claude Code, Copilot, Cursor, Codex, …) working on **your own** React app,
against an Ark IdP that is already running. Fill in the `<…>` values and paste the block. It is
self-contained and short enough for any agent's context. This sample is the worked example of it.

```text
Add sign-in to this React app with the Ark identity provider (OpenID Connect) already hosted at
<ISSUER, e.g. https://id.example.com/my_tenant>. The app is browser-only, with no backend of its own,
so it is a PUBLIC client: authorization code + PKCE, and no client secret anywhere.
client_id: <CLIENT_ID>. App origins: <http://localhost:5173>, <https://app.example.com>.
Ark claims that gate features (optional): <CLAIM, e.g. reports.read>.

Build it with the official package and nothing else for auth:
1. npm install ark-oauth-client-js. Do not hand-roll OAuth or PKCE, do not add oidc-client-ts or any
   other OIDC library, and never set clientSecret (the constructor refuses one).
2. src/ark.js: ONE `new ArkBrowserClient({ authority, clientId })` at module scope, from build-time
   env (Vite: VITE_ARK_AUTHORITY, VITE_ARK_CLIENT_ID; add .env.example, keep .env.local git-ignored).
   Endpoints and signing keys come from discovery. Add apiOrigins only for an API on another origin.
3. Wrap the app in <ArkProvider client={ark} onRedirectCallback={(to) => navigate(to, { replace: true })}>
   from 'ark-oauth-client-js/react', INSIDE the router, so the return after sign-in goes through it.
4. Routes: /signin-oidc renders <ArkCallback>{spinner}</ArkCallback>; /signout-callback-oidc renders a
   "signing out" message. The host must serve index.html for both (SPA history fallback).
5. Guard pages with <RequireArk fallback={spinner}>, adding claims={['<CLAIM>']} for gated features.
   Read UI state from useArk(): status, isAuthenticated, user, arkClaims, signinRedirect, fetch.
   hasArkClaims() only decides what to show; any API must validate the token itself.
6. Sign out with signoutRedirect() (it ends the IdP session too), never by clearing storage. Sign-out
   or switchUser() from a page inside <RequireArk> lets the guard start a new sign-in before the
   browser leaves (SSO then signs the user back in): set a flag first, and render a spinner instead
   of <RequireArk> while it is set.
7. API calls: useArk().fetch(url) attaches the token, refreshes it when due and sends it only to this
   origin and apiOrigins. Or call `await getAccessToken()` per request. Never store or cache tokens.
8. In development, run `await ark.checkSetup()` and show its `problems` (discovery, JWKS, CORS, client).

Then give me this checklist for the IdP administrator, filled in with the values above:
- Client: application_type spa, token_endpoint_auth_method none, grants authorization_code and
  refresh_token, scopes openid profile email offline_access (a whitelist), PKCE required.
- redirect_uris <origin>/signin-oidc and post_logout_redirect_uris <origin>/signout-callback-oidc, for
  every origin, byte for byte.
- ark_oauth_server:Oidc:CorsOrigins lists every exact origin (no trailing slash, no wildcard).
- Every user is mapped to the client (access mapping) with the claims they need; an unmapped user's
  sign-in fails as if the password were wrong.

Done when: the build passes with no secret in the bundle, checkSetup() reports no problems, a
signed-out visit to a guarded route goes to the IdP and comes back to that route, a reload keeps the
session, and sign-out followed by sign-in asks for the password again. Reference: the package README
(node_modules/ark-oauth-client-js/README.md) and the sample at
https://github.com/ir-dev/ark-oauth-oidc/tree/main/Samples/client-js/react-client
```
