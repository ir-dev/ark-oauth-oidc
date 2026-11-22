# ark-oauth-client-js

The OpenID Connect client for **browser apps** signing in against an
[ARK Identity Server](../README.md): React, Next.js, Vue, Angular, Svelte, or plain JavaScript.

One framework-agnostic client does the protocol; thin adapters bind it to each framework. There
are two settings, the issuer (`{BaseUrl}/{TenantId}`) and the client id. Endpoints and signing keys
come from the provider's discovery document, so nothing is rebuilt when a key rotates.

No runtime dependencies: Web Crypto, `fetch`, Web Storage, BroadcastChannel and Web Locks.

```bash
npm install ark-oauth-client-js
```

It is the browser sibling of `ark-oauth-client-node` (Node), `ark-oauth-client` (Python) and
`Ark.oAuth.Client` (.NET), carries the same version number, and uses the same names wherever the
concepts are shared (`TokenSet`, `ArkOAuthError`, `accountSwitch`, `checkSetup()`, ...).

---

## Contents

- [Before you start: register the app](#before-you-start-register-the-app)
- [Quick start (plain JavaScript)](#quick-start-plain-javascript)
- [React](#react) · [Next.js](#nextjs) · [Vue](#vue) · [Angular](#angular) · [Svelte, Solid and the rest](#svelte-solid-and-the-rest) · [A plain `<script>` tag](#a-plain-script-tag)
- [The state and events](#the-state-and-events)
- [Signing in](#signing-in)
- [Calling your API](#calling-your-api)
- [Signing out](#signing-out)
- [Account switching on a shared browser](#account-switching-on-a-shared-browser)
- [Configuration](#configuration)
- [Where tokens live, and how the session is renewed](#where-tokens-live-and-how-the-session-is-renewed)
- [Checking the setup](#checking-the-setup)
- [Errors](#errors)
- [Troubleshooting](#troubleshooting)
- [What it implements](#what-it-implements)
- [Development](#development)

---

## Before you start: register the app

A browser app is a **public client**: it has no secret (anything in a bundle is readable by every
visitor), and PKCE protects its authorization code instead. On the Ark tenant (admin console →
Clients, or the provisioning API):

| Setting | Value |
|---|---|
| Token endpoint auth method | `none` (public client) |
| Grant types | `authorization_code`, `refresh_token` |
| Redirect URI | `https://your.app/signin-oidc`, **byte for byte** what the app sends |
| Post-logout redirect URI | `https://your.app/signout-callback-oidc` |
| Scopes | `openid profile email offline_access` (`offline_access` is what produces a refresh token) |

Then two things on the server that cost real time when they are missed:

1. **CORS.** The app redeems its code from the browser, so the provider must list the app's origin
   in `ark_oauth_server:Oidc:CorsOrigins` (the setup wizard's Protocol step), e.g.
   `"CorsOrigins": ["https://your.app"]`. Without it every token request dies in the browser as
   `Failed to fetch`. [`checkSetup()`](#checking-the-setup) tells you if it is missing.
2. **Map the user to the client.** Ark maps users to clients explicitly; with no mapping the sign-in
   fails with something that reads like a wrong password. The claims you give the mapping arrive
   as `ark_claims`, which is what you authorise against.

The callback paths are the Ark defaults, and are relative to the page's origin unless you give
absolute URLs. A single-page app needs its host to answer `/signin-oidc` and
`/signout-callback-oidc` with the app (history fallback, which Vite, Next.js, Angular CLI and
every SPA host do).

---

## Quick start (plain JavaScript)

```js
import { ArkBrowserClient } from 'ark-oauth-client-js';

const ark = new ArkBrowserClient({
  authority: 'https://idp.example.com/my_idp', // the issuer: {BaseUrl}/{TenantId}
  clientId: 'my-spa'
});

ark.subscribe((state) => {
  // state.status: 'loading' | 'authenticated' | 'unauthenticated' | 'denied'
  document.querySelector('#who').textContent = state.isAuthenticated ? state.user.email : 'signed out';
});

document.querySelector('#sign-in').onclick = () => ark.signinRedirect();
document.querySelector('#sign-out').onclick = () => ark.signoutRedirect();

await ark.init(); // completes /signin-oidc, or restores the session from the last visit

const orders = await (await ark.fetch('/api/orders')).json(); // bearer token attached, refreshed when due
```

`init()` is the one call every app makes once at start-up. On the redirect URI it finishes the
sign-in and sends the user back to the page they started from; anywhere else it restores the
stored session, refreshing it if the access token expired while the page was closed. It never
rejects: failures land in `state.error`.

[`examples/vanilla`](examples/vanilla) is a complete app with no build step:
`ARK_AUTHORITY=… ARK_CLIENT_ID=… node examples/serve.mjs`.

---

## React

```jsx
// ark.js, module scope: one client for the app
import { ArkBrowserClient } from 'ark-oauth-client-js';
export const ark = new ArkBrowserClient({ authority: import.meta.env.VITE_ARK_AUTHORITY, clientId: import.meta.env.VITE_ARK_CLIENT_ID });
```

```jsx
import { ArkProvider, ArkCallback, RequireArk, useArk } from 'ark-oauth-client-js/react';
import { BrowserRouter, Routes, Route, useNavigate } from 'react-router';

function AuthRoot() {
  const navigate = useNavigate(); // the return after sign-in goes through the router
  return (
    <ArkProvider client={ark} onRedirectCallback={(to) => navigate(to, { replace: true })}>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/billing" element={<RequireArk claims={['billing.admin']} fallback={<Spinner />}><Billing /></RequireArk>} />
        <Route path="/signin-oidc" element={<ArkCallback><Spinner /></ArkCallback>} />
      </Routes>
    </ArkProvider>
  );
}

function Home() {
  const { isAuthenticated, user, signinRedirect, signoutRedirect } = useArk();
  return isAuthenticated
    ? <button onClick={() => signoutRedirect()}>Sign out {user.email}</button>
    : <button onClick={() => signinRedirect()}>Sign in</button>;
}
```

- `useArk()` returns the [state](#the-state-and-events) plus `signinRedirect`, `signinPopup`,
  `signoutRedirect`, `signoutLocal`, `switchUser`, `getAccessToken`, `fetch`, `hasArkClaims`,
  `hasAnyArkClaim` and the `client`. `useArkUser()` re-renders only when the user changes.
- `<RequireArk>` renders its children for a signed-in user (holding `claims` / `anyClaims`), starts
  the sign-in for a signed-out one, shows `fallback` meanwhile, and shows `<ArkAccessDenied>` (the
  account-switch page) to a user missing a claim. After a failed sign-in it shows the error with a
  retry instead of signing in again, so a misconfigured client cannot loop.
- `<ArkCallback>` is the element for the redirect URI's route: a single-page app needs a route
  there or its router shows "not found" during the exchange. (A *server-side* client must not have
  one, because it would shadow the handler; in a SPA the provider does the work and the route only
  renders progress.)
- React 18 and 19, StrictMode-safe (start-up is idempotent), SSR-safe.

[`examples/react-vite`](examples/react-vite) is a complete Vite + React Router app.

## Next.js

`ark-oauth-client-js/next` is the React adapter plus `<ArkNextProvider>`, which returns the user
through `next/navigation` after sign-in. App Router:

```tsx
// lib/ark.ts: safe to import from server code; on the server the state is always 'loading'
export const ark = new ArkBrowserClient({ authority: process.env.NEXT_PUBLIC_ARK_AUTHORITY!, clientId: process.env.NEXT_PUBLIC_ARK_CLIENT_ID! });

// app/providers.tsx
'use client';
import { ArkNextProvider } from 'ark-oauth-client-js/next';
export default function Providers({ children }) { return <ArkNextProvider client={ark}>{children}</ArkNextProvider>; }

// app/layout.tsx (server component): <body><Providers>{children}</Providers></body>

// app/signin-oidc/page.tsx
'use client';
import { ArkCallback } from 'ark-oauth-client-js/next';
export default function Callback() { return <ArkCallback><p>Signing you in…</p></ArkCallback>; }
```

Every component that calls `useArk()` is a client component (`'use client'`). The client is never
created per request and holds no state on the server, so there is nothing to leak between users;
the server render and the first browser render both show `loading`, so hydration matches. Use
`<ArkProvider onRedirectCallback={(to) => router.push(to)}>` with `next/router` on the Pages Router.
[`examples/nextjs`](examples/nextjs) is a complete App Router app (it builds and prerenders with
`next build`).

Signing in happens in the browser; the access token is not available to server components or
route handlers. If your Next.js server itself must call APIs as the user, use a server-side
client (`ark-oauth-client-node`) behind the app instead.

## Vue

```js
import { createApp } from 'vue';
import { createArk, createArkGuard } from 'ark-oauth-client-js/vue';

const ark = createArk({ authority: 'https://idp.example.com/my_idp', clientId: 'my-spa' });

createApp(App)
  .use(router) // router first: ark finds it and returns the user through router.replace()
  .use(ark)
  .mount('#app');

router.beforeEach(createArkGuard(ark, { requireMeta: true })); // guards routes with meta.requiresAuth
// { path: '/billing', component: Billing, meta: { requiresAuth: true, arkClaims: ['billing.admin'] } }
```

```vue
<script setup>
import { useArk } from 'ark-oauth-client-js/vue';
const { isAuthenticated, user, signinRedirect, signoutRedirect } = useArk();
</script>

<template>
  <button v-if="!isAuthenticated" @click="signinRedirect()">Sign in</button>
  <button v-else @click="signoutRedirect()">Sign out {{ user.email }}</button>
</template>
```

`useArk()` (or `$ark` in templates) gives computed refs (`status`, `isLoading`, `isAuthenticated`,
`user`, `arkClaims`, `scopes`, `error`, `denial`), the whole `state` as a shallow ref, and the
client's actions. Add a route for `/signin-oidc` that renders a "signing in" message. In Nuxt,
install the plugin from a client-only plugin file (`plugins/ark.client.ts`); on the server it
installs without starting, and the guard cancels rather than start a sign-in.
[`examples/vue`](examples/vue) is a complete Vite + vue-router app (it passes `vue-tsc` under `strict`).

## Angular

Angular 16+, standalone or NgModule, with or without zone.js:

```ts
// app.config.ts
import { provideArk, arkInterceptor } from 'ark-oauth-client-js/angular';

export const appConfig: ApplicationConfig = {
  providers: [
    provideArk({ authority: 'https://idp.example.com/my_idp', clientId: 'my-spa', apiOrigins: ['https://api.example.com'] }),
    provideHttpClient(withInterceptors([arkInterceptor])), // bearer token on your API calls only
    provideRouter(routes)
  ]
};

// app.routes.ts
import { arkAuthGuard, arkClaimsGuard, createArkGuard } from 'ark-oauth-client-js/angular';
export const routes: Routes = [
  { path: 'signin-oidc', component: SigningInComponent },
  { path: 'orders', canActivate: [arkAuthGuard], component: OrdersComponent },
  { path: 'billing', canActivate: [arkClaimsGuard('billing.admin')], component: BillingComponent },
  { path: 'payroll', canActivate: [createArkGuard({ claims: ['payroll'], onDenied: () => inject(Router).parseUrl('/no-access') })], component: PayrollComponent }
];
```

```ts
@Component({
  selector: 'app-header',
  template: `@if (ark.isAuthenticated()) { {{ ark.user()?.email }} <button (click)="ark.signoutRedirect()">Sign out</button> }
             @else { <button (click)="ark.signinRedirect()">Sign in</button> }`
})
export class HeaderComponent {
  ark = injectArk(); // signals: state(), status(), isAuthenticated(), user(), arkClaims(), error(), denial()
}
```

`provideArk` starts the client in an app initializer, so the sign-in callback is complete, and the
address bar already shows the page the user started from, before the router reads the URL. The
interceptor sends the token only to the app's origin and `apiOrigins`, and retries a 401 once
after a refresh. The adapter is plain JavaScript with functional guards and `inject()`, so it needs
no Angular compilation step.

With SSR (`ng new --ssr`), render the guarded routes on the client, since who is signed in is
known only in the browser: `{ path: 'billing', renderMode: RenderMode.Client }` in
`app.routes.server.ts`. A guard that does run on the server cancels the navigation without starting
a sign-in, and says so once in the server log. Angular itself then reports a prerendered route as
"The content returned was empty". [`examples/angular`](examples/angular) is a complete standalone
app.

## Svelte, Solid and the rest

The client is the integration. `client.state` is a Svelte store; `subscribe` / `getSnapshot` is
the contract every other framework's external-store hook takes.

```svelte
<script>
  import { ark } from './ark.js'; // new ArkBrowserClient({...}); ark.init();
  const state = ark.state;
</script>

{#if $state.isAuthenticated}
  Hello {$state.user.email} <button on:click={() => ark.signoutRedirect()}>Sign out</button>
{:else}
  <button on:click={() => ark.signinRedirect()}>Sign in</button>
{/if}
```

Solid: `const state = from((set) => ark.subscribe(set))`. Lit, Alpine, htmx, web components: call
`ark.subscribe(render)` and read `ark.getSnapshot()`.

## A plain `<script>` tag

No modules and no bundler: the IIFE build defines `window.ArkOAuth`.

```html
<script src="https://cdn.jsdelivr.net/npm/ark-oauth-client-js@2.4.1/dist/ark-oauth-client.global.min.js"></script>
<script>
  const ark = new ArkOAuth.ArkBrowserClient({ authority: 'https://idp.example.com/my_idp', clientId: 'my-spa' });
  ark.subscribe((s) => (document.title = s.isAuthenticated ? s.user.email : 'Signed out'));
  ark.init();
</script>
```

`dist/ark-oauth-client.esm.min.js` is the same as one ES module, for an import map. About 19 KB gzipped.

---

## The state and events

`ark.getSnapshot()` returns one immutable object, the same object until something changes:

| Field | |
|---|---|
| `status` | `'loading'` until `init()` finishes, then `'authenticated'`, `'unauthenticated'` or `'denied'` |
| `isLoading`, `isAuthenticated` | shorthands for the two statuses UIs branch on |
| `user` | the validated ID token claims (`sub`, `name`, `email`, ...) or `null` |
| `arkClaims` | the user's Ark authorization claims for this client, from the access token |
| `scopes` | the granted scopes |
| `expiresAt` | access token expiry, epoch seconds |
| `error` | the last failure (an `ArkError`), or `null` |
| `denial` | who was refused and why, when `status` is `'denied'` ([account switching](#account-switching-on-a-shared-browser)) |

There is deliberately no access token in it: read it per call with `getAccessToken()`, because the
client replaces it underneath you on every refresh.

`ark.on(event, handler)` returns an unsubscribe function. Events: `signedIn`, `signedOut`,
`tokensRefreshed`, `refreshFailed` (a network failure; the session is kept and retried),
`sessionExpired` (the refresh token was refused; the user must sign in again), `accessDenied`
and `error`.

`hasArkClaims(...claims)` (all) and `hasAnyArkClaim(...claims)` (any) are for showing and hiding
UI. They are not security: the API must check the token itself (`verifyAccessToken` in the Node
client, `RequireArkClaims` in .NET).

---

## Signing in

```js
await ark.signinRedirect();                                   // back to this page afterwards
await ark.signinRedirect({ returnTo: '/billing' });           // a local path; off-site values are ignored
await ark.signinRedirect({ prompt: 'login', loginHint: 'alice@example.com', maxAge: 300 });
const { user } = await ark.signinPopup();                     // the page never navigates
```

`signinPopup()` must be called straight from a click handler, before any `await`, or the browser
blocks the window (`ArkPopupError` with `reason: 'blocked'`). The popup lands on the redirect URI,
whose page is your app calling `init()`: it hands the response to the opener and closes. Fall back
to `signinRedirect()` when it is blocked.

What `init()` / `handleRedirectCallback()` check, in order: an `error` response becomes an
`ArkOAuthError`; `state` must match a sign-in this tab started (single use, ten minutes); `iss` must
be the provider (RFC 9207); the code is redeemed with the PKCE verifier only this tab holds; the ID
token is verified against the provider's published keys (Web Crypto), its issuer, audience, `exp`,
`iat`, `nonce`, `at_hash` and `c_hash`. The response parameters are removed from the address bar
either way, so a reload cannot replay them.

Afterwards the user is sent to the page they started from: through `onRedirectCallback(returnTo)`
when you pass one (your router's navigate), otherwise with `history.replaceState` and a `popstate`
event, which React Router and the Angular router follow. The Vue plugin and `ArkNextProvider` wire
their routers for you.

## Calling your API

```js
const res = await ark.fetch('/api/orders');                       // the app's own origin
const res2 = await ark.fetch('https://api.example.com/v1/orders', { method: 'POST', body });   // listed in apiOrigins
```

`ark.fetch` attaches `Authorization: Bearer …`, refreshes the token first when it is about to
expire, and retries a `401` with `error="invalid_token"` once after a refresh. It sends the token
**only** to the page's origin and to `apiOrigins`; any other URL throws rather than leak a bearer
token to a third party. Without a session it throws `ArkLoginRequiredError`.

With another HTTP library, ask for the token per request:

```js
axios.interceptors.request.use(async (config) => {
  if (ark.isApiUrl(config.url)) {
    const token = await ark.getAccessToken(); // null when signed out
    if (token) config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});
```

`ark.userInfo()` calls the provider's userinfo endpoint. The API itself validates the access token
(an RS256 `at+jwt` with `ark_claims`) with one of the server-side Ark clients.

## Signing out

```js
await ark.signoutRedirect();                      // this app and the provider; back to accountSwitch.homePath ('/')
await ark.signoutRedirect({ returnTo: '/bye' });
await ark.signoutLocal();                         // this app only; the provider session (and SSO) stays
```

`signoutRedirect()` drops the tokens, revokes the refresh token, and sends the browser to the
provider's end-session endpoint with `id_token_hint` (so Ark ends its session without asking) and
`post_logout_redirect_uri`. Both halves matter: drop only the local tokens and the provider's
session survives, so the next sign-in is silent, as the same person. Other tabs of the app are
signed out too.

## Account switching on a shared browser

Single sign-on is browser-wide. On a shared machine the next person opens the app, is signed in
as the previous one, and sees "no access", for an account that is not theirs, with no way out:
signing in again returns the same session. This is the same feature as `AccountSwitch` in .NET
and `accountSwitch` in Node, and it is **off by default**:

```js
const ark = new ArkBrowserClient({
  authority, clientId,
  accountSwitch: {
    requireArkClaims: true,
    requiredClaims: ['billing.admin'], // recommended: Ark puts identity names (email, sub) in ark_claims too
    appDisplayName: 'Billing'
  }
});
```

With it on, the access check moves to the callback: an account without the claims gets no stored
token, its refresh token is revoked, and the state becomes `denied` with `state.denial` naming the
account. Render the way out with `<ArkAccessDenied />` (React, and the default inside
`<RequireArk>`), `renderAccessDenied(element, ark)` (no framework; CSP-safe DOM, no innerHTML), or
your own page calling:

- `ark.switchUser()`: drops the local session and signs in with `prompt=login`, so the provider draws
  its sign-in form instead of answering from its session. With `endProviderSessionOnSwitch: true`
  the provider session is ended first (right for a kiosk).
- `ark.signoutRedirect()`: sign out completely.

`onEvaluateAccess({ claims, arkClaims, allowedByConfiguration })` replaces the rule with your own.
`ArkChallengeProperties.switchUser(returnTo)` / `.selectAccount()` build the sign-in options by hand.

---

## Configuration

| Option | Default | |
|---|---|---|
| `authority` | (required) | The issuer, `{BaseUrl}/{TenantId}`. Or `authServerUrl` + `tenantId`. |
| `clientId` | (required) | A public client. A `clientSecret` is refused: a browser cannot keep one. |
| `redirectUri` | `'/signin-oidc'` | A path on this origin, or an absolute URL. Matched byte for byte. |
| `postLogoutRedirectUri` | `'/signout-callback-oidc'` | `null` to leave it out (the provider then shows its own "signed out" page). |
| `scopes` | `openid profile email offline_access` | Unregistered scopes are rejected, not dropped. |
| `storage` | `'session'` | `'session'`, `'local'`, `'memory'` or a Storage-like object. See below. |
| `automaticRefresh` | `true` | Renew with the refresh token before expiry. |
| `refreshBeforeSeconds` | `60` | |
| `apiOrigins` | `[]` | Origins besides the app's own that may receive the access token. |
| `responseMode` | `'query'` | Or `'fragment'`. (`form_post` needs a server.) |
| `prompt`, `acrValues`, `extraAuthorizationParams` | | Sent on every sign-in. |
| `accountSwitch` | off | See [above](#account-switching-on-a-shared-browser). |
| `onRedirectCallback(returnTo)` | | Where to go after sign-in: your router's navigate. |
| `syncTabs` | `true` | Sign-out and token sync across tabs (BroadcastChannel). |
| `popup` | `{ width: 520, height: 680, timeoutMs: 300000 }` | |
| `requireHttps` | `true` | Refuses a plain-http authority except on localhost. |
| `clockToleranceSeconds` | `60` | |
| `timeoutMs` | `10000` | Per request. |
| `fetch`, `window`, `navigate`, `redirect` | browser globals | Seams for tests and for unusual hosts (Electron, Capacitor). |

Everything that can be checked without the network is checked when the client is created, with
an `ArkConfigError` that says what to change.

## Where tokens live, and how the session is renewed

**Storage.** `session` (the default) keeps tokens in sessionStorage: they survive a reload, stay
private to the tab, and go when it closes; each new tab signs in silently through the provider's
session. `local` shares one session across tabs and browser restarts. `memory` writes nothing,
so every reload goes back to the provider (silently, while its session lasts). The sign-in
transaction (state, nonce, PKCE verifier) always lives in sessionStorage, for ten minutes, single use.

Whichever you choose, script running on the page can use the session: storage changes how long a
stolen token is good for, not whether XSS can reach it. A strict Content-Security-Policy is what
stops XSS, and the library works under one: it uses no inline script and no `eval`, and the
built-in denied page styles itself through the CSSOM (verified under `script-src 'self';
style-src 'self'`). Keep access
tokens short-lived on the client record. If tokens must never reach the browser at all, put a
server-side client (a "backend for frontend") in front of the API.

**Renewal uses refresh tokens**, `refreshBeforeSeconds` before expiry, or half-way through the
token's life when that is shorter (so a client record with 30-second tokens does not refresh in a
loop). Ark rotates refresh tokens: each refresh returns a new one and retires the old, and
presenting a retired one is treated as theft, so the whole family is revoked. The client is built
around that:

- refreshes are serialised across tabs (Web Locks) and across instances on one page, and the one
  that waited re-reads storage and adopts the new tokens rather than replaying the old ones;
- the new refresh token is stored the moment the server returns it, before the ID token that came
  with it is checked, so a failure after that point (JWKS unreachable) cannot lead to a replay;
- "Duplicate tab" copies sessionStorage, refresh token included. The client keeps hashes of spent
  refresh tokens in localStorage, so the copy that comes second signs in afresh (silently, while
  SSO lasts) instead of presenting the token the other tab already redeemed.

Hidden-iframe renewal (`prompt=none` in an iframe) is not used: Ark's authorization endpoint sends
`Content-Security-Policy: frame-ancestors 'self'`, which refuses to be framed by another origin, and
third-party cookie blocking defeats it in Safari and Firefox anyway. Without `offline_access` there
is no refresh token, and the session ends when the access token does.

Revocation (`/oauth2/revoke`) grants no CORS on the Ark server, so the client sends it as a
CORS-safelisted `no-cors` POST: delivered, response unread (RFC 7009 answers 200 either way).
Sign-out does not depend on it: ending the provider session also ends every refresh token issued
under it.

## Checking the setup

```js
const report = await ark.checkSetup();
// { discoveryOk, jwksOk, tokenEndpointCorsOk, redirectUri, provider: {...}, signingKeys: [...], problems: [...] }
```

It fetches discovery and JWKS and probes the token endpoint with a refresh token that cannot exist
(an OAuth error back proves the endpoint answers this origin; a network error means CORS). It also
checks the secure context, S256, scopes, response mode, `none` auth and PAR. `problems` is in
sentences; render it on a setup page.

## Errors

Everything thrown is an `ArkError`; the same names as the Node client.

| Class | When |
|---|---|
| `ArkConfigError` | Misconfiguration: thrown when the client is created, or naming the setting to change. |
| `ArkOAuthError` | The server (or the authorization response) said `error=…`. `.error` is the code (`access_denied`, `invalid_grant`, `login_required`, ...), plus `.errorDescription`, `.status`, `.endpoint`. |
| `ArkTokenError` | A token came back but did not validate (`.claim` names which check). Never retry. |
| `ArkCallbackError` | The response cannot be tied to a sign-in from this tab (state, iss). |
| `ArkNetworkError` | No response: offline, timeout, or (in a browser, most often) CORS. The message says which. |
| `ArkLoginRequiredError` | `ark.fetch()` with nobody signed in. |
| `ArkPopupError` | `.reason`: `blocked`, `closed` or `timeout`. |

## Troubleshooting

| Symptom | Cause |
|---|---|
| `Failed to fetch` / `ArkNetworkError` mentioning CorsOrigins | The app's origin is not in `ark_oauth_server:Oidc:CorsOrigins`. |
| "redirect_uri does not match" on the provider | The registered URI differs by a character: scheme, port, trailing slash, path. Compare `checkSetup().redirectUri`. |
| The password "is wrong" but it is right | The user is not mapped to this client. |
| `invalid_scope` | A scope the client record does not list (they are a whitelist). |
| Signed out after every reload | `storage: 'memory'`, blocked storage, or no `offline_access` and an expired token. |
| Signed out in all tabs at once, randomly | Something presented a retired refresh token (a copy of the tokens used elsewhere). The client never does; check for code reading the stored token set. |
| "crypto.subtle is unavailable" | The page is not a secure context: use https, or http only on localhost. |
| The callback route shows "not found" | Add a route at the redirect path (`<ArkCallback>`), and history fallback on the host. |
| Sign-in loops between the app and the provider | Not from this library's guards (they stop on errors). Check that nothing calls `signinRedirect()` while `state.error` is set. |
| "the tenant requires pushed authorization requests" | PAR needs client authentication; a browser cannot do it. Turn it off for this client. |

## What it implements

- Authorization code flow with PKCE (S256) as a public client (OAuth 2.1), redirect or popup
- `state` (constant-time, single use, per tab), `nonce`, RFC 9207 `iss`
- ID token validation in the browser: RS/PS/ES 256/384/512 via Web Crypto, issuer, audience,
  `azp`, `exp`/`nbf`/`iat` with tolerance, `nonce`, `at_hash`, `c_hash`, `auth_time` for `max_age`,
  same `sub` on refresh (OIDC Core §12.2); `alg: none` and HMAC never accepted
- Discovery (both well-known spellings) with the issuer check; JWKS caching with rotation and a
  rate-limited refetch for an unknown `kid`
- Refresh token rotation, coordinated across tabs (Web Locks) and instances; automatic renewal
- RP-initiated logout with `id_token_hint`; token revocation (RFC 7009)
- UserInfo; `fetch` with origin allow-list and 401 retry
- Account switching (`prompt=login`), access check at the callback
- Cross-tab sign-out (BroadcastChannel); SSR-safe construction

## Development

```bash
npm install
npm test            # node --test: the client against a stub Ark IdP, plus the React, Vue and Angular adapters
npm run typecheck   # the .d.ts files, against real React, Vue and Angular types
npm run build       # dist/ (IIFE + ESM bundles); runs on npm pack
```

The tests run against `test/stub-idp.js`, which mirrors the real server's wire behaviour (CORS only
where Ark grants it, rotation with family revocation, `iss`, `at_hash`/`c_hash`), in a fake browser
window (`test/browser-env.js`) so redirect and popup flows run end to end in Node. The library has
also been run against a real `Ark.oAuth.Oidc.Host` in Chrome and WebKit; [`examples/`](examples)
holds the apps used for that.

MIT licensed.
