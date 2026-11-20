# Changelog

## 2.2.0

No API change. Published at the family's version, with `Ark.oAuth.Oidc` 2.2.0, a security
release. Upgrade the provider too. Its single sign-on sessions from before the upgrade are not
recognised, so every user signs in at the provider once more.

The Node client this package mirrors is now published as `ark-oauth-client-node` (formerly
`ark-oauth-client`). The docs and the `ArkConfigError` message for a client secret in the browser
use the new name.

## 2.1.1

The first release of the browser client, at the version the .NET, Python and Node clients carry.
It is the fourth port in the family: the same names wherever the concepts are shared (`TokenSet`,
`ArkOAuthError`, `accountSwitch`, `ArkChallengeProperties`, `checkSetup()`), for single-page apps
that sign in from the browser.

**The client.** `ArkBrowserClient`, framework-agnostic, with no runtime dependencies.

* Authorization code + PKCE (S256) as a public client, by redirect or popup. `state` is per tab,
  single use and compared in constant time; `iss` is checked (RFC 9207).
* The ID token is verified in the browser with Web Crypto: signature (RS/PS/ES), issuer,
  audience, `azp`, times, `nonce`, `at_hash`, `c_hash`, `max_age`, and the same `sub` on refresh.
  JWKS rotation is followed, with a rate-limited refetch for an unknown `kid`.
* Rotating refresh tokens renew the session before expiry, or half-way through a short token's
  life. Ark revokes the whole family on a replay, so the client never presents a spent token:
  * refreshes are serialised across tabs (Web Locks) and across instances on one page, which
    re-read storage first;
  * a rotated token is stored before the response is validated;
  * a duplicated tab recognises a refresh token its twin has already redeemed, from hashes kept in
    localStorage.
* `fetch()` attaches the bearer token to the app's origin and `apiOrigins` only, and retries a 401
  once after a refresh.
* `signoutRedirect()` revokes and ends the provider session with `id_token_hint`, so there is no
  confirmation page. `signoutLocal()` ends only this app's session. Other tabs are signed out too.
* Account switching, off by default as in the other clients: `accountSwitch.requireArkClaims` and
  `requiredClaims` refuse an account at the callback without storing a token. `switchUser()`
  signs in with `prompt=login`. `renderAccessDenied()` draws the dead end, with CSP-safe DOM.
* `checkSetup()` proves CORS from the page: it fetches discovery and JWKS and sends a harmless
  token-endpoint probe.
* Safe to create during server-side rendering. Nothing touches `window` until `init()`.
  `isBrowser` tells the two apart. The Angular and Vue route guards cancel on the server instead
  of starting a sign-in, and the Angular one names the fix (`RenderMode.Client`) once.
* Configuration that a browser cannot use safely is refused when the client is created: a client
  secret, `private_key_jwt`, PAR, `form_post` and a plain-http authority. The error explains why.

**Adapters.**

* `ark-oauth-client-js/react`: `ArkProvider`, `useArk`, `useArkUser`, `RequireArk`,
  `ArkCallback`, `ArkAccessDenied`. React 18/19, StrictMode and SSR safe.
* `ark-oauth-client-js/next`: the React adapter plus `ArkNextProvider` (App Router navigation).
* `ark-oauth-client-js/vue`: `createArk` plugin, `useArk` composable and the `createArkGuard`
  router guard.
* `ark-oauth-client-js/angular`: `provideArk`, `injectArk` (signals), `arkAuthGuard`,
  `arkClaimsGuard`, `createArkGuard` and `arkInterceptor`. Angular 16+, no compilation step.
* `client.state` is a Svelte store. `subscribe` / `getSnapshot` serve every other framework.
* `dist/ark-oauth-client.global.min.js` provides `window.ArkOAuth` for a plain `<script>` tag.

**Server behaviour this client is built around**, all checked against `Ark.oAuth.Oidc`:

* CORS is granted on discovery, JWKS, token and userinfo only. Revocation is therefore sent
  `no-cors`, and PAR is unavailable.
* `/authorize` sends `frame-ancestors 'self'`, so renewal uses refresh tokens, not hidden iframes.
* `id_token_hint` is accepted past ID-token expiry, so sign-out keeps the last one.
