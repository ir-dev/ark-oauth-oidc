# ark-oauth-client

The OAuth 2.1 / OpenID Connect client for **Node.js** applications talking to an
[ARK Identity Server](../README.md).

There is one URL to configure — the issuer, `{BaseUrl}/{TenantId}`. Endpoints, signing keys and
capabilities are read from the provider's discovery document, so the application does not have to
be redeployed when a key rotates or an endpoint moves.

No runtime dependencies. Everything is built on `node:crypto` and the global `fetch`.

```bash
npm install ark-oauth-client
```

---

## Contents

- [Quick start](#quick-start)
- [What it implements](#what-it-implements)
- [Configuration](#configuration)
- [The middleware](#the-middleware)
- [Protecting an API](#protecting-an-api)
- [Sessions](#sessions)
- [Using the client directly](#using-the-client-directly)
- [Checking the setup](#checking-the-setup)
- [Errors](#errors)
- [Registering the client](#registering-the-client)
- [Security notes](#security-notes)
- [Troubleshooting](#troubleshooting)
- [Development](#development)

---

## Quick start

```js
import express from 'express';
import { arkExpress } from 'ark-oauth-client';

const app = express();

const auth = arkExpress({
  authority: 'https://idp.example.com/my_idp',   // {BaseUrl}/{TenantId}
  clientId: 'my-app',
  clientSecret: process.env.ARK_CLIENT_SECRET,   // omit for public clients
  redirectUri: 'https://app.example.com/signin-oidc',
  postLogoutRedirectUri: 'https://app.example.com/',
  secret: process.env.ARK_SESSION_SECRET         // signs the session cookie
});

app.use(auth);                                    // serves /login, /signin-oidc and /logout

app.get('/', (req, res) => {
  res.send(req.ark.isAuthenticated ? `Hello ${req.ark.user.name}` : '<a href="/login">Sign in</a>');
});

app.get('/billing', auth.requireClaims('billing.admin'), (req, res) => res.send('billing'));

app.listen(3000);
```

That is the whole integration. Authorization code + PKCE, `state`, `nonce`, `iss`, `at_hash`,
JWKS rotation, silent token refresh and sign-out are handled underneath.

Runnable versions of this and every other flow are in [`examples/`](examples/) — `examples/web-app.js`
needs no dependencies at all.

---

## What it implements

| Specification | What the client does |
|---|---|
| OpenID Connect Discovery 1.0 | Reads and caches `/.well-known/openid-configuration`; verifies `issuer` matches the configured authority |
| RFC 8414 metadata | Falls back to the `oauth-authorization-server` spelling for other providers |
| Authorization code (RFC 6749) | The only interactive flow; implicit and hybrid are gone in OAuth 2.1 and are not offered |
| PKCE (RFC 7636) | Always sent, `S256` only, verifier from `crypto.randomBytes` |
| OpenID Connect Core 1.0 | ID token verification: signature, `iss`, `aud`, `azp`, `exp`, `nbf`, `iat`, `nonce`, `at_hash`, `c_hash`, `auth_time`/`max_age` |
| RFC 7517 JWKS | Cached, and refetched on an unseen `kid`, so a two-phase key rotation needs no restart |
| RFC 9068 access tokens | `typ: at+jwt` enforced, so an ID token cannot be presented to an API in its place |
| Refresh (RFC 6749 §6) | Rotation-aware, scope narrowing, one refresh per session at a time |
| Client credentials | With per-client-and-scope caching |
| Device grant (RFC 8628) | Polling that handles `authorization_pending` and `slow_down` |
| PAR (RFC 9126) | `usePar: true`, or automatically when the tenant requires it |
| Introspection (RFC 7662) | With client authentication |
| Revocation (RFC 7009) | Called on sign-out, so the refresh-token family really ends |
| RP-Initiated Logout 1.0 | `id_token_hint`, `post_logout_redirect_uri`, `state` |
| RFC 9207 `iss` | Checked on every authorization response |
| Dynamic registration (RFC 7591/7592) | Register, read and delete |
| Client authentication | `client_secret_basic`, `client_secret_post`, `private_key_jwt`, `none` |

Ark's per-user-per-client authorization claims (`ark_claims` in the access token) are surfaced as
`req.ark.claims`, and are what `requireClaims()` checks.

---

## Configuration

Only `authority` and `clientId` are required; `redirectUri` too for interactive sign-in.

| Option | Default | Meaning |
|---|---|---|
| `authority` | — | The issuer URL: `{BaseUrl}/{TenantId}` |
| `authServerUrl` + `tenantId` | — | Alternative to `authority`; joined for you, matching the .NET client's config shape |
| `clientId` | — | The client id registered with the tenant |
| `clientSecret` | `null` | Confidential clients only. Omit for SPA, native and CLI clients |
| `tokenEndpointAuthMethod` | derived | `client_secret_basic` when a secret is set, `private_key_jwt` when a key is, otherwise `none` |
| `privateKeyJwt` | `null` | `{ privateKey, kid, alg }` — PEM, JWK or `KeyObject` |
| `redirectUri` | — | Absolute, no fragment, `https` unless loopback. The server matches it **exactly** |
| `postLogoutRedirectUri` | — | Must also be registered |
| `scopes` | `openid profile email offline_access` | `offline_access` is what earns a refresh token |
| `audience` | `null` | Expected `aud` when verifying access tokens in an API |
| `usePar` | `false` | Push authorization parameters over the back channel |
| `responseMode` | `query` | `query`, `fragment` or `form_post` |
| `prompt`, `acrValues`, `extraAuthorizationParams` | — | Passed through to `/authorize` |
| `clockToleranceSeconds` | `60` | Leeway on `exp`, `nbf` and `iat` |
| `requireHttps` | `true` | Only ever `false` for local development |
| `requireTokenHashes` | `true` | Require `at_hash`/`c_hash`; Ark always sends them |
| `timeoutMs` | `10000` | Per-request timeout |
| `metadataTtlMs`, `jwksTtlMs` | `300000` | Cache lifetimes, matching the server's `max-age=300` |
| `jwksMinRefreshIntervalMs` | `10000` | How soon an unseen `kid` may trigger another JWKS fetch |
| `fetch` | global | Inject your own for tracing, proxies or tests |

Mistakes here are caught at construction, not at a user's sign-in: a `redirectUri` with a fragment,
a plain-http authority, `private_key_jwt` with no key, a `clientSecret` alongside
`tokenEndpointAuthMethod: 'none'`.

---

## The middleware

`arkExpress(options)` returns a plain Connect-style middleware. It works with Express, with
`@fastify/middie`, with `koa-connect`, and with a bare `http.createServer` — the package depends on
none of them.

It claims three paths and passes everything else through:

| Path | Purpose |
|---|---|
| `loginPath` (`/login`) | Starts a sign-in. `?returnTo=/somewhere` comes back to that page — same-origin paths only |
| `callbackPath` (path of `redirectUri`, else `/signin-oidc`) | Completes it |
| `logoutPath` (`/logout`) | Revokes the refresh token, destroys the session, clears the cookie, then redirects to the provider's `end_session_endpoint` |

### `req.ark`

| Member | |
|---|---|
| `isAuthenticated` | |
| `user` | ID token claims, plus UserInfo when `fetchUserInfo: true` |
| `sub` | |
| `claims` | Ark authorization claims — **what to authorise on** |
| `scopes` | Granted scopes |
| `tokens` | The `TokenSet` |
| `await accessToken()` | The access token, renewed first if it is close to expiring |
| `await authorize(headers?)` | Returns headers with `Authorization: Bearer …` set, for a downstream call |
| `hasClaim(…)`, `hasScope(…)` | |
| `await login({ returnTo })`, `await logout()` | Drive the flows from your own routes |

### Guards

```js
app.get('/account',  auth.requireAuth(),                     handler);
app.get('/billing',  auth.requireClaims('billing.admin'),    handler);
app.get('/reports',  auth.requireScopes('reports.read'),     handler);
app.get('/admin',    auth.requireAuth({ claims: ['tenant.root'], scopes: ['admin'] }), handler);
```

An unauthenticated **browser** request is redirected to the login page with a `returnTo`. Anything
else — `fetch`, XHR, a mobile client — gets `401` with an RFC 6750 challenge, because redirecting a
background request to a sign-in page produces a CORS error rather than anything the caller can act
on. A signed-in user missing a claim gets `403`, never a redirect loop.

### Middleware options

| Option | Default | |
|---|---|---|
| `secret` | — | **Required**, 16+ characters. Signs the session cookie. Same value on every instance |
| `client` | — | Reuse an existing `ArkOAuthClient` instead of configuring one here |
| `store` | `MemorySessionStore` | See [Sessions](#sessions) |
| `cookieName` | `ark_session` | |
| `cookie` | `{ httpOnly: true, secure: true, sameSite: 'Lax', path: '/' }` | `secure: false` only for local http |
| `sessionTtlSeconds` | `28800` | Matches the server's default session lifetime |
| `refreshLeewaySeconds` | `60` | Renew the access token this long before it expires |
| `fetchUserInfo` | `false` | Also call `/userinfo` at sign-in and merge it into `req.ark.user` |
| `defaultReturnTo` | `/` | |
| `errorPath` | `null` | Where a failed sign-in lands, with `?auth_error=…`. Otherwise a plain 400 |
| `onError` | `null` | `(error, req, res, next)` — full control instead of `errorPath` |
| `trustProxy` | `true` | Honour `X-Forwarded-Proto` / `X-Forwarded-Host` when deriving this app's own origin |

---

## Protecting an API

```js
import { arkBearer } from 'ark-oauth-client';

const bearer = arkBearer({
  authority: 'https://idp.example.com/my_idp',
  clientId: 'my-api',
  audience: 'my_idp_api'          // omit to skip the audience check
});

app.use('/api', bearer);
app.get('/api/me', (req, res) => res.json({ sub: req.ark.sub, claims: req.ark.claims }));
app.get('/api/reports', bearer.require({ claims: ['reports.read'] }), handler);
```

Verification is local, against the cached JWKS, so a request costs no round trip to the identity
server. `optional: true` lets anonymous requests through with `req.ark.isAuthenticated === false`.

---

## Sessions

Tokens never reach the browser. The cookie carries an opaque session id and an HMAC over it;
the access token, refresh token and claims stay server-side in a store.

`MemorySessionStore` is the default and is fine for one process. Behind a load balancer, or across
a restart, supply a shared store — any object with these methods:

```js
const redisStore = {
  async get(id)                { const v = await redis.get(`ark:${id}`); return v ? JSON.parse(v) : null; },
  async set(id, data, ttl)     { await redis.set(`ark:${id}`, JSON.stringify(data), { EX: ttl }); },
  async destroy(id)            { await redis.del(`ark:${id}`); },
  async touch(id, ttl)         { await redis.expire(`ark:${id}`, ttl); }
};

const auth = arkExpress({ /* … */, store: redisStore });
```

One thing to know when you do. This server **rotates refresh tokens**, and presenting a retired one
is treated as theft of the whole family. Concurrent refreshes within a process are serialised for
you; across processes they are not, so a shared store should also carry a short lock around the
refresh if your traffic can put two requests for the same session on two instances at the same
instant.

---

## Using the client directly

For CLIs, workers, Fastify/Koa/Hapi, or any flow the middleware does not cover.

```js
import { ArkOAuthClient } from 'ark-oauth-client';

const client = new ArkOAuthClient({ authority, clientId, clientSecret, redirectUri });
```

### Authorization code by hand

```js
// 1. starting a sign-in
const tx = await client.createAuthorizationUrl({ returnTo: '/dashboard' });
// store tx (state, nonce, codeVerifier) server-side, keyed to this browser
redirect(tx.url);

// 2. on the callback
const tokens = await client.handleCallback(req.query, tx);
tokens.accessToken; tokens.idToken; tokens.refreshToken;
tokens.claims;        // validated ID token claims
tokens.arkClaims();   // Ark authorization claims
```

`state`, `nonce` and `codeVerifier` are the entire security of the flow. Keep them somewhere the
user cannot read or edit — a hidden form field or a plain cookie hands an attacker exactly the
three values the checks are made of.

### Refresh

```js
const next = await client.refresh(tokens.refreshToken);   // store what comes back: the old one is now dead
```

### Client credentials

```js
const token = await client.clientCredentials({ scopes: ['reports.read'] });   // cached until near expiry
```

### Device grant

```js
const authorization = await client.deviceAuthorization({ scopes: ['openid', 'profile'] });
console.log(`Go to ${authorization.verification_uri} and enter ${authorization.user_code}`);
const tokens = await client.pollDeviceToken(authorization);
```

### The rest

```js
await client.userInfo(accessToken);
await client.introspect(token, { tokenTypeHint: 'refresh_token' });
await client.revoke(refreshToken);
await client.endSessionUrl({ idTokenHint: tokens.idToken, state });
await client.verifyAccessToken(token, { scopes: ['reports.read'], arkClaims: ['billing.admin'] });
await client.verifyIdToken(idToken, { nonce });
await client.pushAuthorizationRequest(params);
await client.registerClient(metadata, initialAccessToken);
```

---

## Checking the setup

```js
const report = await client.checkSetup();
if (report.problems.length) console.warn(report.problems);
```

Pairs local configuration with the provider's live metadata and returns what does not line up:
a wrong port, a stopped provider, an issuer mismatch, a scope this client is not registered for, an
authentication method the tenant does not offer, PAR required but not enabled. Render it on a health
page, or run `node examples/setup-check.js` in CI. Without it, the first symptom of any of these is
`invalid_request` on a page a user is looking at.

---

## Errors

Every error carries what is needed to decide what to do next, rather than a string to grep.

| Class | Meaning | Usual response |
|---|---|---|
| `ArkConfigError` | This application is misconfigured | Fix and redeploy; thrown at construction where possible |
| `ArkOAuthError` | The server refused. `.error` is the RFC 6749 code, `.status` the HTTP status, `.endpoint` the URL | Branch on `.error` |
| `ArkTokenError` | A token failed validation — signature, issuer, audience, expiry, `nonce`, `at_hash` | Never retry. The answer cannot be trusted |
| `ArkCallbackError` | The authorization response does not belong to a request this client started | Treat as CSRF or a mix-up attempt |
| `ArkNetworkError` | The call did not complete: refused, DNS, timeout | Retry with backoff |

```js
import { ArkOAuthError } from 'ark-oauth-client';

try {
  await client.refresh(token);
} catch (error) {
  if (error instanceof ArkOAuthError && error.error === 'invalid_grant') signInAgain();
  else throw error;
}
```

---

## Registering the client

In the admin console at `/{tenant}/admin`, or from the generated setup page at
`/{tenant}/oauth2/integrate/{client_id}`:

| Field | Value |
|---|---|
| Redirect URI | Exactly your `redirectUri`, e.g. `https://app.example.com/signin-oidc` |
| Post-logout redirect URI | Your `postLogoutRedirectUri` |
| Grant types | `authorization_code`, `refresh_token` |
| Scopes | `openid`, `profile`, `email`, `offline_access` |
| Auth method | `none` for a public client, `client_secret_basic` for a confidential one |

Then **give each user access to the client**. Ark maps users to clients explicitly, and without a
mapping sign-in fails in a way that looks exactly like a wrong password.

A server-side Node application needs nothing in the tenant's `CorsOrigins` — that list is for
browser clients redeeming their own codes.

---

## Security notes

- **Tokens never reach the browser.** The cookie is an opaque id plus a signature; it is `HttpOnly`,
  `Secure` and `SameSite=Lax`.
- **The session id is replaced at sign-in**, so an id planted before authentication is never the one
  that ends up authenticated.
- **`state` is compared in constant time**, and `iss` is checked on every authorization response.
- **A missing `nonce` or `at_hash` fails as hard as a wrong one.** Absence is the easiest check to
  skip and the easiest one to attack.
- **`alg: none` is refused**, and the accepted algorithms are decided before the token's own header
  is read.
- **JWKS refetching is rate-limited**, and a `kid` already known to be absent never triggers another
  fetch — otherwise a stream of forged tokens turns this client into a request amplifier pointed at
  your identity server.
- **`returnTo` accepts same-origin paths only**, so the login route cannot become an open redirect.
- **Sign-out revokes the refresh token** before ending the local session.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `redirect_uri does not match a registered value` | The registered value differs by a character — scheme, port, trailing slash. Matching is exact, with one carve-out for loopback ports |
| Sign-in fails as though the password were wrong | The user has no access mapping to this client |
| `this sign-in could not be matched to a request from this browser` | The login expired (10 minutes), or the process restarted with the in-memory store |
| `invalid_grant` on the second refresh | A retired refresh token was presented; the family is revoked. Always store what a refresh returns |
| `the provider … identifies itself as '…'` | `authority` is not the issuer. It is `{BaseUrl}/{TenantId}`, tenant id included |
| `no key with kid '…' is published` | A token from a different provider — or a rotation more than `jwksMinRefreshIntervalMs` ago that has not been refetched yet |
| `unable to verify the first certificate` in development | The provider's development certificate is not trusted by Node. Trust it, or set `NODE_TLS_REJECT_UNAUTHORIZED=0` **locally only** |

---

## Development

```bash
npm test          # 94 tests, no install required
```

The suite runs against `test/stub-idp.js`, an in-process stand-in for the Ark server that mirrors
its wire behaviour: the same paths, RS256 with a `kid` and two keys across a rotation, `at+jwt`
access tokens carrying `ark_claims`, ID tokens with `at_hash`/`c_hash`, `iss` on the authorization
response, refresh-token rotation where a replay revokes the family, and RFC 6749 §5.2 error bodies.
It is useful in your own tests too.

**Requirements:** Node 20 or newer. ESM; on Node 22.12+ `require()` of this package works as well.

**License:** MIT.
