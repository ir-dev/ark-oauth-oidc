# Changelog

## 2.4.0

No change to this package. It has the same code, API and options as 2.3.0 and is published at the
family's version. In this release the provider, `Ark.oAuth.Oidc`, is built to hold 30,000
signed-in users and to run on more than one instance: its lookups use indexes, it keeps clients,
scopes and signing keys in memory for a short time, and its instances share one data-protection key
ring through the database.

There is nothing to do when you upgrade. The provider's endpoints, tokens and discovery document are
the same in 2.4.0 as in 2.3.0. This client therefore behaves the same against a 2.3.0 provider and a
2.4.0 one, and you can upgrade the two in either order. The requirements are unchanged: Node 20 or
later, ESM, and no runtime dependencies. The built-in access-denied page names
`ark-oauth-client-node 2.4.0` in its footer.

## 2.3.0

No change to this package. It has the same code, API and options as 2.2.1 and is published at the
family's version. In this release the .NET packages, `Ark.oAuth.Oidc` and `Ark.oAuth.Client`, move
to .NET 10 and EF Core 10.

There is nothing to do when you upgrade. The provider's endpoints, tokens and discovery document are
the same in 2.3.0 as in 2.2.x. This client therefore behaves the same against a 2.2.x provider and a
2.3.0 one, and you can upgrade the two in either order. The requirements are unchanged: Node 20 or
later, ESM, and no runtime dependencies. The built-in access-denied page names
`ark-oauth-client-node 2.3.0` in its footer.

If you are still on the old package name, `ark-oauth-client` (up to 2.1.8), the move to this name is
described under 2.2.0 below.

## 2.2.1

2.2.0 republished through the repository's release workflow. The published files differ from 2.2.0
only in the version number.

## 2.2.0

**Renamed to `ark-oauth-client-node`.** Up to 2.1.8 this package was published as
`ark-oauth-client`. That name is deprecated and gets no further releases. The new name makes the
package distinct from the Python `ark-oauth-client` on PyPI and the browser `ark-oauth-client-js`.

```bash
npm uninstall ark-oauth-client
npm install ark-oauth-client-node
```

Then change the import specifier from `'ark-oauth-client'` to `'ark-oauth-client-node'`, and
`'ark-oauth-client/express'` to `'ark-oauth-client-node/express'`. There is no API change: the
same exports, options and types, and session data and the denial cookie are read as before.

The built-in access-denied page names the package in its footer as `ark-oauth-client-node 2.2.0`.

Published with `Ark.oAuth.Oidc` 2.2.0, a security release. Upgrade the provider too. Its single
sign-on sessions from before the upgrade are not recognised, so every user signs in at the provider
once more.

## 2.1.1

The first release of the Node client published to npm, at the version `Ark.oAuth.Client` and the
Python `ark-oauth-client` already carry. It catches up with 2.1.0 on both and fixes what a review
before publishing found.

**Account switching on a shared browser**, as in the .NET and Python 2.1.0 releases. Everything is
off or unchanged by default:

* `accountSwitch.requireArkClaims` moves the entitlement check to the callback. An account with no
  `ark_claims` for this client is refused before any session is written, and its refresh token is
  revoked.
* A built-in access-denied page at `/ark/no-access`. It names the signed-in account and offers
  "Sign in as a different user", which challenges with `prompt=login`, and "Sign out completely".
  It has no script, a strict CSP, and the library version in its footer. A browser that is signed
  in but lacks a guarded claim lands here instead of on a bare 403.
* `/ark/switch-user` and `/ark/sign-out` accept only a same-origin POST.
* `req.ark.switchUser()`, `signOutEverywhere()`, `signOutLocally()` and `deniedAccount()`, and
  `ArkChallengeProperties`. The `events.onEvaluateAccess` and `events.onAccessDenied` hooks let
  you supply your own rule or your own page. The denial cookie uses the Python client's format
  byte for byte.

**Also new**

* `ArkAuthConfig.fromMapping` binds an `appsettings.json` `ark_oauth_client` section unchanged, in
  C#, camel or snake spelling.
* `auth.checkSetup(req)` reports the redirect URI the request would really send. The report also
  names the tenant, admin console and integration page.
* `VERSION`, read from package.json.

**Fixed**

* A request that waited on another request's refresh kept the retired refresh token in its copy of
  the session. With any store that copies (Redis, a database), its next token read presented that
  token again, and the provider revoked the whole family. Every waiter now receives the rotated
  tokens, and a refresh re-reads the store first.
* A refresh that failed for a transient reason threw, which failed the request. It now keeps the
  session, and the next request tries again.
* `usePar` defaulted to `false`, which hid the tenant's `require_pushed_authorization_requests`.
* `extraAuthorizationParams` / `extra` could replace `state`, `nonce`, the PKCE challenge or the
  redirect URI. Protocol parameters now win.
* The client-credentials cache ignored the secret. A caller presenting a wrong secret was handed a
  token another caller had obtained with the right one.
* A bearer challenge copied error text, including a forged token's `kid`, into
  `WWW-Authenticate`. A CR/LF there made `setHeader` throw inside an async handler. That text is
  now escaped.
* `form_post` bodies are capped at 64 KiB, values are taken as strings only, and `state` is looked
  up as an own property.
* `trustProxy` honoured `X-Forwarded-Host` without `X-Forwarded-Proto`. It now needs both, as the
  Python client does.
* `responseMode: 'form_post'` with a `SameSite=Lax` cookie can never complete a sign-in. It is now
  refused at startup.
* Non-numeric `nbf`/`iat` claims, and token segments that are not JSON objects, are rejected.
  Before, they were skipped or surfaced as a `TypeError`.
* A provider error sent back without `state` was reported as "could not be matched to a request
  from this browser". The provider's own `error` and description are now shown. The error is
  displayed only; nothing is redeemed.
* The set of unknown `kid`s is bounded, and device-grant polling no longer leaks abort listeners.
* `refreshLeewaySeconds` now defaults to 120, the .NET and Python window.

Requires Node 20+. Still no runtime dependencies.
