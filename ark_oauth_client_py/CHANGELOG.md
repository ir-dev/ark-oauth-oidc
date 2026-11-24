# Changelog

## Next release

Agent-to-agent (A2A). Additive: nothing existing changes, and nothing here is used until you call
it. It needs a provider that has A2A (`Ark.oAuth.Oidc`, same release).

- `ArkOAuthClient.agent_token(audience, subject_token=None, scopes=())` returns a token addressed
  to another agent. Without `subject_token` the client calls as itself (`client_credentials` with
  `audience`). With it, the client calls on behalf of that user (token exchange, RFC 8693). Tokens
  are cached per target and per user until shortly before they expire.
- `ArkOAuthClient.verify_agent_token(token)` is `verify_access_token` with the audience fixed to
  this client's own `client_id`.
- `agent_actors(payload)` reads the `act` chain, newest first.
- Flask: `add_ark_agent_api(app, prefix, ...)` and `ArkBearer(agent=True)` accept only tokens
  addressed to this agent. `current_ark.actors` is available on a bearer request, and
  `current_ark.agent_token(audience)` gets a token on behalf of the signed-in user.
- `ArkOAuthClient.agent_card_security(spec=None)` returns the security section for an A2A Agent
  Card.
- New exports: `agent_actors`, `TOKEN_EXCHANGE_GRANT`, `ACCESS_TOKEN_TYPE`.

## 2.4.1

No change to this package. It has the same code, API and dependencies as 2.4.0 and is published at
the family's version. In this release the provider, `Ark.oAuth.Oidc`, gains webhooks: an opt-in
module that a host turns on with `AddArkWebhooks()` and that delivers identity events (sign-ins,
tokens, user and client changes) to endpoints configured in its admin console.

There is nothing to do when you upgrade. The provider's endpoints, tokens and discovery document are
the same in 2.4.1 as in 2.4.0. This client therefore behaves the same against a 2.4.0 provider and a
2.4.1 one, and you can upgrade the two in either order. The requirements are unchanged: Python
`>=3.9` and `cryptography>=49.0.0` (`>=46.0.6` on Python 3.9.0/3.9.1). The built-in access-denied
page names `ark-oauth-client 2.4.1` in its footer.

## 2.4.0

No change to this package. It has the same code, API and dependencies as 2.3.0 and is published at
the family's version. In this release the provider, `Ark.oAuth.Oidc`, is built to hold 30,000
signed-in users and to run on more than one instance: its lookups use indexes, it keeps clients,
scopes and signing keys in memory for a short time, and its instances share one data-protection key
ring through the database.

There is nothing to do when you upgrade. The provider's endpoints, tokens and discovery document are
the same in 2.4.0 as in 2.3.0. This client therefore behaves the same against a 2.3.0 provider and a
2.4.0 one, and you can upgrade the two in either order. The requirements are unchanged: Python
`>=3.9` and `cryptography>=49.0.0` (`>=46.0.6` on Python 3.9.0/3.9.1). The built-in access-denied
page names `ark-oauth-client 2.4.0` in its footer.

## 2.3.0

No change to this package. It has the same code, API and dependencies as 2.2.1 and is published at
the family's version. In this release the .NET packages, `Ark.oAuth.Oidc` and `Ark.oAuth.Client`,
move to .NET 10 and EF Core 10.

There is nothing to do when you upgrade. The provider's endpoints, tokens and discovery document are
the same in 2.3.0 as in 2.2.x. This client therefore behaves the same against a 2.2.x provider and a
2.3.0 one, and you can upgrade the two in either order. The requirements are unchanged: Python
`>=3.9` and `cryptography>=49.0.0` (`>=46.0.6` on Python 3.9.0/3.9.1). The built-in access-denied
page names `ark-oauth-client 2.3.0` in its footer.

## 2.2.1

2.2.0 republished through the repository's release workflow. The published files differ from 2.2.0
only in the version number.

## 2.2.0

A security release, published with `Ark.oAuth.Oidc` 2.2.0. Upgrade the provider too. Its single
sign-on sessions from before the upgrade are not recognised, so every user signs in at the provider
once more.

**Behaviour change: the Flask session cookie is Secure by default**, as the README always said and
as the Node and .NET clients do. `ArkFlask` used to read `SESSION_COOKIE_SECURE`, but Flask presets
that key to `False`, so the cookie went out on plain http. Browsers keep a Secure cookie for
`http://localhost`, so local development is unaffected. Pass `cookie_secure=False` only for a
plain-http host that is not localhost.

**Fixed: the client-credentials cache ignored the secret.** Once a token was cached, a caller with
the right `client_id` and any secret was given it. A setup step that tested a secret could pass for
one the provider refuses. `ArkOAuthClient.client_credentials` and `ArkClientCredentials` key the
cache on a SHA-256 of the secret, so the cache holds no secret.

The Node port is now published on npm as `ark-oauth-client-node`. This package keeps its name.

## 2.0.11

`cryptography` is now required at a version clear of every published advisory. The floor was
`>=41.0`, which admitted releases with a Bleichenbacher timing oracle (CVE-2023-50782), missing EC
subgroup validation (CVE-2026-26007) and bundled vulnerable OpenSSL builds. It is now `>=49.0.0`, or
`>=46.0.6` on Python 3.9.0/3.9.1, which 49 does not support.

`ark_oauth_client.__version__` agrees with the package version again. It had stayed at `2.0.5`
through 2.0.8–2.0.10, so the access-denied page's footer named the wrong release.

Published alongside `Ark.oAuth.Oidc` and `Ark.oAuth.Client` 2.0.11. No API change.

## 2.0.5

The built-in access-denied page now names the library that drew it — `ark-oauth-client <version>`,
quietly at the foot of the card. On a shared browser that page is where a stuck user waits while
somebody else works out why the account is wrong, and answering "which version of the client is
this?" meant a `pip show` on a host the person asking cannot reach.

Published alongside `Ark.oAuth.Oidc` 2.0.5, whose admin console gained the same line in its footer,
and `Ark.oAuth.Client` 2.0.5, whose access-denied page gained it too. No API change: the string is
`ark_oauth_client.__version__`, and an application serving its own page
(`account_switch.serve_default_page = False`) is unaffected.

## 2.0.4

First release of the Python client, published alongside `Ark.oAuth.Client` 2.0.4 and
`ark-oauth-client` 2.0.1 for Node so the three halves carry the same version.

Feature parity with the .NET package:

* `add_ark_oidc_client(app, config)` — interactive sign-in for Flask. Authorization code + PKCE
  against the provider's discovery document: real `state` and `nonce` validation, JWKS rollover,
  silent refresh, and RP-initiated logout that revokes the refresh-token family first.
* `add_ark_oidc_api(app, prefix, …)` — bearer-token protection for an API, verified locally against
  the cached JWKS.
* Account switching on a shared browser, in full: `account_switch.require_ark_claims` moves the
  entitlement check to the callback so no session is written for an account that cannot use the
  application; the built-in access-denied page at `/ark/no-access` names the account and offers
  "Sign in as a different user" with `prompt=login`; `ark_switch_user()`,
  `ark_sign_out_everywhere()`, `ark_sign_out_locally()` and `ark_denied_account()`; and the
  `on_evaluate_access` / `on_access_denied` events for a rule or a page of your own. Every part is
  off or unchanged by default.
* The three non-browser services: `ArkSetupProbe` (configuration against live metadata),
  `ArkClientCredentials` (with caching and a redacted request form) and `ArkRegistration`
  (RFC 7591/7592).
* `ArkOAuthClient` — the whole protocol on its own, for CLIs, workers, Django and FastAPI. Adds the
  device grant (RFC 8628), pushed authorization requests (RFC 9126), introspection, revocation and
  `private_key_jwt` client authentication over what the .NET package exposes.
* `ArkAuthConfig.from_mapping` binds an existing `appsettings.json` unchanged, in either the C# or
  the Python spelling of every key.
* `ArkAuthContext`, `AUserInfo`, `AUser`, `AuthClientHelper`, `ArkJwt`, `ArkJson` and `PkceHelper`
  carry their .NET names.

Not carried over: the legacy cookie/bearer middleware. `use_legacy_flow` is accepted for
configuration parity, but the flow itself never validated `state` or `nonce` and derived its PKCE
verifier from a timestamp; it was a migration aid in the .NET package, not a supported
configuration, and there is nothing in Python to migrate from.

Requires Python 3.9+. One runtime dependency, `cryptography`, for signature verification; Flask is
an optional extra.
