# Changelog

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
