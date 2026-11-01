<!--
  MIGRATION.md — ark-oauth-client (Python)
  Audience: AI coding agents planning an upgrade. Facts from pyproject.toml, CHANGELOG.md, source.
-->

# ark-oauth-client (Python) — versions, compatibility & migration

## Current version

- **`2.0.11`** — the `version` in `pyproject.toml`, which is what the built wheel/sdist and PyPI carry.
- Ships in lockstep with **`Ark.oAuth.Client 2.0.11`** (NuGet) and **`ark-oauth-client 2.0.11`** (npm).
  The three ports deliberately carry the **same version number**; an integration written in one
  translates almost line-for-line into another.

> **`__version__` before 2.0.11.** 2.0.8, 2.0.9 and 2.0.10 shipped with `ark_oauth_client.__version__`
> still reading `2.0.5`, so on those releases the built-in access-denied page names `2.0.5` in its
> footer. From 2.0.11 `__version__` and `pyproject.toml` agree again; use `pip show ark-oauth-client`
> for the installed version on an older release.

## Compatibility

| Requirement | Value |
|---|---|
| Python | `>=3.9` (3.9–3.13 classified) |
| Runtime dependency | `cryptography>=49.0.0` (`>=46.0.6` on Python 3.9.0/3.9.1) — signature verification; everything else is stdlib |
| Optional extra | `flask>=2.2` via `pip install "ark-oauth-client[flask]"` |
| Build backend | `hatchling` |

The Flask integration is the only part that needs Flask; `ArkOAuthClient` and the non-browser helpers
have no web-framework dependency and work under Django, FastAPI, a CLI or a worker.

## Feature parity with the .NET client

Feature for feature with `Ark.oAuth.Client`, plus more exposed on the protocol client. Name mapping
(only the casing changes):

| `Ark.oAuth.Client` (.NET) | `ark_oauth_client` (Python) |
|---|---|
| `services.AddArkOidcClient(configuration)` | `add_ark_oidc_client(app, config)` |
| `AddArkOidcClient(configuration, options => …)` | `add_ark_oidc_client(app, config, configure)` |
| `builder.AddArkOidcApi(config)` | `add_ark_oidc_api(app, prefix, …)` |
| `app.UseArkOidcClient()` | not needed — registration happens in `add_ark_oidc_client` |
| `app.UseArkAccountEndpoints()` | `use_ark_account_endpoints(app)` |
| `HttpContext.GetArkAccessTokenAsync()` | `get_ark_access_token()` |
| `request.WithArkTokenAsync(context)` | `with_ark_token(headers)` |
| `HttpContext.ArkSwitchUserAsync()` | `ark_switch_user()` |
| `ArkChallengeProperties.SwitchUser(...)` | `ArkChallengeProperties.switch_user(...)` |
| `[Authorize(Roles = "billing.admin")]` | `@auth.require_claims("billing.admin")` |
| `ArkSetupProbe` / `ArkClientCredentials` / `ArkRegistration` | same names |
| `ArkJwt.DecodePayload` / `ArkJson.Prettify` | `ArkJwt.decode_payload` / `ArkJson.prettify` |

**Beyond the .NET client**, `ArkOAuthClient` also exposes the device grant (RFC 8628), pushed
authorization requests (RFC 9126), introspection (RFC 7662), revocation (RFC 7009), and
`private_key_jwt` client authentication.

**Two intentional differences from .NET:**
1. The .NET package configures ASP.NET Core's own OIDC/cookie handlers; Python has no equivalent to
   configure, so the protocol is implemented in this package and tested against
   `tests/stub_idp.py`, which mirrors the real server's wire behaviour.
2. `use_legacy_flow` is accepted for configuration parity but the legacy cookie/bearer middleware is
   **not reimplemented** — it never validated `state`/`nonce` and was a .NET migration aid only. The
   standard flow is the only supported one here.

## Changelog (from CHANGELOG.md)

- **2.0.11** — security floor on `cryptography` (`>=49.0.0`; `>=46.0.6` on Python 3.9.0/3.9.1),
  replacing `>=41.0`, which admitted CVE-2023-50782 and CVE-2026-26007. `__version__` synced with the
  package version. No API change.
- **2.0.5** — the built-in access-denied page now names the library (`ark-oauth-client <version>`) in
  its footer. No API change. (Published alongside `Ark.oAuth.Oidc`/`Ark.oAuth.Client` 2.0.5.)
- **2.0.4** — first release of the Python client, published alongside `Ark.oAuth.Client` 2.0.4 (and
  the Node client). Full feature parity with the .NET package: `add_ark_oidc_client`,
  `add_ark_oidc_api`, account switching in full (`account_switch.require_ark_claims`, `/ark/no-access`,
  `ark_switch_user()`/`ark_sign_out_everywhere()`/`ark_sign_out_locally()`/`ark_denied_account()`,
  `on_evaluate_access`/`on_access_denied`), the three non-browser helpers (`ArkSetupProbe`,
  `ArkClientCredentials`, `ArkRegistration`), `ArkOAuthClient`, and `ArkAuthConfig.from_mapping`
  binding an existing `appsettings.json` in either spelling.

  > Note: CHANGELOG entries for 2.0.6–2.0.10 are not written; the package version advanced through
  > them to stay aligned with the NuGet releases.

## Migrating from the .NET or Node client

There is no data or wire migration — the three clients talk to the same provider and read the same
discovery document. Porting code means transliterating names (table above) and moving configuration
into the `ark_oauth_client` section (any spelling; `ArkAuthConfig.from_mapping` binds an existing
`appsettings.json` unchanged). Only `authority` and `client_id` are required.

## Publishing (for maintainers)

Read the checked-in runbook `pip_deploy.txt` before publishing — it prefers **uv** (`uv build` /
`uv publish`) over `build`+`twine`, and versions are **immutable once pushed** to PyPI. The build
backend stays `hatchling` either way. This repository is public: never commit a token, key or secret
(prefer GitHub Actions Trusted Publishing over an API token).
