<!--
  MIGRATION.md — Ark.oAuth.Oidc
  Audience: AI coding agents planning an upgrade. Facts from the .csproj release notes, migration
  scripts, and source.
-->

# Ark.oAuth.Oidc — versions, compatibility & migration

## Current version

- **`2.0.9`** (`<Version>` in `Ark.oAuth.Oidc.csproj`), `net9.0`, EF Core `9.0.x`.
- Ships in lockstep with **`Ark.oAuth.Client 2.0.9`** — deliberately the **same version number**.
  Upgrade both packages together.

> **Version-number vs changelog note (flagged discrepancy):** the `PackageReleaseNotes` are headed by
> the version a feature *landed in*; the server's newest heading is **"2.0.3"**, while the package's
> actual `<Version>` is **`2.0.9`**. The 2.0.3-described features (back-channel logout, browser-wide
> sign-out, the trimmed dependency graph) **are present and compiled** in 2.0.9. Treat the shipped
> assembly and the schema scripts on disk as the source of truth.

## Framework, database & dependency compatibility

| Requirement | Value |
|---|---|
| Target framework | `net9.0` (host is ASP.NET Core, `Microsoft.NET.Sdk.Web`) |
| ORM | EF Core `9.0.x` |
| Databases | SQLite (default), MySQL, PostgreSQL — **SQL Server is not wired** |
| IdentityModel graph | pinned to `8.8.0` (`JsonWebTokens`, `Protocols.OpenIdConnect`, `System.IdentityModel.Tokens.Jwt`) |

**SQL Server:** `Provider: "sqlserver"` falls through every branch of `ArkDataContext.OnConfiguring`
and leaves the context with no provider. It has never worked; do not select it.

**IdentityModel graph:** `MySql.EntityFrameworkCore`/`MySql.Data` request
`Microsoft.IdentityModel.Protocols.OpenIdConnect 7.5.0` while the rest of the package is on `8.8.0`.
The split does not fail at restore or build — it fails at the **first OIDC challenge** with a
`MethodAccessException`/missing-method error naming neither package. The .csproj raises the floor to
`8.8.0`; do not override it downward.

**Dependency change in 2.0.3 (present in 2.0.9):** `Ark.EfCore`, `Azure.Identity` and `BouncyCastle`
were removed. EF Core `9.0.x` and the Sqlite/MySQL/PostgreSQL providers are now referenced directly.
Nothing in this package used a type from `Ark.EfCore`; it was only a carrier for EF packages (and was
dragging in a SQL Server provider stack this package cannot select).

## Schema scripts & the self-applying updater

Schema changes ship as numbered scripts and **run themselves on start-up** via `UseArkAuthData()` →
`ArkSchemaUpdater.Apply`, recorded in `ark_schema_history`. **Only the SQLite scripts are embedded and
auto-applied.** On MySQL/PostgreSQL the equivalent `ALTER TABLE`/`CREATE TABLE` is yours to run.

| Script | Version | Adds |
|---|---|---|
| `00003_sql.sql` | 2.0.0 | Protocol state tables, RFC 7591 metadata columns; seeds the scope catalogue; adopts each tenant's existing RSA key as its active signing key (`kid = tenant_id`) so already-issued tokens keep validating. Rewrites every client that holds no secret. |
| `00004_sql.sql` | 2.0.2 | `users.is_active` (one additive, defaulted column). |
| `00005_sql.sql` | 2.0.3 | `clients.backchannel_logout_uri`, `clients.backchannel_logout_session_required`, `sessions.browser_id`, and the `session_clients` table. All additive and defaulted. |

**Nothing is ever replayed.** A database predating the history table is *measured*, not replayed: each
script is checked against the live schema and one whose tables/columns are all present is recorded as
a **baseline** without executing. This matters because `00003` rewrites secret-less clients (right for
a 2.0.0 upgrade, wrong afterwards). A database created by `EnsureCreated` on this version records all
scripts and runs none.

**Skipping a script fails specifically:** without `00004` the entity carried `users.is_active` and the
table did not, so `/api/oauth/v1/user/list` answered a bare 500 and the console's Users grid came up
empty with nothing saying why.

Run/rollback one by hand: `GET /api/migration/v1/sql?action=up|down&name=00005_sql.sql` (now reports
whether the script actually worked instead of always saying "executed").

## Upgrade playbook

**SQLite:** upgrade the package and restart. `UseArkAuthData()` applies `00003`→`00005` as needed and
records them. Nothing to run by hand.

**MySQL / PostgreSQL:** upgrade the package, apply the equivalent DDL for every script the DB has not
had (00003/00004/00005), then restart. `ReconcileScopeCatalogue`, `ReconcileAdminConsoleClient` and
`ReconcileMachineClient` fill in new built-in scopes, the standard admin-console callback URLs, and a
machine client on start-up.

## Behavioural changes by version (from the .csproj notes)

- **2.0.3** (present in 2.0.9): Back-Channel Logout 1.0 (signed `logout_token`, `typ: logout+jwt`,
  `sid`, no `nonce`); a down client cannot block sign-out (parallel, per-client timeout, logged not
  raised); clients notified because they *took part* (recorded via `session_clients`, not derived from
  live refresh tokens); browser-wide sign-out via the `ark_idp_bid` cookie; discovery corrected —
  `backchannel_logout_supported: true`, `frontchannel_logout_supported: false`; new `Oidc` settings
  (`EnableBackChannelLogout`, `BackChannelLogoutTimeoutSeconds`, `LogoutTokenLifetimeSeconds`,
  `SignOutAllBrowserSessions`, `SignOutAcrossTenants`); the trimmed dependency graph.
- **2.0.2**: one-call provisioning (`/provision/client`); two-level activation
  (`/activation/client`, `/activation/user`); sign-in says which level is off (after password
  verification, preserving anti-enumeration); self-applying schema updates; the console's
  Provisioning page (admin-only) with generated `curl`; client logos inlined as `data:` URIs; a live
  authorization-code+PKCE runner on the setup page; CSP `frame-ancestors 'self'`.
- **2.0.1**: maintenance/packaging (icon + readme at `.nupkg` root, SPDX license, symbol package). No
  API/protocol change.
- **2.0.0 — the standards release**: full protocol core (discovery, JWKS two-phase rotation, code+PKCE
  S256, refresh rotation, client credentials, device grant, PAR, introspection, revocation, dynamic
  registration, RP-initiated logout, RFC 9207); `at+jwt` access tokens (RFC 9068); codes/refresh
  tokens stored as SHA-256 (replay revokes the family); the admin console shipped inside the package
  at `/{tenant}/admin`.
  **Breaking:** the seeded admin account now comes from `ark_oauth_server:AdminUser` (no more
  compiled-in `admin`/`admin`); `Password` is required and a `<<placeholder>>` counts as unset.
  **Not supported:** implicit grant, hybrid flow, ROPC. The v1 `/oauth/{tenant}/v1/...` routes still
  work but delegate to the protocol core (single-use codes, PKCE verified). Existing DBs must run
  `00003`.

## Version immutability

Package versions are **immutable once pushed** on nuget.org (and PyPI/npm for the ports). Read the
checked-in runbook `nuget_deploy.txt` before publishing. Never commit a token, key or secret — this
repository is public, and a live signing key had to be purged from history once already.
