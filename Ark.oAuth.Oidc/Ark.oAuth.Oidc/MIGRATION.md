<!--
  MIGRATION.md — Ark.oAuth.Oidc
  Audience: AI coding agents planning an upgrade. Facts from the .csproj release notes, migration
  scripts, and source.
-->

# Ark.oAuth.Oidc — versions, compatibility & migration

## Current version

- **`2.4.1`** (`<Version>` in `Ark.oAuth.Oidc.csproj`), `net10.0`, EF Core `10.0.x`.
- Ships in lockstep with **`Ark.oAuth.Client 2.4.1`** — deliberately the **same version number** —
  and with the Python, Node and browser clients at 2.4.1. Upgrade both .NET packages together.
- **2.4.1 adds webhooks, an opt-in module.** A host that does not call `AddArkWebhooks()` sees no
  change: no tables, no background work, no console link, and the module's routes answer 404.
  Endpoints, discovery, tokens, pages and existing configuration are as in 2.4.0, so every client
  that works with a 2.4.0 provider works with 2.4.1, and the four client packages are unchanged.
  See the 2.4.1 entry under "Behavioural changes by version" and `WEBHOOKS.md`.
- **2.4.0 is the scale release: built to hold 30,000 signed-in users and to run on more than one
  instance.** Endpoints, discovery, tokens, pages and existing configuration are as in 2.3.0, so
  every client that works with a 2.3.0 provider works with 2.4.0, and the four client packages are
  unchanged. The first start adds indexes to an existing database, and on PostgreSQL and MySQL the
  `data_protection_keys` table; see the 2.4.0 entry under "Behavioural changes by version".
- **2.3.0 moved to .NET 10 (LTS) and EF Core 10, and changed nothing else.** Endpoints, discovery,
  tokens, pages, configuration and schema are as in 2.2.1, so every client that works with a 2.2.x
  provider works with 2.3.0. 2.2.1 is the last `net9.0` release (it is 2.2.0 republished, no code
  change), and .NET 9 left support on 2026-11-10. Retarget a `net9.0` host to `net10.0` before
  upgrading (restore fails with NU1202 otherwise). The database needs nothing: a database built
  under EF Core 9 opens as it is.

> **Release-note headings:** the `PackageReleaseNotes` are headed by the version a change first
> shipped in, newest first, and every later release carries it. Before 2.3.0 some entries were headed
> "Next release" or "Earlier"; they now carry the version that shipped them (2.0.14, 2.1.3, 2.1.6).
> Treat the shipped assembly and the schema scripts on disk as the source of truth.

## Framework, database & dependency compatibility

| Requirement | Value |
|---|---|
| Target framework | `net10.0` (host is ASP.NET Core, `Microsoft.NET.Sdk.Web`); `net9.0` up to 2.2.1 |
| ORM | EF Core `10.0.x`; `9.0.x` up to 2.2.1 |
| Databases | SQLite (default), MySQL, PostgreSQL — **SQL Server is not wired** |
| IdentityModel graph | pinned to `8.23.0`, `8.8.0` up to 2.2.1 (`JsonWebTokens`, `Protocols.OpenIdConnect`, `System.IdentityModel.Tokens.Jwt`) |

**SQL Server:** `Provider: "sqlserver"` falls through every branch of `ArkDataContext.OnConfiguring`
and leaves the context with no provider. It has never worked; do not select it.

**IdentityModel graph:** the framework's OpenID Connect handler asks for
`Microsoft.IdentityModel.Protocols.OpenIdConnect 8.19.2` while `JsonWebTokens` lifts
`Microsoft.IdentityModel.Tokens` to `8.23.0` (and up to 2.2.1, `MySql.Data` asked for Protocols
`7.5.0`). A split graph does not fail at restore or build — it fails at the **first OIDC challenge**
with a `MethodAccessException`/missing-method error naming neither package. The .csproj pins all
three to `8.23.0`; do not override it downward.

**Dependency change in 2.0.3 (present in 2.0.11):** `Ark.EfCore`, `Azure.Identity` and `BouncyCastle`
were removed. EF Core and the Sqlite/MySQL/PostgreSQL providers are now referenced directly.
Nothing in this package used a type from `Ark.EfCore`; it was only a carrier for EF packages (and was
dragging in a SQL Server provider stack this package cannot select).

## Schema scripts & the self-applying updater

Schema changes ship as numbered scripts and **run themselves on start-up** via `UseArkAuthData()` →
`ArkSchemaUpdater.Apply`, recorded in `ark_schema_history`. Only the SQLite scripts are embedded, so
after them, **on every provider**, the updater compares the EF entity model with the live database and
adds any table or column the model has and the database lacks (`ArkSchemaUpdater.AddMissingFromModel`,
audited as `schema_sync`). The DDL comes from the provider's own EF migrations SQL generator, so column
types are the ones `EnsureCreated` would choose; a missing table is created with its indexes, and an
index over an added column is created with it.

- **Strictly additive.** Nothing is dropped, renamed or retyped; a column the DB has and the model
  does not is left alone.
- **Existing rows get the entity's initialiser**, not the CLR default: `is_active`, `require_pkce`
  and `backchannel_logout_session_required` arrive `true`, lifetimes as `3600` etc. A NOT NULL
  column with no initialiser gets `''`/`0`/`false`.
- **One transaction** on PostgreSQL/SQLite, so a failure adds nothing; MySQL commits DDL per statement
  and the next start re-measures.
- **Packages up to 2.0.11 lacked this step.** On MySQL/PostgreSQL every new column reached the DB
  only as the first query selecting it failing, e.g. `42703: column c.backchannel_logout_session_required
  does not exist` from `ReconcileAdminConsoleClient`.

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

Run/rollback one by hand: `POST /api/migration/v1/sql?action=up|down&name=00005_sql.sql` (reports
whether the script actually worked instead of always saying "executed"). Since 2.0.14 the
endpoint is off unless `ark_oauth_server:Management:AllowMigrationEndpoint` is `true`.

## Upgrade playbook

**SQLite:** upgrade the package and restart. `UseArkAuthData()` applies `00003`→`00005` as needed and
records them. Nothing to run by hand.

**MySQL / PostgreSQL:** upgrade the package and restart. The model sync adds whatever 00003/00004/00005
(and anything later) would have added. It does not replay 00003's data rewrite, and does not need to:
`IsPublicClient` already treats a secretless client as public, `ArkKeyService` adopts the tenant's
existing key as `kid = tenant_id` on first use, and `ReconcileScopeCatalogue`,
`ReconcileAdminConsoleClient` and `ReconcileMachineClient` fill in the built-in scopes, the standard
admin-console callback URLs, and a machine client on start-up. The DB login needs `CREATE`/`ALTER` on
its own tables for this; with a DDL-less login, apply the DDL yourself before the upgrade.

**Unblocking a PostgreSQL DB on 2.0.11 or earlier, without a redeploy.** 00004 + 00005 in the types
the model sync (and `EnsureCreated`) produce; every statement is idempotent. Restart the app after.

```sql
ALTER TABLE users    ADD COLUMN IF NOT EXISTS is_active boolean NOT NULL DEFAULT true;
ALTER TABLE clients  ADD COLUMN IF NOT EXISTS backchannel_logout_uri text NULL;
ALTER TABLE clients  ADD COLUMN IF NOT EXISTS backchannel_logout_session_required boolean NOT NULL DEFAULT true;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS browser_id text NULL;
CREATE TABLE IF NOT EXISTS session_clients (
    id         text NOT NULL CONSTRAINT "PK_session_clients" PRIMARY KEY,
    tenant_id  text NOT NULL,
    session_id text NOT NULL,
    client_id  text NOT NULL,
    subject    text NOT NULL,
    created_at timestamp with time zone NOT NULL
);
CREATE INDEX IF NOT EXISTS "IX_session_clients_session_id" ON session_clients (session_id);
CREATE INDEX IF NOT EXISTS "IX_sessions_browser_id" ON sessions (browser_id);
```

## Behavioural changes by version (from the .csproj notes)

- **Next release — agent-to-agent (A2A) tokens; inert until an operator lists a caller.**
  A token can now be addressed to one client (`aud` = its client_id): the `client_credentials`
  grant with `audience` (the agent as itself), or `urn:ietf:params:oauth:grant-type:token-exchange`
  (RFC 8693, the agent on behalf of a user, with an `act` chain). Both are refused with
  `invalid_target` unless the target client lists the caller in `a2a_callers`, which is empty on
  every existing client. `GET {issuer}/a2a/agent-card-security` serves the security section of an
  A2A Agent Card. Options `Oidc:EnableA2A` (true), `A2ATokenLifetimeSeconds` (300),
  `A2AMaxDelegationDepth` (4). See `A2A.md`.
  - **Schema:** one nullable column, `clients.a2a_callers_`, added by the start-up schema sync on
    every provider. Nothing else. An older build runs against the upgraded database unchanged.
  - **Discovery** lists the token-exchange grant in `grant_types_supported`.
  - **Introspection** additionally answers for an A2A token when the caller is the agent it is
    addressed to or the client that obtained it. Every other answer is as before.
  - **One behaviour change:** a `client_credentials` request carrying `audience` or `resource` used
    to have it ignored. It is still ignored when it names the tenant's own audience or the issuer;
    any other value is now an A2A request and is answered `invalid_target` unless it names an
    agent the caller may call. `Oidc:EnableA2A = false` restores the old behaviour entirely.
  - **Not affected:** authorization code, refresh, device, PAR, registration, userinfo, logout,
    the management API (an A2A token is refused there: wrong audience) and every existing token.
  - **Upgrade action:** none.

- **2.4.1 — webhooks, opt-in; nothing changes for a host that does not ask for them.**
  `builder.Services.AddArkWebhooks()` adds an operator-only Webhooks page to the console
  (`/{tenant}/admin/webhooks`), an API under `/api/oauth/v1/webhooks`, and a database-backed
  dispatcher on every instance. Events (sign-ins, token issuance and revocation, device approval,
  user, client and tenant changes, and the host's own through `IArkWebhookPublisher`) are stored,
  signed per Standard Webhooks, retried, dead-lettered and replayable. Each event hook is one call
  beside an existing audit line that does nothing unless the module is registered.
  - **Schema:** none in the IdP's own tables. With the module on, the next start creates two control
    tables, `ark_wh_endpoints` and `ark_wh_shards`, beside the IdP's schema; the shard tables an
    endpoint's plan needs are created when it is saved, in the IdP's database or one named under
    `ark_oauth_server:Webhooks:Databases`. The start-up schema sync, export/import and factory reset
    never touch `ark_wh_*`.
  - **Upgrade action:** none. To use webhooks, add the line and configure an endpoint; nothing is
    sent until one exists. Removing the line turns the module off; its tables stay until dropped.

- **2.4.0 — scale: 30,000 signed-in users, more than one instance; nothing changes on the wire.**
  Sign-in and token lookups ask for the stored value first and fall back to a `lower()` index
  instead of comparing `lower(column)` across the whole table. Tenants, clients, scopes and the
  signing key are kept in memory for `Oidc:ReferenceCacheSeconds` (30), and a confidential client's
  verified secret for `Oidc:ClientSecretCacheSeconds` (300); nothing about a user is cached, and
  nothing is refused on a cached copy. Password hashing is bounded by
  `Oidc:MaxConcurrentPasswordHashes` (0 = half the cores). The data-protection key ring is kept in
  the server's database on PostgreSQL and MySQL (`DataProtectionKeys: auto`). Failed sign-ins are
  counted atomically. The purge also removes refresh tokens whose session has ended. The audit
  trail is written in batches off the request path, and error rows, which were being discarded,
  are now written.
  - **Schema, applied by the first start:** the missing indexes on the hot paths (including
    `refresh_tokens.session_id` and the `expires_at` columns), never a unique index and never
    fatal; and the `data_protection_keys` table where the key ring moves into the database. It
    reads each table once, so allow that start longer on a database with millions of rows.
  - **Upgrade action:** none is required; every new setting has a default. The keys the machine
    was already using are copied into the database the first time, so the upgrade signs nobody
    out. A host that configures its own key storage (`PersistKeysTo…`) keeps it; `off` leaves the
    ring to the host, `database` moves it on SQLite too.
  - **What an operator will notice:** with more than one instance, a change that takes something
    away from a client, scope or tenant reaches the other instances within
    `ReferenceCacheSeconds`; set `0` to read the database every time. The audit table now receives
    the error rows it was missing, and with `EnableLogTrace` on a busy server writes several rows
    per sign-in; `Oidc:AuditRetentionDays` (0 = keep all) trims it. Nobody is turned away by the hashing limit unless `Oidc:MaxPasswordHashWaitSeconds` is set;
    then a sign-in that waits longer gets "the server is busy" (token endpoint: 503
    `temporarily_unavailable`) and is not counted as a failed attempt.
  - Settings and sizing: README → "Running at scale".
- **2.3.0 — .NET 10 and EF Core 10; no behaviour change.** Target framework `net9.0` → `net10.0`;
  EF Core / Sqlite `9.0.19` → `10.0.15`; `Npgsql.EntityFrameworkCore.PostgreSQL` `9.0.4` → `10.0.4`;
  `MySql.EntityFrameworkCore` `9.0.17` → `10.0.12` (MySql.Data 26.10.0, which no longer pulls
  IdentityModel 7.5.0); `Microsoft.AspNetCore.Authentication.OpenIdConnect` `9.0.10` → `10.0.15`;
  `Microsoft.IdentityModel.*` `8.8.0` → `8.23.0`.
  - **Upgrade action:** retarget the host to `net10.0` (SDK and runtime 10; container image
    `mcr.microsoft.com/dotnet/aspnet:10.0`), and raise any EF Core, EF provider,
    `Microsoft.AspNetCore.Authentication.*` or `Microsoft.IdentityModel.*` reference the host
    holds itself.
  - No schema change, no migration, no configuration change. A database created by 2.2.x opens as
    it is (checked on SQLite, PostgreSQL 16 and MySQL 8.4).
- **2.2.1**: 2.2.0 republished through the release workflow; the files differ only in the version.
- **2.2.0 — security release**, **2.1.6 — landing page after sign-in**, **2.1.3 — setup wizard and
  appearance picker**: see `<PackageReleaseNotes>` in the .csproj, which has them in full.

- **2.0.14 — management API authorization (breaking).**
  - `ManageController` and `ProvisionController` take the `ArkOperator` policy instead of a bare
    `[Authorize]`. Admitted: the operator's console session (`AdminUser:Username`, or an `admin` /
    `ark_admin` claim on the console mapping), or a bearer token issued to `{TenantId}_machine` with
    `client.register` (or an operator-approved token from a `Management:OperatorDeviceClients` client).
    Everyone else gets 401/403 JSON instead of a sign-in redirect.
  - **Upgrade action:** a console user who is not `AdminUser` and used the console's grids needs the
    `admin` claim on their mapping to `{TenantId}_client`, or every API call answers 403.
  - **Upgrade action for hosts that added their own bearer scheme** for the API (e.g. a policy scheme
    made the default, or JWT bearer with a client_id check): remove it. The package's schemes are
    `ArkManagement` and `ArkManagementBearer`; a host scheme of either name is a duplicate-scheme error on the first request.
  - New, optional `ark_oauth_server:Management`: `MachineClientSecret` (applied to the machine client
    on start-up; ≥ 16 characters or the bootstrap stops; while set the console refuses to regenerate
    that secret), `OperatorDeviceClients` (default empty), `AllowMigrationEndpoint` (default `false`).
  - `/api/migration` answers 404 unless `AllowMigrationEndpoint` is true.
  - `client.register` is refused when requested through `/provision/client` (`invalid_scope`) or
    `/oauth2/register` (`invalid_client_metadata`); an operator still grants it in the console.
  - No schema change.

- **2.0.14**, too: the operator's **Data** page (`/{tenant}/admin/data`) and API —
  full export (every table and column, optionally AES-256-GCM encrypted), analysed import with three
  modes (`replace`, `merge_skip`, `merge_overwrite`) and rule-based per-record exclusion, and factory
  reset to the first-run seed. **No schema change and no migration**; existing routes are unchanged.
  New optional settings under `ark_oauth_server:Admin:DataTools` (all default on). See API-GUIDE.md.
- **2.0.3** (present in 2.0.11): Back-Channel Logout 1.0 (signed `logout_token`, `typ: logout+jwt`,
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
