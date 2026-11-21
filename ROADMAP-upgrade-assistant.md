# Upcoming: Upgrade assistant and agent skills

> **Status: parked (2026-11-21).** This is a design proposal. Nothing here is built, scheduled or
> promised for a release. Do not start on it without a decision from the maintainer.

## The idea

Two features, proposed together:

1. **An upgrade wizard built into the IdP.** It understands Ark versions, checks compatibility and
   migrates data as a guided process, in the style of the first-run setup wizard. It uses no
   external AI service. Its knowledge comes from the package itself.
2. **Agent skills for client-side coding agents.** The same upgrade and integration knowledge is
   packaged so that whatever coding agent a developer uses can apply it to their own repository.

## Design principle: one source of truth, two consumers

The IdP can see only its own database, its runtime configuration and the assemblies loaded in its
process. It cannot see the host's source code. The work therefore splits:

| Consumer | Owns |
|---|---|
| In-app wizard | Database schema, data migration, configuration checks, runtime checks |
| Agent skill | Code changes in host and client repositories: package pins, target framework, host wiring, removal of the v1 client shape |

Both read one **upgrade manifest**, a machine-readable file embedded in the package. The
"intelligence" is a rules engine over that manifest plus live measurements of the actual database.
A rule can give an exact answer ("rolling back locks out 412 users"), where a language model could
only give a plausible one.

## What already exists

| Exists | Where |
|---|---|
| Start-up schema updater, additive only, model-driven DDL on every provider | `Ark.oAuth.Oidc/Ark.oAuth.Oidc/Migration/ArkSchemaUpdater.cs` |
| Analyse → `plan_hash` → apply pattern (Data tools import) | `Ark.oAuth.Oidc/Ark.oAuth.Oidc/Code/ArkDataTools.cs` |
| Full-fidelity export, usable as the pre-upgrade backup | Data tools, `/{tenant}/admin/data` |
| Wizard shell, setup-code authentication, `/ark-idp/*` routes | `Code/ArkSetup.cs`, `wwwroot/setup/` |
| Copy-paste agent prompts, including "upgrade an IdP host" | `AGENT-HELPER.md` (Prompt 2) |
| AI-oriented docs packed into each package | `AI-PROMPT.md`, `AI-RECIPES.md`, `MIGRATION.md` beside each README |

## Gaps this would close

- **The database does not record which package version last ran against it.**
  `ark_schema_history` holds script names only, so a version jump has to be inferred.
- **The bootstrap lock is per process** (a `SemaphoreSlim` in `ArkExtn`). Two PostgreSQL/MySQL
  instances that start together can both run the schema updater.
- **Schema sync runs unattended**, with no preview or dry run.
- **Version knowledge lives in prose**: csproj release notes and `MIGRATION.md`. `AGENT-HELPER.md`
  Prompt 2 still targets 2.1.4 while the package is on 2.4.0, the kind of drift a generated source
  would prevent.

## Proposed features

Complexity: **S** small, **M** medium, **L** large.

| # | Feature | Value | Complexity |
|---|---|---|---|
| 1 | **Upgrade manifest.** One embedded JSON entry per version and change, with `kind` (additive / behaviour / data-rewrite / irreversible), `rolling_safe`, `affects` (db / config / host-code / clients), a `check` id and fix text. `release.yml` fails when the version being released has no entry. | Foundation for everything below | S–M (mostly back-filling 1.x → current from the csproj notes) |
| 2 | **Database version stamp and instance heartbeat**: package version, host and last-seen time per running instance. | "This database last ran 2.0.11; two live instances are still on 2.0.11" | S |
| 3 | **Migration lock shared across instances**: `pg_advisory_lock`, MySQL `GET_LOCK`, a file lock on SQLite. | Removes a real race in scaled-out deployments | S (worth doing even if nothing else is built) |
| 4 | **Read-only plan API** (`GET …/upgrade/plan`, operator or machine credential): the exact DDL, data steps, findings and a `plan_hash`. | One dry run, used by the wizard, the skill and CI | M (separate computing the plan from executing it in the updater) |
| 5 | **Compatibility check engine**: `IArkUpgradeCheck` returning severity, evidence and fix. | Findings that name counts and client ids | M, plus a little per check |
| 6 | **Upgrade wizard** with modes `Auto` (today's behaviour, stays the default), `Hold` and `AnalyzeOnly`. | Guided upgrade for operators, without blocking unattended container restarts | L |
| 7 | **Client self-check endpoint** (`POST …/clients/{id}/check`): byte-exact redirect URIs including sign-out, scope whitelist, user-to-client mapping, PKCE and grant types. | Ends the "looks like a wrong password" class of support issue | M (server only, so no per-language cost) |
| 8 | **Client version visibility.** The client libraries send `ark-oauth-client-{lang}/{version}`; the IdP records last-seen per `client_id`, plus any use of legacy v1 endpoints. | Answers "which apps break if I upgrade?" | M (small, but owed to all four ports) |
| 9 | **`doctor` command per client package** (`dotnet tool`, `python -m`, `npx`): calls #7 and adds local checks (IdentityModel version graph, clock skew, a route shadowing the callback, .NET middleware order). | Deterministic facts for developers and for agents | M × 4 ports (keep the logic server-side so each port stays thin) |
| 10 | **Agent skills shipped inside the packages** (`ark-upgrade`, `ark-connect`) in the open SKILL.md format, with an `AGENTS.md` pointer for agents that do not read skills. Generated from the manifest, never hand-written. | Works with whichever coding agent the developer uses | S–M |

## Compatibility checks

Each check is a live count or a probe, drawn from problems already met in real deployments:

- **Rollback lockout:** count users already re-hashed to `{iter}.{salt}.{hash}`. Builds before 2.1.4
  cannot verify them, so rolling back locks them out.
- **DDL rights:** probe CREATE/ALTER inside a transaction that is rolled back (PostgreSQL) before
  the real run. Without the rights, show the exact DDL to hand to a DBA.
- **Never-seeded database:** `tenants` is empty, which surfaces later as `23503 FK_clients_tenants`.
- **`DefaultPw` placeholder:** a `<<placeholder>>` value would be hashed and become a real password.
- **Configuration source order:** `settings.json` ranked above environment / App Service settings
  (an `appsettings.local.json` added before `AddArkIdp`). Readable from `IConfigurationRoot.Providers`.
- **Legacy usage:** legacy keys still present (`RsaPublic`, `Tenants`, `UseLegacyFlow`,
  `AuthServerUrl`), and clients still calling the v1 token endpoint without PKCE, which 2.1.4 refuses.
- **Mixed `Microsoft.IdentityModel.*` versions** loaded in the process, caught before the first
  sign-in challenge fails at runtime.
- **Missing email template:** a production host without `wwwroot/email/user_activation_.html`,
  which is read from disk.
- **Old signing key:** still `kid = tenant_id`, adopted from v1. Recommend rotating to a new kid,
  never reusing one a client may have cached.
- **Sign-out callback:** clients with no sign-out callback registered.

Code-side findings belong to the agent skill, because the IdP cannot see them: package pins, target
framework retargets (net9 → net10), a pin to a version that was never published (restores the next
one with NU1603), and a host left half zero-config, half configured.

## Wizard flow

**Detect → Check → Back up → Plan → Apply → Verify → "All set"**

- Each step is tested before the next one opens, matching the setup wizard and the client-app
  onboarding screens.
- **Back up** is a gate built on the existing export.
- **Apply** takes the cross-instance lock and refuses a plan whose `plan_hash` has changed.
- **Verify** runs discovery, JWKS, a machine-client token and a console sign-in.
- In `Hold` mode the wizard authenticates with the **setup code**, not the console sign-in, because
  a schema that is behind can break the console itself.

**Modes**

| Mode | Behaviour |
|---|---|
| `Auto` (default) | Today's behaviour: additive changes apply at start-up |
| `Hold` | Nothing is applied until an operator approves the plan in the wizard; sign-in answers 503 meanwhile |
| `AnalyzeOnly` | Never writes. For a staging slot pointed at the production database: review the plan, apply, then swap. The manifest's `rolling_safe` flag says whether old instances survive in between |

## Suggested phases

1. **Foundation:** features 1–4, a start-up warning for dangerous configuration, and a first agent
   skill generated from the manifest (which also replaces the stale `AGENT-HELPER.md` Prompt 2).
2. **Wizard:** features 5 and 6, with the checks above.
3. **Client apps:** features 7–9, then the client-side skill.

## Non-goals

- **Down scripts for model-sync changes.** Rollback is "restore the export, redeploy the previous
  image", and the wizard says so.
- **A language model inside the IdP.**
- **The IdP editing host source code.** It cannot see it; that is the agent skill's job.

## Open questions

- Should installs created by the setup wizard default to `Hold` rather than `Auto`?
- MySQL commits DDL statement by statement, so the dry-run DDL probe cannot be rolled back there.
  What replaces it: a scratch table, or a privilege query?
- Does client version reporting (#8) need an opt-out in the client libraries?
- Where does check evidence live: the audit trail, or a dedicated table the wizard can page through?
