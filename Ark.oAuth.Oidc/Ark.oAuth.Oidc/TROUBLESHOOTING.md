<!--
  TROUBLESHOOTING.md — Ark.oAuth.Oidc
  Audience: AI coding agents diagnosing the provider. Every cause/fix is from this directory's
  source and README. Do not invent error strings or settings.
-->

# Ark.oAuth.Oidc — troubleshooting matrix

Diagnose against the provider's actual behaviour. Verify .NET changes against a running
`Ark.oAuth.Oidc.Host` — there is **no automated .NET test project** in this repo.

## Startup / bootstrap / database

| Symptom | Likely cause | Diagnosis | Correct solution | Avoid |
|---|---|---|---|---|
| First run throws naming `AdminUser:Password` and seeds nothing | No admin password configured (or a `<<placeholder>>`) | `ResolveAdminUser` refuses to seed | Set `ark_oauth_server:AdminUser:Password` (or `DefaultPw`) out of band and restart — a database with no tenant is seeded on the next start | Re-introducing a compiled-in `admin`/`admin` default |
| Context has no provider configured / DB errors | `Provider: "sqlserver"` | `OnConfiguring` has no `sqlserver` branch | Use `sqlite`/`mysql`/`postgres` | Expecting SQL Server support |
| `/api/oauth/v1/user/list` returns a bare 500, console Users grid empty | A schema change (e.g. 00004 `users.is_active`) never reached the DB | Packages up to 2.0.11 auto-applied only the SQLite scripts | Upgrade: the start-up model sync adds missing tables/columns on every provider | Hand-patching one column and leaving the rest |
| Bootstrap fails with `42703: column c.backchannel_logout_session_required does not exist` (PostgreSQL) in `ReconcileAdminConsoleClient` | DB created by an older package; 00005's columns were never added (up to 2.0.11, nothing did on PG/MySQL) | `schema_update` error in the audit trail; `information_schema.columns` lacks the column | Upgrade and restart — the model sync adds it (audited as `schema_sync`). To unblock without redeploying, run 00005's DDL by hand (MIGRATION.md) | Dropping and recreating the DB |
| Bootstrap fails with `42501: permission denied for database "postgres"` (PostgreSQL, 2.0.12 and earlier); now `database '…' does not exist on the server, and this account may not create databases` | The configured database was not found, so the bootstrap tried to create it — Npgsql runs `CREATE DATABASE` from the `postgres` maintenance database, which an account restricted to its own database cannot open. Usually the name's case: unquoted `CREATE DATABASE CMS_Auth` stores `cms_auth` | `\l` in psql (as an admin) shows the stored name; compare it byte for byte with `Database=` | Create the database beforehand and match `Database=` to its stored name; quote a mixed-case name when creating it | Granting the app account `CONNECT` on `postgres` or `CREATEDB` |
| Bootstrap fails with `42501: permission denied for schema public`; now `this account may not create tables in database '…'` | PostgreSQL 15+: only the database owner may create in `public`, and the app account is not the owner | `\dn+ public` lacks a `C` privilege for the account | `ALTER DATABASE <db> OWNER TO <account>`, or `GRANT USAGE, CREATE ON SCHEMA public TO <account>` | Running the app as a superuser |
| Bootstrap fails in `ArkSchemaUpdater.Apply` with a permission error | The DB login cannot `ALTER`/`CREATE` | Error names the DDL statement | Grant DDL on the app's own tables, or apply the DDL out of band | Running the app as a superuser |
| Every page redirects to `/ark-idp/setup`; APIs answer 503 `setup_required` | The server is unconfigured: `TenantId` or `ConnectionStrings:ArkAuthConnection` is empty | `GET /ark-idp/setup/api/state` | Finish the wizard, or set both settings (the environment wins over the wizard's file) | Setting `Setup:Enabled=false` to hide it: the server then fails on the missing setting instead |
| Wizard asks for a setup code on your own machine | The request is not loopback, or a local proxy added `X-Forwarded-For` / `Forwarded` / `X-Real-IP`, or `Setup:RequireToken` is on | — | Use the code in the start-up log or `{DataPath}/setup-code.txt` | Turning off `RequireToken` on a server reachable by others |
| Wizard asks for a setup code in a container or on a hosted server (Docker, Azure App Service, Kubernetes, behind nginx) | Expected: requests there arrive through a proxy or from another network, never unproxied loopback | — | Read the code from the container log: `docker logs <container> 2>&1 \| grep "setup code"`; App Service: `az webapp log tail` (after `az webapp log config --docker-container-logging filesystem`) or Portal → Log stream. Or `{DataPath}/setup-code.txt` — on App Service, Kudu → Bash, when `DataPath` is under `/home` | Stripping the proxy headers so requests look local |
| No setup code in the log | The line is written once, at start-up, and has scrolled past; or container logging is off (App Service) | Search the log for `Ark.oAuth.Oidc.Setup` | Restart and read the start-up lines, or read `{DataPath}/setup-code.txt` | — |
| The wizard comes back after a restart or redeploy; the setup code changes on every start | `DataPath` is on the container's own filesystem (default `ark-idp-data` under the content root, e.g. `/app/ark-idp-data`), which every restart replaces, `settings.json` included | `settings.json` missing from `DataPath` after a restart | Point `ark_oauth_server__Setup__DataPath` at persistent storage (App Service: under `/home`, with `WEBSITES_ENABLE_APP_SERVICE_STORAGE=true`) and run the wizard again against the same database, which it attaches to; or move the settings into app settings / environment | Seeding a fresh database to get past it |
| Setup code refused although it was copied from the log | Several instances, each holding its own code; or the code is from an earlier start (no persistent `DataPath`) | Instance count; time of the log line | Scale to one instance until setup is finished; use the code from the latest start | — |
| Azure App Service: the wizard pre-fills an `http://` public URL; after install the console sign-in fails with `redirect_uri does not match` | App Service ends TLS in front of the container and ASP.NET Core ignores `X-Forwarded-Proto` unless told, so the app sees `http` | The failing request's `redirect_uri` starts with `http://` | Set `ASPNETCORE_FORWARDEDHEADERS_ENABLED=true` on the slot and restart; the public URL is the `https://` address users will use | Registering the `http://` callback |
| Wizard: "This server cannot write to …" / `cannot_write` | `DataPath` (default `ark-idp-data` under the content root) is not writable; .NET 8+ container images run as a non-root user | `data_directory_writable` in `/ark-idp/setup/api/state` | Set `ark_oauth_server__Setup__DataPath` to a writable, persistent volume and restart | Running the container as root |
| Wizard: `tenant_mismatch` | The database already holds Ark tenants; setup attaches to it rather than seeding | `database/test` lists `tenants` | Use one of those tenant ids, or an empty database | Deleting the existing tenants |
| After a wizard install the console sign-in fails with `redirect_uri does not match` | The public URL entered differs from the address the browser used | Compare `BaseUrl` in `settings.json` with the browser's origin | Browse via the public URL; or correct `BaseUrl` (restart; the console client's URIs are reconciled on start) | Registering every origin by hand |
| Requests fail before the DB exists | App handled a request before `UseArkAuthData()` ran | Check pipeline order | Ensure `UseArkAuthData()` is in the pipeline after `UseRouting()` | Removing `UseArkAuthData()` |
| Bootstrap fails with `23503: insert or update on table "clients" violates foreign key constraint "FK_clients_tenants_tenant_id"` (2.0.12 and earlier) | Tables exist but no tenant was ever seeded — a database created beforehand (it connected, so it was never seeded, and the schema updater created its tables empty), or a seed that failed after creating them. `ReconcileMachineClient` then inserts `{TenantId}_machine` for a tenant that does not exist | `SELECT count(*) FROM tenants` is 0 | Upgrade and restart: seeding is now decided by "no tenant", so it runs on that database. Nothing to delete | Dropping the DB, or inserting a tenant row by hand (no signing key, client or admin comes with it) |
| Bootstrap fails with `ark_oauth_server:TenantId is '…', but this database has no tenant of that name` | `TenantId` was changed after the database was seeded, or differs in case | `SELECT tenant_id FROM tenants` | Set `TenantId` back to the seeded operator tenant | Adding a tenant of the new name by hand |
| Bootstrap "succeeds" but nothing is seeded | 2.0.12 and earlier only — see the `23503` row above | The latch resets on a thrown bootstrap so the next request retries | Upgrade; a database with no tenant is seeded on start | Treating a half-created DB as initialised |

## Sign-in

| Symptom | Likely cause | Diagnosis | Correct solution | Avoid |
|---|---|---|---|---|
| Sign-in says the password is wrong for a correct password | No user-client **access mapping** | Is there a `user_client_claims` row for this user + client? | Add the mapping (provision with `POST /provision/client`, or the console) | Resetting the password |
| "Your account has been deactivated…" | The user's `is_active` is false | Only shown **after** the password verifies | Reactivate via `POST /activation/user` `is_active:true` | Assuming it's a credentials problem |
| "<app> has been deactivated…" | The client's `is_active` is false | Shown after password verifies | `POST /activation/client` `is_active:true` | — |
| Account locked out | `MaxFailedSignIns` consecutive failures | `Oidc:MaxFailedSignIns`/`LockoutMinutes` | Wait `LockoutMinutes`, or adjust the setting | Setting `MaxFailedSignIns=0` in production casually |
| Admin cannot sign in to the console | The admin's access mapping/redirect URIs drifted from `BaseUrl` | `ReconcileAdminConsoleClient` adds `/signin-oidc`; check `BaseUrl` matches the real host | Set `BaseUrl` to the public root and restart | Hand-editing client rows |

## Client integration

| Symptom | Likely cause | Diagnosis | Correct solution | Avoid |
|---|---|---|---|---|
| `redirect_uri does not match a registered value` | Callback not registered byte-for-byte | Compare the client's `redirect_uris` to what the app sends | Register both `/signin-oidc` and `/signout-callback-oidc` exactly | Wildcards |
| `invalid_scope` | Scope not on the client's whitelist, or scope not in the catalogue | Discovery `scopes_supported`; client `scopes` | Add the scope to the client / catalogue; `ReconcileScopeCatalogue` adds new built-ins on start-up | Assuming unknown scopes are dropped |
| `invalid_client` on token | Wrong `token_endpoint_auth_method` vs how the client authenticates | Client record vs the request | Match the registered method (basic/post/private_key_jwt/none) | Guessing the method |
| Client can't discover config | Wrong issuer / `BaseUrl` / tenant in the client's `Authority` | Fetch `{issuer}/.well-known/openid-configuration` | Point the client at `{BaseUrl}/{TenantId}` | Hard-coding endpoints |

## CORS / SPA

| Symptom | Likely cause | Diagnosis | Correct solution | Avoid |
|---|---|---|---|---|
| SPA token/userinfo call fails in the browser CORS preflight | Origin not in `Oidc:CorsOrigins`, or `UseArkOidcCors()` missing/mis-ordered | Browser console shows the blocked preflight | Add the exact origin; place `UseArkOidcCors()` after `UseRouting()`, before `UseAuthorization()` | A wildcard origin (none exists); enabling credentials |
| A rejected preflight has no CORS headers | `UseArkOidcCors()` after `UseAuthorization()` | Pipeline order | Move it before `UseAuthorization()` | — |

## Logout

| Symptom | Likely cause | Diagnosis | Correct solution | Avoid |
|---|---|---|---|---|
| Previous user on a shared machine stays signed in elsewhere after logout | `SignOutAllBrowserSessions` off, or the older session predates the browser cookie | `Oidc:SignOutAllBrowserSessions` | Keep it `true`; the `ark_idp_bid` cookie ties sessions to the browser | Turning it off without reason |
| A client isn't notified on logout | It registered no `backchannel_logout_uri` | Client record | Register one (console / `/oauth2/register` / provisioning) and implement the receiver | Deriving notified clients from live tokens |
| Console Sign out leaves the host cookie | `Admin:SignOutUrl` unset (falls back to `end_session_endpoint`) | Config | Point `Admin:SignOutUrl` at a host route that drops the cookie + OIDC scheme | Expecting the package to drop the host cookie |
| Client configured a front-channel logout that never fires | Front-channel logout is not implemented | Discovery `frontchannel_logout_supported: false` | Use back-channel logout instead | Relying on front-channel |

## Machine-to-machine / registration

| Symptom | Likely cause | Diagnosis | Correct solution | Avoid |
|---|---|---|---|---|
| `{tenant}_machine` can't get a token | It ships without a secret | Client record has no secret | Regenerate its secret in the console, or set `Management:MachineClientSecret` | Expecting it to work unconfigured |
| `/api/oauth/...` answers 401 `unauthorized` with a valid-looking token | Token not from the machine client, or lacks `client.register` | Server log: `management API token rejected: <reason>` | Use a `client_credentials` token from `{tenant}_machine` with `scope=client.register` | Giving another client `client.register` — the scope alone is refused |
| Console grids empty; API answers 403 `forbidden` | Signed in as someone other than the operator | The account is not `AdminUser:Username` and has no `admin` claim | Add the `admin` claim to that user's mapping to the console client, then sign in again | Expecting every console user to be an operator |
| Every request 500s after setting `MachineClientSecret` | Value shorter than 16 characters | Log: `MachineClientSecret is shorter than 16 characters` | Use `openssl rand -base64 32`, or unset it | Lowering the bar |
| "Regenerate secret" on the machine client refuses | `Management:MachineClientSecret` owns it | Setting is present | Rotate by changing the setting and restarting | Expecting a console secret to survive a restart |
| `/api/migration/...` answers 404 | `Management:AllowMigrationEndpoint` is off (default) | — | Switch it on for the repair, sign in as the operator, switch it off | Leaving it on |
| `invalid_scope` / `invalid_client_metadata` naming `client.register` | Privileged scope requested through provisioning or dynamic registration | — | Grant it to the client in the console, if it really needs it | Requesting it from a pipeline |
| `invalid_client: client authentication failed.` for `{tenant}_machine` (e.g. "Could not obtain an initial access token") after it used to work | The IdP database was recreated (deleted `data/`, factory reset, `replace` import), which seeds the machine client with **no** secret; or it was regenerated since | Token request with the stored secret fails; the client row has an empty `client_secret_hash` | Regenerate it in the console and hand the new value to the caller, or set `Management:MachineClientSecret` so every new database gets it | Assuming a secret the caller shows as "configured" still matches; secrets are stored hashed |
| Caller says the machine secret is "configured" although you set `ClientSecret` to null | Two different secrets: `ark_oauth_client:ClientSecret` is the app's own client, the machine secret is a separate setting | Look for the machine-secret setting (`sample:Machine:ClientSecret` in the sample) | Clear or fix that setting | Treating the app's client secret and the machine secret as one |
| `/oauth2/register` 404 / not advertised | Dynamic registration off | Discovery has no `registration_endpoint` | Set `Oidc:EnableDynamicRegistration=true` | Guessing the URL |
| Registration works but no one can sign in to the new client | Registration ≠ access mapping | — | Map a user to the client | Assuming registration grants access |

## Export / import / reset

| Symptom | Cause | Fix |
|---|---|---|
| No **Data** link; `/{tenant}/admin/data` and `/api/oauth/v1/data/*` answer 404 | `ark_oauth_server:Admin:DataTools:Enabled` is `false` | Set it `true` (the default) |
| 403 `operator_only` | Signed in, but not as `AdminUser:Username` and without an `admin` role | Sign in as the administrator |
| Analysis: `checksum_mismatch` | The file was edited (or damaged) after export | Re-export, or tick *edited on purpose* (`allow_modified: true`) |
| Analysis: `passphrase_invalid` | Wrong passphrase, or a truncated file | The passphrase is not stored anywhere; without it the file cannot be read |
| `replace` not possible: `operator_lockout` | The file lacks this server's `TenantId` tenant (exact case), `{TenantId}_client`, the `AdminUser:Username` account or its mapping to that client | Use a merge mode, or export from a server with the same `TenantId` and administrator |
| Every merge excludes `signing_keys` `{TenantId}` with `key_material_conflict` | Each server seeds its first key with `kid = TenantId`; two servers sharing a TenantId always collide | Expected — this server keeps its own key. Other keys from the file are added |
| Imported key arrives as `rollover`, not `active` | Merge never switches a tenant's signer; it already had an active key here | Tokens the key signed still verify (JWKS). Rotate in the console if it should sign |
| Apply: 409 `plan_changed` | The database (or the file / categories) changed after the analysis | Analyse again and review the new plan |
| Rows `excluded` with `case_conflict` | A tenant / client / user matches one here only by letter case | Fix the case in the source and re-import with `merge_skip` |
| Reset: 409 `seed_unavailable`; nothing deleted | No administrator password configured (`AdminUser:Password` / `DefaultPw`, or still a `<<placeholder>>`) | Configure one, restart, reset again |
| After reset/replace the console still shows the old name / keeps working | The host's auth cookie outlives the data | Sign out and back in; after reset use the **configured** admin password |
| After a **replace**, sign-in fails with `IDX10511: Signature validation failed` | The file's key reuses a kid the client already cached (`signing_key_kid_reused`), so it never refetches the JWKS | Wait ~5 minutes, or restart the host / client so it refetches |
| After a **reset**, the first sign-in fails with `IDX10503` (kid not found); the next one works | The reset key has a new kid; the cached JWKS lacks it and the client refetches on that failure | Sign in again |
| 413 `file_too_large` | Larger than `DataTools:MaxImportMegabytes` (default 100) | Raise it (the hard ceiling is 1 GB); the audit trail is usually what makes a file large |

## Runtime / dependency

| Symptom | Likely cause | Diagnosis | Correct solution | Avoid |
|---|---|---|---|---|
| First OIDC challenge dies with `MethodAccessException` / missing-method (naming no package) | Mixed `Microsoft.IdentityModel.*` (MySql.Data pulls Protocols 7.5.0) | `dotnet list package --include-transitive \| grep IdentityModel` | Keep the graph on `8.8.0` (pinned in the .csproj) | Letting MySql.Data pin Protocols down |
| Assets missing on disk in Development | `EmbeddedResourceUnpacker` runs only in Development | They're served from the assembly regardless | Ignore in Production; the served copies come from the assembly | Committing the unpacked copies as the source of truth |
| A revoked/replayed refresh token keeps working | Expected: replay revokes the whole family; issued access tokens live until expiry | Token is `at+jwt`, self-contained | Rely on short access-token lifetimes; revoke refresh to stop new ones | Expecting instant JWT revocation |
