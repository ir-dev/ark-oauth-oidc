<!--
  API-GUIDE.md — Ark.oAuth.Oidc
  Audience: AI coding agents needing exact host APIs, endpoints, settings and management routes.
  Every item is copied from this directory's source. If it is not here, read the .cs file.
-->

# Ark.oAuth.Oidc — API guide

Exact host-facing surface (namespace **`Ark.oAuth.Oidc`**, package `Ark.oAuth.Oidc` v2.0.11, `net9.0`).
Verified against the source. The provider is consumed by *hosting* it (three extension methods +
configuration) and by *calling* its HTTP endpoints (protocol + management APIs).

## Host extension methods (`ArkExtn`)

| Signature | Purpose | Order |
|---|---|---|
| `void IServiceCollection.AddArkOidcServer(IWebHostEnvironment environment)` | Register the DbContext, protocol services, CORS configurator, controllers/views, antiforgery. Unpacks embedded assets to the content root in Development. | in `ConfigureServices` |
| `void IApplicationBuilder.UseArkAuthData()` | One-time DB bootstrap: create + seed on first run, apply pending schema scripts, reconcile the admin/machine clients and scope catalogue. Latched (runs once per process). | after `UseRouting` |
| `void IApplicationBuilder.UseArkOidcCors()` | Enables the CORS middleware for endpoints marked `[EnableCors(ArkCors.PolicyName)]`. | after `UseRouting`, **before** `UseAuthorization` |

The host also calls **`AddArkOidcClient(configuration)`** and **`UseArkOidcClient()`** from
`Ark.oAuth.Client` (the admin console is itself an OIDC client). Full pipeline order:

```csharp
app.UseRouting();
app.UseArkOidcCors();     // only if SPA clients call token/userinfo cross-origin
app.UseArkAuthData();
app.UseArkOidcClient();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllerRoute("default", "{controller=Home}/{action=Index}/{id?}");
```

## Configuration (`ArkAuthServerConfig`, section `ark_oauth_server`)

| Property | Type | Default | Notes |
|---|---|---|---|
| `TenantId` | `string` | — | **Required.** A client `{TenantId}_client` is seeded for the console. |
| `BaseUrl` | `string` | — | **Required in practice.** Issuer = `{BaseUrl}/{TenantId}`. |
| `BasePath` | `string` | `""` | Set only if hosted under a sub-path. |
| `Provider` | `string` | `sqlite` | `sqlite` \| `mysql` \| `postgres`. **Not** `sqlserver`. |
| `UploadPath` | `string` | — | e.g. `./wwwroot/{0}/`. |
| `DefaultPw` | `string` | — | Initial password for new users; fallback for `AdminUser:Password`. |
| `UserPasswordMode` | `string` | `auto` | `admin_managed` \| `email_based` \| `auto`. |
| `AdminUser` | `ArkAdminUserConfig` | — | Seed account. `Username` (default `admin`), **`Password` (required, no safe default)**, `Name`. |
| `Admin` | `ArkAdminConsoleConfig` | — | `SignOutUrl` — host route the console's Sign out uses. `DataTools` — export / import / reset switches, see below. |
| `Oidc` | `ArkOidcOptions` | see below | Protocol switches; every value has a default. |
| `EmailConfig` | `ArkEmailConfig` | — | SMTP + branding (`host_logo`, `client_logo`, links, …). |
| `ConnectionStrings:ArkAuthConnection` | `string` | — | The database connection string. |

**`ArkOidcOptions`** (section `ark_oauth_server:Oidc`):

| Property | Default | Notes |
|---|---|---|
| `EnableDynamicRegistration` | `false` | RFC 7591 `/register`. Off — it creates clients. |
| `RequireRegistrationAccessToken` | `true` | Require an initial access token on `/register`. |
| `EnableDeviceFlow` | `true` | RFC 8628. |
| `EnablePushedAuthorizationRequests` | `true` | RFC 9126 `/par`. |
| `RequirePushedAuthorizationRequests` | `false` | Refuse plain `/authorize` not via PAR. |
| `DeviceCodeLifetimeSeconds` | `600` | |
| `DevicePollIntervalSeconds` | `5` | |
| `ParLifetimeSeconds` | `90` | |
| `SessionLifetimeMinutes` | `480` | |
| `MaxFailedSignIns` | `10` | 0 disables lockout. |
| `LockoutMinutes` | `15` | |
| `AlwaysRequireConsent` | `false` | |
| `EnableBackChannelLogout` | `true` | Notifies only clients with a `backchannel_logout_uri`. |
| `BackChannelLogoutTimeoutSeconds` | `5` | Per client; deliveries run in parallel. |
| `LogoutTokenLifetimeSeconds` | `120` | |
| `SignOutAllBrowserSessions` | `true` | Off ends only the session the cookie names. |
| `SignOutAcrossTenants` | `true` | Off keeps sign-out inside the tenant. |
| `CorsOrigins` | `[]` | Exact SPA origins; empty = cross-origin off (no wildcard). |

**`ArkDataToolsConfig`** (section `ark_oauth_server:Admin:DataTools`). Every value defaults to on, so
a configuration written before this section existed gets the data page as documented. Whatever these
say, every data route is restricted to the operator account.

| Property | Default | Notes |
|---|---|---|
| `Enabled` | `true` | The whole data page and its API. `false` hides the nav link and answers 404. |
| `AllowReset` | `true` | Factory reset. `false` answers 403 before anything is read. |
| `AllowImport` | `true` | Import in any mode. `false` leaves export only. |
| `AllowReplace` | `true` | The `replace` import mode (the one that deletes first). Merge modes never delete a row. |
| `MaxImportMegabytes` | `100` | Largest import body accepted (hard ceiling 1 GB). Over it: 413 `file_too_large`. |

**`ArkUserPasswordMode`** enum: `Auto`, `AdminManaged`, `EmailBased`. Helper:
`ArkAuthServerConfig.EffectiveUserPasswordMode`, `ShouldUseEmailPasswordFlow(loginId, requestedByCaller)`.

## Protocol endpoints (relative to the issuer `{BaseUrl}/{TenantId}`)

Built by `Protocol.ArkOidcEndpoints`. All advertised in discovery.

| Purpose | Path |
|---|---|
| Discovery | `/.well-known/openid-configuration` (also `/.well-known/oauth-authorization-server`, RFC 8414) |
| JWKS | `/.well-known/jwks.json` (also `/oauth2/jwks`) |
| Authorization | `/oauth2/authorize` |
| Token | `/oauth2/token` |
| UserInfo | `/oauth2/userinfo` |
| Introspection | `/oauth2/introspect` (RFC 7662) |
| Revocation | `/oauth2/revoke` (RFC 7009) |
| End session | `/oauth2/logout` (RP-initiated; browser-wide) |
| Device authorization | `/oauth2/device_authorization` (RFC 8628) · verification `/oauth2/device` |
| Pushed authorization request | `/oauth2/par` (RFC 9126) |
| Dynamic registration | `/oauth2/register` (RFC 7591/7592; only if enabled) |
| Client setup page | `/oauth2/integrate/{client_id}` |

**Discovery advertises** (verified in `OidcDiscoveryController`):
`response_types_supported: [code]`; `grant_types_supported: authorization_code, refresh_token,
client_credentials` (+ `urn:ietf:params:oauth:grant-type:device_code` if device flow on);
`code_challenge_methods_supported: [S256]`; `id_token_signing_alg_values_supported: [RS256]`;
`subject_types_supported: [public]`;
`token_endpoint_auth_methods_supported: client_secret_basic, client_secret_post, private_key_jwt, none`;
`authorization_response_iss_parameter_supported: true` (RFC 9207);
`backchannel_logout_supported: true`, `backchannel_logout_session_supported: true`;
`frontchannel_logout_supported: false` (front-channel logout is **not** implemented);
`scopes_supported`/`claims_supported` from the catalogue. Access tokens are `at+jwt` (RFC 9068) with
`client_id`, `jti`, `scope`.

**Not supported (by design):** implicit grant, hybrid flow, resource-owner password credentials,
plain PKCE, SQL Server.

## Provisioning & activation API (`ProvisionController`, `[Authorize]`, base `/api/oauth`)

| Method + route | Body | Result |
|---|---|---|
| `POST /v1/provision/client` | `ArkProvisionRequest` | 200 `{error:false, code:"provisioned", data: ArkProvisionResult}`; 409 `{error:true, code:"client_exists"}` (nothing written) |
| `POST /v1/provision/user` | `ArkProvisionUserRequest` | 200 `{error:false, code:"provisioned", data: ArkProvisionUserResult}`; 404 `unknown_client` / `unknown_tenant`; 400 `invalid_request` |
| `POST /v1/activation/client` | `ArkActivationRequest` | client `is_active` on/off; deactivation revokes its refresh tokens |
| `POST /v1/activation/user` | `ArkActivationRequest` | user `is_active` on/off; deactivation revokes sessions + refresh tokens |

**`ArkProvisionRequest`**: `client_name` (**required**), `user_name` (**required**), `tenant_id`
(default `TenantId`), `client_id` (derived from name), `client_logo`, `redirect_uris`,
`post_logout_redirect_uris`, `backchannel_logout_uri`, `scopes` (default openid/profile/email/
offline_access), `application_type` (web|spa|native|service, default web), `token_endpoint_auth_method`
(default `none`), `user_display_name`, `claims` (default identity claims), `send_activation_email`
(default false).

**`ArkProvisionResult`**: `tenant_id`, `client_id`, `client_name`, `client_created`, `user_name`,
`user_created`, `user_credential` (`default_password`|`activation_email`|`existing_account`),
`mapping_created`, `claims`, `redirect_uris`, `issuer`, `discovery`, `setup_url`.

**`ArkProvisionUserRequest`**: `client_id` (**required**, the public client_id of an existing client),
`user_name` (**required**), `tenant_id` (default `TenantId`), `user_display_name` (new accounts only;
default `user_name`), `claims` (added to `sub name email email_verified`, which are always mapped),
`send_activation_email` (default false). An existing account is never modified — only its mapping is
written, keeping the claims it already held. A new account gets `DefaultPw`.

**`ArkProvisionUserResult`**: `tenant_id`, `client_id`, `client_name`, `user_name`, `user_created`,
`user_credential` (`default_password`|`activation_email`|`existing_account`), `mapping_created`,
`claims` (what the mapping now holds).

**`ArkActivationRequest`**: `tenant_id`, `client_id`, `user_name`, `is_active`, `reason`.

## Management API (`ManageController`, operator policy, base `/api/oauth`)

All `v1/...`; list endpoints are GET, mutations are POST with the entity in the body. On failure they
return `{ error, msg }`.

**Who may call it** (`ManageController` and `ProvisionController`, policy `ArkManagementAuth.PolicyName`).
The package registers this itself in `AddArkOidcServer`; the host adds nothing and keeps its own default
scheme. Two callers are admitted:

| Caller | Admitted when |
|---|---|
| Console session (the host's default scheme, normally the `ArkCookie` from `AddArkOidcClient`) | the account is the operator: `AdminUser:Username`, or an `admin` / `ark_admin` claim on its mapping to the console client |
| `Authorization: Bearer <token>` | the token was issued by this server's operator tenant, carries `client.register`, and was issued to `{TenantId}_machine` — or to a client in `Management:OperatorDeviceClients` that is public, device-code-only, has no redirect URIs, and whose code the operator approved |

Not admitted answers `401` (no or refused credential, with `WWW-Authenticate: Bearer`) or `403`
(signed in, not the operator), each with `{ error: true, code, msg }` — never a redirect to the sign-in
page. The reason a token was refused is logged by the server, not returned.

```http
POST /{TenantId}/oauth2/token
grant_type=client_credentials&client_id={TenantId}_machine&client_secret=<secret>&scope=client.register

GET /api/oauth/v1/client/list
Authorization: Bearer <access_token>
```

Configuration, all optional (`ark_oauth_server:Management`):

| Key | Default | Meaning |
|---|---|---|
| `MachineClientSecret` | unset | Applied to `{TenantId}_machine` on start-up; changing it rotates the secret on the next start. At least 16 characters, or the bootstrap stops with a message. While set, `v1/client/secret/reset` refuses that client. Keep it in a key vault or environment variable. |
| `OperatorDeviceClients` | `[]` | Device-code clients whose operator-approved tokens may drive the API. |
| `AllowMigrationEndpoint` | `false` | `/api/migration` answers 404 while off. |

| Area | Routes |
|---|---|
| Tenants | `v1/tenant/list`, `v1/tenant/upsert` |
| Clients | `v1/client/list`, `v1/client/upsert`, `v1/client/delete`, `v1/client/secret/reset` |
| Claims | `v1/claim/list`, `v1/claim/upsert`, `v1/claim/delete` |
| Scopes | `v1/scope/list`, `v1/scope/upsert`, `v1/scope/delete` |
| Users | `v1/user/list`, `v1/user/upsert`, `v1/user/pw/reset/init`, `v1/user/pw/set` |
| Access mapping | `v1/user/list/client/claims/mapping/{email}/{ten_id}`, `v1/user/client/claims/upsert`, `v1/user/client/claims/delete` |
| Service token | `v1/service/pw/reset` |
| Legacy onboarding | `onboard/full`, `onboard/user` (superseded by provisioning) |

## Data tools API — export, import, factory reset (`DataToolsController`, base `/api/oauth`)

Operator only (`ArkOperator.IsOperator`: the `AdminUser:Username` account, or a principal with an
`admin` / `ark_admin` role) — a signed-in non-operator gets 403 `operator_only`, an anonymous caller
401. 404 when `DataTools:Enabled` is false. Everything that changes data is a **POST with a JSON
body**; cross-origin, that needs a CORS preflight this server never grants, which is the CSRF
protection (the console reads an import file in the browser and posts it as JSON, never multipart).
Responses: `{ error, code, msg, data }` with a real HTTP status — except export, which returns the file.

| Method + route | Body | Result |
|---|---|---|
| `GET  /v1/data/summary` | — | `data`: `counts` per table, `categories`, `operator_tenant`, `admin_user`, `package_version`, `format_version`, `allow_reset`, `allow_import`, `allow_replace`, `max_import_mb`, `seed_problem` (why a reset could not seed, or null) |
| `POST /v1/data/export` | `ArkExportRequest` | 200 `application/json` attachment `ark-idp-{TenantId}-{yyyyMMdd-HHmmss}[.encrypted].json` |
| `POST /v1/data/import/analyze` | `ArkImportRequest` | 200 `code:"analysed"` or `"file_blocked"`, `data: ArkImportAnalysis`. **Writes nothing.** |
| `POST /v1/data/import/apply` | `ArkImportRequest` + `mode`, `plan_hash` (+ `confirm` for replace) | 200 `code:"imported"`, `data: ArkImportResult` |
| `POST /v1/data/reset` | `ArkResetRequest` | 200 `code:"reset"`, `data: ArkResetResult` |

Every export, import and reset writes an audit row (`log_type:"audit"`, `ref_key` `data_export` /
`data_import` / `data_reset`, `by` = the operator) **regardless of `EnableLogTrace`**.

### Export

**`ArkExportRequest`**: `passphrase` (optional — encrypts the file), `include_setting_secrets`
(default `false` — secrets in the settings block are written as `<<redacted>>`).

What is in the file — **every mapped table and every mapped column**, read from the EF model rather
than a hand-written list, so a column added in a later release is exported with no change to the
exporter. That includes what the management API never returns: `users.hash_pw`,
`clients.client_secret_hash`, `clients.registration_access_token_hash`, `signing_keys.private_key`,
`tenants.rsa_private`. Rows are ordered by primary key, so two exports of an unchanged database
differ only in `exported_at`.

| Category | Tables |
|---|---|
| `configuration` | `tenants`, `signing_keys`, `claims`, `scopes`, `clients`, `users`, `user_client_claims`, `service_accounts` |
| `grants` | `consents`, `sessions`, `session_clients`, `refresh_tokens` |
| `transient` | `auth_codes`, `device_codes`, `par_requests`, `pkce_code_flow` |
| `history` | `auth_status`, `audit_trace` |
| `other` | any table a later release adds that is not listed above |

App settings: the `ark_oauth_server`, `ark_oauth_client` and `ConnectionStrings` configuration
sections, as a JSON tree. A value is a secret when its key **ends** in `password`, `passwd`,
`secret`, `token`, `apikey`, `api_key`, `privatekey`, `private_key`, `pw` or `connectionstring`, or sits
under `ConnectionStrings` — and is not a plain `true`/`false` or number. Not exported:
`ark_schema_history` (the target keeps its own schema state).

File format (`format_version` 1):

```json
{
  "format": "ark-idp-export",
  "format_version": 1,
  "manifest": {
    "exported_at": "2026-10-31T15:41:13Z", "exported_by": "admin", "package_version": "2.0.13",
    "provider": "sqlite", "operator_tenant": "ark_idp", "base_url": "https://idp.example.com",
    "admin_user": "admin", "encrypted": false, "settings_secrets_redacted": true,
    "checksum": "sha256:…", "counts": { "tenants": 2, "clients": 5, "…": 0 }
  },
  "settings": { "ark_oauth_server": { "…": "…" }, "ark_oauth_client": { }, "ConnectionStrings": { } },
  "data":     { "tenants": [ { "tenant_id": "ark_idp", "…": "…" } ], "clients": [ ], "…": [ ] }
}
```

- `checksum` = SHA-256 over the canonical form of `{ settings, data }`: object keys sorted, no
  whitespace, values re-emitted from their parsed form. Re-indenting the file keeps it valid; changing
  any value does not.
- Encrypted (`passphrase` given): `settings` and `data` are replaced by `payload` =
  `{ alg: "A256GCM", kdf: "PBKDF2-SHA256", iterations: 210000, salt, nonce, tag, ciphertext }`
  (base64), with associated data `ark-idp-export/1`. The checksum is of the plaintext and is verified
  after decryption. Nothing about the passphrase is stored; a lost passphrase is a lost file.

### Import — analyse, choose, apply

**`ArkImportRequest`**: `file` (the export, as a JSON object), `passphrase` (encrypted files),
`include` (categories to load; omitted = all; `configuration` is always added; an unknown name is 400
`invalid_request`), `allow_modified` (accept a checksum mismatch), and for apply only: `mode`,
`plan_hash`, `confirm`.

1. **Analyse.** The server parses the file, loads this database, and works out **all three modes in
   full**. Nothing is written.
2. **Choose.** The response says which modes are possible, what each would do to every row, and
   recommends one (below). The operator — or the calling script — picks.
3. **Apply** with `mode` and that mode's `plan_hash`. The server works the plan out again; if the hash
   differs (the database or the file changed since the analysis) it refuses with 409 `plan_changed`
   and writes nothing. Otherwise the whole plan runs in **one transaction** — a failure rolls
   everything back — followed, inside the same transaction, by the start-up reconciliations (the
   admin console client's callbacks for *this* host, missing default scopes, the machine client).

**Modes:**

| Mode | Deletes first | Row already here (same identity) | Row not here |
|---|---|---|---|
| `merge_skip` | nothing | left as it is (`skip_existing`, reason `exists`) | inserted |
| `merge_overwrite` | nothing | updated to the file's values (`update`) — except protected records | inserted |
| `replace` | **every table** (also the categories not selected) | — | inserted, ids kept as exported |

`replace` requires `confirm` = the operator tenant id, exactly (400 `confirmation_required`), and is
refused by `AllowReplace:false` (403 `replace_disabled`). After a replace the database is an exact
copy of the file — same surrogate ids, password hashes, secret hashes and private keys — plus the
reconciled console callbacks and any claim a mapping needed.

**Recommendation** (deterministic): `replace` when this server holds nothing but its first-run seed
(`target_pristine`) and replace is possible; otherwise `merge_skip` — with the reason stated, and the
count of rows `merge_overwrite` would change.

**Identity of a row** — what "already here" means. Compared case-insensitively:

| Table | Identity |
|---|---|
| `tenants` | `tenant_id` |
| `clients` | `tenant_id` + `client_id` (the surrogate `id` is remapped to this server's) |
| `users` | `email` (lower-cased first) |
| `user_client_claims` | `email` + `tenant_id` + client — the file's client **surrogate id is followed** to wherever that client ended up here |
| `consents` | `tenant_id` + `client_id` + `subject` |
| `auth_status` | `email` (the int id is left for the database to number) |
| every other table | its primary key (`kid`, `key`, `name`, `token_hash`, `session_id`, …) |

**Actions** a row can get: `insert`, `update`, `unchanged` (identical in every column),
`skip_existing`, `excluded`, `not_selected` (its category was not in `include`).

**Exclusion rules.** A row that cannot be loaded safely is **excluded — never loaded, never partly
loaded** — and so is every row that depends on it (`parent_excluded`). The rest of the import goes
ahead. Rows are visited in the fixed table order above and in file order within a table; for
duplicates the first row wins.

| Reason | When |
|---|---|
| `invalid_record` | the row is not a JSON object |
| `invalid_value` | a column holds a value of the wrong type (e.g. `"is_active": "yes"`) |
| `missing_required` | a NOT NULL column is empty |
| `duplicate_in_file` | an earlier row in the file has the same identity (case-insensitive) |
| `case_conflict` | the row, or a tenant/client it references, matches an existing one **only by letter case** — references must match exactly because the foreign keys do |
| `missing_tenant` / `missing_user` / `missing_client` | a reference to something neither in the file nor on this server |
| `parent_excluded` | it references a row that was itself excluded |
| `tenant_mismatch` | a mapping names a tenant other than its client's |
| `invalid_login_id` | a user id that is neither an email nor a 2–64 char `[a-z0-9._-]` username |
| `unsafe_uri` | a client URI carries script (`javascript:`, `data:`, `file:`, whitespace) |
| `client_name_conflict` | another client in the same tenant already has this name |
| `kid_conflict` | the key id exists here under a different tenant |
| `key_material_conflict` | the key id exists here with different key material (always the case for the seeded `kid = TenantId` key between two servers sharing a TenantId — this server keeps its own) |
| `unique_conflict` | another unique column (e.g. `device_codes.user_code`) is taken by a different record |
| `expired` | a `grants` / `transient` row whose `expires_at` has passed |
| `id_conflict` | no free surrogate id could be derived (practically unreachable) |

**Skip reasons** (`skip_existing`): `exists` (merge_skip), `protected_operator_record` —
merge_overwrite never overwrites the operator tenant, `{TenantId}_client`, `{TenantId}_machine`, the
administrator account or `service_account_{TenantId}` (its credential is a token signed by its own
server's key) — and `key_state_owned_by_target` (an identical key already here keeps its
active/rollover/retired status).

**Adjustments** — changes made so a row can be loaded, listed per row: email lower-cased; a mapping's
client reference remapped to this server's id for the same client; a surrogate id that belongs to a
*different* record here regenerated as `SHA-256(table + natural key)` → GUID (deterministic, never
random); an imported `active` signing key demoted to `rollover` when its tenant already signs with a
key here (merge modes — the server's signer is never switched by an import; tokens the key signed
still verify via JWKS); a claim a mapping uses but neither side defines added to the catalogue
(`claim_added`).

**File blockers** stop every mode (analyse answers 200 `file_blocked`; apply 422 `import_blocked`):
`invalid_format`, `unsupported_version` (a newer `format_version`), `passphrase_required`,
`passphrase_invalid`, `checksum_mismatch` (unless `allow_modified` — then a warning).

**Mode blockers** stop one mode (apply 422 `mode_blocked`): `operator_lockout` — replace when the file
does not supply the operator tenant (exact `TenantId`), `{TenantId}_client`, the administrator account
**and** a mapping between those two, because the console would be left with nobody able to sign in;
`replace_disabled`.

**Warnings** (informational): `checksum_missing`, `checksum_mismatch` (allowed), `unknown_table`
(ignored), `table_absent` (older export; treated as empty — and emptied by replace), `newer_source`
(unknown columns ignored), `base_url_differs`, `operator_records_kept`, and per mode
`signing_key_kid_reused` — replace loads a key whose kid exists here with different material (always
true for the seeded `kid = TenantId` key between two servers); relying parties with a cached JWKS,
this host's console included, reject signatures until they refetch (≈5 minutes for ASP.NET Core) or
restart.

**Determinism.** The plan is a pure function of (file, database, mode, categories). Analysing twice
returns the same `plan_hash`; the hash covers every row's action, reason and adjustments, the file
checksum, the categories and the per-table row counts of this database — except the `history`
tables, which the server writes by itself (sign-ins, the backup export taken just before an import).

**App settings are compared, never applied.** `settings` lists each key that differs —
`different`, `only_in_file`, `only_here`, `redacted_in_file` — with secrets shown as `<<redacted>>`.
Configuration belongs to the host (appsettings, environment, a secret store), and the file's
connection string points at the database it was exported from. To load them as they are,
`settings_file` in the analysis returns the file's settings verbatim in `appsettings.json` shape
(the page offers it as a download, `appsettings.imported.json`); values redacted at export stay
`<<redacted>>` and have to be filled in.

**Response types.** `ArkImportAnalysis`: `file` (`ArkExportFileInfo`: manifest fields, `encrypted`,
`checksum_ok`, `counts`), `blockers`, `warnings`, `target_counts`, `target_pristine`, `include`,
`recommended_mode`, `recommendation`, `modes` (`replace` / `merge_skip` / `merge_overwrite` →
`ArkImportPlan`), `settings` (`ArkSettingDiff[]`), `settings_same`, `settings_file`. `ArkImportPlan`: `mode`,
`possible`, `blockers`, `warnings`, `plan_hash`, `summary` (count per action, plus `adjusted`),
`tables` (count per action per table), `deletes` (replace), `records` (`ArkImportRecord`: `table`,
`index`, `key`, `action`, `reason`, `detail`, `adjustments` — every excluded, skipped, updated or
adjusted row, first 1000), `records_truncated`. `ArkImportResult`: `mode`, `summary`, `tables`,
`deleted`, `records`, `records_truncated`, `follow_up`.

```bash
# analyse, then apply the recommended mode (jq)
curl -s -b cookies -H 'Content-Type: application/json' -X POST "$API/v1/data/import/analyze" \
     -d "$(jq -n --slurpfile f export.json '{file:$f[0]}')" > analysis.json
MODE=$(jq -r .data.recommended_mode analysis.json); HASH=$(jq -r ".data.modes.$MODE.plan_hash" analysis.json)
curl -s -b cookies -H 'Content-Type: application/json' -X POST "$API/v1/data/import/apply" \
     -d "$(jq -n --slurpfile f export.json --arg m "$MODE" --arg h "$HASH" --arg c "$TENANT" \
           '{file:$f[0], mode:$m, plan_hash:$h, confirm:$c}')"
```

### Factory reset

**`ArkResetRequest`**: `confirm` = the operator tenant id, exactly (400 `confirmation_required`).

1. **Pre-flight, before anything is deleted:** the seed must be able to run — `TenantId` set and an
   administrator password configured (`AdminUser:Password` or `DefaultPw`, not a `<<placeholder>>`).
   Otherwise 409 `seed_unavailable` and nothing changes. `summary.seed_problem` shows the same check.
2. In one transaction: delete every row of every table (children first), then run **the same seed a
   new database gets** (`ArkExtn.SeedDatabase` — one implementation, shared with the bootstrap), then
   the start-up reconciliations. A failure rolls back to the data as it was.
3. The schema and `ark_schema_history` are kept, so the server stays current — just empty.

Afterwards: one tenant `{TenantId}` with a **new** signing key — named by its thumbprint, not
`kid = TenantId` as on a fresh install (the only difference from one): reusing the old kid for new
material would let every relying party with a cached JWKS, the host's own console first, keep the
kid it knows and fail signatures (`IDX10511`) for minutes. With a new kid the first token fails with
`IDX10503`, the client refetches, and the next sign-in succeeds. Beside the key:
`{TenantId}_client`,
`{TenantId}_machine` (no secret), the default scopes and identity claims, the administrator account on
its **configured** password, the default service account, their two mappings — and one audit row
recording the reset. Every other client, user, mapping, key, session and token is gone; the
operator's browser cookie stays valid until it expires, but should sign out and in again.

### Compatibility

- **Additive only.** New routes, page, settings and types; no schema change, no migration, no change
  to an existing route's behaviour. `SeedDatabase` / `Reconcile` are the bootstrap's former inline
  code, extracted unchanged. `DataAccess.Record` is a new method; `DataAccess.Log` is untouched.
- **Files across releases.** An export from an older release lacks newer columns — the import fills
  them with the entity defaults (e.g. `is_active = true`) — and may lack newer tables (`table_absent`).
  A file from a newer release imports as long as its `format_version` is supported; columns this
  server does not know are ignored (`newer_source`). A higher `format_version` is refused.
- **Across providers.** The file is provider-neutral: export from SQLite, import into PostgreSQL or
  MySQL, and back.

## Migration API (`MigrationController`, base `/api/migration`)

| Method + route | Purpose |
|---|---|
| `POST /v1/sql?action=up\|down&name=00005_sql.sql` | Run or roll back one script by hand (reports whether it worked). |
| `GET /v1/embeded/list` | List embedded migration resources. |

> Off unless `ark_oauth_server:Management:AllowMigrationEndpoint` is `true` — both routes answer 404
> while off, to anyone. When on, they need the operator's console session (not a machine token). The
> schema updates itself on start-up, so switch this on only for a repair, then off again.

## Admin console (UI)

| Purpose | Path |
|---|---|
| Console | `/{tenant_id}/admin` (`/admin` → configured tenant) |
| Provisioning page (admin-only) | `/{tenant_id}/admin/provisioning` |
| Data page — export, import, factory reset (admin-only; `DataTools:Enabled`) | `/{tenant_id}/admin/data` |
| Assets (from assembly) | `/ark-admin/asset/ark-admin.css`, `/ark-admin/asset/ark-admin.js` |

Restricted to the administrator account (`AdminUser:Username`, or a principal carrying an `admin`
claim). Override a page by placing your own `Views/Admin/Manage.cshtml` in the host. The v1 console at
`/oauth/{tenant}/v1/server/{client_id}/manage` is still served but no longer developed.

## Seeded on first run

- Tenant `{TenantId}` with an in-process RSA signing key (`kid == tenant_id`, `RS256`).
- Admin console client `{TenantId}_client` (public, PKCE, `authorization_code`+`refresh_token`,
  redirect URIs include `/signin-oidc` and the v1 callback).
- Machine client `{TenantId}_machine` (`client_credentials`, `client_secret_post`, scope
  `client.register`) — **without a secret**; regenerate one in the console, or set
  `Management:MachineClientSecret`, before use. It is the only client whose tokens drive the
  management API.
- The default scope catalogue, identity claims, the admin user, and a default service account.

## Public types (for reference)

- `Protocol.ArkOidcOptions`, `Protocol.ArkCors.PolicyName = "ark-oidc-browser"`,
  `Protocol.ArkOidcEndpoints` (issuer/endpoint builder).
- `ArkAuthServerConfig`, `ArkAdminUserConfig`, `ArkAdminConsoleConfig`, `ArkEmailConfig`,
  `ArkUserPasswordMode`.
- `ArkProvisioning` (DI-registered), `ArkProvisionRequest`/`ArkProvisionResult`/`ArkProvisionException`.
- `ArkActivationLevel`, `ArkAccountInactiveException` (`FriendlyMessage`).
- `ArkDataTools` (DI-registered), `ArkDataToolsConfig`, `ArkExportRequest`, `ArkImportRequest`,
  `ArkResetRequest`, `ArkImportAnalysis`, `ArkImportPlan`, `ArkImportRecord`, `ArkImportResult`,
  `ArkResetResult`, `ArkExportFileInfo`, `ArkSettingDiff`, `ArkDataIssue`, `ArkDataToolsException`.
- `EmbeddedResourceUnpacker` (Development asset unpacking).
