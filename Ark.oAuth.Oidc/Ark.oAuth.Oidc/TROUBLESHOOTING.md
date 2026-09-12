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
| First run throws naming `AdminUser:Password` and creates no DB | No admin password configured (or a `<<placeholder>>`) | `ResolveAdminUser` refuses to seed | Set `ark_oauth_server:AdminUser:Password` (or `DefaultPw`) out of band | Re-introducing a compiled-in `admin`/`admin` default |
| Context has no provider configured / DB errors | `Provider: "sqlserver"` | `OnConfiguring` has no `sqlserver` branch | Use `sqlite`/`mysql`/`postgres` | Expecting SQL Server support |
| `/api/oauth/v1/user/list` returns a bare 500, console Users grid empty | A schema script (e.g. 00004 `users.is_active`) was never applied | On MySQL/PostgreSQL only SQLite scripts auto-apply | Apply the `ALTER TABLE`/`CREATE TABLE` for 00003/00004/00005 | Assuming MySQL/PG auto-migrate |
| Requests fail before the DB exists | App handled a request before `UseArkAuthData()` ran | Check pipeline order | Ensure `UseArkAuthData()` is in the pipeline after `UseRouting()` | Removing `UseArkAuthData()` |
| Bootstrap "succeeds" but nothing is seeded | An empty schema left behind by a failed earlier seed | The latch resets on a thrown bootstrap so the next request retries | Fix the underlying cause; delete the empty DB file so seeding re-runs | Treating a half-created DB as initialised |

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
| `{tenant}_machine` can't get a token | It ships without a secret | Client record has no secret | Regenerate its secret in the console | Expecting it to work unconfigured |
| `/oauth2/register` 404 / not advertised | Dynamic registration off | Discovery has no `registration_endpoint` | Set `Oidc:EnableDynamicRegistration=true` | Guessing the URL |
| Registration works but no one can sign in to the new client | Registration ≠ access mapping | — | Map a user to the client | Assuming registration grants access |

## Runtime / dependency

| Symptom | Likely cause | Diagnosis | Correct solution | Avoid |
|---|---|---|---|---|
| First OIDC challenge dies with `MethodAccessException` / missing-method (naming no package) | Mixed `Microsoft.IdentityModel.*` (MySql.Data pulls Protocols 7.5.0) | `dotnet list package --include-transitive \| grep IdentityModel` | Keep the graph on `8.8.0` (pinned in the .csproj) | Letting MySql.Data pin Protocols down |
| Assets missing on disk in Development | `EmbeddedResourceUnpacker` runs only in Development | They're served from the assembly regardless | Ignore in Production; the served copies come from the assembly | Committing the unpacked copies as the source of truth |
| A revoked/replayed refresh token keeps working | Expected: replay revokes the whole family; issued access tokens live until expiry | Token is `at+jwt`, self-contained | Rely on short access-token lifetimes; revoke refresh to stop new ones | Expecting instant JWT revocation |
