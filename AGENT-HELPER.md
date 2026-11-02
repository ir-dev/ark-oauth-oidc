# AGENT-HELPER — copy-paste prompts for AI coding agents

Four prompts, one per job. Each sits in a fenced block: copy the whole block into your coding agent
(Claude Code, Copilot, Cursor and so on), fill in the `<<PLACEHOLDERS>>` and send it. Every prompt
stands alone and repeats the facts it depends on, so you can paste one without the others.

| # | Scenario | Prompt |
|---|---|---|
| 1 | New ASP.NET Core MVC project that **is** the identity provider | [Prompt 1](#prompt-1--new-aspnet-core-mvc-project-hosting-the-ark-idp) |
| 2 | Upgrade an existing Ark IdP host to the latest version | [Prompt 2](#prompt-2--upgrade-an-existing-ark-idp-host-to-214) |
| 3 | Connect an app to an **existing** Ark IdP: .NET, Python or Node | [Prompt 3](#prompt-3--connect-an-app-to-an-existing-ark-idp-net--python--node) |
| 4 | Point the Ark client libraries at **any other** OIDC provider | [Prompt 4](#prompt-4--use-the-ark-client-libraries-against-an-external-idp) |

**Facts behind the prompts** (checked against the source and the registries on 2026-11-02):

| | |
|---|---|
| Latest release | **2.1.4**, the same number for all four packages (git tag `v2.1.4`) |
| IdP | NuGet `Ark.oAuth.Oidc`, `net9.0`, namespace `Ark.oAuth.Oidc` |
| .NET client | NuGet `Ark.oAuth.Client`, `net9.0`, namespace **`Ark.oAuth`** (not `Ark.oAuth.Client`) |
| Python client | PyPI `ark-oauth-client`, Python 3.9+, import `ark_oauth_client` |
| Node client | npm `ark-oauth-client`, Node 20+, ESM, no runtime dependencies |
| Issuer / authority | `{BaseUrl}{BasePath}/{TenantId}`. Discovery is at `{issuer}/.well-known/openid-configuration` |
| Deeper docs, shipped inside each package | `AI-PROMPT.md`, `AI-RECIPES.md`, `API-GUIDE.md`, `TROUBLESHOOTING.md`, `MIGRATION.md`, next to each README |

**Placeholder conventions used throughout:**

| Placeholder | Example | Meaning |
|---|---|---|
| `<<IDP_BASE_URL>>` | `https://idp.example.com` | Public origin of the IdP, with no trailing slash |
| `<<TENANT_ID>>` | `my_idp` | The tenant the app signs in against |
| `<<DISCOVERY_URL>>` | `https://idp.example.com/my_idp/.well-known/openid-configuration` | Paste this if you have it. The authority is this URL with `/.well-known/openid-configuration` removed |
| `<<CLIENT_ID>>` | `billing_portal` | The client registered on the IdP |
| `<<APP_BASE_URL>>` | `https://localhost:5001` | Origin of the app being built, exactly as the browser sees it |

> Do not put secrets in a prompt you keep, in `appsettings.json` or in a committed `.env`. This
> repository is public. Every prompt below tells the agent to use user-secrets or environment
> variables for secrets.

---

## Prompt 1 — New ASP.NET Core MVC project hosting the Ark IdP

Use this when the MVC app **is** the identity provider. It hosts the sign-in pages, the tokens and
the admin console. For an app that only *signs users in against* an IdP, use Prompt 3.

```text
Create a new ASP.NET Core MVC project and turn it into an Ark OAuth 2.1 / OpenID Connect identity
provider, using the published NuGet package Ark.oAuth.Oidc (latest: 2.1.4).

INPUTS
- Project name:            <<PROJECT_NAME>>            (e.g. MyCompany.Idp)
- Setup mode:              <<wizard | configured>>     (wizard = nothing configured, browser setup on first run;
                                                        configured = everything in appsettings/user-secrets)
- Keep MVC home page at /: <<yes | no>>                (no = "/" redirects to the IdP admin console)
Only needed for "configured" mode:
- Public base URL:         <<IDP_BASE_URL>>            (e.g. https://localhost:7233; must match launchSettings)
- Tenant id:               <<TENANT_ID>>               (lowercase, e.g. my_idp; becomes part of the issuer)
- Database:                <<sqlite | postgres | mysql>>
- Connection string:       <<CONNECTION_STRING>>       (sqlite default: Data Source=ark-idp-data/ark_idp.db)
- Admin username:          <<ADMIN_USERNAME>>          (default "admin")

HARD RULES (do not deviate)
1. Use the package's own extension methods. Do not hand-write OAuth/OIDC endpoints, token code,
   signing-key handling, or a login page. Do not invent APIs or settings: if unsure, read the
   README.md / AI-PROMPT.md / API-GUIDE.md packed in the Ark.oAuth.Oidc nupkg
   (~/.nuget/packages/ark.oauth.oidc/2.1.4/).
2. Target net9.0 (the package targets net9.0). SQL Server is NOT supported; do not offer it.
3. Keep every Microsoft.IdentityModel.* package on ONE version (the package pins 8.8.0). Do not add
   a lower Microsoft.IdentityModel.* / System.IdentityModel.Tokens.Jwt reference. A split graph
   builds fine and then fails on the first sign-in with a message that names none of this.
4. Never write a password, client secret or signing key into appsettings.json or any tracked file.
   Use `dotnet user-secrets` locally and environment variables in deployed environments.
5. Do NOT also add Ark.oAuth.Client / AddArkOidcClient. AddArkIdp() already registers the admin
   console's sign-in (cookie scheme "ArkIdpConsole" + OIDC scheme "ArkIdpConsoleOidc").
6. Never map a route of your own at /signin-oidc, /signout-callback-oidc, /ark-idp/*, /admin,
   /{tenant}/..., /oauth/..., /api/oauth/..., or /.well-known/... — the package owns them.

STEPS
1. Scaffold:
     dotnet new mvc -n <<PROJECT_NAME>> -f net9.0
     cd <<PROJECT_NAME>>
     dotnet add package Ark.oAuth.Oidc --version 2.1.4

2. Program.cs: replace the template's pipeline with exactly this shape. UseArkIdp() already calls
   UseStaticFiles, UseRouting, UseArkOidcCors, UseArkAuthData (setup wizard + database bootstrap),
   UseAuthentication, UseAuthorization and MapControllers, in that order. REMOVE the template's own
   app.UseRouting() and app.UseAuthorization() so they do not run twice. AddArkIdp() calls
   AddControllersWithViews() itself, so a second call from the template is harmless and can stay.

     using Ark.oAuth.Oidc;

     var builder = WebApplication.CreateBuilder(args);
     builder.AddArkIdp(o =>
     {
         // false keeps HomeController at "/"; true (default) makes "/" redirect to /admin.
         o.MapRootToConsole = <<false if "Keep MVC home page" = yes, else true>>;
     });
     builder.Services.AddControllersWithViews();

     var app = builder.Build();

     if (!app.Environment.IsDevelopment())
     {
         app.UseExceptionHandler("/Home/Error");
         app.UseHsts();
     }
     app.UseHttpsRedirection();

     app.UseArkIdp();   // static files, routing, CORS, wizard/bootstrap, authn, authz, IdP endpoints

     // If the template has MapStaticAssets()/.WithStaticAssets(), keep them.
     app.MapControllerRoute(name: "default", pattern: "{controller=Home}/{action=Index}/{id?}");
     app.Run();

   Anything that must run BEFORE the IdP (UseForwardedHeaders behind a proxy, exception handling,
   HSTS) goes above app.UseArkIdp(). Behind a reverse proxy, add UseForwardedHeaders first so the
   issuer is built from the public scheme and host.

3. .csproj: keep what the wizard writes out of build output and publish (it is machine-specific
   configuration, not source):

     <ItemGroup>
       <Content Remove="ark-idp-data\**" />
       <None Remove="ark-idp-data\**" />
     </ItemGroup>

4. Configuration, by mode:

   A) wizard mode: add NO ark_oauth_server section. On first `dotnet run`, every browser request goes
      to /ark-idp/setup (other requests get 503 setup_required). The wizard collects organisation and
      logos, public URL, tenant, database (with a connection test), RSA signing key, administrator,
      SMTP, protocol options, CORS origins and the machine-client secret. It then writes
      ark-idp-data/settings.json (mode 0600, git-ignores itself), seeds the database and reloads
      configuration. The same process becomes the IdP with no restart. From localhost no code is
      needed; from another machine it asks for the setup code printed in the startup log.
      For containers: set ark_oauth_server__Setup__DataPath to a mounted volume.
      Optional switches (ark_oauth_server:Setup): Enabled (true), RequireToken (false), DataPath.

   B) configured mode: write appsettings.json with NO secrets in it:

     {
       "ark_oauth_server": {
         "TenantId": "<<TENANT_ID>>",
         "BaseUrl": "<<IDP_BASE_URL>>",
         "BasePath": "",                       // only if hosted under a sub-path; then add app.UsePathBase to match
         "Provider": "<<sqlite|postgres|mysql>>",
         "UserPasswordMode": "admin_managed",  // admin_managed | email_based | auto
         "PasswordLinkLifetimeHours": 72,
         "AdminUser": { "Username": "<<ADMIN_USERNAME>>", "Name": "Administrator" },
         "Admin": { "SignOutUrl": "/ark-idp/signout" },   // the built-in console sign-out route
         "Oidc": {
           "EnableDeviceFlow": true,
           "EnablePushedAuthorizationRequests": true,
           "EnableDynamicRegistration": false,
           "RequireRegistrationAccessToken": true,
           "IntrospectionClients": [],
           "CorsOrigins": []                   // exact origins of SPA clients only; no wildcards
         },
         "Management": { "OperatorDeviceClients": [], "AllowMigrationEndpoint": false }
       },
       "ConnectionStrings": { "ArkAuthConnection": "<<CONNECTION_STRING>>" }
     }

     Then set the secrets out of band (generate strong values; do not echo them into files):
       dotnet user-secrets init
       dotnet user-secrets set "ark_oauth_server:AdminUser:Password" "<<generate>>"
       dotnet user-secrets set "ark_oauth_server:DefaultPw" "<<generate>>"
       dotnet user-secrets set "ark_oauth_server:Management:MachineClientSecret" "<<generate, >= 16 chars>>"
     In production use environment variables with double underscores, e.g.
       ark_oauth_server__AdminUser__Password, ark_oauth_server__Management__MachineClientSecret.
     AdminUser:Password is REQUIRED before first run. A "<<placeholder>>" value counts as unset,
     and seeding stops with a message naming the setting. It is read only when the database is first
     created; after that, change passwords in the console.
     SQLite does not create the folder for the .db file, so create it (e.g. mkdir ark-idp-data).

5. Optional, only if the user wants the MVC app's OWN pages behind sign-in: [Authorize] on your
   controllers works as-is. The default scheme is the console sign-in, which signs in through this
   IdP as client "<<TENANT_ID>>_client". A user must have an access mapping to that client (the
   seeded admin already has one). Use [Authorize(Roles = "<claim>")]: ark_claims become "role" claims.
   For a separate app identity, register a separate client and use Prompt 3 in a separate project.

6. launchSettings.json: make the https applicationUrl equal <<IDP_BASE_URL>> (configured mode), so
   the issuer the server prints matches the URL clients use.

VERIFY (run these and report the actual output; do not claim success without them)
- dotnet build: no errors, and `dotnet list package --include-transitive | grep -i identitymodel`
  shows a single version.
- dotnet run, then:
    curl -sk <<IDP_BASE_URL>>/<<TENANT_ID>>/.well-known/openid-configuration   -> JSON whose "issuer" is <<IDP_BASE_URL>>/<<TENANT_ID>>
    curl -sk -o /dev/null -w "%{http_code}" <<IDP_BASE_URL>>/<<TENANT_ID>>/.well-known/jwks.json  -> 200
- Wizard mode: /ark-idp/setup loads before install and returns 404 after install.
- Browse to /admin, sign in as the administrator, and confirm the console opens. "Sign out" must
  return you to a signed-out state (it ends both the console cookie and the IdP session).
- / shows the MVC home page (MapRootToConsole=false) or redirects to /admin (true).

DELIVERABLE
Summarise: files changed, which mode was used, the issuer and discovery URL, where each secret lives
(never print a secret's value), and the next step: register client apps in the console
(/<<TENANT_ID>>/admin → Clients, or the Provisioning page, which registers the client, its redirect
URIs, the user and the user→client access mapping in one call).
```

---

## Prompt 2 — Upgrade an existing Ark IdP host to 2.1.4

The prompt first finds the installed version, then branches. **Below 2.1.4** it upgrades and runs a
full cleanup pass for every version band the host has skipped. **Already on 2.1.4** it changes no
code, checks the host against the before/after reference at the end, and reports any drift.

```text
Upgrade this repository's Ark identity provider host (NuGet Ark.oAuth.Oidc, plus Ark.oAuth.Client if
it is referenced) to version 2.1.4, the latest. Then clean up everything that older versions needed
and 2.1.4 does not.

GROUND RULES
- Do not invent APIs or settings. After restoring 2.1.4, read MIGRATION.md, README.md and
  API-GUIDE.md from ~/.nuget/packages/ark.oauth.oidc/2.1.4/. They are authoritative over this prompt.
- Before deleting or overwriting anything, show me what will go. Do not commit; leave changes
  uncommitted for me to review.
- Never write secrets into tracked files. Move any secret you find in appsettings*.json to
  user-secrets (local) or an environment variable (deployed), and tell me which keys moved.
- Package versions are immutable on NuGet. Use exactly 2.1.4 and pin both Ark packages to it.
- Back up the database before the first start on 2.1.4. Schema updates are additive and apply
  themselves on start-up, but a backup is the only rollback.

STEP 0 — DETECT
1. Find every reference: grep the *.csproj / Directory.Packages.props for Ark.oAuth.Oidc,
   Ark.oAuth.Client, Ark.Auth.Client.Web, Ark.EfCore, Microsoft.IdentityModel.*,
   System.IdentityModel.Tokens.Jwt.
2. Report the CURRENT version of each, the database provider (ark_oauth_server:Provider) and the
   host shape:
     shape A "zero-config":  builder.AddArkIdp() + app.UseArkIdp()
     shape B "configured":   services.AddArkOidcServer(env) [+ AddArkOidcClient] + UseArkAuthData()
     shape C "v1":           a pasted RsaPublic key, an ark_oauth_client section with Tenants/RsaPublic/
                             AuthServerUrl, custom callback controllers, or a reference to Ark.Auth.Client.Web
3. Branch:
     current < 2.1.4  -> do STEP 1 (upgrade) and every STEP 2 band from the current version up.
     current == 2.1.4 -> skip STEP 1 and STEP 2, and do only STEP 3 (compare with the reference).

STEP 1 — UPGRADE THE PACKAGES
  dotnet add <<HOST_PROJECT>> package Ark.oAuth.Oidc --version 2.1.4
  dotnet add <<HOST_PROJECT>> package Ark.oAuth.Client --version 2.1.4   (only if already referenced)
  Target framework must be net9.0 or later.
  Remove any explicit Microsoft.IdentityModel.* / System.IdentityModel.Tokens.Jwt reference lower
  than 8.8.0 (2.1.4 pins 8.8.0). Then confirm a single version with:
    dotnet list package --include-transitive | grep -i identitymodel

STEP 2 — CLEANUP, BAND BY BAND (apply each band whose range includes the current version)

  Band 1.x (v1, any 1.0.x / 1.0.5.x):
  - Delete the v1 client shape: a pasted RsaPublic, Issuer/Audience mirrors, the per-tenant
    "tenants" key table, custom /callback controllers, timestamp-derived PKCE, any reference to
    Ark.Auth.Client.Web. The replacement is AddArkOidcClient with only Authority + ClientId
    (endpoints and keys come from discovery). Keys to delete from ark_oauth_client: RsaPublic,
    Issuer, Audience, Tenants, RedirectUri, RedirectRelative, RouteKey, Suffix, LogoutUri.
  - Remove ark_oauth_client:UseLegacyFlow, or set it to false. It validates neither state nor nonce.
  - The seeded admin no longer comes from a compiled-in admin/admin. Add ark_oauth_server:AdminUser
    (Username, Name) and set AdminUser:Password via user-secrets/env. It is read only when a NEW
    database is created; on an existing database, change the admin password in the console.
  - Implicit grant, hybrid flow and ROPC are gone (OAuth 2.1). Any client still using them must
    move to authorization code + PKCE.
  - v1 routes /oauth/{tenant}/v1/... still answer, but delegate to the protocol core: codes are
    single-use, and since 2.1.4 /oauth/{t}/v1/token REFUSES any code issued without PKCE. Find
    callers of /oauth/{tenant}/v1/token and move them to /{tenant}/oauth2/token with PKCE.
  - Schema: 00003 (protocol tables, scope catalogue, adopts the tenant's existing RSA key as
    kid = tenant_id so issued tokens keep validating) applies itself on start-up.

  Band 2.0.0 – 2.0.2:
  - Schema 00004 (users.is_active) and 00005 (back-channel logout metadata, sessions.browser_id,
    session_clients) apply themselves. Nothing to run by hand.
  - New settings, all defaulted: Oidc:EnableBackChannelLogout, BackChannelLogoutTimeoutSeconds,
    LogoutTokenLifetimeSeconds, SignOutAllBrowserSessions, SignOutAcrossTenants. Discovery now
    reports frontchannel_logout_supported=false; remove any client config that relies on it.

  Band 2.0.0 – 2.0.11 (dependency + schema cleanup):
  - Remove direct references to Ark.EfCore, Azure.Identity and BouncyCastle if they were added only
    for this package. Ark.EfCore was a carrier for EF packages, never a used dependency.
  - If Provider is "sqlserver": it never worked and is not supported. Stop and tell me.
  - MySQL / PostgreSQL on <= 2.0.11 had no schema sync: new columns failed at the first query with
    "42703: column ... does not exist". 2.1.4 adds missing tables and columns on start-up from the
    EF model (additive only). The DB login needs CREATE/ALTER on its own tables; if it has no DDL
    rights, show me the DDL from MIGRATION.md to run before the upgrade.
  - Delete any hand-written ALTER TABLE scripts or start-up code added as a workaround for this.

  Band <= 2.0.14 (management API became operator-only; first shipped in 2.1.1, BREAKING):
  - DELETE any authentication scheme the host added for /api/oauth/v1/... (a JWT bearer scheme,
    a policy scheme made the default, a client_id check). The package's own schemes are
    "ArkManagement" and "ArkManagementBearer"; a host scheme with either name throws a
    duplicate-scheme error on the first request.
  - Console users other than ark_oauth_server:AdminUser:Username who used the console grids need an
    "admin" claim on their mapping to <<TENANT_ID>>_client. Otherwise every API call returns 403.
  - Pipelines that provision: get a token as <<TENANT_ID>>_machine with scope client.register.
    Give the machine client a secret via ark_oauth_server:Management:MachineClientSecret (>= 16
    chars, environment or key vault only). It is applied at start-up and rotated by changing it.
  - /api/migration now answers 404 unless Management:AllowMigrationEndpoint=true. Remove scripts
    that call it; schema updates are automatic now.
  - client.register can no longer be requested through /provision/client or /oauth2/register;
    only an operator grants it in the console.

  Band <= 2.1.2 (zero-config hosting arrived in 2.1.3):
  - Optional but recommended for hosts with no custom pipeline: switch shape B to shape A (see
    the BEFORE/AFTER reference below). Moving to the built-in console sign-in means:
      * remove AddArkOidcClient/UseArkOidcClient AND the ark_oauth_client section, if they existed
        only for the admin console (keep them if the host's own pages need them, and then use
        builder.AddArkIdp(o => o.ConsoleSignIn = false) instead);
      * set ark_oauth_server:Admin:SignOutUrl to "/ark-idp/signout";
      * delete the host's own SignOutAll action if it existed only for the console;
      * delete EnsureSqliteDirectory-style helpers only if the DB path is inside ark-idp-data
        (otherwise keep creating the directory).
  - A host that already has TenantId + ConnectionStrings:ArkAuthConnection never sees the wizard.
    To make sure it never appears in production, set ark_oauth_server:Setup:Enabled=false.
  - New transitive dependency: Microsoft.AspNetCore.Authentication.OpenIdConnect 9.0.x. This is
    expected; IdentityModel stays on 8.8.0.

  Band <= 2.1.3 (2.1.4 security release; check each behaviour change against this host):
  - /oauth/{t}/v1/token refuses codes issued without PKCE (see Band 1.x).
  - v1 sign-in and v1 password-reset forms now require an antiforgery token. If the host overrides
    Views/Server/Index.cshtml or PasswordReset.cshtml, re-copy them from 2.1.4 or add
    @Html.AntiForgeryToken() inside the form.
  - /oauth2/logout WITHOUT a valid id_token_hint now shows a confirm page while a session is live.
    Clients that sign out must send id_token_hint (the Ark clients already do).
  - Introspection: a client may introspect only its own tokens. A resource server that introspects
    other clients' tokens must be listed in ark_oauth_server:Oidc:IntrospectionClients.
  - Activation / reset links expire after ark_oauth_server:PasswordLinkLifetimeHours (default 72;
    0 = never) and are single-use. Tell support teams.
  - Dynamic registration refuses the reserved ids {tenant}_machine, {tenant}_client and any
    OperatorDeviceClients id.
  - Passwords are re-hashed at 210k iterations on each user's next sign-in (no action needed).
    Service-account tokens are stored as digests: regenerate any service-account token that has to
    be read back.
  - New table used_assertions (private_key_jwt replay store, shared across instances). It is added
    automatically.

STEP 3 — COMPARE WITH THE 2.1.4 REFERENCE (BEFORE/AFTER)
  Compare the host with the AFTER blocks below. List every difference. Fix differences that are
  leftovers; ask me about differences that are deliberate customisation.

  ===================== BEFORE (typical 2.0.x – 2.1.2 "configured" host) =====================
  // Program.cs
  using Ark.oAuth;
  using Ark.oAuth.Oidc;
  var builder = WebApplication.CreateBuilder(args);
  builder.Services.AddArkOidcServer(builder.Environment);
  builder.Services.AddArkOidcClient(builder.Configuration);      // console signs in as a client
  builder.Services.AddControllersWithViews();
  builder.Services.AddAuthentication().AddJwtBearer("Api", ...); // REMOVE: host bearer for /api/oauth
  var app = builder.Build();
  EnsureSqliteDirectory(app.Configuration);
  app.UseHttpsRedirection();
  app.UseStaticFiles();
  app.UseRouting();
  app.UseArkOidcCors();
  app.UseArkAuthData();
  app.UseArkOidcClient();                                        // no-op unless UseLegacyFlow
  app.UseAuthentication();
  app.UseAuthorization();
  app.MapControllerRoute("default", "{controller=Home}/{action=Index}/{id?}");
  app.Run();

  // appsettings.json (excerpt)
  "ark_oauth_server": {
    "TenantId": "my_idp", "BaseUrl": "https://idp.example.com", "Provider": "postgres",
    "DefaultPw": "Welcome@123",                       // REMOVE: secret in a tracked file
    "AdminUser": { "Username": "admin", "Password": "admin" },  // REMOVE: secret, and a weak one
    "Admin": { "SignOutUrl": "/Home/SignOutAll" },
    "EmailConfig": { "pw": "smtp-password" }          // REMOVE: secret in a tracked file
  },
  "ark_oauth_client": {
    "Authority": "https://idp.example.com/my_idp", "ClientId": "my_idp_client",
    "RsaPublic": "MIIBIjANBg...", "Tenants": { ... }, // REMOVE: v1 keys, ignored since 2.0
    "UseLegacyFlow": true                              // REMOVE: no state/nonce validation
  }

  ===================== AFTER (2.1.4, shape A: recommended unless the pipeline is custom) =====================
  // Program.cs
  using Ark.oAuth.Oidc;
  var builder = WebApplication.CreateBuilder(args);
  builder.AddArkIdp();                       // server + built-in console sign-in (+ settings.json source)
  builder.Services.AddControllersWithViews(); // only if the host has its own MVC pages
  var app = builder.Build();
  if (!app.Environment.IsDevelopment()) { app.UseExceptionHandler("/Home/Error"); app.UseHsts(); }
  app.UseHttpsRedirection();
  app.UseArkIdp();                           // static files, routing, CORS, bootstrap, authn, authz, endpoints
  app.MapControllerRoute("default", "{controller=Home}/{action=Index}/{id?}"); // only with own MVC pages
  app.Run();

  // appsettings.json (excerpt). No secrets.
  "ark_oauth_server": {
    "TenantId": "my_idp", "BaseUrl": "https://idp.example.com", "Provider": "postgres",
    "PasswordLinkLifetimeHours": 72,
    "AdminUser": { "Username": "admin", "Name": "Administrator" },
    "Admin": { "SignOutUrl": "/ark-idp/signout" },
    "Oidc": { "IntrospectionClients": [], "CorsOrigins": [] },
    "Management": { "OperatorDeviceClients": [], "AllowMigrationEndpoint": false },
    "Setup": { "Enabled": false }            // production: never fall back to the wizard
  }
  // no "ark_oauth_client" section in shape A
  // secrets, from user-secrets / env / key vault:
  //   ark_oauth_server__AdminUser__Password, ark_oauth_server__DefaultPw,
  //   ark_oauth_server__EmailConfig__pw, ark_oauth_server__Management__MachineClientSecret,
  //   ConnectionStrings__ArkAuthConnection (if it carries a password)

  ===================== AFTER (2.1.4, shape B: kept when the host brings its own client) =====================
  // Program.cs
  using Ark.oAuth;
  using Ark.oAuth.Oidc;
  var builder = WebApplication.CreateBuilder(args);
  builder.AddArkIdp(o => o.ConsoleSignIn = false);           // wizard + settings source, no built-in console auth
  builder.Services.AddArkOidcClient(builder.Configuration);  // host's own sign-in (Authority + ClientId only)
  builder.Services.AddControllersWithViews();
  var app = builder.Build();
  app.UseHttpsRedirection();
  app.UseArkIdp();
  app.MapControllerRoute("default", "{controller=Home}/{action=Index}/{id?}");
  app.Run();
  // ark_oauth_server:Admin:SignOutUrl -> a host route that signs out of BOTH
  //   ArkOidcClient.CookieScheme and ArkOidcClient.OidcScheme (or calls HttpContext.ArkSignOutEverywhereAsync()).
  // ark_oauth_client: { "Authority": "...", "ClientId": "<<TENANT_ID>>_client", "ClientSecret": null,
  //   "Scopes": ["openid","profile","email","offline_access"] }. No RsaPublic, Tenants or UseLegacyFlow.
  // The fully manual pipeline (UseRouting → UseArkOidcCors → UseArkAuthData → UseArkOidcClient →
  //   UseAuthentication → UseAuthorization) is still supported; keep it only if something must sit between those calls.

VERIFY (run and report real output)
- dotnet build is clean; there is a single Microsoft.IdentityModel.* version.
- Start against a BACKUP COPY of the database first. Check the log for schema_sync / ark_schema_history
  entries and confirm there are no 42703 / "no such column" errors.
- GET {issuer}/.well-known/openid-configuration: issuer unchanged, backchannel_logout_supported=true.
- GET {issuer}/.well-known/jwks.json: still lists the existing kid (tokens issued before the upgrade keep validating).
- Admin console: sign in, open Clients/Users grids (no 403 for the admin), Sign out returns to signed-out.
- If anything provisions: client_credentials as <<TENANT_ID>>_machine with scope client.register
  returns a token, and GET /api/oauth/v1/client/list with it returns 200.
- Each existing client app can still sign in and sign out (sign-out passes id_token_hint, so no confirm page).

DELIVERABLE
A table: version before → after, bands applied, files changed, settings added/removed/moved to secrets,
behaviour changes that affect users or client apps, and anything left for me to decide.
```

---

## Prompt 3 — Connect an app to an existing Ark IdP (.NET / Python / Node)

The IdP is already running. Pick one stack, or `all three` to get the same app in each. The prompt
covers the IdP registration as well as the code, because most "the password is wrong" reports come
from a missing registration step.

```text
Integrate this application with our EXISTING Ark identity provider as an OAuth 2.1 / OpenID Connect
client, using the official Ark client library for the stack. Do not hand-roll any part of OAuth/OIDC.

INPUTS
- Stack:                <<dotnet | python | node | all three>>
- Discovery URL:        <<DISCOVERY_URL>>        e.g. https://idp.example.com/my_idp/.well-known/openid-configuration
                        (authority = this URL minus "/.well-known/openid-configuration" = {BaseUrl}/{TenantId})
- Client id:            <<CLIENT_ID>>
- Client type:          <<confidential | public>> (server-rendered web app = confidential; SPA/native/CLI = public + PKCE, no secret)
- App base URL:         <<APP_BASE_URL>>          exactly as the browser sees it: scheme + host + port, no trailing slash
- Authorization claims: <<e.g. billing.admin, billing.read | none>>   (Ark per-user-per-client claims, NOT OAuth scopes)
- Shared/kiosk browsers: <<yes | no>>
- Framework (python):   <<flask | django | fastapi | worker/cli>>
- Framework (node):     <<express | fastify | koa | plain http | worker/cli>>

FIRST, VALIDATE THE IdP (do this before writing code, and show me the result)
  curl -s <<DISCOVERY_URL>>
  - "issuer" must equal the authority exactly (tenant segment included, no trailing slash).
  - Note authorization_endpoint, token_endpoint, end_session_endpoint, scopes_supported,
    token_endpoint_auth_methods_supported and code_challenge_methods_supported (must include S256).
  - If the host serves a self-signed / dev certificate, say so. Never disable TLS checks outside local dev.

INSTALL (latest 2.1.4; the three packages share one version number)
  .NET:    dotnet add package Ark.oAuth.Client --version 2.1.4          (net9.0+, namespace: using Ark.oAuth;)
  Python:  pip install "ark-oauth-client[flask]==2.1.4"   (drop [flask] for Django/FastAPI/CLI)
  Node:    npm install ark-oauth-client@2.1.4             (Node 20+, ESM)

THE CALLBACK URLs EACH STACK SENDS (register these byte for byte on the IdP)
  | Stack  | Sign-in redirect URI              | Post-logout redirect URI                                   |
  |--------|-----------------------------------|------------------------------------------------------------|
  | .NET   | <<APP_BASE_URL>>/signin-oidc      | <<APP_BASE_URL>>/signout-callback-oidc                     |
  | Python | <<APP_BASE_URL>>/signin-oidc      | <<APP_BASE_URL>>/  (Flask default; any ?returnTo target must also be registered) |
  | Node   | value of redirectUri              | value of postLogoutRedirectUri (e.g. <<APP_BASE_URL>>/)    |

GENERATE THE CODE + LOCAL CONFIG FOR EACH SELECTED STACK

---- .NET (ASP.NET Core MVC / Razor Pages / minimal API) ----
Program.cs:
    using Ark.oAuth;
    builder.Services.AddArkOidcClient(builder.Configuration);   // binds the "ark_oauth_client" section
    // optional entitlement hook:
    // builder.Services.AddArkOidcClient(builder.Configuration, o =>
    //     o.Events.OnEvaluateAccess = ctx => Task.FromResult(ctx.ArkClaims.Count > 0));
    ...
    app.UseRouting();          // MUST come before the next two
    app.UseAuthentication();
    app.UseAuthorization();

appsettings.json (committed, no secrets):
    "ark_oauth_client": {
      "Authority": "<<authority>>",
      "ClientId": "<<CLIENT_ID>>",
      "ClientSecret": null,
      "Scopes": [ "openid", "profile", "email", "offline_access" ],
      "CallbackPath": "/signin-oidc",
      "SignedOutCallbackPath": "/signout-callback-oidc",
      "SignedOutRedirectUri": "/",
      "AuthErrorPath": "/",
      "RequireHttpsMetadata": true,
      "CookieName": "<<app>>_auth",
      "RoleClaimType": "role",
      "ExpireMins": 480,
      "AccountSwitch": {
        "RequireArkClaims": <<true if shared browsers = yes, else false>>,
        "RequiredClaims": [ <<authorization claims, or omit>> ],
        "AppDisplayName": "<<App name>>"
      }
    }
Local overrides: appsettings.Development.json (git-ignored) for Authority/RequireHttpsMetadata against
a local IdP. Confidential client secret ONLY via:
    dotnet user-secrets set "ark_oauth_client:ClientSecret" "<<secret>>"
    (deployed: env var ark_oauth_client__ClientSecret)
Usage:
    [Authorize] on controllers; [Authorize(Roles = "billing.admin")]: ark_claims are projected to "role".
    Downstream call: await request.WithArkTokenAsync(HttpContext);  raw: await HttpContext.GetArkAccessTokenAsync();
    Sign out: await HttpContext.ArkSignOutEverywhereAsync("/");   (both schemes; never only the cookie)
    API project instead of a web app: builder.Services.AddAuthentication().AddArkOidcApi(arkConfig);
    Machine-to-machine: inject ArkClientCredentials, call GetTokenAsync(clientId, secret, scopes).
    Diagnostics page: inject ArkSetupProbe, render await probe.ProbeAsync(HttpContext).

---- Python (Flask) ----
app.py:
    import os
    from flask import Flask
    from ark_oauth_client.flask import add_ark_oidc_client, current_ark
    app = Flask(__name__)
    app.secret_key = os.environ["ARK_SESSION_SECRET"]      # >= 16 chars, SAME on every instance
    auth = add_ark_oidc_client(app, {
        "authority": os.environ["ARK_AUTHORITY"],
        "client_id": os.environ["ARK_CLIENT_ID"],
        "client_secret": os.environ.get("ARK_CLIENT_SECRET"),   # omit/None for a public client
        "scopes": ["openid", "profile", "email", "offline_access"],
        "callback_path": "/signin-oidc",
        "auth_error_path": "/",
        "require_https_metadata": True,
        "account_switch": {"require_ark_claims": <<True|False>>, "required_claims": [<<claims>>],
                           "app_display_name": "<<App name>>"},
    })

    @app.get("/billing")
    @auth.require_claims("billing.admin")       # Ark claims; use @auth.require_scopes(...) for scopes
    def billing(): return current_ark.user["name"]
  The library owns /login, /signin-oidc, /logout, /ark/no-access, /ark/switch-user, /ark/sign-out.
  Do not add routes at those paths.
  Tokens: current_ark.access_token() per request; headers = current_ark.authorize(headers) for downstream calls.
  Multiple instances or restarts: pass store=<shared store with get/set/destroy/touch> (default is per-process).
  An existing appsettings.json can be bound as-is: ArkAuthConfig.from_mapping(json["ark_oauth_client"]).
  Django / FastAPI / worker: use ArkOAuthClient(authority=, client_id=, client_secret=, redirect_uri=)
    → create_authorization_url / handle_callback / refresh / end_session_url; keep state, nonce and
    code_verifier server-side only. API: add_ark_oidc_api(app, "/api", authority=, client_id=, audience=).
.env.example (committed, values blank) + .env (git-ignored):
    ARK_AUTHORITY=<<authority>>
    ARK_CLIENT_ID=<<CLIENT_ID>>
    ARK_CLIENT_SECRET=
    ARK_SESSION_SECRET=

---- Node (Express / Connect) ----
server.js:
    import express from 'express';
    import { arkExpress } from 'ark-oauth-client';
    const app = express();
    const auth = arkExpress({
      authority: process.env.ARK_AUTHORITY,
      clientId: process.env.ARK_CLIENT_ID,
      clientSecret: process.env.ARK_CLIENT_SECRET || undefined,   // omit for public clients
      redirectUri: `${process.env.APP_BASE_URL}/signin-oidc`,
      postLogoutRedirectUri: `${process.env.APP_BASE_URL}/`,
      scopes: ['openid', 'profile', 'email', 'offline_access'],
      secret: process.env.ARK_SESSION_SECRET,                     // >= 16 chars, same on every instance
      errorPath: '/',
      accountSwitch: { requireArkClaims: <<true|false>>, requiredClaims: [<<claims>>], appDisplayName: '<<App name>>' }
    });
    app.use(auth);                                                 // serves /login, /signin-oidc, /logout, /ark/*
    app.get('/billing', auth.requireClaims('billing.admin'), (req, res) => res.send(req.ark.user.name));
  NOTE: with requireArkClaims, ALWAYS set requiredClaims. Ark puts the whole access-mapping list in
  ark_claims, identity names included, so "any ark_claims" is satisfied even without an authorization claim.
  Tokens: await req.ark.accessToken() per request; await req.ark.authorize(headers) for downstream calls.
  Multiple instances: pass store: { get, set, destroy, touch } (e.g. Redis) and add a short lock around refresh.
  Existing appsettings.json: { ...ArkAuthConfig.fromMapping(json), secret } reads the C# keys unchanged.
  API: app.use('/api', arkBearer({ authority, clientId, audience })); bearer.require({ claims: [...] }).
  Non-Express / worker: new ArkOAuthClient({...}) → createAuthorizationUrl / handleCallback / refresh /
    clientCredentials / deviceAuthorization + pollDeviceToken.
.env.example (committed, blank) + .env (git-ignored):
    APP_BASE_URL=<<APP_BASE_URL>>
    ARK_AUTHORITY=<<authority>>
    ARK_CLIENT_ID=<<CLIENT_ID>>
    ARK_CLIENT_SECRET=
    ARK_SESSION_SECRET=

REGISTER THE CLIENT ON THE IdP (produce this as a checklist for me; do not skip any line)
  Either in the admin console (<<IdP base>>/<<tenant>>/admin → Clients) or with ONE provisioning call
  (operator-only: console session, or a bearer token for <<tenant>>_machine with scope client.register):
    POST <<IdP base>>/api/oauth/v1/provision/client
    { "client_name": "<<App name>>", "client_id": "<<CLIENT_ID>>", "tenant_id": "<<tenant>>",
      "user_name": "<<first user's email or username>>",
      "redirect_uris": [ "<<sign-in URI>>", "<<post-logout URI>>" ] }
  It registers the client, the redirect URIs, the user, and the user→client access mapping in one go.
  Checklist:
  [ ] Client exists with id <<CLIENT_ID>>; grant types authorization_code + refresh_token
      (+ client_credentials only if this app also calls APIs as itself).
  [ ] token_endpoint_auth_method: none (public) or client_secret_basic/post (confidential), with the
      secret copied into user-secrets/.env, NEVER into a tracked file.
      (Python ArkClientCredentials always uses client_secret_post; use ArkOAuthClient.client_credentials
       for a client registered with another method.)
  [ ] BOTH redirect URIs from the table above, byte for byte: scheme, host, port, path, no trailing slash
      unless the app sends one. No wildcards.
  [ ] Scopes whitelisted on the client include every scope the app requests. offline_access is needed
      for a refresh token. An unregistered scope is REJECTED, not dropped.
  [ ] EVERY user who signs in has an access MAPPING to this client, with the authorization claims
      (e.g. billing.admin) on that mapping. Without a mapping the sign-in page says the password is wrong.
  [ ] Optional: backchannel_logout_uri if the app will implement back-channel logout itself (none of
      the three libraries hosts that endpoint).
  [ ] SPA (browser redeems its own code) only: add the SPA origin to ark_oauth_server:Oidc:CorsOrigins.
      Server-side apps need no CORS entry.

RULES FOR ALL STACKS
- Only authority + client_id are required; everything else comes from discovery. Do not hard-code
  endpoint URLs or paste signing keys.
- Never add your own route at the callback path. Read the access token per request; never cache it.
- Sign out of the local session AND the provider (the library's logout/sign-out does both).
- Keep RequireHttpsMetadata / require_https / requireHttps on, except for local http development.
- On shared browsers, enable account switching (RequireArkClaims / require_ark_claims / requireArkClaims).
  Otherwise SSO signs the next person in as the previous one, and the "no access" page has no way out.

VERIFY (run and report real output)
- The app starts with no config error (all three validate config at startup).
- Diagnostics: .NET ArkSetupProbe.ProbeAsync, Python auth.setup_model() / client.check_setup(),
  Node await client.checkSetup(). All three should report no issuer mismatch, no unsupported scope,
  and the exact redirect URI that will be sent.
- Full round trip in a private window: protected page → IdP sign-in → back to the app signed in →
  a claim-guarded page works for a mapped user and shows the access-denied page (with "Sign in as a
  different user") for an unmapped one → sign out returns signed-out, and the next visit asks for a password.
- Repo search: no secret values in tracked files.
```

---

## Prompt 4 — Use the Ark client libraries against an external IdP

The three Ark client libraries are standards-based relying parties, not Ark-only ones. This prompt
connects one to Microsoft Entra ID, Auth0, Okta, Keycloak, Google, AWS Cognito or any other
compliant provider, and covers the parts of an Ark integration that do not carry over.

```text
Use the Ark OAuth client library for this app's stack to sign users in against an EXTERNAL OpenID
Connect provider (not an Ark IdP). Use the library's existing options and the framework's standard
extension points only: no forks, no hand-rolled OAuth, no invented options. When unsure of an option,
read the package's README.md / API-GUIDE.md (they ship inside the package) or the source.

INPUTS
- Stack:            <<dotnet | python | node>>
- Provider:         <<entra | auth0 | okta | keycloak | google | cognito | other>>
- Issuer/authority: <<ISSUER>>          (the exact "issuer" value from the provider's discovery document)
- Client id:        <<CLIENT_ID>>
- Client secret:    <<yes (confidential web app) | no (public: SPA/native/CLI → PKCE only)>>
- App base URL:     <<APP_BASE_URL>>
- Flows needed:     <<interactive sign-in | API protection | client credentials | device code | refresh>>
- API audience:     <<AUDIENCE or none>> (needed when the app calls/validates an API's access token)
- Role/group claim: <<e.g. roles (Entra), groups (Okta/Keycloak/Cognito), a namespaced claim (Auth0) | none>>

STEP 1 — READ THE PROVIDER'S DISCOVERY DOCUMENT FIRST (show me the relevant fields)
  curl -s <<ISSUER>>/.well-known/openid-configuration
  Record: issuer (must equal the configured authority character for character, including any
  trailing slash), authorization_endpoint, token_endpoint, end_session_endpoint (may be ABSENT),
  scopes_supported, response_types_supported (must include "code"), code_challenge_methods_supported
  (S256), token_endpoint_auth_methods_supported, grant_types_supported, device_authorization_endpoint,
  pushed_authorization_request_endpoint. Base the configuration on this document, not on assumptions.

SUPPORTED FLOWS (what the Ark libraries implement against any compliant provider)
  | Flow                                  | .NET Ark.oAuth.Client                    | Python ark-oauth-client                | Node ark-oauth-client                 |
  |---------------------------------------|------------------------------------------|----------------------------------------|---------------------------------------|
  | Authorization code + PKCE (S256)      | AddArkOidcClient (framework OIDC handler)| add_ark_oidc_client / ArkFlask / ArkOAuthClient | arkExpress / ArkOAuthClient   |
  | Refresh token (rotation-aware)        | automatic (cookie handler)               | automatic / client.refresh             | automatic / client.refresh            |
  | Client credentials                    | ArkClientCredentials                     | client.client_credentials              | client.clientCredentials              |
  | Device code (RFC 8628)                | (not exposed)                            | device_authorization + poll_device_token | deviceAuthorization + pollDeviceToken |
  | PAR (RFC 9126)                        | (not exposed)                            | use_par=True                           | usePar: true                          |
  | Bearer API validation (JWKS)          | AddArkOidcApi                            | add_ark_oidc_api                       | arkBearer                             |
  | Introspection / revocation            | (not exposed)                            | introspect / revoke                    | introspect / revoke                   |
  | RP-initiated logout                   | built in (if end_session_endpoint exists)| built in (falls back to local-only)    | built in                              |
  | private_key_jwt client auth           | (not exposed)                            | private_key_jwt=                       | privateKeyJwt                         |
  NOT supported anywhere, by design: implicit grant, hybrid flow, ROPC (password grant).

WHAT DOES NOT CARRY OVER FROM ARK (handle each explicitly)
  1. ark_claims do not exist outside Ark. Authorise on the provider's own role/group claim instead:
       .NET:   set "RoleClaimType" to that claim name (e.g. "roles" for Entra, "groups" for Okta /
               Keycloak / Cognito "cognito:groups"). Inbound claim mapping is off, so JWT names are kept
               as issued. Then use [Authorize(Roles = "...")].
       Python: role_claim_type in the config; or check current_ark.user["<claim>"] in your own decorator.
       Node:   read req.ark.user['<claim>'] in a small guard; requireClaims() checks ark_claims only.
       Use OAuth scopes with @auth.require_scopes / auth.requireScopes where the provider puts them in "scope".
  2. Keep account switching's RequireArkClaims / require_ark_claims / requireArkClaims = FALSE: it would
     refuse every user, because there are no ark_claims. For a callback-time entitlement check, use the
     OnEvaluateAccess / on_evaluate_access / onEvaluateAccess event with the provider's claims.
     The switch-user page still works, and the Prompt setting can be "select_account" where the
     provider has an account picker (Entra, Google).
  3. User→client access mapping is an Ark concept. Assignment happens in the provider (Entra
     "Assignment required", Okta app assignment, Keycloak client roles, and so on).
  4. at_hash in ID tokens: Python and Node REQUIRE it by default (require_token_hashes / requireTokenHashes).
     If the provider omits at_hash from code-flow ID tokens (it is optional in the spec, and some
     providers leave it out), set it to False / false. Leave it on for providers that send it.
  5. Access-token type: Python/Node API validation enforces typ "at+jwt" (RFC 9068) by default. Most
     providers issue typ "JWT": pass require_type_header=False (Python add_ark_oidc_api /
     verify_access_token) or requireTypeHeader: false (Node arkBearer / verifyAccessToken). ALWAYS set
     an audience in that case, so an ID token cannot be replayed to the API.
  6. Sign-out: if discovery has no end_session_endpoint (e.g. Google), sign-out is local only, and
     the provider session stays alive. Say so in the UI. Back-channel logout is not hosted by any of
     the three libraries.
  7. offline_access: some providers need a different mechanism for refresh tokens (Google:
     access_type=offline + prompt=consent; Auth0 / Okta / Keycloak / Entra: offline_access).
     Request only scopes listed in scopes_supported.

PROVIDER CHEAT-SHEET (confirm each value against the discovery document)
  | Provider | Authority / issuer                                        | Notes |
  |----------|-----------------------------------------------------------|-------|
  | Entra ID | https://login.microsoftonline.com/<<tenant-guid>>/v2.0     | Roles claim "roles"; API scopes look like api://<id>/.default; register redirect URIs as "Web" (confidential) or "SPA"/"Mobile" (public) |
  | Auth0    | https://<<domain>>/  (TRAILING SLASH is part of the issuer)| A JWT access token for your API requires the "audience" authorize parameter; custom claims are namespaced URLs |
  | Okta     | https://<<org>>.okta.com/oauth2/default  (custom AS)       | The org AS (no /oauth2/...) issues tokens for Okta's own API only; use a custom AS for your APIs |
  | Keycloak | https://<<host>>/realms/<<realm>>                          | Roles in realm_access/resource_access (nested); add a mapper for a flat "roles"/"groups" claim |
  | Google   | https://accounts.google.com                                | No end_session_endpoint; no offline_access scope (use access_type=offline); no custom APIs |
  | Cognito  | https://cognito-idp.<<region>>.amazonaws.com/<<pool-id>>   | Groups in "cognito:groups"; logout lives on the hosted-UI domain, not in discovery |

STACK-SPECIFIC WIRING
---- .NET ----
  appsettings.json "ark_oauth_client": Authority=<<ISSUER>>, ClientId, ClientSecret (user-secrets only),
  Scopes from scopes_supported, RoleClaimType=<<claim>>, AccountSwitch.RequireArkClaims=false.
  Extra authorize parameters (Auth0 audience, Google access_type, Entra domain_hint) go in the
  framework's standard extension point. No new Ark API is needed:
    using Microsoft.AspNetCore.Authentication.OpenIdConnect;
    builder.Services.AddArkOidcClient(builder.Configuration);
    builder.Services.PostConfigure<OpenIdConnectOptions>(ArkOidcClient.OidcScheme, o =>
    {
        var previous = o.Events.OnRedirectToIdentityProvider;   // keep Ark's prompt/login_hint handling
        o.Events.OnRedirectToIdentityProvider = async ctx =>
        {
            await previous(ctx);
            ctx.ProtocolMessage.SetParameter("audience", "<<AUDIENCE>>");   // example: Auth0
        };
    });
  The ID token audience is validated against ClientId. API: AddArkOidcApi with Authority + Audience.
  Client credentials: ArkClientCredentials.GetTokenAsync(clientId, secret, scopes).
---- Python ----
  add_ark_oidc_client(app, config) passes on only the ark_oauth_client keys plus session options. For
  provider options (require_token_hashes, extra_authorization_params, post_logout_redirect_uri,
  audience, prompt, use_par, ...), construct ArkFlask directly; it forwards them to the protocol client:
    from ark_oauth_client.flask import ArkFlask, current_ark
    auth = ArkFlask(app, {"authority": os.environ["OIDC_ISSUER"], "client_id": os.environ["OIDC_CLIENT_ID"],
                          "client_secret": os.environ.get("OIDC_CLIENT_SECRET"),
                          "scopes": [<<from scopes_supported>>], "role_claim_type": "<<claim>>",
                          "account_switch": {"require_ark_claims": False}},
                    secret=os.environ["ARK_SESSION_SECRET"],
                    require_token_hashes=<<False only if the provider omits at_hash>>,
                    extra_authorization_params={<<e.g. "audience": "...">>},
                    post_logout_redirect_uri=f"{os.environ['APP_BASE_URL']}/")
  API: add_ark_oidc_api(app, "/api", authority=..., client_id=..., audience="<<AUDIENCE>>",
       require_type_header=False). Non-Flask: ArkOAuthClient(authority=..., client_id=..., ...) with the same options.
---- Node ----
  arkExpress({ authority: process.env.OIDC_ISSUER, clientId, clientSecret, redirectUri, postLogoutRedirectUri,
               scopes: [<<from scopes_supported>>], secret: process.env.ARK_SESSION_SECRET,
               requireTokenHashes: <<false only if the provider omits at_hash>>,
               extraAuthorizationParams: { <<e.g. audience: '...'>> },
               accountSwitch: { requireArkClaims: false } })
  Authorization: a small guard on req.ark.user['<<claim>>'] (requireClaims checks ark_claims only).
  API: arkBearer({ authority, clientId, audience: '<<AUDIENCE>>', requireTypeHeader: false }).
  The client falls back to /.well-known/oauth-authorization-server for providers that publish only RFC 8414.

REGISTER ON THE PROVIDER (checklist for me)
  [ ] App/client created with authorization code (+ refresh) enabled; PKCE allowed/required.
  [ ] Redirect URI(s), exact: .NET <<APP_BASE_URL>>/signin-oidc + <<APP_BASE_URL>>/signout-callback-oidc;
      Python <<APP_BASE_URL>>/signin-oidc + the post-logout URL; Node redirectUri + postLogoutRedirectUri.
  [ ] Public vs confidential matches the presence of a client secret.
  [ ] Role/group claim emitted into the ID token (or userinfo) under <<claim>>.
  [ ] Users/groups assigned to the app.
  [ ] For APIs: an API/resource with audience <<AUDIENCE>> and its scopes granted to this client.

VERIFY (run and report real output)
- Startup: no config error; the setup probe reports no issuer mismatch (the most common failure is a
  trailing-slash difference).
- Private window: protected page → provider sign-in → back signed in; the role-guarded page allows an
  assigned user and denies an unassigned one; sign-out behaves as the provider allows (state whether
  the provider session ends).
- API (if any): a real access token passes; an ID token sent as a bearer token is REJECTED (audience check).
- No secrets in tracked files.
```

---

## Keeping this file current

It is checked against **2.1.4**. When a release changes host wiring, a config key, a default or a
breaking behaviour, update the matching prompt and the version facts table above. The canonical
detail stays in each package's `MIGRATION.md` and `AI-PROMPT.md`. This file only routes an agent to
the right steps.
