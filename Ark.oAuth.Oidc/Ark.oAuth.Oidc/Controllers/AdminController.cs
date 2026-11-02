using System.Reflection;
using Ark.oAuth.Oidc.Protocol;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Ark.oAuth.Oidc.Controllers
{
    /// <summary>
    /// The v2 admin console — tenants, clients, users, scopes, claims and the per-user-per-client
    /// access mapping — served from inside this package.
    ///
    /// It used to live in the sample host, which meant the only way to get a console with a
    /// NuGet reference was to copy a controller, a view, a stylesheet and 800 lines of JavaScript
    /// out of this repository and keep them in step by hand. Everything it needs now ships in the
    /// assembly: the view sets <c>Layout = null</c> and brings its own shell, and
    /// <see cref="Asset"/> serves the stylesheet and script as embedded resources, so a host that
    /// references the package gets /{tenant}/admin with no wiring at all.
    ///
    /// It replaces the v1 console at /oauth/{tenant}/v1/server/{client}/manage, which is still
    /// served for existing deployments. Every URL this one hands out is a current one:
    ///
    ///   * management API   /api/oauth/v1/...
    ///   * client setup     /{tenant}/oauth2/integrate/{client_id}
    ///   * discovery        /{tenant}/.well-known/openid-configuration
    ///
    /// Identity comes off the authenticated principal, built by the host's OIDC handler from the
    /// ID token and UserInfo. The v1 console read it from a separate /userinfo call whose result
    /// it then had to trust.
    /// </summary>
    [Authorize]
    public class AdminController : Controller
    {
        private readonly DataAccess _da;
        private readonly IConfiguration _config;

        public AdminController(DataAccess da, IConfiguration config)
        {
            _da = da;
            _config = config;
        }

        private ArkAuthServerConfig ServerConfig =>
            _config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>()
            ?? throw new ApplicationException("the 'ark_oauth_server' configuration section is missing.");

        /// <summary>Convenience entry point: sends the operator to their own tenant's console.</summary>
        [HttpGet("/admin")]
        public IActionResult Index() => RedirectToAction(nameof(Manage), new { tenant_id = ServerConfig.TenantId });

        [HttpGet("/{tenant_id}/admin")]
        public async Task<IActionResult> Manage([FromRoute] string tenant_id)
        {
            var tenant = await _da.GetTenant(tenant_id);
            if (tenant == null) return NotFound($"unknown tenant '{tenant_id}'.");
            BuildConsoleView(tenant, "console");
            return View();
        }

        /// <summary>
        /// Onboarding: provision an application, and switch applications or accounts off and on.
        ///
        /// A page of its own rather than two more panels on the console, because these two are the
        /// only operations there that are not "edit a row" — they create an application and its
        /// user in one call, and they revoke sessions and refresh tokens. Both are worth reaching
        /// deliberately rather than scrolling past on the way to the scope catalogue.
        ///
        /// Restricted to the operator account (see <see cref="IsOperator"/>). That is a narrowing
        /// of the console's own model, where every signed-in user is a global operator over every
        /// tenant — the link is hidden for everybody else and the route refuses them, so this page
        /// does not become the way an ordinary console user discovers it.
        /// </summary>
        [HttpGet("/{tenant_id}/admin/provisioning")]
        public async Task<IActionResult> Provisioning([FromRoute] string tenant_id)
        {
            var tenant = await _da.GetTenant(tenant_id);
            if (tenant == null) return NotFound($"unknown tenant '{tenant_id}'.");
            if (!IsOperator())
                return StatusCode(403, "Provisioning and activation are restricted to the administrator account.");

            BuildConsoleView(tenant, "provisioning");

            // The machine-to-machine client seeded beside the console. It is what the generated
            // curl authenticates as, so the page needs its client_id and whether it can hold a
            // secret at all — a public client cannot run client_credentials.
            var machine = await _da.GetClient(tenant.tenant_id, $"{ServerConfig.TenantId}_machine");
            ViewBag.MachineClientId = machine?.client_id ?? "";
            ViewBag.MachineHasSecret = !string.IsNullOrEmpty(machine?.client_secret_hash);
            // Set from Management:MachineClientSecret: the API refuses to regenerate it, so the
            // page says so rather than offering a button that fails.
            ViewBag.MachineSecretManaged = ServerConfig.Management?.ConfiguredMachineClientSecret != null;

            // Absolute, and taken from the same builder the discovery document uses — a command
            // meant to be pasted into somebody else's shell cannot be built from
            // window.location, which is whatever address this particular browser happened to
            // reach the server on.
            var ep = ArkOidcEndpoints.For(Request, ServerConfig, tenant.tenant_id);
            ViewBag.TokenEndpoint = ep.Token;
            ViewBag.ApiRoot = $"{ep.BaseUrl}/api/oauth/v1";
            return View();
        }

        /// <summary>
        /// Export, import and factory reset of the whole server.
        ///
        /// Operator only, for the same reason as provisioning and more so: an export carries every
        /// private signing key and password hash, and the other two can replace or delete
        /// everything. The page is a shell — what each mode of an import would do is worked out by
        /// the API (<see cref="ArkDataTools"/>), so a script gets the same answers the screen does.
        /// </summary>
        [HttpGet("/{tenant_id}/admin/data")]
        public async Task<IActionResult> Data([FromRoute] string tenant_id)
        {
            var tenant = await _da.GetTenant(tenant_id);
            if (tenant == null) return NotFound($"unknown tenant '{tenant_id}'.");
            if (!DataToolsEnabled) return NotFound();
            if (!IsOperator())
                return StatusCode(403, "Export, import and reset are restricted to the administrator account.");

            BuildConsoleView(tenant, "data");
            var tools = ServerConfig.Admin?.DataTools ?? new ArkDataToolsConfig();
            ViewBag.OperatorTenant = ServerConfig.TenantId;
            ViewBag.AllowReset = tools.AllowReset;
            ViewBag.AllowImport = tools.AllowImport;
            ViewBag.AllowReplace = tools.AllowImport && tools.AllowReplace;
            return View();
        }

        private bool DataToolsEnabled => ServerConfig.Admin?.DataTools?.Enabled ?? true;

        /// <summary>
        /// The view data both console pages share: branding, endpoints, asset URLs and identity.
        /// </summary>
        private void BuildConsoleView(ArkTenant tenant, string page)
        {
            var ser = ServerConfig;

            var endpoints = ArkOidcEndpoints.For(Request, ser, tenant.tenant_id);

            // Everything the page fetches is relative to the app root, which is not necessarily
            // "/" — it is whatever the app is mounted under. Reading it from PathBase keeps the
            // console working under a sub-path without a second setting to keep in step.
            var appRoot = Request.PathBase.HasValue ? Request.PathBase.Value!.TrimEnd('/') : "";
            ViewBag.AppRoot = appRoot;

            ViewBag.Tenant = tenant;
            ViewBag.TenantId = tenant.tenant_id;
            ViewBag.Issuer = endpoints.Issuer;
            ViewBag.Discovery = endpoints.Discovery;
            ViewBag.Jwks = endpoints.Jwks;
            // The same two marks the sign-in page shows, in the same order, so the console and
            // the pages it configures read as one product rather than two. The client mark here
            // is the configured default — the per-client ones are drawn against their own rows.
            ViewBag.HostLogo = ser.EmailConfig?.host_logo ?? "";
            ViewBag.ClientLogo = ser.EmailConfig?.client_logo ?? "";
            ViewBag.HostName = ser.EmailConfig?.host_company_display ?? ser.EmailConfig?.host_company_name ?? "Identity Provider";
            ViewBag.ConsoleCss = AssetUrl(appRoot, CssAsset);
            ViewBag.ConsoleJs = AssetUrl(appRoot, JsAsset);
            ViewBag.ThemeCss = AssetUrl(appRoot, ThemeCssAsset);
            ViewBag.ThemeJs = AssetUrl(appRoot, ThemeJsAsset);
            ViewBag.ShieldUrl = AssetUrl(appRoot, ShieldAsset);
            ViewBag.ShowPoweredBy = ser.ShowPoweredBy;
            // Named in the footer: which build of the server package is serving this console.
            ViewBag.PackageVersion = PackageVersion;
            ViewBag.UserPasswordMode = ser.EffectiveUserPasswordMode switch
            {
                ArkUserPasswordMode.AdminManaged => "admin_managed",
                ArkUserPasswordMode.EmailBased => "email_based",
                _ => "auto"
            };

            // The console's session is the host's authentication cookie, and only the host can
            // drop it. With no route configured, end_session at least ends the session at the IdP
            // and lands on its signed-out page — no post_logout_redirect_uri, because the endpoint
            // honours only URIs the client registered and would ignore anything passed here.
            var signOut = ser.Admin?.SignOutUrl;
            ViewBag.SignOutUrl = string.IsNullOrWhiteSpace(signOut) ? endpoints.EndSession : signOut;

            var name = User.FindFirst("name")?.Value;
            var email = User.FindFirst("email")?.Value ?? User.FindFirst("preferred_username")?.Value;
            ViewBag.UserName = string.IsNullOrWhiteSpace(name) ? (email ?? "signed in") : name;
            ViewBag.UserEmail = email ?? "";

            // Which page is being drawn, and what the nav should offer. The provisioning link is
            // drawn only for the operator: a link that answers 403 is worse than no link.
            ViewBag.Page = page;
            ViewBag.IsOperator = IsOperator();
            ViewBag.ConsoleUrl = $"{appRoot}/{tenant.tenant_id}/admin";
            ViewBag.ProvisioningUrl = $"{appRoot}/{tenant.tenant_id}/admin/provisioning";
            ViewBag.DataUrl = $"{appRoot}/{tenant.tenant_id}/admin/data";
            ViewBag.DataToolsEnabled = DataToolsEnabled;
        }

        /// <summary>Whether the signed-in principal is the operator account — see <see cref="ArkOperator"/>.</summary>
        private bool IsOperator() => ArkOperator.IsOperator(User, ServerConfig);

        // ------------------------------------------------------------------ static assets

        public const string CssAsset = "ark-admin.css";
        public const string JsAsset = "ark-admin.js";
        /// <summary>Appearance (theme, text size) script — every IdP page, see wwwroot/js/ark-theme.js.</summary>
        public const string ThemeJsAsset = "ark-theme.js";
        /// <summary>The appearance picker and "Powered by" mark styling, beside <see cref="ThemeJsAsset"/>.</summary>
        public const string ThemeCssAsset = "ark-theme.css";
        /// <summary>The Ark shield, small: the "Powered by" mark.</summary>
        public const string ShieldAsset = "ark-shield-64.png";
        /// <summary>The Ark shield, full size, for touch icons and anywhere it is drawn large.</summary>
        public const string ShieldLargeAsset = "ark-shield-512.png";

        /// <summary>
        /// The files the console and the sign-in pages are built from, as embedded resources.
        ///
        /// An allow-list rather than a name-to-resource translation: the route segment is
        /// attacker-supplied, and every string in this assembly's manifest — the migration
        /// scripts included — is one resource lookup away from a caller who can shape it.
        /// </summary>
        private static readonly Dictionary<string, (string Resource, string ContentType)> Assets =
            new(StringComparer.OrdinalIgnoreCase)
            {
                [CssAsset] = ("Ark.oAuth.Oidc.wwwroot.css.ark-admin.css", "text/css; charset=utf-8"),
                [JsAsset] = ("Ark.oAuth.Oidc.wwwroot.js.ark-admin.js", "text/javascript; charset=utf-8"),
                [ThemeCssAsset] = ("Ark.oAuth.Oidc.wwwroot.css.ark-theme.css", "text/css; charset=utf-8"),
                [ThemeJsAsset] = ("Ark.oAuth.Oidc.wwwroot.js.ark-theme.js", "text/javascript; charset=utf-8"),
                [ShieldAsset] = ("Ark.oAuth.Oidc.wwwroot.img.ark-shield-64.png", "image/png"),
                [ShieldLargeAsset] = ("Ark.oAuth.Oidc.wwwroot.img.ark-shield-512.png", "image/png")
            };

        /// <summary>The package version, used to bust the cache of the URLs below on upgrade.</summary>
        private static readonly string AssetVersion =
            typeof(AdminController).Assembly.GetName().Version?.ToString() ?? "1";

        /// <summary>
        /// The version the console names in its footer.
        ///
        /// The informational version rather than <see cref="AssetVersion"/>: that one is the
        /// four-part assembly version and exists only to bust a cache, while this is the version
        /// as published to nuget.org — "2.0.4", the number a support conversation starts from.
        /// Source Link appends "+{commit}" on a CI build, which is trimmed off.
        /// </summary>
        private static readonly string PackageVersion = ReadPackageVersion();

        private static string ReadPackageVersion()
        {
            var assembly = typeof(AdminController).Assembly;
            var informational = assembly
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;

            if (string.IsNullOrWhiteSpace(informational))
                return assembly.GetName().Version?.ToString() ?? "";

            var plus = informational.IndexOf('+');
            return plus < 0 ? informational : informational.Substring(0, plus);
        }

        /// <summary>
        /// The console's stylesheet and script, at a stable path a host page can link to as well —
        /// see <see cref="AssetUrl"/>.
        ///
        /// Anonymous: this is the same static CSS and JavaScript for every caller and holds
        /// nothing worth authenticating for. Behind <c>[Authorize]</c> an expired session would
        /// answer the stylesheet request with the sign-in page, at which point the console renders
        /// unstyled instead of redirecting.
        /// </summary>
        [AllowAnonymous]
        [HttpGet("/ark-admin/asset/{file}")]
        [ResponseCache(Duration = 31536000, Location = ResponseCacheLocation.Any)]
        public IActionResult Asset([FromRoute] string file)
        {
            if (!Assets.TryGetValue(file ?? "", out var asset)) return NotFound();

            var stream = typeof(AdminController).Assembly.GetManifestResourceStream(asset.Resource);
            if (stream == null) return NotFound();

            return File(stream, asset.ContentType);
        }

        /// <summary>
        /// Absolute-path URL for one of the console assets, version-stamped.
        ///
        /// Public because the assets carry the shell styling (top bar, panels, buttons, the
        /// landing layout) that a host's own pages sit inside — the sample host links its layout
        /// here rather than keeping a second copy of the same stylesheet.
        /// </summary>
        public static string AssetUrl(string appRoot, string file) =>
            $"{(appRoot ?? "").TrimEnd('/')}/ark-admin/asset/{file}?v={AssetVersion}";
    }
}
