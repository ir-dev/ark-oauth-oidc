using System.Text.Json.Nodes;
using Ark.Client.Web.Models;
using Ark.oAuth;
using Microsoft.AspNetCore.Mvc;

namespace Ark.Client.Web.Controllers
{
    /// <summary>
    /// The flows that are not "a web application signing a user in".
    ///
    /// The rest of this sample shows the authorization code flow through a confidential-ish web
    /// app, where ASP.NET Core's OpenID Connect handler does everything. These three are the cases
    /// that handler does not cover, and each one is here because the difference is easy to get
    /// wrong:
    ///
    ///  * <b>SPA</b> — the same authorization code flow, but run by JavaScript in a public client
    ///    with no secret. PKCE stops being an extra protection and becomes the only thing tying
    ///    the redeemed code to the browser that started the flow.
    ///  * <b>client_credentials</b> — no user at all. The token says "this service", not "this
    ///    person", and using it to act for a signed-in user silently escalates their authority.
    ///  * <b>dynamic registration</b> — creating a client at runtime rather than by hand, and the
    ///    one-shot credentials that come back with it.
    /// </summary>
    [Route("flows")]
    public class FlowsController : Controller
    {
        private readonly ArkAuthConfig _config;
        private readonly ArkSetupProbe _setup;
        private readonly ArkClientCredentials _clientCredentials;
        private readonly ArkRegistration _registration;
        private readonly IConfiguration _appConfig;

        public FlowsController(
            ArkAuthConfig config,
            ArkSetupProbe setup,
            ArkClientCredentials clientCredentials,
            ArkRegistration registration,
            IConfiguration appConfig)
        {
            _config = config;
            _setup = setup;
            _clientCredentials = clientCredentials;
            _registration = registration;
            _appConfig = appConfig;
        }

        // -----------------------------------------------------------------------------------------
        // Single-page application: authorization code + PKCE in the browser.
        // -----------------------------------------------------------------------------------------

        /// <summary>
        /// Serves the SPA page. This action does no OAuth work of its own — it hands the browser
        /// the provider's endpoints and gets out of the way.
        ///
        /// The same URL is the registered redirect_uri, so the authorization server returns the
        /// user here with <c>?code=</c> and the page's JavaScript completes the exchange. That is
        /// why the action must stay anonymous: putting [Authorize] on it would start a second,
        /// server-side sign-in the moment the SPA's callback arrived.
        /// </summary>
        [HttpGet("spa")]
        public async Task<IActionResult> Spa()
        {
            var origin = $"{Request.Scheme}://{Request.Host}{Request.PathBase}";
            var model = new SpaModel
            {
                ClientId = _appConfig["sample:Spa:ClientId"] ?? "ark_sample_spa",
                RedirectUri = $"{origin}/flows/spa",
                Origin = origin,
                Authority = _config.ResolveAuthority(),
                // No offline_access: a refresh token in a browser has nowhere safe to live.
                Scopes = _appConfig.GetSection("sample:Spa:Scopes").Get<string[]>()?.ToList()
                         ?? new List<string> { "openid", "profile", "email" }
            };

            try
            {
                model.Provider = await _setup.ReadMetadataAsync();
                model.DiscoveryOk = true;
            }
            catch (Exception ex)
            {
                model.DiscoveryError = ex.Message;
            }

            return View(model);
        }

        // -----------------------------------------------------------------------------------------
        // Client credentials: a service authenticating as itself.
        // -----------------------------------------------------------------------------------------

        [HttpGet("machine")]
        public async Task<IActionResult> Machine() => View(await BuildMachineModelAsync());

        /// <summary>
        /// Runs the grant and shows the exchange.
        ///
        /// Deliberately uses <c>RequestTokenAsync</c> rather than the cached <c>GetTokenAsync</c>:
        /// this page exists to show a request happening. Real service code should call the cached
        /// one — a client credentials token lasts an hour and has no session behind it, so asking
        /// for a fresh one per outbound call doubles the traffic and rate-limits the caller
        /// against its own identity provider.
        /// </summary>
        [HttpPost("machine")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> MachineToken()
        {
            var model = await BuildMachineModelAsync();
            var secret = MachineSecret();

            if (string.IsNullOrWhiteSpace(secret))
            {
                model.Result = new ArkTokenResult
                {
                    Error = "not_configured",
                    ErrorDescription = "sample:Machine:ClientSecret is not set — see the steps above."
                };
                return View("Machine", model);
            }

            model.Result = await _clientCredentials.RequestTokenAsync(
                model.ClientId, secret!, model.Scopes);

            return View("Machine", model);
        }

        // -----------------------------------------------------------------------------------------
        // Dynamic client registration (RFC 7591) and management (RFC 7592).
        // -----------------------------------------------------------------------------------------

        [HttpGet("register")]
        public async Task<IActionResult> Register()
        {
            return View(await BuildRegisterModelAsync());
        }

        /// <summary>
        /// Obtains an initial access token with the client credentials grant, then registers the
        /// client with it.
        ///
        /// The two steps are chained because that is the shape of the real thing: registration is
        /// an authorized operation, and the authority to perform it is itself an OAuth token. On
        /// Ark that token has to carry the <c>client.register</c> scope, which the machine client
        /// is registered for.
        /// </summary>
        [HttpPost("register")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RegisterClient(RegisterModel form)
        {
            var model = await BuildRegisterModelAsync();
            model.ClientName = form.ClientName;
            model.RedirectUris = form.RedirectUris;
            model.PostLogoutRedirectUris = form.PostLogoutRedirectUris;
            model.GrantTypes = form.GrantTypes;
            model.Scope = form.Scope;
            model.TokenEndpointAuthMethod = form.TokenEndpointAuthMethod;
            model.ApplicationType = form.ApplicationType;

            // The page can carry a secret pasted from the admin console. It is echoed back to the
            // form and kept nowhere else, so the response must not be cached either.
            Response.Headers.CacheControl = "no-store";
            var pasted = (form.MachineSecret ?? "").Trim();
            model.MachineSecret = pasted;

            string? initialAccessToken = null;
            var secret = pasted.Length > 0 ? pasted : MachineSecret();
            if (!string.IsNullOrWhiteSpace(secret))
            {
                // A configured secret is served from the cache: within this token's hour the second
                // registration skips the round trip. A pasted one never is — the cache is keyed by
                // client, not secret, so a token minted with an older secret would hide a wrong paste.
                model.InitialAccessToken = pasted.Length > 0
                    ? await _clientCredentials.RequestTokenAsync(model.MachineClientId, pasted, new[] { "client.register" })
                    : await _clientCredentials.GetTokenAsync(model.MachineClientId, secret!, new[] { "client.register" });
                initialAccessToken = model.InitialAccessToken.AccessToken;

                if (pasted.Length > 0)
                {
                    model.MachineSecretStatus = model.InitialAccessToken.Succeeded ? "works" : "rejected";
                    model.MachineSecretError = model.InitialAccessToken.Succeeded
                        ? null : $"{model.InitialAccessToken.Error}: {model.InitialAccessToken.ErrorDescription}";
                }
            }

            var metadata = new JsonObject
            {
                ["client_name"] = form.ClientName,
                ["application_type"] = form.ApplicationType,
                ["token_endpoint_auth_method"] = form.TokenEndpointAuthMethod,
                ["redirect_uris"] = ToJsonArray(form.RedirectUris),
                ["post_logout_redirect_uris"] = ToJsonArray(form.PostLogoutRedirectUris),
                ["grant_types"] = ToJsonArray(form.GrantTypes),
                ["response_types"] = new JsonArray("code"),
                // RFC 7591 carries scopes as one space-delimited string, not an array
                ["scope"] = (form.Scope ?? "").Trim()
            };

            model.Registration = await _registration.RegisterAsync(metadata, initialAccessToken);

            // Prefill the management form from the response. These values are shown once and are
            // not stored anywhere — reload the page and they are gone, which is exactly what
            // happens to the real credentials.
            if (model.Registration.Succeeded)
            {
                model.ManageClientId = model.Registration.ClientId ?? "";
                model.ManageAccessToken = model.Registration.RegistrationAccessToken ?? "";
            }

            return View("Register", model);
        }

        /// <summary>
        /// Reads or deletes an existing registration with its registration access token
        /// (RFC 7592). The token is the only credential that works here — the client's own access
        /// token does not, and neither does the initial access token that created it.
        /// </summary>
        [HttpPost("register/manage")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageRegistration(string clientId, string accessToken, string action)
        {
            var model = await BuildRegisterModelAsync();
            model.ManageClientId = clientId ?? "";
            model.ManageAccessToken = accessToken ?? "";
            model.ManagementAction = action;

            if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(accessToken))
            {
                model.Management = new ArkRegistrationResult
                {
                    Error = "invalid_request",
                    ErrorDescription = "both the client_id and its registration access token are required."
                };
                return View("Register", model);
            }

            model.Management = action == "delete"
                ? await _registration.DeleteAsync(clientId, accessToken)
                : await _registration.ReadAsync(clientId, accessToken);

            return View("Register", model);
        }

        // -----------------------------------------------------------------------------------------

        private string? MachineSecret() => _appConfig["sample:Machine:ClientSecret"];

        private async Task<MachineModel> BuildMachineModelAsync()
        {
            var authority = _config.ResolveAuthority();
            var model = new MachineModel
            {
                ClientId = _appConfig["sample:Machine:ClientId"] ?? $"{TenantId(authority)}_machine",
                SecretConfigured = !string.IsNullOrWhiteSpace(MachineSecret()),
                Scopes = _appConfig.GetSection("sample:Machine:Scopes").Get<string[]>()?.ToList()
                         ?? new List<string> { "client.register" },
                Authority = authority,
                AdminConsoleUrl = AdminConsoleUrl(authority)
            };

            try
            {
                var metadata = await _setup.ReadMetadataAsync();
                model.DiscoveryOk = true;
                model.TokenEndpoint = metadata.TokenEndpoint;
                model.SupportsClientCredentials = metadata.GrantTypesSupported
                    .Contains("client_credentials", StringComparer.OrdinalIgnoreCase);
            }
            catch (Exception ex)
            {
                model.DiscoveryError = ex.Message;
            }

            return model;
        }

        private async Task<RegisterModel> BuildRegisterModelAsync()
        {
            var authority = _config.ResolveAuthority();
            var model = new RegisterModel
            {
                Authority = authority,
                MachineClientId = _appConfig["sample:Machine:ClientId"] ?? $"{TenantId(authority)}_machine",
                MachineSecretConfigured = !string.IsNullOrWhiteSpace(MachineSecret()),
                AdminConsoleUrl = AdminConsoleUrl(authority),
                Origin = $"{Request.Scheme}://{Request.Host}{Request.PathBase}",
                AppClientId = _config.ClientId,
                AppIsConfidential = !string.IsNullOrWhiteSpace(_config.ClientSecret),
                AppRequiresArkClaims = _config.AccountSwitch?.RequireArkClaims == true
            };

            // This app's own callbacks. They prefill the form, so the client registered here is one
            // this app can sign in with once its ClientId points at it.
            model.AppRedirectUri = $"{model.Origin}{CallbackPath(_config.CallbackPath, "/signin-oidc")}";
            model.RedirectUris = model.AppRedirectUri;
            model.PostLogoutRedirectUris = $"{model.Origin}{CallbackPath(_config.SignedOutCallbackPath, "/signout-callback-oidc")}";

            try
            {
                var metadata = await _setup.ReadMetadataAsync();
                model.DiscoveryOk = true;
                model.RegistrationEndpoint = metadata.RegistrationEndpoint;
            }
            catch (Exception ex)
            {
                model.DiscoveryError = ex.Message;
            }

            // A configured value is not a working one. The IdP keeps only a hash, and a recreated
            // IdP database seeds the machine client with no secret at all, so the only way to tell
            // is to try it. Uncached on purpose: a token cached from before the IdP changed would
            // report "works" for up to an hour after it stopped being true.
            var configured = MachineSecret();
            if (!string.IsNullOrWhiteSpace(configured))
            {
                if (model.DiscoveryOk)
                {
                    var check = await _clientCredentials.RequestTokenAsync(
                        model.MachineClientId, configured!, new[] { "client.register" });
                    model.MachineSecretStatus = check.Succeeded ? "works" : "rejected";
                    model.MachineSecretError = check.Succeeded ? null : $"{check.Error}: {check.ErrorDescription}";
                }
                else
                {
                    model.MachineSecretStatus = "unchecked";
                }
            }

            return model;
        }

        private static string TenantId(string authority)
        {
            var trimmed = (authority ?? "").TrimEnd('/');
            var slash = trimmed.LastIndexOf('/');
            return slash > 0 && slash < trimmed.Length - 1 ? trimmed[(slash + 1)..] : "";
        }

        private static string AdminConsoleUrl(string authority)
        {
            var trimmed = (authority ?? "").TrimEnd('/');
            var slash = trimmed.LastIndexOf('/');
            return slash > 0 ? $"{trimmed[..slash]}/{TenantId(authority)}/admin" : trimmed + "/admin";
        }

        private static string CallbackPath(string? configured, string fallback) =>
            string.IsNullOrWhiteSpace(configured) ? fallback : "/" + configured.TrimStart('/');

        private static JsonArray ToJsonArray(string? spaceOrNewlineSeparated)
        {
            var array = new JsonArray();
            foreach (var value in (spaceOrNewlineSeparated ?? "")
                     .Split(new[] { ' ', '\r', '\n', '\t', ',' }, StringSplitOptions.RemoveEmptyEntries))
                array.Add(value.Trim());
            return array;
        }
    }
}
