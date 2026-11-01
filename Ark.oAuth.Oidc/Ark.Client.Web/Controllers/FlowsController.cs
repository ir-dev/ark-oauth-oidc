using System.Net.Http.Headers;
using System.Text.Json;
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
        private readonly IHttpClientFactory _http;

        public FlowsController(
            ArkAuthConfig config,
            ArkSetupProbe setup,
            ArkClientCredentials clientCredentials,
            ArkRegistration registration,
            IConfiguration appConfig,
            IHttpClientFactory http)
        {
            _config = config;
            _setup = setup;
            _clientCredentials = clientCredentials;
            _registration = registration;
            _appConfig = appConfig;
            _http = http;
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
        ///
        /// The form asks for this app's own client id by default. Ark honours a requested
        /// <c>client_id</c> when it is free, so the client created here is the one this app is
        /// already configured to sign in as, and nothing has to be reconfigured or restarted.
        /// </summary>
        [HttpPost("register")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RegisterClient(RegisterModel form)
        {
            // The page can carry a secret pasted from the admin console. It is echoed back to the
            // form and kept nowhere else, so the response must not be cached either.
            Response.Headers.CacheControl = "no-store";

            var requestedId = (form.RequestedClientId ?? "").Trim();
            var model = await BuildRegisterModelAsync(form.MachineSecret, requestedId);
            model.ClientName = form.ClientName;
            model.RequestedClientId = requestedId;
            model.RedirectUris = form.RedirectUris;
            model.PostLogoutRedirectUris = form.PostLogoutRedirectUris;
            model.GrantTypes = form.GrantTypes;
            model.Scope = form.Scope;
            model.TokenEndpointAuthMethod = form.TokenEndpointAuthMethod;
            model.ApplicationType = form.ApplicationType;
            model.InitialAccessToken = model.SecretCheck;

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
            // RFC 7591 leaves the identifier to the server; Ark accepts a requested one, and
            // refuses (rather than replaces) one that is taken or badly shaped.
            if (requestedId.Length > 0) metadata["client_id"] = requestedId;

            model.Registration = await _registration.RegisterAsync(metadata, model.ManagementToken);

            // Prefill the management form from the response. These values are shown once and are
            // not stored anywhere — reload the page and they are gone, which is exactly what
            // happens to the real credentials.
            if (model.Registration.Succeeded)
            {
                model.ManageClientId = model.Registration.ClientId ?? "";
                model.ManageAccessToken = model.Registration.RegistrationAccessToken ?? "";
                model.TargetClientId = model.Registration.ClientId ?? model.TargetClientId;
                await LookupTargetClientAsync(model);
            }

            return View("Register", model);
        }

        /// <summary>
        /// Removes the target client through the management API, for when it already exists and
        /// its registration access token is long gone — the usual state after registering once
        /// and reloading the page. RFC 7592's delete (Step 6) needs that token; the machine
        /// client's operator token does not.
        /// </summary>
        [HttpPost("register/remove")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RemoveClient(RegisterModel form)
        {
            Response.Headers.CacheControl = "no-store";
            var model = await BuildRegisterModelAsync(form.MachineSecret, form.TargetClientId);

            if (model.ManagementToken == null || model.TargetClient == null)
            {
                model.Removal = Failed("not_ready", model.ManagementToken == null
                    ? "Step 1 has no working machine secret, so the management API cannot be called."
                    : $"'{model.TargetClientId}' is not registered on the IdP, so there is nothing to remove.");
            }
            else if (string.Equals(model.TargetClient.ClientId, model.MachineClientId, StringComparison.Ordinal))
            {
                // the page's own credential; removing it would strand every step on this page
                model.Removal = Failed("refused", $"'{model.MachineClientId}' is the machine client this page authenticates with.");
            }
            else
            {
                model.Removal = await ManagementAsync(HttpMethod.Post, "client/delete", model.ManagementToken, new JsonObject
                {
                    ["id"] = model.TargetClient.Id,
                    ["tenant_id"] = TenantId(model.Authority),
                    ["client_id"] = model.TargetClient.ClientId
                });
                await LookupTargetClientAsync(model);
            }

            return View("Register", model);
        }

        /// <summary>
        /// Grants a user access to the target client: Ark's per-user, per-client mapping, done
        /// through the management API with the machine client's token.
        ///
        /// The mapping is one row per user and client, and saving it replaces the row's claims, so
        /// the claims already there are read first and kept. Granting <c>sample.admin</c> must not
        /// take <c>name</c> and <c>email</c> away.
        /// </summary>
        [HttpPost("register/map")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> MapUser(RegisterModel form)
        {
            Response.Headers.CacheControl = "no-store";
            var model = await BuildRegisterModelAsync(form.MachineSecret, form.TargetClientId);
            model.ManageClientId = form.ManageClientId ?? "";
            model.ManageAccessToken = form.ManageAccessToken ?? "";
            model.MapUser = (form.MapUser ?? "").Trim().ToLowerInvariant();
            model.MapClaims = form.MapClaims ?? "";

            var requested = ToJsonArray(model.MapClaims).Select(c => c!.GetValue<string>()).ToList();

            if (model.ManagementToken == null)
                model.Mapping = Failed("not_ready", "Step 1 has no working machine secret, so the management API cannot be called.");
            else if (model.TargetClient == null)
                model.Mapping = Failed("unknown_client", $"'{model.TargetClientId}' is not registered on the IdP — register it in Step 2 first.");
            else if (model.MapUser.Length == 0)
                model.Mapping = Failed("invalid_request", "name the user to grant access to.");
            else if (model.Users.Count > 0 && !model.Users.Contains(model.MapUser, StringComparer.OrdinalIgnoreCase))
                // the mapping table has no foreign key to users, so the IdP would store this happily
                model.Mapping = Failed("unknown_user", $"there is no account '{model.MapUser}' on the IdP. Create it under Users in the admin console.");
            else if (requested.Count == 0)
                model.Mapping = Failed("invalid_request", "add at least one claim.");
            else
            {
                var tenant = TenantId(model.Authority);
                var existing = await ManagementAsync(HttpMethod.Get,
                    $"user/list/client/claims/mapping/{Uri.EscapeDataString(model.MapUser)}/{Uri.EscapeDataString(tenant)}",
                    model.ManagementToken);
                var row = (existing.Data as JsonArray)?.FirstOrDefault(r =>
                    string.Equals(Str(r, "client_id"), model.TargetClient.Id, StringComparison.OrdinalIgnoreCase));
                var claims = ClaimsOf(row).Concat(requested).Distinct(StringComparer.Ordinal).ToList();

                model.Mapping = await ManagementAsync(HttpMethod.Post, "user/client/claims/upsert", model.ManagementToken, new JsonObject
                {
                    ["email"] = model.MapUser,
                    ["tenant_id"] = tenant,
                    // the client's surrogate id: what the token endpoint joins on to resolve ark_claims
                    ["client_id"] = model.TargetClient.Id,
                    ["claims"] = new JsonArray(claims.Select(c => (JsonNode?)c).ToArray()),
                    ["claims_"] = JsonSerializer.Serialize(claims)
                });
                if (model.Mapping.Succeeded) model.MappedClaims = claims;
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
        public async Task<IActionResult> ManageRegistration(string clientId, string accessToken, string action, RegisterModel form)
        {
            Response.Headers.CacheControl = "no-store";
            var model = await BuildRegisterModelAsync(form.MachineSecret, form.TargetClientId);
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

            if (action == "delete" && model.Management.Succeeded) await LookupTargetClientAsync(model);

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

        /// <param name="pastedSecret">A machine secret pasted on the page, tried in place of the configured one.</param>
        /// <param name="targetClientId">The client the later steps act on; this app's own by default.</param>
        private async Task<RegisterModel> BuildRegisterModelAsync(string? pastedSecret = null, string? targetClientId = null)
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

            // The form is prefilled with this app's own registration — its client id, its callbacks,
            // its scopes and its kind of client — so the client registered here is the one this app
            // already signs in as.
            model.AppRedirectUri = $"{model.Origin}{CallbackPath(_config.CallbackPath, "/signin-oidc")}";
            model.RedirectUris = model.AppRedirectUri;
            model.PostLogoutRedirectUris = $"{model.Origin}{CallbackPath(_config.SignedOutCallbackPath, "/signout-callback-oidc")}";
            model.RequestedClientId = model.AppClientId;
            model.ClientName = model.AppClientId;
            model.TokenEndpointAuthMethod = model.AppIsConfidential ? "client_secret_post" : "none";
            if (_config.Scopes is { Count: > 0 } scopes) model.Scope = string.Join(" ", scopes);
            model.TargetClientId = string.IsNullOrWhiteSpace(targetClientId) ? model.AppClientId : targetClientId.Trim();

            // Identity claims shape the ID token; the role is what the Roles page and
            // RequireArkClaims look for.
            var role = _appConfig["sample:RequiredRole"] ?? "sample.admin";
            model.MapClaims = $"name email email_verified {role}";

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
            // report "works" for up to an hour after it stopped being true. A pasted secret is
            // tried instead of the configured one, and only echoed back to the page's forms.
            var pasted = (pastedSecret ?? "").Trim();
            model.MachineSecret = pasted;
            var secret = pasted.Length > 0 ? pasted : MachineSecret();
            if (!string.IsNullOrWhiteSpace(secret))
            {
                if (model.DiscoveryOk)
                {
                    var check = await _clientCredentials.RequestTokenAsync(
                        model.MachineClientId, secret!, new[] { "client.register" });
                    model.SecretCheck = check;
                    model.MachineSecretStatus = check.Succeeded ? "works" : "rejected";
                    model.MachineSecretError = check.Succeeded ? null : $"{check.Error}: {check.ErrorDescription}";
                    if (check.Succeeded) model.ManagementToken = check.AccessToken;
                }
                else
                {
                    model.MachineSecretStatus = "unchecked";
                }
            }

            if (model.ManagementToken != null)
            {
                await LookupTargetClientAsync(model);

                var users = await ManagementAsync(HttpMethod.Get, "user/list", model.ManagementToken);
                model.Users = (users.Data as JsonArray ?? new JsonArray())
                    .Select(u => Str(u, "email"))
                    .Where(e => !string.IsNullOrWhiteSpace(e))
                    .Select(e => e!)
                    .OrderBy(e => e, StringComparer.OrdinalIgnoreCase)
                    .ToList();
            }

            return model;
        }

        /// <summary>
        /// Asks the IdP whether <see cref="RegisterModel.TargetClientId"/> exists in this tenant.
        /// The management API answers the machine client's token, so the page can say "already
        /// registered" before Step 2 runs into a 409, and Step 3 can find the client's surrogate id.
        /// </summary>
        private async Task LookupTargetClientAsync(RegisterModel model)
        {
            model.TargetClient = null;
            model.TargetLookupError = null;
            if (model.ManagementToken == null)
            {
                model.TargetLookup = "unchecked";
                return;
            }

            var list = await ManagementAsync(HttpMethod.Get, "client/list", model.ManagementToken);
            if (!list.Succeeded)
            {
                model.TargetLookup = "failed";
                model.TargetLookupError = list.Message;
                return;
            }

            var tenant = TenantId(model.Authority);
            var record = (list.Data as JsonArray)?.FirstOrDefault(c =>
                string.Equals(Str(c, "tenant_id"), tenant, StringComparison.OrdinalIgnoreCase)
                && string.Equals(Str(c, "client_id"), model.TargetClientId, StringComparison.Ordinal));

            model.TargetLookup = record == null ? "missing" : "found";
            if (record != null)
            {
                model.TargetClient = new ArkClientSummary
                {
                    Id = Str(record, "id") ?? "",
                    ClientId = Str(record, "client_id") ?? "",
                    Name = Str(record, "client_name") ?? Str(record, "name"),
                    TokenEndpointAuthMethod = Str(record, "token_endpoint_auth_method"),
                    IsActive = record["is_active"] is not JsonValue active || !active.TryGetValue<bool>(out var on) || on
                };
            }
        }

        /// <summary>
        /// One call to the IdP's management API, authenticated with the machine client's token.
        /// It lives at the host root (<c>{BaseUrl}/api/oauth/v1</c>), not under the tenant, and
        /// mostly answers HTTP 200 with <c>error: true</c> in the body, so both are read.
        /// </summary>
        private async Task<ArkManagementResult> ManagementAsync(HttpMethod method, string path, string token, JsonObject? body = null)
        {
            var result = new ArkManagementResult();
            try
            {
                using var request = new HttpRequestMessage(method, $"{ManagementBase(_config.ResolveAuthority())}/{path}");
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                if (body != null) request.Content = System.Net.Http.Json.JsonContent.Create(body);

                using var response = await _http.CreateClient("ark-management").SendAsync(request);
                result.StatusCode = (int)response.StatusCode;
                var raw = await response.Content.ReadAsStringAsync();
                result.RawResponse = ArkJson.Prettify(raw);

                JsonObject? json = null;
                try { json = JsonNode.Parse(raw) as JsonObject; } catch (JsonException) { }

                var error = json?["error"] is JsonValue e && e.TryGetValue<bool>(out var flag) ? flag : json == null;
                result.Succeeded = response.IsSuccessStatusCode && !error;
                result.Code = Str(json, "code");
                result.Message = Str(json, "msg") ?? (json == null ? $"HTTP {result.StatusCode}, not a management API response." : null);
                result.Data = json?["data"];
            }
            catch (Exception ex)
            {
                result.Message = ex.Message;
            }
            return result;
        }

        private static ArkManagementResult Failed(string code, string message) =>
            new() { Code = code, Message = message };

        private static string? Str(JsonNode? node, string name) =>
            node?[name] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

        /// <summary>A mapping row's claims, sent as an array or as the JSON string column behind it.</summary>
        private static List<string> ClaimsOf(JsonNode? row)
        {
            if (row?["claims"] is JsonArray array)
                return array.Select(c => c?.GetValue<string>()).Where(c => !string.IsNullOrEmpty(c)).Select(c => c!).ToList();
            var raw = Str(row, "claims_");
            if (string.IsNullOrWhiteSpace(raw)) return new List<string>();
            try { return JsonSerializer.Deserialize<List<string>>(raw) ?? new List<string>(); }
            catch (JsonException) { return new List<string>(); }
        }

        /// <summary>The host the management API is served from: the Authority without its tenant segment.</summary>
        private static string ManagementBase(string authority)
        {
            var trimmed = (authority ?? "").TrimEnd('/');
            var slash = trimmed.LastIndexOf('/');
            return $"{(slash > "https://".Length ? trimmed[..slash] : trimmed)}/api/oauth/v1";
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
