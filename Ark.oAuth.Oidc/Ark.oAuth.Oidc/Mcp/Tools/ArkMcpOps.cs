using System.Text.RegularExpressions;
using Ark.oAuth.Oidc.Protocol;
using Ark.Watch.Core;
using Microsoft.EntityFrameworkCore;

namespace Ark.oAuth.Oidc.Mcp.Tools
{
    /// <summary>
    /// What the tools of every level do, once: applications, accounts, access, agents, sessions.
    ///
    /// Each change goes through the code the console and the management API use, and leaves the
    /// same audit line and webhook event. What is added here is the boundary: a caller that is not
    /// the operator changes nothing outside its tenant, and an account only when its tenant owns it.
    /// </summary>
    internal static class ArkMcpOps
    {
        public static bool Same(string? a, string? b) => ArkMcpIndicators.Same(a, b);

        static string Now => DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");

        // ---------------------------------------------------------------- views

        public static object TenantView(ArkMcpCall call, ArkTenant t)
        {
            var ep = call.Endpoint.OidcFor(t.tenant_id);
            return new
            {
                tenant_id = t.tenant_id, name = t.name, display = t.display, token_expire_minutes_v1 = t.expire_mins, updated_at = t.at,
                is_operator_tenant = Same(t.tenant_id, call.Endpoint.OperatorTenantId),
                issuer = ep.Issuer, discovery = ep.Discovery, jwks = ep.Jwks, console = $"{call.Endpoint.Root}/{t.tenant_id}/admin",
                mcp = ArkMcpResources.Tenant(call.Endpoint.Root, t.tenant_id)
            };
        }

        public static string KindOf(ArkClient c)
        {
            var grants = c.EffectiveGrantTypes;
            bool Grant(string g) => grants.Contains(g, StringComparer.OrdinalIgnoreCase);
            if (c.is_agent == true) return "agent";
            if (grants.All(g => g.Equals("client_credentials", StringComparison.OrdinalIgnoreCase)
                || g.Equals(ArkAgentTokens.TokenExchangeGrant, StringComparison.OrdinalIgnoreCase))) return "service";
            if (Grant(DeviceGrant) && !Grant("authorization_code")) return "device";
            if (Grant("authorization_code"))
                return !c.IsPublicClient ? "web" : c.application_type is "native" or "spa" ? c.application_type : "public";
            return c.application_type ?? "web";
        }

        public const string DeviceGrant = "urn:ietf:params:oauth:grant-type:device_code";

        public static object ClientSummary(ArkMcpCall call, ArkClient c, int? people = null) => new
        {
            client_id = c.client_id, name = c.client_name ?? c.display, kind = KindOf(c), active = c.is_active,
            has_secret = c.has_client_secret, people, system = IsSystem(c) ? true : (bool?)null,
            mcp = ArkMcpResources.Client(call.Endpoint.Root, c.tenant_id, c.client_id)
        };

        public static object ClientView(ArkMcpCall call, ArkClient c) => new
        {
            client_id = c.client_id, tenant_id = c.tenant_id, name = c.client_name ?? c.display, kind = KindOf(c),
            system = IsSystem(c) ? "one of the server's own clients" : null,
            active = c.is_active, is_agent = c.is_agent == true,
            application_type = c.application_type, public_client = c.IsPublicClient,
            token_endpoint_auth_method = c.token_endpoint_auth_method, has_secret = c.has_client_secret,
            secret_expires_at = c.client_secret_expires_at,
            redirect_uris = c.EffectiveRedirectUris, post_logout_redirect_uris = c.EffectivePostLogoutRedirectUris,
            grant_types = c.EffectiveGrantTypes, scopes = c.EffectiveScopes,
            require_pkce = c.require_pkce, require_consent = c.require_consent, require_par = c.require_par,
            backchannel_logout_uri = Blank(c.backchannel_logout_uri), jwks_uri = Blank(c.jwks_uri),
            client_uri = Blank(c.client_uri), policy_uri = Blank(c.policy_uri), tos_uri = Blank(c.tos_uri),
            logo = (c.client_logo ?? "").StartsWith("data:", StringComparison.OrdinalIgnoreCase) ? "(an embedded image)" : Blank(c.client_logo),
            access_token_seconds = c.access_token_lifetime_seconds, refresh_token_seconds = c.refresh_token_lifetime_seconds,
            callers = c.a2a_callers.Select(a => new { client_id = a.client_id, claims = a.claims, delegate_users = a.delegate_users }),
            updated_at = c.at,
            mcp = ArkMcpResources.Client(call.Endpoint.Root, c.tenant_id, c.client_id)
        };

        static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;

        public static object UserView(ArkMcpCall call, ArkUser u, IEnumerable<(string Client, List<string> Claims)>? access = null) => new
        {
            username = u.email, name = u.name, type = u.type, active = u.is_active,
            waiting_for_password = u.reset_mode == true,
            managed_by = u.home_tenant_id ?? "operator",
            manageable_here = MayManage(call, u),
            updated_at = u.at,
            access = access?.Select(a => new { client_id = a.Client, claims = a.Claims })
        };

        /// <summary>The console, the machine client: the clients the server itself stands on.</summary>
        public static bool IsSystem(ArkClient c) =>
            Same(c.client_id, ArkManagementAuth.MachineClientId(c.tenant_id)) || Same(c.client_id, $"{c.tenant_id}_client");

        // ---------------------------------------------------------------- lookups

        /// <summary>An application of the endpoint's tenant: untracked, safe to change and save.</summary>
        public static async Task<ArkClient> ClientAsync(ArkMcpCall call, string clientId)
        {
            call.Touches("client", clientId);
            return await ArkLookup.ClientAsync(call.Db, call.Tenant.tenant_id, clientId)
                ?? throw new ArkMcpToolException("unknown_client", $"no application '{clientId}' is registered in tenant '{call.Tenant.tenant_id}'. client_list shows the ones that are.");
        }

        /// <summary>The application a call is about: the endpoint's own at the client level, else the one named.</summary>
        public static Task<ArkClient> TargetAsync(ArkMcpCall call) =>
            ClientAsync(call, call.Endpoint.Level == ArkMcpLevel.Client ? call.Client.client_id : call.Args.Required("client_id"));

        public static async Task<ArkUser?> FindUserAsync(ArkMcpCall call, string? username)
        {
            call.Touches("user", username);
            return await ArkLookup.UserAsync(call.Db, username);
        }

        /// <summary>
        /// Whether the caller may change the account itself. The operator may change any; an
        /// administrator of a tenant only those its tenant made — see <see cref="ArkUser.home_tenant_id"/>.
        /// </summary>
        public static bool MayManage(ArkMcpCall call, ArkUser u) =>
            call.Caller.Operator || (call.Caller.TenantAdmin && call.Endpoint.Tenant != null && Same(u.home_tenant_id, call.Endpoint.Tenant.tenant_id));

        /// <summary>Whether the caller may know the account exists: it is its tenant's, or has access there.</summary>
        public static async Task<bool> MaySeeAsync(ArkMcpCall call, ArkUser u)
        {
            if (call.Caller.Operator) return true;
            if (call.Endpoint.Tenant == null) return false;
            var tenant = call.Endpoint.Tenant.tenant_id;
            if (call.Endpoint.Level == ArkMcpLevel.Client && !call.Caller.TenantAdmin)
                return await ArkLookup.MappingAsync(call.Db, u.email, tenant, call.Client.id) != null;
            return await BelongsAsync(call, u);
        }

        /// <summary>Whether the account is one of the endpoint's tenant: made there, or with access to something there.</summary>
        static async Task<bool> BelongsAsync(ArkMcpCall call, ArkUser u)
        {
            var tenant = call.Tenant.tenant_id;
            return Same(u.home_tenant_id, tenant)
                || await call.Db.user_client_claims.AsNoTracking().AnyAsync(m => m.email == u.email && m.tenant_id == tenant);
        }

        /// <summary>An account the caller may see. One it may not is answered as one that does not exist.</summary>
        public static async Task<ArkUser> VisibleUserAsync(ArkMcpCall call, string username)
        {
            var user = await FindUserAsync(call, username);
            if (user == null || !await MaySeeAsync(call, user))
                throw new ArkMcpToolException("unknown_user", $"there is no account '{username}' here.");
            return user;
        }

        public static async Task<ArkUser> ManageableUserAsync(ArkMcpCall call, string username)
        {
            var user = await VisibleUserAsync(call, username);
            if (!MayManage(call, user))
                throw new ArkMcpToolException("not_your_account",
                    $"'{user.email}' is managed by {(user.home_tenant_id is { } home ? $"tenant '{home}'" : "the operator")}. " +
                    "From here their access can be granted or revoked, but the account itself cannot be changed.");
            return user;
        }

        // ---------------------------------------------------------------- applications

        static readonly Regex PlainId = new("^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$", RegexOptions.CultureInvariant);

        public static readonly string[] Kinds = { "web", "spa", "native", "device", "service", "agent", "mcp_server", "mcp_client" };

        public const string KindHelp =
            "web: server-side application, with a secret. spa: browser only. native: desktop or mobile. device: TV or command line (device sign-in). " +
            "service: a backend that calls APIs as itself. agent: software that calls other applications, as itself or for a person (A2A). " +
            "mcp_server: an MCP server protected by this issuer; its client_id is its own URL. mcp_client: an MCP client that signs people in, such as an editor or assistant.";

        /// <summary>A registration with the settings its kind needs, so nobody has to know which those are.</summary>
        public static ArkClient Preset(string kind, string tenantId, string clientId, string name)
        {
            var c = new ArkClient
            {
                tenant_id = tenantId, client_id = clientId, client_name = name, name = name, display = name,
                is_active = true, expire_mins = 480, require_pkce = true, refresh_token_rotation = true, at = Now,
                response_types = new List<string> { "code" },
                scopes = new List<string> { "openid", "profile", "email", "offline_access" },
                grant_types = new List<string> { "authorization_code", "refresh_token" },
                application_type = "web", token_endpoint_auth_method = "none",
                redirect_url = "", logout_url = ""
            };
            switch (kind)
            {
                case "web":
                    // What the .NET handler and the Ark client packages send.
                    c.token_endpoint_auth_method = "client_secret_post";
                    break;
                case "spa": c.application_type = "spa"; break;
                case "native": c.application_type = "native"; break;
                case "mcp_client":
                    c.application_type = "native";
                    c.scopes = new List<string> { "openid", "profile", "offline_access", ArkMcpScopes.Read };
                    break;
                case "device":
                    c.application_type = "native";
                    c.grant_types = new List<string> { DeviceGrant, "refresh_token" };
                    break;
                case "service":
                case "agent":
                case "mcp_server":
                    c.application_type = "service";
                    c.token_endpoint_auth_method = "client_secret_post";
                    c.require_pkce = false;
                    c.response_types = new List<string>();
                    c.scopes = new List<string> { "profile" };
                    c.grant_types = new List<string> { "client_credentials" };
                    if (kind != "service")
                    {
                        c.is_agent = true;
                        c.grant_types = new List<string> { "client_credentials", ArkAgentTokens.TokenExchangeGrant };
                    }
                    if (kind == "agent") c.scopes = new List<string> { "profile", ArkMcpScopes.Read };
                    break;
            }
            return c;
        }

        public static ArkMcpParams ClientFields(ArkMcpParams p, bool creating) => p
            .List("redirect_uris", "Where sign-in may return to. Matched byte for byte, so give them exactly.")
            .List("post_logout_redirect_uris", "Where sign-out may return to. Also matched byte for byte.")
            .List("scopes", "The scopes it may request: a whitelist. offline_access is what gives it a refresh token. client.register and mcp.manage are authority over this server.")
            .List("grant_types", "Grants, when the kind's own are not the right ones.",
                values: new[] { "authorization_code", "refresh_token", "client_credentials", DeviceGrant, ArkAgentTokens.TokenExchangeGrant })
            .Text("token_endpoint_auth_method", "How it authenticates at the token endpoint.", values: new[] { "client_secret_basic", "client_secret_post", "private_key_jwt", "none" })
            .Text("jwks_uri", "For private_key_jwt: where its public keys are published (https).")
            .Text("backchannel_logout_uri", "Where to tell it that a session has ended (https).")
            .Text("client_uri", "Its home page.").Text("policy_uri", "Its privacy policy.").Text("tos_uri", "Its terms of service.")
            .Text("logo", "Its logo: an http(s) image URL.")
            .Flag("require_consent", "Always ask people for consent.").Flag("require_par", "Refuse authorization requests that were not pushed.")
            .Int("access_token_seconds", "Lifetime of its access tokens.", min: 60, max: 86400)
            .Int("refresh_token_seconds", "Lifetime of its refresh tokens.", min: 300, max: 31536000);

        /// <summary>Applies whichever of <see cref="ClientFields"/> were given, with the checks dynamic registration makes.</summary>
        public static async Task ApplyAsync(ArkMcpCall call, ArkClient c, ArkMcpArgs a)
        {
            List<string> Uris(string name)
            {
                var list = a.List(name)!;
                foreach (var uri in list.Where(u => !RedirectUriValidator.IsAcceptableRedirect(u)))
                    throw new ArkMcpToolException("invalid_uri",
                        $"'{uri}' is not an acceptable redirect URI: absolute, no fragment, https (http only for localhost) or a custom app scheme.");
                return list;
            }
            string? Web(string name, bool https = false)
            {
                var value = a.Text(name);
                if (value != null && !(RedirectUriValidator.IsWebUrl(value) && (!https || RedirectUriValidator.IsAcceptableRedirect(value))))
                    throw new ArkMcpToolException("invalid_uri", $"{name} must be {(https ? "an https URL (http only for localhost)" : "an http or https URL")}.");
                return value;
            }

            if (a.Has("redirect_uris")) c.redirect_uris = Uris("redirect_uris");
            if (a.Has("post_logout_redirect_uris")) c.post_logout_redirect_uris = Uris("post_logout_redirect_uris");
            if (a.Has("scopes")) c.scopes = await KnownScopesAsync(call, a.List("scopes")!);
            if (a.Has("grant_types")) c.grant_types = a.List("grant_types")!;
            if (a.Text("token_endpoint_auth_method") is { } method) c.token_endpoint_auth_method = method;
            if (a.Has("jwks_uri")) c.jwks_uri = Web("jwks_uri", https: true);
            if (a.Has("backchannel_logout_uri")) c.backchannel_logout_uri = Web("backchannel_logout_uri", https: true);
            if (a.Has("client_uri")) c.client_uri = Web("client_uri");
            if (a.Has("policy_uri")) c.policy_uri = Web("policy_uri");
            if (a.Has("tos_uri")) c.tos_uri = Web("tos_uri");
            if (a.Has("logo")) c.client_logo = Web("logo");
            if (a.Flag("require_consent") is { } consent) c.require_consent = consent;
            if (a.Flag("require_par") is { } par) c.require_par = par;
            if (a.Int("access_token_seconds") is { } at) c.access_token_lifetime_seconds = at;
            if (a.Int("refresh_token_seconds") is { } rt) c.refresh_token_lifetime_seconds = rt;

            if (c.EffectiveGrantTypes.Contains("authorization_code", StringComparer.OrdinalIgnoreCase) && c.redirect_uris.Count == 0 && c.EffectiveRedirectUris.Count == 0)
                throw new ArkMcpToolException("redirect_uris_required",
                    "an application people sign in to through a browser needs at least one redirect URI: the exact address its sign-in callback is at, for example https://app.example.com/signin-oidc.");
            if (c.token_endpoint_auth_method == "private_key_jwt" && string.IsNullOrEmpty(c.jwks_uri))
                throw new ArkMcpToolException("jwks_uri_required", "private_key_jwt needs jwks_uri.");
            if (c.token_endpoint_auth_method == "none" && c.grant_types.Contains("client_credentials"))
                throw new ArkMcpToolException("secret_required", "client_credentials needs a client that can authenticate: choose client_secret_post, client_secret_basic or private_key_jwt.");

            // The single-valued columns the v1 endpoints read, kept in step.
            c.redirect_url = c.redirect_uris.FirstOrDefault() ?? c.redirect_url ?? "";
            c.logout_url = c.post_logout_redirect_uris.FirstOrDefault() ?? c.logout_url ?? "";
        }

        static async Task<List<string>> KnownScopesAsync(ArkMcpCall call, List<string> scopes)
        {
            var known = new HashSet<string>((await ArkIdpCache.ScopesAsync(call.Db)).Select(s => s.name), StringComparer.OrdinalIgnoreCase);
            var unknown = scopes.Where(s => !known.Contains(s)).ToList();
            if (unknown.Count > 0)
                throw new ArkMcpToolException("unknown_scope", $"this server has no scope {string.Join(", ", unknown)}. scope_list shows the ones it has; permissions of an application are claims, not scopes.");
            return scopes;
        }

        public static string NameOf(string value)
        {
            if (value.Length > 120 || value.Any(ch => char.IsControl(ch) || ch is '<' or '>'))
                throw new ArkMcpToolException("invalid_name", "a name has at most 120 characters, with no '<', '>' or control characters.");
            return value;
        }

        public static async Task<(ArkClient Client, string? Secret)> CreateClientAsync(ArkMcpCall call, ArkMcpArgs a)
        {
            var kind = a.Required("kind");
            var name = NameOf(a.Required("name"));
            var clientId = a.Text("client_id");
            if (kind == "mcp_server")
            {
                if (clientId == null || !RedirectUriValidator.IsWebUrl(clientId) || !RedirectUriValidator.IsAcceptableRedirect(clientId))
                    throw new ArkMcpToolException("invalid_client_id", "an MCP server is registered under its own address: give client_id as the https URL its clients connect to.");
            }
            else
            {
                clientId ??= ArkProvisioning.Slug(name);
                if (!PlainId.IsMatch(clientId))
                    throw new ArkMcpToolException("invalid_client_id", "client_id: 2 to 64 letters, digits, dot, dash or underscore, starting with a letter or digit.");
            }
            call.Touches("client", clientId);

            var tenant = call.Tenant.tenant_id;
            if (Same(clientId, ArkManagementAuth.MachineClientId(tenant)) || Same(clientId, $"{tenant}_client"))
                throw new ArkMcpToolException("reserved_client_id", $"'{clientId}' is reserved for the server. Choose another.");
            if (await ArkLookup.ClientAsync(call.Db, tenant, clientId) is { } taken)
                throw new ArkMcpToolException("client_exists", $"'{clientId}' is already registered as '{taken.client_name ?? taken.display}'. Change it with client_update, or choose another client_id.");
            // A client's own tokens carry its id as the subject: one named like an account would
            // read as that person wherever the subject is what is checked.
            if (await ArkLookup.UserAsync(call.Db, clientId) != null)
                throw new ArkMcpToolException("client_exists", $"'{clientId}' cannot be used. Choose another client_id.");

            var client = Preset(kind, tenant, clientId, name);
            await ApplyAsync(call, client, a);

            string? secret = null;
            if (client.token_endpoint_auth_method is "client_secret_basic" or "client_secret_post")
            {
                secret = ArkCrypto.RandomToken(32);
                client.client_secret_hash = ArkCrypto.HashSecret(secret);
            }
            var saved = await call.Da.UpsertClient(client);
            call.Da.Log("client_upsert", saved.client_id, "Client updated success", $"created over mcp : ci: {saved.client_id}, name: {name}, kind: {kind}");
            Webhooks.ArkWebhookEvents.Raise(call.Http, tenant, Webhooks.ArkWebhookEvents.ClientUpdated,
                new { client_id = saved.client_id, name, display = name, is_active = true, created = true }, saved.client_id);
            return (saved, secret);
        }

        /// <summary>
        /// Saves a changed registration. The server's own clients are left to the operator, and
        /// keep what they stand on: the console's sign-in and the machine client's grant.
        /// </summary>
        public static async Task<ArkClient> SaveClientAsync(ArkMcpCall call, ArkClient client)
        {
            var saved = await call.Da.UpsertClient(client);
            call.Da.Log("client_upsert", saved.client_id, "Client updated success", $"changed over mcp : ci: {saved.client_id}, ti: {saved.tenant_id}");
            Webhooks.ArkWebhookEvents.Raise(call.Http, saved.tenant_id, Webhooks.ArkWebhookEvents.ClientUpdated,
                new { client_id = saved.client_id, name = saved.name, display = saved.display, is_active = saved.is_active }, saved.client_id);
            return saved;
        }

        public static void NotSystem(ArkClient client, string what)
        {
            if (IsSystem(client))
                throw new ArkMcpToolException("system_client", $"'{client.client_id}' is one of the server's own clients and cannot be {what} here.");
        }

        public static async Task<string> ResetSecretAsync(ArkMcpCall call, ArkClient client)
        {
            if (client.token_endpoint_auth_method is not ("client_secret_basic" or "client_secret_post"))
                throw new ArkMcpToolException("no_secret", $"'{client.client_id}' authenticates with {client.token_endpoint_auth_method}; it has no secret to reset.");
            if (call.Config.Management?.ConfiguredMachineClientSecret != null
                && Same(client.tenant_id, call.Endpoint.OperatorTenantId)
                && Same(client.client_id, ArkManagementAuth.MachineClientId(call.Endpoint.OperatorTenantId)))
                throw new ArkMcpToolException("secret_configured",
                    "this client's secret is set by ark_oauth_server:Management:MachineClientSecret, and the next restart would replace one generated here. Rotate it by changing that setting.");

            var secret = ArkCrypto.RandomToken(32);
            client.client_secret_hash = ArkCrypto.HashSecret(secret);
            client.client_secret_expires_at = null;
            await call.Da.UpsertClient(client);
            call.Da.Log("client_secret_reset", client.client_id, "Client secret reset success", $"over mcp : ci: {client.client_id}, ti: {client.tenant_id}");
            Webhooks.ArkWebhookEvents.Raise(call.Http, client.tenant_id, Webhooks.ArkWebhookEvents.ClientSecretReset,
                new { client_id = client.client_id }, client.client_id);
            return secret;
        }

        public static async Task SetActiveAsync(ArkMcpCall call, ArkClient client, bool active, string? reason)
        {
            await call.Da.SetClientActive(client.tenant_id, client.client_id, active);
            call.Da.Log("client_activation", client.client_id, active ? "client activated" : "client deactivated",
                $"details : ci: {client.client_id}, ti: {client.tenant_id}, reason: {reason}");
            Webhooks.ArkWebhookEvents.Raise(call.Http, client.tenant_id, Webhooks.ArkWebhookEvents.ClientActivationChanged,
                new { client_id = client.client_id, is_active = active, reason }, client.client_id);
        }

        public static async Task DeleteClientAsync(ArkMcpCall call, ArkClient client)
        {
            // Off first: that is what withdraws the refresh tokens it has been issued.
            if (client.is_active) await call.Da.SetClientActive(client.tenant_id, client.client_id, false);
            call.Db.ChangeTracker.Clear();
            await call.Da.DeleteClient(client);
            call.Da.Log("client_delete", client.client_id, "Client deleted success", $"over mcp : ci: {client.client_id}, ti: {client.tenant_id}");
            Webhooks.ArkWebhookEvents.Raise(call.Http, client.tenant_id, Webhooks.ArkWebhookEvents.ClientDeleted,
                new { client_id = client.client_id, method = "mcp" }, client.client_id);
        }

        /// <summary>How to wire an application up, with this server's actual values.</summary>
        public static object Integration(ArkMcpCall call, ArkClient c)
        {
            var ep = call.Endpoint.OidcFor(c.tenant_id);
            var secret = c.IsPublicClient ? null : "<client secret>";
            var scopes = string.Join(" ", c.EffectiveScopes);
            var interactive = c.EffectiveGrantTypes.Contains("authorization_code", StringComparer.OrdinalIgnoreCase);
            return new
            {
                authority = ep.Issuer, client_id = c.client_id, needs_secret = secret != null, scopes = c.EffectiveScopes,
                redirect_uris = c.EffectiveRedirectUris, post_logout_redirect_uris = c.EffectivePostLogoutRedirectUris,
                endpoints = new
                {
                    discovery = ep.Discovery, authorization = interactive ? ep.Authorization : null, token = ep.Token, jwks = ep.Jwks,
                    userinfo = ep.UserInfo, end_session = ep.EndSession, device_authorization = c.EffectiveGrantTypes.Contains(DeviceGrant) ? ep.DeviceAuthorization : null
                },
                setup_page = $"{ep.Issuer}/oauth2/integrate/{Uri.EscapeDataString(c.client_id)}",
                dotnet = interactive ? new
                {
                    package = "Ark.oAuth.Client",
                    code = "builder.Services.AddArkOidcClient(builder.Configuration);\napp.UseRouting(); app.UseAuthentication(); app.UseAuthorization();",
                    settings = new { ark_oauth_client = new { Authority = ep.Issuer, ClientId = c.client_id, ClientSecret = secret, Scopes = c.EffectiveScopes } }
                } : null,
                python = new
                {
                    package = interactive ? "ark-oauth-client[flask]" : "ark-oauth-client",
                    code = interactive
                        ? $"from ark_oauth_client.flask import add_ark_oidc_client\nauth = add_ark_oidc_client(app, {{\"authority\": \"{ep.Issuer}\", \"client_id\": \"{c.client_id}\"}})"
                        : $"from ark_oauth_client import ArkOAuthClient\nark = ArkOAuthClient(authority=\"{ep.Issuer}\", client_id=\"{c.client_id}\", client_secret=SECRET)"
                },
                node = new
                {
                    package = "ark-oauth-client-node",
                    code = interactive
                        ? $"import {{ arkExpress }} from 'ark-oauth-client-node';\napp.use(arkExpress({{ authority: '{ep.Issuer}', clientId: '{c.client_id}', redirectUri, secret }}));"
                        : $"import {{ ArkOAuthClient }} from 'ark-oauth-client-node';\nconst ark = new ArkOAuthClient({{ authority: '{ep.Issuer}', clientId: '{c.client_id}', clientSecret }});"
                },
                token_request = c.EffectiveGrantTypes.Contains("client_credentials", StringComparer.OrdinalIgnoreCase)
                    ? $"curl -X POST {ep.Token} -d grant_type=client_credentials -d client_id={Uri.EscapeDataString(c.client_id)} -d client_secret=$CLIENT_SECRET" : null,
                scope_parameter = scopes,
                remember = new[]
                {
                    "Redirect URIs are matched byte for byte, the sign-out one too.",
                    "A person needs access granted to this application, or sign-in fails with what reads like a wrong password (access_grant).",
                    "Permissions arrive as ark_claims in the access token, not as scopes."
                }
            };
        }

        // ---------------------------------------------------------------- accounts

        public static readonly string[] Credentials = { "activation_link", "email", "default_password", "password" };

        public const string CredentialHelp =
            "How the new account gets its password. activation_link (default): a one-time link, returned here to hand over, with which the person sets it. " +
            "email: the server emails that link. default_password: the server's common initial password. password: the one given in password.";

        /// <summary>
        /// Creates an account, owned by the endpoint's tenant unless the operator makes it.
        /// Returns the one-time link when that is how the password is to be set.
        /// </summary>
        public static async Task<(ArkUser User, string Credential, string? Link)> CreateUserAsync(
            ArkMcpCall call, string username, string? name, string? credential, string? password, string? homeTenant)
        {
            var login = username.ToLowerInvariant().Trim();
            call.Touches("user", login);
            credential ??= "activation_link";
            // An account is good at every application of the tenant it is later given access to, so one
            // application does not choose the password of somebody it adds.
            if (call.Endpoint.Level == ArkMcpLevel.Client && !call.Caller.TenantAdmin && credential is "password" or "default_password")
                throw new ArkMcpToolException("link_only",
                    "an application adds people with activation_link or email, so that each sets their own password. An administrator of the tenant may choose one.");
            if (!DataAccess.IsValidLoginId(login))
                throw new ArkMcpToolException("invalid_username", "use an email address, or 2-64 characters of letters, digits, dot, dash or underscore.");
            if (await FindUserAsync(call, login) is { } existing)
                throw await MaySeeAsync(call, existing)
                    ? new ArkMcpToolException("user_exists", $"'{login}' already has an account. Give it access with access_grant.", UserView(call, existing))
                    : new ArkMcpToolException("username_taken",
                        $"'{login}' cannot be created here. If it is a person who signs in elsewhere on this server, an operator grants them access.");
            if (await call.Db.clients.AsNoTracking().AnyAsync(c => c.client_id == login))
                throw new ArkMcpToolException("username_taken", $"'{login}' cannot be used as a username. Choose another.");

            var util = call.Get<ArkUtil>();
            var user = new ArkUser
            {
                email = login, name = string.IsNullOrWhiteSpace(name) ? login : NameOf(name!), type = "user", is_active = true,
                home_tenant_id = homeTenant, at = Now, ref_uid = Guid.NewGuid().ToString(), emailed = false, reset_mode = false
            };
            string? link = null;
            switch (credential)
            {
                case "password":
                    if ((password ?? "").Length < 10) throw new ArkMcpToolException("weak_password", "a password needs at least 10 characters.");
                    user.hash_pw = util.HashPasswordPBKDF2(password!);
                    break;
                case "default_password":
                    user.hash_pw = util.HashPasswordPBKDF2(call.Config.RequireDefaultPw());
                    break;
                case "email":
                    if (string.IsNullOrWhiteSpace(call.Config.EmailConfig?.smtp))
                        throw new ArkMcpToolException("email_off", "this server does not send email. Use activation_link and hand the link over yourself.");
                    if (!ark.net.util.EmailUtil.IsValidFormat(login))
                        throw new ArkMcpToolException("invalid_username", "a link can only be emailed to an email address.");
                    user.hash_pw = util.HashPasswordPBKDF2(ArkCrypto.RandomToken(32));
                    user.reset_mode = true;
                    break;
                default:
                    user.hash_pw = util.HashPasswordPBKDF2(ArkCrypto.RandomToken(32));
                    user.reset_mode = true;
                    break;
            }

            call.Db.ChangeTracker.Clear();
            call.Db.users.Add(user);
            await call.Db.SaveChangesAsync();
            if (credential == "activation_link")
            {
                link = await call.Da.IssuePasswordLinkAsync(login, LinkTenant(call));
            }
            else if (credential == "email")
            {
                try
                {
                    var html = await util.GetActivationEmail(LinkTenant(call), user.ref_uid!);
                    var sent = await util.SendMail(login, html, $"{call.Config.EmailConfig?.subject} Activation Link", call.Da);
                    await call.Db.users.Where(u => u.email == login).ExecuteUpdateAsync(s => s.SetProperty(u => u.emailed, (bool?)sent));
                    if (!sent) credential = "email_not_sent";
                }
                catch (Exception ex) when (ex is IOException or NullReferenceException or FormatException)
                {
                    call.Da.LogError(ex, "user_activation_email", login, "activation email could not be built or sent; account still created");
                    credential = "email_not_sent";
                }
                call.Db.ChangeTracker.Clear();
            }

            call.Da.Log("user_upsert", "mcp", "user created", $"created over mcp : e: {login}, home: {homeTenant}", "trace",
                ArkWatchMap.Admin("user.create", AuditLevel.Notice, "user", login, $"account '{login}' created", homeTenant).With("credential", credential));
            Webhooks.ArkWebhookEvents.Raise(call.Http, Webhooks.ArkWebhookEvents.OperatorTenant(call.Http), Webhooks.ArkWebhookEvents.UserUpdated,
                new { user = login, name = user.name, created = true }, login);
            return (user, credential, link);
        }

        /// <summary>The tenant whose name goes in a password link. Any will do; the page reads only the link's secret.</summary>
        static string LinkTenant(ArkMcpCall call) => call.Endpoint.Tenant?.tenant_id ?? call.Endpoint.OperatorTenantId;

        public static async Task<object> ResetPasswordAsync(ArkMcpCall call)
        {
            var user = await ManageableUserAsync(call, call.Args.Required("username"));
            if (string.Equals(user.type, "service", StringComparison.OrdinalIgnoreCase))
                throw new ArkMcpToolException("service_account", "a service account has no password.");
            var how = call.Args.Text("credential") ?? "activation_link";
            string? link = null;
            switch (how)
            {
                case "password":
                    var password = call.Args.Text("password") ?? "";
                    if (password.Length < 10) throw new ArkMcpToolException("weak_password", "a password needs at least 10 characters.");
                    // Sessions are ended below, where they are counted and end_sessions is asked.
                    await call.Da.SetUserPassword(user.email, password, endAccess: false);
                    break;
                case "email":
                    var saved = await call.Da.UserResetPw(new ArkUser { email = user.email }, endAccess: false);
                    if (saved.emailed != true) throw new ArkMcpToolException("email_not_sent", "the email could not be sent; the reason is in the audit trail. Use activation_link instead.");
                    break;
                default:
                    link = await call.Da.IssuePasswordLinkAsync(user.email, LinkTenant(call));
                    break;
            }
            var ended = call.Args.Flag("end_sessions") == false ? 0 : await EndSessionsAsync(call, user.email, null, "password_reset");
            call.Da.Log("user_password_set", "mcp", "user password reset", $"over mcp : e: {user.email}, how: {how}", "trace",
                ArkWatchMap.Admin("user.password_set", AuditLevel.Security, "user", user.email, $"an administrator reset the password of '{user.email}'").With("method", how));
            Webhooks.ArkWebhookEvents.Raise(call.Http, Webhooks.ArkWebhookEvents.OperatorTenant(call.Http), Webhooks.ArkWebhookEvents.UserPasswordChanged,
                new { user = user.email, by = "administrator" }, user.email);
            return new
            {
                username = user.email, how, password_link = link, sessions_ended = ended,
                note = link == null ? null : $"Hand this link to them over a private channel. It works once, for {call.Config.PasswordLinkLifetimeHours} hours; until it is used they cannot sign in."
            };
        }

        /// <summary>Ends somebody's sessions, everywhere or in one tenant, and tells the applications they had open.</summary>
        public static async Task<int> EndSessionsAsync(ArkMcpCall call, string username, string? tenantId, string reason)
        {
            var now = DateTime.UtcNow;
            var ids = await call.Db.sessions.AsNoTracking()
                .Where(s => s.subject == username && !s.revoked && s.expires_at > now && (tenantId == null || s.tenant_id == tenantId))
                .Select(s => s.session_id).ToListAsync();
            return await EndSessionsAsync(call, ids, reason);
        }

        public static async Task<int> EndSessionsAsync(ArkMcpCall call, IEnumerable<string> sessionIds, string reason)
        {
            call.Db.ChangeTracker.Clear();
            var ended = await call.Get<ArkGrantStore>().RevokeSessionsAsync(sessionIds);
            if (ended.Count > 0)
                await call.Get<ArkBackChannelLogout>().NotifyAsync(ended, tid => call.Endpoint.OidcFor(tid).Issuer, reason);
            return ended.Count;
        }

        // ---------------------------------------------------------------- access

        /// <summary>
        /// Claims a caller may put on an access mapping. The <c>ark.</c> names make administrators and
        /// <c>service_role</c> registers applications in the tenant, so each may be handed out only by
        /// somebody at that level or above.
        /// </summary>
        public static void CheckClaims(ArkMcpCall call, IEnumerable<string> claims)
        {
            foreach (var claim in claims)
            {
                if (claim.Length > 200 || claim.Any(char.IsControl))
                    throw new ArkMcpToolException("invalid_claim", "a claim has at most 200 characters and no control characters.");
                // Here as well as at the save, so that no account is made for a claim that is refused after it.
                if (ArkText.ClaimKeyProblem(claim) is { } problem) throw new ArkMcpToolException("invalid_claim", problem);
                if (!ArkMcpClaims.IsReserved(claim)) continue;
                var allowed = claim.ToLowerInvariant() switch
                {
                    ArkMcpClaims.HostAdmin => call.Caller.Operator,
                    ArkMcpClaims.TenantAdmin or ArkMcpClaims.ClientAdmin or ArkMcpClaims.ServiceRole => call.Caller.TenantAdmin,
                    _ => call.Caller.Operator
                };
                if (!allowed)
                    throw new ArkMcpToolException("reserved_claim", $"'{claim}' is an administrator's authority, and you may not hand it out from here.");
            }
            // The console reads these two on its own mapping as "is the operator".
            if (!call.Caller.Operator && call.Endpoint.IsOperatorTenant && claims.Any(c => c is "admin" or "ark_admin"))
                throw new ArkMcpToolException("reserved_claim", "in the operator tenant these claims make an operator; only the operator hands them out.");
        }

        public static async Task<List<(ArkClient Client, ArkUserClientClaim Mapping)>> AccessOfAsync(ArkMcpCall call, string username, string? tenantId)
        {
            var rows = await call.Db.user_client_claims.AsNoTracking()
                .Where(m => m.email == username && (tenantId == null || m.tenant_id == tenantId)).ToListAsync();
            var ids = rows.Select(r => r.client_id).ToList();
            var clients = await call.Db.clients.AsNoTracking().Where(c => ids.Contains(c.id)).ToListAsync();
            return rows.Select(r => (clients.FirstOrDefault(c => c.id == r.client_id)!, r)).Where(x => x.Item1 != null).ToList();
        }

        /// <summary>Who can set the password of an account: a tenant, or the operator.</summary>
        public static string ManagedBy(ArkUser user) => string.IsNullOrWhiteSpace(user.home_tenant_id) ? "operator" : user.home_tenant_id!;

        /// <summary>
        /// Access is given to a person, and held by whoever can sign in as them. A username exists once
        /// per server and the first to ask for it gets it, so an administrator of one tenant could make
        /// the account of somebody expected at another, know its password, and receive whatever that
        /// tenant, or the operator, later gave the name. So an account another tenant manages is never
        /// made an administrator, is given anything else only by somebody who has been told whose it is,
        /// and one that was there already (not <paramref name="made"/> by this very call) becomes an
        /// administrator only on a second, explicit word.
        /// </summary>
        static void CheckOwner(ArkMcpCall call, ArkUser user, ArkClient client, ArkUserClientClaim? existing, IReadOnlyCollection<string> claims, bool made, string? confirm)
        {
            var atOperator = Same(client.tenant_id, call.Endpoint.OperatorTenantId);
            var home = Same(user.home_tenant_id, call.Endpoint.OperatorTenantId) ? null : Blank(user.home_tenant_id);
            var elsewhere = home != null && !Same(home, client.tenant_id);
            // What is new to them: repeating what they hold hands out nothing.
            var authority = claims.Where(c => ArkMcpClaims.IsReserved(c) || (atOperator && c is "admin" or "ark_admin"))
                .Where(c => existing?.claims.Contains(c, StringComparer.OrdinalIgnoreCase) != true).ToList();

            if (home != null && authority.FirstOrDefault(c => elsewhere || c.Equals(ArkMcpClaims.HostAdmin, StringComparison.OrdinalIgnoreCase)) is { } refused)
                throw new ArkMcpToolException("not_your_account",
                    $"'{refused}' is not given to '{user.email}': the account is managed by tenant '{home}', whose administrators can set its password and would hold it too. " +
                    "The operator can take the account over with user_set_home.", new { username = user.email, managed_by = home });

            void Confirm(string expected, string why)
            {
                if (!string.Equals(confirm, expected, StringComparison.OrdinalIgnoreCase))
                    throw new ArkMcpToolException("confirmation_required", $"{why} To go ahead, call again with confirm set to \"{expected}\".",
                        new { confirm = expected, managed_by = ManagedBy(user) });
            }
            if (elsewhere)
                Confirm(home!, $"'{user.email}' is managed by tenant '{home}': whoever administers that tenant can set its password, and so can use any access given here.");
            else if (authority.Count > 0 && !made)
                Confirm(user.email, $"'{user.email}' already has an account, and whoever knows its password becomes an administrator here. " +
                                    "Make sure it is the person's own; when in doubt, reset it first with user_reset_password.");
        }

        /// <summary>Gives somebody access to an application, or changes what they may do there.</summary>
        public static async Task<(bool Created, List<string> Claims)> GrantAsync(ArkMcpCall call, ArkUser user, ArkClient client, List<string> claims, bool replace,
            bool made = false, string? confirm = null)
        {
            CheckClaims(call, claims);
            var existing = await ArkLookup.MappingAsync(call.Db, user.email, client.tenant_id, client.id);
            CheckOwner(call, user, client, existing, claims, made, confirm);
            var kept = replace ? Enumerable.Empty<string>() : existing?.claims ?? new List<string>();
            // Administrator claims the caller could not have given stay as they are when the rest
            // is replaced: taking one away is as much a decision as giving it.
            if (replace)
                kept = (existing?.claims ?? new List<string>()).Where(c => ArkMcpClaims.IsReserved(c) && !call.Caller.TenantAdmin);
            var merged = ArkProvisioning.DefaultClaims.Concat(kept).Concat(claims)
                .Where(c => !string.IsNullOrWhiteSpace(c)).Select(c => c.Trim()).Distinct(StringComparer.Ordinal).ToList();

            foreach (var key in merged)
                if (await call.Da.GetClaim(key) == null)
                    await call.Da.UpsertClaim(new ArkClaim { key = key, display = key });
            call.Db.ChangeTracker.Clear();
            await call.Da.UpsertUsersClientClaims(new ArkUserClientClaim
            {
                id = existing?.id!, email = user.email, tenant_id = client.tenant_id, client_id = client.id, claims = merged
            });
            call.Da.Log("user_cl_cl_upsert", "mcp", "user client claims updated", $"over mcp : e: {user.email}, ci: {client.client_id}", "trace",
                ArkWatchMap.Admin("access.grant", AuditLevel.Security, "user", user.email, $"access of '{user.email}' to '{client.client_id}' granted or changed", client.tenant_id)
                    .With("client_ref", client.client_id).With("claims", merged));
            Webhooks.ArkWebhookEvents.Raise(call.Http, client.tenant_id, Webhooks.ArkWebhookEvents.UserAccessChanged,
                new { user = user.email, client_id = client.client_id, change = "granted", claims = merged }, user.email);
            return (existing == null, merged);
        }

        /// <summary>Takes access away, and the refresh tokens that were issued under it.</summary>
        public static async Task RevokeAsync(ArkMcpCall call, string username, ArkClient client)
        {
            var mapping = await ArkLookup.MappingAsync(call.Db, username, client.tenant_id, client.id)
                ?? throw new ArkMcpToolException("no_access", $"'{username}' has no access to '{client.client_id}'.");
            if (mapping.claims.Any(ArkMcpClaims.IsReserved) && !call.Caller.TenantAdmin)
                throw new ArkMcpToolException("reserved_claim", $"'{username}' is an administrator here; an administrator of the tenant takes that away.");
            if (IsSystem(client) && !call.Caller.Operator)
                throw new ArkMcpToolException("system_client", "access to the server's own clients is the operator's to change.");
            call.Db.ChangeTracker.Clear();
            await call.Da.DeleteUsersClientClaims(mapping);
            call.Db.ChangeTracker.Clear();
            await RevokeRefreshAsync(call, mapping.email, client);
            call.Da.Log("user_cl_cl_delete", "mcp", "delete client claims updated", $"over mcp : e: {username}, ci: {client.client_id}", "trace",
                ArkWatchMap.Admin("access.revoke", AuditLevel.Security, "user", username, $"access of '{username}' to '{client.client_id}' removed", client.tenant_id)
                    .With("client_ref", client.client_id));
            Webhooks.ArkWebhookEvents.Raise(call.Http, client.tenant_id, Webhooks.ArkWebhookEvents.UserAccessChanged,
                new { user = username, client_id = client.client_id, change = "removed" }, username);
        }

        public static Task<int> RevokeRefreshAsync(ArkMcpCall call, string username, ArkClient client) =>
            call.Db.refresh_tokens.Where(t => t.subject == username && t.client_id == client.client_id && t.tenant_id == client.tenant_id && !t.revoked)
                .ExecuteUpdateAsync(s => s.SetProperty(t => t.revoked, true));

        /// <summary>
        /// The person a grant is for. Created when missing and <paramref name="create"/> says how;
        /// a person of another tenant is granted access only by name and never learned about.
        /// </summary>
        public static async Task<(ArkUser User, bool Created, string? Credential, string? Link)> PersonAsync(
            ArkMcpCall call, string username, string? name, string? credential, string? password, bool create)
        {
            var user = await FindUserAsync(call, username);
            if (user != null)
            {
                // An application adds people of its tenant, whom its administrators know by name.
                // Anybody else on the server is not theirs to find.
                if (call.Endpoint.Level == ArkMcpLevel.Client && !call.Caller.TenantAdmin && !await BelongsAsync(call, user))
                    throw new ArkMcpToolException("unknown_user", $"'{username}' cannot be given access from here. An administrator of the tenant can.");
                return (user, false, null, null);
            }
            if (!create)
                throw new ArkMcpToolException("unknown_user", $"there is no account '{username}'. Create it with user_create, or use onboard_user, which does both.");
            // An account the operator makes for a tenant belongs to that tenant's administrators;
            // one made in the operator tenant belongs to the server.
            var home = call.Endpoint.Tenant == null || call.Endpoint.IsOperatorTenant ? null : call.Endpoint.Tenant.tenant_id;
            var made = await CreateUserAsync(call, username, name, credential, password, home);
            return (made.User, true, made.Credential, made.Link);
        }

        // ---------------------------------------------------------------- diagnosis

        /// <summary>Why somebody cannot sign in to an application: every condition, in the order sign-in checks them.</summary>
        public static async Task<object> DiagnoseAsync(ArkMcpCall call, string username, ArkClient? client)
        {
            var checks = new List<object>();
            var failed = 0;
            void Check(string what, bool ok, string detail, object? fix = null)
            {
                if (!ok) failed++;
                checks.Add(new { check = what, ok, detail, fix = ok ? null : fix });
            }

            var user = await FindUserAsync(call, username);
            if (user != null && !await MaySeeAsync(call, user)) user = null;
            if (client != null)
            {
                Check("application is active", client.is_active, client.is_active ? "yes" : "it has been deactivated, so sign-in is refused before the form is drawn",
                    new { tool = "client_set_active", arguments = new { client_id = client.client_id, active = true } });
                var interactive = client.EffectiveGrantTypes.Contains("authorization_code", StringComparer.OrdinalIgnoreCase)
                    || client.EffectiveGrantTypes.Contains(DeviceGrant, StringComparer.OrdinalIgnoreCase);
                Check("application takes sign-ins", interactive, interactive ? "yes" : "it has no grant a person can sign in with");
                if (client.EffectiveGrantTypes.Contains("authorization_code", StringComparer.OrdinalIgnoreCase))
                    Check("a redirect URI is registered", client.EffectiveRedirectUris.Count > 0,
                        client.EffectiveRedirectUris.Count > 0 ? string.Join(", ", client.EffectiveRedirectUris) : "none, so every sign-in is refused",
                        new { tool = "client_update", arguments = new { client_id = client.client_id, redirect_uris = new[] { "<exact callback address>" } } });
            }
            Check("account exists", user != null, user != null ? $"'{user.email}'" : $"there is no account '{username}' here; sign-in reports it like a wrong password",
                new { tool = "onboard_user", arguments = new { username, client_id = client?.client_id } });
            if (user != null)
            {
                Check("account is active", user.is_active, user.is_active ? "yes" : "it has been deactivated",
                    new { tool = "user_set_active", arguments = new { username = user.email, active = true } });
                Check("password is set", user.reset_mode != true, user.reset_mode != true ? "yes" : "it is waiting for its password to be set through a one-time link",
                    new { tool = "user_reset_password", arguments = new { username = user.email } });
                var status = await call.Da.GetAuthStatus(user.email);
                var oidc = call.Config.Oidc ?? new ArkOidcOptions();
                var locked = status != null && oidc.MaxFailedSignIns > 0 && status.retry_count >= oidc.MaxFailedSignIns
                    && (DateTime.UtcNow - status.at).TotalMinutes < oidc.LockoutMinutes;
                Check("account is not locked", !locked, locked ? $"locked after {status!.retry_count} failed attempts, for {oidc.LockoutMinutes} minutes" : $"{status?.retry_count ?? 0} failed attempts since the last sign-in",
                    new { tool = "user_unlock", arguments = new { username = user.email } });
                if (client != null)
                {
                    var mapping = await ArkLookup.MappingAsync(call.Db, user.email, client.tenant_id, client.id);
                    Check("access is granted", mapping != null,
                        mapping != null ? $"claims: {string.Join(", ", mapping.claims)}" : "there is no access mapping to this application; sign-in reports that exactly like a wrong password",
                        new { tool = "access_grant", arguments = new { username = user.email, client_id = client.client_id } });
                }
            }
            return new
            {
                username, client_id = client?.client_id, can_sign_in = failed == 0, checks,
                note = failed == 0 ? "Nothing here stops a sign-in, so what is left is the password itself, or a redirect URI in the request that differs from the registered one." : null
            };
        }

        // ---------------------------------------------------------------- findings

        public sealed record Finding(string Severity, string Code, string About, string Message, string? Tool = null, object? Arguments = null);

        static int Rank(string severity) => severity switch { "error" => 0, "warning" => 1, _ => 2 };

        public static object FindingView(Finding f) => new { severity = f.Severity, code = f.Code, about = f.About, message = f.Message, fix = f.Tool == null ? null : new { tool = f.Tool, arguments = f.Arguments } };

        public static object NextSteps(IEnumerable<Finding> findings, int max = 8) => findings.Where(f => f.Tool != null)
            .OrderBy(f => Rank(f.Severity)).Take(max).Select((f, i) => new { step = i + 1, why = f.Message, tool = f.Tool, arguments = f.Arguments });

        /// <summary>What is wrong or unfinished about one application.</summary>
        public static IEnumerable<Finding> Inspect(ArkClient c, int people, IReadOnlyCollection<ArkClient> siblings)
        {
            var about = c.client_id;
            bool Grant(string g) => c.EffectiveGrantTypes.Contains(g, StringComparer.OrdinalIgnoreCase);
            var interactive = Grant("authorization_code") || Grant(DeviceGrant);

            if (!c.is_active) yield return new Finding("info", "inactive", about, $"'{about}' is deactivated.", "client_set_active", new { client_id = about, active = true });
            if (Grant("authorization_code") && c.EffectiveRedirectUris.Count == 0)
                yield return new Finding("error", "no_redirect_uri", about, $"'{about}' has no redirect URI, so nobody can sign in to it.", "client_update", new { client_id = about });
            foreach (var uri in c.EffectiveRedirectUris.Where(u => u.StartsWith("http:", StringComparison.OrdinalIgnoreCase)
                && Uri.TryCreate(u, UriKind.Absolute, out var parsed) && !parsed.IsLoopback))
                yield return new Finding("warning", "plain_http_redirect", about, $"'{about}' receives authorization codes over plain http: {uri}.", "client_update", new { client_id = about });
            if (interactive && !IsSystem(c) && people == 0 && c.is_active)
                yield return new Finding("warning", "nobody_has_access", about, $"nobody has been given access to '{about}', so every sign-in fails like a wrong password.", "onboard_user", new { client_id = about });
            if (c.token_endpoint_auth_method is "client_secret_basic" or "client_secret_post" && !c.has_client_secret)
                yield return new Finding(IsSystem(c) ? "info" : "error", "no_secret", about, $"'{about}' authenticates with a secret and has none.", "client_secret_reset", new { client_id = about });
            if (c.client_secret_expires_at is { } ends && ends < DateTime.UtcNow.AddDays(30))
                yield return new Finding(ends < DateTime.UtcNow ? "error" : "warning", "secret_expiring", about,
                    $"the secret of '{about}' {(ends < DateTime.UtcNow ? "expired" : "expires")} on {ends:yyyy-MM-dd}.", "client_secret_reset", new { client_id = about });
            // Only where people sign out through a browser: an editor or an agent has no page to return to.
            if (Grant("authorization_code") && !IsSystem(c) && c.is_active && c.is_agent != true && c.application_type != "native"
                && c.EffectivePostLogoutRedirectUris.Count == 0)
                yield return new Finding("info", "no_sign_out_return", about, $"'{about}' has no post-logout redirect URI, so signing out ends on the identity server's page.", "client_update", new { client_id = about });
            foreach (var caller in c.a2a_callers.Where(a => !siblings.Any(s => Same(s.client_id, a.client_id))))
                yield return new Finding("warning", "unknown_caller", about, $"'{about}' lists '{caller.client_id}' as a caller, and there is no such application.", "agent_caller_remove", new { client_id = about, caller = caller.client_id });
        }

        // ---------------------------------------------------------------- paging and audit

        public static ArkMcpParams Paging(ArkMcpParams p, int max = 200) => p
            .Int("limit", $"How many to return (default 50, at most {max}).", min: 1, max: max)
            .Text("cursor", "next_cursor of the previous answer, for the rest.", maxLength: 500);

        /// <summary>
        /// Lines whose reference is something other than a tenant: a client, an account, a scope, or the
        /// word for where the change was made (<c>mcp</c>, <c>v1/user/upsert</c>). A tenant that happens to
        /// have that name is not who they are about.
        /// </summary>
        static readonly List<string> NotByTenant = new()
        {
            "client_upsert", "client_activation", "client_secret_reset", "client_delete",
            "user_upsert", "user_activation", "user_unlock", "user_password_set", "user_cl_cl_upsert", "user_cl_cl_delete",
            "scope_upsert", "scope_delete", "claim_upsert", "claim_delete",
            "migration", "migration_rollback", "schema_update", "schema_sync", "schema_index", "schema_index_skipped", "schema_baseline",
            "data_import", "data_export"
        };

        public static async Task<object> AuditAsync(ArkMcpCall call)
        {
            var limit = call.Args.Int("limit") ?? 50;
            var hours = call.Args.Int("hours") ?? 24;
            var since = DateTime.UtcNow.AddHours(-hours);
            var query = call.Db.audit_trace.AsNoTracking().Where(a => a.at >= since);
            if (call.Endpoint.Level != ArkMcpLevel.Host)
            {
                // A row belongs to a tenant when it says so first. Faults are the operator's: they
                // carry stack traces, and other tenants' details.
                var tenant = call.Tenant.tenant_id;
                var prefix = tenant + "/";
                query = query.Where(a => a.log_type != "error" && !NotByTenant.Contains(a.ref_key) && (a.ref_val == tenant || a.ref_val.StartsWith(prefix)));
                // What the host level was called in the trail until it was renamed, and what a tenant
                // of this name still is. Nothing tells the two apart, so neither is shown.
                if (Same(tenant, "host")) query = query.Where(a => a.ref_val != "host/mcp");
                if (call.Endpoint.Level == ArkMcpLevel.Client)
                {
                    // A line names its client first, or last after the person: the whole name, or
                    // an application would read the lines of every other that begins like it.
                    var mine = $"client: {call.Client.client_id}";
                    var first = mine + ", ";
                    var last = ", " + mine;
                    query = query.Where(a => a.details == mine || a.details.StartsWith(first) || a.details.EndsWith(last));
                }
            }
            if (call.Args.Text("event") is { } key) query = query.Where(a => a.ref_key == key);
            if (call.Args.Text("contains") is { } text) query = query.Where(a => a.message.Contains(text) || a.details.Contains(text) || a.ref_val.Contains(text));
            var rows = await query.OrderByDescending(a => a.at).Take(limit).ToListAsync();
            return new
            {
                since, count = rows.Count,
                trace_is_on = call.Config.EnableLogTrace,
                note = call.Config.EnableLogTrace ? null : "EnableLogTrace is off, so only changes and refusals are recorded here, not sign-ins and tokens.",
                events = rows.Select(r => new { at = r.at, @event = r.ref_key, reference = r.ref_val, level = r.log_type, message = r.message, details = Clip(r.details), by = r.by })
            };
        }

        static string? Clip(string? text) => text is { Length: > 600 } ? text[..600] + "…" : text;

        public static ArkMcpParams AuditParams() => new ArkMcpParams()
            .Int("hours", "How far back (default 24).", min: 1, max: 24 * 90)
            .Int("limit", "How many, newest first (default 50).", min: 1, max: 200)
            .Text("event", "Only this kind, for example signin_failed, mcp_call, client_upsert.", maxLength: 100)
            .Text("contains", "Only lines containing this text.", maxLength: 200);
    }
}
