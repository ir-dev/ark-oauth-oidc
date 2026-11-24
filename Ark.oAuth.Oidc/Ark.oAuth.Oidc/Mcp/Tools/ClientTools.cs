using Ark.oAuth.Oidc.Protocol;
using Microsoft.EntityFrameworkCore;

namespace Ark.oAuth.Oidc.Mcp.Tools
{
    /// <summary>
    /// <c>/{tenant}/mcp/{client_id}</c>: one application. For the application itself, for the
    /// people who sign in to it, for its administrators, and for the agents it lists as callers —
    /// each through whichever flow the application is registered for.
    /// </summary>
    internal static class ClientTools
    {
        public const string Instructions =
            "You are at one application of an identity server. whoami says who you are here and what you may do.\n" +
            "A signed-in person sees their own profile, access and sessions (my_*). The application itself, and its administrators, see its people and registration and may change " +
            "them when the token carries mcp.manage. Anything beyond this application is done at the tenant's endpoint.";

        const ArkMcpRole Admin = ArkMcpRole.ClientAdmin;

        public static readonly IReadOnlyList<ArkMcpTool> All = Build();

        static List<ArkMcpTool> Build()
        {
            var tools = new List<ArkMcpTool>
            {
                CommonTools.WhoAmI,
                new()
                {
                    Name = "app_info", Title = "About this application",
                    Description = "The application's name, how it signs people in, and the addresses it uses. Nothing secret.",
                    Access = ArkMcpAccess.Self, Role = ArkMcpRole.Anyone,
                    Run = call =>
                    {
                        var c = call.Client;
                        var ep = call.Endpoint.OidcFor(c.tenant_id);
                        return Task.FromResult<object>(new
                        {
                            client_id = c.client_id, name = c.client_name ?? c.display, kind = ArkMcpOps.KindOf(c), active = c.is_active,
                            home_page = c.client_uri, privacy_policy = c.policy_uri, terms = c.tos_uri,
                            issuer = ep.Issuer, discovery = ep.Discovery, flows = c.EffectiveGrantTypes, scopes = c.EffectiveScopes,
                            ways_in = WaysIn(call, c)
                        });
                    }
                },

                // ------------------------------------------------ the person
                new()
                {
                    Name = "my_profile", Title = "My profile", Description = "The signed-in person: what the identity server knows of them under the scopes this token carries.",
                    Access = ArkMcpAccess.Self, Role = ArkMcpRole.Person,
                    Run = async call => new
                    {
                        username = call.Caller.Subject,
                        profile = await call.Get<ArkClaimsService>().GetIdentityClaimsAsync(call.Caller.Subject, call.Caller.Scopes),
                        through = call.Caller.Actors.Count > 0 ? call.Caller.Actors : null
                    }
                },
                new()
                {
                    Name = "my_access", Title = "My access", Description = "What the signed-in person may do at this application.",
                    Access = ArkMcpAccess.Self, Role = ArkMcpRole.Person,
                    Run = async call =>
                    {
                        var mapping = await ArkLookup.MappingAsync(call.Db, call.Caller.Subject, call.Client.tenant_id, call.Client.id);
                        return new { username = call.Caller.Subject, client_id = call.Client.client_id, has_access = mapping != null, claims = mapping?.claims ?? new List<string>() };
                    }
                },
                new()
                {
                    Name = "my_sessions", Title = "My sessions", Description = "Where the signed-in person is signed in at this application, and since when.",
                    Access = ArkMcpAccess.Self, Role = ArkMcpRole.Person,
                    Run = async call =>
                    {
                        var now = DateTime.UtcNow;
                        var tenant = call.Tenant.tenant_id;
                        var client = call.Client.client_id;
                        var who = call.Caller.Subject;
                        var rows = await call.Db.sessions.AsNoTracking()
                            .Where(s => s.subject == who && s.tenant_id == tenant && !s.revoked && s.expires_at > now
                                && call.Db.session_clients.Any(c => c.session_id == s.session_id && c.client_id == client))
                            .OrderByDescending(s => s.created_at).Take(50).ToListAsync();
                        return new { sessions = rows.Select(s => new { signed_in_at = s.auth_time, expires_at = s.expires_at }) };
                    }
                },
                new()
                {
                    Name = "my_sign_out", Title = "Sign me out of this application",
                    Description = "Withdraws the refresh tokens this application holds for the signed-in person, so it has to ask them to sign in again. Their session at the identity server, and other applications, are not touched.",
                    Access = ArkMcpAccess.Self, Role = ArkMcpRole.Person, Destructive = true, Idempotent = true,
                    Run = async call =>
                    {
                        // An agent carrying somebody must not be able to end what they themselves began.
                        if (call.Caller.Actors.Count > 0)
                            throw new ArkMcpToolException("not_permitted", "only the person themselves, signed in to this application, may do that.");
                        var n = await ArkMcpOps.RevokeRefreshAsync(call, call.Caller.Subject, call.Client);
                        call.Da.Log("revoke", $"{call.Tenant.tenant_id}/mcp", "refresh tokens withdrawn by their owner", $"client: {call.Client.client_id}, sub: {call.Caller.Subject}");
                        return new { refresh_tokens_withdrawn = n, note = "Access tokens already out run until they expire." };
                    }
                },

                // ------------------------------------------------ the application
                new()
                {
                    Name = "app_registration", Title = "The registration", Description = "The application's whole registration, and what is unfinished or wrong about it.",
                    Role = Admin,
                    Run = async call =>
                    {
                        var client = await ArkMcpOps.TargetAsync(call);
                        var people = await call.Db.user_client_claims.CountAsync(m => m.client_id == client.id);
                        var callers = client.a2a_callers.Select(a => a.client_id).ToList();
                        var siblings = await call.Db.clients.AsNoTracking().Where(c => c.tenant_id == client.tenant_id && callers.Contains(c.client_id)).ToListAsync();
                        return new
                        {
                            application = ArkMcpOps.ClientView(call, client), people,
                            // Findings name tools; the ones for this caller are at the tenant level.
                            findings = ArkMcpOps.Inspect(client, people, siblings).Select(f => new { severity = f.Severity, code = f.Code, message = f.Message })
                        };
                    }
                },
                new()
                {
                    Name = "app_integration", Title = "Settings for its developers", Description = "The exact authority, endpoints, redirect URIs and code to wire the application up. Holds no secret.",
                    Role = Admin, Run = async call => ArkMcpOps.Integration(call, await ArkMcpOps.TargetAsync(call))
                },
                new()
                {
                    Name = "app_update_profile", Title = "Change how it is presented",
                    Description = "Its name, logo and links, as people see them when they sign in. Redirect URIs, scopes and flows are an administrator of the tenant's to change.",
                    Access = ArkMcpAccess.Manage, Role = Admin, Idempotent = true,
                    Params = new ArkMcpParams().Text("name", "Name people see.", maxLength: 120).Text("logo", "An http(s) image URL.")
                        .Text("client_uri", "Home page.").Text("policy_uri", "Privacy policy.").Text("tos_uri", "Terms of service."),
                    Run = async call =>
                    {
                        var client = await ArkMcpOps.TargetAsync(call);
                        ArkMcpOps.NotSystem(client, "changed");
                        if (!call.Args.Names.Any()) throw new ArkMcpToolException("invalid_arguments", "give at least one value to change.");
                        if (call.Args.Text("name") is { } name) client.client_name = client.name = client.display = ArkMcpOps.NameOf(name);
                        string? Web(string field)
                        {
                            var value = call.Args.Text(field);
                            if (value != null && !RedirectUriValidator.IsWebUrl(value)) throw new ArkMcpToolException("invalid_uri", $"{field} must be an http or https URL.");
                            return value;
                        }
                        if (call.Args.Has("logo")) client.client_logo = Web("logo");
                        if (call.Args.Has("client_uri")) client.client_uri = Web("client_uri");
                        if (call.Args.Has("policy_uri")) client.policy_uri = Web("policy_uri");
                        if (call.Args.Has("tos_uri")) client.tos_uri = Web("tos_uri");
                        var saved = await ArkMcpOps.SaveClientAsync(call, client);
                        return new { application = new { saved.client_id, name = saved.client_name, saved.client_uri, saved.policy_uri, saved.tos_uri } };
                    }
                },
                new()
                {
                    Name = "app_secret_rotate", Title = "Rotate its secret",
                    Description = "Returns a new secret for the application, once. The one in use stops working at once.",
                    Access = ArkMcpAccess.Manage, Role = Admin, Destructive = true, ReturnsSecret = true,
                    Params = new ArkMcpParams().Text("confirm", "The application's client_id.", maxLength: 500),
                    Run = async call =>
                    {
                        var client = await ArkMcpOps.TargetAsync(call);
                        // A person's or an agent's token is not the application: only it, or whoever
                        // administers the tenant, gets to hold its credential.
                        if (!call.Caller.TenantAdmin && (call.Caller.IsUser || call.Caller.Kind != "client"))
                            throw new ArkMcpToolException("not_permitted", "only the application itself, or an administrator of the tenant, gets its secret.");
                        ArkMcpOps.NotSystem(client, "given a secret");
                        call.Confirm(client.client_id, $"The secret '{client.client_id}' uses now stops working immediately.");
                        return new { client_id = client.client_id, client_secret = await ArkMcpOps.ResetSecretAsync(call, client), note = "Shown once; only its hash is stored." };
                    }
                },
                new()
                {
                    Name = "agent_caller_list", Title = "Who may call this application",
                    Description = "The agents that may obtain a token addressed to it, what each holds there, and whether it may bring a person along. An administrator of the tenant changes the list.",
                    Role = Admin,
                    Run = async call =>
                    {
                        var client = await ArkMcpOps.TargetAsync(call);
                        return new { client_id = client.client_id, callers = client.a2a_callers.Select(a => new { client_id = a.client_id, claims = a.claims, delegate_users = a.delegate_users }) };
                    }
                }
            };

            tools.AddRange(CommonTools.Users(Admin));
            tools.AddRange(CommonTools.Access(Admin, client: false));
            tools.Add(new ArkMcpTool
            {
                Name = "user_tokens_revoke", Title = "Make somebody sign in again",
                Description = "Withdraws the refresh tokens the application holds for a person. Their session at the identity server, and other applications, are not touched.",
                Access = ArkMcpAccess.Manage, Role = Admin, Destructive = true, Idempotent = true,
                Params = new ArkMcpParams().Text("username", "Who.", required: true, maxLength: 200),
                Run = async call =>
                {
                    var user = await ArkMcpOps.VisibleUserAsync(call, call.Args.Required("username"));
                    var n = await ArkMcpOps.RevokeRefreshAsync(call, user.email, call.Client);
                    return new { username = user.email, refresh_tokens_withdrawn = n };
                }
            });
            tools.Add(CommonTools.Audit(Admin));
            return tools;
        }

        /// <summary>The flows by which a caller gets a token for this endpoint, as the application is registered.</summary>
        static List<object> WaysIn(ArkMcpCall call, ArkClient c)
        {
            var ep = call.Endpoint.OidcFor(c.tenant_id);
            var ways = new List<object>();
            bool Grant(string g) => c.EffectiveGrantTypes.Contains(g, StringComparer.OrdinalIgnoreCase);
            if (Grant("authorization_code")) ways.Add(new { who = "a person, in a browser", grant = "authorization_code", at = ep.Authorization, resource = call.Endpoint.Resource });
            if (Grant(ArkMcpOps.DeviceGrant)) ways.Add(new { who = "a person, on another device", grant = "device_code", at = ep.DeviceAuthorization, resource = call.Endpoint.Resource });
            if (Grant("client_credentials")) ways.Add(new { who = "the application itself", grant = "client_credentials", at = ep.Token, resource = call.Endpoint.Resource });
            if (c.a2a_callers.Count > 0)
            {
                ways.Add(new { who = "an agent it lists as a caller", grant = "client_credentials", at = ep.Token, resource = call.Endpoint.Resource });
                if (c.a2a_callers.Any(a => a.delegate_users))
                    ways.Add(new { who = "an agent it lists, for a person", grant = ArkAgentTokens.TokenExchangeGrant, at = ep.Token, resource = call.Endpoint.Resource });
            }
            return ways;
        }
    }
}
