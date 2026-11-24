using Ark.oAuth.Oidc.Protocol;
using Microsoft.EntityFrameworkCore;

namespace Ark.oAuth.Oidc.Mcp.Tools
{
    /// <summary><c>/{tenant}/mcp</c>: everything an administrator of one tenant does.</summary>
    internal static class TenantTools
    {
        public const string Instructions =
            "You administer one tenant of an identity server. Begin with tenant_overview: it shows what exists, what is unfinished or wrong, and the next steps with the tool and arguments for each.\n" +
            "To bring an application in: onboard_application registers it and adds its first people; client_integration gives its developers the exact settings. " +
            "To add people: onboard_user. When somebody cannot sign in: user_diagnose.\n" +
            "Secrets and password links are returned once. Store or hand them over before doing anything else, and do not repeat them in conversation.\n" +
            "Redirect URIs are matched byte for byte: never guess one, ask the application's owner. Tools that take something away ask you to confirm by name; " +
            "get a person's agreement first.";

        const ArkMcpRole Admin = ArkMcpRole.TenantAdmin;

        static ArkMcpParams ClientId() => new ArkMcpParams().Text("client_id", "The application's client_id.", required: true, maxLength: 500);

        public static readonly IReadOnlyList<ArkMcpTool> All = Build();

        static List<ArkMcpTool> Build()
        {
            var tools = new List<ArkMcpTool>
            {
                CommonTools.WhoAmI,
                new()
                {
                    Name = "tenant_overview", Title = "The state of the tenant",
                    Description = "Start here. The tenant's addresses, what it holds, what is switched on, what is unfinished or wrong, and the next steps in order with the tool and arguments for each.",
                    Role = Admin, Run = OverviewAsync
                },
                new()
                {
                    Name = "tenant_update", Title = "Rename the tenant", Description = "Changes the tenant's name and display name. Its id, and so its issuer, cannot change.",
                    Access = ArkMcpAccess.Manage, Role = Admin, Idempotent = true,
                    Params = new ArkMcpParams().Text("display", "Display name.", maxLength: 120).Text("name", "Name.", maxLength: 120),
                    Run = call => HostTools.UpdateTenantAsync(call, call.Tenant.tenant_id)
                },

                // ------------------------------------------------ applications
                new()
                {
                    Name = "client_list", Title = "List applications", Description = "Every application of the tenant, with its kind and how many people have access to it.",
                    Role = Admin,
                    Params = new ArkMcpParams().Text("query", "Only those whose id or name contains this.", maxLength: 200)
                        .Text("kind", "Only of this kind.", values: new[] { "web", "spa", "native", "public", "device", "service", "agent" })
                        .Flag("active", "Only active (true) or deactivated (false) ones."),
                    Run = async call =>
                    {
                        var clients = await ClientsAsync(call);
                        var people = await PeopleAsync(call);
                        var query = call.Args.Text("query");
                        var shown = clients
                            .Where(c => query == null || c.client_id.Contains(query, StringComparison.OrdinalIgnoreCase) || (c.client_name ?? c.display ?? "").Contains(query, StringComparison.OrdinalIgnoreCase))
                            .Where(c => call.Args.Text("kind") is not { } kind || ArkMcpOps.KindOf(c) == kind)
                            .Where(c => call.Args.Flag("active") is not { } active || c.is_active == active).ToList();
                        return new { count = shown.Count, applications = shown.Select(c => ArkMcpOps.ClientSummary(call, c, people.GetValueOrDefault(c.id))) };
                    }
                },
                new()
                {
                    Name = "client_get", Title = "Look an application up", Description = "Its whole registration, and what is unfinished or wrong about it.",
                    Role = Admin, Params = ClientId(),
                    Run = async call =>
                    {
                        var client = await ArkMcpOps.TargetAsync(call);
                        var people = await call.Db.user_client_claims.CountAsync(m => m.client_id == client.id);
                        return new
                        {
                            application = ArkMcpOps.ClientView(call, client), people,
                            findings = ArkMcpOps.Inspect(client, people, await ClientsAsync(call)).Select(ArkMcpOps.FindingView)
                        };
                    }
                },
                new()
                {
                    Name = "client_create", Title = "Register an application",
                    Description = "Registers an application with the settings its kind needs. A confidential one gets a secret, returned once. Nobody can sign in to it before they are given access (onboard_user).",
                    Access = ArkMcpAccess.Manage, Role = Admin, ReturnsSecret = true,
                    Params = ArkMcpOps.ClientFields(new ArkMcpParams()
                        .Text("name", "Name people see when they sign in.", required: true, maxLength: 120)
                        .Text("kind", ArkMcpOps.KindHelp, required: true, values: ArkMcpOps.Kinds)
                        .Text("client_id", "Its id in every request and token. Made from the name when left out; for mcp_server, its URL.", maxLength: 500), true),
                    Run = async call =>
                    {
                        var (client, secret) = await ArkMcpOps.CreateClientAsync(call, call.Args);
                        return Registered(call, client, secret);
                    }
                },
                new()
                {
                    Name = "client_update", Title = "Change an application",
                    Description = "Changes whatever is given and leaves the rest. A list replaces the whole list, so read it first with client_get.",
                    Access = ArkMcpAccess.Manage, Role = Admin, Idempotent = true,
                    Params = ArkMcpOps.ClientFields(ClientId().Text("name", "Name people see.", maxLength: 120).Flag("is_agent", "Marks it as an agent: a label in the console, not a permission."), false),
                    Run = async call =>
                    {
                        var client = await ArkMcpOps.TargetAsync(call);
                        ArkMcpOps.NotSystem(client, "changed");
                        if (call.Args.Text("name") is { } name) client.client_name = client.name = client.display = ArkMcpOps.NameOf(name);
                        if (call.Args.Flag("is_agent") is { } agent) client.is_agent = agent;
                        await ArkMcpOps.ApplyAsync(call, client, call.Args);
                        var saved = await ArkMcpOps.SaveClientAsync(call, client);
                        return new { application = ArkMcpOps.ClientView(call, saved) };
                    }
                },
                new()
                {
                    Name = "client_set_active", Title = "Switch an application on or off",
                    Description = "Off, nobody can sign in to it, it gets no tokens, and the refresh tokens it holds are withdrawn at once.",
                    Access = ArkMcpAccess.Manage, Role = Admin, Idempotent = true, Destructive = true,
                    Params = ClientId().Flag("active", "true switches it on, false off.", required: true).Text("reason", "Why, for the audit trail.", maxLength: 500),
                    Run = async call =>
                    {
                        var client = await ArkMcpOps.TargetAsync(call);
                        ArkMcpOps.NotSystem(client, "switched off");
                        var active = call.Args.Flag("active")!.Value;
                        await ArkMcpOps.SetActiveAsync(call, client, active, call.Args.Text("reason"));
                        return new { client_id = client.client_id, active };
                    }
                },
                new()
                {
                    Name = "client_delete", Title = "Delete an application",
                    Description = "Removes the registration, everybody's access to it and its refresh tokens. Cannot be undone; switching it off can (client_set_active).",
                    Access = ArkMcpAccess.Manage, Role = Admin, Destructive = true,
                    Params = ClientId().Text("confirm", "The client_id again.", maxLength: 500),
                    Run = async call =>
                    {
                        var client = await ArkMcpOps.TargetAsync(call);
                        ArkMcpOps.NotSystem(client, "deleted");
                        var people = await call.Db.user_client_claims.CountAsync(m => m.client_id == client.id);
                        call.Confirm(client.client_id, $"This deletes '{client.client_name ?? client.client_id}' and the access of {people} people to it.");
                        await ArkMcpOps.DeleteClientAsync(call, client);
                        return new { client_id = client.client_id, deleted = true };
                    }
                },
                new()
                {
                    Name = "client_secret_reset", Title = "Give an application a new secret",
                    Description = "Returns a new secret, once; the old one stops working at once. For the machine client this is the credential of this tenant's administration, your own perhaps included.",
                    Access = ArkMcpAccess.Manage, Role = Admin, Destructive = true, ReturnsSecret = true,
                    Params = ClientId().Text("confirm", "The client_id again.", maxLength: 500),
                    Run = async call =>
                    {
                        var client = await ArkMcpOps.TargetAsync(call);
                        if (client.has_client_secret)
                            call.Confirm(client.client_id, $"The secret '{client.client_id}' uses now stops working immediately.");
                        var secret = await ArkMcpOps.ResetSecretAsync(call, client);
                        return new { client_id = client.client_id, client_secret = secret, note = "Shown once; only its hash is stored." };
                    }
                },
                new()
                {
                    Name = "client_integration", Title = "Settings for an application's developers",
                    Description = "The exact authority, endpoints, redirect URIs and code to wire an application up, for .NET, Python and Node. Holds no secret.",
                    Role = Admin, Params = ClientId(),
                    Run = async call => ArkMcpOps.Integration(call, await ArkMcpOps.TargetAsync(call))
                },
                new()
                {
                    Name = "onboard_application", Title = "Bring an application in",
                    Description = "Registers an application and adds its first people, in one call: what would be client_create followed by onboard_user for each. " +
                                  "Answers with the secret, a password link for every new account, and the settings for its developers.",
                    Access = ArkMcpAccess.Manage, Role = Admin, ReturnsSecret = true,
                    Params = ArkMcpOps.ClientFields(new ArkMcpParams()
                        .Text("name", "Name people see when they sign in.", required: true, maxLength: 120)
                        .Text("kind", ArkMcpOps.KindHelp, required: true, values: ArkMcpOps.Kinds)
                        .Text("client_id", "Made from the name when left out.", maxLength: 500)
                        .Objects("people", "Who gets access to it.", new ArkMcpParams()
                            .Text("username", "An email address or username.", required: true, maxLength: 200)
                            .Text("name", "Full name, for a new account.", maxLength: 120)
                            .List("claims", "What they may do there.")
                            .Text("credential", ArkMcpOps.CredentialHelp, values: ArkMcpOps.Credentials), max: 50), true),
                    Run = OnboardAsync
                },

                // ------------------------------------------------ agents
                new()
                {
                    Name = "agent_caller_list", Title = "Who may call an agent",
                    Description = "The applications that may obtain a token addressed to this one (A2A), what each holds there, and whether it may bring a person along.",
                    Role = Admin, Params = ClientId(),
                    Run = async call =>
                    {
                        var target = await ArkMcpOps.TargetAsync(call);
                        var all = await ClientsAsync(call);
                        return new
                        {
                            client_id = target.client_id,
                            callers = target.a2a_callers.Select(a => new { client_id = a.client_id, claims = a.claims, delegate_users = a.delegate_users }),
                            may_call = all.Where(c => c.a2a_callers.Any(a => ArkMcpOps.Same(a.client_id, target.client_id))).Select(c => c.client_id)
                        };
                    }
                },
                new()
                {
                    Name = "agent_caller_set", Title = "Let an application call another",
                    Description = "Lets one application obtain tokens addressed to another, with the claims given. delegate_users also lets it act there for people: their own claims then apply, not these.",
                    Access = ArkMcpAccess.Manage, Role = Admin, Idempotent = true,
                    Params = ClientId().Text("caller", "client_id of the application that may call it.", required: true, maxLength: 500)
                        .List("claims", "What the caller may do there as itself.")
                        .Flag("delegate_users", "Whether it may act there for people (default false)."),
                    Run = async call =>
                    {
                        var target = await ArkMcpOps.TargetAsync(call);
                        ArkMcpOps.NotSystem(target, "called by agents");
                        var caller = await ArkMcpOps.ClientAsync(call, call.Args.Required("caller"));
                        var claims = call.Args.List("claims") ?? new List<string>();
                        ArkMcpOps.CheckClaims(call, claims);
                        var delegates = call.Args.Flag("delegate_users") ?? false;
                        target.a2a_callers = target.a2a_callers.Where(a => !ArkMcpOps.Same(a.client_id, caller.client_id))
                            .Append(new ArkAgentCaller { client_id = caller.client_id, claims = claims, delegate_users = delegates }).ToList();
                        await ArkMcpOps.SaveClientAsync(call, target);
                        var notes = new List<string>();
                        if (caller.IsPublicClient) notes.Add($"'{caller.client_id}' has no secret, and an agent must authenticate to get a token.");
                        if (delegates && !caller.EffectiveGrantTypes.Contains(ArkAgentTokens.TokenExchangeGrant, StringComparer.OrdinalIgnoreCase))
                            notes.Add($"'{caller.client_id}' is not registered for token exchange; add that grant with client_update before it can act for people.");
                        return new { client_id = target.client_id, caller = caller.client_id, claims, delegate_users = delegates, notes };
                    }
                },
                new()
                {
                    Name = "agent_caller_remove", Title = "Stop an application calling another",
                    Description = "Takes a caller off an application's list. No new token is issued to it; one it holds runs out within minutes.",
                    Access = ArkMcpAccess.Manage, Role = Admin, Idempotent = true, Destructive = true,
                    Params = ClientId().Text("caller", "client_id of the caller.", required: true, maxLength: 500),
                    Run = async call =>
                    {
                        var target = await ArkMcpOps.TargetAsync(call);
                        var caller = call.Args.Required("caller");
                        if (!target.a2a_callers.Any(a => ArkMcpOps.Same(a.client_id, caller)))
                            throw new ArkMcpToolException("not_listed", $"'{caller}' is not a caller of '{target.client_id}'.");
                        target.a2a_callers = target.a2a_callers.Where(a => !ArkMcpOps.Same(a.client_id, caller)).ToList();
                        await ArkMcpOps.SaveClientAsync(call, target);
                        return new { client_id = target.client_id, removed = caller };
                    }
                }
            };

            tools.AddRange(CommonTools.Users(Admin));
            tools.AddRange(CommonTools.UserAdministration(Admin));
            tools.AddRange(CommonTools.Access(Admin, client: true));

            tools.AddRange(new ArkMcpTool[]
            {
                new()
                {
                    Name = "access_list", Title = "Who has access to what",
                    Description = "The people with access to an application, or the applications somebody has access to, with their claims.",
                    Role = Admin,
                    Params = ArkMcpOps.Paging(new ArkMcpParams().Text("client_id", "An application.", maxLength: 500).Text("username", "Or a person.", maxLength: 200)),
                    Run = AccessAsync
                },

                // ------------------------------------------------ sessions and keys
                new()
                {
                    Name = "session_list", Title = "Live sessions", Description = "Who is signed in, since when, and the applications they have opened.",
                    Role = Admin,
                    Params = new ArkMcpParams().Text("username", "Only this person's.", maxLength: 200).Int("limit", "How many, newest first (default 50).", min: 1, max: 200),
                    Run = async call =>
                    {
                        var now = DateTime.UtcNow;
                        var tenant = call.Tenant.tenant_id;
                        var who = call.Args.Text("username")?.ToLowerInvariant();
                        var query = call.Db.sessions.AsNoTracking().Where(s => s.tenant_id == tenant && !s.revoked && s.expires_at > now && (who == null || s.subject == who));
                        var total = await query.CountAsync();
                        var rows = await query.OrderByDescending(s => s.created_at).Take(call.Args.Int("limit") ?? 50).ToListAsync();
                        var opened = await call.Get<ArkGrantStore>().GetSessionClientsAsync(rows.Select(r => r.session_id));
                        return new
                        {
                            total,
                            sessions = rows.Select(s => new
                            {
                                session_id = s.session_id, username = s.subject, signed_in_at = s.auth_time, expires_at = s.expires_at,
                                applications = opened.Where(o => o.session_id == s.session_id).Select(o => o.client_id)
                            })
                        };
                    }
                },
                new()
                {
                    Name = "session_end", Title = "End a session", Description = "Ends one session with its refresh tokens, and tells the applications that asked to be told.",
                    Access = ArkMcpAccess.Manage, Role = Admin, Idempotent = true, Destructive = true,
                    Params = new ArkMcpParams().Text("session_id", "From session_list.", required: true, maxLength: 200),
                    Run = async call =>
                    {
                        var id = call.Args.Required("session_id");
                        var tenant = call.Tenant.tenant_id;
                        if (!await call.Db.sessions.AnyAsync(s => s.session_id == id && s.tenant_id == tenant))
                            throw new ArkMcpToolException("unknown_session", "there is no such session in this tenant.");
                        return new { sessions_ended = await ArkMcpOps.EndSessionsAsync(call, new[] { id }, "administrator") };
                    }
                },
                new()
                {
                    Name = "signing_key_list", Title = "Signing keys", Description = "The keys tokens are signed and verified with: which is active, which is being phased out, since when. Public parts only.",
                    Role = Admin,
                    Run = async call =>
                    {
                        var tenant = call.Tenant.tenant_id;
                        await call.Get<ArkKeyService>().GetActiveKeyAsync(tenant);
                        var keys = await call.Db.signing_keys.AsNoTracking().Where(k => k.tenant_id == tenant).OrderByDescending(k => k.created_at).ToListAsync();
                        return new { jwks = call.Endpoint.OidcFor(tenant).Jwks, keys = keys.Select(k => new { kid = k.kid, algorithm = k.alg, status = k.status, created_at = k.created_at, not_after = k.not_after }) };
                    }
                },
                new()
                {
                    Name = "signing_key_rotate", Title = "Rotate the signing key",
                    Description = "New tokens are signed with a new key; the old one stays published so tokens already out still verify. Applications that read the JWKS notice nothing; one with a pasted key stops working.",
                    Access = ArkMcpAccess.Manage, Role = Admin, Destructive = true,
                    Params = new ArkMcpParams().Text("confirm", "The tenant id.", maxLength: 63),
                    Run = async call =>
                    {
                        call.Confirm(call.Tenant.tenant_id, "This changes the key every new token of the tenant is signed with.");
                        var key = await call.Get<ArkKeyService>().RotateAsync(call.Tenant.tenant_id);
                        call.Da.Log("signing_key_rotate", call.Tenant.tenant_id, "signing key rotated", $"over mcp : kid: {key.kid}");
                        return new { active_kid = key.kid, note = "Retire the previous key with signing_key_retire once its last token has expired." };
                    }
                },
                new()
                {
                    Name = "signing_key_retire", Title = "Retire an old signing key",
                    Description = "Takes a key that is being phased out off the published set. Tokens signed with it stop verifying. The active key cannot be retired.",
                    Access = ArkMcpAccess.Manage, Role = Admin, Destructive = true,
                    Params = new ArkMcpParams().Text("kid", "The key.", required: true, maxLength: 200).Text("confirm", "The kid again.", maxLength: 200),
                    Run = async call =>
                    {
                        var kid = call.Args.Required("kid");
                        var tenant = call.Tenant.tenant_id;
                        var key = await call.Db.signing_keys.AsNoTracking().FirstOrDefaultAsync(k => k.tenant_id == tenant && k.kid == kid)
                            ?? throw new ArkMcpToolException("unknown_key", "there is no such key in this tenant.");
                        if (key.status != "rollover") throw new ArkMcpToolException("not_in_rollover", $"that key is {key.status}; only one that is being phased out can be retired.");
                        call.Confirm(kid, "Tokens signed with this key stop verifying.");
                        await call.Get<ArkKeyService>().RetireAsync(tenant, kid);
                        call.Da.Log("signing_key_retire", tenant, "signing key retired", $"over mcp : kid: {kid}");
                        return new { kid, status = "retired" };
                    }
                },

                // ------------------------------------------------ catalogues
                new()
                {
                    Name = "scope_list", Title = "Scopes of the server", Description = "The scopes an application can be registered for. Shared by every tenant; only the operator changes them.",
                    Role = Admin, Run = HostTools.ScopesAsync
                },
                new()
                {
                    Name = "claim_list", Title = "Claims of the server", Description = "The claim names in use. Shared by every tenant. Granting access with a new one adds it.",
                    Role = Admin, Run = HostTools.ClaimsAsync
                },
                CommonTools.Audit(Admin)
            });
            return tools;
        }

        // ---------------------------------------------------------------- pieces

        static Task<List<ArkClient>> ClientsAsync(ArkMcpCall call)
        {
            var tenant = call.Tenant.tenant_id;
            return call.Db.clients.AsNoTracking().Where(c => c.tenant_id == tenant).OrderBy(c => c.client_id).ToListAsync();
        }

        /// <summary>How many people have access to each application, by its row id.</summary>
        static async Task<Dictionary<string, int>> PeopleAsync(ArkMcpCall call)
        {
            var tenant = call.Tenant.tenant_id;
            var counts = await call.Db.user_client_claims.AsNoTracking().Where(m => m.tenant_id == tenant)
                .GroupBy(m => m.client_id).Select(g => new { g.Key, Count = g.Count() }).ToListAsync();
            return counts.ToDictionary(c => c.Key, c => c.Count, StringComparer.Ordinal);
        }

        static object Registered(ArkMcpCall call, ArkClient client, string? secret) => new
        {
            application = ArkMcpOps.ClientView(call, client),
            client_secret = secret,
            note = secret == null ? "A public client: it has no secret and proves itself with PKCE." : "The secret is shown once; only its hash is stored.",
            mcp = ArkMcpResources.Client(call.Endpoint.Root, client.tenant_id, client.client_id),
            next_steps = client.EffectiveGrantTypes.Contains("authorization_code", StringComparer.OrdinalIgnoreCase)
                ? new[]
                {
                    (object)new { why = "nobody can sign in to it yet", tool = "onboard_user", arguments = new { client_id = client.client_id } },
                    new { why = "its developers need the settings", tool = "client_integration", arguments = new { client_id = client.client_id } }
                }
                : new[] { (object)new { why = "its developers need the settings", tool = "client_integration", arguments = new { client_id = client.client_id } } }
        };

        static async Task<object> OnboardAsync(ArkMcpCall call)
        {
            var people = call.Args.Objects("people") ?? new List<ArkMcpArgs>();
            // What could stop part of the way is checked before anything is made.
            foreach (var p in people) ArkMcpOps.CheckClaims(call, p.List("claims") ?? new List<string>());
            foreach (var p in people)
                if (!DataAccess.IsValidLoginId(p.Required("username").ToLowerInvariant()))
                    throw new ArkMcpToolException("invalid_username", $"'{p.Text("username")}': use an email address, or 2-64 characters of letters, digits, dot, dash or underscore.");

            var (client, secret) = await ArkMcpOps.CreateClientAsync(call, call.Args);
            var added = new List<object>();
            foreach (var p in people)
            {
                try
                {
                    var (user, created, credential, link) = await ArkMcpOps.PersonAsync(call, p.Required("username"), p.Text("name"), p.Text("credential"), null, create: true);
                    var granted = await ArkMcpOps.GrantAsync(call, user, client, p.List("claims") ?? new(), replace: false);
                    added.Add(new { username = user.email, ok = true, account = created ? "created" : "already existed", credential, password_link = link, claims = granted.Claims });
                }
                catch (Exception ex) when (ex is ArkMcpToolException or ApplicationException)
                {
                    // One person who cannot be added does not undo the application or the others.
                    added.Add(new { username = p.Text("username"), ok = false, error = ex.Message });
                }
            }
            return new
            {
                application = ArkMcpOps.ClientView(call, client),
                client_secret = secret,
                people = added,
                note = "The secret and the password links are shown once. Hand each to the person it belongs to over a private channel.",
                integration = ArkMcpOps.Integration(call, client),
                mcp = ArkMcpResources.Client(call.Endpoint.Root, client.tenant_id, client.client_id)
            };
        }

        static async Task<object> AccessAsync(ArkMcpCall call)
        {
            if (call.Args.Text("username") is { } username)
            {
                var user = await ArkMcpOps.VisibleUserAsync(call, username);
                var access = await ArkMcpOps.AccessOfAsync(call, user.email, call.Tenant.tenant_id);
                return new { username = user.email, access = access.Select(a => new { client_id = a.Client.client_id, name = a.Client.client_name ?? a.Client.display, claims = a.Mapping.claims }) };
            }
            var client = await ArkMcpOps.ClientAsync(call, call.Args.Text("client_id")
                ?? throw new ArkMcpToolException("invalid_arguments", "give client_id or username."));
            var limit = call.Args.Int("limit") ?? 50;
            var after = call.Args.Text("cursor");
            var rows = await call.Db.user_client_claims.AsNoTracking()
                .Where(m => m.client_id == client.id && (after == null || string.Compare(m.email, after) > 0))
                .OrderBy(m => m.email).Take(limit + 1).ToListAsync();
            return new
            {
                client_id = client.client_id,
                people = rows.Take(limit).Select(m => new { username = m.email, claims = m.claims }),
                next_cursor = rows.Count > limit ? rows[limit - 1].email : null
            };
        }

        static async Task<object> OverviewAsync(ArkMcpCall call)
        {
            var tenant = call.Tenant;
            var clients = await ClientsAsync(call);
            var people = await PeopleAsync(call);
            var id = tenant.tenant_id;
            var now = DateTime.UtcNow;
            var accounts = call.Db.users.AsNoTracking().Where(u => u.home_tenant_id == id
                || call.Db.user_client_claims.Any(m => m.email == u.email && m.tenant_id == id));
            var total = await accounts.CountAsync();
            var waiting = await accounts.CountAsync(u => u.reset_mode == true);
            var sessions = await call.Db.sessions.CountAsync(s => s.tenant_id == id && !s.revoked && s.expires_at > now);
            var stranded = await call.Db.users.AsNoTracking().Where(u => u.home_tenant_id == id && !call.Db.user_client_claims.Any(m => m.email == u.email))
                .OrderBy(u => u.email).Select(u => u.email).Take(20).ToListAsync();
            var active = await call.Get<ArkKeyService>().GetActiveKeyAsync(id);
            var own = clients.Where(c => !ArkMcpOps.IsSystem(c)).ToList();
            var oidc = call.Config.Oidc ?? new ArkOidcOptions();
            var machine = clients.FirstOrDefault(c => ArkMcpOps.Same(c.client_id, ArkManagementAuth.MachineClientId(id)));

            var findings = clients.SelectMany(c => ArkMcpOps.Inspect(c, people.GetValueOrDefault(c.id), clients)).ToList();
            if (own.Count == 0)
                findings.Insert(0, new ArkMcpOps.Finding("warning", "no_application", id, "no application has been registered yet.", "onboard_application", new { name = "<ask>", kind = "<ask>", redirect_uris = new[] { "<ask>" } }));
            foreach (var username in stranded)
                findings.Add(new ArkMcpOps.Finding("info", "no_access", username, $"'{username}' has an account and access to nothing.", "access_grant", new { username }));
            if (waiting > 0)
                findings.Add(new ArkMcpOps.Finding("info", "waiting_for_password", id, $"{waiting} account(s) still wait for their password to be set. A link older than {call.Config.PasswordLinkLifetimeHours} hours has expired.", "user_list", new { waiting = true }));
            if (active.created_at < now.AddYears(-1))
                findings.Add(new ArkMcpOps.Finding("info", "old_signing_key", active.kid, $"the signing key is from {active.created_at:yyyy-MM-dd}.", "signing_key_rotate", new { confirm = id }));
            if (machine is null)
                findings.Add(new ArkMcpOps.Finding("info", "no_machine_client", id, "this tenant has no machine client, so nothing can administer it unattended. The operator makes one with tenant_machine_secret_reset."));
            if (machine != null && own.Any(c => c.EffectiveGrantTypes.Contains("authorization_code", StringComparer.OrdinalIgnoreCase)) && call.Endpoint.Root.StartsWith("http:", StringComparison.OrdinalIgnoreCase)
                && Uri.TryCreate(call.Endpoint.Root, UriKind.Absolute, out var root) && !root.IsLoopback)
                findings.Add(new ArkMcpOps.Finding("error", "plain_http", id, "the issuer's address is plain http: passwords and tokens cross the network unencrypted."));

            return new
            {
                tenant = ArkMcpOps.TenantView(call, tenant),
                counts = new
                {
                    applications = own.Count, agents = own.Count(c => c.is_agent == true), deactivated_applications = own.Count(c => !c.is_active),
                    people = total, waiting_for_password = waiting, live_sessions = sessions
                },
                applications = clients.Select(c => ArkMcpOps.ClientSummary(call, c, people.GetValueOrDefault(c.id))),
                switched_on = new
                {
                    dynamic_registration = oidc.EnableDynamicRegistration, device_sign_in = oidc.EnableDeviceFlow,
                    pushed_authorization_requests = oidc.EnablePushedAuthorizationRequests, agent_to_agent = oidc.EnableA2A,
                    back_channel_logout = oidc.EnableBackChannelLogout, email = !string.IsNullOrWhiteSpace(call.Config.EmailConfig?.smtp),
                    audit_trail = (call.Services.GetService(typeof(ArkWatchAudit)) as ArkWatchAudit)?.Enabled ?? false,
                    changes_over_mcp = !call.Config.Mcp.ReadOnly
                },
                registration = new
                {
                    dynamic_registration_endpoint = oidc.EnableDynamicRegistration ? call.Endpoint.OidcFor(id).Registration : null,
                    note = oidc.EnableDynamicRegistration
                        ? "An agent registers itself there (RFC 7591) with an access token of the machine client that carries client.register and no resource."
                        : "Dynamic registration is off (ark_oauth_server:Oidc:EnableDynamicRegistration). client_create registers on an application's behalf."
                },
                findings = findings.Select(ArkMcpOps.FindingView),
                next_steps = ArkMcpOps.NextSteps(findings)
            };
        }
    }
}
