using Ark.oAuth.Oidc.Protocol;
using Microsoft.EntityFrameworkCore;

namespace Ark.oAuth.Oidc.Mcp.Tools
{
    /// <summary>Tools offered at more than one level, written once. What they reach is decided by the endpoint and the caller.</summary>
    internal static class CommonTools
    {
        // ---------------------------------------------------------------- the caller

        public static readonly ArkMcpTool WhoAmI = new()
        {
            Name = "whoami", Title = "Who am I here",
            Description = "Who the server takes you for, at which level, and what that lets you do. Works for any token addressed to this endpoint, so start here when another tool is refused.",
            Access = ArkMcpAccess.Self, Role = ArkMcpRole.Anyone,
            Run = call =>
            {
                var c = call.Caller;
                var e = call.Endpoint;
                var missing = new List<string>();
                if (e.Level == ArkMcpLevel.Host && !c.Operator)
                    missing.Add($"To run the server: the machine client of the operator tenant, or {ArkMcpClaims.HostAdmin} on your access mapping to '{c.ClientId}' there.");
                if (e.Level == ArkMcpLevel.Tenant && !c.TenantAdmin)
                    missing.Add(e.IsOperatorTenant
                        ? $"To administer the operator tenant: its machine client, or {ArkMcpClaims.HostAdmin} on your access mapping to '{c.ClientId}'."
                        : $"To administer this tenant: its machine client, or {ArkMcpClaims.TenantAdmin} on your access mapping to '{c.ClientId}'.");
                if (e.Level == ArkMcpLevel.Client && !c.ClientAdmin)
                    missing.Add($"To administer this application: {ArkMcpClaims.ClientAdmin} on your access mapping to it.");
                if (!c.CanRead) missing.Add($"To look things up: the scope {ArkMcpScopes.Read}.");
                if (!c.CanManage)
                    missing.Add(e.Config.Mcp.ReadOnly ? "Changes are switched off on this server (Mcp:ReadOnly)." : $"To change things: the scope {ArkMcpScopes.Manage}.");
                return Task.FromResult<object>(new
                {
                    subject = c.Subject, kind = c.Kind, client_id = c.ClientId, issuer_tenant = c.TenantId, credential = c.Credential,
                    acting_for_them = c.Actors.Count > 0 ? c.Actors : null,
                    level = e.Level.ToString().ToLowerInvariant(), tenant_id = e.Tenant?.tenant_id, application = e.Client?.client_id,
                    is_operator = c.Operator, is_tenant_administrator = c.TenantAdmin, is_application_administrator = c.ClientAdmin,
                    may_read = c.CanRead, may_change = c.CanManage, scopes = c.Scopes, claims = c.Claims, token_expires_at = c.ExpiresAt,
                    not_yet = missing,
                    other_levels = new
                    {
                        host = ArkMcpResources.Host(e.Root),
                        tenant = ArkMcpResources.Tenant(e.Root, e.Tenant?.tenant_id ?? e.OperatorTenantId)
                    },
                    note = "A token is good at one endpoint only. For another level, request one with that address as resource."
                });
            }
        };

        // ---------------------------------------------------------------- accounts

        static ArkMcpParams Username(string description = "The account's username.") =>
            new ArkMcpParams().Text("username", description, required: true, maxLength: 200);

        public static List<ArkMcpTool> Users(ArkMcpRole role) => new()
        {
            new ArkMcpTool
            {
                Name = "user_list", Title = "List accounts",
                Description = "Accounts: at the host level every one on the server, at the tenant level those the tenant owns or that have access in it, at an application those with access to it.",
                Access = ArkMcpAccess.Read, Role = role,
                Params = ArkMcpOps.Paging(new ArkMcpParams()
                    .Text("query", "Only usernames or names containing this.", maxLength: 200)
                    .Text("client_id", "Only people with access to this application.", maxLength: 500)
                    .Flag("waiting", "Only accounts still waiting for their password to be set.")
                    .Flag("active", "Only active (true) or deactivated (false) accounts.")),
                Run = ListUsersAsync
            },
            new ArkMcpTool
            {
                Name = "user_get", Title = "Look an account up",
                Description = "One account: whether it is active, who manages it, which applications it has access to with which claims, and its live sessions.",
                Access = ArkMcpAccess.Read, Role = role, Params = Username(),
                Run = async call =>
                {
                    var user = await ArkMcpOps.VisibleUserAsync(call, call.Args.Required("username"));
                    var tenant = call.Endpoint.Tenant?.tenant_id;
                    var access = await ArkMcpOps.AccessOfAsync(call, user.email, tenant);
                    if (call.Endpoint.Level == ArkMcpLevel.Client && !call.Caller.TenantAdmin)
                        access = access.Where(a => a.Client.id == call.Client.id).ToList();
                    var now = DateTime.UtcNow;
                    var sessions = await call.Db.sessions.AsNoTracking()
                        .CountAsync(s => s.subject == user.email && !s.revoked && s.expires_at > now && (tenant == null || s.tenant_id == tenant));
                    return new
                    {
                        user = ArkMcpOps.UserView(call, user, access.Select(a => (tenant == null ? $"{a.Client.tenant_id}/{a.Client.client_id}" : a.Client.client_id, a.Mapping.claims))),
                        live_sessions = sessions
                    };
                }
            },
            new ArkMcpTool
            {
                Name = "user_diagnose", Title = "Why can they not sign in",
                Description = "Goes through every condition of a sign-in in order and says which one fails and which tool puts it right. " +
                              "Use it for any \"it says my password is wrong\": a missing access grant reads exactly like that.",
                Access = ArkMcpAccess.Read, Role = role,
                Params = Username("Who cannot sign in.").Text("client_id", "The application they are signing in to.", maxLength: 500)
                    .Text("tenant_id", "Host level: the application's tenant.", maxLength: 63),
                Run = async call =>
                {
                    ArkClient? client = null;
                    if (call.Endpoint.Level == ArkMcpLevel.Client) client = await ArkMcpOps.TargetAsync(call);
                    else if (call.Args.Text("client_id") is { } id)
                        client = call.Endpoint.Tenant != null ? await ArkMcpOps.ClientAsync(call, id)
                            : await ArkLookup.ClientAsync(call.Db, call.Args.Text("tenant_id") ?? call.Endpoint.OperatorTenantId, id)
                              ?? throw new ArkMcpToolException("unknown_client", $"no application '{id}' there.");
                    return await ArkMcpOps.DiagnoseAsync(call, call.Args.Required("username"), client);
                }
            }
        };

        static async Task<object> ListUsersAsync(ArkMcpCall call)
        {
            var limit = call.Args.Int("limit") ?? 50;
            var query = call.Db.users.AsNoTracking().AsQueryable();
            var mappings = call.Db.user_client_claims.AsNoTracking();

            string? rowId = null;
            if (call.Endpoint.Level == ArkMcpLevel.Client) rowId = call.Client.id;
            else if (call.Args.Text("client_id") is { } id && call.Endpoint.Tenant != null) rowId = (await ArkMcpOps.ClientAsync(call, id)).id;

            if (rowId != null) query = query.Where(u => mappings.Any(m => m.email == u.email && m.client_id == rowId));
            else if (call.Endpoint.Tenant is { } tenant)
                query = query.Where(u => u.home_tenant_id == tenant.tenant_id || mappings.Any(m => m.email == u.email && m.tenant_id == tenant.tenant_id));
            if (call.Args.Text("query")?.ToLowerInvariant() is { } text)
                query = query.Where(u => u.email.ToLower().Contains(text) || u.name.ToLower().Contains(text));
            if (call.Args.Flag("waiting") == true) query = query.Where(u => u.reset_mode == true);
            if (call.Args.Flag("active") is { } active) query = query.Where(u => u.is_active == active);
            if (call.Args.Text("cursor") is { } after) query = query.Where(u => string.Compare(u.email, after) > 0);

            var rows = await query.OrderBy(u => u.email).Take(limit + 1).ToListAsync();
            var page = rows.Take(limit).ToList();
            var claims = new Dictionary<string, List<string>>(StringComparer.Ordinal);
            if (rowId != null)
            {
                var emails = page.Select(u => u.email).ToList();
                foreach (var m in await mappings.Where(m => m.client_id == rowId && emails.Contains(m.email)).ToListAsync())
                    claims[m.email] = m.claims;
            }
            return new
            {
                count = page.Count,
                accounts = page.Select(u => new
                {
                    username = u.email, name = u.name, type = u.type, active = u.is_active, waiting_for_password = u.reset_mode == true ? true : (bool?)null,
                    managed_by = u.home_tenant_id ?? "operator", claims = claims.GetValueOrDefault(u.email)
                }),
                next_cursor = rows.Count > limit ? page[^1].email : null
            };
        }

        /// <summary>Changes to accounts themselves: at the host and tenant levels.</summary>
        public static List<ArkMcpTool> UserAdministration(ArkMcpRole role) => new()
        {
            new ArkMcpTool
            {
                Name = "user_create", Title = "Create an account",
                Description = "Creates an account. It can sign in nowhere until it is given access to an application (access_grant); onboard_user does both. " + ArkMcpOps.CredentialHelp,
                Access = ArkMcpAccess.Manage, Role = role, ReturnsSecret = true,
                Params = Username("An email address, or 2-64 characters of letters, digits, dot, dash or underscore.")
                    .Text("name", "Full name.", maxLength: 120)
                    .Text("credential", ArkMcpOps.CredentialHelp, values: ArkMcpOps.Credentials)
                    .Text("password", "With credential password: at least 10 characters. Prefer a link, so that nobody but the person ever holds it.", maxLength: 200, sensitive: true),
                Run = async call =>
                {
                    var home = call.Endpoint.Tenant == null || call.Endpoint.IsOperatorTenant ? null : call.Endpoint.Tenant.tenant_id;
                    var (user, credential, link) = await ArkMcpOps.CreateUserAsync(call, call.Args.Required("username"), call.Args.Text("name"),
                        call.Args.Text("credential"), call.Args.Text("password"), home);
                    return new
                    {
                        created = ArkMcpOps.UserView(call, user), credential, password_link = link,
                        note = link == null ? null : $"Hand this link to them over a private channel: it sets their password, once, within {call.Config.PasswordLinkLifetimeHours} hours.",
                        next_steps = new[] { new { why = "the account can sign in nowhere yet", tool = "access_grant", arguments = new { username = user.email } } }
                    };
                }
            },
            new ArkMcpTool
            {
                Name = "user_update", Title = "Rename an account's owner",
                Description = "Changes the person's display name. The username is the account and cannot change.",
                Access = ArkMcpAccess.Manage, Role = role, Idempotent = true,
                Params = Username().Text("name", "Full name.", required: true, maxLength: 120),
                Run = async call =>
                {
                    var user = await ArkMcpOps.ManageableUserAsync(call, call.Args.Required("username"));
                    var name = ArkMcpOps.NameOf(call.Args.Required("name"));
                    await call.Db.users.Where(u => u.email == user.email).ExecuteUpdateAsync(s => s.SetProperty(u => u.name, name));
                    call.Da.Log("user_upsert", "mcp", "user updated", $"over mcp : e: {user.email}, name: {name}", "trace",
                        ArkWatchMap.Admin("user.update", Ark.Watch.Core.AuditLevel.Notice, "user", user.email, $"account '{user.email}' changed"));
                    Webhooks.ArkWebhookEvents.Raise(call.Http, Webhooks.ArkWebhookEvents.OperatorTenant(call.Http), Webhooks.ArkWebhookEvents.UserUpdated,
                        new { user = user.email, name, created = false }, user.email);
                    return new { username = user.email, name };
                }
            },
            new ArkMcpTool
            {
                Name = "user_set_active", Title = "Switch an account on or off",
                Description = "Off, the person cannot sign in anywhere on the server, and their sessions and refresh tokens end at once.",
                Access = ArkMcpAccess.Manage, Role = role, Idempotent = true, Destructive = true,
                Params = Username().Flag("active", "true switches it on, false off.", required: true).Text("reason", "Why, for the audit trail.", maxLength: 500),
                Run = async call =>
                {
                    var user = await ArkMcpOps.ManageableUserAsync(call, call.Args.Required("username"));
                    var active = call.Args.Flag("active")!.Value;
                    if (!active && ArkMcpOps.Same(user.email, call.Config.AdminUser?.Username))
                        throw new ArkMcpToolException("operator_account", $"'{user.email}' is the operator's own account; switching it off here would lock the console.");
                    if (!active) await ArkMcpOps.EndSessionsAsync(call, user.email, null, "user_deactivated");
                    await call.Da.SetUserActive(user.email, active);
                    var reason = call.Args.Text("reason");
                    call.Da.Log("user_activation", user.email, active ? "user activated" : "user deactivated", $"details : e: {user.email}, reason: {reason}");
                    Webhooks.ArkWebhookEvents.Raise(call.Http, Webhooks.ArkWebhookEvents.OperatorTenant(call.Http), Webhooks.ArkWebhookEvents.UserActivationChanged,
                        new { user = user.email, is_active = active, reason }, user.email);
                    return new { username = user.email, active };
                }
            },
            new ArkMcpTool
            {
                Name = "user_reset_password", Title = "Reset a password",
                Description = "Returns a one-time link with which the person sets a new password (credential activation_link, the default), emails it, or sets the one given. Ends their sessions unless told not to.",
                Access = ArkMcpAccess.Manage, Role = role, Destructive = true, ReturnsSecret = true,
                Params = Username().Text("credential", "activation_link, email or password.", values: new[] { "activation_link", "email", "password" })
                    .Text("password", "With credential password: at least 10 characters.", maxLength: 200, sensitive: true)
                    .Flag("end_sessions", "Sign them out everywhere (default true)."),
                Run = ArkMcpOps.ResetPasswordAsync
            },
            new ArkMcpTool
            {
                Name = "user_unlock", Title = "Clear a lockout",
                Description = "Forgets the failed sign-in attempts of an account, so a locked one may try again now.",
                Access = ArkMcpAccess.Manage, Role = role, Idempotent = true, Params = Username(),
                Run = async call =>
                {
                    var user = await ArkMcpOps.ManageableUserAsync(call, call.Args.Required("username"));
                    await call.Da.UpdateStatus(user.email, "reset");
                    call.Da.Log("user_unlock", user.email, "lockout cleared", $"over mcp : e: {user.email}");
                    return new { username = user.email, unlocked = true };
                }
            },
            new ArkMcpTool
            {
                Name = "user_sign_out", Title = "Sign somebody out",
                Description = "Ends the person's sessions and refresh tokens, here or on the whole server, and tells the applications that asked to be told. The account stays as it is.",
                Access = ArkMcpAccess.Manage, Role = role, Idempotent = true, Destructive = true, Params = Username(),
                Run = async call =>
                {
                    var user = await ArkMcpOps.VisibleUserAsync(call, call.Args.Required("username"));
                    var ended = await ArkMcpOps.EndSessionsAsync(call, user.email, call.Endpoint.Tenant?.tenant_id, "administrator");
                    return new { username = user.email, sessions_ended = ended, where = call.Endpoint.Tenant?.tenant_id ?? "the whole server" };
                }
            }
        };

        // ---------------------------------------------------------------- access

        static ArkMcpParams GrantParams(bool client) =>
            (client ? new ArkMcpParams().Text("client_id", "The application.", required: true, maxLength: 500) : new ArkMcpParams())
            .Text("username", "Who.", required: true, maxLength: 200)
            .List("claims", "What they may do there, as the application's own claims (for example billing.admin). " +
                            $"{ArkMcpClaims.ClientAdmin} makes them its administrator over MCP, {ArkMcpClaims.TenantAdmin} the tenant's.")
            .Text("confirm", "Asked for when another tenant manages the account, or when an account that exists is made an administrator. The answer says what to put here.", maxLength: 200);

        /// <summary>Who may use an application: at the tenant level any of its applications, at an application its own.</summary>
        public static List<ArkMcpTool> Access(ArkMcpRole role, bool client) => new()
        {
            new ArkMcpTool
            {
                Name = "access_grant", Title = "Give access to an application",
                Description = "Lets somebody who has an account sign in to an application, with the claims given. Claims they already hold there stay. Without this a sign-in fails like a wrong password.",
                Access = ArkMcpAccess.Manage, Role = role, Idempotent = true, Params = GrantParams(client),
                Run = async call =>
                {
                    var app = await ArkMcpOps.TargetAsync(call);
                    if (ArkMcpOps.IsSystem(app) && !call.Caller.Operator)
                        throw new ArkMcpToolException("system_client", "access to the server's own clients is the operator's to give.");
                    var (user, _, _, _) = await ArkMcpOps.PersonAsync(call, call.Args.Required("username"), null, null, null, create: false);
                    var (created, claims) = await ArkMcpOps.GrantAsync(call, user, app, call.Args.List("claims") ?? new(), replace: false, confirm: call.Args.Text("confirm"));
                    return new { username = user.email, managed_by = ArkMcpOps.ManagedBy(user), client_id = app.client_id, access = created ? "granted" : "extended", claims };
                }
            },
            new ArkMcpTool
            {
                Name = "access_set_claims", Title = "Replace what somebody may do",
                Description = "Replaces the claims somebody holds at an application with the ones given. The identity claims every sign-in needs are always kept.",
                Access = ArkMcpAccess.Manage, Role = role, Idempotent = true, Destructive = true, Params = GrantParams(client),
                Run = async call =>
                {
                    var app = await ArkMcpOps.TargetAsync(call);
                    if (ArkMcpOps.IsSystem(app) && !call.Caller.Operator)
                        throw new ArkMcpToolException("system_client", "access to the server's own clients is the operator's to change.");
                    var user = await ArkMcpOps.VisibleUserAsync(call, call.Args.Required("username"));
                    if (await ArkLookup.MappingAsync(call.Db, user.email, app.tenant_id, app.id) == null)
                        throw new ArkMcpToolException("no_access", $"'{user.email}' has no access to '{app.client_id}' yet; give it with access_grant.");
                    var (_, claims) = await ArkMcpOps.GrantAsync(call, user, app, call.Args.List("claims") ?? new(), replace: true, confirm: call.Args.Text("confirm"));
                    return new { username = user.email, managed_by = ArkMcpOps.ManagedBy(user), client_id = app.client_id, claims };
                }
            },
            new ArkMcpTool
            {
                Name = "access_revoke", Title = "Take access away",
                Description = "Removes somebody's access to an application and withdraws the refresh tokens it holds for them. The account stays.",
                Access = ArkMcpAccess.Manage, Role = role, Destructive = true, Idempotent = true,
                Params = (client ? new ArkMcpParams().Text("client_id", "The application.", required: true, maxLength: 500) : new ArkMcpParams())
                    .Text("username", "Who.", required: true, maxLength: 200),
                Run = async call =>
                {
                    var app = await ArkMcpOps.TargetAsync(call);
                    var user = await ArkMcpOps.VisibleUserAsync(call, call.Args.Required("username"));
                    await ArkMcpOps.RevokeAsync(call, user.email, app);
                    return new { username = user.email, client_id = app.client_id, access = "revoked" };
                }
            },
            new ArkMcpTool
            {
                Name = "onboard_user", Title = "Add a person to an application",
                Description = "Everything a person needs to sign in to an application, in one call: creates the account if there is none, and gives it access with the claims given. " +
                              "An account that exists is left as it is. " + ArkMcpOps.CredentialHelp,
                Access = ArkMcpAccess.Manage, Role = role, ReturnsSecret = true,
                Params = GrantParams(client).Text("name", "Full name, for a new account.", maxLength: 120)
                    .Text("credential", ArkMcpOps.CredentialHelp, values: ArkMcpOps.Credentials)
                    .Text("password", "With credential password: at least 10 characters.", maxLength: 200, sensitive: true),
                Run = async call =>
                {
                    var app = await ArkMcpOps.TargetAsync(call);
                    if (ArkMcpOps.IsSystem(app) && !call.Caller.Operator)
                        throw new ArkMcpToolException("system_client", "access to the server's own clients is the operator's to give.");
                    var claims = call.Args.List("claims") ?? new List<string>();
                    ArkMcpOps.CheckClaims(call, claims); // before an account is made for nothing
                    var (user, created, credential, link) = await ArkMcpOps.PersonAsync(call, call.Args.Required("username"),
                        call.Args.Text("name"), call.Args.Text("credential"), call.Args.Text("password"), create: true);
                    var granted = await ArkMcpOps.GrantAsync(call, user, app, claims, replace: false, made: created, confirm: call.Args.Text("confirm"));
                    return new
                    {
                        username = user.email, account = created ? "created" : "already existed", managed_by = ArkMcpOps.ManagedBy(user), credential, password_link = link,
                        client_id = app.client_id, access = granted.Created ? "granted" : "extended", claims = granted.Claims,
                        note = link == null ? null : $"Hand this link to them over a private channel: it sets their password, once, within {call.Config.PasswordLinkLifetimeHours} hours."
                    };
                }
            }
        };

        // ---------------------------------------------------------------- audit

        public static ArkMcpTool Audit(ArkMcpRole role) => new()
        {
            Name = "audit_search", Title = "Look into the audit trail",
            Description = "Recent events, newest first: sign-ins, refusals, tokens, and every change made in the console, the API or over MCP. " +
                          "Below the host level, the lines that name this tenant or application.",
            Access = ArkMcpAccess.Read, Role = role, Params = ArkMcpOps.AuditParams(), Run = ArkMcpOps.AuditAsync
        };
    }
}
