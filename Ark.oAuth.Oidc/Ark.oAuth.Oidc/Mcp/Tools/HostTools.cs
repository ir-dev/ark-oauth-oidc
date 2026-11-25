using System.Text.RegularExpressions;
using Ark.oAuth.Oidc.Protocol;
using Ark.oAuth.Oidc.Webhooks;
using Microsoft.EntityFrameworkCore;

namespace Ark.oAuth.Oidc.Mcp.Tools
{
    /// <summary><c>/ark-idp/mcp</c> on a configured server: what belongs to no one tenant. For the operator.</summary>
    internal static class HostTools
    {
        public const string Instructions =
            "You run an identity server as its operator. Begin with host_overview: it shows the server's health, every tenant, what is wrong, and the next steps.\n" +
            "tenant_create adds a tenant and returns the credential and the MCP address it is administered with; that is where its applications and people are managed, not here. " +
            "Accounts, scopes and claims are shared by all tenants, so changing one here changes it for everybody.\n" +
            "Secrets and password links are returned once. Store or hand them over first, and do not repeat them in conversation. Get a person's agreement before anything you are asked to confirm.";

        const ArkMcpRole Operator = ArkMcpRole.Operator;

        static readonly Regex TenantId = new("^[A-Za-z0-9][A-Za-z0-9_-]{1,62}$", RegexOptions.CultureInvariant);

        /// <summary>
        /// First path segments this server uses itself: a tenant of that name would be unreachable.
        /// The last three are what the audit trail calls the server's own doings. A tenant that has
        /// one of them already goes on working; a new one is not made.
        /// </summary>
        static readonly string[] Reserved = { "ark-idp", "ark-admin", "api", "oauth", "admin", "signin-oidc", "signout-callback-oidc", "host", "mcp", "v1" };

        static bool HasWebhooks(ArkMcpCall call) => call.Services.GetService(typeof(ArkWebhookRegistry)) != null;

        public static readonly IReadOnlyList<ArkMcpTool> All = Build();

        static List<ArkMcpTool> Build()
        {
            var tools = new List<ArkMcpTool>
            {
                CommonTools.WhoAmI,
                new()
                {
                    Name = "host_overview", Title = "The state of the server",
                    Description = "Start here. Version, health, every tenant with its counts, what is switched on, what is wrong, and the next steps in order.",
                    Role = Operator, Run = OverviewAsync
                },

                // ------------------------------------------------ tenants
                new()
                {
                    Name = "tenant_list", Title = "List tenants", Description = "Every tenant, with its issuer, its MCP address and how much it holds.", Role = Operator,
                    Run = async call => new { tenants = await TenantsAsync(call) }
                },
                new()
                {
                    Name = "tenant_get", Title = "Look a tenant up", Description = "One tenant: its addresses, and how to connect an agent to it.", Role = Operator,
                    Params = new ArkMcpParams().Text("tenant_id", "The tenant.", required: true, maxLength: 63),
                    Run = async call =>
                    {
                        var tenant = await TenantAsync(call, call.Args.Required("tenant_id"));
                        return new { tenant = ArkMcpOps.TenantView(call, tenant), mcp = Handover(call, tenant) };
                    }
                },
                new()
                {
                    Name = "tenant_create", Title = "Create a tenant",
                    Description = "Creates a tenant with a signing key of its own and, unless told not to, a machine client to administer it with. The secret is returned once, with the tenant's MCP configuration. " +
                                  "The id becomes part of every token's issuer and cannot change.",
                    Access = ArkMcpAccess.Manage, Role = Operator, ReturnsSecret = true,
                    Params = new ArkMcpParams().Text("tenant_id", "2-63 letters, digits, '_' or '-'.", required: true, maxLength: 63)
                        .Text("display", "Display name.", maxLength: 120).Text("name", "Name.", maxLength: 120)
                        .Flag("machine_client", "Create its machine client (default true)."),
                    Run = CreateTenantAsync
                },
                new()
                {
                    Name = "tenant_update", Title = "Rename a tenant", Description = "Changes a tenant's name and display name.",
                    Access = ArkMcpAccess.Manage, Role = Operator, Idempotent = true,
                    Params = new ArkMcpParams().Text("tenant_id", "The tenant.", required: true, maxLength: 63)
                        .Text("display", "Display name.", maxLength: 120).Text("name", "Name.", maxLength: 120),
                    Run = call => UpdateTenantAsync(call, call.Args.Required("tenant_id"))
                },
                new()
                {
                    Name = "tenant_machine_secret_reset", Title = "Give a tenant a new machine credential",
                    Description = "Creates the tenant's machine client if it has none, and returns a new secret for it, once. The old one stops working at once.",
                    Access = ArkMcpAccess.Manage, Role = Operator, Destructive = true, ReturnsSecret = true,
                    Params = new ArkMcpParams().Text("tenant_id", "The tenant.", required: true, maxLength: 63).Text("confirm", "The tenant id again.", maxLength: 63),
                    Run = async call =>
                    {
                        var tenant = await TenantAsync(call, call.Args.Required("tenant_id"));
                        var machineId = ArkManagementAuth.MachineClientId(tenant.tenant_id);
                        var machine = await ArkLookup.ClientAsync(call.Db, tenant.tenant_id, machineId);
                        if (machine is { has_client_secret: true })
                            call.Confirm(tenant.tenant_id, $"Whatever uses '{machineId}' now stops working until it has the new secret.");
                        machine ??= await call.Da.UpsertClient(ArkExtn.BuildMachineClient(tenant.tenant_id, HostName(call)));
                        call.Db.ChangeTracker.Clear();
                        machine = await ArkLookup.ClientAsync(call.Db, tenant.tenant_id, machineId);
                        var secret = await ArkMcpOps.ResetSecretAsync(call, machine!);
                        return new { tenant_id = tenant.tenant_id, client_id = machineId, client_secret = secret, note = "Shown once; only its hash is stored.", mcp = Handover(call, tenant) };
                    }
                }
            };

            tools.AddRange(CommonTools.Users(Operator));
            tools.AddRange(CommonTools.UserAdministration(Operator));
            tools.AddRange(new ArkMcpTool[]
            {
                new()
                {
                    Name = "user_set_home", Title = "Say which tenant manages an account",
                    Description = "Hands the management of an account to a tenant's administrators: setting its password, switching it off. Empty hands it back to the operator. Access is not affected.",
                    Access = ArkMcpAccess.Manage, Role = Operator, Idempotent = true,
                    Params = new ArkMcpParams().Text("username", "The account.", required: true, maxLength: 200)
                        .Text("tenant_id", "The tenant, or empty for the operator.", maxLength: 63),
                    Run = async call =>
                    {
                        var user = await ArkMcpOps.VisibleUserAsync(call, call.Args.Required("username"));
                        if (ArkMcpOps.Same(user.email, call.Config.AdminUser?.Username))
                            throw new ArkMcpToolException("operator_account", "the operator's own account is managed by nobody else.");
                        var home = call.Args.Text("tenant_id") is { } t ? (await TenantAsync(call, t)).tenant_id : null;
                        await call.Db.users.Where(u => u.email == user.email).ExecuteUpdateAsync(s => s.SetProperty(u => u.home_tenant_id, home));
                        call.Da.Log("user_upsert", "mcp", "user updated", $"over mcp : e: {user.email}, home: {home}", "trace",
                            ArkWatchMap.Admin("user.update", Ark.Watch.Core.AuditLevel.Security, "user", user.email, $"account '{user.email}' is now managed by {home ?? "the operator"}", home).With("home_tenant", home));
                        return new { username = user.email, managed_by = home ?? "operator" };
                    }
                },

                // ------------------------------------------------ catalogues
                new() { Name = "scope_list", Title = "Scopes", Description = "Every scope the server issues, and the identity claims it unlocks.", Role = Operator, Run = ScopesAsync },
                new()
                {
                    Name = "scope_save", Title = "Add or change a scope",
                    Description = "Adds a scope, or changes one, for every tenant. An application may request it once it is on that application's list. Permissions of an application belong in claims, not scopes.",
                    Access = ArkMcpAccess.Manage, Role = Operator, Idempotent = true,
                    Params = new ArkMcpParams().Text("name", "Its name in requests.", required: true, pattern: "^[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}$", maxLength: 100)
                        .Text("display", "Name on the consent page.", maxLength: 120).Text("description", "What it lets an application do, on the consent page.", maxLength: 500)
                        .List("claims", "Identity claims it unlocks.").Flag("is_default", "Granted when an application asks for no scope.").Flag("require_consent", "Shown on the consent page (default true)."),
                    Run = SaveScopeAsync
                },
                new()
                {
                    Name = "scope_delete", Title = "Delete a scope", Description = "Removes a scope from every tenant. Applications that request it are refused. Protocol scopes cannot be deleted.",
                    Access = ArkMcpAccess.Manage, Role = Operator, Destructive = true,
                    Params = new ArkMcpParams().Text("name", "The scope.", required: true, maxLength: 100).Text("confirm", "Its name again.", maxLength: 100),
                    Run = async call =>
                    {
                        var name = call.Args.Required("name");
                        var scope = await call.Db.scopes.AsNoTracking().FirstOrDefaultAsync(s => s.name == name)
                            ?? throw new ArkMcpToolException("unknown_scope", $"there is no scope '{name}'.");
                        call.Confirm(name, "Applications that request this scope are refused from now on.");
                        await call.Da.DeleteScope(scope);
                        call.Da.Log("scope_delete", name, "Scope deleted success", $"over mcp : n: {name}");
                        return new { name, deleted = true };
                    }
                },
                new() { Name = "claim_list", Title = "Claims", Description = "The claim names in use, shared by every tenant.", Role = Operator, Run = ClaimsAsync },
                new()
                {
                    Name = "claim_save", Title = "Add or name a claim", Description = "Adds a claim to the catalogue, or changes its display name.",
                    Access = ArkMcpAccess.Manage, Role = Operator, Idempotent = true,
                    Params = new ArkMcpParams().Text("key", "The claim as it appears in tokens.", required: true, maxLength: 200).Text("display", "Its name in the console.", maxLength: 200),
                    Run = async call =>
                    {
                        var key = call.Args.Required("key");
                        call.Db.ChangeTracker.Clear();
                        await call.Da.UpsertClaim(new ArkClaim { key = key, display = call.Args.Text("display") ?? key });
                        call.Da.Log("claim_upsert", key, "Claim updated success", $"over mcp : k: {key}");
                        return new { key, saved = true };
                    }
                },
                new()
                {
                    Name = "claim_delete", Title = "Delete a claim", Description = "Removes a claim from the catalogue. People who hold it keep it until their access is changed.",
                    Access = ArkMcpAccess.Manage, Role = Operator, Destructive = true,
                    Params = new ArkMcpParams().Text("key", "The claim.", required: true, maxLength: 200).Text("confirm", "It again.", maxLength: 200),
                    Run = async call =>
                    {
                        var key = call.Args.Required("key");
                        var claim = await call.Db.claims.AsNoTracking().FirstOrDefaultAsync(c => c.key == key)
                            ?? throw new ArkMcpToolException("unknown_claim", $"there is no claim '{key}'.");
                        call.Confirm(key, "The claim disappears from the catalogue.");
                        call.Db.ChangeTracker.Clear();
                        await call.Da.DeleteClaim(claim);
                        call.Da.Log("claim_delete", key, "Claim deleted success", $"over mcp : k: {key}");
                        return new { key, deleted = true };
                    }
                },

                // ------------------------------------------------ the server
                CommonTools.Audit(Operator),
                new()
                {
                    Name = "audit_trail_status", Title = "The external audit trail", Description = "Whether events are being sent to an ARK-RAPID Watch server, and how that is going. Never its key.", Role = Operator,
                    Run = call => Task.FromResult<object>((call.Services.GetService(typeof(ArkWatchAudit)) as ArkWatchAudit)?.Status() ?? new ArkWatchStatus { reason = "not registered" })
                },
                new()
                {
                    Name = "settings_get", Title = "The server's settings", Description = "The settings in force, secrets only as set or not. They are changed in configuration, not here.", Role = Operator,
                    Run = call => Task.FromResult(Settings(call))
                }
            });

            tools.AddRange(Webhooks());
            return tools;
        }

        // ---------------------------------------------------------------- tenants

        static async Task<ArkTenant> TenantAsync(ArkMcpCall call, string id)
        {
            call.Touches("tenant", id);
            return await ArkLookup.TenantAsync(call.Db, id) ?? throw new ArkMcpToolException("unknown_tenant", $"there is no tenant '{id}'.");
        }

        static string HostName(ArkMcpCall call) => Uri.TryCreate(call.Endpoint.Root, UriKind.Absolute, out var u) ? u.Host : "";

        static async Task<List<object>> TenantsAsync(ArkMcpCall call)
        {
            var tenants = await call.Db.tenants.AsNoTracking().OrderBy(t => t.tenant_id).ToListAsync();
            var clients = await call.Db.clients.AsNoTracking().GroupBy(c => c.tenant_id).Select(g => new { g.Key, Count = g.Count() }).ToListAsync();
            var people = await call.Db.user_client_claims.AsNoTracking().GroupBy(m => m.tenant_id)
                .Select(g => new { g.Key, Count = g.Select(m => m.email).Distinct().Count() }).ToListAsync();
            return tenants.Select(t => (object)new
            {
                tenant = ArkMcpOps.TenantView(call, t),
                applications = clients.FirstOrDefault(c => c.Key == t.tenant_id)?.Count ?? 0,
                people = people.FirstOrDefault(p => p.Key == t.tenant_id)?.Count ?? 0
            }).ToList();
        }

        /// <summary>The address and connection settings an agent of that tenant needs.</summary>
        static object Handover(ArkMcpCall call, ArkTenant tenant)
        {
            var endpoint = new ArkMcpEndpoint
            {
                Level = ArkMcpLevel.Tenant, Tenant = tenant, Config = call.Config, Root = call.Endpoint.Root,
                Resource = ArkMcpResources.Tenant(call.Endpoint.Root, tenant.tenant_id)
            };
            return new { url = endpoint.Resource, server_card = $"{endpoint.Resource}/server-card", config = ArkMcpDocuments.Config(endpoint) };
        }

        static async Task<object> CreateTenantAsync(ArkMcpCall call)
        {
            var id = call.Args.Required("tenant_id");
            call.Touches("tenant", id);
            if (!TenantId.IsMatch(id))
                throw new ArkMcpToolException("invalid_tenant", "tenant_id: 2-63 letters, digits, '_' or '-', starting with a letter or digit.");
            if (Reserved.Contains(id, StringComparer.OrdinalIgnoreCase))
                throw new ArkMcpToolException("reserved_tenant", $"'{id}' is a name the server uses itself. Choose another id.");
            if (await ArkLookup.TenantAsync(call.Db, id) != null)
                throw new ArkMcpToolException("tenant_exists", $"tenant '{id}' already exists.");

            var tenant = await call.Da.UpsertTenant(new ArkTenant
            {
                tenant_id = id,
                name = ArkMcpOps.NameOf(call.Args.Text("name") ?? id),
                display = ArkMcpOps.NameOf(call.Args.Text("display") ?? call.Args.Text("name") ?? id),
                // The audience is its own, not the one the console gives every tenant it adds: a
                // token made at one tenant must not read as addressed to another.
                audience = $"{call.Endpoint.Root}/{id}"
            });
            call.Da.Log("tenant_upsert", id, "Tenant updated success", $"created over mcp : ti: {id}, n: {tenant.name}, d: {tenant.display}");
            ArkWebhookEvents.Raise(call.Http, ArkWebhookEvents.OperatorTenant(call.Http), ArkWebhookEvents.TenantUpdated,
                new { tenant_id = id, name = tenant.name, display = tenant.display, created = true }, id);
            call.Db.ChangeTracker.Clear();
            await call.Get<ArkKeyService>().GetActiveKeyAsync(id);

            string? secret = null;
            if (call.Args.Flag("machine_client") != false)
            {
                call.Db.ChangeTracker.Clear();
                var machine = await call.Da.UpsertClient(ArkExtn.BuildMachineClient(id, HostName(call)));
                call.Db.ChangeTracker.Clear();
                secret = await ArkMcpOps.ResetSecretAsync(call, (await ArkLookup.ClientAsync(call.Db, id, machine.client_id))!);
            }
            return new
            {
                tenant = ArkMcpOps.TenantView(call, tenant),
                machine_client = secret == null ? null : new { client_id = ArkManagementAuth.MachineClientId(id), client_secret = secret, note = "Shown once; only its hash is stored. Whoever holds it administers this tenant." },
                mcp = Handover(call, tenant),
                next_steps = new[]
                {
                    "Store the machine credential.",
                    $"Connect to {ArkMcpResources.Tenant(call.Endpoint.Root, id)} with it and call tenant_overview: applications and people of this tenant are managed there."
                }
            };
        }

        public static async Task<object> UpdateTenantAsync(ArkMcpCall call, string id)
        {
            var tenant = await TenantAsync(call, id);
            if (!call.Args.Has("name") && !call.Args.Has("display")) throw new ArkMcpToolException("invalid_arguments", "give name or display.");
            if (call.Args.Text("name") is { } name) tenant.name = ArkMcpOps.NameOf(name);
            if (call.Args.Text("display") is { } display) tenant.display = ArkMcpOps.NameOf(display);
            call.Db.ChangeTracker.Clear();
            var saved = await call.Da.UpsertTenant(tenant);
            call.Da.Log("tenant_upsert", saved.tenant_id, "Tenant updated success", $"over mcp : ti: {saved.tenant_id}, n: {saved.name}, d: {saved.display}");
            ArkWebhookEvents.Raise(call.Http, ArkWebhookEvents.OperatorTenant(call.Http), ArkWebhookEvents.TenantUpdated,
                new { tenant_id = saved.tenant_id, name = saved.name, display = saved.display }, saved.tenant_id);
            return new { tenant = ArkMcpOps.TenantView(call, saved) };
        }

        // ---------------------------------------------------------------- overview

        static async Task<object> OverviewAsync(ArkMcpCall call)
        {
            var config = call.Config;
            var oidc = config.Oidc ?? new ArkOidcOptions();
            var now = DateTime.UtcNow;
            var day = now.AddHours(-24);
            var tenants = await TenantsAsync(call);
            var accounts = await call.Db.users.CountAsync();
            var waiting = await call.Db.users.CountAsync(u => u.reset_mode == true);
            var sessions = await call.Db.sessions.CountAsync(s => !s.revoked && s.expires_at > now);
            var faults = await call.Db.audit_trace.CountAsync(a => a.log_type == "error" && a.at >= day);
            var machineId = ArkManagementAuth.MachineClientId(call.Endpoint.OperatorTenantId);
            var machine = await ArkLookup.ClientAsync(call.Db, call.Endpoint.OperatorTenantId, machineId);
            var watch = call.Services.GetService(typeof(ArkWatchAudit)) as ArkWatchAudit;
            var status = watch?.Status();
            var defaultPw = (config.DefaultPw ?? "").Trim();
            var hasDefault = defaultPw.Length > 0 && !(defaultPw.StartsWith("<<") && defaultPw.EndsWith(">>"));
            var email = !string.IsNullOrWhiteSpace(config.EmailConfig?.smtp);

            var findings = new List<ArkMcpOps.Finding>();
            void Find(string severity, string code, string message, string? tool = null, object? arguments = null) =>
                findings.Add(new ArkMcpOps.Finding(severity, code, "server", message, tool, arguments));
            if (call.Endpoint.Root.StartsWith("http:", StringComparison.OrdinalIgnoreCase) && Uri.TryCreate(call.Endpoint.Root, UriKind.Absolute, out var root) && !root.IsLoopback)
                Find("error", "plain_http", "the public address is plain http: passwords and tokens cross the network unencrypted. Set ark_oauth_server:BaseUrl to an https address.");
            if (string.IsNullOrWhiteSpace(config.BaseUrl))
                Find("warning", "no_base_url", "ark_oauth_server:BaseUrl is not set, so the issuer follows whatever Host a request was sent to. Set it.");
            if (machine is not { has_client_secret: true })
                Find("warning", "no_machine_secret", $"'{machineId}' has no secret, so nothing can administer the server unattended.", "tenant_machine_secret_reset", new { tenant_id = call.Endpoint.OperatorTenantId, confirm = call.Endpoint.OperatorTenantId });
            if (!email && config.EffectiveUserPasswordMode == ArkUserPasswordMode.EmailBased)
                Find("error", "email_needed", "UserPasswordMode is email_based and no SMTP server is configured, so new people never get their activation email.");
            if (!email)
                Find("info", "email_off", "this server sends no email; new people get their one-time link from whoever adds them.");
            if (!hasDefault && config.EffectiveUserPasswordMode == ArkUserPasswordMode.AdminManaged)
                Find("info", "no_default_password", "there is no default password, so accounts added in the console or through the provisioning API are refused until one is set. Accounts added over MCP get a one-time link instead.");
            if (status is { enabled: true } && status.health != "ok")
                Find("warning", "audit_trail", $"the external audit trail is {status.health}.", "audit_trail_status");
            if (faults > 0)
                Find("warning", "faults", $"{faults} fault(s) were logged in the last 24 hours.", "audit_search", new { hours = 24, contains = "" });
            if (!oidc.EnableDynamicRegistration)
                Find("info", "no_dynamic_registration", "agents cannot register themselves: ark_oauth_server:Oidc:EnableDynamicRegistration is off. client_create at the tenant level registers for them.");
            if (oidc.MaxFailedSignIns <= 0)
                Find("warning", "no_lockout", "accounts are never locked after failed sign-ins (Oidc:MaxFailedSignIns is 0).");
            if (config.Provider is null or "" or "sqlite")
                Find("info", "sqlite", "the database is SQLite: one instance only, and the file has to be on persistent storage and backed up.");

            return new
            {
                server = new
                {
                    version = ArkWatchAudit.PackageVersion, address = call.Endpoint.Root, operator_tenant = call.Endpoint.OperatorTenantId,
                    database = string.IsNullOrWhiteSpace(config.Provider) ? "sqlite" : config.Provider, time = now
                },
                counts = new { tenants = tenants.Count, accounts, waiting_for_password = waiting, live_sessions = sessions, faults_last_24h = faults },
                switched_on = new
                {
                    dynamic_registration = oidc.EnableDynamicRegistration, device_sign_in = oidc.EnableDeviceFlow, pushed_authorization_requests = oidc.EnablePushedAuthorizationRequests,
                    agent_to_agent = oidc.EnableA2A, back_channel_logout = oidc.EnableBackChannelLogout, email, webhooks = HasWebhooks(call),
                    audit_trail = status?.enabled ?? false, trace = config.EnableLogTrace, changes_over_mcp = !config.Mcp.ReadOnly
                },
                tenants,
                findings = findings.Select(ArkMcpOps.FindingView),
                next_steps = ArkMcpOps.NextSteps(findings)
            };
        }

        static object Settings(ArkMcpCall call)
        {
            var c = call.Config;
            static string Is(string? v) => string.IsNullOrWhiteSpace(v) ? "not set" : "set";
            return new
            {
                note = "Changed in settings.json, environment variables or the host's own configuration; see the README. Secrets are shown only as set.",
                server = new { c.TenantId, c.BaseUrl, c.BasePath, Provider = string.IsNullOrWhiteSpace(c.Provider) ? "sqlite" : c.Provider, c.EnableLogTrace, c.ShowPoweredBy, c.PasswordLinkLifetimeHours },
                people = new { UserPasswordMode = c.EffectiveUserPasswordMode.ToString(), DefaultPw = Is(c.DefaultPw), AdminUser = c.AdminUser?.Username },
                email = new { smtp = c.EmailConfig?.smtp, c.EmailConfig?.port, c.EmailConfig?.from, password = Is(c.EmailConfig?.pw) },
                oidc = c.Oidc,
                management = new { MachineClientSecret = Is(c.Management?.MachineClientSecret), c.Management?.OperatorDeviceClients },
                mcp = c.Mcp,
                audit_trail = new { c.Watch?.Enabled, c.Watch?.Endpoint, ApiKey = Is(c.Watch?.ApiKey), c.Watch?.Application, c.Watch?.Environment }
            };
        }

        // ---------------------------------------------------------------- catalogues

        public static async Task<object> ScopesAsync(ArkMcpCall call) => new
        {
            scopes = (await ArkIdpCache.ScopesAsync(call.Db)).OrderBy(s => s.name, StringComparer.Ordinal).Select(s => new
            {
                name = s.name, display = s.display, description = s.description, claims = s.claims, is_default = s.is_default, require_consent = s.require_consent,
                protocol = s.is_protocol ? true : (bool?)null,
                authority_over_the_server = ArkClaimsService.PrivilegedScopes.Contains(s.name, StringComparer.OrdinalIgnoreCase) ? true : (bool?)null
            })
        };

        public static async Task<object> ClaimsAsync(ArkMcpCall call) => new
        {
            claims = await call.Db.claims.AsNoTracking().OrderBy(c => c.key).Select(c => new { c.key, c.display }).ToListAsync(),
            administrators = new[]
            {
                new { claim = ArkMcpClaims.ClientAdmin, means = "administers the application it is held at, over MCP" },
                new { claim = ArkMcpClaims.TenantAdmin, means = "administers the tenant, through the application it is held at" },
                new { claim = ArkMcpClaims.HostAdmin, means = "operates the server; counts only in the operator tenant" }
            }
        };

        static async Task<object> SaveScopeAsync(ArkMcpCall call)
        {
            var name = call.Args.Required("name");
            var existing = await call.Db.scopes.AsNoTracking().FirstOrDefaultAsync(s => s.name == name);
            if (existing is { is_protocol: true })
                throw new ArkMcpToolException("protocol_scope", $"'{name}' is one of the server's own scopes and cannot be changed.");
            var scope = existing ?? new ArkScope { name = name, require_consent = true };
            if (call.Args.Text("display") is { } display) scope.display = ArkMcpOps.NameOf(display);
            if (call.Args.Text("description") is { } description) scope.description = description;
            if (call.Args.Has("claims")) scope.claims = call.Args.List("claims")!;
            if (call.Args.Flag("is_default") is { } isDefault) scope.is_default = isDefault;
            if (call.Args.Flag("require_consent") is { } consent) scope.require_consent = consent;
            scope.display ??= name;
            call.Db.ChangeTracker.Clear();
            await call.Da.UpsertScope(scope);
            call.Da.Log("scope_upsert", name, "Scope updated success", $"over mcp : n: {name}, claims: {scope.claims_}");
            return new { scope = new { scope.name, scope.display, scope.description, scope.claims, scope.is_default, scope.require_consent }, created = existing == null };
        }

        // ---------------------------------------------------------------- webhooks

        /// <summary>
        /// The webhook module, when the host added it. Operator only, at the host level: an endpoint
        /// sends who signed in, and from where, to an address of the caller's choosing.
        /// </summary>
        static IEnumerable<ArkMcpTool> Webhooks()
        {
            ArkWebhookService Service(ArkMcpCall call) => call.Get<ArkWebhookService>();
            string Who(ArkMcpCall call) => call.Caller.Subject;
            void Record(ArkMcpCall call, string key, string? reference, string message)
            {
                try { call.Da.Record(key, reference, message, "over mcp", Who(call), ArkWatchAudit.Address(call.Http)); } catch { }
            }
            ArkMcpParams Id() => new ArkMcpParams().Text("id", "The webhook's id.", required: true, maxLength: 100);

            return new ArkMcpTool[]
            {
                new()
                {
                    Name = "webhook_list", Title = "Webhooks", Description = "The webhooks of the server or of one tenant, with their state, and the events there are.", Role = Operator, When = HasWebhooks,
                    Params = new ArkMcpParams().Text("tenant_id", "Only this tenant's.", maxLength: 63),
                    Run = async call => new { webhooks = await Service(call).ListAsync(call.Args.Text("tenant_id")), events = ArkWebhookEvents.Catalogue.Select(e => new { type = e.Type, group = e.Group, description = e.Description }) }
                },
                new()
                {
                    Name = "webhook_save", Title = "Add or change a webhook",
                    Description = "Sends the chosen events of a tenant to an address, signed. The signing secret of a new one is returned once. Authentication to the receiver and sharding are set in the console.",
                    Access = ArkMcpAccess.Manage, Role = Operator, When = HasWebhooks, OpenWorld = true, ReturnsSecret = true,
                    Params = new ArkMcpParams().Text("id", "An existing webhook, to change it.", maxLength: 100).Text("tenant_id", "Whose events.", maxLength: 63)
                        .Text("name", "Its name.", maxLength: 120).Text("description", "What it is for.", maxLength: 500).Text("url", "Where to send them (https).")
                        .List("events", "Event types, or * for all.").Text("status", "On create: active or paused.", values: new[] { "active", "paused" }),
                    Run = async call =>
                    {
                        var request = new ArkWebhookUpsertRequest
                        {
                            id = call.Args.Text("id"), tenant_id = call.Args.Text("tenant_id"), name = call.Args.Text("name"), description = call.Args.Text("description"),
                            url = call.Args.Text("url"), events = call.Args.List("events"), status = call.Args.Text("status")
                        };
                        if (request.id != null)
                        {
                            // A change over MCP carries only what was given; the rest is as stored.
                            var now = System.Text.Json.JsonSerializer.SerializeToElement(await Service(call).GetAsync(request.id), ArkMcpJson.Options);
                            string? Stored(string name) => now.TryGetProperty(name, out var v) && v.ValueKind == System.Text.Json.JsonValueKind.String ? v.GetString() : null;
                            request.tenant_id ??= Stored("tenant_id");
                            request.name ??= Stored("name");
                            request.description ??= Stored("description");
                            request.url ??= Stored("url");
                            request.events ??= now.TryGetProperty("events", out var ev) && ev.ValueKind == System.Text.Json.JsonValueKind.Array
                                ? ev.EnumerateArray().Select(x => x.GetString() ?? "").ToList() : null;
                        }
                        var (endpoint, secret, created) = await Service(call).UpsertAsync(request, Who(call));
                        Record(call, created ? "webhook_create" : "webhook_update", request.id ?? "(new)", $"webhook '{request.name}' {(created ? "created" : "updated")}");
                        return new { webhook = endpoint, signing_secret = secret, created };
                    }
                },
                new()
                {
                    Name = "webhook_set_status", Title = "Pause, resume or disable a webhook", Description = "pause and resume keep what is waiting; disable moves it to the dead letters.",
                    Access = ArkMcpAccess.Manage, Role = Operator, When = HasWebhooks, Idempotent = true,
                    Params = Id().Text("action", "What to do.", required: true, values: new[] { "pause", "resume", "enable", "disable" }),
                    Run = async call =>
                    {
                        var id = call.Args.Required("id");
                        var result = await Service(call).SetStatusAsync(new ArkWebhookStatusRequest { id = id, action = call.Args.Required("action") }, Who(call));
                        Record(call, "webhook_status", id, $"webhook {call.Args.Text("action")}");
                        return new { webhook = result };
                    }
                },
                new()
                {
                    Name = "webhook_test", Title = "Test a webhook", Description = "Sends one test event to it and says what came back.",
                    Access = ArkMcpAccess.Manage, Role = Operator, When = HasWebhooks, OpenWorld = true, Params = Id(),
                    Run = async call => new { result = await Service(call).TestAsync(call.Args.Required("id"), Who(call)) }
                },
                new()
                {
                    Name = "webhook_delete", Title = "Delete a webhook", Description = "Removes it. Its history stays unless purge is set.",
                    Access = ArkMcpAccess.Manage, Role = Operator, When = HasWebhooks, Destructive = true,
                    Params = Id().Flag("purge", "Also remove its deliveries and dead letters.").Text("confirm", "Its id again.", maxLength: 100),
                    Run = async call =>
                    {
                        var id = call.Args.Required("id");
                        call.Confirm(id, "Events stop being sent there.");
                        var result = await Service(call).DeleteAsync(new ArkWebhookIdRequest { id = id, purge = call.Args.Flag("purge") ?? false }, Who(call));
                        Record(call, "webhook_delete", id, "webhook deleted");
                        return new { result };
                    }
                },
                new()
                {
                    Name = "webhook_deliveries", Title = "Webhook deliveries", Description = "What was sent, what is waiting and what failed, newest first.", Role = Operator, When = HasWebhooks,
                    Params = new ArkMcpParams().Text("id", "Only this webhook's.", maxLength: 100).Text("tenant_id", "Only this tenant's.", maxLength: 63)
                        .Text("status", "Only in this state.", maxLength: 40).Int("limit", "How many (default 50).", min: 1, max: 200),
                    Run = async call => new { deliveries = await Service(call).DeliveriesAsync(call.Args.Text("id"), call.Args.Text("tenant_id"), call.Args.Text("status"), call.Args.Int("limit") ?? 50, null) }
                },
                new()
                {
                    Name = "webhook_dead_letters", Title = "Webhook dead letters", Description = "Events that could not be delivered.", Role = Operator, When = HasWebhooks,
                    Params = new ArkMcpParams().Text("id", "Only this webhook's.", maxLength: 100).Text("tenant_id", "Only this tenant's.", maxLength: 63).Int("limit", "How many (default 100).", min: 1, max: 500),
                    Run = async call => new { dead_letters = await Service(call).DeadLettersAsync(call.Args.Text("id"), call.Args.Text("tenant_id"), false, call.Args.Int("limit") ?? 100) }
                },
                new()
                {
                    Name = "webhook_replay_dead_letters", Title = "Send dead letters again", Description = "Queues every open dead letter of a webhook for delivery again.",
                    Access = ArkMcpAccess.Manage, Role = Operator, When = HasWebhooks, OpenWorld = true, Params = Id(),
                    Run = async call =>
                    {
                        var id = call.Args.Required("id");
                        var result = await Service(call).ReplayDeadLettersAsync(new ArkWebhookRowsRequest { endpoint_id = id }, Who(call));
                        Record(call, "webhook_dlq_replay", id, "dead letters replayed");
                        return new { result };
                    }
                }
            };
        }
    }
}
