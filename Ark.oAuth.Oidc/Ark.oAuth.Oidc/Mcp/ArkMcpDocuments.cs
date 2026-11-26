using System.Text.Json.Nodes;

namespace Ark.oAuth.Oidc.Mcp
{
    /// <summary>
    /// The public documents beside each MCP endpoint: what it is, and how to connect to it.
    ///
    ///   * <c>{endpoint}/server-card</c> — discovery: the server card of SEP-2127, at the location
    ///     it recommends. The card format is still settling, so what is ours is under <c>_meta</c>.
    ///   * <c>{endpoint}/config</c> — the block an MCP client's configuration takes, and how an
    ///     unattended agent gets its token.
    ///   * <c>/.well-known/oauth-protected-resource…</c> — RFC 9728, once there is an issuer.
    ///
    /// Nothing in them is secret, and nothing in them depends on who asks.
    /// </summary>
    internal static class ArkMcpDocuments
    {
        const string Vendor = "io.github.ir-dev/ark-idp";
        const string Site = "https://ir-dev.github.io/ark-oauth-oidc/";

        public static string ServerName(ArkMcpEndpoint e) => ArkMcpServer.ServerInfo(e)["name"]!.GetValue<string>();

        public static JsonObject Card(ArkMcpEndpoint e, string packageVersion)
        {
            var info = ArkMcpServer.ServerInfo(e);
            var meta = new JsonObject
            {
                ["phase"] = e.Setup ? "setup" : "ready",
                ["level"] = e.Level.ToString().ToLowerInvariant(),
                ["resource"] = e.Resource,
                ["config"] = $"{e.Resource}/config",
                ["authorization"] = Authorization(e)
            };
            if (e.Tenant != null) meta["tenant_id"] = e.Tenant.tenant_id;
            if (e.Client != null) meta["client_id"] = e.Client.client_id;
            if (!e.Setup) meta["resource_metadata"] = e.MetadataUrl;
            meta["endpoints"] = Endpoints(e);

            return new JsonObject
            {
                ["name"] = $"{Vendor}-{(e.Setup ? "setup" : e.Level.ToString().ToLowerInvariant())}",
                ["title"] = info["title"]!.GetValue<string>(),
                ["description"] = Description(e),
                ["version"] = packageVersion,
                ["websiteUrl"] = Site,
                ["remotes"] = new JsonArray(new JsonObject
                {
                    ["type"] = "streamable-http",
                    ["url"] = e.Resource,
                    ["supportedProtocolVersions"] = new JsonArray("2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"),
                    ["headers"] = new JsonArray(new JsonObject
                    {
                        ["name"] = "Authorization",
                        ["description"] = e.Setup
                            ? "Bearer and the setup code from the server's log."
                            : "Bearer and an access token addressed to this endpoint.",
                        ["isRequired"] = true,
                        ["isSecret"] = true
                    })
                }),
                ["_meta"] = new JsonObject { [Vendor] = meta }
            };
        }

        static string Description(ArkMcpEndpoint e) => e.Setup
            ? "Sets this identity server up: collects its settings section by section, checks them, and creates the first tenant."
            : e.Level switch
            {
                ArkMcpLevel.Host => "Runs this identity server: tenants, shared catalogues, accounts and health.",
                ArkMcpLevel.Tenant => $"Administers the tenant {e.Tenant!.tenant_id}: applications, people, access, agents, keys and sessions.",
                _ => $"The application {e.Client!.client_name ?? e.Client.client_id}: its registration, its people and their access."
            };

        /// <summary>Where the other levels are.</summary>
        static JsonObject Endpoints(ArkMcpEndpoint e)
        {
            var tenantId = e.Tenant?.tenant_id ?? (e.OperatorTenantId.Length > 0 ? e.OperatorTenantId : null);
            var map = new JsonObject { ["host"] = ArkMcpResources.Host(e.Root), ["tenant_template"] = $"{e.Root}/{{tenant_id}}/mcp", ["client_template"] = $"{e.Root}/{{tenant_id}}/mcp/{{client_id}}" };
            if (tenantId != null) map["tenant"] = ArkMcpResources.Tenant(e.Root, tenantId);
            return map;
        }

        static JsonObject Authorization(ArkMcpEndpoint e)
        {
            if (e.Setup)
                return new JsonObject
                {
                    ["type"] = "setup_code",
                    ["header"] = "Authorization: Bearer <setup code>",
                    ["where"] = "The setup code is printed in the server's start-up log and kept in setup-code.txt in its data directory. " +
                                "When ark_oauth_server:Setup:AccessKey is set, the setup link (/ark-idp/setup#key=<key>) shows it too. It stops working when setup finishes."
                };

            var issuer = e.OidcFor(e.Tenant?.tenant_id ?? e.OperatorTenantId);
            var o = new JsonObject
            {
                ["type"] = "oauth2",
                ["authorization_servers"] = new JsonArray(issuer.Issuer),
                ["resource"] = e.Resource,
                ["scopes"] = new JsonArray(ArkMcpScopes.Read, ArkMcpScopes.Manage),
                ["client_secret_accepted"] = e.Config.Mcp.AllowClientSecret
            };
            o["unattended_client"] = e.Level == ArkMcpLevel.Client
                ? e.Client!.client_id
                : ArkManagementAuth.MachineClientId(e.Tenant?.tenant_id ?? e.OperatorTenantId);
            return o;
        }

        public static JsonObject Config(ArkMcpEndpoint e)
        {
            var name = ServerName(e);
            JsonObject Servers(string? authorization)
            {
                var server = new JsonObject { ["type"] = "http", ["url"] = e.Resource };
                if (authorization != null) server["headers"] = new JsonObject { ["Authorization"] = authorization };
                return new JsonObject { [name] = server };
            }

            if (e.Setup)
                return new JsonObject
                {
                    ["phase"] = "setup",
                    ["mcpServers"] = Servers("Bearer ${ARK_SETUP_CODE}"),
                    ["note"] = "ARK_SETUP_CODE is the code in the server's start-up log. After setup this endpoint takes an access token instead; " +
                               "the answer to setup_complete carries the configuration to use from then on.",
                    ["server_card"] = $"{e.Resource}/server-card"
                };

            var issuer = e.OidcFor(e.Tenant?.tenant_id ?? e.OperatorTenantId);
            var clientId = e.Level == ArkMcpLevel.Client ? e.Client!.client_id : ArkManagementAuth.MachineClientId(issuer.TenantId);
            var unattended = new JsonObject
            {
                ["client_id"] = clientId,
                ["token_request"] = new JsonObject
                {
                    ["method"] = "POST",
                    ["url"] = issuer.Token,
                    ["form"] = new JsonObject
                    {
                        ["grant_type"] = "client_credentials",
                        ["client_id"] = clientId,
                        ["client_secret"] = "${ARK_CLIENT_SECRET}",
                        ["resource"] = e.Resource,
                        ["scope"] = $"{ArkMcpScopes.Read} {ArkMcpScopes.Manage}"
                    }
                },
                ["mcpServers"] = Servers("Bearer ${ARK_ACCESS_TOKEN}")
            };
            if (e.Config.Mcp.AllowClientSecret)
                unattended["header_only"] = new JsonObject
                {
                    ["note"] = "For a client that can only be given a fixed header: base64 of client_id:client_secret.",
                    ["mcpServers"] = Servers("Basic ${ARK_CLIENT_BASIC}")
                };
            return new JsonObject
            {
                ["phase"] = "ready",
                ["mcpServers"] = Servers(null),
                ["note"] = "An MCP client that signs people in discovers the rest from the 401. An unattended agent asks for its token as below.",
                ["unattended"] = unattended,
                ["server_card"] = $"{e.Resource}/server-card"
            };
        }

        /// <summary>Protected resource metadata (RFC 9728).</summary>
        public static JsonObject Metadata(ArkMcpEndpoint e)
        {
            var servers = new JsonArray(e.OidcFor(e.Tenant?.tenant_id ?? e.OperatorTenantId).Issuer);
            // The operator administers every tenant with tokens of its own issuer. Second, because
            // a client that takes the first must end up at the tenant's own sign-in.
            if (e.Tenant != null && !e.IsOperatorTenant && e.OperatorTenantId.Length > 0)
                servers.Add(e.OidcFor(e.OperatorTenantId).Issuer);

            return new JsonObject
            {
                ["resource"] = e.Resource,
                ["authorization_servers"] = servers,
                ["scopes_supported"] = new JsonArray(Scopes(e).Select(s => (JsonNode?)JsonValue.Create(s)).ToArray()),
                ["bearer_methods_supported"] = new JsonArray("header"),
                ["resource_name"] = ArkMcpServer.ServerInfo(e)["title"]!.GetValue<string>(),
                ["resource_documentation"] = Site
            };
        }

        /// <summary>
        /// The scopes to ask for. An MCP client requests every one it finds here, and this server
        /// refuses a scope the client is not registered for; so an application's endpoint names
        /// only what that application holds, and the administrative ones name the one that lets a
        /// caller start by looking.
        /// </summary>
        public static List<string> Scopes(ArkMcpEndpoint e)
        {
            if (e.Client == null) return new List<string> { ArkMcpScopes.Read };
            var held = e.Client.EffectiveScopes;
            var mcp = held.Where(s => s.Equals(ArkMcpScopes.Read, StringComparison.OrdinalIgnoreCase)).ToList();
            if (mcp.Count > 0) return mcp;
            var plain = held.FirstOrDefault(s => s.Equals("profile", StringComparison.OrdinalIgnoreCase))
                ?? held.FirstOrDefault(s => !Protocol.ArkClaimsService.PrivilegedScopes.Contains(s, StringComparer.OrdinalIgnoreCase));
            return plain == null ? new List<string>() : new List<string> { plain };
        }
    }
}
