namespace Ark.oAuth.Oidc.Mcp
{
    /// <summary>One MCP endpoint and the public documents beside it.</summary>
    internal sealed class ArkMcpDirectoryEntry
    {
        /// <summary><c>host</c>, <c>tenant</c> or <c>client</c>.</summary>
        public string level { get; init; } = "";
        public string name { get; init; } = "";
        /// <summary>Null at the host level.</summary>
        public string? tenant_id { get; init; }
        /// <summary>Null except at the client level.</summary>
        public string? client_id { get; init; }
        /// <summary>False for an application that is switched off: nothing it holds opens its endpoint.</summary>
        public bool is_active { get; init; } = true;
        /// <summary>The endpoint's address, exactly as tokens for it name it in <c>aud</c>.</summary>
        public string url { get; init; } = "";
        public string server_card { get; init; } = "";
        public string config { get; init; } = "";
        public string resource_metadata { get; init; } = "";
    }

    /// <summary>
    /// Every MCP endpoint of this server, for an operator to look through: the host's, one per
    /// tenant, and one per application.
    ///
    /// Addresses come from <see cref="ArkMcpEndpoint"/> and <see cref="ArkMcpResources"/>, the same
    /// code the endpoints themselves are resolved with, because a token is accepted only when its
    /// audience is the address to the letter. A level that is switched off is left out: it answers
    /// 404, and a list of addresses that do not exist is worse than a shorter one.
    /// </summary>
    internal static class ArkMcpDirectory
    {
        /// <summary>Whether the server has any MCP endpoint at all.</summary>
        public static bool Any(ArkMcpConfig? config) =>
            Enum.GetValues<ArkMcpLevel>().Any(level => ArkMcpResources.LevelEnabled(config, level));

        /// <summary>The host first, then each tenant followed by its applications.</summary>
        public static List<ArkMcpDirectoryEntry> List(
            ArkAuthServerConfig config, string root, IEnumerable<ArkTenant> tenants, IEnumerable<ArkClient> clients)
        {
            var entries = new List<ArkMcpDirectoryEntry>();
            if (ArkMcpResources.LevelEnabled(config.Mcp, ArkMcpLevel.Host))
                entries.Add(Entry(new ArkMcpEndpoint
                {
                    Level = ArkMcpLevel.Host, Config = config, Root = root, Resource = ArkMcpResources.Host(root)
                }, "This server"));

            var byTenant = clients.ToLookup(c => (c.tenant_id ?? "").Trim(), StringComparer.OrdinalIgnoreCase);
            foreach (var tenant in tenants.OrderBy(t => t.tenant_id, StringComparer.OrdinalIgnoreCase))
            {
                if (ArkMcpResources.LevelEnabled(config.Mcp, ArkMcpLevel.Tenant))
                    entries.Add(Entry(new ArkMcpEndpoint
                    {
                        Level = ArkMcpLevel.Tenant, Tenant = tenant, Config = config, Root = root,
                        Resource = ArkMcpResources.Tenant(root, tenant.tenant_id)
                    }, First(tenant.display, tenant.name, tenant.tenant_id)));

                if (!ArkMcpResources.LevelEnabled(config.Mcp, ArkMcpLevel.Client)) continue;
                foreach (var client in byTenant[tenant.tenant_id.Trim()].OrderBy(c => c.client_id, StringComparer.OrdinalIgnoreCase))
                    entries.Add(Entry(new ArkMcpEndpoint
                    {
                        Level = ArkMcpLevel.Client, Tenant = tenant, Client = client, Config = config, Root = root,
                        Resource = ArkMcpResources.Client(root, tenant.tenant_id, client.client_id)
                    }, First(client.client_name, client.display, client.name, client.client_id)));
            }
            return entries;
        }

        static ArkMcpDirectoryEntry Entry(ArkMcpEndpoint e, string name) => new()
        {
            level = e.Level.ToString().ToLowerInvariant(),
            name = name,
            tenant_id = e.Tenant?.tenant_id,
            client_id = e.Client?.client_id,
            is_active = e.Client?.is_active ?? true,
            url = e.Resource,
            server_card = $"{e.Resource}/server-card",
            config = $"{e.Resource}/config",
            resource_metadata = e.MetadataUrl
        };

        static string First(params string?[] values) => values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v))?.Trim() ?? "";
    }
}
