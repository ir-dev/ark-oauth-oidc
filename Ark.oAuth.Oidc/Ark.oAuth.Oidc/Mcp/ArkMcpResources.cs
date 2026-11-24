using Ark.oAuth.Oidc.Protocol;

namespace Ark.oAuth.Oidc.Mcp
{
    /// <summary>How much of the server an MCP endpoint speaks for.</summary>
    public enum ArkMcpLevel
    {
        /// <summary>The whole server: every tenant, the shared catalogues, the server's health.</summary>
        Host,
        /// <summary>One tenant: its applications, people, access, keys and sessions.</summary>
        Tenant,
        /// <summary>One application.</summary>
        Client
    }

    /// <summary>The scopes an MCP access token carries.</summary>
    public static class ArkMcpScopes
    {
        /// <summary>Call the tools that only look.</summary>
        public const string Read = "mcp.read";
        /// <summary>Call the tools that change something. Only an operator registers a client for it.</summary>
        public const string Manage = "mcp.manage";

        /// <summary>
        /// Whether a client registered for <paramref name="held"/> may ask for <paramref name="scope"/>
        /// although it is not on its list. <c>client.register</c> is authority over this server, and
        /// the two MCP scopes are parts of it, so the machine client — registered for that scope
        /// alone, on every database there is — can be given either without anyone editing it.
        /// </summary>
        public static bool ImpliedBy(IEnumerable<string> held, string scope) =>
            (string.Equals(scope, Read, StringComparison.OrdinalIgnoreCase)
             || string.Equals(scope, Manage, StringComparison.OrdinalIgnoreCase))
            && held.Contains(ArkManagementAuth.ManagementScope, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The authorization claims that make a person an administrator over MCP, on their access
    /// mapping to the application they sign in through. Named apart from any claim an application
    /// uses for itself: an <c>admin</c> of some app must not become an administrator of the tenant.
    /// </summary>
    public static class ArkMcpClaims
    {
        public const string Prefix = "ark.";
        /// <summary>Operator of the server. Counts only on a mapping in the operator tenant.</summary>
        public const string HostAdmin = "ark.host.admin";
        /// <summary>Administrator of the tenant the mapping is in. Not enough in the operator tenant.</summary>
        public const string TenantAdmin = "ark.tenant.admin";
        /// <summary>Administrator of the application the mapping is to.</summary>
        public const string ClientAdmin = "ark.client.admin";

        public static bool IsReserved(string? claim) =>
            (claim ?? "").Trim().StartsWith(Prefix, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>What an MCP resource identifier names, before it is looked up.</summary>
    public sealed record ArkMcpTarget(ArkMcpLevel Level, string? TenantId, string? ClientId);

    /// <summary>
    /// The addresses of the MCP endpoints, which are also their OAuth resource identifiers
    /// (RFC 8707): the <c>aud</c> of every token one of them accepts.
    /// </summary>
    public static class ArkMcpResources
    {
        public const string HostPath = "/ark-idp/mcp";
        const string Segment = "mcp";

        public static string Host(string root) => $"{root}{HostPath}";
        public static string Tenant(string root, string tenantId) => $"{root}/{tenantId}/{Segment}";
        /// <summary>The client_id is escaped: one may be a URL, as an MCP server's own is.</summary>
        public static string Client(string root, string tenantId, string clientId) =>
            $"{root}/{tenantId}/{Segment}/{Uri.EscapeDataString(clientId)}";

        /// <summary>Protected resource metadata (RFC 9728): the well-known path inserted before the resource's own.</summary>
        public static string Metadata(string root, string resource) =>
            $"{root}/.well-known/oauth-protected-resource{resource[root.Length..]}";

        /// <summary>
        /// The endpoint a resource identifier names on this server, or null when it names none:
        /// another server's address, a client_id, the tenant's audience.
        /// </summary>
        public static ArkMcpTarget? Parse(string root, string? value)
        {
            var text = (value ?? "").Trim();
            if (text.Length <= root.Length + 1 || text.Contains('?') || text.Contains('#')) return null;
            // Scheme and host are case-insensitive and MCP clients lower-case them.
            if (!text.StartsWith(root, StringComparison.OrdinalIgnoreCase) || text[root.Length] != '/') return null;
            var parts = text[(root.Length + 1)..].TrimEnd('/').Split('/');
            if (parts.Length == 2 && parts[0] == "ark-idp" && parts[1] == Segment)
                return new ArkMcpTarget(ArkMcpLevel.Host, null, null);
            if (parts.Length is < 2 or > 3 || parts[0].Length == 0 || parts[1] != Segment) return null;
            if (parts.Length == 2) return new ArkMcpTarget(ArkMcpLevel.Tenant, parts[0], null);
            return parts[2].Length == 0 ? null : new ArkMcpTarget(ArkMcpLevel.Client, parts[0], Uri.UnescapeDataString(parts[2]));
        }

        public static bool LevelEnabled(ArkMcpConfig? config, ArkMcpLevel level) =>
            config is { Enabled: true } && level switch
            {
                ArkMcpLevel.Host => config.HostLevel,
                ArkMcpLevel.Tenant => config.TenantLevel,
                _ => config.ClientLevel
            };
    }

    /// <summary>An MCP resource a token request names, looked up: what it is and its one spelling.</summary>
    public sealed class ArkMcpResource
    {
        public ArkMcpLevel Level { get; init; }
        /// <summary>Null at the host level.</summary>
        public ArkTenant? Tenant { get; init; }
        /// <summary>Null except at the client level.</summary>
        public ArkClient? Client { get; init; }
        /// <summary>The identifier as it is written into <c>aud</c>.</summary>
        public string Uri { get; init; } = "";
    }

    /// <summary>
    /// Resource indicators (RFC 8707) for this server's own MCP endpoints.
    ///
    /// An MCP client names the endpoint it is going to call — at /authorize, at /token and when it
    /// refreshes — and the token it gets is good there and nowhere else. Every other value of
    /// <c>resource</c> is handled as it was before: ignored on a sign-in, an agent's client_id on
    /// a client_credentials or token exchange request (A2A.md).
    /// </summary>
    internal static class ArkMcpIndicators
    {
        /// <summary>
        /// The MCP resource among <paramref name="values"/>, or null when there is none. A request
        /// naming one that does not exist, that is switched off, or that this issuer may not issue
        /// for is refused with <c>invalid_target</c>: told apart, the three would answer whether a
        /// tenant or a client exists.
        /// </summary>
        public static async Task<ArkMcpResource?> RequestedAsync(
            ArkDataContext db, ArkAuthServerConfig config, ArkOidcEndpoints ep, ArkTenant issuer, IEnumerable<string?> values)
        {
            if (config.Mcp is not { Enabled: true }) return null;
            var named = values.Select(v => (v ?? "").Trim()).Where(v => v.Length > 0).Distinct(StringComparer.Ordinal).ToList();
            var target = named.Select(v => ArkMcpResources.Parse(ep.BaseUrl, v)).FirstOrDefault(t => t != null);
            if (target == null) return null;
            if (named.Count > 1)
                throw new OAuthException(ArkAgentTokens.InvalidTarget, "a token is addressed to exactly one resource: send a single one.");

            var resource = await ResolveAsync(db, config, ep.BaseUrl, target);
            var operatorTenant = (config.TenantId ?? "").Trim();
            var issuedByOperator = Same(issuer.tenant_id, operatorTenant);
            var issuable = resource != null && (resource.Level == ArkMcpLevel.Host
                ? issuedByOperator
                // The operator administers every tenant, so its issuer may address a token to any
                // of them. What the token is then worth there is decided at the endpoint.
                : issuedByOperator || Same(resource.Tenant!.tenant_id, issuer.tenant_id));
            if (!issuable)
                throw new OAuthException(ArkAgentTokens.InvalidTarget, $"'{named[0]}' is not a resource this issuer issues tokens for.");
            return resource;
        }

        /// <summary>Looks an endpoint up, or null when it does not exist or is switched off.</summary>
        public static async Task<ArkMcpResource?> ResolveAsync(ArkDataContext db, ArkAuthServerConfig config, string root, ArkMcpTarget target)
        {
            if (!ArkMcpResources.LevelEnabled(config.Mcp, target.Level)) return null;
            if (target.Level == ArkMcpLevel.Host)
                return new ArkMcpResource { Level = ArkMcpLevel.Host, Uri = ArkMcpResources.Host(root) };

            var tenant = await ArkIdpCache.TenantAsync(db, target.TenantId);
            if (tenant == null) return null;
            if (target.Level == ArkMcpLevel.Tenant)
                return new ArkMcpResource { Level = ArkMcpLevel.Tenant, Tenant = tenant, Uri = ArkMcpResources.Tenant(root, tenant.tenant_id) };

            var client = await ArkIdpCache.ClientAsync(db, tenant.tenant_id, target.ClientId);
            return client == null ? null : new ArkMcpResource
            {
                Level = ArkMcpLevel.Client, Tenant = tenant, Client = client,
                Uri = ArkMcpResources.Client(root, tenant.tenant_id, client.client_id)
            };
        }

        /// <summary>
        /// Whether a client may be issued a token for an application's endpoint directly: the
        /// application itself, or the machine client that administers the tenant. Any other client
        /// is an agent calling this one, and goes through the A2A caller list.
        /// </summary>
        public static bool IsOwnOrMachine(ArkMcpResource resource, ArkTenant issuer, ArkClient client) =>
            Same(client.client_id, ArkManagementAuth.MachineClientId(issuer.tenant_id))
            || (Same(client.client_id, resource.Client!.client_id) && Same(client.tenant_id, resource.Client.tenant_id));

        /// <summary>
        /// The resource a grant carries, checked against the one the request names. A client may
        /// repeat the resource the grant was given for, or leave it out; it may not name one the
        /// grant was never given for, which is what a stolen code or refresh token would be used
        /// to ask.
        /// </summary>
        public static async Task<string?> ForGrantAsync(ArkDataContext db, ArkAuthServerConfig config, ArkOidcEndpoints ep,
            ArkTenant issuer, string? granted, IEnumerable<string?> requested)
        {
            var named = await RequestedAsync(db, config, ep, issuer, requested);
            if (named != null && !string.Equals(named.Uri, granted, StringComparison.Ordinal))
                throw new OAuthException(ArkAgentTokens.InvalidTarget,
                    "the authorization this grant came from did not name that resource.");
            if (string.IsNullOrEmpty(granted)) return null;
            // Switched off, or the application deleted, since the grant was made.
            var target = ArkMcpResources.Parse(ep.BaseUrl, granted);
            if (config.Mcp is not { Enabled: true } || target == null || await ResolveAsync(db, config, ep.BaseUrl, target) == null)
                throw new OAuthException(ArkAgentTokens.InvalidTarget, "the resource this grant was made for is no longer served here.");
            return granted;
        }

        internal static bool Same(string? a, string? b) =>
            !string.IsNullOrEmpty(a) && string.Equals(a.Trim(), (b ?? "").Trim(), StringComparison.OrdinalIgnoreCase);
    }
}
