using System.Security.Claims;
using System.Text.Json;
using Ark.oAuth.Oidc.Protocol;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Ark.oAuth.Oidc.Mcp
{
    /// <summary>The endpoint a request arrived at, looked up.</summary>
    internal sealed class ArkMcpEndpoint
    {
        public ArkMcpLevel Level { get; init; }
        /// <summary>The server is unconfigured and this is the host endpoint: setup and nothing else.</summary>
        public bool Setup { get; init; }
        public ArkTenant? Tenant { get; init; }
        public ArkClient? Client { get; init; }
        public ArkAuthServerConfig Config { get; init; } = new();
        /// <summary>The public root every address is built from.</summary>
        public string Root { get; init; } = "";
        /// <summary>This endpoint's own address: its resource identifier, and the audience it accepts.</summary>
        public string Resource { get; init; } = "";
        public string MetadataUrl => ArkMcpResources.Metadata(Root, Resource);
        public string OperatorTenantId => (Config.TenantId ?? "").Trim();
        /// <summary>The operator tenant administers the server, so its own level is the operator's.</summary>
        public bool IsOperatorTenant => Tenant != null && ArkMcpIndicators.Same(Tenant.tenant_id, OperatorTenantId);
        public ArkOidcEndpoints OidcFor(string tenantId) => new(Root, tenantId);
        /// <summary>How this endpoint is named in the audit trail.</summary>
        public string Reference => Level switch
        {
            // The slash in front keeps it from being read as the tenant endpoint of a tenant called that.
            ArkMcpLevel.Host => ArkMcpResources.HostPath,
            ArkMcpLevel.Tenant => $"{Tenant!.tenant_id}/mcp",
            _ => $"{Tenant!.tenant_id}/mcp/{Client!.client_id}"
        };
    }

    /// <summary>Who is calling, and what that lets them do at this endpoint.</summary>
    internal sealed class ArkMcpCaller
    {
        /// <summary><c>setup</c>, <c>machine</c>, <c>client</c>, <c>agent</c> or <c>user</c>.</summary>
        public string Kind { get; init; } = "";
        /// <summary><c>setup_code</c>, <c>access_token</c> or <c>client_secret</c>.</summary>
        public string Credential { get; init; } = "";
        /// <summary>The tenant whose issuer vouches for the caller.</summary>
        public string? TenantId { get; init; }
        public string? ClientId { get; init; }
        public string Subject { get; init; } = "";
        public bool IsUser { get; init; }
        /// <summary>The agents acting for the subject, newest first.</summary>
        public List<string> Actors { get; init; } = new();
        public List<string> Scopes { get; init; } = new();
        /// <summary>The caller's authorization claims, read afresh: a claim taken away counts at once.</summary>
        public List<string> Claims { get; init; } = new();
        public string? TokenId { get; init; }
        public DateTime? ExpiresAt { get; init; }

        /// <summary>The operator of the server.</summary>
        public bool Operator { get; init; }
        /// <summary>An administrator of the endpoint's tenant; every operator is one.</summary>
        public bool TenantAdmin { get; init; }
        /// <summary>An administrator of the endpoint's application; every tenant administrator is one.</summary>
        public bool ClientAdmin { get; init; }
        public bool CanRead { get; init; }
        public bool CanManage { get; init; }
        /// <summary>Scopes that stand for both: client.register on the machine client.</summary>
        public bool FullScope { get; init; }

        public ClaimsPrincipal ToPrincipal()
        {
            var identity = new ClaimsIdentity("ArkMcp");
            identity.AddClaim(new Claim("sub", Subject));
            if (!string.IsNullOrEmpty(ClientId)) identity.AddClaim(new Claim("client_id", ClientId!));
            return new ClaimsPrincipal(identity);
        }
    }

    /// <summary>The caller could not be established, or lacks the scope a tool needs (RFC 6750 §3).</summary>
    internal sealed class ArkMcpAuthException : Exception
    {
        public int Status { get; }
        public string? Error { get; }
        public string? Scope { get; }

        public ArkMcpAuthException(int status, string? error, string message, string? scope = null) : base(message)
        {
            Status = status;
            Error = error;
            Scope = scope;
        }

        public static ArkMcpAuthException Missing(string message) => new(401, null, message);
        public static ArkMcpAuthException Invalid(string message) => new(401, OAuthErrorCodes.InvalidToken, message);
    }

    /// <summary>
    /// Establishes who is calling an MCP endpoint.
    ///
    /// A token is accepted only when all of this holds: it is an access token (<c>typ: at+jwt</c>)
    /// this server signed, for the tenant of the endpoint or for the operator's; its one audience
    /// is this endpoint, so a token made for an application, for another tenant's endpoint or for
    /// the host level is worth nothing here; the client it was issued to still exists and is
    /// active; and when it is for a person, the account is active, the session behind it is alive
    /// and the access it was issued under has not been withdrawn. Authority is read from the
    /// database as it is now, never from the token: taking a claim or a caller away counts on the
    /// next call, not when the token runs out.
    /// </summary>
    internal sealed class ArkMcpAuth
    {
        private readonly ArkDataContext _db;
        private readonly DataAccess _da;
        private readonly ArkTokenService _tokens;
        private readonly ArkClaimsService _claims;
        private readonly ArkGrantStore _grants;
        private readonly ArkClientAuthenticator _clients;

        public ArkMcpAuth(ArkDataContext db, DataAccess da, ArkTokenService tokens, ArkClaimsService claims,
            ArkGrantStore grants, ArkClientAuthenticator clients)
        {
            _db = db;
            _da = da;
            _tokens = tokens;
            _claims = claims;
            _grants = grants;
            _clients = clients;
        }

        public async Task<ArkMcpCaller> AuthenticateAsync(HttpRequest request, ArkMcpEndpoint endpoint)
        {
            var header = request.Headers.Authorization.ToString();
            if (header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                return await FromTokenAsync(header["Bearer ".Length..].Trim(), endpoint);
            if (header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
                return await FromSecretAsync(request, endpoint);
            throw ArkMcpAuthException.Missing(
                $"present an access token addressed to this endpoint: request one with resource={endpoint.Resource}.");
        }

        // ---------------------------------------------------------------- access token

        private async Task<ArkMcpCaller> FromTokenAsync(string token, ArkMcpEndpoint endpoint)
        {
            JsonWebToken unverified;
            try
            {
                unverified = new JsonWebTokenHandler().ReadJsonWebToken(token);
            }
            catch (Exception ex) when (ex is ArgumentException or SecurityTokenMalformedException or FormatException)
            {
                throw ArkMcpAuthException.Invalid(
                    "the bearer token is not an access token of this server. The setup code is accepted only until setup is finished.");
            }

            // Which issuer claims to have made it. Only decides whose keys it is checked against.
            var issuer = await IssuerOfAsync(unverified.Issuer, endpoint)
                ?? throw ArkMcpAuthException.Invalid("the token is not from an issuer this endpoint accepts.");
            var issuerUrl = endpoint.OidcFor(issuer.tenant_id).Issuer;

            var result = await _tokens.ValidateAccessTokenAnyAudienceAsync(token, issuer, issuerUrl);
            if (!result.IsValid || result.SecurityToken is not JsonWebToken jwt)
                throw ArkMcpAuthException.Invalid("the token is expired, malformed, or not an access token.");

            var audiences = jwt.Audiences.ToList();
            if (audiences.Count != 1 || !string.Equals(audiences[0], endpoint.Resource, StringComparison.Ordinal))
                throw ArkMcpAuthException.Invalid(
                    $"the token is not addressed to this endpoint. Request one with resource={endpoint.Resource}.");

            using var payload = JsonDocument.Parse(Base64UrlEncoder.Decode(jwt.EncodedPayload));
            string? Text(string name) =>
                payload.RootElement.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

            var subject = Text("sub");
            var clientId = Text("client_id");
            if (string.IsNullOrEmpty(subject) || string.IsNullOrEmpty(clientId))
                throw ArkMcpAuthException.Invalid("the token names no subject or no client.");
            var scopes = (Text("scope") ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();
            var actors = payload.RootElement.TryGetProperty("act", out var act) ? ArkAgentTokens.ActorChain(act) : new List<string>();

            var client = await ArkIdpCache.ClientAsync(_db, issuer.tenant_id, clientId);
            if (client is { is_active: false }) client = await ArkIdpCache.ClientIfChangedAsync(_db, client);
            if (client is not { is_active: true })
                throw ArkMcpAuthException.Invalid("the client the token was issued to is no longer active here.");

            // A person, unless the client acts as itself: its own id as the subject and no session.
            // A session id is what every sign-in leaves in a token, so an account that happens to
            // be named like a client is still a person.
            var sid = Text("sid");
            var isUser = actors.Count > 0 || !string.IsNullOrEmpty(sid)
                || !string.Equals(subject, client.client_id, StringComparison.OrdinalIgnoreCase);
            var isMachine = !isUser && string.Equals(clientId, ArkManagementAuth.MachineClientId(issuer.tenant_id), StringComparison.Ordinal);
            var issuedByOperator = ArkMcpIndicators.Same(issuer.tenant_id, endpoint.OperatorTenantId);

            // At an application's endpoint, anyone but the application itself is an agent calling it,
            // and has to be on its list still.
            ArkAgentCaller? listed = null;
            var ownClient = endpoint.Client != null && ArkMcpIndicators.Same(issuer.tenant_id, endpoint.Client.tenant_id)
                && ArkMcpIndicators.Same(clientId, endpoint.Client.client_id);
            if (endpoint.Level == ArkMcpLevel.Client && !ownClient && !isMachine)
            {
                var target = await ArkIdpCache.ClientIfChangedAsync(_db, endpoint.Client!);
                // The list names clients of its own tenant. A client_id means nothing outside one.
                listed = ArkMcpIndicators.Same(issuer.tenant_id, target.tenant_id)
                    ? target.a2a_callers.FirstOrDefault(c => ArkMcpIndicators.Same(c.client_id, clientId)) : null;
                if (listed == null || !target.is_active || (isUser && (actors.Count == 0 || !listed.delegate_users)))
                    throw ArkMcpAuthException.Invalid($"'{clientId}' is not, or is no longer, allowed to call '{target.client_id}'.");
            }

            var claims = listed is { } entry && !isUser ? entry.claims ?? new List<string>() : new List<string>();
            if (isUser)
            {
                var user = await _claims.FindUserAsync(subject);
                if (user is not { is_active: true })
                    throw ArkMcpAuthException.Invalid("the account the token is for does not exist or has been deactivated.");
                if (!string.IsNullOrEmpty(sid) && await _grants.GetSessionAsync(sid) == null)
                    throw ArkMcpAuthException.Invalid("the session behind the token has ended.");
                // The mapping the token stands on: to the application it is for, when an agent
                // carries the person there; to the client they signed in through, otherwise.
                var mapped = actors.Count > 0 && endpoint.Client != null ? endpoint.Client : client;
                if (!await _claims.HasClientAccessAsync(subject!, mapped.tenant_id, mapped))
                    throw ArkMcpAuthException.Invalid("the person the token is for no longer has access to that application.");
                claims = await _claims.GetAuthorizationClaimsAsync(subject!, mapped.tenant_id, mapped);
            }

            // The operator: the machine client of the operator tenant, whoever else the management
            // API would admit with this token, or a person given the claim for it.
            var managementToken = issuedByOperator && result.ClaimsIdentity != null
                && !(isUser && string.Equals(clientId, ArkManagementAuth.MachineClientId(issuer.tenant_id), StringComparison.Ordinal))
                && await ArkManagementAuth.RefusalAsync(result.ClaimsIdentity, endpoint.Config, _da) == null;
            var isOperator = issuedByOperator && (isMachine || managementToken || (isUser && actors.Count == 0 && Has(claims, ArkMcpClaims.HostAdmin)));
            var tenantAdmin = isOperator || (endpoint.Tenant != null && !endpoint.IsOperatorTenant
                && ArkMcpIndicators.Same(issuer.tenant_id, endpoint.Tenant.tenant_id)
                && (isMachine || (isUser && actors.Count == 0 && Has(claims, ArkMcpClaims.TenantAdmin))));
            var clientAdmin = tenantAdmin || (endpoint.Level == ArkMcpLevel.Client
                && ((ownClient && !isUser) || Has(claims, ArkMcpClaims.ClientAdmin)));

            var full = managementToken || (isMachine && Has(scopes, ArkManagementAuth.ManagementScope));
            return new ArkMcpCaller
            {
                Kind = isMachine ? "machine" : isUser ? (actors.Count > 0 ? "agent" : "user") : listed != null ? "agent" : "client",
                Credential = "access_token",
                TenantId = issuer.tenant_id,
                ClientId = client.client_id,
                Subject = subject!,
                IsUser = isUser,
                Actors = actors,
                Scopes = scopes,
                Claims = claims,
                TokenId = Text("jti"),
                ExpiresAt = DateTime.SpecifyKind(jwt.ValidTo, DateTimeKind.Utc),
                Operator = isOperator,
                TenantAdmin = tenantAdmin,
                ClientAdmin = clientAdmin,
                FullScope = full,
                CanRead = full || Has(scopes, ArkMcpScopes.Read) || Has(scopes, ArkMcpScopes.Manage),
                CanManage = (full || Has(scopes, ArkMcpScopes.Manage)) && !endpoint.Config.Mcp.ReadOnly
            };
        }

        private async Task<ArkTenant?> IssuerOfAsync(string? issuer, ArkMcpEndpoint endpoint)
        {
            foreach (var id in new[] { endpoint.Tenant?.tenant_id, endpoint.OperatorTenantId })
            {
                var tenant = string.IsNullOrEmpty(id) ? null : await ArkIdpCache.TenantAsync(_db, id);
                if (tenant != null && string.Equals(issuer, endpoint.OidcFor(tenant.tenant_id).Issuer, StringComparison.Ordinal)) return tenant;
            }
            return null;
        }

        // ---------------------------------------------------------------- client secret

        private async Task<ArkMcpCaller> FromSecretAsync(HttpRequest request, ArkMcpEndpoint endpoint)
        {
            if (!endpoint.Config.Mcp.AllowClientSecret)
                throw ArkMcpAuthException.Invalid("this server takes an access token here, not a client secret (Mcp:AllowClientSecret is off).");
            if (!ArkClientAuthenticator.TryReadBasicHeader(request, out var clientId, out var secret) || string.IsNullOrEmpty(clientId))
                throw ArkMcpAuthException.Invalid("the Basic credentials could not be read.");

            // Only a client that may act here at all: the two machine clients, and the application.
            var candidates = new List<(string Tenant, string Client)>();
            if (endpoint.Tenant != null)
            {
                candidates.Add((endpoint.Tenant.tenant_id, ArkManagementAuth.MachineClientId(endpoint.Tenant.tenant_id)));
                if (endpoint.Client != null) candidates.Add((endpoint.Tenant.tenant_id, endpoint.Client.client_id));
            }
            candidates.Add((endpoint.OperatorTenantId, ArkManagementAuth.MachineClientId(endpoint.OperatorTenantId)));

            var match = candidates.FirstOrDefault(c => string.Equals(c.Client, clientId, StringComparison.Ordinal));
            var client = await _clients.VerifySecretAsync(match.Tenant ?? endpoint.OperatorTenantId, match.Client ?? "", secret);
            if (match.Client == null || client == null)
                throw ArkMcpAuthException.Invalid("that client_id and secret do not open this endpoint.");

            var isMachine = string.Equals(client.client_id, ArkManagementAuth.MachineClientId(client.tenant_id), StringComparison.Ordinal);
            var isOperator = isMachine && ArkMcpIndicators.Same(client.tenant_id, endpoint.OperatorTenantId);
            var registered = client.EffectiveScopes;
            // The secret stands for a token with every MCP scope the client could ask for.
            var full = isMachine && Has(registered, ArkManagementAuth.ManagementScope);
            var canManage = full || Has(registered, ArkMcpScopes.Manage);
            return new ArkMcpCaller
            {
                Kind = isMachine ? "machine" : "client",
                Credential = "client_secret",
                TenantId = client.tenant_id,
                ClientId = client.client_id,
                Subject = client.client_id,
                Scopes = registered.Where(s => s.StartsWith("mcp.", StringComparison.OrdinalIgnoreCase)
                    || s.Equals(ArkManagementAuth.ManagementScope, StringComparison.OrdinalIgnoreCase)).ToList(),
                Operator = isOperator,
                TenantAdmin = isOperator || (isMachine && endpoint.Tenant != null && !endpoint.IsOperatorTenant
                    && ArkMcpIndicators.Same(client.tenant_id, endpoint.Tenant.tenant_id)),
                ClientAdmin = isMachine || endpoint.Level == ArkMcpLevel.Client,
                FullScope = full,
                CanRead = canManage || Has(registered, ArkMcpScopes.Read),
                CanManage = canManage && !endpoint.Config.Mcp.ReadOnly
            };
        }

        private static bool Has(IEnumerable<string> values, string value) => values.Contains(value, StringComparer.OrdinalIgnoreCase);
    }
}
