using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace Ark.oAuth.Oidc
{
    /// <summary>
    /// Who may call the management API (<c>/api/oauth/...</c>): the operator, and nobody else.
    ///
    /// Those controllers used to carry a bare <c>[Authorize]</c> against the host's default
    /// scheme, which left the decision to every host and got it wrong in both of the obvious
    /// configurations. With the console's cookie as the default, any account mapped to the
    /// console client could create clients and reset secrets across every tenant, although the
    /// console's own operator pages refused the same person. With a bearer scheme as the default
    /// — which these controllers' documentation used to suggest — every access token this server
    /// issued to anybody drove the API.
    ///
    /// The policy admits two callers, decided per request:
    ///
    ///   * a console session (the host's default scheme) whose account passes
    ///     <see cref="ArkOperator.IsOperator"/>;
    ///   * a bearer token this server issued, carrying <c>client.register</c>, to either the
    ///     machine client (<c>{TenantId}_machine</c>) or one of
    ///     <see cref="ArkManagementConfig.OperatorDeviceClients"/> on the operator's approval.
    ///
    /// The scope alone is not enough. It names an authority a client can be registered for, and a
    /// client is not the operator because someone gave it a scope; tying the token to the
    /// machine client's identity is what makes holding its secret the one way in.
    ///
    /// Unauthenticated and refused calls answer 401 and 403 with the API's <c>{ error, code, msg }</c>
    /// body, never a redirect to the sign-in page: a script and the console's own fetch() would
    /// both read that HTML page as a success.
    /// </summary>
    public static class ArkManagementAuth
    {
        /// <summary>The authorization policy on the management controllers.</summary>
        public const string PolicyName = "ArkOperator";

        /// <summary>Picks the console cookie or <see cref="BearerScheme"/> for each request.</summary>
        public const string Scheme = "ArkManagement";

        /// <summary>Validates management bearer tokens with this server's own keys.</summary>
        public const string BearerScheme = "ArkManagementBearer";

        /// <summary>Seeded in the scope catalogue; the authority to create clients.</summary>
        public const string ManagementScope = "client.register";

        /// <summary>The machine client seeded beside the console.</summary>
        public static string MachineClientId(string tenantId) => $"{(tenantId ?? "").Trim()}_machine";

        internal static void AddArkManagementAuth(this IServiceCollection services)
        {
            // No defaults are set here: the host's default scheme stays the console's cookie, and
            // the policy below reaches it through the selector rather than by replacing it.
            services.AddAuthentication()
                .AddScheme<AuthenticationSchemeOptions, ArkManagementBearerHandler>(BearerScheme, null)
                .AddPolicyScheme(Scheme, Scheme, options =>
                {
                    options.ForwardDefaultSelector = SelectScheme;
                    // Every route under this policy is an API route, so both outcomes are a status
                    // code and a JSON body, whichever scheme authenticated the caller.
                    options.ForwardChallenge = BearerScheme;
                    options.ForwardForbid = BearerScheme;
                });

            services.AddAuthorization(options => options.AddPolicy(PolicyName, policy => policy
                .AddAuthenticationSchemes(Scheme)
                .RequireAuthenticatedUser()
                .AddRequirements(new ArkOperatorRequirement())));
            services.AddSingleton<IAuthorizationHandler, ArkOperatorHandler>();
        }

        /// <summary>
        /// A bearer token goes to <see cref="BearerScheme"/>; anything else to whatever the host
        /// authenticates browsers with. Read per request rather than captured, because the
        /// host's client is usually registered after the server.
        /// </summary>
        private static string SelectScheme(HttpContext context)
        {
            if (BearerToken(context.Request) != null) return BearerScheme;

            var options = context.RequestServices.GetRequiredService<IOptions<AuthenticationOptions>>().Value;
            var fallback = options.DefaultAuthenticateScheme ?? options.DefaultScheme;
            return string.IsNullOrEmpty(fallback) || fallback == Scheme ? BearerScheme : fallback;
        }

        internal static string? BearerToken(HttpRequest request)
        {
            var header = request.Headers.Authorization.ToString();
            if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return null;
            var token = header.Substring("Bearer ".Length).Trim();
            return token.Length == 0 ? null : token;
        }

        /// <summary>
        /// Why a validly signed token may still not drive the API, or null when it may.
        /// Separate from the handler so the rule reads as one list.
        /// </summary>
        internal static async Task<string?> RefusalAsync(
            ClaimsIdentity identity, ArkAuthServerConfig config, DataAccess da)
        {
            var clientId = identity.FindFirst("client_id")?.Value;

            // RFC 9068: the granted scopes travel as one space-delimited claim.
            var scopes = identity.FindAll("scope")
                .SelectMany(c => c.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries));
            if (!scopes.Contains(ManagementScope, StringComparer.Ordinal))
                return $"the token issued to '{clientId}' does not carry the '{ManagementScope}' scope";

            var tenantId = (config.TenantId ?? "").Trim();
            var machine = MachineClientId(tenantId);
            if (string.Equals(clientId, machine, StringComparison.Ordinal)) return null;

            var deviceClients = config.Management?.OperatorDeviceClients ?? new List<string>();
            if (!string.IsNullOrWhiteSpace(clientId)
                && deviceClients.Any(c => string.Equals(c?.Trim(), clientId, StringComparison.Ordinal)))
            {
                // The setting names the client; the registration has to back it up. A client that
                // can also take a redirect, or authenticate on its own, could come by a token
                // without the operator approving anything on this server.
                var client = await da.GetClient(tenantId, clientId);
                var grants = client?.EffectiveGrantTypes ?? new List<string>();
                var deviceOnly = client != null
                    && string.Equals(client.token_endpoint_auth_method, "none", StringComparison.OrdinalIgnoreCase)
                    && grants.Contains(DeviceCodeGrant)
                    && grants.All(g => g == DeviceCodeGrant || g == "refresh_token")
                    && client.EffectiveRedirectUris.Count == 0;
                if (!deviceOnly)
                    return $"'{clientId}' is listed in Management:OperatorDeviceClients but is not registered as a " +
                           "public client with only the device_code grant and no redirect URIs";

                if (!ArkOperator.IsOperator(new ClaimsPrincipal(identity), config))
                    return $"the device code for '{clientId}' was approved by " +
                           $"'{identity.FindFirst("sub")?.Value}', who is not the operator";
                return null;
            }

            return $"the token was issued to '{clientId}', which is neither the machine client '{machine}' " +
                   "nor a client listed in Management:OperatorDeviceClients";
        }

        private const string DeviceCodeGrant = "urn:ietf:params:oauth:grant-type:device_code";
    }

    internal sealed class ArkOperatorRequirement : IAuthorizationRequirement { }

    /// <summary>
    /// A principal from <see cref="ArkManagementAuth.BearerScheme"/> has already passed
    /// <see cref="ArkManagementAuth.RefusalAsync"/> — the handler admits no other — so only a
    /// console session is left to test here.
    /// </summary>
    internal sealed class ArkOperatorHandler : AuthorizationHandler<ArkOperatorRequirement>
    {
        private readonly ArkUtil _util;

        public ArkOperatorHandler(ArkUtil util) => _util = util;

        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ArkOperatorRequirement requirement)
        {
            var bearer = context.User.Identities.Any(i =>
                i.IsAuthenticated && i.AuthenticationType == ArkManagementAuth.BearerScheme);

            if (bearer || ArkOperator.IsOperator(context.User, _util.ServerConfig))
                context.Succeed(requirement);
            return Task.CompletedTask;
        }
    }

    /// <summary>
    /// Bearer tokens for the management API, validated with <see cref="Protocol.ArkTokenService"/>
    /// — the same check /userinfo and dynamic registration apply — against the operator tenant's
    /// published keys, read from the database. Fetching this server's own discovery document over
    /// HTTP would fail wherever its public address is unreachable from inside, which behind an
    /// App Service front end is most of the time.
    /// </summary>
    internal sealed class ArkManagementBearerHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private readonly ArkUtil _util;
        private readonly DataAccess _da;
        private readonly Protocol.ArkTokenService _tokens;

        public ArkManagementBearerHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder,
            ArkUtil util, DataAccess da, Protocol.ArkTokenService tokens)
            : base(options, logger, encoder)
        {
            _util = util;
            _da = da;
            _tokens = tokens;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var token = ArkManagementAuth.BearerToken(Request);
            if (token == null) return AuthenticateResult.NoResult();

            var config = _util.ServerConfig;
            var tenant = await _da.GetTenant((config.TenantId ?? "").Trim());
            if (tenant == null) return AuthenticateResult.Fail("the operator tenant does not exist yet.");

            var issuer = Protocol.ArkOidcEndpoints.For(Request, config, tenant.tenant_id).Issuer;
            var result = await _tokens.ValidateAsync(token, tenant, issuer);
            if (!result.IsValid || result.ClaimsIdentity == null)
            {
                Logger.LogWarning("management API token rejected: {Reason}", result.Exception?.Message ?? "invalid token");
                return AuthenticateResult.Fail("the bearer token is not valid.");
            }

            var refusal = await ArkManagementAuth.RefusalAsync(result.ClaimsIdentity, config, _da);
            if (refusal != null)
            {
                // Logged here because the caller only sees a 401: a well-formed token refused
                // after it validated is the hardest kind to account for from a pipeline.
                Logger.LogWarning("management API token rejected: {Reason}.", refusal);
                return AuthenticateResult.Fail(refusal);
            }

            var identity = new ClaimsIdentity(result.ClaimsIdentity.Claims, ArkManagementAuth.BearerScheme);
            return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name));
        }

        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            var presented = ArkManagementAuth.BearerToken(Request) != null;
            Response.Headers.WWWAuthenticate = presented ? "Bearer error=\"invalid_token\"" : "Bearer";
            return WriteAsync(StatusCodes.Status401Unauthorized, "unauthorized", presented
                ? "the bearer token was refused - it must be issued by this server to the machine client, with the 'client.register' scope."
                : "sign in to the admin console again, or present a bearer token from the machine client.");
        }

        protected override Task HandleForbiddenAsync(AuthenticationProperties properties) =>
            WriteAsync(StatusCodes.Status403Forbidden, "forbidden",
                "the management API is restricted to the administrator account. Another console user needs the " +
                "'admin' claim on their mapping to the console client.");

        private Task WriteAsync(int status, string code, string msg)
        {
            Response.StatusCode = status;
            Response.ContentType = "application/json";
            return Response.WriteAsync(JsonSerializer.Serialize(new { error = true, code, msg }));
        }
    }
}
