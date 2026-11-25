using System.Collections.Concurrent;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace Ark.oAuth
{
    /// <summary>
    /// Agent-to-agent (A2A) tokens — what one agent presents to another.
    ///
    /// A token from here is addressed to one agent (its <c>aud</c> is that agent's client_id) and
    /// is good nowhere else. There are two ways to ask, and one method for both:
    ///
    ///  * <b>as itself</b> — no subject token. The <c>client_credentials</c> grant with
    ///    <c>audience</c>; the token's <c>sub</c> is this client and its <c>ark_claims</c> are what
    ///    the target granted it.
    ///  * <b>on behalf of a user</b> — with a subject token: the signed-in user's access token, or
    ///    an agent token this agent was sent. Token exchange (RFC 8693); <c>sub</c> stays the
    ///    user, <c>ark_claims</c> are the user's own at the target, and <c>act</c> names every
    ///    agent on the way.
    ///
    /// The target decides who may call it: an operator lists this client on the target's client
    /// record in the console. Until then the provider answers <c>invalid_target</c>.
    /// </summary>
    public sealed class ArkAgentTokens
    {
        public const string TokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange";
        public const string AccessTokenType = "urn:ietf:params:oauth:token-type:access_token";

        private readonly ArkAuthConfig _config;
        private readonly IHttpClientFactory _http;

        // Per target, and per user when acting for one. Agent tokens live minutes, so the window
        // before expiry in which a new one is fetched is short too.
        private static readonly ConcurrentDictionary<string, ArkTokenResult> Cache = new();
        private static readonly TimeSpan RenewBefore = TimeSpan.FromSeconds(30);

        public ArkAgentTokens(ArkAuthConfig config, IHttpClientFactory http)
        {
            _config = config;
            _http = http;
        }

        /// <summary>
        /// A token for calling the agent <paramref name="audience"/> (its client_id), cached until
        /// shortly before it expires. Send <see cref="ArkTokenResult.AccessToken"/> as
        /// <c>Authorization: Bearer</c>; check <see cref="ArkTokenResult.Succeeded"/> first.
        /// </summary>
        public async Task<ArkTokenResult> GetTokenAsync(
            string audience, string? subjectToken = null, IEnumerable<string>? scopes = null,
            CancellationToken cancellationToken = default)
        {
            var scopeValue = string.Join(" ", scopes ?? Enumerable.Empty<string>());
            // Hashed, so the cache never holds the user's token; and part of the key, so one
            // user's token is never answered with another's.
            var onBehalfOf = Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(subjectToken ?? "")));
            var key = $"{_config.ResolveAuthority()}|{_config.ClientId}|{audience}|{onBehalfOf}|{scopeValue}";

            if (Cache.TryGetValue(key, out var cached) && cached.Succeeded &&
                cached.ExpiresAt - DateTimeOffset.UtcNow > RenewBefore)
                return cached;

            var result = await RequestTokenAsync(audience, subjectToken, scopes, cancellationToken);
            if (result.Succeeded)
            {
                // One entry per user per target would otherwise grow for as long as the process lives.
                if (Cache.Count > 512)
                    foreach (var stale in Cache.Where(kv => kv.Value.ExpiresAt <= DateTimeOffset.UtcNow).ToList())
                        Cache.TryRemove(stale.Key, out _);
                Cache[key] = result;
            }
            return result;
        }

        /// <summary>
        /// Performs the request, bypassing the cache, and reports the exchange in full — request
        /// form, HTTP status and response body — so a refusal can be read rather than guessed at.
        /// </summary>
        public async Task<ArkTokenResult> RequestTokenAsync(
            string audience, string? subjectToken = null, IEnumerable<string>? scopes = null,
            CancellationToken cancellationToken = default)
        {
            var result = new ArkTokenResult();

            if (string.IsNullOrWhiteSpace(audience))
            {
                result.Error = "invalid_request";
                result.ErrorDescription = "an agent token needs the client_id of the agent to call.";
                return result;
            }
            if (string.IsNullOrWhiteSpace(_config.ClientId) || string.IsNullOrWhiteSpace(_config.ClientSecret))
            {
                result.Error = "invalid_client";
                result.ErrorDescription = "an agent must be a confidential client: ark_oauth_client needs ClientId and ClientSecret.";
                return result;
            }

            try
            {
                var client = _http.CreateClient(ArkOidcClient.HttpClientName);
                var metadata = await ArkDiscoveryCache.GetAsync(client, _config);
                if (string.IsNullOrEmpty(metadata?.TokenEndpoint))
                {
                    result.Error = "server_error";
                    result.ErrorDescription = "the provider's discovery document could not be read, or has no token_endpoint.";
                    return result;
                }
                result.TokenEndpoint = metadata.TokenEndpoint;

                var form = new Dictionary<string, string>
                {
                    ["grant_type"] = string.IsNullOrEmpty(subjectToken) ? "client_credentials" : TokenExchangeGrant,
                    ["audience"] = audience,
                    ["client_id"] = _config.ClientId,
                    ["client_secret"] = _config.ClientSecret!
                };
                if (!string.IsNullOrEmpty(subjectToken))
                {
                    form["subject_token"] = subjectToken!;
                    form["subject_token_type"] = AccessTokenType;
                }
                var scopeValue = string.Join(" ", scopes ?? Enumerable.Empty<string>());
                if (!string.IsNullOrWhiteSpace(scopeValue)) form["scope"] = scopeValue;

                // What gets shown to an operator: never the secret, never the user's token.
                result.RequestForm = form
                    .Select(kv => new KeyValuePair<string, string>(
                        kv.Key, kv.Key is "client_secret" or "subject_token" ? "••••••••" : kv.Value))
                    .ToList();

                using var response = await client.PostAsync(
                    metadata.TokenEndpoint, new FormUrlEncodedContent(form), cancellationToken);
                var body = await response.Content.ReadAsStringAsync(cancellationToken);
                result.StatusCode = (int)response.StatusCode;
                result.RawResponse = ArkJson.Prettify(body);

                using var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;
                string? Str(string name) =>
                    root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

                if (!response.IsSuccessStatusCode)
                {
                    result.Error = Str("error") ?? "invalid_request";
                    result.ErrorDescription = Str("error_description");
                    return result;
                }

                result.AccessToken = Str("access_token");
                result.TokenType = Str("token_type");
                result.Scope = Str("scope");
                var lifetime = root.TryGetProperty("expires_in", out var exp) && exp.TryGetInt32(out var seconds)
                    ? seconds : 300;
                result.ExpiresIn = lifetime;
                result.ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(lifetime);
            }
            catch (Exception ex)
            {
                result.Error = "request_failed";
                result.ErrorDescription = ex.Message;
            }

            return result;
        }

        /// <summary>
        /// The security section of this agent's A2A Agent Card, as the provider writes it, as
        /// JSON: <c>securitySchemes</c> and <c>securityRequirements</c> (A2A 1.0), or with
        /// <paramref name="spec"/> "0.3" the <c>securitySchemes</c> and <c>security</c> of A2A 0.3.
        /// Merge it into the card you publish at <c>/.well-known/agent-card.json</c>.
        /// </summary>
        public async Task<string> GetAgentCardSecurityAsync(string? spec = null, CancellationToken cancellationToken = default)
        {
            var url = $"{_config.ResolveAuthority()}/a2a/agent-card-security";
            if (!string.IsNullOrWhiteSpace(spec)) url += $"?spec={Uri.EscapeDataString(spec)}";
            return await _http.CreateClient(ArkOidcClient.HttpClientName).GetStringAsync(url, cancellationToken);
        }

        /// <summary>Clears the cache — for a screen that wants to show a live exchange.</summary>
        public static void ClearCache() => Cache.Clear();
    }

    /// <summary>The agent-to-agent (A2A) pieces an application touches directly.</summary>
    public static class ArkAgentExtensions
    {
        /// <summary>
        /// Protects an agent's endpoints: <see cref="ArkOidcClient.AddArkOidcApi"/> that accepts
        /// only tokens addressed to this agent — <c>aud</c> is its own client_id — so a token
        /// another agent was given for somebody else is refused here.
        /// </summary>
        public static AuthenticationBuilder AddArkAgentApi(
            this AuthenticationBuilder builder, ArkAuthConfig config, string scheme = JwtBearerDefaults.AuthenticationScheme)
        {
            if (string.IsNullOrWhiteSpace(config.ClientId))
                throw new InvalidOperationException("AddArkAgentApi needs ark_oauth_client:ClientId — it is the audience an agent accepts.");
            builder.Services.AddArkHttpClient();
            builder.Services.TryAddAgentTokens(config);

            builder.AddArkOidcApi(config, scheme);
            builder.Services.PostConfigure<JwtBearerOptions>(scheme, options =>
            {
                options.TokenValidationParameters.ValidateAudience = true;
                options.TokenValidationParameters.ValidAudience = config.ClientId;
                options.TokenValidationParameters.AudienceValidator = null;
                // Whatever RequireAccessTokenTypeHeader says: this client's own ID tokens and logout
                // tokens carry the same audience, and the type is the only thing that tells them
                // from an agent token.
                options.TokenValidationParameters.ValidTypes = new[] { "at+jwt", "application/at+jwt" };
            });
            return builder;
        }

        internal static void TryAddAgentTokens(this IServiceCollection services, ArkAuthConfig config)
        {
            if (services.Any(d => d.ServiceType == typeof(ArkAgentTokens))) return;
            if (!services.Any(d => d.ServiceType == typeof(ArkAuthConfig))) services.AddSingleton(config);
            services.AddSingleton<ArkAgentTokens>();
        }

        /// <summary>
        /// The agents acting for this caller (A2A), newest first, from the token's <c>act</c>
        /// claim (RFC 8693 §4.1). The first is the agent that called you; each later one handed
        /// the user on to it. Empty when the caller acts as itself.
        /// </summary>
        public static IReadOnlyList<string> ArkActors(this ClaimsPrincipal? user)
        {
            var chain = new List<string>();
            var raw = user?.FindFirst("act")?.Value;
            if (string.IsNullOrWhiteSpace(raw)) return chain;
            try
            {
                using var doc = JsonDocument.Parse(raw);
                var current = doc.RootElement;
                while (current.ValueKind == JsonValueKind.Object && chain.Count < 32)
                {
                    if (current.TryGetProperty("sub", out var sub) && sub.ValueKind == JsonValueKind.String
                        && !string.IsNullOrEmpty(sub.GetString()))
                        chain.Add(sub.GetString()!);
                    if (!current.TryGetProperty("act", out var next)) break;
                    current = next;
                }
            }
            catch (JsonException)
            {
                // not an act claim this library wrote; nobody is named
            }
            return chain;
        }

        /// <summary>
        /// A token for calling the agent <paramref name="audience"/> on behalf of whoever this
        /// request is from: the signed-in user (their session's access token), or — inside an
        /// agent — the bearer token it was called with. Null when the request carries neither or
        /// the provider refuses.
        ///
        /// The session goes first. A request authenticated by its cookie is that user's, whatever
        /// Authorization header came with it; read the other way round, an application authorized
        /// one person and called the agent as another.
        /// </summary>
        public static async Task<string?> GetArkAgentTokenAsync(
            this HttpContext context, string audience, IEnumerable<string>? scopes = null)
        {
            var tokens = context.RequestServices.GetService(typeof(ArkAgentTokens)) as ArkAgentTokens;
            if (tokens == null) return null;

            // Which scheme spoke for this request, where the pipeline says: a bearer token that
            // authenticated it goes first there, so a cookie that merely came along does not.
            var scheme = context.Features.Get<IAuthenticateResultFeature>()?.AuthenticateResult?.Ticket?.AuthenticationScheme;
            var bySession = scheme == ArkOidcClient.CookieScheme;
            var byBearer = scheme != null && !scheme.Split(';').Contains(ArkOidcClient.CookieScheme);

            string? subjectToken = null;
            if (!byBearer)
            {
                try { subjectToken = await context.GetArkAccessTokenAsync(); }
                catch (InvalidOperationException) { /* no cookie scheme in an API-only host */ }
            }
            if (string.IsNullOrEmpty(subjectToken) && !bySession)
            {
                var header = context.Request.Headers.Authorization.ToString();
                if (header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                    subjectToken = header["Bearer ".Length..].Trim();
            }
            if (string.IsNullOrEmpty(subjectToken)) return null;

            var result = await tokens.GetTokenAsync(audience, subjectToken, scopes, context.RequestAborted);
            return result.Succeeded ? result.AccessToken : null;
        }
    }
}
