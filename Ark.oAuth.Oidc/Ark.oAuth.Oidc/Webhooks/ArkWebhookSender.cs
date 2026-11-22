using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Ark.oAuth.Oidc.Webhooks
{
    /// <summary>What one attempt came to.</summary>
    public sealed class ArkWebhookSendResult
    {
        public bool Success { get; init; }
        public int? StatusCode { get; init; }
        public string? Error { get; init; }
        public int DurationMs { get; init; }
        public string? ResponseBody { get; init; }
        public TimeSpan? RetryAfter { get; init; }
        /// <summary>Worth another attempt: a timeout, a network failure, 408, 429 or 5xx (and 4xx when the endpoint asks).</summary>
        public bool Retryable { get; init; }
    }

    /// <summary>When the next attempt is due, and whether there should be one.</summary>
    public static class ArkWebhookRetryPolicy
    {
        public const int MaxAttemptsCeiling = 50;

        /// <summary>The wait after attempt <paramref name="attemptNo"/> (1-based) failed.</summary>
        public static TimeSpan Delay(ArkWebhookEndpoint ep, int attemptNo, TimeSpan? retryAfter = null, double? jitter = null)
        {
            var initial = Math.Max(1, ep.initial_delay_seconds);
            var max = Math.Max(initial, ep.max_delay_seconds);
            var n = Math.Max(1, attemptNo);
            double seconds = ep.backoff switch
            {
                ArkBackoff.Linear => (double)initial * n,
                ArkBackoff.Fixed => initial,
                _ => initial * Math.Pow(2, Math.Min(n - 1, 30))
            };
            seconds = Math.Min(seconds, max);
            // ±20%, so endpoints that failed together do not all come back in the same second.
            seconds *= 0.8 + (jitter ?? Random.Shared.NextDouble()) * 0.4;
            // A receiver that says when to come back is believed, up to the policy's ceiling.
            if (retryAfter is { } ra && ra.TotalSeconds > seconds) seconds = Math.Min(ra.TotalSeconds, max);
            return TimeSpan.FromSeconds(Math.Max(1, seconds));
        }

        public static bool IsRetryableStatus(int status, bool retryOn4xx) =>
            status == 408 || status == 429 || status >= 500 || (retryOn4xx && status >= 400 && status < 500);
    }

    /// <summary>
    /// Sends one attempt: the body as stored, the Standard Webhooks signature, the custom headers
    /// and whichever authentication the endpoint uses.
    ///
    /// No redirects are followed — a 3xx is an answer, not a forwarding address, so a receiver
    /// cannot bounce a signed event to somewhere the operator never configured — and only the
    /// first few KB of a response are read.
    /// </summary>
    public sealed class ArkWebhookSender
    {
        public const string HttpClientName = "ark-webhooks";
        public const int ResponseSnippetBytes = 4096;

        /// <summary>Headers the subsystem sets itself; a custom header may not replace them.</summary>
        public static readonly HashSet<string> ReservedHeaders = new(StringComparer.OrdinalIgnoreCase)
        {
            "host", "content-type", "content-length", "transfer-encoding", "connection", "user-agent",
            "webhook-id", "webhook-timestamp", "webhook-signature",
            "x-ark-event", "x-ark-delivery", "x-ark-attempt", "x-ark-tenant"
        };

        private static readonly string UserAgent =
            $"Ark-Webhooks/{typeof(ArkWebhookSender).Assembly.GetName().Version?.ToString(3) ?? "1"}";

        private readonly IHttpClientFactory _http;
        private readonly ArkWebhookSecrets _secrets;
        private readonly ArkWebhookTokenManager _tokens;
        private readonly IServiceScopeFactory _scopes;
        private readonly IConfiguration _config;
        private readonly ArkWebhookRegistry _registry;

        public ArkWebhookSender(IHttpClientFactory http, ArkWebhookSecrets secrets, ArkWebhookTokenManager tokens,
            IServiceScopeFactory scopes, IConfiguration config, ArkWebhookRegistry registry)
        {
            _http = http;
            _secrets = secrets;
            _tokens = tokens;
            _scopes = scopes;
            _config = config;
            _registry = registry;
        }

        /// <summary>
        /// Refuses a URL the subsystem should never call: anything but http(s), credentials in the
        /// URL, and plain http to anything but loopback unless AllowInsecureHttp is on.
        /// </summary>
        public static string? UrlProblem(string? url, bool allowInsecureHttp)
        {
            if (string.IsNullOrWhiteSpace(url)) return "a URL is required.";
            if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri)) return "the URL is not an absolute URL.";
            if (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp) return "the URL must be http or https.";
            if (!string.IsNullOrEmpty(uri.UserInfo)) return "credentials do not belong in the URL - use Basic authentication.";
            if (uri.Scheme == Uri.UriSchemeHttp && !uri.IsLoopback && !allowInsecureHttp)
                return "plain http is allowed only to localhost unless ark_oauth_server:Webhooks:AllowInsecureHttp is true.";
            if (url.Length > 2048) return "the URL is longer than 2048 characters.";
            return null;
        }

        public async Task<ArkWebhookSendResult> SendAsync(ArkWebhookEndpointView ep, ArkWebhookDelivery delivery, int attemptNo, CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            var timeout = TimeSpan.FromSeconds(Math.Clamp(ep.Row.timeout_seconds, 1, 120));
            try
            {
                var problem = UrlProblem(ep.Row.url, _registry.Options.AllowInsecureHttp);
                if (problem != null) return Fail(sw, null, problem, retryable: false);

                var bag = _secrets.Unprotect(ep.Row.secrets_);
                using var request = new HttpRequestMessage(HttpMethod.Post, ep.Row.url.Trim());
                request.Content = new StringContent(delivery.payload, Encoding.UTF8, "application/json");

                // Custom headers first: everything set after them is the subsystem's own.
                foreach (var name in ep.HeaderNames)
                {
                    if (ReservedHeaders.Contains(name) || !bag.headers.TryGetValue(name, out var value)) continue;
                    if (!request.Headers.TryAddWithoutValidation(name, value))
                        request.Content.Headers.TryAddWithoutValidation(name, value);
                }

                var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
                request.Headers.TryAddWithoutValidation("User-Agent", UserAgent);
                request.Headers.TryAddWithoutValidation("webhook-id", delivery.event_id);
                request.Headers.TryAddWithoutValidation("webhook-timestamp", timestamp);
                if (!string.IsNullOrEmpty(bag.signing_secret))
                    request.Headers.TryAddWithoutValidation("webhook-signature", Sign(bag.signing_secret, delivery.event_id, timestamp, delivery.payload));
                request.Headers.TryAddWithoutValidation("X-Ark-Event", delivery.event_type);
                request.Headers.TryAddWithoutValidation("X-Ark-Delivery", delivery.id);
                request.Headers.TryAddWithoutValidation("X-Ark-Attempt", attemptNo.ToString());
                request.Headers.TryAddWithoutValidation("X-Ark-Tenant", delivery.tenant_id);

                string? sentToken = null;
                try
                {
                    sentToken = await ApplyAuthAsync(request, ep, bag, delivery, attemptNo, ct);
                }
                catch (ArkWebhookException ex)
                {
                    // A token endpoint that is down is worth retrying; credentials that cannot be
                    // read, or a configuration that cannot work, are not.
                    return Fail(sw, null, $"authentication: {ex.Message}", retryable: ex.Code is "token_failed" or "token_busy");
                }

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(timeout);
                var client = _http.CreateClient(HttpClientName);
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token);
                var body = await ReadSnippetAsync(response, cts.Token);
                var status = (int)response.StatusCode;
                sw.Stop();

                if (status >= 200 && status < 300)
                    return new ArkWebhookSendResult { Success = true, StatusCode = status, DurationMs = (int)sw.ElapsedMilliseconds, ResponseBody = body };

                var retryable = ArkWebhookRetryPolicy.IsRetryableStatus(status, ep.Row.retry_on_4xx);
                if (status == 401 && ep.Row.auth_type == ArkWebhookAuthType.OAuth2 && sentToken != null)
                {
                    // The access token was refused: the next attempt gets a new one.
                    _tokens.Reject(ep.Id, sentToken);
                    retryable = true;
                }
                var reason = status >= 300 && status < 400
                    ? $"HTTP {status}: redirects are not followed - configure the final URL"
                    : $"HTTP {status} {response.ReasonPhrase}".Trim();
                return new ArkWebhookSendResult
                {
                    Success = false,
                    StatusCode = status,
                    Error = reason,
                    DurationMs = (int)sw.ElapsedMilliseconds,
                    ResponseBody = body,
                    RetryAfter = RetryAfter(response),
                    Retryable = retryable
                };
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return Fail(sw, null, $"timed out after {timeout.TotalSeconds:0} s", retryable: true);
            }
            catch (HttpRequestException ex)
            {
                return Fail(sw, null, $"connection failed: {ex.GetBaseException().Message}", retryable: true);
            }
            catch (ArkWebhookException ex)
            {
                return Fail(sw, null, ex.Message, retryable: false);
            }
        }

        private static ArkWebhookSendResult Fail(Stopwatch sw, int? status, string error, bool retryable)
        {
            sw.Stop();
            return new ArkWebhookSendResult { Success = false, StatusCode = status, Error = error, DurationMs = (int)sw.ElapsedMilliseconds, Retryable = retryable };
        }

        /// <summary>
        /// Standard Webhooks (standardwebhooks.com): HMAC-SHA256 over "{id}.{timestamp}.{body}"
        /// with the base64 key after "whsec_", sent as "v1,{base64}". Any of its libraries verifies it.
        /// </summary>
        public static string Sign(string secret, string id, string timestamp, string body)
        {
            var raw = secret.StartsWith("whsec_", StringComparison.Ordinal) ? secret[6..] : secret;
            byte[] key;
            try { key = Convert.FromBase64String(raw); }
            catch (FormatException) { key = Encoding.UTF8.GetBytes(raw); }
            var mac = HMACSHA256.HashData(key, Encoding.UTF8.GetBytes($"{id}.{timestamp}.{body}"));
            return "v1," + Convert.ToBase64String(mac);
        }

        /// <summary>Adds the endpoint's authentication. Returns the bearer token sent, when there is one.</summary>
        private async Task<string?> ApplyAuthAsync(HttpRequestMessage request, ArkWebhookEndpointView ep, ArkWebhookSecretBag bag,
            ArkWebhookDelivery delivery, int attemptNo, CancellationToken ct)
        {
            var auth = ep.Auth;
            switch (ep.Row.auth_type)
            {
                case ArkWebhookAuthType.Basic:
                {
                    var raw = Encoding.UTF8.GetBytes($"{auth.basic_username}:{bag.basic_password}");
                    request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(raw));
                    return null;
                }
                case ArkWebhookAuthType.Bearer:
                {
                    if (string.IsNullOrEmpty(bag.bearer_token))
                        throw new ArkWebhookException("auth_incomplete", "no bearer token is stored.");
                    SetToken(request, auth.bearer_header, auth.bearer_scheme ?? "Bearer", bag.bearer_token);
                    return bag.bearer_token;
                }
                case ArkWebhookAuthType.Jwt:
                {
                    var token = await MintJwtAsync(ep, bag, delivery, attemptNo);
                    SetToken(request, auth.jwt_header, "Bearer", token);
                    return token;
                }
                case ArkWebhookAuthType.OAuth2:
                {
                    var token = await _tokens.GetAsync(ep, bag, ct);
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                    return token;
                }
                default:
                    return null;
            }
        }

        private static void SetToken(HttpRequestMessage request, string? header, string scheme, string token)
        {
            if (string.IsNullOrWhiteSpace(header) || header.Equals("Authorization", StringComparison.OrdinalIgnoreCase))
            {
                request.Headers.Authorization = string.IsNullOrWhiteSpace(scheme)
                    ? null
                    : new AuthenticationHeaderValue(scheme.Trim(), token);
                if (string.IsNullOrWhiteSpace(scheme)) request.Headers.TryAddWithoutValidation("Authorization", token);
                return;
            }
            request.Headers.Remove(header);
            request.Headers.TryAddWithoutValidation(header.Trim(), token);
        }

        /// <summary>Claims a mint may not be given by the extra-claims JSON.</summary>
        private static readonly HashSet<string> ReservedClaims = new(StringComparer.Ordinal)
        {
            "iss", "aud", "iat", "nbf", "exp", "jti", "sub", "evt", "evt_type", "tenant_id", "body_sha256"
        };

        /// <summary>A short-lived JWT for this attempt, carrying a hash of the body so it cannot be lifted onto another one.</summary>
        internal async Task<string> MintJwtAsync(ArkWebhookEndpointView ep, ArkWebhookSecretBag bag, ArkWebhookDelivery delivery, int attemptNo)
        {
            var auth = ep.Auth;
            var now = DateTime.UtcNow;
            var lifetime = Math.Clamp(auth.jwt_lifetime_seconds <= 0 ? 300 : auth.jwt_lifetime_seconds, 30, 3600);
            var claims = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["sub"] = ep.Id,
                ["jti"] = $"{delivery.id}.{attemptNo}",
                ["evt"] = delivery.event_id,
                ["evt_type"] = delivery.event_type,
                ["tenant_id"] = delivery.tenant_id,
                ["body_sha256"] = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(delivery.payload)))
            };
            foreach (var (k, v) in ExtraClaims(auth.jwt_claims))
                if (!ReservedClaims.Contains(k)) claims[k] = v;

            SigningCredentials credentials;
            string issuer = auth.jwt_issuer ?? "";
            if (string.Equals(auth.jwt_alg, "RS256", StringComparison.OrdinalIgnoreCase))
            {
                using var scope = _scopes.CreateScope();
                var keys = scope.ServiceProvider.GetRequiredService<Protocol.ArkKeyService>();
                var key = await keys.GetActiveKeyAsync(delivery.tenant_id);
                credentials = keys.GetSigningCredentials(key);
                if (string.IsNullOrWhiteSpace(issuer))
                {
                    var server = Protocol.ArkConfigSnapshot.Server(_config);
                    try { issuer = server == null ? "" : Protocol.ArkOidcEndpoints.For(server, delivery.tenant_id).Issuer; }
                    catch (ApplicationException) { issuer = ""; }
                }
            }
            else
            {
                if (string.IsNullOrEmpty(bag.jwt_secret) || Encoding.UTF8.GetByteCount(bag.jwt_secret) < 32)
                    throw new ArkWebhookException("auth_incomplete", "the HS256 secret is missing or shorter than 32 bytes.");
                credentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(bag.jwt_secret)), SecurityAlgorithms.HmacSha256);
            }

            var audience = auth.jwt_audience;
            if (string.IsNullOrWhiteSpace(audience) && Uri.TryCreate(ep.Row.url, UriKind.Absolute, out var uri))
                audience = uri.GetLeftPart(UriPartial.Authority);

            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = string.IsNullOrWhiteSpace(issuer) ? null : issuer,
                Audience = audience,
                IssuedAt = now,
                NotBefore = now.AddSeconds(-5),
                Expires = now.AddSeconds(lifetime),
                Claims = claims,
                SigningCredentials = credentials
            };
            return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(descriptor);
        }

        internal static Dictionary<string, object> ExtraClaims(string? json)
        {
            var result = new Dictionary<string, object>(StringComparer.Ordinal);
            if (string.IsNullOrWhiteSpace(json)) return result;
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return result;
            foreach (var p in doc.RootElement.EnumerateObject())
            {
                result[p.Name] = p.Value.ValueKind switch
                {
                    JsonValueKind.String => p.Value.GetString()!,
                    JsonValueKind.True => true,
                    JsonValueKind.False => false,
                    JsonValueKind.Number when p.Value.TryGetInt64(out var l) => l,
                    JsonValueKind.Number => p.Value.GetDouble(),
                    _ => p.Value.Clone()
                };
            }
            return result;
        }

        private static async Task<string?> ReadSnippetAsync(HttpResponseMessage response, CancellationToken ct)
        {
            try
            {
                await using var stream = await response.Content.ReadAsStreamAsync(ct);
                var buffer = new byte[ResponseSnippetBytes];
                var read = 0;
                while (read < buffer.Length)
                {
                    var n = await stream.ReadAsync(buffer.AsMemory(read, buffer.Length - read), ct);
                    if (n == 0) break;
                    read += n;
                }
                return read == 0 ? null : Encoding.UTF8.GetString(buffer, 0, read);
            }
            catch
            {
                return null;
            }
        }

        private static TimeSpan? RetryAfter(HttpResponseMessage response)
        {
            var ra = response.Headers.RetryAfter;
            if (ra == null) return null;
            if (ra.Delta is { } delta) return delta;
            if (ra.Date is { } date) return date - DateTimeOffset.UtcNow;
            return null;
        }
    }
}
