using System.Collections.Concurrent;
using System.Text.Json;

namespace Ark.oAuth
{
    /// <summary>
    /// The client credentials grant (RFC 6749 §4.4) — a service authenticating as itself.
    ///
    /// There is no user in this flow and no browser: the client sends its own credentials to the
    /// token endpoint and gets back an access token that says nothing about a person. Use it for
    /// scheduled jobs, service-to-service calls and daemons; never to act on behalf of a signed-in
    /// user, because the resulting token carries the service's authority rather than theirs, and
    /// nothing downstream can tell the difference.
    ///
    /// The token endpoint is read from the provider's discovery document, so this class needs the
    /// issuer and nothing else.
    /// </summary>
    public sealed class ArkClientCredentials
    {
        private readonly ArkAuthConfig _config;
        private readonly ArkSetupProbe _probe;
        private readonly IHttpClientFactory _http;

        // Cached per client_id + scope: a service that asks for a token on every outbound call
        // turns one request into two and rate-limits itself against its own IdP.
        private static readonly ConcurrentDictionary<string, ArkTokenResult> Cache = new();
        private static readonly TimeSpan RenewBefore = TimeSpan.FromSeconds(60);

        public ArkClientCredentials(ArkAuthConfig config, ArkSetupProbe probe, IHttpClientFactory http)
        {
            _config = config;
            _probe = probe;
            _http = http;
        }

        /// <summary>
        /// Returns a cached token when one is still valid, and requests a new one otherwise.
        ///
        /// This is what production code should call. A client credentials token is not tied to a
        /// session and typically lasts an hour, so re-requesting it per call is pure overhead.
        /// </summary>
        public async Task<ArkTokenResult> GetTokenAsync(
            string clientId, string clientSecret, IEnumerable<string>? scopes = null,
            string? authority = null, CancellationToken cancellationToken = default)
        {
            var scopeValue = string.Join(" ", scopes ?? Enumerable.Empty<string>());
            var key = $"{authority ?? _config.ResolveAuthority()}|{clientId}|{scopeValue}";

            if (Cache.TryGetValue(key, out var cached) && cached.Succeeded &&
                cached.ExpiresAt - DateTimeOffset.UtcNow > RenewBefore)
                return cached;

            var result = await RequestTokenAsync(clientId, clientSecret, scopes, authority, cancellationToken);
            if (result.Succeeded) Cache[key] = result;
            return result;
        }

        /// <summary>
        /// Performs the grant, bypassing the cache, and reports the exchange in full — request
        /// form, HTTP status and response body — so a failure can be read rather than guessed at.
        /// </summary>
        public async Task<ArkTokenResult> RequestTokenAsync(
            string clientId, string clientSecret, IEnumerable<string>? scopes = null,
            string? authority = null, CancellationToken cancellationToken = default)
        {
            var result = new ArkTokenResult();

            if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret))
            {
                result.Error = "invalid_client";
                result.ErrorDescription = "the client_credentials grant needs a client_id and a client_secret.";
                return result;
            }

            try
            {
                var metadata = await _probe.ReadMetadataAsync(authority, cancellationToken);
                if (string.IsNullOrEmpty(metadata.TokenEndpoint))
                {
                    result.Error = "server_error";
                    result.ErrorDescription = "the provider's discovery document has no token_endpoint.";
                    return result;
                }

                result.TokenEndpoint = metadata.TokenEndpoint!;

                var form = new Dictionary<string, string>
                {
                    ["grant_type"] = "client_credentials",
                    // client_secret_post rather than an Authorization: Basic header. Both are
                    // standard; this one is easier to read in a trace, and Ark accepts either.
                    ["client_id"] = clientId,
                    ["client_secret"] = clientSecret
                };
                var scopeValue = string.Join(" ", scopes ?? Enumerable.Empty<string>());
                if (!string.IsNullOrWhiteSpace(scopeValue)) form["scope"] = scopeValue;

                // What gets shown to an operator: never the secret itself.
                result.RequestForm = form
                    .Select(kv => new KeyValuePair<string, string>(
                        kv.Key, kv.Key == "client_secret" ? "••••••••" : kv.Value))
                    .ToList();

                var client = _http.CreateClient("ark-oidc-client");
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
                    ? seconds : 3600;
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

        /// <summary>Clears the cache — for a screen that wants to show a live exchange.</summary>
        public static void ClearCache() => Cache.Clear();
    }

    /// <summary>The outcome of a token request, success or failure, with enough to diagnose it.</summary>
    public class ArkTokenResult
    {
        public string TokenEndpoint { get; set; } = "";
        public int StatusCode { get; set; }

        public string? AccessToken { get; set; }
        public string? TokenType { get; set; }
        public string? Scope { get; set; }
        public int ExpiresIn { get; set; }
        public DateTimeOffset ExpiresAt { get; set; }

        public string? Error { get; set; }
        public string? ErrorDescription { get; set; }

        /// <summary>The posted form, with the secret redacted.</summary>
        public List<KeyValuePair<string, string>> RequestForm { get; set; } = new();
        public string? RawResponse { get; set; }

        public bool Succeeded => !string.IsNullOrEmpty(AccessToken) && string.IsNullOrEmpty(Error);

        /// <summary>The token's payload, decoded for display only.</summary>
        public string? AccessTokenPayload => ArkJwt.DecodePayload(AccessToken);
    }
}
