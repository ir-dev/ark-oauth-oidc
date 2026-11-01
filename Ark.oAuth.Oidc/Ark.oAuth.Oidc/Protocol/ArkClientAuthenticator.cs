using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Ark.oAuth.Oidc.Protocol
{
    /// <summary>The outcome of authenticating a client at a token-family endpoint.</summary>
    public class ClientAuthResult
    {
        public ArkClient Client { get; set; } = default!;
        public string Method { get; set; } = "none";
        /// <summary>True when credentials arrived in the Authorization header, which changes a failure to 401.</summary>
        public bool UsedAuthorizationHeader { get; set; }
    }

    /// <summary>
    /// Authenticates clients at /token, /introspect, /revoke, /par and /device_authorization.
    ///
    /// Supports the methods named in discovery: client_secret_basic, client_secret_post,
    /// private_key_jwt and none. RFC 6749 §2.3 forbids presenting more than one set of
    /// credentials in a single request, so that is rejected rather than resolved by precedence.
    /// </summary>
    public class ArkClientAuthenticator
    {
        private readonly ArkDataContext _ctx;
        private readonly IMemoryCache _cache;
        private readonly IHttpClientFactory _httpFactory;

        public const string PrivateKeyJwtAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

        public ArkClientAuthenticator(ArkDataContext ctx, IMemoryCache cache, IHttpClientFactory httpFactory)
        {
            _ctx = ctx;
            _cache = cache;
            _httpFactory = httpFactory;
        }

        public async Task<ClientAuthResult> AuthenticateAsync(HttpRequest request, string tenantId, string tokenEndpoint)
        {
            var form = request.HasFormContentType ? await request.ReadFormAsync() : null;

            string? basicId = null, basicSecret = null;
            var hasBasic = TryReadBasicHeader(request, out basicId, out basicSecret);

            var postId = form?["client_id"].ToString();
            var postSecret = form?["client_secret"].ToString();
            var hasPost = !string.IsNullOrEmpty(postSecret);

            var assertionType = form?["client_assertion_type"].ToString();
            var assertion = form?["client_assertion"].ToString();
            var hasAssertion = !string.IsNullOrEmpty(assertion);

            var methodCount = (hasBasic ? 1 : 0) + (hasPost ? 1 : 0) + (hasAssertion ? 1 : 0);
            if (methodCount > 1)
                throw OAuthException.InvalidRequest("more than one client authentication method was used.");

            if (hasBasic)
                return await AuthenticateSecretAsync(tenantId, basicId!, basicSecret, "client_secret_basic", true);

            if (hasPost)
                return await AuthenticateSecretAsync(tenantId, postId!, postSecret, "client_secret_post", false);

            if (hasAssertion)
            {
                if (!string.Equals(assertionType, PrivateKeyJwtAssertionType, StringComparison.Ordinal))
                    throw OAuthException.InvalidRequest("unsupported client_assertion_type.");
                return await AuthenticatePrivateKeyJwtAsync(tenantId, assertion!, tokenEndpoint);
            }

            // No credentials: only a registered public client may proceed.
            var clientId = postId;
            if (string.IsNullOrEmpty(clientId))
                throw OAuthException.InvalidClient("client authentication failed: no client_id was supplied.");

            var client = await FindClientAsync(tenantId, clientId);
            if (client == null)
                throw OAuthException.InvalidClient("client authentication failed: unknown client.");
            if (!client.IsPublicClient)
                throw OAuthException.InvalidClient("this client is confidential and must authenticate.");
            // Every method refuses a deactivated client, not only the secret-based ones — a public
            // SPA or CLI switched off in the console must stop at the token endpoint too.
            if (!client.is_active)
                throw OAuthException.InvalidClient("client is disabled.");

            return new ClientAuthResult { Client = client, Method = "none" };
        }

        private async Task<ClientAuthResult> AuthenticateSecretAsync(
            string tenantId, string clientId, string? secret, string method, bool viaHeader)
        {
            var client = await FindClientAsync(tenantId, clientId);

            // Verify against a dummy hash when the client is unknown so that a bad client_id and a
            // bad secret cost the same amount of time and cannot be told apart by an attacker.
            var stored = client?.client_secret_hash ?? DummyHash.Value;
            var ok = ArkCrypto.VerifySecret(secret, stored);

            if (client == null || !ok)
                throw OAuthException.InvalidClient("client authentication failed.", viaHeader);
            if (!client.is_active)
                throw OAuthException.InvalidClient("client is disabled.", viaHeader);
            if (client.client_secret_expires_at != null && client.client_secret_expires_at <= DateTime.UtcNow)
                throw OAuthException.InvalidClient("client secret has expired.", viaHeader);
            if (!string.Equals(client.token_endpoint_auth_method, method, StringComparison.OrdinalIgnoreCase))
                throw OAuthException.InvalidClient($"client is registered for {client.token_endpoint_auth_method}.", viaHeader);

            return new ClientAuthResult { Client = client, Method = method, UsedAuthorizationHeader = viaHeader };
        }

        /// <summary>
        /// private_key_jwt (OIDC Core §9). Verifies the assertion against the client's published
        /// JWKS and rejects a repeated jti, so a captured assertion cannot be replayed.
        /// </summary>
        private async Task<ClientAuthResult> AuthenticatePrivateKeyJwtAsync(string tenantId, string assertion, string tokenEndpoint)
        {
            var handler = new JsonWebTokenHandler();
            JsonWebToken parsed;
            try
            {
                parsed = handler.ReadJsonWebToken(assertion);
            }
            catch
            {
                throw OAuthException.InvalidClient("client_assertion is not a well-formed JWT.");
            }

            var clientId = parsed.Issuer;
            if (string.IsNullOrEmpty(clientId))
                throw OAuthException.InvalidClient("client_assertion is missing 'iss'.");

            var client = await FindClientAsync(tenantId, clientId)
                ?? throw OAuthException.InvalidClient("client authentication failed: unknown client.");
            if (!client.is_active)
                throw OAuthException.InvalidClient("client is disabled.");
            if (!string.Equals(client.token_endpoint_auth_method, "private_key_jwt", StringComparison.OrdinalIgnoreCase))
                throw OAuthException.InvalidClient($"client is registered for {client.token_endpoint_auth_method}.");
            if (string.IsNullOrEmpty(client.jwks_uri))
                throw OAuthException.InvalidClient("client has no jwks_uri registered to verify the assertion.");

            // iss and sub must both be the client id (OIDC Core §9)
            if (!string.Equals(parsed.Subject, clientId, StringComparison.Ordinal))
                throw OAuthException.InvalidClient("client_assertion 'sub' must equal 'iss'.");

            var keys = await GetClientKeysAsync(client.jwks_uri!);
            var result = await handler.ValidateTokenAsync(assertion, new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = clientId,
                ValidateAudience = true,
                // the endpoint URL is the canonical audience; the issuer identifier is widely accepted too
                ValidAudiences = new[] { tokenEndpoint, TrimEndpoint(tokenEndpoint) },
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = keys,
                ClockSkew = TimeSpan.FromMinutes(1)
            });

            if (!result.IsValid)
                throw OAuthException.InvalidClient($"client_assertion is invalid: {result.Exception?.Message}");

            // replay protection: a jti may be presented only once within its lifetime
            var jti = parsed.Id;
            if (string.IsNullOrEmpty(jti))
                throw OAuthException.InvalidClient("client_assertion is missing 'jti'.");
            var cacheKey = $"ark:pkjwt:{clientId}:{jti}";
            if (_cache.TryGetValue(cacheKey, out _))
                throw OAuthException.InvalidClient("client_assertion has already been used.");
            _cache.Set(cacheKey, true, parsed.ValidTo == default ? DateTimeOffset.UtcNow.AddMinutes(5) : new DateTimeOffset(parsed.ValidTo));

            return new ClientAuthResult { Client = client, Method = "private_key_jwt" };
        }

        private static string TrimEndpoint(string endpoint)
        {
            var idx = endpoint.IndexOf("/oauth2/", StringComparison.OrdinalIgnoreCase);
            return idx > 0 ? endpoint[..idx] : endpoint;
        }

        private async Task<List<SecurityKey>> GetClientKeysAsync(string jwksUri)
        {
            var cacheKey = $"ark:jwks:{jwksUri}";
            if (_cache.TryGetValue<List<SecurityKey>>(cacheKey, out var cached) && cached != null) return cached;

            try
            {
                var http = _httpFactory.CreateClient("ark-oidc");
                var json = await http.GetStringAsync(jwksUri);
                var jwks = new JsonWebKeySet(json);
                var keys = jwks.GetSigningKeys().ToList();
                _cache.Set(cacheKey, keys, TimeSpan.FromMinutes(10));
                return keys;
            }
            catch
            {
                // No exception text: the URI is fetched server-side, and echoing what the fetch ran
                // into turns the token endpoint into a probe of whatever network this host sits on.
                throw OAuthException.InvalidClient("could not retrieve the client's JWKS.");
            }
        }

        private static bool TryReadBasicHeader(HttpRequest request, out string? clientId, out string? secret)
        {
            clientId = null;
            secret = null;
            var header = request.Headers["Authorization"].ToString();
            if (string.IsNullOrEmpty(header) || !header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
                return false;
            try
            {
                var raw = Encoding.UTF8.GetString(Convert.FromBase64String(header["Basic ".Length..].Trim()));
                var split = raw.IndexOf(':');
                if (split < 0) return false;
                // RFC 6749 §2.3.1: both halves are form-urlencoded before being joined
                clientId = Uri.UnescapeDataString(raw[..split]);
                secret = Uri.UnescapeDataString(raw[(split + 1)..]);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public async Task<ArkClient?> FindClientAsync(string tenantId, string? clientId)
        {
            if (string.IsNullOrEmpty(clientId)) return null;
            return await _ctx.clients.FirstOrDefaultAsync(c =>
                c.tenant_id.ToLower() == (tenantId ?? "").ToLower() &&
                c.client_id.ToLower() == clientId.ToLower());
        }

        /// <summary>A fixed valid-format hash used to keep unknown-client timing indistinguishable.</summary>
        private static readonly Lazy<string> DummyHash = new(() => ArkCrypto.HashSecret("ark-oidc-dummy-secret"));
    }

    /// <summary>Redirect URI matching per OAuth 2.1 §4.1.3 and RFC 8252 §7.3.</summary>
    public static class RedirectUriValidator
    {
        /// <summary>
        /// Exact string comparison, with one carve-out: a native client registered against a
        /// loopback address may vary the port, because it cannot reserve one in advance.
        /// No wildcards, no prefix matching, no case folding of the path.
        /// </summary>
        public static bool Matches(IEnumerable<string> registered, string candidate)
        {
            if (string.IsNullOrEmpty(candidate)) return false;

            foreach (var uri in registered)
            {
                if (string.Equals(uri, candidate, StringComparison.Ordinal)) return true;
                if (IsLoopbackVariant(uri, candidate)) return true;
            }
            return false;
        }

        private static bool IsLoopbackVariant(string registered, string candidate)
        {
            if (!Uri.TryCreate(registered, UriKind.Absolute, out var a)) return false;
            if (!Uri.TryCreate(candidate, UriKind.Absolute, out var b)) return false;
            if (!IsLoopbackHost(a.Host) || !IsLoopbackHost(b.Host)) return false;
            return string.Equals(a.Scheme, b.Scheme, StringComparison.OrdinalIgnoreCase)
                && string.Equals(a.Host, b.Host, StringComparison.OrdinalIgnoreCase)
                && string.Equals(a.AbsolutePath, b.AbsolutePath, StringComparison.Ordinal);
        }

        private static bool IsLoopbackHost(string host) =>
            host == "127.0.0.1" || host == "::1" || host == "[::1]" ||
            string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// Schemes a browser executes or renders as a document from the page that navigates to
        /// them. A redirect URI is written into this server's own pages — the form_post action
        /// above all — so one of these registered as a "redirect" is script running on the
        /// identity provider's origin. Custom native-app schemes (com.example.app:/cb) stay legal.
        /// </summary>
        private static readonly HashSet<string> ScriptSchemes = new(StringComparer.OrdinalIgnoreCase)
        {
            "javascript", "vbscript", "data", "file", "blob", "about", "filesystem"
        };

        /// <summary>
        /// An absolute URI, free of whitespace and control characters, whose scheme is not one of
        /// <see cref="ScriptSchemes"/>. Whitespace is refused outright rather than parsed around:
        /// browsers drop tabs and newlines from a URL before reading its scheme, so
        /// <c>java&#9;script:</c> fails <see cref="Uri.TryCreate(string, UriKind, out Uri)"/>
        /// here and still runs there.
        ///
        /// The console's client editor checks only this, so an operator's existing http redirect
        /// on an intranet host keeps saving; dynamic registration applies the stricter
        /// <see cref="IsAcceptableRedirect"/>.
        /// </summary>
        public static bool IsSafeUri(string? uri) =>
            !string.IsNullOrEmpty(uri)
            && !CarriesScript(uri)
            && ExplicitScheme.IsMatch(uri)
            // Uri also reads a bare "/path" as an absolute file: URI on Unix, so the parsed scheme
            // is checked as well as the literal one.
            && Uri.TryCreate(uri, UriKind.Absolute, out var parsed)
            && !ScriptSchemes.Contains(parsed.Scheme);

        /// <summary>
        /// Whitespace or a control character anywhere, or a script scheme in front. The minimum
        /// any stored URI has to clear; relative values pass, since they can never match a real
        /// redirect and some legacy columns hold them.
        ///
        /// The scheme is read off the text the way a browser reads it — everything before the
        /// first colon — not through <see cref="Uri"/>, which on Unix parses "/logout" as
        /// file:///logout and would refuse every relative value as a file: URI.
        /// </summary>
        public static bool CarriesScript(string uri)
        {
            if (uri.Any(c => char.IsWhiteSpace(c) || char.IsControl(c))) return true;
            var scheme = ExplicitScheme.Match(uri);
            return scheme.Success && ScriptSchemes.Contains(scheme.Groups[1].Value);
        }

        private static readonly System.Text.RegularExpressions.Regex ExplicitScheme =
            new(@"^([A-Za-z][A-Za-z0-9+.\-]*):", System.Text.RegularExpressions.RegexOptions.Compiled);

        /// <summary>A safe URI with no fragment, and http only for loopback (RFC 8252 §7.3).</summary>
        public static bool IsAcceptableRedirect(string? uri) =>
            IsSafeUri(uri)
            && Uri.TryCreate(uri, UriKind.Absolute, out var parsed)
            && string.IsNullOrEmpty(parsed.Fragment)
            && (parsed.Scheme != Uri.UriSchemeHttp || parsed.IsLoopback);

        /// <summary>An absolute http(s) URL — for metadata rendered as a link or fetched server-side.</summary>
        public static bool IsWebUrl(string? uri) =>
            IsSafeUri(uri)
            && Uri.TryCreate(uri, UriKind.Absolute, out var parsed)
            && (parsed.Scheme == Uri.UriSchemeHttps || parsed.Scheme == Uri.UriSchemeHttp);
    }
}
