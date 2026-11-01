using System.Text.Json;
using Microsoft.AspNetCore.Http;

namespace Ark.oAuth
{
    /// <summary>
    /// Reads the provider's discovery document and pairs it with this application's own
    /// configuration.
    ///
    /// Fetching discovery here is not duplicated work — it is exactly what the OpenID Connect
    /// handler does on its first challenge, done somewhere the failure can be read. Without it the
    /// first symptom of a wrong port, a stopped provider or an untrusted development certificate
    /// is an exception thrown out of the sign-in redirect, which says nothing about which of the
    /// three it was.
    ///
    /// Registered by <c>AddArkOidcClient</c>; inject it into any page that wants to show setup
    /// state.
    /// </summary>
    public sealed class ArkSetupProbe
    {
        private readonly ArkAuthConfig _config;
        private readonly IHttpClientFactory _http;

        public ArkSetupProbe(ArkAuthConfig config, IHttpClientFactory http)
        {
            _config = config;
            _http = http;
        }

        /// <summary>
        /// Builds the full picture for the current request: configured values, the provider's
        /// metadata, and whether anyone is signed in.
        /// </summary>
        public async Task<ArkSetupModel> ProbeAsync(HttpContext context, CancellationToken cancellationToken = default)
        {
            var authority = _config.ResolveAuthority();
            var request = context.Request;
            var origin = $"{request.Scheme}://{request.Host}{request.PathBase}";

            var model = new ArkSetupModel
            {
                Authority = authority,
                ClientId = _config.ClientId ?? "",
                IsConfidential = !string.IsNullOrWhiteSpace(_config.ClientSecret),
                Scopes = _config.ResolveScopes(),
                RoleClaimType = _config.RoleClaimType ?? "role",
                Origin = origin,
                RedirectUri = origin + (_config.CallbackPath ?? "/signin-oidc"),
                PostLogoutRedirectUri = origin + (_config.SignedOutCallbackPath ?? "/signout-callback-oidc"),
                DiscoveryUrl = DiscoveryUrl(authority),
                IsAuthenticated = context.User?.Identity?.IsAuthenticated == true,
                SignedInAs = context.User?.FindFirst("name")?.Value ?? context.User?.FindFirst("email")?.Value
            };

            if (string.IsNullOrWhiteSpace(authority))
            {
                model.DiscoveryError = "ark_oauth_client:Authority is not set.";
                return model;
            }

            try
            {
                model.Provider = await ReadMetadataAsync(authority, cancellationToken);
                model.DiscoveryOk = true;
            }
            catch (Exception ex)
            {
                model.DiscoveryError = ex.Message;
            }

            return model;
        }

        /// <summary>
        /// Fetches and parses the provider metadata document.
        ///
        /// Throws rather than returning a null-ish object, because every caller has to say
        /// something different about the failure and swallowing it here would hide the only
        /// diagnostic there is.
        /// </summary>
        public async Task<ArkProviderMetadata> ReadMetadataAsync(string? authority = null, CancellationToken cancellationToken = default)
        {
            authority = string.IsNullOrWhiteSpace(authority) ? _config.ResolveAuthority() : authority!;
            if (string.IsNullOrWhiteSpace(authority))
                throw new InvalidOperationException("ark_oauth_client:Authority is not set.");

            var client = _http.CreateClient("ark-oidc-client");
            using var response = await client.GetAsync(DiscoveryUrl(authority), cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            if (!response.IsSuccessStatusCode)
                throw new HttpRequestException($"the provider answered {(int)response.StatusCode} {response.ReasonPhrase}.");

            return Parse(body);
        }

        public static string DiscoveryUrl(string authority) =>
            $"{authority.TrimEnd('/')}/.well-known/openid-configuration";

        private static ArkProviderMetadata Parse(string json)
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            string? Str(string name) =>
                root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

            List<string> Arr(string name) =>
                root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array
                    ? v.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.String)
                       .Select(e => e.GetString() ?? "").ToList()
                    : new List<string>();

            return new ArkProviderMetadata
            {
                Issuer = Str("issuer"),
                AuthorizationEndpoint = Str("authorization_endpoint"),
                TokenEndpoint = Str("token_endpoint"),
                UserInfoEndpoint = Str("userinfo_endpoint"),
                EndSessionEndpoint = Str("end_session_endpoint"),
                JwksUri = Str("jwks_uri"),
                RegistrationEndpoint = Str("registration_endpoint"),
                DeviceAuthorizationEndpoint = Str("device_authorization_endpoint"),
                PushedAuthorizationRequestEndpoint = Str("pushed_authorization_request_endpoint"),
                IntrospectionEndpoint = Str("introspection_endpoint"),
                RevocationEndpoint = Str("revocation_endpoint"),
                ScopesSupported = Arr("scopes_supported"),
                GrantTypesSupported = Arr("grant_types_supported"),
                ResponseTypesSupported = Arr("response_types_supported"),
                ResponseModesSupported = Arr("response_modes_supported"),
                CodeChallengeMethodsSupported = Arr("code_challenge_methods_supported"),
                TokenEndpointAuthMethodsSupported = Arr("token_endpoint_auth_methods_supported"),
                ClaimsSupported = Arr("claims_supported"),
                Raw = ArkJson.Prettify(json)
            };
        }
    }
}
