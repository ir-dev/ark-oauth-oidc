using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;

namespace Ark.oAuth.Oidc.Webhooks
{
    /// <summary>
    /// The non-secret half of an endpoint's authentication, stored as JSON in
    /// <see cref="ArkWebhookEndpoint.auth_"/> and returned to the console as it is.
    /// </summary>
    public sealed class ArkWebhookAuthConfig
    {
        // basic
        public string? basic_username { get; set; }

        // bearer (static token)
        /// <summary>Header carrying the token; "Authorization" sends "{scheme} {token}".</summary>
        public string? bearer_header { get; set; }
        public string? bearer_scheme { get; set; }

        // jwt (minted per request)
        /// <summary>HS256 (shared secret) or RS256 (the tenant's active signing key, verifiable against its JWKS).</summary>
        public string? jwt_alg { get; set; }
        public string? jwt_issuer { get; set; }
        public string? jwt_audience { get; set; }
        public int jwt_lifetime_seconds { get; set; } = 300;
        public string? jwt_header { get; set; }
        /// <summary>Extra claims, as a JSON object. Never secret: anyone holding a request can read them.</summary>
        public string? jwt_claims { get; set; }

        // oauth2
        /// <summary>refresh_token or client_credentials.</summary>
        public string? oauth_grant { get; set; }
        public string? oauth_token_url { get; set; }
        public string? oauth_client_id { get; set; }
        public string? oauth_scope { get; set; }
        public string? oauth_audience { get; set; }
        /// <summary>client_secret_post or client_secret_basic.</summary>
        public string? oauth_client_auth { get; set; }

        public static ArkWebhookAuthConfig Read(string? json)
        {
            if (string.IsNullOrWhiteSpace(json)) return new ArkWebhookAuthConfig();
            try { return JsonSerializer.Deserialize<ArkWebhookAuthConfig>(json) ?? new ArkWebhookAuthConfig(); }
            catch { return new ArkWebhookAuthConfig(); }
        }

        public string Write() => JsonSerializer.Serialize(this);
    }

    /// <summary>Every secret an endpoint holds. Never returned by the API; only "is it set".</summary>
    public sealed class ArkWebhookSecretBag
    {
        public string? basic_password { get; set; }
        public string? bearer_token { get; set; }
        public string? jwt_secret { get; set; }
        public string? oauth_client_secret { get; set; }
        public string? oauth_refresh_token { get; set; }
        /// <summary>The Standard Webhooks signing secret, "whsec_" + base64.</summary>
        public string? signing_secret { get; set; }
        /// <summary>Custom header values by name. Values are treated as secret because they usually are (API keys).</summary>
        public Dictionary<string, string> headers { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>An OAuth 2.0 access token, and the refresh token it was rotated to, shared by every instance.</summary>
    public sealed class ArkWebhookTokenState
    {
        public string? access_token { get; set; }
        public DateTime expires_at { get; set; }
        /// <summary>The newest refresh token, when the token endpoint rotated it.</summary>
        public string? refresh_token { get; set; }
    }

    /// <summary>
    /// Encrypts endpoint secrets with ASP.NET Core data protection — the key ring the IdP already
    /// keeps in its database for every instance (or in the host's own store), so any instance can
    /// read what another wrote. A secret that cannot be decrypted (the key ring was replaced) fails
    /// the attempt with a message saying to enter it again, rather than sending an empty one.
    /// </summary>
    public sealed class ArkWebhookSecrets
    {
        private const string Purpose = "Ark.oAuth.Oidc.Webhooks.Secrets.v1";
        private readonly IDataProtector _protector;

        public ArkWebhookSecrets(IDataProtectionProvider provider) => _protector = provider.CreateProtector(Purpose);

        public string Protect(ArkWebhookSecretBag bag) => _protector.Protect(JsonSerializer.Serialize(bag));

        public ArkWebhookSecretBag Unprotect(string? blob)
        {
            if (string.IsNullOrWhiteSpace(blob)) return new ArkWebhookSecretBag();
            try
            {
                var bag = JsonSerializer.Deserialize<ArkWebhookSecretBag>(_protector.Unprotect(blob)) ?? new ArkWebhookSecretBag();
                bag.headers = new Dictionary<string, string>(bag.headers ?? new(), StringComparer.OrdinalIgnoreCase);
                return bag;
            }
            catch (CryptographicException)
            {
                throw new ArkWebhookException("credentials_unreadable",
                    "the endpoint's stored credentials could not be decrypted (the data-protection key ring changed) - enter them again.", 409);
            }
        }

        public string ProtectToken(ArkWebhookTokenState state) => _protector.Protect(JsonSerializer.Serialize(state));

        public ArkWebhookTokenState? UnprotectToken(string? blob)
        {
            if (string.IsNullOrWhiteSpace(blob)) return null;
            try { return JsonSerializer.Deserialize<ArkWebhookTokenState>(_protector.Unprotect(blob)); }
            catch { return null; }   // unreadable token state is simply fetched again
        }

        /// <summary>A new Standard Webhooks signing secret.</summary>
        public static string NewSigningSecret() => "whsec_" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    }
}
