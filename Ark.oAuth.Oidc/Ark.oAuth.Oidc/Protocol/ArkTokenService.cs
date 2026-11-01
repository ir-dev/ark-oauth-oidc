using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Ark.oAuth.Oidc.Protocol
{
    /// <summary>Everything needed to mint the tokens for one grant.</summary>
    public class TokenRequestContext
    {
        public ArkTenant Tenant { get; set; } = default!;
        public ArkClient Client { get; set; } = default!;
        /// <summary>
        /// The issuer identifier these tokens assert. Supplied by the caller so the standard
        /// endpoints can use the discovery issuer while the v1 shim keeps the legacy value.
        /// </summary>
        public string Issuer { get; set; } = default!;
        /// <summary>Access token audience — the resource server, not the client.</summary>
        public string Audience { get; set; } = default!;
        public string Subject { get; set; } = default!;
        public List<string> Scopes { get; set; } = new();
        public string? SessionId { get; set; }
        public string? Nonce { get; set; }
        public DateTime AuthTime { get; set; } = DateTime.UtcNow;
        /// <summary>Set for the authorization_code grant so the ID token can carry c_hash.</summary>
        public string? AuthorizationCode { get; set; }
    }

    /// <summary>
    /// Mints the signed artefacts: access tokens as RFC 9068 JWTs and ID tokens per OIDC Core.
    /// Refresh tokens are deliberately *not* JWTs — they are opaque random strings stored as
    /// hashes by <see cref="ArkGrantStore"/>, so they can be revoked server-side.
    /// </summary>
    public class ArkTokenService
    {
        private readonly ArkKeyService _keys;
        private readonly ArkClaimsService _claims;

        public ArkTokenService(ArkKeyService keys, ArkClaimsService claims)
        {
            _keys = keys;
            _claims = claims;
        }

        /// <summary>
        /// An access token as a JWT (RFC 9068). Carries `typ: at+jwt` in the header so a resource
        /// server can refuse to accept an ID token in its place.
        /// </summary>
        public async Task<(string token, DateTime expiresAt, string jti)> IssueAccessTokenAsync(TokenRequestContext ctx)
        {
            var key = await _keys.GetActiveKeyAsync(ctx.Tenant.tenant_id);
            var now = DateTime.UtcNow;
            var expires = now.AddSeconds(ctx.Client.access_token_lifetime_seconds);
            var jti = ArkCrypto.RandomToken(16);

            var payload = new Dictionary<string, object>
            {
                ["iss"] = ctx.Issuer,
                ["aud"] = ctx.Audience,
                ["sub"] = ctx.Subject,
                ["client_id"] = ctx.Client.client_id,
                ["jti"] = jti,
                ["iat"] = ToUnix(now),
                ["nbf"] = ToUnix(now),
                ["exp"] = ToUnix(expires)
            };
            if (ctx.Scopes.Count > 0) payload["scope"] = string.Join(" ", ctx.Scopes);
            if (!string.IsNullOrEmpty(ctx.SessionId)) payload["sid"] = ctx.SessionId!;

            // authorization claims the tenant has mapped to this user/client pair
            var granted = await _claims.GetAuthorizationClaimsAsync(ctx.Subject, ctx.Tenant.tenant_id, ctx.Client);
            if (granted.Count > 0) payload["ark_claims"] = granted;

            var token = Sign(payload, key, "at+jwt");
            return (token, expires, jti);
        }

        /// <summary>
        /// An ID token per OIDC Core §2. Includes at_hash/c_hash when the corresponding artefact
        /// was issued, which is what lets a client detect a substituted access token or code.
        /// </summary>
        public async Task<string> IssueIdTokenAsync(TokenRequestContext ctx, string? accessToken)
        {
            var key = await _keys.GetActiveKeyAsync(ctx.Tenant.tenant_id);
            var now = DateTime.UtcNow;
            var expires = now.AddSeconds(ctx.Client.id_token_lifetime_seconds);

            var payload = new Dictionary<string, object>
            {
                ["iss"] = ctx.Issuer,
                ["aud"] = ctx.Client.client_id,
                ["sub"] = ctx.Subject,
                ["azp"] = ctx.Client.client_id,
                ["iat"] = ToUnix(now),
                ["nbf"] = ToUnix(now),
                ["exp"] = ToUnix(expires),
                ["auth_time"] = ToUnix(ctx.AuthTime)
            };
            if (!string.IsNullOrEmpty(ctx.Nonce)) payload["nonce"] = ctx.Nonce!;
            if (!string.IsNullOrEmpty(ctx.SessionId)) payload["sid"] = ctx.SessionId!;
            if (!string.IsNullOrEmpty(accessToken)) payload["at_hash"] = ArkCrypto.LeftHalfHash(accessToken!);
            if (!string.IsNullOrEmpty(ctx.AuthorizationCode)) payload["c_hash"] = ArkCrypto.LeftHalfHash(ctx.AuthorizationCode!);

            // identity claims unlocked by the granted scopes (profile, email, ...)
            foreach (var kv in await _claims.GetIdentityClaimsAsync(ctx.Subject, ctx.Scopes))
                payload[kv.Key] = kv.Value;

            return Sign(payload, key, "JWT");
        }

        /// <summary>
        /// A logout token (OIDC Back-Channel Logout 1.0 §2.4) — the artefact POSTed to a client's
        /// backchannel_logout_uri to tell it a session has ended.
        ///
        /// It deliberately looks almost, but not quite, like an ID token, and the differences are
        /// the security-relevant part. <c>typ: logout+jwt</c> in the header and the <c>events</c>
        /// claim identify it positively, and there is no <c>nonce</c> — the spec forbids one, so
        /// that a client which validates logout tokens through its ID token path cannot be handed
        /// a logout token where an ID token was expected, or the reverse.
        /// </summary>
        public async Task<string> IssueLogoutTokenAsync(ArkTenant tenant, ArkClient client, string issuer,
            string subject, string? sessionId, int lifetimeSeconds)
        {
            var key = await _keys.GetActiveKeyAsync(tenant.tenant_id);
            var now = DateTime.UtcNow;

            var payload = new Dictionary<string, object>
            {
                ["iss"] = issuer,
                ["aud"] = client.client_id,
                ["iat"] = ToUnix(now),
                ["exp"] = ToUnix(now.AddSeconds(lifetimeSeconds > 0 ? lifetimeSeconds : 120)),
                ["jti"] = ArkCrypto.RandomToken(16),
                // The literal URN from §2.4. Its presence, and the empty object as its value, is
                // how a client tells a logout token from any other JWT this server signs.
                ["events"] = new Dictionary<string, object>
                {
                    ["http://schemas.openid.net/event/backchannel-logout"] = new Dictionary<string, object>()
                }
            };

            // §2.4 requires at least one of sub and sid. Both are sent when both are known: sid
            // lets the client end exactly the session that ended here, and sub lets a client that
            // never stored the sid fall back to ending every session it holds for that user.
            if (!string.IsNullOrEmpty(subject)) payload["sub"] = subject;
            if (!string.IsNullOrEmpty(sessionId)) payload["sid"] = sessionId!;

            return Sign(payload, key, "logout+jwt");
        }

        private static string Sign(Dictionary<string, object> payload, ArkSigningKey key, string typ)
        {
            var rsa = ArkCrypto.ImportPrivateKey(key.private_key);
            var creds = new SigningCredentials(new RsaSecurityKey(rsa) { KeyId = key.kid }, SecurityAlgorithms.RsaSha256)
            {
                CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
            };
            var handler = new JsonWebTokenHandler();
            return handler.CreateToken(new SecurityTokenDescriptor
            {
                Claims = payload,
                SigningCredentials = creds,
                AdditionalHeaderClaims = new Dictionary<string, object> { ["typ"] = typ }
            });
        }

        /// <summary>
        /// Validates a token this server issued. Used by /userinfo and /introspect.
        ///
        /// Accepts any key currently published in JWKS, so a token signed just before a key
        /// rotation still verifies; and accepts both the standard and the legacy issuer/audience
        /// pair, so tokens minted by the v1 endpoints remain usable while clients migrate.
        /// </summary>
        public async Task<TokenValidationResult> ValidateAsync(
            string token, ArkTenant tenant, string standardIssuer, string? expectedAudience = null)
        {
            var keys = await _keys.GetPublishedKeysAsync(tenant.tenant_id);
            var issuers = new[] { standardIssuer, tenant.issuer }
                .Where(i => !string.IsNullOrEmpty(i)).Distinct().ToArray();
            var audiences = new[] { expectedAudience, tenant.audience, standardIssuer }
                .Where(a => !string.IsNullOrEmpty(a)).Distinct().ToArray()!;

            var handler = new JsonWebTokenHandler();
            return await handler.ValidateTokenAsync(token, new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuers = issuers,
                ValidateAudience = true,
                ValidAudiences = audiences!,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = _keys.GetValidationKeys(keys),
                ClockSkew = TimeSpan.FromMinutes(1)
            });
        }

        internal static long ToUnix(DateTime utc) => new DateTimeOffset(DateTime.SpecifyKind(utc, DateTimeKind.Utc)).ToUnixTimeSeconds();
    }
}
