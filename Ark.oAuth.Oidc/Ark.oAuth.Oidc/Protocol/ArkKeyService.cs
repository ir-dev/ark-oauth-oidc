using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace Ark.oAuth.Oidc.Protocol
{
    /// <summary>
    /// Owns the tenant signing keys behind /jwks.json.
    ///
    /// Rotation is two-phase so it never invalidates tokens that are still in flight:
    /// the new key becomes 'active' and starts signing, the previous key moves to 'rollover'
    /// and stays published in JWKS until it is retired. Clients that cache JWKS therefore
    /// keep verifying older tokens across a rotation.
    /// </summary>
    public class ArkKeyService
    {
        private readonly ArkDataContext _ctx;

        public ArkKeyService(ArkDataContext ctx)
        {
            _ctx = ctx;
        }

        /// <summary>
        /// The key new tokens are signed with. On first call for a tenant this adopts the
        /// tenant's existing rsa_private/rsa_public pair, keeping kid == tenant_id so tokens
        /// issued by earlier versions of the server continue to validate against published JWKS.
        /// </summary>
        public async Task<ArkSigningKey> GetActiveKeyAsync(string tenantId)
        {
            var key = await _ctx.signing_keys
                .Where(k => k.tenant_id == tenantId && k.status == "active")
                .OrderByDescending(k => k.created_at)
                .FirstOrDefaultAsync();
            if (key != null) return key;

            var tenant = await _ctx.tenants.FirstOrDefaultAsync(t => t.tenant_id == tenantId)
                ?? throw OAuthException.ServerError($"unknown tenant '{tenantId}'.");

            if (!string.IsNullOrEmpty(tenant.rsa_private) && !string.IsNullOrEmpty(tenant.rsa_public))
            {
                // adopt the legacy tenant key; kid stays the tenant id for backwards compatibility
                key = new ArkSigningKey
                {
                    kid = tenant.tenant_id,
                    tenant_id = tenant.tenant_id,
                    alg = "RS256",
                    usage = "sig",
                    public_key = tenant.rsa_public,
                    private_key = tenant.rsa_private,
                    status = "active",
                    created_at = DateTime.UtcNow
                };
            }
            else
            {
                var (pub, priv) = ArkCrypto.GenerateRsaKeyPair();
                key = new ArkSigningKey
                {
                    kid = ArkCrypto.ComputeKid(pub),
                    tenant_id = tenantId,
                    alg = "RS256",
                    usage = "sig",
                    public_key = pub,
                    private_key = priv,
                    status = "active",
                    created_at = DateTime.UtcNow
                };
                tenant.rsa_public = pub;
                tenant.rsa_private = priv;
                _ctx.tenants.Update(tenant);
            }

            _ctx.signing_keys.Add(key);
            await _ctx.SaveChangesAsync();
            return key;
        }

        /// <summary>Every key that should appear in JWKS: the signing key plus any still in rollover.</summary>
        public async Task<List<ArkSigningKey>> GetPublishedKeysAsync(string tenantId)
        {
            await GetActiveKeyAsync(tenantId); // ensure at least one key exists
            return await _ctx.signing_keys
                .Where(k => k.tenant_id == tenantId && (k.status == "active" || k.status == "rollover"))
                .OrderByDescending(k => k.created_at)
                .ToListAsync();
        }

        /// <summary>
        /// Generates a fresh signing key and demotes the current one to 'rollover'.
        /// Retire the old key separately once its longest-lived token has expired.
        /// </summary>
        public async Task<ArkSigningKey> RotateAsync(string tenantId)
        {
            var current = await GetActiveKeyAsync(tenantId);
            current.status = "rollover";
            current.not_after = DateTime.UtcNow;
            _ctx.signing_keys.Update(current);

            var (pub, priv) = ArkCrypto.GenerateRsaKeyPair();
            var next = new ArkSigningKey
            {
                kid = ArkCrypto.ComputeKid(pub),
                tenant_id = tenantId,
                alg = "RS256",
                usage = "sig",
                public_key = pub,
                private_key = priv,
                status = "active",
                created_at = DateTime.UtcNow
            };
            _ctx.signing_keys.Add(next);

            // keep the tenant row pointing at the signing key so legacy consumers stay in step
            var tenant = await _ctx.tenants.FirstOrDefaultAsync(t => t.tenant_id == tenantId);
            if (tenant != null)
            {
                tenant.rsa_public = pub;
                tenant.rsa_private = priv;
                _ctx.tenants.Update(tenant);
            }

            await _ctx.SaveChangesAsync();
            return next;
        }

        /// <summary>Drops a rollover key out of JWKS. Tokens signed by it stop validating.</summary>
        public async Task RetireAsync(string tenantId, string kid)
        {
            var key = await _ctx.signing_keys.FirstOrDefaultAsync(k => k.tenant_id == tenantId && k.kid == kid);
            if (key == null || key.status == "active") return;
            key.status = "retired";
            key.not_after = DateTime.UtcNow;
            _ctx.signing_keys.Update(key);
            await _ctx.SaveChangesAsync();
        }

        public SigningCredentials GetSigningCredentials(ArkSigningKey key)
        {
            var rsa = ArkCrypto.ImportPrivateKey(key.private_key);
            return new SigningCredentials(new RsaSecurityKey(rsa) { KeyId = key.kid }, SecurityAlgorithms.RsaSha256)
            {
                CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
            };
        }

        public IEnumerable<SecurityKey> GetValidationKeys(IEnumerable<ArkSigningKey> keys) =>
            keys.Select(k => new RsaSecurityKey(ArkCrypto.ImportPublicKey(k.public_key)) { KeyId = k.kid });

        /// <summary>Renders keys as an RFC 7517 JWK Set.</summary>
        public object BuildJwks(IEnumerable<ArkSigningKey> keys)
        {
            var jwks = new List<object>();
            foreach (var k in keys)
            {
                using var rsa = ArkCrypto.ImportPublicKey(k.public_key);
                var p = rsa.ExportParameters(false);
                jwks.Add(new
                {
                    kty = "RSA",
                    use = k.usage,
                    alg = k.alg,
                    kid = k.kid,
                    n = ArkCrypto.Base64UrlEncode(p.Modulus!),
                    e = ArkCrypto.Base64UrlEncode(p.Exponent!)
                });
            }
            return new { keys = jwks };
        }
    }
}
