using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Ark.oAuth.Oidc
{
    public class TokenServer
    {
        private readonly IConfiguration _configuration;
        DataAccess _da;

        public TokenServer(IConfiguration configuration, DataAccess da)
        {
            _configuration = configuration;
            _da = da;
        }
        public async System.Threading.Tasks.Task<(string, DateTime)> BuildAsymmetric_AccessToken(ArkTenant tenant, string code)
        {
            if (string.IsNullOrEmpty(tenant.rsa_private)) throw new ApplicationException("tenant_cert_missing.");
            return BuildToken(tenant, 300, new Claim[] { new Claim("code", code) });
        }
        (string, DateTime) BuildToken(ArkTenant tenant, int exiration_mins, Claim[] claims)
        {
            var privateKey = tenant.rsa_private.ToByteArray();
            //uncomment for ubuntu releases
            RSA rsa = RSA.Create();
            //comment below for ubuntu
            #region WindowsSupport
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                CspParameters cspParams = new CspParameters();
                cspParams.KeyContainerName = Guid.NewGuid().ToString().ToUpperInvariant();
                cspParams.Flags = CspProviderFlags.UseMachineKeyStore;
                //RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(cspParams);
                rsa = new RSACryptoServiceProvider(cspParams);
            }
            #endregion
            rsa.ImportPkcs8PrivateKey(privateKey, out _);
            //var signCreds = new SigningCredentials(new RsaSecurityKey(rsa) { KeyId = client.client_id }, SecurityAlgorithms.RsaSha256)
            //{
            //    CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
            //};
            var signCreds = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256)
            {
                CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
            };
            var now = DateTime.UtcNow;
            var exp_at = now.AddMinutes(exiration_mins);
            var unixTimeSeconds = new DateTimeOffset(now).ToUnixTimeSeconds();
            var jwt = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
                audience: tenant.audience,
                issuer: tenant.issuer,
                claims: claims,
                notBefore: now,
                expires: exp_at,
                signingCredentials: signCreds
            );
            //jwt.Header.Add("kid", client.client_id);
            string token = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().WriteToken(jwt);
            return (token, exp_at);
        }
    }
}
