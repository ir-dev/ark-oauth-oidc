using Ark.oAuth.Oidc;
using Ark.oAuth.Oidc.Protocol;
using System.Security.Cryptography;

namespace Ark.oAuth
{
    /// <summary>
    /// An RSA signing pair, base64 SubjectPublicKeyInfo / PKCS#8.
    ///
    /// Named rather than anonymous because <see cref="ArkUtil.GetKeys"/> is typed
    /// <c>dynamic</c>: anonymous types are internal, so `dd.private_key` binds inside this
    /// assembly but throws RuntimeBinderException for anyone consuming the package.
    /// </summary>
    public class ArkKeyPair
    {
        public string private_key { get; set; } = "";
        public string public_key { get; set; } = "";
    }

    public class ArkUtil
    {
        private readonly IConfiguration _config;
        public ArkUtil(IConfiguration config)
        {
            _config = config;
        }

        // Read per use, not captured in the constructor. This is a singleton, and a server started
        // with nothing configured is configured later, by the setup wizard, without a restart:
        // a copy taken at construction would keep the empty one for the life of the process.
        private ArkAuthServerConfig _ser =>
            _config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>() ?? throw new ApplicationException("server config missing");

        private ark.net.util.EmailUtil _email
        {
            get
            {
                var ec = _ser.EmailConfig ?? throw new ApplicationException("ark_oauth_server:EmailConfig is not configured");
                return new ark.net.util.EmailUtil(ec.email, ec.pw, ec.from, ec.display, ec.subject, ec.smtp, ec.port);
            }
        }
        public ArkAuthServerConfig ServerConfig { get { return _ser; } }
        /// <summary>
        /// Mints an RSA signing pair for a tenant, base64 SubjectPublicKeyInfo / PKCS#8 — the
        /// same shape <see cref="Oidc.Protocol.ArkCrypto.GenerateRsaKeyPair"/> writes into
        /// signing_keys, so a tenant created here and one created by the bootstrap seed are
        /// indistinguishable.
        ///
        /// This used to GET https://rsa-key-gen.immanuel.co/api/keys. That service is a single
        /// point of failure the server cannot do without — while it is down (it currently answers
        /// 503) creating a tenant fails outright — and it put the tenant's *private* key on the
        /// wire and on a third-party machine. Seeding and key rotation were already moved
        /// in-process; this was the last caller left behind.
        /// </summary>
        public Task<dynamic> GetKeys()
        {
            var (publicKey, privateKey) = Oidc.Protocol.ArkCrypto.GenerateRsaKeyPair();
            return Task.FromResult<dynamic>(new ArkKeyPair
            {
                private_key = privateKey,
                public_key = publicKey
            });
        }
        //public async Task<string> GetActivationEmail(ArkTenantConfig tc, string uid)
        //{
        //    string email_content = System.IO.File.ReadAllText(System.IO.Path.Combine(Environment.CurrentDirectory, "wwwroot", "email", "user_activation_.html"));
        //    email_content = email_content.Replace("{{host_logo}}", tc.host_logo);
        //    email_content = email_content.Replace("{{client_logo}}", tc.client_logo);
        //    email_content = email_content.Replace("{{client_website_url}}", tc.client_website_url);
        //    email_content = email_content.Replace("{{host_website_url}}", tc.host_website_url);
        //    var reg_link = string.Format(tc.activation_link, tc.tenant_id, uid);
        //    email_content = email_content.Replace("{{registration_link}}", reg_link);
        //    email_content = email_content.Replace("{{registration_link}}", reg_link);
        //    email_content = email_content.Replace("{{privacy_policy_url}}", tc.privacy_policy_url);
        //    email_content = email_content.Replace("{{terms_url}}", tc.terms_url);
        //    email_content = email_content.Replace("{{host_company_name}}", tc.host_company_name);
        //    return email_content;
        //}
        public async Task<string> GetActivationEmail(string tenant_id, string uid)
        {
            string email_content = System.IO.File.ReadAllText(System.IO.Path.Combine(Environment.CurrentDirectory, "wwwroot", "email", "user_activation_.html"));
            email_content = email_content.Replace("{{host_logo}}", _ser.EmailConfig.host_logo);
            email_content = email_content.Replace("{{client_logo}}", _ser.EmailConfig.client_logo);
            email_content = email_content.Replace("{{client_website_url}}", _ser.EmailConfig.client_website_url);
            email_content = email_content.Replace("{{host_website_url}}", _ser.EmailConfig.host_website_url);
            var reg_link = string.Format(_ser.EmailConfig.activation_link, tenant_id, uid);
            email_content = email_content.Replace("{{registration_link}}", reg_link);
            email_content = email_content.Replace("{{registration_link}}", reg_link);
            email_content = email_content.Replace("{{privacy_policy_url}}", _ser.EmailConfig.privacy_policy_url);
            email_content = email_content.Replace("{{terms_url}}", _ser.EmailConfig.terms_url);
            email_content = email_content.Replace("{{host_company_name}}", _ser.EmailConfig.host_company_name);
            email_content = email_content.Replace("{{host_company_display}}", _ser.EmailConfig.host_company_display);
            return email_content;
        }
        public async Task<bool> SendMail(string to, string html, string subject, DataAccess da)
        {
            try
            {
                _email.SendEmail(new string[] { to }, (_ser.CcList ?? "").Split(',', ';').Where(t => !string.IsNullOrEmpty(t.Trim())).Select(t => t.Trim()).ToArray() , (_ser.BccList ?? "").Split(',', ';').Where(t => !string.IsNullOrEmpty(t.Trim())).Select(t => t.Trim()).ToArray(), html, subject, _ser.EmailConfig.display);
                return true;
            }
            catch (Exception ex)
            {
                da.LogError(ex, "send_email", $"{to}", $"sending email failed");
                return false;
            }
        }
        /// <summary>
        /// Hashes a password in <see cref="ArkCrypto.HashSecret(string, int)"/>'s format —
        /// <c>{iterations}.{salt}.{hash}</c>, a 32-byte PBKDF2-SHA256 at no less than
        /// <see cref="ArkCrypto.SecretIterations"/>. The original format (base64 of a
        /// 16-byte salt and a 20-byte hash, 100,000 iterations implied) is still verified, and is
        /// rewritten in this one at the next successful sign-in.
        /// </summary>
        public string HashPasswordPBKDF2(string password, int iterations = 100000) =>
            ArkCrypto.HashSecret(password, Math.Max(iterations, ArkCrypto.SecretIterations));

        /// <summary>
        /// How a service account's bearer token is stored in <c>hash_pw</c>: a digest, so the
        /// column no longer holds a year-long credential in the clear. The prefix keeps it from
        /// ever verifying as a password.
        /// </summary>
        public static string ServiceTokenDigest(string token) => "sha256:" + ArkCrypto.Sha256Base64Url(token);

        /// <summary>True for a hash in the original format, which sign-in upgrades.</summary>
        public static bool IsLegacyPasswordHash(string? savedPasswordHash) =>
            !string.IsNullOrEmpty(savedPasswordHash) && !savedPasswordHash.Contains('.');

        public bool IsTraceEnabled { get { return _ser.EnableLogTrace; } }

        /// <summary>
        /// Verifies a password in constant time. False — never an exception — for an empty or
        /// malformed hash, which includes a service account's bearer token in the same column.
        /// </summary>
        public bool VerifyPasswordPBKDF2(string password, string savedPasswordHash, int iterations = 100000)
        {
            if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(savedPasswordHash)) return false;
            if (!IsLegacyPasswordHash(savedPasswordHash))
                return ArkCrypto.VerifySecret(password, savedPasswordHash);
            try
            {
                byte[] hashBytes = Convert.FromBase64String(savedPasswordHash);
                if (hashBytes.Length != 36) return false;
                var hash = Rfc2898DeriveBytes.Pbkdf2(password, hashBytes.AsSpan(0, 16), iterations, HashAlgorithmName.SHA256, 20);
                // The loop this replaces returned at the first differing byte.
                return CryptographicOperations.FixedTimeEquals(hash, hashBytes.AsSpan(16, 20));
            }
            catch (FormatException)
            {
                return false;
            }
        }

        /// <summary>
        /// Verified when there is no account, or no mapping, to check against, so those failures
        /// take as long as a wrong password and the response time does not reveal which it was.
        /// </summary>
        internal static readonly Lazy<string> DummyPasswordHash =
            new(() => ArkCrypto.HashSecret(ArkCrypto.RandomToken(16)));
    }
}
