using Ark.oAuth.Oidc;
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
        private readonly ArkAuthServerConfig _ser;
        private readonly ark.net.util.EmailUtil _email;
        public ArkUtil(IConfiguration config)
        {
            _config = config;
            _ser = _config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>() ?? throw new ApplicationException("server config missing");
            _email = new ark.net.util.EmailUtil(_ser.EmailConfig.email,
                _ser.EmailConfig.pw,
                _ser.EmailConfig.from,
                _ser.EmailConfig.display,
                _ser.EmailConfig.subject,
                _ser.EmailConfig.smtp,
                _ser.EmailConfig.port);
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
        public string HashPasswordPBKDF2(string password, int iterations = 100000)
        {
            // Generate a random salt
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            //new RNGCryptoServiceProvider().GetBytes(salt = new byte[16]);

            // Create the hash
            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
            byte[] hash = pbkdf2.GetBytes(20); // 20-byte hash

            // Combine salt and hash
            byte[] hashBytes = new byte[36];
            Array.Copy(salt, 0, hashBytes, 0, 16);
            Array.Copy(hash, 0, hashBytes, 16, 20);

            // Convert to base64
            string savedPasswordHash = Convert.ToBase64String(hashBytes);

            return savedPasswordHash;
        }
        public bool IsTraceEnabled { get { return _ser.EnableLogTrace; } }
        public bool VerifyPasswordPBKDF2(string password, string savedPasswordHash, int iterations = 100000)
        {
            // Extract bytes from saved hash
            byte[] hashBytes = Convert.FromBase64String(savedPasswordHash);

            // Get salt
            byte[] salt = new byte[16];
            Array.Copy(hashBytes, 0, salt, 0, 16);

            // Compute hash of the provided password
            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
            byte[] hash = pbkdf2.GetBytes(20);

            // Compare hashes
            for (int i = 0; i < 20; i++)
            {
                if (hashBytes[i + 16] != hash[i])
                {
                    return false;
                }
            }

            return true;
        }
    }
}
