using Ark.oAuth.Oidc;
using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace Ark.oAuth
{
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
        //https://rsa-key-gen.immanuel.co/api/keys
        public async Task<dynamic> GetKeys()
        {
            HttpClient httpClient = new HttpClient();
            httpClient.BaseAddress = new Uri(@"https://rsa-key-gen.immanuel.co");
            var resp = await httpClient.GetStringAsync("api/keys");
            var jo = System.Text.Json.JsonSerializer.Deserialize<JsonObject>(resp);
            return new
            {
                private_key = jo["private_key"]?.GetValue<string>(),
                public_key = jo["public_key"]?.GetValue<string>()
            };
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
            return email_content;
        }
        public async Task<bool> SendMail(string to, string html, string subject)
        {
            try
            {
                _email.SendEmail(new string[] { to }, (_ser.CcList ?? "").Split(',', ';').Where(t => !string.IsNullOrEmpty(t.Trim())).Select(t => t.Trim()).ToArray() , (_ser.BccList ?? "").Split(',', ';').Where(t => !string.IsNullOrEmpty(t.Trim())).Select(t => t.Trim()).ToArray(), html, subject, _ser.EmailConfig.display);
                return true;
            }
            catch (Exception ex)
            {
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
