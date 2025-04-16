using Ark.oAuth.Oidc;
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
        public async Task<bool> SendMail(string to, string html, string subject)
        {
            try
            {
                _email.SendEmail(to, html, subject);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
