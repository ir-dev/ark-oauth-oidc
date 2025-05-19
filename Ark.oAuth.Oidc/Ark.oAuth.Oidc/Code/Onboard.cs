
using System.Text;
using ZstdSharp.Unsafe;

namespace Ark.oAuth
{
    public class Onboard
    {
        Ark.oAuth.Oidc.DataAccess _da;
        Ark.oAuth.ArkUtil _util;
        StringBuilder _error = new StringBuilder();
        public Onboard(Ark.oAuth.Oidc.DataAccess da, Ark.oAuth.ArkUtil util)
        {
            _da = da;
            _util = util;
        }
        public async Task<string> FullSet(string ten_id,
            string client_id,
            string suffix,
            string client_base_url,
            string client_relative_url,
            List<string> claim_keys,
            string user_email,
            string user_suffix,
            string user_type)
        {
            await PopulateTenant(ten_id);
            await PopulateClient(ten_id, client_id, client_base_url, client_relative_url, suffix);
            await PopulateClaim(claim_keys);
            await PopulateUser(ten_id, client_id, user_email, _util.ServerConfig.DefaultPw, user_suffix ?? "", string.IsNullOrEmpty((user_type ?? "").Trim()) ? "user" : user_type);
            await PopulateUserClaims(ten_id, client_id, user_email, claim_keys);
            return _error.ToString();
        }
        async Task PopulateUserClaims(string ten_id, string client_id, string user_email, List<string> claim_keys)
        {
            var cll = await _da.GetClient(ten_id, client_id);
            if (cll == null) return;
            var us_cl = await _da.UpsertUsersClientClaims(new ArkUserClientClaim()
            {
                email = user_email,
                claims = claim_keys,
                client_id = cll.id, // reference of ID not actuale client_id
                tenant_id = ten_id,
                at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss")
            });
        }
        async Task PopulateUser(string ten_id, string client_id, string user_email, string default_pw, string suffix = $"", string utype = "user")
        {
            var cll = await _da.GetClient(ten_id, client_id);
            if (cll == null) return;
            var usr = await _da.UpsertUser(new ArkUser()
            {
                email = user_email,
                emailed = false,
                hash_pw = _util.HashPasswordPBKDF2(default_pw),
                reset_mode = false,
                type = utype,
                //name = $"{user_email} [Admin]",
                name = $"{user_email}{suffix}",
                at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss")
            });
        }
        async Task PopulateClaim(List<string> claim_keys)
        {
            foreach (var claim_key in claim_keys)
            {
                var clm = await _da.GetClaim(claim_key);
                if (clm == null)
                    await _da.UpsertClaim(new ArkClaim()
                    {
                        key = claim_key,
                        display = $"{claim_key}"
                    });
                else
                    _error.AppendLine($"claim: {claim_key} already exists in the list.");
            }
        }
        async Task PopulateClient(string ten_id, string client_id, string client_base_url, string client_relative_url, string suffix)
        {
            var cll = await _da.GetClient(ten_id, client_id);
            if (cll == null)
            {
                var domain = new Uri(client_base_url).Host;
                cll = await _da.UpsertClient(new ArkClient()
                {
                    tenant_id = ten_id,
                    client_id = $"{client_id}",
                    display = $"{client_id} [{suffix}-Display]",
                    domain = $"{domain}",
                    expire_mins = 480,
                    name = $"{client_id} [{suffix}-Name]",
                    //redirect_relative = $"/planner/{client_id}/schedule/landing", //move to parameter
                    redirect_relative = client_relative_url,
                    redirect_url = $"{client_base_url}/oauth/{ten_id}/v1/client/{client_id}/callback",
                    logout_url = $"{client_base_url}/oauth/{ten_id}/v1/client/{client_id}/logoff",
                    at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss")
                });
            }
            else
            {
                _error.AppendLine($"client: {client_id} already exists in tenant: {ten_id}.");
                throw new ApplicationException($"client: {client_id} already exists in tenant: {ten_id}.");
            }
        }
        async Task PopulateTenant(string ten_id)
        {
            var tnt = await _da.GetTenant(ten_id);
            if (tnt == null)
            {
                var dd = await _util.GetKeys();
                tnt = await _da.UpsertTenant(new Ark.oAuth.ArkTenant()
                {
                    tenant_id = ten_id,
                    name = $"{ten_id} (Name)",
                    display = $"{ten_id} (Disp)",
                    audience = $"{_util.ServerConfig.BaseUrl}/{_util.ServerConfig.BasePath}/ark/oauth/v1/aud",
                    issuer = $"{_util.ServerConfig.BaseUrl}/{_util.ServerConfig.BasePath}/ark/oauth/v1/iss",
                    expire_mins = 480,
                    rsa_private = dd.private_key,
                    rsa_public = dd.public_key,
                    at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss")
                });
            }
            else
                _error.AppendLine($"tenant {ten_id} already existed.");
        }
    }
}