using System.Text.Json.Nodes;

namespace Ark.oAuth;

public class AuthClientHelper
{
    HttpClient client = new HttpClient();
    IConfiguration _config;
    public AuthClientHelper(IConfiguration config)
    {
        _config = config;
        var tkn = _config.GetSection("auth_service_tkn").Get<string>();
        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {tkn}");
    }
    ArkAuthConfig LoadConfig()
    {
        return _config.GetSection("ark_oauth_client").Get<ArkAuthConfig>() ?? throw new ApplicationException("config missing");
    }
    public async Task<dynamic> OnboardUser(string user_email, string pw, string user_claims, string full_name)
    {
        var cc = LoadConfig();
        if (cc != null && !string.IsNullOrEmpty(cc.AuthServerUrl))
        {
            try
            {
                var f_url = @$"{cc.AuthServerUrl}/api/oauth/onboard/user?ten_id={cc.TenantId}&client_id={cc.ClientId}&claim_keys={user_claims}&user_email={user_email}&user_pw={pw}&full_name={full_name}&user_type=user";
                var str = await client.GetStringAsync(f_url);
                var jo = System.Text.Json.JsonSerializer.Deserialize<JsonObject>(str);
                var att = jo["error"]?.GetValue<bool>();
                if (!att.HasValue || att.Value)
                {
                    bool client_exist = (jo["msg"]?.GetValue<string>() ?? "").Replace(" ", "").ToLower().Contains($"alreadyexistsintenant:{cc.TenantId}".ToLower());
                    if (!client_exist) return jo;
                }
                return new
                {
                    error = false,
                    msg = $"customer created succesfully"
                };
            }
            catch (Exception exp)
            {
                return new
                {
                    error = true,
                    msg = $"user creation failed, pls contact admin.",
                    data = exp.ToString()
                };
            }
        }
        else
        {
            return new
            {
                error = true,
                msg = $"user creation failed, auth config missing."
            };
        }
    }
    public async Task<dynamic> OnboardCustomer(string rel_url, string f_url)
    {
        var cc = LoadConfig();
        if (cc != null && !string.IsNullOrEmpty(cc.AuthServerUrl))
        {
            try
            {
                //f_url = @$"{cc.AuthServerUrl}/api/oauth/onboard/full?ten_id={cc.TenantId}&client_id={customer.customer_uid}&suffix={cc.Suffix}&client_base_url={ctx.base_url_saas}{ctx.base_path}&client_relative_url={rel_url}&claim_keys=ntt-is-fa&user_email={customer.email}&user_suffix= [Admin]&user_type=user";
                var str = await client.GetStringAsync(f_url);
                var jo = System.Text.Json.JsonSerializer.Deserialize<JsonObject>(str);
                var att = jo["error"]?.GetValue<bool>();
                if (!att.HasValue || att.Value)
                {
                    bool client_exist = (jo["msg"]?.GetValue<string>() ?? "").Replace(" ", "").ToLower().Contains($"alreadyexistsintenant:{cc.TenantId}".ToLower());
                    if (!client_exist) return jo;
                }
                return new
                {
                    error = false,
                    msg = $"customer created succesfully"
                };
            }
            catch (Exception exp)
            {
                return new
                {
                    error = true,
                    msg = $"customer creation failed, pls contact admin.",
                    data = exp.ToString(),
                    rel_url = rel_url,
                    f_url = f_url
                };
            }
        }
        else
        {
            return new
            {
                error = true,
                msg = $"customer creation failed, auth config missing.",
                rel_url = rel_url,
                f_url = f_url
            };
        }
    }
}