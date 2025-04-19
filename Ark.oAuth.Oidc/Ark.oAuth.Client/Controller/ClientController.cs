using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Ark.oAuth.Client
{
    [Route("oauth")]
    public class ClientController : Controller
    {
        IConfiguration _config;
        public ClientController(IConfiguration config)
        {
            _config = config;
        }
        ArkAuthConfig LoadConfig()
        {
            return _config.GetSection("ark_oauth_client").Get<ArkAuthConfig>() ?? throw new ApplicationException("config missing");
        }
        [Route("{tenant_id}/v1/client/callback")]
        public async Task<ActionResult> Callback([FromQuery] string code, [FromQuery] string state)
        {
            var cc = LoadConfig();

            HttpClient httpClient = new HttpClient();
            //httpClient.BaseAddress = new Uri($"{cc.AuthServerUrl}");
            var dic = new Dictionary<string, string>() {
                { "grant_type", "authorization_code" },
                { "code", code },
                { "redirect_uri", cc.RedirectUri },
                { "client_id", cc.ClientId },
                { "code_verifier",  $"ark_oauth_cv_{cc.ClientId}"}
            };
            var ff = $"{cc.AuthServerUrl}/{cc.TenantId}/v1/token";
            var resp = await httpClient.PostAsync($"{ff}", new FormUrlEncodedContent(dic));
            var rr = await resp.Content.ReadAsStringAsync();
            resp.EnsureSuccessStatusCode();
            var jo = System.Text.Json.JsonSerializer.Deserialize<JsonObject>(rr);
            Response.Cookies.Delete($"ark_oauth_cv_{cc.ClientId}");

            //CookieOptions option = new CookieOptions();
            //    option.Expires = DateTime.Now.AddDays(cc.ExpireMins).ToLocalTime();
            //    option.Secure = true;
            //    option.HttpOnly = true;
            //    option.SameSite = SameSiteMode.None;
            //    option.Domain = cc.Domain;
            //    Response.Cookies.Append($"ark_oauth_tkn", token, option);



            Response.StoreCookie($"ark_oauth_tkn_{cc.ClientId}", jo["access_token"].GetValue<string>(), cc.ExpireMins, cc.Domain);
            //ViewBag.redirect = string.IsNullOrEmpty(redirect_relative) ? cc.RedirectRelative : redirect_relative;
            ViewBag.redirect = cc.RedirectRelative;
            return View();
            //Response.Redirect($"{cc.RedirectRelative}");
        }
        [Authorize]
        [Route("{tenant_id}/v1/client/config")]
        public dynamic Config([FromQuery] string token)
        {
            var cc = LoadConfig();
            return cc;
        }

    }
}
