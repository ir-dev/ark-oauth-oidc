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
        [Route("{tenant_id}/v1/client/{client_id}/callback")]
        public async Task<ActionResult> Callback([FromRoute] string tenant_id, [FromRoute] string client_id, [FromQuery] string code, [FromQuery] string state)
        {
            var cc = LoadConfig();

            HttpClient httpClient = new HttpClient();
            //httpClient.BaseAddress = new Uri($"{cc.AuthServerUrl}");
            var dic = new Dictionary<string, string>() {
                { "grant_type", "authorization_code" },
                { "code", code },
                { "redirect_uri", cc.RedirectUri },
                { "client_id", client_id },
                { "code_verifier",  $"ark_oauth_cv_{client_id}"}
            };
            var ff = $"{cc.AuthServerUrl}/{tenant_id}/v1/token";
            var resp = await httpClient.PostAsync($"{ff}", new FormUrlEncodedContent(dic));
            var rr = await resp.Content.ReadAsStringAsync();
            resp.EnsureSuccessStatusCode();
            var jo = System.Text.Json.JsonSerializer.Deserialize<JsonObject>(rr);
            Response.Cookies.Delete($"ark_oauth_cv_{client_id}");

            //CookieOptions option = new CookieOptions();
            //    option.Expires = DateTime.Now.AddDays(cc.ExpireMins).ToLocalTime();
            //    option.Secure = true;
            //    option.HttpOnly = true;
            //    option.SameSite = SameSiteMode.None;
            //    option.Domain = cc.Domain;
            //    Response.Cookies.Append($"ark_oauth_tkn", token, option);

            var att = jo["access_token"].GetValue<string>();
            //var rel_redirect = jo["redirect_relative"].GetValue<string>();
            Response.StoreCookie($"ark_oauth_tkn_{client_id}", att, cc.ExpireMins, cc.Domain);
            //ViewBag.redirect = string.IsNullOrEmpty(redirect_relative) ? cc.RedirectRelative : redirect_relative;
            //ViewBag.redirect = rel_redirect ?? cc.Clients[client_id];
            KeyValuePair<string, ArkApp> capp = cc.Clients.FirstOrDefault(t2 => t2.Key.ToLower() == client_id.ToLower());
            capp = capp.Key == null ? new KeyValuePair<string, ArkApp>(client_id, new ArkApp() { ClientId = client_id, RedirectRelative = cc.RedirectRelative, RedirectUri = cc.RedirectUri }) : capp;
            ViewBag.redirect = capp.Value.RedirectRelative;
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
