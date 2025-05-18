using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

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
            try
            {
                ViewBag.error = "";
                ViewBag.redirect = "";
                var ccc = LoadConfig();
                HttpClient httpClient = new HttpClient();
                var dic = new Dictionary<string, string>() {
                { "grant_type", "authorization_code" },
                { "code", code },
                { "redirect_uri",  string.Format(ccc.RedirectUri, client_id) },
                { "client_id", client_id },
                { "code_verifier", Request.ReadCookie($"ark_oauth_cv_{client_id}") }
            };
                var ff = $"{ccc.AuthServerUrl}/oauth/{tenant_id}/v1/token";
                var resp = await httpClient.PostAsync($"{ff}", new FormUrlEncodedContent(dic));
                var rr = await resp.Content.ReadAsStringAsync();
                resp.EnsureSuccessStatusCode();
                var jo = System.Text.Json.JsonSerializer.Deserialize<JsonObject>(rr);
                Response.DeleteCookie($"ark_oauth_cv_{client_id}", ccc.Domain);
                var att = jo["access_token"].GetValue<string>();
                Response.StoreCookie($"ark_oauth_tkn_{client_id}", att, ccc.ExpireMins, ccc.Domain);
                ViewBag.redirect = string.Format(ccc.RedirectRelative, client_id);
            }
            catch (Exception exp)
            {
                ViewBag.error = exp.ToString();
            }
            return View();
        }
        [Authorize]
        [Route("{tenant_id}/v1/client/{client_id}/config")]
        public dynamic Config([FromQuery] string token)
        {
            var cc = LoadConfig();
            return cc;
        }
        [Authorize]
        [Route("{tenant_id}/v1/client{client_id}/logoff")]
        public dynamic Logoff()
        {
            var cc = LoadConfig();
            foreach (var cookie in Request.Cookies.Keys)
            {
                Response.Cookies.Delete(cookie, new CookieOptions()
                {
                    Secure = true,
                    Domain = cc.Domain
                });
            }
            return new
            {
                msg = "logged off, beter close the browser."
            };
        }
    }
}
