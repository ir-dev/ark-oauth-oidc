using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Ocsp;

namespace Ark.oAuth.Client
{
    // OIDC callback/sign-out routes: reached before a session exists, by design.
    [Route("oauth")]  // nosemgrep: csharp.dotnet.security.audit.missing-or-broken-authorization.missing-or-broken-authorization
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

        /// <summary>
        /// The routes below are the v1 flow. They used to answer in every MVC host that referenced
        /// this package — it is an application part whether or not the legacy flow is in use —
        /// so a standard-flow application served an anonymous callback that printed stack traces
        /// and, behind a bare [Authorize], a /config route that returned this configuration
        /// section, client secret included, to any signed-in user. They now exist only where
        /// `ark_oauth_client:UseLegacyFlow` is set.
        /// </summary>
        public override void OnActionExecuting(Microsoft.AspNetCore.Mvc.Filters.ActionExecutingContext context)
        {
            var conf = _config.GetSection("ark_oauth_client").Get<ArkAuthConfig>();
            if (conf?.UseLegacyFlow != true) context.Result = NotFound();
            else base.OnActionExecuting(context);
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
                try
                {
                    var ff_c = $"{ccc.AuthServerUrl}/oauth/{tenant_id}/v1/server/{client_id}/userinfo";
                    httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {att}");
                    var resp_c = await httpClient.GetStringAsync($"{ff_c}");
                    var jo_c = System.Text.Json.JsonSerializer.Deserialize<JsonObject>(resp_c);
                    Response.StoreCookie($"ark_oauth_ui_claims_{client_id}", resp_c, ccc.ExpireMins, ccc.Domain);
                }
                catch (Exception ex)
                {
                    // Logged, not written into a cookie: the exception text is server internals.
                    Console.WriteLine(ex);
                }
                ViewBag.redirect = string.Format(ccc.RedirectRelative, client_id);
            }
            catch (Exception exp)
            {
                // The page used to print exp.ToString() — a stack trace with source paths, to
                // anyone, in Production too.
                Console.WriteLine(exp);
                ViewBag.error = "Sign-in could not be completed. Please try again.";
            }
            return View();
        }
        [Authorize]
        [Route("{tenant_id}/v1/client/{client_id}/userinfo")]
        public async Task<dynamic> UserINfo([FromRoute] string tenant_id, [FromRoute] string client_id, [FromQuery] string token)
        {
            var ccc = LoadConfig();
            var resp_c = "";
            try
            {
                HttpClient httpClient = new HttpClient();
                //get userinfo claims
                var ff_c = $"{ccc.AuthServerUrl}/oauth/{tenant_id}/v1/server/{client_id}/userinfo";
                httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");
                resp_c = await httpClient.GetStringAsync($"{ff_c}");
                var jo_c = System.Text.Json.JsonSerializer.Deserialize<JsonObject>(resp_c);
                Response.StoreCookie($"ark_oauth_ui_claims_{client_id}", resp_c, ccc.ExpireMins, ccc.Domain);
                return jo_c;
            }
            catch
            {
                try
                {
                    Response.StoreCookie($"ark_oauth_ui_claims_{client_id}", $"user_info errored, {resp_c.Substring(0, resp_c.Length > 501 ? 500 : resp_c.Length)}", ccc.ExpireMins, ccc.Domain);
                }
                catch { }
            }
            return new
            {
                error = true,
                msg = "user_info_error"
            };
        }
        // The /config route is gone: it returned this whole configuration section, ClientSecret
        // included, to any signed-in user — every customer of a customer-facing app — and nothing
        // in the v1 flow ever needed a browser to have it.
        [Authorize]
        [Route("{tenant_id}/v1/client/{client_id}/logoff")]
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
