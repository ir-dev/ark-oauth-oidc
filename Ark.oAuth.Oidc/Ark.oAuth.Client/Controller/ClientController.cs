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
        public ActionResult Callback([FromQuery] string token)
        {
            var cc = LoadConfig();
            CookieOptions option = new CookieOptions();
            option.Expires = DateTime.Now.AddDays(cc.ExpireMins).ToLocalTime();
            option.Secure = true;
            option.HttpOnly = true;
            option.SameSite = SameSiteMode.None;
            option.Domain = cc.Domain;
            Response.Cookies.Append($"ark_oauth_tkn", token, option);
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
