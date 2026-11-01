using Ark.oAuth;
using Ark.oAuth.Oidc;
using Ark.oAuth.Oidc.Host.Models;
using Ark.oAuth.Oidc.Protocol;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace Ark.oAuth.Oidc.Host.Controllers
{
    public class HomeController : Controller
    {
        private readonly IConfiguration _config;

        public HomeController(IConfiguration config)
        {
            _config = config;
        }

        private ArkAuthServerConfig ServerConfig =>
            _config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>()
            ?? throw new ApplicationException("the 'ark_oauth_server' configuration section is missing.");

        public IActionResult Index()
        {
            var ser = ServerConfig;
            var endpoints = ArkOidcEndpoints.For(Request, ser, ser.TenantId);
            ViewBag.TenantId = ser.TenantId;
            ViewBag.Issuer = endpoints.Issuer;
            ViewBag.Discovery = endpoints.Discovery;
            ViewBag.Jwks = endpoints.Jwks;
            ViewBag.HostName = ser.EmailConfig?.host_company_display ?? ser.EmailConfig?.host_company_name ?? "Identity Provider";
            ViewBag.AuthError = Request.Query["auth_error"].ToString();
            return View();
        }

        /// <summary>Starts an authorization request; the OIDC handler returns here signed in.</summary>
        [Authorize]
        public IActionResult SignIn() => RedirectToAction("Index", "Admin");

        /// <summary>
        /// RP-initiated logout. Signing out of both schemes clears the local cookie and sends the
        /// browser to the server's end_session_endpoint, which is where the IdP session actually
        /// lives. Dropping only the local cookie would leave the user silently signed straight
        /// back in on the next authorization request.
        /// </summary>
        [Authorize]
        public IActionResult SignOutAll() =>
            SignOut(
                new AuthenticationProperties { RedirectUri = "/" },
                ArkOidcClient.CookieScheme,
                ArkOidcClient.OidcScheme);

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error() =>
            View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
