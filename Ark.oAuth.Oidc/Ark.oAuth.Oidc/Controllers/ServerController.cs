using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using MySqlX.XDevAPI;
using System.Runtime.ConstrainedExecution;

namespace Ark.oAuth.Oidc.Controllers
{
    [Route("oauth")]
    public class ServerController : Controller
    {
        TokenServer _ts;
        DataAccess _da;
        IConfiguration _config;
        public ServerController(TokenServer ts, DataAccess da, IConfiguration config)
        {
            _ts = ts;
            _da = da;
            _config = config;
        }
        [Route("{tenant_id}/v1/signin-oidc/claims/{client_id}")]
        public async Task<dynamic> GetClaimsByCode([FromRoute] string tenant_id, [FromRoute] string client_id, [FromQuery] string code)
        {
            var ser = _config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>() ?? throw new ApplicationException("server config missing");
            ViewBag.IsError = false;
            tenant_id = string.IsNullOrEmpty(tenant_id) ? ser.TenantId : tenant_id;
            var tnt = await _da.GetTenant(tenant_id);
            client_id = string.IsNullOrEmpty(client_id) ? throw new ApplicationException("client_id_empty") : client_id;
            ViewBag.client_url = $"{Request.Scheme}://{Request.Host}/{(string.IsNullOrEmpty(ser.BasePath) ? "" : $"{ser.BasePath}")}/oauth/v1/.well-known/{tenant_id}/openid-configuration";
            return View();
        }
        [Route("{tenant_id}/v1/password/reset/{uid}")]
        public async Task<dynamic> PasswordReset([FromRoute] string tenant_id, [FromRoute] string uid)
        {
            var ser = _config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>() ?? throw new ApplicationException("server config missing");
            ViewBag.IsError = false;
            ViewBag.config = ser.EmailConfig;
            tenant_id = string.IsNullOrEmpty(tenant_id) ? ser.TenantId : tenant_id;
            var tnt = await _da.GetTenant(tenant_id);
            return View();
        }
        [HttpPost]
        [Route("{tenant_id}/v1/password/reset/{uid}")]
        public async Task<dynamic> PasswordReset([FromRoute] string tenant_id, [FromRoute] string uid, 
            [FromForm] string action_type, [FromForm] string pw1, [FromForm] string pw2)
        {
            ViewBag.IsError = false;
            ViewBag.msg = "";
            var ser = _config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>() ?? throw new ApplicationException("server config missing");
            ViewBag.config = ser.EmailConfig;
            try
            {
                if (action_type == "Cancel") return View();
                if (string.IsNullOrEmpty(pw1)) throw new ApplicationException("empty password.");
                if (pw1 != pw2) throw new ApplicationException("password mismatch.");
                await _da.UpdatePassword(uid, pw1);
                tenant_id = string.IsNullOrEmpty(tenant_id) ? ser.TenantId : tenant_id;
                var tnt = await _da.GetTenant(tenant_id);
                return RedirectToAction("PwdResetThank");
            }
            catch (Exception exp)
            {
                ViewBag.IsError = true;
                ViewBag.msg = exp.Message;
                return View();
            }
        }
        public async Task<IActionResult> PwdResetThank()
        {
            return View();
        }
        [Route("{tenant_id}/v1/connect/authorize")]
        public async Task<IActionResult> Index([FromRoute] string tenant_id, [FromQuery] string client_id)
        {
            var ser = _config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>() ?? throw new ApplicationException("server config missing");
            ViewBag.IsError = false;
            tenant_id = string.IsNullOrEmpty(tenant_id) ? ser.TenantId : tenant_id;
            var tnt = await _da.GetTenant(tenant_id);
            client_id = string.IsNullOrEmpty(client_id) ? throw new ApplicationException("client_id_empty") : client_id;
            ViewBag.client_url = $"{Request.Scheme}://{Request.Host}/{(string.IsNullOrEmpty(ser.BasePath) ? "" : $"{ser.BasePath}")}/oauth/v1/.well-known/{client_id}/openid-configuration";
            return View();
        }
        [HttpPost]
        [Route("{tenant_id}/v1/connect/authorize")]
        public async Task<IActionResult> Index([FromRoute] string tenant_id, 
            [FromForm] string Username, 
            [FromForm] string Password,
            [FromQuery] string response_type,
            [FromQuery] string client_id,
            [FromQuery] string redirect_uri,
            [FromQuery] string scope,
            [FromQuery] string state,
            [FromQuery] string code_challenge,
            [FromQuery] string code_challenge_method)
        {
            ViewBag.IsError = false;
            var ser = _config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>() ?? throw new ApplicationException("server config missing");
            ViewBag.client_url = $"{Request.Scheme}://{Request.Host}/{(string.IsNullOrEmpty(ser.BasePath) ? "" : $"{ser.BasePath}")}/v1/.well-known/{client_id}/openid-configuration";
            try
            {
                var tt = await _da.GetTenant(tenant_id);
                if (tt == null) throw new ApplicationException("invalid_tenant");
                var cc = await _da.GetClient(client_id);
                if (cc.redirect_url.ToLower().Trim() != redirect_uri.ToLower().Trim()) throw new ApplicationException("invalid_redirect_uri");
                var tkn = await _ts.BuildAsymmetric_AccessToken(tt, code_challenge);
                await _da.UpsertPkceCode(tkn.Item1, tt, code_challenge, code_challenge, code_challenge_method, state, scope, "", tkn.Item2, redirect_uri, response_type);
                return Redirect($"{cc.redirect_url}?token={tkn.Item1}");
            }
            catch (Exception ex)
            {
                ViewBag.IsError = true;
                ViewBag.msg = ex.ToString();
            }
            return View();
        }
        [Authorize]
        [Route("{tenant_id}/v1/server/manage")]
        public async Task<IActionResult> Manage([FromRoute] string tenant_id)
        {
            //allowed only for server app (app_server)
            var tt = await _da.GetTenant(tenant_id);
            var ser = _config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>() ?? throw new ApplicationException("server config missing");
            ViewBag.tenant = tt;
            ViewBag.base_path = ser.BasePath;
            ViewBag.IsError = false;
            //ViewBag.ctx = 
            return View();
        }

        [Route("{tenant_id}/v1/.well-known/{client_id}/openid-configuration")]
        public async Task<dynamic> Wellknown([FromRoute] string tenant_id, [FromRoute] string client_id)
        {
            var tt = await _da.GetTenant(tenant_id);
            var ser = _config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>() ?? throw new ApplicationException("server config missing");
            var cc = await _da.GetClient(client_id);
            return new
            {
                code_challenge_methods_supported = new List<string>() { "S256" },
                grant_types_supported = new List<string>() { "authorization_code", "client_credentials", "refresh_token" },
                response_types_supported = new List<string>() { "code" },
                client_config_section = new
                {
                    ark_oauth_client = new 
                    {
                        Issuer = tt.issuer,
                        Audience = tt.audience,
                        RsaPublic = tt.rsa_public,
                        RedirectUri = cc.redirect_url,
                        RedirectRelative = cc.redirect_relative,// "/auth/oauth/ark_server/v1/server/manage",
                        AuthServerUrl = $"{Request.Scheme}://{Request.Host}/{(string.IsNullOrEmpty(ser.BasePath) ? "" : $"{ser.BasePath}/oauth")}",
                        ClientId = client_id,
                        TenantId = tt.tenant_id,
                        Domain = cc.domain,
                        ExpireMins = tt.expire_mins
                    }
                }
            };
        }
    }
}