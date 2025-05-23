﻿using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

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
        public async Task<IActionResult> Index([FromRoute] string tenant_id, [FromQuery] string client_id, [FromQuery] string redirect_uri)
        {
            var ser = _config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>() ?? throw new ApplicationException("server config missing");
            ViewBag.IsError = false;
            ViewBag.host_logo = ser.EmailConfig?.host_logo ?? $"";
            ViewBag.client_logo = ser.EmailConfig?.client_logo ?? $"";
            try
            {
                tenant_id = string.IsNullOrEmpty(tenant_id) ? ser.TenantId : tenant_id;
                var tnt = await _da.GetTenant(tenant_id);
                client_id = string.IsNullOrEmpty(client_id) ? throw new ApplicationException("mismatch_client") : client_id;
                redirect_uri = string.IsNullOrEmpty(redirect_uri) ? throw new ApplicationException("invalid_request, check if client config is managed right.") : redirect_uri;
                ViewBag.client_url = $"{Request.Scheme}://{Request.Host}/{(string.IsNullOrEmpty(ser.BasePath) ? "" : $"{ser.BasePath}")}/oauth/{tenant_id}/v1/.well-known/{client_id}/openid-configuration";
            }
            catch (Exception ex)
            {
                _da.LogError(ex, "authorize_get", $"{tenant_id}/v1/connect/authorize", $"ci: {client_id}, ti: {tenant_id}, ru: {redirect_uri}");
                ViewBag.IsError = true;
                ViewBag.msg = ex.Message;
            }
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
            var baseurl = !string.IsNullOrEmpty(ser.BaseUrl) ? ser.BaseUrl : $"{Request.Scheme}://{Request.Host}/{(string.IsNullOrEmpty(ser.BasePath) ? "" : $"{ser.BasePath}")}";
            ViewBag.client_url = $"{baseurl}/oauth/{tenant_id}/v1/.well-known/{client_id}/openid-configuration";
            ViewBag.host_logo = ser.EmailConfig?.host_logo ?? $"";
            ViewBag.client_logo = ser.EmailConfig?.client_logo ?? $"";
            try
            {
                var tt = await _da.GetTenant(tenant_id);
                if (tt == null) throw new ApplicationException("invalid_tenant");
                var cc = await _da.GetClient(tenant_id, client_id);
                if (cc == null) throw new ApplicationException("invalid_client");
                if (cc.redirect_url.ToLower().Trim() != redirect_uri.ToLower().Trim()) throw new ApplicationException("invalid_redirect_uri");
                var usr = await _da.ValidateUserCreds(Username, Password, client_id, tenant_id);
                var tkn = await _ts.BuildAsymmetric_AccessToken(tt, code_challenge);
                string code = Guid.NewGuid().ToString();
                await _da.UpsertPkceCode(tkn.Item1, tt, code, code_challenge, code_challenge_method, state, scope, "", tkn.Item2, redirect_uri, response_type);
                return Redirect($"{cc.redirect_url}?code={code}&state={state}");
            }
            catch (Exception ex)
            {
                _da.LogError(ex, "authorize_post", $"{tenant_id}/v1/connect/authorize", $"un: {Username}, ci: {client_id}, ti: {tenant_id}, rt: {response_type}, ru: {redirect_uri}, cc: {code_challenge}, ccm: {code_challenge_method}, sc: {scope}, st: {state}");
                ViewBag.IsError = true;
                ViewBag.msg = ex.Message;
                //ViewBag.msg = ex.ToString();
            }
            return View();
        }
        [HttpPost]
        [Consumes("application/x-www-form-urlencoded")]
        [Route("{tenant_id}/v1/token")]
        public async Task<dynamic> Token([FromRoute] string tenant_id,
            [FromForm] string grant_type,
            [FromForm] string code,
            [FromForm] string redirect_uri,
            [FromForm] string client_id,
            [FromForm] string code_verifier)
        {
            _da.Log("v1_token", $"{tenant_id}/v1/token", $"reached.", "", "verbose");
            var ser = _config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>() ?? throw new ApplicationException("server config missing");
            try
            {
                _da.Log("v1_token", $"{tenant_id}/v1/token", $"step-1", "", "verbose");
                var tt = await _da.GetTenant(tenant_id);
                _da.Log("v1_token", $"{tenant_id}/v1/token", $"step-2", "", "verbose");
                if (tt == null) throw new ApplicationException("invalid_tenant");
                var cc = await _da.GetClient(tenant_id, client_id);
                if (cc == null) throw new ApplicationException("invalid_client");
                _da.Log("v1_token", $"{tenant_id}/v1/token", $"step-3", "", "verbose");
                if (cc == null) throw new ApplicationException("unauthorized_client");
                if (cc.redirect_url.ToLower().Trim() != redirect_uri.ToLower().Trim()) throw new ApplicationException("invalid_request");
                _da.Log("v1_token", $"{tenant_id}/v1/token", $"step-4", "", "verbose");
                var pk = await _da.GetPkceCode(code, true);
                _da.Log("v1_token", $"{tenant_id}/v1/token", $"step-5", "", "verbose");
                if (pk == null) throw new ApplicationException("invalid_grant");
                return new
                {
                    access_token = pk.access_token,
                    id_token = "",
                    refresh_token = pk.refresh_token,
                    redirect_relative = cc.redirect_relative
                };
            }
            catch (Exception ex)
            {
                _da.LogError(ex, "v1_token", $"{tenant_id}/v1/token", $"ci: {client_id}, ti: {tenant_id}, ru: {redirect_uri}");
                return new { error = ex.Message };
            }
        }
        [Authorize]
        [Route("{tenant_id}/v1/server/{client_id}/manage")]
        public async Task<IActionResult> Manage([FromRoute] string tenant_id, [FromRoute] string client_id)
        {
            //allowed only for server app (app_server)
            var tt = await _da.GetTenant(tenant_id);
            var ser = _config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>() ?? throw new ApplicationException("server config missing");
            ViewBag.tenant = tt;
            ViewBag.base_path = ser.BasePath;
            ViewBag.IsError = false;
            ViewBag.host_logo = ser.EmailConfig?.host_logo ?? $"";
            ViewBag.client_logo = ser.EmailConfig?.client_logo ?? $"";
            ViewBag.logout_url = (await _da.GetClients()).FirstOrDefault()?.logout_url;
            return View();
        }

        [Route("{tenant_id}/v1/.well-known/{client_id}/openid-configuration")]
        public async Task<dynamic> Wellknown([FromRoute] string tenant_id, [FromRoute] string client_id)
        {
            var tt = await _da.GetTenant(tenant_id);
            var ser = _config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>() ?? throw new ApplicationException("server config missing");
            var cc = await _da.GetClient(tenant_id, client_id);
            if (cc == null) throw new ApplicationException("invalid_client");
            var baseurl = $"{(!string.IsNullOrEmpty(ser.BaseUrl) ? ser.BaseUrl : $"{Request.Scheme}://{Request.Host}")}/{(string.IsNullOrEmpty(ser.BasePath) ? "" : ser.BasePath)}";
            return new
            {
                code_challenge_methods_supported = new List<string>() { "S256" },
                grant_types_supported = new List<string>() { "authorization_code", "client_credentials", "refresh_token" },
                response_types_supported = new List<string>() { "code" },
                ark_oauth_client = new
                {
                    Issuer = tt.issuer,
                    Audience = tt.audience,
                    RsaPublic = tt.rsa_public,
                    RedirectUri = cc.redirect_url,
                    RedirectRelative = cc.redirect_relative,// "/auth/oauth/ark_server/v1/server/{0}/manage", client_id (for saas)
                    LogoutUri = cc.logout_url,
                    AuthServerUrl = baseurl,
                    ClientId = client_id,
                    RouteKey = new List<string>() { "client_id", "company" },
                    TenantId = tt.tenant_id,
                    Domain = cc.domain,
                    Suffix = "",
                    ExpireMins = tt.expire_mins
                }
            };
        }
    }
}