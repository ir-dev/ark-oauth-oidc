using System.Security.Claims;
using ark.net.util;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Ark.oAuth.Oidc.Protocol;

namespace Ark.oAuth.Oidc.Controllers
{
    /// <summary>
    /// The /v1 compatibility surface.
    ///
    /// These are the routes shipped before the server became standards-compliant, kept so
    /// deployed clients and published NuGet packages keep working. They preserve the original
    /// request and response *shapes*, but the protocol work is now delegated to the same core
    /// the standard endpoints use — which means codes issued here are single-use, expire, and
    /// have their PKCE verifier checked. That check simply did not exist before.
    ///
    /// New integrations should use the standard endpoints under /{tenant_id}/oauth2/ and
    /// discover them from /{tenant_id}/.well-known/openid-configuration.
    /// </summary>
    [Route("oauth")]
    public class ServerController : Controller
    {
        TokenServer _ts;
        DataAccess _da;
        IConfiguration _config;
        ArkGrantStore _grants;
        ArkTokenService _tokens;
        ArkClaimsService _claims;
        ArkDataContext _ctx;

        public ServerController(TokenServer ts, DataAccess da, IConfiguration config,
            ArkGrantStore grants, ArkTokenService tokens, ArkClaimsService claims, ArkDataContext ctx)
        {
            _ts = ts;
            _da = da;
            _config = config;
            _grants = grants;
            _tokens = tokens;
            _claims = claims;
            _ctx = ctx;
        }

        ArkOidcEndpoints V1Endpoints(ArkAuthServerConfig ser, string tenantId) =>
            ArkOidcEndpoints.For(Request, ser, tenantId);
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
        public async Task<IActionResult> Landing()
        {
            return View();
        }
        [Route("PwdResetThank")]
        public async Task<IActionResult> PwdResetThank()
        {
            return View();
        }
        [Route("{tenant_id}/v1/connect/authorize")]
        public async Task<IActionResult> Index([FromRoute] string tenant_id, [FromQuery] string client_id, [FromQuery] string redirect_uri)
        {
            var ser = _config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>() ?? throw new ApplicationException("server config missing");
            var cc = await _da.GetClient(tenant_id, client_id);
            ViewBag.IsError = false;
            ViewBag.host_logo = ser.EmailConfig?.host_logo ?? $"";
            ViewBag.client_logo = cc?.client_logo ?? ser.EmailConfig?.client_logo ?? $"";
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

                // The same lockout the standard sign-in page enforces. Without it this form was an
                // unthrottled password oracle sitting beside a throttled one.
                var opt = ser.Oidc ?? new ArkOidcOptions();
                if (opt.MaxFailedSignIns > 0)
                {
                    var login = (Username ?? "").ToLower().Trim();
                    var status = await _ctx.auth_status.AsNoTracking()
                        .FirstOrDefaultAsync(s => s.email.ToLower() == login);
                    if (status != null && status.retry_count >= opt.MaxFailedSignIns
                        && (DateTime.UtcNow - status.at).TotalMinutes < opt.LockoutMinutes)
                        throw new ApplicationException($"Too many failed attempts. Try again in {opt.LockoutMinutes} minutes.");
                }

                var usr = await _da.ValidateUserCreds(Username, Password, client_id, tenant_id);

                // Delegate to the standard grant store. The original code here minted the access
                // token up front and stored it against a bare GUID, so the "code" was really a
                // bearer token in a query string. Now a proper single-use code is issued and the
                // token is only minted when the code is redeemed with a matching verifier.
                var scopes = new List<string> { "openid", "profile", "email" };
                var session = await _grants.CreateSessionAsync(tt.tenant_id, usr.email,
                    (ser.Oidc ?? new ArkOidcOptions()).SessionLifetimeMinutes);
                var code = await _grants.CreateAuthCodeAsync(cc, tt.tenant_id, usr.email, redirect_uri,
                    scopes, code_challenge, code_challenge_method, null, session.session_id, session.auth_time);

                return Redirect($"{cc.redirect_url}?code={Uri.EscapeDataString(code)}&state={Uri.EscapeDataString(state ?? "")}");
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
            var ser = _config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>() ?? throw new ApplicationException("server config missing");
            try
            {
                var tt = await _da.GetTenant(tenant_id);
                if (tt == null) throw new ApplicationException("invalid_tenant");
                var cc = await _da.GetClient(tenant_id, client_id);
                if (cc == null) throw new ApplicationException("invalid_client");
                if (cc.redirect_url.ToLower().Trim() != (redirect_uri ?? "").ToLower().Trim()) throw new ApplicationException("invalid_request");

                // The verifier is now actually checked against the stored challenge. Format
                // validation is relaxed because the original client library generated a short,
                // non-conforming verifier; the match itself is enforced either way.
                var entry = await _grants.ConsumeAuthCodeAsync(code, cc, redirect_uri, code_verifier,
                    enforceVerifierFormat: false);

                var ep = V1Endpoints(ser, tt.tenant_id);
                var scopes = (entry.scope ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();
                var ctx = new TokenRequestContext
                {
                    Tenant = tt,
                    Client = cc,
                    // v1 tokens keep the tenant's legacy issuer/audience so clients configured
                    // against the old well-known document continue to validate them
                    Issuer = tt.issuer,
                    Audience = tt.audience,
                    Subject = entry.subject,
                    Scopes = scopes,
                    SessionId = entry.session_id,
                    AuthTime = entry.auth_time,
                    AuthorizationCode = code
                };

                var (accessToken, _, _) = await _tokens.IssueAccessTokenAsync(ctx);
                var idToken = await _tokens.IssueIdTokenAsync(ctx, accessToken);
                var refreshToken = await _grants.CreateRefreshTokenAsync(
                    cc, tt.tenant_id, entry.subject, scopes, entry.session_id);

                return new
                {
                    access_token = accessToken,
                    id_token = idToken,
                    refresh_token = refreshToken,
                    redirect_relative = cc.redirect_relative
                };
            }
            catch (OAuthException ex)
            {
                _da.LogError(ex, "v1_token", $"{tenant_id}/v1/token", $"ci: {client_id}, ti: {tenant_id}, ru: {redirect_uri}");
                // the v1 shape is an HTTP 200 with an "error" member; preserved on purpose
                return new { error = ex.Error, error_description = ex.ErrorDescription };
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
            var cc = await _da.GetClient(tenant_id, client_id);
            var ser = _config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>() ?? throw new ApplicationException("server config missing");
            ViewBag.tenant = tt;
            ViewBag.base_path = ser.BasePath.AnyNull() ? "" : $"/{ser.BasePath}";
            ViewBag.IsError = false;
            ViewBag.host_logo = ser.EmailConfig?.host_logo ?? $"";
            ViewBag.client_logo = cc.client_logo ?? ser.EmailConfig?.client_logo ?? $"";
            ViewBag.logout_url = cc.logout_url;
            ViewBag.profile = await UserInfo(tenant_id, client_id);
            return View();
        }
        [Authorize]
        [Route("{tenant_id}/v1/server/{client_id}/userinfo")]
        public async Task<dynamic> UserInfo([FromRoute] string tenant_id, [FromRoute] string client_id, [FromQuery] string sub = null)
        {
            // Another user's record is the operator's to read, nobody else's: honouring `sub` for
            // every signed-in caller let any of them read any account's claims for any client.
            var ser = _config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>();
            if (!ArkOperator.IsOperator(User, ser)) sub = null;
            sub = sub ?? Request.HttpContext.User.Claims.FirstOrDefault(t => t.Type?.ToLower() == "sub" || t.Type?.ToLower() == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")?.Value;
            var name = Request.HttpContext.User.Claims.FirstOrDefault(t => t.Type?.ToLower() == "name");
            return await _da.GetUserInfo(sub, tenant_id, client_id);
        }

        [Route("{tenant_id}/v1/.well-known/{client_id}/openid-configuration")]
        public async Task<dynamic> Wellknown([FromRoute] string tenant_id, [FromRoute] string client_id)
        {
            var tt = await _da.GetTenant(tenant_id);
            var ser = _config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>() ?? throw new ApplicationException("server config missing");
            var cc = await _da.GetClient(tenant_id, client_id);
            if (cc == null) throw new ApplicationException("invalid_client");
            var baseurl = $"{(!string.IsNullOrEmpty(ser.BaseUrl) ? ser.BaseUrl : $"{Request.Scheme}://{Request.Host}")}{(string.IsNullOrEmpty(ser.BasePath) ? "" : $"/{ser.BasePath}")}";
            var ep = V1Endpoints(ser, tt.tenant_id);
            return new
            {
                issuer = tt.issuer,
                authorization_endpoint = $"{baseurl}/oauth/{tenant_id}/v1/connect/authorize",
                token_endpoint = $"{baseurl}/oauth/{tenant_id}/v1/token",
                userinfo_endpoint = $"{baseurl}/oauth/{tenant_id}/v1/server/{client_id}/userinfo",
                jwks_uri = ep.Jwks,
                code_challenge_methods_supported = new List<string>() { "S256" },
                grant_types_supported = new List<string>() { "authorization_code", "refresh_token" },
                response_types_supported = new List<string>() { "code" },

                // Where to go next. This document describes the deprecated /v1 surface; the
                // standard one is self-configuring and works with any OIDC client library.
                deprecated = true,
                standard_configuration_endpoint = ep.Discovery,
                standard_issuer = ep.Issuer,

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
                    ExpireMins = tt.expire_mins,
                    // Only this tenant's key. Returning every tenant here let anyone holding one
                    // client_id enumerate the issuer, audience and key id of every other tenant
                    // on the deployment, and a client only ever validates its own tenant's kid.
                    tenants = new Dictionary<string, object>
                    {
                        [tt.tenant_id] = new { RsaPublic = tt.rsa_public, kid = tt.tenant_id, Audience = tt.audience, Issuer = tt.issuer }
                    }
                }
            };
        }
        /// <summary>
        /// Stores a branding image under <c>UploadPath/{client_id}/{type}/</c>.
        ///
        /// This was anonymous, unbounded and wrote to a path built from three caller-supplied
        /// strings, so <c>..</c> in any of them — the file name included — wrote anywhere the
        /// process could, which on most hosts includes its own binaries and wwwroot. It now needs
        /// the operator account, takes images only, and refuses any path that resolves outside
        /// the upload folder. The v2 console inlines logos as data URIs and does not call it.
        /// </summary>
        [Authorize]
        [RequestSizeLimit(MaxUploadBytes)]
        [HttpPost]
        [Route("v1/{client_id}/{type}/upload")]
        public async Task<IActionResult> Upload([FromRoute] string client_id, [FromRoute] string type, IFormFile file)
        {
            var ser = _config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>() ?? throw new ApplicationException("server config missing");
            if (!ArkOperator.IsOperator(User, ser)) return StatusCode(403, "uploads are restricted to the administrator account.");
            if (file == null || file.Length == 0) return BadRequest("No file uploaded or file is empty.");
            if (file.Length > MaxUploadBytes) return BadRequest("file is too large.");
            if (string.IsNullOrWhiteSpace(ser.UploadPath)) return BadRequest("uploads are not configured (ark_oauth_server:UploadPath).");
            if (!SafeSegment.IsMatch(client_id ?? "") || !SafeSegment.IsMatch(type ?? ""))
                return BadRequest("client_id and type may contain only letters, digits, dot, dash and underscore.");

            // The browser's file name is a suggestion, not a path: keep its last segment only.
            var fileName = System.IO.Path.GetFileName(file.FileName ?? "");
            if (!SafeSegment.IsMatch(fileName) || !UploadExtensions.Contains(System.IO.Path.GetExtension(fileName)))
                return BadRequest($"only {string.Join(", ", UploadExtensions)} files with a plain name are accepted.");

            var root = System.IO.Path.GetFullPath(ser.UploadPath);
            var path = System.IO.Path.GetFullPath(System.IO.Path.Combine(root, client_id!, type!, fileName));
            if (!path.StartsWith(root.TrimEnd(System.IO.Path.DirectorySeparatorChar) + System.IO.Path.DirectorySeparatorChar, StringComparison.Ordinal))
                return BadRequest("invalid upload path.");

            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
            // Create, not OpenOrCreate: a shorter file over a longer one would keep the old tail.
            using (var stream = new FileStream(path, FileMode.Create))
                await file.CopyToAsync(stream);
            return Ok(new
            {
                url = $"/{ser.UploadPath.Trim('/')}/{client_id}/{type}/{fileName}"
            });
        }

        private const long MaxUploadBytes = 2 * 1024 * 1024;

        private static readonly System.Text.RegularExpressions.Regex SafeSegment =
            new(@"^(?!\.)[A-Za-z0-9._-]{1,100}$", System.Text.RegularExpressions.RegexOptions.Compiled);

        // No SVG: it is a document that can carry script, served from this origin.
        private static readonly HashSet<string> UploadExtensions =
            new(StringComparer.OrdinalIgnoreCase) { ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico" };
    }
}