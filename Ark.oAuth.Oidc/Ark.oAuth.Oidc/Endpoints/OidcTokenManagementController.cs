using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;
using Ark.oAuth.Oidc.Protocol;

namespace Ark.oAuth.Oidc.Endpoints
{
    /// <summary>
    /// Token introspection (RFC 7662), revocation (RFC 7009) and RP-initiated logout
    /// (OIDC RP-Initiated Logout 1.0).
    /// </summary>
    [Route("{tenant_id}/oauth2")]
    public class OidcTokenManagementController : ArkOidcControllerBase
    {
        private readonly ArkClientAuthenticator _clientAuth;
        private readonly ArkGrantStore _grants;
        private readonly ArkTokenService _tokens;
        private readonly ArkBackChannelLogout _backchannel;
        private readonly DataAccess _da;

        public OidcTokenManagementController(ArkDataContext ctx, IConfiguration config,
            ArkClientAuthenticator clientAuth, ArkGrantStore grants, ArkTokenService tokens,
            ArkBackChannelLogout backchannel, DataAccess da)
            : base(ctx, config)
        {
            _clientAuth = clientAuth;
            _grants = grants;
            _tokens = tokens;
            _backchannel = backchannel;
            _da = da;
        }

        // -----------------------------------------------------------------
        // Introspection (RFC 7662)
        // -----------------------------------------------------------------

        [HttpPost("introspect")]
        [Consumes("application/x-www-form-urlencoded")]
        public async Task<IActionResult> Introspect([FromRoute] string tenant_id)
        {
            NoStore();
            return await ProtectAsync(async () =>
            {
                var tenant = await ResolveTenantAsync(tenant_id);
                var ep = Endpoints(tenant.tenant_id);

                // §2.1: the endpoint requires client authentication, otherwise it is an oracle
                // that lets anyone test captured tokens.
                var auth = await _clientAuth.AuthenticateAsync(Request, tenant.tenant_id, ep.Introspection);
                if (auth.Method == "none")
                    throw OAuthException.InvalidClient("the introspection endpoint requires client authentication.");

                var token = Request.Form["token"].ToString();
                if (string.IsNullOrWhiteSpace(token))
                    throw OAuthException.InvalidRequest("token is required.");

                var hint = Request.Form["token_type_hint"].ToString();

                // §2.2: an unknown or expired token is not an error — it is simply not active.
                var inactive = new Dictionary<string, object> { ["active"] = false };

                if (hint != "refresh_token")
                {
                    var result = await _tokens.ValidateAsync(token, tenant, ep.Issuer);
                    if (result.IsValid)
                    {
                        var id = result.ClaimsIdentity;
                        var body = new Dictionary<string, object> { ["active"] = true };
                        void Copy(string claim, string? outName = null)
                        {
                            var v = id?.FindFirst(claim)?.Value;
                            if (!string.IsNullOrEmpty(v)) body[outName ?? claim] = v!;
                        }
                        Copy("sub"); Copy("scope"); Copy("client_id"); Copy("iss"); Copy("jti"); Copy("sid");
                        if (long.TryParse(id?.FindFirst("exp")?.Value, out var exp)) body["exp"] = exp;
                        if (long.TryParse(id?.FindFirst("iat")?.Value, out var iat)) body["iat"] = iat;
                        if (long.TryParse(id?.FindFirst("nbf")?.Value, out var nbf)) body["nbf"] = nbf;
                        var aud = id?.FindFirst("aud")?.Value;
                        if (!string.IsNullOrEmpty(aud)) body["aud"] = aud!;
                        body["token_type"] = "Bearer";
                        body["username"] = id?.FindFirst("sub")?.Value ?? "";
                        return Ok(body);
                    }
                }

                if (hint != "access_token")
                {
                    var refresh = await _grants.FindRefreshTokenAsync(token);
                    if (refresh != null && !refresh.revoked && refresh.consumed_at == null
                        && refresh.expires_at > DateTime.UtcNow)
                    {
                        return Ok(new Dictionary<string, object>
                        {
                            ["active"] = true,
                            ["sub"] = refresh.subject,
                            ["client_id"] = refresh.client_id,
                            ["scope"] = refresh.scope ?? "",
                            ["token_type"] = "refresh_token",
                            ["exp"] = ArkTokenService.ToUnix(refresh.expires_at),
                            ["iat"] = ArkTokenService.ToUnix(refresh.created_at),
                            ["iss"] = ep.Issuer
                        });
                    }
                }

                return Ok(inactive);
            }, _da, "introspect");
        }

        // -----------------------------------------------------------------
        // Revocation (RFC 7009)
        // -----------------------------------------------------------------

        [HttpPost("revoke")]
        [Consumes("application/x-www-form-urlencoded")]
        public async Task<IActionResult> Revoke([FromRoute] string tenant_id)
        {
            NoStore();
            return await ProtectAsync(async () =>
            {
                var tenant = await ResolveTenantAsync(tenant_id);
                var ep = Endpoints(tenant.tenant_id);
                var auth = await _clientAuth.AuthenticateAsync(Request, tenant.tenant_id, ep.Revocation);

                var token = Request.Form["token"].ToString();
                if (string.IsNullOrWhiteSpace(token))
                    throw OAuthException.InvalidRequest("token is required.");

                // Revoking a refresh token kills its whole rotation family.
                var revoked = await _grants.RevokeRefreshTokenAsync(token, auth.Client.client_id);

                if (!revoked)
                {
                    // An access token is a self-contained JWT and cannot be withdrawn, but
                    // revoking the session behind it stops any further tokens being minted.
                    var result = await _tokens.ValidateAsync(token, tenant, ep.Issuer);
                    if (result.IsValid)
                    {
                        var sid = result.ClaimsIdentity?.FindFirst("sid")?.Value;
                        if (!string.IsNullOrEmpty(sid))
                        {
                            var ended = await _grants.RevokeSessionsAsync(new[] { sid! });
                            await _backchannel.NotifyAsync(ended, tid => Endpoints(tid).Issuer, "token_revocation");
                        }
                    }
                }

                _da.Log("revoke", $"{tenant.tenant_id}/oauth2/revoke", "token revocation processed",
                    $"client: {auth.Client.client_id}");

                // §2.2: an unknown token is still a success — the caller's goal is already met.
                return Ok();
            }, _da, "revoke");
        }

        // -----------------------------------------------------------------
        // RP-initiated logout (OIDC RP-Initiated Logout 1.0) and back-channel logout
        // (OIDC Back-Channel Logout 1.0)
        // -----------------------------------------------------------------

        [HttpGet("logout")]
        [HttpPost("logout")]
        public async Task<IActionResult> EndSession([FromRoute] string tenant_id)
        {
            NoStore();
            var tenant = await ResolveTenantAsync(tenant_id);
            var opt = Options;

            string? Param(string name) =>
                Request.Query[name].FirstOrDefault()
                ?? (Request.HasFormContentType ? Request.Form[name].FirstOrDefault() : null);

            var idTokenHint = Param("id_token_hint");
            var postLogoutRedirectUri = Param("post_logout_redirect_uri");
            var state = Param("state");
            var clientId = Param("client_id");

            // Identify the client from the hint when one was not named explicitly.
            if (string.IsNullOrEmpty(clientId) && !string.IsNullOrEmpty(idTokenHint))
            {
                try
                {
                    var parsed = new JsonWebTokenHandler().ReadJsonWebToken(idTokenHint);
                    clientId = parsed.Audiences.FirstOrDefault();
                }
                catch { /* an unreadable hint simply yields no client */ }
            }

            // --- decide what is being signed out ---
            //
            // The cookie names one session, but a browser accumulates them: each sign-in creates a
            // session and overwrites the cookie, so every earlier session stays live and becomes
            // unreachable from the browser while remaining perfectly valid at the token endpoint.
            // On a shared machine that is two different people, and ending only the newest is a
            // sign-out that leaves the previous user signed in everywhere they had been.
            var sessionId = Request.Cookies[OidcAuthorizeController.SessionCookie];
            var browserId = Request.Cookies[OidcAuthorizeController.BrowserCookie];

            var targets = new List<string>();
            if (!string.IsNullOrEmpty(sessionId)) targets.Add(sessionId!);

            if (opt.SignOutAllBrowserSessions && !string.IsNullOrEmpty(browserId))
            {
                // Scoped to the tenant unless the deployment says otherwise. The browser cookie is
                // one per deployment, not one per tenant, so crossing that boundary is a choice.
                var scope = opt.SignOutAcrossTenants ? null : tenant.tenant_id;
                foreach (var session in await _grants.GetBrowserSessionsAsync(browserId, scope))
                    targets.Add(session.session_id);
            }

            // Revoked first, and before any redirect is validated, so the sign-out has already
            // happened even if the rest of this request fails. RevokeSessionsAsync returns only
            // the sessions that were actually live, so a resubmitted logout does not re-notify.
            var ended = await _grants.RevokeSessionsAsync(targets);

            ClearCookie(OidcAuthorizeController.SessionCookie);
            // The browser id is deliberately kept: it identifies the user agent, not the user, and
            // dropping it would leave the next sign-in unable to find sessions created before it.

            var report = await _backchannel.NotifyAsync(ended, tid => Endpoints(tid).Issuer, "rp_logout");

            _da.Log("logout", $"{tenant.tenant_id}/oauth2/logout",
                $"{report.SessionsEnded} session(s) ended for {report.SubjectsEnded} user(s)",
                $"client: {clientId}, notified: {report.Notified}, failed: {report.Failed}, " +
                $"not registered: {report.NotRegistered}");

            if (!string.IsNullOrEmpty(postLogoutRedirectUri))
            {
                var client = await Ctx.clients.AsNoTracking().FirstOrDefaultAsync(c =>
                    c.tenant_id.ToLower() == tenant.tenant_id.ToLower() &&
                    c.client_id.ToLower() == (clientId ?? "").ToLower());

                // Only redirect to a URI the client registered — otherwise this is an open redirect.
                if (client != null && RedirectUriValidator.Matches(client.EffectivePostLogoutRedirectUris, postLogoutRedirectUri!))
                {
                    var target = postLogoutRedirectUri!;
                    if (!string.IsNullOrEmpty(state))
                        target += (target.Contains('?') ? "&" : "?") + $"state={Uri.EscapeDataString(state!)}";
                    return Redirect(target);
                }
            }

            return View("~/Views/Oidc/LoggedOut.cshtml", new LoggedOutPageModel
            {
                Brand = new OidcBrandModel
                {
                    HostLogo = ServerConfig.EmailConfig?.host_logo,
                    HostName = ServerConfig.EmailConfig?.host_company_display ?? "Identity Provider",
                    PrivacyUrl = ServerConfig.EmailConfig?.privacy_policy_url,
                    TermsUrl = ServerConfig.EmailConfig?.terms_url
                },
                Error = "signed_out",
                Description = Describe(report),
                SessionsEnded = report.SessionsEnded,
                SubjectsEnded = report.SubjectsEnded,
                ClientsNotified = report.Notified,
                ClientsFailed = report.Failed
            });
        }

        /// <summary>
        /// What the signed-out page says. It names the scale of the sign-out when more than one
        /// session ended, because on a shared browser that is the fact the person needs — "you
        /// have been signed out" is misleading when it was three people.
        /// </summary>
        private static string Describe(BackChannelLogoutReport report)
        {
            if (report.SessionsEnded == 0) return "You were not signed in.";
            if (report.SubjectsEnded > 1)
                return $"All {report.SubjectsEnded} accounts signed in on this browser have been signed out.";
            if (report.SessionsEnded > 1)
                return $"All {report.SessionsEnded} of your sessions on this browser have been signed out.";
            return "You have been signed out.";
        }

        private void ClearCookie(string name)
        {
            Response.Cookies.Delete(name, new CookieOptions
            {
                Path = string.IsNullOrEmpty(Request.PathBase) ? "/" : Request.PathBase.Value!
            });
        }
    }
}
