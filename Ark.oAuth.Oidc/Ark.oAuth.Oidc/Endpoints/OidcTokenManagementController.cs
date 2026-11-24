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

                // §4: which tokens this caller may ask about. Its own, always; anyone else's only
                // when it is configured as a resource server. Answered as inactive rather than
                // refused, so the response does not confirm that the token exists.
                var caller = auth.Client.client_id;
                var mayInspectOthers = (Options.IntrospectionClients ?? new List<string>())
                    .Any(c => string.Equals(c?.Trim(), caller, StringComparison.OrdinalIgnoreCase));
                bool MayInspect(string? issuedTo) =>
                    mayInspectOthers || string.Equals(issuedTo, caller, StringComparison.OrdinalIgnoreCase);

                if (hint != "refresh_token")
                {
                    var result = await _tokens.ValidateAsync(token, tenant, ep.Issuer);
                    if (result.IsValid && !await IsSupersededServiceTokenAsync(result.ClaimsIdentity, token))
                    {
                        if (!MayInspect(result.ClaimsIdentity?.FindFirst("client_id")?.Value))
                            return Ok(inactive);
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

                    // An agent-to-agent token is addressed to one client, not to the tenant, so
                    // the check above never passes it. The agent it is addressed to may ask about
                    // it, as may the client it was issued to and a configured resource server.
                    // So is a token for one of this server's MCP endpoints.
                    if (!result.IsValid && (Options.EnableA2A || ServerConfig.Mcp is { Enabled: true }))
                    {
                        var a2a = await IntrospectAgentTokenAsync(token, tenant, ep.Issuer, caller, mayInspectOthers);
                        if (a2a != null) return Ok(a2a);
                    }
                }

                if (hint != "access_token")
                {
                    var refresh = await _grants.FindRefreshTokenAsync(token);
                    // Refresh tokens are looked up server-wide, so the tenant is checked here: a
                    // token issued at another tenant is not this endpoint's to describe, even to a
                    // client of the same id or one listed in IntrospectionClients.
                    if (refresh != null && !refresh.revoked && refresh.consumed_at == null
                        && refresh.expires_at > DateTime.UtcNow
                        && string.Equals(refresh.tenant_id, tenant.tenant_id, StringComparison.OrdinalIgnoreCase)
                        && MayInspect(refresh.client_id))
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

        /// <summary>
        /// The introspection response for an agent-to-agent token, or null when it is not one this
        /// caller may ask about. Carries <c>act</c> (RFC 8693 §4.1), which is the reason an agent
        /// would introspect rather than read the claims itself: the answer also says the session
        /// behind a delegated token is still alive.
        /// </summary>
        private async Task<Dictionary<string, object>?> IntrospectAgentTokenAsync(
            string token, ArkTenant tenant, string issuer, string caller, bool mayInspectOthers)
        {
            var result = await _tokens.ValidateAccessTokenAnyAudienceAsync(token, tenant, issuer);
            if (!result.IsValid || result.SecurityToken is not JsonWebToken jwt) return null;

            using var doc = System.Text.Json.JsonDocument.Parse(
                Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Decode(jwt.EncodedPayload));
            var claims = doc.RootElement;
            string? Text(string name) =>
                claims.TryGetProperty(name, out var v) && v.ValueKind == System.Text.Json.JsonValueKind.String ? v.GetString() : null;

            var audiences = jwt.Audiences.ToList();
            var addressedToCaller = audiences.Any(a => string.Equals(a, caller, StringComparison.OrdinalIgnoreCase));
            var issuedToCaller = string.Equals(Text("client_id"), caller, StringComparison.OrdinalIgnoreCase);

            // Only a token addressed to a client is an agent token; anything else that reaches
            // here (a token for another tenant audience, say) is not this trail's business.
            // A token for one of this server's own MCP endpoints is not an agent token either.
            var root = Endpoints(tenant.tenant_id).BaseUrl;
            var agentToken = audiences.Count > 0
                && !audiences.Any(a => ArkAgentTokens.IsTenantAudience(a, tenant, issuer) || Mcp.ArkMcpResources.Parse(root, a) != null);
            var sid = Text("sid");
            var actors = claims.TryGetProperty("act", out var chain) ? ArkAgentTokens.ActorChain(chain) : new List<string>();
            void Asked(bool active, string relation, string? reason)
            {
                if (!agentToken) return;
                _da.Log("a2a_introspect", $"{tenant.tenant_id}/oauth2/introspect",
                    active ? "a2a token introspected: active" : $"a2a token introspected: not active ({reason})",
                    $"client: {caller}, jti: {Text("jti")}, audience: {string.Join(" ", audiences)}", active ? "trace" : "warn",
                    ArkAgentAudit.Introspected(tenant, caller, active, relation, reason, Text("jti"), Text("sub"),
                        Text("client_id"), audiences, actors, sid));
            }

            if (!addressedToCaller && !issuedToCaller && !mayInspectOthers)
            {
                // Somebody is holding an agent token that is neither theirs nor for them.
                Asked(false, "none", "the token is neither addressed to this client nor was it issued to it");
                return null;
            }
            var relation = addressedToCaller ? "addressed_to_caller" : issuedToCaller ? "issued_to_caller" : "resource_server";

            // Issued on behalf of a user in a session: it is live only while that session is.
            if (!string.IsNullOrEmpty(sid) && await _grants.GetSessionAsync(sid) == null)
            {
                Asked(false, relation, "the session behind the token has ended");
                return null;
            }
            Asked(true, relation, null);

            var body = new Dictionary<string, object> { ["active"] = true, ["token_type"] = "Bearer" };
            foreach (var name in new[] { "sub", "scope", "client_id", "iss", "jti", "sid" })
            {
                var v = Text(name);
                if (!string.IsNullOrEmpty(v)) body[name] = v!;
            }
            foreach (var name in new[] { "exp", "iat", "nbf" })
                if (claims.TryGetProperty(name, out var n) && n.TryGetInt64(out var seconds)) body[name] = seconds;
            if (audiences.Count > 0) body["aud"] = audiences.Count == 1 ? audiences[0] : audiences;
            body["username"] = Text("sub") ?? "";
            if (claims.TryGetProperty("ark_claims", out var granted)) body["ark_claims"] = granted.Clone();
            if (claims.TryGetProperty("act", out var act)) body["act"] = act.Clone();
            return body;
        }

        /// <summary>
        /// A legacy service-account token (the <c>service_role</c> JWT, valid for a year) is live
        /// only while it is the one the account holds: regenerating it in the console replaces the
        /// stored digest, and that is what retires the old token here. A row still holding a token
        /// in the clear, from before digests, is matched as it stands.
        /// </summary>
        private async Task<bool> IsSupersededServiceTokenAsync(System.Security.Claims.ClaimsIdentity? identity, string token)
        {
            if (identity?.FindFirst("service_role") == null) return false;
            var digest = ArkUtil.ServiceTokenDigest(token);
            return !await Ctx.users.AsNoTracking()
                .AnyAsync(u => u.type == "service" && (u.hash_pw == digest || u.hash_pw == token));
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
                var revoked = await _grants.RevokeRefreshTokenAsync(token, auth.Client);

                if (!revoked)
                {
                    // An access token is a self-contained JWT and cannot be withdrawn, but
                    // revoking the session behind it stops any further tokens being minted.
                    var result = await _tokens.ValidateAsync(token, tenant, ep.Issuer);
                    // RFC 7009 §2.1: only the client the token was issued to may revoke it. This
                    // check was missing, so any client — a public one needs nothing but its id —
                    // could end another application's user session by presenting its token.
                    var issuedTo = result.ClaimsIdentity?.FindFirst("client_id")?.Value;
                    if (result.IsValid && string.Equals(issuedTo, auth.Client.client_id, StringComparison.OrdinalIgnoreCase))
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
                Webhooks.ArkWebhookEvents.Raise(HttpContext, tenant.tenant_id, Webhooks.ArkWebhookEvents.TokenRevoked,
                    new { client_id = auth.Client.client_id, refresh_token_revoked = revoked }, auth.Client.client_id);

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
            FrameAncestorsSelf(); // the logout confirmation is a button too
            var tenant = await ResolveTenantAsync(tenant_id);
            var opt = Options;

            string? Param(string name) =>
                Request.Query[name].FirstOrDefault()
                ?? (Request.HasFormContentType ? Request.Form[name].FirstOrDefault() : null);

            var idTokenHint = Param("id_token_hint");
            var postLogoutRedirectUri = Param("post_logout_redirect_uri");
            var state = Param("state");
            var clientId = Param("client_id");

            // The hint counts only once its signature checks out. Read unverified, it named the
            // client but proved nothing — and a hint that proves nothing cannot stand in for the
            // user's confirmation below.
            var hintValid = false;
            JsonWebToken? hintToken = null;
            if (!string.IsNullOrEmpty(idTokenHint))
            {
                var hint = await _tokens.ValidateIdTokenHintAsync(idTokenHint!, tenant, Endpoints(tenant.tenant_id).Issuer,
                    TimeSpan.FromMinutes(Math.Max(1, opt.SessionLifetimeMinutes)));
                if (hint.IsValid)
                {
                    hintValid = true;
                    hintToken = hint.SecurityToken as JsonWebToken;
                    // Identify the client from the hint when one was not named explicitly.
                    if (string.IsNullOrEmpty(clientId))
                        clientId = hintToken?.Audiences.FirstOrDefault();
                    // ...and when one was, it has to be a client the hint was issued to: the
                    // post_logout_redirect_uri below is checked against that client's list.
                    else if (hintToken != null && !hintToken.Audiences.Contains(clientId, StringComparer.OrdinalIgnoreCase))
                        hintValid = false;
                }
            }

            // --- decide what is being signed out ---
            //
            // The cookie names one session, but a browser accumulates them: each sign-in creates a
            // session and overwrites the cookie, so every earlier session stays live and becomes
            // unreachable from the browser while remaining perfectly valid at the token endpoint.
            // On a shared machine that is two different people, and ending only the newest is a
            // sign-out that leaves the previous user signed in everywhere they had been.
            var sessionCookie = Request.Cookies[OidcAuthorizeController.SessionCookie];
            var sessionId = string.IsNullOrEmpty(sessionCookie) ? null : ArkGrantStore.SessionIdFor(sessionCookie!);
            var browserId = Request.Cookies[OidcAuthorizeController.BrowserCookie];

            var targets = new List<string>();
            var targetSubjects = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (!string.IsNullOrEmpty(sessionId)) targets.Add(sessionId!);
            var current = await _grants.GetSessionAsync(sessionId);
            var live = current != null;
            if (current != null) targetSubjects.Add(current.subject);

            if (opt.SignOutAllBrowserSessions && !string.IsNullOrEmpty(browserId))
            {
                // Scoped to the tenant unless the deployment says otherwise. The browser cookie is
                // one per deployment, not one per tenant, so crossing that boundary is a choice.
                var scope = opt.SignOutAcrossTenants ? null : tenant.tenant_id;
                foreach (var session in await _grants.GetBrowserSessionsAsync(browserId, scope))
                {
                    targets.Add(session.session_id);
                    targetSubjects.Add(session.subject);
                    live = true;
                }
            }

            // A hint stands in for the user's confirmation only when it is about the sessions
            // being ended. Any ID token this tenant signed used to do — so a page could send the
            // victim's browser here with the attacker's own hint and sign them out of every
            // application, in every tenant, with no confirmation shown.
            if (hintValid && live && hintToken != null)
            {
                var hintSid = hintToken.TryGetPayloadValue<string>("sid", out var s) ? s : null;
                var aboutThese = (!string.IsNullOrEmpty(hintSid) && targets.Contains(hintSid!))
                                 || (!string.IsNullOrEmpty(hintToken.Subject) && targetSubjects.Contains(hintToken.Subject));
                if (!aboutThese) hintValid = false;
            }

            // RP-Initiated Logout 1.0 §2: without a valid id_token_hint the request could have come
            // from any page — an <img> pointed here signed the visitor out of every application,
            // and on a shared browser out of every account. Such a request is asked to confirm,
            // with a form only this origin can submit. Nothing live to end means nothing to ask.
            if (!hintValid && live)
            {
                var confirmed = HttpMethods.IsPost(Request.Method) && Request.HasFormContentType
                    && Request.Form["ark_action"] == "logout"
                    && await HttpContext.RequestServices
                        .GetRequiredService<Microsoft.AspNetCore.Antiforgery.IAntiforgery>()
                        .IsRequestValidAsync(HttpContext);
                if (!confirmed)
                {
                    var fields = new Dictionary<string, string>();
                    if (!string.IsNullOrEmpty(postLogoutRedirectUri)) fields["post_logout_redirect_uri"] = postLogoutRedirectUri!;
                    if (!string.IsNullOrEmpty(state)) fields["state"] = state!;
                    if (!string.IsNullOrEmpty(clientId)) fields["client_id"] = clientId!;
                    return View("~/Views/Oidc/LogoutConfirm.cshtml", new LogoutConfirmPageModel
                    {
                        Brand = new OidcBrandModel
                        {
                            HostLogo = ServerConfig.EmailConfig?.host_logo,
                            HostName = ServerConfig.EmailConfig?.host_company_display ?? "Identity Provider",
                            PrivacyUrl = ServerConfig.EmailConfig?.privacy_policy_url,
                            TermsUrl = ServerConfig.EmailConfig?.terms_url
                        },
                        ActionUrl = $"{Request.PathBase}{Request.Path}",
                        Fields = fields
                    });
                }
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
            foreach (var endedSession in ended)
                Webhooks.ArkWebhookEvents.Raise(HttpContext, endedSession.tenant_id, Webhooks.ArkWebhookEvents.UserSignedOut,
                    new { user = endedSession.subject, session_id = endedSession.session_id, client_id = clientId, reason = "rp_logout" }, endedSession.subject);

            if (!string.IsNullOrEmpty(postLogoutRedirectUri))
            {
                var client = await FindClientAsync(tenant, (clientId ?? ""));

                // Only redirect to a URI the client registered — otherwise this is an open redirect.
                if (client != null && RedirectUriValidator.Matches(client.EffectivePostLogoutRedirectUris, postLogoutRedirectUri!)
                    && !RedirectUriValidator.CarriesScript(postLogoutRedirectUri!))
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
