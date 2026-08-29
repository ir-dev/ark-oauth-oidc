using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Ark.oAuth.Oidc.Protocol;

namespace Ark.oAuth.Oidc.Endpoints
{
    /// <summary>
    /// The authorization endpoint (RFC 6749 §3.1, OIDC Core §3.1.2).
    ///
    /// The ordering of checks here is deliberate and load-bearing. Until the client and
    /// redirect_uri are both known-good, an error is rendered as a page; only afterwards is it
    /// safe to send errors back to the redirect_uri, because redirecting to an unvalidated URI
    /// is itself an open redirect.
    /// </summary>
    [Route("{tenant_id}/oauth2")]
    public class OidcAuthorizeController : ArkOidcControllerBase
    {
        private readonly ArkGrantStore _grants;
        private readonly ArkClaimsService _claims;
        private readonly ArkBackChannelLogout _backchannel;
        private readonly DataAccess _da;

        public const string SessionCookie = "ark_idp_sid";

        /// <summary>
        /// Identifies the browser rather than the sign-in. Long-lived and re-used across sessions,
        /// so every session created in this user agent can be found again — see
        /// <see cref="ArkSession.browser_id"/>. Carries no identity of its own: it is a random
        /// value that means nothing without the session rows that point at it.
        /// </summary>
        public const string BrowserCookie = "ark_idp_bid";

        public OidcAuthorizeController(ArkDataContext ctx, IConfiguration config,
            ArkGrantStore grants, ArkClaimsService claims, ArkBackChannelLogout backchannel, DataAccess da)
            : base(ctx, config)
        {
            _grants = grants;
            _claims = claims;
            _backchannel = backchannel;
            _da = da;
        }

        [HttpGet("authorize")]
        public Task<IActionResult> AuthorizeGet([FromRoute] string tenant_id) => Handle(tenant_id, null);

        [HttpPost("authorize")]
        [ValidateAntiForgeryToken]
        public Task<IActionResult> AuthorizePost([FromRoute] string tenant_id) => Handle(tenant_id, Request.Form);

        // -----------------------------------------------------------------

        private async Task<IActionResult> Handle(string tenantId, IFormCollection? form)
        {
            NoStore();
            FrameAncestorsSelf();
            ArkTenant tenant;
            try
            {
                tenant = await ResolveTenantAsync(tenantId);
            }
            catch (OAuthException ex)
            {
                return ErrorPage(ex.Error, ex.ErrorDescription, null, null);
            }

            var ep = Endpoints(tenant.tenant_id);
            var p = await ReadParametersAsync(form);

            // --- phase 1: identify the client. Errors cannot be redirected yet. ---
            var brand = await BuildBrandAsync(null);
            var clientId = p.GetValueOrDefault("client_id");
            if (string.IsNullOrWhiteSpace(clientId))
                return ErrorPage(OAuthErrorCodes.InvalidRequest, "client_id is required.", brand, tenant);

            var client = await Ctx.clients.FirstOrDefaultAsync(c =>
                c.tenant_id.ToLower() == tenant.tenant_id.ToLower() && c.client_id.ToLower() == clientId.ToLower());
            if (client == null)
                return ErrorPage(OAuthErrorCodes.InvalidRequest, "unknown client_id.", brand, tenant);
            if (!client.is_active)
                // Named, and phrased for the person in front of the screen rather than for the
                // developer reading a log. There is nothing they can retype to get past this, so
                // the page has to say what happened and who can undo it.
                return ErrorPage(OAuthErrorCodes.UnauthorizedClient,
                    $"{(string.IsNullOrWhiteSpace(client.display) ? client.client_id : client.display)} has been deactivated, " +
                    "so it is not accepting sign-ins at the moment. Please contact your administrator.",
                    brand, tenant);

            brand = await BuildBrandAsync(client);

            // --- phase 2: pushed authorization request, if used ---
            var requestUri = p.GetValueOrDefault("request_uri");
            if (!string.IsNullOrEmpty(requestUri))
            {
                if (!Options.EnablePushedAuthorizationRequests)
                    return ErrorPage(OAuthErrorCodes.RequestNotSupported, "pushed authorization requests are not enabled.", brand, tenant);
                try
                {
                    // Read without spending it: this handler re-enters with the same request_uri
                    // for the sign-in and consent posts. It is marked used once the request
                    // reaches a terminal outcome, below.
                    var pushed = await _grants.ReadParRequestAsync(requestUri!, client.client_id);
                    // PAR parameters replace the query entirely (RFC 9126 §4)
                    pushed["client_id"] = client.client_id;
                    p = pushed;
                }
                catch (OAuthException ex)
                {
                    return ErrorPage(ex.Error, ex.ErrorDescription, brand, tenant);
                }
            }
            else if (Options.RequirePushedAuthorizationRequests || client.require_par)
            {
                return ErrorPage(OAuthErrorCodes.InvalidRequest,
                    "this client must use pushed authorization requests.", brand, tenant);
            }

            // --- phase 3: validate redirect_uri before any error may be redirected ---
            var redirectUri = p.GetValueOrDefault("redirect_uri");
            var registered = client.EffectiveRedirectUris;
            if (string.IsNullOrWhiteSpace(redirectUri))
            {
                if (registered.Count == 1) redirectUri = registered[0];
                else return ErrorPage(OAuthErrorCodes.InvalidRequest,
                    "redirect_uri is required because this client has several registered.", brand, tenant);
            }
            if (!RedirectUriValidator.Matches(registered, redirectUri!))
                return ErrorPage(OAuthErrorCodes.InvalidRequest,
                    "redirect_uri does not match a registered value for this client.", brand, tenant);

            // --- from here on, errors go back to the client ---
            var state = p.GetValueOrDefault("state");
            var responseMode = p.GetValueOrDefault("response_mode");
            if (string.IsNullOrEmpty(responseMode)) responseMode = "query";
            if (responseMode is not ("query" or "fragment" or "form_post"))
            {
                await _grants.MarkParConsumedAsync(requestUri!);
                return Fail(redirectUri!, "query", OAuthErrorCodes.InvalidRequest, "unsupported response_mode.", state, ep);
            }

            try
            {
                var responseType = p.GetValueOrDefault("response_type");
                if (string.IsNullOrWhiteSpace(responseType))
                    throw OAuthException.InvalidRequest("response_type is required.");
                if (responseType!.Trim() != "code")
                    throw new OAuthException(OAuthErrorCodes.UnsupportedResponseType,
                        "only the authorization code flow (response_type=code) is supported; implicit and hybrid flows are removed in OAuth 2.1.");

                if (!client.EffectiveGrantTypes.Contains("authorization_code", StringComparer.OrdinalIgnoreCase))
                    throw OAuthException.UnauthorizedClient("this client is not registered for the authorization_code grant.");

                // PKCE (RFC 7636). Mandatory for public clients and for any client configured to require it.
                var codeChallenge = p.GetValueOrDefault("code_challenge");
                var codeChallengeMethod = p.GetValueOrDefault("code_challenge_method");
                if (client.require_pkce || client.IsPublicClient)
                {
                    if (string.IsNullOrWhiteSpace(codeChallenge))
                        throw OAuthException.InvalidRequest("code_challenge is required (PKCE).");
                    if (string.IsNullOrWhiteSpace(codeChallengeMethod))
                        codeChallengeMethod = "S256";
                    if (!string.Equals(codeChallengeMethod, "S256", StringComparison.OrdinalIgnoreCase))
                        throw OAuthException.InvalidRequest("code_challenge_method must be S256.");
                }

                var scopes = await _claims.ResolveScopesAsync(p.GetValueOrDefault("scope"), client);
                var prompt = (p.GetValueOrDefault("prompt") ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries);
                var nonce = p.GetValueOrDefault("nonce");

                // --- authentication ---
                var session = await _grants.GetSessionAsync(Request.Cookies[SessionCookie]);
                if (session != null && !string.Equals(session.tenant_id, tenant.tenant_id, StringComparison.OrdinalIgnoreCase))
                    session = null;

                // max_age forces re-authentication once the existing session is too old
                if (session != null && int.TryParse(p.GetValueOrDefault("max_age"), out var maxAge) && maxAge >= 0)
                {
                    if ((DateTime.UtcNow - session.auth_time).TotalSeconds > maxAge) session = null;
                }
                if (prompt.Contains("login")) session = null;

                // A session outlives the switch that created it. Deactivating a user revokes their
                // sessions, so this is only reached when the flag was flipped straight in the
                // database — but without it, a browser that already holds the cookie would keep
                // being issued codes for an account that is switched off, which is the one thing
                // the switch is for.
                if (session != null)
                {
                    var holder = await Ctx.users.AsNoTracking()
                        .FirstOrDefaultAsync(u => u.email.ToLower() == session.subject.ToLower());
                    if (holder != null && !holder.is_active)
                    {
                        var dropped = await _grants.RevokeSessionsAsync(new[] { session.session_id });
                        // The applications this session had opened are still showing the user as
                        // signed in. Dropping the session here without telling them is what leaves
                        // a deactivated account working everywhere except the sign-in page.
                        await _backchannel.NotifyAsync(dropped, tid => Endpoints(tid).Issuer, "user_deactivated");
                        var inactive = new ArkAccountInactiveException(ArkActivationLevel.User, holder.name ?? holder.email);
                        _da.Log("signin_inactive", tenant.tenant_id, "session dropped: user deactivated",
                            $"user: {session.subject}, client: {client.client_id}", "warn");
                        return LoginPage(brand, client, inactive.FriendlyMessage, session.subject, tenant);
                    }
                }

                var action = form?["ark_action"].ToString();

                if (session == null)
                {
                    if (prompt.Contains("none"))
                        throw new OAuthException(OAuthErrorCodes.LoginRequired, "the user is not signed in.");

                    if (action == "signin")
                    {
                        var username = form?["username"].ToString() ?? "";
                        var password = form?["password"].ToString() ?? "";
                        var signIn = await TrySignInAsync(tenant, client, username, password, EnsureBrowserId());
                        if (signIn.error != null)
                            return LoginPage(brand, client, signIn.error, username, tenant);
                        session = signIn.session!;
                        AppendSessionCookie(session!);
                    }
                    else
                    {
                        return LoginPage(brand, client, null, p.GetValueOrDefault("login_hint"), tenant);
                    }
                }

                // --- consent ---
                var needsConsent = client.require_consent || Options.AlwaysRequireConsent || prompt.Contains("consent");
                var stored = await _grants.GetConsentAsync(tenant.tenant_id, client.client_id, session!.subject);
                var alreadyGranted = stored?.scopes ?? new List<string>();
                var missing = scopes.Where(s => !alreadyGranted.Contains(s, StringComparer.OrdinalIgnoreCase)).ToList();

                if (needsConsent || missing.Count > 0)
                {
                    if (prompt.Contains("none"))
                        throw new OAuthException(OAuthErrorCodes.ConsentRequired, "user consent is required.");

                    if (action == "consent")
                    {
                        var granted = form?["scope"].ToArray().Where(s => !string.IsNullOrEmpty(s)).Select(s => s!).ToList()
                                      ?? new List<string>();
                        // protocol scopes are not user-deselectable
                        foreach (var s in scopes.Where(IsProtocolScope))
                            if (!granted.Contains(s, StringComparer.OrdinalIgnoreCase)) granted.Add(s);

                        var denied = scopes.Where(s => !granted.Contains(s, StringComparer.OrdinalIgnoreCase)).ToList();
                        if (granted.Count == 0)
                            throw new OAuthException(OAuthErrorCodes.AccessDenied, "the user denied the request.");

                        await _grants.SaveConsentAsync(tenant.tenant_id, client.client_id, session.subject, granted);
                        scopes = scopes.Where(s => granted.Contains(s, StringComparer.OrdinalIgnoreCase)).ToList();
                    }
                    else if (action == "deny")
                    {
                        throw new OAuthException(OAuthErrorCodes.AccessDenied, "the user denied the request.");
                    }
                    else
                    {
                        return await ConsentPageAsync(brand, client, session.subject, scopes, tenant);
                    }
                }

                // --- issue the code ---
                var code = await _grants.CreateAuthCodeAsync(client, tenant.tenant_id, session.subject,
                    redirectUri!, scopes, codeChallenge, codeChallengeMethod, nonce, session.session_id, session.auth_time);

                // From here the client is logged in under this session, so it has to be told when
                // the session ends. Recorded at the code rather than at the token exchange: a code
                // that is never redeemed costs one row, whereas a client missed here is a client
                // that silently keeps its own session alive after logout.
                await _grants.TrackSessionClientAsync(tenant.tenant_id, session.session_id, client.client_id, session.subject);

                var response = new Dictionary<string, string> { ["code"] = code };
                if (!string.IsNullOrEmpty(state)) response["state"] = state!;
                response["iss"] = ep.Issuer; // RFC 9207 mix-up defence

                _da.Log("authorize", $"{tenant.tenant_id}/oauth2/authorize",
                    $"code issued for {client.client_id}", $"sub: {session.subject}, scopes: {string.Join(" ", scopes)}");

                // the request is finished, so the request_uri may not drive another one
                await _grants.MarkParConsumedAsync(requestUri!);
                return Respond(redirectUri!, responseMode!, response);
            }
            catch (OAuthException ex)
            {
                await _grants.MarkParConsumedAsync(requestUri!);
                return Fail(redirectUri!, responseMode!, ex.Error, ex.ErrorDescription, state, ep);
            }
            catch (Exception ex)
            {
                _da.LogError(ex, "authorize", Request.Path, ex.Message);
                await _grants.MarkParConsumedAsync(requestUri!);
                return Fail(redirectUri!, responseMode!, OAuthErrorCodes.ServerError,
                    "the authorization server encountered an unexpected condition.", state, ep);
            }
        }

        // -----------------------------------------------------------------
        // sign-in
        // -----------------------------------------------------------------

        private async Task<(ArkSession? session, string? error)> TrySignInAsync(
            ArkTenant tenant, ArkClient client, string username, string password, string browserId)
        {
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
                return (null, "Enter your username and password.");

            var opt = Options;
            if (opt.MaxFailedSignIns > 0)
            {
                var status = await Ctx.auth_status.AsNoTracking()
                    .FirstOrDefaultAsync(s => s.email.ToLower() == username.ToLower());
                if (status != null && status.retry_count >= opt.MaxFailedSignIns
                    && (DateTime.UtcNow - status.at).TotalMinutes < opt.LockoutMinutes)
                {
                    _da.Log("signin_lockout", tenant.tenant_id, "sign-in blocked by lockout", $"user: {username}", "warn");
                    return (null, $"Too many failed attempts. Try again in {opt.LockoutMinutes} minutes.");
                }
            }

            try
            {
                var user = await _da.ValidateUserCreds(username, password, client.client_id, tenant.tenant_id);
                if (user.reset_mode ?? false)
                    return (null, "This account needs its password set. Check your email for the activation link.");

                var session = await _grants.CreateSessionAsync(
                    tenant.tenant_id, user.email, opt.SessionLifetimeMinutes, browserId);
                _da.Log("signin", tenant.tenant_id, "sign-in succeeded", $"user: {username}, client: {client.client_id}");
                return (session, null);
            }
            catch (ArkAccountInactiveException ex)
            {
                // The one failure that is told apart from the others. It is only ever reached
                // after the password has been verified — see DataAccess.ValidateUserCreds — so
                // naming the reason tells nobody anything they could not already establish, and
                // it saves the user retyping credentials that are in fact correct.
                _da.Log("signin_inactive", tenant.tenant_id, $"sign-in refused: {ex.Level} deactivated",
                    $"user: {username}, client: {client.client_id}", "warn");
                return (null, ex.FriendlyMessage);
            }
            catch (Exception ex)
            {
                _da.Log("signin_failed", tenant.tenant_id, "sign-in failed", $"user: {username}, reason: {ex.Message}", "warn");
                // one message for every failure mode, so the page cannot be used to enumerate accounts
                return (null, "That username and password combination was not recognised.");
            }
        }

        /// <summary>
        /// Reads the browser id, minting and setting one when this user agent has not been here
        /// before. Called at sign-in, so a browser that only ever gets redirected away is not
        /// given a cookie it has no use for.
        ///
        /// The cookie deliberately outlives any single session — it is what a later sign-out uses
        /// to find every session created here, including ones whose sid the session cookie has
        /// long since overwritten.
        /// </summary>
        private string EnsureBrowserId()
        {
            var existing = Request.Cookies[BrowserCookie];
            if (!string.IsNullOrWhiteSpace(existing)) return existing!;
            // The request cookie collection is read-only, so a value minted here would be
            // unreadable for the rest of this request; hold it instead.
            if (!string.IsNullOrEmpty(_mintedBrowserId)) return _mintedBrowserId!;

            var browserId = ArkCrypto.RandomToken(16);
            Response.Cookies.Append(BrowserCookie, browserId, new CookieOptions
            {
                HttpOnly = true,
                Secure = Request.IsHttps,
                SameSite = SameSiteMode.Lax,
                Expires = DateTimeOffset.UtcNow.AddYears(1),
                Path = string.IsNullOrEmpty(Request.PathBase) ? "/" : Request.PathBase.Value!
            });
            _mintedBrowserId = browserId;
            return browserId;
        }

        private string? _mintedBrowserId;

        private void AppendSessionCookie(ArkSession session)
        {
            Response.Cookies.Append(SessionCookie, session.session_id, new CookieOptions
            {
                HttpOnly = true,
                Secure = Request.IsHttps,
                SameSite = SameSiteMode.Lax, // Lax still arrives on the top-level redirect from the client
                Expires = new DateTimeOffset(session.expires_at, TimeSpan.Zero),
                Path = string.IsNullOrEmpty(Request.PathBase) ? "/" : Request.PathBase.Value!
            });
        }

        // -----------------------------------------------------------------
        // responses
        // -----------------------------------------------------------------

        private IActionResult Respond(string redirectUri, string responseMode, Dictionary<string, string> values)
        {
            if (responseMode == "form_post")
                return View("~/Views/Oidc/FormPost.cshtml", new FormPostModel { RedirectUri = redirectUri, Fields = values });

            var query = string.Join("&", values.Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
            if (responseMode == "fragment")
                return Redirect($"{redirectUri}#{query}");

            var separator = redirectUri.Contains('?') ? "&" : "?";
            return Redirect($"{redirectUri}{separator}{query}");
        }

        private IActionResult Fail(string? redirectUri, string responseMode, string error, string? description, string? state, ArkOidcEndpoints ep)
        {
            if (string.IsNullOrEmpty(redirectUri))
                return ErrorPage(error, description, null, null);

            var values = new Dictionary<string, string> { ["error"] = error };
            if (!string.IsNullOrEmpty(description)) values["error_description"] = description!;
            if (!string.IsNullOrEmpty(state)) values["state"] = state!;
            values["iss"] = ep.Issuer;
            return Respond(redirectUri, responseMode, values);
        }

        // -----------------------------------------------------------------
        // pages
        // -----------------------------------------------------------------

        private IActionResult LoginPage(OidcBrandModel brand, ArkClient client, string? error, string? username, ArkTenant tenant)
        {
            Response.StatusCode = error == null ? 200 : 400;
            var reset = ServerConfig.EmailConfig?.activation_link;
            return View("~/Views/Oidc/Login.cshtml", new LoginPageModel
            {
                Brand = brand,
                ClientDisplay = string.IsNullOrWhiteSpace(client.display) ? client.client_id : client.display,
                ActionUrl = CurrentUrl(),
                Error = error,
                Username = username,
                PasswordResetUrl = string.IsNullOrEmpty(reset) ? null : null
            });
        }

        private async Task<IActionResult> ConsentPageAsync(OidcBrandModel brand, ArkClient client, string subject, List<string> scopes, ArkTenant tenant)
        {
            var catalogue = await Ctx.scopes.AsNoTracking().ToListAsync();
            var models = scopes.Select(s =>
            {
                var known = catalogue.FirstOrDefault(c => string.Equals(c.name, s, StringComparison.OrdinalIgnoreCase));
                return new ConsentScopeModel
                {
                    Name = s,
                    Display = known?.display ?? s,
                    Description = known?.description,
                    Required = IsProtocolScope(s)
                };
            }).ToList();

            return View("~/Views/Oidc/Consent.cshtml", new ConsentPageModel
            {
                Brand = brand,
                ClientDisplay = string.IsNullOrWhiteSpace(client.display) ? client.client_id : client.display,
                ClientUri = client.client_uri,
                Subject = subject,
                ActionUrl = CurrentUrl(),
                Scopes = models
            });
        }

        private IActionResult ErrorPage(string error, string? description, OidcBrandModel? brand, ArkTenant? tenant)
        {
            Response.StatusCode = 400;
            return View("~/Views/Oidc/Error.cshtml", new OidcErrorPageModel
            {
                Brand = brand ?? new OidcBrandModel { HostName = ServerConfig.EmailConfig?.host_company_display ?? "Identity Provider" },
                Error = error,
                Description = description
            });
        }

        private static bool IsProtocolScope(string scope) =>
            string.Equals(scope, "openid", StringComparison.OrdinalIgnoreCase);

        private string CurrentUrl() =>
            $"{Request.PathBase}{Request.Path}{Request.QueryString}";

        private async Task<Dictionary<string, string>> ReadParametersAsync(IFormCollection? form)
        {
            await Task.CompletedTask;
            var result = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var kv in Request.Query)
                if (kv.Value.Count > 0 && kv.Value[0] != null) result[kv.Key] = kv.Value[0]!;
            // a form value wins only where the query did not carry the parameter
            if (form != null)
                foreach (var kv in form)
                    if (!result.ContainsKey(kv.Key) && kv.Value.Count > 0 && kv.Value[0] != null) result[kv.Key] = kv.Value[0]!;
            return result;
        }

        private async Task<OidcBrandModel> BuildBrandAsync(ArkClient? client)
        {
            await Task.CompletedTask;
            var cfg = ServerConfig.EmailConfig;
            return new OidcBrandModel
            {
                HostLogo = cfg?.host_logo,
                // A logo registered against the client wins; the configured one is the fallback
                // for every client that has not uploaded its own.
                ClientLogo = string.IsNullOrWhiteSpace(client?.client_logo) ? cfg?.client_logo : client!.client_logo,
                HostName = cfg?.host_company_display ?? cfg?.host_company_name ?? "Identity Provider",
                ClientName = client == null
                    ? null
                    : new[] { client.client_name, client.display, client.name, client.client_id }
                        .FirstOrDefault(v => !string.IsNullOrWhiteSpace(v)),
                PrivacyUrl = cfg?.privacy_policy_url,
                TermsUrl = cfg?.terms_url
            };
        }
    }
}
