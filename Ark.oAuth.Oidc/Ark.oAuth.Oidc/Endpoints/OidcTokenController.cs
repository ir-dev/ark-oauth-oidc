using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Ark.oAuth.Oidc.Protocol;

namespace Ark.oAuth.Oidc.Endpoints
{
    /// <summary>
    /// The token endpoint (RFC 6749 §3.2). Handles the authorization_code, refresh_token,
    /// client_credentials and device_code grants, and token exchange (RFC 8693) for
    /// agent-to-agent calls made on behalf of a user.
    ///
    /// Every response — success or failure — follows the spec: a JSON body with `token_type`
    /// and `expires_in` on success, and an HTTP 400/401 with `error`/`error_description` on
    /// failure, rather than an HTTP 200 carrying an error string.
    /// </summary>
    [Route("{tenant_id}/oauth2")]
    [ApiController]
    [Microsoft.AspNetCore.Cors.EnableCors(ArkCors.PolicyName)]
    public class OidcTokenController : ArkOidcControllerBase
    {
        private readonly ArkClientAuthenticator _clientAuth;
        private readonly ArkGrantStore _grants;
        private readonly ArkTokenService _tokens;
        private readonly ArkClaimsService _claims;
        private readonly ArkAgentTokens _agents;
        private readonly DataAccess _da;

        /// <summary>The grants this server implements — mirrors grant_types_supported in discovery.</summary>
        private static readonly string[] SupportedGrantTypes =
        {
            "authorization_code", "refresh_token", "client_credentials",
            "urn:ietf:params:oauth:grant-type:device_code"
        };

        public OidcTokenController(ArkDataContext ctx, IConfiguration config, ArkClientAuthenticator clientAuth,
            ArkGrantStore grants, ArkTokenService tokens, ArkClaimsService claims, ArkAgentTokens agents, DataAccess da) : base(ctx, config)
        {
            _clientAuth = clientAuth;
            _grants = grants;
            _tokens = tokens;
            _claims = claims;
            _agents = agents;
            _da = da;
        }

        [HttpPost("token")]
        [Consumes("application/x-www-form-urlencoded")]
        public async Task<IActionResult> Token([FromRoute] string tenant_id)
        {
            NoStore();
            return await ProtectAsync(async () =>
            {
                var tenant = await ResolveTenantAsync(tenant_id);
                var ep = Endpoints(tenant.tenant_id);
                var form = Request.Form;

                var auth = await _clientAuth.AuthenticateAsync(Request, tenant.tenant_id, ep.Token);
                var client = auth.Client;

                var grantType = form["grant_type"].ToString();
                if (string.IsNullOrWhiteSpace(grantType))
                    throw OAuthException.InvalidRequest("grant_type is required.");

                // Whether the server implements the grant at all is decided before whether this
                // client is registered for it. RFC 6749 §5.2 reserves unauthorized_client for a
                // grant the client may not use; answering it for `password` — which this server
                // does not implement at any client — tells a caller to fix its registration when
                // the grant is simply gone in OAuth 2.1.
                // Token exchange exists for agent-to-agent calls only; with A2A off it is a
                // grant this server does not have, as it was before.
                var tokenExchange = Options.EnableA2A
                    && string.Equals(grantType, ArkAgentTokens.TokenExchangeGrant, StringComparison.OrdinalIgnoreCase);
                if (!tokenExchange && !SupportedGrantTypes.Contains(grantType, StringComparer.OrdinalIgnoreCase))
                    throw OAuthException.UnsupportedGrantType(grantType);

                if (!client.EffectiveGrantTypes.Contains(grantType, StringComparer.OrdinalIgnoreCase))
                    client = await FreshClientAsync(client); // a grant added through another instance
                if (!client.EffectiveGrantTypes.Contains(grantType, StringComparer.OrdinalIgnoreCase))
                {
                    var refusal = OAuthException.UnauthorizedClient($"this client is not registered for the '{grantType}' grant.");
                    // A client reaching for token exchange without the grant is an agent trying
                    // to act for a user it was never set up to act for: worth a line of its own.
                    if (tokenExchange)
                        AgentRefused(tenant, client, new AgentTokenTrace
                        {
                            Mode = AgentTokenTrace.OnBehalfOf,
                            RequestedAudience = string.Join(" ", form["audience"].Concat(form["resource"]))
                        }, refusal, auth);
                    throw refusal;
                }

                if (tokenExchange)
                    return await TokenExchangeGrantAsync(tenant, ep, client, form, auth);

                return grantType switch
                {
                    "authorization_code" => await AuthorizationCodeGrantAsync(tenant, ep, client, form),
                    "refresh_token" => await RefreshTokenGrantAsync(tenant, ep, client, form),
                    "client_credentials" => await ClientCredentialsGrantAsync(tenant, ep, client, form, auth),
                    "urn:ietf:params:oauth:grant-type:device_code" => await DeviceCodeGrantAsync(tenant, ep, client, form),
                    _ => throw OAuthException.UnsupportedGrantType(grantType)
                };
            }, _da, "token");
        }

        // -----------------------------------------------------------------

        private async Task<IActionResult> AuthorizationCodeGrantAsync(
            ArkTenant tenant, ArkOidcEndpoints ep, ArkClient client, IFormCollection form)
        {
            var code = form["code"].ToString();
            if (string.IsNullOrWhiteSpace(code))
                throw OAuthException.InvalidRequest("code is required.");

            var entry = await _grants.ConsumeAuthCodeAsync(
                code, client, form["redirect_uri"].ToString(), form["code_verifier"].ToString());

            var scopes = (entry.scope ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();
            var ctx = new TokenRequestContext
            {
                Tenant = tenant,
                Client = client,
                Issuer = ep.Issuer,
                Audience = tenant.audience,
                Subject = entry.subject,
                Scopes = scopes,
                SessionId = entry.session_id,
                Nonce = entry.nonce,
                AuthTime = entry.auth_time,
                AuthorizationCode = code
            };

            var (accessToken, expiresAt, _) = await _tokens.IssueAccessTokenAsync(ctx);

            string? refreshToken = null;
            if (scopes.Contains("offline_access", StringComparer.OrdinalIgnoreCase)
                && client.EffectiveGrantTypes.Contains("refresh_token", StringComparer.OrdinalIgnoreCase))
            {
                refreshToken = await _grants.CreateRefreshTokenAsync(
                    client, tenant.tenant_id, entry.subject, scopes, entry.session_id);
            }

            string? idToken = null;
            if (scopes.Contains("openid", StringComparer.OrdinalIgnoreCase))
                idToken = await _tokens.IssueIdTokenAsync(ctx, accessToken);

            _da.Log("token", $"{tenant.tenant_id}/oauth2/token", "authorization_code redeemed",
                $"client: {client.client_id}, sub: {entry.subject}");
            Webhooks.ArkWebhookEvents.Raise(HttpContext, tenant.tenant_id, Webhooks.ArkWebhookEvents.TokenIssued,
                new { grant_type = "authorization_code", client_id = client.client_id, subject = entry.subject, scopes, refresh_token_issued = refreshToken != null, id_token_issued = idToken != null }, entry.subject);

            return Ok(BuildResponse(accessToken, expiresAt, scopes, refreshToken, idToken));
        }

        private async Task<IActionResult> RefreshTokenGrantAsync(
            ArkTenant tenant, ArkOidcEndpoints ep, ArkClient client, IFormCollection form)
        {
            var presented = form["refresh_token"].ToString();
            if (string.IsNullOrWhiteSpace(presented))
                throw OAuthException.InvalidRequest("refresh_token is required.");

            var entry = await _grants.RedeemRefreshTokenAsync(presented, client);
            var scopes = (entry.scope ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();

            // A refresh may narrow scope but never widen it (RFC 6749 §6).
            var requested = form["scope"].ToString();
            if (!string.IsNullOrWhiteSpace(requested))
            {
                var wanted = requested.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();
                var widened = wanted.Where(s => !scopes.Contains(s, StringComparer.OrdinalIgnoreCase)).ToList();
                if (widened.Count > 0)
                    throw OAuthException.InvalidScope($"scope cannot be widened on refresh: {string.Join(", ", widened)}.");
                scopes = wanted;
            }

            // auth_time is when the user authenticated, not when this refresh token was minted:
            // under rotation created_at moves forward on every refresh, and an ID token claiming
            // a fresh sign-in would satisfy a client's max_age check for a session days old.
            var authTime = entry.created_at;

            // the session must still be alive, so ending a session really does end access
            if (!string.IsNullOrEmpty(entry.session_id))
            {
                var session = await _grants.GetSessionAsync(entry.session_id);
                if (session == null)
                {
                    await _grants.RevokeFamilyAsync(entry.family_id);
                    throw OAuthException.InvalidGrant("the session behind this refresh token has ended.");
                }
                authTime = session.auth_time;
            }

            // ...and so must the account. Deactivating a user revokes their refresh tokens, so
            // this normally never fires; it is what makes the switch hold when the flag is set
            // some other way, and it costs one indexed lookup on a grant that runs hourly at most.
            // (A deactivated *client* never reaches here — ArkClientAuthenticator refuses it.)
            var holder = await _claims.FindUserAsync(entry.subject);
            if (holder != null && !holder.is_active)
            {
                await _grants.RevokeFamilyAsync(entry.family_id);
                throw OAuthException.InvalidGrant("the account this refresh token belongs to has been deactivated.");
            }

            // ...and so must the user's access to this client. The authorization and device
            // endpoints refuse a user with no access mapping, but removing the mapping revoked
            // nothing: the refresh token kept minting access tokens (with no ark_claims) until the
            // session ended, so taking someone off an application did not take effect for hours.
            // Every refresh token is issued to a user who held the mapping at the time, so this
            // only ever refuses one whose access has since been withdrawn.
            if (!await _claims.HasClientAccessAsync(entry.subject, tenant.tenant_id, client))
            {
                await _grants.RevokeFamilyAsync(entry.family_id);
                throw OAuthException.InvalidGrant("the account this refresh token belongs to no longer has access to this client.");
            }

            var ctx = new TokenRequestContext
            {
                Tenant = tenant,
                Client = client,
                Issuer = ep.Issuer,
                Audience = tenant.audience,
                Subject = entry.subject,
                Scopes = scopes,
                SessionId = entry.session_id,
                AuthTime = authTime
            };

            var (accessToken, expiresAt, _) = await _tokens.IssueAccessTokenAsync(ctx);

            string? rotated = null;
            if (client.refresh_token_rotation)
            {
                rotated = await _grants.CreateRefreshTokenAsync(
                    client, tenant.tenant_id, entry.subject, scopes, entry.session_id, entry.family_id);
            }

            string? idToken = null;
            if (scopes.Contains("openid", StringComparer.OrdinalIgnoreCase))
                idToken = await _tokens.IssueIdTokenAsync(ctx, accessToken);

            return Ok(BuildResponse(accessToken, expiresAt, scopes, rotated, idToken));
        }

        private async Task<IActionResult> ClientCredentialsGrantAsync(
            ArkTenant tenant, ArkOidcEndpoints ep, ArkClient client, IFormCollection form, ClientAuthResult auth)
        {
            // RFC 6749 §4.4: there is no resource owner, so a public client has nothing to prove.
            if (auth.Method == "none")
                throw OAuthException.InvalidClient("the client_credentials grant requires client authentication.");

            var scopes = await _claims.ResolveScopesAsync(form["scope"].ToString(), client);
            // no user is present, so identity scopes are meaningless here
            scopes = scopes.Where(s => !string.Equals(s, "openid", StringComparison.OrdinalIgnoreCase)
                                    && !string.Equals(s, "offline_access", StringComparison.OrdinalIgnoreCase)).ToList();

            // Agent-to-agent: the request names the agent it is going to call, and the token is
            // good there and nowhere else. Naming the tenant's own audience is not that request.
            string? audience = null;
            if (Options.EnableA2A)
            {
                try { audience = ArkAgentTokens.RequestedAudience(form); }
                catch (OAuthException ex)
                {
                    AgentRefused(tenant, client, new AgentTokenTrace
                    {
                        RequestedAudience = string.Join(" ", form["audience"].Concat(form["resource"])), RequestedScopes = scopes
                    }, ex, auth);
                    throw;
                }
            }
            if (audience != null && !ArkAgentTokens.IsTenantAudience(audience, tenant, ep.Issuer))
            {
                var trace = new AgentTokenTrace();
                AgentTokenResult issued;
                try { issued = await _agents.AsItselfAsync(tenant, ep.Issuer, client, audience, scopes, trace); }
                catch (OAuthException ex)
                {
                    AgentRefused(tenant, client, trace, ex, auth);
                    throw;
                }
                _da.Log("token", $"{tenant.tenant_id}/oauth2/token", "a2a token issued",
                    ArkAgentAudit.Details(client, trace, issued), "trace",
                    ArkAgentAudit.Issued(tenant, client, issued, trace, auth.Method));
                Webhooks.ArkWebhookEvents.Raise(HttpContext, tenant.tenant_id, Webhooks.ArkWebhookEvents.TokenIssued,
                    new { grant_type = "client_credentials", client_id = client.client_id, subject = issued.Subject, scopes, audience = issued.Audience }, client.client_id);
                return Ok(BuildResponse(issued.AccessToken, issued.ExpiresAt, scopes, null, null));
            }

            var ctx = new TokenRequestContext
            {
                Tenant = tenant,
                Client = client,
                Issuer = ep.Issuer,
                Audience = tenant.audience,
                Subject = client.client_id, // the client acts as itself
                Scopes = scopes
            };

            var (accessToken, expiresAt, _) = await _tokens.IssueAccessTokenAsync(ctx);
            _da.Log("token", $"{tenant.tenant_id}/oauth2/token", "client_credentials issued", $"client: {client.client_id}");
            Webhooks.ArkWebhookEvents.Raise(HttpContext, tenant.tenant_id, Webhooks.ArkWebhookEvents.TokenIssued,
                new { grant_type = "client_credentials", client_id = client.client_id, subject = client.client_id, scopes }, client.client_id);

            // §4.4.3: a refresh token SHOULD NOT be issued — the client can just ask again.
            return Ok(BuildResponse(accessToken, expiresAt, scopes, null, null));
        }

        /// <summary>
        /// Token exchange (RFC 8693), in the one form this server offers: an agent that holds a
        /// user's access token asks for one addressed to the next agent. See <see cref="ArkAgentTokens"/>.
        /// </summary>
        private async Task<IActionResult> TokenExchangeGrantAsync(
            ArkTenant tenant, ArkOidcEndpoints ep, ArkClient client, IFormCollection form, ClientAuthResult auth)
        {
            var trace = new AgentTokenTrace { Mode = AgentTokenTrace.OnBehalfOf };
            AgentTokenResult issued;
            try
            {
                // The actor is the authenticated client, so it has to be one that can authenticate.
                if (auth.Method == "none")
                    throw OAuthException.InvalidClient("token exchange requires client authentication.");

                issued = await _agents.OnBehalfOfAsync(tenant, ep.Issuer, client, form, trace);
            }
            catch (OAuthException ex)
            {
                AgentRefused(tenant, client, trace, ex, auth);
                throw;
            }
            _da.Log("token", $"{tenant.tenant_id}/oauth2/token", "a2a token issued on behalf of a user",
                ArkAgentAudit.Details(client, trace, issued), "trace",
                ArkAgentAudit.Issued(tenant, client, issued, trace, auth.Method));
            Webhooks.ArkWebhookEvents.Raise(HttpContext, tenant.tenant_id, Webhooks.ArkWebhookEvents.TokenIssued,
                new { grant_type = ArkAgentTokens.TokenExchangeGrant, client_id = client.client_id, subject = issued.Subject, scopes = issued.Scopes, audience = issued.Audience, actors = issued.Actors }, issued.Subject);

            var body = BuildResponse(issued.AccessToken, issued.ExpiresAt, issued.Scopes, null, null);
            body["issued_token_type"] = ArkAgentTokens.AccessTokenType; // RFC 8693 §2.2.1
            return Ok(body);
        }

        /// <summary>
        /// Records an agent-token request that was turned down. Until now a refusal left no
        /// trace at all: the caller got its error and the server forgot. An agent asking for
        /// access it was not given — to an agent that has not listed it, for a user who has no
        /// access there, past a session that has ended — is the half of the audit trail that
        /// matters most, so it is written here before the error goes back.
        /// </summary>
        private void AgentRefused(ArkTenant tenant, ArkClient client, AgentTokenTrace trace, OAuthException ex, ClientAuthResult auth)
        {
            try
            {
                _da.Log("a2a_refused", $"{tenant.tenant_id}/oauth2/token", $"a2a token refused: {ex.Error}",
                    ArkAgentAudit.Details(client, trace, refused: ex), "warn",
                    ArkAgentAudit.Refused(tenant, client, trace, ex, auth.Method));
            }
            catch
            {
                // The refusal itself is what the caller must get; the record of it is best effort.
            }
        }

        private async Task<IActionResult> DeviceCodeGrantAsync(
            ArkTenant tenant, ArkOidcEndpoints ep, ArkClient client, IFormCollection form)
        {
            if (!Options.EnableDeviceFlow)
                throw OAuthException.UnsupportedGrantType("urn:ietf:params:oauth:grant-type:device_code");

            var deviceCode = form["device_code"].ToString();
            if (string.IsNullOrWhiteSpace(deviceCode))
                throw OAuthException.InvalidRequest("device_code is required.");

            var entry = await _grants.PollDeviceCodeAsync(deviceCode, client);
            var scopes = (entry.scope ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();

            // The approving session's sign-in time; left unset it defaulted to now.
            var session = await _grants.GetSessionAsync(entry.session_id);

            var ctx = new TokenRequestContext
            {
                Tenant = tenant,
                Client = client,
                Issuer = ep.Issuer,
                Audience = tenant.audience,
                Subject = entry.subject!,
                Scopes = scopes,
                SessionId = entry.session_id,
                AuthTime = session?.auth_time ?? entry.created_at
            };

            var (accessToken, expiresAt, _) = await _tokens.IssueAccessTokenAsync(ctx);

            string? refreshToken = null;
            if (scopes.Contains("offline_access", StringComparer.OrdinalIgnoreCase)
                && client.EffectiveGrantTypes.Contains("refresh_token", StringComparer.OrdinalIgnoreCase))
            {
                refreshToken = await _grants.CreateRefreshTokenAsync(
                    client, tenant.tenant_id, entry.subject!, scopes, entry.session_id);
            }

            string? idToken = null;
            if (scopes.Contains("openid", StringComparer.OrdinalIgnoreCase))
                idToken = await _tokens.IssueIdTokenAsync(ctx, accessToken);

            return Ok(BuildResponse(accessToken, expiresAt, scopes, refreshToken, idToken));
        }

        // -----------------------------------------------------------------

        private static Dictionary<string, object> BuildResponse(
            string accessToken, DateTime expiresAt, List<string> scopes, string? refreshToken, string? idToken)
        {
            var body = new Dictionary<string, object>
            {
                ["access_token"] = accessToken,
                ["token_type"] = "Bearer",
                ["expires_in"] = Math.Max(0, (int)(expiresAt - DateTime.UtcNow).TotalSeconds)
            };
            if (!string.IsNullOrEmpty(refreshToken)) body["refresh_token"] = refreshToken!;
            if (!string.IsNullOrEmpty(idToken)) body["id_token"] = idToken!;
            if (scopes.Count > 0) body["scope"] = string.Join(" ", scopes);
            return body;
        }
    }
}
