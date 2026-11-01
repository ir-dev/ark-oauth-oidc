using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Ark.oAuth.Oidc.Protocol;

namespace Ark.oAuth.Oidc.Endpoints
{
    /// <summary>
    /// The token endpoint (RFC 6749 §3.2). Handles the authorization_code, refresh_token,
    /// client_credentials and device_code grants.
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
        private readonly DataAccess _da;

        /// <summary>The grants this server implements — mirrors grant_types_supported in discovery.</summary>
        private static readonly string[] SupportedGrantTypes =
        {
            "authorization_code", "refresh_token", "client_credentials",
            "urn:ietf:params:oauth:grant-type:device_code"
        };

        public OidcTokenController(ArkDataContext ctx, IConfiguration config, ArkClientAuthenticator clientAuth,
            ArkGrantStore grants, ArkTokenService tokens, ArkClaimsService claims, DataAccess da) : base(ctx, config)
        {
            _clientAuth = clientAuth;
            _grants = grants;
            _tokens = tokens;
            _claims = claims;
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
                if (!SupportedGrantTypes.Contains(grantType, StringComparer.OrdinalIgnoreCase))
                    throw OAuthException.UnsupportedGrantType(grantType);

                if (!client.EffectiveGrantTypes.Contains(grantType, StringComparer.OrdinalIgnoreCase))
                    throw OAuthException.UnauthorizedClient($"this client is not registered for the '{grantType}' grant.");

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

            // the session must still be alive, so ending a session really does end access
            if (!string.IsNullOrEmpty(entry.session_id))
            {
                var session = await _grants.GetSessionAsync(entry.session_id);
                if (session == null)
                {
                    await _grants.RevokeFamilyAsync(entry.family_id);
                    throw OAuthException.InvalidGrant("the session behind this refresh token has ended.");
                }
            }

            // ...and so must the account. Deactivating a user revokes their refresh tokens, so
            // this normally never fires; it is what makes the switch hold when the flag is set
            // some other way, and it costs one indexed lookup on a grant that runs hourly at most.
            // (A deactivated *client* never reaches here — ArkClientAuthenticator refuses it.)
            var holder = await Ctx.users.AsNoTracking()
                .FirstOrDefaultAsync(u => u.email.ToLower() == entry.subject.ToLower());
            if (holder != null && !holder.is_active)
            {
                await _grants.RevokeFamilyAsync(entry.family_id);
                throw OAuthException.InvalidGrant("the account this refresh token belongs to has been deactivated.");
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
                AuthTime = entry.created_at
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

            // §4.4.3: a refresh token SHOULD NOT be issued — the client can just ask again.
            return Ok(BuildResponse(accessToken, expiresAt, scopes, null, null));
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

            var ctx = new TokenRequestContext
            {
                Tenant = tenant,
                Client = client,
                Issuer = ep.Issuer,
                Audience = tenant.audience,
                Subject = entry.subject!,
                Scopes = scopes,
                SessionId = entry.session_id
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
