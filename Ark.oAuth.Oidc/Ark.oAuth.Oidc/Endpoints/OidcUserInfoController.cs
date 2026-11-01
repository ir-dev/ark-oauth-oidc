using Microsoft.AspNetCore.Mvc;
using Ark.oAuth.Oidc.Protocol;

namespace Ark.oAuth.Oidc.Endpoints
{
    /// <summary>
    /// The UserInfo endpoint (OIDC Core §5.3). Returns exactly the claims the presented access
    /// token was granted scope for — never the full user record.
    /// </summary>
    [Route("{tenant_id}/oauth2")]
    [ApiController]
    [Microsoft.AspNetCore.Cors.EnableCors(ArkCors.PolicyName)]
    public class OidcUserInfoController : ArkOidcControllerBase
    {
        private readonly ArkTokenService _tokens;
        private readonly ArkClaimsService _claims;

        public OidcUserInfoController(ArkDataContext ctx, IConfiguration config,
            ArkTokenService tokens, ArkClaimsService claims) : base(ctx, config)
        {
            _tokens = tokens;
            _claims = claims;
        }

        [HttpGet("userinfo")]
        [HttpPost("userinfo")]
        public async Task<IActionResult> UserInfo([FromRoute] string tenant_id)
        {
            NoStore();
            var token = BearerToken();
            if (string.IsNullOrEmpty(token))
                return BearerChallenge(401, OAuthErrorCodes.InvalidToken, "an access token is required.");

            ArkTenant tenant;
            try
            {
                tenant = await ResolveTenantAsync(tenant_id);
            }
            catch (OAuthException ex)
            {
                return OAuthError(ex);
            }

            var ep = Endpoints(tenant.tenant_id);
            var result = await _tokens.ValidateAsync(token!, tenant, ep.Issuer);
            if (!result.IsValid)
                return BearerChallenge(401, OAuthErrorCodes.InvalidToken, "the access token is expired, malformed or invalid.");

            var claims = result.ClaimsIdentity;
            var subject = claims?.FindFirst("sub")?.Value;
            if (string.IsNullOrEmpty(subject))
                return BearerChallenge(401, OAuthErrorCodes.InvalidToken, "the access token has no subject.");

            var scopes = (claims?.FindFirst("scope")?.Value ?? "")
                .Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();

            // OIDC Core §5.4: the openid scope is what authorises the UserInfo endpoint at all.
            if (!scopes.Contains("openid", StringComparer.OrdinalIgnoreCase))
                return BearerChallenge(403, OAuthErrorCodes.InsufficientScope, "the 'openid' scope is required.");

            var body = new Dictionary<string, object> { ["sub"] = subject! };
            foreach (var kv in await _claims.GetIdentityClaimsAsync(subject!, scopes))
                body[kv.Key] = kv.Value;

            return Ok(body);
        }

        /// <summary>An RFC 6750 §3 bearer-token challenge.</summary>
        private IActionResult BearerChallenge(int status, string error, string description)
        {
            Response.Headers["WWW-Authenticate"] =
                $"Bearer realm=\"ark\", error=\"{error}\", error_description=\"{description}\"";
            return StatusCode(status, new { error, error_description = description });
        }
    }
}
