using Microsoft.AspNetCore.Mvc;
using Ark.oAuth.Oidc.Protocol;

namespace Ark.oAuth.Oidc.Endpoints
{
    /// <summary>
    /// Discovery and JWKS.
    ///
    /// The document is published at <c>{issuer}/.well-known/openid-configuration</c> under both the
    /// OpenID Connect Discovery name and the RFC 8414 <c>oauth-authorization-server</c> name, and
    /// carries no client-specific data — earlier versions required a client_id in the path and
    /// returned every tenant's configuration, which meant discovery leaked the whole deployment.
    /// </summary>
    [ApiController]
    [Microsoft.AspNetCore.Cors.EnableCors(ArkCors.PolicyName)]
    public class OidcDiscoveryController : ArkOidcControllerBase
    {
        private readonly ArkKeyService _keys;
        private readonly ArkClaimsService _claims;

        public OidcDiscoveryController(ArkDataContext ctx, IConfiguration config, ArkKeyService keys, ArkClaimsService claims)
            : base(ctx, config)
        {
            _keys = keys;
            _claims = claims;
        }

        [HttpGet("{tenant_id}/.well-known/openid-configuration")]
        [HttpGet("{tenant_id}/.well-known/oauth-authorization-server")]
        public async Task<IActionResult> OpenIdConfiguration([FromRoute] string tenant_id)
        {
            return await ProtectAsync(async () =>
            {
                var tenant = await ResolveTenantAsync(tenant_id);
                var ep = Endpoints(tenant.tenant_id);
                var opt = Options;

                var grantTypes = new List<string> { "authorization_code", "refresh_token", "client_credentials" };
                if (opt.EnableDeviceFlow) grantTypes.Add("urn:ietf:params:oauth:grant-type:device_code");

                var doc = new Dictionary<string, object?>
                {
                    ["issuer"] = ep.Issuer,
                    ["authorization_endpoint"] = ep.Authorization,
                    ["token_endpoint"] = ep.Token,
                    ["userinfo_endpoint"] = ep.UserInfo,
                    ["jwks_uri"] = ep.Jwks,
                    ["introspection_endpoint"] = ep.Introspection,
                    ["revocation_endpoint"] = ep.Revocation,
                    ["end_session_endpoint"] = ep.EndSession,

                    ["scopes_supported"] = await _claims.GetSupportedScopesAsync(),
                    ["claims_supported"] = await _claims.GetSupportedClaimsAsync(),
                    ["response_types_supported"] = new[] { "code" },
                    ["response_modes_supported"] = new[] { "query", "fragment", "form_post" },
                    ["grant_types_supported"] = grantTypes,
                    ["subject_types_supported"] = new[] { "public" },
                    ["id_token_signing_alg_values_supported"] = new[] { "RS256" },
                    ["userinfo_signing_alg_values_supported"] = new[] { "none" },
                    ["token_endpoint_auth_methods_supported"] = new[]
                    {
                        "client_secret_basic", "client_secret_post", "private_key_jwt", "none"
                    },
                    ["token_endpoint_auth_signing_alg_values_supported"] = new[] { "RS256" },
                    ["introspection_endpoint_auth_methods_supported"] = new[]
                    {
                        "client_secret_basic", "client_secret_post", "private_key_jwt"
                    },
                    ["revocation_endpoint_auth_methods_supported"] = new[]
                    {
                        "client_secret_basic", "client_secret_post", "private_key_jwt"
                    },

                    // PKCE is mandatory for public clients; S256 only (OAuth 2.1 drops 'plain')
                    ["code_challenge_methods_supported"] = new[] { "S256" },

                    ["claims_parameter_supported"] = false,
                    ["request_parameter_supported"] = false,
                    ["request_uri_parameter_supported"] = opt.EnablePushedAuthorizationRequests,
                    ["require_request_uri_registration"] = false,
                    ["authorization_response_iss_parameter_supported"] = true, // RFC 9207
                    // Back-channel logout is implemented: a client that registers a
                    // backchannel_logout_uri is POSTed a logout token when a session it took part
                    // in ends, and that token always carries sid.
                    ["backchannel_logout_supported"] = true,
                    ["backchannel_logout_session_supported"] = true,
                    // Front-channel logout is not. These two advertised it anyway, which is worse
                    // than saying nothing: a client that reads the document configures a logout
                    // flow that this server has no endpoint for and no way to register.
                    ["frontchannel_logout_supported"] = false,
                    ["frontchannel_logout_session_supported"] = false,

                    ["service_documentation"] = $"{ep.BaseUrl}/oauth/docs",
                    ["ui_locales_supported"] = new[] { "en" },
                    ["op_policy_uri"] = ServerConfig.EmailConfig?.privacy_policy_url,
                    ["op_tos_uri"] = ServerConfig.EmailConfig?.terms_url
                };

                if (opt.EnableDeviceFlow)
                    doc["device_authorization_endpoint"] = ep.DeviceAuthorization;

                if (opt.EnablePushedAuthorizationRequests)
                {
                    doc["pushed_authorization_request_endpoint"] = ep.PushedAuthorizationRequest;
                    doc["require_pushed_authorization_requests"] = opt.RequirePushedAuthorizationRequests;
                }

                if (opt.EnableDynamicRegistration)
                    doc["registration_endpoint"] = ep.Registration;

                // discovery is public and stable; let clients cache it
                Response.Headers["Cache-Control"] = "public, max-age=300";
                return Ok(doc.Where(kv => kv.Value != null).ToDictionary(kv => kv.Key, kv => kv.Value!));
            });
        }

        [HttpGet("{tenant_id}/.well-known/jwks.json")]
        [HttpGet("{tenant_id}/oauth2/jwks")]
        public async Task<IActionResult> Jwks([FromRoute] string tenant_id)
        {
            return await ProtectAsync(async () =>
            {
                var tenant = await ResolveTenantAsync(tenant_id);
                var keys = await _keys.GetPublishedKeysAsync(tenant.tenant_id);
                Response.Headers["Cache-Control"] = "public, max-age=300";
                return Ok(_keys.BuildJwks(keys));
            });
        }
    }
}
