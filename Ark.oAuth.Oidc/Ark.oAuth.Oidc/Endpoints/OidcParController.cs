using Microsoft.AspNetCore.Mvc;
using Ark.oAuth.Oidc.Protocol;

namespace Ark.oAuth.Oidc.Endpoints
{
    /// <summary>
    /// Pushed authorization requests (RFC 9126).
    ///
    /// The client submits its authorization parameters over an authenticated back channel and
    /// receives a one-time request_uri to send the browser to. The parameters therefore never
    /// travel through the user agent, where they could be logged, tampered with or replayed.
    /// </summary>
    [Route("{tenant_id}/oauth2")]
    [ApiController]
    public class OidcParController : ArkOidcControllerBase
    {
        private readonly ArkClientAuthenticator _clientAuth;
        private readonly ArkGrantStore _grants;
        private readonly DataAccess _da;

        public OidcParController(ArkDataContext ctx, IConfiguration config,
            ArkClientAuthenticator clientAuth, ArkGrantStore grants, DataAccess da) : base(ctx, config)
        {
            _clientAuth = clientAuth;
            _grants = grants;
            _da = da;
        }

        [HttpPost("par")]
        [Consumes("application/x-www-form-urlencoded")]
        public async Task<IActionResult> PushAuthorizationRequest([FromRoute] string tenant_id)
        {
            NoStore();
            return await ProtectAsync(async () =>
            {
                if (!Options.EnablePushedAuthorizationRequests)
                    throw OAuthException.InvalidRequest("pushed authorization requests are not enabled on this server.");

                var tenant = await ResolveTenantAsync(tenant_id);
                var ep = Endpoints(tenant.tenant_id);
                var auth = await _clientAuth.AuthenticateAsync(Request, tenant.tenant_id, ep.PushedAuthorizationRequest);
                var client = auth.Client;

                var parameters = new Dictionary<string, string>();
                foreach (var kv in Request.Form)
                {
                    // §2.1: a PAR request must not itself carry a request_uri
                    if (kv.Key == "request_uri")
                        throw OAuthException.InvalidRequest("request_uri must not be present in a pushed authorization request.");
                    // client credentials are consumed by authentication and must not be replayed at /authorize
                    if (kv.Key is "client_secret" or "client_assertion" or "client_assertion_type") continue;
                    if (kv.Value.Count > 0 && kv.Value[0] != null) parameters[kv.Key] = kv.Value[0]!;
                }

                // §2.1: client_id must be present and must be the authenticated client
                var claimed = parameters.GetValueOrDefault("client_id");
                if (!string.IsNullOrEmpty(claimed) &&
                    !string.Equals(claimed, client.client_id, StringComparison.OrdinalIgnoreCase))
                    throw OAuthException.InvalidRequest("client_id does not match the authenticated client.");
                parameters["client_id"] = client.client_id;

                // Validate the redirect_uri now rather than at /authorize, so a bad value fails
                // on the back channel where the client can actually read the error.
                var redirectUri = parameters.GetValueOrDefault("redirect_uri");
                if (!string.IsNullOrEmpty(redirectUri) &&
                    !RedirectUriValidator.Matches(client.EffectiveRedirectUris, redirectUri!))
                    throw OAuthException.InvalidRequest("redirect_uri does not match a registered value for this client.");

                var (requestUri, expiresAt) = await _grants.CreateParRequestAsync(
                    client, tenant.tenant_id, parameters, Options.ParLifetimeSeconds);

                _da.Log("par", tenant.tenant_id, "pushed authorization request stored", $"client: {client.client_id}");

                // §2.2: the successful response is 201 Created
                return StatusCode(201, new Dictionary<string, object>
                {
                    ["request_uri"] = requestUri,
                    ["expires_in"] = Math.Max(0, (int)(expiresAt - DateTime.UtcNow).TotalSeconds)
                });
            }, _da, "par");
        }
    }
}
