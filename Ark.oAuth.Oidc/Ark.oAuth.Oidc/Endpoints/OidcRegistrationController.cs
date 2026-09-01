using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Ark.oAuth.Oidc.Protocol;

namespace Ark.oAuth.Oidc.Endpoints
{
    /// <summary>
    /// Dynamic client registration (RFC 7591) and client configuration management (RFC 7592).
    ///
    /// Disabled by default: an open registration endpoint lets anyone create clients on the
    /// server. Enable it with <c>ark_oauth_server:Oidc:EnableDynamicRegistration</c>, and keep
    /// <c>RequireRegistrationAccessToken</c> on unless registration is deliberately public.
    /// </summary>
    [Route("{tenant_id}/oauth2")]
    [ApiController]
    public class OidcRegistrationController : ArkOidcControllerBase
    {
        private readonly ArkTokenService _tokens;
        private readonly DataAccess _da;

        private static readonly string[] SupportedAuthMethods =
            { "client_secret_basic", "client_secret_post", "private_key_jwt", "none" };

        private static readonly string[] SupportedGrantTypes =
            { "authorization_code", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:device_code" };

        public OidcRegistrationController(ArkDataContext ctx, IConfiguration config, ArkTokenService tokens, DataAccess da)
            : base(ctx, config)
        {
            _tokens = tokens;
            _da = da;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromRoute] string tenant_id, [FromBody] JsonObject metadata)
        {
            NoStore();
            return await ProtectAsync(async () =>
            {
                if (!Options.EnableDynamicRegistration)
                    throw new OAuthException(OAuthErrorCodes.RegistrationNotSupported,
                        "dynamic client registration is not enabled on this server.", 403);

                var tenant = await ResolveTenantAsync(tenant_id);
                var ep = Endpoints(tenant.tenant_id);

                if (Options.RequireRegistrationAccessToken)
                    await RequireInitialAccessTokenAsync(tenant, ep);

                var client = new ArkClient
                {
                    tenant_id = tenant.tenant_id,
                    client_id = $"c_{ArkCrypto.RandomToken(12)}",
                    at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss"),
                    expire_mins = 480
                };

                ApplyMetadata(client, metadata, ep);
                await EnforceUniqueClientNameAsync(client);

                // Public clients get no secret; everything else does.
                string? secret = null;
                if (!string.Equals(client.token_endpoint_auth_method, "none", StringComparison.OrdinalIgnoreCase)
                    && !string.Equals(client.token_endpoint_auth_method, "private_key_jwt", StringComparison.OrdinalIgnoreCase))
                {
                    secret = ArkCrypto.RandomToken(32);
                    client.client_secret_hash = ArkCrypto.HashSecret(secret);
                }

                var registrationToken = ArkCrypto.RandomToken(32);
                client.registration_access_token_hash = ArkCrypto.Sha256Base64Url(registrationToken);

                Ctx.clients.Add(client);
                await Ctx.SaveChangesAsync();

                _da.Log("client_register", tenant.tenant_id, "client registered dynamically", $"client: {client.client_id}");

                var body = BuildClientResponse(client, ep);
                if (secret != null)
                {
                    body["client_secret"] = secret;
                    body["client_secret_expires_at"] = client.client_secret_expires_at == null
                        ? 0 : ArkTokenService.ToUnix(client.client_secret_expires_at.Value);
                }
                body["registration_access_token"] = registrationToken;
                body["registration_client_uri"] = $"{ep.Registration}/{client.client_id}";

                return StatusCode(201, body);
            }, _da, "register");
        }

        /// <summary>Read the current registration (RFC 7592 §2.1).</summary>
        [HttpGet("register/{client_id}")]
        public async Task<IActionResult> Read([FromRoute] string tenant_id, [FromRoute] string client_id)
        {
            NoStore();
            return await ProtectAsync(async () =>
            {
                var tenant = await ResolveTenantAsync(tenant_id);
                var ep = Endpoints(tenant.tenant_id);
                var client = await AuthorizeRegistrationAccessAsync(tenant, client_id);
                return Ok(BuildClientResponse(client, ep));
            }, _da, "register_read");
        }

        /// <summary>Delete the registration (RFC 7592 §2.3).</summary>
        [HttpDelete("register/{client_id}")]
        public async Task<IActionResult> Delete([FromRoute] string tenant_id, [FromRoute] string client_id)
        {
            NoStore();
            return await ProtectAsync(async () =>
            {
                var tenant = await ResolveTenantAsync(tenant_id);
                var client = await AuthorizeRegistrationAccessAsync(tenant, client_id);
                Ctx.clients.Remove(client);
                await Ctx.SaveChangesAsync();
                _da.Log("client_deregister", tenant.tenant_id, "client registration deleted", $"client: {client_id}");
                return NoContent();
            }, _da, "register_delete");
        }

        // -----------------------------------------------------------------

        private async Task RequireInitialAccessTokenAsync(ArkTenant tenant, ArkOidcEndpoints ep)
        {
            var token = BearerToken();
            if (string.IsNullOrEmpty(token))
                throw OAuthException.InvalidClient("an initial access token is required to register a client.");

            var result = await _tokens.ValidateAsync(token!, tenant, ep.Issuer);
            if (!result.IsValid)
                throw OAuthException.InvalidClient("the initial access token is invalid.");

            // the token must carry authority to register
            var scopes = (result.ClaimsIdentity?.FindFirst("scope")?.Value ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var arkClaims = result.ClaimsIdentity?.FindAll("ark_claims").Select(c => c.Value) ?? Enumerable.Empty<string>();
            if (!scopes.Contains("client.register") && !arkClaims.Contains("service_role"))
                throw new OAuthException(OAuthErrorCodes.InsufficientScope,
                    "the initial access token needs the 'client.register' scope.", 403);
        }

        private async Task<ArkClient> AuthorizeRegistrationAccessAsync(ArkTenant tenant, string clientId)
        {
            var token = BearerToken();
            if (string.IsNullOrEmpty(token))
                throw OAuthException.InvalidClient("a registration access token is required.");

            var client = await Ctx.clients.FirstOrDefaultAsync(c =>
                c.tenant_id.ToLower() == tenant.tenant_id.ToLower() && c.client_id == clientId)
                ?? throw OAuthException.InvalidClient("unknown client.");

            var presented = ArkCrypto.Sha256Base64Url(token!);
            if (!ArkCrypto.FixedTimeEquals(presented, client.registration_access_token_hash))
                throw OAuthException.InvalidClient("the registration access token is not valid for this client.");

            return client;
        }

        private void ApplyMetadata(ArkClient client, JsonObject metadata, ArkOidcEndpoints ep)
        {
            List<string> Strings(string name)
            {
                var node = metadata[name];
                if (node is JsonArray arr)
                    return arr.Where(x => x != null).Select(x => x!.GetValue<string>()).ToList();
                if (node is JsonValue v && v.TryGetValue<string>(out var single))
                    return new List<string> { single };
                return new List<string>();
            }
            string? Str(string name) => metadata[name] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;
            bool? Bool(string name) => metadata[name] is JsonValue v && v.TryGetValue<bool>(out var b) ? b : null;

            var redirectUris = Strings("redirect_uris");
            var grantTypes = Strings("grant_types");
            if (grantTypes.Count == 0) grantTypes = new List<string> { "authorization_code" };

            foreach (var g in grantTypes)
                if (!SupportedGrantTypes.Contains(g))
                    throw new OAuthException(OAuthErrorCodes.InvalidClientMetadata, $"unsupported grant_type '{g}'.");

            // redirect_uris is mandatory for any grant that comes back through the browser
            if (grantTypes.Contains("authorization_code") && redirectUris.Count == 0)
                throw new OAuthException(OAuthErrorCodes.InvalidRedirectUri,
                    "redirect_uris is required for the authorization_code grant.");

            foreach (var uri in redirectUris)
            {
                if (!Uri.TryCreate(uri, UriKind.Absolute, out var parsed))
                    throw new OAuthException(OAuthErrorCodes.InvalidRedirectUri, $"'{uri}' is not an absolute URI.");
                if (!string.IsNullOrEmpty(parsed.Fragment))
                    throw new OAuthException(OAuthErrorCodes.InvalidRedirectUri, $"'{uri}' must not contain a fragment.");
                // http is only acceptable for loopback native clients (RFC 8252 §7.3)
                var loopback = parsed.IsLoopback;
                if (parsed.Scheme == "http" && !loopback)
                    throw new OAuthException(OAuthErrorCodes.InvalidRedirectUri,
                        $"'{uri}' must use https (http is only permitted for loopback redirects).");
            }

            var authMethod = Str("token_endpoint_auth_method") ?? "client_secret_basic";
            if (!SupportedAuthMethods.Contains(authMethod))
                throw new OAuthException(OAuthErrorCodes.InvalidClientMetadata,
                    $"unsupported token_endpoint_auth_method '{authMethod}'.");
            if (authMethod == "private_key_jwt" && string.IsNullOrEmpty(Str("jwks_uri")))
                throw new OAuthException(OAuthErrorCodes.InvalidClientMetadata,
                    "jwks_uri is required when token_endpoint_auth_method is private_key_jwt.");

            var scopeValue = Str("scope");
            var scopes = string.IsNullOrWhiteSpace(scopeValue)
                ? new List<string> { "openid", "profile", "email" }
                : scopeValue!.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();

            client.client_name = Str("client_name") ?? client.client_id;
            client.name = client.client_name;
            client.display = client.client_name;
            client.client_logo = Str("logo_uri");
            client.client_uri = Str("client_uri");
            client.policy_uri = Str("policy_uri");
            client.tos_uri = Str("tos_uri");
            client.jwks_uri = Str("jwks_uri");
            client.application_type = Str("application_type") ?? "web";
            client.token_endpoint_auth_method = authMethod;
            client.redirect_uris = redirectUris;
            client.post_logout_redirect_uris = Strings("post_logout_redirect_uris");
            client.grant_types = grantTypes;
            client.response_types = Strings("response_types").Count > 0 ? Strings("response_types") : new List<string> { "code" };
            client.scopes = scopes;
            client.contacts = Strings("contacts");
            client.require_pkce = true;
            client.is_active = true;

            // OIDC Back-Channel Logout 1.0 §3.1 registration metadata. A URI here is what puts the
            // client on the notification list when a session it took part in ends; without one it
            // is simply never told, so this is optional and defaults to off.
            var backchannel = Str("backchannel_logout_uri");
            if (!string.IsNullOrWhiteSpace(backchannel))
            {
                if (!Uri.TryCreate(backchannel, UriKind.Absolute, out var logoutUri))
                    throw new OAuthException(OAuthErrorCodes.InvalidClientMetadata,
                        $"'{backchannel}' is not an absolute URI.");
                if (!string.IsNullOrEmpty(logoutUri.Fragment))
                    throw new OAuthException(OAuthErrorCodes.InvalidClientMetadata,
                        "backchannel_logout_uri must not contain a fragment.");
                // The logout token is a bearer assertion about who has just been signed out, and
                // it is delivered server to server with no user present to notice a warning.
                if (logoutUri.Scheme != "https" && !logoutUri.IsLoopback)
                    throw new OAuthException(OAuthErrorCodes.InvalidClientMetadata,
                        "backchannel_logout_uri must use https (http is only permitted for loopback).");
                client.backchannel_logout_uri = backchannel!.Trim();
            }
            else
            {
                client.backchannel_logout_uri = null;
            }
            client.backchannel_logout_session_required = Bool("backchannel_logout_session_required") ?? true;

            // legacy single-valued columns, kept in step for the v1 endpoints
            client.redirect_url = redirectUris.FirstOrDefault() ?? "";
            client.logout_url = client.post_logout_redirect_uris.FirstOrDefault() ?? "";
            client.domain = redirectUris.Count > 0 && Uri.TryCreate(redirectUris[0], UriKind.Absolute, out var d) ? d.Host : "";
        }

        private async Task EnforceUniqueClientNameAsync(ArkClient client)
        {
            try
            {
                await _da.EnsureUniqueClientName(client.tenant_id, client.client_name ?? client.client_id, client.id);
            }
            catch (ArkClientValidationException ex)
            {
                throw new OAuthException(OAuthErrorCodes.InvalidClientMetadata, ex.Message, ex.StatusCode);
            }
        }

        private static Dictionary<string, object> BuildClientResponse(ArkClient client, ArkOidcEndpoints ep)
        {
            var body = new Dictionary<string, object>
            {
                ["client_id"] = client.client_id,
                ["client_id_issued_at"] = DateTime.TryParse(client.at, out var issued)
                    ? ArkTokenService.ToUnix(issued) : ArkTokenService.ToUnix(DateTime.UtcNow),
                ["client_name"] = client.client_name ?? client.client_id,
                ["redirect_uris"] = client.EffectiveRedirectUris,
                ["grant_types"] = client.EffectiveGrantTypes,
                ["response_types"] = client.EffectiveResponseTypes,
                ["scope"] = string.Join(" ", client.EffectiveScopes),
                ["token_endpoint_auth_method"] = client.token_endpoint_auth_method,
                ["application_type"] = client.application_type
            };
            if (client.post_logout_redirect_uris.Count > 0) body["post_logout_redirect_uris"] = client.post_logout_redirect_uris;
            if (!string.IsNullOrEmpty(client.client_logo)) body["logo_uri"] = client.client_logo!;
            if (!string.IsNullOrEmpty(client.client_uri)) body["client_uri"] = client.client_uri!;
            if (!string.IsNullOrEmpty(client.policy_uri)) body["policy_uri"] = client.policy_uri!;
            if (!string.IsNullOrEmpty(client.tos_uri)) body["tos_uri"] = client.tos_uri!;
            if (!string.IsNullOrEmpty(client.jwks_uri)) body["jwks_uri"] = client.jwks_uri!;
            if (client.contacts.Count > 0) body["contacts"] = client.contacts;
            if (!string.IsNullOrEmpty(client.backchannel_logout_uri))
            {
                body["backchannel_logout_uri"] = client.backchannel_logout_uri!;
                body["backchannel_logout_session_required"] = client.backchannel_logout_session_required;
            }
            return body;
        }
    }
}
