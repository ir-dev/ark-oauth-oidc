using Microsoft.AspNetCore.Mvc;
using Ark.oAuth.Oidc.Protocol;

namespace Ark.oAuth.Oidc.Endpoints
{
    /// <summary>
    /// The one thing the A2A protocol asks of an agent that this server can write for it: the
    /// security section of its Agent Card.
    ///
    /// An agent publishes a card at <c>/.well-known/agent-card.json</c> saying, among other
    /// things, how a caller authenticates. For an agent secured by this server the answer is the
    /// same for every agent of the tenant — an OAuth 2.0 access token from this issuer — so it is
    /// served here ready to merge into the card, and stays right when an endpoint moves.
    ///
    /// Nothing here is about any one client, and nothing is secret: it is the discovery
    /// document's token endpoint in the shape the A2A specification uses.
    /// </summary>
    [ApiController]
    [Route("{tenant_id}/a2a")]
    public class OidcAgentController : ArkOidcControllerBase
    {
        private readonly ArkClaimsService _claims;

        public OidcAgentController(ArkDataContext ctx, IConfiguration config, ArkClaimsService claims)
            : base(ctx, config)
        {
            _claims = claims;
        }

        /// <summary>The name the scheme goes by in the card. A label, nothing more.</summary>
        public const string SchemeName = "ark";

        /// <summary>
        /// <c>securitySchemes</c> and <c>securityRequirements</c> as A2A 1.0 spells them, or with
        /// <c>?spec=0.3</c> the <c>securitySchemes</c> and <c>security</c> of A2A 0.3.
        /// </summary>
        [HttpGet("agent-card-security")]
        public async Task<IActionResult> AgentCardSecurity([FromRoute] string tenant_id, [FromQuery] string? spec = null)
        {
            return await ProtectAsync(async () =>
            {
                if (!Options.EnableA2A) return NotFound();
                var tenant = await ResolveTenantAsync(tenant_id);
                var ep = Endpoints(tenant.tenant_id);

                // Scopes a machine can be granted: the catalogue without the ones that describe
                // a signed-in person or the protocol itself.
                var scopes = (await ArkIdpCache.ScopesAsync(Ctx))
                    .Where(s => !s.is_protocol && !ArkClaimsService.StandardScopeClaims.ContainsKey(s.name))
                    .ToDictionary(s => s.name, s => string.IsNullOrWhiteSpace(s.description) ? (s.display ?? s.name) : s.description);

                var flows = new Dictionary<string, object>
                {
                    ["clientCredentials"] = new Dictionary<string, object>
                    {
                        ["tokenUrl"] = ep.Token,
                        ["scopes"] = scopes
                    }
                };
                const string description =
                    "An OAuth 2.0 access token from this issuer, addressed to this agent: request it with " +
                    "the client_credentials grant and audience set to the agent's client_id, or by token " +
                    "exchange (RFC 8693) when acting for a user. Send it as Authorization: Bearer.";
                var metadataUrl = $"{ep.Issuer}/.well-known/oauth-authorization-server";

                Dictionary<string, object> card;
                if (string.Equals(spec?.Trim(), "0.3", StringComparison.Ordinal))
                {
                    card = new Dictionary<string, object>
                    {
                        ["securitySchemes"] = new Dictionary<string, object>
                        {
                            [SchemeName] = new Dictionary<string, object>
                            {
                                ["type"] = "oauth2",
                                ["description"] = description,
                                ["flows"] = flows,
                                ["oauth2MetadataUrl"] = metadataUrl
                            }
                        },
                        ["security"] = new[] { new Dictionary<string, object> { [SchemeName] = Array.Empty<string>() } }
                    };
                }
                else
                {
                    card = new Dictionary<string, object>
                    {
                        ["securitySchemes"] = new Dictionary<string, object>
                        {
                            [SchemeName] = new Dictionary<string, object>
                            {
                                ["oauth2SecurityScheme"] = new Dictionary<string, object>
                                {
                                    ["description"] = description,
                                    ["flows"] = flows,
                                    ["oauth2MetadataUrl"] = metadataUrl
                                }
                            }
                        },
                        ["securityRequirements"] = new[]
                        {
                            new Dictionary<string, object>
                            {
                                ["schemes"] = new Dictionary<string, object>
                                {
                                    [SchemeName] = new Dictionary<string, object> { ["list"] = Array.Empty<string>() }
                                }
                            }
                        }
                    };
                }

                Response.Headers["Cache-Control"] = "public, max-age=300";
                return Ok(card);
            });
        }
    }
}
