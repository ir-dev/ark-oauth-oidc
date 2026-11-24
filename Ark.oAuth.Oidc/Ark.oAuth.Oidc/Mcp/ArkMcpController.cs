using System.Text.Json.Nodes;
using Ark.oAuth.Oidc.Endpoints;
using Ark.oAuth.Oidc.Mcp.Tools;
using Ark.oAuth.Oidc.Protocol;
using Microsoft.AspNetCore.Mvc;

namespace Ark.oAuth.Oidc.Mcp
{
    /// <summary>
    /// The MCP endpoints of a configured server, and the documents beside them. See MCP.md.
    ///
    /// Only POST is mapped at an endpoint: there is no event stream to GET and no session to
    /// DELETE, and leaving those verbs unmapped means a host's own page at such a path is still
    /// the host's. The documents are public; everything else is authenticated by
    /// <see cref="ArkMcpAuth"/>, whatever the host's default scheme is, so a browser's console
    /// cookie is never enough here.
    /// </summary>
    // Authenticated by ArkMcpAuth in HandleAsync: bearer token or client secret, never a cookie.
    [ApiController]  // nosemgrep: csharp.dotnet.security.audit.missing-or-broken-authorization.missing-or-broken-authorization
    [IgnoreAntiforgeryToken]
    [Microsoft.AspNetCore.Cors.EnableCors(ArkCors.PolicyName)]
    public class ArkMcpController : ArkOidcControllerBase
    {
        public ArkMcpController(ArkDataContext ctx, IConfiguration config) : base(ctx, config) { }

        // ---------------------------------------------------------------- the endpoints

        [HttpPost("ark-idp/mcp")]  // nosemgrep: csharp.dotnet.security.mvc-missing-antiforgery.mvc-missing-antiforgery
        public Task HostEndpoint() => ServeAsync(ArkMcpLevel.Host, null, null);

        [HttpPost("{tenant_id}/mcp")]  // nosemgrep: csharp.dotnet.security.mvc-missing-antiforgery.mvc-missing-antiforgery
        public Task TenantEndpoint([FromRoute] string tenant_id) => ServeAsync(ArkMcpLevel.Tenant, tenant_id, null);

        [HttpPost("{tenant_id}/mcp/{client_id}")]  // nosemgrep: csharp.dotnet.security.mvc-missing-antiforgery.mvc-missing-antiforgery
        public Task ClientEndpoint([FromRoute] string tenant_id, [FromRoute] string client_id) =>
            ServeAsync(ArkMcpLevel.Client, tenant_id, client_id);

        // ---------------------------------------------------------------- the documents

        [HttpGet("ark-idp/mcp/server-card")]
        public Task<IActionResult> HostCard() => DocumentAsync(ArkMcpLevel.Host, null, null, Card);

        [HttpGet("{tenant_id}/mcp/server-card")]
        public Task<IActionResult> TenantCard([FromRoute] string tenant_id) => DocumentAsync(ArkMcpLevel.Tenant, tenant_id, null, Card);

        [HttpGet("{tenant_id}/mcp/{client_id}/server-card")]
        public Task<IActionResult> ClientCard([FromRoute] string tenant_id, [FromRoute] string client_id) =>
            DocumentAsync(ArkMcpLevel.Client, tenant_id, client_id, Card);

        [HttpGet("ark-idp/mcp/config")]
        public Task<IActionResult> HostConfig() => DocumentAsync(ArkMcpLevel.Host, null, null, ArkMcpDocuments.Config);

        [HttpGet("{tenant_id}/mcp/config")]
        public Task<IActionResult> TenantConfig([FromRoute] string tenant_id) =>
            DocumentAsync(ArkMcpLevel.Tenant, tenant_id, null, ArkMcpDocuments.Config);

        [HttpGet("{tenant_id}/mcp/{client_id}/config")]
        public Task<IActionResult> ClientConfig([FromRoute] string tenant_id, [FromRoute] string client_id) =>
            DocumentAsync(ArkMcpLevel.Client, tenant_id, client_id, ArkMcpDocuments.Config);

        [HttpGet(".well-known/oauth-protected-resource/ark-idp/mcp")]
        public Task<IActionResult> HostMetadata() => DocumentAsync(ArkMcpLevel.Host, null, null, ArkMcpDocuments.Metadata);

        [HttpGet(".well-known/oauth-protected-resource/{tenant_id}/mcp")]
        public Task<IActionResult> TenantMetadata([FromRoute] string tenant_id) =>
            DocumentAsync(ArkMcpLevel.Tenant, tenant_id, null, ArkMcpDocuments.Metadata);

        [HttpGet(".well-known/oauth-protected-resource/{tenant_id}/mcp/{client_id}")]
        public Task<IActionResult> ClientMetadata([FromRoute] string tenant_id, [FromRoute] string client_id) =>
            DocumentAsync(ArkMcpLevel.Client, tenant_id, client_id, ArkMcpDocuments.Metadata);

        // ---------------------------------------------------------------- plumbing

        private static JsonObject Card(ArkMcpEndpoint e) => ArkMcpDocuments.Card(e, ArkWatchAudit.PackageVersion);

        private async Task<ArkMcpEndpoint?> ResolveAsync(ArkMcpLevel level, string? tenantId, string? clientId)
        {
            var config = ServerConfig;
            var root = Endpoints(config.TenantId ?? "").BaseUrl;
            // The path arrives decoded except for %2F, which is what a client_id that is a URL has.
            var target = new ArkMcpTarget(level, tenantId, clientId == null ? null : Uri.UnescapeDataString(clientId));
            var resource = await ArkMcpIndicators.ResolveAsync(Ctx, config, root, target);
            return resource == null ? null : new ArkMcpEndpoint
            {
                Level = level, Tenant = resource.Tenant, Client = resource.Client,
                Config = config, Root = root, Resource = resource.Uri
            };
        }

        private async Task<IActionResult> DocumentAsync(ArkMcpLevel level, string? tenantId, string? clientId, Func<ArkMcpEndpoint, JsonObject> build)
        {
            var endpoint = await ResolveAsync(level, tenantId, clientId);
            if (endpoint == null) return NotFound();
            Response.Headers.CacheControl = "public, max-age=300";
            Response.Headers.XContentTypeOptions = "nosniff";
            return Content(build(endpoint).ToJsonString(ArkMcpJson.Indented), "application/json; charset=utf-8");
        }

        private async Task ServeAsync(ArkMcpLevel level, string? tenantId, string? clientId)
        {
            var endpoint = await ResolveAsync(level, tenantId, clientId);
            if (endpoint == null)
            {
                Response.StatusCode = StatusCodes.Status404NotFound;
                return;
            }
            var auth = HttpContext.RequestServices.GetRequiredService<ArkMcpAuth>();
            var (tools, instructions) = level switch
            {
                ArkMcpLevel.Host => (HostTools.All, HostTools.Instructions),
                ArkMcpLevel.Tenant => (TenantTools.All, TenantTools.Instructions),
                _ => (ClientTools.All, ClientTools.Instructions)
            };
            var scopes = ArkMcpDocuments.Scopes(endpoint);
            await ArkMcpServer.HandleAsync(HttpContext, new ArkMcpServer.Binding
            {
                Endpoint = endpoint,
                Authenticate = () => auth.AuthenticateAsync(Request, endpoint),
                Tools = tools,
                Instructions = instructions,
                ChallengeScope = scopes.Count == 0 ? null : string.Join(" ", scopes),
                OnCalled = ArkMcpAudit.Called
            });
        }
    }
}
