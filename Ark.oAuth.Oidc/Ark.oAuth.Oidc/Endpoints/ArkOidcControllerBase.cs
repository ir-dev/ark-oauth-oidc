using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Ark.oAuth.Oidc.Protocol;

namespace Ark.oAuth.Oidc.Endpoints
{
    /// <summary>
    /// Shared plumbing for the standard OAuth endpoints: tenant resolution, endpoint URLs and —
    /// the part that matters for interoperability — rendering failures in the shape each spec
    /// requires. A client library can only recover from an error it can parse, so errors here are
    /// never HTTP 200 with a message in the body.
    /// </summary>
    public abstract class ArkOidcControllerBase : Controller
    {
        protected readonly ArkDataContext Ctx;
        protected readonly IConfiguration Config;

        protected ArkOidcControllerBase(ArkDataContext ctx, IConfiguration config)
        {
            Ctx = ctx;
            Config = config;
        }

        protected ArkAuthServerConfig ServerConfig =>
            Config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>()
            ?? throw new ApplicationException("the 'ark_oauth_server' configuration section is missing.");

        protected ArkOidcOptions Options => ServerConfig.Oidc ?? new ArkOidcOptions();

        protected ArkOidcEndpoints Endpoints(string tenantId) =>
            ArkOidcEndpoints.For(Request, ServerConfig, tenantId);

        protected async Task<ArkTenant> ResolveTenantAsync(string tenantId)
        {
            var tenant = await Ctx.tenants.AsNoTracking()
                .FirstOrDefaultAsync(t => t.tenant_id.ToLower() == (tenantId ?? "").ToLower());
            if (tenant == null)
                throw OAuthException.InvalidRequest($"unknown tenant '{tenantId}'.");
            return tenant;
        }

        /// <summary>An RFC 6749 §5.2 error response, with the caching headers the spec requires.</summary>
        protected IActionResult OAuthError(OAuthException ex)
        {
            Response.Headers["Cache-Control"] = "no-store";
            Response.Headers["Pragma"] = "no-cache";
            if (ex.StatusCode == 401 && !Response.Headers.ContainsKey("WWW-Authenticate"))
                Response.Headers["WWW-Authenticate"] = $"Basic realm=\"ark\", error=\"{ex.Error}\"";
            return StatusCode(ex.StatusCode, ex.ToResponseBody());
        }

        /// <summary>Wraps a handler so protocol failures render correctly and unexpected ones become server_error.</summary>
        protected async Task<IActionResult> ProtectAsync(Func<Task<IActionResult>> handler, DataAccess? da = null, string? refKey = null)
        {
            try
            {
                return await handler();
            }
            catch (OAuthException ex)
            {
                return OAuthError(ex);
            }
            catch (Exception ex)
            {
                da?.LogError(ex, refKey ?? "oidc", Request.Path, ex.Message);
                // never leak internals to a client
                return OAuthError(OAuthException.ServerError("the authorization server encountered an unexpected condition."));
            }
        }

        protected void NoStore()
        {
            Response.Headers["Cache-Control"] = "no-store";
            Response.Headers["Pragma"] = "no-cache";
        }

        /// <summary>
        /// Declares that this page may be framed by this origin and no other.
        ///
        /// Two things at once. It is the clickjacking protection the interactive pages never had:
        /// a sign-in form that any site may frame can be overlaid and its keystrokes harvested,
        /// and nothing on this server previously said otherwise. And it is what the client setup
        /// page's live flow needs — that page embeds the authorization endpoint in an iframe on
        /// the same origin, which this permits while still refusing every other origin.
        ///
        /// frame-ancestors is used rather than X-Frame-Options because the latter has no
        /// "same origin plus nothing else" that browsers agree on, and it is ignored when a CSP
        /// is present anyway.
        /// </summary>
        protected void FrameAncestorsSelf()
        {
            Response.Headers["Content-Security-Policy"] = "frame-ancestors 'self'";
        }

        /// <summary>Reads a bearer token from the Authorization header.</summary>
        protected string? BearerToken()
        {
            var header = Request.Headers["Authorization"].ToString();
            if (string.IsNullOrEmpty(header) || !header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                return null;
            return header["Bearer ".Length..].Trim();
        }
    }
}
