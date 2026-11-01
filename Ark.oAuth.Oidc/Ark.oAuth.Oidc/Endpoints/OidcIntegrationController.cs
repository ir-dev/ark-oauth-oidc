using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Ark.oAuth.Oidc.Protocol;

namespace Ark.oAuth.Oidc.Endpoints
{
    /// <summary>
    /// A per-client integration page: the exact values and config snippets needed to wire an
    /// application up to this server.
    ///
    /// This exists because "what do I paste where" was the hardest part of using the old server —
    /// the answer lived in a hand-maintained text file and a discovery document that mixed public
    /// metadata with client-specific settings. Everything shown here is derived live from the
    /// client's own registration, so it cannot drift out of date.
    /// </summary>
    [Route("{tenant_id}/oauth2")]
    public class OidcIntegrationController : ArkOidcControllerBase
    {
        private readonly ArkGrantStore _grants;

        public OidcIntegrationController(ArkDataContext ctx, IConfiguration config, ArkGrantStore grants)
            : base(ctx, config)
        {
            _grants = grants;
        }

        [HttpGet("integrate/{client_id}")]
        public async Task<IActionResult> Integrate([FromRoute] string tenant_id, [FromRoute] string client_id)
        {
            NoStore();
            FrameAncestorsSelf();
            var tenant = await ResolveTenantAsync(tenant_id);

            // Only a signed-in user of this tenant may view a client's setup details. Nothing
            // secret is rendered, but the registration shape is not public information either.
            //
            // The operator tenant is the exception. The admin console manages every tenant on the
            // server but signs its users in against its own — so a session there is never scoped
            // to the tenant whose client is being set up, and without this the console's "Setup
            // page" link fails with login_required for every tenant but the operator's own.
            //
            // This deliberately does not start an authorization request of its own: the verifier
            // for such a request would have nowhere to live, and the user would be bounced to the
            // admin console rather than back to this page. Asking them to sign in is honest.
            var session = await _grants.GetSessionAsync(Request.Cookies[OidcAuthorizeController.SessionCookie]);
            var operatorTenant = ServerConfig.TenantId;
            var permitted = session != null
                && (string.Equals(session.tenant_id, tenant.tenant_id, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(session.tenant_id, operatorTenant, StringComparison.OrdinalIgnoreCase));
            if (!permitted)
            {
                Response.StatusCode = 401;
                return View("~/Views/Oidc/Error.cshtml", new OidcErrorPageModel
                {
                    Brand = Brand(),
                    Error = "login_required",
                    Description = "Sign in to the admin console for this tenant, then open this page again."
                });
            }

            var client = await Ctx.clients.AsNoTracking().FirstOrDefaultAsync(c =>
                c.tenant_id.ToLower() == tenant.tenant_id.ToLower() && c.client_id.ToLower() == client_id.ToLower());
            if (client == null)
                return View("~/Views/Oidc/Error.cshtml", new OidcErrorPageModel
                {
                    Brand = Brand(),
                    Error = "unknown_client",
                    Description = $"No client '{client_id}' is registered in tenant '{tenant_id}'."
                });

            var ep = Endpoints(tenant.tenant_id);
            return View("~/Views/Oidc/Integrate.cshtml", new IntegrationPageModel
            {
                Brand = Brand(client),
                TenantId = tenant.tenant_id,
                Client = client,
                Endpoints = ep,
                DeviceFlowEnabled = Options.EnableDeviceFlow,
                ParEnabled = Options.EnablePushedAuthorizationRequests
            });
        }

        private OidcBrandModel Brand(ArkClient? client = null)
        {
            var cfg = ServerConfig.EmailConfig;
            return new OidcBrandModel
            {
                HostLogo = cfg?.host_logo,
                ClientLogo = string.IsNullOrWhiteSpace(client?.client_logo) ? null : client!.client_logo,
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

    public class IntegrationPageModel
    {
        public OidcBrandModel Brand { get; set; } = new();
        public string TenantId { get; set; } = default!;
        public ArkClient Client { get; set; } = default!;
        public ArkOidcEndpoints Endpoints { get; set; } = default!;
        public bool DeviceFlowEnabled { get; set; }
        public bool ParEnabled { get; set; }
    }
}
