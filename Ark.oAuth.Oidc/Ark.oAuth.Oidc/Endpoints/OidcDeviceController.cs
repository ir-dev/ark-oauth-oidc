using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Ark.oAuth.Oidc.Protocol;

namespace Ark.oAuth.Oidc.Endpoints
{
    /// <summary>
    /// The device authorization grant (RFC 8628), for TVs, CLIs and anything else without a
    /// usable browser or keyboard. The device polls /token while the user approves the request
    /// on a second device at /oauth2/device.
    /// </summary>
    [Route("{tenant_id}/oauth2")]
    public class OidcDeviceController : ArkOidcControllerBase
    {
        private readonly ArkClientAuthenticator _clientAuth;
        private readonly ArkGrantStore _grants;
        private readonly ArkClaimsService _claims;
        private readonly DataAccess _da;

        public OidcDeviceController(ArkDataContext ctx, IConfiguration config, ArkClientAuthenticator clientAuth,
            ArkGrantStore grants, ArkClaimsService claims, DataAccess da) : base(ctx, config)
        {
            _clientAuth = clientAuth;
            _grants = grants;
            _claims = claims;
            _da = da;
        }

        /// <summary>Device authorization request (§3.1). Called by the device, not the browser.</summary>
        [HttpPost("device_authorization")]
        [Consumes("application/x-www-form-urlencoded")]
        public async Task<IActionResult> DeviceAuthorization([FromRoute] string tenant_id)
        {
            NoStore();
            return await ProtectAsync(async () =>
            {
                if (!Options.EnableDeviceFlow)
                    throw OAuthException.InvalidRequest("the device grant is not enabled on this server.");

                var tenant = await ResolveTenantAsync(tenant_id);
                var ep = Endpoints(tenant.tenant_id);
                var auth = await _clientAuth.AuthenticateAsync(Request, tenant.tenant_id, ep.DeviceAuthorization);
                var client = auth.Client;

                if (!client.EffectiveGrantTypes.Contains("urn:ietf:params:oauth:grant-type:device_code", StringComparer.OrdinalIgnoreCase))
                    throw OAuthException.UnauthorizedClient("this client is not registered for the device grant.");

                var scopes = await _claims.ResolveScopesAsync(Request.Form["scope"].ToString(), client);
                var (deviceCode, userCode, entry) = await _grants.CreateDeviceCodeAsync(
                    client, tenant.tenant_id, scopes, Options.DeviceCodeLifetimeSeconds, Options.DevicePollIntervalSeconds);

                _da.Log("device_authorization", tenant.tenant_id, "device code issued", $"client: {client.client_id}");

                return Ok(new Dictionary<string, object>
                {
                    ["device_code"] = deviceCode,
                    ["user_code"] = userCode,
                    ["verification_uri"] = ep.DeviceVerification,
                    // §3.3.1: lets the device render a QR code the user can follow directly
                    ["verification_uri_complete"] = $"{ep.DeviceVerification}?user_code={Uri.EscapeDataString(userCode)}",
                    ["expires_in"] = Math.Max(0, (int)(entry.expires_at - DateTime.UtcNow).TotalSeconds),
                    ["interval"] = entry.interval_seconds
                });
            }, _da, "device_authorization");
        }

        /// <summary>The page where the user enters the code shown on the device (§3.3).</summary>
        [HttpGet("device")]
        public async Task<IActionResult> DeviceVerificationGet([FromRoute] string tenant_id)
        {
            NoStore();
            var tenant = await ResolveTenantAsync(tenant_id);
            var userCode = Request.Query["user_code"].FirstOrDefault();

            if (string.IsNullOrWhiteSpace(userCode))
                return DevicePage(tenant, "enter_code", null, null, null);

            return await ShowConfirmationAsync(tenant, userCode!, null);
        }

        [HttpPost("device")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeviceVerificationPost([FromRoute] string tenant_id)
        {
            NoStore();
            var tenant = await ResolveTenantAsync(tenant_id);
            var form = Request.Form;
            var userCode = form["user_code"].ToString();
            var action = form["ark_action"].ToString();

            if (string.IsNullOrWhiteSpace(userCode))
                return DevicePage(tenant, "enter_code", "Enter the code shown on your device.", null, null);

            var entry = await _grants.FindDeviceCodeByUserCodeAsync(userCode);
            if (entry == null || entry.expires_at <= DateTime.UtcNow)
                return DevicePage(tenant, "enter_code", "That code is not valid or has expired.", userCode, null);
            if (entry.status != "pending")
                return DevicePage(tenant, "enter_code", "That code has already been used.", userCode, null);

            // The user must be signed in before they can approve anything.
            var session = await _grants.GetSessionAsync(Request.Cookies[OidcAuthorizeController.SessionCookie]);
            if (session == null || !string.Equals(session.tenant_id, tenant.tenant_id, StringComparison.OrdinalIgnoreCase))
            {
                var ep = Endpoints(tenant.tenant_id);
                var returnTo = Uri.EscapeDataString($"{ep.DeviceVerification}?user_code={Uri.EscapeDataString(entry.user_code)}");
                return Redirect($"{ep.DeviceVerification}?user_code={Uri.EscapeDataString(entry.user_code)}&signin=1&return_to={returnTo}");
            }

            if (action == "approve")
            {
                var scopes = (entry.scope ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();
                await _grants.SaveConsentAsync(tenant.tenant_id, entry.client_id, session.subject, scopes);
                await _grants.SetDeviceCodeStatusAsync(entry, "approved", session.subject, session.session_id);
                // The device is now logged in under this session, so it is part of the audience
                // for back-channel logout when the session ends.
                await _grants.TrackSessionClientAsync(tenant.tenant_id, session.session_id, entry.client_id, session.subject);
                _da.Log("device_approved", tenant.tenant_id, "device authorization approved",
                    $"client: {entry.client_id}, sub: {session.subject}");
                return DevicePage(tenant, "done", null, entry.user_code,
                    "You're all set — return to your device, it will continue automatically.");
            }

            if (action == "deny")
            {
                await _grants.SetDeviceCodeStatusAsync(entry, "denied", session.subject, session.session_id);
                return DevicePage(tenant, "done", null, entry.user_code, "The request was denied. You can close this page.");
            }

            return await ShowConfirmationAsync(tenant, userCode, null);
        }

        // -----------------------------------------------------------------

        private async Task<IActionResult> ShowConfirmationAsync(ArkTenant tenant, string userCode, string? error)
        {
            var entry = await _grants.FindDeviceCodeByUserCodeAsync(userCode);
            if (entry == null || entry.expires_at <= DateTime.UtcNow)
                return DevicePage(tenant, "enter_code", "That code is not valid or has expired.", userCode, null);
            if (entry.status != "pending")
                return DevicePage(tenant, "enter_code", "That code has already been used.", userCode, null);

            var client = await Ctx.clients.AsNoTracking().FirstOrDefaultAsync(c =>
                c.tenant_id.ToLower() == tenant.tenant_id.ToLower() &&
                c.client_id.ToLower() == entry.client_id.ToLower());

            var catalogue = await Ctx.scopes.AsNoTracking().ToListAsync();
            var scopes = (entry.scope ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Select(s =>
                {
                    var known = catalogue.FirstOrDefault(c => string.Equals(c.name, s, StringComparison.OrdinalIgnoreCase));
                    return new ConsentScopeModel
                    {
                        Name = s,
                        Display = known?.display ?? s,
                        Description = known?.description,
                        Required = string.Equals(s, "openid", StringComparison.OrdinalIgnoreCase)
                    };
                }).ToList();

            var model = BuildModel(tenant, "confirm", error, entry.user_code, null);
            model.ClientDisplay = client == null ? entry.client_id
                : (string.IsNullOrWhiteSpace(client.display) ? client.client_id : client.display);
            model.Scopes = scopes;
            return View("~/Views/Oidc/Device.cshtml", model);
        }

        private IActionResult DevicePage(ArkTenant tenant, string stage, string? error, string? userCode, string? message)
            => View("~/Views/Oidc/Device.cshtml", BuildModel(tenant, stage, error, userCode, message));

        private DevicePageModel BuildModel(ArkTenant tenant, string stage, string? error, string? userCode, string? message)
        {
            var cfg = ServerConfig.EmailConfig;
            return new DevicePageModel
            {
                Brand = new OidcBrandModel
                {
                    HostLogo = cfg?.host_logo,
                    ClientLogo = cfg?.client_logo,
                    HostName = cfg?.host_company_display ?? cfg?.host_company_name ?? "Identity Provider",
                    PrivacyUrl = cfg?.privacy_policy_url,
                    TermsUrl = cfg?.terms_url
                },
                ActionUrl = $"{Request.PathBase}{Request.Path}",
                Stage = stage,
                Error = error,
                Message = message,
                UserCode = userCode
            };
        }
    }
}
