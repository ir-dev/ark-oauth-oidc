using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Ark.oAuth.Oidc
{
    /// <summary>
    /// Onboarding and lifecycle for an application and its users, as a machine-callable API.
    ///
    /// Everything here is doable in the admin console already; the point is that it is doable in
    /// one call, from another system, without a person clicking through five panels in the right
    /// order. The two operations are:
    ///
    ///   * <c>POST v1/provision/client</c>   — register an application and give a user access to it.
    ///   * <c>POST v1/activation/{client|user}</c> — switch either of them off, and back on.
    ///
    /// Authorization is the same as the rest of the management API: operator only, through
    /// <see cref="ArkManagementAuth"/> — the operator's console session, or a bearer token
    /// issued to the machine client with <c>client.register</c>. A pipeline uses the second; the
    /// host registers nothing for it.
    ///
    /// Responses keep the <c>{ error, msg, data }</c> shape the rest of the management API uses,
    /// and add a stable <c>code</c> so a caller can branch without matching on prose. Unlike the
    /// rest of the API, failures also carry a real HTTP status — a provisioning script is not a
    /// person reading a toast, and "already exists" has to be distinguishable from "worked"
    /// without parsing the body.
    /// </summary>
    [Authorize(Policy = ArkManagementAuth.PolicyName)]
    [Route("api/oauth")]
    [ApiController]
    public class ProvisionController : ControllerBase
    {
        /// <summary>
        /// Registers an application and gives one user access to it.
        ///
        /// The four steps this replaces are: create the client, register its redirect URIs,
        /// create the account, and add the user-client access mapping. The last one is the one
        /// that gets forgotten, and its absence looks exactly like a wrong password on the
        /// sign-in page — so it is not optional here.
        ///
        /// Behaviour on collision is deliberately asymmetric:
        ///
        ///   * an existing <b>client name</b> is refused (409 <c>client_exists</c>) and nothing is
        ///     written, because quietly rewriting the redirect URIs of a live application would
        ///     turn an onboarding script into a way to redirect somebody else's authorization
        ///     codes;
        ///   * an existing <b>user</b> is reused and mapped to the new client, because that is
        ///     precisely what happens when a person is given their second application.
        ///
        /// A user this call creates gets the configured default password
        /// (<c>ark_oauth_server:DefaultPw</c>) and can sign in immediately. Pass
        /// <c>send_activation_email: true</c> to email an activation link instead — the account
        /// then cannot sign in until the link is used.
        /// </summary>
        [HttpPost]
        [Route("v1/provision/client")]
        public async Task<IActionResult> ProvisionClient(
            [FromServices] ArkProvisioning provisioning,
            [FromServices] DataAccess da,
            [FromServices] ArkUtil util,
            [FromBody] ArkProvisionRequest request)
        {
            try
            {
                // Built from this request, so a deployment that leaves BaseUrl unset and derives
                // its public address from the host header still gets a usable issuer and setup
                // URL back rather than a configuration error.
                var tenantId = string.IsNullOrWhiteSpace(request?.tenant_id)
                    ? util.ServerConfig.TenantId
                    : request!.tenant_id!.Trim();
                var endpoints = Protocol.ArkOidcEndpoints.For(Request, util.ServerConfig, tenantId);
                var result = await provisioning.ProvisionAsync(request, endpoints);
                var what = result.user_created
                    ? (result.user_credential == "activation_email"
                        ? "an activation link has been emailed to the new user"
                        : "the new user signs in with the configured default password")
                    : "the existing user has been mapped to it";
                return Ok(new
                {
                    error = false,
                    code = "provisioned",
                    msg = $"client '{result.client_id}' created in tenant '{result.tenant_id}' - {what}.",
                    data = result
                });
            }
            catch (ArkProvisionException ex)
            {
                // Expected outcomes, not faults: logged as a trace so a noisy onboarding script
                // does not fill the error log with rows nobody needs to act on.
                da.Log("provision_refused", $"{request?.tenant_id}/{request?.client_id}", ex.Code, ex.Message, "warn");
                return StatusCode(ex.StatusCode, new
                {
                    error = true,
                    code = ex.Code,
                    msg = ex.Message,
                    data = ex.Data
                });
            }
            catch (Exception ex)
            {
                da.LogError(ex, "provision", "v1/provision/client",
                    $"details : cn: {request?.client_name}, un: {request?.user_name}, ti: {request?.tenant_id}");
                return StatusCode(500, new
                {
                    error = true,
                    code = "provision_failed",
                    msg = ex.Message,
                    data = (object?)null
                });
            }
        }

        /// <summary>
        /// Switches an application on or off.
        ///
        /// Turning it off also revokes the refresh tokens already issued to it. Without that the
        /// switch would only close the front door: existing refresh tokens keep minting access
        /// tokens for their full lifetime — fourteen days by default — so a "deactivated"
        /// application would carry on working for a fortnight.
        /// </summary>
        [HttpPost]
        [Route("v1/activation/client")]
        public async Task<IActionResult> SetClientActivation(
            [FromServices] DataAccess da, [FromServices] ArkUtil util, [FromBody] ArkActivationRequest request)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(request?.client_id))
                    throw new ApplicationException("client_id is required.");
                var tenantId = string.IsNullOrWhiteSpace(request.tenant_id)
                    ? util.ServerConfig.TenantId
                    : request.tenant_id!.Trim();

                var client = await da.SetClientActive(tenantId, request.client_id!, request.is_active);
                da.Log("client_activation", client.client_id,
                    request.is_active ? "client activated" : "client deactivated",
                    $"details : ci: {client.client_id}, ti: {client.tenant_id}, reason: {request.reason}");
                return Ok(new
                {
                    error = false,
                    code = request.is_active ? "activated" : "deactivated",
                    msg = $"'{client.client_name ?? client.client_id}' is now {(request.is_active ? "active" : "deactivated")}."
                        + (request.is_active ? "" : " Refresh tokens issued to it have been revoked; sign-ins are refused with a message naming the application."),
                    data = new { client.tenant_id, client.client_id, client.client_name, client.is_active }
                });
            }
            catch (Exception ex)
            {
                da.LogError(ex, "client_activation", "v1/activation/client", $"details : ci: {request?.client_id}, ti: {request?.tenant_id}");
                return StatusCode(400, new { error = true, code = "activation_failed", msg = ex.Message, data = (object?)null });
            }
        }

        /// <summary>
        /// Switches an account on or off across every application on the server.
        ///
        /// Turning it off ends the user's IdP sessions and revokes their refresh tokens as well,
        /// for the same reason as the client switch — a signed-in browser holds a session cookie
        /// that skips the sign-in page, so otherwise the change would not take effect until that
        /// session aged out.
        /// </summary>
        [HttpPost]
        [Route("v1/activation/user")]
        public async Task<IActionResult> SetUserActivation([FromServices] DataAccess da, [FromBody] ArkActivationRequest request)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(request?.user_name))
                    throw new ApplicationException("user_name is required.");

                var user = await da.SetUserActive(request.user_name!, request.is_active);
                da.Log("user_activation", user.email,
                    request.is_active ? "user activated" : "user deactivated",
                    $"details : e: {user.email}, reason: {request.reason}");
                return Ok(new
                {
                    error = false,
                    code = request.is_active ? "activated" : "deactivated",
                    msg = $"'{user.email}' is now {(request.is_active ? "active" : "deactivated")}."
                        + (request.is_active ? "" : " Their sessions and refresh tokens have been revoked; sign-ins are refused with a message saying the account is deactivated."),
                    data = new { user.email, user.name, user.type, user.is_active }
                });
            }
            catch (Exception ex)
            {
                da.LogError(ex, "user_activation", "v1/activation/user", $"details : un: {request?.user_name}");
                return StatusCode(400, new { error = true, code = "activation_failed", msg = ex.Message, data = (object?)null });
            }
        }
    }

    /// <summary>Body of the two activation endpoints. Set <see cref="user_name"/> or
    /// <see cref="tenant_id"/> + <see cref="client_id"/>, depending on which one is being called.</summary>
    public class ArkActivationRequest
    {
        public string? tenant_id { get; set; }
        public string? client_id { get; set; }
        public string? user_name { get; set; }
        /// <summary>true reactivates, false deactivates.</summary>
        public bool is_active { get; set; }
        /// <summary>Free text, recorded in the audit trail. Not shown to the user.</summary>
        public string? reason { get; set; }
    }
}
