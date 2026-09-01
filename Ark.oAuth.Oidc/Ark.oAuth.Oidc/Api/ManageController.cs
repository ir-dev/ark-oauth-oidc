using Bogus;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Ark.oAuth.Oidc
{
    public class ArkPasswordChangeRequest
    {
        public string? email { get; set; }
        public string? password { get; set; }
    }

    [Authorize]
    [Route("api/oauth")]
    [ApiController]
    public class ManageController : ControllerBase
    {
        [Route("v1/tenant/list")]
        public async Task<dynamic> TenantList([FromServices] DataAccess da)
        {
            try
            {
                var tenants = await da.GetTenants();
                return new
                {
                    error = false,
                    msg = "tenatns list loaded.",
                    // rsa_private is deliberately not projected. This response is read by a page in a
                    // browser, so returning it published every tenant's *signing* key to the client —
                    // anything that can read the DOM or the response cache could then mint tokens the
                    // server would accept. Nothing needs it: the console renders only a
                    // present/absent badge off rsa_public, and an upsert that omits the pair is
                    // treated as "leave the key alone".
                    data = tenants.Select(t => new
                    {
                        t.tenant_id,
                        t.name,
                        t.display,
                        t.rsa_public,
                        t.issuer,
                        t.audience,
                        t.expire_mins,
                        t.at
                    })
                };
            }
            catch (Exception ex)
            {
                da.LogError(ex, "tenant_list", "v1/tenant/list", "loading the tenant list failed");
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = new List<ArkTenant>()
                };
            }
        }
        [HttpPost]
        [Route("v1/tenant/upsert")]
        public async Task<dynamic> TenantUpdate([FromServices] DataAccess da, [FromServices] ArkUtil util, [FromBody] ArkTenant tenant)
        {
            try
            {
                if (string.IsNullOrEmpty(tenant.rsa_private))
                {
                    // An edit that does not carry the key back must not rotate it. Regenerating here
                    // silently invalidates every token and JWKS entry already issued for the tenant,
                    // so the stored pair is preserved and a new one is only minted for a new tenant.
                    var existing = await da.GetTenant(tenant.tenant_id);
                    if (existing != null && !string.IsNullOrEmpty(existing.rsa_private))
                    {
                        tenant.rsa_private = existing.rsa_private;
                        tenant.rsa_public = existing.rsa_public;
                    }
                    else
                    {
                        dynamic dd = await util.GetKeys();
                        tenant.rsa_private = dd.private_key;
                        tenant.rsa_public = dd.public_key;
                    }
                }
                await da.UpsertTenant(tenant);
                da.Log("tenant_upsert", $"{tenant.tenant_id}", "Tenant updated success", $"details : ti: {tenant.tenant_id}, n: {tenant.name}, d: {tenant.display}, em: {tenant.expire_mins}");
                return new
                {
                    error = false,
                    msg = "tenants updated successfully.",
                    data = tenant
                };
            }
            catch (Exception ex)
            {
                // Without this the console saw a bare 500 (or, while key generation was still an
                // outbound call, a 503) with no message describing what went wrong.
                da.LogError(ex, "tenant_upsert", "v1/tenant/upsert", $"details : ti: {tenant?.tenant_id}, n: {tenant?.name}");
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = tenant
                };
            }
        }
        [Route("v1/client/list")]
        public async Task<dynamic> ClientList([FromServices] DataAccess da)
        {
            try
            {
                return new
                {
                    error = false,
                    msg = "clients list loaded.",
                    data = await da.GetClients()
                };
            }
            catch (Exception ex)
            {
                da.LogError(ex, "client_list", "v1/client/list", "loading the clients list failed");
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = new List<ArkClient>()
                };
            }
        }
        [HttpPost]
        [Route("v1/client/upsert")]
        public async Task<dynamic> ClientUpdate([FromServices] DataAccess da, [FromBody] ArkClient client)
        {
            try
            {
                await da.UpsertClient(client);
                da.Log("client_upsert", $"{client.client_id}", "Client updated success", $"deails : d: {client.display}, ci: {client.client_id}, name: {client.name}, do: {client.domain}, ru: {client.redirect_url}, em: {client.expire_mins}");
                return new
                {
                    error = false,
                    msg = "clients updated.",
                    data = client
                };
            }
            catch (Exception ex)
            {
                da.LogError(ex, "v1/client/upsert", $"{client?.client_id}/client/upsert", $"deails : d: {client?.display}, ci: {client?.client_id}, name: {client?.name}, do: {client?.domain}, ru: {client?.redirect_url}, em: {client?.expire_mins}");
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = client
                };
            }
        }
        [HttpPost]
        [Route("v1/client/delete")]
        public async Task<dynamic> ClientDelete([FromServices] DataAccess da, [FromBody] ArkClient client)
        {
            try
            {
                await da.DeleteClient(client);
                da.Log("client_delete", $"{client.client_id}", "Client deleted success", $"details : d: {client.display}, ci: {client.client_id}, name: {client.name}, do: {client.domain}, ru: {client.redirect_url}, em: {client.expire_mins}");
                return new
                {
                    error = false,
                    msg = "clients deleted.",
                    data = client
                };
            }
            catch (Exception ex)
            {
                da.LogError(ex, "v1/client/delete", $"{client?.client_id}/v1/client/delete", $"deails : d: {client?.display}, ci: {client?.client_id}, name: {client?.name}, do: {client?.domain}, ru: {client?.redirect_url}, em: {client?.expire_mins}");
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = client
                };
            }
        }
        /// <summary>
        /// Issues a fresh secret for a confidential client and returns it exactly once.
        ///
        /// Only the PBKDF2 hash is stored, matching what the token endpoint verifies against, so
        /// the value cannot be read back afterwards — the same contract dynamic client
        /// registration (RFC 7591) gives. Without this there is no way to give a
        /// `client_credentials` client a secret short of enabling dynamic registration.
        /// </summary>
        [HttpPost]
        [Route("v1/client/secret/reset")]
        public async Task<dynamic> ClientSecretReset([FromServices] DataAccess da, [FromBody] ArkClient client)
        {
            try
            {
                var stored = await da.GetClient(client.tenant_id, client.client_id)
                    ?? throw new ApplicationException("unknown client.");
                if (string.Equals(stored.token_endpoint_auth_method, "none", StringComparison.OrdinalIgnoreCase))
                    throw new ApplicationException("this is a public client (token_endpoint_auth_method 'none'); it does not use a secret.");

                var secret = Protocol.ArkCrypto.RandomToken(32);
                stored.client_secret_hash = Protocol.ArkCrypto.HashSecret(secret);
                stored.client_secret_expires_at = null; // 0 == does not expire, per RFC 7591
                await da.UpsertClient(stored);
                da.Log("client_secret_reset", $"{stored.client_id}", "Client secret reset success", $"details : ci: {stored.client_id}, ti: {stored.tenant_id}");
                return new
                {
                    error = false,
                    msg = "client secret regenerated - copy it now, it cannot be shown again.",
                    data = new { stored.client_id, stored.tenant_id, client_secret = secret }
                };
            }
            catch (Exception ex)
            {
                da.LogError(ex, "client_secret_reset", "v1/client/secret/reset", $"details : ci: {client?.client_id}, ti: {client?.tenant_id}");
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = (object?)null
                };
            }
        }
        [Route("v1/claim/list")]
        public async Task<dynamic> ClaimsList([FromServices] DataAccess da)
        {
            try
            {
                return new
                {
                    error = false,
                    msg = "claims list loaded.",
                    data = await da.GetClaims()
                };
            }
            catch (Exception ex)
            {
                da.LogError(ex, "claim_list", "v1/claim/list", "loading the claims list failed");
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = new List<ArkClaim>()
                };
            }
        }
        [HttpPost]
        [Route("v1/claim/upsert")]
        public async Task<dynamic> ClaimUpdate([FromServices] DataAccess da, [FromBody] ArkClaim claim)
        {
            try
            {
                await da.UpsertClaim(claim);
                return new
                {
                    error = false,
                    msg = "claims updated.",
                    data = claim
                };
            }
            catch (Exception ex)
            {
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = claim
                };
            }
        }
        [HttpPost]
        [Route("v1/claim/delete")]
        public async Task<dynamic> ClaimDelete([FromServices] DataAccess da, [FromBody] ArkClaim claim)
        {
            try
            {
                await da.DeleteClaim(claim);
                da.Log("claim_delete", $"{claim.key}", "Claim deleted success", $"details : k: {claim.key}, d: {claim.display}");
                return new
                {
                    error = false,
                    msg = "claim deleted.",
                    data = claim
                };
            }
            catch (Exception ex)
            {
                da.LogError(ex, "claim_delete", "v1/claim/delete", $"details : k: {claim?.key}");
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = claim
                };
            }
        }
        [Route("v1/scope/list")]
        public async Task<dynamic> ScopeList([FromServices] DataAccess da)
        {
            try
            {
                return new
                {
                    error = false,
                    msg = "scopes list loaded.",
                    data = await da.GetScopes()
                };
            }
            catch (Exception ex)
            {
                da.LogError(ex, "scope_list", "v1/scope/list", "loading the scopes list failed");
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = new List<ArkScope>()
                };
            }
        }
        [HttpPost]
        [Route("v1/scope/upsert")]
        public async Task<dynamic> ScopeUpdate([FromServices] DataAccess da, [FromBody] ArkScope scope)
        {
            try
            {
                await da.UpsertScope(scope);
                da.Log("scope_upsert", $"{scope.name}", "Scope updated success", $"details : n: {scope.name}, d: {scope.display}, claims: {scope.claims_}");
                return new
                {
                    error = false,
                    msg = "scope updated.",
                    data = scope
                };
            }
            catch (Exception ex)
            {
                da.LogError(ex, "scope_upsert", "v1/scope/upsert", $"details : n: {scope?.name}, claims: {scope?.claims_}");
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = scope
                };
            }
        }
        [HttpPost]
        [Route("v1/scope/delete")]
        public async Task<dynamic> ScopeDelete([FromServices] DataAccess da, [FromBody] ArkScope scope)
        {
            try
            {
                await da.DeleteScope(scope);
                da.Log("scope_delete", $"{scope.name}", "Scope deleted success", $"details : n: {scope.name}, d: {scope.display}");
                return new
                {
                    error = false,
                    msg = "scope deleted.",
                    data = scope
                };
            }
            catch (Exception ex)
            {
                da.LogError(ex, "scope_delete", "v1/scope/delete", $"details : n: {scope?.name}");
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = scope
                };
            }
        }
        /// <summary>
        /// Every account on the server.
        ///
        /// Wrapped, like the writes above, because the one failure this endpoint actually has is
        /// a schema behind the entities — a database that never ran the script adding
        /// "users"."is_active" throws here on the SELECT itself. Unhandled, that is a 500 with no
        /// body: the console's grid comes up empty and neither the operator nor the audit trail
        /// is told why. Start-up now applies pending scripts on its own (see ArkSchemaUpdater),
        /// so this is the second line of defence rather than the first.
        /// </summary>
        [Route("v1/user/list")]
        public async Task<dynamic> UserList([FromServices] DataAccess da)
        {
            try
            {
                return new
                {
                    error = false,
                    msg = "users list loaded.",
                    data = await da.GetUsers()
                };
            }
            catch (Exception ex)
            {
                da.LogError(ex, "user_list", "v1/user/list", "loading the user list failed");
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = new List<ArkUser>()
                };
            }
        }
        [Route("v1/user/list/client/claims/mapping/{email}/{ten_id}")]
        public async Task<dynamic> UserClientCLaimsList([FromRoute] string email, [FromRoute] string ten_id, [FromServices] DataAccess da)
        {
            try
            {
                return new
                {
                    error = false,
                    msg = $"users mapping list loaded.",
                    data = await da.GetUsersClientClaims(email, ten_id)
                };
            }
            catch (Exception ex)
            {
                da.LogError(ex, "user_mapping_list", "v1/user/list/client/claims/mapping", $"details : e: {email}, ti: {ten_id}");
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = new List<ArkUserClientClaim>()
                };
            }
        }
        [HttpPost]
        [Route("v1/user/client/claims/upsert")]
        public async Task<dynamic> UserClaimsUpdate([FromServices] DataAccess da, [FromBody] ArkUserClientClaim us_cl)
        {
            try
            {
                await da.UpsertUsersClientClaims(us_cl);
                da.Log("user_cl_cl_upsert", "v1/user/client/claims/upsert", "user client claims updated", $"deails : e: {us_cl?.email}, ci: {us_cl?.client_id}, claims: {us_cl?.claims_}");
                return new
                {
                    error = false,
                    msg = "user client claims updated.",
                    data = us_cl
                };
            }
            catch (Exception ex)
            {
                da.LogError(ex, "user_cl_cl_upsert", "v1/user/client/claims/upsert", $"deails : e: {us_cl?.email}, ci: {us_cl?.client_id}, claims: {us_cl?.claims_}");
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = us_cl
                };
            }
        }
        [HttpPost]
        [Route("v1/user/client/claims/delete")]
        public async Task<dynamic> UserClaimsDelete([FromServices] DataAccess da, [FromBody] ArkUserClientClaim us_cl)
        {
            try
            {
                await da.DeleteUsersClientClaims(us_cl);
                da.Log("user_cl_cl_delete", "v1/user/client/claims/delete", "delete client claims updated", $"deails : e: {us_cl?.email}, ci: {us_cl?.client_id}, claims: {us_cl?.claims_}");
                return new
                {
                    error = false,
                    msg = "user client claims mapping deleted.",
                    data = us_cl
                };
            }
            catch (Exception ex)
            {
                da.LogError(ex, "user_cl_cl_delete", "v1/user/client/claims/elete", $"deails : e: {us_cl?.email}, ci: {us_cl?.client_id}, claims: {us_cl?.claims_}");
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = us_cl
                };
            }
        }
        [HttpPost]
        [Route("v1/user/upsert")]
        public async Task<dynamic> UserUpdate([FromServices] DataAccess da, [FromBody] ArkUser user)
        {
            try
            {
                var existing = await da.GetUser((user?.email ?? "").ToLower().Trim());
                var saved = await da.UpsertUser(user);
                da.Log("user_upsert", "v1/user/upsert", "user updated", $"deails : e: {user?.email}, name: {user?.name}, rm: {user?.reset_mode}");
                // A new account is usable in one of two ways, and which one it is decides what the
                // operator has to do next — so say so rather than reporting a bare "user updated."
                var msg = existing != null
                    ? "user updated."
                    : (saved.reset_mode ?? false)
                        ? ((saved.emailed ?? false)
                            ? "user created - an activation link has been emailed."
                            : "user created, but the activation email could not be sent - use 'Reset password' to retry.")
                        : "user created - it signs in with the configured default password (ark_oauth_server:DefaultPw).";
                return new
                {
                    error = false,
                    msg,
                    data = saved
                };
            }
            catch (Exception ex)
            {
                da.LogError(ex, "user_upsert", "v1/user/upsert", $"deails : e: {user?.email}, name: {user?.name}, rm: {user?.reset_mode}");
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = user
                };
            }
        }
        [HttpPost]
        [Route("v1/user/pw/reset/init")]
        public async Task<dynamic> UserPasswordResetInit([FromServices] DataAccess da, [FromBody] ArkUser user)
        {
            try
            {
                var dd = await da.UserResetPw(user);
                return new
                {
                    error = !(dd.emailed ?? false),
                    msg = (dd.emailed ?? false) ? "user reset password request initiated." : "user reset password request failed",
                    data = user
                };
            }
            catch (Exception ex)
            {
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = user
                };
            }
        }
        [HttpPost]
        [Route("v1/user/pw/set")]
        public async Task<dynamic> UserPasswordSet([FromServices] DataAccess da, [FromBody] ArkPasswordChangeRequest request)
        {
            try
            {
                var saved = await da.SetUserPassword(request?.email, request?.password);
                da.Log("user_password_set", "v1/user/pw/set", "user password updated", $"details : e: {saved?.email}");
                return new
                {
                    error = false,
                    msg = "password updated.",
                    data = new { saved.email, saved.at }
                };
            }
            catch (Exception ex)
            {
                da.LogError(ex, "user_password_set", "v1/user/pw/set", $"details : e: {request?.email}");
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = request
                };
            }
        }
        [HttpPost]
        [Route("v1/service/pw/reset")]
        public async Task<dynamic> ServiceUserRegenerateToken([FromServices] DataAccess da, [FromServices] TokenServer ts, [FromBody] ArkUserClientClaim us_cl)
        {
            try
            {
                ArkUser user = await da.GetUser(us_cl.email);
                ArkTenant tnt = await da.GetTenant(us_cl.tenant_id);
                user.hash_pw = (await ts.BuildAsymmetric_AccessToken(tnt, new System.Security.Claims.Claim[] { new System.Security.Claims.Claim("service_role", "service_role") }, 525600)).Item1;
                var dd = await da.UserResetPw(user);
                return new
                {
                    msg = "service account token reset completed.",
                    data = user
                };
            }
            catch (Exception ex)
            {
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = us_cl
                };
            }
        }
        [Route("onboard/full")]
        public async Task<dynamic> OnboardFull([FromServices] Onboard onb,
            [FromQuery] string ten_id,
            [FromQuery] string client_id,
            [FromQuery] string suffix,
            [FromQuery] string client_base_url,
            [FromQuery] string client_relative_url,
            [FromQuery] string claim_keys, //"claim1, claim2"
            [FromQuery] string user_email,
            [FromQuery] string user_suffix,
            [FromQuery] string user_type)
        {
            try
            {
                await onb.FullSet(ten_id,
                    client_id,
                    suffix,
                    client_base_url,
                    client_relative_url,
                    (claim_keys ?? "").Split(',').Where(t => !string.IsNullOrWhiteSpace(t)).Select(t => t.Trim()).ToList(),
                    user_email,
                    user_suffix,
                    user_type);
                return new
                {
                    error = false,
                    msg = $"onboarded client {client_id} to tenant {ten_id}"
                };
            }
            catch (Exception ex)
            {
                return new
                {
                    error = true,
                    msg = $"{ex.Message}"
                };
            }
        }
        [Route("onboard/user")]
        public async Task<dynamic> OnboardUser([FromServices] Onboard onb,
            [FromQuery] string ten_id,
            [FromQuery] string client_id,
            [FromQuery] string claim_keys, //"claim1, claim2"
            [FromQuery] string user_email,
            [FromQuery] string user_pw,
            [FromQuery] string full_name,
            [FromQuery] string user_type)
        {
            try
            {
                await onb.UserOnboard(ten_id,
                    client_id,
                    (claim_keys ?? "").Split(',').Where(t => !string.IsNullOrWhiteSpace(t)).Select(t => t.Trim()).ToList(),
                    user_email,
                    user_pw,
                    full_name,
                    user_type);
                return new
                {
                    error = false,
                    msg = $"onboarded user {user_email} to client_id: {client_id}."
                };
            }
            catch (Exception ex)
            {
                return new
                {
                    error = true,
                    msg = $"{ex.Message}"
                };
            }
        }
    }
}
