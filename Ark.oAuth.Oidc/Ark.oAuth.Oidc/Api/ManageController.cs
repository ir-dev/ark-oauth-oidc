using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Ark.oAuth.Oidc
{
    [Authorize]
    [Route("api/oauth")]
    [ApiController]
    public class ManageController : ControllerBase
    {
        [Route("v1/tenant/list")]
        public async Task<dynamic> TenantList([FromServices] DataAccess da)
        {
            return new
            { 
                error = false,
                msg = "tenatns list loaded.",
                data = await da.GetTenants() 
            };
        }
        [HttpPost]
        [Route("v1/tenant/upsert")]
        public async Task<dynamic> TenantUpdate([FromServices] DataAccess da, [FromBody] ArkTenant tenant)
        {
            if (string.IsNullOrEmpty(tenant.rsa_private))
            {
                dynamic dd = await ArkUtil.GetKeys();
                tenant.rsa_private = dd.private_key;
                tenant.rsa_public = dd.public_key;
            }
            await da.UpsertTenant(tenant);
            return new
            {
                error = false,
                msg = "tenatns updated successfully.",
                data = tenant
            };
        }
        [Route("v1/client/list")]
        public async Task<dynamic> ClientList([FromServices] DataAccess da)
        {
            return new
            {
                error = false,
                msg = "clients list loaded.",
                data = await da.GetClients()
            };
        }
        [HttpPost]
        [Route("v1/client/upsert")]
        public async Task<dynamic> ClientUpdate([FromServices] DataAccess da, [FromBody] ArkClient client)
        {
            try
            {
                await da.UpsertClient(client);
                return new
                {
                    error = false,
                    msg = "clients updated.",
                    data = client
                };
            }
            catch (Exception ex)
            {
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = client
                };
            }
        }
    }
}
