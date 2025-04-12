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
            return new
            {
                error = false,
                msg = "tenatns list loaded.",
                data = await da.GetTenants()
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
        public async Task<dynamic> ClientUpdate([FromServices] DataAccess da, [FromBody] ArkClient tenant)
        {
            return new
            {
                error = false,
                msg = "clients list loaded.",
                data = await da.GetClients()
            };
        }
    }
}
