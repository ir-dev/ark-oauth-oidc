using System.Net;
using Ark.oAuth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Ark.Client.Web.Controllers
{
    /// <summary>
    /// Who may open the pages that hold the IdP's machine credential.
    ///
    /// <c>/flows/machine</c> and <c>/flows/register</c> act with the machine client's secret, and on
    /// the operator tenant that client <i>is</i> the operator: it creates accounts, grants access and
    /// removes clients. Whatever those pages can do, whoever can open them can do — an antiforgery
    /// token says the form came from this app, not who sent it.
    ///
    /// So they need somebody signed in here who holds the operator role
    /// (<c>sample:OperatorRole</c>, <c>sample.operator</c> unless set). The one exception is a
    /// developer at this machine, in Development: the first use of the register page is to create
    /// the client that signing in needs.
    /// </summary>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public sealed class OperatorOnlyAttribute : Attribute, IAuthorizationFilter
    {
        public void OnAuthorization(AuthorizationFilterContext context)
        {
            if (context.ActionDescriptor.EndpointMetadata.OfType<IAllowAnonymous>().Any()) return;

            var http = context.HttpContext;
            if (IsLocalDevelopment(http)) return;

            if (http.User.Identity?.IsAuthenticated != true)
            {
                context.Result = new ChallengeResult();
                return;
            }

            var services = http.RequestServices;
            var roleType = services.GetRequiredService<ArkAuthConfig>().RoleClaimType ?? "role";
            if (!http.User.HasClaim(roleType, Role(services.GetRequiredService<IConfiguration>())))
                context.Result = new ForbidResult();
        }

        public static string Role(IConfiguration configuration) =>
            configuration["sample:OperatorRole"] is { Length: > 0 } role ? role : "sample.operator";

        /// <summary>
        /// Development, and a browser on this machine asking for this machine. The Host header is
        /// part of that: a proxy here, or a name somebody pointed at 127.0.0.1, also arrives over
        /// loopback.
        /// </summary>
        private static bool IsLocalDevelopment(HttpContext http)
        {
            if (!http.RequestServices.GetRequiredService<IWebHostEnvironment>().IsDevelopment()) return false;
            if (http.Request.Headers.ContainsKey("X-Forwarded-For")) return false;

            var from = http.Connection.RemoteIpAddress;
            if (from == null || !IPAddress.IsLoopback(from)) return false;

            var host = http.Request.Host.Host.Trim('[', ']');
            return host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
                || (IPAddress.TryParse(host, out var address) && IPAddress.IsLoopback(address));
        }
    }
}
