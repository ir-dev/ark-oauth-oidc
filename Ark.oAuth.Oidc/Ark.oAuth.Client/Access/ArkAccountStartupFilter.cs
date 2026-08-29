using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;

namespace Ark.oAuth
{
    /// <summary>
    /// Puts the account endpoints into the pipeline without the host having to remember a
    /// <c>Use…</c> call.
    ///
    /// The endpoints exist for a user who is stuck, and an application whose Program.cs predates
    /// this feature is exactly the one whose users are stuck. A startup filter registers them for
    /// every host that calls <c>AddArkOidcClient</c>, at the front of the pipeline, where nothing
    /// can redirect the page away before it renders.
    ///
    /// It is idempotent with <c>UseArkAccountEndpoints</c>: the first registration wins, so a host
    /// that also calls it explicitly does not get two copies. To choose the position yourself —
    /// behind forwarded headers or an HTTPS redirect, say — set
    /// <c>AccountSwitch:AutoRegisterEndpoints</c> to false and call it where you want it.
    /// </summary>
    internal sealed class ArkAccountStartupFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) =>
            builder =>
            {
                builder.UseArkAccountEndpoints();
                next(builder);
            };
    }
}
