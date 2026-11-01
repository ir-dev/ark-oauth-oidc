using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Ark.oAuth
{
    /// <summary>
    /// The three endpoints the access-denied page needs, served as middleware rather than as
    /// routed controller actions.
    ///
    /// Middleware, because the page has to render for a user who is not signed in and may not be
    /// allowed to be. A controller action would sit behind the authorization middleware, and in an
    /// application with a fallback policy — which is the sort of application that hits this
    /// problem — a page that requires authentication to explain why authentication failed is a
    /// redirect loop. Short-circuiting ahead of routing sidesteps that entirely, and means the
    /// host does not have to remember to map anything.
    /// </summary>
    internal sealed class ArkAccountEndpoints
    {
        private readonly RequestDelegate _next;
        private readonly ArkAuthConfig _config;

        public ArkAccountEndpoints(RequestDelegate next, ArkAuthConfig config)
        {
            _next = next;
            _config = config;
        }

        public async Task Invoke(HttpContext context)
        {
            var options = _config.AccountSwitch;
            if (options is not { Enabled: true }) { await _next(context); return; }

            if (Matches(context, options.SwitchUserPath))
            {
                if (!await GuardAsync(context)) return;
                var form = context.Request.HasFormContentType ? await context.Request.ReadFormAsync() : null;
                await context.ArkSwitchUserAsync(Field(context, form, "returnUrl"), Field(context, form, "login_hint"));
                return;
            }

            if (Matches(context, options.SignOutPath))
            {
                if (!options.AllowFullSignOut) { context.Response.StatusCode = StatusCodes.Status404NotFound; return; }
                if (!await GuardAsync(context)) return;
                var form = context.Request.HasFormContentType ? await context.Request.ReadFormAsync() : null;
                await context.ArkSignOutEverywhereAsync(Field(context, form, "returnUrl"));
                return;
            }

            if (options.ServeDefaultPage && Matches(context, options.AccessDeniedPath))
            {
                await ArkAccessDeniedPage.RenderAsync(context, _config);
                return;
            }

            await _next(context);
        }

        /// <summary>
        /// Form first, then the query string. StringValues returns an empty string rather than
        /// null for an absent key, so a null-coalescing chain would stop at the form and never
        /// look at the query.
        /// </summary>
        private static string? Field(HttpContext context, IFormCollection? form, string name)
        {
            var value = form?[name].ToString();
            if (!string.IsNullOrEmpty(value)) return value;
            value = context.Request.Query[name].ToString();
            return string.IsNullOrEmpty(value) ? null : value;
        }

        private static bool Matches(HttpContext context, string? path) =>
            !string.IsNullOrWhiteSpace(path) &&
            context.Request.Path.Equals(new PathString(path), StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// POST, from this origin.
        ///
        /// Neither endpoint is a security boundary — the worst a forged request achieves is an
        /// unwanted sign-out — but a cross-site page should not be able to end a user's session,
        /// and requiring a POST from the same origin costs nothing. The library cannot use MVC's
        /// antiforgery token because <c>IAntiforgery</c> is only registered when the host has
        /// added MVC or Razor Pages, and this middleware runs in hosts that have added neither.
        /// </summary>
        private static async Task<bool> GuardAsync(HttpContext context)
        {
            if (!HttpMethods.IsPost(context.Request.Method))
            {
                context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                context.Response.Headers["Allow"] = "POST";
                await context.Response.WriteAsync("POST required.");
                return false;
            }

            var fetchSite = context.Request.Headers["Sec-Fetch-Site"].ToString();
            if (!string.IsNullOrEmpty(fetchSite))
            {
                if (fetchSite is not ("same-origin" or "none"))
                {
                    context.Response.StatusCode = StatusCodes.Status400BadRequest;
                    await context.Response.WriteAsync("cross-site request rejected.");
                    return false;
                }
                return true;
            }

            var origin = context.Request.Headers["Origin"].ToString();
            if (string.IsNullOrEmpty(origin)) return true; // not a browser form post
            if (string.Equals(origin, $"{context.Request.Scheme}://{context.Request.Host.Value}",
                    StringComparison.OrdinalIgnoreCase))
                return true;

            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("cross-site request rejected.");
            return false;
        }

        /// <summary>
        /// Keeps a return URL inside this application. Echoing an arbitrary one would turn the
        /// access-denied page into an open redirect, which is a phishing primitive.
        /// </summary>
        internal static string LocalOrDefault(string? url, string? fallback)
        {
            var home = string.IsNullOrWhiteSpace(fallback) ? "/" : fallback!;
            if (string.IsNullOrWhiteSpace(url)) return home;
            var candidate = url!.Trim();
            if (candidate.Length == 0 || candidate[0] != '/') return home;
            if (candidate.StartsWith("//", StringComparison.Ordinal)) return home;   // protocol-relative
            if (candidate.StartsWith("/\\", StringComparison.Ordinal)) return home;  // backslash variant
            if (candidate.Any(char.IsControl)) return home;
            return candidate;
        }
    }

    /// <summary>Registers <see cref="ArkAccountEndpoints"/>. Called for you by <c>UseArkOidcClient</c>.</summary>
    public static class ArkAccountMiddlewareExtensions
    {
        /// <summary>
        /// Serves the access-denied page and the switch-user / sign-out posts.
        ///
        /// Idempotent: <c>UseArkOidcClient</c> already calls it, and calling it again is a no-op
        /// rather than a second copy of the middleware.
        /// </summary>
        public static IApplicationBuilder UseArkAccountEndpoints(this IApplicationBuilder builder)
        {
            const string registered = "ark.account.endpoints";
            if (builder.Properties.ContainsKey(registered)) return builder;
            builder.Properties[registered] = true;

            var config = builder.ApplicationServices.GetService<ArkAuthConfig>();
            if (config == null || config.UseLegacyFlow) return builder;
            if (config.AccountSwitch is not { Enabled: true }) return builder;

            return builder.UseMiddleware<ArkAccountEndpoints>(config);
        }
    }
}
