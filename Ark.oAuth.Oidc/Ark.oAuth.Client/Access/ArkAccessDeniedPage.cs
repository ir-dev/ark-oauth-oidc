using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Ark.oAuth
{
    /// <summary>
    /// The built-in dead end.
    ///
    /// Self-contained HTML with inlined styles and no script: it has to render in an application
    /// that has no view engine, no static files and a strict Content-Security-Policy, and it is
    /// the one page a stuck user sees, so it cannot itself depend on anything.
    ///
    /// Replace it by pointing <c>AccessDeniedPath</c> at your own route and setting
    /// <c>ServeDefaultPage</c> to false; <c>HttpContext.ArkDeniedAccount()</c> gives your page the
    /// same information, and the two POST endpoints keep working.
    /// </summary>
    internal static class ArkAccessDeniedPage
    {
        public static async Task RenderAsync(HttpContext context, ArkAuthConfig config)
        {
            var options = config.AccountSwitch ?? new ArkAccountSwitchOptions();
            var denied = ArkAccessDeniedState.Read(context);

            // Spent on read: a stale cookie must not name the wrong account on a later visit.
            ArkAccessDeniedState.Clear(context);

            string? email = denied?.email, name = denied?.name;
            if (email == null && name == null)
            {
                // Arrived from a 403 rather than from a refused callback, so there is a session to
                // read the account off.
                var result = await context.AuthenticateAsync(ArkOidcClient.CookieScheme);
                if (result.Succeeded)
                {
                    email = result.Principal?.FindFirst("email")?.Value
                            ?? result.Principal?.FindFirst("preferred_username")?.Value;
                    name = result.Principal?.FindFirst("name")?.Value;
                }
            }

            var account = options.ShowSignedInAccount ? (email ?? name) : null;
            var app = string.IsNullOrWhiteSpace(options.AppDisplayName) ? config.ClientId : options.AppDisplayName;
            var queryReturn = context.Request.Query["returnUrl"].ToString();
            var returnUrl = ArkAccountEndpoints.LocalOrDefault(
                string.IsNullOrEmpty(queryReturn) ? denied?.return_url : queryReturn, options.HomePath);

            var html = Build(options, app, account, returnUrl);

            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.ContentType = "text/html; charset=utf-8";
            context.Response.Headers["Cache-Control"] = "no-store, no-cache";
            context.Response.Headers["Pragma"] = "no-cache";
            await context.Response.WriteAsync(html, Encoding.UTF8);
        }

        private static string Build(ArkAccountSwitchOptions options, string? app, string? account, string returnUrl)
        {
            var e = HtmlEncoder.Default;
            var appName = e.Encode(string.IsNullOrWhiteSpace(app) ? "this application" : app!);
            var target = e.Encode(returnUrl);
            var home = e.Encode(ArkAccountEndpoints.LocalOrDefault(options.HomePath, "/"));

            var lede = account == null
                ? $"The account you are signed in with does not have access to {appName}."
                : $"You are signed in as <strong>{e.Encode(account)}</strong>, and that account does not have access to {appName}.";

            var sb = new StringBuilder();
            sb.Append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">");
            sb.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
            sb.Append("<title>No access — ").Append(appName).Append("</title><style>");
            sb.Append(":root{--bg:#f7f7f8;--surface:#fff;--border:#e2e2e6;--fg:#17171a;--muted:#6a6a73;--accent:#4f46e5;--accent-fg:#fff}");
            sb.Append("@media(prefers-color-scheme:dark){:root{--bg:#111114;--surface:#1a1a1f;--border:#313139;--fg:#ececf1;--muted:#9a9aa5;--accent:#8b85ff;--accent-fg:#16161c}}");
            sb.Append("*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;");
            sb.Append("background:var(--bg);color:var(--fg);font:15px/1.55 ui-sans-serif,-apple-system,\"Segoe UI\",Roboto,Helvetica,Arial,sans-serif}");
            sb.Append(".card{width:100%;max-width:480px;background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:28px}");
            sb.Append("h1{margin:0 0 10px;font-size:19px;font-weight:640}p{margin:0 0 14px;color:var(--muted)}p.lede{color:var(--fg)}");
            sb.Append("form{margin:0}.actions{display:flex;flex-direction:column;gap:10px;margin-top:20px}");
            sb.Append("button{width:100%;padding:11px 14px;border-radius:8px;border:1px solid var(--accent);background:var(--accent);color:var(--accent-fg);");
            sb.Append("font:inherit;font-weight:560;cursor:pointer}button.secondary{background:transparent;color:var(--fg);border-color:var(--border)}");
            sb.Append(".foot{margin-top:18px;padding-top:14px;border-top:1px solid var(--border);font-size:13px;color:var(--muted)}");
            sb.Append(".foot a{color:var(--accent)}");
            sb.Append(".ver{margin:18px 0 0;padding-top:14px;border-top:1px solid var(--border);font-size:12px;color:var(--muted);text-align:center}");
            // One rule above the fold, not two: when the support line is drawn it already carries
            // the separator, so the version tucks under it instead of ruling the card twice.
            sb.Append(".foot+.ver{margin-top:8px;padding-top:0;border-top:0}");
            sb.Append("</style></head><body><main class=\"card\">");

            sb.Append("<h1>You do not have access to ").Append(appName).Append("</h1>");
            sb.Append("<p class=\"lede\">").Append(lede).Append("</p>");
            sb.Append("<p>If somebody else was using this browser, their sign-in is still active and it is the one being offered to ")
              .Append(appName).Append(". Choose “Sign in as a different user” to enter your own credentials.</p>");

            sb.Append("<div class=\"actions\">");

            sb.Append("<form method=\"post\" action=\"").Append(e.Encode(options.SwitchUserPath)).Append("\">");
            sb.Append("<input type=\"hidden\" name=\"returnUrl\" value=\"").Append(target).Append("\">");
            sb.Append("<button type=\"submit\">Sign in as a different user</button></form>");

            if (options.AllowFullSignOut)
            {
                sb.Append("<form method=\"post\" action=\"").Append(e.Encode(options.SignOutPath)).Append("\">");
                sb.Append("<input type=\"hidden\" name=\"returnUrl\" value=\"").Append(home).Append("\">");
                sb.Append("<button class=\"secondary\" type=\"submit\">Sign out completely</button></form>");
            }

            sb.Append("</div>");

            if (!string.IsNullOrWhiteSpace(options.SupportUrl) || !string.IsNullOrWhiteSpace(options.SupportEmail))
            {
                sb.Append("<p class=\"foot\">Need access to ").Append(appName).Append("? ");
                if (!string.IsNullOrWhiteSpace(options.SupportUrl))
                    sb.Append("<a href=\"").Append(e.Encode(options.SupportUrl!)).Append("\">Request it here</a>");
                else
                    sb.Append("<a href=\"mailto:").Append(e.Encode(options.SupportEmail!)).Append("\">")
                      .Append(e.Encode(options.SupportEmail!)).Append("</a>");
                sb.Append("</p>");
            }

            // Which client library drew this page. It is the one screen a stuck user is looking
            // at while somebody tries to work out why the account is wrong, and the version is
            // otherwise a file property on a server they cannot reach.
            sb.Append("<p class=\"ver\">Ark.oAuth.Client ").Append(e.Encode(ArkOidcClient.Version)).Append("</p>");

            sb.Append("</main></body></html>");
            return sb.ToString();
        }
    }
}
