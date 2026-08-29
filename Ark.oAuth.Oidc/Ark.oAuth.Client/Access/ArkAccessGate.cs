using System.Security.Claims;
using Microsoft.AspNetCore.Http;

namespace Ark.oAuth
{
    /// <summary>
    /// Decides, once per sign-in, whether the account the provider authenticated is entitled to
    /// this application, and drives the denial when it is not.
    ///
    /// The check belongs at the callback rather than at each <c>[Authorize]</c>. An entitlement
    /// failure is not "this user may not open that page", it is "this user may not use this
    /// application at all", and the difference is visible in what happens next: refuse at the
    /// callback and no cookie is ever written, so the person at the keyboard is not left holding
    /// somebody else's session while every page they open answers 403.
    /// </summary>
    internal static class ArkAccessGate
    {
        public static async Task<bool> AllowedAsync(
            HttpContext http, ArkAuthConfig config, ArkClientEvents? events,
            ClaimsPrincipal? principal, IReadOnlyList<string> arkClaims)
        {
            var options = config.AccountSwitch ?? new ArkAccountSwitchOptions();

            var allowed = !options.RequireArkClaims
                || (options.RequiredClaims is { Count: > 0 }
                    ? arkClaims.Any(c => options.RequiredClaims!.Contains(c, StringComparer.OrdinalIgnoreCase))
                    : arkClaims.Count > 0);

            if (events?.OnEvaluateAccess == null) return allowed;

            // The host's rule replaces the configured one outright rather than being ANDed with
            // it — a handler that wants both can read AllowedByConfiguration and say so.
            return await events.OnEvaluateAccess(new ArkAccessEvaluationContext(http)
            {
                Principal = principal,
                ArkClaims = arkClaims,
                AllowedByConfiguration = allowed
            });
        }

        public static async Task DenyAsync(
            HttpContext http, ArkAuthConfig config, ArkClientEvents? events, string reason,
            ClaimsPrincipal? principal, IReadOnlyList<string> arkClaims, string? returnUrl)
        {
            var options = config.AccountSwitch ?? new ArkAccountSwitchOptions();

            string? Claim(params string[] types) => types
                .Select(t => principal?.FindFirst(t)?.Value)
                .FirstOrDefault(v => !string.IsNullOrEmpty(v));

            var denied = new ArkAccessDeniedContext(http)
            {
                Reason = reason,
                Subject = Claim("sub", ClaimTypes.NameIdentifier),
                Email = Claim("email", "preferred_username", ClaimTypes.Email),
                Name = Claim("name", ClaimTypes.Name),
                ArkClaims = arkClaims,
                ReturnUrl = returnUrl
            };

            if (events?.OnAccessDenied != null)
            {
                await events.OnAccessDenied(denied);
                if (denied.Handled) return;
            }

            ArkAccessDeniedState.Write(http, new ArkDeniedAccount
            {
                subject = denied.Subject,
                email = denied.Email,
                name = denied.Name,
                reason = denied.Reason,
                return_url = returnUrl
            });

            var path = string.IsNullOrWhiteSpace(options.AccessDeniedPath) ? "/ark/no-access" : options.AccessDeniedPath;
            var target = path;
            if (!string.IsNullOrWhiteSpace(returnUrl))
                target += (path.Contains('?') ? "&" : "?") + "returnUrl=" + Uri.EscapeDataString(returnUrl!);

            http.Response.Redirect(target);
        }

        /// <summary>The authorization claims Ark issued for this client, read off the access token.</summary>
        public static IReadOnlyList<string> ReadClaims(string? accessToken) =>
            string.IsNullOrEmpty(accessToken)
                ? Array.Empty<string>()
                : ArkClaimReader.ReadArkClaims(accessToken!).ToList();
    }
}
