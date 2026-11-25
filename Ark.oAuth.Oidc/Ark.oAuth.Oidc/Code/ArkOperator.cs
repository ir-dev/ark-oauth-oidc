using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Ark.oAuth.Oidc
{
    /// <summary>
    /// Whether a signed-in principal is the operator account.
    ///
    /// Two ways to be one, because there are two ways deployments describe it:
    ///
    ///   * the account named by <c>ark_oauth_server:AdminUser:Username</c> — the one seeded
    ///     when the database was created, matched against whichever of sub / email /
    ///     preferred_username the host's handler put on the principal;
    ///   * an <c>admin</c> authorization claim, which arrives as a role because the Ark client
    ///     projects <c>ark_claims</c> onto the configured role claim type. That is how an
    ///     operator who is not the seeded account gets in, without a second setting.
    ///
    /// Deliberately not a claim on the access token alone: the seeded administrator has no
    /// "admin" claim on it, and locking a route to a claim nobody has yet would make it
    /// unreachable on every existing deployment.
    ///
    /// Shared rather than private to the console, because the routes that can damage the
    /// deployment as a whole — rolling the schema back, writing files to disk — have to answer
    /// to the same test the provisioning page does, not to a bare <c>[Authorize]</c>.
    /// </summary>
    public static class ArkOperator
    {
        public static bool IsOperator(ClaimsPrincipal? user, ArkAuthServerConfig? config)
        {
            if (user?.Identity?.IsAuthenticated != true) return false;
            return IsNamed(user, config) || user.IsInRole("admin") || user.IsInRole("ark_admin");
        }

        /// <summary>Whether the principal is the account <c>AdminUser:Username</c> names.</summary>
        private static bool IsNamed(ClaimsPrincipal user, ArkAuthServerConfig? config)
        {
            var admin = config?.AdminUser?.Username;
            if (string.IsNullOrWhiteSpace(admin)) return false;
            foreach (var type in new[] { "sub", "email", "preferred_username", ClaimTypes.Name })
            {
                var value = user.FindFirst(type)?.Value;
                if (!string.IsNullOrWhiteSpace(value) &&
                    string.Equals(value.Trim(), admin.Trim(), StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        /// <summary>
        /// The same question, answered by the claims and then by the database as it is now.
        ///
        /// <see cref="IsOperator"/> reads what the sign-in left in a cookie. On a host whose
        /// console is <c>AddArkOidcClient</c> nothing read it again for as long as that cookie
        /// lived: an operator who had been deactivated, or lost the admin claim, kept every
        /// management right, an export of all signing keys included. Whatever lets an operator
        /// change or read the deployment asks here.
        ///
        /// A principal this server did not sign in (a host with a directory of its own) is taken
        /// at its claims, as before, unless the login id is an account here that is switched off.
        /// Asked of the database once per request; nothing is remembered between two.
        /// </summary>
        public static async Task<bool> IsOperatorNowAsync(HttpContext http, ClaimsPrincipal? user, ArkAuthServerConfig? config)
        {
            if (!IsOperator(user, config)) return false;
            if (http.Items.TryGetValue(AnswerKey, out var known) && known is (ClaimsPrincipal who, bool answer) && ReferenceEquals(who, user))
                return answer;
            var stands = await StandsAsync(http, user!, config!);
            http.Items[AnswerKey] = (user!, stands);
            return stands;
        }

        private static readonly object AnswerKey = new();

        private static async Task<bool> StandsAsync(HttpContext http, ClaimsPrincipal principal, ArkAuthServerConfig config)
        {
            var tenant = (config.TenantId ?? "").Trim();
            var subject = principal.FindFirst("sub");
            var ours = IssuedHere(subject, config, tenant);

            var db = http.RequestServices.GetRequiredService<ArkDataContext>();
            var login = subject?.Value ?? principal.FindFirst("email")?.Value ?? principal.FindFirst("preferred_username")?.Value;
            var account = await Protocol.ArkLookup.UserAsync(db, login);
            if (account == null) return !ours;
            if (!account.is_active) return false;
            if (!ours) return true;
            if (await ArkConsoleSession.EndedAsync(principal, account, db, config)) return false;
            if (IsNamed(principal, config)) return true;

            // Operator by claim: it has to be on the mapping still, to the client the console signs
            // in as.
            var console = await Protocol.ArkLookup.ClientAsync(db, tenant, await ConsoleClientIdAsync(http, tenant));
            var mapping = console == null ? null
                : await Protocol.ArkLookup.MappingAsync(db, account.email, console.tenant_id, console.id);
            return mapping?.claims.Any(c => c is "admin" or "ark_admin") == true;
        }

        /// <summary>
        /// Whether a claim came from this server's operator tenant. The issuer it was validated
        /// under travels with it, in the cookie as well.
        ///
        /// With no BaseUrl that issuer followed the Host of the request it was made for, and the
        /// Host of this one is the caller's to choose: the tenant is all there is to go by, and
        /// anything that ends in it is held to the database.
        /// </summary>
        private static bool IssuedHere(Claim? subject, ArkAuthServerConfig config, string tenant)
        {
            if (subject == null || tenant.Length == 0) return false;
            return string.IsNullOrWhiteSpace(config.BaseUrl)
                ? subject.Issuer.EndsWith($"/{tenant}", StringComparison.Ordinal)
                : string.Equals(subject.Issuer, Protocol.ArkOidcEndpoints.For(config, tenant).Issuer, StringComparison.Ordinal);
        }

        /// <summary>The client_id the host's console signs in as: the one its challenge sends, else the seeded one.</summary>
        private static async Task<string> ConsoleClientIdAsync(HttpContext http, string tenant)
        {
            var schemes = http.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>();
            var challenge = await schemes.GetDefaultChallengeSchemeAsync();
            if (challenge != null && typeof(OpenIdConnectHandler).IsAssignableFrom(challenge.HandlerType))
            {
                var id = http.RequestServices.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get(challenge.Name).ClientId;
                if (!string.IsNullOrWhiteSpace(id)) return id.Trim();
            }
            return $"{tenant}_client";
        }
    }

    /// <summary>
    /// Whether a console session has been ended since it was opened: the password of the account
    /// changed, its sessions were ended, or the whole server was reset or replaced.
    /// </summary>
    internal static class ArkConsoleSession
    {
        /// <summary>What the built-in console puts in its cookie at sign-in.</summary>
        internal const string StampClaim = "ark_stamp";

        /// <summary>
        /// Differs as soon as the account's password does, or the account is another one under the
        /// same name, which is what a factory reset leaves. Nothing can be worked back from it.
        /// </summary>
        internal static string Stamp(ArkUser account) =>
            Protocol.ArkCrypto.Sha256Base64Url($"{StampClaim}\n{account.id}\n{account.hash_pw}");

        internal static async Task<bool> EndedAsync(ClaimsPrincipal principal, ArkUser account, ArkDataContext db, ArkAuthServerConfig config)
        {
            // A cookie from before there was a stamp has none, and is not held to one.
            var stamp = principal.FindFirst(StampClaim)?.Value;
            if (!string.IsNullOrEmpty(stamp) && !Protocol.ArkCrypto.FixedTimeEquals(stamp, Stamp(account))) return true;

            // The session it was opened under, which every way of ending somebody's access revokes.
            var sid = principal.FindFirst("sid")?.Value;
            if (string.IsNullOrEmpty(sid)) return false;
            var session = await db.sessions.AsNoTracking().FirstOrDefaultAsync(s => s.session_id == sid);
            if (session != null) return session.revoked;

            // Gone. A session is removed once it has run out, and the console's own may outlive it;
            // one that cannot have run out yet went with everything else on the server.
            var lifetime = Math.Max(1, (config.Oidc ?? new Protocol.ArkOidcOptions()).SessionLifetimeMinutes);
            return long.TryParse(principal.FindFirst("auth_time")?.Value, out var signedIn)
                && DateTimeOffset.UtcNow.ToUnixTimeSeconds() < signedIn + lifetime * 60L;
        }
    }
}
