using System.Security.Claims;

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

            var admin = config?.AdminUser?.Username;
            if (!string.IsNullOrWhiteSpace(admin))
            {
                foreach (var type in new[] { "sub", "email", "preferred_username", ClaimTypes.Name })
                {
                    var value = user.FindFirst(type)?.Value;
                    if (!string.IsNullOrWhiteSpace(value) &&
                        string.Equals(value.Trim(), admin.Trim(), StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }

            return user.IsInRole("admin") || user.IsInRole("ark_admin");
        }
    }
}
