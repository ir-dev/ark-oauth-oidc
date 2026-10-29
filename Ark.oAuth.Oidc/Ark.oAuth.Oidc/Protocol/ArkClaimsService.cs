using Microsoft.EntityFrameworkCore;

namespace Ark.oAuth.Oidc.Protocol
{
    /// <summary>
    /// Resolves scopes to claims.
    ///
    /// Two different notions of "claim" meet here and are kept apart on purpose:
    ///  * <b>identity claims</b> — OIDC standard claims (name, email, ...) unlocked by scopes
    ///    such as `profile` and `email`. These go in the ID token and /userinfo.
    ///  * <b>authorization claims</b> — the tenant's own per-user-per-client permission strings
    ///    held in <see cref="ArkUserClientClaim"/>. These ride in the access token under
    ///    `ark_claims` and are what an application actually authorizes against.
    /// </summary>
    public class ArkClaimsService
    {
        private readonly ArkDataContext _ctx;

        public ArkClaimsService(ArkDataContext ctx)
        {
            _ctx = ctx;
        }

        /// <summary>The OIDC standard scope-to-claim mapping (OIDC Core §5.4).</summary>
        public static readonly IReadOnlyDictionary<string, string[]> StandardScopeClaims =
            new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["profile"] = new[]
                {
                    "name", "family_name", "given_name", "middle_name", "nickname",
                    "preferred_username", "profile", "picture", "website", "gender",
                    "birthdate", "zoneinfo", "locale", "updated_at"
                },
                ["email"] = new[] { "email", "email_verified" },
                ["address"] = new[] { "address" },
                ["phone"] = new[] { "phone_number", "phone_number_verified" }
            };

        /// <summary>Identity claims for the ID token and /userinfo, filtered by granted scope.</summary>
        public async Task<Dictionary<string, object>> GetIdentityClaimsAsync(string subject, List<string> scopes)
        {
            var result = new Dictionary<string, object>();
            var user = await _ctx.users.AsNoTracking().FirstOrDefaultAsync(u => u.email.ToLower() == (subject ?? "").ToLower());
            if (user == null) return result;

            var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var scope in scopes)
            {
                if (StandardScopeClaims.TryGetValue(scope, out var std))
                    foreach (var c in std) allowed.Add(c);

                var custom = await _ctx.scopes.AsNoTracking().FirstOrDefaultAsync(s => s.name == scope);
                if (custom != null)
                    foreach (var c in custom.claims) allowed.Add(c);
            }

            void Add(string claim, object? value)
            {
                if (value == null) return;
                if (value is string s && string.IsNullOrWhiteSpace(s)) return;
                if (allowed.Contains(claim)) result[claim] = value;
            }

            Add("name", user.name);
            Add("preferred_username", user.email);
            Add("email", user.email);
            Add("email_verified", !(user.reset_mode ?? false));
            if (!string.IsNullOrWhiteSpace(user.name) && allowed.Contains("given_name"))
            {
                var parts = user.name.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length > 0) result["given_name"] = parts[0];
                if (parts.Length > 1 && allowed.Contains("family_name")) result["family_name"] = parts[^1];
            }
            Add("updated_at", user.at);

            return result;
        }

        /// <summary>The tenant's per-user-per-client authorization claim strings.</summary>
        public async Task<List<string>> GetAuthorizationClaimsAsync(string subject, string tenantId, ArkClient client)
        {
            var mapping = await _ctx.user_client_claims.AsNoTracking().FirstOrDefaultAsync(m =>
                (m.email ?? "").ToLower() == (subject ?? "").ToLower() &&
                (m.tenant_id ?? "").ToLower() == (tenantId ?? "").ToLower() &&
                (m.client_id ?? "").ToLower() == (client.id ?? "").ToLower());
            return mapping?.claims ?? new List<string>();
        }

        /// <summary>
        /// Whether the subject has an access mapping to this client — the same row
        /// <see cref="DataAccess.ValidateUserCreds"/> insists on at the password prompt.
        /// </summary>
        public async Task<bool> HasClientAccessAsync(string subject, string tenantId, ArkClient client)
        {
            return await _ctx.user_client_claims.AsNoTracking().AnyAsync(m =>
                (m.email ?? "").ToLower() == (subject ?? "").ToLower() &&
                (m.tenant_id ?? "").ToLower() == (tenantId ?? "").ToLower() &&
                (m.client_id ?? "").ToLower() == (client.id ?? "").ToLower());
        }

        /// <summary>
        /// Validates the requested scopes against the catalogue and what the client is registered
        /// for. An unregistered scope is rejected rather than silently dropped, so a client never
        /// believes it holds authority it was not granted.
        /// </summary>
        public async Task<List<string>> ResolveScopesAsync(string? requested, ArkClient client)
        {
            var known = await _ctx.scopes.AsNoTracking().ToListAsync();
            var clientScopes = new HashSet<string>(client.EffectiveScopes, StringComparer.OrdinalIgnoreCase);

            var requestedList = (requested ?? "")
                .Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (requestedList.Count == 0)
            {
                var defaults = known.Where(s => s.is_default).Select(s => s.name)
                    .Where(s => clientScopes.Contains(s)).ToList();
                return defaults.Count > 0 ? defaults : clientScopes.Take(1).ToList();
            }

            foreach (var scope in requestedList)
            {
                if (!clientScopes.Contains(scope))
                    throw OAuthException.InvalidScope($"scope '{scope}' is not allowed for this client.");
            }
            return requestedList;
        }

        /// <summary>Scopes advertised in discovery.</summary>
        public async Task<List<string>> GetSupportedScopesAsync()
        {
            var known = await _ctx.scopes.AsNoTracking().Select(s => s.name).ToListAsync();
            return known.Count > 0 ? known : DefaultScopes().Select(s => s.name).ToList();
        }

        /// <summary>Claims advertised in discovery.</summary>
        public async Task<List<string>> GetSupportedClaimsAsync()
        {
            var claims = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "at_hash", "c_hash", "azp", "sid"
            };
            foreach (var set in StandardScopeClaims.Values)
                foreach (var c in set) claims.Add(c);
            foreach (var s in await _ctx.scopes.AsNoTracking().ToListAsync())
                foreach (var c in s.claims) claims.Add(c);
            return claims.ToList();
        }

        /// <summary>The scope catalogue seeded into a new database.</summary>
        public static List<ArkScope> DefaultScopes() => new()
        {
            new ArkScope { name = "openid", display = "Sign you in", description = "Verify your identity.", is_default = true, require_consent = false, is_protocol = true },
            new ArkScope { name = "profile", display = "Your basic profile", description = "Your name and profile details.", is_default = true, claims = StandardScopeClaims["profile"].ToList() },
            new ArkScope { name = "email", display = "Your email address", description = "Your email address and whether it is verified.", is_default = true, claims = StandardScopeClaims["email"].ToList() },
            new ArkScope { name = "address", display = "Your address", description = "Your postal address.", claims = StandardScopeClaims["address"].ToList() },
            new ArkScope { name = "phone", display = "Your phone number", description = "Your phone number and whether it is verified.", claims = StandardScopeClaims["phone"].ToList() },
            new ArkScope { name = "offline_access", display = "Stay signed in", description = "Keep access when you are not using the app.", require_consent = true, is_protocol = true },
            // Machine-to-machine scope: what an initial access token must carry to create clients
            // through the RFC 7591 registration endpoint. Never a default — a client only holds it
            // if someone registered it for that client deliberately.
            new ArkScope { name = "client.register", display = "Register clients", description = "Create and manage client registrations.", is_protocol = true }
        };
    }
}
