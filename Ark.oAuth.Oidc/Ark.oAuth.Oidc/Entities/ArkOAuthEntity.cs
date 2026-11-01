using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace Ark.oAuth
{
    /// <summary>
    /// Helper for the "store a JSON list in a string column" pattern used across the entities.
    /// </summary>
    internal static class JsonList
    {
        public static List<string> Read(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return new List<string>();
            try
            {
                return System.Text.Json.JsonSerializer.Deserialize<List<string>>(raw) ?? new List<string>();
            }
            catch
            {
                // tolerate space/comma separated legacy values
                return raw.Split(new[] { ' ', ',', ';' }, StringSplitOptions.RemoveEmptyEntries).ToList();
            }
        }
        public static string Write(List<string>? values) =>
            System.Text.Json.JsonSerializer.Serialize(values ?? new List<string>());
    }

    /// <summary>
    /// A signing key for a tenant. Kept separate from <see cref="ArkTenant"/> so keys can be
    /// rotated without downtime: a tenant may hold one 'active' key (used to sign) plus any
    /// number of 'rollover' keys (still published in JWKS so previously issued tokens verify).
    /// </summary>
    [Microsoft.AspNetCore.Mvc.ModelBinding.Validation.ValidateNever]
    [Index(nameof(tenant_id), nameof(status))]
    public class ArkSigningKey
    {
        [Key]
        public string kid { get; set; } = default!;
        public string tenant_id { get; set; } = default!;
        public string alg { get; set; } = "RS256";
        /// <summary>JWK "use" parameter. Always "sig" today.</summary>
        public string usage { get; set; } = "sig";
        /// <summary>Base64 SubjectPublicKeyInfo.</summary>
        public string public_key { get; set; } = default!;
        /// <summary>Base64 PKCS#8. Never leaves the server.</summary>
        public string private_key { get; set; } = default!;
        /// <summary>active = signs new tokens; rollover = published but no longer signing; retired = neither.</summary>
        public string status { get; set; } = "active";
        public DateTime created_at { get; set; } = DateTime.UtcNow;
        public DateTime? not_after { get; set; }
    }

    /// <summary>
    /// A single-use authorization code (RFC 6749 §4.1). The code itself is never persisted —
    /// only its SHA-256 hash — so a database leak does not hand out redeemable codes.
    /// </summary>
    [Microsoft.AspNetCore.Mvc.ModelBinding.Validation.ValidateNever]
    [Index(nameof(expires_at))]
    public class ArkAuthCode
    {
        [Key]
        public string code_hash { get; set; } = default!;
        public string tenant_id { get; set; } = default!;
        public string client_id { get; set; } = default!;
        public string subject { get; set; } = default!;
        public string? session_id { get; set; }
        public string redirect_uri { get; set; } = default!;
        public string? scope { get; set; }
        public string? code_challenge { get; set; }
        public string? code_challenge_method { get; set; }
        public string? nonce { get; set; }
        public string? auth_context { get; set; }
        public DateTime auth_time { get; set; } = DateTime.UtcNow;
        public DateTime expires_at { get; set; }
        public DateTime created_at { get; set; } = DateTime.UtcNow;
        public bool consumed { get; set; }
    }

    /// <summary>
    /// A refresh token. Tokens are grouped into a rotation "family": when a client redeems a
    /// refresh token it is marked consumed and a successor is issued into the same family.
    /// Re-presenting an already-consumed token is treated as theft and revokes the whole family
    /// (OAuth 2.1 §4.14.2 refresh token replay detection).
    /// </summary>
    [Microsoft.AspNetCore.Mvc.ModelBinding.Validation.ValidateNever]
    [Index(nameof(family_id))]
    [Index(nameof(subject), nameof(client_id))]
    public class ArkRefreshToken
    {
        [Key]
        public string token_hash { get; set; } = default!;
        public string family_id { get; set; } = default!;
        public string tenant_id { get; set; } = default!;
        public string client_id { get; set; } = default!;
        public string subject { get; set; } = default!;
        public string? session_id { get; set; }
        public string? scope { get; set; }
        public DateTime expires_at { get; set; }
        public DateTime created_at { get; set; } = DateTime.UtcNow;
        public DateTime? consumed_at { get; set; }
        public bool revoked { get; set; }
    }

    /// <summary>Device authorization grant state (RFC 8628).</summary>
    [Microsoft.AspNetCore.Mvc.ModelBinding.Validation.ValidateNever]
    [Index(nameof(user_code), IsUnique = true)]
    public class ArkDeviceCode
    {
        [Key]
        public string device_code_hash { get; set; } = default!;
        /// <summary>Short, human-keyable code shown on the device (e.g. "WDJB-MJHT").</summary>
        public string user_code { get; set; } = default!;
        public string tenant_id { get; set; } = default!;
        public string client_id { get; set; } = default!;
        public string? scope { get; set; }
        /// <summary>pending | approved | denied</summary>
        public string status { get; set; } = "pending";
        public string? subject { get; set; }
        public string? session_id { get; set; }
        public int interval_seconds { get; set; } = 5;
        public DateTime expires_at { get; set; }
        public DateTime created_at { get; set; } = DateTime.UtcNow;
        public DateTime? last_polled_at { get; set; }
    }

    /// <summary>A pushed authorization request (RFC 9126). Holds the parameter set until /authorize claims it.</summary>
    [Microsoft.AspNetCore.Mvc.ModelBinding.Validation.ValidateNever]
    public class ArkParRequest
    {
        [Key]
        public string request_uri { get; set; } = default!;
        public string tenant_id { get; set; } = default!;
        public string client_id { get; set; } = default!;
        /// <summary>JSON object of the original authorization parameters.</summary>
        public string payload { get; set; } = default!;
        public DateTime expires_at { get; set; }
        public DateTime created_at { get; set; } = DateTime.UtcNow;
        public bool consumed { get; set; }
    }

    /// <summary>A remembered user consent, so a returning user is not re-prompted for scopes already granted.</summary>
    [Microsoft.AspNetCore.Mvc.ModelBinding.Validation.ValidateNever]
    [Index(nameof(tenant_id), nameof(client_id), nameof(subject), IsUnique = true)]
    public class ArkConsent
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public string id { get; set; } = default!;
        public string tenant_id { get; set; } = default!;
        public string client_id { get; set; } = default!;
        public string subject { get; set; } = default!;
        public string? scopes_ { get; set; }
        [NotMapped]
        public List<string> scopes
        {
            get => JsonList.Read(scopes_);
            set => scopes_ = JsonList.Write(value);
        }
        public DateTime granted_at { get; set; } = DateTime.UtcNow;
        public DateTime? expires_at { get; set; }
    }

    /// <summary>
    /// An authenticated browser session at the IdP. Surfaces as the `sid` claim and is what
    /// RP-initiated logout (end_session) terminates.
    /// </summary>
    [Microsoft.AspNetCore.Mvc.ModelBinding.Validation.ValidateNever]
    [Index(nameof(subject))]
    [Index(nameof(browser_id))]
    public class ArkSession
    {
        [Key]
        public string session_id { get; set; } = default!;
        public string tenant_id { get; set; } = default!;
        public string subject { get; set; } = default!;
        /// <summary>
        /// The browser this session was created in, from the long-lived ark_idp_bid cookie.
        ///
        /// A session id identifies one sign-in; this identifies the user agent all of them
        /// happened in. Without it there is no way to answer "who else is signed in here": the
        /// session cookie only ever holds the most recent sid, so a second person signing in on
        /// the same machine leaves the first session live in the database with its refresh
        /// tokens intact, and signing out only ends the one the cookie happens to name. Grouping
        /// by browser is what lets end_session close all of them at once.
        ///
        /// Nullable, because sessions created before this column existed have no browser to
        /// name, and because a session may be created outside a browser flow.
        /// </summary>
        public string? browser_id { get; set; }
        public DateTime auth_time { get; set; } = DateTime.UtcNow;
        public DateTime created_at { get; set; } = DateTime.UtcNow;
        public DateTime expires_at { get; set; }
        public bool revoked { get; set; }
    }

    /// <summary>
    /// A client that took part in a session — one row the first time a session issues that
    /// client an authorization code or approves a device request.
    ///
    /// This is the audience list for back-channel logout (OIDC Back-Channel Logout 1.0 §2.6):
    /// when a session ends, the clients to notify are exactly those that were logged in under
    /// it. The alternative — deriving the list from live refresh tokens — misses every client
    /// that never asked for offline_access, which is most of them, and misses any client whose
    /// tokens have already expired while its own application cookie is still valid.
    /// </summary>
    [Microsoft.AspNetCore.Mvc.ModelBinding.Validation.ValidateNever]
    [Index(nameof(session_id))]
    public class ArkSessionClient
    {
        /// <summary>
        /// "{session_id}.{client_id}" — derived rather than generated, so recording the same
        /// pair twice is a primary-key lookup and not a scan plus a duplicate row.
        /// </summary>
        [Key]
        public string id { get; set; } = default!;
        public string tenant_id { get; set; } = default!;
        public string session_id { get; set; } = default!;
        public string client_id { get; set; } = default!;
        public string subject { get; set; } = default!;
        public DateTime created_at { get; set; } = DateTime.UtcNow;

        public static string KeyFor(string sessionId, string clientId) => $"{sessionId}.{clientId}";
    }

    /// <summary>
    /// A scope the authorization server will issue, and the claims it unlocks at /userinfo.
    /// Seeded with the OIDC standard scopes (openid, profile, email, address, phone, offline_access).
    /// </summary>
    [Microsoft.AspNetCore.Mvc.ModelBinding.Validation.ValidateNever]
    public class ArkScope
    {
        [Key]
        public string name { get; set; } = default!;
        public string? display { get; set; }
        public string? description { get; set; }
        public string? claims_ { get; set; }
        [NotMapped]
        public List<string> claims
        {
            get => JsonList.Read(claims_);
            set => claims_ = JsonList.Write(value);
        }
        /// <summary>Granted automatically when a client omits `scope`.</summary>
        public bool is_default { get; set; }
        /// <summary>Whether this scope has to appear on the consent screen.</summary>
        public bool require_consent { get; set; } = true;
        /// <summary>Hidden from the consent screen and discovery (e.g. protocol scopes like openid).</summary>
        public bool is_protocol { get; set; }
    }
}
