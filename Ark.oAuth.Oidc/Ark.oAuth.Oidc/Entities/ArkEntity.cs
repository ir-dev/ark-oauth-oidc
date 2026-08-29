using Microsoft.EntityFrameworkCore.Metadata.Internal;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using Microsoft.EntityFrameworkCore;

namespace Ark.oAuth
{
    [Microsoft.AspNetCore.Mvc.ModelBinding.Validation.ValidateNever]
    public class ArkTenant
    {
        [Key]
        public string tenant_id { get; set; }
        public string name { get; set; }
        public string display { get; set; }
        public string rsa_public { get; set; }
        public string rsa_private { get; set; }
        public string issuer { get; set; }
        public string audience { get; set; }
        public int expire_mins { get; set; } = 480; // durations
        public string at { get; set; }
    }
    [Microsoft.AspNetCore.Mvc.ModelBinding.Validation.ValidateNever]
    public class ArkTenantConfig
    {
        [Key]
        public string tenant_id { get; set; }
        [ForeignKey(nameof(tenant_id))]
        public ArkTenant tenant { get; set; }
        public string host_company_name { get; set; }
        public string client_logo { get; set; }
        public string host_logo { get; set; }
        public string activation_link { get; set; }
        public string privacy_policy_url { get; set; }
        public string host_website_url { get; set; }
        public string client_website_url { get; set; }
        public string terms_url { get; set; }
        public string at { get; set; }
    }
    [Index(nameof(tenant_id), nameof(client_id), IsUnique = true)]
    [Microsoft.AspNetCore.Mvc.ModelBinding.Validation.ValidateNever]
    public class ArkClient
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public string id { get; set; }
        public string tenant_id { get; set; }
        public string client_id { get; set; }
        public string? client_logo { get; set; }
        public string name { get; set; }
        public string display { get; set; }
        public string domain { get; set; }
        public string redirect_url { get; set; }
        public string logout_url { get; set; }
        public string? redirect_relative { get; set; }
        [ForeignKey(nameof(tenant_id))]
        public ArkTenant tenant { get; set; }
        public int expire_mins { get; set; } = 480; // durations
        public string at { get; set; }

        // ---------------------------------------------------------------------
        // Standard OAuth 2.1 / OIDC client registration metadata (RFC 7591 names).
        // The legacy single-valued redirect_url / logout_url above are retained so the
        // v1 compatibility endpoints keep working; the plural forms win when populated.
        // ---------------------------------------------------------------------

        /// <summary>RFC 7591 client_name. Falls back to <see cref="display"/> / <see cref="name"/> when unset.</summary>
        public string? client_name { get; set; }
        /// <summary>PBKDF2 hash of the client secret. Null for public clients.</summary>
        public string? client_secret_hash { get; set; }
        public DateTime? client_secret_expires_at { get; set; }
        /// <summary>client_secret_basic | client_secret_post | private_key_jwt | none</summary>
        public string token_endpoint_auth_method { get; set; } = "client_secret_basic";
        /// <summary>web | native | spa | service</summary>
        public string application_type { get; set; } = "web";
        public string? client_uri { get; set; }
        public string? policy_uri { get; set; }
        public string? tos_uri { get; set; }
        /// <summary>Client's own JWKS endpoint, used to verify private_key_jwt assertions.</summary>
        public string? jwks_uri { get; set; }

        public string? redirect_uris_ { get; set; }
        [NotMapped]
        public List<string> redirect_uris
        {
            get => JsonList.Read(redirect_uris_);
            set => redirect_uris_ = JsonList.Write(value);
        }
        public string? post_logout_redirect_uris_ { get; set; }
        [NotMapped]
        public List<string> post_logout_redirect_uris
        {
            get => JsonList.Read(post_logout_redirect_uris_);
            set => post_logout_redirect_uris_ = JsonList.Write(value);
        }
        public string? grant_types_ { get; set; }
        [NotMapped]
        public List<string> grant_types
        {
            get => JsonList.Read(grant_types_);
            set => grant_types_ = JsonList.Write(value);
        }
        public string? response_types_ { get; set; }
        [NotMapped]
        public List<string> response_types
        {
            get => JsonList.Read(response_types_);
            set => response_types_ = JsonList.Write(value);
        }
        public string? scopes_ { get; set; }
        [NotMapped]
        public List<string> scopes
        {
            get => JsonList.Read(scopes_);
            set => scopes_ = JsonList.Write(value);
        }
        public string? contacts_ { get; set; }
        [NotMapped]
        public List<string> contacts
        {
            get => JsonList.Read(contacts_);
            set => contacts_ = JsonList.Write(value);
        }

        public bool require_pkce { get; set; } = true;
        public bool require_par { get; set; }
        public bool require_consent { get; set; }
        public bool refresh_token_rotation { get; set; } = true;
        public bool is_active { get; set; } = true;

        public int access_token_lifetime_seconds { get; set; } = 3600;
        public int id_token_lifetime_seconds { get; set; } = 3600;
        public int refresh_token_lifetime_seconds { get; set; } = 1209600; // 14 days
        public int authorization_code_lifetime_seconds { get; set; } = 60;

        /// <summary>Hash of the registration access token issued by dynamic client registration (RFC 7591).</summary>
        public string? registration_access_token_hash { get; set; }

        /// <summary>
        /// Where to POST a logout token when a session this client took part in ends
        /// (OIDC Back-Channel Logout 1.0 §2.2). Empty means the client is not notified — its own
        /// application cookie then outlives the IdP session, which is the whole problem
        /// back-channel logout exists to solve.
        /// </summary>
        public string? backchannel_logout_uri { get; set; }

        /// <summary>
        /// Whether the logout token has to carry a <c>sid</c>. On by default, matching how this
        /// server signs users in: every browser session has a session id and puts it in the
        /// id_token, so a client can end exactly the session that was named rather than every
        /// session it holds for that subject.
        /// </summary>
        public bool backchannel_logout_session_required { get; set; } = true;

        /// <summary>True when this client has somewhere to receive a logout token.</summary>
        [NotMapped]
        public bool SupportsBackChannelLogout => !string.IsNullOrWhiteSpace(backchannel_logout_uri);

        // --- effective views: fall back to the legacy single-valued columns ---

        [NotMapped]
        public List<string> EffectiveRedirectUris =>
            redirect_uris.Count > 0
                ? redirect_uris
                : (string.IsNullOrWhiteSpace(redirect_url) ? new List<string>() : new List<string> { redirect_url });

        [NotMapped]
        public List<string> EffectivePostLogoutRedirectUris =>
            post_logout_redirect_uris.Count > 0
                ? post_logout_redirect_uris
                : (string.IsNullOrWhiteSpace(logout_url) ? new List<string>() : new List<string> { logout_url });

        [NotMapped]
        public List<string> EffectiveGrantTypes =>
            grant_types.Count > 0
                ? grant_types
                : new List<string> { "authorization_code", "refresh_token" };

        [NotMapped]
        public List<string> EffectiveResponseTypes =>
            response_types.Count > 0 ? response_types : new List<string> { "code" };

        [NotMapped]
        public List<string> EffectiveScopes =>
            scopes.Count > 0
                ? scopes
                : new List<string> { "openid", "profile", "email", "offline_access" };

        /// <summary>A client with no secret is public and must therefore use PKCE.</summary>
        [NotMapped]
        public bool IsPublicClient =>
            string.IsNullOrEmpty(client_secret_hash) ||
            string.Equals(token_endpoint_auth_method, "none", StringComparison.OrdinalIgnoreCase);
    }
    [Microsoft.AspNetCore.Mvc.ModelBinding.Validation.ValidateNever]
    [Index(nameof(email), IsUnique = true)]
    public class ArkUser
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public string id { get; set; } 
        public string email { get; set; } // used for login
        public string? hash_pw { get; set; }
        public string? ref_uid { get; set; } // referecee uid, used in url sent to email
        public bool? reset_mode { get; set; } = false; // password reset mode is in enabled sate, if false, all is well
        public bool? emailed { get; set; } = false; // set to true, once email is sent successful 
        public string name { get; set; } // full name
        public string type { get; set; } = "user"; // type of account - defaul: null, 'user', 'service'
        /// <summary>
        /// Whether the account may sign in at all, anywhere on the server.
        ///
        /// The client-level switch is <see cref="ArkClient.is_active"/>; this is the user-level
        /// one, and the two are reported separately at sign-in so the person in front of the
        /// screen is told which of the two is off rather than being handed a credentials error
        /// for something their password cannot fix.
        /// </summary>
        public bool is_active { get; set; } = true;
        public string at { get; set; }
    }
    [Microsoft.AspNetCore.Mvc.ModelBinding.Validation.ValidateNever]
    [Index(nameof(email), nameof(tenant_id), nameof(client_id), IsUnique = true)]
    public class ArkUserClientClaim
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public string id { get; set; }
        public string email { get; set; } // used for login
        public string client_id { get; set; }
        [ForeignKey(nameof(client_id))]
        public ArkClient client { get; set; }
        public string? tenant_id { get; set; }
        [ForeignKey(nameof(tenant_id))]
        public ArkTenant tenant { get; set; }
        public string? claims_ { get; set; }
        [NotMapped]
        public List<string> claims
        {
            get => System.Text.Json.JsonSerializer.Deserialize<List<string>>(string.IsNullOrEmpty(claims_) ? "[]" : claims_);
            set => claims_ = System.Text.Json.JsonSerializer.Serialize(value ?? new List<string>());
        }
        public string at { get; set; }
    }
    [Microsoft.AspNetCore.Mvc.ModelBinding.Validation.ValidateNever]
    public class ArkClaim
    {
        [Key]
        public string key { get; set; }
        public string display { get; set; }
    }
    public class PkceCodeFlow
    {
        [Key]
        public string code { get; set; }
        string _client_id;
        public string client_id { get => (_client_id ?? "").ToLower(); set => _client_id = value; }
        public string? client_secret { get; set; }
        string _redirect_uri;
        public string redirect_uri { get => (_redirect_uri ?? "").ToLower(); set => _redirect_uri = value; }
        string _audience;
        public string audience { get => (_audience ?? "").ToLower(); set => _audience = value; }
        string _response_type;
        public string response_type { get => (_response_type ?? "").ToLower(); set => _response_type = value; }
        public string code_challenge { get; set; } //code_verifier
        string _code_challenge_method;
        public string code_challenge_method { get => (_code_challenge_method ?? "").ToLower(); set => _code_challenge_method = value; }
        public string? state { get; set; }
        public bool inactivate { get; set; }
        public string? access_token { get; set; }
        public string? scopes { get; set; }
        public string? claims { get; set; }
        public string? refresh_token { get; set; }
        public DateTime expires_at { get; set; }
        public DateTime created_at { get; set; } = DateTime.UtcNow;
    }
    public class ArkServiceAccount
    {
        [Key]
        public string account_id { get; set; }
        public string client_secret { get; set; }
        public int expiration_mins { get; set; } = 525600;
        public string access_token { get; set; }
        public string client_id { get; set; }
        public string claims_ { get; set; }
        [NotMapped]
        public List<ArkClaim> claims
        {
            get => System.Text.Json.JsonSerializer.Deserialize<List<ArkClaim>>(claims_ ?? "[]");
            set => claims_ = System.Text.Json.JsonSerializer.Serialize(value);
        }
        public bool is_active { get; set; } = true;
    }

    [Microsoft.AspNetCore.Mvc.ModelBinding.Validation.ValidateNever]
    public class ArkAudit
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public string id { get; set; }
        public string ref_key { get; set; }
        public string ref_val { get; set; }
        public string log_type { get; set; }
        public string message { get; set; }
        public string details { get; set; }
        public string by { get; set; }
        public string ip { get; set; }
        public DateTime at { get; set; } = DateTime.UtcNow;

    }
    [Microsoft.AspNetCore.Mvc.ModelBinding.Validation.ValidateNever]
    [Index(nameof(email), IsUnique = true)]
    public class ArkAuthStatusTrace
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int id { get; set; }
        public string email { get; set; }
        public int retry_count { get; set; }
        public bool complex_policy { get; set; } = false;
        public string ip { get; set; }
        public DateTime at { get; set; } = DateTime.UtcNow;

    }
}
