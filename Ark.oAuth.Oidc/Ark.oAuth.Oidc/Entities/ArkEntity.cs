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
    [Index(nameof(tenant_id), nameof(client_id), IsUnique = true)]
    [Microsoft.AspNetCore.Mvc.ModelBinding.Validation.ValidateNever]
    public class ArkClient
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public string id { get; set; }
        public string tenant_id { get; set; }
        public string client_id { get; set; }
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
}
