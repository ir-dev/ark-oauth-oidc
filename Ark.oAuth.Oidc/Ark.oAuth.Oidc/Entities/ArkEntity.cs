using Microsoft.EntityFrameworkCore.Metadata.Internal;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

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
        public bool active { get; set; } = true;
        public int expire_mins { get; set; } = 480; // durations
        public string at { get; set; }
    }
    [Microsoft.AspNetCore.Mvc.ModelBinding.Validation.ValidateNever]
    public class ArkClient
    {
        [Key]
        public string client_id { get; set; }
        public string name { get; set; }
        public string display { get; set; }
        public string domain { get; set; }
        public string redirect_url { get; set; }
        public string? redirect_relative { get; set; }
        public string? tenants_ { get; set; }
        [NotMapped]
        public List<string> tenants
        {
            get => System.Text.Json.JsonSerializer.Deserialize<List<string>>(string.IsNullOrEmpty(tenants_) ? "[]" : tenants_);
            set => tenants_ = System.Text.Json.JsonSerializer.Serialize(value ?? new List<string>());
        }
        public int expire_mins { get; set; } = 480; // durations
        public string at { get; set; }
    }
    public class ArkUser
    {
        [Key]
        public string user_id { get; set; }
        public string client_id { get; set; }
        [ForeignKey("client_id")]
        public string client { get; set; }
        public string email { get; set; }
        public string at { get; set; }
    }
    public class ArkRole
    {
        [Key]
        public string key { get; set; }
        public string name { get; set; }
        public string display { get; set; }
        public string client_id { get; set; }
        [ForeignKey("client_id")]
        public string client { get; set; }
        public string claims_ { get; set; }
        [NotMapped]
        public List<ArkClaim> claims
        {
            get => System.Text.Json.JsonSerializer.Deserialize<List<ArkClaim>>(claims_ ?? "[]");
            set => claims_ = System.Text.Json.JsonSerializer.Serialize(value);
        }
    }
    public class ArkClaim
    {
        [Key]
        public string key { get; set; }
        public string name { get; set; }
        public string display { get; set; }
        public string value { get; set; }
        public string client_id { get; set; }
        [ForeignKey("client_id")]
        public string client { get; set; }
    }
    public class ArkApp
    {
        string _client_id;
        public string client_id { get => (_client_id ?? "").ToLower(); set => _client_id = value; } //micro services - uniquename (onboarding)
        string _redirect_uri;
        public string redirect_uri { get => (_redirect_uri ?? "").ToLower(); set => _redirect_uri = value; }
        string _base_url;
        public string base_url { get => (_base_url ?? "").ToLower(); set => _base_url = value; }
        string _grant_type;
        public string grant_type { get => (_grant_type ?? "").ToLower(); set => _grant_type = value; }
        string _tenant_id;
        public string tenant_id { get => (_tenant_id ?? "").ToLower(); set => _tenant_id = value; }
        public int expiration_mins { get; set; }
        public string client_secret { get; set; }
        public string display { get; set; }
        public bool is_debug { get; set; }
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
        public string code_challenge { get; set; }
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
}
