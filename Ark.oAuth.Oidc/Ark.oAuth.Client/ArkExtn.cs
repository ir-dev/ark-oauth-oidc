using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Asn1.Ocsp;
using System.Security.Cryptography;
using System.Text;
using static Org.BouncyCastle.Crypto.Engines.SM2Engine;

namespace Ark.oAuth
{
    public class ArkAuthConfig
    {
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public string RsaPublic { get; set; }
        public string RedirectUri { get; set; }
        public string RedirectRelative { get; set; }
        public string AuthServerUrl { get; set; }
        public string ClientId { get; set; } //fallback, incase not found in utl route
        public List<string> RouteKey { get; set; } // client route or querystring key eg: client_id, 
        public string TenantId { get; set; }
        public string Domain { get; set; }
        public Dictionary<string, ArkApp> Clients { get; set; }
        public int ExpireMins { get; set; } = 480;
    }
    public class ArkApp
    {
        public string RedirectUri { get; set; }
        public string RedirectRelative { get; set; }
        public string ClientId { get; set; }
    }
    public static class ArkExtn
    {
        static ArkAuthConfig LoadConfig(IConfiguration configuration)
        {
            //return configuration.GetSection("ark_oauth_client").Get<ArkAuthConfig>() ?? throw new ApplicationException("config missing");
            return configuration.GetSection("ark_oauth_client").Get<ArkAuthConfig>() ?? new ArkAuthConfig();
        }
        public static void StoreCookie(this HttpResponse response, string key, string val, int mins, string domain, SameSiteMode ss_mode = SameSiteMode.None)
        {
            CookieOptions option = new CookieOptions();
            option.Expires = DateTime.Now.AddMinutes(mins).ToLocalTime();
            option.Secure = true;
            option.HttpOnly = true;
            option.SameSite = ss_mode;
            option.Domain = domain;
            response.Cookies.Append(key, val, option);
        }
        public static string? ReadCookie(this HttpRequest request, string key)
        {
            return request.Cookies[key];
        }
        public static void DeleteCookie(this HttpResponse response, string key, string domain)
        {
            response.Cookies.Delete(key, new CookieOptions()
            {
                Secure = true,
                Domain = domain
            });
        }
        public static string? ReadRoute(this HttpRequest request, string key)
        {
            return string.IsNullOrEmpty(key)
                ? null : request.RouteValues.ContainsKey(key)
                ? request.RouteValues[key].ToString() : request.Query.ContainsKey(key)
                ? request.Query[key][0] : null;
        }
        public static string? ReadRoute(this HttpRequest request, List<string> keys)
        {
            string ree = null;
            keys = keys ?? new List<string>();
            foreach (var key in keys)
            {
                ree = request.ReadRoute(key);
                if (!string.IsNullOrEmpty(ree)) break;
            }
            return ree;
        }
        public static bool IsApi(this HttpRequest request)
        {
            var acceptHeader = request.Headers["Accept"].ToString();
            return request.Path.StartsWithSegments("/api") || acceptHeader.Contains("application/json", StringComparison.OrdinalIgnoreCase);
        }
        //All client config is taken from app settings
        public static void AddArkOidcClient(this IServiceCollection services, IConfiguration configuration)
        {
            services
                .AddAuthentication(Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme)
            //    .AddAuthentication(options =>
            //{
            //    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            //    //options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            //})
            .AddJwtBearer(options =>
            {
                options.RequireHttpsMetadata = false; // Set to true in production
                options.SaveToken = true;
                // Enable detailed logging in your token validation
                options.IncludeErrorDetails = true;
                var ccc = LoadConfig(configuration);
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = ccc.Issuer,
                    ValidateAudience = true,
                    ValidAudience = ccc.Audience,
                    ValidateLifetime = true,
                    IssuerSigningKeyResolver = (string token, SecurityToken securityToken, string kid, TokenValidationParameters validationParameters) =>
                    {
                        List<SecurityKey> keys = new List<SecurityKey>();
                        //if (!config.app_list.ContainsKey(kid)) throw new SecurityTokenInvalidSignatureException("Unable to validate signature, invalid token with 'kid' value.");
                        //var app = config.app_list[kid];
                        var pub_conf_key = ccc.RsaPublic;
                        var publicKey = Convert.FromBase64String(pub_conf_key);
                        RSA rsa = RSA.Create();
                        rsa.ImportSubjectPublicKeyInfo(publicKey, out _);
                        keys.Add(new RsaSecurityKey(rsa));
                        return keys;
                    },
                    ValidateIssuerSigningKey = true,
                    //AudienceValidator = (IEnumerable<string> issuer, SecurityToken securityToken, TokenValidationParameters validationParameters) =>
                    //{
                    //    return true;
                    //},
                    //IssuerValidator = (string issuer, SecurityToken securityToken, TokenValidationParameters validationParameters) =>
                    //{
                    //    return issuer;
                    //},
                    //LifetimeValidator = (DateTime? notBefore, DateTime? expires, SecurityToken securityToken, TokenValidationParameters validationParameters) =>
                    //{
                    //    if (notBefore.HasValue && DateTime.UtcNow > notBefore.Value
                    //    && expires.HasValue && DateTime.UtcNow < expires.Value)
                    //        return true;
                    //    return false;
                    //},
                    ClockSkew = TimeSpan.FromMinutes(1)
                };
                options.Events = new JwtBearerEvents
                {
                    //No token (should trigger OnChallenge)
                    //Invalid token (should trigger OnAuthenticationFailed)
                    //Valid token (should trigger OnMessageReceived → OnTokenValidated)
                    OnAuthenticationFailed = ctx =>
                    {
                        //https://localhost:5001/connect/authorize?response_type=code
                        //&client_id=webapp
                        //&redirect_uri=https://localhost:5002/signin-oidc
                        //&scope=openid profile email api1
                        //&state=random_state_value
                        //&code_challenge=your_code_challenge
                        //&code_challenge_method=S256
                        var client_id = ctx.Request.ReadRoute(ccc.RouteKey) ?? ccc.ClientId;
                        KeyValuePair<string, ArkApp> capp = ccc.Clients.FirstOrDefault(t2 => t2.Key.ToLower() == client_id.ToLower());
                        capp = capp.Key == null ? new KeyValuePair<string, ArkApp>(client_id, new ArkApp() { ClientId = client_id, RedirectRelative = ccc.RedirectRelative, RedirectUri = ccc.RedirectUri }) : capp;
                        var state = ctx.Request.Query.ContainsKey("state") ? ctx.Request.Query["state"][0] : "";
                        var code_challenge = ctx.Request.Query.ContainsKey("code_challenge") ? ctx.Request.Query["code_challenge"][0] : "";
                        var ff = $"{ccc.AuthServerUrl}/{ccc.TenantId}/v1/connect/authorize?response_type=code&client_id={client_id}&redirect_uri={capp.Value.RedirectUri}&state={state}&code_challenge={code_challenge}&code_challenge_method=S256&err=invalid_token";
                        ctx.Response.Redirect($"{ff}");
                        return Task.CompletedTask;
                    },
                    OnForbidden = ctx =>
                    {
                        var ff = $"err=access_denied";
                        ctx.Response.Redirect($"/auth?{ff}");
                        return Task.CompletedTask;
                    },
                    OnTokenValidated = ctx =>
                    {
                        Console.WriteLine("correct token");
                        return Task.CompletedTask;
                    },
                    OnChallenge = ctx =>
                    {
                        //if (ctx.AuthenticateFailure != null || ctx.Error != null || ctx.ErrorUri != null)
                        //{
                        //its no tken, so inititate auth process
                        ctx.HandleResponse();
                        var client_id = ctx.Request.ReadRoute(ccc.RouteKey) ?? ccc.ClientId;
                        KeyValuePair<string, ArkApp> capp = ccc.Clients.FirstOrDefault(t2 => t2.Key.ToLower() == client_id.ToLower());
                        capp = capp.Key == null ? new KeyValuePair<string, ArkApp>(client_id, new ArkApp() { ClientId = client_id, RedirectRelative = ccc.RedirectRelative, RedirectUri = ccc.RedirectUri }) : capp;
                        var state = ctx.Request.Query.ContainsKey("state") ? ctx.Request.Query["state"][0] : "";
                        var code_verifier = $"JESUSmyLORD_{ark.net.util.DateUtil.CurrentTimeStamp()}";
                        var code_challenge = PkceHelper.GenerateCodeChallenge(code_verifier);
                        var ff = $"{ccc.AuthServerUrl}/{ccc.TenantId}/v1/connect/authorize?response_type=code&client_id={client_id}&redirect_uri={capp.Value.RedirectUri}&state={state}&code_challenge={code_challenge}&code_challenge_method=S256&err=token_error";
                        ctx.Response.StoreCookie($"ark_oauth_cv_{client_id}", code_verifier, ccc.ExpireMins, ccc.Domain);
                        ctx.Response.Redirect($"{ff}");
                        //}
                        return Task.CompletedTask;
                    },
                    OnMessageReceived = msg =>
                    {
                        Console.WriteLine(msg);
                        return Task.CompletedTask;
                    }
                };
            });

            services.AddHttpContextAccessor();
            services.AddScoped<ArkAuthContext>();
        }

        public static void UseArkOidcClient(this IApplicationBuilder builder)
        {
            builder.Use(async (context, next) =>
            {
                var endpoint = context.GetEndpoint();
                var authorizeData = endpoint?.Metadata.GetOrderedMetadata<IAuthorizeData>();
                if (authorizeData?.Any() == true) //authorize attribute
                {
                    var config = builder.ApplicationServices.GetRequiredService<IConfiguration>();
                    var ccc = LoadConfig(config);
                    var client_id = context.Request.ReadRoute(ccc.RouteKey) ?? ccc.ClientId;
                    KeyValuePair<string, ArkApp> capp = ccc.Clients.FirstOrDefault(t2 => t2.Key.ToLower() == client_id.ToLower());
                    capp = capp.Key == null ? new KeyValuePair<string, ArkApp>(client_id, new ArkApp() { ClientId = client_id, RedirectRelative = ccc.RedirectRelative, RedirectUri = ccc.RedirectUri }) : capp;
                    if (context.Request.Query.ContainsKey("err") && !string.IsNullOrEmpty(context.Request.Query["err"]) && (context.Request.Query["err"] == "access_denied" || context.Request.Query["err"] == "invalid_token" || context.Request.Query["err"] == "token_error"))
                    {
                        context.Response.DeleteCookie($"ark_oauth_tkn_{client_id}", ccc.Domain);
                    }
                    var token = context.Request.ReadCookie($"ark_oauth_tkn_{client_id}");
                    if (!string.IsNullOrEmpty(token) && authorizeData?.Any() == true)
                    {
                        context.Request.Headers.Add("Authorization", "Bearer " + token);
                    }
                }
                await next();
            });
        }
    }
    public static class PkceHelper
    {
        public static string GenerateCodeVerifier()
        {
            var randomBytes = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);
            return Base64UrlEncode(randomBytes);
        }

        public static string GenerateCodeChallenge(string codeVerifier)
        {
            using var sha256 = SHA256.Create();
            var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
            return Base64UrlEncode(challengeBytes);
        }

        private static string Base64UrlEncode(byte[] bytes)
        {
            return Convert.ToBase64String(bytes)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }
    }
    public class ArkAuthContext
    {
        IHttpContextAccessor _http;
        public ArkAuthContext(IHttpContextAccessor http)
        {
            _http = http;
            ip = _http.HttpContext.Request.Cookies["ark_oauth_ip"] ?? "";
            user_id = _http.HttpContext.Request.Cookies["ark_oauth_email"] ?? "";
            var cid = (_http.HttpContext.Request.RouteValues["client_id"] ?? "").ToString().ToLower();
            client_id = string.IsNullOrEmpty(cid)
                ? (_http.HttpContext.Request.Query.ContainsKey("client_id") && _http.HttpContext.Request.Query["client_id"].Count > 0 ? (_http.HttpContext.Request.Query["client_id"][0] ?? "").ToString().ToLower() : "")
                : cid;
        }
        public string client_id { get; private set; }
        public string? user_id { get; private set; } //mob or email (opt 1: mob, opt 2: email)
        public string? ip { get; set; }
    }
}