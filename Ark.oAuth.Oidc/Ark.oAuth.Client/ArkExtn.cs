using ark.net.util;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Ark.oAuth
{
    public class ArkAuthConfig
    {
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public string RsaPublic { get; set; }
        public string LogoutUri { get; set; }
        public string RedirectUri { get; set; }
        public string RedirectRelative { get; set; }
        public string AuthServerUrl { get; set; }
        public string ClientId { get; set; } //fallback, incase not found in utl route
        public List<string> RouteKey { get; set; } // client route or querystring key eg: client_id,
        public string TenantId { get; set; }
        public string Domain { get; set; }
        public string Suffix { get; set; } // suffix after client : lh - localhost, azd - azuredev
        public int ExpireMins { get; set; } = 480;
        public Dictionary<string, ArkCert> tenants { get; set; } = new Dictionary<string, ArkCert>();

        // ---------------------------------------------------------------------
        // Standard OIDC client settings.
        //
        // In practice only Authority and ClientId are needed — everything else is discovered
        // from the provider's /.well-known/openid-configuration document at startup. The
        // properties above are kept for the legacy flow and for existing appsettings files.
        // ---------------------------------------------------------------------

        /// <summary>
        /// The issuer URL of the authorization server, e.g. https://idp.example.com/auth/my_tenant.
        /// Left unset, it is derived from AuthServerUrl + TenantId, so existing configuration
        /// files pick up the standard flow without being rewritten.
        /// </summary>
        public string? Authority { get; set; }

        /// <summary>Set for confidential clients. Public clients (SPAs, native apps) leave this null.</summary>
        public string? ClientSecret { get; set; }

        /// <summary>Defaults to openid, profile, email, offline_access.</summary>
        public List<string>? Scopes { get; set; }

        public string? CallbackPath { get; set; }
        public string? SignedOutCallbackPath { get; set; }
        public string? SignedOutRedirectUri { get; set; }
        /// <summary>Where to land when the sign-in callback fails. Receives ?auth_error=…</summary>
        public string? AuthErrorPath { get; set; }

        public string? CookieName { get; set; }
        /// <summary>Claim type Ark authorization claims are projected onto. Defaults to "role".</summary>
        public string? RoleClaimType { get; set; }

        /// <summary>Only turn this off for local development against a plain-http provider.</summary>
        public bool RequireHttpsMetadata { get; set; } = true;

        /// <summary>
        /// Account switching on a shared browser, and the page shown to a user who is signed in
        /// as somebody without access to this application. See <see cref="ArkAccountSwitchOptions"/>.
        /// </summary>
        public ArkAccountSwitchOptions AccountSwitch { get; set; } = new();

        /// <summary>
        /// Opt back in to the original cookie/bearer middleware. Provided for deployments that
        /// cannot move to the standard callback path yet; the legacy flow does not verify
        /// `state` or `nonce` and derives its PKCE verifier predictably.
        /// </summary>
        public bool UseLegacyFlow { get; set; }

        public string ResolveAuthority()
        {
            if (!string.IsNullOrWhiteSpace(Authority)) return Authority!.TrimEnd('/');
            if (!string.IsNullOrWhiteSpace(AuthServerUrl) && !string.IsNullOrWhiteSpace(TenantId))
                return $"{AuthServerUrl.TrimEnd('/')}/{TenantId}";
            return "";
        }

        public List<string> ResolveScopes() =>
            Scopes is { Count: > 0 } ? Scopes : new List<string> { "openid", "profile", "email", "offline_access" };
    }
    public class ArkCert
    {
        public string kid { get; set; } //key 
        public string RsaPublic { get; set; }
        public string Audience { get; set; }
        public string Issuer { get; set; }
    }
    public class AUserInfo
    {
        public string[] claims { get; set; }
        public string client_guid { get; set; }
        public string client_id { get; set; }
        public string client_name { get; set; }
        public AUser user { get; set; }
    }
    public class AUser
    {
        public string email { get; set; }
        public string name { get; set; }
        public string type { get; set; }
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
                Domain = domain,
                SameSite = SameSiteMode.None
            });
        }
        public static dynamic ArkUser(this HttpRequest request, string client_id)
        {
            return System.Text.Json.JsonSerializer.Deserialize<dynamic>(request.Cookies[$"ark_oauth_ui_claims_{client_id}"] ?? "{}");
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
        /// <summary>
        /// Registers Ark authentication for this application.
        ///
        /// By default this configures ASP.NET Core's OpenID Connect handler against the server's
        /// discovery document — real PKCE, state and nonce validation, JWKS key rollover and
        /// silent refresh all come from the framework. Set `ark_oauth_client:UseLegacyFlow` to
        /// true to keep the original cookie/bearer middleware while migrating.
        /// </summary>
        public static void AddArkOidcClient(this IServiceCollection services, IConfiguration configuration)
            => services.AddArkOidcClient(configuration, null);

        /// <summary>
        /// As above, with a callback that can adjust the bound configuration in code and attach
        /// the <see cref="ArkClientEvents"/> hooks — a custom entitlement rule, or an
        /// access-denied page of your own.
        /// </summary>
        /// <example>
        /// <code>
        /// builder.Services.AddArkOidcClient(builder.Configuration, o =&gt;
        /// {
        ///     o.Config.AccountSwitch.RequireArkClaims = true;
        ///     o.Events.OnAccessDenied = ctx =&gt; { logger.LogWarning("no access: {User}", ctx.Email); return Task.CompletedTask; };
        /// });
        /// </code>
        /// </example>
        public static void AddArkOidcClient(
            this IServiceCollection services, IConfiguration configuration, Action<ArkClientOptions>? configure)
        {
            var ccc = LoadConfig(configuration);
            ccc.AccountSwitch ??= new ArkAccountSwitchOptions();

            var options = new ArkClientOptions(ccc);
            configure?.Invoke(options);
            services.AddSingleton(options.Events);

            // The access-denied page and the switch-user post, registered without the host having
            // to add a Use… call — the applications that need them are the ones whose Program.cs
            // was written before they existed.
            // Not under the legacy flow: it registers no cookie scheme, so there is no local
            // session for a switch to drop and nothing for the page to sign out of.
            if (!ccc.UseLegacyFlow && ccc.AccountSwitch is { Enabled: true, AutoRegisterEndpoints: true })
                services.AddTransient<IStartupFilter, ArkAccountStartupFilter>();

            services.AddHttpContextAccessor();
            services.AddHttpClient("ark-oidc-client", c => c.Timeout = TimeSpan.FromSeconds(15));
            services.AddSingleton<ArkAuthConfig>(t => ccc);
            services.AddSingleton<AuthClientHelper>();
            services.AddScoped<ArkAuthContext>();

            // Registration diagnostics and the two flows that need no browser. All three are
            // stateless over the discovery document, so they are safe as singletons and are
            // registered whether or not this application uses them.
            services.AddSingleton<ArkSetupProbe>();
            services.AddSingleton<ArkClientCredentials>();
            services.AddSingleton<ArkRegistration>();

            if (!ccc.UseLegacyFlow)
            {
                services.AddArkOidcInteractive(ccc, options.Events);
                return;
            }

            AddLegacyArkOidcClient(services, ccc);
        }

        /// <summary>
        /// The original bearer-token-from-cookie middleware.
        ///
        /// Retained only so existing deployments can upgrade the package without changing their
        /// callback routes on the same day. It does not validate `state` or `nonce`, and its
        /// PKCE verifier is derived from a timestamp rather than a random value, so it should be
        /// treated as a migration aid rather than a supported configuration.
        /// </summary>
        private static void AddLegacyArkOidcClient(IServiceCollection services, ArkAuthConfig ccc)
        {
            services
                .AddAuthentication(Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.RequireHttpsMetadata = false; // Set to true in production
                options.SaveToken = true;
                // Enable detailed logging in your token validation
                options.IncludeErrorDetails = true;
                //var ccc = LoadConfig(configuration);
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    //ValidIssuer = ccc.Issuer,
                    ValidateAudience = true,
                    //ValidAudience = ccc.Audience,
                    ValidateLifetime = true,
                    IssuerSigningKeyResolver = (string token, SecurityToken securityToken, string kid, TokenValidationParameters validationParameters) =>
                    {
                        List<SecurityKey> keys = new List<SecurityKey>();
                        var pub_conf_key = (ccc.tenants ?? new Dictionary<string, ArkCert>()).ContainsKey(kid) ? ccc.tenants[kid].RsaPublic : ccc.RsaPublic;
                        var publicKey = Convert.FromBase64String(pub_conf_key);
                        RSA rsa = RSA.Create();
                        rsa.ImportSubjectPublicKeyInfo(publicKey, out _);
                        keys.Add(new RsaSecurityKey(rsa));
                        return keys;
                    },
                    ValidateIssuerSigningKey = true,
                    AudienceValidator = (IEnumerable<string> audiences, SecurityToken securityToken, TokenValidationParameters validationParameters) =>
                    {
                       if (securityToken is JsonWebToken jwtToken)
                        {
                            var kid = jwtToken.Kid?.ToString().ToLower();
                            var expectedAudience = "";
                            if (ccc.tenants.ContainsKey(kid)) expectedAudience = (ccc.tenants[kid].Audience ?? "").ToLower().Trim();
                            return audiences != null && audiences.Select(t => t.ToLower().Trim()).Contains(expectedAudience);
                        }

                        return false;
                    },
                    IssuerValidator = (string issuer, SecurityToken securityToken, TokenValidationParameters validationParameters) =>
                    {
                        if (securityToken is JsonWebToken jwtToken)
                        {
                            var kid = jwtToken.Kid?.ToString().ToLower();
                            var expectedIssuer = "invalid~~";
                            if (ccc.tenants.ContainsKey(kid)) expectedIssuer = (ccc.tenants[kid].Issuer ?? "").ToLower().Trim();
                            if ((issuer ?? "").ToLower().Trim() != expectedIssuer) throw new SecurityTokenInvalidIssuerException($"unexpected issuer for kid: {kid}");
                        }
                        return issuer;
                    },
                    LifetimeValidator = (DateTime? notBefore, DateTime? expires, SecurityToken securityToken, TokenValidationParameters validationParameters) =>
                    {
                        if (notBefore.HasValue && DateTime.UtcNow > notBefore.Value
                        && expires.HasValue && DateTime.UtcNow < expires.Value)
                            return true;
                        return false;
                    },
                    ClockSkew = TimeSpan.FromMinutes(1)
                };
                options.Events = new JwtBearerEvents
                {
                    //No token (should trigger OnChallenge)
                    //Invalid token (should trigger OnAuthenticationFailed)
                    //Valid token (should trigger OnMessageReceived → OnTokenValidated)
                    OnAuthenticationFailed = ctx =>
                    {
                        var client_id = ctx.Request.ReadRoute(ccc.RouteKey) ?? ccc.ClientId;
                        var state = ctx.Request.Query.ContainsKey("state") ? ctx.Request.Query["state"][0] : "";
                        var code_challenge = ctx.Request.Query.ContainsKey("code_challenge") ? ctx.Request.Query["code_challenge"][0] : "";
                        var ff = $"{ccc.AuthServerUrl}/oauth/{ccc.TenantId}/v1/connect/authorize?response_type=code&client_id={client_id}&redirect_uri={string.Format(ccc.RedirectUri, client_id)}&state={state}&code_challenge={code_challenge}&code_challenge_method=S256&err=invalid_token";
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
                        ctx.HandleResponse();
                        var client_id = ctx.Request.ReadRoute(ccc.RouteKey) ?? ccc.ClientId;
                        var state = ctx.Request.Query.ContainsKey("state") ? ctx.Request.Query["state"][0] : "";
                        // Was a timestamp-derived literal, which any observer could reconstruct —
                        // making the PKCE challenge decorative. Now 256 bits from a CSPRNG.
                        var code_verifier = PkceHelper.GenerateCodeVerifier();
                        var code_challenge = PkceHelper.GenerateCodeChallenge(code_verifier);
                        var ff = $"{ccc.AuthServerUrl}/oauth/{ccc.TenantId}/v1/connect/authorize?response_type=code&client_id={client_id}&redirect_uri={string.Format(ccc.RedirectUri, client_id)}&state={state}&code_challenge={code_challenge}&code_challenge_method=S256&err=token_error";
                        ctx.Response.StoreCookie($"ark_oauth_cv_{client_id}", code_verifier, ccc.ExpireMins, ccc.Domain);
                        ctx.Response.Redirect($"{ff}");
                        return Task.CompletedTask;
                    },
                    OnMessageReceived = msg =>
                    {
                        Console.WriteLine(msg);
                        return Task.CompletedTask;
                    }
                };
            });
        }

        /// <summary>
        /// Legacy middleware that promotes the token cookie into an Authorization header.
        ///
        /// A no-op unless `UseLegacyFlow` is set — under the standard flow the cookie handler
        /// carries the identity, and copying a bearer token out of a cookie on every request is
        /// exactly the pattern that makes an app CSRF-able. Kept callable so existing Program.cs
        /// files continue to compile unchanged.
        /// </summary>
        public static void UseArkOidcClient(this IApplicationBuilder builder)
        {
            // Serves the access-denied page and the switch-user / sign-out posts. Registered
            // ahead of the legacy check because it belongs to both flows, and ahead of
            // UseAuthorization because a page explaining why authorization failed must not
            // itself require authorization.
            builder.UseArkAccountEndpoints();

            var startupConfig = builder.ApplicationServices.GetRequiredService<IConfiguration>();
            if (!LoadConfig(startupConfig).UseLegacyFlow) return;

            builder.Use(async (context, next) =>
            {
                var endpoint = context.GetEndpoint();
                var authorizeData = endpoint?.Metadata.GetOrderedMetadata<IAuthorizeData>();
                if (authorizeData?.Any() == true) //authorize attribute
                {
                    var config = builder.ApplicationServices.GetRequiredService<IConfiguration>();
                    var ccc = LoadConfig(config);
                    var client_id = context.Request.ReadRoute(ccc.RouteKey) ?? ccc.ClientId;
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
        ArkAuthConfig _conf;
        public ArkAuthContext(IHttpContextAccessor http, ArkAuthConfig conf)
        {
            _http = http;
            _conf = conf;
            ip = _http.HttpContext.Request.Cookies["ark_oauth_ip"] ?? "";
            ip = ip.AnyNull() ? _http.HttpContext.Connection.RemoteIpAddress?.ToString() : ip;
            user_id = _http.HttpContext.Request.Cookies["ark_oauth_email"] ?? "";
            foreach (var v in (conf.RouteKey ?? new List<string>()))
            {
                client_id = (_http.HttpContext.Request.RouteValues[v] ?? "").ToString().ToLower();
                if (!client_id.AnyNull()) break;
                client_id = _http.HttpContext.Request.Query.ContainsKey(v) && _http.HttpContext.Request.Query[v].Count > 0 ? (_http.HttpContext.Request.Query[v][0] ?? "").ToString().ToLower() : "";
                if (!client_id.AnyNull()) break;
            }
            client_id = client_id.AnyNull() ? conf.ClientId : client_id;
            tenant_id = conf.TenantId;
            auth_client_config = conf;
            SetUserInfo();
        }
        public string client_id { get; private set; }
        public string tenant_id { get; private set; }
        public string? user_id { get; private set; } //mob or email (opt 1: mob, opt 2: email)
        public string? ip { get; set; }
        public Ark.oAuth.ArkAuthConfig auth_client_config { get; }
        public AUserInfo user_info { get; private set; }
        public void SetUserInfo()
        {
            try
            {
                // Under the standard flow the identity lives on the authenticated principal,
                // built from the ID token and UserInfo response by the OIDC handler. The cookie
                // below is only read when running the legacy flow.
                var principal = _http.HttpContext?.User;
                if (principal?.Identity?.IsAuthenticated == true)
                {
                    string? Claim(params string[] types) => types
                        .Select(t => principal.FindFirst(t)?.Value)
                        .FirstOrDefault(v => !string.IsNullOrEmpty(v));

                    var email = Claim("email", "preferred_username", System.Security.Claims.ClaimTypes.Email);
                    var subject = Claim("sub", System.Security.Claims.ClaimTypes.NameIdentifier);
                    user_id = email ?? subject ?? user_id;
                    user_info = new AUserInfo
                    {
                        client_id = client_id,
                        client_name = client_id,
                        claims = principal.FindAll(_conf.RoleClaimType ?? "role").Select(c => c.Value).ToArray(),
                        user = new AUser
                        {
                            email = email ?? subject ?? "",
                            name = Claim("name", System.Security.Claims.ClaimTypes.Name) ?? "",
                            type = "user"
                        }
                    };
                    return;
                }

                var str = _http.HttpContext?.Request.ReadCookie($"ark_oauth_ui_claims_{client_id}");
                if (str.AnyNull()) return;
                System.Text.Json.JsonDocument tt = System.Text.Json.JsonDocument.Parse(str);
                AUserInfo ui = tt.Deserialize<AUserInfo>();
                user_info = ui;
            }
            catch (Exception ex)
            {
               Console.WriteLine(ex);
            }
        }
    }
}