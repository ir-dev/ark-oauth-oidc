using System.Net.Http.Headers;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Ark.oAuth
{
    /// <summary>
    /// The standards-based Ark client.
    ///
    /// This is a thin configuration layer over ASP.NET Core's own OpenID Connect and cookie
    /// handlers rather than a hand-rolled protocol implementation. That single decision fixes
    /// most of what was wrong with the previous client:
    ///
    ///  * PKCE verifiers are cryptographically random per request. The old client derived the
    ///    verifier from a timestamp, so anyone could predict it and PKCE protected nothing.
    ///  * `state` and `nonce` are generated and checked, closing CSRF and token-replay holes.
    ///  * Signing keys come from the provider's JWKS endpoint and refresh on rotation, instead
    ///    of a base64 public key pasted into appsettings.json by hand.
    ///  * Tokens live in an encrypted authentication cookie, not a readable one, and are no
    ///    longer copied into an Authorization header from a cookie on every request.
    ///
    /// Because it is the standard handler underneath, an Ark client can authenticate against
    /// any compliant provider — Entra ID, Okta, Auth0, Keycloak — by changing Authority alone.
    /// </summary>
    public static class ArkOidcClient
    {
        public const string CookieScheme = "ArkCookie";
        public const string OidcScheme = "ArkOidc";

        /// <summary>
        /// Wires up interactive sign-in with the authorization code flow and PKCE.
        /// </summary>
        public static AuthenticationBuilder AddArkOidcInteractive(
            this IServiceCollection services, ArkAuthConfig config) =>
            services.AddArkOidcInteractive(config, null);

        /// <summary>
        /// As above, plus the host's <see cref="ArkClientEvents"/> — the hooks that let an
        /// application decide entitlement for itself and render its own access-denied page.
        /// </summary>
        public static AuthenticationBuilder AddArkOidcInteractive(
            this IServiceCollection services, ArkAuthConfig config, ArkClientEvents? events)
        {
            var switching = config.AccountSwitch ?? new ArkAccountSwitchOptions();
            var authority = config.ResolveAuthority();
            if (string.IsNullOrWhiteSpace(authority))
                throw new ApplicationException(
                    "ark_oauth_client: set 'Authority' (or 'AuthServerUrl' + 'TenantId') to the issuer URL of your Ark server.");

            var builder = services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieScheme;
                options.DefaultChallengeScheme = OidcScheme;
                options.DefaultSignOutScheme = OidcScheme;
            });

            builder.AddCookie(CookieScheme, options =>
            {
                options.Cookie.Name = config.CookieName ?? "ark_auth";
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.Always;
                options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax;
                options.ExpireTimeSpan = TimeSpan.FromMinutes(config.ExpireMins <= 0 ? 480 : config.ExpireMins);
                options.SlidingExpiration = false;
                if (!string.IsNullOrWhiteSpace(config.Domain) && config.Domain != "localhost")
                    options.Cookie.Domain = config.Domain;

                // Refresh silently just before the access token expires, so a signed-in user is
                // not bounced back to the IdP mid-session.
                options.Events.OnValidatePrincipal = ArkTokenRefresher.ValidateAsync;

                // Where an [Authorize] policy sends a user who is signed in but not permitted.
                // The framework's default is /Account/AccessDenied, which most applications never
                // create, so the user meets a 404 instead of an explanation.
                options.AccessDeniedPath = switching.AccessDeniedPath;
                options.Events.OnRedirectToAccessDenied = async ctx =>
                {
                    // Recorded before the redirect so the page can name the account that was
                    // refused, and so a host handler sees the same event for a 403 as for a
                    // refused callback.
                    await ArkAccessGate.DenyAsync(ctx.HttpContext, config, events,
                        ArkAccessDeniedReasons.Forbidden, ctx.HttpContext.User,
                        ctx.HttpContext.User.FindAll(config.RoleClaimType ?? "role").Select(c => c.Value).ToList(),
                        ctx.Request.Path + ctx.Request.QueryString);
                };
            });

            builder.AddOpenIdConnect(OidcScheme, options =>
            {
                options.Authority = authority;
                options.ClientId = config.ClientId;
                options.ClientSecret = string.IsNullOrWhiteSpace(config.ClientSecret) ? null : config.ClientSecret;

                // Authorization code + PKCE. Implicit and hybrid are deliberately not offered:
                // OAuth 2.1 removes them, and this server does not issue tokens from /authorize.
                options.ResponseType = OpenIdConnectResponseType.Code;
                options.UsePkce = true;
                options.ResponseMode = OpenIdConnectResponseMode.Query;

                options.CallbackPath = config.CallbackPath ?? "/signin-oidc";
                options.SignedOutCallbackPath = config.SignedOutCallbackPath ?? "/signout-callback-oidc";
                options.SignedOutRedirectUri = config.SignedOutRedirectUri ?? "/";
                options.SignInScheme = CookieScheme;

                options.SaveTokens = true;
                options.GetClaimsFromUserInfoEndpoint = true;
                options.MapInboundClaims = false; // keep JWT claim names ("sub", not the WS-Fed URI)

                // Only ever relaxed for local development against an http endpoint.
                options.RequireHttpsMetadata = config.RequireHttpsMetadata;

                options.Scope.Clear();
                foreach (var scope in config.ResolveScopes()) options.Scope.Add(scope);

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                    RoleClaimType = config.RoleClaimType ?? "role",
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidAudience = config.ClientId,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromMinutes(1)
                };

                options.Events = new OpenIdConnectEvents
                {
                    // The only place a caller can influence the authorize request. The handler
                    // builds it internally, so parameters like prompt travel as authentication
                    // properties and are copied onto the message here — which is what makes
                    // "sign in as a different user" possible at all: without prompt=login the
                    // provider answers the challenge from the session it already has, and the
                    // wrong person is signed in again.
                    OnRedirectToIdentityProvider = ctx =>
                    {
                        var items = ctx.Properties.Items;
                        if (items.TryGetValue(ArkChallengeProperties.PromptItem, out var prompt)
                            && !string.IsNullOrWhiteSpace(prompt))
                            ctx.ProtocolMessage.Prompt = prompt;
                        if (items.TryGetValue(ArkChallengeProperties.LoginHintItem, out var hint)
                            && !string.IsNullOrWhiteSpace(hint))
                            ctx.ProtocolMessage.LoginHint = hint;
                        if (items.TryGetValue(ArkChallengeProperties.MaxAgeItem, out var maxAge)
                            && !string.IsNullOrWhiteSpace(maxAge))
                            ctx.ProtocolMessage.MaxAge = maxAge;
                        return Task.CompletedTask;
                    },
                    OnTicketReceived = async ctx =>
                    {
                        // Last point before the authentication cookie is written. Refusing here
                        // rather than at the first protected page is the whole difference: the
                        // browser never ends up holding a session for an account that cannot use
                        // this application.
                        if (!switching.RequireArkClaims && events?.OnEvaluateAccess == null) return;

                        var claims = ArkAccessGate.ReadClaims(ctx.Properties?.GetTokenValue("access_token"));
                        if (await ArkAccessGate.AllowedAsync(ctx.HttpContext, config, events, ctx.Principal, claims))
                            return;

                        ctx.HandleResponse(); // suppresses the sign-in
                        await ArkAccessGate.DenyAsync(ctx.HttpContext, config, events,
                            ArkAccessDeniedReasons.NoAppAccess, ctx.Principal, claims,
                            ctx.Properties?.RedirectUri);
                    },
                    OnRemoteFailure = ctx =>
                    {
                        // A failed callback should land somewhere useful rather than throwing a
                        // raw exception page at the user.
                        ctx.HandleResponse();
                        var reason = Uri.EscapeDataString(ctx.Failure?.Message ?? "authentication_failed");
                        ctx.Response.Redirect($"{config.AuthErrorPath ?? "/"}?auth_error={reason}");
                        return Task.CompletedTask;
                    },
                    OnTokenValidated = ctx =>
                    {
                        // Ark issues its authorization claims as `ark_claims`; project them onto
                        // the principal so [Authorize] policies can use them directly.
                        var identity = ctx.Principal?.Identity as ClaimsIdentity;
                        var accessToken = ctx.TokenEndpointResponse?.AccessToken;
                        if (identity != null && !string.IsNullOrEmpty(accessToken))
                        {
                            foreach (var value in ArkClaimReader.ReadArkClaims(accessToken!))
                                identity.AddClaim(new Claim(config.RoleClaimType ?? "role", value));
                        }
                        return Task.CompletedTask;
                    }
                };
            });

            return builder;
        }

        /// <summary>
        /// Adds JWT bearer validation for API endpoints, with signing keys taken from the
        /// provider's JWKS document rather than a statically configured public key.
        /// </summary>
        public static AuthenticationBuilder AddArkOidcApi(
            this AuthenticationBuilder builder, ArkAuthConfig config, string scheme = JwtBearerDefaults.AuthenticationScheme)
        {
            var authority = config.ResolveAuthority();
            return builder.AddJwtBearer(scheme, options =>
            {
                options.Authority = authority;
                options.RequireHttpsMetadata = config.RequireHttpsMetadata;
                options.MapInboundClaims = false;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "sub",
                    RoleClaimType = config.RoleClaimType ?? "role",
                    ValidateIssuer = true,
                    ValidateAudience = !string.IsNullOrWhiteSpace(config.Audience),
                    ValidAudience = config.Audience,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ClockSkew = TimeSpan.FromMinutes(1)
                };
            });
        }
    }

    /// <summary>
    /// Keeps the access token in the authentication cookie fresh.
    ///
    /// ASP.NET Core does not refresh OIDC tokens on its own — without this, a session survives
    /// only as long as the first access token, and the user is redirected back to the IdP the
    /// moment it expires.
    /// </summary>
    internal static class ArkTokenRefresher
    {
        // Refresh a little before expiry so a request in flight never carries a dead token.
        private static readonly TimeSpan RefreshWindow = TimeSpan.FromMinutes(2);

        public static async Task ValidateAsync(CookieValidatePrincipalContext ctx)
        {
            var expiresAtValue = ctx.Properties.GetTokenValue("expires_at");
            var refreshToken = ctx.Properties.GetTokenValue("refresh_token");
            if (string.IsNullOrEmpty(expiresAtValue) || string.IsNullOrEmpty(refreshToken)) return;
            if (!DateTimeOffset.TryParse(expiresAtValue, out var expiresAt)) return;
            if (expiresAt - DateTimeOffset.UtcNow > RefreshWindow) return;

            var services = ctx.HttpContext.RequestServices;
            var config = services.GetService(typeof(ArkAuthConfig)) as ArkAuthConfig;
            var httpFactory = services.GetService(typeof(IHttpClientFactory)) as IHttpClientFactory;
            if (config == null || httpFactory == null) return;

            try
            {
                var http = httpFactory.CreateClient("ark-oidc-client");
                var metadata = await ArkDiscoveryCache.GetAsync(http, config.ResolveAuthority());
                if (metadata?.TokenEndpoint == null) return;

                var form = new Dictionary<string, string>
                {
                    ["grant_type"] = "refresh_token",
                    ["refresh_token"] = refreshToken!,
                    ["client_id"] = config.ClientId
                };
                if (!string.IsNullOrWhiteSpace(config.ClientSecret)) form["client_secret"] = config.ClientSecret!;

                var response = await http.PostAsync(metadata.TokenEndpoint, new FormUrlEncodedContent(form));
                if (!response.IsSuccessStatusCode)
                {
                    // The refresh token is gone, revoked, or was replayed and its family revoked.
                    // Drop the session so the user is asked to sign in again.
                    ctx.RejectPrincipal();
                    await ctx.HttpContext.SignOutAsync(ArkOidcClient.CookieScheme);
                    return;
                }

                var payload = System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
                var tokens = new List<AuthenticationToken>
                {
                    new() { Name = "access_token", Value = payload.GetProperty("access_token").GetString()! }
                };
                if (payload.TryGetProperty("refresh_token", out var newRefresh))
                    tokens.Add(new AuthenticationToken { Name = "refresh_token", Value = newRefresh.GetString()! });
                else
                    tokens.Add(new AuthenticationToken { Name = "refresh_token", Value = refreshToken! });
                if (payload.TryGetProperty("id_token", out var idToken))
                    tokens.Add(new AuthenticationToken { Name = "id_token", Value = idToken.GetString()! });

                var lifetime = payload.TryGetProperty("expires_in", out var expiresIn) ? expiresIn.GetInt32() : 3600;
                tokens.Add(new AuthenticationToken
                {
                    Name = "expires_at",
                    Value = DateTimeOffset.UtcNow.AddSeconds(lifetime).ToString("o")
                });

                ctx.Properties.StoreTokens(tokens);
                ctx.ShouldRenew = true;
            }
            catch
            {
                // A transient refresh failure must not sign the user out; the next request retries.
            }
        }
    }

    /// <summary>Caches the provider's discovery document so refresh does not refetch it each time.</summary>
    internal static class ArkDiscoveryCache
    {
        private static readonly SemaphoreSlim Gate = new(1, 1);
        private static readonly Dictionary<string, (OpenIdConnectConfiguration config, DateTimeOffset fetchedAt)> Cache = new();
        private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(30);

        public static async Task<OpenIdConnectConfiguration?> GetAsync(HttpClient http, string authority)
        {
            if (string.IsNullOrWhiteSpace(authority)) return null;
            await Gate.WaitAsync();
            try
            {
                if (Cache.TryGetValue(authority, out var hit) && DateTimeOffset.UtcNow - hit.fetchedAt < Ttl)
                    return hit.config;

                var json = await http.GetStringAsync($"{authority.TrimEnd('/')}/.well-known/openid-configuration");
                var config = OpenIdConnectConfiguration.Create(json);
                Cache[authority] = (config, DateTimeOffset.UtcNow);
                return config;
            }
            catch
            {
                return Cache.TryGetValue(authority, out var stale) ? stale.config : null;
            }
            finally
            {
                Gate.Release();
            }
        }
    }

    /// <summary>Reads Ark's `ark_claims` array out of an access token without validating it again.</summary>
    internal static class ArkClaimReader
    {
        public static IEnumerable<string> ReadArkClaims(string accessToken)
        {
            try
            {
                var token = new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(accessToken);
                return token.Claims.Where(c => c.Type == "ark_claims").Select(c => c.Value).ToList();
            }
            catch
            {
                return Array.Empty<string>();
            }
        }
    }

    /// <summary>Convenience accessors for the tokens the handler stored in the auth cookie.</summary>
    public static class ArkTokenAccessors
    {
        public static Task<string?> GetArkAccessTokenAsync(this HttpContext context) =>
            context.GetTokenAsync(ArkOidcClient.CookieScheme, "access_token");

        public static Task<string?> GetArkIdTokenAsync(this HttpContext context) =>
            context.GetTokenAsync(ArkOidcClient.CookieScheme, "id_token");

        public static Task<string?> GetArkRefreshTokenAsync(this HttpContext context) =>
            context.GetTokenAsync(ArkOidcClient.CookieScheme, "refresh_token");

        /// <summary>Attaches the caller's access token to an outgoing request to a downstream API.</summary>
        public static async Task<HttpRequestMessage> WithArkTokenAsync(this HttpRequestMessage request, HttpContext context)
        {
            var token = await context.GetArkAccessTokenAsync();
            if (!string.IsNullOrEmpty(token))
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            return request;
        }
    }
}
