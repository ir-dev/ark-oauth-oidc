using System.Net;
using System.Net.Security;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Ark.oAuth.Oidc
{
    /// <summary>What <see cref="ArkIdpHosting.AddArkIdp"/> wires up beyond the server itself.</summary>
    public sealed class ArkIdpOptions
    {
        /// <summary>
        /// Sign-in for the bundled admin console: a cookie, and the framework's OIDC handler
        /// pointed at this same server as <c>{TenantId}_client</c>. Turn it off when the host
        /// brings its own authentication — <c>AddArkOidcClient</c>, say — and then set
        /// <c>ark_oauth_server:Admin:SignOutUrl</c> to the host's own sign-out route.
        /// </summary>
        public bool ConsoleSignIn { get; set; } = true;

        /// <summary>
        /// <c>/</c> signs in, then lands on <c>ark_oauth_server:Admin:LandingUrl</c> — the admin
        /// console unless setup chose another page.
        /// </summary>
        public bool MapRootToConsole { get; set; } = true;
    }

    /// <summary>Present when the built-in console sign-in is registered.</summary>
    internal sealed class ArkIdpConsoleMarker
    {
    }

    /// <summary>The scheme names and routes of the built-in console sign-in.</summary>
    public static class ArkIdpConsole
    {
        public const string CookieScheme = "ArkIdpConsole";
        public const string OidcScheme = "ArkIdpConsoleOidc";
        /// <summary>
        /// Signs in, then goes on: to <c>?returnUrl=</c> when it names a page on this server,
        /// otherwise to the landing page. A host's "Sign in" link points here.
        /// </summary>
        public const string SignInPath = "/ark-idp/signin";
        public const string SignOutPath = "/ark-idp/signout";
        public const string AuthErrorPath = "/ark-idp/auth-error";

        /// <summary>
        /// Where a sign-in started for no page in particular ends: <c>ark_oauth_server:Admin:LandingUrl</c>,
        /// a path in this app or an address anywhere; else the server's root — which, while
        /// <c>/</c> is the console's, means the console.
        /// </summary>
        internal static string LandingUrl(HttpContext ctx)
        {
            var sp = ctx.RequestServices;
            var configured = (sp.GetRequiredService<IConfiguration>()["ark_oauth_server:Admin:LandingUrl"] ?? "").Trim();
            if (Uri.TryCreate(configured, UriKind.Absolute, out var url) && url.Scheme is "http" or "https") return configured;
            var pathBase = ctx.Request.PathBase;
            // The root, or one of sign-in's own routes, would loop — refused by the wizard, but
            // settings.json can be edited by hand.
            if (IsLocalUrl(configured) && !IsRoot(configured) && !IsReservedPath(configured)) return $"{pathBase}{configured}";
            return sp.GetService<ArkIdpOptions>()?.MapRootToConsole ?? true ? $"{pathBase}/admin" : $"{pathBase}/";
        }

        /// <summary>A path on this server. Not <c>//host</c> or <c>/\host</c>, which a browser reads as another site.</summary>
        internal static bool IsLocalUrl(string? url) =>
            !string.IsNullOrEmpty(url) && url[0] == '/' &&
            (url.Length == 1 || url[1] is not ('/' or '\\')) && !url.Any(char.IsControl);

        /// <summary>The app's root, whatever its query string: a sign-in for no page in particular.</summary>
        internal static bool IsRoot(string? url, PathString pathBase = default)
        {
            if (string.IsNullOrEmpty(url)) return true;
            var path = url.Split('?', '#')[0];
            return path == $"{pathBase}/" || (pathBase.HasValue && path == pathBase.Value);
        }

        /// <summary>Sign-in's own routes and callbacks. Landing on one would sign in, or out, again.</summary>
        internal static bool IsReservedPath(string localUrl)
        {
            var path = new PathString(localUrl.Split('?', '#')[0]);
            return path.StartsWithSegments("/ark-idp") || path.StartsWithSegments("/signin-oidc") ||
                   path.StartsWithSegments("/signout-callback-oidc");
        }
    }

    /// <summary>
    /// The whole identity provider in two calls.
    ///
    /// <code>
    /// var builder = WebApplication.CreateBuilder(args);
    /// builder.AddArkIdp();
    /// var app = builder.Build();
    /// app.UseArkIdp();
    /// app.Run();
    /// </code>
    ///
    /// Nothing has to be configured first. Started with no tenant and no database, the server
    /// opens the setup wizard (see <see cref="ArkSetupMiddleware"/>); once that is done the same
    /// process is the IdP, and <c>/</c> leads to its sign-in page. A server configured through
    /// appsettings, user secrets or the environment skips the wizard entirely.
    ///
    /// The lower-level calls — <c>AddArkOidcServer</c>, <c>UseArkAuthData</c> and a host-chosen
    /// client — still work, and get the wizard too, from <c>UseArkAuthData</c>.
    /// </summary>
    public static class ArkIdpHosting
    {
        public static WebApplicationBuilder AddArkIdp(this WebApplicationBuilder builder, Action<ArkIdpOptions>? configure = null)
        {
            var options = new ArkIdpOptions();
            configure?.Invoke(options);

            // Attached here, before anything reads configuration, so a server set up on an earlier
            // run starts with its settings rather than acquiring them on the first request.
            ArkIdpSettings.Attach(builder.Configuration, builder.Environment);

            builder.Services.AddArkOidcServer(builder.Environment);
            builder.Services.AddSingleton(options);
            if (options.ConsoleSignIn) builder.Services.AddArkIdpConsoleSignIn();
            return builder;
        }

        /// <summary>
        /// The request pipeline, in the order it has to be in. Call it where a host would call
        /// <c>UseRouting</c>; anything the host adds before it (exception handling, HSTS,
        /// forwarded headers) runs first.
        /// </summary>
        public static WebApplication UseArkIdp(this WebApplication app)
        {
            var options = app.Services.GetService<ArkIdpOptions>() ?? new ArkIdpOptions();

            app.UseStaticFiles();
            // Routing before CORS, authentication and authorization: each reads the endpoint.
            app.UseRouting();
            app.UseArkOidcCors();
            app.UseArkAuthData();   // the setup wizard, then the one-time database bootstrap
            app.UseAuthentication();
            app.UseAuthorization();
            app.MapControllers();   // every IdP route is attribute-routed
            if (options.ConsoleSignIn) app.MapArkIdpConsole(options.MapRootToConsole);
            return app;
        }

        internal static void AddArkIdpConsoleSignIn(this IServiceCollection services)
        {
            services.AddSingleton<ArkIdpConsoleMarker>();
            services.AddHttpContextAccessor();

            services.AddAuthentication(o =>
                {
                    o.DefaultScheme = ArkIdpConsole.CookieScheme;
                    o.DefaultChallengeScheme = ArkIdpConsole.OidcScheme;
                })
                .AddCookie(ArkIdpConsole.CookieScheme, o =>
                {
                    o.Cookie.Name = "ark_idp_console";
                    o.Cookie.HttpOnly = true;
                    o.Cookie.SameSite = SameSiteMode.Lax;
                    // SameAsRequest, not Always: `dotnet run` also listens on http://localhost.
                    o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                    o.ExpireTimeSpan = TimeSpan.FromHours(8);
                    o.SlidingExpiration = true;
                    o.AccessDeniedPath = ArkIdpConsole.AuthErrorPath;
                })
                .AddOpenIdConnect(ArkIdpConsole.OidcScheme, o =>
                {
                    o.SignInScheme = ArkIdpConsole.CookieScheme;
                    o.ResponseType = OpenIdConnectResponseType.Code;
                    o.ResponseMode = OpenIdConnectResponseMode.Query;
                    o.UsePkce = true;
                    // The two paths the seed registers for the console client, byte for byte.
                    o.CallbackPath = "/signin-oidc";
                    o.SignedOutCallbackPath = "/signout-callback-oidc";
                    o.SaveTokens = true;  // the id_token is the end-session hint
                    o.GetClaimsFromUserInfoEndpoint = true;
                    o.MapInboundClaims = false;
                    o.Scope.Clear();
                    o.Scope.Add("openid");
                    o.Scope.Add("profile");
                    o.Scope.Add("email");
                    o.TokenValidationParameters = new TokenValidationParameters
                    {
                        NameClaimType = "name",
                        RoleClaimType = "role"
                    };
                    // The code is redeemed at this server's own public address. Under `dotnet run`
                    // that is localhost on a development certificate the process may not trust;
                    // a loopback hop has nobody in the middle to protect against.
                    o.BackchannelHttpHandler = new HttpClientHandler
                    {
                        ServerCertificateCustomValidationCallback = (message, _, _, errors) =>
                            errors == SslPolicyErrors.None || message.RequestUri?.IsLoopback == true
                    };
                    o.Events = new OpenIdConnectEvents
                    {
                        OnTokenValidated = ctx =>
                        {
                            // ark_claims ride on the access token; as roles they reach the
                            // operator check (an "admin" claim makes a second operator).
                            var identity = ctx.Principal?.Identity as ClaimsIdentity;
                            var accessToken = ctx.TokenEndpointResponse?.AccessToken;
                            if (identity == null || string.IsNullOrEmpty(accessToken)) return Task.CompletedTask;
                            try
                            {
                                foreach (var claim in new JsonWebToken(accessToken).Claims.Where(c => c.Type == "ark_claims"))
                                    identity.AddClaim(new Claim("role", claim.Value));
                            }
                            catch (ArgumentException) { }
                            return Task.CompletedTask;
                        },
                        OnTicketReceived = ctx =>
                        {
                            // Signed in and validated. The page the sign-in was started on the
                            // way to wins — the challenge carried it through the IdP in `state`.
                            // One started at the root was for no page in particular: it lands.
                            if (ArkIdpConsole.IsRoot(ctx.ReturnUri, ctx.Request.PathBase))
                                ctx.ReturnUri = ArkIdpConsole.LandingUrl(ctx.HttpContext);
                            return Task.CompletedTask;
                        },
                        OnRemoteFailure = ctx =>
                        {
                            // Not "/": that is the console, which would challenge straight back here.
                            ctx.HandleResponse();
                            var reason = Uri.EscapeDataString(ctx.Failure?.Message ?? "authentication_failed");
                            ctx.Response.Redirect($"{ctx.Request.PathBase}{ArkIdpConsole.AuthErrorPath}?reason={reason}");
                            return Task.CompletedTask;
                        }
                    };
                });

            // Who the console is depends on configuration the setup wizard may only write later,
            // so it is read when the options are built, and the options are rebuilt whenever
            // configuration reloads.
            services.AddOptions<OpenIdConnectOptions>(ArkIdpConsole.OidcScheme)
                .Configure<IConfiguration, IServiceProvider>((o, config, sp) =>
                {
                    var tenant = (config["ark_oauth_server:TenantId"] ?? "").Trim();
                    // Never used unconfigured — the setup gate answers first — but the handler
                    // refuses to initialise without a client id.
                    o.ClientId = tenant.Length == 0 ? "ark-idp-unconfigured" : $"{tenant}_client";
                    o.ConfigurationManager = new ArkSelfConfigurationManager(sp);
                });
            services.AddSingleton<IOptionsChangeTokenSource<OpenIdConnectOptions>>(sp =>
                new ConfigurationChangeTokenSource<OpenIdConnectOptions>(ArkIdpConsole.OidcScheme, sp.GetRequiredService<IConfiguration>()));
        }

        internal static void MapArkIdpConsole(this WebApplication app, bool mapRoot)
        {
            if (mapRoot)
                app.MapGet("/", (HttpContext ctx) => SignInAndGo(ctx, $"{ctx.Request.PathBase}/"));

            app.MapGet(ArkIdpConsole.SignInPath, (HttpContext ctx, string? returnUrl) =>
                SignInAndGo(ctx, ArkIdpConsole.IsLocalUrl(returnUrl) ? returnUrl! : $"{ctx.Request.PathBase}/"));

            // Both sessions: the console's cookie here, and the IdP's through end_session —
            // dropping only the first would sign the next visitor straight back in.
            app.MapGet(ArkIdpConsole.SignOutPath, (HttpContext ctx) =>
            {
                var home = new AuthenticationProperties { RedirectUri = $"{ctx.Request.PathBase}/" };
                return ctx.User.Identity?.IsAuthenticated == true
                    ? Results.SignOut(home, new List<string> { ArkIdpConsole.CookieScheme, ArkIdpConsole.OidcScheme })
                    : Results.Redirect(home.RedirectUri);
            });

            app.MapGet(ArkIdpConsole.AuthErrorPath, (HttpContext ctx) =>
            {
                var reason = ctx.Request.Query["reason"].ToString();
                var root = ctx.Request.PathBase.ToString();
                var message = string.IsNullOrWhiteSpace(reason)
                    ? "Your account does not have access to this page."
                    : reason;
                var html = $$$"""
                    <!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
                    <title>Sign-in did not complete</title>
                    <style>body{font:15px/1.5 system-ui,sans-serif;margin:0;display:grid;place-items:center;min-height:100vh;background:#f4f6fb;color:#16192b}
                    main{max-width:32rem;margin:1rem;padding:2rem;background:#fff;border:1px solid #dfe4ee;border-radius:12px}
                    h1{font-size:1.25rem;margin:0 0 .5rem}code{display:block;white-space:pre-wrap;background:#f7f9fc;padding:.75rem;border-radius:8px;margin:1rem 0}
                    a{color:#3457d5}@media (prefers-color-scheme:dark){body{background:#0f1220;color:#e6e9f2}main{background:#171b2e;border-color:#2a3050}code{background:#11142a}a{color:#8ea6ff}}</style>
                    </head><body><main><h1>Sign-in did not complete</h1><code>{{{WebUtility.HtmlEncode(message)}}}</code>
                    <p><a href="{{{WebUtility.HtmlEncode(root)}}}{{{ArkIdpConsole.SignInPath}}}">Try again</a> · <a href="{{{WebUtility.HtmlEncode(root)}}}{{{ArkIdpConsole.SignOutPath}}}">Sign out and use another account</a></p></main></body></html>
                    """;
                return Results.Content(html, "text/html; charset=utf-8");
            });
        }

        /// <summary>
        /// Signed in: on to <paramref name="target"/>, or to the landing page when that is the
        /// root. Not yet: sign in first, carrying the target — <c>OnTicketReceived</c> makes the
        /// same choice once the tokens are validated.
        /// </summary>
        static IResult SignInAndGo(HttpContext ctx, string target)
        {
            if (ctx.User.Identity?.IsAuthenticated != true)
                return Results.Challenge(new AuthenticationProperties { RedirectUri = target }, new List<string> { ArkIdpConsole.OidcScheme });
            return Results.Redirect(ArkIdpConsole.IsRoot(target, ctx.Request.PathBase) ? ArkIdpConsole.LandingUrl(ctx) : target);
        }
    }

    /// <summary>
    /// The console's OIDC metadata and signing keys, read from this process instead of fetched.
    ///
    /// The console is a client of the server it runs in. Fetching that server's discovery
    /// document over HTTP means the process has to reach its own public address — through a
    /// load balancer, a container's port mapping, a certificate it may not trust — before anyone
    /// can sign in. The same values are a database read away. Only the code redemption still
    /// goes over HTTP, because that is the token endpoint doing its job.
    /// </summary>
    internal sealed class ArkSelfConfigurationManager : IConfigurationManager<OpenIdConnectConfiguration>
    {
        readonly IServiceProvider _services;
        OpenIdConnectConfiguration? _cached;
        DateTime _expires;

        public ArkSelfConfigurationManager(IServiceProvider services) => _services = services;

        public async Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancel)
        {
            var cached = _cached;
            if (cached != null && DateTime.UtcNow < _expires) return cached;

            using var scope = _services.CreateScope();
            var sp = scope.ServiceProvider;
            var ser = sp.GetRequiredService<IConfiguration>().GetSection("ark_oauth_server").Get<ArkAuthServerConfig>()
                      ?? throw new InvalidOperationException("ark_oauth_server is not configured");
            var http = sp.GetService<IHttpContextAccessor>()?.HttpContext;
            var ep = http != null
                ? Protocol.ArkOidcEndpoints.For(http.Request, ser, ser.TenantId)
                : Protocol.ArkOidcEndpoints.For(ser, ser.TenantId);

            var keys = sp.GetRequiredService<Protocol.ArkKeyService>();
            var published = await keys.GetPublishedKeysAsync(ser.TenantId);

            var configuration = new OpenIdConnectConfiguration
            {
                Issuer = ep.Issuer,
                AuthorizationEndpoint = ep.Authorization,
                TokenEndpoint = ep.Token,
                UserInfoEndpoint = ep.UserInfo,
                EndSessionEndpoint = ep.EndSession,
                JwksUri = ep.Jwks
            };
            foreach (var key in keys.GetValidationKeys(published)) configuration.SigningKeys.Add(key);

            _cached = configuration;
            _expires = DateTime.UtcNow.AddMinutes(5);
            return configuration;
        }

        /// <summary>Called by the handler when a token names a key it does not have: a rotation.</summary>
        public void RequestRefresh() => _cached = null;
    }

    /// <summary>
    /// Serves <see cref="Protocol.ArkCors.PolicyName"/> from current configuration on every
    /// request, and every other policy as the framework would.
    ///
    /// The framework builds named policies once, so origins added after start-up — by the setup
    /// wizard, or by editing settings — would wait for a restart.
    /// </summary>
    internal sealed class ArkCorsPolicyProvider : ICorsPolicyProvider
    {
        readonly DefaultCorsPolicyProvider _inner;
        readonly IConfiguration _config;

        public ArkCorsPolicyProvider(IOptions<CorsOptions> options, IConfiguration config)
        {
            _inner = new DefaultCorsPolicyProvider(options);
            _config = config;
        }

        public Task<CorsPolicy?> GetPolicyAsync(HttpContext context, string? policyName)
        {
            if (policyName != Protocol.ArkCors.PolicyName) return _inner.GetPolicyAsync(context, policyName);
            var options = new CorsOptions();
            new ArkCorsConfigurator(_config).Configure(options);
            return Task.FromResult(options.GetPolicy(Protocol.ArkCors.PolicyName));
        }

        /// <summary>Takes over from the framework's provider, never from one the host chose.</summary>
        internal static void Register(IServiceCollection services)
        {
            var existing = services.FirstOrDefault(d => d.ServiceType == typeof(ICorsPolicyProvider));
            if (existing != null && existing.ImplementationType != typeof(DefaultCorsPolicyProvider)) return;
            services.Replace(ServiceDescriptor.Transient<ICorsPolicyProvider, ArkCorsPolicyProvider>());
        }
    }
}
