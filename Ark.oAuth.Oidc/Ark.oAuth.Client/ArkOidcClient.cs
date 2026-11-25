using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
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

        /// <summary>The named HttpClient every call to the provider is made with.</summary>
        internal const string HttpClientName = "ark-oidc-client";

        /// <summary>
        /// Registers it. Redirects are not followed: these requests carry a client secret or a
        /// refresh token, and a redirect would forward them somewhere else.
        /// </summary>
        internal static void AddArkHttpClient(this IServiceCollection services) =>
            services.AddHttpClient(HttpClientName, c => c.Timeout = TimeSpan.FromSeconds(15))
                // Changes the handler there is rather than supplying one, so an application that
                // configured its own (a proxy, a development certificate) keeps it.
                .ConfigurePrimaryHttpMessageHandler((handler, _) =>
                {
                    if (handler is HttpClientHandler client) client.AllowAutoRedirect = false;
                    else if (handler is SocketsHttpHandler sockets) sockets.AllowAutoRedirect = false;
                });

        /// <summary>
        /// This package's version, as published to nuget.org.
        ///
        /// Read off the assembly rather than kept as a literal, so it cannot drift from the
        /// csproj. Source Link appends "+{commit}" on a CI build; that is trimmed, because the
        /// number worth quoting is the release. Public because the built-in access-denied page
        /// prints it, and a host that replaces that page with its own wants the same string —
        /// on a shared browser it is the one screen where knowing which client is talking to
        /// the provider settles the question.
        /// </summary>
        public static readonly string Version = ReadVersion();

        private static string ReadVersion()
        {
            var assembly = typeof(ArkOidcClient).Assembly;
            var informational = assembly
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;

            if (string.IsNullOrWhiteSpace(informational))
                return assembly.GetName().Version?.ToString() ?? "";

            var plus = informational.IndexOf('+');
            return plus < 0 ? informational : informational.Substring(0, plus);
        }

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
                options.Events.OnValidatePrincipal = ctx => ArkTokenRefresher.ValidateAsync(ctx, config, events);

                // A request that was already on its way when the user signed out must not be
                // answered with the tokens a refresh has just produced, and a new cookie with them.
                options.Events.OnSigningOut = ctx =>
                {
                    ArkRefreshes.Forget(ctx.HttpContext.Features.Get<IAuthenticateResultFeature>()
                        ?.AuthenticateResult?.Properties?.GetTokenValue("refresh_token"));
                    return Task.CompletedTask;
                };

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
                        // max_age travels through the browser, so only the answer says whether the
                        // provider honoured it (OIDC Core §3.1.3.7, 13).
                        var refusal = ArkChallengeProperties.MaxAgeRefusal(ctx.Properties, ctx.Principal);
                        if (refusal != null)
                        {
                            ctx.Fail(refusal);
                            return Task.CompletedTask;
                        }

                        // Ark issues its authorization claims as `ark_claims`; project them onto
                        // the principal so [Authorize] policies can use them directly.
                        var identity = ctx.Principal?.Identity as ClaimsIdentity;
                        var accessToken = ctx.TokenEndpointResponse?.AccessToken;
                        if (identity != null && !string.IsNullOrEmpty(accessToken))
                            ArkRoles.Project(identity, config.RoleClaimType ?? "role", ArkClaimReader.ReadArkClaims(accessToken!));
                        return Task.CompletedTask;
                    }
                };
            });

            return builder;
        }

        /// <summary>
        /// Adds JWT bearer validation for API endpoints, with signing keys taken from the
        /// provider's JWKS document rather than a statically configured public key.
        ///
        /// The audience is <see cref="ArkAuthConfig.Audience"/> when that is set. Otherwise it is
        /// the one the provider publishes for this tenant's ordinary access tokens
        /// (<c>ark_access_token_audience</c>), so a token addressed to one agent (A2A) or one MCP
        /// endpoint is refused here. See <see cref="ArkAudience"/>.
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
                    ValidateAudience = true,
                    ValidAudience = string.IsNullOrWhiteSpace(config.Audience) ? null : config.Audience,
                    AudienceValidator = string.IsNullOrWhiteSpace(config.Audience) ? ArkAudience.Validate : null,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ClockSkew = TimeSpan.FromMinutes(1),
                    // An ID token is signed by the same keys under the same issuer; the header
                    // type is what tells the two apart (see RequireAccessTokenTypeHeader).
                    ValidTypes = config.RequireAccessTokenTypeHeader ? new[] { "at+jwt", "application/at+jwt" } : null
                };
            });
        }
    }

    /// <summary>
    /// Keeps the access token in the authentication cookie fresh, and what the cookie says about
    /// the user with it.
    ///
    /// ASP.NET Core does not refresh OIDC tokens on its own — without this, a session survives
    /// only as long as the first access token, and the user is redirected back to the IdP the
    /// moment it expires.
    /// </summary>
    internal static class ArkTokenRefresher
    {
        // Refresh a little before expiry so a request in flight never carries a dead token.
        private static readonly TimeSpan RefreshWindow = TimeSpan.FromMinutes(2);

        public static async Task ValidateAsync(
            CookieValidatePrincipalContext ctx, ArkAuthConfig config, ArkClientEvents? events)
        {
            var expiresAtValue = ctx.Properties.GetTokenValue("expires_at");
            var refreshToken = ctx.Properties.GetTokenValue("refresh_token");
            if (string.IsNullOrEmpty(expiresAtValue) || string.IsNullOrEmpty(refreshToken)) return;
            if (!DateTimeOffset.TryParse(expiresAtValue, out var expiresAt)) return;
            if (expiresAt - DateTimeOffset.UtcNow > RefreshWindow) return;

            var services = ctx.HttpContext.RequestServices;
            if (services.GetService(typeof(IHttpClientFactory)) is not IHttpClientFactory httpFactory) return;

            var outcome = await ArkRefreshes.RedeemAsync(refreshToken!, async () =>
            {
                // The document the sign-in itself was made with, so a refresh token goes nowhere
                // the authorization code did not.
                var provider = services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
                    .Get(ArkOidcClient.OidcScheme).ConfigurationManager;
                var metadata = provider == null ? null : await provider.GetConfigurationAsync(CancellationToken.None);
                if (string.IsNullOrEmpty(metadata?.TokenEndpoint)) return null;

                var form = new Dictionary<string, string>
                {
                    ["grant_type"] = "refresh_token",
                    ["refresh_token"] = refreshToken!,
                    ["client_id"] = config.ClientId
                };
                if (!string.IsNullOrWhiteSpace(config.ClientSecret)) form["client_secret"] = config.ClientSecret!;

                using var response = await httpFactory.CreateClient(ArkOidcClient.HttpClientName)
                    .PostAsync(metadata.TokenEndpoint, new FormUrlEncodedContent(form));
                if (!response.IsSuccessStatusCode) return ArkRefreshOutcome.Refused;

                using var document = System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                var payload = document.RootElement;
                string? Text(string name) => payload.TryGetProperty(name, out var value) ? value.GetString() : null;
                var lifetime = payload.TryGetProperty("expires_in", out var expiresIn) ? expiresIn.GetInt32() : 3600;
                return new ArkRefreshOutcome(
                    payload.GetProperty("access_token").GetString()!,
                    // Rotation off: none comes back and the one presented stays valid.
                    Text("refresh_token") ?? refreshToken!,
                    Text("id_token"),
                    DateTimeOffset.UtcNow.AddSeconds(lifetime));
            });

            // A transient refresh failure must not sign the user out; the next request retries.
            if (outcome == null) return;
            if (outcome.AccessToken == null)
            {
                // The refresh token is gone, revoked, or was replayed and its family revoked.
                // Drop the session so the user is asked to sign in again.
                await RejectAsync(ctx);
                return;
            }

            // What the user may do, as the token just issued says it. Read only at the sign-in, a
            // claim taken away was still a role here for as long as the session could be refreshed.
            var roleType = config.RoleClaimType ?? "role";
            var arkClaims = ArkClaimReader.ReadArkClaims(outcome.AccessToken).ToList();
            var principal = ArkRoles.Replace(ctx.Principal!, roleType,
                ArkClaimReader.ReadArkClaims(ctx.Properties.GetTokenValue("access_token") ?? ""), arkClaims);

            // And whether they may use the application at all, which the callback alone used to ask.
            if (config.AccountSwitch is { RequireArkClaims: true } || events?.OnEvaluateAccess != null)
            {
                bool allowed;
                try
                {
                    allowed = await ArkAccessGate.AllowedAsync(ctx.HttpContext, config, events, principal, arkClaims);
                }
                catch (Exception ex)
                {
                    // An entitlement rule that cannot answer has not said yes. The sign-in that
                    // follows asks it again, where the failure is seen.
                    ctx.HttpContext.RequestServices.GetService<ILoggerFactory>()?.CreateLogger("Ark.oAuth.Client")
                        .LogWarning(ex, "the access check failed on refresh; the session was ended.");
                    allowed = false;
                }
                if (!allowed)
                {
                    await RejectAsync(ctx);
                    return;
                }
            }

            var tokens = new List<AuthenticationToken>
            {
                new() { Name = "access_token", Value = outcome.AccessToken },
                new() { Name = "refresh_token", Value = outcome.RefreshToken! },
                new() { Name = "expires_at", Value = outcome.ExpiresAt.ToString("o") }
            };
            // Not reissued by every provider; the last one still serves as id_token_hint at sign-out.
            var idToken = outcome.IdToken ?? ctx.Properties.GetTokenValue("id_token");
            if (!string.IsNullOrEmpty(idToken))
                tokens.Add(new AuthenticationToken { Name = "id_token", Value = idToken });

            ctx.ReplacePrincipal(principal);
            ctx.Properties.StoreTokens(tokens);
            ctx.ShouldRenew = true;
        }

        private static async Task RejectAsync(CookieValidatePrincipalContext ctx)
        {
            ctx.RejectPrincipal();
            await ctx.HttpContext.SignOutAsync(ArkOidcClient.CookieScheme);
        }
    }

    /// <summary>What redeeming a refresh token came to. No access token: the provider refused.</summary>
    internal sealed record ArkRefreshOutcome(
        string? AccessToken, string? RefreshToken, string? IdToken, DateTimeOffset ExpiresAt)
    {
        public static readonly ArkRefreshOutcome Refused = new(null, null, null, default);
    }

    /// <summary>
    /// One redemption per refresh token.
    ///
    /// The session is a cookie, so every request of a page that is drawn just before the access
    /// token expires carries the same refresh token, and each of them used to present it. This
    /// server rotates refresh tokens and reads a second presentation as theft: one request got new
    /// tokens, the others signed the user out, and the whole family was revoked with them. Now the
    /// first redeems and the rest share its answer — including one that set out before the browser
    /// had the new cookie, for as long as that can take. Across instances a rotation still needs
    /// sticky sessions, as it does in the Node and Python clients.
    /// </summary>
    internal static class ArkRefreshes
    {
        private static readonly TimeSpan Keep = TimeSpan.FromSeconds(30);
        // Keyed on a hash, so nothing here is a token to anybody who reads the keys.
        private static readonly ConcurrentDictionary<string, Lazy<Task<ArkRefreshOutcome?>>> Recent = new();
        private static readonly ConcurrentDictionary<string, byte> SignedOut = new();

        /// <summary>The outcome, or null when nothing was learned and the next request should ask again.</summary>
        public static async Task<ArkRefreshOutcome?> RedeemAsync(
            string refreshToken, Func<Task<ArkRefreshOutcome?>> redeem)
        {
            var key = Key(refreshToken);
            if (SignedOut.ContainsKey(key)) return ArkRefreshOutcome.Refused;
            var entry = Recent.GetOrAdd(key, _ => new Lazy<Task<ArkRefreshOutcome?>>(() => RunAsync(key, redeem)));
            var outcome = await entry.Value;
            return SignedOut.ContainsKey(key) ? ArkRefreshOutcome.Refused : outcome;
        }

        /// <summary>
        /// The session holding this refresh token is being signed out: whatever was redeemed into
        /// it, or is being redeemed from it, is given to nobody any more.
        /// </summary>
        public static void Forget(string? refreshToken)
        {
            if (string.IsNullOrEmpty(refreshToken)) return;
            var ended = new Queue<string>();
            ended.Enqueue(Key(refreshToken));
            while (ended.TryDequeue(out var key))
            {
                SignedOut[key] = 0;
                _ = RemoveLaterAsync(key, SignedOut);
                // And the token that one was redeemed from, which a slower request may still hold.
                foreach (var (from, entry) in Recent)
                    if (!SignedOut.ContainsKey(from)
                        && entry is { IsValueCreated: true, Value.IsCompletedSuccessfully: true }
                        && entry.Value.Result?.RefreshToken is { } into && Key(into) == key)
                        ended.Enqueue(from);
            }
        }

        private static async Task<ArkRefreshOutcome?> RunAsync(string key, Func<Task<ArkRefreshOutcome?>> redeem)
        {
            ArkRefreshOutcome? outcome = null;
            try
            {
                outcome = await redeem();
            }
            catch
            {
                // Network, a provider that is restarting, an answer that does not parse.
            }
            if (outcome == null) Recent.TryRemove(key, out _);
            else _ = RemoveLaterAsync(key, Recent);
            return outcome;
        }

        private static async Task RemoveLaterAsync<T>(string key, ConcurrentDictionary<string, T> table)
        {
            await Task.Delay(Keep);
            table.TryRemove(key, out _);
        }

        private static string Key(string refreshToken) =>
            Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(refreshToken)));
    }

    /// <summary>
    /// Ark's authorization claims as roles on the principal.
    /// </summary>
    internal static class ArkRoles
    {
        // Marks a claim this client put there, so that a refresh replaces exactly those and leaves
        // whatever the application added for itself.
        private const string Mark = "ark_claims";

        public static void Project(ClaimsIdentity identity, string roleType, IEnumerable<string> arkClaims)
        {
            foreach (var value in arkClaims)
            {
                var claim = new Claim(roleType, value);
                claim.Properties[Mark] = "1";
                identity.AddClaim(claim);
            }
        }

        /// <summary>
        /// The same principal holding the claims just issued in place of the ones before.
        /// A session that began under an earlier release carries no mark; there the claims of the
        /// token being replaced are the ones that were projected.
        /// </summary>
        public static ClaimsPrincipal Replace(
            ClaimsPrincipal principal, string roleType, IEnumerable<string> before, IEnumerable<string> now)
        {
            var identities = principal.Identities.Select(i => i.Clone()).ToList();
            var target = identities.FirstOrDefault(i => i.IsAuthenticated) ?? identities.FirstOrDefault();
            if (target == null) return principal;

            var marked = identities
                .SelectMany(i => i.Claims.Where(c => c.Type == roleType && c.Properties.ContainsKey(Mark)).Select(c => (Identity: i, Claim: c)))
                .ToList();
            if (marked.Count == 0)
                foreach (var value in before)
                {
                    var claim = target.FindFirst(c => c.Type == roleType && c.Value == value);
                    if (claim != null) target.TryRemoveClaim(claim);
                }
            foreach (var (identity, claim) in marked) identity.TryRemoveClaim(claim);

            Project(target, roleType, now);
            return new ClaimsPrincipal(identities);
        }
    }

    /// <summary>
    /// The audience of an API that was given none.
    ///
    /// Every client of a tenant shares one audience, so an API has usually not been told it. But a
    /// token addressed to one agent (A2A) or one MCP endpoint is meant for that agent or endpoint
    /// alone, and an API that checked no audience took it as readily as its own: whoever was handed
    /// one could replay it here as the user it names.
    /// </summary>
    internal static class ArkAudience
    {
        /// <summary>The discovery member naming what this tenant's ordinary access tokens are addressed to.</summary>
        private const string Published = "ark_access_token_audience";

        public static bool Validate(
            IEnumerable<string> audiences, SecurityToken securityToken, TokenValidationParameters parameters)
        {
            // Both can be set by the application after AddArkOidcApi, and then they decide.
            if (!parameters.ValidateAudience) return true;
            var expected = (parameters.ValidAudiences ?? Enumerable.Empty<string>())
                .Append(parameters.ValidAudience)
                .Where(a => !string.IsNullOrWhiteSpace(a))
                .ToList();
            if (expected.Count > 0) return audiences.Any(a => expected.Contains(a, StringComparer.Ordinal));

            // Read by the handler for the signing keys a moment ago, so this waits for nothing.
            var metadata = parameters.ConfigurationManager?.GetBaseConfigurationAsync(CancellationToken.None)
                .GetAwaiter().GetResult() as OpenIdConnectConfiguration;
            if (metadata != null && metadata.AdditionalData.TryGetValue(Published, out var value)
                && value?.ToString() is { Length: > 0 } published)
            {
                if (audiences.Contains(published, StringComparer.Ordinal)) return true;
                // An operator who changes the tenant's audience changes it in every token from then
                // on; the document is asked for again, at most as often as the manager allows.
                parameters.ConfigurationManager!.RequestRefresh();
                return false;
            }

            // A provider from before that member was published, or somebody else's. A token an
            // agent carries on a user's behalf still says so itself.
            return securityToken is not JsonWebToken token || !token.TryGetClaim("act", out _);
        }
    }

    /// <summary>
    /// What has to hold of an authority before a secret is sent where its discovery document says.
    /// The OpenID Connect handler asks the first of these for itself; the flows that need no
    /// browser read the same setting and send the same secret.
    /// </summary>
    internal static class ArkAuthority
    {
        /// <summary>https, unless the address is loopback or <c>RequireHttpsMetadata</c> is off.</summary>
        public static string RequireHttps(string authority, bool requireHttps)
        {
            if (!Uri.TryCreate(authority, UriKind.Absolute, out var uri)
                || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
                throw new InvalidOperationException($"ark_oauth_client: '{authority}' is not an http or https URL.");
            if (requireHttps && uri.Scheme != Uri.UriSchemeHttps && !uri.IsLoopback)
                throw new InvalidOperationException(
                    $"ark_oauth_client: the authority is {authority}, which is plain http. Tokens would cross the network " +
                    "in the clear. Use https, or set RequireHttpsMetadata to false — only ever for local development.");
            return authority.TrimEnd('/');
        }

        /// <summary>OIDC Discovery §4.3: the issuer in the document is the one it was looked up by.</summary>
        public static void RequireIssuer(string? issuer, string authority)
        {
            if (!string.Equals(issuer?.TrimEnd('/'), authority.TrimEnd('/'), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    $"the provider at {authority} identifies itself as '{issuer}'. Set Authority to exactly the issuer " +
                    "value — for Ark that is the base URL and the tenant id joined.");
        }
    }

    /// <summary>Caches the provider's discovery document for the flows that need no browser.</summary>
    internal static class ArkDiscoveryCache
    {
        private static readonly SemaphoreSlim Gate = new(1, 1);
        private static readonly Dictionary<string, (OpenIdConnectConfiguration config, DateTimeOffset fetchedAt)> Cache = new();
        private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(30);

        public static async Task<OpenIdConnectConfiguration?> GetAsync(HttpClient http, ArkAuthConfig client)
        {
            var authority = client.ResolveAuthority();
            if (string.IsNullOrWhiteSpace(authority)) return null;
            authority = ArkAuthority.RequireHttps(authority, client.RequireHttpsMetadata);
            await Gate.WaitAsync();
            try
            {
                if (Cache.TryGetValue(authority, out var hit) && DateTimeOffset.UtcNow - hit.fetchedAt < Ttl)
                    return hit.config;

                var json = await http.GetStringAsync($"{authority}/.well-known/openid-configuration");
                var config = OpenIdConnectConfiguration.Create(json);
                ArkAuthority.RequireIssuer(config.Issuer, authority);
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
