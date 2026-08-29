using Microsoft.AspNetCore.Http;

namespace Ark.oAuth.Oidc.Protocol
{
    /// <summary>
    /// Server-wide switches for the standard OAuth surface. Bound from the
    /// "ark_oauth_server:Oidc" configuration section; every value has a working default,
    /// so the section can be omitted entirely.
    /// </summary>
    public class ArkOidcOptions
    {
        /// <summary>Serve RFC 7591 dynamic client registration. Off by default — it creates clients.</summary>
        public bool EnableDynamicRegistration { get; set; } = false;
        /// <summary>Require an initial access token on /register when dynamic registration is on.</summary>
        public bool RequireRegistrationAccessToken { get; set; } = true;
        public bool EnableDeviceFlow { get; set; } = true;
        public bool EnablePushedAuthorizationRequests { get; set; } = true;
        /// <summary>Refuse plain /authorize requests that did not arrive via PAR.</summary>
        public bool RequirePushedAuthorizationRequests { get; set; } = false;

        public int DeviceCodeLifetimeSeconds { get; set; } = 600;
        public int DevicePollIntervalSeconds { get; set; } = 5;
        public int ParLifetimeSeconds { get; set; } = 90;
        public int SessionLifetimeMinutes { get; set; } = 480;

        /// <summary>Lock an account after this many consecutive failed sign-ins. 0 disables lockout.</summary>
        public int MaxFailedSignIns { get; set; } = 10;
        public int LockoutMinutes { get; set; } = 15;

        /// <summary>Show the consent screen even for first-party clients that did not ask for it.</summary>
        public bool AlwaysRequireConsent { get; set; } = false;

        /// <summary>
        /// POST a signed logout token to every client that took part in a session that is ending
        /// (OIDC Back-Channel Logout 1.0). Only clients with a <c>backchannel_logout_uri</c>
        /// registered are contacted, so turning this on notifies nobody until a client asks to be
        /// notified.
        /// </summary>
        public bool EnableBackChannelLogout { get; set; } = true;

        /// <summary>
        /// How long to wait for one client's logout endpoint. Delivery is attempted to every
        /// client in parallel and a failure is logged rather than raised — a client that is down
        /// must not be able to stop the user signing out.
        /// </summary>
        public int BackChannelLogoutTimeoutSeconds { get; set; } = 5;

        /// <summary>Lifetime of a logout token. Short: it is delivered immediately or not at all.</summary>
        public int LogoutTokenLifetimeSeconds { get; set; } = 120;

        /// <summary>
        /// End every session that belongs to the same browser, not only the one the session
        /// cookie names.
        ///
        /// This is what makes signing out mean what people expect it to mean on a shared machine.
        /// The session cookie holds a single sid, so a second person signing in replaces it and
        /// leaves the first session live in the database — with its refresh tokens, and with the
        /// first person still signed in at every application they had opened. Signing out then
        /// ends the newer session and silently leaves the older one running.
        ///
        /// Turn it off only where separate sessions in one browser are deliberate and are meant
        /// to survive each other's logout.
        /// </summary>
        public bool SignOutAllBrowserSessions { get; set; } = true;

        /// <summary>
        /// Whether <see cref="SignOutAllBrowserSessions"/> crosses tenant boundaries.
        ///
        /// The browser cookie is one per deployment, not one per tenant, so by default signing
        /// out really does sign out everybody signed in on that browser — which is the point on a
        /// shared machine. Set this false where one browser is expected to hold sessions in
        /// several tenants at once and signing out of one should leave the others alone.
        /// </summary>
        public bool SignOutAcrossTenants { get; set; } = true;

        /// <summary>
        /// Browser origins allowed to call the token, userinfo, discovery and JWKS endpoints with
        /// fetch/XHR — the origins of your single-page applications, e.g.
        /// <c>https://localhost:7255</c>.
        ///
        /// Empty by default, which means no cross-origin call succeeds. A SPA redeems its
        /// authorization code from the browser, so without its origin listed here the exchange
        /// fails in the browser's CORS preflight and never reaches the server. Server-side clients
        /// (the authorization code flow through a web application, client_credentials) do not go
        /// through a browser and need nothing here.
        ///
        /// List exact origins — scheme, host and port. There is no wildcard: the endpoints below
        /// hand out tokens, and an origin list is the only thing keeping any page on the internet
        /// from asking for one.
        /// </summary>
        public List<string> CorsOrigins { get; set; } = new();
    }

    /// <summary>
    /// The CORS policy applied to the endpoints a browser-based client has to reach directly.
    ///
    /// Applied per endpoint with <c>[EnableCors(ArkCors.PolicyName)]</c> rather than globally, so
    /// the interactive pages (sign-in, consent, admin console) stay same-origin only.
    /// </summary>
    public static class ArkCors
    {
        public const string PolicyName = "ark-oidc-browser";
    }

    /// <summary>
    /// Builds every protocol URL for a tenant from a single base, and defines the issuer.
    ///
    /// The issuer is <c>{baseUrl}/{tenant_id}</c> and discovery lives at
    /// <c>{issuer}/.well-known/openid-configuration</c>. That relationship is what lets a stock
    /// OIDC client — ASP.NET Core, Okta's SDKs, Postman, anything — point at the issuer and
    /// configure itself, and it is why the issuer is derived here rather than stored per tenant.
    /// (<see cref="ArkTenant.issuer"/> keeps its legacy value for the v1 compatibility endpoints.)
    /// </summary>
    public class ArkOidcEndpoints
    {
        public string BaseUrl { get; }
        public string TenantId { get; }

        public ArkOidcEndpoints(string baseUrl, string tenantId)
        {
            BaseUrl = baseUrl.TrimEnd('/');
            TenantId = tenantId;
        }

        public string Issuer => $"{BaseUrl}/{TenantId}";

        public string Authorization => $"{Issuer}/oauth2/authorize";
        public string Token => $"{Issuer}/oauth2/token";
        public string UserInfo => $"{Issuer}/oauth2/userinfo";
        public string Jwks => $"{Issuer}/.well-known/jwks.json";
        public string Introspection => $"{Issuer}/oauth2/introspect";
        public string Revocation => $"{Issuer}/oauth2/revoke";
        public string EndSession => $"{Issuer}/oauth2/logout";
        public string DeviceAuthorization => $"{Issuer}/oauth2/device_authorization";
        public string DeviceVerification => $"{Issuer}/oauth2/device";
        public string PushedAuthorizationRequest => $"{Issuer}/oauth2/par";
        public string Registration => $"{Issuer}/oauth2/register";
        public string Discovery => $"{Issuer}/.well-known/openid-configuration";

        /// <summary>
        /// Resolves the public base URL. Prefers the configured BaseUrl so that a server behind a
        /// proxy or load balancer advertises the address clients actually reach, rather than the
        /// internal host from the request.
        /// </summary>
        public static ArkOidcEndpoints For(HttpRequest request, ArkAuthServerConfig config, string tenantId)
        {
            string baseUrl;
            if (!string.IsNullOrWhiteSpace(config.BaseUrl))
            {
                baseUrl = PublicRoot(config);
            }
            else
            {
                baseUrl = $"{request.Scheme}://{request.Host}";
                var pathBase = request.PathBase.HasValue ? request.PathBase.Value!.Trim('/') : "";
                if (!string.IsNullOrEmpty(pathBase)) baseUrl = $"{baseUrl}/{pathBase}";
                else if (!string.IsNullOrWhiteSpace(config.BasePath)) baseUrl = $"{baseUrl}/{config.BasePath!.Trim('/')}";
            }
            return new ArkOidcEndpoints(baseUrl, tenantId);
        }

        /// <summary>
        /// The same endpoints, built without an <see cref="HttpRequest"/> to read.
        ///
        /// For work that has no request to derive a host from — background jobs, and the
        /// provisioning API, whose response carries the issuer and setup URL a caller is expected
        /// to store. Requires <c>BaseUrl</c> to be configured, since there is nothing else to
        /// fall back to.
        /// </summary>
        public static ArkOidcEndpoints For(ArkAuthServerConfig config, string tenantId)
        {
            var root = PublicRoot(config);
            if (string.IsNullOrWhiteSpace(root))
                throw new ApplicationException(
                    "'ark_oauth_server:BaseUrl' is not configured, so the issuer URL cannot be built outside a request.");
            return new ArkOidcEndpoints(root, tenantId);
        }

        /// <summary>
        /// The externally reachable root of the application — <c>BaseUrl</c> with <c>BasePath</c>
        /// appended when it is not already part of it.
        ///
        /// Everything the server hands out or registers has to be built from this one value.
        /// Composing some URLs from BaseUrl alone and others from BaseUrl + BasePath is how the
        /// admin console ended up registered at <c>/signin-oidc</c> while the client actually
        /// called back to <c>/auth/signin-oidc</c>, which the authorization endpoint then rejected
        /// as an unregistered redirect_uri.
        /// </summary>
        public static string PublicRoot(ArkAuthServerConfig config)
        {
            var baseUrl = (config.BaseUrl ?? "").TrimEnd('/');
            if (string.IsNullOrWhiteSpace(config.BasePath)) return baseUrl;

            var basePath = config.BasePath!.Trim('/');
            if (basePath.Length == 0) return baseUrl;

            return baseUrl.EndsWith($"/{basePath}", StringComparison.OrdinalIgnoreCase)
                ? baseUrl
                : $"{baseUrl}/{basePath}";
        }
    }
}
