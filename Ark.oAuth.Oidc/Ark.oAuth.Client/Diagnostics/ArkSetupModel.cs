namespace Ark.oAuth
{
    /// <summary>
    /// What an operator needs in order to tell whether an application is correctly registered.
    ///
    /// The values on the left are read from local configuration; the values on the right come from
    /// the provider's own discovery document. Registration problems are almost always a mismatch
    /// between the two — a redirect URI that was typed slightly differently, an Authority pointing
    /// at the wrong tenant — and holding both halves in one object turns a generic
    /// "invalid_client" into something an operator can act on.
    ///
    /// This lives in the client library rather than in one sample application because every Ark
    /// client hits the same three or four registration mistakes. Build it with
    /// <see cref="ArkSetupProbe"/> and render it however the application likes.
    /// </summary>
    public class ArkSetupModel
    {
        // ---- what this application is configured with -------------------------------------

        public string Authority { get; set; } = "";
        public string ClientId { get; set; } = "";
        public bool IsConfidential { get; set; }
        public List<string> Scopes { get; set; } = new();
        public string RoleClaimType { get; set; } = "role";

        /// <summary>The absolute redirect URI this app will send. Register it exactly.</summary>
        public string RedirectUri { get; set; } = "";
        public string PostLogoutRedirectUri { get; set; } = "";

        /// <summary>This application's own origin, i.e. what it presents as an <c>Origin</c> header.</summary>
        public string Origin { get; set; } = "";

        // ---- what the provider says about itself ------------------------------------------

        public bool DiscoveryOk { get; set; }
        public string? DiscoveryError { get; set; }
        public string DiscoveryUrl { get; set; } = "";
        public ArkProviderMetadata Provider { get; set; } = new();

        public string? Issuer => Provider.Issuer;
        public string? AuthorizationEndpoint => Provider.AuthorizationEndpoint;
        public string? TokenEndpoint => Provider.TokenEndpoint;
        public string? UserInfoEndpoint => Provider.UserInfoEndpoint;
        public string? EndSessionEndpoint => Provider.EndSessionEndpoint;
        public string? JwksUri => Provider.JwksUri;
        public string? RegistrationEndpoint => Provider.RegistrationEndpoint;
        public List<string> ScopesSupported => Provider.ScopesSupported;
        public List<string> GrantTypesSupported => Provider.GrantTypesSupported;

        // ---- the checks worth making --------------------------------------------------------

        /// <summary>Set when the issuer in the discovery document is not the configured Authority.</summary>
        public bool IssuerMismatch => DiscoveryOk &&
            !string.Equals(Issuer?.TrimEnd('/'), Authority.TrimEnd('/'), StringComparison.OrdinalIgnoreCase);

        /// <summary>Scopes this app asks for that the provider does not advertise.</summary>
        public List<string> UnsupportedScopes => DiscoveryOk && ScopesSupported.Count > 0
            ? Scopes.Where(s => !ScopesSupported.Contains(s, StringComparer.OrdinalIgnoreCase)).ToList()
            : new List<string>();

        /// <summary>Whether the provider offers RFC 7591 dynamic client registration.</summary>
        public bool SupportsDynamicRegistration => !string.IsNullOrEmpty(RegistrationEndpoint);

        /// <summary>Whether the provider offers the client_credentials grant.</summary>
        public bool SupportsClientCredentials =>
            GrantTypesSupported.Contains("client_credentials", StringComparer.OrdinalIgnoreCase);

        // ---- current session ---------------------------------------------------------------

        public bool IsAuthenticated { get; set; }
        public string? SignedInAs { get; set; }

        /// <summary>Populated from ?auth_error= when a sign-in callback failed.</summary>
        public string? AuthError { get; set; }

        // ---- convenience links --------------------------------------------------------------

        /// <summary>The tenant segment of the Authority, used to build admin console links.</summary>
        public string TenantId
        {
            get
            {
                var trimmed = Authority.TrimEnd('/');
                var slash = trimmed.LastIndexOf('/');
                return slash > 0 && slash < trimmed.Length - 1 ? trimmed[(slash + 1)..] : "";
            }
        }

        public string AdminConsoleUrl
        {
            get
            {
                var trimmed = Authority.TrimEnd('/');
                var slash = trimmed.LastIndexOf('/');
                return slash > 0 ? $"{trimmed[..slash]}/{TenantId}/admin" : trimmed + "/admin";
            }
        }

        public string IntegrationPageUrl => $"{Authority.TrimEnd('/')}/oauth2/integrate/{ClientId}";
    }

    /// <summary>
    /// The parts of an OpenID Provider Metadata document (RFC 8414 / OIDC Discovery §3) that a
    /// client actually uses.
    ///
    /// Deliberately a plain object rather than <c>OpenIdConnectConfiguration</c>: this is for
    /// showing an operator what the provider advertises, including fields the handler ignores,
    /// and it must survive a document that is missing half of them.
    /// </summary>
    public class ArkProviderMetadata
    {
        public string? Issuer { get; set; }
        public string? AuthorizationEndpoint { get; set; }
        public string? TokenEndpoint { get; set; }
        public string? UserInfoEndpoint { get; set; }
        public string? EndSessionEndpoint { get; set; }
        public string? JwksUri { get; set; }
        public string? RegistrationEndpoint { get; set; }
        public string? DeviceAuthorizationEndpoint { get; set; }
        public string? PushedAuthorizationRequestEndpoint { get; set; }
        public string? IntrospectionEndpoint { get; set; }
        public string? RevocationEndpoint { get; set; }

        public List<string> ScopesSupported { get; set; } = new();
        public List<string> GrantTypesSupported { get; set; } = new();
        public List<string> ResponseTypesSupported { get; set; } = new();
        public List<string> ResponseModesSupported { get; set; } = new();
        public List<string> CodeChallengeMethodsSupported { get; set; } = new();
        public List<string> TokenEndpointAuthMethodsSupported { get; set; } = new();
        public List<string> ClaimsSupported { get; set; } = new();

        /// <summary>The document exactly as served, for the "show me the raw JSON" case.</summary>
        public string? Raw { get; set; }
    }
}
