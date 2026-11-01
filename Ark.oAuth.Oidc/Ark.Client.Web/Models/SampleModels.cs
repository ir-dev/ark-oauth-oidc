using Ark.oAuth;

namespace Ark.Client.Web.Models
{
    // ---------------------------------------------------------------------------------------------
    // View models for this sample's pages.
    //
    // The registration-diagnostics model that used to live here is now ArkSetupModel in
    // Ark.oAuth.Client: every client application needs the same "am I registered correctly?"
    // check, and keeping a copy per application meant fixing the same discovery bug in each one.
    // Build it with ArkSetupProbe.ProbeAsync. What remains below is genuinely sample-specific.
    // ---------------------------------------------------------------------------------------------

    public class ProfileModel
    {
        public string? Subject { get; set; }
        public string? Name { get; set; }
        public string? Email { get; set; }
        public List<string> Roles { get; set; } = new();
        public List<KeyValuePair<string, string>> Claims { get; set; } = new();

        public bool HasAccessToken { get; set; }
        public bool HasRefreshToken { get; set; }
        public bool HasIdToken { get; set; }
        public DateTimeOffset? AccessTokenExpiresAt { get; set; }
        public string? AccessTokenPayload { get; set; }
        public string? IdTokenPayload { get; set; }
        public string RequiredRole { get; set; } = "";
    }

    public class DownstreamModel
    {
        public string Endpoint { get; set; } = "";
        public int StatusCode { get; set; }
        public string? Body { get; set; }
        public string? Error { get; set; }
    }

    /// <summary>
    /// The single-page application flow: authorization code + PKCE, run entirely in the browser
    /// by a public client that has no secret to protect.
    ///
    /// Everything here is rendered into the page for the JavaScript to use; the flow itself
    /// happens in the browser, which is the whole point of the screen.
    /// </summary>
    public class SpaModel
    {
        public string ClientId { get; set; } = "";
        public string RedirectUri { get; set; } = "";
        public string Origin { get; set; } = "";
        public List<string> Scopes { get; set; } = new();

        public string Authority { get; set; } = "";
        public bool DiscoveryOk { get; set; }
        public string? DiscoveryError { get; set; }
        public ArkProviderMetadata Provider { get; set; } = new();

        /// <summary>False when the provider does not offer S256, which a public client requires.</summary>
        public bool SupportsS256 => Provider.CodeChallengeMethodsSupported
            .Contains("S256", StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>The client credentials flow: a service authenticating as itself, no user involved.</summary>
    public class MachineModel
    {
        public string ClientId { get; set; } = "";
        public bool SecretConfigured { get; set; }
        public List<string> Scopes { get; set; } = new();

        public string Authority { get; set; } = "";
        public string AdminConsoleUrl { get; set; } = "";
        public bool DiscoveryOk { get; set; }
        public string? DiscoveryError { get; set; }
        public bool SupportsClientCredentials { get; set; }
        public string? TokenEndpoint { get; set; }

        /// <summary>Set once the "request a token" button has been used.</summary>
        public ArkTokenResult? Result { get; set; }
    }

    /// <summary>Dynamic client registration (RFC 7591) and its management endpoints (RFC 7592).</summary>
    public class RegisterModel
    {
        public string Authority { get; set; } = "";
        public bool DiscoveryOk { get; set; }
        public string? DiscoveryError { get; set; }
        public string? RegistrationEndpoint { get; set; }
        public bool SupportsDynamicRegistration => !string.IsNullOrEmpty(RegistrationEndpoint);

        /// <summary>The machine client used to obtain the initial access token.</summary>
        public string MachineClientId { get; set; } = "";
        public bool MachineSecretConfigured { get; set; }

        /// <summary>
        /// What the IdP said when the secret was tried: <c>works</c>, <c>rejected</c>,
        /// <c>unchecked</c> (the IdP could not be reached) or <c>not_set</c>. A value being present
        /// says nothing about whether it still matches what the IdP holds.
        /// </summary>
        public string MachineSecretStatus { get; set; } = "not_set";
        public string? MachineSecretError { get; set; }

        /// <summary>Pasted on the page for this request. Echoed back to the form, stored nowhere.</summary>
        public string? MachineSecret { get; set; }
        public bool MachineSecretPasted => !string.IsNullOrWhiteSpace(MachineSecret);

        // What the walkthrough needs to say "change this, then sign in": where the console is,
        // and the client this app is signing in with right now.
        public string AdminConsoleUrl { get; set; } = "";
        public string Origin { get; set; } = "";
        public string AppClientId { get; set; } = "";
        public string AppRedirectUri { get; set; } = "";
        public bool AppIsConfidential { get; set; }
        public bool AppRequiresArkClaims { get; set; }

        // the form, echoed back so a failed submission is not retyped
        public string ClientName { get; set; } = "My new client";
        public string RedirectUris { get; set; } = "";
        public string PostLogoutRedirectUris { get; set; } = "";
        public string GrantTypes { get; set; } = "authorization_code refresh_token";
        public string Scope { get; set; } = "openid profile email offline_access";
        public string TokenEndpointAuthMethod { get; set; } = "none";
        public string ApplicationType { get; set; } = "web";

        /// <summary>How the initial access token was obtained, shown so the chain is visible.</summary>
        public ArkTokenResult? InitialAccessToken { get; set; }

        public ArkRegistrationResult? Registration { get; set; }

        /// <summary>Result of a read-back or delete against an existing registration.</summary>
        public ArkRegistrationResult? Management { get; set; }
        public string? ManagementAction { get; set; }

        // prefilled for the management form after a successful registration
        public string ManageClientId { get; set; } = "";
        public string ManageAccessToken { get; set; } = "";
    }

    public class ErrorViewModel
    {
        public string? RequestId { get; set; }
        public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);
    }
}
