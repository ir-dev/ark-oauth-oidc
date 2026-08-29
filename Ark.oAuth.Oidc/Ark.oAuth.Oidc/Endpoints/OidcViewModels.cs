namespace Ark.oAuth.Oidc.Endpoints
{
    /// <summary>A scope as shown to the user on the consent screen.</summary>
    public class ConsentScopeModel
    {
        public string Name { get; set; } = default!;
        public string Display { get; set; } = default!;
        public string? Description { get; set; }
        /// <summary>Protocol scopes (openid) are listed but cannot be unchecked.</summary>
        public bool Required { get; set; }
    }

    /// <summary>Branding pulled from tenant/client configuration, shared by every interactive page.</summary>
    public class OidcBrandModel
    {
        public string? HostLogo { get; set; }
        public string? ClientLogo { get; set; }
        public string HostName { get; set; } = "Identity Provider";
        /// <summary>The application being signed in to. Used as the client logo's alt text.</summary>
        public string? ClientName { get; set; }
        public string? PrivacyUrl { get; set; }
        public string? TermsUrl { get; set; }

        /// <summary>
        /// How many of the two marks there are to draw — 0, 1 or 2.
        ///
        /// The header layout is driven off this rather than off two independent conditionals: a
        /// lockup built for two logos and handed one leaves a gap where the other should be, and
        /// handed none leaves an empty 44px band above the heading. Both cases are common —
        /// most clients are registered without a logo — so each is laid out deliberately.
        /// </summary>
        public int LogoCount =>
            (string.IsNullOrWhiteSpace(HostLogo) ? 0 : 1) + (string.IsNullOrWhiteSpace(ClientLogo) ? 0 : 1);
    }

    /// <summary>The sign-in page.</summary>
    public class LoginPageModel
    {
        public OidcBrandModel Brand { get; set; } = new();
        public string ClientDisplay { get; set; } = default!;
        /// <summary>The current authorize URL, including its query string, so the POST resumes the same request.</summary>
        public string ActionUrl { get; set; } = default!;
        public string? Error { get; set; }
        public string? Username { get; set; }
        public string? PasswordResetUrl { get; set; }
    }

    /// <summary>The consent page.</summary>
    public class ConsentPageModel
    {
        public OidcBrandModel Brand { get; set; } = new();
        public string ClientDisplay { get; set; } = default!;
        public string? ClientUri { get; set; }
        public string Subject { get; set; } = default!;
        public string ActionUrl { get; set; } = default!;
        public List<ConsentScopeModel> Scopes { get; set; } = new();
        public string? Error { get; set; }
    }

    /// <summary>A protocol error we cannot hand back to the client, so it is shown to the user instead.</summary>
    public class OidcErrorPageModel
    {
        public OidcBrandModel Brand { get; set; } = new();
        public string Error { get; set; } = default!;
        public string? Description { get; set; }
    }

    /// <summary>
    /// The signed-out page. Carries what the sign-out actually did, because on a shared browser
    /// "you have been signed out" understates it — several people may have been.
    /// </summary>
    public class LoggedOutPageModel : OidcErrorPageModel
    {
        public int SessionsEnded { get; set; }
        public int SubjectsEnded { get; set; }
        public int ClientsNotified { get; set; }
        public int ClientsFailed { get; set; }
    }

    /// <summary>The device grant's user-code entry and confirmation page.</summary>
    public class DevicePageModel
    {
        public OidcBrandModel Brand { get; set; } = new();
        public string ActionUrl { get; set; } = default!;
        public string? UserCode { get; set; }
        public string? Error { get; set; }
        public string? Message { get; set; }
        /// <summary>enter_code | confirm | done</summary>
        public string Stage { get; set; } = "enter_code";
        public string? ClientDisplay { get; set; }
        public List<ConsentScopeModel> Scopes { get; set; } = new();
    }

    /// <summary>An auto-submitting form used for response_mode=form_post.</summary>
    public class FormPostModel
    {
        public string RedirectUri { get; set; } = default!;
        public Dictionary<string, string> Fields { get; set; } = new();
    }
}
