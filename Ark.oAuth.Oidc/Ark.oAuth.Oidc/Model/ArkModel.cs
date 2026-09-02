namespace Ark.oAuth.Oidc
{
    public class ArkJwt
    {
        string _email = null;
        public string email
        {
            get
            {
                if (string.IsNullOrEmpty(_email) && !string.IsNullOrEmpty(id_token))
                {
                    var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
                    var decodedValue = handler.ReadJwtToken(id_token);
                    if (decodedValue != null) _email = decodedValue.Claims.First(tt => tt.Type == "email").Value;
                }
                return _email ?? "";
            }
            set
            {
                _email = value;
            }
        }
        public string code { get; set; }
        public string access_token { get; set; }
        public string expires_in { get; set; }
        public string refresh_token { get; set; }
        public string id_token { get; set; }
        public string project_id { get; set; }
        public ArkError error { get; set; }
    }
    public class ArkError
    {
        public string code { get; set; }
        public string message { get; set; }
        public List<ArkErr> errors { get; set; } = new List<ArkErr>();
    }
    public class ArkErr
    {
        public string message { get; set; }
        public string domain { get; set; }
        public string reason { get; set; }
    }
    public class ArkAuthServerConfig
    {
        public string TenantId { get; set; }
        public string BasePath { get; set; }
        public string UploadPath { get; set; }
        public string Provider { get; set; }
        public string DefaultPw { get; set; }
        /// <summary>
        /// How newly created user passwords are onboarded.
        ///
        /// Supported values are:
        ///
        ///   * <c>admin_managed</c> — always create the account on <see cref="DefaultPw"/> and let
        ///     an operator set or communicate the password out of band;
        ///   * <c>email_based</c> — create email-address accounts in <c>reset_mode</c> and send an
        ///     activation link; plain usernames still fall back to <see cref="DefaultPw"/>;
        ///   * <c>auto</c> (or unset) — legacy behaviour: respect the caller's request, which is
        ///     what the existing console and provisioning API already do.
        /// </summary>
        public string UserPasswordMode { get; set; }
        public bool EnableLogTrace { get; set; }
        public string BaseUrl { get; set; }
        public string CcList { get; set; }
        public string BccList { get; set; }
        public ArkEmailConfig EmailConfig { get; set; }
        /// <summary>Standard OAuth 2.1 / OIDC behaviour. Optional — every value has a default.</summary>
        public Protocol.ArkOidcOptions Oidc { get; set; } = new Protocol.ArkOidcOptions();
        /// <summary>The first account seeded into a brand-new database. See <see cref="ArkAdminUserConfig"/>.</summary>
        public ArkAdminUserConfig AdminUser { get; set; } = new ArkAdminUserConfig();
        /// <summary>The bundled v2 admin console. Optional — every value has a working default.</summary>
        public ArkAdminConsoleConfig Admin { get; set; } = new ArkAdminConsoleConfig();

        /// <summary>The parsed onboarding mode, defaulting to the legacy auto behaviour.</summary>
        public ArkUserPasswordMode EffectiveUserPasswordMode =>
            (UserPasswordMode ?? "").Trim().ToLowerInvariant() switch
            {
                "admin" or "admin_managed" or "admin-managed" or "default_password" or "default-password"
                    => ArkUserPasswordMode.AdminManaged,
                "email" or "email_based" or "email-based" or "activation_email" or "activation-email"
                    => ArkUserPasswordMode.EmailBased,
                _ => ArkUserPasswordMode.Auto
            };

        /// <summary>
        /// Whether a user with this login identifier should be sent through the email activation
        /// flow when the caller asked for it.
        /// </summary>
        public bool ShouldUseEmailPasswordFlow(string loginId, bool requestedByCaller = true)
        {
            if (!ark.net.util.EmailUtil.IsValidFormat(loginId)) return false;

            return EffectiveUserPasswordMode switch
            {
                ArkUserPasswordMode.AdminManaged => false,
                ArkUserPasswordMode.EmailBased => true,
                _ => requestedByCaller
            };
        }
    }

    public enum ArkUserPasswordMode
    {
        Auto,
        AdminManaged,
        EmailBased
    }

    /// <summary>
    /// The administrator account created when the database is first built, bound from
    /// <c>ark_oauth_server:AdminUser</c>.
    ///
    /// It used to be <c>admin</c> / <c>admin</c>, compiled in — the same credentials on every
    /// deployment of this server, for the one account that can administer every tenant on it.
    /// <see cref="Password"/> is therefore required: seeding stops with a message naming the
    /// setting rather than falling back to anything guessable.
    ///
    /// Only read while the database is being created. Changing it afterwards renames nothing and
    /// resets no password — use the console for that.
    /// </summary>
    public class ArkAdminUserConfig
    {
        /// <summary>Login identifier. Does not have to be an email address. Defaults to <c>admin</c>.</summary>
        public string Username { get; set; }
        /// <summary>
        /// Initial password. Required; falls back to <c>ark_oauth_server:DefaultPw</c> when unset, so a
        /// deployment that already configures one password does not have to configure two.
        /// </summary>
        public string Password { get; set; }
        /// <summary>Display name for the account. Defaults to <c>Admin User</c>.</summary>
        public string Name { get; set; }
    }

    /// <summary>Behaviour of the admin console shipped inside this package.</summary>
    public class ArkAdminConsoleConfig
    {
        /// <summary>
        /// Where the console's <b>Sign out</b> link goes.
        ///
        /// The console is a page in the host application, so its session is the host's
        /// authentication cookie — which only the host can drop. Point this at the host's own
        /// sign-out route (the sample host uses <c>/Home/SignOutAll</c>, which signs out of both the
        /// cookie and the OIDC scheme). Left empty, the link falls back to the tenant's
        /// <c>end_session_endpoint</c>, which ends the session at the IdP but leaves the host's
        /// cookie in place until it expires.
        /// </summary>
        public string SignOutUrl { get; set; }
    }
    public class ArkEmailConfig
    {
        public string email { get; set; }
        public string pw { get; set; }
        public string from { get; set; }
        public string display { get; set; }
        public string subject { get; set; }
        public string smtp { get; set; }
        public int port { get; set; }
        public string host_logo { get; set; }
        public string client_logo { get; set; }
        public string client_website_url { set; get; }
        public string host_website_url { set; get; }
        public string activation_link { set; get; }
        public string privacy_policy_url { set; get; }
        public string terms_url { set; get; }
        public string host_company_name { set; get; }
        public string host_company_display { set; get; }
    }
}
