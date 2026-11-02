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
        /// <summary>Who may drive the management API, and how. See <see cref="ArkManagementConfig"/>.</summary>
        public ArkManagementConfig Management { get; set; } = new ArkManagementConfig();
        /// <summary>The first-run setup wizard. See <see cref="ArkSetupConfig"/>.</summary>
        public ArkSetupConfig Setup { get; set; } = new ArkSetupConfig();

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

    /// <summary>
    /// The first-run setup wizard, bound from <c>ark_oauth_server:Setup</c>.
    ///
    /// A server with no <c>TenantId</c> or no <c>ConnectionStrings:ArkAuthConnection</c> is not
    /// configured, and while it is not, every request goes to the wizard at <c>/ark-idp/setup</c>.
    /// The wizard writes what it collects to <c>settings.json</c> in <see cref="DataPath"/>, which
    /// is read as configuration from then on — above appsettings.json, below user secrets,
    /// environment variables and the command line — so any value it wrote can still be overridden
    /// the usual way. A server configured any other way never sees the wizard.
    /// </summary>
    public class ArkSetupConfig
    {
        /// <summary>
        /// False turns the wizard off: an unconfigured server then fails the way it always did,
        /// naming the missing setting. For deployments that are only ever configured by pipeline.
        /// </summary>
        public bool Enabled { get; set; } = true;

        /// <summary>
        /// Require the setup code even from this machine. By default a request from a loopback
        /// address with no forwarding headers needs none — that is the developer at
        /// <c>dotnet run</c> — and any other request needs the code printed in the server log.
        /// </summary>
        public bool RequireToken { get; set; }

        /// <summary>
        /// The directory the wizard writes to: <c>settings.json</c>, the uploaded logos and the
        /// setup code. Defaults to <c>ark-idp-data</c> under the content root. In a container,
        /// point it at a persistent volume — the settings are the server's configuration.
        /// </summary>
        public string? DataPath { get; set; }
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

        /// <summary>The operator's data page at /{tenant}/admin/data — see <see cref="ArkDataToolsConfig"/>.</summary>
        public ArkDataToolsConfig DataTools { get; set; } = new ArkDataToolsConfig();
    }

    /// <summary>
    /// Export, import and factory reset (<c>ark_oauth_server:Admin:DataTools</c>).
    ///
    /// All of it is restricted to the operator account whatever these say. They exist for the
    /// deployment that wants the destructive half switched off outright — a production server
    /// that is only ever restored by its own pipeline, say — without losing the export.
    /// Every value defaults to on, so a configuration written before this section existed gets
    /// the page as documented.
    /// </summary>
    public class ArkDataToolsConfig
    {
        /// <summary>The whole page and its API. Off hides the nav link and answers 404.</summary>
        public bool Enabled { get; set; } = true;
        /// <summary>Wipe every table and re-seed. Off refuses with 403 before anything is read.</summary>
        public bool AllowReset { get; set; } = true;
        /// <summary>Import in any mode. Off leaves export only.</summary>
        public bool AllowImport { get; set; } = true;
        /// <summary>
        /// The <c>replace</c> import mode, which empties the database before loading the file.
        /// Separate from <see cref="AllowImport"/> because the two merge modes never delete a row.
        /// </summary>
        public bool AllowReplace { get; set; } = true;
        /// <summary>Largest import body accepted, in megabytes.</summary>
        public int MaxImportMegabytes { get; set; } = 100;
    }

    /// <summary>
    /// The management API (<c>ark_oauth_server:Management</c>): who may call it besides the
    /// operator's console session, and the switches around it.
    ///
    /// The API itself answers only to the operator — see <see cref="ArkManagementAuth"/>. Nothing
    /// here widens that; these settings decide how a pipeline proves it is acting for the
    /// operator, and nothing in this section is needed by a deployment administered from the
    /// console alone.
    /// </summary>
    public class ArkManagementConfig
    {
        /// <summary>The shortest <see cref="MachineClientSecret"/> accepted.</summary>
        public const int MinMachineClientSecretLength = 16;

        /// <summary>
        /// The secret of the machine client (<c>{TenantId}_machine</c>), applied on start-up.
        ///
        /// The machine client is seeded without a secret, so on a new deployment nothing can
        /// obtain a management token until somebody presses <b>Regenerate secret</b> in the
        /// console — which a deployment provisioned from a pipeline cannot do. Set this and the
        /// client gets it on first boot; change it and the next start rotates it. While it is
        /// set, the console refuses to regenerate this client's secret, because the next restart
        /// would silently put this one back.
        ///
        /// Whoever can read this value is the operator. Keep it in a key vault reference or an
        /// environment variable, never in a settings file under source control. A
        /// <c>&lt;&lt;placeholder&gt;&gt;</c> counts as unset.
        /// </summary>
        public string? MachineClientSecret { get; set; }

        /// <summary>
        /// Clients whose device-code tokens (RFC 8628) may drive the management API, for a person
        /// at a terminal rather than a pipeline. Empty by default.
        ///
        /// A token from one of these is admitted only when it carries <c>client.register</c>, the
        /// person who approved the code is the operator, and the client is registered as public,
        /// for the device-code grant and no redirect URIs — so its tokens can come from nowhere
        /// but a code approved on this server. Device-code phishing (someone starts a flow and
        /// sends the operator the user code) is the risk this accepts; leave it empty unless a
        /// CLI needs it.
        /// </summary>
        public List<string> OperatorDeviceClients { get; set; } = new List<string>();

        /// <summary>
        /// Whether <c>/api/migration</c> answers at all. Off by default: the schema updates itself
        /// on start-up, and running or rolling back a script by hand is a repair, not routine.
        /// When off the path answers 404, so a probe cannot confirm it exists; when on it is
        /// still operator-only.
        /// </summary>
        public bool AllowMigrationEndpoint { get; set; }

        /// <summary><see cref="MachineClientSecret"/>, or null when it is empty or a placeholder.</summary>
        public string? ConfiguredMachineClientSecret
        {
            get
            {
                var trimmed = (MachineClientSecret ?? "").Trim();
                if (trimmed.Length == 0 || (trimmed.StartsWith("<<") && trimmed.EndsWith(">>"))) return null;
                return trimmed;
            }
        }
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
