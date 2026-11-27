using System.Data.Common;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Ark.oAuth.Oidc.Protocol;
using static Ark.oAuth.Oidc.ArkSetupMiddleware;

namespace Ark.oAuth.Oidc.Mcp.Tools
{
    /// <summary>
    /// Setup, as tools: everything the wizard asks for, one section at a time, in any order, over
    /// as many conversations as it takes.
    ///
    /// The sections say who usually holds the answer, so an agent can go and ask, and every value
    /// is stored with where it came from. Nothing takes effect until <c>setup_complete</c>, which
    /// installs exactly the draft that <c>setup_review</c> last showed. The checks are the
    /// wizard's own (<see cref="ArkSetupMiddleware"/>), so an agent cannot set up a server a person
    /// could not.
    /// </summary>
    internal sealed class SetupTools
    {
        public const string Instructions =
            "This identity server has not been set up yet. Use these tools to collect what it needs and create its first tenant.\n" +
            "1. setup_status shows every section: what is known, what is missing or wrong, and which department usually has the answer. " +
            "setup_fields explains each value and the question to ask for it.\n" +
            "2. Ask the people responsible, one section at a time, and store each answer with its setup_set_* tool. Always fill in source, " +
            "so the record shows who supplied what. Values may arrive in any order and over several sessions; they are kept.\n" +
            "3. Test what can be tested: setup_test_database, setup_test_email, setup_test_audit.\n" +
            "4. setup_review lists the whole plan, what is assumed and what would go wrong. Show it to a person who may decide, and wait for their agreement.\n" +
            "5. setup_complete installs the reviewed plan. Its answer carries the machine credential and the address of the tenant's own MCP server, " +
            "both shown once (the server also keeps the signing key and the machine credential in its data directory, keys_file); " +
            "from then on this endpoint no longer takes the setup code.\n" +
            "The public URL and the tenant id become part of every token's issuer: treat them as permanent. " +
            "Do not invent values. Leave the administrator's password out, so that they set it themselves through a one-time link.";

        // ---------------------------------------------------------------- what there is to collect

        sealed record Field(string Name, string Type, string Description, string Ask, bool Required = false, string? Default = null,
            bool Sensitive = false, bool Held = false, string[]? Values = null, int? Min = null, int? Max = null, int MaxLength = 2000);

        sealed record Section(string Name, string Title, string Owner, string Purpose, bool Optional, Field[] Fields);

        static readonly Section[] Sections =
        {
            new("organization", "Organization", "Legal or corporate communications",
                "Shown on the sign-in page, in the console and in the emails people receive.", false, new[]
                {
                    new Field("company_name", "string", "The organization's name.", "What is the organization's name, as people should see it when they sign in?", Required: true, MaxLength: 80),
                    new Field("display_name", "string", "Product name on the sign-in page.", "What should the sign-in page be called?", Default: "{company_name} Identity", MaxLength: 120),
                    new Field("website_url", "string", "The organization's website.", "What is the website address?", Default: "the public URL"),
                    new Field("terms_url", "string", "Terms of service, linked under the sign-in form.", "Where are the terms of service published?", Default: "the website"),
                    new Field("privacy_url", "string", "Privacy policy, linked under the sign-in form.", "Where is the privacy policy published?", Default: "the website")
                }),
            new("server", "Server address and tenant", "IT or platform engineering",
                "The issuer of every token is {base_url}/{tenant_id}. Clients are configured with it, so it is as good as permanent.", false, new[]
                {
                    new Field("base_url", "string", "Public https address browsers reach this server at (http only for localhost).", "What public address will people reach the identity server at?", Required: true),
                    new Field("tenant_id", "string", "The operator tenant: 2-63 letters, digits, '_' or '-'. It administers every other tenant.", "What should the first tenant be called? It cannot be renamed.", Required: true, MaxLength: 63),
                    new Field("tenant_display", "string", "Name of the tenant and its console.", "What name should the admin console carry?", Default: "{company_name} Admin Console", MaxLength: 120),
                    new Field("base_path", "string", "Only when the app is served under a sub-path of base_url.", "Is the server behind a sub-path? Which?", Default: "none"),
                    new Field("landing_url", "string", "Where people land after signing in: a path of this app, or an address. Not set: the admin console.", "Where should people land after signing in?", Default: "the admin console")
                }),
            new("database", "Database", "Database administration",
                "Where tenants, applications, people, keys and sessions are kept. The tables are created by setup.", false, new[]
                {
                    new Field("provider", "string", "sqlite, postgres or mysql.", "Which database should it use? SQLite suits development and small sites; PostgreSQL is recommended for production.", Default: "sqlite", Values: new[] { "sqlite", "postgres", "mysql" }),
                    new Field("sqlite_file", "string", "SQLite only: the database file.", "Where should the database file be?", Default: "ark_idp.db in the data directory"),
                    new Field("host", "string", "Database server.", "What is the database server's host name?"),
                    new Field("port", "integer", "Its port.", "Which port?", Default: "5432 for PostgreSQL, 3306 for MySQL", Min: 1, Max: 65535),
                    new Field("database", "string", "Database name, exactly as created.", "What is the database called?"),
                    new Field("username", "string", "Account. It needs to create tables.", "Which account should the server use?"),
                    new Field("password", "string", "Its password.", "What is that account's password?", Sensitive: true),
                    new Field("ssl", "string", "prefer, require or disable.", "Must the connection be encrypted?", Default: "prefer", Values: new[] { "prefer", "require", "disable" }),
                    new Field("connection_string", "string", "The whole connection string, in place of the parts above.", "Is there a ready-made connection string?", Sensitive: true, MaxLength: 4000)
                }),
            new("signing_key", "Token signing key", "Security or PKI",
                "The RSA key every token is signed with. It is stored in the database only.", false, new[]
                {
                    new Field("mode", "string", "generate a key during setup (recommended: nobody handles it), or import one.", "Should a new signing key be generated, or must an existing one be used?", Default: "generate", Values: new[] { "generate", "import" }),
                    new Field("key_size", "integer", "Size of a generated key: 2048, 3072 or 4096.", "Is there a minimum key size?", Default: "2048"),
                    new Field("private_key", "string", "import only: an unencrypted RSA private key in PEM. Kept in memory, never in the draft file.", "Which private key?", Sensitive: true, Held: true, MaxLength: 20000)
                }),
            new("administrator", "First administrator", "Identity or security operations",
                "The account that runs the console and every tenant.", false, new[]
                {
                    new Field("username", "string", "Login name, no spaces. An email address works.", "Who is the first administrator? Which login name?", Required: true, MaxLength: 200),
                    new Field("name", "string", "Full name.", "What is their name?", Default: "Administrator", MaxLength: 200),
                    new Field("password", "string", "Leave it out: the administrator then sets it through a one-time link. If given, at least 10 characters; kept in memory, never in the draft file.", "(Do not ask for this. Hand the administrator the one-time link instead.)", Sensitive: true, Held: true, MaxLength: 200)
                }),
            // Not optional: unless password_mode is email_based, default_password is owed (MissingWhen).
            new("users", "New people", "HR or the service desk",
                "How people added later get their first password.", false, new[]
                {
                    new Field("password_mode", "string", "admin_managed: administrators hand them out. email_based: an activation email (needs email). auto: whoever adds the person chooses.", "How should new people get their first password?", Default: "admin_managed", Values: new[] { "admin_managed", "email_based", "auto" }),
                    new Field("default_password", "string", "The password every account added in the admin console or through the provisioning API starts on; at least 8 characters. " +
                        "Required unless password_mode is email_based.",
                        "Which password should new accounts start on? Administrators hand it to each person they add.", Sensitive: true, MaxLength: 200)
                }),
            new("email", "Outgoing email", "Messaging or IT operations",
                "For activation and password-reset messages. Off, nothing is sent.", true, new[]
                {
                    new Field("enabled", "boolean", "Whether this server sends email.", "Should the server send email?", Default: "false"),
                    new Field("smtp", "string", "SMTP server.", "Which SMTP server?"),
                    new Field("port", "integer", "SMTP port.", "Which port?", Default: "587", Min: 1, Max: 65535),
                    new Field("username", "string", "SMTP account.", "Which account sends?"),
                    new Field("password", "string", "Its password. Ends up in the settings file, readable only by the server's account.", "What is that account's password?", Sensitive: true),
                    new Field("from", "string", "From address.", "Which address should messages come from?"),
                    new Field("display", "string", "From name.", "Which name should messages come from?", Default: "the sign-in page's name"),
                    new Field("subject", "string", "Prefix of every subject line.", "Is there a subject prefix?", Default: "{company_name}: ")
                }),
            new("protocol", "Protocol and security", "Security architecture",
                "Sensible defaults are set; change only what policy requires.", true, new[]
                {
                    new Field("enable_device_flow", "boolean", "Device sign-in (RFC 8628).", "May devices without a browser sign in?", Default: "true"),
                    new Field("enable_pushed_authorization_requests", "boolean", "Pushed authorization requests (RFC 9126).", "Are pushed authorization requests allowed?", Default: "true"),
                    new Field("require_pushed_authorization_requests", "boolean", "Refuse authorization requests that were not pushed.", "Are pushed authorization requests mandatory?", Default: "false"),
                    new Field("enable_dynamic_registration", "boolean", "Dynamic client registration (RFC 7591), behind an access token. Needed for agents that register themselves.", "May applications and agents register themselves, with a token?", Default: "true"),
                    new Field("always_require_consent", "boolean", "Ask for consent even for first-party applications.", "Must people always be asked for consent?", Default: "false"),
                    new Field("enable_back_channel_logout", "boolean", "Tell applications when a session ends.", "Should applications be told when somebody signs out?", Default: "true"),
                    new Field("session_lifetime_minutes", "integer", "How long a browser session lasts.", "After how many minutes must people sign in again?", Default: "480", Min: 5, Max: 525600),
                    new Field("max_failed_sign_ins", "integer", "Lock an account after this many failures; 0 turns it off.", "After how many failed attempts is an account locked?", Default: "10", Min: 0, Max: 1000),
                    new Field("lockout_minutes", "integer", "How long the lock lasts.", "For how many minutes?", Default: "15", Min: 1, Max: 100000),
                    new Field("cors_origins", "array", "Browser origins that may call the token endpoint: only single-page applications need this.", "Which single-page applications will there be, at which origins?", Default: "none")
                }),
            new("management", "Automation", "Platform engineering",
                "The machine client that administers the server through its API and its MCP endpoints. An agent needs it to go on after setup.", true, new[]
                {
                    new Field("machine_secret", "string", "generate: created by setup and shown once (recommended). none: set it later in the console. supplied: machine_client_secret.", "Should the automation credential be generated now?", Default: "generate", Values: new[] { "generate", "none", "supplied" }),
                    new Field("machine_client_secret", "string", "supplied only: at least 16 characters. Kept in memory, never in the draft file.", "Which secret should it have?", Sensitive: true, Held: true, MaxLength: 500)
                }),
            new("audit", "Audit trail", "Compliance or internal audit",
                "Sends everything the server does to an ARK-RAPID Watch audit server. Optional.", true, new[]
                {
                    new Field("enabled", "boolean", "Whether to send it.", "Should an external audit trail be kept?", Default: "false"),
                    new Field("endpoint", "string", "Address of the Watch node.", "What is the audit server's address?"),
                    new Field("api_key", "string", "A secret key of the node (arkw_sk_…).", "What is the API key for this server?", Sensitive: true),
                    new Field("application", "string", "Application name events are filed under.", "Under which application name?", Default: "ark-idp", MaxLength: 100),
                    new Field("environment", "string", "Environment label.", "Which environment is this?", Default: "the host's environment", MaxLength: 60)
                }),
            new("branding", "Branding", "Brand or marketing",
                "Logos on the sign-in page. Optional.", true, new[]
                {
                    new Field("host_logo", "string", "Organization logo: an image URL or a data:image/…;base64 URI, up to 1 MB.", "Is there a logo for the sign-in page?", MaxLength: 1_500_000),
                    new Field("app_logo", "string", "Logo of the console, and of applications without their own.", "Is there a logo for the admin console?", MaxLength: 1_500_000),
                    new Field("show_powered_by", "boolean", "Show \"Powered by Ark Identity Server\".", "May the pages say what they are powered by?", Default: "true")
                })
        };

        static Section Find(string name) => Sections.First(s => s.Name == name);

        readonly ArkSetupMiddleware _setup;
        readonly ArkSetupDraft _draft;

        public IReadOnlyList<ArkMcpTool> All { get; }
        public DateTime? DraftUpdatedAt => _draft.UpdatedAt;

        /// <summary>Setup is finished, by either route: forgets everything that was collected or made for it.</summary>
        public void Close()
        {
            _draft.Close();
            _generatedKey = null;
            _generatedSecret = null;
        }

        public SetupTools(ArkSetupMiddleware setup, ArkSetupDraft draft)
        {
            _setup = setup;
            _draft = draft;
            All = Build();
        }

        // ---------------------------------------------------------------- the tools

        List<ArkMcpTool> Build()
        {
            var source = new ArkMcpParams()
                .Text("department", "Which department supplied this.", maxLength: 120)
                .Text("provided_by", "Who supplied it.", maxLength: 200)
                .Text("reference", "Where it is written down: a ticket, document or message.", maxLength: 500)
                .Text("note", "Anything worth remembering about it.", maxLength: 1000);

            var tools = new List<ArkMcpTool>
            {
                Tool("setup_status", "Where setup stands",
                    "Every section of setup: complete, missing or wrong, who usually has the answer, and what to do next. Start here, and come back after each answer.",
                    ArkMcpAccess.Read, new ArkMcpParams(), call => Status(call)),
                Tool("setup_fields", "What setup asks for",
                    "Every value in detail: what it means, the question to ask for it, whether it is required, its default, and what is stored (secrets only as set or not set).",
                    ArkMcpAccess.Read, new ArkMcpParams().Text("section", "Only this section.", values: Sections.Select(s => s.Name).ToArray()), call => Fields(call)),
            };

            foreach (var section in Sections)
            {
                var parameters = new ArkMcpParams();
                foreach (var f in section.Fields)
                    parameters.Add(new ArkMcpParam
                    {
                        Name = f.Name, Type = f.Type, Description = f.Description + (f.Default == null ? "" : $" Default: {f.Default}."),
                        Values = f.Values, Min = f.Min, Max = f.Type == "array" ? 200 : f.Max, MaxLength = f.MaxLength, Sensitive = f.Sensitive
                    });
                parameters.Object("source", "Where these values came from. Recorded with each of them.", source);
                var name = section.Name;
                tools.Add(Tool($"setup_set_{name}", $"Set: {section.Title}",
                    $"{section.Purpose} Usually known by: {section.Owner}. Set any of the values; the rest stay as they are, and an empty string removes one. " +
                    "Answers with what is still missing or wrong in the section.",
                    ArkMcpAccess.Manage, parameters, call => Set(call, name), idempotent: true));
            }

            tools.Add(Tool("setup_clear", "Clear a section",
                "Forgets everything collected for one section.", ArkMcpAccess.Manage,
                new ArkMcpParams().Text("section", "The section.", required: true, values: Sections.Select(s => s.Name).ToArray()),
                call =>
                {
                    _draft.Clear(call.Args.Required("section"));
                    return Status(call);
                }, idempotent: true, destructive: true));
            tools.Add(Tool("setup_test_database", "Test the database",
                "Connects with the collected settings and says what it found: a new database, an empty one, or an existing Ark database that setup would attach to.",
                ArkMcpAccess.Manage, new ArkMcpParams(), TestDatabase, idempotent: true, openWorld: true));
            tools.Add(Tool("setup_test_email", "Send a test email",
                "Sends a message with the collected SMTP settings.", ArkMcpAccess.Manage,
                new ArkMcpParams().Text("to", "Where to send it.", required: true, maxLength: 320), TestEmail, openWorld: true));
            tools.Add(Tool("setup_test_audit", "Test the audit server",
                "Checks the collected audit server and key, and sends it one test event.", ArkMcpAccess.Manage,
                new ArkMcpParams(), TestAudit, openWorld: true));
            tools.Add(Tool("setup_review", "Review the whole plan",
                "What setup_complete would install, in full, with who supplied what, what is only assumed, and everything that would stop it. " +
                "Its review_id is what setup_complete asks for. Show this to a person before installing.",
                ArkMcpAccess.Read, new ArkMcpParams(), Review));
            tools.Add(new ArkMcpTool
            {
                Name = "setup_complete", Title = "Install the reviewed plan",
                Description = "Writes the settings, creates and seeds the database, and turns this server into an identity provider. Cannot be undone from here. " +
                              "The answer carries the machine credential and the administrator's one-time link, each shown once: store them before doing anything else. " +
                              "The server writes the signing key and the machine credential to a keys file in its data directory (keys_file); the private key is never in the answer.",
                Access = ArkMcpAccess.Manage, Role = ArkMcpRole.Setup, Destructive = true, ReturnsSecret = true,
                Params = new ArkMcpParams()
                    .Text("review_id", "The review_id of the setup_review a person agreed to.", required: true, maxLength: 64)
                    .Text("confirm", "The tenant id, to confirm.", required: true, maxLength: 63),
                Run = Guarded(Complete)
            });
            return tools;
        }

        static ArkMcpTool Tool(string name, string title, string description, ArkMcpAccess access, ArkMcpParams parameters,
            Func<ArkMcpCall, Task<object>> run, bool idempotent = false, bool destructive = false, bool openWorld = false) => new()
        {
            Name = name, Title = title, Description = description, Access = access, Role = ArkMcpRole.Setup, Params = parameters,
            Idempotent = idempotent, Destructive = destructive, OpenWorld = openWorld, Run = Guarded(run)
        };

        /// <summary>The wizard's refusals, as a tool answers them: with the section they are about.</summary>
        static Func<ArkMcpCall, Task<object>> Guarded(Func<ArkMcpCall, Task<object>> run) => async call =>
        {
            try
            {
                return await run(call);
            }
            catch (SetupException ex)
            {
                throw new ArkMcpToolException(ex.Code, ex.Message, new { section = SectionOf(ex.Field), field = ex.Field });
            }
        };

        // ---------------------------------------------------------------- status

        Task<object> Status(ArkMcpCall call)
        {
            var views = Sections.Select(s => Describe(call, s)).ToList();
            var open = views.Where(v => v.Status is "missing" or "invalid").ToList();
            var tested = TestsOwed(call);
            return Task.FromResult<object>(new
            {
                phase = "setup",
                ready_for_review = open.Count == 0,
                environment = EnvironmentFacts(call),
                sections = views.Select(v => new
                {
                    section = v.Section.Name, title = v.Section.Title, status = v.Status, optional = v.Section.Optional ? true : (bool?)null,
                    usually_known_by = v.Section.Owner, collected = v.Collected, missing = v.Missing, problems = v.Problems,
                    test = _draft.TestOf(v.Section.Name) is { } t ? new { ok = t.Ok, message = t.Message } : null
                }),
                draft_updated_at = _draft.UpdatedAt,
                next_steps = NextSteps(open, tested)
            });
        }

        object EnvironmentFacts(ArkMcpCall call)
        {
            var directory = _setup.DataDirectory;
            return new
            {
                version = ArkWatchAudit.PackageVersion,
                name = _setup.EnvironmentName,
                data_directory = directory,
                data_directory_writable = Writable(directory),
                can_apply = _setup.CanApply,
                reached_at = call.Endpoint.Root,
                console_sign_in = HasConsoleSignIn(call.Http),
                warnings = new[]
                {
                    Writable(directory) ? null : $"This server cannot write to {directory}. Set ark_oauth_server__Setup__DataPath to a writable, persistent directory and restart before going on.",
                    _setup.CanApply ? null : "This host's configuration cannot be extended at run time. Build it with WebApplication.CreateBuilder.",
                    call.Http.Request.IsHttps || IsLoopback(call.Endpoint.Root) ? null : "You are connected over plain http: the secrets you send cross the network unencrypted."
                }.Where(w => w != null)
            };
        }

        static bool IsLoopback(string url) => Uri.TryCreate(url, UriKind.Absolute, out var u) && u.IsLoopback;

        sealed record View(Section Section, string Status, List<string> Collected, List<string> Missing, List<object> Problems);

        View Describe(ArkMcpCall call, Section section)
        {
            var values = _draft.Section(section.Name);
            bool Set(Field f) => f.Held ? _draft.Held($"{section.Name}.{f.Name}") != null : values[f.Name] != null;
            var collected = section.Fields.Where(Set).Select(f => f.Name).ToList();
            var missing = section.Fields.Where(f => f.Required && !Set(f)).Select(f => f.Name).ToList();
            missing.AddRange(MissingWhen(section.Name, values, Set, section));

            var problems = new List<object>();
            if (missing.Count == 0)
            {
                try { CheckSection(call, section.Name); }
                catch (SetupException ex) { problems.Add(new { field = ex.Field, code = ex.Code, message = ex.Message }); }
            }
            var status = missing.Count > 0 ? "missing" : problems.Count > 0 ? "invalid" : collected.Count == 0 ? "default" : "complete";
            return new View(section, status, collected, missing, problems);
        }

        /// <summary>Values that are only owed because of another one.</summary>
        static IEnumerable<string> MissingWhen(string section, JsonObject v, Func<Field, bool> set, Section def)
        {
            bool Has(string name) => set(def.Fields.First(f => f.Name == name));
            var owed = new List<string>();
            switch (section)
            {
                case "database" when Str(v, "provider") is "postgres" or "mysql" && !Has("connection_string"):
                    owed.AddRange(new[] { "host", "database", "username" }.Where(n => !Has(n)));
                    break;
                case "signing_key" when Str(v, "mode") == "import":
                    if (!Has("private_key")) owed.Add("private_key");
                    break;
                // The console and the provisioning API create accounts on it (ArkSetup.ValidateUsers).
                case "users" when !string.Equals(Str(v, "password_mode"), "email_based", StringComparison.OrdinalIgnoreCase):
                    if (!Has("default_password")) owed.Add("default_password");
                    break;
                case "email" when Bool(v, "enabled") == true:
                    owed.AddRange(new[] { "smtp", "from" }.Where(n => !Has(n)));
                    break;
                case "audit" when Bool(v, "enabled") == true:
                    owed.AddRange(new[] { "endpoint", "api_key" }.Where(n => !Has(n)));
                    break;
                case "management" when Str(v, "machine_secret") == "supplied":
                    if (!Has("machine_client_secret")) owed.Add("machine_client_secret");
                    break;
            }
            return owed;
        }

        /// <summary>The wizard's own rules, for one section.</summary>
        void CheckSection(ArkMcpCall call, string section)
        {
            var req = Request();
            switch (section)
            {
                case "organization":
                    foreach (var (name, value) in new[] { ("website_url", req.Organization!.WebsiteUrl), ("terms_url", req.Organization.TermsUrl), ("privacy_url", req.Organization.PrivacyUrl) })
                        if (!string.IsNullOrWhiteSpace(value) && !RedirectUriValidator.IsWebUrl(value))
                            throw new SetupException("invalid_url", $"{name}: a full http or https address.", name);
                    break;
                case "server": ValidateServer(req.Server!, HasConsoleSignIn(call.Http)); break;
                case "database": NormalizeDatabase(req.Database); break;
                case "signing_key" when req.Keys?.PrivateKey is { Length: > 0 } key && Str(_draft.Section("signing_key"), "mode") == "import":
                    ParsePrivateKey(key);
                    break;
                case "signing_key" when Number(_draft.Section("signing_key"), "key_size") is { } size and not (2048 or 3072 or 4096):
                    throw new SetupException("invalid_key_size", $"Key size must be 2048, 3072 or 4096 bits, not {size}.", "key_size");
                case "administrator": ValidateAdmin(req.Admin!, needsPassword: !string.IsNullOrEmpty(req.Admin!.Password)); break;
                case "users": ValidateUsers(req.Users!, req.Email); break;
                case "email" when req.Email!.Enabled: ValidateEmail(req.Email); break;
                case "protocol": ValidateProtocol(req.Protocol); break;
                case "management": ValidateManagement(req.Management); break;
                case "audit": _setup.NormalizeWatch(req.Watch); break;
            }
        }

        /// <summary>Tests worth running before a review: settings that can be proven and have not been.</summary>
        List<(string Tool, string Why)> TestsOwed(ArkMcpCall call)
        {
            var owed = new List<(string, string)>();
            if (_draft.TestOf("database") is not { Ok: true }) owed.Add(("setup_test_database", "the database settings have not been tested as they stand"));
            if (Bool(_draft.Section("email"), "enabled") == true && _draft.TestOf("email") is not { Ok: true })
                owed.Add(("setup_test_email", "outgoing email has not been tested as it stands"));
            if (Bool(_draft.Section("audit"), "enabled") == true && _draft.TestOf("audit") is not { Ok: true })
                owed.Add(("setup_test_audit", "the audit server has not been tested as it stands"));
            return owed;
        }

        List<object> NextSteps(List<View> open, List<(string Tool, string Why)> tests)
        {
            var steps = new List<object>();
            foreach (var v in open)
            {
                var fields = v.Section.Fields.Where(f => v.Missing.Contains(f.Name)).ToList();
                steps.Add(new
                {
                    tool = $"setup_set_{v.Section.Name}",
                    ask = v.Section.Owner,
                    questions = fields.Select(f => f.Ask),
                    why = v.Problems.Count > 0 ? "a value is not usable" : $"missing: {string.Join(", ", v.Missing)}"
                });
            }
            foreach (var (tool, why) in tests) steps.Add(new { tool, why });
            if (open.Count == 0) steps.Add(new { tool = "setup_review", why = tests.Count == 0 ? "everything required is in" : "everything required is in; run the tests above first" });
            return steps;
        }

        // ---------------------------------------------------------------- fields

        Task<object> Fields(ArkMcpCall call)
        {
            var only = call.Args.Text("section");
            return Task.FromResult<object>(new
            {
                sections = Sections.Where(s => only == null || s.Name == only).Select(s =>
                {
                    var values = _draft.Section(s.Name);
                    return new
                    {
                        section = s.Name, title = s.Title, usually_known_by = s.Owner, purpose = s.Purpose, set_with = $"setup_set_{s.Name}",
                        fields = s.Fields.Select(f => new
                        {
                            field = f.Name, type = f.Type, required = f.Required, description = f.Description, ask = f.Ask,
                            @default = f.Default, values = f.Values, secret = f.Sensitive ? true : (bool?)null,
                            kept_in_memory_only = f.Held ? true : (bool?)null,
                            value = Shown(s.Name, f, values), source = _draft.Source(s.Name, f.Name)
                        })
                    };
                })
            });
        }

        /// <summary>A stored value as it may be read back: a secret only as set.</summary>
        JsonNode? Shown(string section, Field f, JsonObject values)
        {
            if (f.Held) return _draft.Held($"{section}.{f.Name}") == null ? null : JsonValue.Create("(set)");
            var value = values[f.Name];
            if (value == null) return null;
            if (f.Sensitive) return JsonValue.Create("(set)");
            if (value is JsonValue v && v.TryGetValue<string>(out var text) && text.Length > 300) return JsonValue.Create($"({text.Length} characters)");
            return value.DeepClone();
        }

        // ---------------------------------------------------------------- set

        Task<object> Set(ArkMcpCall call, string name)
        {
            var section = Find(name);
            var values = new Dictionary<string, JsonNode?>(StringComparer.Ordinal);
            var held = new Dictionary<string, string?>(StringComparer.Ordinal);
            foreach (var f in section.Fields.Where(f => call.Args.Has(f.Name)))
            {
                switch (f.Type)
                {
                    case "integer": values[f.Name] = JsonValue.Create(call.Args.Int(f.Name)); break;
                    case "boolean": values[f.Name] = JsonValue.Create(call.Args.Flag(f.Name)); break;
                    case "array":
                        var list = call.Args.List(f.Name) ?? new List<string>();
                        values[f.Name] = list.Count == 0 ? null : new JsonArray(list.Select(x => (JsonNode?)JsonValue.Create(x)).ToArray());
                        break;
                    default:
                        var text = call.Args.Raw(f.Name) ?? "";
                        if (f.Held) held[f.Name] = text.Length == 0 ? null : text;
                        else values[f.Name] = text.Length == 0 ? null : JsonValue.Create(text);
                        break;
                }
            }
            if (values.Count + held.Count == 0)
                throw new ArkMcpToolException("invalid_arguments", $"give at least one of: {string.Join(", ", section.Fields.Select(f => f.Name))}.");

            JsonObject? source = null;
            if (call.Args.Object("source") is { } from)
            {
                source = new JsonObject();
                foreach (var key in new[] { "department", "provided_by", "reference", "note" })
                    if (from.Text(key) is { } said) source[key] = said;
                if (source.Count == 0) source = null;
            }
            _draft.Set(name, values, held, source);
            call.Touches("section", name);

            var view = Describe(call, section);
            var remaining = Sections.Select(s => Describe(call, s)).Where(v => v.Status is "missing" or "invalid").ToList();
            return Task.FromResult<object>(new
            {
                section = name, status = view.Status, stored = values.Keys.Concat(held.Keys), missing = view.Missing, problems = view.Problems,
                source_recorded = source != null,
                note = source == null ? "no source was given; say who supplied these values by setting them again with source" : null,
                still_open = remaining.Select(v => new { section = v.Section.Name, v.Section.Owner, v.Missing }),
                next_steps = NextSteps(remaining, TestsOwed(call))
            });
        }

        // ---------------------------------------------------------------- tests

        async Task<object> TestDatabase(ArkMcpCall call)
        {
            var result = JsonSerializer.SerializeToElement(await _setup.TestDatabaseAsync(Request().Database), Json);
            var ok = result.GetProperty("ok").GetBoolean();
            var message = result.GetProperty("msg").GetString() ?? "";
            _draft.Tested("database", ok, message);
            var tenants = result.TryGetProperty("tenants", out var t) && t.ValueKind == JsonValueKind.Array
                ? t.EnumerateArray().Select(x => x.GetString()).ToList() : new List<string?>();
            return new
            {
                ok, message, existing_tenants = tenants,
                note = tenants.Count == 0 ? null
                    : "Setup would attach to this database instead of creating one: the tenant id must be one of these, the administrator must be its administrator, " +
                      "and no key, account or machine credential is created."
            };
        }

        async Task<object> TestEmail(ArkMcpCall call)
        {
            var req = Request();
            if (req.Email is not { Enabled: true })
                throw new ArkMcpToolException("not_enabled", "email is off; set enabled, smtp and from with setup_set_email first.");
            var result = JsonSerializer.SerializeToElement(
                await TestEmailAsync(new EmailTestRequest { Email = req.Email, To = call.Args.Required("to") }), Json);
            var ok = result.GetProperty("ok").GetBoolean();
            var message = result.GetProperty("msg").GetString() ?? "";
            _draft.Tested("email", ok, message);
            return new { ok, message };
        }

        async Task<object> TestAudit(ArkMcpCall call)
        {
            var watch = Request().Watch;
            if (watch is not { Enabled: true })
                throw new ArkMcpToolException("not_enabled", "the audit trail is off; set enabled, endpoint and api_key with setup_set_audit first.");
            var result = JsonSerializer.SerializeToElement(await _setup.TestWatchAsync(watch), Json);
            var ok = result.GetProperty("ok").GetBoolean();
            var message = result.GetProperty("msg").GetString() ?? "";
            _draft.Tested("audit", ok, message);
            return new { ok, message };
        }

        // ---------------------------------------------------------------- review and install

        async Task<object> Review(ArkMcpCall call)
        {
            // One look at the draft: the plan shown below and the review_id that names it are of the
            // same values, whatever another caller stores while the database is being asked.
            var (views, req, reviewId, sources, owed) = _draft.Read(() =>
                (Sections.Select(s => Describe(call, s)).ToList(), Request(), _draft.ReviewId(), _draft.Sources(), TestsOwed(call)));
            var problems = views.SelectMany(v => v.Missing.Select(m => (object)new { section = v.Section.Name, field = m, code = "missing", message = $"{v.Section.Name}.{m} is required.", ask = v.Section.Owner })
                .Concat(v.Problems.Select(p => (object)new { section = v.Section.Name, problem = p, ask = v.Section.Owner }))).ToList();
            if (!Writable(_setup.DataDirectory))
                problems.Add(new { code = "cannot_write", message = $"this server cannot write to {_setup.DataDirectory}. Set ark_oauth_server__Setup__DataPath to a writable, persistent directory and restart.", ask = "IT or platform engineering" });
            if (!_setup.CanApply)
                problems.Add(new { code = "cannot_apply", message = "this host's configuration cannot be extended at run time, so settings could not take effect.", ask = "IT or platform engineering" });
            var warnings = new List<string>();
            object? plan = null;

            if (problems.Count == 0)
            {
                var byLink = string.IsNullOrEmpty(req.Admin?.Password);
                if (byLink) req.Admin!.Password = ArkCrypto.RandomToken(32);
                try
                {
                    var checkedPlan = await Task.Run(() => _setup.Validate(call.Http, req));
                    plan = PlanView(checkedPlan, req, byLink);
                    foreach (var (_, why) in owed.Where(t => t.Tool != "setup_test_database")) warnings.Add(why + ".");
                    if (!checkedPlan.BaseUrl.Equals(call.Endpoint.Root, StringComparison.OrdinalIgnoreCase))
                        warnings.Add($"You reached this server at {call.Endpoint.Root}, and its public URL will be {checkedPlan.BaseUrl}. People and tokens go through the public URL, so it has to lead here.");
                    if (checkedPlan.Provider == "sqlite")
                        warnings.Add("SQLite keeps everything in one file on this machine. In a container, the data directory must be on persistent storage; for more than one instance, use PostgreSQL or MySQL.");
                    if (checkedPlan.MachineSecret == null && !checkedPlan.ExistingTenant)
                        warnings.Add("No machine credential will be created, so an agent cannot go on over MCP until an administrator makes one in the console.");
                    if (!byLink) warnings.Add("The administrator's password was given here. Prefer leaving it out: they then set it themselves through a one-time link.");
                    if (checkedPlan.Watch != null && checkedPlan.Watch.Endpoint.StartsWith("http:", StringComparison.OrdinalIgnoreCase))
                        warnings.Add("The audit server's address is plain http: its key and every event cross the network unencrypted.");
                }
                catch (SetupException ex)
                {
                    problems.Add(new { section = SectionOf(ex.Field), field = ex.Field, code = ex.Code, message = ex.Message });
                }
            }

            var assumed = views.SelectMany(v => v.Section.Fields
                .Where(f => f.Default != null && !v.Collected.Contains(f.Name) && f.Name is not ("sqlite_file" or "port" or "ssl"))
                .Select(f => $"{v.Section.Name}.{f.Name}: {f.Default}")).ToList();
            var unattributed = views.SelectMany(v => v.Collected.Select(c => $"{v.Section.Name}.{c}")).Where(k => !sources.ContainsKey(k)).ToList();

            return new
            {
                ready = problems.Count == 0,
                review_id = problems.Count == 0 ? reviewId : null,
                plan, problems, warnings,
                assumed_defaults = assumed,
                supplied_by = sources.ToDictionary(s => s.Key, s => s.Value),
                supplied_without_source = unattributed,
                next_step = problems.Count == 0
                    ? "Show this plan to a person who may decide. When they agree, call setup_complete with this review_id and the tenant id."
                    : "Put the problems right, then review again."
            };
        }

        static object PlanView(Plan p, SetupRequest req, bool adminByLink) => new
        {
            organization = req.Organization?.CompanyName,
            issuer = p.Issuer,
            discovery = $"{p.Issuer}/.well-known/openid-configuration",
            tenant_id = p.TenantId,
            public_url = p.AppRoot,
            database = new
            {
                provider = p.Provider, connection = Redact(p.Connection),
                action = p.ExistingTenant ? "attach to the existing Ark database: no key, account or credential is created" : "create the tables and the first tenant"
            },
            signing_key = p.ExistingTenant ? "the existing database's" : "RS256, stored in the database only",
            administrator = new
            {
                username = p.AdminUsername, name = req.Admin?.Name ?? "Administrator",
                password = p.ExistingTenant ? "unchanged" : adminByLink ? "set by the administrator, through a one-time link returned by setup_complete" : "as given"
            },
            new_people = req.Users?.PasswordMode ?? "admin_managed",
            email = req.Email is { Enabled: true } e ? $"{e.Smtp}:{e.Port ?? 587} as {e.From}" : "off",
            dynamic_registration = req.Protocol?.EnableDynamicRegistration ?? false,
            cors_origins = req.Protocol?.CorsOrigins ?? new List<string>(),
            machine_client = new
            {
                client_id = ArkManagementAuth.MachineClientId(p.TenantId),
                secret = p.ExistingTenant ? "unchanged" : p.MachineSecret == null ? "none" : "returned once by setup_complete"
            },
            audit_trail = p.Watch == null ? "off" : $"{p.Watch.Endpoint} as {p.Watch.Application}",
            mcp_after_setup = ArkMcpResources.Tenant(p.AppRoot, p.TenantId)
        };

        async Task<object> Complete(ArkMcpCall call)
        {
            // Checked and taken in one look at the draft: a value stored between the two would have
            // been installed under a review that never showed it.
            var (req, collected) = _draft.Read(() =>
            {
                var tenant = Str(_draft.Section("server"), "tenant_id") ?? "";
                if (!string.Equals(call.Args.Required("confirm"), tenant, StringComparison.Ordinal))
                    throw new ArkMcpToolException("confirmation_required", "confirm must be the tenant id exactly as collected.");
                if (!string.Equals(call.Args.Required("review_id"), _draft.ReviewId(), StringComparison.Ordinal))
                    throw new ArkMcpToolException("not_reviewed",
                        "that is not the review of the draft as it stands: something changed since, or it was never reviewed. Call setup_review again and have the plan agreed.");
                return (Request(), _draft.Sources());
            });
            var byLink = string.IsNullOrEmpty(req.Admin?.Password);
            var sources = collected.ToDictionary(s => s.Key,
                s => string.Join(" / ", new[] { "department", "provided_by", "reference" }.Select(k => s.Value[k]?.GetValue<string>()).Where(v => !string.IsNullOrEmpty(v))),
                StringComparer.Ordinal);

            var done = await _setup.InstallAsync(call.Http, req, "mcp", byLink, sources);
            var plan = done.Plan;
            var config = ArkConfigSnapshot.Server(call.Get<IConfiguration>()) ?? call.Config;
            var endpoint = new ArkMcpEndpoint
            {
                Level = ArkMcpLevel.Tenant, Tenant = new ArkTenant { tenant_id = plan.TenantId }, Config = config, Root = plan.AppRoot,
                Resource = ArkMcpResources.Tenant(plan.AppRoot, plan.TenantId)
            };
            return new
            {
                done = true,
                tenant_id = plan.TenantId,
                issuer = done.Endpoints.Issuer,
                discovery = done.Endpoints.Discovery,
                console = $"{plan.AppRoot}/{plan.TenantId}/admin",
                settings_file = done.SettingsFile,
                // on the server: the wizard's Download JSON, signing key included. A path, never the content.
                keys_file = done.KeysFile,
                attached_existing_database = plan.ExistingTenant,
                administrator = new
                {
                    username = plan.AdminUsername,
                    password_link = done.AdminPasswordLink,
                    note = done.AdminPasswordLink == null ? null
                        : $"Give this link to the administrator over a private channel. It sets their password, works once, and expires after {config.PasswordLinkLifetimeHours} hours. They cannot sign in before."
                },
                machine_client = new
                {
                    client_id = ArkManagementAuth.MachineClientId(plan.TenantId),
                    client_secret = plan.ExistingTenant ? null : plan.MachineSecret,
                    note = plan.ExistingTenant ? "An existing database was attached; its machine secret is unchanged."
                        : plan.MachineSecret == null ? "No secret was set. An administrator generates one in the console."
                        : done.KeysFile == null
                        ? "Shown once; only its hash is stored. Keep it in a secret store: whoever holds it administers this server."
                        : $"Shown once here; the database keeps only its hash, and a copy is in {done.KeysFile} on the server. Keep it in a secret store: whoever holds it administers this server."
                },
                mcp = new
                {
                    tenant = endpoint.Resource,
                    host = ArkMcpResources.Host(plan.AppRoot),
                    server_card = $"{endpoint.Resource}/server-card",
                    config = ArkMcpDocuments.Config(endpoint)
                },
                next_steps = new[]
                {
                    "Store the machine credential and hand the administrator their link.",
                    $"Disconnect from setup: the setup code no longer works. Connect to {endpoint.Resource} with a token for the machine client (see mcp.config).",
                    "Call tenant_overview there: it shows what the tenant still needs, beginning with its first application (onboard_application)."
                }
            };
        }

        // ---------------------------------------------------------------- the draft, as the wizard's request

        SetupRequest Request()
        {
            T Of<T>(string section) where T : new() =>
                _draft.Section(section).Deserialize<T>(Json) ?? new T();

            var database = _draft.Section("database");
            var key = _draft.Section("signing_key");
            var management = _draft.Section("management");
            var admin = _draft.Section("administrator");
            var organization = Of<OrganizationSection>("organization");
            var server = Of<ServerSection>("server");
            if (string.IsNullOrWhiteSpace(server.TenantDisplay) && !string.IsNullOrWhiteSpace(organization.CompanyName))
                server.TenantDisplay = $"{organization.CompanyName} Admin Console";
            // As in the wizard, whose switch starts on. It is always behind an access token.
            var protocol = Of<ProtocolSection>("protocol");
            protocol.EnableDynamicRegistration ??= true;

            return new SetupRequest
            {
                Organization = organization,
                Branding = Of<BrandingSection>("branding"),
                Server = server,
                Database = new DatabaseSection { Provider = Str(database, "provider") ?? "sqlite", ConnectionString = Connection(database) },
                Keys = new KeysSection
                {
                    PrivateKey = Str(key, "mode") == "import" ? _draft.Held("signing_key.private_key") : GeneratedKey(Number(key, "key_size") ?? 2048)
                },
                Admin = new AdminSection { Username = Str(admin, "username"), Name = Str(admin, "name"), Password = _draft.Held("administrator.password") },
                Users = Of<UsersSection>("users"),
                Email = Of<EmailSection>("email"),
                Protocol = protocol,
                Management = new ManagementSection
                {
                    MachineClientSecret = (Str(management, "machine_secret") ?? "generate") switch
                    {
                        "none" => null,
                        "supplied" => _draft.Held("management.machine_client_secret"),
                        _ => GeneratedSecret()
                    }
                },
                Watch = Of<WatchSection>("audit")
            };
        }

        // Made once and kept for the life of the process, so a review and the install that follows
        // it talk about the same key. Never written down before the install stores them.
        string? _generatedKey;
        int _generatedKeySize;
        string? _generatedSecret;

        string GeneratedKey(int size)
        {
            if (size is not (2048 or 3072 or 4096)) size = 2048;
            if (_generatedKey == null || _generatedKeySize != size)
            {
                _generatedKey = ArkCrypto.GenerateRsaKeyPair(size).privateKey;
                _generatedKeySize = size;
            }
            return _generatedKey;
        }

        string GeneratedSecret() => _generatedSecret ??= ArkCrypto.RandomToken(32);

        string Connection(JsonObject db)
        {
            if (Str(db, "connection_string") is { } raw) return raw;
            var provider = Str(db, "provider") ?? "sqlite";
            if (provider == "sqlite") return $"Data Source={Str(db, "sqlite_file") ?? DefaultSqliteFile(_setup.DataDirectory)}";
            if (Str(db, "host") is not { } host) return "";
            var ssl = Str(db, "ssl") ?? "prefer";
            // The builder quotes a password with a ';' in it, which pasting text together would not.
            var b = new DbConnectionStringBuilder();
            if (provider == "postgres")
            {
                b["Host"] = host;
                b["Port"] = Number(db, "port") ?? 5432;
                b["Database"] = Str(db, "database") ?? "";
                b["Username"] = Str(db, "username") ?? "";
                b["Password"] = Str(db, "password") ?? "";
                b["SSL Mode"] = ssl switch { "require" => "Require", "disable" => "Disable", _ => "Prefer" };
            }
            else
            {
                b["Server"] = host;
                b["Port"] = Number(db, "port") ?? 3306;
                b["Database"] = Str(db, "database") ?? "";
                b["User ID"] = Str(db, "username") ?? "";
                b["Password"] = Str(db, "password") ?? "";
                b["SslMode"] = ssl switch { "require" => "Required", "disable" => "Disabled", _ => "Preferred" };
            }
            return b.ConnectionString;
        }

        static string Redact(string connection)
        {
            try
            {
                var b = new DbConnectionStringBuilder { ConnectionString = connection };
                foreach (string name in b.Keys.Cast<string>().ToList())
                    // By what the name contains: each driver has its own spellings (PWD, PSW, SSL Password,
                    // CertificatePassword, Password2), and a plan is shown to people and to a model.
                    if (Regex.IsMatch(name, "pass|pwd|psw|secret|token", RegexOptions.IgnoreCase)) b[name] = "(set)";
                return b.ConnectionString;
            }
            catch (ArgumentException)
            {
                return "(a connection string)";
            }
        }

        static string? SectionOf(string? field) => field switch
        {
            "tenant_id" or "base_url" or "base_path" or "landing_url" => "server",
            "provider" or "connection_string" => "database",
            "private_key" or "key_size" => "signing_key",
            "admin_username" or "admin_password" => "administrator",
            "password_mode" or "default_password" => "users",
            "smtp" or "port" or "from" or "test_to" => "email",
            "cors_origins" => "protocol",
            "machine_client_secret" => "management",
            "host_logo" or "app_logo" => "branding",
            "website_url" or "terms_url" or "privacy_url" => "organization",
            { } f when f.StartsWith("watch_", StringComparison.Ordinal) => "audit",
            _ => null
        };

        static string? Str(JsonObject o, string name) => o[name] is JsonValue v && v.TryGetValue<string>(out var s) && s.Length > 0 ? s : null;
        static bool? Bool(JsonObject o, string name) => o[name] is JsonValue v && v.TryGetValue<bool>(out var b) ? b : null;
        static int? Number(JsonObject o, string name) => o[name] is JsonValue v && v.TryGetValue<int>(out var n) ? n : null;
    }
}
