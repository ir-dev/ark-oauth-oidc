using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Configuration.Json;
using Microsoft.Extensions.FileProviders;

namespace Ark.oAuth.Oidc
{
    /// <summary>
    /// What the setup wizard hands the first-run seed that configuration does not carry.
    ///
    /// Everything here is a secret or is only meaningful once. None of it is written to the
    /// settings file: the administrator's password and the machine secret go into the database
    /// as hashes and the signing key goes into <c>signing_keys</c>. The keys file
    /// (<see cref="ArkIdpSettings.KeysFileName"/>) keeps a copy of the key and the machine secret
    /// beside the settings, unless <c>Setup:SaveKeysFile</c> is false; the password is nowhere.
    /// </summary>
    internal sealed class ArkSeedOverrides
    {
        public string? AdminPassword { get; init; }
        public (string publicKey, string privateKey)? SigningKey { get; init; }
        public string? MachineClientSecret { get; init; }
        public string? TenantDisplay { get; init; }
        public string? ConsoleLogo { get; init; }
    }

    /// <summary>
    /// Where the wizard's output lives, and how it becomes configuration.
    ///
    /// One directory — <c>ark-idp-data</c> under the content root unless
    /// <c>ark_oauth_server:Setup:DataPath</c> says otherwise — holding <c>settings.json</c>, the
    /// keys file setup leaves, the uploaded logos and, until setup is finished, the setup code. The
    /// directory carries its own <c>.gitignore</c>, because <c>dotnet run</c> puts it inside the
    /// project and it holds the SMTP password and the private signing key.
    /// </summary>
    public static class ArkIdpSettings
    {
        public const string SettingsFileName = "settings.json";
        internal const string BrandingFolder = "branding";
        internal const string TokenFileName = "setup-code.txt";

        /// <summary>
        /// The keys file: what the wizard's last screen offers as <b>Download JSON</b>, under the same
        /// name, written into the data directory by whichever route completed setup.
        /// </summary>
        public static string KeysFileName(string tenantId) => $"ark-idp-{tenantId}-keys.json";

        /// <summary>The wizard's directory, absolute.</summary>
        public static string DataDirectory(IConfiguration configuration, IHostEnvironment env)
        {
            var configured = configuration["ark_oauth_server:Setup:DataPath"];
            var path = string.IsNullOrWhiteSpace(configured) ? "ark-idp-data" : configured.Trim();
            return Path.GetFullPath(Path.IsPathRooted(path) ? path : Path.Combine(env.ContentRootPath, path));
        }

        public static string SettingsFile(IConfiguration configuration, IHostEnvironment env) =>
            Path.Combine(DataDirectory(configuration, env), SettingsFileName);

        /// <summary>
        /// Whether the server has what it needs to run: an operator tenant and a database.
        /// Everything else has a default, or is only needed once that much exists.
        /// </summary>
        public static bool IsConfigured(IConfiguration configuration) =>
            !string.IsNullOrWhiteSpace(configuration["ark_oauth_server:TenantId"]) &&
            !string.IsNullOrWhiteSpace(configuration.GetConnectionString("ArkAuthConnection"));

        /// <summary>
        /// Adds the wizard's <c>settings.json</c> to the host's configuration, once.
        ///
        /// Inserted directly after the last appsettings file rather than appended, so it sits
        /// below user secrets, environment variables and the command line. Anything the wizard
        /// wrote can still be overridden the way every other setting is, and a deployment that
        /// sets <c>ark_oauth_server__TenantId</c> in its environment keeps that value.
        ///
        /// Only possible on a configuration that is also a builder — the
        /// <see cref="ConfigurationManager"/> every <c>WebApplication</c> uses. Returns false
        /// otherwise, and the wizard then reports that it cannot apply what it collects.
        /// </summary>
        public static bool Attach(IConfiguration configuration, IHostEnvironment env)
        {
            if (configuration is not IConfigurationBuilder builder) return false;
            if (builder.Sources.OfType<ArkIdpSettingsSource>().Any()) return true;

            var file = SettingsFile(configuration, env);
            var directory = Path.GetDirectoryName(file)!;
            // A PhysicalFileProvider needs its root to exist. Watching the nearest existing
            // ancestor instead would create nothing for a server that never runs the wizard.
            var root = env.ContentRootPath;
            var relative = Path.GetRelativePath(root, file);
            if (relative.StartsWith("..", StringComparison.Ordinal) || Path.IsPathRooted(relative))
            {
                if (!Directory.Exists(directory)) return false;
                root = directory;
                relative = SettingsFileName;
            }

            var source = new ArkIdpSettingsSource
            {
                FileProvider = new PhysicalFileProvider(root),
                Path = relative,
                Optional = true,
                ReloadOnChange = true
            };

            var index = 0;
            for (var i = 0; i < builder.Sources.Count; i++)
            {
                if (builder.Sources[i] is JsonConfigurationSource json && json is not ArkIdpSettingsSource &&
                    (json.Path ?? "").StartsWith("appsettings", StringComparison.OrdinalIgnoreCase))
                    index = i + 1;
            }
            builder.Sources.Insert(index, source);
            return true;
        }

        /// <summary>Writes a file only its owner can read, replacing any previous one in one step.</summary>
        internal static void WritePrivateFile(string path, byte[] content)
        {
            CreatePrivateDirectory(Path.GetDirectoryName(path)!);
            EnsureIgnored(Path.GetDirectoryName(path)!);
            var temp = path + ".tmp";
            // One left by a write that was cut short would keep whatever mode it has.
            File.Delete(temp);
            using (var file = CreatePrivateFile(temp)) file.Write(content);
            File.Move(temp, path, overwrite: true);
        }

        /// <summary>
        /// A new file, its owner's alone from the moment it exists. Tightening it after writing left
        /// it open to every account on the machine in between. A file system without modes — a
        /// network share, say — ignores the request.
        /// </summary>
        internal static FileStream CreatePrivateFile(string path)
        {
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
            if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            return new FileStream(path, options);
        }

        /// <summary>
        /// The data directory, for its owner alone when this creates it. One that is already there is
        /// left as it is: somebody may have opened it to a backup account on purpose.
        /// </summary>
        internal static void CreatePrivateDirectory(string path)
        {
            if (OperatingSystem.IsWindows() || Directory.Exists(path)) Directory.CreateDirectory(path);
            else Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        /// <summary>
        /// The data directory ignores itself. It lands inside the project under <c>dotnet run</c>,
        /// and this repository's history already had to be rewritten once for a committed key.
        /// </summary>
        internal static void EnsureIgnored(string directory)
        {
            var ignore = Path.Combine(directory, ".gitignore");
            if (File.Exists(ignore)) return;
            try
            {
                File.WriteAllText(ignore,
                    "# Written by the Ark IdP setup wizard: this server's settings, secrets included.\n" +
                    "# Back it up; never commit it.\n*\n");
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    /// <summary>Marks the configuration source <see cref="ArkIdpSettings.Attach"/> added.</summary>
    internal sealed class ArkIdpSettingsSource : JsonConfigurationSource
    {
    }

    /// <summary>
    /// The first-run setup wizard.
    ///
    /// A server that starts with no tenant or no database answers every request with the wizard
    /// — a browser is redirected to <c>/ark-idp/setup</c>, anything else gets a 503 naming it —
    /// until the wizard has collected what the server needs, written it to
    /// <see cref="ArkIdpSettings"/>, created and seeded the database, and reloaded configuration.
    /// From the next request on, the same process is the identity provider. No restart.
    ///
    /// <b>Who may run it.</b> Whoever completes setup becomes the administrator, so an
    /// unconfigured server exposed to a network is a race. The wizard asks for a setup code that is
    /// printed in the server's log and written beside the settings, which only someone who can see
    /// the server has. The one exception is a developer at <c>dotnet run</c>: in the Development
    /// environment, from a loopback address, with nothing to say a proxy was in between.
    /// <c>Setup:RequireToken</c> asks for it there too; <c>Setup:Enabled</c> false removes the
    /// wizard altogether.
    ///
    /// <b>When it is gone.</b> A process that has run configured never offers setup again: settings
    /// that go missing, or that a slip of the hand has made unreadable, are a fault to report and not
    /// an invitation to whoever asks next. Nor does one whose settings file is there and cannot be read.
    ///
    /// <b>Cross-site requests.</b> Every API call is a JSON POST carrying a custom header, which a
    /// browser will not send cross-origin without a preflight this middleware never grants.
    ///
    /// Served by middleware rather than controllers, ahead of authentication: an unconfigured
    /// server has no scheme a controller could rely on, and a host's own pipeline need not have
    /// anything in particular in it for the wizard to work.
    /// </summary>
    internal sealed class ArkSetupMiddleware
    {
        public const string SetupPath = "/ark-idp/setup";
        public const string BrandingPath = "/ark-idp/branding";
        const string TokenHeader = "X-Ark-Setup-Code";
        const string CsrfHeader = "X-Ark-Setup";

        static readonly SemaphoreSlim InstallLock = new(1, 1);
        internal static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            WriteIndented = false
        };

        static string? _setupCode;
        static readonly object CodeLock = new();

        readonly RequestDelegate _next;
        readonly IConfiguration _config;
        readonly IHostEnvironment _env;
        readonly ILogger _log;

        public ArkSetupMiddleware(RequestDelegate next, IConfiguration config, IHostEnvironment env, ILoggerFactory logs)
        {
            _next = next;
            _config = config;
            _env = env;
            _log = logs.CreateLogger("Ark.oAuth.Oidc.Setup");

            ArkIdpSettings.Attach(config, env);
            if (Enabled && !Configured() && Withheld() == null) Announce();
        }

        bool Enabled => _config.GetValue("ark_oauth_server:Setup:Enabled", true);

        // Odd while an install is running. Between its two steps, the settings taking effect and the
        // database being seeded, configuration already reads as complete.
        int _installs;
        // This process has served as a configured server, so it never offers setup again.
        volatile bool _wasConfigured;
        int _lossReported;

        /// <summary>
        /// Whether the server is set up, read so that an install under way counts as not yet. A
        /// request let through in the middle of one ran the plain bootstrap: it won the race for the
        /// empty database and seeded it without the password, key and secret that had been collected.
        /// </summary>
        bool Configured()
        {
            while (true)
            {
                var before = Volatile.Read(ref _installs);
                if ((before & 1) != 0) return false;
                var configured = ArkIdpSettings.IsConfigured(_config);
                // An install began or ended meanwhile: what was read may be the half of it.
                if (Volatile.Read(ref _installs) != before) continue;
                if (configured) _wasConfigured = true;
                return configured;
            }
        }

        /// <summary>
        /// Why setup is not to be offered although there is no configuration, or null when it is. A
        /// running server whose settings file was mistyped, half saved or on a volume that went away
        /// used to fall back to the wizard for as long as that lasted, with a live database to attach to.
        /// </summary>
        string? Withheld()
        {
            if (_wasConfigured) return "the settings it was running with are gone or can no longer be read";
            return SettingsUnreadable() ? "its settings file is there but cannot be read" : null;
        }

        /// <summary>Whether there is a settings file configuration cannot load, by configuration's own reading of it.</summary>
        bool SettingsUnreadable()
        {
            var file = ArkIdpSettings.SettingsFile(_config, _env);
            if (!File.Exists(file)) return false;
            try
            {
                using var content = File.OpenRead(file);
                new ConfigurationBuilder().AddJsonStream(content).Build();
                return false;
            }
            catch (FileNotFoundException) { return false; } // removed since: a failed install takes its file back
            catch (Exception ex) when (ex is InvalidDataException or FormatException or JsonException or IOException or UnauthorizedAccessException)
            {
                return true;
            }
        }

        async Task AnswerWithheldAsync(HttpContext context, string why)
        {
            // Once per loss, or a busy server would fill its log with it.
            if (Interlocked.Exchange(ref _lossReported, 1) == 0)
                _log.LogError(
                    "Ark IdP has no usable configuration: {Why}. Every request is answered with 503 and setup is not offered. " +
                    "Put {File} right and the server carries on by itself; to set it up from the beginning, move that file away and restart.",
                    why, ArkIdpSettings.SettingsFile(_config, _env));
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            context.Response.Headers.CacheControl = "no-store";
            await context.Response.WriteAsJsonAsync(new
            {
                error = "configuration_unavailable",
                msg = "This identity provider cannot read its configuration. The reason is in its log."
            });
        }

        // What the setup tools report about this host (Mcp/Tools/SetupTools.cs).
        internal string DataDirectory => ArkIdpSettings.DataDirectory(_config, _env);
        internal string EnvironmentName => _env.EnvironmentName;
        internal bool CanApply => _config is IConfigurationBuilder;

        public async Task InvokeAsync(HttpContext context)
        {
            var path = context.Request.Path;

            if (path.StartsWithSegments(BrandingPath, out var asset))
            {
                await ServeBrandingAsync(context, asset.Value ?? "");
                return;
            }

            var configured = Configured();
            if (configured) Interlocked.Exchange(ref _lossReported, 0);
            else if (Enabled && Withheld() is { } why)
            {
                await AnswerWithheldAsync(context, why);
                return;
            }

            if (path.StartsWithSegments(SetupPath, out var rest))
            {
                if (configured || !Enabled)
                {
                    // Finished: the wizard is gone, and an old bookmark lands on the server instead.
                    if (HttpMethods.IsGet(context.Request.Method) && (rest.Value ?? "").Length <= 1)
                        context.Response.Redirect($"{context.Request.PathBase}/");
                    else
                        context.Response.StatusCode = StatusCodes.Status404NotFound;
                    return;
                }
                await HandleSetupAsync(context, rest.Value ?? "");
                return;
            }

            if (configured || !Enabled)
            {
                await _next(context);
                return;
            }

            // Setup by an agent. The same address is the host level of the MCP server once setup
            // is done, and is then the controller's.
            if (McpEnabled && path.StartsWithSegments(Mcp.ArkMcpResources.HostPath, out var mcp))
            {
                await ServeMcpAsync(context, mcp.Value ?? "");
                return;
            }

            // Not configured: nothing else can be served yet.
            if (path.Equals("/favicon.ico", StringComparison.OrdinalIgnoreCase))
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
            }
            var setupUrl = $"{context.Request.PathBase}{SetupPath}";
            if (HttpMethods.IsGet(context.Request.Method) &&
                context.Request.Headers.Accept.ToString().Contains("text/html", StringComparison.OrdinalIgnoreCase))
            {
                context.Response.Redirect(setupUrl);
                return;
            }
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            await context.Response.WriteAsJsonAsync(new
            {
                error = "setup_required",
                msg = $"This identity provider has not been set up yet. Open {setupUrl} in a browser to set it up."
            });
        }

        // ---------------------------------------------------------------- the setup code

        void Announce()
        {
            var code = EnsureSetupCode();
            var where = !LocalExempt ? $" Enter the setup code {code}."
                : $" From this machine (localhost) no code is needed, because the environment is Development. From any other machine, enter the setup code {code}.";
            var (key, keyProblem) = ReadAccessKey();
            if (key != null)
                where += $" Or open {SetupPath}#key=<the value of ark_oauth_server:Setup:AccessKey> on this server, which shows the code.";
            _log.LogWarning(
                "Ark IdP is not configured yet. Open /ark-idp/setup on this server in a browser to run the setup wizard.{Where}", where);
            if (keyProblem != null)
                _log.LogError(
                    "ark_oauth_server:Setup:AccessKey is ignored: {Why}. The setup link does not work until it is put right; the setup code still does.",
                    keyProblem);
            // Never a property named Code here, nor in any line of this category: the onboarding agent
            // takes a value of that name, at Warning and above, to be the setup code.
            if (code != null && McpEnabled)
                _log.LogWarning(
                    "An agent can set it up instead: connect it to the MCP server at {Path} with the setup code {Code} as its bearer token. " +
                    "The connection settings are at {Path}/config.", Mcp.ArkMcpResources.HostPath, code, Mcp.ArkMcpResources.HostPath);
        }

        /// <summary>Whether an agent may run setup over MCP. Read from configuration directly: there may be no section to bind yet.</summary>
        bool McpEnabled => _config.GetValue("ark_oauth_server:Mcp:Enabled", true) && _config.GetValue("ark_oauth_server:Mcp:HostLevel", true);

        // ---------------------------------------------------------------- the setup link

        /// <summary>Shorter than this, a configured access key is ignored: it would be easier to guess than the code it unlocks.</summary>
        internal const int MinAccessKeyLength = 16;
        const string AccessKeySetting = "ark_oauth_server:Setup:AccessKey";

        /// <summary>
        /// The key that opens the setup link, <c>/ark-idp/setup#key=…</c>, which hands out the setup code
        /// to someone who cannot read the server's log: whoever deploys the server puts it in the
        /// platform's settings and sends the link to whoever sets it up. Null with the reason when it
        /// is set but not usable; null and null when it is not set, or holds a <c>&lt;&lt;placeholder&gt;&gt;</c>.
        /// </summary>
        (string? Key, string? Problem) ReadAccessKey()
        {
            var value = (_config[AccessKeySetting] ?? "").Trim();
            if (value.Length == 0 || (value.StartsWith("<<") && value.EndsWith(">>"))) return (null, null);
            if (value.Length < MinAccessKeyLength)
                return (null, $"it is {value.Length} characters long, and needs at least {MinAccessKeyLength}");
            return (value, null);
        }

        /// <summary>
        /// The setup code an access key stands for: twelve characters of HMAC-SHA256 under the key, from
        /// the same alphabet as a random code, five bits each. The same on every instance and after every
        /// restart, with or without a data directory that survives, so a link opened on one instance is a
        /// code that every other instance accepts.
        /// </summary>
        static string CodeFromAccessKey(string key)
        {
            const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
            var mac = HMACSHA256.HashData(Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes("ark-idp/setup-code/v1"));
            var bits = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(mac);
            var chars = new char[12];
            for (var i = 0; i < chars.Length; i++) chars[i] = alphabet[(int)((bits >> (59 - 5 * i)) & 31)];
            return $"{new string(chars, 0, 4)}-{new string(chars, 4, 4)}-{new string(chars, 8, 4)}";
        }

        // Wrong keys are answered one at a time, a second apart, for the whole process: a person with
        // the right link is not slowed, and a guesser gets one try a second however many requests it
        // sends. Past a short queue the rest are turned away at once rather than held open.
        static readonly SemaphoreSlim WrongKeyGate = new(1, 1);
        static int _wrongKeyQueue;
        static int _wrongKeys;
        const int WrongKeyQueueLimit = 20;

        async Task RevealCodeAsync(HttpContext context)
        {
            var (key, _) = ReadAccessKey();
            if (key == null)
            {
                await Fail(context, 404, "setup_link_disabled",
                    "This server does not accept setup links. Ask whoever runs it for the setup code from its log.");
                return;
            }

            AccessKeyRequest? body;
            try { body = await Read<AccessKeyRequest>(context); }
            catch (JsonException) { body = null; }
            var given = (body?.Key ?? "").Trim();

            if (given.Length == 0 || !Protocol.ArkCrypto.FixedTimeEquals(given, key))
            {
                var count = Interlocked.Increment(ref _wrongKeys);
                if (count == 1 || count % 100 == 0)
                    _log.LogWarning("Ark IdP setup link: {Count} wrong key(s) so far, the latest from {Remote}.",
                        count, context.Connection.RemoteIpAddress?.ToString());
                if (Interlocked.Increment(ref _wrongKeyQueue) > WrongKeyQueueLimit)
                {
                    Interlocked.Decrement(ref _wrongKeyQueue);
                    context.Response.Headers.RetryAfter = "5";
                    await Fail(context, 429, "slow_down", "Too many attempts with a wrong setup link. Wait a moment and try again.");
                    return;
                }
                try
                {
                    await WrongKeyGate.WaitAsync(context.RequestAborted);
                    try { await Task.Delay(TimeSpan.FromSeconds(1), context.RequestAborted); }
                    finally { WrongKeyGate.Release(); }
                }
                catch (OperationCanceledException) { return; } // the caller has gone
                finally { Interlocked.Decrement(ref _wrongKeyQueue); }
                await Fail(context, 403, "invalid_setup_key", "This setup link is not valid for this server. Ask for a new one.");
                return;
            }

            var code = EnsureSetupCode();
            if (code == null)
            {
                // Setup finished between the gate and here.
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
            }
            _log.LogWarning("Ark IdP setup link opened from {Remote}: the setup code was handed out.",
                context.Connection.RemoteIpAddress?.ToString());
            await context.Response.WriteAsJsonAsync(new { code }, Json);
        }

        /// <summary>
        /// The code, created once and kept beside the settings so a restart does not change it. When
        /// it cannot be stored, the log still has it for this process. With an access key it is the
        /// key's code instead (<see cref="CodeFromAccessKey"/>), and the file is kept in step with it.
        /// Null once setup is over.
        /// </summary>
        string? EnsureSetupCode()
        {
            lock (CodeLock)
            {
                if (_setupCode != null) return _setupCode;
                // Forgotten, because setup is over: a call still under way must not bring one back.
                if (ArkIdpSettings.IsConfigured(_config)) return null;
                var file = Path.Combine(ArkIdpSettings.DataDirectory(_config, _env), ArkIdpSettings.TokenFileName);
                if (ReadAccessKey().Key is { } accessKey)
                {
                    var derived = CodeFromAccessKey(accessKey);
                    try
                    {
                        if (!File.Exists(file) || File.ReadAllText(file).Trim() != derived)
                            ArkIdpSettings.WritePrivateFile(file, Encoding.UTF8.GetBytes(derived + "\n"));
                    }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                    return _setupCode = derived;
                }
                try
                {
                    if (File.Exists(file))
                    {
                        var stored = File.ReadAllText(file).Trim();
                        if (stored.Length >= 12) return _setupCode = stored;
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }

                // 12 characters from an unambiguous alphabet, grouped for reading off a log.
                const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
                var chars = new char[12];
                for (var i = 0; i < chars.Length; i++) chars[i] = alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
                var code = $"{new string(chars, 0, 4)}-{new string(chars, 4, 4)}-{new string(chars, 8, 4)}";
                try { ArkIdpSettings.WritePrivateFile(file, Encoding.UTF8.GetBytes(code + "\n")); }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
                return _setupCode = code;
            }
        }

        void ForgetSetupCode()
        {
            lock (CodeLock)
            {
                _setupCode = null;
                try { File.Delete(Path.Combine(ArkIdpSettings.DataDirectory(_config, _env), ArkIdpSettings.TokenFileName)); }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }

        /// <summary>
        /// Whether anybody is spared the code at all. Only in Development, which is what
        /// <c>dotnet run</c> is and what a deployed server is not: there, a loopback address says
        /// nothing about who is asking. nginx's plain <c>proxy_pass</c> adds no forwarding header and
        /// sends its own upstream name, <c>127.0.0.1:5000</c>, as the Host, so every visitor on the
        /// internet looked like somebody at this machine; and a TCP tunnel lets them choose the Host.
        /// </summary>
        bool LocalExempt => _env.IsDevelopment() && !_config.GetValue("ark_oauth_server:Setup:RequireToken", false);

        /// <summary>
        /// What a proxy, or the forwarded-headers middleware behind one, leaves on a request. The
        /// X-Original ones are the trace of a header that middleware has already used up: without
        /// them, a caller that itself sent <c>X-Forwarded-For: 127.0.0.1</c> arrived as loopback.
        /// </summary>
        static readonly string[] Relayed =
        {
            "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded", "X-Real-IP",
            "X-Original-For", "X-Original-Host", "X-Original-Proto"
        };

        /// <summary>
        /// A developer on this machine: in Development, on loopback, and not relayed by a proxy that
        /// is itself on loopback.
        /// </summary>
        bool IsLocal(HttpContext context)
        {
            if (!LocalExempt) return false;
            var remote = context.Connection.RemoteIpAddress;
            if (remote == null || !IPAddress.IsLoopback(remote)) return false;
            if (Relayed.Any(context.Request.Headers.ContainsKey)) return false;
            // ...and addressed to this machine by a loopback name, which a DNS-rebinding page in the
            // developer's own browser is not: it reaches an unconfigured `dotnet run` under its own.
            var host = context.Request.Host.Host.Trim('[', ']');
            return string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
                   || (IPAddress.TryParse(host, out var named) && IPAddress.IsLoopback(named));
        }

        bool CodeAccepted(HttpContext context, string? code = null)
        {
            if (IsLocal(context)) return true;
            var expected = EnsureSetupCode();
            code ??= context.Request.Headers[TokenHeader].ToString();
            var given = (code ?? "").Trim().ToUpperInvariant();
            return expected != null && given.Length > 0 && Protocol.ArkCrypto.FixedTimeEquals(given, expected);
        }

        // ---------------------------------------------------------------- setup over MCP

        Mcp.Tools.SetupTools? _mcpTools;
        // One per process: it holds what the draft file must not.
        Mcp.Tools.SetupTools McpTools => LazyInitializer.EnsureInitialized(ref _mcpTools,
            () => new Mcp.Tools.SetupTools(this, new Mcp.ArkSetupDraft(DataDirectory)))!;

        async Task ServeMcpAsync(HttpContext context, string rest)
        {
            var config = Protocol.ArkConfigSnapshot.Server(_config) ?? new ArkAuthServerConfig();
            var root = Protocol.ArkOidcEndpoints.For(context.Request, config, "setup").BaseUrl;
            var endpoint = new Mcp.ArkMcpEndpoint
            {
                Level = Mcp.ArkMcpLevel.Host, Setup = true, Config = config, Root = root, Resource = Mcp.ArkMcpResources.Host(root)
            };

            if (HttpMethods.IsGet(context.Request.Method) && rest is "/server-card" or "/config")
            {
                context.Response.ContentType = "application/json; charset=utf-8";
                // Not cached: it changes the moment setup finishes.
                context.Response.Headers.CacheControl = "no-store";
                context.Response.Headers.XContentTypeOptions = "nosniff";
                var document = rest == "/config" ? Mcp.ArkMcpDocuments.Config(endpoint) : Mcp.ArkMcpDocuments.Card(endpoint, PackageVersion);
                await context.Response.WriteAsync(document.ToJsonString(Mcp.ArkMcpJson.Indented));
                return;
            }
            if (rest is not ("" or "/"))
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
            }
            if (!HttpMethods.IsPost(context.Request.Method))
            {
                context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                context.Response.Headers.Allow = "POST";
                return;
            }

            await Mcp.ArkMcpServer.HandleAsync(context, new Mcp.ArkMcpServer.Binding
            {
                Endpoint = endpoint,
                Authenticate = () => Task.FromResult(SetupCaller(context)),
                Tools = McpTools.All,
                Instructions = Mcp.Tools.SetupTools.Instructions,
                OnCalled = Mcp.ArkMcpAudit.Called
            });
        }

        /// <summary>
        /// The caller of the setup tools: whoever presents the setup code, as the bearer token.
        /// Always, in Development too — the exemption there is for a developer at a browser, and
        /// what reaches this endpoint is a program.
        /// </summary>
        Mcp.ArkMcpCaller SetupCaller(HttpContext context)
        {
            var header = context.Request.Headers.Authorization.ToString();
            var given = header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? header["Bearer ".Length..].Trim().ToUpperInvariant() : "";
            var expected = EnsureSetupCode();
            if (given.Length == 0)
                throw Mcp.ArkMcpAuthException.Missing("this server is not set up yet. Present the setup code from its start-up log as the bearer token.");
            if (expected == null || !Protocol.ArkCrypto.FixedTimeEquals(given, expected))
                throw Mcp.ArkMcpAuthException.Invalid("that is not the setup code in the server's log.");
            return new Mcp.ArkMcpCaller { Kind = "setup", Credential = "setup_code", Subject = "setup", CanRead = true, CanManage = true, FullScope = true };
        }

        // ---------------------------------------------------------------- routing

        async Task HandleSetupAsync(HttpContext context, string rest)
        {
            var method = context.Request.Method;
            var basePath = $"{context.Request.PathBase}{SetupPath}";

            if (HttpMethods.IsGet(method) && (rest == "" || rest == "/"))
            {
                await ServePageAsync(context, basePath);
                return;
            }
            if (HttpMethods.IsGet(method) && rest.StartsWith("/assets/", StringComparison.Ordinal))
            {
                await ServeAssetAsync(context, rest["/assets/".Length..]);
                return;
            }
            if (!rest.StartsWith("/api/", StringComparison.Ordinal))
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
            }

            context.Response.Headers.CacheControl = "no-store";
            var action = rest["/api/".Length..];

            if (HttpMethods.IsGet(method) && action == "state")
            {
                await context.Response.WriteAsJsonAsync(State(context), Json);
                return;
            }
            if (!HttpMethods.IsPost(method))
            {
                context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                return;
            }
            if (context.Request.Headers[CsrfHeader] != "1" ||
                !(context.Request.ContentType ?? "").StartsWith("application/json", StringComparison.OrdinalIgnoreCase))
            {
                await Fail(context, 400, "bad_request", $"Setup calls are JSON POSTs carrying {CsrfHeader}: 1.");
                return;
            }

            // The setup link: the access key in, the setup code out. Before the gate, like the next one.
            if (action == "code")
            {
                await RevealCodeAsync(context);
                return;
            }
            if (action == "verify-code")
            {
                var body = await Read<CodeRequest>(context);
                if (CodeAccepted(context, body?.Code)) await context.Response.WriteAsJsonAsync(new { ok = true }, Json);
                else await Fail(context, 403, "invalid_setup_code", "That setup code is not the one in the server log.");
                return;
            }
            if (!CodeAccepted(context))
            {
                await Fail(context, 403, "setup_code_required", "Enter the setup code from the server log.");
                return;
            }

            try
            {
                switch (action)
                {
                    case "keys/generate":
                        await context.Response.WriteAsJsonAsync(GenerateKeys(await Read<KeyRequest>(context)), Json);
                        return;
                    case "keys/import":
                        await context.Response.WriteAsJsonAsync(ImportKeys(await Read<KeyRequest>(context)), Json);
                        return;
                    case "database/test":
                        await context.Response.WriteAsJsonAsync(await TestDatabaseAsync(await Read<DatabaseSection>(context)), Json);
                        return;
                    case "email/test":
                        await context.Response.WriteAsJsonAsync(await TestEmailAsync(await Read<EmailTestRequest>(context)), Json);
                        return;
                    case "watch/test":
                        await context.Response.WriteAsJsonAsync(await TestWatchAsync(await Read<WatchSection>(context)), Json);
                        return;
                    case "complete":
                        await CompleteAsync(context, await Read<SetupRequest>(context));
                        return;
                    default:
                        context.Response.StatusCode = StatusCodes.Status404NotFound;
                        return;
                }
            }
            catch (SetupException ex)
            {
                await Fail(context, 400, ex.Code, ex.Message, ex.Field);
            }
            catch (JsonException ex)
            {
                await Fail(context, 400, "bad_request", $"The request could not be read: {ex.Message}");
            }
        }

        static async Task<T?> Read<T>(HttpContext context) where T : class =>
            await JsonSerializer.DeserializeAsync<T>(context.Request.Body, Json);

        static async Task Fail(HttpContext context, int status, string code, string msg, string? field = null)
        {
            context.Response.StatusCode = status;
            await context.Response.WriteAsJsonAsync(new { error = code, msg, field }, Json);
        }

        // ---------------------------------------------------------------- page and assets

        static readonly Dictionary<string, (string Resource, string ContentType)> Assets = new(StringComparer.Ordinal)
        {
            ["wizard.css"] = ("Ark.oAuth.Oidc.wwwroot.setup.wizard.css", "text/css; charset=utf-8"),
            ["wizard.js"] = ("Ark.oAuth.Oidc.wwwroot.setup.wizard.js", "text/javascript; charset=utf-8"),
            // The same appearance files the sign-in pages and console load from /ark-admin/asset —
            // served here as well because, until install, every browser request is the wizard's.
            ["ark-theme.css"] = ("Ark.oAuth.Oidc.wwwroot.css.ark-theme.css", "text/css; charset=utf-8"),
            ["ark-theme.js"] = ("Ark.oAuth.Oidc.wwwroot.js.ark-theme.js", "text/javascript; charset=utf-8"),
            ["ark-shield.png"] = ("Ark.oAuth.Oidc.wwwroot.img.ark-shield-64.png", "image/png")
        };

        static async Task ServePageAsync(HttpContext context, string basePath)
        {
            var html = ReadResource("Ark.oAuth.Oidc.wwwroot.setup.wizard.html")
                .Replace("{{BASE}}", WebUtility.HtmlEncode(basePath))
                .Replace("{{VERSION}}", WebUtility.HtmlEncode(PackageVersion));
            var headers = context.Response.Headers;
            headers.ContentType = "text/html; charset=utf-8";
            headers.CacheControl = "no-store";
            headers.XContentTypeOptions = "nosniff";
            headers["Referrer-Policy"] = "no-referrer";
            // Same-origin everything. Logos are previewed as data: URIs before they are uploaded.
            headers.ContentSecurityPolicy =
                "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; " +
                "connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";
            await context.Response.WriteAsync(html);
        }

        static async Task ServeAssetAsync(HttpContext context, string file)
        {
            if (!Assets.TryGetValue(file, out var asset))
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
            }
            using var stream = typeof(ArkSetupMiddleware).Assembly.GetManifestResourceStream(asset.Resource);
            if (stream == null)
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
            }
            context.Response.ContentType = asset.ContentType;
            context.Response.Headers.XContentTypeOptions = "nosniff";
            context.Response.Headers.CacheControl = "no-cache";
            await stream.CopyToAsync(context.Response.Body);
        }

        static string ReadResource(string name)
        {
            using var stream = typeof(ArkSetupMiddleware).Assembly.GetManifestResourceStream(name)
                ?? throw new InvalidOperationException($"embedded resource '{name}' is missing from the package");
            using var reader = new StreamReader(stream);
            return reader.ReadToEnd();
        }

        static readonly Regex BrandingFile = new("^[a-z0-9-]+\\.(png|jpg|gif|webp|svg|ico)$", RegexOptions.CultureInvariant);

        static readonly Dictionary<string, string> ImageTypes = new(StringComparer.OrdinalIgnoreCase)
        {
            ["png"] = "image/png", ["jpg"] = "image/jpeg", ["gif"] = "image/gif",
            ["webp"] = "image/webp", ["svg"] = "image/svg+xml", ["ico"] = "image/x-icon"
        };

        async Task ServeBrandingAsync(HttpContext context, string asset)
        {
            var name = asset.TrimStart('/');
            var file = Path.Combine(ArkIdpSettings.DataDirectory(_config, _env), ArkIdpSettings.BrandingFolder, name);
            if (!HttpMethods.IsGet(context.Request.Method) && !HttpMethods.IsHead(context.Request.Method) ||
                !BrandingFile.IsMatch(name) || !File.Exists(file))
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
            }
            var headers = context.Response.Headers;
            headers.ContentType = ImageTypes[Path.GetExtension(name).TrimStart('.')];
            headers.XContentTypeOptions = "nosniff";
            // An SVG opened on its own is a document on this origin. This makes it an inert one.
            headers.ContentSecurityPolicy = "default-src 'none'; style-src 'unsafe-inline'; sandbox";
            headers.CacheControl = "public, max-age=86400";
            await context.Response.SendFileAsync(file);
        }

        static readonly string PackageVersion = ReadPackageVersion();

        static string ReadPackageVersion()
        {
            var assembly = typeof(ArkSetupMiddleware).Assembly;
            var v = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                    ?? assembly.GetName().Version?.ToString() ?? "";
            var plus = v.IndexOf('+');
            return plus < 0 ? v : v[..plus];
        }

        // ---------------------------------------------------------------- state

        object State(HttpContext context)
        {
            // Paths and environment are nobody's business until the code is in.
            // Whether a setup link can work here, so the page can say so to someone who has none.
            var setupLink = ReadAccessKey().Key != null;
            if (!CodeAccepted(context))
                return new { configured = false, code_required = true, setup_link = setupLink, version = PackageVersion };

            var request = context.Request;
            var dataDir = ArkIdpSettings.DataDirectory(_config, _env);
            var pathBase = request.PathBase.HasValue ? request.PathBase.Value!.TrimEnd('/') : "";

            return new
            {
                configured = false,
                code_required = !IsLocal(context),
                setup_link = setupLink,
                version = PackageVersion,
                environment = _env.EnvironmentName,
                data_directory = dataDir,
                data_directory_writable = Writable(dataDir),
                settings_file = Path.Combine(dataDir, ArkIdpSettings.SettingsFileName),
                can_apply = _config is IConfigurationBuilder,
                console_sign_in = context.RequestServices.GetService<ArkIdpConsoleMarker>() != null,
                // An agent can do this instead, and may have started: see ServeMcpAsync.
                mcp_url = McpEnabled ? $"{request.Scheme}://{request.Host}{pathBase}{Mcp.ArkMcpResources.HostPath}" : null,
                mcp_draft_at = McpEnabled ? McpTools.DraftUpdatedAt : null,
                // The agent in this server that does it by conversation, and where that stands.
                agent = Agent(context, pathBase),
                defaults = new
                {
                    base_url = $"{request.Scheme}://{request.Host}{pathBase}",
                    tenant_id = "ark_idp",
                    provider = "sqlite",
                    sqlite_file = DefaultSqliteFile(dataDir),
                    https = request.IsHttps
                }
            };
        }

        /// <summary>
        /// The onboarding agent's view, for the wizard's first page to link to: where it is, and what
        /// it is waiting for a person to do. Null when there is none (switched off, or MCP is).
        /// </summary>
        static object? Agent(HttpContext context, string pathBase)
        {
            if (context.RequestServices.GetService<Ark.Agents.TenantOnboarding.Hosting.AgentStatusReader>()?.Read() is not { } s) return null;
            return new
            {
                name = s.Name, url = pathBase + s.Path, phase = s.Phase, why = s.Why, started = s.Started,
                essentials_done = s.EssentialsDone, essentials_total = s.EssentialsTotal, ready_for_review = s.ReadyForReview,
                waiting_for_lead = s.WaitingForLead, waiting_for_colleagues = s.WaitingForColleagues, last_message_at = s.LastMessageAt
            };
        }

        /// <summary>
        /// The database beside the settings, so one directory — one volume, in a container — is
        /// the whole server. Relative to the working directory, which is how SQLite will read it,
        /// when that is where it is; absolute otherwise.
        /// </summary>
        internal static string DefaultSqliteFile(string dataDir)
        {
            var file = Path.Combine(dataDir, "ark_idp.db");
            var relative = Path.GetRelativePath(Directory.GetCurrentDirectory(), file);
            return relative.StartsWith("..", StringComparison.Ordinal) || Path.IsPathRooted(relative)
                ? file
                : relative.Replace('\\', '/');
        }

        internal static bool Writable(string directory)
        {
            try
            {
                ArkIdpSettings.CreatePrivateDirectory(directory);
                var probe = Path.Combine(directory, $".write-test-{Guid.NewGuid():N}");
                File.WriteAllText(probe, "");
                File.Delete(probe);
                return true;
            }
            catch (Exception) { return false; }
        }

        // ---------------------------------------------------------------- keys

        internal static object GenerateKeys(KeyRequest? req)
        {
            var size = req?.KeySize ?? 2048;
            if (size is not (2048 or 3072 or 4096))
                throw new SetupException("invalid_key_size", "Key size must be 2048, 3072 or 4096 bits.", "key_size");
            var (pub, priv) = Protocol.ArkCrypto.GenerateRsaKeyPair(size);
            return DescribeKey(pub, priv, size);
        }

        static object ImportKeys(KeyRequest? req)
        {
            var (pub, priv, size) = ParsePrivateKey(req?.PrivateKey);
            return DescribeKey(pub, priv, size);
        }

        /// <summary>
        /// Any RSA private key a person is likely to paste — PKCS#8 or PKCS#1 PEM, or the bare
        /// base64 PKCS#8 this server stores — normalised to the stored shape.
        /// </summary>
        internal static (string publicKey, string privateKey, int size) ParsePrivateKey(string? input)
        {
            var text = (input ?? "").Trim();
            if (text.Length == 0) throw new SetupException("key_required", "Generate a signing key, or paste an existing RSA private key.", "private_key");
            using var rsa = RSA.Create();
            try
            {
                if (text.Contains("-----BEGIN", StringComparison.Ordinal)) rsa.ImportFromPem(text);
                else rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(text), out _);
            }
            catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException)
            {
                throw new SetupException("invalid_key",
                    "That is not an RSA private key this server can read. Paste a PEM block (BEGIN PRIVATE KEY or BEGIN RSA PRIVATE KEY) without a passphrase.",
                    "private_key");
            }
            if (rsa.KeySize < 2048)
                throw new SetupException("weak_key", $"The key is {rsa.KeySize} bits; signing keys must be at least 2048.", "private_key");
            return (Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo()), Convert.ToBase64String(rsa.ExportPkcs8PrivateKey()), rsa.KeySize);
        }

        static object DescribeKey(string pub, string priv, int size) => new
        {
            kid = Protocol.ArkCrypto.ComputeKid(pub),
            key_size = size,
            algorithm = "RS256",
            public_key = pub,
            private_key = priv,
            public_pem = Pem("PUBLIC KEY", pub),
            private_pem = Pem("PRIVATE KEY", priv)
        };

        static string Pem(string label, string base64)
        {
            var sb = new StringBuilder().Append("-----BEGIN ").Append(label).Append("-----\n");
            for (var i = 0; i < base64.Length; i += 64) sb.Append(base64, i, Math.Min(64, base64.Length - i)).Append('\n');
            return sb.Append("-----END ").Append(label).Append("-----\n").ToString();
        }

        // ---------------------------------------------------------------- database

        internal async Task<object> TestDatabaseAsync(DatabaseSection? db)
        {
            var (provider, connection) = NormalizeDatabase(db);
            try
            {
                return await Task.Run(() => ProbeDatabase(provider, connection)).WaitAsync(TimeSpan.FromSeconds(20));
            }
            catch (TimeoutException)
            {
                return new { ok = false, msg = "No answer from the database server within 20 seconds. Check the host, port and any firewall between this server and it." };
            }
        }

        object ProbeDatabase(string provider, string connection)
        {
            if (provider == "sqlite")
            {
                var file = SqliteFile(connection);
                if (file != null && !File.Exists(file))
                {
                    var dir = Path.GetDirectoryName(file)!;
                    return Writable(dir)
                        ? new { ok = true, exists = false, msg = $"A new database will be created at {file}.", tenants = Array.Empty<string>() }
                        : new { ok = false, exists = false, msg = $"This server cannot write to {dir}, so the database file cannot be created there.", tenants = Array.Empty<string>() };
                }
            }

            try
            {
                using var ctx = new ArkDataContext(Options(provider, connection), _config);
                var creator = ctx.GetService<IRelationalDatabaseCreator>();
                if (!creator.Exists())
                    return new
                    {
                        ok = true, exists = false, tenants = Array.Empty<string>(),
                        msg = "Connected to the server. The database does not exist yet and will be created — this account needs permission to create databases, or create it beforehand."
                    };
                if (!creator.HasTables())
                    return new { ok = true, exists = true, tenants = Array.Empty<string>(), msg = "Connected. The database is empty; the tables will be created." };

                List<string> tenants;
                try { tenants = ctx.tenants.Select(t => t.tenant_id).ToList(); }
                catch (Exception)
                {
                    return new { ok = false, exists = true, tenants = Array.Empty<string>(), msg = "Connected, but the database already has tables that are not this server's. Use an empty database." };
                }
                return tenants.Count == 0
                    ? new { ok = true, exists = true, tenants = tenants.ToArray(), msg = "Connected. The tables exist and hold no tenant yet; this setup will seed them." }
                    : new
                    {
                        ok = true, exists = true, tenants = tenants.ToArray(),
                        msg = $"Connected to an existing Ark database with tenant(s): {string.Join(", ", tenants)}. Setup will attach to it: the tenant id must be one of these, and no administrator, key or client is created."
                    };
            }
            catch (Exception ex)
            {
                return new { ok = false, exists = false, tenants = Array.Empty<string>(), msg = Innermost(ex) };
            }
        }

        static DbContextOptions<ArkDataContext> Options(string provider, string connection)
        {
            var builder = new DbContextOptionsBuilder<ArkDataContext>();
            switch (provider)
            {
                case "mysql": builder.UseMySQL(connection); break;
                case "postgres": builder.UseNpgsql(connection); break;
                default: builder.UseSqlite(connection); break;
            }
            return builder.Options;
        }

        internal static (string provider, string connection) NormalizeDatabase(DatabaseSection? db)
        {
            var provider = (db?.Provider ?? "sqlite").Trim().ToLowerInvariant();
            if (provider is not ("sqlite" or "mysql" or "postgres"))
                throw new SetupException("invalid_provider", "Provider must be sqlite, mysql or postgres.", "provider");
            var connection = (db?.ConnectionString ?? "").Trim();
            if (connection.Length == 0)
                throw new SetupException("connection_required", "Enter the database connection.", "connection_string");
            return (provider, provider switch
            {
                "mysql" => WithoutLocalFiles(connection),
                "postgres" => WithoutPassfile(connection),
                _ => connection
            });
        }

        /// <summary>
        /// A MySQL connection on which the server cannot ask this machine for its files. With
        /// <c>AllowLoadLocalInfile</c> on, whatever answers at the other end names a path and the client
        /// sends what is in it, so testing a connection was a way to read any file the server's account
        /// can. Rebuilt by the driver's own builder, which knows every spelling of an option; what comes
        /// out is what is tested and what is saved. Files named for TLS (SslCa and its kin) stay: they
        /// are read to verify the server and to prove this client, and their content is not sent.
        /// </summary>
        static string WithoutLocalFiles(string connection)
        {
            global::MySql.Data.MySqlClient.MySqlConnectionStringBuilder builder;
            try { builder = new(connection); }
            catch (Exception ex) when (ex is ArgumentException or FormatException or KeyNotFoundException or InvalidOperationException)
            {
                // Not the driver's message: for a password with an unquoted ';' it quotes part of it.
                throw new SetupException("invalid_connection",
                    "That is not a MySQL connection string this server can read: an option or a value it does not know, or a value with ';' or '=' in it that is not quoted.", "connection_string");
            }
            if (!string.IsNullOrWhiteSpace(builder.OciConfigFile))
                throw new SetupException("option_not_allowed", "The connection may not name an OCI configuration file. Sign in with a username and password.", "connection_string");
            builder.AllowLoadLocalInfile = false;
            builder.AllowLoadLocalInfileInPath = "";
            return builder.ConnectionString;
        }

        /// <summary>A PostgreSQL connection that does not take its password from a file of the caller's choosing.</summary>
        static string WithoutPassfile(string connection)
        {
            Npgsql.NpgsqlConnectionStringBuilder builder;
            try { builder = new(connection); }
            catch (Exception ex) when (ex is ArgumentException or FormatException or KeyNotFoundException or InvalidOperationException)
            {
                throw new SetupException("invalid_connection",
                    "That is not a PostgreSQL connection string this server can read: an option or a value it does not know, or a value with ';' or '=' in it that is not quoted.", "connection_string");
            }
            if (!string.IsNullOrWhiteSpace(builder.Passfile))
                throw new SetupException("option_not_allowed", "The connection may not name a password file. Give the password itself.", "connection_string");
            return connection;
        }

        /// <summary>The file a SQLite connection string names, resolved the way SQLite will.</summary>
        internal static string? SqliteFile(string connection)
        {
            var source = connection
                .Split(';', StringSplitOptions.RemoveEmptyEntries)
                .Select(part => part.Split('=', 2))
                .Where(part => part.Length == 2 && part[0].Trim().Replace(" ", "")
                    .Equals("DataSource", StringComparison.OrdinalIgnoreCase))
                .Select(part => part[1].Trim())
                .FirstOrDefault();
            if (string.IsNullOrWhiteSpace(source) || source == ":memory:") return null;
            return Path.GetFullPath(source);
        }

        internal static string Innermost(Exception ex)
        {
            while (ex.InnerException != null && ex is not ApplicationException) ex = ex.InnerException;
            return ex.Message;
        }

        // ---------------------------------------------------------------- email

        internal static async Task<object> TestEmailAsync(EmailTestRequest? req)
        {
            var email = req?.Email ?? new EmailSection();
            var to = (req?.To ?? "").Trim();
            if (!ark.net.util.EmailUtil.IsValidFormat(to))
                throw new SetupException("invalid_email", "Enter the address to send the test message to.", "test_to");
            ValidateEmail(email);
            try
            {
                await Task.Run(() =>
                {
                    var util = new ark.net.util.EmailUtil(email.Username ?? email.From, email.Password ?? "", email.From, email.Display ?? "",
                        email.Subject ?? "", email.Smtp, email.Port ?? 587);
                    util.SendEmail(new[] { to }, Array.Empty<string>(), Array.Empty<string>(),
                        "<p>This is a test message from the Ark IdP setup wizard. Outgoing email works.</p>",
                        "Setup test", email.Display ?? "");
                }).WaitAsync(TimeSpan.FromSeconds(30));
                return new { ok = true, msg = $"Sent. Check the inbox of {to}." };
            }
            catch (TimeoutException)
            {
                return new { ok = false, msg = "The mail server did not answer within 30 seconds." };
            }
            catch (Exception ex)
            {
                return new { ok = false, msg = Innermost(ex) };
            }
        }

        internal static void ValidateEmail(EmailSection email)
        {
            if (string.IsNullOrWhiteSpace(email.Smtp))
                throw new SetupException("smtp_required", "Enter the SMTP server.", "smtp");
            if (email.Port is null or < 1 or > 65535)
                throw new SetupException("invalid_port", "Enter the SMTP port (usually 587, 465 or 25).", "port");
            if (!ark.net.util.EmailUtil.IsValidFormat(email.From ?? ""))
                throw new SetupException("invalid_from", "Enter the address messages are sent from.", "from");
        }

        // ---------------------------------------------------------------- audit trail (ARK-RAPID Watch)

        internal sealed record WatchPlan(string Endpoint, string ApiKey, string Application, string Environment);

        /// <summary>What a test of the audit trail found. Serialized as <c>{ ok, msg }</c>.</summary>
        internal sealed record WatchTestResult(bool ok, string msg);

        /// <summary>
        /// The audit trail's settings, checked, or null when it is not wanted. The step is
        /// optional: switched off, nothing about it is validated or written.
        /// </summary>
        internal WatchPlan? NormalizeWatch(WatchSection? watch) => NormalizeWatch(watch, _env.EnvironmentName);

        /// <summary>
        /// The same check, for whoever has no wizard to hand: the admin console's Audit trail page
        /// uses it, so a destination is held to one rule wherever it is entered.
        /// </summary>
        internal static WatchPlan? NormalizeWatch(WatchSection? watch, string defaultEnvironment)
        {
            if (watch?.Enabled != true) return null;

            var endpoint = (watch.Endpoint ?? "").Trim();
            if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https") ||
                !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
                throw new SetupException("invalid_watch_endpoint",
                    "Audit server address: the absolute http(s) address of the ARK-RAPID Watch node, e.g. https://audit.example.com.", "watch_endpoint");
            if (!endpoint.EndsWith('/')) endpoint += "/";

            var key = (watch.ApiKey ?? "").Trim();
            if (key.Length == 0)
                throw new SetupException("watch_key_required", "Enter the node's API key for this server.", "watch_api_key");
            // A public key is for browsers: bound to origins, rate limited, and its events are
            // stored as client-asserted. An identity provider's trail must not be that.
            if (key.StartsWith("arkw_pk_", StringComparison.OrdinalIgnoreCase))
                throw new SetupException("watch_public_key",
                    "That is a public key (arkw_pk_…), which is for browsers. Use a secret key (arkw_sk_…).", "watch_api_key");
            if (key.Any(char.IsWhiteSpace) || key.Any(char.IsControl))
                throw new SetupException("invalid_watch_key", "The API key contains a space or a line break. Paste the key alone.", "watch_api_key");

            var application = (watch.Application ?? "").Trim();
            if (application.Length == 0) application = ArkWatchConfig.DefaultApplication;
            if (application.Length > 100 || application.Any(char.IsControl))
                throw new SetupException("invalid_watch_application", "Application name: up to 100 characters.", "watch_application");

            var environment = (watch.Environment ?? "").Trim();
            if (environment.Length == 0) environment = defaultEnvironment;
            if (environment.Length > 60 || environment.Any(char.IsControl))
                throw new SetupException("invalid_watch_environment", "Environment: up to 60 characters.", "watch_environment");

            return new WatchPlan(endpoint, key, application, environment);
        }

        /// <summary>
        /// Proves the audit trail end to end before it is saved: that the address is a node, that
        /// the key is one of its keys, and that the node accepts an event from this application.
        ///
        /// Two steps, because they fail for different reasons. <c>GET /api/whoami</c> answers at
        /// once and says which is wrong — the address or the key. Then one real event goes through
        /// the same client the server will use, since a key can be valid and still be bound to
        /// another application, which only ingestion shows.
        /// </summary>
        internal async Task<object> TestWatchAsync(WatchSection? watch)
        {
            if (watch != null) watch.Enabled = true;
            var plan = NormalizeWatch(watch) ?? throw new SetupException("bad_request", "Nothing to test.");
            return await TestWatchAsync(plan, "setup");
        }

        /// <summary>
        /// The test itself, for a destination already checked by <see cref="NormalizeWatch(WatchSection?, string)"/>.
        /// <paramref name="from"/> is <c>setup</c> or <c>console</c>: it names, on the test event,
        /// which screen sent it.
        /// </summary>
        internal static async Task<WatchTestResult> TestWatchAsync(WatchPlan plan, string from)
        {
            var node = new Uri(plan.Endpoint).GetLeftPart(UriPartial.Path);
            var screen = from == "console" ? "admin console" : "setup wizard";

            string name;
            try
            {
                using var handler = new HttpClientHandler { AllowAutoRedirect = false };
                using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
                using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(new Uri(plan.Endpoint), "api/whoami"));
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", plan.ApiKey);
                request.Headers.Accept.ParseAdd("application/json");
                using var response = await http.SendAsync(request);
                var status = (int)response.StatusCode;
                if (status is 401 or 403)
                    return new WatchTestResult(false, $"The node at {node} refused the key ({status}). Check that it is a secret key of this node and has not been revoked.");
                if (status == 503)
                    return new WatchTestResult(false, $"The node at {node} answered 503: it has not finished its own setup, or its storage is unavailable.");
                if (!response.IsSuccessStatusCode)
                    return new WatchTestResult(false, $"{node} answered {status} to /api/whoami, so it does not look like an ARK-RAPID Watch node. Check the address.");

                var body = await response.Content.ReadAsStringAsync();
                try
                {
                    using var doc = JsonDocument.Parse(body);
                    name = doc.RootElement.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String ? n.GetString() ?? "" : "";
                    if (!doc.RootElement.TryGetProperty("id", out _))
                        return new WatchTestResult(false, $"{node} answered, but not as an ARK-RAPID Watch node does. Check the address.");
                }
                catch (JsonException)
                {
                    return new WatchTestResult(false, $"{node} answered, but not as an ARK-RAPID Watch node does. Check the address.");
                }
            }
            catch (TaskCanceledException)
            {
                return new WatchTestResult(false, $"No answer from {node} within 10 seconds. Check the address and any firewall between this server and it.");
            }
            catch (HttpRequestException ex)
            {
                return new WatchTestResult(false, $"{node} could not be reached: {Innermost(ex)}");
            }

            // The key is good. Now one event, through the client itself and with no spool, so
            // "delivered" can only mean the node took it.
            try
            {
                await using var client = new Ark.Watch.Client.ArkWatchClient(new Ark.Watch.Client.ArkWatchClientOptions
                {
                    Endpoint = new Uri(plan.Endpoint),
                    ApiKey = plan.ApiKey,
                    Application = plan.Application,
                    AppVersion = PackageVersion,
                    Environment = plan.Environment,
                    DefaultDomain = ArkWatchDomains.System,
                    DefaultSystem = "ark-idp"
                });
                var entry = new Ark.Watch.Client.AuditEntry
                {
                    Level = Ark.Watch.Core.AuditLevel.Info,
                    Outcome = Ark.Watch.Core.Outcome.Success,
                    Action = "audit_trail.test",
                    Domain = ArkWatchDomains.System,
                    System = from == "console" ? "console" : "setup",
                    Message = $"Test event from the Ark IdP {screen}: this server can write to the audit trail."
                };
                client.Log(in entry);
                await client.FlushAsync(TimeSpan.FromSeconds(10));
                var stats = client.GetStats();
                var who = name.Length > 0 ? $" as “{name}”" : "";
                if (stats.Rejected > 0)
                    return new WatchTestResult(false, $"The key is valid{who}, but the node refused the test event. A key can be bound to one application: set the application name below to the one the key was created for.");
                if (stats.Sent + stats.Duplicates < 1)
                    return new WatchTestResult(false, $"The key is valid{who}, but the test event was not delivered to {node} (the node answered ingestion with an error, or is under backpressure). Try again in a moment.");
                return new WatchTestResult(true, $"Connected to {node}{who}. A test event was accepted for application “{plan.Application}”.");
            }
            catch (Exception ex)
            {
                return new WatchTestResult(false, $"The key is valid, but the test event could not be sent: {Innermost(ex)}");
            }
        }

        // ---------------------------------------------------------------- install

        static readonly Regex TenantId = new("^[A-Za-z0-9][A-Za-z0-9_-]{1,62}$", RegexOptions.CultureInvariant);
        static readonly Regex BasePathPattern = new("^[A-Za-z0-9_\\-/]*$", RegexOptions.CultureInvariant);
        static readonly Regex DataUri = new("^data:(image/(?:png|jpeg|gif|webp|svg\\+xml|x-icon|vnd\\.microsoft\\.icon));base64,([A-Za-z0-9+/=\\s]+)$",
            RegexOptions.CultureInvariant);

        async Task CompleteAsync(HttpContext context, SetupRequest? req)
        {
            var done = await InstallAsync(context, req, "wizard");
            var plan = done.Plan;
            await context.Response.WriteAsJsonAsync(new
            {
                ok = true,
                tenant_id = plan.TenantId,
                issuer = done.Endpoints.Issuer,
                discovery = done.Endpoints.Discovery,
                console = done.Console,
                admin_username = plan.AdminUsername,
                settings_file = done.SettingsFile,
                // where the server kept its copy of the download, or null: attached, turned off, or not writable
                keys_file = done.KeysFile,
                machine_client_id = ArkManagementAuth.MachineClientId(plan.TenantId),
                // an existing database is attached, not seeded, so nothing was set
                machine_client_secret = plan.ExistingTenant ? null : plan.MachineSecret,
                attached_existing = plan.ExistingTenant,
                // where the audit trail goes, never its key
                audit_trail = plan.Watch == null ? null : new Uri(plan.Watch.Endpoint).GetLeftPart(UriPartial.Path),
                audit_application = plan.Watch?.Application,
                // what an agent connects to from here on
                mcp_url = TenantMcpUrl(plan)
            }, Json);
        }

        /// <summary>The tenant's own MCP server, when this server offers one.</summary>
        string? TenantMcpUrl(Plan plan) =>
            _config.GetValue("ark_oauth_server:Mcp:Enabled", true) && _config.GetValue("ark_oauth_server:Mcp:TenantLevel", true)
                ? Mcp.ArkMcpResources.Tenant(plan.AppRoot, plan.TenantId) : null;

        /// <summary>What an install did, for whoever asked for it to report. <c>KeysFile</c> is null when none was written.</summary>
        internal sealed record Installed(
            Plan Plan, string SettingsFile, Protocol.ArkOidcEndpoints Endpoints, string Console, string? AdminPasswordLink,
            string? KeysFile);

        /// <summary>
        /// Checks everything, writes the settings, creates and seeds the database: the whole of
        /// what Install does, for the wizard and for an agent alike.
        /// </summary>
        /// <param name="context">The request that asked for it.</param>
        /// <param name="req">What was collected.</param>
        /// <param name="via"><c>wizard</c> or <c>mcp</c>, for the audit trail.</param>
        /// <param name="adminByLink">
        /// The administrator sets their own password, through a link returned once. The account
        /// starts on a random password nobody has seen, so an agent that ran setup never held it.
        /// </param>
        /// <param name="sources">Who supplied what, for the audit trail.</param>
        internal async Task<Installed> InstallAsync(HttpContext context, SetupRequest? req, string via,
            bool adminByLink = false, IReadOnlyDictionary<string, string>? sources = null)
        {
            if (req == null) throw new SetupException("bad_request", "Nothing to install.");
            if (_config is not IConfigurationRoot root || !ArkIdpSettings.Attach(_config, _env) && !TryCreateAndAttach())
                throw new SetupException("cannot_apply",
                    "This host's configuration cannot be extended at run time, so the settings cannot take effect. Use WebApplication.CreateBuilder.");

            await InstallLock.WaitAsync(context.RequestAborted);
            Interlocked.Increment(ref _installs); // from here until it is even again, nothing is let past: see Configured
            try
            {
                if (_wasConfigured || ArkIdpSettings.IsConfigured(_config))
                    throw new SetupException("already_configured", "This server has already been set up.");

                if (adminByLink && req.Admin != null) req.Admin.Password = Protocol.ArkCrypto.RandomToken(32);
                var plan = Validate(context, req);
                string? passwordLink = null;
                var settingsFile = ArkIdpSettings.SettingsFile(_config, _env);
                var dataDir = Path.GetDirectoryName(settingsFile)!;

                // Logos first: their URLs are part of the settings.
                var hostLogo = StoreLogo(dataDir, "host-logo", req.Branding?.HostLogo, plan.AppRoot, "host_logo");
                var appLogo = StoreLogo(dataDir, "app-logo", req.Branding?.AppLogo, plan.AppRoot, "app_logo");

                var settings = BuildSettings(context, req, plan, hostLogo, appLogo);
                try
                {
                    ArkIdpSettings.WritePrivateFile(settingsFile,
                        Encoding.UTF8.GetBytes(settings.ToJsonString(new JsonSerializerOptions { WriteIndented = true })));
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    throw new SetupException("cannot_write",
                        $"The settings could not be written to {settingsFile}: {ex.Message} Point ark_oauth_server:Setup:DataPath at a writable directory.");
                }

                if (plan.Provider == "sqlite" && SqliteFile(plan.Connection) is { } sqlite)
                    ArkIdpSettings.CreatePrivateDirectory(Path.GetDirectoryName(sqlite)!);

                // The file watcher would get there too, a moment later; this makes it now, and
                // fires the change tokens that rebuild the console's sign-in options.
                root.Reload();

                try
                {
                    if (plan.Provider == "sqlite") CreatePrivateSqlite(plan.Connection);
                    using var scope = context.RequestServices.GetRequiredService<IServiceScopeFactory>().CreateScope();
                    await ArkExtn.BootstrapDatabaseAsync(scope.ServiceProvider, context, new ArkSeedOverrides
                    {
                        AdminPassword = req.Admin?.Password,
                        SigningKey = plan.PublicKey == null ? null : (plan.PublicKey, plan.PrivateKey!),
                        MachineClientSecret = plan.MachineSecret,
                        TenantDisplay = req.Server?.TenantDisplay?.Trim(),
                        ConsoleLogo = appLogo
                    });
                    if (adminByLink && !plan.ExistingTenant)
                        passwordLink = await scope.ServiceProvider.GetRequiredService<DataAccess>()
                            .IssuePasswordLinkAsync(plan.AdminUsername, plan.TenantId);
                    ArkExtn.MarkDataInitialized();
                }
                catch (Exception ex)
                {
                    // Not set up after all: take the settings back so the wizard is still there
                    // to correct whatever this was, rather than a server half-configured.
                    try { File.Delete(settingsFile); } catch (IOException) { }
                    root.Reload();
                    _log.LogError(ex, "Ark IdP setup could not initialise the database");
                    throw new SetupException("database_failed", $"The database could not be set up: {Innermost(ex)}", "connection_string");
                }

                // Only now: a file written before the database took would describe a server that never was.
                var keysFile = SaveKeysFile(plan, dataDir);

                ForgetSetupCode();
                // It holds whatever an agent had collected, some of it secret, and is of no more use.
                // Closed as well as deleted: a setup call still under way would write it back.
                McpTools.Close();
                _log.LogInformation("Ark IdP setup complete: tenant {Tenant}, issuer {Issuer}, settings in {File}",
                    plan.TenantId, plan.Issuer, settingsFile);
                if (!string.IsNullOrWhiteSpace(_config[AccessKeySetting]))
                    _log.LogInformation("{Setting} is no longer used: setup is finished and the setup link no longer works. Remove it from the configuration.",
                        AccessKeySetting);

                // The first line of the audit trail, when there is one: who set this server up,
                // and from where. Whoever completes setup becomes its administrator.
                var record = new ArkWatchEvent
                {
                    Action = "idp.setup",
                    Domain = ArkWatchDomains.System,
                    System = "setup",
                    Level = Ark.Watch.Core.AuditLevel.Security,
                    Outcome = Ark.Watch.Core.Outcome.Success,
                    Tenant = plan.TenantId,
                    ParticipantId = plan.AdminUsername,
                    ParticipantType = Ark.Watch.Core.ParticipantTypes.User,
                    ResourceType = "tenant",
                    ResourceId = plan.TenantId,
                    Message = plan.ExistingTenant
                        ? $"identity provider attached to the existing database of tenant '{plan.TenantId}'"
                        : $"identity provider set up: tenant '{plan.TenantId}', issuer {plan.Issuer}"
                }.With("issuer", plan.Issuer).With("database_provider", plan.Provider)
                    .With("attached_existing", plan.ExistingTenant).With("local_request", IsLocal(context)).With("via", via);
                foreach (var (what, who) in sources ?? new Dictionary<string, string>()) record.With($"source_{what}", who);
                // In the server's own trail as well, which every server has: what an agent collected
                // is deleted now, and who supplied it must not go with it.
                try
                {
                    using var scope = context.RequestServices.GetRequiredService<IServiceScopeFactory>().CreateScope();
                    scope.ServiceProvider.GetRequiredService<DataAccess>().Record("idp_setup", plan.TenantId,
                        plan.ExistingTenant ? "identity provider attached to an existing database" : "identity provider set up",
                        $"via: {via}, issuer: {plan.Issuer}" + string.Concat((sources ?? new Dictionary<string, string>()).Select(s => $"\n{s.Key}: {s.Value}")),
                        plan.AdminUsername, ArkWatchAudit.Address(context), record);
                }
                catch (Exception ex)
                {
                    _log.LogWarning(ex, "Ark IdP setup is complete, but its line could not be written to the audit trail.");
                }

                return new Installed(plan, settingsFile, new Protocol.ArkOidcEndpoints(plan.AppRoot, plan.TenantId),
                    $"{context.Request.PathBase}/{plan.TenantId}/admin", passwordLink, keysFile);
            }
            finally
            {
                Interlocked.Increment(ref _installs);
                InstallLock.Release();
            }
        }

        /// <summary>
        /// Writes the keys file into the data directory: the document the wizard's <b>Download JSON</b>
        /// makes, in the same shape and under the same name, so that it outlives the browser tab, and
        /// an install by an agent (which is never handed the private key) leaves one as well.
        ///
        /// Owner-only and git-ignored like <c>settings.json</c>. One left by an earlier setup is kept,
        /// renamed, since the key in it may still be wanted. Null when there is nothing to hand over
        /// (an existing database was attached, so nothing was created), when <c>Setup:SaveKeysFile</c>
        /// is false, or when it could not be written: setup is complete by then and this is a copy,
        /// so none of these fails it.
        /// </summary>
        string? SaveKeysFile(Plan plan, string dataDir)
        {
            if (plan.ExistingTenant || plan.PublicKey == null || plan.PrivateKey == null) return null;
            if (!_config.GetValue("ark_oauth_server:Setup:SaveKeysFile", true)) return null;

            var file = Path.Combine(dataDir, ArkIdpSettings.KeysFileName(plan.TenantId));
            try
            {
                using var rsa = RSA.Create();
                rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(plan.PublicKey), out _);
                var keys = new JsonObject
                {
                    ["_about"] = "Written by the Ark IdP setup into its data directory: the same as the wizard's Download JSON. " +
                                 "The private key can sign tokens as this server and the machine secret administers it: keep this file " +
                                 "as safe as the database. A key rotated or a secret regenerated since setup is not reflected here.",
                    ["installed_at"] = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", System.Globalization.CultureInfo.InvariantCulture),
                    ["tenant_id"] = plan.TenantId,
                    ["issuer"] = plan.Issuer,
                    ["discovery"] = $"{plan.Issuer}/.well-known/openid-configuration",
                    ["mcp_server"] = TenantMcpUrl(plan),
                    ["admin_console"] = $"{plan.Issuer}/admin",
                    ["administrator"] = plan.AdminUsername,
                    ["signing_key"] = new JsonObject
                    {
                        // as seeded: setup always installs with the thumbprint kid
                        ["kid"] = Protocol.ArkCrypto.ComputeKid(plan.PublicKey),
                        ["algorithm"] = "RS256",
                        ["key_size"] = rsa.KeySize,
                        ["public_key_pem"] = Pem("PUBLIC KEY", plan.PublicKey),
                        ["private_key_pem"] = Pem("PRIVATE KEY", plan.PrivateKey)
                    },
                    ["machine_client"] = new JsonObject
                    {
                        ["client_id"] = ArkManagementAuth.MachineClientId(plan.TenantId),
                        ["client_secret"] = plan.MachineSecret
                    }
                };

                if (File.Exists(file))
                {
                    var stamp = File.GetLastWriteTimeUtc(file).ToString("yyyyMMdd'T'HHmmss'Z'", System.Globalization.CultureInfo.InvariantCulture);
                    File.Move(file, Path.Combine(dataDir, $"ark-idp-{plan.TenantId}-keys.{stamp}.json"));
                }
                ArkIdpSettings.WritePrivateFile(file,
                    Encoding.UTF8.GetBytes(keys.ToJsonString(new JsonSerializerOptions { WriteIndented = true })));
                _log.LogInformation("Ark IdP setup wrote the signing key and the machine credential to {File}. Keep it as safe as the database.", file);
                return file;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or FormatException)
            {
                _log.LogWarning(ex, "Ark IdP setup is complete, but the keys file could not be written to {File}. The wizard's download still has it.", file);
                return null;
            }
        }

        /// <summary>
        /// A new SQLite database file, its owner's alone: it holds the signing keys. SQLite would have
        /// made it readable by every account on the machine. Its -wal and -shm files take the mode of
        /// the database they belong to, so they follow.
        /// </summary>
        static void CreatePrivateSqlite(string connection)
        {
            if (OperatingSystem.IsWindows() || SqliteFile(connection) is not { } file || File.Exists(file)) return;
            ArkIdpSettings.CreatePrivateFile(file).Dispose();
            // EF switches a database it creates itself to write-ahead logging, and leaves one it finds
            // as it is. This one it will find.
            using var db = new Microsoft.Data.Sqlite.SqliteConnection(connection);
            db.Open();
            using var command = db.CreateCommand();
            command.CommandText = "PRAGMA journal_mode = 'wal';";
            command.ExecuteNonQuery();
        }

        /// <summary>Attaches the settings file when its directory did not exist at start-up.</summary>
        bool TryCreateAndAttach()
        {
            try { ArkIdpSettings.CreatePrivateDirectory(ArkIdpSettings.DataDirectory(_config, _env)); }
            catch (Exception) { return false; }
            return ArkIdpSettings.Attach(_config, _env);
        }

        internal sealed record Plan(
            string TenantId, string AppRoot, string BaseUrl, string BasePath, string Issuer,
            string Provider, string Connection, string? PublicKey, string? PrivateKey,
            string AdminUsername, string? MachineSecret, bool ExistingTenant, string? LandingUrl, WatchPlan? Watch);

        /// <summary>The server address and tenant, checked. The landing page only where the built-in sign-in lands anywhere.</summary>
        internal static (string Tenant, string BaseUrl, string BasePath, string AppRoot, string? Landing) ValidateServer(
            ServerSection server, bool consoleSignIn)
        {
            var tenant = (server.TenantId ?? "").Trim();
            if (!TenantId.IsMatch(tenant))
                throw new SetupException("invalid_tenant", "Tenant id: 2–63 letters, digits, '_' or '-', starting with a letter or digit.", "tenant_id");

            var baseUrl = (server.BaseUrl ?? "").Trim().TrimEnd('/');
            if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https") ||
                !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
                throw new SetupException("invalid_base_url", "Public URL: the absolute http(s) address browsers reach this server at, e.g. https://id.example.com.", "base_url");
            if (uri.Scheme == "http" && !uri.IsLoopback)
                throw new SetupException("https_required", "Only a localhost address may use http. Tokens and passwords cross this address.", "base_url");

            var basePath = (server.BasePath ?? "").Trim().Trim('/');
            if (!BasePathPattern.IsMatch(basePath))
                throw new SetupException("invalid_base_path", "Base path: letters, digits, '_', '-' and '/' only.", "base_path");

            var appRoot = Protocol.ArkOidcEndpoints.PublicRoot(new ArkAuthServerConfig { BaseUrl = baseUrl, BasePath = basePath });
            var landing = consoleSignIn ? NormalizeLanding(server.LandingUrl, appRoot) : null;
            return (tenant, baseUrl, basePath, appRoot, landing);
        }

        internal static string ValidateAdmin(AdminSection admin, bool needsPassword)
        {
            var username = (admin.Username ?? "").Trim();
            if (username.Length == 0 || username.Any(char.IsWhiteSpace))
                throw new SetupException("invalid_admin", "Administrator username: no spaces. An email address works.", "admin_username");
            if (needsPassword && (admin.Password ?? "").Length < 10)
                throw new SetupException("weak_password", "The administrator password needs at least 10 characters.", "admin_password");
            return username;
        }

        internal static void ValidateUsers(UsersSection users, EmailSection? email)
        {
            var mode = (users.PasswordMode ?? "admin_managed").Trim().ToLowerInvariant();
            if (mode is not ("admin_managed" or "email_based" or "auto"))
                throw new SetupException("invalid_mode", "Choose how new users get their first password.", "password_mode");
            var emailEnabled = email?.Enabled == true;
            if (emailEnabled) ValidateEmail(email!);
            if (mode == "email_based" && !emailEnabled)
                throw new SetupException("email_required", "Activation emails need outgoing email. Configure SMTP, or let administrators set first passwords.", "password_mode");
            // Outside email_based, the console and the provisioning API create every new account on
            // the default password (RequireDefaultPw), and refuse to create one without it. Setup
            // used to let it be left out, so a server could be installed on which the console
            // could not add a single person.
            var defaultPw = (users.DefaultPassword ?? "").Trim();
            if (defaultPw.StartsWith("<<") && defaultPw.EndsWith(">>")) defaultPw = "";
            if (defaultPw.Length == 0 && mode != "email_based")
                throw new SetupException("default_password_required",
                    "Set a default password for new users: accounts added in the console or through the provisioning API start on it, " +
                    "and are refused without one. Or send activation emails instead.", "default_password");
            if (defaultPw.Length is > 0 and < 8)
                throw new SetupException("weak_default", "The default password for new users needs at least 8 characters.", "default_password");
        }

        internal static string ValidateManagement(ManagementSection? management)
        {
            var secret = (management?.MachineClientSecret ?? "").Trim();
            if (secret.Length > 0 && secret.Length < ArkManagementConfig.MinMachineClientSecretLength)
                throw new SetupException("weak_secret", $"The machine client secret needs at least {ArkManagementConfig.MinMachineClientSecretLength} characters.", "machine_client_secret");
            return secret;
        }

        internal static void ValidateProtocol(ProtocolSection? protocol)
        {
            foreach (var origin in protocol?.CorsOrigins ?? new List<string>())
            {
                if (!Uri.TryCreate(origin.Trim(), UriKind.Absolute, out var o) || o.Scheme is not ("http" or "https") ||
                    o.AbsolutePath != "/" || origin.Trim().TrimEnd('/').Length != o.GetLeftPart(UriPartial.Authority).Length)
                    throw new SetupException("invalid_origin", $"'{origin}' is not an origin. Use scheme://host[:port], nothing after it.", "cors_origins");
            }
        }

        /// <summary>Whether the built-in console sign-in is there to land anywhere.</summary>
        internal static bool HasConsoleSignIn(HttpContext context) => context.RequestServices.GetService<ArkIdpConsoleMarker>() != null;

        internal Plan Validate(HttpContext context, SetupRequest req)
        {
            // Only the built-in sign-in lands anywhere; a host's own client decides for itself.
            var (tenant, baseUrl, basePath, appRoot, landing) = ValidateServer(req.Server ?? new ServerSection(), HasConsoleSignIn(context));
            var (provider, connection) = NormalizeDatabase(req.Database);

            // An existing Ark database: setup attaches to it instead of seeding, and the
            // tenant has to be one it already has.
            var probe = JsonSerializer.SerializeToElement(ProbeDatabase(provider, connection), Json);
            if (!probe.GetProperty("ok").GetBoolean())
                throw new SetupException("database_failed", probe.GetProperty("msg").GetString() ?? "The database is not usable.", "connection_string");
            var tenants = probe.GetProperty("tenants").EnumerateArray().Select(t => t.GetString()).ToList();
            var existing = tenants.Count > 0;
            if (existing && !tenants.Contains(tenant))
                throw new SetupException("tenant_mismatch",
                    $"This database already belongs to tenant(s) {string.Join(", ", tenants)}. Use one of those as the tenant id, or an empty database.", "tenant_id");

            // An existing database keeps the keys it signs with; a new one needs one.
            string? pub = null, priv = null;
            if (!existing) (pub, priv, _) = ParsePrivateKey(req.Keys?.PrivateKey);

            var username = ValidateAdmin(req.Admin ?? new AdminSection(), needsPassword: !existing);
            ValidateUsers(req.Users ?? new UsersSection(), req.Email);
            var secret = ValidateManagement(req.Management);
            ValidateProtocol(req.Protocol);
            var watch = NormalizeWatch(req.Watch);

            return new Plan(tenant, appRoot, baseUrl, basePath, $"{appRoot}/{tenant}", provider, connection, pub, priv,
                username, secret.Length == 0 ? null : secret, existing, landing, watch);
        }

        /// <summary>
        /// The landing page as it is stored: nothing for the public URL itself (the default), a
        /// path for a page of this app — so a later change of public URL carries it along — and an
        /// absolute URL only for a page somewhere else.
        /// </summary>
        static string? NormalizeLanding(string? value, string appRoot)
        {
            var text = (value ?? "").Trim();
            if (text.Equals(appRoot, StringComparison.OrdinalIgnoreCase) ||
                text.StartsWith(appRoot + "/", StringComparison.OrdinalIgnoreCase) ||
                text.StartsWith(appRoot + "?", StringComparison.OrdinalIgnoreCase))
                text = "/" + text[appRoot.Length..].TrimStart('/');
            if (ArkIdpConsole.IsLocalUrl(text))
            {
                if (ArkIdpConsole.IsRoot(text)) return null;
                if (ArkIdpConsole.IsReservedPath(text))
                    throw new SetupException("reserved_landing_url",
                        $"Landing page: {text.Split('?', '#')[0]} is part of signing in itself, so landing there would loop. Choose a page of the app.", "landing_url");
                return text;
            }
            if (text.Length == 0) return null;
            if (Uri.TryCreate(text, UriKind.Absolute, out var url) && url.Scheme is "http" or "https") return text;
            throw new SetupException("invalid_landing_url",
                "Landing page: a path in this app such as /dashboard, or a full http(s) address.", "landing_url");
        }

        /// <summary>
        /// Saves an uploaded logo and returns its public URL, or passes a URL through. Stored as a
        /// file rather than a data: URI because it goes into activation emails too, and most mail
        /// clients will not show a data: image.
        /// </summary>
        static string? StoreLogo(string dataDir, string name, string? value, string appRoot, string field)
        {
            var text = (value ?? "").Trim();
            if (text.Length == 0) return null;
            if (Uri.TryCreate(text, UriKind.Absolute, out var url) && url.Scheme is "https" or "http") return text;

            var m = DataUri.Match(text);
            if (!m.Success) throw new SetupException("invalid_logo", "Logos: upload a PNG, JPEG, GIF, WebP, SVG or ICO image, or give an image URL.", field);
            byte[] bytes;
            try { bytes = Convert.FromBase64String(m.Groups[2].Value); }
            catch (FormatException) { throw new SetupException("invalid_logo", "That image could not be read.", field); }
            if (bytes.Length > 1024 * 1024) throw new SetupException("logo_too_large", "Logos must be 1 MB or smaller.", field);

            var ext = m.Groups[1].Value switch
            {
                "image/png" => "png", "image/jpeg" => "jpg", "image/gif" => "gif",
                "image/webp" => "webp", "image/svg+xml" => "svg", _ => "ico"
            };
            var dir = Path.Combine(dataDir, ArkIdpSettings.BrandingFolder);
            Directory.CreateDirectory(dir);
            foreach (var old in Directory.GetFiles(dir, $"{name}.*")) File.Delete(old);
            File.WriteAllBytes(Path.Combine(dir, $"{name}.{ext}"), bytes);
            var version = Protocol.ArkCrypto.Sha256Base64Url(m.Groups[2].Value)[..8];
            return $"{appRoot}{BrandingPath}/{name}.{ext}?v={version}";
        }

        JsonObject BuildSettings(HttpContext context, SetupRequest req, Plan plan, string? hostLogo, string? appLogo)
        {
            var org = req.Organization ?? new OrganizationSection();
            var email = req.Email ?? new EmailSection();
            var users = req.Users ?? new UsersSection();
            var p = req.Protocol ?? new ProtocolSection();
            var companyName = Or(org.CompanyName, "Ark");
            var display = Or(org.DisplayName, $"{companyName} Identity");

            var emailConfig = new JsonObject
            {
                ["host_company_name"] = companyName,
                ["host_company_display"] = display,
                ["host_logo"] = hostLogo ?? "",
                ["client_logo"] = appLogo ?? hostLogo ?? "",
                ["host_website_url"] = Or(org.WebsiteUrl, plan.AppRoot),
                ["client_website_url"] = Or(org.WebsiteUrl, plan.AppRoot),
                ["terms_url"] = Or(org.TermsUrl, Or(org.WebsiteUrl, plan.AppRoot)),
                ["privacy_policy_url"] = Or(org.PrivacyUrl, Or(org.WebsiteUrl, plan.AppRoot)),
                // {0} = tenant_id, {1} = the user's one-time ref_uid
                ["activation_link"] = $"{plan.AppRoot}/oauth/{{0}}/v1/password/reset/{{1}}",
                ["smtp"] = email.Enabled ? email.Smtp?.Trim() ?? "" : "",
                ["port"] = email.Enabled ? email.Port ?? 587 : 587,
                ["email"] = email.Enabled ? Or(email.Username, email.From ?? "") : "",
                ["pw"] = email.Enabled ? email.Password ?? "" : "",
                ["from"] = email.Enabled ? email.From?.Trim() ?? "" : "",
                ["display"] = Or(email.Display, display),
                ["subject"] = Or(email.Subject, $"{companyName}: ")
            };

            var oidc = new JsonObject
            {
                ["EnableDeviceFlow"] = p.EnableDeviceFlow ?? true,
                ["EnablePushedAuthorizationRequests"] = p.EnablePushedAuthorizationRequests ?? true,
                ["RequirePushedAuthorizationRequests"] = p.RequirePushedAuthorizationRequests ?? false,
                ["EnableDynamicRegistration"] = p.EnableDynamicRegistration ?? false,
                ["RequireRegistrationAccessToken"] = true,
                ["AlwaysRequireConsent"] = p.AlwaysRequireConsent ?? false,
                ["EnableBackChannelLogout"] = p.EnableBackChannelLogout ?? true,
                ["SessionLifetimeMinutes"] = Positive(p.SessionLifetimeMinutes, 480),
                ["MaxFailedSignIns"] = p.MaxFailedSignIns is >= 0 ? p.MaxFailedSignIns.Value : 10,
                ["LockoutMinutes"] = Positive(p.LockoutMinutes, 15),
                ["CorsOrigins"] = new JsonArray((p.CorsOrigins ?? new List<string>())
                    .Select(o => o.Trim().TrimEnd('/')).Where(o => o.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase)
                    .Select(o => (JsonNode?)JsonValue.Create(o)).ToArray())
            };

            var server = new JsonObject
            {
                ["TenantId"] = plan.TenantId,
                ["BaseUrl"] = plan.BaseUrl,
                ["BasePath"] = plan.BasePath,
                ["Provider"] = plan.Provider,
                ["UserPasswordMode"] = (users.PasswordMode ?? "admin_managed").Trim().ToLowerInvariant(),
                ["EnableLogTrace"] = true,
                // The password itself is not here: it went into the database as a hash.
                ["AdminUser"] = new JsonObject
                {
                    ["Username"] = plan.AdminUsername,
                    ["Name"] = Or(req.Admin?.Name, "Administrator")
                },
                ["Oidc"] = oidc,
                ["EmailConfig"] = emailConfig,
                ["ShowPoweredBy"] = req.Branding?.ShowPoweredBy ?? true
            };
            if (!string.IsNullOrEmpty(users.DefaultPassword)) server["DefaultPw"] = users.DefaultPassword;
            // Only when it was asked for: without the section the server sends nothing anywhere.
            if (plan.Watch != null)
                server["Watch"] = new JsonObject
                {
                    ["Enabled"] = true,
                    ["Endpoint"] = plan.Watch.Endpoint,
                    ["ApiKey"] = plan.Watch.ApiKey,
                    ["Application"] = plan.Watch.Application,
                    ["Environment"] = plan.Watch.Environment
                };
            if (context.RequestServices.GetService<ArkIdpConsoleMarker>() != null)
            {
                var admin = new JsonObject { ["SignOutUrl"] = $"{context.Request.PathBase}{ArkIdpConsole.SignOutPath}" };
                if (plan.LandingUrl != null) admin["LandingUrl"] = plan.LandingUrl;
                server["Admin"] = admin;
            }

            return new JsonObject
            {
                ["_about"] = "Written by the Ark IdP setup wizard. This is the server's configuration: back it up, never commit it. " +
                             "Any value here can be overridden by user secrets, environment variables or the command line.",
                ["ark_setup"] = new JsonObject
                {
                    ["completed_at"] = DateTime.UtcNow.ToString("O"),
                    ["package_version"] = PackageVersion,
                    ["signing_key_kid"] = plan.PublicKey == null ? null : Protocol.ArkCrypto.ComputeKid(plan.PublicKey)
                },
                ["ConnectionStrings"] = new JsonObject { ["ArkAuthConnection"] = plan.Connection },
                ["ark_oauth_server"] = server
            };
        }

        static string Or(string? value, string fallback) => string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();
        static int Positive(int? value, int fallback) => value is > 0 ? value.Value : fallback;

        // ---------------------------------------------------------------- request shapes

        internal sealed class SetupException : Exception
        {
            public SetupException(string code, string message, string? field = null) : base(message)
            {
                Code = code;
                Field = field;
            }
            public string Code { get; }
            public string? Field { get; }
        }

        sealed class CodeRequest { public string? Code { get; set; } }
        sealed class AccessKeyRequest { public string? Key { get; set; } }
        internal sealed class KeyRequest { public int? KeySize { get; set; } public string? PrivateKey { get; set; } }
        internal sealed class EmailTestRequest { public EmailSection? Email { get; set; } public string? To { get; set; } }

        internal sealed class SetupRequest
        {
            public OrganizationSection? Organization { get; set; }
            public BrandingSection? Branding { get; set; }
            public ServerSection? Server { get; set; }
            public DatabaseSection? Database { get; set; }
            public KeysSection? Keys { get; set; }
            public AdminSection? Admin { get; set; }
            public UsersSection? Users { get; set; }
            public EmailSection? Email { get; set; }
            public ProtocolSection? Protocol { get; set; }
            public ManagementSection? Management { get; set; }
            public WatchSection? Watch { get; set; }
        }

        /// <summary>The optional audit trail: an ARK-RAPID Watch node and this server's key for it.</summary>
        internal sealed class WatchSection
        {
            public bool Enabled { get; set; }
            public string? Endpoint { get; set; }
            public string? ApiKey { get; set; }
            public string? Application { get; set; }
            public string? Environment { get; set; }
        }

        internal sealed class OrganizationSection
        {
            public string? CompanyName { get; set; }
            public string? DisplayName { get; set; }
            public string? WebsiteUrl { get; set; }
            public string? TermsUrl { get; set; }
            public string? PrivacyUrl { get; set; }
        }

        internal sealed class BrandingSection
        {
            public string? HostLogo { get; set; }
            public string? AppLogo { get; set; }
            public bool? ShowPoweredBy { get; set; }
        }

        internal sealed class ServerSection
        {
            public string? TenantId { get; set; }
            public string? TenantDisplay { get; set; }
            public string? BaseUrl { get; set; }
            public string? BasePath { get; set; }
            public string? LandingUrl { get; set; }
        }

        internal sealed class DatabaseSection { public string? Provider { get; set; } public string? ConnectionString { get; set; } }
        internal sealed class KeysSection { public string? PrivateKey { get; set; } }
        internal sealed class AdminSection { public string? Username { get; set; } public string? Name { get; set; } public string? Password { get; set; } }
        internal sealed class UsersSection { public string? PasswordMode { get; set; } public string? DefaultPassword { get; set; } }

        internal sealed class EmailSection
        {
            public bool Enabled { get; set; }
            public string? Smtp { get; set; }
            public int? Port { get; set; }
            public string? Username { get; set; }
            public string? Password { get; set; }
            public string? From { get; set; }
            public string? Display { get; set; }
            public string? Subject { get; set; }
        }

        internal sealed class ProtocolSection
        {
            public bool? EnableDeviceFlow { get; set; }
            public bool? EnablePushedAuthorizationRequests { get; set; }
            public bool? RequirePushedAuthorizationRequests { get; set; }
            public bool? EnableDynamicRegistration { get; set; }
            public bool? AlwaysRequireConsent { get; set; }
            public bool? EnableBackChannelLogout { get; set; }
            public int? SessionLifetimeMinutes { get; set; }
            public int? MaxFailedSignIns { get; set; }
            public int? LockoutMinutes { get; set; }
            public List<string>? CorsOrigins { get; set; }
        }

        internal sealed class ManagementSection { public string? MachineClientSecret { get; set; } }
    }

    public static class ArkSetupExtensions
    {
        const string Registered = "Ark.oAuth.Oidc.SetupRegistered";

        /// <summary>
        /// The first-run setup wizard, and the gate that sends an unconfigured server to it.
        /// <see cref="ArkExtn.UseArkAuthData"/> calls this, so a host need not; calling it again
        /// adds nothing. Place it after <c>UseRouting</c> and before authentication.
        /// </summary>
        public static IApplicationBuilder UseArkSetup(this IApplicationBuilder app)
        {
            if (app.Properties.ContainsKey(Registered)) return app;
            app.Properties[Registered] = true;
            // Settings first: a server set up on an earlier run has no place for the agent at all.
            ArkIdpSettings.Attach(app.ApplicationServices.GetRequiredService<IConfiguration>(), app.ApplicationServices.GetRequiredService<IHostEnvironment>());
            // In front of the gate, which answers everything else. Behind whatever the host put first.
            Ark.Agents.TenantOnboarding.ArkOnboardingAgentExtensions.UseBuiltIn(app);
            return app.UseMiddleware<ArkSetupMiddleware>();
        }
    }
}
