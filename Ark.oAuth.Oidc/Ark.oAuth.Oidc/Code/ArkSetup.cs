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
    /// as hashes, the signing key goes into <c>signing_keys</c>, and that is the only copy.
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
    /// uploaded logos and, until setup is finished, the setup code. The directory carries its own
    /// <c>.gitignore</c>, because <c>dotnet run</c> puts it inside the project and it holds the
    /// SMTP password.
    /// </summary>
    public static class ArkIdpSettings
    {
        public const string SettingsFileName = "settings.json";
        internal const string BrandingFolder = "branding";
        internal const string TokenFileName = "setup-code.txt";

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
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            EnsureIgnored(Path.GetDirectoryName(path)!);
            var temp = path + ".tmp";
            File.WriteAllBytes(temp, content);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            File.Move(temp, path, overwrite: true);
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
    /// unconfigured server exposed to a network is a race. From this machine — a loopback
    /// address, no forwarding headers — the wizard is open, because that is a developer at
    /// <c>dotnet run</c>. From anywhere else it asks for a setup code that is printed in the
    /// server's log and written beside the settings, which only someone who can see the server
    /// has. <c>Setup:RequireToken</c> asks for it everywhere; <c>Setup:Enabled</c> false removes the
    /// wizard altogether.
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
        static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
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
            if (Enabled && !ArkIdpSettings.IsConfigured(config)) Announce();
        }

        bool Enabled => _config.GetValue("ark_oauth_server:Setup:Enabled", true);

        public async Task InvokeAsync(HttpContext context)
        {
            var path = context.Request.Path;

            if (path.StartsWithSegments(BrandingPath, out var asset))
            {
                await ServeBrandingAsync(context, asset.Value ?? "");
                return;
            }

            var configured = ArkIdpSettings.IsConfigured(_config);
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
            var where = code == null ? "" : $" From any other machine, enter the setup code {code}.";
            _log.LogWarning(
                "Ark IdP is not configured yet. Open /ark-idp/setup on this server in a browser to run the setup wizard. " +
                "From this machine (localhost) no code is needed.{Where}", where);
        }

        /// <summary>
        /// The code, created once and kept beside the settings so a restart does not change it.
        /// Null when it cannot be stored — the log still has it for this process.
        /// </summary>
        string? EnsureSetupCode()
        {
            lock (CodeLock)
            {
                if (_setupCode != null) return _setupCode;
                var file = Path.Combine(ArkIdpSettings.DataDirectory(_config, _env), ArkIdpSettings.TokenFileName);
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
        /// A developer on this machine: loopback, and not relayed by a proxy that is itself on
        /// loopback — nginx or a tunnel in front of Kestrel makes every visitor look local.
        /// </summary>
        bool IsLocal(HttpContext context)
        {
            if (_config.GetValue("ark_oauth_server:Setup:RequireToken", false)) return false;
            var remote = context.Connection.RemoteIpAddress;
            if (remote == null || !IPAddress.IsLoopback(remote)) return false;
            var h = context.Request.Headers;
            return !h.ContainsKey("X-Forwarded-For") && !h.ContainsKey("Forwarded") && !h.ContainsKey("X-Real-IP");
        }

        bool CodeAccepted(HttpContext context, string? code = null)
        {
            if (IsLocal(context)) return true;
            var expected = EnsureSetupCode();
            code ??= context.Request.Headers[TokenHeader].ToString();
            var given = (code ?? "").Trim().ToUpperInvariant();
            return expected != null && given.Length > 0 && Protocol.ArkCrypto.FixedTimeEquals(given, expected);
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
            if (!CodeAccepted(context))
                return new { configured = false, code_required = true, version = PackageVersion };

            var request = context.Request;
            var dataDir = ArkIdpSettings.DataDirectory(_config, _env);
            var pathBase = request.PathBase.HasValue ? request.PathBase.Value!.TrimEnd('/') : "";

            return new
            {
                configured = false,
                code_required = !IsLocal(context),
                version = PackageVersion,
                environment = _env.EnvironmentName,
                data_directory = dataDir,
                data_directory_writable = Writable(dataDir),
                settings_file = Path.Combine(dataDir, ArkIdpSettings.SettingsFileName),
                can_apply = _config is IConfigurationBuilder,
                console_sign_in = context.RequestServices.GetService<ArkIdpConsoleMarker>() != null,
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
        /// The database beside the settings, so one directory — one volume, in a container — is
        /// the whole server. Relative to the working directory, which is how SQLite will read it,
        /// when that is where it is; absolute otherwise.
        /// </summary>
        static string DefaultSqliteFile(string dataDir)
        {
            var file = Path.Combine(dataDir, "ark_idp.db");
            var relative = Path.GetRelativePath(Directory.GetCurrentDirectory(), file);
            return relative.StartsWith("..", StringComparison.Ordinal) || Path.IsPathRooted(relative)
                ? file
                : relative.Replace('\\', '/');
        }

        static bool Writable(string directory)
        {
            try
            {
                Directory.CreateDirectory(directory);
                var probe = Path.Combine(directory, $".write-test-{Guid.NewGuid():N}");
                File.WriteAllText(probe, "");
                File.Delete(probe);
                return true;
            }
            catch (Exception) { return false; }
        }

        // ---------------------------------------------------------------- keys

        static object GenerateKeys(KeyRequest? req)
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

        async Task<object> TestDatabaseAsync(DatabaseSection? db)
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

        static (string provider, string connection) NormalizeDatabase(DatabaseSection? db)
        {
            var provider = (db?.Provider ?? "sqlite").Trim().ToLowerInvariant();
            if (provider is not ("sqlite" or "mysql" or "postgres"))
                throw new SetupException("invalid_provider", "Provider must be sqlite, mysql or postgres.", "provider");
            var connection = (db?.ConnectionString ?? "").Trim();
            if (connection.Length == 0)
                throw new SetupException("connection_required", "Enter the database connection.", "connection_string");
            return (provider, connection);
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

        static string Innermost(Exception ex)
        {
            while (ex.InnerException != null && ex is not ApplicationException) ex = ex.InnerException;
            return ex.Message;
        }

        // ---------------------------------------------------------------- email

        static async Task<object> TestEmailAsync(EmailTestRequest? req)
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

        static void ValidateEmail(EmailSection email)
        {
            if (string.IsNullOrWhiteSpace(email.Smtp))
                throw new SetupException("smtp_required", "Enter the SMTP server.", "smtp");
            if (email.Port is null or < 1 or > 65535)
                throw new SetupException("invalid_port", "Enter the SMTP port (usually 587, 465 or 25).", "port");
            if (!ark.net.util.EmailUtil.IsValidFormat(email.From ?? ""))
                throw new SetupException("invalid_from", "Enter the address messages are sent from.", "from");
        }

        // ---------------------------------------------------------------- install

        static readonly Regex TenantId = new("^[A-Za-z0-9][A-Za-z0-9_-]{1,62}$", RegexOptions.CultureInvariant);
        static readonly Regex BasePathPattern = new("^[A-Za-z0-9_\\-/]*$", RegexOptions.CultureInvariant);
        static readonly Regex DataUri = new("^data:(image/(?:png|jpeg|gif|webp|svg\\+xml|x-icon|vnd\\.microsoft\\.icon));base64,([A-Za-z0-9+/=\\s]+)$",
            RegexOptions.CultureInvariant);

        async Task CompleteAsync(HttpContext context, SetupRequest? req)
        {
            if (req == null) throw new SetupException("bad_request", "Nothing to install.");
            if (_config is not IConfigurationRoot root || !ArkIdpSettings.Attach(_config, _env) && !TryCreateAndAttach())
                throw new SetupException("cannot_apply",
                    "This host's configuration cannot be extended at run time, so the settings cannot take effect. Use WebApplication.CreateBuilder.");

            await InstallLock.WaitAsync(context.RequestAborted);
            try
            {
                if (ArkIdpSettings.IsConfigured(_config))
                    throw new SetupException("already_configured", "This server has already been set up.");

                var plan = Validate(context, req);
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
                    Directory.CreateDirectory(Path.GetDirectoryName(sqlite)!);

                // The file watcher would get there too, a moment later; this makes it now, and
                // fires the change tokens that rebuild the console's sign-in options.
                root.Reload();

                try
                {
                    using var scope = context.RequestServices.GetRequiredService<IServiceScopeFactory>().CreateScope();
                    await ArkExtn.BootstrapDatabaseAsync(scope.ServiceProvider, context, new ArkSeedOverrides
                    {
                        AdminPassword = req.Admin?.Password,
                        SigningKey = plan.PublicKey == null ? null : (plan.PublicKey, plan.PrivateKey!),
                        MachineClientSecret = plan.MachineSecret,
                        TenantDisplay = req.Server?.TenantDisplay?.Trim(),
                        ConsoleLogo = appLogo
                    });
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

                ForgetSetupCode();
                _log.LogInformation("Ark IdP setup complete: tenant {Tenant}, issuer {Issuer}, settings in {File}",
                    plan.TenantId, plan.Issuer, settingsFile);

                var endpoints = new Protocol.ArkOidcEndpoints(plan.AppRoot, plan.TenantId);
                await context.Response.WriteAsJsonAsync(new
                {
                    ok = true,
                    tenant_id = plan.TenantId,
                    issuer = endpoints.Issuer,
                    discovery = endpoints.Discovery,
                    console = $"{context.Request.PathBase}/{plan.TenantId}/admin",
                    admin_username = plan.AdminUsername,
                    settings_file = settingsFile,
                    machine_client_id = ArkManagementAuth.MachineClientId(plan.TenantId),
                    // an existing database is attached, not seeded, so nothing was set
                    machine_client_secret = plan.ExistingTenant ? null : plan.MachineSecret,
                    attached_existing = plan.ExistingTenant
                }, Json);
            }
            finally
            {
                InstallLock.Release();
            }
        }

        /// <summary>Attaches the settings file when its directory did not exist at start-up.</summary>
        bool TryCreateAndAttach()
        {
            try { Directory.CreateDirectory(ArkIdpSettings.DataDirectory(_config, _env)); }
            catch (Exception) { return false; }
            return ArkIdpSettings.Attach(_config, _env);
        }

        sealed record Plan(
            string TenantId, string AppRoot, string BaseUrl, string BasePath, string Issuer,
            string Provider, string Connection, string? PublicKey, string? PrivateKey,
            string AdminUsername, string? MachineSecret, bool ExistingTenant, string? LandingUrl);

        Plan Validate(HttpContext context, SetupRequest req)
        {
            var server = req.Server ?? new ServerSection();
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
            // Only the built-in sign-in lands anywhere; a host's own client decides for itself.
            var landing = context.RequestServices.GetService<ArkIdpConsoleMarker>() != null
                ? NormalizeLanding(server.LandingUrl, appRoot)
                : null;
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

            var admin = req.Admin ?? new AdminSection();
            var username = (admin.Username ?? "").Trim();
            if (username.Length == 0 || username.Any(char.IsWhiteSpace))
                throw new SetupException("invalid_admin", "Administrator username: no spaces. An email address works.", "admin_username");
            if (!existing && (admin.Password ?? "").Length < 10)
                throw new SetupException("weak_password", "The administrator password needs at least 10 characters.", "admin_password");

            var users = req.Users ?? new UsersSection();
            var mode = (users.PasswordMode ?? "admin_managed").Trim().ToLowerInvariant();
            if (mode is not ("admin_managed" or "email_based" or "auto"))
                throw new SetupException("invalid_mode", "Choose how new users get their first password.", "password_mode");
            var emailEnabled = req.Email?.Enabled == true;
            if (emailEnabled) ValidateEmail(req.Email!);
            if (mode == "email_based" && !emailEnabled)
                throw new SetupException("email_required", "Activation emails need outgoing email. Configure SMTP, or let administrators set first passwords.", "password_mode");
            if (!string.IsNullOrEmpty(users.DefaultPassword) && users.DefaultPassword.Length < 8)
                throw new SetupException("weak_default", "The default password for new users needs at least 8 characters.", "default_password");

            var secret = (req.Management?.MachineClientSecret ?? "").Trim();
            if (secret.Length > 0 && secret.Length < ArkManagementConfig.MinMachineClientSecretLength)
                throw new SetupException("weak_secret", $"The machine client secret needs at least {ArkManagementConfig.MinMachineClientSecretLength} characters.", "machine_client_secret");

            foreach (var origin in req.Protocol?.CorsOrigins ?? new List<string>())
            {
                if (!Uri.TryCreate(origin.Trim(), UriKind.Absolute, out var o) || o.Scheme is not ("http" or "https") ||
                    o.AbsolutePath != "/" || origin.Trim().TrimEnd('/').Length != o.GetLeftPart(UriPartial.Authority).Length)
                    throw new SetupException("invalid_origin", $"'{origin}' is not an origin. Use scheme://host[:port], nothing after it.", "cors_origins");
            }

            return new Plan(tenant, appRoot, baseUrl, basePath, $"{appRoot}/{tenant}", provider, connection, pub, priv,
                username, secret.Length == 0 ? null : secret, existing, landing);
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

        sealed class SetupException : Exception
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
        sealed class KeyRequest { public int? KeySize { get; set; } public string? PrivateKey { get; set; } }
        sealed class EmailTestRequest { public EmailSection? Email { get; set; } public string? To { get; set; } }

        sealed class SetupRequest
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
        }

        sealed class OrganizationSection
        {
            public string? CompanyName { get; set; }
            public string? DisplayName { get; set; }
            public string? WebsiteUrl { get; set; }
            public string? TermsUrl { get; set; }
            public string? PrivacyUrl { get; set; }
        }

        sealed class BrandingSection
        {
            public string? HostLogo { get; set; }
            public string? AppLogo { get; set; }
            public bool? ShowPoweredBy { get; set; }
        }

        sealed class ServerSection
        {
            public string? TenantId { get; set; }
            public string? TenantDisplay { get; set; }
            public string? BaseUrl { get; set; }
            public string? BasePath { get; set; }
            public string? LandingUrl { get; set; }
        }

        sealed class DatabaseSection { public string? Provider { get; set; } public string? ConnectionString { get; set; } }
        sealed class KeysSection { public string? PrivateKey { get; set; } }
        sealed class AdminSection { public string? Username { get; set; } public string? Name { get; set; } public string? Password { get; set; } }
        sealed class UsersSection { public string? PasswordMode { get; set; } public string? DefaultPassword { get; set; } }

        sealed class EmailSection
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

        sealed class ProtocolSection
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

        sealed class ManagementSection { public string? MachineClientSecret { get; set; } }
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
            return app.UseMiddleware<ArkSetupMiddleware>();
        }
    }
}
