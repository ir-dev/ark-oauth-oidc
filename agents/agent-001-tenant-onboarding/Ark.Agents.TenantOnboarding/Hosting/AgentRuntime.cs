using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Ark.Agents.TenantOnboarding.Brain;
using Ark.Agents.TenantOnboarding.Llm;
using Ark.Agents.TenantOnboarding.Mcp;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Ark.Agents.TenantOnboarding.Hosting
{
    /// <summary>
    /// The setup code as the identity server announces it. The server logs
    /// "… with the setup code {Code} as its bearer token" under the category
    /// <c>Ark.oAuth.Oidc.Setup</c>; this provider is in the logging pipeline and reads the value
    /// off that entry, so the agent has the code the moment the server does, with no file to find
    /// and nobody to paste it.
    /// </summary>
    internal sealed class SetupCodeLoggerProvider : ILoggerProvider
    {
        const string Category = "Ark.oAuth.Oidc.Setup";
        readonly SetupCodeBox _box;

        public SetupCodeLoggerProvider(SetupCodeBox box) => _box = box;

        public ILogger CreateLogger(string categoryName) => categoryName == Category ? new Listener(_box) : Silent.Instance;

        public void Dispose() { }

        sealed class Listener : ILogger
        {
            readonly SetupCodeBox _box;
            public Listener(SetupCodeBox box) => _box = box;
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Warning;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                if (_box.Remote || state is not IEnumerable<KeyValuePair<string, object?>> values) return;
                foreach (var (key, value) in values)
                    if (key == "Code" && value is string code && code.Length >= 12) _box.Captured(code, "the start-up log");
            }
        }

        sealed class Silent : ILogger
        {
            public static readonly Silent Instance = new();
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => false;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) { }
        }
    }

    /// <summary>Holds the setup code, and what is derived from it.</summary>
    internal sealed class SetupCodeBox
    {
        volatile string? _code;
        volatile bool _pinned;
        /// <summary>The agent sets up a server elsewhere: what this application logs is not that server's code.</summary>
        public bool Remote { get; set; }
        public string? From { get; private set; }
        public string? Code => _code;

        public void Captured(string code, string from)
        {
            code = code.Trim().ToUpperInvariant();
            if (_pinned || code.Length < 12 || _code == code) return;
            From = from;
            _key = Derive(code);
            _code = code;
        }

        byte[]? _key;

        // Slowly. A colleague holds a signature made with this key and could try every code against
        // it at home; a code is twelve characters, made to be read off a log, not to withstand that.
        static byte[] Derive(string code) => Rfc2898DeriveBytes.Pbkdf2(
            code, Encoding.UTF8.GetBytes("ark-onboarding-agent/v2"), 600_000, HashAlgorithmName.SHA256, 32);

        /// <summary>
        /// The code from configuration: the one for the server this agent was pointed at. The
        /// application the agent runs in may be an identity server too, announcing a code of its
        /// own in the same log, and that one is not it.
        /// </summary>
        public void Pin(string code)
        {
            _pinned = false;
            Captured(code, "configuration");
            _pinned = true;
        }

        /// <summary>
        /// The key that signs this agent's cookies and the links it hands to colleagues. Derived
        /// from the setup code, so it survives a restart exactly as long as the code does, and a
        /// link stops working the moment setup is finished and the code is gone. A colleague holds
        /// a signature made with the code, never the code.
        /// </summary>
        public byte[]? SigningKey => _code == null ? null : _key;
    }

    /// <summary>
    /// Whether there is a setup here for the agent to do, read from configuration before anything of
    /// the agent is built.
    ///
    /// The agent is part of every identity server, and nearly every start of nearly every one finds it
    /// set up. Such a start must cost nothing: no HTTP client, no route, no thread that stays.
    /// </summary>
    internal static class AgentGate
    {
        public static bool HasWork(IConfiguration config, ArkOnboardingAgentOptions options) =>
            options.Enabled && (!string.IsNullOrWhiteSpace(options.McpUrl) || (!Configured(config) && SetupTools(config)));

        /// <summary>The identity server in this application has a tenant and a database. Its own rule.</summary>
        public static bool Configured(IConfiguration config) =>
            !string.IsNullOrWhiteSpace(config["ark_oauth_server:TenantId"]) && !string.IsNullOrWhiteSpace(config.GetConnectionString("ArkAuthConnection"));

        /// <summary>The server offers its setup as MCP tools, which is all the agent has to work with.</summary>
        static bool SetupTools(IConfiguration config) =>
            config.GetValue("ark_oauth_server:Setup:Enabled", true) && config.GetValue("ark_oauth_server:Mcp:Enabled", true)
            && config.GetValue("ark_oauth_server:Mcp:HostLevel", true);

        /// <summary>The identity server's data directory, by its own rule (<c>Setup:DataPath</c>, else <c>ark-idp-data</c>).</summary>
        public static string DataDirectory(IConfiguration config, IHostEnvironment env)
        {
            var configured = config["ark_oauth_server:Setup:DataPath"];
            var path = string.IsNullOrWhiteSpace(configured) ? "ark-idp-data" : configured.Trim();
            return Path.GetFullPath(Path.IsPathRooted(path) ? path : Path.Combine(env.ContentRootPath, path));
        }
    }

    /// <summary>
    /// Everything the agent is at run time: the workspace, the client of the setup tools, the
    /// model, and the harness around them. One per application.
    /// </summary>
    internal sealed class AgentRuntime
    {
        public ArkOnboardingAgentOptions Options { get; }
        public Workspace Workspace { get; } = new();
        public SetupCodeBox Code { get; }
        public McpClient Mcp { get; }
        public AgentBrain Brain { get; }
        public IConfiguration Configuration { get; }
        public IHostEnvironment Environment { get; }
        public string? SelfUrl { get; set; }
        /// <summary>The handshake has succeeded: the setup tools answer to the code.</summary>
        public bool Connected { get; set; }

        public AgentRuntime(IOptions<ArkOnboardingAgentOptions> options, SetupCodeBox code, IConfiguration configuration, IHostEnvironment environment,
            ILoggerFactory logs, IEnumerable<IArkAgentModel> hostModels)
        {
            Options = options.Value;
            Code = code;
            Configuration = configuration;
            Environment = environment;
            code.Remote = !string.IsNullOrWhiteSpace(Options.McpUrl);
            if (!string.IsNullOrWhiteSpace(Options.SetupCode)) code.Pin(Options.SetupCode!);

            // The server this agent sets up is usually the application it runs in, reached over
            // loopback on a development certificate nobody issued. That hop, and only that one,
            // is trusted without a chain.
            var local = new HttpClient(new HttpClientHandler
            {
                AllowAutoRedirect = false,
                ServerCertificateCustomValidationCallback = (message, _, _, errors) =>
                    errors == System.Net.Security.SslPolicyErrors.None || message.RequestUri?.IsLoopback == true
            }) { Timeout = TimeSpan.FromSeconds(100) };
            Mcp = new McpClient(local, () => McpUrl, () => code.Code);

            // No redirects: one would take the API key, and the conversation, wherever it points.
            var models = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
            {
                Timeout = TimeSpan.FromSeconds(Math.Clamp(Options.Llm.TimeoutSeconds, 5, 600)), MaxResponseContentBufferSize = 8_000_000
            };
            var model = hostModels.FirstOrDefault() ?? AgentModelFactory.Create(Options, models);
            var log = logs.CreateLogger("Ark.Agents.TenantOnboarding");
            if (model == null) log.LogInformation("Onboarding agent: guided mode, because {Why}.", AgentModelFactory.WhyNot(Options));
            else log.LogInformation("Onboarding agent: using {Model}.", model.Label);
            foreach (var (what, url) in new[]
                     {
                         ("McpUrl, which is sent the setup code", Options.McpUrl), ("Llm:GenericLLM:Url", Options.Llm.GenericLLM.Url), ("Llm:ArkLLM:Url", Options.Llm.ArkLLM.Url),
                         ("Llm:AzureFoundry:Endpoint", Options.Llm.AzureFoundry.Url ?? Options.Llm.AzureFoundry.Endpoint), ("Llm:Bedrock:Endpoint", Options.Llm.Bedrock.Endpoint)
                     })
                if (Uri.TryCreate(url, UriKind.Absolute, out var address) && address.Scheme == "http" && !address.IsLoopback)
                    log.LogWarning("Onboarding agent: {Setting} is a plain http address ({Host}). What is sent there crosses the network unencrypted.", what, address.Host);
            Brain = new AgentBrain(Workspace, Mcp, model, Options, log, () => code.Code);
        }

        public string Prefix => "/" + Options.PathPrefix.Trim('/');

        public string? McpUrl => !string.IsNullOrWhiteSpace(Options.McpUrl) ? Options.McpUrl!.TrimEnd('/')
            : SelfUrl == null ? null : SelfUrl.TrimEnd('/') + "/ark-idp/mcp";

        /// <summary>Whether the agent sets up the application it lives in, or a server somewhere else.</summary>
        public bool SameProcess => string.IsNullOrWhiteSpace(Options.McpUrl);

        public string DataDirectory => AgentGate.DataDirectory(Configuration, Environment);

        /// <summary>The identity server in this process has a tenant and a database: there is nothing left to set up.</summary>
        public bool ServerConfigured => SameProcess && AgentGate.Configured(Configuration);

        /// <summary>The code from where the server keeps it, for a start in which the log line was missed.</summary>
        public void ReadCodeFile()
        {
            if (Code.Code != null || !SameProcess) return;
            try
            {
                var file = Path.Combine(DataDirectory, "setup-code.txt");
                if (File.Exists(file)) Code.Captured(File.ReadAllText(file), "setup-code.txt");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    /// <summary>
    /// The agent as a background service: it is at work before anybody opens the page.
    ///
    /// It waits for the server to listen, takes the setup code, connects to the setup tools with
    /// it, looks around the host, and then keeps watch: for values that arrive by another route
    /// (the wizard, another agent), for colleagues who have gone quiet, and for the moment setup
    /// is finished, by whichever route, after which it has nothing left to do and says so.
    /// </summary>
    internal sealed class OnboardingAgentService : BackgroundService
    {
        AgentRuntime _rt = null!;
        readonly IServiceProvider _services;
        readonly IServer _server;
        readonly IHostApplicationLifetime _lifetime;
        readonly ILogger<OnboardingAgentService> _log;
        readonly HashSet<string> _quietSaid = new(StringComparer.Ordinal);
        static readonly TimeSpan HandoverLifetime = TimeSpan.FromMinutes(60);

        // The runtime is asked for once there is work, not here: see AgentGate.
        public OnboardingAgentService(IServiceProvider services, IServer server, IHostApplicationLifetime lifetime, ILogger<OnboardingAgentService> log)
        {
            _services = services;
            _server = server;
            _lifetime = lifetime;
            _log = log;
        }

        protected override async Task ExecuteAsync(CancellationToken stopping)
        {
            var options = _services.GetRequiredService<IOptions<ArkOnboardingAgentOptions>>().Value;
            if (!options.Enabled) return;
            try
            {
                var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                using (_lifetime.ApplicationStarted.Register(() => started.TrySetResult()))
                using (stopping.Register(() => started.TrySetCanceled()))
                    await started.Task;

                var config = _services.GetRequiredService<IConfiguration>();
                if (!AgentGate.HasWork(config, options))
                {
                    // Configured between two runs: what the last one collected about people is not needed.
                    if (AgentGate.Configured(config)) Workspace.Discard(AgentGate.DataDirectory(config, _services.GetRequiredService<IHostEnvironment>()));
                    _log.LogDebug("Onboarding agent: this identity server is set up, or offers no setup tools. Nothing to do.");
                    return;
                }

                _rt = _services.GetRequiredService<AgentRuntime>();
                _rt.SelfUrl = ChooseAddress();
                var ws = _rt.Workspace;
                var announced = false;
                var since = DateTime.UtcNow;
                while (!stopping.IsCancellationRequested)
                {
                    try
                    {
                        await TickAsync(stopping);
                        if (ws.Phase == AgentPhase.Collecting && !announced)
                        {
                            announced = true;
                            _log.LogWarning(
                                "Onboarding agent: ready. Open {Path} on this server (the setup wizard links to it) and set it up by conversation. " +
                                "I hold the setup code (from {From}); from another machine you will be asked for it once.",
                                _rt.Prefix, _rt.Code.From);
                        }
                    }
                    catch (McpUnauthorizedException) when (ws.Phase == AgentPhase.Collecting)
                    {
                        // The code stopped working while collecting: setup was finished by another route.
                        ws.SetPhase(AgentPhase.NotNeeded);
                        ws.Forget();
                    }
                    catch (Exception ex) when (ex is McpException or McpUnauthorizedException or HttpRequestException or JsonException)
                    {
                        ws.StartingWhy = ex.Message;
                        ws.Touch();
                    }
                    if (ws.Phase == AgentPhase.NotNeeded) return;
                    // Quick while the server comes up. One that cannot be reached after a minute is not asked every second for ever.
                    var quick = ws.Phase == AgentPhase.Starting && DateTime.UtcNow - since < TimeSpan.FromMinutes(1);
                    await Task.Delay(TimeSpan.FromSeconds(quick ? 1 : 15), stopping);
                }
            }
            catch (OperationCanceledException) { }
        }

        async Task TickAsync(CancellationToken cancel)
        {
            var ws = _rt.Workspace;
            if (ws.Phase == AgentPhase.Installed)
            {
                // The one-time secrets wait for the lead, not for ever.
                if (DateTime.UtcNow - ws.HandoverSince < HandoverLifetime) return;
                ws.Handover = null;
                ws.SetPhase(AgentPhase.NotNeeded);
                _log.LogInformation("Onboarding agent: the hand-over was not confirmed within {Minutes} minutes and has been forgotten.", HandoverLifetime.TotalMinutes);
                return;
            }
            if (_rt.ServerConfigured)
            {
                // Finished by the wizard, or by an operator who configured the host.
                ws.SetPhase(AgentPhase.NotNeeded);
                ws.Forget();
                _log.LogInformation("Onboarding agent: the server was set up by another route. Nothing left to do.");
                return;
            }

            if (ws.Phase == AgentPhase.Starting)
            {
                _rt.ReadCodeFile();
                if (_rt.McpUrl == null) { ws.StartingWhy = "I do not know which address this server listens on. Set ark_onboarding_agent:McpUrl."; return; }
                if (_rt.Code.Code == null && !_rt.SameProcess)
                {
                    ws.StartingWhy = "I was pointed at an identity server elsewhere (McpUrl) and need its setup code: set ark_onboarding_agent:SetupCode to the code in that server's start-up log.";
                    return;
                }
                if (_rt.Code.Code == null)
                {
                    // The server writes its code when the first request reaches it. This one does.
                    await Nudge(cancel);
                    _rt.ReadCodeFile();
                    if (_rt.Code.Code == null) { ws.StartingWhy = "Waiting for the identity server to announce its setup code."; return; }
                }

                var (name, version, _) = await _rt.Mcp.InitializeAsync(cancel);
                if (name != "ark-idp-setup")
                {
                    ws.StartingWhy = $"{_rt.McpUrl} is “{name}”, not a server waiting to be set up.";
                    if (name.StartsWith("ark-idp", StringComparison.Ordinal)) ws.SetPhase(AgentPhase.NotNeeded);
                    return;
                }
                ws.Open(_rt.DataDirectory);
                ws.Environment = Advisor.Scout(_rt.Configuration, _rt.Environment, ws.Vault, _rt.Options.LookForDatabases);
                ws.Environment["identity_server_version"] = version;
                await _rt.Brain.RefreshAsync(cancel);
                _rt.Connected = true;
                ws.SetPhase(AgentPhase.Collecting);
                return;
            }

            // Collecting: keep the board true to the server, whoever changed it.
            var before = ws.Status["draft_updated_at"]?.ToString();
            await _rt.Brain.RefreshAsync(cancel);
            var changed = before != ws.Status["draft_updated_at"]?.ToString();

            var now = DateTime.UtcNow;
            lock (ws.Sync)
            {
                foreach (var invite in ws.Invites.Where(i => !i.Revoked && i.AnsweredAt == null && i.OpenedAt == null))
                {
                    var quiet = now - invite.CreatedAt > TimeSpan.FromHours(_rt.Options.QuietAfterHours) && now < invite.ExpiresAt;
                    if (!quiet || !_quietSaid.Add(invite.Id)) continue;
                    ws.Log($"No answer yet from {invite.Name ?? "the colleague"} in {invite.Department} ({string.Join(", ", invite.Sections)}). The link has not been opened.");
                    changed = true;
                }
            }
            if (changed) ws.Touch();
        }

        /// <summary>One request to this server, so that it builds its pipeline's first response and writes the code.</summary>
        async Task Nudge(CancellationToken cancel)
        {
            if (_rt.SelfUrl == null) return;
            try
            {
                using var http = new HttpClient(new HttpClientHandler
                {
                    AllowAutoRedirect = false,
                    ServerCertificateCustomValidationCallback = (m, _, _, e) => e == System.Net.Security.SslPolicyErrors.None || m.RequestUri?.IsLoopback == true
                }) { Timeout = TimeSpan.FromSeconds(10) };
                using var _ = await http.GetAsync(_rt.SelfUrl.TrimEnd('/') + "/ark-idp/mcp/server-card", cancel);
            }
            catch (HttpRequestException) { }
            catch (TaskCanceledException) when (!cancel.IsCancellationRequested) { }
        }

        /// <summary>
        /// An address of this server the agent can call. https before http: a host that redirects
        /// http to https would answer a POST with a redirect, and a redirect drops the bearer token.
        /// </summary>
        string? ChooseAddress()
        {
            var addresses = _server.Features.Get<IServerAddressesFeature>()?.Addresses ?? Array.Empty<string>();
            string? best = null;
            foreach (var raw in addresses)
            {
                var address = raw.Replace("://+", "://localhost").Replace("://*", "://localhost")
                    .Replace("://0.0.0.0", "://localhost").Replace("://[::]", "://localhost");
                if (!Uri.TryCreate(address, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https")) continue;
                if (best == null || (uri.Scheme == "https" && !best.StartsWith("https", StringComparison.Ordinal))) best = uri.GetLeftPart(UriPartial.Authority);
            }
            return best;
        }
    }

    /// <summary>Who is at the other end of a request: the lead, a colleague with a link, or nobody yet.</summary>
    internal sealed class AgentAccess
    {
        public const string Cookie = "ark_agent";
        readonly AgentRuntime _rt;
        int _failures;
        DateTime _window = DateTime.UtcNow;

        public AgentAccess(AgentRuntime runtime) => _rt = runtime;

        /// <summary>
        /// The setup wizard's own rule for "a person at this machine": a Development server, a
        /// loopback connection, no forwarding headers, a loopback host name. Anyone else proves they
        /// can see the server by entering its setup code, as they would for the wizard.
        ///
        /// Development only, because outside it loopback proves nothing: a proxy on the same host
        /// that forwards neither the visitor's address nor the name they asked for (nginx's bare
        /// proxy_pass) makes everybody on the internet look like this.
        /// </summary>
        public bool IsLocal(HttpContext context)
        {
            if (!_rt.SameProcess || !_rt.Environment.IsDevelopment()) return false;
            if (_rt.Configuration.GetValue("ark_oauth_server:Setup:RequireToken", false)) return false;
            var remote = context.Connection.RemoteIpAddress;
            if (remote == null || !IPAddress.IsLoopback(remote)) return false;
            var h = context.Request.Headers;
            // X-Original-*: what ASP.NET Core's forwarded-headers middleware leaves behind when it has already used the header.
            foreach (var relayed in new[] { "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded", "X-Real-IP", "X-Original-For", "X-Original-Host", "X-Original-Proto" })
                if (h.ContainsKey(relayed)) return false;
            var host = context.Request.Host.Host.Trim('[', ']');
            return string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase) || (IPAddress.TryParse(host, out var named) && IPAddress.IsLoopback(named));
        }

        public bool CodeMatches(string? given)
        {
            lock (this)
            {
                if (DateTime.UtcNow - _window > TimeSpan.FromMinutes(1)) { _window = DateTime.UtcNow; _failures = 0; }
                if (_failures >= 10) return false;
                var expected = _rt.Code.Code;
                var ok = expected != null && CryptographicOperations.FixedTimeEquals(
                    Encoding.UTF8.GetBytes((given ?? "").Trim().ToUpperInvariant().PadRight(64)[..64]), Encoding.UTF8.GetBytes(expected.PadRight(64)[..64]));
                if (!ok) _failures++;
                return ok;
            }
        }

        // ---- signed values: "payload.signature", both base64url

        public string? Sign(JsonObject payload)
        {
            if (_rt.Code.SigningKey is not { } key) return null;
            var body = Base64Url(Encoding.UTF8.GetBytes(payload.ToJsonString()));
            return body + "." + Base64Url(HMACSHA256.HashData(key, Encoding.ASCII.GetBytes(body)));
        }

        public JsonObject? Verify(string? token)
        {
            if (string.IsNullOrEmpty(token) || _rt.Code.SigningKey is not { } key) return null;
            var dot = token.IndexOf('.');
            if (dot <= 0) return null;
            var body = token[..dot];
            try
            {
                var given = FromBase64Url(token[(dot + 1)..]);
                if (!CryptographicOperations.FixedTimeEquals(given, HMACSHA256.HashData(key, Encoding.ASCII.GetBytes(body)))) return null;
                var payload = JsonNode.Parse(Encoding.UTF8.GetString(FromBase64Url(body))) as JsonObject;
                if (payload?["exp"]?.GetValue<long>() is { } exp && DateTimeOffset.UtcNow.ToUnixTimeSeconds() > exp) return null;
                return payload;
            }
            catch (Exception ex) when (ex is FormatException or JsonException or InvalidOperationException) { return null; }
        }

        static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        static byte[] FromBase64Url(string text)
        {
            text = text.Replace('-', '+').Replace('_', '/');
            return Convert.FromBase64String(text.PadRight(text.Length + (4 - text.Length % 4) % 4, '='));
        }

        public string? InviteToken(Invite invite) => Sign(new JsonObject
        {
            ["k"] = "invite", ["i"] = invite.Id, ["exp"] = new DateTimeOffset(invite.ExpiresAt, TimeSpan.Zero).ToUnixTimeSeconds()
        });

        /// <summary>The participant of this request, from its cookie. Null: not signed in to the conversation.</summary>
        public Participant? Who(HttpContext context)
        {
            if (Verify(context.Request.Cookies[Cookie]) is not { } payload || payload["k"]?.ToString() != "person") return null;
            var id = payload["p"]?.ToString() ?? "";
            var ws = _rt.Workspace;
            lock (ws.Sync)
            {
                if (ws.People.TryGetValue(id, out var known))
                {
                    // A colleague whose link was withdrawn is out, whatever their cookie says.
                    // So is one whose link has run out: a cookie does not outlive what it was given for.
                    if (known.InviteId != null && !Live(ws.Invites.FirstOrDefault(i => i.Id == known.InviteId))) return null;
                    return known;
                }
                // Signed by this server, but not in the state file: the conversation was lost, the person was not.
                var restored = new Participant { Id = id, Role = payload["r"]?.ToString() ?? "lead", InviteId = payload["i"]?.ToString() };
                if (restored.InviteId != null)
                {
                    if (ws.Invites.FirstOrDefault(i => i.Id == restored.InviteId) is not { } invite || !Live(invite)) return null;
                    restored.Role = "contributor";
                    restored.Sections = invite.Sections.ToList();
                    restored.Department = invite.Department;
                }
                else if (restored.Role != "lead") return null;
                ws.People[id] = restored;
                return restored;
            }
        }

        static bool Live(Invite? invite) => invite is { Revoked: false } && DateTime.UtcNow <= invite.ExpiresAt;

        /// <summary>Whether the browser's connection is encrypted, here or at the proxy in front.</summary>
        public static bool Encrypted(HttpContext context) =>
            context.Request.IsHttps || string.Equals(context.Request.Headers["X-Forwarded-Proto"].ToString().Split(',')[0].Trim(), "https", StringComparison.OrdinalIgnoreCase);

        public void SignIn(HttpContext context, Participant p)
        {
            var token = Sign(new JsonObject
            {
                ["k"] = "person", ["p"] = p.Id, ["r"] = p.Role, ["i"] = p.InviteId,
                ["exp"] = DateTimeOffset.UtcNow.AddDays(30).ToUnixTimeSeconds()
            });
            if (token == null) return;
            context.Response.Cookies.Append(Cookie, token, new CookieOptions
            {
                HttpOnly = true,
                // Lax, not Strict: a colleague arrives by a link in an email, and the redirect that
                // follows it has to carry the cookie the link just set.
                SameSite = SameSiteMode.Lax,
                // The agent is first in the pipeline, before anything has read the proxy's headers for it.
                Secure = Encrypted(context),
                Path = $"{context.Request.PathBase}{_rt.Prefix}",
                MaxAge = TimeSpan.FromDays(30),
                IsEssential = true
            });
        }
    }
}
