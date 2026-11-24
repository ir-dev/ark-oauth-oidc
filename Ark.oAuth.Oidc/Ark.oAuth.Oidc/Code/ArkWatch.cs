using System.Diagnostics;
using System.Reflection;
using System.Security.Claims;
using Ark.Watch.Client;
using Ark.Watch.Core;

namespace Ark.oAuth.Oidc
{
    /// <summary>The business areas the provider's audit events are filed under.</summary>
    public static class ArkWatchDomains
    {
        /// <summary>People signing in and out, and the refusals on the way.</summary>
        public const string SignIn = "SignIn";
        /// <summary>Codes, tokens, device and pushed requests, revocation.</summary>
        public const string Tokens = "Tokens";
        /// <summary>Agent-to-agent: tokens addressed to an agent, delegation, the caller lists.</summary>
        public const string Agents = "Agents";
        /// <summary>Changes made through the console, the management API or provisioning.</summary>
        public const string Administration = "Administration";
        /// <summary>The server itself: setup, schema, data import and export, faults.</summary>
        public const string System = "System";
    }

    /// <summary>
    /// One audit event as the provider describes it, before it is handed to ARK-RAPID Watch.
    ///
    /// Who (<see cref="ParticipantId"/>), did what (<see cref="Action"/>, a stable
    /// <c>noun.verb</c>), to what (<see cref="ResourceType"/> and <see cref="ResourceId"/>), and
    /// how it ended (<see cref="Outcome"/>). Ids go in the resource and the attributes, never in
    /// the action, so one action can be counted across every client and user.
    /// </summary>
    public sealed class ArkWatchEvent
    {
        public string Action { get; set; } = "";
        public string? Message { get; set; }
        public string Domain { get; set; } = ArkWatchDomains.System;
        /// <summary>The part of the server the event came from, e.g. <c>token-endpoint</c>.</summary>
        public string? System { get; set; }
        public AuditLevel Level { get; set; } = AuditLevel.Info;
        public Outcome Outcome { get; set; } = Outcome.Success;
        /// <summary>The tenant the participant belongs to.</summary>
        public string? Tenant { get; set; }
        public string? ParticipantId { get; set; }
        /// <summary><c>user</c>, <c>service</c> (a client or an agent), <c>device</c> or <c>system</c>.</summary>
        public string? ParticipantType { get; set; }
        public string? ParticipantName { get; set; }
        public string? ResourceType { get; set; }
        public string? ResourceId { get; set; }
        /// <summary>
        /// Part of the high-volume protocol trace rather than a statement of who did what, and so
        /// left out when <c>ark_oauth_server:Watch:IncludeProtocolTrace</c> is false.
        /// </summary>
        public bool ProtocolTrace { get; set; }
        public Dictionary<string, object?> Attributes { get; } = new(StringComparer.Ordinal);

        /// <summary>Adds an attribute, unless it has no value: an absent fact is not recorded as null.</summary>
        public ArkWatchEvent With(string key, object? value)
        {
            if (value == null) return this;
            if (value is string text && text.Length == 0) return this;
            if (value is global::System.Collections.ICollection { Count: 0 }) return this;
            Attributes[key] = value;
            return this;
        }
    }

    /// <summary>What the console shows about the audit trail: whether it is on, and how it is doing.</summary>
    public sealed class ArkWatchStatus
    {
        public bool enabled { get; set; }
        /// <summary>Why nothing is sent, when nothing is.</summary>
        public string? reason { get; set; }
        public string? endpoint { get; set; }
        public string? application { get; set; }
        public string? environment { get; set; }
        public bool spool { get; set; }
        public bool protocol_trace { get; set; }
        public long logged { get; set; }
        public long sent { get; set; }
        public long spooled { get; set; }
        public long replayed { get; set; }
        public long rejected { get; set; }
        public long dropped { get; set; }
        public long send_failures { get; set; }
        public string? breaker { get; set; }
        /// <summary><c>ok</c>, <c>waiting</c> (events are held until the node answers) or <c>losing</c>.</summary>
        public string? health { get; set; }
    }

    /// <summary>
    /// The provider's audit trail, sent to an ARK-RAPID Watch node.
    ///
    /// Optional, and nothing at all until <c>ark_oauth_server:Watch</c> has an endpoint and a key:
    /// no client is constructed, no thread started, no spool folder made. Once it has them — from
    /// the setup wizard, a settings file or the environment — the client is built on the first
    /// event, and rebuilt when those settings change, with no restart.
    ///
    /// <see cref="Log"/> is safe to call from anywhere on a request: it writes to an in-memory
    /// ring and returns, it never blocks on the network and it never throws. A node that is down
    /// costs a request nothing; the events wait in the spool and are replayed in order.
    /// </summary>
    public sealed class ArkWatchAudit : IAsyncDisposable, IDisposable
    {
        private const int MaxText = 2000;

        private readonly IConfiguration _config;
        private readonly IHostEnvironment _env;
        private readonly ILogger<ArkWatchAudit> _log;
        private readonly IServiceProvider _services;
        private readonly object _gate = new();

        // The configuration object the current client was built from. ArkConfigSnapshot binds a new
        // one on every reload, so a reference comparison is the whole cost of "has it changed".
        private ArkWatchConfig? _boundTo;
        private ArkWatchClient? _client;
        private string _signature = "";
        private string? _reason = "not configured";
        private bool _includeTrace = true;
        private bool _spool;
        private bool _disposed;

        public ArkWatchAudit(IConfiguration config, IHostEnvironment env, ILogger<ArkWatchAudit> log, IServiceProvider services)
        {
            _config = config;
            _env = env;
            _log = log;
            _services = services;
        }

        /// <summary>Whether events are being sent anywhere.</summary>
        public bool Enabled => Current() != null;

        /// <summary>
        /// Records an event. <paramref name="http"/> supplies the caller's address, the
        /// correlation id and — when the event names nobody — the signed-in operator; without one
        /// the current request is used when there is one.
        /// </summary>
        public void Log(HttpContext? http, ArkWatchEvent e)
        {
            try
            {
                var client = Current();
                if (client == null || e == null || string.IsNullOrWhiteSpace(e.Action)) return;
                if (e.ProtocolTrace && !_includeTrace) return;

                http ??= (_services.GetService(typeof(IHttpContextAccessor)) as IHttpContextAccessor)?.HttpContext;

                var participantId = e.ParticipantId;
                var participantType = e.ParticipantType;
                var participantName = e.ParticipantName;
                if (string.IsNullOrWhiteSpace(participantId) && Operator(http) is { } who)
                {
                    participantId = who.id;
                    participantType = who.type;
                    participantName ??= who.name;
                }

                if (http != null)
                {
                    var agent = http.Request.Headers.UserAgent.ToString();
                    if (agent.Length > 0 && !e.Attributes.ContainsKey("user_agent"))
                        e.Attributes["user_agent"] = Clip(agent, 200);
                }
                if (!string.IsNullOrWhiteSpace(e.Tenant) && !e.Attributes.ContainsKey("tenant"))
                    e.Attributes["tenant"] = e.Tenant;

                var entry = new AuditEntry
                {
                    Level = e.Level,
                    Outcome = e.Outcome,
                    Action = e.Action,
                    Message = Clip(e.Message, MaxText),
                    Domain = e.Domain,
                    System = e.System,
                    ParticipantId = Clip(participantId, 256),
                    ParticipantType = string.IsNullOrWhiteSpace(participantId) ? null : participantType ?? ParticipantTypes.Service,
                    ParticipantName = Clip(participantName, 256),
                    ParticipantTenant = e.Tenant,
                    ResourceType = e.ResourceType,
                    ResourceId = Clip(e.ResourceId, 256),
                    CorrelationId = Correlation(http),
                    Ip = Address(http),
                    Attributes = e.Attributes.Count > 0 ? e.Attributes : null
                };
                client.Log(in entry);
            }
            catch
            {
                // An audit event is never a reason for the identity provider to fail a request.
            }
        }

        /// <summary>Sends what is buffered. True when delivered, or safe in the spool while the node is away.</summary>
        public async Task<bool> FlushAsync(TimeSpan timeout)
        {
            try
            {
                var client = Current();
                return client == null || await client.FlushAsync(timeout);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>The state of the trail, for the console. Carries no key.</summary>
        public ArkWatchStatus Status()
        {
            var status = new ArkWatchStatus();
            try
            {
                var client = Current();
                var cfg = _boundTo;
                status.enabled = client != null;
                status.reason = client == null ? _reason : null;
                status.protocol_trace = _includeTrace;
                status.spool = _spool;
                if (cfg != null && client != null)
                {
                    status.endpoint = Uri.TryCreate((cfg.Endpoint ?? "").Trim(), UriKind.Absolute, out var uri)
                        ? uri.GetLeftPart(UriPartial.Path) : null;
                    status.application = Application(cfg);
                    status.environment = EnvironmentName(cfg);
                    var s = client.GetStats();
                    status.logged = s.Logged;
                    status.sent = s.Sent;
                    status.spooled = s.Spooled;
                    status.replayed = s.Replayed;
                    status.rejected = s.Rejected;
                    status.dropped = s.Dropped;
                    status.send_failures = s.SendFailures;
                    status.breaker = s.BreakerState;
                    status.health = s.Dropped > 0 || s.Rejected > 0 ? "losing"
                        : !string.Equals(s.BreakerState, "Closed", StringComparison.OrdinalIgnoreCase) ? "waiting"
                        : "ok";
                }
            }
            catch
            {
                // The status is a convenience; it says nothing rather than failing the page.
            }
            return status;
        }

        // ---------------------------------------------------------------- the client

        private ArkWatchClient? Current()
        {
            if (_disposed) return null;
            var cfg = Protocol.ArkConfigSnapshot.Server(_config)?.Watch;
            if (ReferenceEquals(cfg, Volatile.Read(ref _boundTo))) return Volatile.Read(ref _client);

            lock (_gate)
            {
                if (_disposed) return null;
                if (ReferenceEquals(cfg, _boundTo)) return _client;

                var signature = Signature(cfg);
                // An empty signature is "nothing to send to". It is still worked out afresh, so
                // the reason the console gives — not configured, turned off, no key — is the
                // current one.
                if (signature != _signature || signature.Length == 0)
                {
                    // The old client is flushed and closed before the new one opens: two clients
                    // must never share a spool folder. Bounded by its shutdown timeout, and only
                    // ever on a change of these settings.
                    var old = _client;
                    _client = null;
                    if (old != null)
                    {
                        try { old.Dispose(); } catch { }
                    }
                    _client = Build(cfg);
                    _signature = signature;
                }
                _includeTrace = cfg?.IncludeProtocolTrace ?? true;
                Volatile.Write(ref _boundTo, cfg);
                return _client;
            }
        }

        private static string Signature(ArkWatchConfig? cfg) =>
            cfg == null || !cfg.IsConfigured
                ? ""
                : string.Join("\n", cfg.Endpoint?.Trim(), cfg.ApiKey?.Trim(), cfg.Application?.Trim(),
                    cfg.Environment?.Trim(), cfg.SpoolDirectory?.Trim());

        private ArkWatchClient? Build(ArkWatchConfig? cfg)
        {
            _spool = false;
            if (cfg == null || !cfg.Enabled)
            {
                _reason = cfg == null ? "not configured" : "turned off (ark_oauth_server:Watch:Enabled is false)";
                return null;
            }
            if (!cfg.IsConfigured)
            {
                var anything = !string.IsNullOrWhiteSpace(cfg.Endpoint) || !string.IsNullOrWhiteSpace(cfg.ApiKey);
                _reason = !anything ? "not configured"
                    : string.IsNullOrWhiteSpace(cfg.ApiKey) ? "no API key (ark_oauth_server:Watch:ApiKey)"
                    : "no usable endpoint (ark_oauth_server:Watch:Endpoint must be an http(s) address)";
                if (anything) _log.LogWarning("Ark IdP audit trail is not being sent: {Reason}.", _reason);
                return null;
            }

            try
            {
                var endpoint = cfg.Endpoint!.Trim();
                // A node hosted under a path is addressed with a trailing slash, or the last
                // segment is dropped when the events path is appended.
                if (!endpoint.EndsWith('/')) endpoint += "/";
                var spool = SpoolDirectory(cfg);
                _spool = spool != null;

                var client = new ArkWatchClient(new ArkWatchClientOptions
                {
                    Endpoint = new Uri(endpoint),
                    ApiKey = cfg.ApiKey!.Trim(),
                    Application = Application(cfg),
                    AppVersion = PackageVersion,
                    Environment = EnvironmentName(cfg),
                    DefaultDomain = ArkWatchDomains.System,
                    DefaultSystem = "ark-idp",
                    SpoolDirectory = spool
                });
                _reason = null;
                _log.LogInformation(
                    "Ark IdP audit trail: sending to ARK-RAPID Watch at {Endpoint} as application {Application}{Spool}.",
                    new Uri(endpoint).GetLeftPart(UriPartial.Path), Application(cfg),
                    spool == null ? ", with no spool (events are held in memory while the node is away)" : $", spool in {spool}");
                return client;
            }
            catch (Exception ex)
            {
                _reason = $"the client could not be started: {ex.Message}";
                _log.LogWarning(ex, "Ark IdP audit trail could not be started; nothing is being sent.");
                return null;
            }
        }

        private static string Application(ArkWatchConfig cfg) =>
            string.IsNullOrWhiteSpace(cfg.Application) ? ArkWatchConfig.DefaultApplication : cfg.Application.Trim();

        private string EnvironmentName(ArkWatchConfig cfg) =>
            string.IsNullOrWhiteSpace(cfg.Environment) ? _env.EnvironmentName : cfg.Environment.Trim();

        /// <summary>
        /// Where events wait while the node is away: the configured folder, or one per machine
        /// under the setup data directory. Null — memory only — when it is switched off or the
        /// folder cannot be written; a trail that cannot spool still sends.
        /// </summary>
        private string? SpoolDirectory(ArkWatchConfig cfg)
        {
            var configured = (cfg.SpoolDirectory ?? "").Trim();
            if (configured.Equals("none", StringComparison.OrdinalIgnoreCase) || configured.Equals("off", StringComparison.OrdinalIgnoreCase))
                return null;
            var path = configured.Length > 0
                ? (Path.IsPathRooted(configured) ? configured : Path.Combine(_env.ContentRootPath, configured))
                : Path.Combine(ArkIdpSettings.DataDirectory(_config, _env), "watch-spool", SafeName(System.Environment.MachineName));
            try
            {
                path = Path.GetFullPath(path);
                Directory.CreateDirectory(path);
                // The default folder sits beside the settings, which ignore themselves; a folder
                // of its own under the content root gets the same treatment.
                if (configured.Length == 0) ArkIdpSettings.EnsureIgnored(ArkIdpSettings.DataDirectory(_config, _env));
                var probe = Path.Combine(path, $".write-test-{Guid.NewGuid():N}");
                File.WriteAllText(probe, "");
                File.Delete(probe);
                return path;
            }
            catch (Exception ex)
            {
                _log.LogWarning(
                    "Ark IdP audit trail: the spool folder {Path} cannot be written ({Error}). Events are held in memory only while the node is away. " +
                    "Set ark_oauth_server:Watch:SpoolDirectory to a writable folder.", path, ex.Message);
                return null;
            }
        }

        private static string SafeName(string value)
        {
            var chars = (value ?? "").Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' or '.' ? c : '_').ToArray();
            return chars.Length == 0 ? "host" : new string(chars);
        }

        internal static readonly string PackageVersion = ReadPackageVersion();

        private static string ReadPackageVersion()
        {
            var assembly = typeof(ArkWatchAudit).Assembly;
            var v = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                    ?? assembly.GetName().Version?.ToString() ?? "";
            var plus = v.IndexOf('+');
            return plus < 0 ? v : v[..plus];
        }

        // ---------------------------------------------------------------- request context

        /// <summary>
        /// Whoever is signed in on this request: a console operator, or the machine client of the
        /// management API. Null on the protocol endpoints, where clients authenticate in the body.
        /// </summary>
        internal static (string id, string type, string? name)? Operator(HttpContext? http)
        {
            try
            {
                var user = http?.User;
                if (user?.Identity?.IsAuthenticated != true) return null;
                var subject = First(user, "sub") ?? First(user, ClaimTypes.NameIdentifier) ?? First(user, "preferred_username")
                              ?? First(user, "email") ?? user.Identity.Name;
                if (string.IsNullOrWhiteSpace(subject)) return null;
                // A machine token's subject is the client itself.
                var clientId = First(user, "client_id");
                var machine = !string.IsNullOrEmpty(clientId) && string.Equals(clientId, subject, StringComparison.OrdinalIgnoreCase);
                return (subject!, machine ? ParticipantTypes.Service : ParticipantTypes.User, First(user, "name"));
            }
            catch
            {
                return null;
            }
        }

        /// <summary>Who is acting and from where, for the audit rows written to the database.</summary>
        internal (string? who, string? ip) Caller()
        {
            try
            {
                var http = (_services.GetService(typeof(IHttpContextAccessor)) as IHttpContextAccessor)?.HttpContext;
                return (Operator(http)?.id, Address(http));
            }
            catch
            {
                return (null, null);
            }
        }

        private static string? First(ClaimsPrincipal user, string type)
        {
            var value = user.FindFirst(type)?.Value;
            return string.IsNullOrWhiteSpace(value) ? null : value;
        }

        /// <summary>The caller's address as the host sees it. A node rejects an event whose ip is not one.</summary>
        internal static string? Address(HttpContext? http)
        {
            try
            {
                var ip = http?.Connection.RemoteIpAddress;
                if (ip == null) return null;
                return (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString();
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// One value for everything a request does: the caller's <c>X-Correlation-ID</c> when it
        /// sent a sane one, else the W3C trace id, else the server's own request id. An agent that
        /// forwards the header ties the provider's events to its own.
        /// </summary>
        internal static string? Correlation(HttpContext? http)
        {
            try
            {
                var header = http?.Request.Headers["X-Correlation-ID"].ToString();
                if (!string.IsNullOrEmpty(header) && header.Length <= 128
                    && header.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or ':'))
                    return header;
                var activity = Activity.Current;
                if (activity != null && activity.IdFormat == ActivityIdFormat.W3C) return activity.TraceId.ToString();
                return http?.TraceIdentifier;
            }
            catch
            {
                return null;
            }
        }

        private static string? Clip(string? value, int max) =>
            string.IsNullOrEmpty(value) || value.Length <= max ? value : value[..max] + "…";

        // ---------------------------------------------------------------- shutdown

        public async ValueTask DisposeAsync()
        {
            ArkWatchClient? client;
            lock (_gate)
            {
                if (_disposed) return;
                _disposed = true;
                client = _client;
                _client = null;
            }
            if (client == null) return;
            // Disposal flushes: what the provider recorded in its last moments reaches the node
            // or the spool before the process ends.
            try { await client.DisposeAsync(); } catch { }
        }

        public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Opens the trail when the host starts and marks the two ends of its life on it.
    ///
    /// The client is otherwise built by the first event, which on a quiet server may be a long
    /// time coming — and until it is built, whatever an earlier run left in the spool stays
    /// there. Recording the start builds it at once, so a server that was restarted during an
    /// outage of the audit server delivers what it was holding as soon as it is back, traffic or
    /// not. And "the identity provider was restarted at 02:14 on this machine" is itself a fact
    /// an audit trail should hold. Unconfigured, both calls do nothing.
    /// </summary>
    internal sealed class ArkWatchLifetime : IHostedService
    {
        private readonly ArkWatchAudit _audit;

        public ArkWatchLifetime(ArkWatchAudit audit) => _audit = audit;

        public Task StartAsync(CancellationToken cancellationToken)
        {
            _audit.Log(null, Event("idp.start", $"identity provider started (Ark.oAuth.Oidc {ArkWatchAudit.PackageVersion})"));
            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            // Flushed when the container disposes the trail, after the server has stopped
            // taking requests.
            _audit.Log(null, Event("idp.stop", "identity provider stopping"));
            return Task.CompletedTask;
        }

        private static ArkWatchEvent Event(string action, string message) =>
            new ArkWatchEvent
            {
                Action = action,
                Domain = ArkWatchDomains.System,
                System = "host",
                Level = AuditLevel.Notice,
                Outcome = Outcome.Success,
                Message = message
            }.With("version", ArkWatchAudit.PackageVersion).With("process_id", Environment.ProcessId);
    }

    /// <summary>
    /// The one call the provider's own code records an audit event with.
    ///
    /// Resolves <see cref="ArkWatchAudit"/> from the request, so a host that registered the
    /// services some other way gets a null back and nothing happens; it cannot throw; and what it
    /// reaches only ever writes to an in-memory ring.
    /// </summary>
    public static class ArkWatch
    {
        public static void Record(HttpContext? http, ArkWatchEvent e)
        {
            try
            {
                if (http?.RequestServices.GetService(typeof(ArkWatchAudit)) is ArkWatchAudit audit) audit.Log(http, e);
            }
            catch
            {
                // Never a reason for the identity provider to fail.
            }
        }

        /// <summary>Whether a trail is configured, so a caller can skip building an expensive event.</summary>
        public static bool Enabled(HttpContext? http)
        {
            try { return http?.RequestServices.GetService(typeof(ArkWatchAudit)) is ArkWatchAudit { Enabled: true }; }
            catch { return false; }
        }
    }

    /// <summary>
    /// Turns a row of the provider's own audit trace into a structured event.
    ///
    /// Every <c>DataAccess.Log</c> call names what happened with a short key (<c>signin_failed</c>,
    /// <c>client_upsert</c>) and describes it in a sentence. The table here says what each key
    /// means in the terms an audit server searches by — action, level, outcome — so every line the
    /// provider already writes, and any it gains later, reaches the trail without the call site
    /// knowing the trail exists. A site that has more to say passes its own event instead.
    /// </summary>
    internal static class ArkWatchMap
    {
        private sealed record Rule(
            string Action, string Domain, AuditLevel Level, Outcome Outcome, string? System = null,
            string? Resource = null, bool Trace = false);

        private const string OAuth = "oauth2";
        private const string Api = "management-api";
        private const string Host = "host";

        private static readonly Dictionary<string, Rule> Rules = new(StringComparer.OrdinalIgnoreCase)
        {
            // --- sign-in ---
            ["signin"] = new("user.signin", ArkWatchDomains.SignIn, AuditLevel.Security, Outcome.Success, OAuth),
            ["signin_failed"] = new("user.signin", ArkWatchDomains.SignIn, AuditLevel.Security, Outcome.Failure, OAuth),
            ["signin_lockout"] = new("user.signin", ArkWatchDomains.SignIn, AuditLevel.Security, Outcome.Denied, OAuth),
            ["signin_inactive"] = new("user.signin", ArkWatchDomains.SignIn, AuditLevel.Security, Outcome.Denied, OAuth),
            ["signin_no_access"] = new("user.signin", ArkWatchDomains.SignIn, AuditLevel.Security, Outcome.Denied, OAuth),
            ["signin_busy"] = new("user.signin", ArkWatchDomains.SignIn, AuditLevel.Warning, Outcome.Failure, OAuth),
            ["logout"] = new("session.end", ArkWatchDomains.SignIn, AuditLevel.Notice, Outcome.Success, OAuth),
            ["backchannel_logout"] = new("session.notify", ArkWatchDomains.SignIn, AuditLevel.Info, Outcome.Success, OAuth, Trace: true),
            ["backchannel_logout_failed"] = new("session.notify", ArkWatchDomains.SignIn, AuditLevel.Warning, Outcome.Failure, OAuth),

            // --- protocol ---
            ["authorize"] = new("authorization.grant", ArkWatchDomains.Tokens, AuditLevel.Info, Outcome.Success, OAuth, Trace: true),
            ["par"] = new("authorization.push", ArkWatchDomains.Tokens, AuditLevel.Info, Outcome.Success, OAuth, Trace: true),
            ["token"] = new("token.issue", ArkWatchDomains.Tokens, AuditLevel.Info, Outcome.Success, OAuth, Trace: true),
            ["revoke"] = new("token.revoke", ArkWatchDomains.Tokens, AuditLevel.Security, Outcome.Success, OAuth),
            ["device_authorization"] = new("device.request", ArkWatchDomains.Tokens, AuditLevel.Info, Outcome.Success, OAuth, Trace: true),
            ["device_approved"] = new("device.approve", ArkWatchDomains.Tokens, AuditLevel.Security, Outcome.Success, OAuth),
            ["device_no_access"] = new("device.approve", ArkWatchDomains.Tokens, AuditLevel.Security, Outcome.Denied, OAuth),

            // --- administration ---
            ["client_register"] = new("client.register", ArkWatchDomains.Administration, AuditLevel.Security, Outcome.Success, OAuth),
            ["client_deregister"] = new("client.delete", ArkWatchDomains.Administration, AuditLevel.Security, Outcome.Success, OAuth),
            ["tenant_upsert"] = new("tenant.update", ArkWatchDomains.Administration, AuditLevel.Notice, Outcome.Success, Api, "tenant"),
            ["client_upsert"] = new("client.update", ArkWatchDomains.Administration, AuditLevel.Notice, Outcome.Success, Api, "client"),
            ["client_upsert_refused"] = new("client.update", ArkWatchDomains.Administration, AuditLevel.Warning, Outcome.Failure, Api),
            ["client_delete"] = new("client.delete", ArkWatchDomains.Administration, AuditLevel.Security, Outcome.Success, Api, "client"),
            ["client_secret_reset"] = new("client.secret_reset", ArkWatchDomains.Administration, AuditLevel.Security, Outcome.Success, Api, "client"),
            ["client_activation"] = new("client.activation", ArkWatchDomains.Administration, AuditLevel.Security, Outcome.Success, Api, "client"),
            ["claim_delete"] = new("claim.delete", ArkWatchDomains.Administration, AuditLevel.Notice, Outcome.Success, Api, "claim"),
            ["scope_upsert"] = new("scope.update", ArkWatchDomains.Administration, AuditLevel.Notice, Outcome.Success, Api, "scope"),
            ["scope_delete"] = new("scope.delete", ArkWatchDomains.Administration, AuditLevel.Notice, Outcome.Success, Api, "scope"),
            ["user_upsert"] = new("user.update", ArkWatchDomains.Administration, AuditLevel.Notice, Outcome.Success, Api),
            ["user_password_set"] = new("user.password_set", ArkWatchDomains.Administration, AuditLevel.Security, Outcome.Success, Api),
            ["user_activation"] = new("user.activation", ArkWatchDomains.Administration, AuditLevel.Security, Outcome.Success, Api, "user"),
            ["user_cl_cl_upsert"] = new("access.grant", ArkWatchDomains.Administration, AuditLevel.Security, Outcome.Success, Api),
            ["user_cl_cl_delete"] = new("access.revoke", ArkWatchDomains.Administration, AuditLevel.Security, Outcome.Success, Api),
            ["provision"] = new("client.provision", ArkWatchDomains.Administration, AuditLevel.Security, Outcome.Success, Api),
            ["provision_user"] = new("access.grant", ArkWatchDomains.Administration, AuditLevel.Security, Outcome.Success, Api),
            ["provision_refused"] = new("client.provision", ArkWatchDomains.Administration, AuditLevel.Warning, Outcome.Failure, Api),
            ["claim_upsert"] = new("claim.update", ArkWatchDomains.Administration, AuditLevel.Notice, Outcome.Success, Api, "claim"),
            ["user_unlock"] = new("user.unlock", ArkWatchDomains.Administration, AuditLevel.Security, Outcome.Success, Api, "user"),
            ["signing_key_rotate"] = new("signing_key.rotate", ArkWatchDomains.Administration, AuditLevel.Security, Outcome.Success, Api, "tenant"),
            ["signing_key_retire"] = new("signing_key.retire", ArkWatchDomains.Administration, AuditLevel.Security, Outcome.Success, Api, "tenant"),
            // The MCP endpoints pass their own event (ArkMcpAudit); these are for the row without one.
            ["mcp_call"] = new("mcp.tool_call", ArkWatchDomains.Administration, AuditLevel.Security, Outcome.Success, "mcp"),
            ["mcp_refused"] = new("mcp.tool_call", ArkWatchDomains.Administration, AuditLevel.Security, Outcome.Denied, "mcp"),

            // --- the server itself ---
            ["idp_setup"] = new("idp.setup", ArkWatchDomains.System, AuditLevel.Security, Outcome.Success, Host, "tenant"),
            ["schema_update"] = new("schema.update", ArkWatchDomains.System, AuditLevel.Notice, Outcome.Success, Host),
            ["schema_sync"] = new("schema.update", ArkWatchDomains.System, AuditLevel.Notice, Outcome.Success, Host),
            ["schema_baseline"] = new("schema.update", ArkWatchDomains.System, AuditLevel.Notice, Outcome.Success, Host),
            ["schema_index"] = new("schema.update", ArkWatchDomains.System, AuditLevel.Notice, Outcome.Success, Host),
            ["schema_index_skipped"] = new("schema.update", ArkWatchDomains.System, AuditLevel.Warning, Outcome.Failure, Host),
            ["migration"] = new("schema.migrate", ArkWatchDomains.System, AuditLevel.Notice, Outcome.Success, Host),
            ["migration_rollback"] = new("schema.rollback", ArkWatchDomains.System, AuditLevel.Security, Outcome.Success, Host),
            ["data_export"] = new("data.export", ArkWatchDomains.System, AuditLevel.Security, Outcome.Success, Api),
            ["data_import"] = new("data.import", ArkWatchDomains.System, AuditLevel.Security, Outcome.Success, Api),
            ["data_reset"] = new("data.reset", ArkWatchDomains.System, AuditLevel.Critical, Outcome.Success, Api),
        };

        /// <summary>The structured event for a trace row.</summary>
        public static ArkWatchEvent FromRow(string? refKey, string? refVal, string? message, string? details, string? logType, string? by = null)
        {
            var key = (refKey ?? "").Trim();
            Rules.TryGetValue(key, out var rule);

            var e = new ArkWatchEvent
            {
                Action = rule?.Action ?? FallbackAction(key),
                Domain = rule?.Domain ?? ArkWatchDomains.System,
                System = rule?.System,
                Level = rule?.Level ?? LevelOf(logType),
                Outcome = rule?.Outcome ?? (string.Equals(logType, "warn", StringComparison.OrdinalIgnoreCase) ? Outcome.Failure : Outcome.Success),
                Message = message,
                ProtocolTrace = rule?.Trace ?? false
            };
            e.With("ref_key", key).With("ref", refVal);
            if (rule?.Resource != null && !string.IsNullOrWhiteSpace(refVal))
            {
                e.ResourceType = rule.Resource;
                e.ResourceId = refVal!.Trim();
            }

            // The reason a sign-in was turned away is in the key, not the sentence.
            if (key.StartsWith("signin_", StringComparison.OrdinalIgnoreCase)) e.With("reason_code", key["signin_".Length..]);

            var facts = Facts(details);
            if (facts == null)
            {
                e.With("details", details);
            }
            else if (rule?.System != OAuth)
            {
                // Console and management lines: whoever is signed in did it, and the names in
                // the sentence are what it was done to.
                foreach (var (name, value) in facts) e.With(name, value);
            }
            else
            {
                foreach (var (name, value) in facts) e.With(name, value);
                // On a protocol endpoint nobody is signed in: the person the line names acted,
                // or else the client that made the request.
                var person = facts.GetValueOrDefault("user") ?? facts.GetValueOrDefault("sub");
                var client = facts.GetValueOrDefault("client");
                if (!string.IsNullOrWhiteSpace(person) && !string.Equals(person, client, StringComparison.OrdinalIgnoreCase))
                {
                    e.ParticipantId = person;
                    e.ParticipantType = ParticipantTypes.User;
                }
                else if (!string.IsNullOrWhiteSpace(client))
                {
                    e.ParticipantId = client;
                    e.ParticipantType = ParticipantTypes.Service;
                }
                if (e.ResourceType == null && !string.IsNullOrWhiteSpace(client) && e.ParticipantType == ParticipantTypes.User)
                {
                    e.ResourceType = "client";
                    e.ResourceId = client;
                }
            }

            // ref_val of a protocol line is "{tenant}/oauth2/…" or the tenant itself.
            if (rule?.System == OAuth && !string.IsNullOrWhiteSpace(refVal))
                e.Tenant = refVal!.Split('/')[0].Trim();

            if (!string.IsNullOrWhiteSpace(by) && !string.Equals(by, "ark_admin", StringComparison.Ordinal) && e.ParticipantId == null)
            {
                e.ParticipantId = by;
                e.ParticipantType = ParticipantTypes.User;
            }
            return e;
        }

        /// <summary>
        /// An event for a change an operator made, for the call sites whose trace line names a
        /// route rather than the thing that changed. The operator is taken from the request.
        /// </summary>
        public static ArkWatchEvent Admin(string action, AuditLevel level, string resourceType, string? resourceId, string message, string? tenant = null) =>
            new()
            {
                Action = action,
                Domain = ArkWatchDomains.Administration,
                System = Api,
                Level = level,
                Outcome = Outcome.Success,
                ResourceType = resourceType,
                ResourceId = resourceId,
                Message = message,
                Tenant = tenant
            };

        /// <summary>The event for a fault: what failed, and the exception without its secrets.</summary>
        public static ArkWatchEvent FromError(Exception ex, string? refKey, string? refVal, string? message)
        {
            var e = new ArkWatchEvent
            {
                Action = "server.error",
                Domain = ArkWatchDomains.System,
                System = Host,
                Level = AuditLevel.Error,
                Outcome = Outcome.Failure,
                Message = message
            };
            e.With("ref_key", refKey).With("ref", refVal)
                .With("error_type", ex.GetType().FullName)
                .With("error", ex.Message);
            var stack = ex.ToString();
            e.With("stack", stack.Length > 4000 ? stack[..4000] + "…" : stack);
            return e;
        }

        private static AuditLevel LevelOf(string? logType) => (logType ?? "").Trim().ToLowerInvariant() switch
        {
            "warn" => AuditLevel.Warning,
            "error" => AuditLevel.Error,
            "audit" => AuditLevel.Security,
            _ => AuditLevel.Info
        };

        /// <summary><c>webhook_endpoint_saved</c> becomes <c>webhook.endpoint_saved</c>: a noun, then what happened to it.</summary>
        private static string FallbackAction(string key)
        {
            if (key.Length == 0) return "idp.event";
            var clean = new string(key.ToLowerInvariant().Select(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '.' ? c : '_').ToArray());
            if (clean.Contains('.')) return clean;
            var cut = clean.IndexOf('_');
            return cut <= 0 || cut == clean.Length - 1 ? $"idp.{clean}" : $"{clean[..cut]}.{clean[(cut + 1)..]}";
        }

        private static readonly HashSet<string> FactKeys = new(StringComparer.Ordinal)
        {
            "user", "client", "sub", "audience", "act", "scopes", "reason", "notified", "failed", "not registered", "error", "jti", "sid",
            "user_created", "claims"
        };

        /// <summary>
        /// The facts in a protocol line's details — <c>client: a, sub: b, reason: …</c> — or null
        /// when the text is not in that shape. Only names this code itself writes are read as
        /// names, and <c>reason</c> runs to the end, because it carries an exception's message.
        /// </summary>
        private static Dictionary<string, string>? Facts(string? details)
        {
            var text = (details ?? "").Trim();
            if (text.Length == 0) return null;

            var facts = new Dictionary<string, string>(StringComparer.Ordinal);
            string? last = null;
            var rest = text;
            while (rest.Length > 0)
            {
                var colon = rest.IndexOf(": ", StringComparison.Ordinal);
                var name = colon > 0 ? rest[..colon].Trim() : null;
                if (name == null || !FactKeys.Contains(name))
                {
                    // Not a name: the first segment means this is prose, a later one is the tail
                    // of a value that had a comma in it.
                    if (last == null) return null;
                    facts[last] = $"{facts[last]}, {rest}";
                    break;
                }

                var value = rest[(colon + 2)..];
                if (name == "reason")
                {
                    facts[name] = value.Trim();
                    break;
                }

                var next = NextFact(value);
                facts[name] = (next < 0 ? value : value[..next]).Trim();
                last = name;
                rest = next < 0 ? "" : value[(next + 2)..].TrimStart();
            }
            return facts.Count == 0 ? null : facts;
        }

        /// <summary>Where the next <c>, name: </c> begins in <paramref name="value"/>, or -1.</summary>
        private static int NextFact(string value)
        {
            var from = 0;
            while (true)
            {
                var comma = value.IndexOf(", ", from, StringComparison.Ordinal);
                if (comma < 0) return -1;
                var tail = value[(comma + 2)..];
                var colon = tail.IndexOf(": ", StringComparison.Ordinal);
                if (colon > 0 && FactKeys.Contains(tail[..colon].Trim())) return comma;
                from = comma + 2;
            }
        }
    }
}
