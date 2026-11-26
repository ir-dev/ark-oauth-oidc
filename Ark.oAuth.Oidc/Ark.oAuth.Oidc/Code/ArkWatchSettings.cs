using System.Text.Json;
using Microsoft.EntityFrameworkCore;

namespace Ark.oAuth.Oidc
{
    /// <summary>
    /// A change to the audit trail's destination, from the console's Audit trail page or a script:
    /// <c>POST /api/oauth/v1/watch/settings</c> and <c>/watch/test</c>.
    /// </summary>
    public sealed class ArkWatchSettingsRequest
    {
        /// <summary>
        /// False turns the trail off and keeps the destination for later; the other fields are then
        /// ignored. Default true.
        /// </summary>
        public bool enabled { get; set; } = true;
        public string? endpoint { get; set; }
        /// <summary>
        /// Blank keeps the key in use, but only for a node on the same server (scheme, host and
        /// port) as the one it was saved for. A key is never sent anywhere else without being
        /// entered again.
        /// </summary>
        public string? api_key { get; set; }
        public string? application { get; set; }
        public string? environment { get; set; }
        public bool? include_protocol_trace { get; set; }
        /// <summary>Save although the test fails: for a node that is down for now. Its events wait in the spool.</summary>
        public bool skip_test { get; set; }
    }

    /// <summary>The audit trail's destination as saved in the console: one row of <c>server_settings</c>, read.</summary>
    internal sealed class ArkWatchStored
    {
        internal ArkWatchStored(ArkWatchConfig config, DateTime updatedAt, string? updatedBy, string version)
        {
            Config = config;
            UpdatedAt = updatedAt;
            UpdatedBy = updatedBy;
            Version = version;
        }

        /// <summary>Everything except the spool folder, which is each instance's own and stays with configuration.</summary>
        public ArkWatchConfig Config { get; }
        public DateTime UpdatedAt { get; }
        public string? UpdatedBy { get; }
        /// <summary>Equal for two reads of the same row, so a read that found nothing new changes no reference.</summary>
        internal string Version { get; }
    }

    /// <summary>The JSON kept in <c>server_settings.value</c> for the <c>watch</c> row.</summary>
    internal sealed class ArkWatchStoredValue
    {
        public bool Enabled { get; set; } = true;
        public string? Endpoint { get; set; }
        public string? ApiKey { get; set; }
        public string? Application { get; set; }
        public string? Environment { get; set; }
        public bool IncludeProtocolTrace { get; set; } = true;
    }

    /// <summary>
    /// The audit trail's destination as the operator set it in the admin console, kept in the
    /// database so that every instance follows it, without a restart.
    ///
    /// <b>Precedence.</b> A destination saved here replaces <c>ark_oauth_server:Watch</c> (the
    /// settings file, appsettings or the environment) as a whole, apart from the spool folder,
    /// until it is removed again. <c>Watch:AllowConsoleChanges = false</c> ignores it and stops
    /// every read of it.
    ///
    /// <b>Cost.</b> Nothing is read on the request path. <see cref="Peek"/> hands back the copy
    /// from the last read and, when that is older than the reference-cache window
    /// (<c>Oidc:ReferenceCacheSeconds</c>, 30 s, at least 5), starts one read in the background:
    /// at most one small primary-key lookup per window, and only while events are being recorded.
    /// The instance that saves applies the change at once; the others within the window.
    ///
    /// <b>When the database is read.</b> Once as the host starts, so that a destination saved
    /// here is where the start is recorded and what an earlier run spooled is replayed to (skipped
    /// for a SQLite file that does not exist yet, which only the bootstrap may create); after that
    /// only once this process has bootstrapped the database, never alongside the schema sync. A
    /// read that fails keeps the copy it had: a database that is away for a moment does not send
    /// the trail back to the configuration's destination.
    /// </summary>
    internal sealed class ArkWatchConsoleSettings
    {
        internal const string RowName = "watch";

        private static readonly JsonSerializerOptions Json = new();

        private readonly IServiceScopeFactory _scopes;
        private readonly IConfiguration _config;
        private readonly ILogger<ArkWatchConsoleSettings> _log;

        private ArkWatchStored? _current;
        // Raised by every save or removal on this instance. A read that started before one of them
        // must not publish what it found: it would put the old destination back for a whole window.
        private long _generation;
        private readonly object _publishGate = new();
        // Environment.TickCount64 at which the copy is next read again. 0: at once.
        private long _nextCheckAt;
        private int _refreshing;
        private volatile bool _tableReady;
        private string? _warnedVersion;

        public ArkWatchConsoleSettings(IServiceScopeFactory scopes, IConfiguration config, ILogger<ArkWatchConsoleSettings> log)
        {
            _scopes = scopes;
            _config = config;
            _log = log;
        }

        /// <summary>Whether configuration lets the console change the destination (<c>Watch:AllowConsoleChanges</c>).</summary>
        internal bool Allowed => Protocol.ArkConfigSnapshot.Server(_config)?.Watch?.AllowConsoleChanges ?? true;

        /// <summary>How long another instance may go on with the old destination, in seconds.</summary>
        internal int WindowSeconds => Math.Clamp(Protocol.ArkConfigSnapshot.Oidc(_config).ReferenceCacheSeconds, 5, 300);

        /// <summary>What the last read found, without reading. Null: nothing saved, or the console may not change it.</summary>
        internal ArkWatchStored? Current => Allowed ? Volatile.Read(ref _current) : null;

        /// <summary>
        /// The same, for the code that sends events: never waits, and starts a read in the
        /// background when the copy is older than the window.
        /// </summary>
        internal ArkWatchStored? Peek()
        {
            if (!Allowed) return null;
            if (Environment.TickCount64 >= Volatile.Read(ref _nextCheckAt) && ArkExtn.DataInitialized &&
                Interlocked.CompareExchange(ref _refreshing, 1, 0) == 0)
            {
                _ = Task.Run(async () =>
                {
                    try { await LoadAsync(); }
                    finally { Volatile.Write(ref _refreshing, 0); }
                });
            }
            return Volatile.Read(ref _current);
        }

        /// <summary>
        /// Reads the row now. True when it was read, whatever it held; false when it could not be,
        /// in which case the copy from before is kept.
        /// </summary>
        /// <param name="startup">The read as the host starts, before any request has bootstrapped the database.</param>
        /// <param name="cancellationToken">Cancels the read; the copy from before is kept.</param>
        internal async Task<bool> LoadAsync(bool startup = false, CancellationToken cancellationToken = default)
        {
            try
            {
                if (!Allowed || !ArkIdpSettings.IsConfigured(_config)) return false;
                if (startup ? !DatabaseMayBeOpened() : !ArkExtn.DataInitialized) return false;

                var generation = Interlocked.Read(ref _generation);
                using var scope = _scopes.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<ArkDataContext>();
                if (!_tableReady)
                {
                    // Probed over the plain connection, so "not there yet" is an answer rather than
                    // an error in the log, and added on a database that has the rest of the schema.
                    if (!ArkSchemaUpdater.EnsureTable(db, typeof(ArkServerSetting))) return false;
                    _tableReady = true;
                }
                var row = await db.server_settings.AsNoTracking()
                    .FirstOrDefaultAsync(s => s.name == RowName, cancellationToken);
                var found = Read(row);
                lock (_publishGate)
                {
                    // A save here since the read began has the newer value; keep it.
                    if (Interlocked.Read(ref _generation) == generation) Swap(found);
                }
                return true;
            }
            catch (Exception ex)
            {
                _log.LogDebug(ex, "Ark IdP audit trail: the destination saved in the console could not be read; the last one read stays in use.");
                return false;
            }
            finally
            {
                Volatile.Write(ref _nextCheckAt, Environment.TickCount64 + WindowSeconds * 1000L);
            }
        }

        /// <summary>
        /// Writes the destination to the database and returns it as read back. Does not apply it:
        /// <see cref="Publish"/> does, once the change has been recorded where the trail goes now.
        /// </summary>
        internal async Task<ArkWatchStored> WriteAsync(ArkDataContext db, ArkWatchStoredValue value, string? who)
        {
            if (!ArkSchemaUpdater.EnsureTable(db, typeof(ArkServerSetting)))
                throw new InvalidOperationException("the server_settings table is not in this server's database and could not be added.");
            _tableReady = true;

            var entity = new ArkServerSetting
            {
                name = RowName,
                value = JsonSerializer.Serialize(value, Json),
                updated_at = DateTime.UtcNow,
                updated_by = Clip(who, 256)
            };
            db.ChangeTracker.Clear();
            var exists = await db.server_settings.AsNoTracking().AnyAsync(s => s.name == RowName);
            if (exists) db.server_settings.Update(entity);
            else db.server_settings.Add(entity);
            await db.SaveChangesAsync();
            db.ChangeTracker.Clear();
            return Read(entity)!;
        }

        /// <summary>Removes the destination saved in the console. False when there was none.</summary>
        internal async Task<bool> DeleteAsync(ArkDataContext db)
        {
            if (!ArkSchemaUpdater.EnsureTable(db, typeof(ArkServerSetting))) return false;
            db.ChangeTracker.Clear();
            var row = await db.server_settings.AsNoTracking().FirstOrDefaultAsync(s => s.name == RowName);
            if (row == null) return false;
            db.server_settings.Remove(row);
            await db.SaveChangesAsync();
            db.ChangeTracker.Clear();
            return true;
        }

        /// <summary>
        /// Makes <paramref name="value"/>, just saved or removed on this instance, the destination here
        /// from the next event on. Wins over any read still under way.
        /// </summary>
        internal void Publish(ArkWatchStored? value)
        {
            lock (_publishGate)
            {
                Interlocked.Increment(ref _generation);
                Swap(value);
            }
            Volatile.Write(ref _nextCheckAt, Environment.TickCount64 + WindowSeconds * 1000L);
        }

        /// <summary>Replaces the copy, keeping the same object when the row did not change.</summary>
        private void Swap(ArkWatchStored? value)
        {
            var current = Volatile.Read(ref _current);
            if (current?.Version != value?.Version) Volatile.Write(ref _current, value);
        }

        // ---------------------------------------------------------------- a change, checked

        /// <summary>
        /// The value to store for <paramref name="request"/>, and for a destination that is on, the
        /// checked plan to test it with. Throws <see cref="ArkSetupMiddleware.SetupException"/> for
        /// what the wizard would refuse, with the same codes and messages.
        /// </summary>
        internal static (ArkWatchStoredValue Value, ArkSetupMiddleware.WatchPlan? Plan) Prepare(
            ArkWatchSettingsRequest request, ArkWatchStored? stored, ArkWatchConfig? configured, string defaultEnvironment)
        {
            if (!request.enabled)
            {
                // Off, with the destination kept so it can be turned on again. Only a key the console
                // already holds is kept: one from configuration is not copied into the database.
                var basis = stored?.Config ?? configured;
                return (new ArkWatchStoredValue
                {
                    Enabled = false,
                    Endpoint = Blank(basis?.Endpoint),
                    ApiKey = Blank(stored?.Config.ApiKey),
                    Application = Blank(basis?.Application),
                    Environment = Blank(basis?.Environment),
                    IncludeProtocolTrace = request.include_protocol_trace ?? basis?.IncludeProtocolTrace ?? true
                }, null);
            }

            var endpoint = (request.endpoint ?? "").Trim();
            var key = (request.api_key ?? "").Trim();
            if (key.Length == 0 && endpoint.Length > 0)
            {
                key = KeptKey(endpoint, stored, configured) ?? "";
                if (key.Length == 0 && HasKey(stored?.Config, configured))
                    throw new ArkSetupMiddleware.SetupException("watch_key_required",
                        "Enter the API key again: this address is on a different server from the one the saved key belongs to, " +
                        "and a saved key is only ever sent to its own server.", "watch_api_key");
            }

            var plan = ArkSetupMiddleware.NormalizeWatch(new ArkSetupMiddleware.WatchSection
            {
                Enabled = true,
                Endpoint = endpoint,
                ApiKey = key,
                Application = request.application,
                Environment = request.environment
            }, defaultEnvironment)!;

            return (new ArkWatchStoredValue
            {
                Enabled = true,
                Endpoint = plan.Endpoint,
                ApiKey = plan.ApiKey,
                Application = plan.Application,
                Environment = plan.Environment,
                IncludeProtocolTrace = request.include_protocol_trace ?? stored?.Config.IncludeProtocolTrace ?? configured?.IncludeProtocolTrace ?? true
            }, plan);
        }

        /// <summary>
        /// The key in use for <paramref name="endpoint"/>: the console's, then configuration's, each
        /// only when it was set for a node on the same server. Pointing the trail at a server of
        /// one's own with the key left blank would otherwise hand that server a key the operator was
        /// never shown, one set in the environment for instance.
        /// </summary>
        internal static string? KeptKey(string endpoint, ArkWatchStored? stored, ArkWatchConfig? configured)
        {
            foreach (var candidate in new[] { stored?.Config, configured })
            {
                if (candidate == null || string.IsNullOrWhiteSpace(candidate.ApiKey)) continue;
                if (SameServer(candidate.Endpoint, endpoint)) return candidate.ApiKey.Trim();
            }
            return null;
        }

        private static bool HasKey(params ArkWatchConfig?[] candidates) =>
            candidates.Any(c => !string.IsNullOrWhiteSpace(c?.ApiKey));

        /// <summary>Same scheme, host and port.</summary>
        internal static bool SameServer(string? a, string? b) =>
            Uri.TryCreate((a ?? "").Trim(), UriKind.Absolute, out var x) &&
            Uri.TryCreate((b ?? "").Trim(), UriKind.Absolute, out var y) &&
            Uri.Compare(x, y, UriComponents.SchemeAndServer, UriFormat.Unescaped, StringComparison.OrdinalIgnoreCase) == 0;

        // ---------------------------------------------------------------- what the page is shown

        /// <summary>Whether a configuration section names a destination at all.</summary>
        internal static bool Names(ArkWatchConfig? cfg) =>
            cfg != null && (!string.IsNullOrWhiteSpace(cfg.Endpoint) || !string.IsNullOrWhiteSpace(cfg.ApiKey));

        /// <summary>A destination as the console may see it: everything but the key, which is only hinted at.</summary>
        internal static object Describe(ArkWatchConfig cfg, bool withSpool = false) => new
        {
            enabled = cfg.Enabled,
            endpoint = DisplayEndpoint(cfg.Endpoint),
            application = Blank(cfg.Application),
            environment = Blank(cfg.Environment),
            include_protocol_trace = cfg.IncludeProtocolTrace,
            key = KeyHint(cfg.ApiKey),
            spool_directory = withSpool ? Blank(cfg.SpoolDirectory) : null
        };

        internal static string? DisplayEndpoint(string? endpoint)
        {
            var text = (endpoint ?? "").Trim();
            if (text.Length == 0) return null;
            return Uri.TryCreate(text, UriKind.Absolute, out var uri) ? uri.GetLeftPart(UriPartial.Path) : text;
        }

        /// <summary>
        /// Enough of a key to tell two apart — <c>arkw_sk_…9f2c</c> — and no more. A short value is
        /// only said to be set.
        /// </summary>
        internal static string? KeyHint(string? key)
        {
            var k = (key ?? "").Trim();
            if (k.Length == 0) return null;
            if (k.Length < 16) return "set";
            var prefix = "";
            if (k.StartsWith("arkw_", StringComparison.OrdinalIgnoreCase))
            {
                var second = k.IndexOf('_', 5);
                if (second > 0 && second < 10) prefix = k[..(second + 1)];
            }
            return $"{prefix}…{k[^4..]}";
        }

        // ---------------------------------------------------------------- reading a row

        private ArkWatchStored? Read(ArkServerSetting? row)
        {
            if (row == null || string.IsNullOrWhiteSpace(row.value)) return null;
            var at = row.updated_at.Kind == DateTimeKind.Unspecified
                ? DateTime.SpecifyKind(row.updated_at, DateTimeKind.Utc)
                : row.updated_at.ToUniversalTime();
            var version = $"{at.Ticks}|{row.value}";
            try
            {
                var v = JsonSerializer.Deserialize<ArkWatchStoredValue>(row.value, Json);
                if (v == null) return null;
                // ArkWatchConfig's strings are null when unset, whatever their declarations say.
                return new ArkWatchStored(new ArkWatchConfig
                {
                    Enabled = v.Enabled,
                    Endpoint = v.Endpoint!,
                    ApiKey = v.ApiKey!,
                    Application = v.Application!,
                    Environment = v.Environment!,
                    IncludeProtocolTrace = v.IncludeProtocolTrace
                }, at, row.updated_by, version);
            }
            catch (JsonException ex)
            {
                // Somebody edited the row by hand. Configuration applies until the console saves again.
                if (_warnedVersion != version)
                {
                    _warnedVersion = version;
                    _log.LogWarning("Ark IdP audit trail: the destination saved in the console (server_settings, row '{Row}') is not valid JSON ({Error}) and is ignored.",
                        RowName, ex.Message);
                }
                return null;
            }
        }

        /// <summary>
        /// Whether the start-up read may open the database. Not a SQLite file that is not there yet:
        /// opening it would create it, without the permissions the bootstrap gives a new one.
        /// </summary>
        private bool DatabaseMayBeOpened()
        {
            var provider = (Protocol.ArkConfigSnapshot.Server(_config)?.Provider ?? "").Trim();
            if (provider.Length > 0 && !provider.Equals("sqlite", StringComparison.OrdinalIgnoreCase)) return true;
            var file = ArkSetupMiddleware.SqliteFile(_config.GetConnectionString("ArkAuthConnection") ?? "");
            return file != null && File.Exists(file);
        }

        private static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

        private static string? Clip(string? value, int max) =>
            string.IsNullOrEmpty(value) || value.Length <= max ? value : value[..max];
    }
}
