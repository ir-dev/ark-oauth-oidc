using System.Collections.Concurrent;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Ark.oAuth.Oidc.Webhooks
{
    /// <summary>An endpoint as the dispatcher and the publisher see it: parsed once per refresh.</summary>
    public sealed class ArkWebhookEndpointView
    {
        public ArkWebhookEndpoint Row { get; }
        public string Id => Row.id;
        public string TenantId => Row.tenant_id;
        public string Status => Row.status;
        public IReadOnlyList<string> Events { get; }
        public ArkWebhookAuthConfig Auth { get; }
        public IReadOnlyList<string> HeaderNames { get; }
        public ArkShardPlan Plan { get; }

        public ArkWebhookEndpointView(ArkWebhookEndpoint row)
        {
            Row = row;
            Events = JsonList.Read(row.events_);
            Auth = ArkWebhookAuthConfig.Read(row.auth_);
            HeaderNames = JsonList.Read(row.header_names_);
            Plan = ArkShardPlan.From(row);
        }

        /// <summary>Whether an event of this type and tenant should be queued for this endpoint.</summary>
        public bool Accepts(string tenantId, string type) =>
            (Status == ArkWebhookStatus.Active || Status == ArkWebhookStatus.Paused)
            && string.Equals(TenantId, tenantId, StringComparison.OrdinalIgnoreCase)
            && Matches(Events, type);

        public static bool Matches(IEnumerable<string> patterns, string type)
        {
            foreach (var raw in patterns)
            {
                var p = (raw ?? "").Trim();
                if (p.Length == 0) continue;
                if (p == "*") return true;
                if (p.EndsWith(".*", StringComparison.Ordinal))
                {
                    if (type.StartsWith(p[..^1], StringComparison.OrdinalIgnoreCase)) return true;
                }
                else if (string.Equals(p, type, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }
    }

    /// <summary>
    /// Where an endpoint's deliveries are stored — the plan the operator chose on the form.
    /// </summary>
    public sealed record ArkShardPlan(string Strategy, IReadOnlyList<string> Databases, int Count, string PartitionKey, string EndpointKey)
    {
        public const int MaxHashedShards = 32;

        public static ArkShardPlan From(ArkWebhookEndpoint row)
        {
            var dbs = JsonList.Read(row.shard_databases_).Select(d => d.Trim().ToLowerInvariant()).Where(d => d.Length > 0).Distinct().ToList();
            if (dbs.Count == 0) dbs.Add(ArkWebhookDatabases.Main);
            var strategy = ArkShardStrategy.All.Contains(row.shard_strategy) ? row.shard_strategy : ArkShardStrategy.Shared;
            var count = strategy == ArkShardStrategy.Hashed ? Math.Clamp(row.shard_count, 1, MaxHashedShards) : 1;
            var key = ArkShardPartitionKey.All.Contains(row.shard_partition_key) ? row.shard_partition_key : ArkShardPartitionKey.Subject;
            return new ArkShardPlan(strategy, dbs, count, key, ArkWebhookRouter.EndpointKey(row.id));
        }
    }

    /// <summary>Pure routing: which shard a delivery goes to, and which shards a plan uses.</summary>
    public static class ArkWebhookRouter
    {
        public static string ShardId(string database, string suffix) => $"{database}:{suffix}";

        public static (string Database, string Suffix) ParseShardId(string? shardId)
        {
            var parts = (shardId ?? "").Split(':', 2);
            if (parts.Length != 2 || !ArkWebhookDatabases.IsValidName(parts[0]) || !ArkWebhookDatabases.IsValidSuffix(parts[1]))
                throw new ArkWebhookException("bad_shard", $"'{shardId}' is not a shard id.", 400);
            return (parts[0], parts[1]);
        }

        /// <summary>The lowercase alphanumeric part of an endpoint id, used in its own table names.</summary>
        public static string EndpointKey(string endpointId)
        {
            var sb = new StringBuilder();
            foreach (var c in (endpointId ?? "").ToLowerInvariant())
                if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) sb.Append(c);
            var s = sb.ToString();
            if (s.StartsWith("wh") && s.Length > 2) s = s[2..];
            return s.Length > 12 ? s[^12..] : (s.Length == 0 ? "x" : s);
        }

        public static string MonthSuffix(DateTime utc) => $"m_{utc:yyyyMM}";

        /// <summary>The shard one delivery goes to.</summary>
        public static (string Database, string Suffix) Route(ArkShardPlan plan, string? partitionValue, DateTime utcNow)
        {
            switch (plan.Strategy)
            {
                case ArkShardStrategy.Dedicated:
                    return (plan.Databases[0], $"d_{plan.EndpointKey}");
                case ArkShardStrategy.Monthly:
                    return (plan.Databases[0], MonthSuffix(utcNow));
                case ArkShardStrategy.Hashed:
                    var i = (int)(Fnv1a(partitionValue ?? "") % (uint)plan.Count);
                    return (plan.Databases[i % plan.Databases.Count], $"h_{plan.EndpointKey}_{i}");
                default:
                    return (plan.Databases[0], "shared");
            }
        }

        /// <summary>Every shard the plan routes to right now (for a monthly plan, this month's).</summary>
        public static List<(string Database, string Suffix)> Targets(ArkShardPlan plan, DateTime utcNow)
        {
            if (plan.Strategy != ArkShardStrategy.Hashed) return new() { Route(plan, null, utcNow) };
            var list = new List<(string, string)>();
            for (var i = 0; i < plan.Count; i++)
                list.Add((plan.Databases[i % plan.Databases.Count], $"h_{plan.EndpointKey}_{i}"));
            return list;
        }

        public static string? PartitionValue(ArkShardPlan plan, ArkWebhookEvent evt) => plan.PartitionKey switch
        {
            ArkShardPartitionKey.EventType => evt.type,
            ArkShardPartitionKey.EventId => evt.id,
            _ => evt.subject ?? evt.id
        };

        /// <summary>FNV-1a, 32 bit: stable across processes and versions, unlike string.GetHashCode.</summary>
        public static uint Fnv1a(string value)
        {
            var hash = 2166136261u;
            foreach (var b in Encoding.UTF8.GetBytes(value))
            {
                hash ^= b;
                hash *= 16777619u;
            }
            return hash;
        }
    }

    /// <summary>
    /// The endpoints and shards, kept in memory and re-read every
    /// <see cref="ArkWebhookOptions.RefreshSeconds"/> — so deciding whether an event is wanted
    /// costs a dictionary walk rather than a query, and an IdP with no endpoints pays nothing per
    /// request. A save on this instance refreshes at once; other instances follow within the
    /// refresh interval.
    /// </summary>
    public sealed class ArkWebhookRegistry : BackgroundService
    {
        public sealed record Snapshot(
            IReadOnlyDictionary<string, ArkWebhookEndpointView> Endpoints,
            IReadOnlyList<ArkWebhookShard> Shards,
            DateTime LoadedAt);

        private readonly ArkWebhookDatabases _dbs;
        private readonly IConfiguration _config;
        private readonly ILogger<ArkWebhookRegistry> _log;
        private readonly SemaphoreSlim _wake = new(0, 1);
        private readonly SemaphoreSlim _refreshGate = new(1, 1);
        private readonly ConcurrentDictionary<string, bool> _activeShards = new();
        private volatile Snapshot? _snapshot;
        private ArkWebhookOptions _options;
        private DateTime _optionsAt;

        public ArkWebhookRegistry(ArkWebhookDatabases dbs, IConfiguration config, ILogger<ArkWebhookRegistry> log)
        {
            _dbs = dbs;
            _config = config;
            _log = log;
            _options = ArkWebhookOptions.From(config);
            _optionsAt = DateTime.UtcNow;
        }

        public Snapshot? Current => _snapshot;
        public bool Loaded => _snapshot != null;
        public string? LastError { get; private set; }
        public bool Running { get; private set; }

        /// <summary>The options, re-read at most every two seconds — cheap enough for every event.</summary>
        public ArkWebhookOptions Options
        {
            get
            {
                if ((DateTime.UtcNow - _optionsAt).TotalSeconds >= 2)
                {
                    _options = ArkWebhookOptions.From(_config);
                    _optionsAt = DateTime.UtcNow;
                }
                return _options;
            }
        }

        /// <summary>
        /// Whether anything would receive this event. True before the first load, so an event
        /// raised in the first seconds after start-up is queued and decided by the ingestor once
        /// the endpoints are known, rather than lost.
        /// </summary>
        public bool Wants(string tenantId, string type)
        {
            var snap = _snapshot;
            if (snap == null) return Running;
            foreach (var ep in snap.Endpoints.Values)
                if (ep.Accepts(tenantId, type)) return true;
            return false;
        }

        public List<ArkWebhookEndpointView> Matching(string tenantId, string type)
        {
            var snap = _snapshot;
            if (snap == null) return new();
            return snap.Endpoints.Values.Where(e => e.Accepts(tenantId, type)).ToList();
        }

        public ArkWebhookEndpointView? Endpoint(string id) =>
            _snapshot?.Endpoints.TryGetValue(id, out var ep) == true ? ep : null;

        /// <summary>Asks for a refresh now (after a save), without waiting for it.</summary>
        public void Invalidate()
        {
            try { _wake.Release(); } catch (SemaphoreFullException) { }
        }

        /// <summary>Re-reads endpoints and shards. Creates the control tables on first use.</summary>
        public async Task RefreshAsync(CancellationToken ct = default)
        {
            await _refreshGate.WaitAsync(ct);
            try
            {
                if (_dbs.TryResolve(Options.ControlDatabase) == null)
                {
                    // Before the setup wizard has written a connection string there is nothing to read.
                    LastError = "no database configured yet";
                    return;
                }
                await using var ctl = _dbs.Control();
                var rows = await ctl.endpoints.AsNoTracking().ToListAsync(ct);
                var shards = await ctl.shards.AsNoTracking().ToListAsync(ct);
                _snapshot = new Snapshot(
                    rows.ToDictionary(r => r.id, r => new ArkWebhookEndpointView(r), StringComparer.Ordinal),
                    shards,
                    DateTime.UtcNow);
                _activeShards.Clear();
                foreach (var s in shards.Where(s => s.status == "active")) _activeShards[s.id] = true;
                LastError = null;
            }
            finally
            {
                _refreshGate.Release();
            }
        }

        /// <summary>
        /// Makes sure a shard's tables exist and the registry lists it as active — before the
        /// first delivery is written to it, so the dispatcher's scan always covers it.
        /// </summary>
        public async Task EnsureShardAsync(string database, string suffix, string strategy, string? endpointId, CancellationToken ct = default)
        {
            var id = ArkWebhookRouter.ShardId(database, suffix);
            if (_activeShards.ContainsKey(id)) return;

            await using (var _ = _dbs.Shard(database, suffix)) { }   // creates the tables

            await using var ctl = _dbs.Control();
            var row = await ctl.shards.FirstOrDefaultAsync(s => s.id == id, ct);
            if (row == null)
            {
                ctl.shards.Add(new ArkWebhookShard
                {
                    id = id,
                    database_name = database,
                    table_suffix = suffix,
                    strategy = strategy,
                    endpoint_id = strategy is ArkShardStrategy.Dedicated or ArkShardStrategy.Hashed ? endpointId : null,
                    status = "active",
                    created_at = DateTime.UtcNow
                });
                try { await ctl.SaveChangesAsync(ct); }
                catch (DbUpdateException)
                {
                    // Another instance registered it in the same moment; make sure it is active.
                    ctl.ChangeTracker.Clear();
                    await ctl.shards.Where(s => s.id == id && s.status != "active")
                        .ExecuteUpdateAsync(s => s.SetProperty(x => x.status, "active").SetProperty(x => x.sealed_at, (DateTime?)null), ct);
                }
            }
            else if (row.status != "active")
            {
                row.status = "active";
                row.sealed_at = null;
                await ctl.SaveChangesAsync(ct);
            }
            _activeShards[id] = true;
            Invalidate();
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            Running = true;
            // Not at the first instruction: the IdP's own bootstrap runs on the first requests,
            // and the setup wizard may not have written a connection string yet.
            try { await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken); }
            catch (OperationCanceledException) { return; }

            var failures = 0;
            while (!stoppingToken.IsCancellationRequested)
            {
                var wait = TimeSpan.FromSeconds(Options.EffectiveRefreshSeconds);
                if (Options.Enabled)
                {
                    try
                    {
                        await RefreshAsync(stoppingToken);
                        failures = 0;
                    }
                    catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
                    catch (Exception ex)
                    {
                        failures++;
                        LastError = ex.GetBaseException().Message;
                        _dbs.ForgetSchema();
                        if (failures == 1 || failures % 30 == 0)
                            _log.LogWarning(ex, "Ark webhooks could not read their configuration; retrying.");
                        wait = TimeSpan.FromSeconds(Math.Min(60, 2 * failures));
                    }
                }
                try { await _wake.WaitAsync(wait, stoppingToken); }
                catch (OperationCanceledException) { return; }
            }
        }
    }
}
