using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Ark.oAuth.Oidc.Webhooks
{
    /// <summary>
    /// Sends what the delivery tables hold — the database-backed background dispatcher.
    ///
    /// <b>Claiming.</b> A delivery is taken with a compare-and-swap on its
    /// <see cref="ArkWebhookDelivery.lock_version"/>: the worker reads candidates, then updates
    /// each one "where id = x and lock_version = v". Exactly one worker can win that update,
    /// whichever instance it runs on and whichever database it is — SQLite, PostgreSQL and MySQL
    /// all answer it the same way — so any number of instances can run this service against the
    /// same tables. Every later change to the row (finished, retrying, dead, cancelled, replayed)
    /// is the same compare-and-swap, so a worker that lost its claim cannot overwrite the winner.
    ///
    /// <b>Leases.</b> A claim sets <see cref="ArkWebhookDelivery.next_attempt_at"/> to the end of
    /// a lease (the endpoint's timeout plus <see cref="ArkWebhookOptions.LeaseMarginSeconds"/>). A
    /// worker that dies holding a claim simply lets the lease run out, after which the delivery is
    /// due again and another worker takes it. Delivery is therefore at least once; receivers
    /// de-duplicate on the <c>webhook-id</c> header.
    ///
    /// <b>Bounded concurrency.</b> No more than <see cref="ArkWebhookOptions.MaxConcurrency"/>
    /// requests are in flight on an instance, and no more than an endpoint's
    /// <see cref="ArkWebhookEndpoint.max_concurrency"/> to any one receiver; the dispatcher claims
    /// only as many deliveries as it has free slots for, so nothing it holds sits waiting while
    /// its lease runs down.
    /// </summary>
    public sealed class ArkWebhookDispatcher : BackgroundService
    {
        private static readonly TimeSpan ShutdownGrace = TimeSpan.FromSeconds(20);

        private readonly ArkWebhookRegistry _registry;
        private readonly ArkWebhookDatabases _dbs;
        private readonly ArkWebhookSender _sender;
        private readonly ArkWebhookSignal _signal;
        private readonly ILogger<ArkWebhookDispatcher> _log;
        private readonly ConcurrentDictionary<string, int> _perEndpoint = new();
        private readonly ConcurrentDictionary<Task, bool> _running = new();
        private readonly ConcurrentDictionary<string, DateTime> _successWritten = new();
        private readonly CancellationTokenSource _hardStop = new();
        private int _inFlight;
        private int _shardCursor;
        private DateTime _nextHousekeeping = DateTime.UtcNow + TimeSpan.FromMinutes(1) + TimeSpan.FromSeconds(Random.Shared.Next(0, 60));
        private Task? _housekeeping;

        public ArkWebhookDispatcher(ArkWebhookRegistry registry, ArkWebhookDatabases dbs, ArkWebhookSender sender,
            ArkWebhookSignal signal, ArkWebhookTokenManager tokens, ILogger<ArkWebhookDispatcher> log)
        {
            _registry = registry;
            _dbs = dbs;
            _sender = sender;
            _signal = signal;
            _log = log;
            var configured = registry.Options.WorkerId;
            WorkerId = string.IsNullOrWhiteSpace(configured)
                ? $"{Environment.MachineName}:{Environment.ProcessId}:{Convert.ToHexString(RandomNumberGenerator.GetBytes(2)).ToLowerInvariant()}"
                : configured.Trim();
            if (WorkerId.Length > 96) WorkerId = WorkerId[..96];
            tokens.Worker = WorkerId;
        }

        public string WorkerId { get; }
        public bool Running { get; private set; }
        public int InFlight => Volatile.Read(ref _inFlight);
        public long Claimed => Interlocked.Read(ref _claimed);
        public long Delivered => Interlocked.Read(ref _delivered);
        public long FailedAttempts => Interlocked.Read(ref _failed);
        public long DeadLettered => Interlocked.Read(ref _dead);
        public DateTime? LastHousekeeping { get; private set; }
        public string? LastError { get; private set; }
        private long _claimed, _delivered, _failed, _dead;

        private sealed record Claim(string Database, string Suffix, ArkWebhookDelivery Row, int Version);

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            Running = true;
            using var stopLink = stoppingToken.Register(() => _hardStop.CancelAfter(ShutdownGrace));
            try { await Task.Delay(TimeSpan.FromSeconds(3), stoppingToken); }
            catch (OperationCanceledException) { return; }

            while (!stoppingToken.IsCancellationRequested)
            {
                var options = _registry.Options;
                var poll = TimeSpan.FromMilliseconds(options.EffectivePollIntervalMs);
                if (!options.Enabled || !_registry.Loaded)
                {
                    await _signal.WaitAsync(poll, stoppingToken);
                    continue;
                }

                var claimed = 0;
                var free = options.EffectiveMaxConcurrency - InFlight;
                if (free > 0)
                {
                    var shards = ActiveShards();
                    for (var i = 0; i < shards.Count && free > 0 && !stoppingToken.IsCancellationRequested; i++)
                    {
                        // Start at a different shard each pass, so one busy shard cannot take every slot.
                        var shard = shards[(i + _shardCursor) % shards.Count];
                        try
                        {
                            var batch = await ClaimAsync(shard, Math.Min(free, options.EffectiveBatchSize), options, stoppingToken);
                            foreach (var claim in batch) Start(claim);
                            claimed += batch.Count;
                            free -= batch.Count;
                        }
                        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
                        catch (Exception ex)
                        {
                            LastError = $"{shard.id}: {ex.GetBaseException().Message}";
                            _log.LogDebug(ex, "Ark webhooks could not claim from shard {Shard}.", shard.id);
                        }
                    }
                    _shardCursor++;
                }

                if (DateTime.UtcNow >= _nextHousekeeping && (_housekeeping == null || _housekeeping.IsCompleted))
                {
                    _nextHousekeeping = DateTime.UtcNow + TimeSpan.FromMinutes(options.EffectiveHousekeepingMinutes)
                                        + TimeSpan.FromSeconds(Random.Shared.Next(0, Math.Min(60, options.EffectiveHousekeepingMinutes * 15)));
                    _housekeeping = Task.Run(() => HousekeepingAsync(stoppingToken), CancellationToken.None);
                }

                // Full: wait for a slot (each completion pulses). Idle: wait for the poll interval
                // or for this instance to write new deliveries. Busy: go straight round again.
                if (claimed == 0) await _signal.WaitAsync(poll, stoppingToken);
                else if (free <= 0) await _signal.WaitAsync(TimeSpan.FromMilliseconds(250), stoppingToken);
            }

            // Stop claiming; let what is in flight finish within the grace period.
            var pending = _running.Keys.ToArray();
            if (pending.Length > 0)
                await Task.WhenAny(Task.WhenAll(pending), Task.Delay(ShutdownGrace + TimeSpan.FromSeconds(2)));
        }

        private List<ArkWebhookShard> ActiveShards() =>
            _registry.Current?.Shards.Where(s => s.status == "active").OrderBy(s => s.id, StringComparer.Ordinal).ToList()
            ?? new List<ArkWebhookShard>();

        private int EndpointLoad(string endpointId) => _perEndpoint.TryGetValue(endpointId, out var n) ? n : 0;

        private async Task<List<Claim>> ClaimAsync(ArkWebhookShard shard, int max, ArkWebhookOptions options, CancellationToken ct)
        {
            var snapshot = _registry.Current;
            if (snapshot == null || max <= 0) return new();

            // Paused endpoints, and endpoints already at their concurrency on this instance, are
            // left out of the query itself — otherwise their oldest rows would fill every batch.
            var exclude = snapshot.Endpoints.Values
                .Where(e => e.Status == ArkWebhookStatus.Paused || EndpointLoad(e.Id) >= Math.Max(1, e.Row.max_concurrency))
                .Select(e => e.Id)
                .ToList();

            await using var ctx = _dbs.Shard(shard.database_name, shard.table_suffix);
            var now = DateTime.UtcNow;
            var candidates = await ctx.deliveries.AsNoTracking()
                .Where(d => (d.status == ArkDeliveryStatus.Pending || d.status == ArkDeliveryStatus.Retrying || d.status == ArkDeliveryStatus.InFlight)
                            && d.next_attempt_at <= now
                            && !exclude.Contains(d.endpoint_id))
                .OrderBy(d => d.next_attempt_at)
                .Select(d => new { d.id, d.lock_version, d.endpoint_id })
                .Take(max * 2)
                .ToListAsync(ct);
            if (candidates.Count == 0) return new();

            var won = new List<(string Id, int Version, string Endpoint)>();
            var taking = new Dictionary<string, int>();
            foreach (var c in candidates)
            {
                if (won.Count >= max) break;
                var ep = _registry.Endpoint(c.endpoint_id);
                var cap = Math.Max(1, ep?.Row.max_concurrency ?? 1);
                taking.TryGetValue(c.endpoint_id, out var already);
                if (EndpointLoad(c.endpoint_id) + already >= cap) continue;

                var lease = now.AddSeconds(Math.Clamp(ep?.Row.timeout_seconds ?? 30, 1, 120) + Math.Clamp(options.LeaseMarginSeconds, 10, 3600));
                var version = c.lock_version;
                var worker = WorkerId;
                var rows = await ctx.deliveries
                    .Where(d => d.id == c.id && d.lock_version == version)
                    .ExecuteUpdateAsync(s => s
                        .SetProperty(d => d.status, ArkDeliveryStatus.InFlight)
                        .SetProperty(d => d.locked_by, worker)
                        .SetProperty(d => d.next_attempt_at, lease)
                        .SetProperty(d => d.lock_version, version + 1)
                        .SetProperty(d => d.updated_at, now), ct);
                if (rows != 1) continue;   // another worker won it
                won.Add((c.id, version + 1, c.endpoint_id));
                taking[c.endpoint_id] = already + 1;
            }
            if (won.Count == 0) return new();

            var ids = won.Select(w => w.Id).ToList();
            var loaded = await ctx.deliveries.AsNoTracking().Where(d => ids.Contains(d.id)).ToListAsync(ct);
            var claims = new List<Claim>();
            foreach (var w in won)
            {
                var row = loaded.FirstOrDefault(r => r.id == w.Id);
                if (row == null) continue;
                claims.Add(new Claim(shard.database_name, shard.table_suffix, row, w.Version));
            }
            Interlocked.Add(ref _claimed, claims.Count);
            return claims;
        }

        private void Start(Claim claim)
        {
            Interlocked.Increment(ref _inFlight);
            _perEndpoint.AddOrUpdate(claim.Row.endpoint_id, 1, (_, n) => n + 1);
            var task = Task.Run(() => ProcessAsync(claim));
            _running[task] = true;
            task.ContinueWith(t => _running.TryRemove(t, out _), TaskScheduler.Default);
        }

        private async Task ProcessAsync(Claim claim)
        {
            var d = claim.Row;
            var ct = _hardStop.Token;
            try
            {
                var ep = _registry.Endpoint(d.endpoint_id);
                if (ep == null)
                {
                    // Possibly created on another instance a moment ago: look once more.
                    await _registry.RefreshAsync(ct);
                    ep = _registry.Endpoint(d.endpoint_id);
                }
                if (ep == null)
                {
                    await FinishAsync(claim, ArkDeliveryStatus.Cancelled, d.attempt_count, null, "the endpoint was deleted", null);
                    return;
                }
                if (ep.Status == ArkWebhookStatus.Disabled)
                {
                    await DeadLetterAsync(claim, d.attempt_count, d.last_status_code, d.last_error ?? "the endpoint is disabled", "endpoint_disabled");
                    return;
                }
                if (ep.Status == ArkWebhookStatus.Paused)
                {
                    await RequeueAsync(claim, DateTime.UtcNow.AddSeconds(30));
                    return;
                }

                var attemptNo = d.attempt_count + 1;
                var result = await _sender.SendAsync(ep, d, attemptNo, ct);
                await RecordAttemptAsync(claim, attemptNo, result);

                if (result.Success)
                {
                    Interlocked.Increment(ref _delivered);
                    await FinishAsync(claim, ArkDeliveryStatus.Delivered, attemptNo, result.StatusCode, null, DateTime.UtcNow);
                    await EndpointSucceededAsync(ep, result);
                    return;
                }

                Interlocked.Increment(ref _failed);
                var disabledNow = await EndpointFailedAsync(ep, result);
                if (disabledNow)
                {
                    await DeadLetterAsync(claim, attemptNo, result.StatusCode, result.Error, "endpoint_disabled");
                    _ = Task.Run(() => DeadLetterWaitingAsync(ep.Id, "endpoint_disabled", CancellationToken.None));
                }
                else if (result.Retryable && attemptNo < Math.Clamp(ep.Row.max_attempts, 1, ArkWebhookRetryPolicy.MaxAttemptsCeiling))
                {
                    var due = DateTime.UtcNow + ArkWebhookRetryPolicy.Delay(ep.Row, attemptNo, result.RetryAfter);
                    await RetryLaterAsync(claim, attemptNo, result, due);
                }
                else
                {
                    await DeadLetterAsync(claim, attemptNo, result.StatusCode, result.Error, result.Retryable ? "max_attempts" : "non_retryable");
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                // Shutting down mid-request: hand it back now rather than when the lease lapses.
                // The receiver may have had it already — delivery is at least once.
                try { await RequeueAsync(claim, DateTime.UtcNow); } catch { }
            }
            catch (Exception ex)
            {
                LastError = ex.GetBaseException().Message;
                _log.LogWarning(ex, "Ark webhooks failed to process delivery {Delivery}; it will be tried again.", d.id);
                try { await RequeueAsync(claim, DateTime.UtcNow.AddMinutes(1)); } catch { }
            }
            finally
            {
                Interlocked.Decrement(ref _inFlight);
                _perEndpoint.AddOrUpdate(d.endpoint_id, 0, (_, n) => Math.Max(0, n - 1));
                _signal.Pulse();
            }
        }

        // ------------------------------------------------------------ row transitions

        private async Task<bool> FinishAsync(Claim c, string status, int attempts, int? code, string? error, DateTime? deliveredAt)
        {
            await using var ctx = _dbs.Shard(c.Database, c.Suffix);
            var now = DateTime.UtcNow;
            var v = c.Version;
            var rows = await ctx.deliveries.Where(d => d.id == c.Row.id && d.lock_version == v)
                .ExecuteUpdateAsync(s => s
                    .SetProperty(d => d.status, status)
                    .SetProperty(d => d.attempt_count, attempts)
                    .SetProperty(d => d.last_status_code, code)
                    .SetProperty(d => d.last_error, ArkWebhookFanout.Truncate(error, 2000))
                    .SetProperty(d => d.delivered_at, deliveredAt)
                    .SetProperty(d => d.locked_by, (string?)null)
                    .SetProperty(d => d.lock_version, v + 1)
                    .SetProperty(d => d.updated_at, now), CancellationToken.None);
            if (rows == 0) _log.LogDebug("Ark webhooks lost the claim on {Delivery} before finishing it.", c.Row.id);
            return rows == 1;
        }

        private async Task RetryLaterAsync(Claim c, int attempts, ArkWebhookSendResult result, DateTime due)
        {
            await using var ctx = _dbs.Shard(c.Database, c.Suffix);
            var now = DateTime.UtcNow;
            var v = c.Version;
            var error = ArkWebhookFanout.Truncate(result.Error, 2000);
            await ctx.deliveries.Where(d => d.id == c.Row.id && d.lock_version == v)
                .ExecuteUpdateAsync(s => s
                    .SetProperty(d => d.status, ArkDeliveryStatus.Retrying)
                    .SetProperty(d => d.attempt_count, attempts)
                    .SetProperty(d => d.next_attempt_at, due)
                    .SetProperty(d => d.last_status_code, result.StatusCode)
                    .SetProperty(d => d.last_error, error)
                    .SetProperty(d => d.locked_by, (string?)null)
                    .SetProperty(d => d.lock_version, v + 1)
                    .SetProperty(d => d.updated_at, now), CancellationToken.None);
        }

        /// <summary>Hands a claimed delivery back without counting an attempt.</summary>
        private async Task RequeueAsync(Claim c, DateTime due)
        {
            await using var ctx = _dbs.Shard(c.Database, c.Suffix);
            var v = c.Version;
            var status = c.Row.attempt_count == 0 ? ArkDeliveryStatus.Pending : ArkDeliveryStatus.Retrying;
            var now = DateTime.UtcNow;
            await ctx.deliveries.Where(d => d.id == c.Row.id && d.lock_version == v)
                .ExecuteUpdateAsync(s => s
                    .SetProperty(d => d.status, status)
                    .SetProperty(d => d.next_attempt_at, due)
                    .SetProperty(d => d.locked_by, (string?)null)
                    .SetProperty(d => d.lock_version, v + 1)
                    .SetProperty(d => d.updated_at, now), CancellationToken.None);
        }

        /// <summary>Moves a claimed delivery to the dead-letter queue, in one transaction.</summary>
        private async Task DeadLetterAsync(Claim c, int attempts, int? code, string? error, string reason)
        {
            await using var ctx = _dbs.Shard(c.Database, c.Suffix);
            if (await DeadLetterRowAsync(ctx, c.Row, c.Version, attempts, code, error, reason))
                Interlocked.Increment(ref _dead);
        }

        internal static async Task<bool> DeadLetterRowAsync(ArkWebhookShardContext ctx, ArkWebhookDelivery row, int version,
            int attempts, int? code, string? error, string reason)
        {
            var now = DateTime.UtcNow;
            var trimmed = ArkWebhookFanout.Truncate(error, 2000);
            await using var tx = await ctx.Database.BeginTransactionAsync(CancellationToken.None);
            var rows = await ctx.deliveries.Where(d => d.id == row.id && d.lock_version == version)
                .ExecuteUpdateAsync(s => s
                    .SetProperty(d => d.status, ArkDeliveryStatus.Dead)
                    .SetProperty(d => d.attempt_count, attempts)
                    .SetProperty(d => d.last_status_code, code)
                    .SetProperty(d => d.last_error, trimmed)
                    .SetProperty(d => d.locked_by, (string?)null)
                    .SetProperty(d => d.lock_version, version + 1)
                    .SetProperty(d => d.updated_at, now), CancellationToken.None);
            if (rows != 1)
            {
                await tx.RollbackAsync(CancellationToken.None);
                return false;
            }
            ctx.dead_letters.Add(new ArkWebhookDeadLetter
            {
                id = "dlq_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant(),
                delivery_id = row.id,
                endpoint_id = row.endpoint_id,
                tenant_id = row.tenant_id,
                event_id = row.event_id,
                event_type = row.event_type,
                payload = row.payload,
                reason = reason,
                attempts = attempts,
                last_status_code = code,
                last_error = trimmed,
                dead_at = now
            });
            await ctx.SaveChangesAsync(CancellationToken.None);
            await tx.CommitAsync(CancellationToken.None);
            return true;
        }

        private async Task RecordAttemptAsync(Claim c, int attemptNo, ArkWebhookSendResult result)
        {
            try
            {
                await using var ctx = _dbs.Shard(c.Database, c.Suffix);
                ctx.attempts.Add(new ArkWebhookAttempt
                {
                    id = "att_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant(),
                    delivery_id = c.Row.id,
                    endpoint_id = c.Row.endpoint_id,
                    attempt_no = attemptNo,
                    started_at = DateTime.UtcNow.AddMilliseconds(-result.DurationMs),
                    duration_ms = result.DurationMs,
                    status_code = result.StatusCode,
                    success = result.Success,
                    error = ArkWebhookFanout.Truncate(result.Error, 2000),
                    response_body = result.ResponseBody,
                    worker = WorkerId
                });
                await ctx.SaveChangesAsync(CancellationToken.None);
            }
            catch (Exception ex)
            {
                // History is worth having, not worth failing the delivery over.
                _log.LogDebug(ex, "Ark webhooks could not record an attempt for {Delivery}.", c.Row.id);
            }
        }

        // ------------------------------------------------------------ endpoint health

        private async Task EndpointSucceededAsync(ArkWebhookEndpointView ep, ArkWebhookSendResult result)
        {
            try
            {
                await using var ctl = _dbs.Control();
                var now = DateTime.UtcNow;
                var code = result.StatusCode;
                // The failure count is reset whenever it is not already zero; a WHERE that matches
                // nothing takes no row lock, so a healthy endpoint costs one cheap read per success.
                await ctl.endpoints.Where(e => e.id == ep.Id && e.consecutive_failures > 0)
                    .ExecuteUpdateAsync(s => s.SetProperty(e => e.consecutive_failures, 0), CancellationToken.None);
                // The "last success" stamp is written at most every 30 s per instance, so a busy
                // endpoint does not turn its row into the hottest one in the database.
                if (!_successWritten.TryGetValue(ep.Id, out var last) || (now - last).TotalSeconds >= 30)
                {
                    _successWritten[ep.Id] = now;
                    await ctl.endpoints.Where(e => e.id == ep.Id)
                        .ExecuteUpdateAsync(s => s.SetProperty(e => e.last_success_at, now).SetProperty(e => e.last_status_code, code), CancellationToken.None);
                }
            }
            catch (Exception ex) { _log.LogDebug(ex, "Ark webhooks could not record a success for {Endpoint}.", ep.Id); }
        }

        /// <summary>Counts a failed attempt; true when this one crossed the threshold and disabled the endpoint.</summary>
        private async Task<bool> EndpointFailedAsync(ArkWebhookEndpointView ep, ArkWebhookSendResult result)
        {
            try
            {
                await using var ctl = _dbs.Control();
                var now = DateTime.UtcNow;
                var code = result.StatusCode;
                var error = ArkWebhookFanout.Truncate(result.Error, 2000);
                await ctl.endpoints.Where(e => e.id == ep.Id)
                    .ExecuteUpdateAsync(s => s
                        .SetProperty(e => e.consecutive_failures, e => e.consecutive_failures + 1)
                        .SetProperty(e => e.last_failure_at, now)
                        .SetProperty(e => e.last_status_code, code)
                        .SetProperty(e => e.last_error, error), CancellationToken.None);

                // Disabled exactly once, by whichever worker's failure reached the threshold: the
                // status test in the WHERE makes it a compare-and-swap like every claim.
                var reason = ArkWebhookFanout.Truncate(
                    $"Disabled automatically: {Math.Max(1, ep.Row.failure_threshold)} consecutive failed attempts. Last error: {result.Error}", 2000);
                var disabled = await ctl.endpoints
                    .Where(e => e.id == ep.Id && e.status == ArkWebhookStatus.Active && e.failure_threshold > 0
                                && e.consecutive_failures >= e.failure_threshold)
                    .ExecuteUpdateAsync(s => s
                        .SetProperty(e => e.status, ArkWebhookStatus.Disabled)
                        .SetProperty(e => e.disabled_at, now)
                        .SetProperty(e => e.disabled_reason, reason)
                        .SetProperty(e => e.updated_at, now), CancellationToken.None);
                if (disabled == 1)
                {
                    _log.LogWarning("Ark webhook endpoint {Endpoint} ({Name}, tenant {Tenant}) was disabled after {Count} consecutive failures.",
                        ep.Id, ep.Row.name, ep.TenantId, ep.Row.failure_threshold);
                    await _registry.RefreshAsync(CancellationToken.None);
                    return true;
                }
            }
            catch (Exception ex) { _log.LogDebug(ex, "Ark webhooks could not record a failure for {Endpoint}.", ep.Id); }
            return false;
        }

        /// <summary>
        /// Moves everything still waiting for an endpoint to the dead-letter queue — after it was
        /// disabled — so it can be replayed once the receiver is fixed, instead of retrying into a
        /// receiver known to be down.
        /// </summary>
        internal async Task<int> DeadLetterWaitingAsync(string endpointId, string reason, CancellationToken ct)
        {
            var moved = 0;
            var shards = _registry.Current?.Shards.Where(s => s.endpoint_id == null || s.endpoint_id == endpointId).ToList() ?? new();
            foreach (var shard in shards)
            {
                try
                {
                    await using var ctx = _dbs.Shard(shard.database_name, shard.table_suffix);
                    while (!ct.IsCancellationRequested)
                    {
                        var rows = await ctx.deliveries.AsNoTracking()
                            .Where(d => d.endpoint_id == endpointId && (d.status == ArkDeliveryStatus.Pending || d.status == ArkDeliveryStatus.Retrying))
                            .OrderBy(d => d.created_at).Take(200).ToListAsync(ct);
                        if (rows.Count == 0) break;
                        var progressed = 0;
                        foreach (var row in rows)
                        {
                            if (await DeadLetterRowAsync(ctx, row, row.lock_version, row.attempt_count, row.last_status_code,
                                    row.last_error ?? "the endpoint was disabled before this was sent", reason))
                            {
                                moved++;
                                progressed++;
                            }
                        }
                        if (progressed == 0) break;
                    }
                }
                catch (Exception ex) { _log.LogDebug(ex, "Ark webhooks could not dead-letter waiting deliveries in {Shard}.", shard.id); }
            }
            Interlocked.Add(ref _dead, moved);
            return moved;
        }

        // ------------------------------------------------------------ housekeeping

        /// <summary>
        /// Retention and shard upkeep, every <see cref="ArkWebhookOptions.HousekeepingMinutes"/> on every instance. Every step is
        /// idempotent, so instances running it at once only find less to do.
        /// </summary>
        internal async Task HousekeepingAsync(CancellationToken ct)
        {
            try
            {
                var options = _registry.Options;
                var snapshot = _registry.Current;
                if (snapshot == null) return;
                var now = DateTime.UtcNow;
                var keep = now.AddDays(-Math.Max(1, options.RetentionDays));
                var keepDead = now.AddDays(-Math.Max(1, options.DeadLetterRetentionDays));

                var routed = new HashSet<string>(StringComparer.Ordinal);
                foreach (var ep in snapshot.Endpoints.Values)
                    foreach (var (db, suffix) in ArkWebhookRouter.Targets(ep.Plan, now))
                        routed.Add(ArkWebhookRouter.ShardId(db, suffix));

                foreach (var shard in snapshot.Shards)
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        await using var ctx = _dbs.Shard(shard.database_name, shard.table_suffix);
                        // Finished deliveries past retention, attempts first.
                        await ctx.attempts.Where(a => ctx.deliveries.Any(d => d.id == a.delivery_id
                                && (d.status == ArkDeliveryStatus.Delivered || d.status == ArkDeliveryStatus.Cancelled || d.status == ArkDeliveryStatus.TestFailed)
                                && d.updated_at < keep))
                            .ExecuteDeleteAsync(ct);
                        await ctx.deliveries.Where(d => (d.status == ArkDeliveryStatus.Delivered || d.status == ArkDeliveryStatus.Cancelled || d.status == ArkDeliveryStatus.TestFailed)
                                && d.updated_at < keep)
                            .ExecuteDeleteAsync(ct);
                        // Dead letters, and the deliveries and attempts behind them, on their own clock.
                        await ctx.dead_letters.Where(l => l.dead_at < keepDead).ExecuteDeleteAsync(ct);
                        await ctx.attempts.Where(a => ctx.deliveries.Any(d => d.id == a.delivery_id && d.status == ArkDeliveryStatus.Dead && d.updated_at < keepDead))
                            .ExecuteDeleteAsync(ct);
                        await ctx.deliveries.Where(d => d.status == ArkDeliveryStatus.Dead && d.updated_at < keepDead).ExecuteDeleteAsync(ct);

                        var unfinished = await ctx.deliveries.AnyAsync(d =>
                            d.status == ArkDeliveryStatus.Pending || d.status == ArkDeliveryStatus.Retrying || d.status == ArkDeliveryStatus.InFlight, ct);

                        await using var ctl = _dbs.Control();
                        if (shard.status == "active" && !routed.Contains(shard.id) && !unfinished)
                        {
                            // Nothing routes here any more (last month's table, a plan that changed)
                            // and nothing waits: stop scanning it. History stays readable.
                            await ctl.shards.Where(s => s.id == shard.id && s.status == "active")
                                .ExecuteUpdateAsync(s => s.SetProperty(x => x.status, "sealed").SetProperty(x => x.sealed_at, now), ct);
                        }
                        else if (shard.status != "active" && unfinished)
                        {
                            // A delivery landed as the shard was being sealed: scan it again.
                            await ctl.shards.Where(s => s.id == shard.id)
                                .ExecuteUpdateAsync(s => s.SetProperty(x => x.status, "active").SetProperty(x => x.sealed_at, (DateTime?)null), ct);
                        }
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        LastError = $"housekeeping {shard.id}: {ex.GetBaseException().Message}";
                        _log.LogWarning(ex, "Ark webhooks housekeeping skipped shard {Shard}; it is tried again next run.", shard.id);
                    }
                }
                LastHousekeeping = DateTime.UtcNow;
                _registry.Invalidate();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _log.LogWarning(ex, "Ark webhooks housekeeping failed; it runs again next interval.");
            }
        }
    }
}
