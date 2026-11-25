using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Ark.oAuth.Oidc.Webhooks
{
    /// <summary>One event, already serialized into the exact body every endpoint will receive.</summary>
    public sealed class ArkWebhookEvent
    {
        public string id { get; init; } = default!;
        public string type { get; init; } = default!;
        public string tenant_id { get; init; } = default!;
        public string? subject { get; init; }
        public DateTime created_at { get; init; }
        /// <summary>The JSON envelope: id, type, tenant_id, subject, created_at, data.</summary>
        public string body { get; init; } = default!;
        /// <summary>When set, the event goes to this endpoint only, whatever it subscribes to (tests).</summary>
        public string? only_endpoint { get; init; }

        private static readonly JsonSerializerOptions Json = new() { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never };

        public static string NewId() => "evt_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

        public static ArkWebhookEvent Create(string tenantId, string type, object? data, string? subject, string? onlyEndpoint = null)
        {
            var id = NewId();
            var now = DateTime.UtcNow;
            var body = JsonSerializer.Serialize(new
            {
                id,
                type,
                tenant_id = tenantId,
                subject,
                created_at = now.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                data = data ?? new { }
            }, Json);
            return new ArkWebhookEvent { id = id, type = type, tenant_id = tenantId, subject = subject, created_at = now, body = body, only_endpoint = onlyEndpoint };
        }
    }

    /// <summary>
    /// Raises webhook events. Inject it in host code to publish events of your own; the IdP
    /// raises its built-in ones through <see cref="ArkWebhookEvents.Raise"/>.
    /// </summary>
    public interface IArkWebhookPublisher
    {
        /// <summary>
        /// Queues an event and returns at once. Never throws and never waits on the database:
        /// true when the event was queued, false when nothing subscribes to it, webhooks are off,
        /// or the queue is full. An event still queued when the process is killed outright is lost
        /// (a normal shutdown writes it).
        /// </summary>
        bool Publish(string tenantId, string eventType, object? data = null, string? subject = null);

        /// <summary>Writes the deliveries before returning; the number written. For callers that must not lose the event.</summary>
        Task<int> PublishAndWaitAsync(string tenantId, string eventType, object? data = null, string? subject = null, CancellationToken ct = default);
    }

    public sealed class ArkWebhookPublisher : IArkWebhookPublisher
    {
        private readonly ArkWebhookRegistry _registry;
        private readonly ArkWebhookFanout _fanout;
        private readonly ILogger<ArkWebhookPublisher> _log;
        private Channel<ArkWebhookEvent>? _queue;
        private readonly object _gate = new();
        private long _dropped;
        private long _accepted;

        public ArkWebhookPublisher(ArkWebhookRegistry registry, ArkWebhookFanout fanout, ILogger<ArkWebhookPublisher> log)
        {
            _registry = registry;
            _fanout = fanout;
            _log = log;
        }

        public long Dropped => Interlocked.Read(ref _dropped);
        public long Accepted => Interlocked.Read(ref _accepted);
        public int Queued => _queue?.Reader.CanCount == true ? _queue.Reader.Count : 0;

        internal ChannelReader<ArkWebhookEvent> Reader => Queue.Reader;

        private Channel<ArkWebhookEvent> Queue
        {
            get
            {
                if (_queue != null) return _queue;
                lock (_gate)
                {
                    return _queue ??= Channel.CreateBounded<ArkWebhookEvent>(new BoundedChannelOptions(_registry.Options.EffectiveQueueCapacity)
                    {
                        FullMode = BoundedChannelFullMode.DropWrite,
                        SingleReader = true
                    });
                }
            }
        }

        internal long TakeDropped() => Interlocked.Exchange(ref _dropped, 0);

        public bool Publish(string tenantId, string eventType, object? data = null, string? subject = null)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(tenantId) || string.IsNullOrWhiteSpace(eventType)) return false;
                var options = _registry.Options;
                if (!options.Enabled) return false;
                // Decided before anything is serialized: an event nobody subscribes to costs a
                // walk over the endpoints in memory and nothing else.
                if (!_registry.Wants(tenantId.Trim(), eventType.Trim())) return false;
                var evt = ArkWebhookEvent.Create(tenantId.Trim(), eventType.Trim(), data, subject);
                if (evt.body.Length > options.EffectiveMaxPayloadBytes)
                {
                    _log.LogWarning("Ark webhooks dropped a {Type} event: {Bytes} bytes is over MaxPayloadBytes.", evt.type, evt.body.Length);
                    return false;
                }
                if (!Queue.Writer.TryWrite(evt))
                {
                    Interlocked.Increment(ref _dropped);
                    return false;
                }
                Interlocked.Increment(ref _accepted);
                return true;
            }
            catch (Exception ex)
            {
                // Never into the caller: an event is not worth failing a sign-in over.
                _log.LogDebug(ex, "Ark webhooks could not queue an event.");
                return false;
            }
        }

        public async Task<int> PublishAndWaitAsync(string tenantId, string eventType, object? data = null, string? subject = null, CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(tenantId) || string.IsNullOrWhiteSpace(eventType))
                throw new ArgumentException("tenantId and eventType are required.");
            if (!_registry.Options.Enabled) return 0;
            if (!_registry.Loaded) await _registry.RefreshAsync(ct);
            var evt = ArkWebhookEvent.Create(tenantId.Trim(), eventType.Trim(), data, subject);
            return await _fanout.WriteAsync(new[] { evt }, "api", ct);
        }
    }

    /// <summary>Wakes the dispatcher when this instance has just written deliveries.</summary>
    public sealed class ArkWebhookSignal
    {
        private readonly SemaphoreSlim _signal = new(0, 1);

        public void Pulse()
        {
            try { _signal.Release(); } catch (SemaphoreFullException) { }
        }

        public async Task WaitAsync(TimeSpan timeout, CancellationToken ct)
        {
            try { await _signal.WaitAsync(timeout, ct); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
        }
    }

    /// <summary>
    /// Turns events into delivery rows: one per matching endpoint, written to the shard its plan
    /// chooses. The rows are the durable queue the dispatcher works from.
    /// </summary>
    public sealed class ArkWebhookFanout
    {
        private readonly ArkWebhookRegistry _registry;
        private readonly ArkWebhookDatabases _dbs;
        private readonly ArkWebhookSignal _signal;

        public ArkWebhookFanout(ArkWebhookRegistry registry, ArkWebhookDatabases dbs, ArkWebhookSignal signal)
        {
            _registry = registry;
            _dbs = dbs;
            _signal = signal;
        }

        public async Task<int> WriteAsync(IReadOnlyList<ArkWebhookEvent> events, string trigger, CancellationToken ct, int attemptsPerShard = 1)
        {
            var now = DateTime.UtcNow;
            var groups = new Dictionary<(string Db, string Suffix), (ArkWebhookEndpointView Ep, List<ArkWebhookDelivery> Rows)>();
            foreach (var evt in events)
            {
                IEnumerable<ArkWebhookEndpointView> targets;
                if (evt.only_endpoint != null)
                {
                    var one = _registry.Endpoint(evt.only_endpoint);
                    targets = one == null ? Array.Empty<ArkWebhookEndpointView>() : new[] { one };
                }
                else targets = _registry.Matching(evt.tenant_id, evt.type);

                foreach (var ep in targets)
                {
                    // An endpoint receives what happened after it existed. An event raised while
                    // the endpoint list was still loading is decided once it has loaded, and must
                    // not reach an endpoint created in the meantime.
                    if (evt.only_endpoint == null && ep.Row.created_at > evt.created_at) continue;
                    var partition = ArkWebhookRouter.PartitionValue(ep.Plan, evt);
                    var shard = ArkWebhookRouter.Route(ep.Plan, partition, now);
                    if (!groups.TryGetValue(shard, out var group))
                        groups[shard] = group = (ep, new List<ArkWebhookDelivery>());
                    group.Rows.Add(new ArkWebhookDelivery
                    {
                        id = NewDeliveryId(),
                        endpoint_id = ep.Id,
                        tenant_id = evt.tenant_id,
                        event_id = evt.id,
                        event_type = evt.type,
                        partition_key = Truncate(partition, 256),
                        payload = evt.body,
                        status = ArkDeliveryStatus.Pending,
                        next_attempt_at = now,
                        created_at = now,
                        updated_at = now,
                        trigger = trigger
                    });
                }
            }

            // Each shard is written, and retried, on its own: a retry of the whole batch after one
            // shard failed would write the others twice.
            var written = 0;
            var lost = 0;
            Exception? failure = null;
            foreach (var ((db, suffix), group) in groups)
            {
                for (var attempt = 1; ; attempt++)
                {
                    try
                    {
                        await _registry.EnsureShardAsync(db, suffix, group.Ep.Plan.Strategy, group.Ep.Id, ct);
                        await using var shard = _dbs.Shard(db, suffix);
                        shard.deliveries.AddRange(group.Rows);
                        await shard.SaveChangesAsync(ct);
                        written += group.Rows.Count;
                        break;
                    }
                    catch (Exception ex)
                    {
                        if (await WriteSinglyAsync(db, suffix, group.Rows, ct) is { } singly)
                        {
                            written += singly.Written;
                            lost += group.Rows.Count - singly.Written;
                            failure ??= singly.Failure;
                            break;
                        }
                        if (attempt < attemptsPerShard && !ct.IsCancellationRequested)
                        {
                            try { await Task.Delay(TimeSpan.FromSeconds(1 << attempt), ct); } catch (OperationCanceledException) { }
                            continue;
                        }
                        lost += group.Rows.Count;
                        failure ??= ex;
                        break;
                    }
                }
            }
            if (written > 0) _signal.Pulse();
            if (failure != null)
                throw new ArkWebhookFanoutException(written, lost, failure);
            return written;
        }

        public static string NewDeliveryId() => "dlv_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

        /// <summary>
        /// Writes rows a shard refused together again, one at a time: an event that cannot be
        /// stored costs itself, not the hundreds that happened to be waiting beside it. Null when
        /// there is only one, or the database does not answer; then nothing is wrong with the rows
        /// and the batch is worth trying again.
        /// </summary>
        private async Task<(int Written, Exception? Failure)?> WriteSinglyAsync(string db, string suffix, List<ArkWebhookDelivery> rows, CancellationToken ct)
        {
            if (rows.Count < 2 || ct.IsCancellationRequested) return null;
            try
            {
                await using var probe = _dbs.Shard(db, suffix);
                if (!await probe.Database.CanConnectAsync(ct)) return null;
            }
            catch
            {
                return null;
            }

            var written = 0;
            Exception? failure = null;
            foreach (var row in rows)
            {
                try
                {
                    // A context each: one that has failed keeps the row it failed on.
                    await using var shard = _dbs.Shard(db, suffix);
                    shard.deliveries.Add(row);
                    await shard.SaveChangesAsync(ct);
                    written++;
                }
                catch (Exception ex)
                {
                    failure ??= ex;
                }
            }
            return (written, failure);
        }

        internal static string? Truncate(string? value, int max) => ArkText.Truncate(value, max);
    }

    /// <summary>Some shards of a fan-out could not be written; the others were.</summary>
    public sealed class ArkWebhookFanoutException : Exception
    {
        public int Written { get; }
        public int Lost { get; }

        public ArkWebhookFanoutException(int written, int lost, Exception inner)
            : base($"{lost} deliveries could not be written ({written} were): {inner.GetBaseException().Message}", inner)
        {
            Written = written;
            Lost = lost;
        }
    }

    /// <summary>
    /// Writes queued events to the delivery tables, off the request path and in batches — the
    /// same shape as <see cref="ArkAuditWriter"/>. A batch that cannot be written is tried again
    /// a few times, then dropped and logged: the queue is bounded so a database outage costs
    /// events, never the IdP's memory.
    /// </summary>
    public sealed class ArkWebhookIngestor : BackgroundService
    {
        private const int BatchSize = 500;
        private readonly ArkWebhookPublisher _publisher;
        private readonly ArkWebhookFanout _fanout;
        private readonly ArkWebhookRegistry _registry;
        private readonly ILogger<ArkWebhookIngestor> _log;

        public ArkWebhookIngestor(ArkWebhookPublisher publisher, ArkWebhookFanout fanout, ArkWebhookRegistry registry, ILogger<ArkWebhookIngestor> log)
        {
            _publisher = publisher;
            _fanout = fanout;
            _registry = registry;
            _log = log;
        }

        public long Written { get; private set; }
        public long Lost { get; private set; }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            var reader = _publisher.Reader;
            var batch = new List<ArkWebhookEvent>(BatchSize);
            try
            {
                while (await reader.WaitToReadAsync(stoppingToken))
                {
                    batch.Clear();
                    while (batch.Count < BatchSize && reader.TryRead(out var evt)) batch.Add(evt);
                    await WriteWithRetryAsync(batch, stoppingToken);
                    var dropped = _publisher.TakeDropped();
                    if (dropped > 0) _log.LogWarning("Ark webhooks dropped {Count} events: the queue was full.", dropped);
                }
            }
            catch (OperationCanceledException) { }
            finally
            {
                // A normal shutdown writes what is queued, with a deadline of its own.
                batch.Clear();
                while (reader.TryRead(out var evt)) batch.Add(evt);
                if (batch.Count > 0)
                {
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                    await WriteWithRetryAsync(batch, cts.Token, attempts: 1);
                }
            }
        }

        private async Task WriteWithRetryAsync(List<ArkWebhookEvent> batch, CancellationToken ct, int attempts = 4)
        {
            if (batch.Count == 0) return;
            // Events raised in the first seconds after start-up wait for the endpoint list.
            for (var i = 0; i < 30 && !_registry.Loaded && !ct.IsCancellationRequested; i++)
            {
                try { await Task.Delay(1000, ct); } catch (OperationCanceledException) { break; }
            }
            if (!_registry.Loaded)
            {
                Lost += batch.Count;
                return;
            }
            try
            {
                Written += await _fanout.WriteAsync(batch, "system", ct, attempts);
            }
            catch (ArkWebhookFanoutException ex)
            {
                Written += ex.Written;
                Lost += ex.Lost;
                _log.LogWarning(ex.InnerException, "Ark webhooks lost {Count} deliveries: they could not be written.", ex.Lost);
            }
            catch (Exception ex)
            {
                Lost += batch.Count;
                _log.LogWarning(ex, "Ark webhooks lost {Count} events: they could not be written.", batch.Count);
            }
        }
    }
}
