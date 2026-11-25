using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Ark.oAuth.Oidc
{
    /// <summary>
    /// Writes the audit trail off the request path, in batches.
    ///
    /// <see cref="DataAccess.Log"/> used to insert its row then and there: a synchronous
    /// <c>SaveChanges</c> on the request's own context, once per event. An authorization request
    /// logs two or three events, so with <c>EnableLogTrace</c> on — which the sample host ships —
    /// every sign-in blocked a thread on two or three extra round trips to the database, and a
    /// row that failed to insert stayed in the request's change tracker to fail the next save too.
    ///
    /// Rows are queued here instead and inserted a few hundred at a time on one connection. The
    /// trade is the usual one for a trace: a row reaches the table a moment after the event, and
    /// what is still queued when the process is killed outright is lost (a normal shutdown drains
    /// it). <see cref="DataAccess.Record"/> — the audit rows for an import or a factory reset —
    /// does not come through here; those are written before the call returns.
    ///
    /// The queue is bounded. If the database cannot keep up, the newest trace rows are dropped and
    /// counted, rather than the process growing without limit behind a store that is already
    /// struggling.
    /// </summary>
    public sealed class ArkAuditWriter : BackgroundService
    {
        private const int Capacity = 20_000;
        private const int BatchSize = 500;

        private readonly Channel<ArkAudit> _queue = Channel.CreateBounded<ArkAudit>(new BoundedChannelOptions(Capacity)
        {
            FullMode = BoundedChannelFullMode.DropWrite,
            SingleReader = true
        });

        private readonly IServiceScopeFactory _scopes;
        private readonly ILogger<ArkAuditWriter> _log;
        private volatile bool _running;
        private long _dropped;

        public ArkAuditWriter(IServiceScopeFactory scopes, ILogger<ArkAuditWriter> log)
        {
            _scopes = scopes;
            _log = log;
        }

        /// <summary>The longest text a row keeps in <c>details</c>: a stack trace, a list of what changed.</summary>
        internal const int MaxDetails = 4000;
        /// <summary>...and in each of its other columns.</summary>
        internal const int MaxText = 400;

        /// <summary>
        /// The row with every text in it fit to store (<see cref="ArkText"/>), of a length worth
        /// storing, and none of them null: the columns are required, and what is in them was
        /// partly typed by whoever was being turned away. A form field may be megabytes.
        /// </summary>
        internal static ArkAudit Storable(ArkAudit row)
        {
            row.ref_key = ArkText.Truncate(row.ref_key, MaxText) ?? "";
            row.ref_val = ArkText.Truncate(row.ref_val, MaxText) ?? "";
            row.log_type = ArkText.Truncate(row.log_type, MaxText) ?? "";
            row.message = ArkText.Truncate(row.message, MaxText) ?? "";
            row.details = ArkText.Truncate(row.details, MaxDetails) ?? "";
            row.by = ArkText.Truncate(row.by, MaxText) ?? "";
            row.ip = ArkText.Truncate(row.ip, MaxText) ?? "";
            return row;
        }

        /// <summary>
        /// Queues a row. False when the writer is not running — a host that registered the
        /// services without starting hosted services, or one that is shutting down — and the
        /// caller then writes the row itself, as it always did.
        /// </summary>
        public bool TryEnqueue(ArkAudit row)
        {
            if (!_running) return false;
            if (!_queue.Writer.TryWrite(Storable(row))) Interlocked.Increment(ref _dropped);
            return true;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _running = true;
            var batch = new List<ArkAudit>(BatchSize);
            try
            {
                while (await _queue.Reader.WaitToReadAsync(stoppingToken))
                {
                    batch.Clear();
                    while (batch.Count < BatchSize && _queue.Reader.TryRead(out var row)) batch.Add(row);
                    await WriteAsync(batch);
                }
            }
            catch (OperationCanceledException)
            {
            }
            finally
            {
                // From here DataAccess writes inline again; what is already queued is drained below.
                _running = false;
                batch.Clear();
                while (_queue.Reader.TryRead(out var row))
                {
                    batch.Add(row);
                    if (batch.Count < BatchSize) continue;
                    await WriteAsync(batch);
                    batch.Clear();
                }
                await WriteAsync(batch);
            }
        }

        private async Task WriteAsync(List<ArkAudit> batch)
        {
            if (batch.Count == 0) return;
            try
            {
                using var scope = _scopes.CreateScope();
                var ctx = scope.ServiceProvider.GetRequiredService<ArkDataContext>();
                ctx.audit_trace.AddRange(batch);
                await ctx.SaveChangesAsync();

                var dropped = Interlocked.Exchange(ref _dropped, 0);
                if (dropped > 0)
                    _log.LogWarning("Ark IdP dropped {Count} audit rows: the audit queue was full.", dropped);
            }
            catch (Exception ex)
            {
                // Never fatal, as it never was: a trace that cannot be written must not take the
                // server down. Before the setup wizard has run there is no database to write to.
                var lost = await WriteSinglyAsync(batch);
                _log.LogWarning(ex, "Ark IdP could not write {Count} of {Total} audit rows.", lost, batch.Count);
            }
        }

        /// <summary>
        /// Writes a batch the database refused again, one row at a time, and says how many were
        /// lost. The rows are the audit trail of everybody who did anything in the same moment:
        /// one that cannot be stored costs itself, not the rest. Only when the database answers at
        /// all; a database that is down is not asked five hundred times.
        /// </summary>
        private async Task<int> WriteSinglyAsync(List<ArkAudit> batch)
        {
            if (batch.Count < 2) return batch.Count;
            try
            {
                using var probe = _scopes.CreateScope();
                if (!await probe.ServiceProvider.GetRequiredService<ArkDataContext>().Database.CanConnectAsync()) return batch.Count;
            }
            catch
            {
                return batch.Count;
            }

            var lost = 0;
            foreach (var row in batch)
            {
                try
                {
                    // A context each: one that has failed keeps the row it failed on.
                    using var scope = _scopes.CreateScope();
                    var ctx = scope.ServiceProvider.GetRequiredService<ArkDataContext>();
                    ctx.audit_trace.Add(row);
                    await ctx.SaveChangesAsync();
                }
                catch
                {
                    lost++;
                }
            }
            return lost;
        }
    }
}
