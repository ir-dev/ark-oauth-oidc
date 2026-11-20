using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Ark.oAuth.Oidc.Protocol
{
    /// <summary>
    /// Purges expired codes, refresh tokens, device codes, pushed requests, used assertions and
    /// sessions on a timer (<see cref="ArkOidcOptions.CleanupIntervalMinutes"/>, 0 turns it off).
    ///
    /// <see cref="ArkGrantStore.CleanupExpiredAsync"/> existed with no caller, so every row of
    /// short-lived state was kept for ever — and PAR, which a public client can call with nothing
    /// but its id, let anyone add to that at will.
    ///
    /// Safe on several instances at once: each run deletes only rows already expired, so two
    /// instances racing simply find less to do. A run that fails — no database yet while the
    /// setup wizard is up, a transient outage — is logged and tried again next interval.
    /// </summary>
    public sealed class ArkGrantCleanupService : BackgroundService
    {
        private readonly IServiceScopeFactory _scopes;
        private readonly IConfiguration _config;
        private readonly ILogger<ArkGrantCleanupService> _log;

        public ArkGrantCleanupService(IServiceScopeFactory scopes, IConfiguration config, ILogger<ArkGrantCleanupService> log)
        {
            _scopes = scopes;
            _config = config;
            _log = log;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            // Not at start-up: the first requests bootstrap the database, and the wizard may not
            // have written a connection string yet.
            var delay = TimeSpan.FromMinutes(5);
            while (!stoppingToken.IsCancellationRequested)
            {
                try { await Task.Delay(delay, stoppingToken); }
                catch (OperationCanceledException) { return; }

                // Read per run, so the setting can change without a restart.
                var minutes = _config.GetValue("ark_oauth_server:Oidc:CleanupIntervalMinutes", 60);
                delay = TimeSpan.FromMinutes(minutes > 0 ? minutes : 60);
                if (minutes <= 0) continue;

                try
                {
                    using var scope = _scopes.CreateScope();
                    var removed = await scope.ServiceProvider.GetRequiredService<ArkGrantStore>().CleanupExpiredAsync();
                    if (removed > 0) _log.LogInformation("Ark IdP removed {Count} expired grant rows.", removed);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _log.LogWarning(ex, "Ark IdP expired-grant cleanup failed; it will run again in {Minutes} minutes.", delay.TotalMinutes);
                }
            }
        }
    }
}
