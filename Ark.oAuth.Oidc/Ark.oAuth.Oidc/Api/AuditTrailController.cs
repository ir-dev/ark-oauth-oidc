using System.Text.Json.Nodes;
using Ark.Watch.Core;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Ark.oAuth.Oidc
{
    /// <summary>
    /// The audit trail's destination, changed while the server runs: the API behind the console's
    /// Audit trail page (<c>/{tenant}/admin/audit</c>).
    ///
    /// Behind the same policy as the rest of the management API (<see cref="ArkManagementAuth"/>):
    /// the operator's console session, or a <c>client.register</c> token of the machine client. A
    /// saved destination is kept in the database (<see cref="ArkWatchConsoleSettings"/>), applies
    /// on this instance at once and on every other within the reference-cache window, and replaces
    /// <c>ark_oauth_server:Watch</c> until it is removed. <c>Watch:AllowConsoleChanges = false</c>
    /// makes every change here answer 403.
    ///
    /// <b>A change is itself on the record.</b> It is recorded in the trail that is closing, before
    /// its client is flushed and closed, then as the first event of the trail that opens, and in this
    /// server's own <c>audit_trace</c> whatever <c>EnableLogTrace</c> says. Turning the trail off is
    /// therefore the last thing the old destination receives, with who did it.
    ///
    /// Every change is a POST with a JSON body ([Consumes]): a browser sends application/json
    /// cross-origin only after a CORS preflight this server never grants. Responses are
    /// <c>{ error, code, msg, data }</c> with a real HTTP status. No response carries a key.
    /// </summary>
    [Authorize(Policy = ArkManagementAuth.PolicyName)]
    [Route("api/oauth/v1/watch")]
    [ApiController]
    public class ArkAuditTrailController : ControllerBase
    {
        private ArkWatchConsoleSettings Store => HttpContext.RequestServices.GetRequiredService<ArkWatchConsoleSettings>();
        private ArkWatchAudit Audit => HttpContext.RequestServices.GetRequiredService<ArkWatchAudit>();
        private ArkWatchConfig? Configured => Protocol.ArkConfigSnapshot.Server(HttpContext.RequestServices.GetRequiredService<IConfiguration>())?.Watch;
        private string EnvironmentName => HttpContext.RequestServices.GetRequiredService<IHostEnvironment>().EnvironmentName;

        /// <summary>
        /// What is in effect and where it comes from, what the console saved, what configuration
        /// says, and this instance's counters. Read from the database now, so this instance follows
        /// a change made on another one as soon as somebody looks.
        /// </summary>
        [HttpGet("settings")]
        public async Task<IActionResult> Settings()
        {
            Response.Headers.CacheControl = "no-store";
            await Store.LoadAsync();
            return Ok(new { error = false, code = "settings", msg = "audit trail settings.", data = View() });
        }

        /// <summary>
        /// Tests a destination without saving it: the wizard's test (<c>GET /api/whoami</c> with the
        /// key, then one event through the client). A blank key is the one in use, on the same server only.
        /// </summary>
        // CSRF: JSON-only ([Consumes]) and no CORS grant, so a cross-site page cannot send it; operator-only.
        [HttpPost("test")]  // nosemgrep: csharp.dotnet.security.mvc-missing-antiforgery.mvc-missing-antiforgery
        [Consumes("application/json")]
        public async Task<IActionResult> Test([FromBody] ArkWatchSettingsRequest? request)
        {
            Response.Headers.CacheControl = "no-store";
            if (!Store.Allowed) return Locked();
            request ??= new ArkWatchSettingsRequest();
            request.enabled = true;
            try
            {
                await Store.LoadAsync();
                var (_, plan) = ArkWatchConsoleSettings.Prepare(request, Store.Current, Configured, EnvironmentName);
                var result = await ArkSetupMiddleware.TestWatchAsync(plan!, "console");
                return Ok(new { error = false, code = result.ok ? "connected" : "test_failed", msg = result.msg, data = new { result.ok } });
            }
            catch (ArkSetupMiddleware.SetupException ex)
            {
                return Refusal(400, ex.Code, ex.Message, ex.Field);
            }
        }

        /// <summary>
        /// Saves the destination and applies it. A destination that is on is tested first and not
        /// saved when the test fails (422 <c>test_failed</c>), unless <c>skip_test</c> says to save
        /// it anyway. <c>enabled: false</c> turns the trail off and keeps the destination.
        /// </summary>
        // CSRF: JSON-only ([Consumes]) and no CORS grant, so a cross-site page cannot send it; operator-only.
        [HttpPost("settings")]  // nosemgrep: csharp.dotnet.security.mvc-missing-antiforgery.mvc-missing-antiforgery
        [Consumes("application/json")]
        public async Task<IActionResult> Save([FromBody] ArkWatchSettingsRequest? request)
        {
            Response.Headers.CacheControl = "no-store";
            if (!Store.Allowed) return Locked();
            request ??= new ArkWatchSettingsRequest();

            await Store.LoadAsync();
            var before = Snapshot();
            ArkWatchStoredValue value;
            ArkSetupMiddleware.WatchPlan? plan;
            try
            {
                (value, plan) = ArkWatchConsoleSettings.Prepare(request, Store.Current, Configured, EnvironmentName);
            }
            catch (ArkSetupMiddleware.SetupException ex)
            {
                return Refusal(400, ex.Code, ex.Message, ex.Field);
            }

            var tested = false;
            if (plan != null && !request.skip_test)
            {
                var result = await ArkSetupMiddleware.TestWatchAsync(plan, "console");
                if (!result.ok)
                    return Refusal(422, "test_failed", $"{result.msg} Nothing was saved.", null, new { can_skip = true });
                tested = true;
            }

            var db = HttpContext.RequestServices.GetRequiredService<ArkDataContext>();
            var who = Who();
            ArkWatchStored written;
            try
            {
                written = await Store.WriteAsync(db, value, who);
            }
            catch (Exception ex)
            {
                Da.LogError(ex, "audit_trail_update", "watch", "the audit trail's destination could not be saved");
                return Refusal(500, "save_failed", $"The destination could not be saved: {ex.Message}");
            }

            var after = Describe(written.Config, "console");
            var action = value.Enabled ? "audit_trail.update" : "audit_trail.disable";
            var message = value.Enabled
                ? $"audit trail set in the console: {after.Endpoint} as {after.Application} ({after.Environment})"
                : "audit trail turned off in the console";
            // Turning it off copies no key, so "changed" would say nothing true.
            var keyChanged = value.Enabled && !string.Equals(before.Key, written.Config.ApiKey?.Trim(), StringComparison.Ordinal);
            Apply(written, () => ChangeEvent(action, message, before, after, keyChanged, tested, request.skip_test && plan != null),
                "audit_trail_update", message, Details(before, after, keyChanged, tested), who);

            return Ok(new
            {
                error = false,
                code = value.Enabled ? "saved" : "turned_off",
                msg = value.Enabled
                    ? $"Saved. The audit trail now goes to {after.Endpoint}, on this instance at once and on the others within {Store.WindowSeconds} seconds."
                    : $"Saved. The audit trail is off, on this instance at once and on the others within {Store.WindowSeconds} seconds.",
                data = View()
            });
        }

        /// <summary>Removes the destination saved in the console: configuration applies again.</summary>
        // CSRF: JSON-only ([Consumes]) and no CORS grant, so a cross-site page cannot send it; operator-only.
        [HttpPost("settings/remove")]  // nosemgrep: csharp.dotnet.security.mvc-missing-antiforgery.mvc-missing-antiforgery
        [Consumes("application/json")]
        public async Task<IActionResult> Remove([FromBody] JsonObject? body)
        {
            Response.Headers.CacheControl = "no-store";
            if (!Store.Allowed) return Locked();

            await Store.LoadAsync();
            if (Store.Current == null)
                return Ok(new { error = false, code = "nothing_saved", msg = "Nothing was saved in the console: configuration already applies.", data = View() });

            var before = Snapshot();
            var db = HttpContext.RequestServices.GetRequiredService<ArkDataContext>();
            var who = Who();
            try
            {
                await Store.DeleteAsync(db);
            }
            catch (Exception ex)
            {
                Da.LogError(ex, "audit_trail_revert", "watch", "the audit trail's console settings could not be removed");
                return Refusal(500, "remove_failed", $"The console's settings could not be removed: {ex.Message}");
            }

            var configured = Configured;
            var after = ArkWatchConsoleSettings.Names(configured) ? Describe(configured!, "configuration") : Destination.None;
            var message = after.Source == "none"
                ? "audit trail settings removed from the console; configuration names no destination, so nothing is sent"
                : $"audit trail settings removed from the console; configuration applies again: {after.Endpoint}";
            var keyChanged = !string.Equals(before.Key, configured?.ApiKey?.Trim(), StringComparison.Ordinal);
            Apply(null, () => ChangeEvent("audit_trail.revert", message, before, after, keyChanged, false, false),
                "audit_trail_revert", message, Details(before, after, keyChanged, false), who);

            return Ok(new
            {
                error = false,
                code = "removed",
                msg = after.Source == "none"
                    ? "Removed. Configuration names no audit destination, so nothing is sent."
                    : $"Removed. Configuration applies again: {after.Endpoint}, on this instance at once and on the others within {Store.WindowSeconds} seconds.",
                data = View()
            });
        }

        // ---------------------------------------------------------------- applying a change

        /// <summary>
        /// Records the change where the trail goes now, makes the new destination this instance's,
        /// and — when that opened a different client — records it again as the new trail's first event.
        /// The old client is flushed and closed as the new one is built, so the record of the change
        /// reaches the old node, or its spool, before anything is sent to the new one.
        /// </summary>
        private void Apply(ArkWatchStored? stored, Func<ArkWatchEvent> change, string refKey, string message, string details, string who)
        {
            var audit = Audit;
            var oldClient = audit.ActiveClient();
            Da.Record(refKey, "watch", message, details, who, ArkWatchAudit.Address(HttpContext), change().With("phase", "closing"));
            Store.Publish(stored);
            var newClient = audit.ActiveClient();
            // A second event, not the first one changed: the client may still hold the first one's
            // attributes, unsent, in its ring.
            if (newClient != null && !ReferenceEquals(newClient, oldClient))
                audit.Log(HttpContext, change().With("phase", "opening"));
        }

        private sealed record Destination(string Source, bool Enabled, string? Endpoint, string? Application, string? Environment,
            bool ProtocolTrace, string? Key)
        {
            public static readonly Destination None = new("none", false, null, null, null, true, null);
        }

        /// <summary>What is in effect now, with the key itself, for comparing — never for a response.</summary>
        private Destination Snapshot()
        {
            var stored = Store.Current;
            if (stored != null) return Describe(stored.Config, "console");
            var configured = Configured;
            return ArkWatchConsoleSettings.Names(configured) ? Describe(configured!, "configuration") : Destination.None;
        }

        private Destination Describe(ArkWatchConfig c, string source) => new(
            source,
            c.Enabled,
            ArkWatchConsoleSettings.DisplayEndpoint(c.Endpoint),
            string.IsNullOrWhiteSpace(c.Application) ? ArkWatchConfig.DefaultApplication : c.Application.Trim(),
            string.IsNullOrWhiteSpace(c.Environment) ? EnvironmentName : c.Environment.Trim(),
            c.IncludeProtocolTrace,
            c.ApiKey?.Trim());

        private static ArkWatchEvent ChangeEvent(string action, string message, Destination before, Destination after,
            bool keyChanged, bool tested, bool testSkipped) =>
            new ArkWatchEvent
            {
                Action = action,
                Domain = ArkWatchDomains.Administration,
                System = "console",
                Level = AuditLevel.Security,
                Outcome = Outcome.Success,
                ResourceType = "audit_trail",
                ResourceId = "watch",
                Message = message
            }
            .With("from_source", before.Source).With("from_enabled", before.Enabled).With("from_endpoint", before.Endpoint)
            .With("from_application", before.Application).With("from_environment", before.Environment)
            .With("to_source", after.Source).With("to_enabled", after.Enabled).With("to_endpoint", after.Endpoint)
            .With("to_application", after.Application).With("to_environment", after.Environment)
            .With("to_protocol_trace", after.ProtocolTrace)
            .With("key_changed", keyChanged).With("tested", tested).With("test_skipped", testSkipped)
            .With("instance", Environment.MachineName);

        private static string Details(Destination before, Destination after, bool keyChanged, bool tested) =>
            $"from: {Line(before)}\nto: {Line(after)}\nkey: {(keyChanged ? "changed" : "unchanged")}, tested: {(tested ? "yes" : "no")}";

        private static string Line(Destination d) =>
            d.Source == "none" ? "nothing (none)"
            : $"{(d.Enabled ? "on" : "off")}, {d.Endpoint ?? "(no address)"} as {d.Application} ({d.Environment}), protocol trace {(d.ProtocolTrace ? "on" : "off")} ({d.Source})";

        // ---------------------------------------------------------------- what the page is shown

        private object View()
        {
            var store = Store;
            var configured = Configured;
            var stored = store.Current;
            return new
            {
                allow_console_changes = store.Allowed,
                source = stored != null ? "console" : ArkWatchConsoleSettings.Names(configured) ? "configuration" : "none",
                console = stored == null ? null : new
                {
                    updated_at = stored.UpdatedAt,
                    updated_by = stored.UpdatedBy,
                    settings = ArkWatchConsoleSettings.Describe(stored.Config)
                },
                configuration = configured == null || !ArkWatchConsoleSettings.Names(configured)
                    ? null : ArkWatchConsoleSettings.Describe(configured, withSpool: true),
                defaults = new { application = ArkWatchConfig.DefaultApplication, environment = EnvironmentName },
                refresh_seconds = store.WindowSeconds,
                instance = Environment.MachineName,
                status = Audit.Status()
            };
        }

        private string Who() => ArkWatchAudit.Operator(HttpContext)?.id ?? "operator";

        private DataAccess Da => HttpContext.RequestServices.GetRequiredService<DataAccess>();

        private IActionResult Locked() => Refusal(403, "console_changes_off",
            "The audit trail is pinned to configuration (ark_oauth_server:Watch:AllowConsoleChanges is false), so it cannot be changed here.");

        private static ObjectResult Refusal(int status, string code, string msg, string? field = null, object? data = null) =>
            new(new { error = true, code, msg, field, data }) { StatusCode = status };
    }
}
