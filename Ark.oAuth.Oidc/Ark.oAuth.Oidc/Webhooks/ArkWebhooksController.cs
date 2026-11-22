using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Ark.oAuth.Oidc.Webhooks
{
    /// <summary>
    /// Answers 404 for every webhook route when the host never called <c>AddArkWebhooks()</c>.
    ///
    /// MVC discovers every controller in this assembly whether or not the module is registered,
    /// so without this the routes would exist — and fail — on hosts that never opted in. A
    /// resource filter runs before the controller is constructed, so its services are never asked for.
    /// </summary>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public sealed class ArkWebhooksEnabledAttribute : Attribute, IResourceFilter
    {
        public void OnResourceExecuting(ResourceExecutingContext context)
        {
            if (context.HttpContext.RequestServices.GetService(typeof(ArkWebhookRegistry)) == null)
                context.Result = new NotFoundResult();
        }

        public void OnResourceExecuted(ResourceExecutedContext context) { }
    }

    /// <summary>
    /// The webhook management API — what /{tenant}/admin/webhooks drives, and what a script can
    /// drive with the machine client's token.
    ///
    /// Behind the same policy as the rest of the management API (<see cref="ArkManagementAuth"/>):
    /// the operator's console session or a <c>client.register</c> token of the machine client.
    /// An endpoint sends identity events — who signed in, from where — to a URL of the caller's
    /// choosing, so this is operator business and nobody else's.
    ///
    /// Every change is a POST with a JSON body ([Consumes]): a browser sends application/json
    /// cross-origin only after a CORS preflight this server never grants, so a page elsewhere
    /// cannot make a signed-in operator's browser create a webhook. Responses are
    /// <c>{ error, code, msg, data }</c> with a real HTTP status.
    /// </summary>
    [Authorize(Policy = ArkManagementAuth.PolicyName)]
    [Route("api/oauth/v1/webhooks")]
    [ApiController]
    [ArkWebhooksEnabled]
    public class ArkWebhooksController : ControllerBase
    {
        private ArkWebhookService Service => HttpContext.RequestServices.GetRequiredService<ArkWebhookService>();
        private DataAccess Da => HttpContext.RequestServices.GetRequiredService<DataAccess>();

        [HttpGet("meta")]
        public Task<IActionResult> Meta() => Run("meta", async () => Ok(Wrap("meta", "webhook settings", await Service.MetaAsync())));

        [HttpGet("list")]
        public Task<IActionResult> List([FromQuery] string? tenant_id) =>
            Run("list", async () => Ok(Wrap("list", "webhooks", await Service.ListAsync(tenant_id))));

        [HttpGet("get")]
        public Task<IActionResult> Get([FromQuery] string? id) =>
            Run("get", async () => Ok(Wrap("webhook", "webhook", await Service.GetAsync(id))));

        // CSRF: JSON-only ([Consumes]) and no CORS grant, so a cross-site page cannot send it; operator-only.
        [HttpPost("upsert")]  // nosemgrep: csharp.dotnet.security.mvc-missing-antiforgery.mvc-missing-antiforgery
        [Consumes("application/json")]
        public Task<IActionResult> Upsert([FromBody] ArkWebhookUpsertRequest request) => Run("upsert", async () =>
        {
            var (endpoint, secret, created) = await Service.UpsertAsync(request, Who());
            // The origin only: some receivers (Slack, Teams) carry their secret in the URL path.
            Audit(created ? "webhook_create" : "webhook_update", request?.id ?? "(new)", $"webhook '{request?.name}' {(created ? "created" : "updated")}",
                $"tenant: {request?.tenant_id}, host: {Origin(request?.url)}, events: {string.Join(" ", request?.events ?? new())}, auth: {request?.auth?.type}, shard: {request?.shard?.strategy}");
            return Ok(Wrap(created ? "created" : "updated",
                created ? "webhook created - copy the signing secret now; it is not shown again." : "webhook saved.",
                new { endpoint, signing_secret = secret }));
        });

        // CSRF: JSON-only ([Consumes]) and no CORS grant, so a cross-site page cannot send it; operator-only.
        [HttpPost("delete")]  // nosemgrep: csharp.dotnet.security.mvc-missing-antiforgery.mvc-missing-antiforgery
        [Consumes("application/json")]
        public Task<IActionResult> Delete([FromBody] ArkWebhookIdRequest request) => Run("delete", async () =>
        {
            var result = await Service.DeleteAsync(request, Who());
            Audit("webhook_delete", request?.id, "webhook deleted", $"purge: {request?.purge}");
            return Ok(Wrap("deleted", "webhook deleted.", result));
        });

        // CSRF: JSON-only ([Consumes]) and no CORS grant, so a cross-site page cannot send it; operator-only.
        [HttpPost("status")]  // nosemgrep: csharp.dotnet.security.mvc-missing-antiforgery.mvc-missing-antiforgery
        [Consumes("application/json")]
        public Task<IActionResult> Status([FromBody] ArkWebhookStatusRequest request) => Run("status", async () =>
        {
            var result = await Service.SetStatusAsync(request, Who());
            Audit("webhook_status", request?.id, $"webhook {request?.action}", "");
            return Ok(Wrap(request?.action ?? "status", $"webhook {request?.action} done.", result));
        });

        // CSRF: JSON-only ([Consumes]) and no CORS grant, so a cross-site page cannot send it; operator-only.
        [HttpPost("secret/rotate")]  // nosemgrep: csharp.dotnet.security.mvc-missing-antiforgery.mvc-missing-antiforgery
        [Consumes("application/json")]
        public Task<IActionResult> RotateSecret([FromBody] ArkWebhookIdRequest request) => Run("rotate", async () =>
        {
            var secret = await Service.RotateSecretAsync(request?.id, Who());
            Audit("webhook_secret_rotate", request?.id, "webhook signing secret rotated", "");
            return Ok(Wrap("rotated", "new signing secret - copy it now; it is not shown again.", new { signing_secret = secret }));
        });

        // CSRF: JSON-only ([Consumes]) and no CORS grant, so a cross-site page cannot send it; operator-only.
        [HttpPost("test")]  // nosemgrep: csharp.dotnet.security.mvc-missing-antiforgery.mvc-missing-antiforgery
        [Consumes("application/json")]
        public Task<IActionResult> Test([FromBody] ArkWebhookIdRequest request) =>
            Run("test", async () => Ok(Wrap("tested", "test sent.", await Service.TestAsync(request?.id, Who()))));

        // CSRF: JSON-only ([Consumes]) and no CORS grant, so a cross-site page cannot send it; read-only.
        [HttpPost("plan")]  // nosemgrep: csharp.dotnet.security.mvc-missing-antiforgery.mvc-missing-antiforgery
        [Consumes("application/json")]
        public Task<IActionResult> Plan([FromBody] ArkWebhookPlanRequest request) =>
            Run("plan", async () => Ok(Wrap("plan", "shard plan", await Service.PlanAsync(request))));

        [HttpGet("deliveries")]
        public Task<IActionResult> Deliveries([FromQuery] string? endpoint_id, [FromQuery] string? tenant_id, [FromQuery] string? status,
            [FromQuery] int limit = 50, [FromQuery] DateTime? before = null) =>
            Run("deliveries", async () => Ok(Wrap("deliveries", "delivery history",
                await Service.DeliveriesAsync(endpoint_id, tenant_id, status, limit, AsUtc(before)))));

        [HttpGet("delivery")]
        public Task<IActionResult> Delivery([FromQuery] string? shard, [FromQuery] string? id) =>
            Run("delivery", async () => Ok(Wrap("delivery", "delivery", await Service.DeliveryAsync(shard, id))));

        // CSRF: JSON-only ([Consumes]) and no CORS grant, so a cross-site page cannot send it; operator-only.
        [HttpPost("delivery/replay")]  // nosemgrep: csharp.dotnet.security.mvc-missing-antiforgery.mvc-missing-antiforgery
        [Consumes("application/json")]
        public Task<IActionResult> ReplayDelivery([FromBody] ArkWebhookRowRef request) => Run("replay", async () =>
        {
            var result = await Service.ReplayDeliveryAsync(request, Who());
            Audit("webhook_replay", $"{request?.shard}/{request?.id}", "delivery replayed", "");
            return Ok(Wrap("replayed", "queued for delivery again.", result));
        });

        // CSRF: JSON-only ([Consumes]) and no CORS grant, so a cross-site page cannot send it; operator-only.
        [HttpPost("delivery/cancel")]  // nosemgrep: csharp.dotnet.security.mvc-missing-antiforgery.mvc-missing-antiforgery
        [Consumes("application/json")]
        public Task<IActionResult> CancelDelivery([FromBody] ArkWebhookRowRef request) =>
            Run("cancel", async () => Ok(Wrap("cancelled", "delivery cancelled.", await Service.CancelDeliveryAsync(request))));

        [HttpGet("deadletters")]
        public Task<IActionResult> DeadLetters([FromQuery] string? endpoint_id, [FromQuery] string? tenant_id,
            [FromQuery] bool include_replayed = false, [FromQuery] int limit = 100) =>
            Run("deadletters", async () => Ok(Wrap("deadletters", "dead-letter queue",
                await Service.DeadLettersAsync(endpoint_id, tenant_id, include_replayed, limit))));

        // CSRF: JSON-only ([Consumes]) and no CORS grant, so a cross-site page cannot send it; operator-only.
        [HttpPost("deadletters/replay")]  // nosemgrep: csharp.dotnet.security.mvc-missing-antiforgery.mvc-missing-antiforgery
        [Consumes("application/json")]
        public Task<IActionResult> ReplayDeadLetters([FromBody] ArkWebhookRowsRequest request) => Run("dlq_replay", async () =>
        {
            var result = await Service.ReplayDeadLettersAsync(request, Who());
            Audit("webhook_dlq_replay", request?.endpoint_id ?? $"{request?.items?.Count ?? 0} items", "dead letters replayed", "");
            return Ok(Wrap("replayed", "dead letters queued for delivery again.", result));
        });

        // CSRF: JSON-only ([Consumes]) and no CORS grant, so a cross-site page cannot send it; operator-only.
        [HttpPost("deadletters/purge")]  // nosemgrep: csharp.dotnet.security.mvc-missing-antiforgery.mvc-missing-antiforgery
        [Consumes("application/json")]
        public Task<IActionResult> PurgeDeadLetters([FromBody] ArkWebhookRowsRequest request) => Run("dlq_purge", async () =>
        {
            var result = await Service.PurgeDeadLettersAsync(request);
            Audit("webhook_dlq_purge", request?.endpoint_id ?? $"{request?.items?.Count ?? 0} items", "dead letters purged", "");
            return Ok(Wrap("purged", "dead letters removed.", result));
        });

        [HttpGet("analytics")]
        public Task<IActionResult> Analytics([FromQuery] string? tenant_id, [FromQuery] string? endpoint_id, [FromQuery] int hours = 24) =>
            Run("analytics", async () => Ok(Wrap("analytics", "webhook analytics", await Service.AnalyticsAsync(tenant_id, endpoint_id, hours))));

        [HttpGet("shards")]
        public Task<IActionResult> Shards() =>
            Run("shards", async () => Ok(Wrap("shards", "shard registry", await Service.ShardsAsync())));

        // ------------------------------------------------------------------ helpers

        private static object Wrap(string code, string msg, object? data) => new { error = false, code, msg, data };

        private static string Origin(string? url) =>
            Uri.TryCreate(url ?? "", UriKind.Absolute, out var uri) ? uri.GetLeftPart(UriPartial.Authority) : "";

        /// <summary>Every timestamp the API hands out is UTC, but SQLite returns some without the zone; read them back as UTC.</summary>
        private static DateTime? AsUtc(DateTime? value) => value switch
        {
            null => null,
            { Kind: DateTimeKind.Utc } v => v,
            { Kind: DateTimeKind.Local } v => v.ToUniversalTime(),
            { } v => DateTime.SpecifyKind(v, DateTimeKind.Utc)
        };

        private async Task<IActionResult> Run(string operation, Func<Task<IActionResult>> action)
        {
            try
            {
                return await action();
            }
            catch (ArkWebhookException ex)
            {
                return StatusCode(ex.StatusCode, new { error = true, code = ex.Code, msg = ex.Message, data = (object?)null });
            }
            catch (Exception ex)
            {
                try { Da.LogError(ex, $"webhook_{operation}", $"v1/webhooks/{operation}", $"{operation} failed"); } catch { }
                return StatusCode(500, new { error = true, code = $"{operation}_failed", msg = $"{operation} failed: {ex.GetBaseException().Message}", data = (object?)null });
            }
        }

        /// <summary>Configuration changes go to the audit trail whatever EnableLogTrace says: who pointed identity events where.</summary>
        private void Audit(string key, string? reference, string message, string details)
        {
            try { Da.Record(key, reference, message, details, Who(), Ip()); } catch { }
        }

        private string Who() =>
            User.FindFirst("email")?.Value ?? User.FindFirst("preferred_username")?.Value
            ?? User.FindFirst("sub")?.Value ?? User.Identity?.Name ?? "operator";

        private string Ip() => HttpContext.Connection.RemoteIpAddress?.ToString() ?? "";
    }
}
