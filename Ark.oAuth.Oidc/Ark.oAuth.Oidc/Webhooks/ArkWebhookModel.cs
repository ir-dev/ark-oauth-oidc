using System.ComponentModel.DataAnnotations;

namespace Ark.oAuth.Oidc.Webhooks
{
    // ---------------------------------------------------------------------------------------
    // The webhook subsystem's data model.
    //
    // Two groups of tables, in two contexts, neither of them ArkDataContext:
    //
    //   * control tables (ArkWebhookControlContext): the endpoints an operator configured and the
    //     registry of shards that exist. Small, read every few seconds, in the IdP's database
    //     unless ark_oauth_server:Webhooks:ControlDatabase names another.
    //   * shard tables (ArkWebhookShardContext): deliveries, attempts and dead letters. One set of
    //     three tables per shard, named ark_wh_{deliveries|attempts|dead_letters}_{suffix}, on
    //     whichever database the endpoint's shard plan put them.
    //
    // Keeping them out of ArkDataContext is what keeps the module from touching the IdP: the
    // start-up schema sync, export/import and factory reset all walk that context's model, so
    // they neither create, export nor delete anything here.
    // ---------------------------------------------------------------------------------------

    /// <summary>The states an endpoint can be in.</summary>
    public static class ArkWebhookStatus
    {
        /// <summary>Receives events and is dispatched to.</summary>
        public const string Active = "active";
        /// <summary>Paused by the operator: events are still queued, nothing is sent until resumed.</summary>
        public const string Paused = "paused";
        /// <summary>
        /// Switched off — by the operator, or automatically after
        /// <see cref="ArkWebhookEndpoint.failure_threshold"/> consecutive failed attempts. No new
        /// events are queued; whatever was waiting is moved to the dead-letter queue.
        /// </summary>
        public const string Disabled = "disabled";

        public static readonly string[] All = { Active, Paused, Disabled };
    }

    /// <summary>The states a delivery moves through.</summary>
    public static class ArkDeliveryStatus
    {
        public const string Pending = "pending";
        public const string Retrying = "retrying";
        public const string InFlight = "in_flight";
        public const string Delivered = "delivered";
        /// <summary>Gave up: moved to the dead-letter queue.</summary>
        public const string Dead = "dead";
        /// <summary>The endpoint was deleted, or the operator cancelled it.</summary>
        public const string Cancelled = "cancelled";
        /// <summary>A console test that failed. Never retried, never dead-lettered.</summary>
        public const string TestFailed = "test_failed";

        /// <summary>Statuses the dispatcher still owns.</summary>
        public static readonly string[] Unfinished = { Pending, Retrying, InFlight };
    }

    /// <summary>How an endpoint's deliveries are spread over tables and databases.</summary>
    public static class ArkShardStrategy
    {
        /// <summary>One table set per database, shared by every endpoint that picks it.</summary>
        public const string Shared = "shared";
        /// <summary>A table set of the endpoint's own.</summary>
        public const string Dedicated = "dedicated";
        /// <summary>N table sets of the endpoint's own, chosen by a hash of the event's partition key, spread round-robin over the chosen databases.</summary>
        public const string Hashed = "hashed";
        /// <summary>One table set per calendar month (UTC), shared by every endpoint that picks it.</summary>
        public const string Monthly = "monthly";

        public static readonly string[] All = { Shared, Dedicated, Hashed, Monthly };
    }

    /// <summary>What a hashed plan hashes.</summary>
    public static class ArkShardPartitionKey
    {
        public const string Subject = "subject";
        public const string EventType = "event_type";
        public const string EventId = "event_id";

        public static readonly string[] All = { Subject, EventType, EventId };
    }

    /// <summary>How each request authenticates to the receiver.</summary>
    public static class ArkWebhookAuthType
    {
        public const string None = "none";
        public const string Basic = "basic";
        /// <summary>A static token — an API key or a JWT issued elsewhere — sent as given.</summary>
        public const string Bearer = "bearer";
        /// <summary>A JWT minted for every request: HS256 with a shared secret, or RS256 with the tenant's signing key.</summary>
        public const string Jwt = "jwt";
        /// <summary>An access token obtained from a token endpoint with a refresh token or client credentials.</summary>
        public const string OAuth2 = "oauth2";

        public static readonly string[] All = { None, Basic, Bearer, Jwt, OAuth2 };
    }

    /// <summary>How the wait between attempts grows.</summary>
    public static class ArkBackoff
    {
        public const string Exponential = "exponential";
        public const string Linear = "linear";
        public const string Fixed = "fixed";

        public static readonly string[] All = { Exponential, Linear, Fixed };
    }

    /// <summary>A configured receiver: where events go, which ones, how, and where their deliveries are stored.</summary>
    [Microsoft.AspNetCore.Mvc.ModelBinding.Validation.ValidateNever]
    public class ArkWebhookEndpoint
    {
        [Key, MaxLength(40)]
        public string id { get; set; } = default!;
        [MaxLength(128)]
        public string tenant_id { get; set; } = default!;
        [MaxLength(200)]
        public string name { get; set; } = default!;
        public string? description { get; set; }
        [MaxLength(2048)]
        public string url { get; set; } = default!;
        /// <summary>JSON list of event types; "*" and "prefix.*" are wildcards.</summary>
        public string events_ { get; set; } = "[\"*\"]";

        [MaxLength(16)]
        public string status { get; set; } = ArkWebhookStatus.Active;
        public string? disabled_reason { get; set; }
        public DateTime? disabled_at { get; set; }

        /// <summary>Failed attempts in a row, across deliveries. Any success resets it.</summary>
        public int consecutive_failures { get; set; }
        /// <summary>Disable after this many consecutive failed attempts; 0 never disables.</summary>
        public int failure_threshold { get; set; } = 15;

        public int timeout_seconds { get; set; } = 15;
        /// <summary>Concurrent requests to this endpoint, per instance.</summary>
        public int max_concurrency { get; set; } = 4;

        // retry policy
        public int max_attempts { get; set; } = 8;
        [MaxLength(16)]
        public string backoff { get; set; } = ArkBackoff.Exponential;
        public int initial_delay_seconds { get; set; } = 30;
        public int max_delay_seconds { get; set; } = 3600;
        /// <summary>Retry 4xx answers other than 408/429 too. Off: those go straight to the dead-letter queue.</summary>
        public bool retry_on_4xx { get; set; }

        // authentication
        [MaxLength(16)]
        public string auth_type { get; set; } = ArkWebhookAuthType.None;
        /// <summary>The non-secret half of the auth configuration, as JSON (<see cref="ArkWebhookAuthConfig"/>).</summary>
        public string? auth_ { get; set; }
        /// <summary>JSON list of custom header names. The values are secret and live in <see cref="secrets_"/>.</summary>
        public string? header_names_ { get; set; }
        /// <summary>Every secret this endpoint holds, encrypted with ASP.NET Core data protection.</summary>
        public string? secrets_ { get; set; }

        // shard plan
        [MaxLength(16)]
        public string shard_strategy { get; set; } = ArkShardStrategy.Shared;
        /// <summary>JSON list of database names ("main" = the IdP's own database).</summary>
        public string? shard_databases_ { get; set; }
        public int shard_count { get; set; } = 1;
        [MaxLength(24)]
        public string shard_partition_key { get; set; } = ArkShardPartitionKey.Subject;

        // OAuth 2.0 token state, shared by every instance
        public string? token_state_ { get; set; }
        [MaxLength(96)]
        public string? token_lock_by { get; set; }
        public DateTime? token_lock_until { get; set; }

        public DateTime created_at { get; set; } = DateTime.UtcNow;
        public DateTime updated_at { get; set; } = DateTime.UtcNow;
        [MaxLength(256)]
        public string? created_by { get; set; }
        [MaxLength(256)]
        public string? updated_by { get; set; }

        public DateTime? last_success_at { get; set; }
        public DateTime? last_failure_at { get; set; }
        public int? last_status_code { get; set; }
        public string? last_error { get; set; }
    }

    /// <summary>
    /// One physical shard: a set of delivery, attempt and dead-letter tables on one database.
    /// Written when a plan first routes to it, so the dispatcher knows every table worth scanning.
    /// </summary>
    [Microsoft.AspNetCore.Mvc.ModelBinding.Validation.ValidateNever]
    public class ArkWebhookShard
    {
        /// <summary>"{database}:{suffix}".</summary>
        [Key, MaxLength(96)]
        public string id { get; set; } = default!;
        [MaxLength(64)]
        public string database_name { get; set; } = default!;
        [MaxLength(32)]
        public string table_suffix { get; set; } = default!;
        [MaxLength(16)]
        public string strategy { get; set; } = default!;
        /// <summary>The owning endpoint for dedicated and hashed shards; null for shared and monthly ones.</summary>
        [MaxLength(40)]
        public string? endpoint_id { get; set; }
        /// <summary>active = routed to and scanned; sealed = nothing routes here and nothing is waiting.</summary>
        [MaxLength(16)]
        public string status { get; set; } = "active";
        public DateTime created_at { get; set; } = DateTime.UtcNow;
        public DateTime? sealed_at { get; set; }
    }

    /// <summary>One event bound for one endpoint. Lives in a shard table.</summary>
    [Microsoft.AspNetCore.Mvc.ModelBinding.Validation.ValidateNever]
    public class ArkWebhookDelivery
    {
        [Key, MaxLength(40)]
        public string id { get; set; } = default!;
        [MaxLength(40)]
        public string endpoint_id { get; set; } = default!;
        [MaxLength(128)]
        public string tenant_id { get; set; } = default!;
        [MaxLength(48)]
        public string event_id { get; set; } = default!;
        [MaxLength(128)]
        public string event_type { get; set; } = default!;
        [MaxLength(256)]
        public string? partition_key { get; set; }
        /// <summary>The exact JSON body sent, so a retry or replay sends the same bytes.</summary>
        public string payload { get; set; } = default!;

        [MaxLength(16)]
        public string status { get; set; } = ArkDeliveryStatus.Pending;
        public int attempt_count { get; set; }
        /// <summary>When the next attempt is due — or, while in flight, when the claim lapses.</summary>
        public DateTime next_attempt_at { get; set; } = DateTime.UtcNow;
        [MaxLength(96)]
        public string? locked_by { get; set; }
        /// <summary>Bumped by every claim and every state change: the compare-and-swap token that makes claims safe across workers.</summary>
        public int lock_version { get; set; }

        public DateTime created_at { get; set; } = DateTime.UtcNow;
        public DateTime updated_at { get; set; } = DateTime.UtcNow;
        public DateTime? delivered_at { get; set; }
        public int? last_status_code { get; set; }
        public string? last_error { get; set; }

        /// <summary>system | replay | test | api</summary>
        [MaxLength(16)]
        public string trigger { get; set; } = "system";
        /// <summary>"{shard}/{delivery}" this one replays.</summary>
        [MaxLength(160)]
        public string? replay_of { get; set; }
    }

    /// <summary>One HTTP attempt at a delivery: the delivery history.</summary>
    [Microsoft.AspNetCore.Mvc.ModelBinding.Validation.ValidateNever]
    public class ArkWebhookAttempt
    {
        [Key, MaxLength(40)]
        public string id { get; set; } = default!;
        [MaxLength(40)]
        public string delivery_id { get; set; } = default!;
        [MaxLength(40)]
        public string endpoint_id { get; set; } = default!;
        public int attempt_no { get; set; }
        public DateTime started_at { get; set; } = DateTime.UtcNow;
        public int duration_ms { get; set; }
        public int? status_code { get; set; }
        public bool success { get; set; }
        public string? error { get; set; }
        /// <summary>The first few KB of the receiver's answer.</summary>
        public string? response_body { get; set; }
        [MaxLength(96)]
        public string? worker { get; set; }
    }

    /// <summary>A delivery the dispatcher gave up on, kept for inspection and manual replay.</summary>
    [Microsoft.AspNetCore.Mvc.ModelBinding.Validation.ValidateNever]
    public class ArkWebhookDeadLetter
    {
        [Key, MaxLength(40)]
        public string id { get; set; } = default!;
        [MaxLength(40)]
        public string delivery_id { get; set; } = default!;
        [MaxLength(40)]
        public string endpoint_id { get; set; } = default!;
        [MaxLength(128)]
        public string tenant_id { get; set; } = default!;
        [MaxLength(48)]
        public string event_id { get; set; } = default!;
        [MaxLength(128)]
        public string event_type { get; set; } = default!;
        public string payload { get; set; } = default!;
        /// <summary>max_attempts | non_retryable | endpoint_disabled | expired</summary>
        [MaxLength(32)]
        public string reason { get; set; } = default!;
        public int attempts { get; set; }
        public int? last_status_code { get; set; }
        public string? last_error { get; set; }
        public DateTime dead_at { get; set; } = DateTime.UtcNow;
        public DateTime? replayed_at { get; set; }
        [MaxLength(256)]
        public string? replayed_by { get; set; }
        /// <summary>"{shard}/{delivery}" the replay created.</summary>
        [MaxLength(160)]
        public string? replay_delivery { get; set; }
    }

    /// <summary>An expected refusal, carried to the API as a status code and a sentence.</summary>
    public sealed class ArkWebhookException : Exception
    {
        public string Code { get; }
        public int StatusCode { get; }

        public ArkWebhookException(string code, string message, int statusCode = 400) : base(message)
        {
            Code = code;
            StatusCode = statusCode;
        }
    }
}
