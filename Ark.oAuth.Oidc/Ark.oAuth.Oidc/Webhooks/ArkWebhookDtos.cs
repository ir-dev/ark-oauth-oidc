namespace Ark.oAuth.Oidc.Webhooks
{
    // Request bodies of the webhook management API. Secrets follow one rule throughout: null
    // keeps what is stored, "" clears it, anything else replaces it. The API never returns a
    // stored secret, only whether one is set.

    public sealed class ArkWebhookUpsertRequest
    {
        public string? id { get; set; }
        public string? tenant_id { get; set; }
        public string? name { get; set; }
        public string? description { get; set; }
        public string? url { get; set; }
        public List<string>? events { get; set; }
        /// <summary>active or paused, on create; use the status call afterwards.</summary>
        public string? status { get; set; }
        public int? failure_threshold { get; set; }
        public int? timeout_seconds { get; set; }
        public int? max_concurrency { get; set; }
        public ArkWebhookRetryDto? retry { get; set; }
        public ArkWebhookAuthDto? auth { get; set; }
        public List<ArkWebhookHeaderDto>? headers { get; set; }
        public ArkWebhookShardDto? shard { get; set; }
    }

    public sealed class ArkWebhookRetryDto
    {
        public int? max_attempts { get; set; }
        public string? backoff { get; set; }
        public int? initial_delay_seconds { get; set; }
        public int? max_delay_seconds { get; set; }
        public bool? retry_on_4xx { get; set; }
    }

    public sealed class ArkWebhookAuthDto
    {
        public string? type { get; set; }
        public string? basic_username { get; set; }
        public string? basic_password { get; set; }
        public string? bearer_token { get; set; }
        public string? bearer_header { get; set; }
        public string? bearer_scheme { get; set; }
        public string? jwt_alg { get; set; }
        public string? jwt_secret { get; set; }
        public string? jwt_issuer { get; set; }
        public string? jwt_audience { get; set; }
        public int? jwt_lifetime_seconds { get; set; }
        public string? jwt_header { get; set; }
        public string? jwt_claims { get; set; }
        public string? oauth_grant { get; set; }
        public string? oauth_token_url { get; set; }
        public string? oauth_client_id { get; set; }
        public string? oauth_client_secret { get; set; }
        public string? oauth_refresh_token { get; set; }
        public string? oauth_scope { get; set; }
        public string? oauth_audience { get; set; }
        public string? oauth_client_auth { get; set; }
    }

    public sealed class ArkWebhookHeaderDto
    {
        public string? name { get; set; }
        /// <summary>null keeps the stored value for this name.</summary>
        public string? value { get; set; }
    }

    public sealed class ArkWebhookShardDto
    {
        public string? strategy { get; set; }
        public List<string>? databases { get; set; }
        public int? count { get; set; }
        public string? partition_key { get; set; }
    }

    public sealed class ArkWebhookIdRequest
    {
        public string? id { get; set; }
        /// <summary>delete: also remove every delivery, attempt and dead letter the endpoint has.</summary>
        public bool purge { get; set; }
    }

    public sealed class ArkWebhookStatusRequest
    {
        public string? id { get; set; }
        /// <summary>pause | resume | enable | disable</summary>
        public string? action { get; set; }
    }

    public sealed class ArkWebhookPlanRequest
    {
        public string? id { get; set; }
        public ArkWebhookShardDto? shard { get; set; }
    }

    public sealed class ArkWebhookRowRef
    {
        public string? shard { get; set; }
        public string? id { get; set; }
    }

    public sealed class ArkWebhookRowsRequest
    {
        public List<ArkWebhookRowRef>? items { get; set; }
        /// <summary>Instead of items: every open dead letter of this endpoint.</summary>
        public string? endpoint_id { get; set; }
    }
}
