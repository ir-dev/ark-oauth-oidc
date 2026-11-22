using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;

namespace Ark.oAuth.Oidc.Webhooks
{
    /// <summary>
    /// Everything the console and the management API do with webhooks: configure endpoints and
    /// their shard plans, test them, read delivery history and analytics, and work the
    /// dead-letter queue. Validation lives here, so a script gets the same refusals the page does.
    /// </summary>
    public sealed class ArkWebhookService
    {
        private static readonly Regex EventPatternRe = new("^(\\*|[a-z0-9_-]+(\\.[a-z0-9_-]+)*(\\.\\*)?)$", RegexOptions.Compiled);
        private static readonly Regex HeaderNameRe = new("^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,100}$", RegexOptions.Compiled);
        private const int MaxHeaders = 20;
        private const int MaxShardFanOut = 64;

        private readonly ArkWebhookDatabases _dbs;
        private readonly ArkWebhookRegistry _registry;
        private readonly ArkWebhookSecrets _secrets;
        private readonly ArkWebhookSender _sender;
        private readonly ArkWebhookTokenManager _tokens;
        private readonly ArkWebhookDispatcher _dispatcher;
        private readonly ArkWebhookPublisher _publisher;
        private readonly ArkWebhookSignal _signal;
        private readonly DataAccess _da;

        public ArkWebhookService(ArkWebhookDatabases dbs, ArkWebhookRegistry registry, ArkWebhookSecrets secrets,
            ArkWebhookSender sender, ArkWebhookTokenManager tokens, ArkWebhookDispatcher dispatcher,
            ArkWebhookPublisher publisher, ArkWebhookSignal signal, DataAccess da)
        {
            _dbs = dbs;
            _registry = registry;
            _secrets = secrets;
            _sender = sender;
            _tokens = tokens;
            _dispatcher = dispatcher;
            _publisher = publisher;
            _signal = signal;
            _da = da;
        }

        // ================================================================== meta

        public async Task<object> MetaAsync()
        {
            var options = _registry.Options;
            var tenants = (await _da.GetTenants()).Select(t => new { t.tenant_id, name = t.display ?? t.name }).OrderBy(t => t.tenant_id).ToList();
            var defaults = new ArkWebhookEndpoint();
            return new
            {
                enabled = options.Enabled,
                status = new
                {
                    worker_id = _dispatcher.WorkerId,
                    dispatcher_running = _dispatcher.Running,
                    registry_loaded = _registry.Loaded,
                    registry_error = _registry.LastError,
                    dispatcher_error = _dispatcher.LastError,
                    in_flight = _dispatcher.InFlight,
                    claimed = _dispatcher.Claimed,
                    delivered = _dispatcher.Delivered,
                    failed_attempts = _dispatcher.FailedAttempts,
                    dead_lettered = _dispatcher.DeadLettered,
                    queued_events = _publisher.Queued,
                    accepted_events = _publisher.Accepted,
                    last_housekeeping = _dispatcher.LastHousekeeping
                },
                options = new
                {
                    max_concurrency = options.EffectiveMaxConcurrency,
                    batch_size = options.EffectiveBatchSize,
                    poll_interval_ms = options.EffectivePollIntervalMs,
                    retention_days = options.RetentionDays,
                    dead_letter_retention_days = options.DeadLetterRetentionDays,
                    allow_insecure_http = options.AllowInsecureHttp,
                    control_database = string.IsNullOrWhiteSpace(options.ControlDatabase) ? ArkWebhookDatabases.Main : options.ControlDatabase
                },
                events = ArkWebhookEvents.Catalogue.Select(e => new { type = e.Type, group = e.Group, description = e.Description }),
                databases = _dbs.List().Select(d => new { name = d.Name, provider = d.Provider, configured = d.Configured }),
                strategies = ArkShardStrategy.All,
                partition_keys = ArkShardPartitionKey.All,
                auth_types = ArkWebhookAuthType.All,
                backoffs = ArkBackoff.All,
                tenants,
                defaults = new
                {
                    failure_threshold = defaults.failure_threshold,
                    timeout_seconds = defaults.timeout_seconds,
                    max_concurrency = defaults.max_concurrency,
                    max_attempts = defaults.max_attempts,
                    backoff = defaults.backoff,
                    initial_delay_seconds = defaults.initial_delay_seconds,
                    max_delay_seconds = defaults.max_delay_seconds
                },
                limits = new
                {
                    max_attempts = ArkWebhookRetryPolicy.MaxAttemptsCeiling,
                    max_hashed_shards = ArkShardPlan.MaxHashedShards,
                    max_headers = MaxHeaders,
                    timeout_seconds = 120,
                    max_concurrency = 64
                },
                signature = new
                {
                    scheme = "Standard Webhooks (standardwebhooks.com)",
                    headers = new[] { "webhook-id", "webhook-timestamp", "webhook-signature" },
                    signed_content = "{webhook-id}.{webhook-timestamp}.{body}",
                    algorithm = "HMAC-SHA256, base64, prefixed v1,"
                }
            };
        }

        // ================================================================== endpoints

        public async Task<List<object>> ListAsync(string? tenantId)
        {
            await using var ctl = _dbs.Control();
            var q = ctl.endpoints.AsNoTracking();
            if (!string.IsNullOrWhiteSpace(tenantId)) q = q.Where(e => e.tenant_id == tenantId);
            var rows = await q.OrderBy(e => e.tenant_id).ThenBy(e => e.name).ToListAsync();
            return rows.Select(r => Describe(r)).ToList();
        }

        public async Task<object> GetAsync(string? id)
        {
            var row = await LoadAsync(id);
            return Describe(row);
        }

        private async Task<ArkWebhookEndpoint> LoadAsync(string? id, ArkWebhookControlContext? ctl = null)
        {
            if (string.IsNullOrWhiteSpace(id)) throw new ArkWebhookException("id_required", "id is required.");
            if (ctl != null)
                return await ctl.endpoints.FirstOrDefaultAsync(e => e.id == id)
                    ?? throw new ArkWebhookException("not_found", $"webhook '{id}' does not exist.", 404);
            await using var own = _dbs.Control();
            return await own.endpoints.AsNoTracking().FirstOrDefaultAsync(e => e.id == id)
                ?? throw new ArkWebhookException("not_found", $"webhook '{id}' does not exist.", 404);
        }

        /// <summary>An endpoint as the API returns it: every setting, no secret.</summary>
        public object Describe(ArkWebhookEndpoint r)
        {
            var view = new ArkWebhookEndpointView(r);
            ArkWebhookSecretBag? bag = null;
            string? secretsProblem = null;
            try { bag = _secrets.Unprotect(r.secrets_); }
            catch (ArkWebhookException ex) { secretsProblem = ex.Message; }
            var a = view.Auth;
            var now = DateTime.UtcNow;
            return new
            {
                r.id,
                r.tenant_id,
                r.name,
                r.description,
                r.url,
                events = view.Events,
                r.status,
                auto_disabled = r.status == ArkWebhookStatus.Disabled && (r.disabled_reason ?? "").StartsWith("Disabled automatically", StringComparison.Ordinal),
                r.disabled_reason,
                r.disabled_at,
                r.consecutive_failures,
                r.failure_threshold,
                r.timeout_seconds,
                r.max_concurrency,
                retry = new { r.max_attempts, r.backoff, r.initial_delay_seconds, r.max_delay_seconds, r.retry_on_4xx },
                auth = new
                {
                    type = r.auth_type,
                    a.basic_username,
                    a.bearer_header,
                    a.bearer_scheme,
                    a.jwt_alg,
                    a.jwt_issuer,
                    a.jwt_audience,
                    a.jwt_lifetime_seconds,
                    a.jwt_header,
                    a.jwt_claims,
                    a.oauth_grant,
                    a.oauth_token_url,
                    a.oauth_client_id,
                    a.oauth_scope,
                    a.oauth_audience,
                    a.oauth_client_auth,
                    has_basic_password = !string.IsNullOrEmpty(bag?.basic_password),
                    has_bearer_token = !string.IsNullOrEmpty(bag?.bearer_token),
                    has_jwt_secret = !string.IsNullOrEmpty(bag?.jwt_secret),
                    has_oauth_client_secret = !string.IsNullOrEmpty(bag?.oauth_client_secret),
                    has_oauth_refresh_token = !string.IsNullOrEmpty(bag?.oauth_refresh_token),
                    has_access_token = !string.IsNullOrEmpty(r.token_state_)
                },
                headers = view.HeaderNames.Select(n => new { name = n, has_value = bag?.headers.ContainsKey(n) == true }),
                has_signing_secret = !string.IsNullOrEmpty(bag?.signing_secret),
                secrets_problem = secretsProblem,
                shard = new
                {
                    strategy = view.Plan.Strategy,
                    databases = view.Plan.Databases,
                    count = view.Plan.Count,
                    partition_key = view.Plan.PartitionKey,
                    targets = ArkWebhookRouter.Targets(view.Plan, now).Select(t => new
                    {
                        shard = ArkWebhookRouter.ShardId(t.Database, t.Suffix),
                        database = t.Database,
                        tables = Tables(t.Suffix)
                    })
                },
                r.created_at,
                r.updated_at,
                r.created_by,
                r.updated_by,
                r.last_success_at,
                r.last_failure_at,
                r.last_status_code,
                r.last_error
            };
        }

        private static string[] Tables(string suffix) => new[]
        {
            ArkWebhookShardContext.DeliveriesTable(suffix),
            ArkWebhookShardContext.AttemptsTable(suffix),
            ArkWebhookShardContext.DeadLettersTable(suffix)
        };

        public static string NewEndpointId() =>
            "wh_" + string.Concat(RandomNumberGenerator.GetBytes(10).Select(b => "abcdefghijklmnopqrstuvwxyz234567"[b % 32]));

        /// <summary>Creates or updates an endpoint. On create, the answer carries the signing secret — the only time it is shown.</summary>
        public async Task<(object Endpoint, string? SigningSecret, bool Created)> UpsertAsync(ArkWebhookUpsertRequest req, string who)
        {
            if (req == null) throw new ArkWebhookException("body_required", "a request body is required.");
            var options = _registry.Options;
            await using var ctl = _dbs.Control();
            var creating = string.IsNullOrWhiteSpace(req.id);
            var row = creating ? new ArkWebhookEndpoint { id = NewEndpointId(), created_by = who, created_at = DateTime.UtcNow } : await LoadAsync(req.id, ctl);
            var bag = creating ? new ArkWebhookSecretBag() : _secrets.Unprotect(row.secrets_);
            var oldAuth = ArkWebhookAuthConfig.Read(row.auth_);
            var oldAuthType = row.auth_type;

            // ---- identity
            var tenantId = (req.tenant_id ?? row.tenant_id ?? "").Trim();
            if (tenantId.Length == 0) throw new ArkWebhookException("tenant_required", "tenant_id is required.");
            if (creating || !string.Equals(tenantId, row.tenant_id, StringComparison.Ordinal))
            {
                var tenant = await _da.GetTenant(tenantId) ?? throw new ArkWebhookException("unknown_tenant", $"tenant '{tenantId}' does not exist.");
                tenantId = tenant.tenant_id;
            }
            row.tenant_id = tenantId;
            var name = (req.name ?? row.name ?? "").Trim();
            if (name.Length == 0) throw new ArkWebhookException("name_required", "a name is required.");
            if (name.Length > 200) throw new ArkWebhookException("name_too_long", "the name is longer than 200 characters.");
            row.name = name;
            if (req.description != null) row.description = req.description.Trim().Length == 0 ? null : req.description.Trim();
            var url = (req.url ?? row.url ?? "").Trim();
            if (ArkWebhookSender.UrlProblem(url, options.AllowInsecureHttp) is { } urlProblem)
                throw new ArkWebhookException("bad_url", urlProblem);
            row.url = url;

            if (req.events != null || creating)
            {
                var events = (req.events ?? new List<string>()).Select(e => (e ?? "").Trim().ToLowerInvariant()).Where(e => e.Length > 0).Distinct().ToList();
                if (events.Count == 0) throw new ArkWebhookException("events_required", "subscribe to at least one event (\"*\" for all).");
                var bad = events.FirstOrDefault(e => e.Length > 128 || !EventPatternRe.IsMatch(e));
                if (bad != null) throw new ArkWebhookException("bad_event", $"'{bad}' is not an event type or pattern (\"user.signed_in\", \"user.*\" or \"*\").");
                row.events_ = JsonList.Write(events);
            }

            if (creating)
            {
                var status = (req.status ?? ArkWebhookStatus.Active).Trim().ToLowerInvariant();
                if (status != ArkWebhookStatus.Active && status != ArkWebhookStatus.Paused)
                    throw new ArkWebhookException("bad_status", "a new webhook starts active or paused.");
                row.status = status;
            }

            // ---- delivery and retry policy
            row.failure_threshold = Range(req.failure_threshold ?? row.failure_threshold, 0, 10_000, "failure_threshold");
            row.timeout_seconds = Range(req.timeout_seconds ?? row.timeout_seconds, 1, 120, "timeout_seconds");
            row.max_concurrency = Range(req.max_concurrency ?? row.max_concurrency, 1, 64, "max_concurrency");
            if (req.retry != null)
            {
                row.max_attempts = Range(req.retry.max_attempts ?? row.max_attempts, 1, ArkWebhookRetryPolicy.MaxAttemptsCeiling, "retry.max_attempts");
                var backoff = (req.retry.backoff ?? row.backoff).Trim().ToLowerInvariant();
                if (!ArkBackoff.All.Contains(backoff)) throw new ArkWebhookException("bad_backoff", $"backoff must be one of {string.Join(", ", ArkBackoff.All)}.");
                row.backoff = backoff;
                row.initial_delay_seconds = Range(req.retry.initial_delay_seconds ?? row.initial_delay_seconds, 1, 86_400, "retry.initial_delay_seconds");
                row.max_delay_seconds = Range(req.retry.max_delay_seconds ?? row.max_delay_seconds, 1, 7 * 86_400, "retry.max_delay_seconds");
                if (row.max_delay_seconds < row.initial_delay_seconds)
                    throw new ArkWebhookException("bad_retry", "retry.max_delay_seconds must be at least retry.initial_delay_seconds.");
                row.retry_on_4xx = req.retry.retry_on_4xx ?? row.retry_on_4xx;
            }

            // ---- authentication
            var authChanged = false;
            if (req.auth != null)
            {
                authChanged = ApplyAuth(row, bag, req.auth, oldAuth, options.AllowInsecureHttp);
            }
            else if (creating)
            {
                row.auth_type = ArkWebhookAuthType.None;
                row.auth_ = new ArkWebhookAuthConfig().Write();
            }

            // ---- custom headers
            if (req.headers != null)
            {
                var names = new List<string>();
                var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var h in req.headers)
                {
                    var hn = (h?.name ?? "").Trim();
                    if (hn.Length == 0) continue;
                    if (!HeaderNameRe.IsMatch(hn)) throw new ArkWebhookException("bad_header", $"'{hn}' is not a valid header name.");
                    if (ArkWebhookSender.ReservedHeaders.Contains(hn)) throw new ArkWebhookException("reserved_header", $"'{hn}' is set by the webhook sender and cannot be overridden.");
                    if (hn.Equals("Authorization", StringComparison.OrdinalIgnoreCase) && row.auth_type != ArkWebhookAuthType.None)
                        throw new ArkWebhookException("reserved_header", "the Authorization header is set by the authentication type - use auth type \"none\" to set it yourself.");
                    if (names.Contains(hn, StringComparer.OrdinalIgnoreCase)) throw new ArkWebhookException("duplicate_header", $"header '{hn}' is listed twice.");
                    string value;
                    if (h!.value == null)
                    {
                        if (!bag.headers.TryGetValue(hn, out var kept)) throw new ArkWebhookException("header_value_required", $"header '{hn}' needs a value.");
                        value = kept;
                    }
                    else value = h.value;
                    if (value.Length > 4096 || value.IndexOfAny(new[] { '\r', '\n' }) >= 0)
                        throw new ArkWebhookException("bad_header", $"the value of header '{hn}' is too long or contains a line break.");
                    names.Add(hn);
                    values[hn] = value;
                }
                if (names.Count > MaxHeaders) throw new ArkWebhookException("too_many_headers", $"at most {MaxHeaders} custom headers.");
                row.header_names_ = JsonList.Write(names);
                bag.headers = values;
            }

            // ---- shard plan
            if (req.shard != null || creating)
                ApplyShard(row, req.shard ?? new ArkWebhookShardDto());

            string? newSecret = null;
            if (creating || string.IsNullOrEmpty(bag.signing_secret))
                bag.signing_secret = newSecret = ArkWebhookSecrets.NewSigningSecret();

            if (authChanged || oldAuthType != row.auth_type)
            {
                // New credentials: the token held for the old ones must not be used again.
                row.token_state_ = null;
                _tokens.Forget(row.id);
            }

            row.secrets_ = _secrets.Protect(bag);
            row.updated_at = DateTime.UtcNow;
            row.updated_by = who;

            // The plan is proven before it is saved: every shard it routes to is created now, on
            // its database, so a database that cannot be reached is a refusal on this form and not
            // a stream of lost deliveries later.
            var view = new ArkWebhookEndpointView(row);
            foreach (var (db, suffix) in ArkWebhookRouter.Targets(view.Plan, DateTime.UtcNow))
            {
                try { await _registry.EnsureShardAsync(db, suffix, view.Plan.Strategy, row.id); }
                catch (Exception ex) when (ex is not ArkWebhookException)
                {
                    throw new ArkWebhookException("shard_unavailable", $"shard database '{db}' could not be prepared: {ex.GetBaseException().Message}");
                }
            }

            if (creating) ctl.endpoints.Add(row);
            await ctl.SaveChangesAsync();
            await _registry.RefreshAsync();
            return (Describe(row), newSecret, creating);
        }

        private static int Range(int value, int min, int max, string field)
        {
            if (value < min || value > max) throw new ArkWebhookException("out_of_range", $"{field} must be between {min} and {max}.");
            return value;
        }

        /// <summary>Applies the auth part of a save. True when a credential the token depends on changed.</summary>
        private static bool ApplyAuth(ArkWebhookEndpoint row, ArkWebhookSecretBag bag, ArkWebhookAuthDto dto, ArkWebhookAuthConfig old, bool allowInsecureHttp)
        {
            var type = (dto.type ?? row.auth_type ?? ArkWebhookAuthType.None).Trim().ToLowerInvariant();
            if (!ArkWebhookAuthType.All.Contains(type)) throw new ArkWebhookException("bad_auth_type", $"auth.type must be one of {string.Join(", ", ArkWebhookAuthType.All)}.");
            var cfg = new ArkWebhookAuthConfig();
            var changed = false;

            static string? Secret(string? incoming, string? stored) => incoming == null ? stored : (incoming.Length == 0 ? null : incoming);
            static string? Clean(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

            switch (type)
            {
                case ArkWebhookAuthType.Basic:
                    cfg.basic_username = Clean(dto.basic_username) ?? throw new ArkWebhookException("auth_incomplete", "Basic authentication needs a username.");
                    if (cfg.basic_username.Contains(':')) throw new ArkWebhookException("auth_incomplete", "a Basic username cannot contain ':'.");
                    bag.basic_password = Secret(dto.basic_password, bag.basic_password)
                        ?? throw new ArkWebhookException("auth_incomplete", "Basic authentication needs a password.");
                    break;
                case ArkWebhookAuthType.Bearer:
                    bag.bearer_token = Secret(dto.bearer_token, bag.bearer_token)
                        ?? throw new ArkWebhookException("auth_incomplete", "Bearer authentication needs a token.");
                    cfg.bearer_header = Clean(dto.bearer_header);
                    cfg.bearer_scheme = dto.bearer_scheme == null ? "Bearer" : dto.bearer_scheme.Trim();
                    if (cfg.bearer_header != null && (!HeaderNameRe.IsMatch(cfg.bearer_header) || ArkWebhookSender.ReservedHeaders.Contains(cfg.bearer_header)))
                        throw new ArkWebhookException("bad_header", $"'{cfg.bearer_header}' cannot carry the token.");
                    break;
                case ArkWebhookAuthType.Jwt:
                    cfg.jwt_alg = string.Equals(Clean(dto.jwt_alg), "RS256", StringComparison.OrdinalIgnoreCase) ? "RS256" : "HS256";
                    cfg.jwt_issuer = Clean(dto.jwt_issuer);
                    cfg.jwt_audience = Clean(dto.jwt_audience);
                    cfg.jwt_lifetime_seconds = Range(dto.jwt_lifetime_seconds ?? 300, 30, 3600, "auth.jwt_lifetime_seconds");
                    cfg.jwt_header = Clean(dto.jwt_header);
                    if (cfg.jwt_header != null && (!HeaderNameRe.IsMatch(cfg.jwt_header) || ArkWebhookSender.ReservedHeaders.Contains(cfg.jwt_header)))
                        throw new ArkWebhookException("bad_header", $"'{cfg.jwt_header}' cannot carry the token.");
                    cfg.jwt_claims = Clean(dto.jwt_claims);
                    if (cfg.jwt_claims != null)
                    {
                        try
                        {
                            using var doc = JsonDocument.Parse(cfg.jwt_claims);
                            if (doc.RootElement.ValueKind != JsonValueKind.Object) throw new JsonException();
                        }
                        catch (JsonException) { throw new ArkWebhookException("bad_claims", "auth.jwt_claims must be a JSON object."); }
                    }
                    if (cfg.jwt_alg == "HS256")
                    {
                        bag.jwt_secret = Secret(dto.jwt_secret, bag.jwt_secret);
                        if (string.IsNullOrEmpty(bag.jwt_secret) || System.Text.Encoding.UTF8.GetByteCount(bag.jwt_secret) < 32)
                            throw new ArkWebhookException("auth_incomplete", "HS256 needs a shared secret of at least 32 bytes.");
                    }
                    break;
                case ArkWebhookAuthType.OAuth2:
                    cfg.oauth_grant = string.Equals(Clean(dto.oauth_grant), "client_credentials", StringComparison.OrdinalIgnoreCase) ? "client_credentials" : "refresh_token";
                    cfg.oauth_token_url = Clean(dto.oauth_token_url) ?? throw new ArkWebhookException("auth_incomplete", "OAuth 2.0 needs the token endpoint URL.");
                    // The same rule the sender applies, so a URL it would refuse is refused here instead.
                    if (ArkWebhookSender.UrlProblem(cfg.oauth_token_url, allowInsecureHttp) is { } tokenUrlProblem)
                        throw new ArkWebhookException("bad_url", $"token endpoint: {tokenUrlProblem}");
                    cfg.oauth_client_id = Clean(dto.oauth_client_id);
                    cfg.oauth_scope = Clean(dto.oauth_scope);
                    cfg.oauth_audience = Clean(dto.oauth_audience);
                    cfg.oauth_client_auth = string.Equals(Clean(dto.oauth_client_auth), "client_secret_basic", StringComparison.OrdinalIgnoreCase) ? "client_secret_basic" : "client_secret_post";
                    var secretBefore = bag.oauth_client_secret;
                    var refreshBefore = bag.oauth_refresh_token;
                    bag.oauth_client_secret = Secret(dto.oauth_client_secret, bag.oauth_client_secret);
                    bag.oauth_refresh_token = Secret(dto.oauth_refresh_token, bag.oauth_refresh_token);
                    if (cfg.oauth_grant == "refresh_token" && string.IsNullOrEmpty(bag.oauth_refresh_token))
                        throw new ArkWebhookException("auth_incomplete", "the refresh_token grant needs a refresh token.");
                    if (cfg.oauth_grant == "client_credentials" && (cfg.oauth_client_id == null || string.IsNullOrEmpty(bag.oauth_client_secret)))
                        throw new ArkWebhookException("auth_incomplete", "the client_credentials grant needs a client id and secret.");
                    changed = secretBefore != bag.oauth_client_secret || refreshBefore != bag.oauth_refresh_token
                              || old.oauth_token_url != cfg.oauth_token_url || old.oauth_grant != cfg.oauth_grant
                              || old.oauth_client_id != cfg.oauth_client_id || old.oauth_scope != cfg.oauth_scope
                              || old.oauth_audience != cfg.oauth_audience;
                    break;
            }

            // Credentials of a type no longer in use are not kept.
            if (type != ArkWebhookAuthType.Basic) bag.basic_password = null;
            if (type != ArkWebhookAuthType.Bearer) bag.bearer_token = null;
            if (type != ArkWebhookAuthType.Jwt || cfg.jwt_alg != "HS256") bag.jwt_secret = null;
            if (type != ArkWebhookAuthType.OAuth2) { bag.oauth_client_secret = null; bag.oauth_refresh_token = null; }

            row.auth_type = type;
            row.auth_ = cfg.Write();
            return changed;
        }

        private void ApplyShard(ArkWebhookEndpoint row, ArkWebhookShardDto dto)
        {
            var strategy = (dto.strategy ?? row.shard_strategy ?? ArkShardStrategy.Shared).Trim().ToLowerInvariant();
            if (!ArkShardStrategy.All.Contains(strategy)) throw new ArkWebhookException("bad_strategy", $"shard.strategy must be one of {string.Join(", ", ArkShardStrategy.All)}.");
            var dbs = (dto.databases ?? JsonList.Read(row.shard_databases_)).Select(d => (d ?? "").Trim().ToLowerInvariant()).Where(d => d.Length > 0).Distinct().ToList();
            if (dbs.Count == 0) dbs.Add(ArkWebhookDatabases.Main);
            foreach (var db in dbs)
                if (!_dbs.Exists(db)) throw new ArkWebhookException("unknown_database", $"database '{db}' is not configured under ark_oauth_server:Webhooks:Databases.");
            if (strategy != ArkShardStrategy.Hashed && dbs.Count > 1)
                throw new ArkWebhookException("bad_plan", "only the hashed strategy spreads over more than one database.");
            var count = strategy == ArkShardStrategy.Hashed ? Range(dto.count ?? Math.Max(2, row.shard_count), 2, ArkShardPlan.MaxHashedShards, "shard.count") : 1;
            var key = (dto.partition_key ?? row.shard_partition_key ?? ArkShardPartitionKey.Subject).Trim().ToLowerInvariant();
            if (!ArkShardPartitionKey.All.Contains(key)) throw new ArkWebhookException("bad_partition_key", $"shard.partition_key must be one of {string.Join(", ", ArkShardPartitionKey.All)}.");
            row.shard_strategy = strategy;
            row.shard_databases_ = JsonList.Write(dbs);
            row.shard_count = count;
            row.shard_partition_key = key;
        }

        /// <summary>
        /// What a shard plan would create, before anything is saved: the tables, the database
        /// each lands on and whether that database answers. The form draws this as the operator
        /// types.
        /// </summary>
        public async Task<object> PlanAsync(ArkWebhookPlanRequest req)
        {
            var row = new ArkWebhookEndpoint { id = string.IsNullOrWhiteSpace(req?.id) ? "wh_newendpoint" : req!.id!.Trim() };
            ApplyShard(row, req?.shard ?? new ArkWebhookShardDto());
            var plan = ArkShardPlan.From(row);
            var now = DateTime.UtcNow;
            var existing = new HashSet<string>(_registry.Current?.Shards.Select(s => s.id) ?? Enumerable.Empty<string>());
            var reach = new Dictionary<string, string?>();
            foreach (var db in plan.Databases.Distinct())
            {
                try
                {
                    reach[db] = await CanConnectAsync(_dbs.Resolve(db));
                }
                catch (Exception ex) { reach[db] = ex.GetBaseException().Message; }
            }
            var targets = ArkWebhookRouter.Targets(plan, now).Select(t =>
            {
                var id = ArkWebhookRouter.ShardId(t.Database, t.Suffix);
                return new { shard = id, database = t.Database, suffix = t.Suffix, tables = Tables(t.Suffix), exists = existing.Contains(id) };
            }).ToList();
            var explain = plan.Strategy switch
            {
                ArkShardStrategy.Dedicated => "Deliveries for this webhook get a table set of their own: a busy or failing receiver cannot slow anybody else's, and its history can be purged on its own.",
                ArkShardStrategy.Hashed => $"Deliveries are spread over {plan.Count} table sets by a hash of the event's {plan.PartitionKey.Replace('_', ' ')}, round-robin over {plan.Databases.Count} database(s). Events with the same key always land in the same shard.",
                ArkShardStrategy.Monthly => "Deliveries go to one table set per calendar month (UTC), shared with every other monthly webhook. Old months stop being scanned once nothing in them is waiting.",
                _ => "Deliveries share one table set per database with every other webhook on the shared plan. Simplest; right for most webhooks."
            };
            return new
            {
                strategy = plan.Strategy,
                databases = plan.Databases.Select(d => new { name = d, reachable = reach.GetValueOrDefault(d) == null, error = reach.GetValueOrDefault(d) }),
                count = plan.Count,
                partition_key = plan.PartitionKey,
                explain,
                targets
            };
        }

        private static async Task<string?> CanConnectAsync(ArkWebhookDatabase db)
        {
            if (db.Provider == "sqlite")
            {
                // EF answers "cannot connect" for a SQLite file that does not exist yet, which the
                // save would simply create. What can actually fail is the folder it goes in.
                try
                {
                    var source = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder(db.ConnectionString).DataSource;
                    if (string.IsNullOrWhiteSpace(source) || source == ":memory:" || File.Exists(source)) { /* open it below */ }
                    else
                    {
                        var dir = Path.GetDirectoryName(Path.GetFullPath(source));
                        return string.IsNullOrEmpty(dir) || Directory.Exists(dir) ? null : $"the folder '{dir}' does not exist";
                    }
                }
                catch (Exception ex) { return ex.GetBaseException().Message; }
            }
            var builder = new DbContextOptionsBuilder<ArkWebhookControlContext>();
            switch (db.Provider)
            {
                case "sqlite": builder.UseSqlite(db.ConnectionString); break;
                case "postgres": builder.UseNpgsql(db.ConnectionString); break;
                case "mysql": builder.UseMySQL(db.ConnectionString); break;
                default: return $"provider '{db.Provider}' is not supported";
            }
            try
            {
                await using var ctx = new ArkWebhookControlContext(builder.Options);
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(8));
                return await ctx.Database.CanConnectAsync(cts.Token) ? null : "the database did not answer";
            }
            catch (Exception ex) { return ex.GetBaseException().Message; }
        }

        public async Task<object> SetStatusAsync(ArkWebhookStatusRequest req, string who)
        {
            await using var ctl = _dbs.Control();
            var row = await LoadAsync(req?.id, ctl);
            var action = (req?.action ?? "").Trim().ToLowerInvariant();
            var now = DateTime.UtcNow;
            var deadLetter = false;
            switch (action)
            {
                case "pause":
                    if (row.status != ArkWebhookStatus.Active) throw new ArkWebhookException("bad_transition", "only an active webhook can be paused.", 409);
                    row.status = ArkWebhookStatus.Paused;
                    break;
                case "resume":
                case "enable":
                    if (row.status == ArkWebhookStatus.Active) throw new ArkWebhookException("bad_transition", "the webhook is already active.", 409);
                    row.status = ArkWebhookStatus.Active;
                    row.consecutive_failures = 0;
                    row.disabled_at = null;
                    row.disabled_reason = null;
                    break;
                case "disable":
                    if (row.status == ArkWebhookStatus.Disabled) throw new ArkWebhookException("bad_transition", "the webhook is already disabled.", 409);
                    row.status = ArkWebhookStatus.Disabled;
                    row.disabled_at = now;
                    row.disabled_reason = $"Disabled by {who}.";
                    deadLetter = true;
                    break;
                default:
                    throw new ArkWebhookException("bad_action", "action must be pause, resume, enable or disable.");
            }
            row.updated_at = now;
            row.updated_by = who;
            await ctl.SaveChangesAsync();
            await _registry.RefreshAsync();
            var moved = deadLetter ? await _dispatcher.DeadLetterWaitingAsync(row.id, "endpoint_disabled", CancellationToken.None) : 0;
            if (!deadLetter) _signal.Pulse();
            return new { endpoint = Describe(row), dead_lettered = moved };
        }

        public async Task<string> RotateSecretAsync(string? id, string who)
        {
            await using var ctl = _dbs.Control();
            var row = await LoadAsync(id, ctl);
            var bag = _secrets.Unprotect(row.secrets_);
            bag.signing_secret = ArkWebhookSecrets.NewSigningSecret();
            row.secrets_ = _secrets.Protect(bag);
            row.updated_at = DateTime.UtcNow;
            row.updated_by = who;
            await ctl.SaveChangesAsync();
            await _registry.RefreshAsync();
            return bag.signing_secret;
        }

        public async Task<object> DeleteAsync(ArkWebhookIdRequest req, string who)
        {
            await using var ctl = _dbs.Control();
            var row = await LoadAsync(req?.id, ctl);
            var shards = await ctl.shards.AsNoTracking().Where(s => s.endpoint_id == null || s.endpoint_id == row.id).ToListAsync();
            var cancelled = 0;
            var purged = 0;
            foreach (var shard in shards)
            {
                try
                {
                    await using var ctx = _dbs.Shard(shard.database_name, shard.table_suffix);
                    if (req!.purge)
                    {
                        purged += await ctx.attempts.Where(a => a.endpoint_id == row.id).ExecuteDeleteAsync();
                        purged += await ctx.dead_letters.Where(l => l.endpoint_id == row.id).ExecuteDeleteAsync();
                        purged += await ctx.deliveries.Where(d => d.endpoint_id == row.id).ExecuteDeleteAsync();
                    }
                    else
                    {
                        var now = DateTime.UtcNow;
                        cancelled += await ctx.deliveries
                            .Where(d => d.endpoint_id == row.id && (d.status == ArkDeliveryStatus.Pending || d.status == ArkDeliveryStatus.Retrying))
                            .ExecuteUpdateAsync(s => s
                                .SetProperty(d => d.status, ArkDeliveryStatus.Cancelled)
                                .SetProperty(d => d.last_error, "the endpoint was deleted")
                                .SetProperty(d => d.lock_version, d => d.lock_version + 1)
                                .SetProperty(d => d.updated_at, now));
                    }
                }
                catch (ArkWebhookException) { /* an unconfigured database: nothing reachable to clean */ }
            }
            ctl.endpoints.Remove(row);
            await ctl.SaveChangesAsync();
            _tokens.Forget(row.id);
            await _registry.RefreshAsync();
            return new { id = row.id, cancelled, purged_rows = purged };
        }

        // ================================================================== test

        /// <summary>
        /// Sends a webhook.test event now and waits for the answer. Recorded in the delivery
        /// history, but never retried, never dead-lettered and never counted towards the
        /// failure threshold — testing a broken receiver must not be what disables it.
        /// </summary>
        public async Task<object> TestAsync(string? id, string who)
        {
            var row = await LoadAsync(id);
            var view = new ArkWebhookEndpointView(row);
            var evt = ArkWebhookEvent.Create(row.tenant_id, ArkWebhookEvents.WebhookTest, new
            {
                message = "Test event sent from the Ark identity server's webhook console.",
                endpoint_id = row.id,
                endpoint_name = row.name,
                sent_by = who
            }, who, row.id);
            var now = DateTime.UtcNow;
            var (db, suffix) = ArkWebhookRouter.Route(view.Plan, ArkWebhookRouter.PartitionValue(view.Plan, evt), now);
            await _registry.EnsureShardAsync(db, suffix, view.Plan.Strategy, row.id);
            var delivery = new ArkWebhookDelivery
            {
                id = ArkWebhookFanout.NewDeliveryId(),
                endpoint_id = row.id,
                tenant_id = row.tenant_id,
                event_id = evt.id,
                event_type = evt.type,
                partition_key = evt.subject,
                payload = evt.body,
                status = ArkDeliveryStatus.InFlight,
                locked_by = "console",
                next_attempt_at = now.AddMinutes(5),
                created_at = now,
                updated_at = now,
                trigger = "test"
            };
            await using var ctx = _dbs.Shard(db, suffix);
            ctx.deliveries.Add(delivery);
            await ctx.SaveChangesAsync();

            var result = await _sender.SendAsync(view, delivery, 1, CancellationToken.None);
            ctx.attempts.Add(new ArkWebhookAttempt
            {
                id = "att_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant(),
                delivery_id = delivery.id,
                endpoint_id = row.id,
                attempt_no = 1,
                started_at = DateTime.UtcNow.AddMilliseconds(-result.DurationMs),
                duration_ms = result.DurationMs,
                status_code = result.StatusCode,
                success = result.Success,
                error = ArkWebhookFanout.Truncate(result.Error, 2000),
                response_body = result.ResponseBody,
                worker = "console"
            });
            delivery.status = result.Success ? ArkDeliveryStatus.Delivered : ArkDeliveryStatus.TestFailed;
            delivery.attempt_count = 1;
            delivery.delivered_at = result.Success ? DateTime.UtcNow : null;
            delivery.last_status_code = result.StatusCode;
            delivery.last_error = ArkWebhookFanout.Truncate(result.Error, 2000);
            delivery.locked_by = null;
            delivery.lock_version++;
            delivery.updated_at = DateTime.UtcNow;
            await ctx.SaveChangesAsync();
            return new
            {
                success = result.Success,
                status_code = result.StatusCode,
                duration_ms = result.DurationMs,
                error = result.Error,
                response_body = result.ResponseBody,
                shard = ArkWebhookRouter.ShardId(db, suffix),
                delivery_id = delivery.id,
                event_id = evt.id
            };
        }

        // ================================================================== history

        private async Task<List<ArkWebhookShard>> ShardsForAsync(IEnumerable<string>? endpointIds)
        {
            await using var ctl = _dbs.Control();
            var all = await ctl.shards.AsNoTracking().OrderBy(s => s.id).ToListAsync();
            if (endpointIds == null) return all.Take(MaxShardFanOut * 4).ToList();
            var ids = new HashSet<string>(endpointIds);
            return all.Where(s => s.endpoint_id == null || ids.Contains(s.endpoint_id)).ToList();
        }

        private async Task<List<string>> EndpointIdsAsync(string? tenantId, string? endpointId)
        {
            await using var ctl = _dbs.Control();
            var q = ctl.endpoints.AsNoTracking();
            if (!string.IsNullOrWhiteSpace(endpointId)) q = q.Where(e => e.id == endpointId);
            if (!string.IsNullOrWhiteSpace(tenantId)) q = q.Where(e => e.tenant_id == tenantId);
            return await q.Select(e => e.id).ToListAsync();
        }

        public async Task<object> DeliveriesAsync(string? endpointId, string? tenantId, string? status, int limit, DateTime? before)
        {
            limit = Math.Clamp(limit <= 0 ? 50 : limit, 1, 500);
            var ids = await EndpointIdsAsync(tenantId, endpointId);
            if (ids.Count == 0) return new { items = Array.Empty<object>(), more = false };
            var statuses = (status ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
            var results = new List<(string Shard, ArkWebhookDelivery Row)>();
            var errors = new List<string>();
            foreach (var shard in await ShardsForAsync(ids))
            {
                try
                {
                    await using var ctx = _dbs.Shard(shard.database_name, shard.table_suffix);
                    var q = ctx.deliveries.AsNoTracking().Where(d => ids.Contains(d.endpoint_id));
                    if (statuses.Count > 0) q = q.Where(d => statuses.Contains(d.status));
                    if (before != null) q = q.Where(d => d.created_at < before);
                    var rows = await q.OrderByDescending(d => d.created_at).Take(limit + 1)
                        .Select(d => new ArkWebhookDelivery
                        {
                            id = d.id, endpoint_id = d.endpoint_id, tenant_id = d.tenant_id, event_id = d.event_id, event_type = d.event_type,
                            status = d.status, attempt_count = d.attempt_count, next_attempt_at = d.next_attempt_at, created_at = d.created_at,
                            updated_at = d.updated_at, delivered_at = d.delivered_at, last_status_code = d.last_status_code,
                            last_error = d.last_error, trigger = d.trigger, replay_of = d.replay_of, payload = ""
                        })
                        .ToListAsync();
                    results.AddRange(rows.Select(r => (shard.id, r)));
                }
                catch (Exception ex) { errors.Add($"{shard.id}: {ex.GetBaseException().Message}"); }
            }
            var page = results.OrderByDescending(r => r.Row.created_at).ThenByDescending(r => r.Row.id).ToList();
            return new
            {
                items = page.Take(limit).Select(r => new
                {
                    shard = r.Shard,
                    r.Row.id,
                    r.Row.endpoint_id,
                    r.Row.tenant_id,
                    r.Row.event_id,
                    r.Row.event_type,
                    r.Row.status,
                    r.Row.attempt_count,
                    next_attempt_at = Unfinished(r.Row.status) ? r.Row.next_attempt_at : (DateTime?)null,
                    r.Row.created_at,
                    r.Row.updated_at,
                    r.Row.delivered_at,
                    r.Row.last_status_code,
                    r.Row.last_error,
                    r.Row.trigger,
                    r.Row.replay_of
                }),
                more = page.Count > limit,
                errors
            };
        }

        private static bool Unfinished(string status) => ArkDeliveryStatus.Unfinished.Contains(status);

        public async Task<object> DeliveryAsync(string? shardId, string? id)
        {
            var (db, suffix) = ArkWebhookRouter.ParseShardId(shardId);
            if (string.IsNullOrWhiteSpace(id)) throw new ArkWebhookException("id_required", "id is required.");
            await using var ctx = _dbs.Shard(db, suffix);
            var row = await ctx.deliveries.AsNoTracking().FirstOrDefaultAsync(d => d.id == id)
                ?? throw new ArkWebhookException("not_found", $"delivery '{id}' is not in shard '{shardId}'.", 404);
            var attempts = await ctx.attempts.AsNoTracking().Where(a => a.delivery_id == id).OrderBy(a => a.attempt_no).ThenBy(a => a.started_at).ToListAsync();
            var dead = await ctx.dead_letters.AsNoTracking().Where(l => l.delivery_id == id).OrderByDescending(l => l.dead_at).FirstOrDefaultAsync();
            return new
            {
                shard = shardId,
                delivery = row,
                attempts,
                dead_letter = dead
            };
        }

        public async Task<object> CancelDeliveryAsync(ArkWebhookRowRef req)
        {
            var (db, suffix) = ArkWebhookRouter.ParseShardId(req?.shard);
            await using var ctx = _dbs.Shard(db, suffix);
            var row = await ctx.deliveries.AsNoTracking().FirstOrDefaultAsync(d => d.id == req!.id)
                ?? throw new ArkWebhookException("not_found", "the delivery does not exist.", 404);
            if (row.status != ArkDeliveryStatus.Pending && row.status != ArkDeliveryStatus.Retrying)
                throw new ArkWebhookException("bad_transition", $"a {row.status} delivery cannot be cancelled.", 409);
            var v = row.lock_version;
            var now = DateTime.UtcNow;
            var n = await ctx.deliveries.Where(d => d.id == row.id && d.lock_version == v)
                .ExecuteUpdateAsync(s => s.SetProperty(d => d.status, ArkDeliveryStatus.Cancelled)
                    .SetProperty(d => d.last_error, "cancelled by an administrator")
                    .SetProperty(d => d.lock_version, v + 1)
                    .SetProperty(d => d.updated_at, now));
            if (n != 1) throw new ArkWebhookException("conflict", "the delivery changed while it was being cancelled - it may be in flight. Reload and try again.", 409);
            return new { shard = req!.shard, id = row.id, status = ArkDeliveryStatus.Cancelled };
        }

        /// <summary>
        /// Sends a finished delivery again, as a new delivery routed by the endpoint's current
        /// plan, with the same event id and body. The original is left as it was, for the record.
        /// </summary>
        public async Task<object> ReplayDeliveryAsync(ArkWebhookRowRef req, string who)
        {
            var (db, suffix) = ArkWebhookRouter.ParseShardId(req?.shard);
            ArkWebhookDelivery row;
            await using (var ctx = _dbs.Shard(db, suffix))
            {
                row = await ctx.deliveries.AsNoTracking().FirstOrDefaultAsync(d => d.id == req!.id)
                    ?? throw new ArkWebhookException("not_found", "the delivery does not exist.", 404);
            }
            if (Unfinished(row.status))
                throw new ArkWebhookException("bad_transition", $"the delivery is still {row.status.Replace('_', ' ')} - cancel it first or wait for it to finish.", 409);
            var created = await ReplayAsync(row.endpoint_id, row.tenant_id, row.event_id, row.event_type, row.partition_key, row.payload,
                $"{req!.shard}/{row.id}");
            if (row.status == ArkDeliveryStatus.Dead)
            {
                await using var ctx = _dbs.Shard(db, suffix);
                var now = DateTime.UtcNow;
                await ctx.dead_letters.Where(l => l.delivery_id == row.id && l.replayed_at == null)
                    .ExecuteUpdateAsync(s => s.SetProperty(l => l.replayed_at, now).SetProperty(l => l.replayed_by, who).SetProperty(l => l.replay_delivery, created));
            }
            return new { replayed = $"{req.shard}/{row.id}", delivery = created };
        }

        private async Task<string> ReplayAsync(string endpointId, string tenantId, string eventId, string eventType, string? partition, string payload, string replayOf)
        {
            var ep = _registry.Endpoint(endpointId);
            if (ep == null)
            {
                await _registry.RefreshAsync();
                ep = _registry.Endpoint(endpointId) ?? throw new ArkWebhookException("endpoint_gone", "the webhook this belonged to has been deleted.", 409);
            }
            if (ep.Status == ArkWebhookStatus.Disabled)
                throw new ArkWebhookException("endpoint_disabled", $"'{ep.Row.name}' is disabled - enable it before replaying.", 409);
            var now = DateTime.UtcNow;
            var (db, suffix) = ArkWebhookRouter.Route(ep.Plan, partition ?? eventId, now);
            await _registry.EnsureShardAsync(db, suffix, ep.Plan.Strategy, ep.Id);
            var delivery = new ArkWebhookDelivery
            {
                id = ArkWebhookFanout.NewDeliveryId(),
                endpoint_id = ep.Id,
                tenant_id = tenantId,
                event_id = eventId,
                event_type = eventType,
                partition_key = partition,
                payload = payload,
                status = ArkDeliveryStatus.Pending,
                next_attempt_at = now,
                created_at = now,
                updated_at = now,
                trigger = "replay",
                replay_of = ArkWebhookFanout.Truncate(replayOf, 160)
            };
            await using var ctx = _dbs.Shard(db, suffix);
            ctx.deliveries.Add(delivery);
            await ctx.SaveChangesAsync();
            _signal.Pulse();
            return $"{ArkWebhookRouter.ShardId(db, suffix)}/{delivery.id}";
        }

        // ================================================================== dead letters

        public async Task<object> DeadLettersAsync(string? endpointId, string? tenantId, bool includeReplayed, int limit)
        {
            limit = Math.Clamp(limit <= 0 ? 100 : limit, 1, 1000);
            var ids = await EndpointIdsAsync(tenantId, endpointId);
            if (ids.Count == 0) return new { items = Array.Empty<object>(), open = 0 };
            var items = new List<(string Shard, ArkWebhookDeadLetter Row)>();
            var open = 0;
            var errors = new List<string>();
            foreach (var shard in await ShardsForAsync(ids))
            {
                try
                {
                    await using var ctx = _dbs.Shard(shard.database_name, shard.table_suffix);
                    var q = ctx.dead_letters.AsNoTracking().Where(l => ids.Contains(l.endpoint_id));
                    open += await q.CountAsync(l => l.replayed_at == null);
                    if (!includeReplayed) q = q.Where(l => l.replayed_at == null);
                    var rows = await q.OrderByDescending(l => l.dead_at).Take(limit)
                        .Select(l => new ArkWebhookDeadLetter
                        {
                            id = l.id, delivery_id = l.delivery_id, endpoint_id = l.endpoint_id, tenant_id = l.tenant_id,
                            event_id = l.event_id, event_type = l.event_type, reason = l.reason, attempts = l.attempts,
                            last_status_code = l.last_status_code, last_error = l.last_error, dead_at = l.dead_at,
                            replayed_at = l.replayed_at, replayed_by = l.replayed_by, replay_delivery = l.replay_delivery, payload = ""
                        }).ToListAsync();
                    items.AddRange(rows.Select(r => (shard.id, r)));
                }
                catch (Exception ex) { errors.Add($"{shard.id}: {ex.GetBaseException().Message}"); }
            }
            return new
            {
                items = items.OrderByDescending(i => i.Row.dead_at).Take(limit).Select(i => new
                {
                    shard = i.Shard,
                    i.Row.id,
                    i.Row.delivery_id,
                    i.Row.endpoint_id,
                    i.Row.tenant_id,
                    i.Row.event_id,
                    i.Row.event_type,
                    i.Row.reason,
                    i.Row.attempts,
                    i.Row.last_status_code,
                    i.Row.last_error,
                    i.Row.dead_at,
                    i.Row.replayed_at,
                    i.Row.replayed_by,
                    i.Row.replay_delivery
                }),
                open,
                errors
            };
        }

        private async Task<List<(string Shard, ArkWebhookDeadLetter Row)>> ResolveDeadLettersAsync(ArkWebhookRowsRequest req, bool openOnly)
        {
            var list = new List<(string, ArkWebhookDeadLetter)>();
            if (!string.IsNullOrWhiteSpace(req?.endpoint_id))
            {
                var ids = new List<string> { req!.endpoint_id!.Trim() };
                foreach (var shard in await ShardsForAsync(ids))
                {
                    await using var ctx = _dbs.Shard(shard.database_name, shard.table_suffix);
                    var q = ctx.dead_letters.AsNoTracking().Where(l => l.endpoint_id == ids[0]);
                    if (openOnly) q = q.Where(l => l.replayed_at == null);
                    list.AddRange((await q.OrderBy(l => l.dead_at).Take(5000).ToListAsync()).Select(r => (shard.id, r)));
                }
                return list;
            }
            foreach (var item in (req?.items ?? new()).Take(1000))
            {
                var (db, suffix) = ArkWebhookRouter.ParseShardId(item.shard);
                await using var ctx = _dbs.Shard(db, suffix);
                var row = await ctx.dead_letters.AsNoTracking().FirstOrDefaultAsync(l => l.id == item.id);
                if (row != null && (!openOnly || row.replayed_at == null)) list.Add((item.shard!, row));
            }
            return list;
        }

        public async Task<object> ReplayDeadLettersAsync(ArkWebhookRowsRequest req, string who)
        {
            var letters = await ResolveDeadLettersAsync(req, openOnly: true);
            var replayed = new List<object>();
            var failed = new List<object>();
            foreach (var (shard, l) in letters)
            {
                try
                {
                    var created = await ReplayAsync(l.endpoint_id, l.tenant_id, l.event_id, l.event_type, null, l.payload, $"{shard}/{l.delivery_id}");
                    var (db, suffix) = ArkWebhookRouter.ParseShardId(shard);
                    await using var ctx = _dbs.Shard(db, suffix);
                    var now = DateTime.UtcNow;
                    await ctx.dead_letters.Where(x => x.id == l.id && x.replayed_at == null)
                        .ExecuteUpdateAsync(s => s.SetProperty(x => x.replayed_at, now).SetProperty(x => x.replayed_by, who).SetProperty(x => x.replay_delivery, created));
                    replayed.Add(new { shard, l.id, delivery = created });
                }
                catch (ArkWebhookException ex)
                {
                    failed.Add(new { shard, l.id, error = ex.Message });
                    // One disabled or deleted endpoint fails the rest of its letters the same way.
                    if (ex.Code is "endpoint_disabled" or "endpoint_gone" && !string.IsNullOrWhiteSpace(req.endpoint_id)) break;
                }
            }
            return new { replayed = replayed.Count, failed, items = replayed };
        }

        public async Task<object> PurgeDeadLettersAsync(ArkWebhookRowsRequest req)
        {
            var letters = await ResolveDeadLettersAsync(req, openOnly: false);
            var removed = 0;
            foreach (var group in letters.GroupBy(l => l.Shard))
            {
                var (db, suffix) = ArkWebhookRouter.ParseShardId(group.Key);
                await using var ctx = _dbs.Shard(db, suffix);
                var ids = group.Select(g => g.Row.id).ToList();
                removed += await ctx.dead_letters.Where(l => ids.Contains(l.id)).ExecuteDeleteAsync();
            }
            return new { removed };
        }

        // ================================================================== analytics

        private sealed class Tally
        {
            public int Delivered, Dead, Cancelled, Backlog, AttemptsOk, AttemptsFailed, OpenDeadLetters;
            public double DurationSum;
            public int DurationCount;
            public List<int> Durations = new();
        }

        /// <summary>
        /// Deliveries, attempts, failures and dead letters per endpoint over the last
        /// <paramref name="hours"/>, and an hourly series for the chart. Counted from the shard
        /// tables directly, so the figures are what is stored, on every instance.
        /// </summary>
        public async Task<object> AnalyticsAsync(string? tenantId, string? endpointId, int hours)
        {
            hours = Math.Clamp(hours <= 0 ? 24 : hours, 1, 24 * 30);
            var now = DateTime.UtcNow;
            var since = now.AddHours(-hours);
            List<ArkWebhookEndpoint> endpoints;
            await using (var ctl = _dbs.Control())
            {
                var q = ctl.endpoints.AsNoTracking();
                if (!string.IsNullOrWhiteSpace(tenantId)) q = q.Where(e => e.tenant_id == tenantId);
                if (!string.IsNullOrWhiteSpace(endpointId)) q = q.Where(e => e.id == endpointId);
                endpoints = await q.ToListAsync();
            }
            var ids = endpoints.Select(e => e.id).ToList();
            var tallies = ids.ToDictionary(i => i, _ => new Tally());
            // Hourly buckets, oldest first; the series aggregates every endpoint in scope.
            var bucketHours = hours <= 48 ? 1 : (hours <= 24 * 7 ? 6 : 24);
            var bucketCount = (int)Math.Ceiling(hours / (double)bucketHours);
            var start = new DateTime(since.Year, since.Month, since.Day, since.Hour, 0, 0, DateTimeKind.Utc);
            var ok = new int[bucketCount + 1];
            var bad = new int[bucketCount + 1];
            var errors = new List<string>();
            var sampled = false;

            if (ids.Count > 0)
            {
                foreach (var shard in await ShardsForAsync(ids))
                {
                    try
                    {
                        await using var ctx = _dbs.Shard(shard.database_name, shard.table_suffix);
                        var byStatus = await ctx.deliveries.AsNoTracking()
                            .Where(d => ids.Contains(d.endpoint_id) && d.created_at >= since)
                            .GroupBy(d => new { d.endpoint_id, d.status })
                            .Select(g => new { g.Key.endpoint_id, g.Key.status, n = g.Count() })
                            .ToListAsync();
                        foreach (var g in byStatus)
                        {
                            var t = tallies[g.endpoint_id];
                            if (g.status == ArkDeliveryStatus.Delivered) t.Delivered += g.n;
                            else if (g.status == ArkDeliveryStatus.Dead) t.Dead += g.n;
                            else if (g.status == ArkDeliveryStatus.Cancelled) t.Cancelled += g.n;
                        }
                        var backlog = await ctx.deliveries.AsNoTracking()
                            .Where(d => ids.Contains(d.endpoint_id) && (d.status == ArkDeliveryStatus.Pending || d.status == ArkDeliveryStatus.Retrying || d.status == ArkDeliveryStatus.InFlight))
                            .GroupBy(d => d.endpoint_id)
                            .Select(g => new { endpoint_id = g.Key, n = g.Count() })
                            .ToListAsync();
                        foreach (var g in backlog) tallies[g.endpoint_id].Backlog += g.n;

                        var openLetters = await ctx.dead_letters.AsNoTracking()
                            .Where(l => ids.Contains(l.endpoint_id) && l.replayed_at == null)
                            .GroupBy(l => l.endpoint_id)
                            .Select(g => new { endpoint_id = g.Key, n = g.Count() })
                            .ToListAsync();
                        foreach (var g in openLetters) tallies[g.endpoint_id].OpenDeadLetters += g.n;

                        var attempts = await ctx.attempts.AsNoTracking()
                            .Where(a => ids.Contains(a.endpoint_id) && a.started_at >= since)
                            .OrderByDescending(a => a.started_at)
                            .Select(a => new { a.endpoint_id, a.started_at, a.success, a.duration_ms })
                            .Take(50_000)
                            .ToListAsync();
                        if (attempts.Count == 50_000) sampled = true;
                        foreach (var a in attempts)
                        {
                            var t = tallies[a.endpoint_id];
                            if (a.success) t.AttemptsOk++; else t.AttemptsFailed++;
                            t.DurationSum += a.duration_ms;
                            t.DurationCount++;
                            if (t.Durations.Count < 20_000) t.Durations.Add(a.duration_ms);
                            var started = DateTime.SpecifyKind(a.started_at, DateTimeKind.Utc);
                            var i = (int)((started - start).TotalHours / bucketHours);
                            if (i < 0 || i > bucketCount) continue;
                            if (a.success) ok[i]++; else bad[i]++;
                        }
                    }
                    catch (Exception ex) { errors.Add($"{shard.id}: {ex.GetBaseException().Message}"); }
                }
            }

            static int? P95(List<int> values)
            {
                if (values.Count == 0) return null;
                values.Sort();
                return values[(int)Math.Min(values.Count - 1, Math.Ceiling(values.Count * 0.95) - 1)];
            }

            var perEndpoint = endpoints.OrderBy(e => e.tenant_id).ThenBy(e => e.name).Select(e =>
            {
                var t = tallies[e.id];
                var attempts = t.AttemptsOk + t.AttemptsFailed;
                return new
                {
                    e.id,
                    e.tenant_id,
                    e.name,
                    e.url,
                    e.status,
                    auto_disabled = e.status == ArkWebhookStatus.Disabled && (e.disabled_reason ?? "").StartsWith("Disabled automatically", StringComparison.Ordinal),
                    e.disabled_reason,
                    e.disabled_at,
                    e.consecutive_failures,
                    e.failure_threshold,
                    delivered = t.Delivered,
                    dead = t.Dead,
                    cancelled = t.Cancelled,
                    backlog = t.Backlog,
                    attempts,
                    failed_attempts = t.AttemptsFailed,
                    success_rate = attempts == 0 ? (double?)null : Math.Round(100.0 * t.AttemptsOk / attempts, 1),
                    avg_ms = t.DurationCount == 0 ? (int?)null : (int)(t.DurationSum / t.DurationCount),
                    p95_ms = P95(t.Durations),
                    open_dead_letters = t.OpenDeadLetters,
                    e.last_success_at,
                    e.last_failure_at,
                    e.last_status_code,
                    e.last_error
                };
            }).ToList();

            var totalAttempts = perEndpoint.Sum(p => p.attempts);
            var totalFailed = perEndpoint.Sum(p => p.failed_attempts);
            return new
            {
                hours,
                since,
                bucket_hours = bucketHours,
                sampled,
                totals = new
                {
                    endpoints = endpoints.Count,
                    active = endpoints.Count(e => e.status == ArkWebhookStatus.Active),
                    paused = endpoints.Count(e => e.status == ArkWebhookStatus.Paused),
                    disabled = endpoints.Count(e => e.status == ArkWebhookStatus.Disabled),
                    auto_disabled = perEndpoint.Count(p => p.auto_disabled),
                    failing = endpoints.Count(e => e.status == ArkWebhookStatus.Active && e.consecutive_failures > 0),
                    delivered = perEndpoint.Sum(p => p.delivered),
                    dead = perEndpoint.Sum(p => p.dead),
                    backlog = perEndpoint.Sum(p => p.backlog),
                    attempts = totalAttempts,
                    failed_attempts = totalFailed,
                    success_rate = totalAttempts == 0 ? (double?)null : Math.Round(100.0 * (totalAttempts - totalFailed) / totalAttempts, 1),
                    open_dead_letters = perEndpoint.Sum(p => p.open_dead_letters)
                },
                series = Enumerable.Range(0, bucketCount + 1)
                    .Select(i => new { at = start.AddHours(i * bucketHours), ok = ok[i], failed = bad[i] })
                    .Where(b => b.at <= now)
                    .ToList(),
                endpoints = perEndpoint,
                errors
            };
        }

        // ================================================================== shards

        public async Task<object> ShardsAsync()
        {
            List<ArkWebhookShard> shards;
            Dictionary<string, string> names;
            await using (var ctl = _dbs.Control())
            {
                shards = await ctl.shards.AsNoTracking().OrderBy(s => s.id).ToListAsync();
                names = await ctl.endpoints.AsNoTracking().ToDictionaryAsync(e => e.id, e => e.name);
            }
            var list = new List<object>();
            foreach (var s in shards)
            {
                object? counts = null;
                string? error = null;
                try
                {
                    await using var ctx = _dbs.Shard(s.database_name, s.table_suffix);
                    var byStatus = await ctx.deliveries.AsNoTracking().GroupBy(d => d.status)
                        .Select(g => new { status = g.Key, n = g.Count() }).ToListAsync();
                    counts = new
                    {
                        deliveries = byStatus.Sum(b => b.n),
                        by_status = byStatus.ToDictionary(b => b.status, b => b.n),
                        attempts = await ctx.attempts.CountAsync(),
                        dead_letters = await ctx.dead_letters.CountAsync()
                    };
                }
                catch (Exception ex) { error = ex.GetBaseException().Message; }
                list.Add(new
                {
                    s.id,
                    database = s.database_name,
                    suffix = s.table_suffix,
                    s.strategy,
                    s.endpoint_id,
                    endpoint_name = s.endpoint_id != null && names.TryGetValue(s.endpoint_id, out var n) ? n : null,
                    s.status,
                    s.created_at,
                    s.sealed_at,
                    tables = Tables(s.table_suffix),
                    counts,
                    error
                });
            }
            return new { items = list };
        }
    }
}
