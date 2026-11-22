namespace Ark.oAuth.Oidc.Webhooks
{
    /// <summary>
    /// <c>ark_oauth_server:Webhooks</c>. Every value is optional and shown at its default.
    ///
    /// Read from configuration on every use rather than bound once, so a change to appsettings,
    /// the environment or the setup wizard's settings file applies without a restart — the same
    /// rule the rest of the server follows.
    /// </summary>
    public sealed class ArkWebhookOptions
    {
        public const string Section = "ark_oauth_server:Webhooks";

        /// <summary>Master switch. False stops queuing and dispatching; configuration and history stay.</summary>
        public bool Enabled { get; set; } = true;
        /// <summary>Requests in flight at once on this instance, across every endpoint.</summary>
        public int MaxConcurrency { get; set; } = 16;
        /// <summary>Deliveries claimed per shard per poll.</summary>
        public int BatchSize { get; set; } = 50;
        /// <summary>How often an idle dispatcher looks for due deliveries.</summary>
        public int PollIntervalMs { get; set; } = 2000;
        /// <summary>Seconds a claim is held beyond the endpoint's timeout before another worker may take it over.</summary>
        public int LeaseMarginSeconds { get; set; } = 60;
        /// <summary>How often the endpoint list and shard registry are re-read from the database.</summary>
        public int RefreshSeconds { get; set; } = 10;
        /// <summary>Delivered, cancelled and failed-test deliveries (and their attempts) are deleted after this many days.</summary>
        public int RetentionDays { get; set; } = 30;
        /// <summary>Dead letters, and the deliveries they came from, are deleted after this many days.</summary>
        public int DeadLetterRetentionDays { get; set; } = 90;
        /// <summary>How often retention and shard upkeep run, in minutes.</summary>
        public int HousekeepingMinutes { get; set; } = 10;
        /// <summary>Events waiting to be written, per instance. When full, new events are dropped and counted.</summary>
        public int QueueCapacity { get; set; } = 10_000;
        /// <summary>Largest event body accepted, in bytes.</summary>
        public int MaxPayloadBytes { get; set; } = 256 * 1024;
        /// <summary>Plain http:// endpoints. Loopback addresses are always allowed, for development.</summary>
        public bool AllowInsecureHttp { get; set; }
        /// <summary>The database holding the control tables; empty = the IdP's own.</summary>
        public string? ControlDatabase { get; set; }
        /// <summary>Overrides the worker name recorded on claims and attempts.</summary>
        public string? WorkerId { get; set; }

        internal int EffectiveMaxConcurrency => Math.Clamp(MaxConcurrency, 1, 512);
        internal int EffectiveBatchSize => Math.Clamp(BatchSize, 1, 500);
        internal int EffectivePollIntervalMs => Math.Clamp(PollIntervalMs, 100, 60_000);
        internal int EffectiveRefreshSeconds => Math.Clamp(RefreshSeconds, 2, 300);
        internal int EffectiveHousekeepingMinutes => Math.Clamp(HousekeepingMinutes, 1, 1440);
        internal int EffectiveQueueCapacity => Math.Clamp(QueueCapacity, 100, 1_000_000);
        internal int EffectiveMaxPayloadBytes => Math.Clamp(MaxPayloadBytes, 1024, 4 * 1024 * 1024);

        public static ArkWebhookOptions From(IConfiguration config)
        {
            var options = new ArkWebhookOptions();
            try { config.GetSection(Section).Bind(options); }
            catch { /* a malformed value leaves the defaults rather than stopping the IdP */ }
            return options;
        }
    }
}
