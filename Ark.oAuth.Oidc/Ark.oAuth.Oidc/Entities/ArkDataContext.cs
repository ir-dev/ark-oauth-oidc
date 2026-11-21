using Microsoft.EntityFrameworkCore;

namespace Ark.oAuth.Oidc
{
    public class ArkDataContext : DbContext
    {
        public virtual DbSet<ArkServiceAccount> service_accounts { get; set; }
        public virtual DbSet<ArkTenant> tenants { get; set; }
        public virtual DbSet<ArkClient> clients { get; set; }
        public virtual DbSet<ArkUser> users { get; set; }
        public virtual DbSet<PkceCodeFlow> pkce_code_flow { get; set; }
        public virtual DbSet<ArkClaim> claims { get; set; }
        public virtual DbSet<ArkUserClientClaim> user_client_claims { get; set; }
        public virtual DbSet<ArkAudit> audit_trace { get; set; }
        public virtual DbSet<ArkAuthStatusTrace> auth_status { get; set; }

        // --- standard OAuth 2.1 / OIDC protocol state ---
        public virtual DbSet<ArkSigningKey> signing_keys { get; set; }
        public virtual DbSet<ArkAuthCode> auth_codes { get; set; }
        public virtual DbSet<ArkRefreshToken> refresh_tokens { get; set; }
        public virtual DbSet<ArkDeviceCode> device_codes { get; set; }
        public virtual DbSet<ArkParRequest> par_requests { get; set; }
        public virtual DbSet<ArkUsedAssertion> used_assertions { get; set; }
        public virtual DbSet<ArkConsent> consents { get; set; }
        public virtual DbSet<ArkSession> sessions { get; set; }
        public virtual DbSet<ArkSessionClient> session_clients { get; set; }
        public virtual DbSet<ArkScope> scopes { get; set; }
        /// <summary>The ASP.NET Core data-protection key ring, when it is kept here — see <see cref="ArkDataProtectionKey"/>.</summary>
        public virtual DbSet<ArkDataProtectionKey> data_protection_keys { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<ArkClaim>()
                .HasIndex(prop => prop.key);
            modelBuilder.Entity<ArkUser>()
                .HasIndex(prop => prop.email);
            modelBuilder.Entity<ArkServiceAccount>()
                .HasIndex(prop => prop.account_id);
            //modelBuilder.Entity<ArkAudit>()
            //    .ToTable($"audit_trace_{ark.net.util.DateUtil.CurrentDateStamp()}"); // not createing every day
        }
        protected virtual void InitalizeContext()
        {
            // https://blog.oneunicorn.com/2012/03/12/secrets-of-detectchanges-part-3-switching-off-automatic-detectchanges/
            ChangeTracker.AutoDetectChangesEnabled = false;
            ChangeTracker.QueryTrackingBehavior = QueryTrackingBehavior.NoTracking;
            Database.SetCommandTimeout(360);
        }
        protected override void OnConfiguring(DbContextOptionsBuilder options)
        {
            // A context built with explicit options keeps them — the setup wizard tests a
            // connection string before it is anybody's configuration.
            if (options.IsConfigured) return;
            var ser = Protocol.ArkConfigSnapshot.Server(_config) ?? throw new ApplicationException("server config missing");
            if (string.IsNullOrEmpty(ser.Provider) || ser.Provider.ToLower() == "sqlite")
                options.UseSqlite(_config.GetConnectionString("ArkAuthConnection"));
            else if (ser.Provider.ToLower() == "mysql")
                options.UseMySQL(_config.GetConnectionString("ArkAuthConnection"));
            else if (ser.Provider.ToLower() == "postgres")
                options.UseNpgsql(_config.GetConnectionString("ArkAuthConnection"));
        }
        //=> options.UseSqlite(_config.GetConnectionString("ArkAuthConnection"));
        //=> options.UseMySQL(_config.GetConnectionString("ArkAuthConnection"));

        public ArkDataContext(DbContextOptions<ArkDataContext> options, IConfiguration config) : base(options)
        {
            _config = config;
        }
        IConfiguration _config;

        /// <summary>The configuration this context was built with.</summary>
        internal IConfiguration Configuration => _config;

        /// <summary>Which database this context is on; part of every <see cref="Protocol.ArkIdpCache"/> key.</summary>
        internal string CacheScope => _cacheScope ??= Database.GetConnectionString() ?? "";
        string? _cacheScope;

        // ------------------------------------------------------------------
        // Tenants, clients, scopes and signing keys are answered from ArkIdpCache. Whatever writes
        // one of them — the console, provisioning, dynamic registration, key rotation, an import —
        // comes through one of these two methods, so this is the one place that can promise a
        // write on this instance is visible to the very next request.
        // ------------------------------------------------------------------

        public override int SaveChanges(bool acceptAllChangesOnSuccess)
        {
            var cached = TouchesCachedRows();
            var written = base.SaveChanges(acceptAllChangesOnSuccess);
            if (cached) Protocol.ArkIdpCache.Reset();
            return written;
        }

        public override async Task<int> SaveChangesAsync(bool acceptAllChangesOnSuccess, CancellationToken cancellationToken = default)
        {
            var cached = TouchesCachedRows();
            var written = await base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken);
            if (cached) Protocol.ArkIdpCache.Reset();
            return written;
        }

        private bool TouchesCachedRows()
        {
            foreach (var entry in ChangeTracker.Entries())
            {
                if (entry.State is not (EntityState.Added or EntityState.Modified or EntityState.Deleted)) continue;
                if (entry.Entity is ArkTenant or ArkClient or ArkScope or ArkSigningKey) return true;
            }
            return false;
        }
    }
}