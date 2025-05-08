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
        public virtual DbSet<ArkAudit> audit_trace { get; set; }
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
            var ser = _config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>() ?? throw new ApplicationException("server config missing");
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
    }
}