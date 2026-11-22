using System.Collections.Concurrent;
using System.Data;
using System.Data.Common;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;

namespace Ark.oAuth.Oidc.Webhooks
{
    /// <summary>The control tables: endpoints and the shard registry.</summary>
    public sealed class ArkWebhookControlContext : DbContext
    {
        public ArkWebhookControlContext(DbContextOptions<ArkWebhookControlContext> options) : base(options) { }

        public DbSet<ArkWebhookEndpoint> endpoints => Set<ArkWebhookEndpoint>();
        public DbSet<ArkWebhookShard> shards => Set<ArkWebhookShard>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<ArkWebhookEndpoint>(e =>
            {
                e.ToTable("ark_wh_endpoints");
                e.HasIndex(x => x.tenant_id).HasDatabaseName("ix_wh_endpoints_tenant");
            });
            modelBuilder.Entity<ArkWebhookShard>(e => e.ToTable("ark_wh_shards"));
        }
    }

    /// <summary>
    /// One shard's three tables. The table names carry <see cref="Suffix"/>, so one context type
    /// maps any number of physical table sets; <see cref="ArkWebhookModelCacheKeyFactory"/> keeps a
    /// model per suffix rather than handing every shard the first one built.
    /// </summary>
    public sealed class ArkWebhookShardContext : DbContext
    {
        public string Suffix { get; }

        public ArkWebhookShardContext(DbContextOptions<ArkWebhookShardContext> options, string suffix) : base(options)
        {
            if (!ArkWebhookDatabases.IsValidSuffix(suffix))
                throw new ArgumentException($"'{suffix}' is not a valid shard suffix.", nameof(suffix));
            Suffix = suffix;
        }

        public DbSet<ArkWebhookDelivery> deliveries => Set<ArkWebhookDelivery>();
        public DbSet<ArkWebhookAttempt> attempts => Set<ArkWebhookAttempt>();
        public DbSet<ArkWebhookDeadLetter> dead_letters => Set<ArkWebhookDeadLetter>();

        public static string DeliveriesTable(string suffix) => $"ark_wh_deliveries_{suffix}";
        public static string AttemptsTable(string suffix) => $"ark_wh_attempts_{suffix}";
        public static string DeadLettersTable(string suffix) => $"ark_wh_dead_letters_{suffix}";

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            var s = Suffix;
            // Index names are spelled out, short and suffixed: PostgreSQL wants them unique per
            // schema and truncates past 63 characters, so EF's IX_{table}_{columns} would collide
            // between two long suffixes that share a prefix.
            modelBuilder.Entity<ArkWebhookDelivery>(e =>
            {
                e.ToTable(DeliveriesTable(s));
                e.HasIndex(x => new { x.status, x.next_attempt_at }).HasDatabaseName($"ix_whd_{s}_due");
                e.HasIndex(x => new { x.endpoint_id, x.created_at }).HasDatabaseName($"ix_whd_{s}_ep");
                e.HasIndex(x => x.event_id).HasDatabaseName($"ix_whd_{s}_evt");
            });
            modelBuilder.Entity<ArkWebhookAttempt>(e =>
            {
                e.ToTable(AttemptsTable(s));
                e.HasIndex(x => x.delivery_id).HasDatabaseName($"ix_wha_{s}_dlv");
                e.HasIndex(x => new { x.endpoint_id, x.started_at }).HasDatabaseName($"ix_wha_{s}_ep");
            });
            modelBuilder.Entity<ArkWebhookDeadLetter>(e =>
            {
                e.ToTable(DeadLettersTable(s));
                e.HasIndex(x => new { x.endpoint_id, x.dead_at }).HasDatabaseName($"ix_whl_{s}_ep");
                e.HasIndex(x => x.delivery_id).HasDatabaseName($"ix_whl_{s}_dlv");
            });
        }
    }

    /// <summary>A model per shard suffix — see <see cref="ArkWebhookShardContext"/>.</summary>
    internal sealed class ArkWebhookModelCacheKeyFactory : IModelCacheKeyFactory
    {
        public object Create(DbContext context, bool designTime) => context is ArkWebhookShardContext shard
            ? (context.GetType(), shard.Suffix, designTime)
            : (context.GetType(), designTime);
    }

    /// <summary>A database the subsystem may write to.</summary>
    public sealed record ArkWebhookDatabase(string Name, string Provider, string ConnectionString);

    /// <summary>
    /// Which databases exist and how to open a context on each.
    ///
    /// <c>main</c> is always the IdP's own database (<c>ark_oauth_server:Provider</c> and
    /// <c>ConnectionStrings:ArkAuthConnection</c>). Others are named under
    /// <c>ark_oauth_server:Webhooks:Databases:{name}</c> with a <c>Provider</c> (sqlite | postgres
    /// | mysql) and either a <c>ConnectionString</c> or a <c>ConnectionStringName</c> that points
    /// into <c>ConnectionStrings</c>. Shard plans refer to databases by name only, so a connection
    /// string never reaches the console or the endpoint rows.
    /// </summary>
    public sealed class ArkWebhookDatabases
    {
        public const string Main = "main";
        private const string DatabasesSection = ArkWebhookOptions.Section + ":Databases";

        private static readonly Regex NameRe = new("^[a-z0-9][a-z0-9_-]{0,31}$", RegexOptions.Compiled);
        private static readonly Regex SuffixRe = new("^[a-z0-9][a-z0-9_]{0,23}$", RegexOptions.Compiled);

        private readonly IConfiguration _config;
        private readonly ConcurrentDictionary<string, DbContextOptions> _options = new();
        private readonly ConcurrentDictionary<string, bool> _ensured = new();

        public ArkWebhookDatabases(IConfiguration config) => _config = config;

        public static bool IsValidName(string? name) => name != null && NameRe.IsMatch(name);
        public static bool IsValidSuffix(string? suffix) => suffix != null && SuffixRe.IsMatch(suffix);

        public static string NormalizeProvider(string? provider) => (provider ?? "").Trim().ToLowerInvariant() switch
        {
            "" or "sqlite" => "sqlite",
            "postgres" or "postgresql" or "npgsql" => "postgres",
            "mysql" => "mysql",
            var other => other
        };

        /// <summary>Every database a plan may name, with its provider; never the connection string.</summary>
        public List<(string Name, string Provider, bool Configured)> List()
        {
            var list = new List<(string, string, bool)>();
            var main = TryResolve(Main);
            list.Add((Main, main?.Provider ?? "", main != null));
            foreach (var child in _config.GetSection(DatabasesSection).GetChildren())
            {
                var name = child.Key.Trim().ToLowerInvariant();
                if (name == Main || !IsValidName(name)) continue;
                var db = TryResolve(name);
                list.Add((name, db?.Provider ?? NormalizeProvider(child["Provider"]), db != null));
            }
            return list;
        }

        public bool Exists(string name) => List().Any(d => d.Name == name && d.Configured);

        public ArkWebhookDatabase? TryResolve(string? name)
        {
            name = string.IsNullOrWhiteSpace(name) ? Main : name.Trim().ToLowerInvariant();
            if (name == Main)
            {
                var provider = NormalizeProvider(_config["ark_oauth_server:Provider"]);
                var cs = _config.GetConnectionString("ArkAuthConnection");
                return string.IsNullOrWhiteSpace(cs) ? null : new ArkWebhookDatabase(Main, provider, cs);
            }
            if (!IsValidName(name)) return null;
            var section = _config.GetSection($"{DatabasesSection}:{name}");
            if (!section.Exists())
            {
                // Configuration keys are case-insensitive, but be explicit about it.
                section = _config.GetSection(DatabasesSection).GetChildren()
                    .FirstOrDefault(c => string.Equals(c.Key, name, StringComparison.OrdinalIgnoreCase)) ?? section;
            }
            var connection = section["ConnectionString"];
            if (string.IsNullOrWhiteSpace(connection) && !string.IsNullOrWhiteSpace(section["ConnectionStringName"]))
                connection = _config.GetConnectionString(section["ConnectionStringName"]!);
            if (string.IsNullOrWhiteSpace(connection)) return null;
            var p = NormalizeProvider(section["Provider"]);
            return p is "sqlite" or "postgres" or "mysql" ? new ArkWebhookDatabase(name, p, connection) : null;
        }

        public ArkWebhookDatabase Resolve(string? name) => TryResolve(name)
            ?? throw new ArkWebhookException("unknown_database",
                $"webhook database '{name}' is not configured (ark_oauth_server:Webhooks:Databases:{name}).", 400);

        public ArkWebhookDatabase ControlDatabase() => Resolve(ArkWebhookOptions.From(_config).ControlDatabase);

        /// <summary>A context on the control tables, schema ensured once per process.</summary>
        public ArkWebhookControlContext Control()
        {
            var db = ControlDatabase();
            var ctx = new ArkWebhookControlContext(OptionsFor<ArkWebhookControlContext>(db));
            EnsureOnce($"control|{db.Provider}|{db.ConnectionString}", ctx, db.Provider);
            return ctx;
        }

        /// <summary>A context on one shard's tables, schema ensured once per process.</summary>
        public ArkWebhookShardContext Shard(string database, string suffix)
        {
            var db = Resolve(database);
            var ctx = new ArkWebhookShardContext(OptionsFor<ArkWebhookShardContext>(db), suffix);
            EnsureOnce($"shard|{suffix}|{db.Provider}|{db.ConnectionString}", ctx, db.Provider);
            return ctx;
        }

        /// <summary>Whether the control tables are already there, without creating them.</summary>
        public bool ControlSchemaExists()
        {
            var db = TryResolve(ArkWebhookOptions.From(_config).ControlDatabase);
            if (db == null) return false;
            using var ctx = new ArkWebhookControlContext(OptionsFor<ArkWebhookControlContext>(db));
            return ArkWebhookSchema.TableExists(ctx, db.Provider, "ark_wh_endpoints");
        }

        private void EnsureOnce(string key, DbContext ctx, string provider)
        {
            if (_ensured.ContainsKey(key)) return;
            try
            {
                ArkWebhookSchema.Ensure(ctx, provider);
                _ensured[key] = true;
            }
            catch
            {
                ctx.Dispose();
                throw;
            }
        }

        /// <summary>Forgets which schemas were ensured, so the next context checks again.</summary>
        internal void ForgetSchema() => _ensured.Clear();

        private DbContextOptions<T> OptionsFor<T>(ArkWebhookDatabase db) where T : DbContext
        {
            var key = $"{typeof(T).Name}|{db.Provider}|{db.ConnectionString}";
            return (DbContextOptions<T>)_options.GetOrAdd(key, _ =>
            {
                var builder = new DbContextOptionsBuilder<T>();
                switch (db.Provider)
                {
                    case "sqlite": builder.UseSqlite(db.ConnectionString); break;
                    case "postgres": builder.UseNpgsql(db.ConnectionString); break;
                    case "mysql": builder.UseMySQL(db.ConnectionString); break;
                    default: throw new ArkWebhookException("unknown_provider", $"database provider '{db.Provider}' is not supported for webhooks.", 500);
                }
                builder.ReplaceService<IModelCacheKeyFactory, ArkWebhookModelCacheKeyFactory>();
                return builder.Options;
            });
        }
    }

    /// <summary>
    /// Creates the subsystem's tables, and adds columns a later version introduced. Strictly
    /// additive, like <see cref="ArkSchemaUpdater"/> — nothing is dropped, renamed or retyped —
    /// and only ever pointed at the webhook contexts, never at the IdP's model.
    /// </summary>
    internal static class ArkWebhookSchema
    {
        public static void Ensure(DbContext ctx, string provider)
        {
            var model = ctx.GetService<IDesignTimeModel>().Model;
            var relational = model.GetRelationalModel();
            var operations = ctx.GetService<IMigrationsModelDiffer>().GetDifferences(null, relational);

            var connection = ctx.Database.GetDbConnection();
            var wasClosed = connection.State != ConnectionState.Open;
            if (wasClosed) connection.Open();
            try
            {
                var pending = new List<MigrationOperation>();
                var creates = new List<string>();
                foreach (var create in operations.OfType<CreateTableOperation>())
                {
                    if (!TableExists(connection, provider, create.Name))
                    {
                        pending.Add(create);
                        pending.AddRange(operations.OfType<CreateIndexOperation>().Where(i => i.Table == create.Name));
                        creates.Add(create.Name);
                        continue;
                    }
                    var live = LiveColumns(connection, provider, create.Name);
                    foreach (var column in create.Columns)
                    {
                        if (live.Contains(column.Name)) continue;
                        if (!column.IsNullable && column.DefaultValue == null && column.DefaultValueSql == null)
                            column.DefaultValue = InitialValue(column.ClrType);
                        pending.Add(column);
                    }
                }
                if (pending.Count == 0) return;

                Exception? failure = null;
                foreach (var command in ctx.GetService<IMigrationsSqlGenerator>().Generate(pending, model))
                {
                    try
                    {
                        using var cmd = connection.CreateCommand();
                        cmd.CommandText = command.CommandText;
                        cmd.ExecuteNonQuery();
                    }
                    catch (Exception ex)
                    {
                        // Most often a second instance creating the same shard in the same second.
                        // Measured again below: only a table that is still missing is a failure.
                        failure ??= ex;
                    }
                }
                if (failure != null && creates.Any(t => !TableExists(connection, provider, t)))
                    throw new ArkWebhookException("schema_failed",
                        $"the webhook tables could not be created: {failure.GetBaseException().Message}", 500);
            }
            finally
            {
                if (wasClosed) connection.Close();
            }
        }

        public static bool TableExists(DbContext ctx, string provider, string table)
        {
            var connection = ctx.Database.GetDbConnection();
            var wasClosed = connection.State != ConnectionState.Open;
            if (wasClosed) connection.Open();
            try { return TableExists(connection, provider, table); }
            finally { if (wasClosed) connection.Close(); }
        }

        private static bool TableExists(DbConnection connection, string provider, string table)
        {
            using var cmd = connection.CreateCommand();
            cmd.CommandText = provider switch
            {
                "sqlite" => "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = @n",
                "postgres" => "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = @n",
                _ => "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = @n"
            };
            AddParameter(cmd, "@n", table);
            return Convert.ToInt64(cmd.ExecuteScalar()) > 0;
        }

        private static HashSet<string> LiveColumns(DbConnection connection, string provider, string table)
        {
            var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            using var cmd = connection.CreateCommand();
            if (provider == "sqlite")
            {
                // Table names here come from the model and are validated suffixes; never input.
                cmd.CommandText = $"PRAGMA table_info(\"{table.Replace("\"", "")}\")";
                using var r = cmd.ExecuteReader();
                while (r.Read()) columns.Add(r.GetString(1));
                return columns;
            }
            cmd.CommandText = provider == "postgres"
                ? "SELECT column_name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = @n"
                : "SELECT column_name FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = @n";
            AddParameter(cmd, "@n", table);
            using (var r = cmd.ExecuteReader())
                while (r.Read()) columns.Add(r.GetString(0));
            return columns;
        }

        private static void AddParameter(DbCommand cmd, string name, object value)
        {
            var p = cmd.CreateParameter();
            p.ParameterName = name;
            p.Value = value;
            cmd.Parameters.Add(p);
        }

        private static object? InitialValue(Type type)
        {
            type = Nullable.GetUnderlyingType(type) ?? type;
            if (type == typeof(string)) return "";
            if (type == typeof(bool)) return false;
            if (type == typeof(DateTime)) return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            if (type.IsValueType) return Activator.CreateInstance(type);
            return null;
        }
    }
}
