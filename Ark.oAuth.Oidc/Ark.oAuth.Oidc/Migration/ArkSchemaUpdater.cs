using System.Data;
using System.Data.Common;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;

namespace Ark.oAuth.Oidc
{
    /// <summary>
    /// Brings an existing database up to the schema this build expects, at startup.
    ///
    /// The scripts in <c>Migration/{provider}/up</c> were previously an operator's job: run
    /// <c>GET /api/migration/v1/sql?action=up&amp;name=00004_sql.sql</c> after upgrading the
    /// package, or don't. Skipping it does not fail loudly — the app starts, signs people in, and
    /// then answers <c>/api/oauth/v1/user/list</c> with a bare 500, because the entity carries a
    /// column ("users"."is_active") that the table does not have. The admin console shows an empty
    /// grid and nothing says why. That is a release note asking to be missed, so this runs the
    /// pending scripts itself.
    ///
    /// Three properties matter, because a schema updater that runs unattended on every start is
    /// only acceptable if it cannot do damage:
    ///
    ///   * <b>It never re-runs a script.</b> Applied names are recorded in
    ///     <see cref="HistoryTable"/>. Re-running 00003 would reset every client that holds no
    ///     secret back to <c>token_endpoint_auth_method = 'none'</c> — including a
    ///     <c>private_key_jwt</c> client, which legitimately has no secret.
    ///   * <b>A database that predates the history table is measured, not replayed.</b> The first
    ///     run reads what each script would create — its <c>CREATE TABLE</c> and
    ///     <c>ALTER TABLE … ADD COLUMN</c> targets — and marks a script as already applied when
    ///     all of them are present. A database built by <c>EnsureCreated</c> on this version has
    ///     the whole current schema, so every script is recorded as a baseline and none of them
    ///     executes.
    ///   * <b>Only additive work is left to it.</b> A statement it cannot run is fatal for that
    ///     script: the name is not recorded, so the next start tries again rather than leaving a
    ///     half-applied schema recorded as done.
    ///
    /// Only the SQLite scripts exist in this repository, so on every provider the scripts are
    /// followed by <see cref="AddMissingFromModel"/>: whatever table or column the entity model
    /// has and the live database does not is added, with DDL written by the provider's own
    /// migrations generator. That is what keeps MySQL and PostgreSQL current without a script per
    /// provider per release — and without it, a column added to an entity reached those databases
    /// only as the first query that selected it failing.
    /// </summary>
    public static class ArkSchemaUpdater
    {
        /// <summary>Names of the scripts already applied to this database.</summary>
        public const string HistoryTable = "ark_schema_history";

        private const string ResourcePrefix = "Ark.oAuth.Oidc.Migration.";

        /// <summary>What one call did, for the caller's log.</summary>
        public sealed class Result
        {
            public List<string> Applied { get; } = new();
            public List<string> Baselined { get; } = new();
            public List<string> Skipped { get; } = new();
            /// <summary>Tables ("session_clients") and columns ("clients.backchannel_logout_uri") added from the model.</summary>
            public List<string> Added { get; } = new();
            public bool Any => Applied.Count > 0 || Baselined.Count > 0 || Added.Count > 0;
        }

        /// <summary>
        /// Maps an EF provider name onto the folder its scripts live in. Shared with
        /// <see cref="MigrationScript"/> so the two cannot disagree about where to look.
        /// </summary>
        public static string? ProviderFolder(string? providerName) => providerName switch
        {
            "Microsoft.EntityFrameworkCore.SqlServer" => "Sqlserver",
            "Npgsql.EntityFrameworkCore.PostgreSQL" => "Postgres",
            "MySql.EntityFrameworkCore" => "Mysql",
            "Microsoft.EntityFrameworkCore.Sqlite" => "Sqlite",
            _ => null
        };

        public static Result Apply(ArkDataContext ctx)
        {
            var result = new Result();
            var folder = ProviderFolder(ctx.Database.ProviderName);
            if (folder == null) return result;

            var connection = ctx.Database.GetDbConnection();
            var wasClosed = connection.State != ConnectionState.Open;
            if (wasClosed) connection.Open();
            try
            {
                // Scripts first: they carry data steps the model knows nothing about (00003's
                // client rewrite, the signing-key adoption), and they decide whether to run by
                // probing for their columns — which the model step would otherwise add first.
                ApplyScripts(connection, folder, result);
                AddMissingFromModel(ctx, connection, folder, result);
            }
            finally
            {
                if (wasClosed) connection.Close();
            }
            return result;
        }

        private static void ApplyScripts(DbConnection connection, string folder, Result result)
        {
            var assembly = typeof(ArkSchemaUpdater).Assembly;
            var prefix = $"{ResourcePrefix}{folder}.up.";
            var scripts = assembly.GetManifestResourceNames()
                .Where(n => n.StartsWith(prefix, StringComparison.Ordinal))
                .OrderBy(n => n, StringComparer.Ordinal)
                .ToList();
            if (scripts.Count == 0) return;

            EnsureHistoryTable(connection, folder);
            var applied = ReadHistory(connection);

            foreach (var resource in scripts)
            {
                var name = resource.Substring(prefix.Length);
                if (applied.Contains(name)) { result.Skipped.Add(name); continue; }

                var sql = ReadResource(assembly, resource);
                if (string.IsNullOrWhiteSpace(sql)) { result.Skipped.Add(name); continue; }

                if (AlreadyInSchema(connection, folder, sql))
                {
                    Record(connection, name, "baseline");
                    result.Baselined.Add(name);
                    continue;
                }

                Run(connection, folder, sql);
                Record(connection, name, "applied");
                result.Applied.Add(name);
            }
        }

        // ------------------------------------------------------------ model sync

        /// <summary>
        /// Adds every table and column the entity model has and the live database lacks.
        ///
        /// The model is the one description of the schema that every provider shares, so it is
        /// what gets measured; the DDL comes from the provider's own
        /// <see cref="IMigrationsSqlGenerator"/>, so the column types are the ones
        /// <c>EnsureCreated</c> would have chosen on that provider. On PostgreSQL this is what
        /// turns "column c.backchannel_logout_session_required does not exist" (42703, thrown from
        /// ReconcileAdminConsoleClient on the first request) into an <c>ALTER TABLE</c> at start-up.
        ///
        /// Strictly additive: nothing is dropped, renamed or retyped, and a column the database
        /// has but the model does not is left alone. A missing table is created whole, with its
        /// indexes. A missing NOT NULL column is given the entity's own initial value as its
        /// default, so existing rows read as a freshly constructed entity would — adding
        /// <c>is_active</c> with the CLR default instead would switch every existing client off.
        /// </summary>
        private static void AddMissingFromModel(ArkDataContext ctx, DbConnection connection, string folder, Result result)
        {
            var model = ctx.GetService<IDesignTimeModel>().Model;
            var relational = model.GetRelationalModel();
            var operations = ctx.GetService<IMigrationsModelDiffer>().GetDifferences(null, relational);

            var pending = new List<MigrationOperation>();
            foreach (var create in operations.OfType<CreateTableOperation>())
            {
                if (!TableExists(connection, folder, create.Name))
                {
                    pending.Add(create);
                    pending.AddRange(operations.OfType<CreateIndexOperation>()
                        .Where(i => i.Table == create.Name && i.Schema == create.Schema));
                    result.Added.Add(create.Name);
                    continue;
                }

                var live = LiveColumns(connection, folder, create.Name);
                var table = relational.FindTable(create.Name, create.Schema)!;
                var added = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var column in create.Columns)
                {
                    if (live.Contains(column.Name)) continue;
                    if (!column.IsNullable && column.DefaultValue == null &&
                        column.DefaultValueSql == null && column.ComputedColumnSql == null)
                        column.DefaultValue = InitialValue(table.FindColumn(column.Name)!, column.ClrType);
                    pending.Add(column);
                    added.Add(column.Name);
                    result.Added.Add($"{create.Name}.{column.Name}");
                }
                // An index over a column that was not there cannot exist yet either.
                pending.AddRange(operations.OfType<CreateIndexOperation>()
                    .Where(i => i.Table == create.Name && i.Schema == create.Schema &&
                                i.Columns.Any(added.Contains)));
            }
            if (pending.Count == 0) return;

            // One transaction, so a statement that fails on PostgreSQL or SQLite leaves nothing
            // half-added for the next start to mistake for done. MySQL commits each DDL statement
            // implicitly whatever is asked; there the next start's measurement is the retry.
            using var transaction = connection.BeginTransaction();
            foreach (var command in ctx.GetService<IMigrationsSqlGenerator>().Generate(pending, model))
                Execute(connection, command.CommandText, transaction);
            transaction.Commit();
        }

        /// <summary>
        /// The value a new entity carries for this column — its property initialiser
        /// (<c>require_pkce = true</c>, <c>access_token_lifetime_seconds = 3600</c>,
        /// <c>application_type = "web"</c>) — in provider form. Falls back to the CLR default, and
        /// to "" for a string, because NOT NULL with no default cannot be added to a table that
        /// has rows.
        /// </summary>
        private static object? InitialValue(IColumn column, Type providerType)
        {
            var mapping = column.PropertyMappings.First();
            var property = mapping.Property;
            var entityType = property.DeclaringType.ClrType;

            object? value = null;
            if (property.PropertyInfo != null && !entityType.IsAbstract &&
                entityType.GetConstructor(Type.EmptyTypes) != null)
                value = property.PropertyInfo.GetValue(Activator.CreateInstance(entityType));

            if (value != null && mapping.TypeMapping.Converter is { } converter)
                value = converter.ConvertToProvider(value);

            value ??= providerType == typeof(string) ? ""
                : providerType.IsValueType ? Activator.CreateInstance(providerType)
                : null;

            // Npgsql refuses an Unspecified DateTime for timestamptz, and default(DateTime) is one.
            if (value is DateTime dt && dt.Kind != DateTimeKind.Utc)
                value = DateTime.SpecifyKind(dt, DateTimeKind.Utc);
            return value;
        }

        // ----------------------------------------------------------------- history

        private static void EnsureHistoryTable(DbConnection connection, string folder)
        {
            // Every provider but SQL Server understands CREATE TABLE IF NOT EXISTS.
            var sql = folder == "Sqlserver"
                ? $@"IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = '{HistoryTable}')
                     CREATE TABLE [{HistoryTable}] (
                        [name] NVARCHAR(200) NOT NULL PRIMARY KEY,
                        [applied_at] NVARCHAR(40) NOT NULL,
                        [state] NVARCHAR(20) NOT NULL);"
                : $@"CREATE TABLE IF NOT EXISTS {Quote(folder, HistoryTable)} (
                        {Quote(folder, "name")} VARCHAR(200) NOT NULL PRIMARY KEY,
                        {Quote(folder, "applied_at")} VARCHAR(40) NOT NULL,
                        {Quote(folder, "state")} VARCHAR(20) NOT NULL);";
            Execute(connection, sql);
        }

        private static HashSet<string> ReadHistory(DbConnection connection)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            using var command = connection.CreateCommand();
            command.CommandText = $"SELECT name FROM {HistoryTable}";
            using var reader = command.ExecuteReader();
            while (reader.Read()) names.Add(reader.GetString(0));
            return names;
        }

        private static void Record(DbConnection connection, string name, string state)
        {
            using var command = connection.CreateCommand();
            command.CommandText =
                $"INSERT INTO {HistoryTable} (name, applied_at, state) VALUES (@name, @at, @state)";
            command.Parameters.Add(Parameter(command, "@name", name));
            command.Parameters.Add(Parameter(command, "@at", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss")));
            command.Parameters.Add(Parameter(command, "@state", state));
            command.ExecuteNonQuery();
        }

        // ------------------------------------------------------------ schema probe

        private static readonly Regex CreateTableRe = new(
            @"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[""`\[]?(?<t>[A-Za-z0-9_]+)[""`\]]?",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private static readonly Regex AddColumnRe = new(
            @"ALTER\s+TABLE\s+[""`\[]?(?<t>[A-Za-z0-9_]+)[""`\]]?\s+ADD\s+(?:COLUMN\s+)?[""`\[]?(?<c>[A-Za-z0-9_]+)[""`\]]?",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        /// <summary>
        /// True when everything the script creates is already there.
        ///
        /// This is how a database that predates <see cref="HistoryTable"/> is classified without
        /// executing anything. A script that creates nothing — a pure data script — cannot be
        /// measured this way and is treated as pending, so such a script has to be written to be
        /// safe to run twice.
        /// </summary>
        private static bool AlreadyInSchema(DbConnection connection, string folder, string sql)
        {
            var probes = 0;
            // Statement by statement, because SplitStatements has already dropped the comments.
            // Reading the raw script instead means prose is measured as though it were DDL — the
            // header of 00003 contains the words "the CREATE TABLE statements", which probed for a
            // table called "statements", found none, and concluded that a script already applied
            // in full was pending. Running it then flipped every secretless client to
            // token_endpoint_auth_method 'none', which is the one thing this class exists to
            // prevent.
            foreach (var statement in SplitStatements(sql))
            {
                foreach (Match m in CreateTableRe.Matches(statement))
                {
                    probes++;
                    if (!TableExists(connection, folder, m.Groups["t"].Value)) return false;
                }
                foreach (Match m in AddColumnRe.Matches(statement))
                {
                    probes++;
                    if (!ColumnExists(connection, folder, m.Groups["t"].Value, m.Groups["c"].Value)) return false;
                }
            }
            return probes > 0;
        }

        private static bool TableExists(DbConnection connection, string folder, string table)
        {
            using var command = connection.CreateCommand();
            if (folder == "Sqlite")
            {
                command.CommandText =
                    "SELECT COUNT(*) FROM sqlite_master WHERE type IN ('table','view') AND lower(name) = lower(@t)";
            }
            else
            {
                command.CommandText =
                    "SELECT COUNT(*) FROM information_schema.tables WHERE lower(table_name) = lower(@t)" +
                    SchemaScope(folder);
            }
            command.Parameters.Add(Parameter(command, "@t", table));
            return Convert.ToInt32(command.ExecuteScalar() ?? 0) > 0;
        }

        private static HashSet<string> LiveColumns(DbConnection connection, string folder, string table)
        {
            using var command = connection.CreateCommand();
            command.CommandText = folder == "Sqlite"
                ? "SELECT name FROM pragma_table_info(@t)"
                : "SELECT column_name FROM information_schema.columns WHERE lower(table_name) = lower(@t)" +
                  SchemaScope(folder);
            command.Parameters.Add(Parameter(command, "@t", table));
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            using var reader = command.ExecuteReader();
            while (reader.Read()) names.Add(reader.GetString(0));
            return names;
        }

        /// <summary>
        /// Limits an information_schema probe to the schema this connection resolves names in.
        /// MySQL's information_schema spans every database on the server, so unscoped, a "clients"
        /// table in a neighbouring database reads as this one already having it.
        /// </summary>
        private static string SchemaScope(string folder) => folder switch
        {
            "Postgres" => " AND table_schema = current_schema()",
            "Mysql" => " AND table_schema = DATABASE()",
            "Sqlserver" => " AND table_schema = SCHEMA_NAME()",
            _ => ""
        };

        private static bool ColumnExists(DbConnection connection, string folder, string table, string column)
        {
            using var command = connection.CreateCommand();
            if (folder == "Sqlite")
            {
                // pragma_table_info takes the table name as an argument, so it is still a
                // parameter rather than string concatenation.
                command.CommandText =
                    "SELECT COUNT(*) FROM pragma_table_info(@t) WHERE lower(name) = lower(@c)";
            }
            else
            {
                command.CommandText =
                    "SELECT COUNT(*) FROM information_schema.columns " +
                    "WHERE lower(table_name) = lower(@t) AND lower(column_name) = lower(@c)" +
                    SchemaScope(folder);
            }
            command.Parameters.Add(Parameter(command, "@t", table));
            command.Parameters.Add(Parameter(command, "@c", column));
            return Convert.ToInt32(command.ExecuteScalar() ?? 0) > 0;
        }

        // --------------------------------------------------------------- execution

        /// <summary>
        /// Runs one script, statement by statement.
        ///
        /// Not as a single batch: SQLite ignores IF NOT EXISTS on ADD COLUMN, so a script that is
        /// half-applied — the state a database is left in by the old manual endpoint, which
        /// swallowed the failure and still reported success — aborts the batch at the first
        /// duplicate column and silently drops every statement after it. Each ADD COLUMN is
        /// therefore checked against the live schema first and skipped if it is already there.
        /// </summary>
        private static void Run(DbConnection connection, string folder, string sql)
        {
            foreach (var statement in SplitStatements(sql))
            {
                var add = AddColumnRe.Match(statement);
                if (add.Success &&
                    ColumnExists(connection, folder, add.Groups["t"].Value, add.Groups["c"].Value))
                    continue;

                Execute(connection, statement);
            }
        }

        private static void Execute(DbConnection connection, string sql, DbTransaction? transaction = null)
        {
            using var command = connection.CreateCommand();
            command.CommandText = sql;
            // Microsoft.Data.Sqlite refuses a command that is not enlisted in the open transaction.
            command.Transaction = transaction;
            command.ExecuteNonQuery();
        }

        /// <summary>
        /// Splits a script on semicolons that are not inside a string literal or a comment.
        /// The scope catalogue in 00003 inserts JSON arrays of claim names, so a naive
        /// <c>Split(';')</c> would be one bad literal away from cutting a statement in half.
        /// </summary>
        internal static List<string> SplitStatements(string sql)
        {
            var statements = new List<string>();
            var current = new StringBuilder();
            var inString = false;
            var inLineComment = false;
            var inBlockComment = false;

            for (var i = 0; i < sql.Length; i++)
            {
                var c = sql[i];
                var next = i + 1 < sql.Length ? sql[i + 1] : '\0';

                if (inLineComment)
                {
                    if (c == '\n') { inLineComment = false; current.Append(c); }
                    continue;
                }
                if (inBlockComment)
                {
                    if (c == '*' && next == '/') { inBlockComment = false; i++; }
                    continue;
                }
                if (inString)
                {
                    current.Append(c);
                    // '' is an escaped quote, not the end of the literal
                    if (c == '\'' && next == '\'') { current.Append(next); i++; }
                    else if (c == '\'') inString = false;
                    continue;
                }
                if (c == '-' && next == '-') { inLineComment = true; i++; continue; }
                if (c == '/' && next == '*') { inBlockComment = true; i++; continue; }
                if (c == '\'') { inString = true; current.Append(c); continue; }
                if (c == ';')
                {
                    var done = current.ToString().Trim();
                    if (done.Length > 0) statements.Add(done);
                    current.Clear();
                    continue;
                }
                current.Append(c);
            }

            var tail = current.ToString().Trim();
            if (tail.Length > 0) statements.Add(tail);
            return statements;
        }

        // ------------------------------------------------------------------ util

        private static string Quote(string folder, string identifier) => folder switch
        {
            "Mysql" => $"`{identifier}`",
            _ => $"\"{identifier}\""
        };

        private static DbParameter Parameter(DbCommand command, string name, string value)
        {
            var parameter = command.CreateParameter();
            parameter.ParameterName = name;
            parameter.Value = value;
            return parameter;
        }

        private static string? ReadResource(Assembly assembly, string resource)
        {
            using var stream = assembly.GetManifestResourceStream(resource);
            if (stream == null) return null;
            using var reader = new StreamReader(stream);
            return reader.ReadToEnd();
        }
    }
}
