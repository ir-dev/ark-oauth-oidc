using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace Ark.oAuth.Oidc
{
    // ====================================================================== requests

    /// <summary>Body of <c>POST v1/data/export</c>. Both members are optional.</summary>
    public class ArkExportRequest
    {
        /// <summary>
        /// Write the configuration's secrets (passwords, client secrets, connection strings) into
        /// the settings section as they are. Off by default: they are redacted, because the
        /// settings are informational on import and a secret written into a file is a secret
        /// that outlives the reason it was written.
        /// </summary>
        public bool include_setting_secrets { get; set; }
        /// <summary>Encrypts the export (AES-256-GCM, key from PBKDF2-SHA256). Strongly advised.</summary>
        public string? passphrase { get; set; }
    }

    /// <summary>Body of <c>POST v1/data/import/analyze</c> and <c>POST v1/data/import/apply</c>.</summary>
    public class ArkImportRequest
    {
        /// <summary>The export file, as the JSON object it is.</summary>
        public JsonElement file { get; set; }
        /// <summary>Required when the file was exported with a passphrase.</summary>
        public string? passphrase { get; set; }
        /// <summary>
        /// Which categories to load: configuration, grants, transient, history, other.
        /// Omitted means all of them.
        /// </summary>
        public List<string>? include { get; set; }
        /// <summary>
        /// Accept a file whose checksum no longer matches its content — one edited by hand after
        /// it was exported. Off, such a file is refused outright.
        /// </summary>
        public bool allow_modified { get; set; }
        /// <summary>apply only: replace | merge_skip | merge_overwrite.</summary>
        public string? mode { get; set; }
        /// <summary>apply only: the plan_hash the analysis returned for the chosen mode.</summary>
        public string? plan_hash { get; set; }
        /// <summary>apply in replace mode only: the operator tenant id, typed out.</summary>
        public string? confirm { get; set; }
    }

    /// <summary>Body of <c>POST v1/data/reset</c>.</summary>
    public class ArkResetRequest
    {
        /// <summary>The operator tenant id (<c>ark_oauth_server:TenantId</c>), typed out exactly.</summary>
        public string? confirm { get; set; }
    }

    /// <summary>
    /// A refusal the caller can act on, with a stable <see cref="Code"/> and the HTTP status to
    /// answer it with — the same contract <see cref="ArkProvisionException"/> has.
    /// </summary>
    public class ArkDataToolsException : ApplicationException
    {
        public string Code { get; }
        public int StatusCode { get; }
        public object? Payload { get; }

        public ArkDataToolsException(string code, string message, int statusCode = 400, object? payload = null)
            : base(message)
        {
            Code = code;
            StatusCode = statusCode;
            Payload = payload;
        }
    }

    // ====================================================================== results

    public class ArkDataIssue
    {
        public string code { get; set; } = default!;
        public string msg { get; set; } = default!;
        public ArkDataIssue() { }
        public ArkDataIssue(string code, string msg) { this.code = code; this.msg = msg; }
    }

    /// <summary>What the import will do, or did, with one row of the file.</summary>
    public class ArkImportRecord
    {
        public string table { get; set; } = default!;
        /// <summary>Position of the row in that table's array in the file, from 0.</summary>
        public int index { get; set; }
        /// <summary>The row's identity: its natural key (tenant/client_id, email, kid…).</summary>
        public string key { get; set; } = default!;
        /// <summary>insert | update | unchanged | skip_existing | excluded | not_selected</summary>
        public string action { get; set; } = default!;
        /// <summary>Stable code for why — set for excluded and skip_existing rows.</summary>
        public string? reason { get; set; }
        public string? detail { get; set; }
        /// <summary>Changes the import makes to the row so it can be loaded, in the order made.</summary>
        public List<string>? adjustments { get; set; }
    }

    /// <summary>One import mode, worked out in full against the database as it is now.</summary>
    public class ArkImportPlan
    {
        public string mode { get; set; } = default!;
        public bool possible { get; set; }
        /// <summary>Why this mode cannot run. Empty when <see cref="possible"/>.</summary>
        public List<ArkDataIssue> blockers { get; set; } = new();
        public List<ArkDataIssue> warnings { get; set; } = new();
        /// <summary>Pass back to apply. Apply refuses if the plan it works out differs.</summary>
        public string plan_hash { get; set; } = "";
        /// <summary>Row counts by action, every table together.</summary>
        public Dictionary<string, int> summary { get; set; } = new();
        /// <summary>Row counts by action, per table.</summary>
        public Dictionary<string, Dictionary<string, int>> tables { get; set; } = new();
        /// <summary>Rows this server holds that the mode deletes first — replace only.</summary>
        public Dictionary<string, int> deletes { get; set; } = new();
        /// <summary>Every row that is not a plain insert or unchanged, or that was adjusted.</summary>
        public List<ArkImportRecord> records { get; set; } = new();
        /// <summary>How many such rows were left out of <see cref="records"/> to bound the response.</summary>
        public int records_truncated { get; set; }
    }

    public class ArkExportFileInfo
    {
        public string? format { get; set; }
        public int format_version { get; set; }
        public string? exported_at { get; set; }
        public string? exported_by { get; set; }
        public string? package_version { get; set; }
        public string? provider { get; set; }
        public string? operator_tenant { get; set; }
        public string? base_url { get; set; }
        public bool encrypted { get; set; }
        public bool settings_secrets_redacted { get; set; }
        /// <summary>true = matches, false = does not, null = the file carries none.</summary>
        public bool? checksum_ok { get; set; }
        public Dictionary<string, int> counts { get; set; } = new();
    }

    /// <summary>One configuration value that differs between the file and this server.</summary>
    public class ArkSettingDiff
    {
        public string key { get; set; } = default!;
        /// <summary>different | only_in_file | only_here | redacted_in_file</summary>
        public string status { get; set; } = default!;
        public string? here { get; set; }
        public string? in_file { get; set; }
    }

    public class ArkImportAnalysis
    {
        public ArkExportFileInfo file { get; set; } = new();
        /// <summary>Problems with the file itself. Any one of them stops every mode.</summary>
        public List<ArkDataIssue> blockers { get; set; } = new();
        public List<ArkDataIssue> warnings { get; set; } = new();
        public Dictionary<string, int> target_counts { get; set; } = new();
        /// <summary>This server holds nothing but its first-run seed.</summary>
        public bool target_pristine { get; set; }
        public List<string> include { get; set; } = new();
        public string? recommended_mode { get; set; }
        public string? recommendation { get; set; }
        public Dictionary<string, ArkImportPlan> modes { get; set; } = new();
        public int settings_same { get; set; }
        /// <summary>Settings are never applied — see the API guide — only compared.</summary>
        public List<ArkSettingDiff> settings { get; set; } = new();
        /// <summary>
        /// The file's settings exactly as exported (secrets redacted if they were at export), in
        /// appsettings.json shape — for the operator to load into the host's own configuration.
        /// </summary>
        public JsonObject? settings_file { get; set; }
    }

    public class ArkImportResult
    {
        public string mode { get; set; } = default!;
        public Dictionary<string, int> summary { get; set; } = new();
        public Dictionary<string, Dictionary<string, int>> tables { get; set; } = new();
        public Dictionary<string, int> deleted { get; set; } = new();
        public List<ArkImportRecord> records { get; set; } = new();
        public int records_truncated { get; set; }
        public List<string> follow_up { get; set; } = new();
    }

    public class ArkResetResult
    {
        public Dictionary<string, int> removed { get; set; } = new();
        public Dictionary<string, int> seeded { get; set; } = new();
        public string admin_user { get; set; } = default!;
        public string operator_tenant { get; set; } = default!;
        public List<string> follow_up { get; set; } = new();
    }

    /// <summary>
    /// Export, import and factory reset of the whole identity server.
    ///
    /// <b>Export</b> walks the EF model rather than a list of tables written out by hand, so every
    /// mapped table and every mapped column is in the file — including the ones the management API
    /// deliberately never serialises (password hashes, client secret hashes, private signing keys).
    /// A column added in a later release is exported by that release with no change here, and a
    /// file from an earlier release simply lacks it, which the import fills with the entity's
    /// default. That is the backward-compatibility contract in both directions.
    ///
    /// <b>Import</b> is two calls. <c>analyze</c> works out all three modes against the database as
    /// it is now — what each row would become, which rows cannot be loaded and why — and returns
    /// a hash per mode. <c>apply</c> works the chosen mode out again, refuses if the hash differs
    /// (the database or the file changed in between), and then runs it in one transaction. Every
    /// decision is a pure function of (file, database, mode, categories): rows are visited in a
    /// fixed table order and in file order within a table, the first occurrence of a key wins,
    /// and an identifier that has to be invented is derived from the row's natural key rather
    /// than drawn at random — so analysing twice gives the same plan and the same hash.
    ///
    /// <b>Reset</b> empties every table and runs the same seed a new database gets
    /// (<see cref="ArkExtn.SeedDatabase"/>), in one transaction, after first checking the seed can
    /// run — a reset that emptied the tables and then could not seed would leave a server nobody
    /// can sign in to.
    /// </summary>
    public class ArkDataTools
    {
        public const string Format = "ark-idp-export";
        public const int FormatVersion = 1;
        /// <summary>Hard ceiling on an import body; the configured limit is checked under it.</summary>
        public const long MaxImportBytesCeiling = 1024L * 1024 * 1024;
        /// <summary>Most rows listed per mode; counts are always complete.</summary>
        public const int RecordListLimit = 1000;

        public const string ModeReplace = "replace";
        public const string ModeMergeSkip = "merge_skip";
        public const string ModeMergeOverwrite = "merge_overwrite";
        public static readonly string[] Modes = { ModeReplace, ModeMergeSkip, ModeMergeOverwrite };

        public const string Insert = "insert";
        public const string Update = "update";
        public const string Unchanged = "unchanged";
        public const string SkipExisting = "skip_existing";
        public const string Excluded = "excluded";
        public const string NotSelected = "not_selected";

        public static readonly string[] Categories = { "configuration", "grants", "transient", "history", "other" };

        /// <summary>
        /// Load order, and with it the order foreign keys need: a tenant before its clients and
        /// keys, a client and a user before the mapping between them, clients before the grants
        /// that name them. Deletes run in the reverse order. A table the model has that is not
        /// listed here goes last, in the "other" category.
        /// </summary>
        static readonly (string Table, string Category)[] KnownTables =
        {
            ("tenants", "configuration"),
            ("signing_keys", "configuration"),
            ("claims", "configuration"),
            ("scopes", "configuration"),
            ("clients", "configuration"),
            ("users", "configuration"),
            ("user_client_claims", "configuration"),
            ("service_accounts", "configuration"),
            ("consents", "grants"),
            ("sessions", "grants"),
            ("session_clients", "grants"),
            ("refresh_tokens", "grants"),
            ("auth_codes", "transient"),
            ("device_codes", "transient"),
            ("par_requests", "transient"),
            ("used_assertions", "transient"),
            ("pkce_code_flow", "transient"),
            ("auth_status", "history"),
            ("audit_trace", "history"),
        };

        /// <summary>Configuration sections written to the export's settings block.</summary>
        static readonly string[] SettingSections = { "ark_oauth_server", "ark_oauth_client", "ConnectionStrings" };
        const string Redacted = "<<redacted>>";
        /// <summary>
        /// Setting names that hold a secret, matched on how the name ends — "UserPasswordMode" and
        /// "RequireRegistrationAccessToken" are switches, not secrets. A value that is a plain
        /// true/false or number is never treated as one either (see <see cref="IsSecret"/>).
        /// </summary>
        static readonly Regex SecretKey = new(@"(password|passwd|secret|token|apikey|api_key|privatekey|private_key|pw|connectionstring)$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        static bool IsSecret(string key, string? value, bool allSecret) =>
            !string.IsNullOrEmpty(value)
            && !bool.TryParse(value, out _)
            && !double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out _)
            && (allSecret || SecretKey.IsMatch(key));

        const int KdfIterations = 210_000;
        static readonly byte[] AssociatedData = Encoding.UTF8.GetBytes($"{Format}/{FormatVersion}");

        static readonly JsonSerializerOptions FileJson = new()
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

        readonly ArkDataContext _ctx;
        readonly DataAccess _da;
        readonly ArkUtil _util;
        readonly IConfiguration _config;
        readonly IServiceProvider _services;

        public ArkDataTools(ArkDataContext ctx, DataAccess da, ArkUtil util, IConfiguration config, IServiceProvider services)
        {
            _ctx = ctx;
            _da = da;
            _util = util;
            _config = config;
            _services = services;
        }

        ArkAuthServerConfig Ser => _util.ServerConfig;
        ArkDataToolsConfig Cfg => Ser.Admin?.DataTools ?? new ArkDataToolsConfig();
        string AdminUsername => string.IsNullOrWhiteSpace(Ser.AdminUser?.Username) ? "admin" : Ser.AdminUser.Username.Trim().ToLowerInvariant();

        // ================================================================== model

        internal sealed class TableMeta
        {
            public string Name = "";
            public string Category = "other";
            public Type Clr = default!;
            public List<IProperty> Columns = new();
            public Dictionary<string, IProperty> ByName = new(StringComparer.Ordinal);
            public IProperty[] Key = default!;
            /// <summary>The database (or EF) makes the key up: a surrogate, not an identity.</summary>
            public bool KeyGenerated;
            public bool KeyIsNumeric;
            /// <summary>What identifies the row across two databases.</summary>
            public IProperty[] Natural = default!;
            /// <summary>Unique indexes other than <see cref="Natural"/>.</summary>
            public List<IProperty[]> OtherUnique = new();
            public IProperty? ExpiresAt;
        }

        List<TableMeta>? _tables;

        internal List<TableMeta> Tables()
        {
            if (_tables != null) return _tables;
            var order = KnownTables.Select((t, i) => (t.Table, i)).ToDictionary(x => x.Table, x => x.i, StringComparer.OrdinalIgnoreCase);
            var list = new List<TableMeta>();
            foreach (var et in _ctx.Model.GetEntityTypes().Where(e => !e.IsOwned() && e.GetTableName() != null))
            {
                var name = et.GetTableName()!;
                var pk = et.FindPrimaryKey();
                if (pk == null) continue;
                var meta = new TableMeta
                {
                    Name = name,
                    Category = KnownTables.FirstOrDefault(k => string.Equals(k.Table, name, StringComparison.OrdinalIgnoreCase)).Category ?? "other",
                    Clr = et.ClrType,
                    Columns = et.GetProperties().Where(p => !p.IsShadowProperty()).OrderBy(p => p.Name, StringComparer.Ordinal).ToList(),
                    Key = pk.Properties.ToArray()
                };
                foreach (var c in meta.Columns) meta.ByName[c.Name] = c;
                meta.KeyGenerated = meta.Key.Length == 1 && meta.Key[0].ValueGenerated == ValueGenerated.OnAdd;
                meta.KeyIsNumeric = meta.Key.Length == 1 && (meta.Key[0].ClrType == typeof(int) || meta.Key[0].ClrType == typeof(long));
                var unique = et.GetIndexes().Where(i => i.IsUnique).Select(i => i.Properties.ToArray()).ToList();
                meta.Natural = meta.KeyGenerated && unique.Count > 0 ? unique[0] : meta.Key;
                meta.OtherUnique = unique.Where(u => !u.SequenceEqual(meta.Natural)).ToList();
                meta.ExpiresAt = meta.ByName.TryGetValue("expires_at", out var exp) &&
                                 (exp.ClrType == typeof(DateTime) || exp.ClrType == typeof(DateTime?)) ? exp : null;
                list.Add(meta);
            }
            _tables = list
                .OrderBy(t => order.TryGetValue(t.Name, out var i) ? i : int.MaxValue)
                .ThenBy(t => t.Name, StringComparer.Ordinal)
                .ToList();
            return _tables;
        }

        static object? Get(IProperty p, object entity) =>
            p.FieldInfo != null ? p.FieldInfo.GetValue(entity) : p.PropertyInfo?.GetValue(entity);

        static void Set(IProperty p, object entity, object? value)
        {
            if (p.FieldInfo != null) p.FieldInfo.SetValue(entity, value);
            else p.PropertyInfo?.SetValue(entity, value);
        }

        /// <summary>
        /// Every timestamp this server writes is <c>DateTime.UtcNow</c>, but SQLite and MySQL hand
        /// it back with no kind, and a file carries whatever the source provider produced.
        /// PostgreSQL's timestamptz accepts UTC only, so a value with no kind is taken for what it
        /// is — UTC — on the way out and on the way in.
        /// </summary>
        static object? AsUtc(object? v) => v is DateTime d
            ? d.Kind switch
            {
                DateTimeKind.Utc => d,
                DateTimeKind.Local => d.ToUniversalTime(),
                _ => DateTime.SpecifyKind(d, DateTimeKind.Utc)
            }
            : v;

        static string Text(object? v) => v switch
        {
            null => "",
            DateTime d => d.ToString("yyyy-MM-ddTHH:mm:ss.fffffff", CultureInfo.InvariantCulture),
            _ => Convert.ToString(v, CultureInfo.InvariantCulture) ?? ""
        };

        static string Canon(object? v) => v switch
        {
            null => "null",
            DateTime d => d.ToString("yyyy-MM-ddTHH:mm:ss.fffffff", CultureInfo.InvariantCulture),
            _ => JsonSerializer.Serialize(v, v.GetType())
        };

        static string KeyText(IEnumerable<IProperty> props, object entity) =>
            string.Join("/", props.Select(p => Text(Get(p, entity))));

        static bool SameAs(TableMeta t, object a, object b) =>
            t.Columns.All(c => Canon(Get(c, a)) == Canon(Get(c, b)));

        List<object> LoadAll(TableMeta t) =>
            (List<object>)GetType().GetMethod(nameof(LoadAllOf), BindingFlags.NonPublic | BindingFlags.Instance)!
                .MakeGenericMethod(t.Clr).Invoke(this, null)!;

        List<object> LoadAllOf<T>() where T : class => _ctx.Set<T>().AsNoTracking().AsEnumerable().Cast<object>().ToList();

        int DeleteAll(TableMeta t) =>
            (int)GetType().GetMethod(nameof(DeleteAllOf), BindingFlags.NonPublic | BindingFlags.Instance)!
                .MakeGenericMethod(t.Clr).Invoke(this, null)!;

        int DeleteAllOf<T>() where T : class => _ctx.Set<T>().ExecuteDelete();

        int Count(TableMeta t) =>
            (int)GetType().GetMethod(nameof(CountOf), BindingFlags.NonPublic | BindingFlags.Instance)!
                .MakeGenericMethod(t.Clr).Invoke(this, null)!;

        int CountOf<T>() where T : class => _ctx.Set<T>().Count();

        public Dictionary<string, int> Counts() => Tables().ToDictionary(t => t.Name, Count);

        /// <summary>Which tables are in which category, for the screen and the docs.</summary>
        public Dictionary<string, List<string>> TableCategories() =>
            Categories.ToDictionary(c => c, c => Tables().Where(t => t.Category == c).Select(t => t.Name).ToList());

        // ================================================================== export

        public (byte[] Content, string FileName) Export(ArkExportRequest? req, string? exportedBy)
        {
            req ??= new ArkExportRequest();
            var data = new JsonObject();
            var counts = new JsonObject();
            foreach (var t in Tables())
            {
                var rows = LoadAll(t).OrderBy(r => KeyText(t.Key, r), StringComparer.Ordinal).ToList();
                var array = new JsonArray();
                foreach (var row in rows)
                {
                    var obj = new JsonObject();
                    foreach (var c in t.Columns)
                        obj[c.Name] = JsonSerializer.SerializeToNode(AsUtc(Get(c, row)), c.ClrType);
                    array.Add(obj);
                }
                data[t.Name] = array;
                counts[t.Name] = rows.Count;
            }

            var settings = SettingsSnapshot(req.include_setting_secrets);
            var body = new JsonObject { ["settings"] = settings, ["data"] = data };
            // Through text and back, so the checksum is taken over exactly what an importer will
            // parse — see Canonical.
            var canonical = Canonical(JsonNode.Parse(body.ToJsonString())!);
            var encrypted = !string.IsNullOrEmpty(req.passphrase);

            var manifest = new JsonObject
            {
                ["exported_at"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture),
                ["exported_by"] = exportedBy ?? "",
                ["package_version"] = PackageVersion,
                ["provider"] = string.IsNullOrWhiteSpace(Ser.Provider) ? "sqlite" : Ser.Provider.ToLowerInvariant(),
                ["operator_tenant"] = Ser.TenantId,
                ["base_url"] = Protocol.ArkOidcEndpoints.PublicRoot(Ser),
                ["admin_user"] = AdminUsername,
                ["encrypted"] = encrypted,
                ["settings_secrets_redacted"] = !req.include_setting_secrets,
                ["checksum"] = "sha256:" + Sha256Hex(canonical),
                ["counts"] = counts
            };
            var file = new JsonObject
            {
                ["format"] = Format,
                ["format_version"] = FormatVersion,
                ["manifest"] = manifest
            };
            if (encrypted)
            {
                file["payload"] = Encrypt(canonical, req.passphrase!);
            }
            else
            {
                file["settings"] = settings.DeepClone();
                file["data"] = data.DeepClone();
            }

            var bytes = Encoding.UTF8.GetBytes(file.ToJsonString(FileJson));
            var name = $"ark-idp-{ProvisionSafe(Ser.TenantId)}-{DateTime.UtcNow:yyyyMMdd-HHmmss}{(encrypted ? ".encrypted" : "")}.json";
            return (bytes, name);
        }

        static string ProvisionSafe(string? value) => Regex.Replace(value ?? "idp", @"[^A-Za-z0-9._-]+", "_");

        internal static string PackageVersion
        {
            get
            {
                var assembly = typeof(ArkDataTools).Assembly;
                var v = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                        ?? assembly.GetName().Version?.ToString() ?? "";
                var plus = v.IndexOf('+');
                return plus < 0 ? v : v.Substring(0, plus);
            }
        }

        JsonObject SettingsSnapshot(bool includeSecrets)
        {
            var root = new JsonObject();
            foreach (var name in SettingSections)
            {
                var section = _config.GetSection(name);
                if (!section.Exists()) continue;
                root[name] = SectionToNode(section, includeSecrets, name == "ConnectionStrings");
            }
            return root;
        }

        static JsonNode? SectionToNode(IConfigurationSection section, bool includeSecrets, bool allSecret)
        {
            var children = section.GetChildren().ToList();
            if (children.Count == 0)
            {
                var value = section.Value;
                if (value == null) return null;
                if (!includeSecrets && IsSecret(section.Key, value, allSecret))
                    return JsonValue.Create(Redacted);
                return JsonValue.Create(value);
            }
            // Configuration has no arrays, only keys "0", "1", … — put them back as one.
            var indexes = children.Select(c => int.TryParse(c.Key, NumberStyles.None, CultureInfo.InvariantCulture, out var i) ? i : -1).ToList();
            if (indexes.All(i => i >= 0) && indexes.OrderBy(i => i).SequenceEqual(Enumerable.Range(0, indexes.Count)))
            {
                var array = new JsonArray();
                foreach (var child in children.OrderBy(c => int.Parse(c.Key, CultureInfo.InvariantCulture)))
                    array.Add(SectionToNode(child, includeSecrets, allSecret));
                return array;
            }
            var obj = new JsonObject();
            foreach (var child in children.OrderBy(c => c.Key, StringComparer.Ordinal))
                obj[child.Key] = SectionToNode(child, includeSecrets, allSecret);
            return obj;
        }

        // ================================================================== canonical form + crypto

        /// <summary>
        /// The text a checksum is taken over: object keys sorted, no whitespace, strings and
        /// numbers re-emitted from their parsed values. Independent of indentation and key order,
        /// so a file that was only re-formatted still verifies, and one whose values were edited
        /// does not.
        /// </summary>
        static string Canonical(JsonNode node)
        {
            using var stream = new MemoryStream();
            using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
                WriteCanonical(writer, node);
            return Encoding.UTF8.GetString(stream.ToArray());
        }

        static void WriteCanonical(Utf8JsonWriter w, JsonNode? node)
        {
            switch (node)
            {
                case null:
                    w.WriteNullValue();
                    break;
                case JsonObject o:
                    w.WriteStartObject();
                    foreach (var kv in o.OrderBy(k => k.Key, StringComparer.Ordinal))
                    {
                        w.WritePropertyName(kv.Key);
                        WriteCanonical(w, kv.Value);
                    }
                    w.WriteEndObject();
                    break;
                case JsonArray a:
                    w.WriteStartArray();
                    foreach (var item in a) WriteCanonical(w, item);
                    w.WriteEndArray();
                    break;
                case JsonValue v:
                    var el = v.GetValue<JsonElement>();
                    switch (el.ValueKind)
                    {
                        case JsonValueKind.String: w.WriteStringValue(el.GetString()); break;
                        case JsonValueKind.Number: w.WriteRawValue(el.GetRawText(), skipInputValidation: true); break;
                        case JsonValueKind.True: w.WriteBooleanValue(true); break;
                        case JsonValueKind.False: w.WriteBooleanValue(false); break;
                        default: w.WriteNullValue(); break;
                    }
                    break;
            }
        }

        static string Sha256Hex(string text) =>
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();

        static JsonObject Encrypt(string plaintext, string passphrase)
        {
            var salt = RandomNumberGenerator.GetBytes(16);
            var nonce = RandomNumberGenerator.GetBytes(12);
            var key = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(passphrase), salt, KdfIterations, HashAlgorithmName.SHA256, 32);
            var pt = Encoding.UTF8.GetBytes(plaintext);
            var ct = new byte[pt.Length];
            var tag = new byte[16];
            using (var aes = new AesGcm(key, 16))
                aes.Encrypt(nonce, pt, ct, tag, AssociatedData);
            return new JsonObject
            {
                ["alg"] = "A256GCM",
                ["kdf"] = "PBKDF2-SHA256",
                ["iterations"] = KdfIterations,
                ["salt"] = Convert.ToBase64String(salt),
                ["nonce"] = Convert.ToBase64String(nonce),
                ["tag"] = Convert.ToBase64String(tag),
                ["ciphertext"] = Convert.ToBase64String(ct)
            };
        }

        static string Decrypt(JsonElement payload, string passphrase)
        {
            var iterations = payload.TryGetProperty("iterations", out var it) && it.TryGetInt32(out var n) ? n : KdfIterations;
            // A hostile file could otherwise name a work factor that ties the server up for minutes.
            if (iterations < 10_000 || iterations > 5_000_000) throw new CryptographicException("unsupported iteration count");
            var salt = Convert.FromBase64String(payload.GetProperty("salt").GetString() ?? "");
            var nonce = Convert.FromBase64String(payload.GetProperty("nonce").GetString() ?? "");
            var tag = Convert.FromBase64String(payload.GetProperty("tag").GetString() ?? "");
            var ct = Convert.FromBase64String(payload.GetProperty("ciphertext").GetString() ?? "");
            var key = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(passphrase), salt, iterations, HashAlgorithmName.SHA256, 32);
            var pt = new byte[ct.Length];
            using (var aes = new AesGcm(key, 16))
                aes.Decrypt(nonce, ct, tag, pt, AssociatedData);
            return Encoding.UTF8.GetString(pt);
        }

        // ================================================================== reading a file

        internal sealed class ParsedFile
        {
            public ArkExportFileInfo Info = new();
            public List<ArkDataIssue> Blockers = new();
            public List<ArkDataIssue> Warnings = new();
            public JsonObject? Settings;
            public JsonObject? Data;
            public string Checksum = "";
        }

        ParsedFile Parse(ArkImportRequest req)
        {
            var pf = new ParsedFile();
            var file = req.file;
            if (file.ValueKind != JsonValueKind.Object)
            {
                pf.Blockers.Add(new("invalid_format", "the upload is not a JSON object, so it is not an Ark export file."));
                return pf;
            }

            pf.Info.format = Str(file, "format");
            pf.Info.format_version = file.TryGetProperty("format_version", out var fv) && fv.TryGetInt32(out var v) ? v : 0;
            if (pf.Info.format != Format)
            {
                pf.Blockers.Add(new("invalid_format", $"the file's format is '{pf.Info.format ?? "(none)"}', not '{Format}' - it was not produced by this server's export."));
                return pf;
            }
            if (pf.Info.format_version < 1 || pf.Info.format_version > FormatVersion)
            {
                pf.Blockers.Add(new("unsupported_version",
                    $"the file is export format {pf.Info.format_version}; this server ({PackageVersion}) reads format {FormatVersion} and earlier. Upgrade this server before importing it."));
                return pf;
            }

            string? checksum = null;
            if (file.TryGetProperty("manifest", out var m) && m.ValueKind == JsonValueKind.Object)
            {
                pf.Info.exported_at = Str(m, "exported_at");
                pf.Info.exported_by = Str(m, "exported_by");
                pf.Info.package_version = Str(m, "package_version");
                pf.Info.provider = Str(m, "provider");
                pf.Info.operator_tenant = Str(m, "operator_tenant");
                pf.Info.base_url = Str(m, "base_url");
                pf.Info.settings_secrets_redacted = m.TryGetProperty("settings_secrets_redacted", out var r) && r.ValueKind == JsonValueKind.True;
                checksum = Str(m, "checksum");
            }

            JsonNode? body;
            if (file.TryGetProperty("payload", out var payload) && payload.ValueKind == JsonValueKind.Object)
            {
                pf.Info.encrypted = true;
                if (string.IsNullOrEmpty(req.passphrase))
                {
                    pf.Blockers.Add(new("passphrase_required", "the file is encrypted - enter the passphrase it was exported with."));
                    return pf;
                }
                try
                {
                    body = JsonNode.Parse(Decrypt(payload, req.passphrase!));
                }
                catch (Exception ex) when (ex is CryptographicException or FormatException or KeyNotFoundException or InvalidOperationException or JsonException)
                {
                    pf.Blockers.Add(new("passphrase_invalid", "the file could not be decrypted with that passphrase, or its encrypted payload is damaged."));
                    return pf;
                }
            }
            else
            {
                body = new JsonObject
                {
                    ["settings"] = file.TryGetProperty("settings", out var s) ? JsonNode.Parse(s.GetRawText()) : null,
                    ["data"] = file.TryGetProperty("data", out var d) ? JsonNode.Parse(d.GetRawText()) : null
                };
            }

            pf.Settings = body?["settings"] as JsonObject;
            pf.Data = body?["data"] as JsonObject;
            if (pf.Data == null)
            {
                pf.Blockers.Add(new("invalid_format", "the file has no data section."));
                return pf;
            }

            pf.Checksum = "sha256:" + Sha256Hex(Canonical(body!));
            if (string.IsNullOrEmpty(checksum))
            {
                pf.Info.checksum_ok = null;
                pf.Warnings.Add(new("checksum_missing", "the file carries no checksum, so it cannot be shown to be unmodified."));
            }
            else if (!string.Equals(checksum, pf.Checksum, StringComparison.OrdinalIgnoreCase))
            {
                pf.Info.checksum_ok = false;
                if (req.allow_modified)
                    pf.Warnings.Add(new("checksum_mismatch", "the file was changed after it was exported; it is being imported anyway because allow_modified is set."));
                else
                    pf.Blockers.Add(new("checksum_mismatch",
                        "the file's content no longer matches the checksum written when it was exported - it was edited or damaged. Re-export it, or set allow_modified to import an edited file deliberately."));
            }
            else pf.Info.checksum_ok = true;

            foreach (var kv in pf.Data)
                pf.Info.counts[kv.Key] = (kv.Value as JsonArray)?.Count ?? 0;

            var known = Tables().Select(t => t.Name).ToHashSet(StringComparer.Ordinal);
            foreach (var name in pf.Data.Select(kv => kv.Key).Where(n => !known.Contains(n)))
                pf.Warnings.Add(new("unknown_table", $"table '{name}' is in the file but not in this server's model; its rows are ignored."));
            foreach (var t in Tables().Where(t => !pf.Data.ContainsKey(t.Name)))
                pf.Warnings.Add(new("table_absent", $"table '{t.Name}' is not in the file (an export from an older release); it is treated as empty."));

            if (CompareVersions(pf.Info.package_version, PackageVersion) > 0)
                pf.Warnings.Add(new("newer_source", $"the file was exported by {pf.Info.package_version}, which is newer than this server ({PackageVersion}); columns this server does not know are ignored."));
            var here = Protocol.ArkOidcEndpoints.PublicRoot(Ser);
            if (!string.IsNullOrWhiteSpace(pf.Info.base_url) && !string.IsNullOrWhiteSpace(here) &&
                !string.Equals(pf.Info.base_url!.TrimEnd('/'), here.TrimEnd('/'), StringComparison.OrdinalIgnoreCase))
                pf.Warnings.Add(new("base_url_differs",
                    $"the file comes from {pf.Info.base_url}, this server is {here}. Issuer URLs change with the host, so every client has to point its authority at this server; the admin console client's callbacks are re-added for this host automatically."));
            return pf;
        }

        static string? Str(JsonElement e, string name) =>
            e.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null;

        static int CompareVersions(string? a, string? b)
        {
            if (!Version.TryParse((a ?? "").Split('-')[0], out var va)) return 0;
            if (!Version.TryParse((b ?? "").Split('-')[0], out var vb)) return 0;
            return va.CompareTo(vb);
        }

        // ================================================================== planning

        internal sealed class Row
        {
            public TableMeta T = default!;
            public int Index;
            public object? Entity;
            /// <summary>A generated key as the file had it, before any remapping.</summary>
            public string? OriginalId;
            public string Key = "";
            public string Action = "";
            public string? Reason;
            public string? Detail;
            public List<string> Adjustments = new();
        }

        internal sealed class Plan
        {
            public string Mode = "";
            public List<Row> Rows = new();
            public List<ArkDataIssue> Blockers = new();
            public List<ArkDataIssue> Warnings = new();
            public Dictionary<string, int> Deletes = new();
            public string Hash = "";
        }

        static bool Accepted(string action) => action is Insert or Update or Unchanged or SkipExisting;

        /// <summary>Lower-cased key for every lookup: the server compares identifiers case-insensitively.</summary>
        static string L(string? s) => (s ?? "").Trim().ToLowerInvariant();

        static string DeterministicId(string table, string naturalKey)
        {
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes($"{table}\n{naturalKey}"));
            return new Guid(hash.AsSpan(0, 16)).ToString();
        }

        /// <summary>
        /// Works one mode out in full. Pure: reads <paramref name="target"/> and the file, writes
        /// nothing. Every rule below that excludes, skips or adjusts a row is listed, with its
        /// code, in API-GUIDE.md under "Import rules".
        /// </summary>
        Plan BuildPlan(string mode, ParsedFile pf, Dictionary<string, List<object>> target, HashSet<string> include)
        {
            var plan = new Plan { Mode = mode };
            var replace = mode == ModeReplace;
            var now = DateTime.UtcNow;
            var opTenant = Ser.TenantId ?? "";
            var consoleClient = $"{opTenant}_client";
            var machineClient = $"{opTenant}_machine";
            var tables = Tables();

            List<object> Existing(string table) =>
                replace || !target.TryGetValue(table, out var rows) ? new List<object>() : rows;

            if (replace)
                foreach (var t in tables) plan.Deletes[t.Name] = target.TryGetValue(t.Name, out var rows) ? rows.Count : 0;

            // ---- what is available to point at: this server's rows (merge), then accepted file rows
            // lower-cased -> exact. Lookups are case-insensitive so a near miss can be named, but a
            // reference has to match exactly: the foreign keys behind it compare bytes.
            var tenants = Existing("tenants").Cast<ArkTenant>().ToDictionary(t => L(t.tenant_id), t => t.tenant_id);
            var excludedTenants = new HashSet<string>();
            var clientsNatural = Existing("clients").Cast<ArkClient>().ToDictionary(c => L($"{c.tenant_id}/{c.client_id}"), c => $"{c.tenant_id}/{c.client_id}");
            var clientTenantById = Existing("clients").Cast<ArkClient>().ToDictionary(c => L(c.id), c => c.tenant_id ?? "");
            var fileClientIds = new Dictionary<string, string?>();   // file surrogate id -> final id, null = excluded
            var excludedClientsNatural = new HashSet<string>();
            var clientNames = new Dictionary<string, string>();        // tenant/name -> owning tenant/client_id
            foreach (var c in Existing("clients").Cast<ArkClient>())
                clientNames[L($"{c.tenant_id}/{ClientLabel(c)}")] = L($"{c.tenant_id}/{c.client_id}");
            var users = new HashSet<string>(Existing("users").Cast<ArkUser>().Select(u => L(u.email)));
            var excludedUsers = new HashSet<string>();
            var claims = new HashSet<string>(Existing("claims").Cast<ArkClaim>().Select(c => L(c.key)));
            var activeKeyTenants = new HashSet<string>(Existing("signing_keys").Cast<ArkSigningKey>()
                .Where(k => k.status == "active").Select(k => L(k.tenant_id)));

            foreach (var t in tables)
            {
                var existing = Existing(t.Name);
                var byNatural = new Dictionary<string, object>();
                var byKey = new Dictionary<string, object>();
                foreach (var e in existing)
                {
                    byNatural.TryAdd(L(KeyText(t.Natural, e)), e);
                    byKey.TryAdd(L(KeyText(t.Key, e)), e);
                }
                var byUnique = t.OtherUnique.Select(u =>
                {
                    var set = new Dictionary<string, object>();
                    foreach (var e in existing) set.TryAdd(L(KeyText(u, e)), e);
                    return (Props: u, Index: set);
                }).ToList();

                var seen = new HashSet<string>();
                var array = pf.Data![t.Name] as JsonArray ?? new JsonArray();

                for (var i = 0; i < array.Count; i++)
                {
                    var row = new Row { T = t, Index = i };
                    plan.Rows.Add(row);

                    void Exclude(string reason, string detail)
                    {
                        row.Action = Excluded;
                        row.Reason = reason;
                        row.Detail = detail;
                        if (t.Name == "tenants" && row.Entity is ArkTenant xt) excludedTenants.Add(L(xt.tenant_id));
                        if (t.Name == "users" && row.Entity is ArkUser xu) excludedUsers.Add(L(xu.email));
                        if (t.Name == "clients" && row.Entity is ArkClient xc)
                        {
                            if (!string.IsNullOrEmpty(row.OriginalId)) fileClientIds[L(row.OriginalId)] = null;
                            excludedClientsNatural.Add(L($"{xc.tenant_id}/{xc.client_id}"));
                        }
                    }

                    if (array[i] is not JsonObject obj)
                    {
                        row.Key = $"#{i}";
                        Exclude("invalid_record", "the row is not a JSON object.");
                        continue;
                    }
                    var (entity, error) = Materialise(t, obj);
                    if (entity == null)
                    {
                        row.Key = $"#{i}";
                        Exclude("invalid_value", error ?? "the row could not be read.");
                        continue;
                    }
                    row.Entity = entity;
                    row.Key = KeyText(t.Natural, entity);
                    if (t.KeyGenerated) row.OriginalId = Text(Get(t.Key[0], entity));

                    if (!include.Contains(t.Category))
                    {
                        row.Action = NotSelected;
                        continue;
                    }

                    // ---- normalise, and resolve what the row points at
                    // Why a tenant reference cannot be followed, or null when it can.
                    (string Code, string Detail)? Missing(string? tenantId)
                    {
                        if (tenants.TryGetValue(L(tenantId), out var exact))
                            return exact == tenantId ? null
                                : ("case_conflict", $"refers to tenant '{tenantId}', but the tenant is '{exact}'; the reference has to match exactly.");
                        return excludedTenants.Contains(L(tenantId))
                            ? ("parent_excluded", $"tenant '{tenantId}' is excluded from this import.")
                            : ("missing_tenant", $"tenant '{tenantId}' is neither in the file nor on this server.");
                    }

                    switch (entity)
                    {
                        case ArkUser u:
                        {
                            var lower = (u.email ?? "").Trim().ToLowerInvariant();
                            if (lower != u.email) { row.Adjustments.Add($"email lower-cased: '{u.email}' -> '{lower}'"); u.email = lower; }
                            break;
                        }
                        case ArkClient c:
                        {
                            if (Missing(c.tenant_id) is { } why) { Exclude(why.Code, why.Detail); continue; }
                            break;
                        }
                        case ArkSigningKey k:
                        {
                            if (Missing(k.tenant_id) is { } why) { Exclude(why.Code, why.Detail); continue; }
                            break;
                        }
                        case ArkUserClientClaim m:
                        {
                            var lower = (m.email ?? "").Trim().ToLowerInvariant();
                            if (lower != m.email) { row.Adjustments.Add($"email lower-cased: '{m.email}' -> '{lower}'"); m.email = lower; }
                            if (!users.Contains(lower))
                            {
                                Exclude(excludedUsers.Contains(lower) ? "parent_excluded" : "missing_user",
                                    $"user '{lower}' is {(excludedUsers.Contains(lower) ? "excluded from this import" : "neither in the file nor on this server")}.");
                                continue;
                            }
                            if (Missing(m.tenant_id) is { } why) { Exclude(why.Code, why.Detail); continue; }
                            // The mapping names the client by its surrogate id, which differs between
                            // two databases holding the same client — so it is followed through the
                            // file's client rows to wherever that client ended up.
                            var original = m.client_id ?? "";
                            string? finalId;
                            if (fileClientIds.TryGetValue(L(original), out var mapped))
                            {
                                if (mapped == null) { Exclude("parent_excluded", $"the client this mapping points at ({original}) is excluded from this import."); continue; }
                                finalId = mapped;
                            }
                            else if (clientTenantById.ContainsKey(L(original))) finalId = original;
                            else { Exclude("missing_client", $"no client with id '{original}' is in the file or on this server."); continue; }
                            if (!string.Equals(finalId, original, StringComparison.Ordinal))
                            {
                                row.Adjustments.Add($"client reference remapped: {original} -> {finalId} (the same client's id on this server)");
                                m.client_id = finalId!;
                            }
                            if (!string.Equals(clientTenantById[L(finalId)], m.tenant_id, StringComparison.Ordinal))
                            {
                                Exclude("tenant_mismatch", $"the mapping says tenant '{m.tenant_id}' but its client belongs to tenant '{clientTenantById[L(finalId)]}'.");
                                continue;
                            }
                            break;
                        }
                        default:
                        {
                            // Grants name their client by tenant + client_id, not by surrogate.
                            var tenantProp = t.ByName.GetValueOrDefault("tenant_id");
                            var clientProp = t.ByName.GetValueOrDefault("client_id");
                            if (t.Category is "grants" or "transient" && tenantProp != null)
                            {
                                var tid = Text(Get(tenantProp, entity));
                                if (Missing(tid) is { } why) { Exclude(why.Code, why.Detail); continue; }
                                if (clientProp != null)
                                {
                                    var cid = Text(Get(clientProp, entity));
                                    var nk = L($"{tid}/{cid}");
                                    if (clientsNatural.TryGetValue(nk, out var exactClient))
                                    {
                                        if (exactClient != $"{tid}/{cid}")
                                        {
                                            Exclude("case_conflict", $"refers to client '{tid}/{cid}', but the client is '{exactClient}'; the reference has to match exactly.");
                                            continue;
                                        }
                                    }
                                    else
                                    {
                                        Exclude(excludedClientsNatural.Contains(nk) ? "parent_excluded" : "missing_client",
                                            $"client '{cid}' in tenant '{tid}' is {(excludedClientsNatural.Contains(nk) ? "excluded from this import" : "neither in the file nor on this server")}.");
                                        continue;
                                    }
                                }
                            }
                            break;
                        }
                    }

                    // ---- every NOT NULL column has a value (a generated key is filled in below)
                    var missingCols = t.Columns
                        .Where(c => !c.IsNullable && Get(c, entity) == null && !(t.KeyGenerated && t.Key.Contains(c)))
                        .Select(c => c.Name).ToList();
                    if (missingCols.Count > 0)
                    {
                        Exclude("missing_required", $"required column(s) empty: {string.Join(", ", missingCols)}.");
                        continue;
                    }

                    row.Key = KeyText(t.Natural, entity);
                    var natural = L(row.Key);
                    if (!seen.Add(natural))
                    {
                        Exclude("duplicate_in_file", $"an earlier row in the file has the same {string.Join(" + ", t.Natural.Select(p => p.Name))}; the first one is used.");
                        continue;
                    }

                    // ---- rules about the row's own values
                    if (t.ExpiresAt != null && t.Category is "grants" or "transient" &&
                        Get(t.ExpiresAt, entity) is DateTime expires && expires < now)
                    {
                        Exclude("expired", $"expired at {expires:yyyy-MM-dd HH:mm:ss} UTC; loading it would only be cleaned up again.");
                        continue;
                    }
                    if (entity is ArkUser vu && !DataAccess.IsValidLoginId(vu.email))
                    {
                        Exclude("invalid_login_id", $"'{vu.email}' is neither an email address nor a 2-64 character username of letters, digits, dot, dash or underscore.");
                        continue;
                    }
                    if (entity is ArkClient vc)
                    {
                        var unsafeUri = vc.redirect_uris.Concat(vc.post_logout_redirect_uris)
                            .Append(vc.redirect_url).Append(vc.logout_url).Append(vc.client_uri)
                            .Append(vc.policy_uri).Append(vc.tos_uri).Append(vc.jwks_uri).Append(vc.backchannel_logout_uri)
                            .FirstOrDefault(u => !string.IsNullOrWhiteSpace(u) && Protocol.RedirectUriValidator.CarriesScript(u.Trim()));
                        if (unsafeUri != null)
                        {
                            Exclude("unsafe_uri", $"'{unsafeUri}' would run as script on this server's origin (javascript:, data:, file: or whitespace).");
                            continue;
                        }
                        var nameKey = L($"{vc.tenant_id}/{ClientLabel(vc)}");
                        if (clientNames.TryGetValue(nameKey, out var owner) && owner != natural)
                        {
                            Exclude("client_name_conflict", $"another client in tenant '{vc.tenant_id}' ({owner.Split('/').Last()}) already has the name '{ClientLabel(vc)}'; two applications with one name cannot be told apart.");
                            continue;
                        }
                    }
                    if (entity is ArkSigningKey vk && byKey.TryGetValue(L(vk.kid), out var ek) && ek is ArkSigningKey existingKey)
                    {
                        if (!string.Equals(existingKey.tenant_id, vk.tenant_id, StringComparison.OrdinalIgnoreCase))
                        {
                            Exclude("kid_conflict", $"key id '{vk.kid}' already belongs to tenant '{existingKey.tenant_id}' on this server.");
                            continue;
                        }
                        if (existingKey.public_key != vk.public_key || existingKey.private_key != vk.private_key)
                        {
                            Exclude("key_material_conflict", $"key id '{vk.kid}' exists here with different key material; replacing it would invalidate every token it has signed." +
                                (string.Equals(vk.kid, vk.tenant_id, StringComparison.OrdinalIgnoreCase)
                                    ? " Every server seeds its first key with kid = tenant id, so two servers sharing a TenantId always meet this; this server keeps its own key."
                                    : ""));
                            continue;
                        }
                    }

                    // ---- against this server
                    if (byNatural.TryGetValue(natural, out var match))
                    {
                        var matchKey = KeyText(t.Natural, match);
                        if (!string.Equals(matchKey, row.Key, StringComparison.Ordinal))
                        {
                            Exclude("case_conflict", $"'{row.Key}' differs only in letter case from '{matchKey}' on this server; the two cannot be merged safely.");
                            continue;
                        }
                        if (t.KeyGenerated)
                        {
                            // The same record under this server's surrogate id. Not reported as an
                            // adjustment: the stored row keeps the id it has.
                            var ours = Get(t.Key[0], match);
                            Remember(row, Text(ours));
                            Set(t.Key[0], entity, ours);
                        }

                        if (SameAs(t, entity, match))
                        {
                            row.Action = Unchanged;
                        }
                        else if (mode == ModeMergeOverwrite && IsOperatorRecord(entity, opTenant, consoleClient, machineClient))
                        {
                            row.Action = SkipExisting;
                            row.Reason = "protected_operator_record";
                            row.Detail = "the operator tenant, the admin console and machine clients, the administrator account and the default service account are never overwritten by a merge - doing so could lock the console out. Use replace to load them from the file.";
                        }
                        else if (entity is ArkSigningKey)
                        {
                            row.Action = SkipExisting;
                            row.Reason = "key_state_owned_by_target";
                            row.Detail = "the same key is already here; its status (active / rollover / retired) is this server's rotation state and is left as it is.";
                        }
                        else if (mode == ModeMergeSkip)
                        {
                            row.Action = SkipExisting;
                            row.Reason = "exists";
                            row.Detail = "already on this server with different values; merge_skip keeps this server's version.";
                        }
                        else row.Action = Update;
                    }
                    else
                    {
                        if (t.KeyGenerated)
                        {
                            if (t.KeyIsNumeric)
                            {
                                // An int identity is left for the database to number: an explicit
                                // value would put PostgreSQL's sequence behind the table.
                                Set(t.Key[0], entity, Convert.ChangeType(0, t.Key[0].ClrType, CultureInfo.InvariantCulture));
                            }
                            else
                            {
                                var current = Text(Get(t.Key[0], entity));
                                if (string.IsNullOrEmpty(current) || byKey.ContainsKey(L(current)))
                                {
                                    var fresh = DeterministicId(t.Name, natural);
                                    if (byKey.ContainsKey(L(fresh)))
                                    {
                                        Exclude("id_conflict", $"no free id could be derived for this row.");
                                        continue;
                                    }
                                    row.Adjustments.Add(string.IsNullOrEmpty(current)
                                        ? $"{t.Key[0].Name} assigned: {fresh}"
                                        : $"{t.Key[0].Name} {current} is a different record on this server; regenerated as {fresh}");
                                    Remember(row, fresh);
                                    Set(t.Key[0], entity, fresh);
                                }
                                else Remember(row, current);
                            }
                        }
                        var clash = byUnique.FirstOrDefault(u => u.Index.ContainsKey(L(KeyText(u.Props, entity))));
                        if (clash.Props != null)
                        {
                            Exclude("unique_conflict", $"{string.Join(" + ", clash.Props.Select(p => p.Name))} '{KeyText(clash.Props, entity)}' is already used by a different record on this server.");
                            continue;
                        }
                        if (!replace && entity is ArkSigningKey nk && nk.status == "active" && activeKeyTenants.Contains(L(nk.tenant_id)))
                        {
                            nk.status = "rollover";
                            row.Adjustments.Add("status active -> rollover: the tenant already signs with its own key here; this one is published in JWKS so tokens it signed still verify");
                        }
                        row.Action = Insert;
                    }

                    // ---- now available to rows that point at it
                    switch (entity)
                    {
                        case ArkTenant at: tenants[L(at.tenant_id)] = at.tenant_id; break;
                        case ArkUser au: users.Add(L(au.email)); break;
                        case ArkClaim ac: claims.Add(L(ac.key)); break;
                        case ArkClient cc:
                            clientsNatural[natural] = row.Key;
                            clientTenantById[L(cc.id)] = cc.tenant_id;
                            clientNames[L($"{cc.tenant_id}/{ClientLabel(cc)}")] = natural;
                            break;
                    }
                }

                // A mapping may name a claim the catalogue lacks; the console's palette is built
                // from the catalogue, so it is added rather than left invisible.
                if (t.Name == "user_client_claims")
                {
                    var claimsMeta = tables.FirstOrDefault(x => x.Name == "claims");
                    if (claimsMeta == null) continue;
                    var needed = plan.Rows
                        .Where(r => r.T == t && Accepted(r.Action) && r.Entity is ArkUserClientClaim)
                        .SelectMany(r => ((ArkUserClientClaim)r.Entity!).claims)
                        .Where(k => !string.IsNullOrWhiteSpace(k))
                        .Select(k => k.Trim())
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .Where(k => !claims.Contains(L(k)))
                        .OrderBy(k => k, StringComparer.Ordinal)
                        .ToList();
                    foreach (var key in needed)
                    {
                        claims.Add(L(key));
                        plan.Rows.Add(new Row
                        {
                            T = claimsMeta,
                            Index = -1,
                            Entity = new ArkClaim { key = key, display = key },
                            Key = key,
                            Action = Insert,
                            Reason = "claim_added",
                            Adjustments = { "added to the claim catalogue: a mapping in the file uses it and neither the file nor this server defines it" }
                        });
                    }
                }
            }

            // ---- replace must leave someone able to sign in to the console
            if (replace)
            {
                if (!Cfg.AllowReplace)
                    plan.Blockers.Add(new("replace_disabled", "replace is switched off by ark_oauth_server:Admin:DataTools:AllowReplace."));

                var acceptedTenant = plan.Rows.Any(r => r.Entity is ArkTenant at && Accepted(r.Action) && at.tenant_id == opTenant);
                var console = plan.Rows.Where(r => r.Entity is ArkClient ac && Accepted(r.Action) &&
                        ac.tenant_id == opTenant && string.Equals(ac.client_id, consoleClient, StringComparison.OrdinalIgnoreCase))
                    .Select(r => (ArkClient)r.Entity!).FirstOrDefault();
                var admin = plan.Rows.Any(r => r.Entity is ArkUser au && Accepted(r.Action) && L(au.email) == AdminUsername);
                var mapped = console != null && plan.Rows.Any(r => r.Entity is ArkUserClientClaim um && Accepted(r.Action) &&
                    L(um.email) == AdminUsername && um.client_id == console.id);

                var missing = new List<string>();
                if (!acceptedTenant) missing.Add($"the operator tenant '{opTenant}' (ark_oauth_server:TenantId, compared exactly)");
                if (console == null) missing.Add($"its admin console client '{consoleClient}'");
                if (!admin) missing.Add($"the administrator account '{AdminUsername}' (ark_oauth_server:AdminUser:Username)");
                else if (console != null && !mapped) missing.Add($"an access mapping from '{AdminUsername}' to '{consoleClient}'");
                if (missing.Count > 0)
                    plan.Blockers.Add(new("operator_lockout",
                        "replace would leave nobody able to sign in to this console, because the file does not supply " +
                        string.Join(", ", missing) + ". Use a merge mode, or import a file exported from a server with the same TenantId and administrator."));
            }

            if (replace)
            {
                var ours = target.TryGetValue("signing_keys", out var keys) ? keys.Cast<ArkSigningKey>().ToList() : new List<ArkSigningKey>();
                var reused = plan.Rows
                    .Where(r => r.Action == Insert && r.Entity is ArkSigningKey)
                    .Select(r => (ArkSigningKey)r.Entity!)
                    .Where(k => ours.Any(o => o.kid == k.kid && o.public_key != k.public_key))
                    .Select(k => k.kid)
                    .ToList();
                if (reused.Count > 0)
                    plan.Warnings.Add(new("signing_key_kid_reused",
                        $"key id(s) {string.Join(", ", reused.Select(k => $"'{k}'"))} exist here with different key material and are replaced by the file's. " +
                        "Relying parties that cached this server's JWKS - this host's own console included - see a kid they already know, do not refetch, and reject " +
                        "signatures until their cache refreshes (about 5 minutes for ASP.NET Core clients) or they restart."));
            }

            if (mode == ModeMergeOverwrite)
            {
                var protectedCount = plan.Rows.Count(r => r.Reason == "protected_operator_record");
                if (protectedCount > 0)
                    plan.Warnings.Add(new("operator_records_kept", $"{protectedCount} operator record(s) differ in the file and are kept as they are here."));
            }

            plan.Hash = HashPlan(plan, pf, target, include,
                tables.Where(t => t.Category == "history").Select(t => t.Name).ToHashSet());
            return plan;

            // Where a file client's surrogate id ended up, for the mappings that name it.
            void Remember(Row r, string finalId)
            {
                if (r.Entity is ArkClient && !string.IsNullOrEmpty(r.OriginalId)) fileClientIds[L(r.OriginalId)] = finalId;
            }
        }

        static string ClientLabel(ArkClient c) =>
            new[] { c.client_name, c.display, c.name, c.client_id }.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v))?.Trim() ?? "";

        bool IsOperatorRecord(object entity, string opTenant, string consoleClient, string machineClient) => entity switch
        {
            ArkTenant t => string.Equals(t.tenant_id, opTenant, StringComparison.OrdinalIgnoreCase),
            ArkClient c => string.Equals(c.tenant_id, opTenant, StringComparison.OrdinalIgnoreCase) &&
                           (string.Equals(c.client_id, consoleClient, StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(c.client_id, machineClient, StringComparison.OrdinalIgnoreCase)),
            // The default service account's credential is a token signed by its own server's key,
            // so the file's would not verify here.
            ArkUser u => L(u.email) == AdminUsername || L(u.email) == L($"service_account_{opTenant}"),
            _ => false
        };

        (object? Entity, string? Error) Materialise(TableMeta t, JsonObject row)
        {
            var entity = Activator.CreateInstance(t.Clr)!;
            foreach (var kv in row)
            {
                if (!t.ByName.TryGetValue(kv.Key, out var p)) continue; // a newer release's column
                try
                {
                    var value = kv.Value == null ? null : JsonSerializer.Deserialize(kv.Value, p.ClrType);
                    if (value == null && p.ClrType.IsValueType && Nullable.GetUnderlyingType(p.ClrType) == null)
                        return (null, $"column '{kv.Key}' is null but must have a value.");
                    Set(p, entity, AsUtc(value));
                }
                catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException or NotSupportedException)
                {
                    return (null, $"column '{kv.Key}' holds a value of the wrong type ({ex.Message}).");
                }
            }
            return (entity, null);
        }

        /// <param name="unwatched">
        /// Tables left out of the row-count fingerprint: the history tables, which the server
        /// writes on its own — every sign-in, and the backup export the page takes just before an
        /// import. Counting them made that backup invalidate the plan it was protecting. A history
        /// row that would change a decision still changes the hash through the rows below.
        /// </param>
        static string HashPlan(Plan plan, ParsedFile pf, Dictionary<string, List<object>> target, HashSet<string> include, HashSet<string> unwatched)
        {
            var sb = new StringBuilder();
            sb.Append(plan.Mode).Append('\n').Append(pf.Checksum).Append('\n')
              .Append(string.Join(",", include.OrderBy(c => c, StringComparer.Ordinal))).Append('\n');
            foreach (var kv in target.Where(k => !unwatched.Contains(k.Key)).OrderBy(k => k.Key, StringComparer.Ordinal))
                sb.Append(kv.Key).Append('=').Append(kv.Value.Count).Append(';');
            sb.Append('\n');
            foreach (var r in plan.Rows)
                sb.Append(r.T.Name).Append('|').Append(r.Index).Append('|').Append(r.Key).Append('|')
                  .Append(r.Action).Append('|').Append(r.Reason).Append('|').Append(string.Join(";", r.Adjustments)).Append('\n');
            foreach (var b in plan.Blockers) sb.Append("!").Append(b.code).Append('\n');
            return Sha256Hex(sb.ToString());
        }

        static (Dictionary<string, int> Summary, Dictionary<string, Dictionary<string, int>> Tables, List<ArkImportRecord> Records, int Truncated)
            Describe(Plan plan)
        {
            var summary = new Dictionary<string, int>();
            var tables = new Dictionary<string, Dictionary<string, int>>();
            foreach (var r in plan.Rows)
            {
                summary[r.Action] = summary.GetValueOrDefault(r.Action) + 1;
                if (!tables.TryGetValue(r.T.Name, out var t)) tables[r.T.Name] = t = new Dictionary<string, int>();
                t[r.Action] = t.GetValueOrDefault(r.Action) + 1;
            }
            // Only rows that are written can have been adjusted; a note on a skipped or identical
            // row describes how it was matched, not a change.
            static bool Adjusted(Row r) => r.Adjustments.Count > 0 && r.Action is Insert or Update;
            summary["adjusted"] = plan.Rows.Count(Adjusted);

            var notable = plan.Rows
                .Where(r => r.Action is Excluded or Update or SkipExisting || Adjusted(r))
                .OrderBy(r => r.Action switch { Excluded => 0, SkipExisting => 1, Update => 2, _ => 3 })
                .ToList();
            var records = notable.Take(RecordListLimit).Select(r => new ArkImportRecord
            {
                table = r.T.Name,
                index = r.Index,
                key = r.Key,
                action = r.Action,
                reason = r.Reason,
                detail = r.Detail,
                adjustments = Adjusted(r) ? r.Adjustments : null
            }).ToList();
            return (summary, tables, records, Math.Max(0, notable.Count - RecordListLimit));
        }

        HashSet<string> IncludeSet(List<string>? include)
        {
            if (include == null || include.Count == 0) return Categories.ToHashSet();
            var set = include.Select(c => (c ?? "").Trim().ToLowerInvariant()).Where(c => c.Length > 0).ToHashSet();
            var unknown = set.Where(c => !Categories.Contains(c)).ToList();
            if (unknown.Count > 0)
                throw new ArkDataToolsException("invalid_request", $"unknown categor{(unknown.Count == 1 ? "y" : "ies")} {string.Join(", ", unknown)} - use {string.Join(", ", Categories)}.");
            // Nothing else can be loaded without the configuration it points at.
            set.Add("configuration");
            return set;
        }

        Dictionary<string, List<object>> LoadTarget() => Tables().ToDictionary(t => t.Name, LoadAll);

        /// <summary>Nothing here but the first-run seed: replacing it loses nothing anybody made.</summary>
        bool IsPristine(Dictionary<string, List<object>> target)
        {
            var op = Ser.TenantId ?? "";
            var seedClients = new[] { $"{op}_client", $"{op}_machine" };
            var seedUsers = new[] { AdminUsername, L($"service_account_{op}") };
            return target["tenants"].Cast<ArkTenant>().All(t => t.tenant_id == op)
                && target["clients"].Cast<ArkClient>().All(c => c.tenant_id == op && seedClients.Contains(c.client_id, StringComparer.OrdinalIgnoreCase))
                && target["users"].Cast<ArkUser>().All(u => seedUsers.Contains(L(u.email)))
                && target["user_client_claims"].Count <= 2
                && target.GetValueOrDefault("service_accounts", new List<object>()).Count == 0;
        }

        // ================================================================== analyse / apply

        public ArkImportAnalysis Analyze(ArkImportRequest req)
        {
            var include = IncludeSet(req.include);
            var pf = Parse(req);
            var target = LoadTarget();
            var analysis = new ArkImportAnalysis
            {
                file = pf.Info,
                blockers = pf.Blockers,
                warnings = pf.Warnings,
                target_counts = target.ToDictionary(kv => kv.Key, kv => kv.Value.Count),
                target_pristine = IsPristine(target),
                include = Categories.Where(include.Contains).ToList()
            };
            if (pf.Blockers.Count > 0) return analysis;

            foreach (var mode in Modes)
            {
                var plan = BuildPlan(mode, pf, target, include);
                var (summary, tables, records, truncated) = Describe(plan);
                analysis.modes[mode] = new ArkImportPlan
                {
                    mode = mode,
                    possible = plan.Blockers.Count == 0,
                    blockers = plan.Blockers,
                    warnings = plan.Warnings,
                    plan_hash = plan.Hash,
                    summary = summary,
                    tables = tables,
                    deletes = plan.Deletes,
                    records = records,
                    records_truncated = truncated
                };
            }

            var replace = analysis.modes[ModeReplace];
            var overwrite = analysis.modes[ModeMergeOverwrite];
            if (analysis.target_pristine && replace.possible)
            {
                analysis.recommended_mode = ModeReplace;
                analysis.recommendation = "this server holds nothing but its first-run data, so replacing it with the file loses nothing and loads the file exactly as exported.";
            }
            else if (overwrite.summary.GetValueOrDefault(Update) == 0)
            {
                analysis.recommended_mode = ModeMergeSkip;
                analysis.recommendation = "no record in the file differs from one already here, so the merge modes do the same thing; merge_skip is the one that can never change an existing record.";
            }
            else
            {
                analysis.recommended_mode = ModeMergeSkip;
                analysis.recommendation = $"{overwrite.summary.GetValueOrDefault(Update)} record(s) already exist here with different values. merge_skip adds what is missing and keeps this server's versions; choose merge_overwrite to take the file's versions instead.";
            }

            (analysis.settings, analysis.settings_same) = CompareSettings(pf.Settings);
            analysis.settings_file = pf.Settings?.DeepClone() as JsonObject;
            return analysis;
        }

        public ArkImportResult Apply(ArkImportRequest req, string? by, string? ip)
        {
            var mode = (req.mode ?? "").Trim().ToLowerInvariant();
            if (!Modes.Contains(mode))
                throw new ArkDataToolsException("invalid_request", $"mode must be one of {string.Join(", ", Modes)}.");
            if (mode == ModeReplace && !Cfg.AllowReplace)
                throw new ArkDataToolsException("replace_disabled", "replace is switched off by ark_oauth_server:Admin:DataTools:AllowReplace.", 403);
            if (mode == ModeReplace && !string.Equals(req.confirm, Ser.TenantId, StringComparison.Ordinal))
                throw new ArkDataToolsException("confirmation_required", $"replace empties this server first - type the operator tenant id '{Ser.TenantId}' to confirm.");
            if (string.IsNullOrWhiteSpace(req.plan_hash))
                throw new ArkDataToolsException("plan_hash_required", "analyse the file first and pass the plan_hash of the mode you chose.");

            var include = IncludeSet(req.include);
            var pf = Parse(req);
            if (pf.Blockers.Count > 0)
                throw new ArkDataToolsException("import_blocked", pf.Blockers[0].msg, 422, new { blockers = pf.Blockers });

            var target = LoadTarget();
            var plan = BuildPlan(mode, pf, target, include);
            if (plan.Blockers.Count > 0)
                throw new ArkDataToolsException("mode_blocked", plan.Blockers[0].msg, 422, new { blockers = plan.Blockers });
            if (!string.Equals(plan.Hash, req.plan_hash.Trim(), StringComparison.OrdinalIgnoreCase))
                throw new ArkDataToolsException("plan_changed",
                    "the database or the file has changed since it was analysed, so the plan you reviewed is not the one that would run. Analyse again.", 409);

            var deleted = new Dictionary<string, int>();
            _ctx.ChangeTracker.Clear();
            using (var tx = _ctx.Database.BeginTransaction())
            {
                if (mode == ModeReplace)
                    foreach (var t in Enumerable.Reverse(Tables()))
                        deleted[t.Name] = DeleteAll(t);

                foreach (var row in plan.Rows)
                {
                    if (row.Action == Insert) _ctx.Add(row.Entity!);
                    else if (row.Action == Update) _ctx.Update(row.Entity!);
                }
                _ctx.SaveChanges();
                _ctx.ChangeTracker.Clear();

                // The imported console client carries the source server's callback URLs; these
                // add this server's, and the scopes and machine client a file may lack.
                ArkExtn.Reconcile(_services);
                tx.Commit();
            }
            _ctx.ChangeTracker.Clear();

            var (summary, tables, records, truncated) = Describe(plan);
            var result = new ArkImportResult
            {
                mode = mode,
                summary = summary,
                tables = tables,
                deleted = deleted,
                records = records,
                records_truncated = truncated,
                follow_up = FollowUp(mode, pf, plan)
            };
            _da.Record("data_import", mode,
                $"import ({mode}): {summary.GetValueOrDefault(Insert)} inserted, {summary.GetValueOrDefault(Update)} updated, {summary.GetValueOrDefault(Excluded)} excluded",
                $"file: {pf.Info.exported_at} from {pf.Info.base_url} ({pf.Info.package_version}), checksum {pf.Checksum}, include: {string.Join(",", include)}",
                by, ip);
            return result;
        }

        List<string> FollowUp(string mode, ParsedFile pf, Plan plan)
        {
            var list = new List<string>();
            if (mode == ModeReplace)
                list.Add("This server now holds the file's data: sign out and back in, with the administrator password from the file.");
            if (plan.Warnings.Any(w => w.code == "signing_key_kid_reused"))
                list.Add("A signing key was replaced under the same kid: if signing in fails with IDX10511, wait about 5 minutes or restart the host and its clients so they refetch the JWKS.");
            if (plan.Rows.Any(r => r.Action == Excluded))
                list.Add("Excluded rows were not loaded. Each one names its reason; fix the source and import again with merge_skip to add them.");
            if (pf.Warnings.Any(w => w.code == "base_url_differs"))
                list.Add("The file came from another host: point each client's authority at this server's issuer, and register this host's callback URLs where the clients need them.");
            if (plan.Rows.Any(r => r.Entity is ArkSigningKey && r.Adjustments.Any(a => a.Contains("rollover"))))
                list.Add("Imported signing keys were added as rollover keys; rotate in the console if one of them should sign.");
            list.Add("Configuration settings are never applied by an import - compare them on the analysis and change appsettings / environment by hand where needed.");
            return list;
        }

        (List<ArkSettingDiff> Diffs, int Same) CompareSettings(JsonObject? fileSettings)
        {
            var here = Flatten(SettingsSnapshot(includeSecrets: true));
            var file = Flatten(fileSettings);
            var diffs = new List<ArkSettingDiff>();
            var same = 0;
            foreach (var key in here.Keys.Union(file.Keys).OrderBy(k => k, StringComparer.OrdinalIgnoreCase))
            {
                var hasHere = here.TryGetValue(key, out var h);
                var hasFile = file.TryGetValue(key, out var f);
                var allSecret = key.StartsWith("ConnectionStrings:", StringComparison.OrdinalIgnoreCase);
                string? Show(string? v) => v != null && v != Redacted && IsSecret(key.Split(':').Last(), v, allSecret) ? Redacted : v;

                if (hasHere && hasFile && h == f) { same++; continue; }
                diffs.Add(new ArkSettingDiff
                {
                    key = key,
                    status = !hasFile ? "only_here" : !hasHere ? "only_in_file" : f == Redacted ? "redacted_in_file" : "different",
                    here = Show(h),
                    in_file = Show(f)
                });
            }
            return (diffs, same);
        }

        static Dictionary<string, string?> Flatten(JsonNode? node)
        {
            var map = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
            void Walk(JsonNode? n, string path)
            {
                switch (n)
                {
                    case JsonObject o: foreach (var kv in o) Walk(kv.Value, path.Length == 0 ? kv.Key : $"{path}:{kv.Key}"); break;
                    case JsonArray a: for (var i = 0; i < a.Count; i++) Walk(a[i], $"{path}:{i}"); break;
                    case null: if (path.Length > 0) map[path] = null; break;
                    default: map[path] = n.GetValueKind() == JsonValueKind.String ? n.GetValue<string>() : n.ToJsonString(); break;
                }
            }
            Walk(node, "");
            return map;
        }

        // ================================================================== factory reset

        /// <summary>
        /// Whether a reset could seed this server again, and why not. Checked before anything is
        /// deleted, and shown on the screen so the button is never the way to find out.
        /// </summary>
        public string? SeedProblem()
        {
            if (string.IsNullOrWhiteSpace(Ser.TenantId)) return "ark_oauth_server:TenantId is not set.";
            try { ArkExtn.ResolveAdminUser(Ser); }
            catch (ApplicationException ex) { return ex.Message; }
            return null;
        }

        public async Task<ArkResetResult> ResetAsync(ArkResetRequest? req, HttpContext? http, string? by, string? ip)
        {
            if (!string.Equals(req?.confirm, Ser.TenantId, StringComparison.Ordinal))
                throw new ArkDataToolsException("confirmation_required",
                    $"a reset deletes everything on this server - type the operator tenant id '{Ser.TenantId}' exactly to confirm.");
            var problem = SeedProblem();
            if (problem != null)
                throw new ArkDataToolsException("seed_unavailable", $"nothing was deleted: the server could not seed itself again afterwards. {problem}", 409);

            var removed = Counts();
            _ctx.ChangeTracker.Clear();
            using (var tx = await _ctx.Database.BeginTransactionAsync())
            {
                foreach (var t in Enumerable.Reverse(Tables()))
                    DeleteAll(t);
                _ctx.ChangeTracker.Clear();
                await ArkExtn.SeedDatabase(_services, Ser, http, thumbprintKid: true);
                _ctx.ChangeTracker.Clear();
                ArkExtn.Reconcile(_services);
                await tx.CommitAsync();
            }
            _ctx.ChangeTracker.Clear();

            var seeded = Counts();
            _da.Record("data_reset", Ser.TenantId, "factory reset: every table emptied and re-seeded",
                string.Join(", ", removed.Where(kv => kv.Value > 0).Select(kv => $"{kv.Key}: {kv.Value}")), by, ip);
            return new ArkResetResult
            {
                removed = removed,
                seeded = seeded,
                admin_user = AdminUsername,
                operator_tenant = Ser.TenantId,
                follow_up = new List<string>
                {
                    $"Sign in again as '{AdminUsername}' with the password configured in ark_oauth_server:AdminUser:Password (or DefaultPw) - any password changed in the console is gone.",
                    "Every client application, user and mapping is gone, and the signing key is new: applications must be registered again and their users signed in again.",
                    "The new key has a new kid. A client holding the old JWKS (this console included) rejects the first token it sees with IDX10503 and refetches - sign in once more and it succeeds.",
                    $"The machine client '{Ser.TenantId}_machine' has no secret until one is generated in the console."
                }
            };
        }
    }
}
