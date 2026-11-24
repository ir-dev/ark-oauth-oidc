using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Ark.oAuth.Oidc.Protocol;

namespace Ark.oAuth.Oidc.Mcp
{
    /// <summary>
    /// What an agent has collected for setup so far.
    ///
    /// Setting a server up over MCP is not one form filled in by one person: the legal name comes
    /// from one department, the database account from another, and the answers arrive over days.
    /// So each value is kept as it comes, with who supplied it, in <c>setup-draft.json</c> beside
    /// the settings: readable only by the server's account, git-ignored with the rest of that
    /// directory, and deleted when setup finishes by either route.
    ///
    /// Three values never reach the file. The administrator's password, an imported signing key
    /// and a chosen machine secret are written to no settings file by an install, so they are not
    /// written here either: they are held in this process and have to be given again after a
    /// restart. The default for each is not to have an agent carry it at all.
    /// </summary>
    internal sealed class ArkSetupDraft
    {
        public const string FileName = "setup-draft.json";

        readonly string _directory;
        readonly object _lock = new();
        JsonObject? _document;
        readonly Dictionary<string, string> _held = new(StringComparer.Ordinal);

        public ArkSetupDraft(string directory) => _directory = directory;

        string PathName => Path.Combine(_directory, FileName);

        /// <summary>Removes the file. Called when setup finishes, and safe when there is none.</summary>
        public static void Delete(string directory)
        {
            try { File.Delete(Path.Combine(directory, FileName)); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        JsonObject Document
        {
            get
            {
                if (_document != null) return _document;
                try
                {
                    if (File.Exists(PathName) && JsonNode.Parse(File.ReadAllText(PathName)) is JsonObject stored)
                        return _document = stored;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException) { }
                return _document = new JsonObject();
            }
        }

        JsonObject Part(string name)
        {
            if (Document[name] is JsonObject part) return part;
            part = new JsonObject();
            Document[name] = part;
            return part;
        }

        public DateTime? UpdatedAt
        {
            get
            {
                lock (_lock)
                    return Document["updated_at"] is JsonValue v && v.TryGetValue<DateTime>(out var at) ? at : null;
            }
        }

        /// <summary>A copy of the values collected for one section.</summary>
        public JsonObject Section(string name)
        {
            lock (_lock) return Part("sections")[name] is JsonObject s ? (JsonObject)s.DeepClone() : new JsonObject();
        }

        public string? Held(string key) { lock (_lock) return _held.GetValueOrDefault(key); }

        public JsonObject? Source(string section, string field)
        {
            lock (_lock) return Part("sources")[$"{section}.{field}"] is JsonObject s ? (JsonObject)s.DeepClone() : null;
        }

        public Dictionary<string, JsonObject> Sources()
        {
            lock (_lock)
                return Part("sources").Where(p => p.Value is JsonObject).ToDictionary(p => p.Key, p => (JsonObject)p.Value!.DeepClone(), StringComparer.Ordinal);
        }

        /// <summary>
        /// Sets fields of a section. A null value removes one. <paramref name="held"/> are the
        /// values that stay in memory.
        /// </summary>
        public void Set(string section, IReadOnlyDictionary<string, JsonNode?> values, IReadOnlyDictionary<string, string?> held, JsonObject? source)
        {
            lock (_lock)
            {
                var sections = Part("sections");
                if (sections[section] is not JsonObject target) sections[section] = target = new JsonObject();
                foreach (var (field, value) in values)
                {
                    if (value == null) target.Remove(field);
                    else target[field] = value.DeepClone();
                    Attribute(section, field, value == null ? null : source);
                }
                foreach (var (field, value) in held)
                {
                    var key = $"{section}.{field}";
                    if (string.IsNullOrEmpty(value)) _held.Remove(key); else _held[key] = value!;
                    Attribute(section, field, string.IsNullOrEmpty(value) ? null : source);
                }
                Save();
            }
        }

        void Attribute(string section, string field, JsonObject? source)
        {
            var sources = Part("sources");
            var key = $"{section}.{field}";
            if (source == null) { sources.Remove(key); return; }
            var entry = (JsonObject)source.DeepClone();
            entry["at"] = DateTime.UtcNow.ToString("O");
            sources[key] = entry;
        }

        public void Clear(string section)
        {
            lock (_lock)
            {
                Part("sections").Remove(section);
                foreach (var key in Part("sources").Select(p => p.Key).Where(k => k.StartsWith(section + ".", StringComparison.Ordinal)).ToList())
                    Part("sources").Remove(key);
                foreach (var key in _held.Keys.Where(k => k.StartsWith(section + ".", StringComparison.Ordinal)).ToList()) _held.Remove(key);
                Part("tests").Remove(section);
                Save();
            }
        }

        /// <summary>Records a test of a section, against the values it was run with.</summary>
        public void Tested(string section, bool ok, string message)
        {
            lock (_lock)
            {
                Part("tests")[section] = new JsonObject
                {
                    ["ok"] = ok, ["message"] = message, ["at"] = DateTime.UtcNow.ToString("O"), ["of"] = Fingerprint(section)
                };
                Save();
            }
        }

        /// <summary>The last test of a section as it stands now, or null: a test of other values says nothing.</summary>
        public (bool Ok, string Message)? TestOf(string section)
        {
            lock (_lock)
                return Part("tests")[section] is JsonObject t && t["of"]?.GetValue<string>() == Fingerprint(section)
                    ? (t["ok"]?.GetValue<bool>() == true, t["message"]?.GetValue<string>() ?? "")
                    : null;
        }

        string Fingerprint(string section) => ArkCrypto.Sha256Base64Url(Part("sections")[section]?.ToJsonString() ?? "");

        /// <summary>
        /// Names this exact draft, secrets included. What was reviewed is what is installed: an
        /// install names the review it follows, and a value changed in between changes this.
        /// </summary>
        public string ReviewId()
        {
            lock (_lock)
            {
                var text = new StringBuilder(Part("sections").ToJsonString());
                foreach (var (key, value) in _held.OrderBy(h => h.Key, StringComparer.Ordinal))
                    text.Append('\n').Append(key).Append('=').Append(ArkCrypto.Sha256Base64Url(value));
                return ArkCrypto.Sha256Base64Url(text.ToString())[..20];
            }
        }

        void Save()
        {
            Document["_about"] = "Collected over MCP for the setup of this server. Deleted when setup finishes; holds secrets until then.";
            Document["updated_at"] = DateTime.UtcNow;
            try
            {
                ArkIdpSettings.WritePrivateFile(PathName, Encoding.UTF8.GetBytes(
                    Document.ToJsonString(new JsonSerializerOptions { WriteIndented = true })));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                throw new ArkMcpToolException("cannot_write",
                    $"The draft could not be saved in {_directory}: {ex.Message} Point ark_oauth_server:Setup:DataPath at a writable directory.");
            }
        }
    }
}
