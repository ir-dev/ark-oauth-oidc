using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Ark.Agents.TenantOnboarding.Brain
{
    internal enum AgentPhase
    {
        /// <summary>Waiting for the server to listen and for the setup code.</summary>
        Starting,
        /// <summary>Connected to the setup tools: collecting.</summary>
        Collecting,
        /// <summary>Installed by this agent. The hand-over is waiting for the lead.</summary>
        Installed,
        /// <summary>The server is set up already, by the wizard or before this start: nothing to do.</summary>
        NotNeeded
    }

    internal sealed class Participant
    {
        public string Id { get; set; } = "";
        public string Name { get; set; } = "";
        public string Department { get; set; } = "";
        /// <summary><c>lead</c>: may see everything, invite, review and install. <c>contributor</c>: the sections of one invite.</summary>
        public string Role { get; set; } = "lead";
        public List<string> Sections { get; set; } = new();
        public string? InviteId { get; set; }
        /// <summary>Guided mode: the value the last question asked for, as <c>section.field</c>.</summary>
        public string? Pending { get; set; }
        public bool Greeted { get; set; }
        /// <summary>The address this person's browser reached the agent at. Proof that the address leads here.</summary>
        public string? Origin { get; set; }

        public bool IsLead => Role == "lead";
        public bool May(string section) => IsLead || Sections.Contains(section, StringComparer.Ordinal);
    }

    internal sealed class Invite
    {
        public string Id { get; set; } = "";
        public string Department { get; set; } = "";
        public string? Name { get; set; }
        public List<string> Sections { get; set; } = new();
        public string CreatedBy { get; set; } = "";
        public DateTime CreatedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
        public DateTime? OpenedAt { get; set; }
        public DateTime? LastActivityAt { get; set; }
        public DateTime? AnsweredAt { get; set; }
        public bool Revoked { get; set; }
        public string? ParticipantId { get; set; }

        public string Status(DateTime now, int quietAfterHours) =>
            Revoked ? "revoked" : AnsweredAt != null ? "answered" : now > ExpiresAt ? "expired"
            : OpenedAt != null ? "opened" : now - CreatedAt > TimeSpan.FromHours(quietAfterHours) ? "quiet" : "sent";
    }

    internal sealed class ChatMessage
    {
        public string Id { get; set; } = "";
        /// <summary><c>agent</c> or <c>user</c>.</summary>
        public string From { get; set; } = "agent";
        public string Text { get; set; } = "";
        public JsonArray? Widgets { get; set; }
        public DateTime At { get; set; }
    }

    internal sealed class Proposal
    {
        public string Id { get; set; } = "";
        public string Section { get; set; } = "";
        public string Field { get; set; } = "";
        public JsonNode? Value { get; set; }
        public string Why { get; set; } = "";
        /// <summary>Who it is waiting for.</summary>
        public string ParticipantId { get; set; } = "";
        /// <summary><c>open</c>, <c>accepted</c> or <c>dismissed</c>.</summary>
        public string State { get; set; } = "open";
        /// <summary>The person said it themselves and it is permanent: a confirmation, not a suggestion.</summary>
        public bool Confirm { get; set; }
    }

    internal sealed class Activity
    {
        public DateTime At { get; set; }
        public string Text { get; set; } = "";
    }

    internal sealed record FieldDef(string Name, string Type, bool Required, string Description, string Ask, string? Default,
        string[]? Values, bool Secret, bool Held);

    internal sealed record SectionDef(string Name, string Title, string Owner, string Purpose, FieldDef[] Fields)
    {
        public FieldDef? Field(string name) => Fields.FirstOrDefault(f => f.Name == name);
    }

    /// <summary>
    /// Everything the agent knows, in one place: who is taking part, what was said, what is
    /// proposed, and the identity server's own account of where setup stands.
    ///
    /// Kept in <c>agent-state.json</c> beside the server's setup draft, because collecting takes
    /// days and the process restarts in between. Secrets are not part of it: they live in
    /// <see cref="Vault"/>, in memory, until the setup tools have them.
    /// </summary>
    internal sealed class Workspace
    {
        public const string FileName = "agent-state.json";

        /// <summary>The four values a setup cannot do without: everything else has a default.</summary>
        public static readonly string[] Essentials = { "organization.company_name", "server.base_url", "server.tenant_id", "administrator.username" };

        /// <summary>
        /// What the progress ring counts: <see cref="Essentials"/>, and the default password unless new
        /// people get an activation email. The console creates every account on it, so the server
        /// owes it before a review (setup_status lists it as missing) and the ring must not show
        /// "4/4" while it is open.
        /// </summary>
        public string[] EssentialKeys()
        {
            lock (_lock)
                return Values.TryGetValue("users.password_mode", out var mode) && string.Equals(mode?.ToString(), "email_based", StringComparison.OrdinalIgnoreCase)
                    ? Essentials
                    : Essentials.Append("users.default_password").ToArray();
        }

        readonly object _lock = new();
        TaskCompletionSource _changed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        string? _file;

        public AgentPhase Phase { get; private set; } = AgentPhase.Starting;
        public string StartingWhy { get; set; } = "The server is starting.";
        public long Version { get; private set; } = 1;

        public Dictionary<string, Participant> People { get; private set; } = new(StringComparer.Ordinal);
        public Dictionary<string, List<ChatMessage>> Conversations { get; private set; } = new(StringComparer.Ordinal);
        public List<Invite> Invites { get; private set; } = new();
        public List<Proposal> Proposals { get; private set; } = new();
        public List<Activity> Activities { get; private set; } = new();
        /// <summary>What the model kept for later turns, by whose turn it was. A colleague's turn never sees the lead's.</summary>
        public Dictionary<string, List<string>> NotesOf { get; private set; } = new(StringComparer.Ordinal);
        /// <summary><c>section.field</c> of a stored secret → the participant who gave it. Whose it is, not what it is.</summary>
        public Dictionary<string, string> SecretOwners { get; private set; } = new(StringComparer.Ordinal);

        /// <summary>What the scout found before anyone arrived. No secrets.</summary>
        public JsonObject Environment { get; set; } = new();
        public List<SectionDef> Catalogue { get; private set; } = new();
        /// <summary><c>section.field</c> → the stored value as the server shows it (a secret only as "(set)").</summary>
        public Dictionary<string, JsonNode?> Values { get; private set; } = new(StringComparer.Ordinal);
        public Dictionary<string, JsonObject> Sources { get; private set; } = new(StringComparer.Ordinal);
        public JsonObject Status { get; private set; } = new();
        public JsonObject? Review { get; set; }
        /// <summary>The answer of setup_complete: one-time secrets. Memory only, until the lead has them.</summary>
        public JsonObject? Handover { get; set; }
        public DateTime HandoverSince { get; set; }
        public string? ModelNotice { get; set; }

        public Vault Vault { get; } = new();
        public object Sync => _lock;

        // ------------------------------------------------------------ change notification

        public void Touch()
        {
            TaskCompletionSource waiting;
            lock (_lock)
            {
                Version++;
                waiting = _changed;
                _changed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            }
            waiting.TrySetResult();
            Save();
        }

        /// <summary>Completes when something changes after <paramref name="version"/>, or at once if it already has.</summary>
        public Task WaitAsync(long version)
        {
            lock (_lock) return Version > version ? Task.CompletedTask : _changed.Task;
        }

        public void SetPhase(AgentPhase phase)
        {
            lock (_lock)
            {
                if (Phase == phase) return;
                Phase = phase;
            }
            Touch();
        }

        // ------------------------------------------------------------ the server's account

        public void Absorb(JsonObject status, JsonObject fields)
        {
            lock (_lock)
            {
                Status = status;
                var catalogue = new List<SectionDef>();
                var values = new Dictionary<string, JsonNode?>(StringComparer.Ordinal);
                var sources = new Dictionary<string, JsonObject>(StringComparer.Ordinal);
                foreach (var s in fields["sections"] as JsonArray ?? new JsonArray())
                {
                    if (s is not JsonObject section) continue;
                    var name = Text(section, "section");
                    var defs = new List<FieldDef>();
                    foreach (var f in section["fields"] as JsonArray ?? new JsonArray())
                    {
                        if (f is not JsonObject field) continue;
                        var fieldName = Text(field, "field");
                        defs.Add(new FieldDef(fieldName, Text(field, "type"), field["required"]?.GetValue<bool>() == true,
                            Text(field, "description"), Text(field, "ask"), field["default"]?.GetValue<string>(),
                            (field["values"] as JsonArray)?.Select(v => v!.GetValue<string>()).ToArray(),
                            field["secret"]?.GetValue<bool>() == true || field["kept_in_memory_only"]?.GetValue<bool>() == true,
                            field["kept_in_memory_only"]?.GetValue<bool>() == true));
                        if (field["value"] is { } value) values[$"{name}.{fieldName}"] = value.DeepClone();
                        if (field["source"] is JsonObject source) sources[$"{name}.{fieldName}"] = (JsonObject)source.DeepClone();
                    }
                    catalogue.Add(new SectionDef(name, Text(section, "title"), Text(section, "usually_known_by"), Text(section, "purpose"), defs.ToArray()));
                }
                Catalogue = catalogue;
                Values = values;
                Sources = sources;
            }
        }

        public SectionDef? Section(string name)
        {
            lock (_lock) return Catalogue.FirstOrDefault(s => s.Name == name);
        }

        public JsonObject? StatusOf(string section)
        {
            lock (_lock)
                return (Status["sections"] as JsonArray)?.OfType<JsonObject>().FirstOrDefault(s => Text(s, "section") == section);
        }

        public bool ReadyForReview
        {
            get { lock (_lock) return Status["ready_for_review"]?.GetValue<bool>() == true; }
        }

        public bool Has(string key)
        {
            lock (_lock) return Values.ContainsKey(key);
        }

        public string? ValueText(string key)
        {
            lock (_lock) return Values.TryGetValue(key, out var v) && v is JsonValue value && value.TryGetValue<string>(out var s) ? s : null;
        }

        static string Text(JsonObject o, string name) => o[name] is JsonValue v && v.TryGetValue<string>(out var s) ? s : "";

        // ------------------------------------------------------------ conversation

        public ChatMessage Say(Participant to, string text, JsonArray? widgets = null) => Add(to, "agent", text, widgets);

        public ChatMessage Heard(Participant from, string text) => Add(from, "user", text, null);

        ChatMessage Add(Participant p, string from, string text, JsonArray? widgets)
        {
            var message = new ChatMessage { Id = NewId(), From = from, Text = text, Widgets = widgets, At = DateTime.UtcNow };
            lock (_lock)
            {
                if (!Conversations.TryGetValue(p.Id, out var list)) Conversations[p.Id] = list = new List<ChatMessage>();
                list.Add(message);
                // Days of collecting, not an archive: the whole of it travels to the page and the file each time.
                if (list.Count > 500) list.RemoveRange(0, list.Count - 500);
            }
            return message;
        }

        public List<ChatMessage> Conversation(Participant p)
        {
            lock (_lock) return Conversations.TryGetValue(p.Id, out var list) ? list.ToList() : new List<ChatMessage>();
        }

        public void Log(string text)
        {
            lock (_lock)
            {
                Activities.Add(new Activity { At = DateTime.UtcNow, Text = text });
                if (Activities.Count > 200) Activities.RemoveRange(0, Activities.Count - 200);
            }
        }

        public void Remember(Participant p, IEnumerable<string> notes)
        {
            lock (_lock)
            {
                if (!NotesOf.TryGetValue(p.Id, out var kept)) NotesOf[p.Id] = kept = new List<string>();
                foreach (var note in notes.Select(n => n.Trim()).Where(n => n.Length is > 0 and <= 300))
                    if (!kept.Contains(note, StringComparer.OrdinalIgnoreCase)) kept.Add(note);
                if (kept.Count > 40) kept.RemoveRange(0, kept.Count - 40);
            }
        }

        /// <summary>What was kept from this person's own turns; for a lead, from any lead's.</summary>
        public List<string> Notes(Participant p)
        {
            lock (_lock)
                return NotesOf.Where(n => n.Key == p.Id || (p.IsLead && People.TryGetValue(n.Key, out var other) && other.IsLead))
                    .SelectMany(n => n.Value).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        /// <summary>
        /// What this person has typed, lower-cased: what a value has to appear in to count as theirs.
        /// A lead's turn is answered for by leads and by what the host showed; a colleague's by the
        /// colleague alone. What a colleague wrote never makes a value the lead's.
        /// </summary>
        public string Corpus(Participant p)
        {
            lock (_lock)
            {
                var text = new StringBuilder();
                bool Counts(string id) => id == p.Id || (p.IsLead && People.TryGetValue(id, out var other) && other.IsLead);
                foreach (var (id, list) in Conversations)
                    if (Counts(id))
                        foreach (var m in list.Where(m => m.From == "user")) text.Append(m.Text).Append('\n');
                foreach (var person in People.Values)
                    if (Counts(person.Id)) text.Append(person.Origin).Append('\n').Append(person.Name).Append('\n');
                if (p.IsLead) text.Append(Environment.ToJsonString());
                return text.ToString().ToLowerInvariant();
            }
        }

        public static string NewId() => Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();

        // ------------------------------------------------------------ persistence

        static readonly JsonSerializerOptions FileJson = new() { WriteIndented = true };

        sealed class Stored
        {
            public Dictionary<string, Participant> People { get; set; } = new();
            public Dictionary<string, List<ChatMessage>> Conversations { get; set; } = new();
            public List<Invite> Invites { get; set; } = new();
            public List<Proposal> Proposals { get; set; } = new();
            public List<Activity> Activities { get; set; } = new();
            public Dictionary<string, List<string>> NotesOf { get; set; } = new();
            public Dictionary<string, string> SecretOwners { get; set; } = new();
        }

        /// <summary>Reads what an earlier run of this process left, if anything.</summary>
        public void Open(string directory)
        {
            lock (_lock)
            {
                _file = Path.Combine(directory, FileName);
                try
                {
                    if (!File.Exists(_file)) return;
                    var stored = JsonSerializer.Deserialize<Stored>(File.ReadAllText(_file));
                    if (stored == null) return;
                    People = new Dictionary<string, Participant>(stored.People, StringComparer.Ordinal);
                    Conversations = new Dictionary<string, List<ChatMessage>>(stored.Conversations, StringComparer.Ordinal);
                    Invites = stored.Invites;
                    Proposals = stored.Proposals;
                    Activities = stored.Activities;
                    NotesOf = new Dictionary<string, List<string>>(stored.NotesOf, StringComparer.Ordinal);
                    SecretOwners = new Dictionary<string, string>(stored.SecretOwners, StringComparer.Ordinal);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
                {
                    // A state file that cannot be read costs the conversation, never the setup: the
                    // collected values are the identity server's, in its own draft.
                }
            }
        }

        readonly object _fileLock = new();

        void Save()
        {
            // One writer at a time, and the phase is looked at inside: a write that began before the
            // install must not put the file back after Forget has removed it.
            lock (_fileLock)
            {
                string? file;
                string json;
                lock (_lock)
                {
                    file = _file;
                    if (file == null || Phase is AgentPhase.Installed or AgentPhase.NotNeeded) return;
                    json = JsonSerializer.Serialize(new Stored
                    {
                        People = People, Conversations = Conversations, Invites = Invites, Proposals = Proposals, Activities = Activities,
                        NotesOf = NotesOf, SecretOwners = SecretOwners
                    }, FileJson);
                }
                try
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(file)!);
                    var temp = file + ".tmp";
                    File.Delete(temp);
                    // Private from its first byte, not made private after it was written.
                    var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
                    if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
                    using (var stream = new FileStream(temp, options)) stream.Write(Encoding.UTF8.GetBytes(json));
                    File.Move(temp, file, overwrite: true);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            }
        }

        /// <summary>
        /// Setup is over: the conversations named people and their systems, and whatever is still in
        /// the vault was on its way to a server that no longer takes it. None of it is needed.
        /// </summary>
        public void Forget()
        {
            Vault.Clear();
            string? file;
            lock (_lock) file = _file;
            // Not while a write is under way: it would put the file back.
            if (file != null) lock (_fileLock) Discard(Path.GetDirectoryName(file)!);
        }

        /// <summary>Removes what an earlier run left, for a start at which setup turns out to be finished already.</summary>
        public static void Discard(string directory)
        {
            foreach (var name in new[] { FileName, FileName + ".tmp" })
                try { File.Delete(Path.Combine(directory, name)); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    /// <summary>
    /// Secrets on their way from a person to the identity server. The model is shown a placeholder
    /// (<c>[[vault:3]]</c>) and the harness puts the value back when a tool is called. Memory only.
    ///
    /// Every secret is somebody's, and a placeholder only works in its owner's turn: the numbers are
    /// easy to guess, and a colleague who types one gets nothing for it. A password the harness read
    /// off the host application belongs to the application: only the lead's turn may use it, and
    /// only for the host it is the password of.
    /// </summary>
    internal sealed class Vault
    {
        /// <summary>The owner of what was found in the host application's own configuration.</summary>
        public const string Application = "(application)";

        sealed record Entry(string Secret, string Owner, string? Host);

        readonly Dictionary<string, Entry> _values = new(StringComparer.Ordinal);
        int _next;

        public string Put(string secret, string owner, string? host = null)
        {
            lock (_values)
            {
                // Told apart by owner as well: that somebody else's secret is the same is not for anybody to find out.
                foreach (var (key, value) in _values)
                    if (value.Secret == secret && value.Owner == owner && value.Host == host) return key;
                var placeholder = $"[[vault:{++_next}]]";
                _values[placeholder] = new Entry(secret, owner, host);
                return placeholder;
            }
        }

        /// <summary>One person's own secrets, longest first.</summary>
        public List<(string Placeholder, string Secret)> Of(string owner)
        {
            lock (_values)
                return _values.Where(v => v.Value.Owner == owner).Select(v => (v.Key, v.Value.Secret)).OrderByDescending(v => v.Secret.Length).ToList();
        }

        public static bool Mentions(string text) => Any.IsMatch(text);

        /// <summary>
        /// The text with every placeholder replaced, for a value this person is storing; null when
        /// one of them is unknown, or not theirs to use there.
        /// </summary>
        /// <param name="host">Where the secret would be sent, for one that is tied to a host.</param>
        public string? Resolve(string text, Participant p, string? host = null)
        {
            var refused = false;
            var resolved = Any.Replace(text, m =>
            {
                lock (_values)
                {
                    if (_values.TryGetValue(m.Value, out var entry)
                        && (entry.Owner == p.Id || (entry.Owner == Application && p.IsLead))
                        // A tied one is used whole, and for its own host: never as a part of something longer.
                        && (entry.Host == null || (text.Trim() == m.Value && string.Equals(entry.Host, host?.Trim(), StringComparison.OrdinalIgnoreCase))))
                        return entry.Secret;
                }
                refused = true;
                return m.Value;
            });
            return refused ? null : resolved;
        }

        public void Clear()
        {
            lock (_values) _values.Clear();
        }

        static readonly System.Text.RegularExpressions.Regex Any = new(@"\[\[vault:\d+\]\]", System.Text.RegularExpressions.RegexOptions.CultureInvariant);
    }
}
