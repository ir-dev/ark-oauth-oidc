using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Ark.Agents.TenantOnboarding.Brain
{
    /// <summary>
    /// How a small model is asked, and how little.
    ///
    /// A model of a few billion parameters cannot hold the whole situation, choose tools and write
    /// good prose, and the server it runs on cannot read a long prompt quickly. It can do one thing
    /// well: pick stated values out of a paragraph. So it is asked for that alone, with only the
    /// settings the message seems to touch, and everything it returns is checked against the
    /// message and against the shape of the value before anybody sees it.
    /// </summary>
    internal static class SmallModel
    {
        internal sealed record Offered(string Key, SectionDef Section, FieldDef Field, int Score);

        internal sealed class Reading
        {
            public List<(string Key, JsonNode? Value)> Values { get; } = new();
        }

        const RegexOptions Flags = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

        // ------------------------------------------------------------ is it worth a call?

        static readonly Regex SmallTalk = new(@"^\s*(?:hi|hello|hey|thanks?|thank you|ok(?:ay)?|great|cool|good|fine|perfect|done|yes|no|sure|bye)\b[\s\w!.,']{0,24}$", Flags);
        static readonly Regex QuestionStart = new(@"^\s*(?:what|why|how|which|who|when|where|can|could|should|would|do|does|is|are|will|may|explain|tell me)\b", Flags);
        static readonly Regex Address = new(@"https?://\S+|[\w.+-]+@[\w-]+\.[\w.]+", Flags);
        static readonly Regex Leftovers = new(@"\[database:[^\]]*(?:\[\[vault:\d+\]\][^\]]*)*\]|\[\[vault:\d+\]\]", Flags);

        public static bool IsSmallTalk(string text) => SmallTalk.IsMatch(text);

        public static bool IsQuestion(string text) =>
            !Address.IsMatch(text) && (text.TrimEnd().EndsWith('?') || QuestionStart.IsMatch(text) && !text.Contains('.', StringComparison.Ordinal));

        public static int Words(string text) => text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Length;

        /// <summary>One line, a few words, not a question: the answer to what was just asked.</summary>
        public static bool IsAnswer(string text, int words) =>
            text.Trim() is { Length: > 0 and <= 300 } t && !t.Contains('\n') && !t.Contains('?') && Words(t) <= words;

        /// <summary>What is left of a message once the connection strings and secrets in it have been dealt with.</summary>
        public static string Remainder(string clean) => Leftovers.Replace(clean, " ").Trim();

        static readonly Regex LeadIn = new(
            @"^(?:no[,;]?\s+)?(?:it'?s|it is|its|that'?s|that is|that would be|we are|we're|i am|i'm|the (?:name|address|id|answer) is|call it|use|make it)\s+", Flags);

        /// <summary>"It's Acme Corp." is Acme Corp.</summary>
        public static string Answer(string text)
        {
            var t = LeadIn.Replace(text.Trim(), "").Trim().Trim('"', '“', '”', '`');
            return t.EndsWith('.') && !Regex.IsMatch(t, @"\b(?:Inc|Ltd|Corp|Co|S\.A|B\.V|Pty)\.$", Flags) ? t.TrimEnd('.') : t;
        }

        // ------------------------------------------------------------ is it that kind of value?

        static readonly Regex TenantId = new(@"^[A-Za-z0-9][A-Za-z0-9_-]{1,62}$", RegexOptions.CultureInvariant);
        static readonly Regex HostName = new(@"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", Flags);

        /// <summary>
        /// The value as it can be stored, or why it cannot be this setting. Catches what a small
        /// model mixes up (an email address offered as the public address) and what people leave
        /// out (the https:// of one).
        /// </summary>
        public static (string? Value, string? Problem) Shape(string key, string value)
        {
            value = value.Trim().TrimEnd(',', ';');
            switch (key)
            {
                case "server.base_url" or "audit.endpoint" or "organization.website_url" or "organization.terms_url" or "organization.privacy_url":
                    if (HostName.IsMatch(value)) value = "https://" + value;
                    return Uri.TryCreate(value, UriKind.Absolute, out var url) && url.Scheme is "http" or "https" ? (value, null)
                        : (null, "That does not look like an address. It starts with https://, for example https://id.example.com.");
                case "server.tenant_id":
                    return TenantId.IsMatch(value) ? (value, null) : (null, "A tenant id is 2 to 63 letters, digits, '_' or '-', without spaces.");
                case "administrator.username":
                    return value.Any(char.IsWhiteSpace) ? (null, "A login name has no spaces. An email address works.") : (value, null);
                case "email.from":
                    return value.Contains('@') && !value.Any(char.IsWhiteSpace) ? (value, null) : (null, "That does not look like an email address.");
                case "email.smtp" or "database.host":
                    return value.Any(char.IsWhiteSpace) || value.Contains('@') ? (null, "That does not look like a server name.") : (value, null);
                case "organization.company_name":
                    return value.Length <= 80 && !Address.IsMatch(value) ? (value, null) : (null, "That does not look like an organization's name.");
                case "protocol.cors_origins":
                    return Uri.TryCreate(value, UriKind.Absolute, out var origin) && origin.Scheme is "http" or "https" ? (origin.GetLeftPart(UriPartial.Authority), null)
                        : (null, "An origin is an address like https://app.example.com.");
                default:
                    return (value, null);
            }
        }

        // ------------------------------------------------------------ which settings does it touch?

        static readonly HashSet<string> Common = new(StringComparer.Ordinal)
        {
            "the", "and", "for", "are", "our", "you", "your", "with", "that", "this", "will", "have", "has", "was", "can", "not", "but", "from", "they", "them",
            "who", "what", "which", "how", "should", "would", "could", "does", "did", "its", "it's", "we're", "i'm", "use", "using", "used", "need", "want", "like",
            "there", "here", "when", "where", "also", "any", "all", "some", "one", "set", "server", "please", "about", "into", "their", "very", "just", "new", "people"
        };

        /// <summary>Words people use for settings that are called something else.</summary>
        static readonly Dictionary<string, string[]> Also = new(StringComparer.Ordinal)
        {
            ["react"] = new[] { "protocol.cors_origins" }, ["angular"] = new[] { "protocol.cors_origins" }, ["vue"] = new[] { "protocol.cors_origins" },
            ["spa"] = new[] { "protocol.cors_origins" }, ["frontend"] = new[] { "protocol.cors_origins" }, ["single-page"] = new[] { "protocol.cors_origins" },
            ["postgres"] = new[] { "database.provider" }, ["postgresql"] = new[] { "database.provider" }, ["mysql"] = new[] { "database.provider" }, ["sqlite"] = new[] { "database.provider" },
            ["dba"] = new[] { "database.provider", "database.host" }, ["admin"] = new[] { "administrator.username", "administrator.name" },
            ["mail"] = new[] { "email.smtp", "email.from" }, ["smtp"] = new[] { "email.smtp", "email.from" }, ["url"] = new[] { "server.base_url" },
            ["domain"] = new[] { "server.base_url" }, ["live"] = new[] { "server.base_url" }, ["hosted"] = new[] { "server.base_url" },
            ["company"] = new[] { "organization.company_name" }, ["timeout"] = new[] { "protocol.session_lifetime_minutes" }, ["logout"] = new[] { "protocol.enable_back_channel_logout" },
            ["attempts"] = new[] { "protocol.max_failed_sign_ins", "protocol.lockout_minutes" }, ["locked"] = new[] { "protocol.max_failed_sign_ins", "protocol.lockout_minutes" },
            ["2048"] = new[] { "signing_key.key_size" }, ["3072"] = new[] { "signing_key.key_size" }, ["4096"] = new[] { "signing_key.key_size" },
            ["privacy"] = new[] { "organization.privacy_url" }, ["terms"] = new[] { "organization.terms_url" }, ["consent"] = new[] { "protocol.always_require_consent" },
            ["tv"] = new[] { "protocol.enable_device_flow" }, ["devices"] = new[] { "protocol.enable_device_flow" }, ["subject"] = new[] { "email.subject" }
        };

        static HashSet<string> Terms(string text) =>
            Regex.Matches(text.ToLowerInvariant(), @"[a-z0-9][a-z0-9'-]+").Select(m => m.Value.Trim('\'', '-')).Where(w => (w.Length >= 3 || Also.ContainsKey(w)) && !Common.Contains(w)).ToHashSet(StringComparer.Ordinal);

        static bool Same(string a, string b) => a == b || (a.Length >= 5 && b.Length >= 5 && (a.StartsWith(b[..5], StringComparison.Ordinal) && Math.Abs(a.Length - b.Length) <= 4));

        /// <summary>
        /// The settings a message seems to be about, best first. Never a secret: a model is not
        /// asked to find one.
        /// </summary>
        public static List<Offered> Relevant(Workspace ws, Participant p, string message, int take, bool withOpenEssentials)
        {
            var words = Terms(message);
            var hinted = words.Where(Also.ContainsKey).SelectMany(w => Also[w]).ToHashSet(StringComparer.Ordinal);
            var offered = new List<Offered>();
            foreach (var section in ws.Catalogue.Where(s => p.May(s.Name)))
            {
                var status = ws.StatusOf(section.Name);
                var missing = (status?["missing"] as JsonArray)?.Select(m => m!.ToString()).ToHashSet() ?? new HashSet<string>();
                foreach (var f in section.Fields.Where(f => !f.Secret && f.Name is not ("host_logo" or "app_logo")))
                {
                    var key = $"{section.Name}.{f.Name}";
                    var names = Terms(f.Name.Replace('_', ' '));
                    // The section's title speaks for all its fields alike, so it counts for little:
                    // one mention of "database" must not crowd everything else out.
                    var about = Terms($"{section.Title} {f.Description} {f.Ask}");
                    var score = words.Sum(w => names.Any(n => Same(n, w)) ? 3 : about.Any(n => Same(n, w)) ? 1 : 0) + (hinted.Contains(key) ? 6 : 0);
                    if (withOpenEssentials && (f.Required || missing.Contains(f.Name)) && !ws.Has(key)) score += 100;
                    if (score > 0) offered.Add(new Offered(key, section, f, score));
                }
            }
            // At most four from any one section, its open essentials aside.
            var perSection = new Dictionary<string, int>(StringComparer.Ordinal);
            var chosen = new List<Offered>();
            foreach (var o in offered.OrderByDescending(o => o.Score))
            {
                if (chosen.Count >= take) break;
                var n = perSection.GetValueOrDefault(o.Section.Name);
                if (o.Score < 100 && n >= 4 && p.IsLead) continue;
                perSection[o.Section.Name] = n + 1;
                chosen.Add(o);
            }
            return chosen;
        }

        /// <summary>
        /// The whole of what was written where a model copied only a part: "dana.okafor" from
        /// "dana.okafor@acme.com". A part of an address is in the message, and is not what it says.
        /// </summary>
        public static string WholeToken(string message, string value)
        {
            value = value.Trim();
            if (value.Length == 0 || value.Any(char.IsWhiteSpace)) return value;
            string? longer = null;
            for (var at = message.IndexOf(value, StringComparison.OrdinalIgnoreCase); at >= 0; at = message.IndexOf(value, at + 1, StringComparison.OrdinalIgnoreCase))
            {
                int start = at, end = at + value.Length;
                while (start > 0 && Joins(message, start - 1)) start--;
                while (end < message.Length && Joins(message, end)) end++;
                var token = message[start..end].TrimEnd('.', '-', '/');
                if (token.Length <= value.Length) return value;     // stands on its own somewhere
                longer ??= token;
            }
            return longer ?? value;
        }

        /// <summary>A character that is inside an address or a name rather than beside it.</summary>
        static bool Joins(string text, int i) =>
            char.IsLetterOrDigit(text[i]) || text[i] is '@' or '/' or '_' or '+'
            || (text[i] is '.' or '-' or ':' && i + 1 < text.Length && (char.IsLetterOrDigit(text[i + 1]) || text[i + 1] == '/') && i > 0 && !char.IsWhiteSpace(text[i - 1]));

        // ------------------------------------------------------------ what code can read by itself

        static readonly Regex Place = new(@"https?://[^\s,;()<>""']+|(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?![\w@])", Flags);
        static readonly Regex Mail = new(@"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", Flags);
        static readonly Regex BrowserApp = new(@"\b(?:react|angular|vue|svelte|spa|single[- ]page|browser[- ]based)\b", Flags);
        static readonly Regex ServerPlace = new(
            @"\b(?:lives?|reach(?:ed|able)?|hosted|public (?:url|address|https address)|base url|base address|identity (?:server|provider)|idp|sign-?in (?:server|service)|sso|issuer)\b", Flags);
        static readonly Regex Company = new(
            @"(?<![\w])(?i:we are|we're|company(?: name)? is|organi[sz]ation(?: name)? is|on behalf of|i work (?:for|at)|this is for)\s+(?:(?i:the)\s+)?(?<name>[A-Z][\w&'-]*(?:\s+(?:[A-Z][\w&'-]*|of|and|&|de|van|von))*)",
            RegexOptions.CultureInvariant);
        static readonly Regex Tenant = new(@"\btenant(?:\s+id)?\s*(?:should be|must be|is|called|named|:|=)\s*[""'“`]?(?<id>[a-z0-9][a-z0-9_-]{1,62})\b", Flags);
        static readonly Regex Admin = new(@"\badmin(?:istrator)?s?\b", Flags);
        static readonly Regex Myself = new(@"\b(?:me|myself|i am|i'm|i will be|i'll be)\b", Flags);

        /// <summary>
        /// The values a message states in so many words: an address next to what it is the address
        /// of, the administrator's login, the organization's name. What code can read, no model is
        /// asked to, and what code read, no model's reading replaces.
        /// </summary>
        public static List<(string Key, string Value)> Stated(string message, Participant p)
        {
            var found = new List<(string Key, string Value)>();
            void Add(string key, string value)
            {
                value = value.Trim().TrimEnd('.', ',', ';', ':');
                if (value.Length > 0 && found.All(f => f.Key != key)) found.Add((key, value));
            }

            foreach (var sentence in Regex.Split(message, @"(?<=[.!?;])\s+|\r?\n").Where(s => s.Length > 0))
            {
                // Each address is described by the words between it and the one before.
                var from = 0;
                foreach (Match m in Place.Matches(sentence))
                {
                    var words = sentence[from..m.Index];
                    from = m.Index + m.Length;
                    if (BrowserApp.IsMatch(words)) Add("protocol.cors_origins", m.Value);
                    else if (Regex.IsMatch(words, @"\bprivacy\b", Flags)) Add("organization.privacy_url", m.Value);
                    else if (Regex.IsMatch(words, @"\bterms\b", Flags)) Add("organization.terms_url", m.Value);
                    else if (Regex.IsMatch(words, @"\b(?:website|home ?page)\b", Flags)) Add("organization.website_url", m.Value);
                    else if (Regex.IsMatch(words, @"\bsmtp\b", Flags)) Add("email.smtp", m.Value);
                    else if (Regex.IsMatch(words, @"\b(?:database|db|postgres\w*|mysql)\b", Flags)) Add("database.host", m.Value);
                    else if (ServerPlace.IsMatch(words)) Add("server.base_url", m.Value);
                }
                if (Admin.IsMatch(sentence) && Mail.Match(sentence) is { Success: true } login)
                {
                    Add("administrator.username", login.Value);
                    if (Myself.IsMatch(sentence) && p.Name.Contains(' ')) Add("administrator.name", p.Name);
                }
                else if (Regex.IsMatch(sentence, @"\b(?:from address|sender|sent from|send from|comes? from)\b", Flags) && Mail.Match(sentence) is { Success: true } sender) Add("email.from", sender.Value);
                if (Tenant.Match(sentence) is { Success: true } tenant) Add("server.tenant_id", tenant.Groups["id"].Value);
                if (Company.Match(sentence) is { Success: true } company)
                {
                    var name = Regex.Replace(company.Groups["name"].Value.Trim(), @"(?:\s+(?:of|and|&|de|van|von))+$", "");
                    if (name.Length >= 2 && !Regex.IsMatch(name, @"^(?:I|It|The|This|That|A|An|IT|Production|Prod|Our|My|Regulated|Using|On|In)$")) Add("organization.company_name", name);
                }
            }
            return found;
        }

        static readonly Regex Knows = new(
            @"\b(?:knows?|has (?:the|all|those|that)|have (?:the|those)|handles?|owns?|looks? after|in charge of|responsible for|ask|speak to|talk to|check with|don'?t know|do not know|no idea|not sure|(?:team|department|group) (?:does|do|will))\b", Flags);
        static readonly Regex Person = new(@"(?<![\w])(?!(?:I|The|We|Our|It|They|He|She|In|On|My|A|An|And|But|For|IT|DBA|HR|SMTP|Postgre\w*|MySQL|SQLite|Please|Ask|Also|Not|No)\b)(?<name>[A-Z][a-zà-ÿ]+(?:\s+[A-Z][a-zà-ÿ'-]+)?)", RegexOptions.CultureInvariant);

        static readonly (Regex Words, string Section)[] Subjects =
        {
            (new Regex(@"\b(?:databases?|dbas?|postgres\w*|mysql|connection string)\b", Flags), "database"),
            (new Regex(@"\b(?:e-?mails?|mail|smtp|messaging)\b(?!\s+(?:me|you|us|address))", Flags), "email"),
            (new Regex(@"\b(?:signing keys?|pki|certificates?)\b", Flags), "signing_key"),
            (new Regex(@"\b(?:audit|compliance)\b", Flags), "audit"),
            (new Regex(@"\b(?:logos?|brand(?:ing)?)\b", Flags), "branding")
        };

        /// <summary>"Priya in the DBA team has the database details": who to ask for what.</summary>
        public static List<(string Section, string? Name)> Colleagues(string message, string self)
        {
            var found = new List<(string Section, string? Name)>();
            foreach (var sentence in Regex.Split(message, @"(?<=[.!?;])\s+|\r?\n"))
            {
                if (!Knows.IsMatch(sentence)) continue;
                var text = Mail.Replace(Place.Replace(sentence, " "), " ");
                foreach (var (words, section) in Subjects)
                {
                    if (!words.IsMatch(text) || found.Any(f => f.Section == section)) continue;
                    // The first word of a sentence is capitalised whoever it is; a name there counts only with what follows it.
                    var name = Person.Matches(text).Select(m => m.Groups["name"].Value)
                        .FirstOrDefault(n => !n.Equals(self, StringComparison.OrdinalIgnoreCase) && !words.IsMatch(n)
                                             && Regex.IsMatch(text, Regex.Escape(n) + @"\s+(?:in|from|of|at|on|knows|has|handles|owns|looks|does|is|\()|(?:ask|to|with)\s+" + Regex.Escape(n)));
                    found.Add((section, name));
                }
            }
            return found;
        }

        /// <summary>The sentences in which nothing has been read yet.</summary>
        public static string Unread(string message, IEnumerable<string> read)
        {
            var values = read.ToList();
            return string.Join('\n', Regex.Split(message, @"(?<=[.!?;])\s+|\r?\n")
                .Where(s => s.Trim().Length > 0 && !values.Any(v => s.Contains(v, StringComparison.OrdinalIgnoreCase)) && Colleagues(s, "").Count == 0));
        }

        // ------------------------------------------------------------ asking for values

        const string Brief =
            "Read the MESSAGE of somebody who is setting up a company's sign-in server. Pick out the values it states for the KEYS below. " +
            "Copy each value exactly as it is written. Leave out every key the message gives no value for. Never guess. " +
            "Answer with one line of JSON and nothing else.\n\n";

        const string Example =
            "\nEXAMPLE\nMESSAGE: We are Zephyr Foods and the admin is kim@zephyr.example.\n" +
            "{\"values\":{\"organization.company_name\":\"Zephyr Foods\",\"administrator.username\":\"kim@zephyr.example\"}}\n\nMESSAGE: ";

        /// <summary>The prompt for one message, and whether only part of the message fitted.</summary>
        public static (string Prompt, List<Offered> Keys, bool Skimmed) Extraction(Workspace ws, Participant p, string message, int budget,
            IReadOnlyCollection<string>? known = null)
        {
            var keys = Relevant(ws, p, message, 12, withOpenEssentials: true).Where(k => known?.Contains(k.Key) != true).Take(8).ToList();
            var text = new StringBuilder(Brief).Append("KEYS\n");
            foreach (var k in keys)
                text.Append(k.Key).Append(" = ").Append(Clip(k.Field.Description, 64))
                    .Append(k.Field.Values != null ? $" One of: {string.Join(", ", k.Field.Values)}." : "").Append('\n');
            text.Append(Example);
            const string end = "\nJSON: ";
            var (fitted, skimmed) = Fit(message, Math.Max(200, budget - text.Length - end.Length - 8));
            return (text.Append(fitted.Replace('\n', ' ')).Append(end).ToString(), keys, skimmed);
        }

        /// <summary>A question, with the server's own words about the settings it touches. Null: nothing here to answer it from.</summary>
        public static string? Question(Workspace ws, Participant p, string message, int budget)
        {
            // One word in common with some description is chance, not a subject.
            var facts = Relevant(ws, p, message, 6, withOpenEssentials: false).Where(f => f.Score >= 2).ToList();
            if (facts.Count == 0) return null;
            var text = new StringBuilder("Answer the QUESTION of somebody setting up a sign-in server in at most two short plain sentences, using only the FACTS. ")
                .Append("If the FACTS do not answer it, say that you do not know.\n\nFACTS\n");
            foreach (var f in facts)
            {
                var now = ws.Values.TryGetValue(f.Key, out var v) && v != null ? $" Now: {v}." : f.Field.Default != null ? $" Default: {f.Field.Default}." : "";
                text.Append("- ").Append(f.Section.Title).Append(", ").Append(f.Field.Name.Replace('_', ' ')).Append(": ").Append(Clip(f.Field.Description, 150)).Append(now).Append('\n');
            }
            var question = Clip(message.Replace('\n', ' '), Math.Max(120, budget - text.Length - 30));
            return text.Append("\nQUESTION: ").Append(question).Append("\nANSWER: ").ToString();
        }

        static string Clip(string text, int length) => text.Length <= length ? text : text[..(length - 1)].TrimEnd() + "…";

        static readonly Regex Signal = new(@"[:=]|\d+|\b(?:admin(?:istrator)?|database|postgres\w*|mysql|smtp|mail|tenant|domain|session|company|organi[sz]ation|knows|ask)\b", Flags);

        // An address or a named subject says more than a number somewhere in a sentence.
        static int Weight(string line) =>
            Address.Matches(line).Count * 4 + Signal.Matches(line).Sum(m => char.IsLetter(m.Value[0]) ? 2 : 1);

        /// <summary>The message, or the parts of a long one that look like settings, in their own order.</summary>
        internal static (string Text, bool Skimmed) Fit(string message, int budget)
        {
            if (message.Length <= budget) return (message, false);
            var parts = Regex.Split(message, @"(?<=[.!?])\s+|\r?\n").Select((t, i) => (Text: t.Trim(), Index: i)).Where(t => t.Text.Length > 0).ToList();
            var kept = new SortedDictionary<int, string>();
            var room = budget;
            foreach (var part in parts.OrderByDescending(t => Weight(t.Text)).ThenBy(t => t.Index))
            {
                var take = Clip(part.Text, 240);
                if (take.Length + 1 > room) continue;
                kept[part.Index] = take;
                room -= take.Length + 1;
            }
            return (string.Join('\n', kept.Values), true);
        }

        // ------------------------------------------------------------ reading the answer

        static readonly HashSet<string> Nothing = new(StringComparer.OrdinalIgnoreCase)
        {
            "", "null", "none", "n/a", "na", "unknown", "not stated", "not given", "not specified", "not provided", "not mentioned", "undefined", "value", "…", "..."
        };

        public static Reading Parse(string raw, IReadOnlyList<Offered> keys)
        {
            var reading = new Reading();
            // "values" as asked, or the keys straight at the top, which small models also write, or
            // an object they forgot to close.
            var json = Reply.FirstObject(raw, "values") ?? Reply.FirstObject(raw);
            if (json == null) return reading;
            var values = json["values"] as JsonObject ?? json;
            foreach (var (name, value) in values.ToList())
            {
                if (name is "values" || value == null) continue;
                if (value is JsonObject nested && keys.Any(k => k.Section.Name == name))
                {
                    foreach (var (field, inner) in nested) Add($"{name}.{field}", inner);
                    continue;
                }
                Add(name, value);
            }
            return reading;

            void Add(string key, JsonNode? value)
            {
                var match = keys.FirstOrDefault(k => k.Key == key);
                if (match == null)
                {
                    var byField = keys.Where(k => k.Field.Name == key).ToList();
                    if (byField.Count == 1) match = byField[0];
                }
                if (match == null || value == null) return;
                if (value is JsonValue v && v.TryGetValue<string>(out var s) && Nothing.Contains(s.Trim())) return;
                if (reading.Values.All(x => x.Key != match.Key)) reading.Values.Add((match.Key, value.DeepClone()));
            }
        }

        /// <summary>A small model's prose, made fit to show: one paragraph, no markup, no runaway.</summary>
        public static string Plain(string raw)
        {
            var text = Regex.Replace(raw, @"[*_#`>]+|\s*\n\s*", m => m.Value.Contains('\n') ? " " : "").Trim().Trim('"');
            text = Regex.Replace(Regex.Replace(text, @"\s+", " ").Trim(), @"^answer\s*:\s*", "", Flags);
            if (text.Length <= 420) return text;
            var end = text.LastIndexOf('.', 420);
            return end > 80 ? text[..(end + 1)] : text[..420] + " …";
        }
    }
}
