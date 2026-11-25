using System.Data.Common;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Ark.Agents.TenantOnboarding.Brain
{
    /// <summary>Something the harness recognised in a message, with the tool call that would file it.</summary>
    internal sealed record Detection(string Summary, string? Section = null, JsonObject? Values = null);

    /// <summary>
    /// Takes secrets out of what people type before a model, a log or the state file sees it.
    ///
    /// People paste connection strings, .env files and settings, and write "the password is …"
    /// however often they are asked not to. Each secret found goes into the <see cref="Vault"/>
    /// under the name of the person who typed it, and the text carries its placeholder instead.
    /// What can be read off the secret without being one (the host of a connection string, its
    /// database, its account) is handed on in the clear, as a <see cref="Detection"/>, so nothing
    /// useful is lost.
    ///
    /// It goes by shape, so it errs on the side of taking too much: a word held back by mistake
    /// costs a question, a secret let through cannot be called back. A secret that is an ordinary
    /// word in an ordinary sentence still has no shape; that is what the lock button is for.
    /// </summary>
    internal static class Scrubber
    {
        const RegexOptions Flags = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

        // A message that cannot be read in this time is refused, never passed on half read.
        static readonly TimeSpan Limit = TimeSpan.FromSeconds(2);

        static Regex Rx(string pattern, RegexOptions options = Flags) => new(pattern, options, Limit);

        // Every kind of private key, and one that was cut off before its last line.
        static readonly Regex Pem = Rx(
            @"-----BEGIN (?<kind>(?:[A-Z0-9]+ )*)PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|\z)");

        // The password runs to the last '@': one that was not percent-encoded may have an '@' in it.
        static readonly Regex DatabaseUrl = Rx(
            @"\b(?<scheme>postgres(?:ql)?|mysql|mariadb)(?:\+\w+)?://(?<user>[^:@/\s]*):(?<password>\S+)@(?<host>[^:@/\s?""'`]+)(?::(?<port>\d{2,5}))?(?:/(?<database>[^\s?;""'`,]*))?(?:\?[^\s""'`]*)?");

        // scheme://user:password@host, whatever the scheme. A port followed by a path is not a password.
        static readonly Regex UrlPassword = Rx(@"\b(?<head>[a-z][a-z0-9+.-]{1,20}://[^:@/\s]*:)(?<value>(?!\d{2,5}[/?#])\S+)@");

        // …?password=…&sig=…
        static readonly Regex QuerySecret = Rx(
            @"(?<=[?&;])(?<head>(?:[a-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)|sig|signature|key|code)=)(?<value>[^&\s#""'`]{4,})");

        // A run of key=value pairs, as ADO.NET writes them. Where it starts; where it ends is found in code.
        static readonly Regex ConnectionStart = Rx(
            @"(?<![\w.])(?:Host|Server|Data Source|DataSource|Addr|Address|User ID|UserID|Uid|Username|Database|Initial Catalog)[ \t]*=");

        static readonly Regex WatchKey = Rx(@"\barkw_sk_[A-Za-z0-9_\-]{8,}", RegexOptions.CultureInvariant);

        // Credentials that say what they are.
        static readonly Regex Known = Rx(
            @"\b(?:eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{16,}" +
            @"|xox[abeoprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}|[sr]k_(?:live|test)_[A-Za-z0-9]{16,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}" +
            @"|npm_[A-Za-z0-9]{30,}|pypi-[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{30,}|hf_[A-Za-z0-9]{20,}|A(?:KIA|SIA)[0-9A-Z]{16}|oy2[a-z0-9]{43})",
            RegexOptions.CultureInvariant);

        static readonly Regex AuthorizationHeader = Rx(@"\b(?<head>(?:Bearer|Basic|Negotiate|ApiKey)\s+)(?<value>[A-Za-z0-9+/_=.~\-]{12,})");

        const string Core =
            @"pass(?:word|wd|phrase|code)?|pwd|secret|api[ _-]?key|access[ _-]?key|account[ _-]?key|private[ _-]?key|signing[ _-]?key|encryption[ _-]?key" +
            @"|master[ _-]?key|subscription[ _-]?key|shared[ _-]?key|client[ _-]?key|storage[ _-]?key|token";

        const string Quoted = @"""(?:[^""\\\r\n]|\\.)*""|'(?:[^'\\\r\n]|\\.)*'|`[^`\r\n]*`";

        // A line of an .env file: the value is the rest of it.
        static readonly Regex EnvLine = Rx(
            @"^(?<head>[ \t]*(?:export[ \t]+|set[ \t]+)?(?<label>[A-Z0-9_.]*(?:" + Core + @")(?:[_.\-]?[A-Z0-9_.\-]*)?)[ \t]*=[ \t]*)(?<value>[^\r\n]+)$",
            RegexOptions.CultureInvariant | RegexOptions.IgnoreCase | RegexOptions.Multiline);

        // label = value, "label": "value", label: value, label is value. The label may be the end of a longer name (DB_PASSWORD, clientSecret).
        static readonly Regex Labelled = Rx(
            @"(?<![A-Za-z0-9_.\-])(?<head>[""'`]?(?<label>[A-Za-z0-9_.\-]*(?:" + Core + @")(?:[_.\-][A-Za-z0-9_.\-]*|\d{1,3}|(?-i:[A-Z][A-Za-z0-9]*))?)[""'`]?" +
            @"(?<join>\s*(?:=>|:=|==?|:|->)\s*|\s+is\s+(?:=\s*|:\s*)?))(?<value>" + Quoted + @"|<[^<>\r\n]{1,60}>|(?:(?!;\s*[A-Za-z][A-Za-z _]{0,30}=)(?!,\s)\S)+)");

        // <add key="Password" value="…"/> and <password>…</password>
        static readonly Regex XmlAttribute = Rx(@"(?<head>(?:key|name)\s*=\s*""(?<label>[^""]*(?:" + Core + @")[^""]*)""\s+(?:value|connectionString)\s*=\s*"")(?<value>[^""]+)(?="")");
        static readonly Regex XmlElement = Rx(@"(?<head><(?<label>[A-Za-z0-9_.:\-]*(?:" + Core + @")[A-Za-z0-9_.\-]*)>\s*)(?<value>[^<\s][^<]*?)(?=\s*</)");

        // "the password for ark_svc is …", "credentials are svc / …", "password …"
        static readonly Regex Prose = Rx(
            @"\b(?<label>pass(?:word|wd|phrase|code)?|pwd|pw|secret|api[ _-]?key|access[ _-]?key|token|credentials?)\b(?<mid>[^\r\n.;:=?!]{0,60}?)(?:\s+(?:is|are|was)\s+|\s*[:=]\s*)(?<value>[^\r\n]{1,200})");
        static readonly Regex Bare = Rx(@"\b(?:password|passwd|passphrase|pwd|pw)\s+(?<value>\S{6,})");

        // A long run with capitals, small letters and digits in it: a key, until somebody says otherwise.
        static readonly Regex LongRun = Rx(@"(?<![A-Za-z0-9+/_=.~@\-])(?<!base64,)[A-Za-z0-9+/_=~\-]{28,}(?![A-Za-z0-9+/_=~\-])", RegexOptions.CultureInvariant);

        // password_mode, token_lifetime, TOKEN_ENDPOINT, AWS_ACCESS_KEY_ID: about a secret, not one.
        static readonly Regex AboutOne = Rx(
            @"(?:[_.\- ]|(?-i:(?<=[a-z0-9])(?=[A-Z])))(?:mode|policy|lifetime|length|minutes?|hours?|days?|seconds?|expir(?:y|es?|ation)(?:_?(?:in|at|minutes|days))?|ttl|url|uri|endpoint|file|path|id|name|type|method|issuer|audience|header|hint|count|size|format|required|enabled|reset|rotation|min|max|attempts)$" +
            @"|(?:^|[^a-z])(?:bypass|compass|encompass|trespass|overpass|surpass)$");
        static readonly Regex AboutOneInProse = Rx(@"\b(?:polic(?:y|ies)|modes?|lifetimes?|length|endpoints?|urls?|uris?|types?|formats?|methods?|resets?|links?|rotation|managers?|expiry|authentication|audience|issuer)\b");

        static readonly Regex StandsForOne = Rx(@"^(?:\$\{?[\w.:\-]+\}?|\$\([^)]*\)|%\w+%|<[^>]*>|\{\{?[^}]*\}?\}|\*{2,}|x{3,}|•+|\.{3,}|…|\(set\))$");
        static readonly Regex Address = Rx(@"^(?:[a-z][a-z0-9+.-]*://\S+|[^@\s]+@[^@\s]+\.[^@\s]+|(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?::\d+)?|\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?|[\d.,:/\-]+)$");
        static readonly Regex Guid = Rx(@"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$");

        // "the password is required": words that follow such a label without being one.
        static readonly HashSet<string> NotSecrets = new(StringComparer.OrdinalIgnoreCase)
        {
            "required", "optional", "missing", "needed", "unknown", "wrong", "correct", "empty", "blank", "none", "null", "same", "different",
            "there", "here", "that", "this", "what", "which", "something", "anything", "nothing", "with", "from", "they", "them", "their",
            "your", "yours", "mine", "have", "having", "will", "would", "should", "could", "must", "been", "being", "kept", "held", "stored",
            "given", "sent", "coming", "pending", "later", "tomorrow", "today", "soon", "about", "also", "already", "always", "never", "only",
            "mode", "link", "reset", "policy", "based", "managed", "generated", "generate", "rotated", "expired", "changed", "going", "known",
            "secret", "password", "safe", "secure", "weak", "strong", "long", "short", "good", "fine", "okay", "ready", "done", "tbd", "todo",
            "[[vault", "true", "false", "bearer", "basic", "undefined", "not", "in", "on", "the", "an", "and", "for", "held.", "set", "unset"
        };

        /// <summary>
        /// The message with its secrets replaced, and what was recognised in it. The secrets are
        /// <paramref name="owner"/>'s: nobody else's turn can use their placeholders.
        /// </summary>
        /// <param name="setupCode">
        /// The server's setup code, if the agent holds it. Whoever has it becomes the administrator,
        /// so it is cut out of a message altogether and not even held.
        /// </param>
        public static (string Clean, List<Detection> Found) Scrub(string text, Vault vault, string owner, string? setupCode = null)
        {
            var found = new List<Detection>();

            string Hold(string secret, string what)
            {
                var held = vault.Put(secret, owner);
                found.Add(new Detection($"A secret written in the message ({what}), now held as {held}."));
                return held;
            }

            if (setupCode?.Where(char.IsLetterOrDigit).ToArray() is { Length: >= 8 } code)
            {
                var without = Regex.Replace(text, string.Join(@"[-\s]?", code.Select(c => Regex.Escape(c.ToString()))), "[the setup code, removed]", Flags, Limit);
                if (without != text) found.Add(new Detection("The server's setup code was in the message and has been taken out. It is not needed: the harness holds it."));
                text = without;
            }

            // A secret this person has given before, wherever it turns up again.
            foreach (var (held, secret) in vault.Of(owner))
                if (secret.Length >= 8 && LooksSecret(secret)) text = text.Replace(secret, held, StringComparison.Ordinal);

            text = Pem.Replace(text, m =>
            {
                var held = vault.Put(m.Value, owner);
                var kind = m.Groups["kind"].Value.Trim().ToUpperInvariant();
                found.Add(kind is "" or "RSA" or "ENCRYPTED" && m.Value.Contains("-----END", StringComparison.OrdinalIgnoreCase)
                    ? new Detection("An RSA private key. If it is the token signing key to import: signing_key mode import.",
                        "signing_key", new JsonObject { ["mode"] = "import", ["private_key"] = held })
                    : new Detection($"A private key that cannot be the token signing key (not a whole RSA key), now held as {held}."));
                return held;
            });

            text = DatabaseUrl.Replace(text, m =>
            {
                var provider = m.Groups["scheme"].Value.StartsWith("postgres", StringComparison.OrdinalIgnoreCase) ? "postgres" : "mysql";
                var values = new JsonObject { ["provider"] = provider, ["host"] = m.Groups["host"].Value };
                if (m.Groups["database"].Value is { Length: > 0 } database) values["database"] = Uri.UnescapeDataString(database);
                if (m.Groups["user"].Value is { Length: > 0 } user) values["username"] = Uri.UnescapeDataString(user);
                values["password"] = vault.Put(Uri.UnescapeDataString(m.Groups["password"].Value), owner);
                if (int.TryParse(m.Groups["port"].Value, out var port)) values["port"] = port;
                found.Add(new Detection($"A {provider} database address.", "database", values));
                return Describe(values);
            });

            text = ReplaceConnectionStrings(text, raw =>
            {
                var values = Parse(raw, vault, owner, bind: false, out var note);
                if (values == null) return raw;
                found.Add(new Detection(note, note.StartsWith("A SQL Server", StringComparison.Ordinal) ? null : "database", values));
                return Describe(values);
            });

            text = WatchKey.Replace(text, m =>
            {
                var held = vault.Put(m.Value, owner);
                found.Add(new Detection("An ARK-RAPID Watch API key, for the audit trail.", "audit", new JsonObject { ["api_key"] = held }));
                return held;
            });

            text = UrlPassword.Replace(text, m => Held(m.Groups["value"].Value) ? m.Value
                : m.Groups["head"].Value + Hold(Uri.UnescapeDataString(m.Groups["value"].Value), "a password in an address") + "@");
            text = QuerySecret.Replace(text, m => Held(m.Groups["value"].Value) || StandsForOne.IsMatch(m.Groups["value"].Value) ? m.Value
                : m.Groups["head"].Value + Hold(Uri.UnescapeDataString(m.Groups["value"].Value), "in an address"));
            text = Known.Replace(text, m => Hold(m.Value, "a token"));
            text = AuthorizationHeader.Replace(text, m => m.Groups["value"].Value.Any(char.IsDigit) || m.Groups["value"].Length >= 24
                ? m.Groups["head"].Value + Hold(m.Groups["value"].Value, "an authorization header") : m.Value);

            text = EnvLine.Replace(text, m =>
            {
                var value = m.Groups["value"].Value.Trim();
                // On a line that goes on after the value ("password = x and the host is y") the next rule is the better reader.
                if (value.Contains(' ') && !IsQuoted(value) && !m.Groups["label"].Value.Contains('_')) return m.Value;
                return Secret(m.Groups["label"].Value, value, 3) is { } secret ? m.Groups["head"].Value + Hold(secret, m.Groups["label"].Value) : m.Value;
            });
            text = XmlAttribute.Replace(text, m => Secret(m.Groups["label"].Value, m.Groups["value"].Value, 3) is { } s ? m.Groups["head"].Value + Hold(s, m.Groups["label"].Value) : m.Value);
            text = XmlElement.Replace(text, m => Secret(m.Groups["label"].Value, m.Groups["value"].Value, 3) is { } s ? m.Groups["head"].Value + Hold(s, m.Groups["label"].Value) : m.Value);

            text = Labelled.Replace(text, m =>
            {
                var raw = m.Groups["value"].Value;
                // In a sentence the full stop after it, or the bracket, is not part of it.
                var value = IsQuoted(raw) ? raw : raw.TrimEnd(m.Groups["join"].Value.Trim() == "=" ? new[] { ',', ')', ']', '}' } : new[] { '.', ',', ';', ')', ']', '}' });
                if (Secret(m.Groups["label"].Value, value, 4) is not { } secret) return m.Value;
                var held = Hold(secret, m.Groups["label"].Value);
                return m.Groups["head"].Value + (IsQuoted(raw) ? $"{raw[0]}{held}{raw[0]}" : held + raw[value.Length..]);
            });

            text = Prose.Replace(text, m =>
            {
                // Something between the label and the value ("for ark_svc"): only what looks like a secret is taken for one.
                // It is the first word, unless it is credentials that were announced: then it is any of them.
                if (AboutOneInProse.IsMatch(m.Groups["mid"].Value)) return m.Value;
                var start = m.Groups["value"].Index - m.Index;
                var any = m.Groups["label"].Value.StartsWith("cred", StringComparison.OrdinalIgnoreCase);
                var first = true;
                return m.Value[..start] + Words(m.Groups["value"].Value, word =>
                {
                    var mine = any || first;
                    first = false;
                    return mine && LooksSecret(word) ? Hold(word, m.Groups["label"].Value) : null;
                });
            });
            text = Bare.Replace(text, m => m.Value[..(m.Groups["value"].Index - m.Index)]
                + Words(m.Groups["value"].Value, word => LooksSecret(word) ? Hold(word, "password") : null));

            text = LongRun.Replace(text, m => LooksLikeAKey(m.Value) ? Hold(m.Value, "something that looks like a key") : m.Value);

            return (text, found);
        }

        // ------------------------------------------------------------ is it one?

        static bool Held(string value) => value.Contains("[[vault:", StringComparison.Ordinal);

        static bool IsQuoted(string value) => value.Length >= 2 && value[0] is '"' or '\'' or '`' && value[^1] == value[0];

        static string Unquote(string value) => !IsQuoted(value) ? value : value[0] == '`' ? value[1..^1] : value[1..^1].Replace("\\" + value[0], value[0].ToString()).Replace("\\\\", "\\");

        /// <summary>The secret a labelled value holds, or null: a word about one, a stand-in for one, or too short.</summary>
        static string? Secret(string label, string value, int atLeast)
        {
            if (AboutOne.IsMatch(label)) return null;
            value = Unquote(value.Trim());
            if (value.Length < atLeast || Held(value) || StandsForOne.IsMatch(value) || NotSecrets.Contains(value.TrimEnd('.', '!', '?', ','))) return null;
            // token: 3600
            if (label.EndsWith("token", StringComparison.OrdinalIgnoreCase) && value.Length < 8 && value.All(char.IsDigit)) return null;
            return value;
        }

        /// <summary>A word that is more like a password than like a word: several kinds of character, and not an address.</summary>
        static bool LooksSecret(string word)
        {
            if (word.Length < 6 || Held(word) || Address.IsMatch(word) || StandsForOne.IsMatch(word) || Guid.IsMatch(word)) return false;
            var kinds = (word.Any(char.IsLower) ? 1 : 0) + (word.Any(char.IsUpper) ? 1 : 0) + (word.Any(char.IsDigit) ? 1 : 0) + (word.Any(c => !char.IsLetterOrDigit(c)) ? 1 : 0);
            return kinds >= 3 || (word.Length >= 8 && word.Any(char.IsDigit) && word.Any(char.IsLetter));
        }

        static bool LooksLikeAKey(string run) =>
            run[0] != '/' && !Guid.IsMatch(run) && run.Any(char.IsUpper) && run.Any(char.IsLower) && run.Count(char.IsDigit) >= 2 && run.Distinct().Count() >= 14
            // A path or a sentence joined with hyphens has short parts; a key does not.
            && run.Split('/', '-', '_').Max(part => part.Length) >= 12;

        /// <summary>The text with some of its words replaced; the punctuation around a word stays where it was.</summary>
        static string Words(string text, Func<string, string?> replace) => Regex.Replace(text, @"\S+", m =>
        {
            var word = m.Value.TrimStart('(', '"', '\'', '`', '“').TrimEnd('.', ',', ';', ')', '"', '\'', '`', '”');
            return word.Length > 0 && replace(word) is { } by ? m.Value.Replace(word, by, StringComparison.Ordinal) : m.Value;
        }, RegexOptions.CultureInvariant, Limit);

        // ------------------------------------------------------------ connection strings

        static string ReplaceConnectionStrings(string text, Func<string, string> replace)
        {
            var output = new StringBuilder();
            var at = 0;
            while (at < text.Length && ConnectionStart.Match(text, at) is { Success: true } m)
            {
                var (end, pairs) = ConnectionEnd(text, m.Index);
                if (pairs < 2)
                {
                    output.Append(text, at, m.Index + m.Length - at);
                    at = m.Index + m.Length;
                    continue;
                }
                output.Append(text, at, m.Index - at).Append(replace(text[m.Index..end]));
                at = end;
            }
            return output.Append(text, at, text.Length - at).ToString();
        }

        /// <summary>
        /// Where a run of pairs ends. A value may be quoted, and may have spaces in it when another
        /// pair follows; otherwise it ends at white space, so that the sentence a connection string
        /// was pasted into is not read as part of it.
        /// </summary>
        static (int End, int Pairs) ConnectionEnd(string text, int start)
        {
            var pairs = 0;
            var at = start;
            while (true)
            {
                var value = text.IndexOf('=', at) + 1;
                while (value < text.Length && text[value] is ' ' or '\t') value++;
                int end;
                var closing = value < text.Length && text[value] is '"' or '\'' ? Closing(text, value) : -1;
                if (closing >= 0) end = closing + 1;
                else
                {
                    var semicolon = text.IndexOf(';', value);
                    var line = text.IndexOfAny(new[] { '\r', '\n' }, value);
                    if (semicolon >= 0 && (line < 0 || semicolon < line) && KeyAt(text, semicolon + 1)) end = semicolon;
                    else
                    {
                        end = value;
                        while (end < text.Length && text[end] != ';' && !char.IsWhiteSpace(text[end])) end++;
                    }
                }
                pairs++;
                var next = end;
                while (next < text.Length && text[next] is ' ' or '\t') next++;
                if (next >= text.Length || text[next] != ';') return (end, pairs);
                if (!KeyAt(text, next + 1)) return (next == end ? next + 1 : end, pairs);
                at = next + 1;
            }
        }

        static int Closing(string text, int open)
        {
            for (var i = open + 1; i < text.Length; i++)
            {
                if (text[i] != text[open]) continue;
                if (i + 1 < text.Length && text[i + 1] == text[open]) { i++; continue; }    // doubled: part of the value
                return i;
            }
            return -1;
        }

        static bool KeyAt(string text, int at)
        {
            while (at < text.Length && char.IsWhiteSpace(text[at])) at++;
            var start = at;
            while (at < text.Length && at - start < 40 && (char.IsAsciiLetter(text[at]) || text[at] is ' ' or '_')) at++;
            return at > start && char.IsAsciiLetter(text[start]) && at < text.Length && text[at] == '=';
        }

        static string Describe(JsonObject values)
        {
            var parts = values.Where(p => p.Value != null).Select(p => $"{p.Key}={p.Value!.ToString()}");
            return $"[database: {string.Join(", ", parts)}]";
        }

        /// <summary>A key=value connection string as the setup tools' database fields, the password in the vault.</summary>
        static JsonObject? Parse(string raw, Vault vault, string owner, bool bind, out string note)
        {
            note = "";
            DbConnectionStringBuilder b;
            try { b = new DbConnectionStringBuilder { ConnectionString = raw }; }
            catch (ArgumentException) { return null; }

            string? Get(params string[] names) => names.Select(n => b.TryGetValue(n, out var v) ? v?.ToString() : null).FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));

            var host = Get("host", "server", "data source", "datasource", "addr", "address");
            if (host == null) return null;
            var database = Get("database", "initial catalog");
            var user = Get("username", "user id", "userid", "uid", "user", "user name");
            var password = Get("password", "pwd");
            var port = Get("port");

            // SQLite: a file, and nothing secret about it.
            if (database == null && user == null && password == null && Regex.IsMatch(host, @"\.(db|sqlite3?)$|^:memory:$", Flags))
            {
                note = "A SQLite database file.";
                return new JsonObject { ["provider"] = "sqlite", ["sqlite_file"] = host };
            }
            if (user == null && password == null && database == null) return null;

            var sqlServer = b.ContainsKey("initial catalog") || b.ContainsKey("trusted_connection") || b.ContainsKey("integrated security")
                            || b.ContainsKey("trustservercertificate") || b.ContainsKey("multipleactiveresultsets") || host.Contains(",1433", StringComparison.Ordinal);
            if (sqlServer)
            {
                if (password != null) vault.Put(password, owner);
                note = "A SQL Server connection string. This identity server runs on PostgreSQL, MySQL or SQLite, not SQL Server.";
                return new JsonObject { ["unsupported"] = "sqlserver", ["host"] = host };
            }

            // Npgsql says Host and Username; MySQL says Server and Uid/User ID. The port settles a tie.
            var provider = port == "3306" || b.ContainsKey("uid") || (b.ContainsKey("server") && !b.ContainsKey("host") && port != "5432") ? "mysql" : "postgres";
            var values = new JsonObject { ["provider"] = provider, ["host"] = host };
            if (int.TryParse(port, out var number)) values["port"] = number;
            if (database != null) values["database"] = database;
            if (user != null) values["username"] = user;
            if (password != null) values["password"] = vault.Put(password, owner, bind ? host : null);
            var ssl = Get("ssl mode", "sslmode");
            if (ssl != null)
                values["ssl"] = ssl.StartsWith("req", StringComparison.OrdinalIgnoreCase) || ssl.StartsWith("verify", StringComparison.OrdinalIgnoreCase) ? "require"
                    : ssl.StartsWith("dis", StringComparison.OrdinalIgnoreCase) || ssl.Equals("none", StringComparison.OrdinalIgnoreCase) ? "disable" : "prefer";
            note = $"A {(provider == "mysql" ? "MySQL" : "PostgreSQL")} connection string.";
            return values;
        }

        /// <summary>
        /// The same reading for a connection string the host application already has in its
        /// configuration: what kind of database, and where. Its password belongs to the application,
        /// not to anybody in the conversation: only the lead's turn can use it, and only for that host.
        /// </summary>
        public static JsonObject? Classify(string connectionString, Vault vault)
        {
            var values = Parse(connectionString, vault, Vault.Application, bind: true, out _);
            return values == null || values["unsupported"] != null || values["provider"]?.GetValue<string>() == "sqlite" ? null : values;
        }
    }
}
