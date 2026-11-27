using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Ark.Agents.TenantOnboarding.Brain
{
    /// <summary>What the model answered, read leniently: a model that adds a sentence around its JSON is still understood.</summary>
    internal sealed class Reply
    {
        public string Say { get; set; } = "";
        public List<(string Tool, JsonObject Args)> Actions { get; } = new();
        public List<(string Section, string Field, JsonNode? Value, string Why)> Proposals { get; } = new();
        public JsonArray Ask { get; } = new();
        public List<string> Remember { get; } = new();
        public bool Continue { get; set; }
        /// <summary>
        /// The answer stopped in mid-sentence: a gateway's length limit. What was complete before
        /// the cut is kept, and nothing that was not: half a value is not a value.
        /// </summary>
        public bool Truncated { get; set; }

        /// <summary>Cut off before anything usable was written.</summary>
        public bool Empty => Truncated && Actions.Count == 0 && Proposals.Count == 0 && Ask.Count == 0 && Say.Length == 0;

        public static Reply Parse(string raw)
        {
            var reply = new Reply();
            var json = FirstObject(raw, "say", "actions");
            if (json == null && Salvage(raw) is { } rescued)
            {
                json = rescued;
                reply.Truncated = true;
            }
            if (json == null)
            {
                // Not JSON at all: what it wrote is still an answer to the person. Unless it is the
                // opening of one that was cut off before anything in it was complete, or nothing.
                reply.Truncated = raw.Trim().Length == 0 || raw.TrimStart().StartsWith('{');
                reply.Say = reply.Truncated ? "" : raw.Trim();
                return reply;
            }

            reply.Say = json["say"] is JsonValue s && s.TryGetValue<string>(out var say) ? say.Trim() : "";
            foreach (var a in json["actions"] as JsonArray ?? new JsonArray())
                if (a is JsonObject action && action["tool"] is JsonValue t && t.TryGetValue<string>(out var tool))
                    reply.Actions.Add((tool, (action["args"] ?? action["arguments"]) is JsonObject args ? (JsonObject)args.DeepClone() : new JsonObject()));
            foreach (var p in json["propose"] as JsonArray ?? new JsonArray())
                if (p is JsonObject proposal && Text(proposal, "section") is { Length: > 0 } section && Text(proposal, "field") is { Length: > 0 } field)
                    reply.Proposals.Add((section, field, proposal["value"]?.DeepClone(), Text(proposal, "why") ?? ""));
            foreach (var a in json["ask"] as JsonArray ?? new JsonArray())
                if (a is JsonObject ask) reply.Ask.Add(ask.DeepClone());
            foreach (var n in json["remember"] as JsonArray ?? new JsonArray())
                if (n is JsonValue note && note.TryGetValue<string>(out var text)) reply.Remember.Add(text);
            reply.Continue = json["continue"] is JsonValue c && c.TryGetValue<bool>(out var more) && more;
            // A sentence that was cut off is still worth showing, marked as unfinished.
            if (reply.Truncated && reply.Say.Length == 0 && PartialSay.Match(raw) is { Success: true } said)
            {
                try { reply.Say = JsonNode.Parse('"' + said.Groups[1].Value.TrimEnd('\\') + '"')!.GetValue<string>().Trim() + " …"; }
                catch (JsonException) { }
            }
            return reply;
        }

        static readonly System.Text.RegularExpressions.Regex PartialSay = new("\"say\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)$");

        /// <summary>
        /// A JSON object that ends too early, cut back to the last point at which everything in it
        /// is whole, and closed. A string that was being written when the answer stopped is
        /// dropped with whatever it belonged to: "https://id." is not an address.
        /// </summary>
        static JsonObject? Salvage(string raw)
        {
            var start = raw.IndexOf('{');
            if (start < 0) return null;
            var text = raw[start..];
            var attempts = 0;
            for (var cut = text.Length; cut > 1 && attempts < 400; cut--)
            {
                var last = text[cut - 1];
                if (last is not ('}' or ']' or '"' or 'e' or 'l' or (>= '0' and <= '9'))) continue;

                var open = new Stack<char>();
                var inString = false;
                for (var i = 0; i < cut; i++)
                {
                    var c = text[i];
                    if (inString)
                    {
                        if (c == '\\') i++;
                        else if (c == '"') inString = false;
                    }
                    else if (c == '"') inString = true;
                    else if (c is '{' or '[') open.Push(c == '{' ? '}' : ']');
                    else if (c is '}' or ']' && open.Count > 0) open.Pop();
                }
                if (inString || open.Count == 0) continue;

                attempts++;
                try
                {
                    if (JsonNode.Parse(text[..cut] + string.Concat(open)) is JsonObject found
                        && (found.ContainsKey("say") || found.ContainsKey("actions") || found.ContainsKey("propose"))) return found;
                }
                catch (JsonException) { }
            }
            return null;
        }

        static string? Text(JsonObject o, string name) => o[name] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

        /// <summary>The first complete JSON object in the text, whatever surrounds it.</summary>
        internal static JsonObject? FirstObject(string raw, params string[] having)
        {
            for (var start = raw.IndexOf('{'); start >= 0; start = raw.IndexOf('{', start + 1))
            {
                var depth = 0;
                var inString = false;
                for (var i = start; i < raw.Length; i++)
                {
                    var c = raw[i];
                    if (inString)
                    {
                        if (c == '\\') i++;
                        else if (c == '"') inString = false;
                        continue;
                    }
                    if (c == '"') inString = true;
                    else if (c == '{') depth++;
                    else if (c == '}' && --depth == 0)
                    {
                        try
                        {
                            if (JsonNode.Parse(raw[start..(i + 1)]) is JsonObject found && (having.Length == 0 || having.Any(found.ContainsKey))) return found;
                        }
                        catch (JsonException) { }
                        break;
                    }
                }
            }
            return null;
        }
    }

    /// <summary>
    /// The agent's instructions, and each turn's account of the situation. Instructions are fixed
    /// text; everything that changes is in the message. A gateway that takes one string gets the
    /// two joined, and one that caches a prompt prefix can cache the first.
    /// </summary>
    internal static class Prompt
    {
        public static string Instructions(string agentName) => $$$"""
            You are {{{agentName}}}, the onboarding agent built into an Ark identity server (an OAuth 2.1 / OpenID Connect provider) that has not been set up yet. You are a senior identity architect who has stood up many identity providers: you know which decisions are permanent, which defaults are fine, and who inside a company holds each answer. Your job is to get this server installed with as little effort from people as possible, without ever guessing a fact.

            HOW YOU WORK
            - You are not a form. People tell you things in any order and paste emails, tickets, .env files, meeting notes. File every usable fact from a message where it belongs, in one go.
            - Only four values are required: organization.company_name, server.base_url, server.tenant_id, administrator.username. One more is owed unless users.password_mode is email_based: users.default_password, the password every account added in the admin console starts on (without it the console cannot add anybody). It is a secret: get it with an "ask" of type "secret", or offer to hand the section to whoever hands out accounts. Everything else has a default. Never walk through optional sections one by one. Raise one only when what you have learned makes its default wrong, and say why in one sentence.
            - Ask at most one question at a time, the most valuable one, and prefer offering choices to an open question.
            - A value the person stated goes in "actions". A value you worked out yourself (a tenant id from the company name, a setting your experience recommends) goes in "propose" with a one-line reason; they accept it with one click. Never put a guess in "actions", and never invent a fact such as an address, a host name or a person.
            - server.base_url and server.tenant_id become the issuer of every token and cannot be changed after install. When the person states one, put it in "actions" like any other stated value: the harness does not store it but turns it into a card for the person to confirm. So never say it is set; ask them to confirm it on the card, and say once that the two are permanent.
            - A question ("what would you recommend?", "what would you change?", "is that enough?") asks for your proposals, never for changes. Recommendations always go in "propose", however confident you are.
            - Speak the person's language, not the field names: "the public address", "the tenant id", "session length", never base_url or session_lifetime_minutes.
            - Secrets (passwords, keys, connection strings) never pass through you. Text like [[vault:3]] stands for a secret the harness is holding: use the placeholder, exactly as written, as the value. To get a secret you do not have, add an "ask" of type "secret". Never ask anyone to type a secret into the chat. Never ask for the administrator's password at all: they set it themselves through a one-time link after install.
            - When the person you are talking to would not know something, do not press them. Offer to hand that section to the colleague who does, with an "ask" of type "invite". Every section says who usually knows.
            - When SETUP STATUS says ready_for_review and you are talking to the lead, stop collecting: say in a sentence or two what will be assumed, and add an "ask" of type "review". You cannot install. Only the lead can, with a button, after reading the plan.
            - After storing database settings with a host, email settings or audit settings, test them in the same answer (setup_test_database, setup_test_email with "to", setup_test_audit) and set "continue" to true so you can say what the test found.
            - Be brief and plain: two or three sentences, no headings, no list of everything that remains, no repeating what the board beside the chat already shows. Write for a busy person who is not an identity specialist.
            - Answer at once. Do not deliberate before answering: the harness checks every action you take, so a wrong one costs nothing, while a long answer is cut off. Your whole answer, thinking included, has to fit in about 700 tokens. If there is more to do than fits, do the most important part and set "continue" to true.

            WHAT EXPERIENCE TELLS YOU (use it to propose, and give the reason)
            - A trial on one machine: SQLite and every default are right. Ask about nothing else.
            - Production: PostgreSQL or MySQL. SQLite is one file on one machine, and a second instance of the server is impossible with it. Outgoing email, so that new people activate their own accounts (users.password_mode email_based needs email enabled).
            - In a container, a Kubernetes pod or Azure App Service the data directory must be persistent storage, or the settings are gone at the next start. Say so when ENVIRONMENT says so.
            - Regulated or high-security organizations (banking, health, government): signing_key key_size 3072 or 4096; session_lifetime_minutes 60 to 120; max_failed_sign_ins 5 and lockout_minutes 30; always_require_consent true; an external audit trail; enable_device_flow false unless there are devices without a browser; require_pushed_authorization_requests true only if every client application supports it.
            - Single-page applications need their origins in protocol.cors_origins. Nothing else does.
            - enable_dynamic_registration is only needed for agents and applications that register themselves.
            - The public address must be https unless it is localhost. Someone on localhost who calls this production needs to give the real public address.
            - The first administrator should be a named person, by email address, not a shared "admin" account.
            - A tenant id is short, lower-case and names the organization (acme), not a product or an environment.
            - If ENVIRONMENT lists a database the host application already uses, offer the same database server with a separate database for identity, before asking which database to use.

            YOUR ANSWER
            Answer with one JSON object and nothing else: no prose before or after it, no code fence, written compactly on one line, with the keys in this order.
            {"actions":[{"tool":"setup_set_server","args":{"base_url":"https://id.example.com"}}],"propose":[{"section":"server","field":"tenant_id","value":"acme","why":"short form of the organization's name"}],"ask":[{"type":"choices","options":["PostgreSQL","MySQL","SQLite"]}],"remember":["a fact about this organization worth keeping for later turns"],"continue":false,"say":"what you say to the person, under 60 words (plain language; **bold** and `code` are allowed)"}
            Every key except "say" may be left out. One action per section: put all of a section's values in one setup_set call.
            "actions": the tools are setup_set_<section> (its args are that section's fields; an empty string removes a value), setup_clear {"section"}, setup_test_database {}, setup_test_email {"to"}, setup_test_audit {}. Leave "source" out: the harness records who supplied each value.
            "ask" items, any of:
              { "type": "choices", "options": ["…", "…"] }   buttons that answer your question; at most five, each a few words
              { "type": "secret", "section": "database", "field": "password", "label": "Password for ark_svc" }
              { "type": "invite", "sections": ["database"], "department": "Database administration", "why": "one line" }
              { "type": "review" }
            "continue": true only when you must see the results of your actions before you can say anything useful. You are then called once more with them.
            """;

        public static string Situation(Workspace ws, Participant p, string message, IReadOnlyList<Detection> found, string? results, string? note = null)
        {
            var text = new StringBuilder();
            lock (ws.Sync)
            {
                text.Append("YOU ARE TALKING TO\n");
                text.Append(p.Name.Length > 0 ? p.Name : "someone who has not given a name")
                    .Append(p.Department.Length > 0 ? $" ({p.Department})" : "");
                if (p.IsLead) text.Append(". Role: lead. May change every section, invite colleagues, review and install.\n");
                else
                    text.Append($". Role: contributor, invited for: {string.Join(", ", p.Sections)}. They may only change those sections. ")
                        .Append("Ask only about those. When they are complete and tested, thank them and tell them they are done; the lead is told.\n");

                // The host, its directories and the databases its application uses are the lead's to see.
                if (p.IsLead)
                {
                    text.Append("\nENVIRONMENT\n").Append(ws.Environment.ToJsonString()).Append('\n');
                    if (ws.Status["environment"] is JsonObject server) text.Append("server: ").Append(server.ToJsonString()).Append('\n');
                }
                if (p.Origin != null) text.Append("their browser reached this server at: ").Append(p.Origin).Append('\n');

                text.Append("\nSETUP STATUS\nready_for_review: ").Append(ws.ReadyForReview ? "true" : "false").Append('\n');
                foreach (var section in ws.Catalogue.Where(s => p.May(s.Name)))
                {
                    var status = ws.StatusOf(section.Name);
                    text.Append($"- {section.Name} ({section.Title}; usually known by {section.Owner}): {status?["status"]}");
                    if (status?["missing"] is JsonArray { Count: > 0 } missing) text.Append("; missing ").Append(string.Join(", ", missing.Select(m => m!.ToString())));
                    if (status?["problems"] is JsonArray { Count: > 0 } problems) text.Append("; problems ").Append(problems.ToJsonString());
                    if (status?["test"] is JsonObject test) text.Append("; last test ").Append(test.ToJsonString());
                    text.Append('\n');
                }

                text.Append("\nFIELDS (section.field | type | meaning | default | current value)\n");
                foreach (var section in ws.Catalogue.Where(s => p.May(s.Name)))
                    foreach (var f in section.Fields)
                    {
                        var key = $"{section.Name}.{f.Name}";
                        text.Append(key).Append(" | ").Append(f.Type);
                        if (f.Values != null) text.Append(" one of ").Append(string.Join("/", f.Values));
                        if (f.Required) text.Append(" REQUIRED");
                        if (f.Secret) text.Append(" SECRET");
                        text.Append(" | ").Append(f.Description).Append(" | ").Append(f.Default ?? "-").Append(" | ");
                        text.Append(ws.Values.TryGetValue(key, out var value) && value != null ? value.ToJsonString() : "-").Append('\n');
                    }

                if (p.IsLead && ws.Invites.Count > 0)
                {
                    text.Append("\nCOLLEAGUES ASKED\n");
                    foreach (var i in ws.Invites.Where(i => !i.Revoked))
                        text.Append($"- {i.Name ?? "someone"} in {i.Department} for {string.Join(", ", i.Sections)}: {i.Status(DateTime.UtcNow, 4)}\n");
                }
                if (ws.Notes(p) is { Count: > 0 } notes) text.Append("\nNOTES YOU KEPT\n").Append(string.Join('\n', notes.Select(n => "- " + n))).Append('\n');

                var open = ws.Proposals.Where(x => x.State == "open" && x.ParticipantId == p.Id).ToList();
                if (open.Count > 0)
                {
                    text.Append("\nPROPOSALS WAITING FOR THEIR CLICK (do not propose these again)\n");
                    foreach (var x in open) text.Append($"- {x.Section}.{x.Field} = {x.Value?.ToJsonString()}\n");
                }

                var history = ws.Conversations.TryGetValue(p.Id, out var list) ? list : new List<ChatMessage>();
                // The message being answered is the last one heard: it is given separately below.
                var earlier = history.Take(Math.Max(0, history.Count - 1)).TakeLast(16).ToList();
                if (earlier.Count > 0)
                {
                    text.Append("\nCONVERSATION SO FAR\n");
                    foreach (var m in earlier)
                        text.Append(m.From == "agent" ? "You: " : "Them: ").Append(Shorten(m.Text, 1500)).Append('\n');
                }
            }

            text.Append("\nTHEIR NEW MESSAGE\n").Append(message).Append('\n');
            if (found.Count > 0)
            {
                text.Append("\nFOUND IN THEIR MESSAGE BY THE HARNESS (secrets replaced by placeholders)\n");
                foreach (var d in found)
                    text.Append("- ").Append(d.Summary)
                        .Append(d.Section != null && d.Values != null ? $" As setup_set_{d.Section} args: {d.Values.ToJsonString()}" : "").Append('\n');
            }
            if (results != null) text.Append("\nRESULTS OF YOUR ACTIONS (now tell the person what happened; do not repeat the actions)\n").Append(results).Append('\n');
            if (note != null) text.Append('\n').Append(note).Append('\n');
            return text.ToString();
        }

        static string Shorten(string text, int length) => text.Length <= length ? text : text[..length] + " …";
    }
}
