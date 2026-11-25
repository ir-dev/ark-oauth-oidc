using System.Collections.Concurrent;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Ark.Agents.TenantOnboarding.Llm;
using Ark.Agents.TenantOnboarding.Mcp;
using Microsoft.Extensions.Logging;

namespace Ark.Agents.TenantOnboarding.Brain
{
    /// <summary>
    /// The harness: what stands between a language model and the identity server's setup tools.
    ///
    /// The model reads what people say and proposes tool calls. Everything that matters is decided
    /// here, in code, where a clever sentence cannot change it:
    ///
    /// * who may change which section (a colleague's link reaches the sections it names);
    /// * that a value is one somebody actually gave: a string the model produced that nobody typed
    ///   becomes a proposal to click, never a stored value;
    /// * that the two permanent values, the public address and the tenant id, are confirmed by a
    ///   person each time;
    /// * that secrets go from the person to the server without the model seeing them;
    /// * that who supplied a value is recorded from who was signed in to the conversation, not
    ///   from what the model says;
    /// * and that the install is a button only the lead has, on a plan they were shown.
    ///
    /// With no model, or when the model does not answer, the same harness asks the server's own
    /// questions one at a time (guided mode), so setup never depends on a gateway being up.
    /// </summary>
    internal sealed class AgentBrain
    {
        static readonly HashSet<string> Permanent = new(StringComparer.Ordinal) { "server.base_url", "server.tenant_id" };

        readonly Workspace _ws;
        readonly McpClient _mcp;
        readonly IArkAgentModel? _model;
        readonly ArkOnboardingAgentOptions _options;
        readonly ILogger _log;
        readonly Func<string?> _setupCode;
        readonly ConcurrentDictionary<string, SemaphoreSlim> _turns = new(StringComparer.Ordinal);

        public AgentBrain(Workspace ws, McpClient mcp, IArkAgentModel? model, ArkOnboardingAgentOptions options, ILogger log, Func<string?>? setupCode = null)
        {
            _setupCode = setupCode ?? (() => null);
            _ws = ws;
            _mcp = mcp;
            _model = model;
            _options = options;
            _log = log;
        }

        public string? ModelLabel => _model?.Label;

        /// <summary>A small model is in use: asked little, and only to read free text.</summary>
        public bool SmallModel => _model?.SmallPromptChars != null;

        /// <summary>The server's own questions lead the conversation: there is no model, or a small one that only reads.</summary>
        bool Guided => _model == null || SmallModel;

        /// <summary>One person's turns happen one after another; different people do not wait for each other.</summary>
        public async Task<IDisposable> EnterAsync(Participant p, CancellationToken cancel)
        {
            var gate = _turns.GetOrAdd(p.Id, _ => new SemaphoreSlim(1, 1));
            await gate.WaitAsync(cancel);
            return new Releaser(gate);
        }

        sealed class Releaser : IDisposable
        {
            readonly SemaphoreSlim _gate;
            public Releaser(SemaphoreSlim gate) => _gate = gate;
            public void Dispose() => _gate.Release();
        }

        // ------------------------------------------------------------ the server's account

        public async Task RefreshAsync(CancellationToken cancel)
        {
            var status = await _mcp.CallAsync("setup_status", null, cancel);
            var fields = await _mcp.CallAsync("setup_fields", null, cancel);
            _ws.Absorb(status.Content, fields.Content);
        }

        JsonObject Source(Participant p, string? note) => new()
        {
            ["department"] = p.Department.Length > 0 ? p.Department : p.IsLead ? "Setup lead" : "Colleague",
            ["provided_by"] = p.Name.Length > 0 ? p.Name : "unnamed",
            // A colleague types their own name. Which link they came by is not theirs to say.
            ["reference"] = $"{_options.AgentName} conversation" + (InviteOf(p) is { } invite ? $", by the link made for {invite.Name ?? "a colleague"} in {invite.Department}" : ""),
            ["note"] = note ?? "typed in the conversation"
        };

        Invite? InviteOf(Participant p)
        {
            if (p.InviteId == null) return null;
            lock (_ws.Sync) return _ws.Invites.FirstOrDefault(i => i.Id == p.InviteId);
        }

        // ------------------------------------------------------------ greeting

        public void Greet(Participant p)
        {
            if (p.Greeted) return;
            p.Greeted = true;
            var guided = Guided;

            if (!p.IsLead)
            {
                var titles = p.Sections.Select(s => _ws.Section(s)?.Title ?? s).ToList();
                var company = _ws.ValueText("organization.company_name");
                var lead = _ws.People.Values.FirstOrDefault(x => x.IsLead && x.Name.Length > 0)?.Name;
                var intro = new StringBuilder($"Hello {First(p.Name)}. ")
                    .Append(lead != null ? $"{lead} is" : "A colleague is")
                    .Append($" setting up {(company != null ? company + "'s" : "your organization's")} sign-in service and asked for your help with **{string.Join(" and ", titles)}**. ")
                    .Append("Tell me what you know in your own words, or paste it: a connection string, a ticket, an email. ")
                    .Append("Anything secret goes through the lock button, never into the chat, and nothing is installed without their sign-off.");
                _ws.Say(p, intro.ToString());
                if (guided) AskNext(p, null);
                else
                {
                    var questions = Questions(p.Sections).Take(5).ToList();
                    if (questions.Count > 0) _ws.Say(p, "What I am hoping you can tell me:\n" + string.Join('\n', questions.Select(q => "- " + q)));
                }
                return;
            }

            var found = new List<string>();
            var server = _ws.Status["environment"] as JsonObject;
            found.Add($"This is a **{_ws.Environment["environment"]}** server running on {_ws.Environment["hosting"]}.");
            if (server?["data_directory_writable"]?.GetValue<bool>() == false)
                found.Add($"⚠ It cannot write to its data directory (`{server["data_directory"]}`). That has to be fixed before anything can be installed.");
            foreach (var advice in _ws.Environment["advice"] as JsonArray ?? new JsonArray()) found.Add(advice!.ToString());
            foreach (var db in _ws.Environment["application_databases"] as JsonArray ?? new JsonArray())
                found.Add($"The application I live in already uses a {(db!["provider"]!.ToString() == "mysql" ? "MySQL" : "PostgreSQL")} server at `{db["host"]}`. Identity could have its own database there.");
            var resumed = _ws.Values.Count > 0;

            var hello = new StringBuilder($"Hi {First(p.Name)}, I'm {_options.AgentName}. I'll get this identity server set up with you, and there is no form to fill in. ");
            if (resumed) hello.Append("Some of it is collected already: the board shows where things stand. ");
            hello.Append(_model == null
                ? "I only need four things, and everything else has a sensible default."
                : guided
                ? "I only need four things, and everything else has a sensible default. Answer one at a time, or tell me everything at once: " +
                  "I read plain sentences and pasted text too, and I check with you before I keep anything I read. " +
                  "I run on a small model, so a long message takes me a little while."
                : "Tell me about it in your own words, or paste whatever you have: an email, a ticket, an `.env` file, a connection string. " +
                  "I only *need* four things (your organization's name, the address people will reach this server at, a short tenant id, and who the first administrator is). " +
                  "Everything else has a sensible default, and I will say so when a default is wrong for you.");
            _ws.Say(p, hello.ToString(), new JsonArray(new JsonObject
            {
                ["type"] = "found",
                ["items"] = new JsonArray(found.Select(f => (JsonNode?)JsonValue.Create(f)).ToArray())
            }));

            var starts = new JsonObject { ["type"] = "choices", ["options"] = new JsonArray(Advisor.Trial, Advisor.Production, Advisor.Regulated, Advisor.Others) };
            if (guided) AskNext(p, null, extra: resumed ? null : new JsonArray(starts));
            else if (!resumed) _ws.Say(p, "Where would you like to start?", new JsonArray(starts));
        }

        /// <summary>"Database administration" in mid-sentence; "IT or platform engineering" as it is.</summary>
        internal static string Lower(string phrase) =>
            phrase.Length > 1 && char.IsUpper(phrase[0]) && char.IsLower(phrase[1]) ? char.ToLowerInvariant(phrase[0]) + phrase[1..] : phrase;

        static string First(string name) => name.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "there";

        /// <summary>The server's own questions for what is still open in some sections.</summary>
        IEnumerable<string> Questions(IEnumerable<string> sections)
        {
            foreach (var name in sections)
            {
                if (_ws.Section(name) is not { } section) continue;
                var missing = (_ws.StatusOf(name)?["missing"] as JsonArray)?.Select(m => m!.ToString()).ToHashSet() ?? new HashSet<string>();
                // Nothing collected yet: the section's opening question, and what has no default.
                var nothingYet = _ws.StatusOf(name)?["status"]?.ToString() == "default";
                for (var i = 0; i < section.Fields.Length; i++)
                {
                    var f = section.Fields[i];
                    if (missing.Contains(f.Name) || (nothingYet && !f.Secret && (i == 0 || f.Default == null) && f.Name != "connection_string"))
                        yield return f.Ask;
                }
            }
        }

        // ------------------------------------------------------------ a turn

        public async Task TurnAsync(Participant p, string text, CancellationToken cancel)
        {
            var (clean, found) = Scrubber.Scrub(text, _ws.Vault, p.Id, _setupCode());
            _ws.Heard(p, clean);
            _ws.Touch();
            await RefreshAsync(cancel);

            var receipts = new List<Receipt>();
            var proposals = new List<Proposal>();
            Reply? reply = null;

            if (_model?.SmallPromptChars is { } room)
            {
                await SmallTurnAsync(p, clean, found, receipts, room, cancel);
                return;
            }
            if (_model != null)
            {
                try
                {
                    string? results = null;
                    var empties = 0;
                    for (var round = 0; round < 4; round++)
                    {
                        var raw = await _model.CompleteAsync(Prompt.Instructions(_options.AgentName),
                            Prompt.Situation(_ws, p, clean, found, results, empties == 0 ? null
                                : "YOUR PREVIOUS ATTEMPT RAN OUT OF LENGTH BEFORE WRITING ANYTHING. Write the JSON object now, as the first thing you produce, and keep it short."), cancel);
                        var answer = Reply.Parse(raw);
                        // A gateway that counts thinking against a small allowance sometimes leaves
                        // no room for the answer. Asking again is the cure, a few times.
                        if (answer.Empty)
                        {
                            if (++empties >= 3) throw new ArkAgentModelException("it ran out of room three times before writing an answer");
                            _log.LogInformation("Onboarding agent: the model's answer was cut off before it began; asking again ({Attempt}).", empties);
                            round--;
                            continue;
                        }
                        // The first answer's proposals and questions stand; a later round only adds.
                        if (reply != null)
                        {
                            foreach (var x in reply.Proposals) answer.Proposals.Add(x);
                            if (answer.Ask.Count == 0) foreach (var a in reply.Ask) answer.Ask.Add(a!.DeepClone());
                        }
                        // What a cut-off answer managed to say is kept if the next round says nothing.
                        if (answer.Say.Length == 0 && reply is { Say.Length: > 0 }) answer.Say = reply.Say;
                        reply = answer;
                        _ws.Remember(p, reply.Remember);
                        if (reply.Actions.Count == 0 && !reply.Truncated) break;

                        var round1 = await ExecuteAsync(p, reply.Actions, proposals, clean, cancel);
                        receipts.AddRange(round1);
                        if (round1.Count > 0) await RefreshAsync(cancel);
                        if (!reply.Continue && !reply.Truncated && round1.All(r => r.Ok)) break;
                        results = round1.Count == 0 ? "(none of your actions were complete)" : string.Join('\n', round1.Select(r => r.ForModel));
                        // A gateway's length limit cut the answer short. What was whole has been
                        // done; the model is told so, and finishes the rest in a shorter answer.
                        if (reply.Truncated)
                            results += "\nYOUR LAST ANSWER WAS CUT OFF by the length limit. Only the actions listed above were carried out; anything after them was lost, " +
                                       "including proposals, questions and what you said. Do what is still missing, nothing twice, and keep this answer much shorter.";
                        reply.Actions.Clear();
                    }
                    _ws.ModelNotice = null;
                }
                catch (ArkAgentModelException ex)
                {
                    _log.LogWarning("Onboarding agent: the model did not answer ({Reason}). Continuing in guided mode for this turn.", ex.Message);
                    _ws.ModelNotice = $"My language model did not answer ({ex.Message}). I am asking the questions one at a time until it does.";
                    reply = null;
                }
            }

            if (reply == null)
            {
                await GuidedAsync(p, clean, found, receipts, cancel);
                return;
            }

            p.Pending = null;
            foreach (var (section, field, value, why) in reply.Proposals)
                if (Proposable(p, section, field, value) is { } proposal)
                {
                    proposal.Why = why;
                    proposals.Add(proposal);
                }
            Finish(p, reply.Say, receipts, proposals, reply.Ask);
        }

        /// <summary>The end of every turn: what was done, what is proposed, what is asked, and what follows from it.</summary>
        void Finish(Participant p, string say, List<Receipt> receipts, List<Proposal> proposals, JsonArray ask, string? about = null)
        {
            // In guided mode a suggestion is shown beside the question it answers, not before.
            foreach (var inferred in Advisor.Infer(_ws, p, Guided).Where(x => about == null || x.Section == about))
                if (!proposals.Any(x => x.Section == inferred.Section && x.Field == inferred.Field)) proposals.Add(inferred);

            // One suggestion per value: the model's own, with its reason, before the harness's.
            proposals = proposals.GroupBy(x => (x.Section, x.Field)).Select(g => g.OrderBy(x => x.Why.StartsWith("My suggestion", StringComparison.Ordinal)).First()).ToList();

            var widgets = new JsonArray();
            if (receipts.Count > 0)
                widgets.Add(new JsonObject
                {
                    ["type"] = "receipts",
                    ["items"] = new JsonArray(receipts.Select(r => (JsonNode?)new JsonObject { ["ok"] = r.Ok, ["text"] = r.Text }).ToArray())
                });

            lock (_ws.Sync)
            {
                // A newer suggestion for the same value replaces an older one that is still open.
                foreach (var fresh in proposals)
                    foreach (var old in _ws.Proposals.Where(x => x.State == "open" && x.ParticipantId == p.Id && x.Section == fresh.Section && x.Field == fresh.Field))
                        old.State = "dismissed";
                _ws.Proposals.AddRange(proposals);
                if (_ws.Proposals.Count > 300) _ws.Proposals.RemoveRange(0, _ws.Proposals.Count - 300);
            }
            if (proposals.Count > 0)
                widgets.Add(new JsonObject
                {
                    ["type"] = "proposal",
                    ["ids"] = new JsonArray(proposals.Select(x => (JsonNode?)JsonValue.Create(x.Id)).ToArray())
                });

            var reviewAsked = false;
            foreach (var item in ask.OfType<JsonObject>())
            {
                switch (item["type"]?.ToString())
                {
                    case "choices" when item["options"] is JsonArray { Count: > 0 } options:
                        widgets.Add(new JsonObject
                        {
                            ["type"] = "choices",
                            ["options"] = new JsonArray(options.Take(6).Select(o => (JsonNode?)JsonValue.Create(o?.ToString() ?? "")).ToArray())
                        });
                        break;
                    case "secret":
                        var section = item["section"]?.ToString() ?? "";
                        var field = item["field"]?.ToString() ?? "";
                        // Never the administrator's password: they choose it themselves, after the install.
                        if (p.May(section) && _ws.Section(section)?.Field(field) is { Secret: true } && $"{section}.{field}" != "administrator.password")
                            widgets.Add(new JsonObject
                            {
                                ["type"] = "secret", ["section"] = section, ["field"] = field,
                                ["label"] = item["label"]?.ToString() ?? $"{_ws.Section(section)!.Title}: {field}"
                            });
                        break;
                    case "invite" when p.IsLead && item["sections"] is JsonArray sections:
                        var names = sections.Select(s => s?.ToString() ?? "").Where(s => _ws.Section(s) != null).Distinct().ToList();
                        if (names.Count > 0)
                            widgets.Add(new JsonObject
                            {
                                ["type"] = "invite",
                                ["sections"] = new JsonArray(names.Select(n => (JsonNode?)JsonValue.Create(n)).ToArray()),
                                ["department"] = item["department"]?.ToString() ?? _ws.Section(names[0])!.Owner,
                                ["why"] = item["why"]?.ToString() ?? "",
                                ["name"] = item["name"]?.ToString()
                            });
                        break;
                    case "review":
                        reviewAsked = true;
                        break;
                }
            }

            // Ready is ready, whether or not the model noticed.
            var ready = p.IsLead && _ws.ReadyForReview && proposals.Count == 0;
            if (ready && (reviewAsked || receipts.Count > 0)) widgets.Add(new JsonObject { ["type"] = "review" });

            if (string.IsNullOrWhiteSpace(say))
                say = receipts.Count == 0 && proposals.Count > 0 ? "Here is what I would suggest."
                    : receipts.All(r => r.Ok) ? "Done." : "That did not all go through; see below.";
            _ws.Say(p, say, widgets.Count > 0 ? widgets : null);
            AfterChange(p);
            _ws.Touch();
        }

        // ------------------------------------------------------------ what the model may do

        internal sealed record Receipt(bool Ok, string Text, string ForModel);

        async Task<List<Receipt>> ExecuteAsync(Participant p, List<(string Tool, JsonObject Args)> actions, List<Proposal> proposals, string message, CancellationToken cancel)
        {
            var receipts = new List<Receipt>();
            var corpus = _ws.Corpus(p);
            // A yes/no setting has no text to find in what was typed. The model's reading of one is
            // taken as the person's only when their message was an answer: short, and not a question.
            // "We are regulated; what would you change?" gets a card to accept, not seven changes.
            var words = message.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Length;
            var anAnswer = !message.Contains('?') && words <= 15;
            // Taking a value away is asked for in so many words. A null in the model's answer, or a
            // pasted page that says "clear", is not somebody asking.
            var mayRemove = words <= 40 && Removal.IsMatch(message);

            foreach (var (tool, args) in actions.Take(12))
            {
                if (tool.StartsWith("setup_set_", StringComparison.Ordinal))
                {
                    var name = tool["setup_set_".Length..];
                    if (_ws.Section(name) is not { } section)
                    {
                        receipts.Add(Refused($"There is no section called “{name}”.", tool));
                        continue;
                    }
                    if (!p.May(name))
                    {
                        receipts.Add(Refused($"{section.Title} is not something {(p.Name.Length > 0 ? p.Name : "this person")} was asked for, so I left it alone.", tool));
                        continue;
                    }

                    var send = new JsonObject();
                    var secrets = new List<(string Field, string Text)>();
                    foreach (var (fieldName, given) in args.ToList())
                    {
                        if (fieldName == "source") continue;
                        if (section.Field(fieldName) is not { } field)
                        {
                            receipts.Add(Refused($"{section.Title} has no value called “{fieldName}”.", tool));
                            continue;
                        }
                        var key = $"{name}.{fieldName}";
                        var value = Coerce(field, given);
                        if (value == null) continue;
                        var text = value is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

                        if (text is { Length: 0 })
                        {
                            if (mayRemove) send[fieldName] = "";
                            continue;
                        }
                        if (field.Secret)
                        {
                            if (key == "administrator.password")
                                receipts.Add(Refused("I do not take the administrator's password: they set it themselves through a one-time link after the install.", tool));
                            else if (text != null && Vault.Mentions(text)) secrets.Add((fieldName, text));
                            else receipts.Add(Refused($"A secret has to come from the person, through the lock button ({section.Title}: {fieldName}).", tool));
                            continue;
                        }
                        if (Vault.Mentions(value.ToJsonString()))
                        {
                            // A value that can be read back is no place for a secret, whoever's it is.
                            receipts.Add(Refused($"I held part of that back because it looks like a secret, and {section.Title}: {fieldName.Replace('_', ' ')} is shown on the board. If it is not one, please type it on the board.", tool));
                            continue;
                        }
                        if (text is { Length: > 0 } && !(field.Values == null ? Grounded(corpus, text) : Grounded(corpus, text) || Grounded(corpus, text.Replace('_', ' ')))
                                 || value is JsonValue number && number.TryGetValue<int>(out var digits) && !Regex.IsMatch(corpus, $@"(?<!\d){digits}(?!\d)"))
                        {
                            // Nobody said this. It may be a good idea; it is not a fact.
                            if (Proposable(p, name, fieldName, value) is { } guess)
                            {
                                guess.Why = "My suggestion: nobody has given this value yet.";
                                proposals.Add(guess);
                            }
                            continue;
                        }
                        else if (value is JsonValue flag && flag.TryGetValue<bool>(out _) && !anAnswer)
                        {
                            if (Proposable(p, name, fieldName, value) is { } reading)
                            {
                                reading.Why = "How I read what you said. Accept it if that is what you meant.";
                                proposals.Add(reading);
                            }
                            continue;
                        }
                        else if (value is JsonArray list && list.Any(x => !Grounded(corpus, x?.ToString() ?? "")))
                        {
                            if (Proposable(p, name, fieldName, value) is { } guess)
                            {
                                guess.Why = "My suggestion: not all of these were given by anybody.";
                                proposals.Add(guess);
                            }
                            continue;
                        }

                        if (Permanent.Contains(key) && text is { Length: > 0 })
                        {
                            if (Proposable(p, name, fieldName, value) is { } confirm)
                            {
                                confirm.Confirm = true;
                                confirm.Why = key == "server.tenant_id"
                                    ? "Please confirm: the tenant id is part of every token's issuer and cannot be renamed after the install."
                                    : "Please confirm: this address is part of every token's issuer, and every application is configured with it.";
                                proposals.Add(confirm);
                            }
                            continue;
                        }
                        send[fieldName] = value.DeepClone();
                    }
                    // Last, when it is known where they would be sent: the host stored in this same call, or the one stored already.
                    foreach (var (fieldName, text) in secrets)
                    {
                        var host = send["host"]?.ToString() ?? _ws.ValueText($"{name}.host");
                        if (_ws.Vault.Resolve(text, p, host) is { } secret) send[fieldName] = secret;
                        else receipts.Add(Refused($"A secret has to come from the person, through the lock button ({section.Title}: {fieldName}).", tool));
                    }
                    if (send.Count > 0) receipts.Add(await StoreAsync(p, section, send, null, cancel, unattended: true));
                    continue;
                }

                switch (tool)
                {
                    case "setup_test_database" when p.May("database"):
                        receipts.Add(await TestAsync("database", "setup_test_database", null, cancel));
                        break;
                    case "setup_test_audit" when p.May("audit"):
                        receipts.Add(await TestAsync("audit", "setup_test_audit", null, cancel));
                        break;
                    case "setup_test_email" when p.May("email"):
                        var to = args["to"]?.ToString() ?? "";
                        receipts.Add(Grounded(corpus, to)
                            ? await TestAsync("email", "setup_test_email", new JsonObject { ["to"] = to }, cancel)
                            : Refused("I need an address to send the test email to.", tool));
                        break;
                    case "setup_clear" when !mayRemove:
                        receipts.Add(Refused("I clear a section only when you ask me to in a short message of its own.", tool));
                        break;
                    case "setup_clear" when args["section"]?.ToString() is { } clear && p.May(clear) && _ws.Section(clear) is { } cleared:
                        var result = await _mcp.CallAsync("setup_clear", new JsonObject { ["section"] = clear }, cancel);
                        _ws.Log($"{Who(p)} cleared {cleared.Title}.");
                        receipts.Add(new Receipt(!result.IsError, result.IsError ? result.Message : $"Cleared {cleared.Title}.", $"setup_clear {clear}: {(result.IsError ? result.Message : "done")}"));
                        break;
                    case "setup_review" or "setup_status" or "setup_fields":
                        break; // the harness already does these
                    case "setup_complete":
                        receipts.Add(Refused("Installing is the lead's decision, with the button under the reviewed plan.", tool));
                        break;
                    default:
                        receipts.Add(Refused($"“{tool}” is not something I can do for {(p.Name.Length > 0 ? p.Name : "this person")}.", tool));
                        break;
                }
            }
            return receipts;
        }

        static readonly Regex Removal = new(@"\b(?:clear|remove|delete|drop|reset|forget|undo|unset|wipe|scrap|empty|without|no longer|start over|take (?:it|that|this) (?:out|off|back))\b",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        static Receipt Refused(string text, string tool) => new(false, text, $"{tool}: refused by the harness. {text}");

        /// <summary>Whether somebody typed this, or the environment showed it: case and a trailing slash aside.</summary>
        static bool Grounded(string corpus, string value)
        {
            var needle = value.Trim().TrimEnd('/').ToLowerInvariant();
            return needle.Length > 0 && corpus.Contains(needle, StringComparison.Ordinal);
        }

        /// <summary>A value in the type its field takes: a model writes "5432" and "yes" as readily as 5432 and true.</summary>
        static JsonNode? Coerce(FieldDef field, JsonNode? given)
        {
            if (given == null) return JsonValue.Create("");
            var text = given is JsonValue v && v.TryGetValue<string>(out var s) ? s.Trim() : null;
            switch (field.Type)
            {
                case "integer":
                    if (given is JsonValue n && n.TryGetValue<int>(out var number)) return JsonValue.Create(number);
                    if (text == "") return JsonValue.Create("");
                    return int.TryParse(text, out var parsed) ? JsonValue.Create(parsed) : null;
                case "boolean":
                    if (given is JsonValue b && b.TryGetValue<bool>(out var flag)) return JsonValue.Create(flag);
                    return text?.ToLowerInvariant() switch
                    {
                        "true" or "yes" or "on" or "y" => JsonValue.Create(true),
                        "false" or "no" or "off" or "n" => JsonValue.Create(false),
                        "" => JsonValue.Create(""),
                        _ => null
                    };
                case "array":
                    if (given is JsonArray list) return new JsonArray(list.Select(x => (JsonNode?)JsonValue.Create(x?.ToString() ?? "")).ToArray());
                    return text == null ? null
                        : new JsonArray(text.Split(new[] { ',', ' ', '\n' }, StringSplitOptions.RemoveEmptyEntries).Select(x => (JsonNode?)JsonValue.Create(x)).ToArray());
                default:
                    if (text == null) return JsonValue.Create(given.ToString());
                    if (field.Values != null && text.Length > 0)
                    {
                        var match = field.Values.FirstOrDefault(x => x.Equals(text, StringComparison.OrdinalIgnoreCase))
                                    ?? field.Values.FirstOrDefault(x => text.Contains(x, StringComparison.OrdinalIgnoreCase));
                        return match == null ? null : JsonValue.Create(match);
                    }
                    return JsonValue.Create(text);
            }
        }

        /// <summary>A proposal for this person, if it would change anything and they may change it.</summary>
        Proposal? Proposable(Participant p, string section, string field, JsonNode? value)
        {
            if (value == null || !p.May(section) || _ws.Section(section)?.Field(field) is not { Secret: false } def) return null;
            if (Coerce(def, value) is not { } typed || typed.ToJsonString() == "\"\"") return null;
            lock (_ws.Sync)
            {
                if (_ws.Values.TryGetValue($"{section}.{field}", out var now) && now?.ToJsonString() == typed.ToJsonString()) return null;
                if (_ws.Proposals.Any(x => x.State == "open" && x.ParticipantId == p.Id && x.Section == section && x.Field == field
                                           && x.Value?.ToJsonString() == typed.ToJsonString())) return null;
            }
            return new Proposal { Id = Workspace.NewId(), Section = section, Field = field, Value = typed, ParticipantId = p.Id };
        }

        // ------------------------------------------------------------ storing and testing

        string Who(Participant p) => p.Name.Length > 0 ? p.Department.Length > 0 ? $"{p.Name} ({p.Department})" : p.Name : "Someone";

        /// <summary>Where a section's secret is sent, and the secrets that would be.</summary>
        static readonly Dictionary<string, (string[] Where, string[] Secrets)> Destinations = new(StringComparer.Ordinal)
        {
            ["database"] = (new[] { "host", "connection_string" }, new[] { "password", "connection_string" }),
            ["email"] = (new[] { "smtp" }, new[] { "password" }),
            ["audit"] = (new[] { "endpoint" }, new[] { "api_key" })
        };

        /// <summary>
        /// The stored secrets that must not follow a change of address. A test signs in wherever the
        /// section points, so whoever can point it somewhere else could have a password they cannot
        /// read sent to a server of their own. A colleague's change drops what somebody else gave;
        /// a change nobody clicked (the model's, or one read off pasted text) drops it whoever gave it.
        /// </summary>
        List<string> NotToFollow(Participant p, SectionDef section, JsonObject values, bool unattended)
        {
            var dropped = new List<string>();
            if (!Destinations.TryGetValue(section.Name, out var to)) return dropped;
            lock (_ws.Sync)
            {
                bool Moves(string field, bool fromNowhere)
                {
                    if (values[field] is not JsonValue v || !v.TryGetValue<string>(out var next)) return false;
                    var now = _ws.ValueText($"{section.Name}.{field}");
                    // A stored connection string reads back as "(set)": another one is another place.
                    return now == null ? fromNowhere : !string.Equals(now.Trim(), next.Trim(), StringComparison.OrdinalIgnoreCase);
                }
                foreach (var secret in to.Secrets)
                {
                    var key = $"{section.Name}.{secret}";
                    if (values.ContainsKey(secret) || !_ws.Values.ContainsKey(key)) continue;
                    var theirs = _ws.SecretOwners.TryGetValue(key, out var owner) && owner == p.Id;
                    if ((!p.IsLead && !theirs && to.Where.Any(f => Moves(f, fromNowhere: true))) || (unattended && to.Where.Any(f => Moves(f, fromNowhere: false))))
                        dropped.Add(secret);
                }
            }
            return dropped;
        }

        async Task<Receipt> StoreAsync(Participant p, SectionDef section, JsonObject values, string? note, CancellationToken cancel, bool unattended = false)
        {
            var dropped = NotToFollow(p, section, values, unattended);
            var args = (JsonObject)values.DeepClone();
            foreach (var secret in dropped) args[secret] = "";
            args["source"] = Source(p, note);
            var result = await _mcp.CallAsync($"setup_set_{section.Name}", args, cancel);
            var names = string.Join(", ", values.Select(v => v.Key.Replace('_', ' ')));
            if (result.IsError)
                return new Receipt(false, $"{section.Title}: {result.Message}", $"setup_set_{section.Name}: error {result.Error}: {result.Message}");

            _ws.Log($"{Who(p)} supplied {section.Title}: {names}.");
            lock (_ws.Sync)
            {
                foreach (var x in _ws.Proposals.Where(x => x.State == "open" && x.Section == section.Name && values.ContainsKey(x.Field))) x.State = "dismissed";
                foreach (var (name, value) in values)
                    if (section.Field(name) is { Secret: true })
                    {
                        if (value?.ToString() is { Length: > 0 }) _ws.SecretOwners[$"{section.Name}.{name}"] = p.Id;
                        else _ws.SecretOwners.Remove($"{section.Name}.{name}");
                    }
                foreach (var secret in dropped) _ws.SecretOwners.Remove($"{section.Name}.{secret}");
                if (p.InviteId != null && _ws.Invites.FirstOrDefault(i => i.Id == p.InviteId) is { } invite) invite.LastActivityAt = DateTime.UtcNow;
            }
            var problems = (result.Content["problems"] as JsonArray ?? new JsonArray()).Select(x => x?["message"]?.ToString() ?? "").Where(x => x.Length > 0).ToList();
            var forModel = new JsonObject
            {
                ["tool"] = $"setup_set_{section.Name}", ["stored"] = names, ["status"] = result.Content["status"]?.DeepClone(),
                ["missing"] = result.Content["missing"]?.DeepClone(), ["problems"] = result.Content["problems"]?.DeepClone()
            }.ToJsonString();
            var moved = dropped.Count == 0 ? ""
                : $". The {string.Join(" and ", dropped.Select(d => d.Replace('_', ' ')))} stored before was for the previous address, so I removed it: it has to be entered again, through the lock button";
            return problems.Count > 0
                ? new Receipt(false, $"{section.Title}: stored {names}, but {string.Join(" ", problems)}{moved}", forModel)
                : new Receipt(true, $"Stored {section.Title}: {names}{moved}", forModel);
        }

        async Task<Receipt> TestAsync(string section, string tool, JsonObject? args, CancellationToken cancel)
        {
            var result = await _mcp.CallAsync(tool, args, cancel);
            var title = _ws.Section(section)?.Title ?? section;
            var ok = !result.IsError && result.Content["ok"]?.GetValue<bool>() == true;
            var message = result.Content["message"]?.ToString() ?? "";
            _ws.Log($"{title} test: {(ok ? "passed" : "failed")}. {message}");
            return new Receipt(ok, $"{title} test {(ok ? "passed" : "failed")}: {message}", $"{tool}: {result.Content.ToJsonString()}");
        }

        /// <summary>
        /// Values straight from a person: an edit on the board, a secret from the lock button, an
        /// accepted proposal. No model is involved, so nothing here is checked against what was
        /// said; only against who may change what.
        /// </summary>
        public async Task<(bool Ok, string Text)> SetAsync(Participant p, string sectionName, JsonObject values, string note, CancellationToken cancel)
        {
            if (_ws.Section(sectionName) is not { } section) return (false, "There is no such section.");
            if (!p.May(sectionName)) return (false, $"{section.Title} is not part of what you were asked for.");
            var send = new JsonObject();
            foreach (var (name, given) in values)
            {
                if (section.Field(name) is not { } field) return (false, $"{section.Title} has no value called “{name}”.");
                if ($"{sectionName}.{name}" == "administrator.password")
                    return (false, "Leave the administrator's password out: they set it themselves through a one-time link after the install.");
                if (Coerce(field, given) is not { } typed) return (false, $"“{given}” is not a usable value for {name}.");
                send[name] = typed;
            }
            if (send.Count == 0) return (false, "Nothing to store.");
            var receipt = await StoreAsync(p, section, send, note, cancel);
            await RefreshAsync(cancel);
            AfterChange(p);
            _ws.Touch();
            return (receipt.Ok, receipt.Text);
        }

        public async Task AcceptAsync(Participant p, IReadOnlyCollection<string> ids, bool accept, CancellationToken cancel)
        {
            List<Proposal> chosen;
            lock (_ws.Sync) chosen = _ws.Proposals.Where(x => ids.Contains(x.Id) && x.ParticipantId == p.Id && x.State == "open").ToList();
            if (chosen.Count == 0) return;
            if (!accept)
            {
                lock (_ws.Sync) chosen.ForEach(x => x.State = "dismissed");
                _ws.Touch();
                return;
            }

            var receipts = new List<Receipt>();
            foreach (var group in chosen.GroupBy(x => x.Section))
            {
                if (_ws.Section(group.Key) is not { } section || !p.May(group.Key)) continue;
                var values = new JsonObject();
                foreach (var x in group) values[x.Field] = x.Value?.DeepClone();
                var suggested = group.Any(x => !x.Confirm);
                receipts.Add(await StoreAsync(p, section, values,
                    suggested ? $"suggested by {_options.AgentName}, accepted by {p.Name}" : $"confirmed by {p.Name}", cancel));
                lock (_ws.Sync) foreach (var x in group) x.State = "accepted";
            }
            await RefreshAsync(cancel);
            if (Guided) AskNext(p, receipts);
            else
            {
                var (say, ask) = Next(p);
                Finish(p, receipts.All(r => r.Ok) ? say : "", receipts, new List<Proposal>(), ask);
            }
        }

        /// <summary>
        /// What to say after a click, without calling the model for it: what is still open, and
        /// who would know. An open section the lead has not asked anybody for comes with the
        /// offer to.
        /// </summary>
        (string Say, JsonArray Ask) Next(Participant p)
        {
            var ask = new JsonArray();
            if (p.IsLead && _ws.ReadyForReview)
                return ("That is everything I need. The rest is on sensible defaults, which the plan lists; have a look before I install anything.", ask);

            var open = new List<string>();
            foreach (var section in _ws.Catalogue.Where(s => p.May(s.Name)))
            {
                var status = _ws.StatusOf(section.Name);
                var missing = (status?["missing"] as JsonArray ?? new JsonArray()).Select(m => m!.ToString().Replace('_', ' ')).ToList();
                var wrong = (status?["problems"] as JsonArray ?? new JsonArray()).Select(x => x?["message"]?.ToString() ?? "").Where(x => x.Length > 0).ToList();
                if (missing.Count == 0 && wrong.Count == 0) continue;
                open.Add($"**{section.Title}** ({(missing.Count > 0 ? string.Join(", ", missing) : wrong[0])})");
                bool asked;
                lock (_ws.Sync) asked = _ws.Invites.Any(i => !i.Revoked && i.Sections.Contains(section.Name));
                if (p.IsLead && !asked && missing.Count > 0 && section.Name is not ("organization" or "server" or "administrator"))
                    ask.Add(new JsonObject
                    {
                        ["type"] = "invite", ["sections"] = new JsonArray(section.Name), ["department"] = section.Owner,
                        ["why"] = $"Usually known by {Lower(section.Owner)}."
                    });
            }
            return (open.Count == 0 ? "Noted." : $"Noted. Still open: {string.Join("; ", open)}. Tell me if you have them, or I can ask the colleague who does.", ask);
        }

        public async Task<(bool Ok, string Text)> RunTestAsync(Participant p, string section, string? to, CancellationToken cancel)
        {
            if (!p.May(section)) return (false, "That is not part of what you were asked for.");
            var receipt = section switch
            {
                "database" => await TestAsync("database", "setup_test_database", null, cancel),
                "audit" => await TestAsync("audit", "setup_test_audit", null, cancel),
                "email" when !string.IsNullOrWhiteSpace(to) => await TestAsync("email", "setup_test_email", new JsonObject { ["to"] = to!.Trim() }, cancel),
                "email" => new Receipt(false, "Give an address to send the test email to.", ""),
                _ => new Receipt(false, "There is nothing to test in that section.", "")
            };
            await RefreshAsync(cancel);
            AfterChange(p);
            _ws.Touch();
            return (receipt.Ok, receipt.Text);
        }

        /// <summary>
        /// After anything changed: has a colleague finished what they were asked for? Then they
        /// are thanked, and the lead is told, once.
        /// </summary>
        void AfterChange(Participant p)
        {
            if (p.IsLead || p.InviteId == null) return;
            Invite? invite;
            lock (_ws.Sync) invite = _ws.Invites.FirstOrDefault(i => i.Id == p.InviteId);
            if (invite == null || invite.AnsweredAt != null) return;

            foreach (var name in invite.Sections)
            {
                var status = _ws.StatusOf(name);
                if (status?["status"]?.ToString() != "complete") return;
                // Proven, where there is something to prove.
                if (name is "database" && status["test"]?["ok"]?.GetValue<bool>() != true) return;
                if (name is "email" or "audit" && _ws.Values.TryGetValue($"{name}.enabled", out var on) && on?.ToString() == "true"
                    && status["test"]?["ok"]?.GetValue<bool>() != true) return;
            }

            invite.AnsweredAt = DateTime.UtcNow;
            var titles = string.Join(" and ", invite.Sections.Select(s => _ws.Section(s)?.Title ?? s));
            _ws.Log($"{Who(p)} completed {titles}.");
            _ws.Say(p, $"That is everything I needed from you for {titles}. Thank you, {First(p.Name)}: you can close this page. The person running the setup has been told.");
            List<Participant> leads;
            lock (_ws.Sync) leads = _ws.People.Values.Where(x => x.IsLead && x.Greeted).ToList();
            foreach (var lead in leads)
            {
                var widgets = _ws.ReadyForReview ? new JsonArray(new JsonObject { ["type"] = "review" }) : null;
                _ws.Say(lead, $"✅ {Who(p)} has completed **{titles}**" +
                              (invite.Sections.Contains("database") ? ", and the connection test passed." : "."), widgets);
            }
        }

        // ------------------------------------------------------------ guided mode

        /// <summary>What the harness recognised by itself, stored and tested. True when there was any.</summary>
        async Task<bool> FileDetectedAsync(Participant p, List<Detection> found, List<Receipt> receipts, CancellationToken cancel)
        {
            var filed = false;
            foreach (var d in found.Where(d => d.Section != null && d.Values != null && d.Values["unsupported"] == null))
            {
                if (_ws.Section(d.Section!) is not { } section || !p.May(d.Section!)) continue;
                var send = new JsonObject();
                foreach (var (name, value) in d.Values!)
                {
                    if (section.Field(name) is not { } field || value == null) continue;
                    var text = value.ToString();
                    if (!field.Secret) { send[name] = value.DeepClone(); continue; }
                    if (_ws.Vault.Resolve(text, p) is { } secret) send[name] = secret;
                }
                if (send.Count == 0) continue;
                receipts.Add(await StoreAsync(p, section, send, "pasted into the conversation", cancel, unattended: true));
                if (d.Section == "database" && send["provider"]?.ToString() != "sqlite") receipts.Add(await TestAsync("database", "setup_test_database", null, cancel));
                filed = true;
            }
            foreach (var d in found.Where(d => d.Values?["unsupported"] != null))
                receipts.Add(new Receipt(false, d.Summary, ""));
            return filed;
        }

        /// <summary>The value the last question asked for, if it is still open and this person may give it.</summary>
        (SectionDef Section, FieldDef Field, string Key)? Asked(Participant p) =>
            // An answer belongs to the question it follows, and only while that value is still open:
            // it may have been filled in on the board, or by a colleague, since it was asked.
            p.Pending is { } pending && !_ws.Has(pending) && pending.Split('.') is [var sectionName, var fieldName]
            && _ws.Section(sectionName) is { } section && section.Field(fieldName) is { } field && p.May(sectionName) ? (section, field, pending) : null;

        async Task GuidedAsync(Participant p, string clean, List<Detection> found, List<Receipt> receipts, CancellationToken cancel)
        {
            var filed = await FileDetectedAsync(p, found, receipts, cancel);
            var (advice, suggested) = Advisor.Posture(_ws, p, clean);

            if (!filed && !Advisor.IsStart(clean) && !Brain.SmallModel.IsSmallTalk(clean) && Asked(p) is { } asked)
            {
                var answer = Brain.SmallModel.Answer(clean);
                var (shaped, problem) = Brain.SmallModel.Shape(asked.Key, answer);
                if (asked.Field.Secret)
                    receipts.Add(new Receipt(false, "That one is a secret: please use the lock button, so it does not end up in the conversation.", ""));
                else if (!Brain.SmallModel.IsAnswer(clean, 12))
                    receipts.Add(new Receipt(false, "That is more than I can read without a language model. Please answer one question at a time, or fill it in on the board.", ""));
                else if (problem != null)
                    receipts.Add(new Receipt(false, problem, ""));
                else if (Coerce(asked.Field, JsonValue.Create(shaped)) is { } typed)
                    receipts.Add(await StoreAsync(p, asked.Section, new JsonObject { [asked.Field.Name] = typed }, null, cancel));
                else
                    receipts.Add(new Receipt(false, asked.Field.Values != null ? $"Please choose one of: {string.Join(", ", asked.Field.Values)}." : "I could not read that as a value for this question.", ""));
            }
            await RefreshAsync(cancel);
            AskNext(p, receipts, StartSaid(clean) ?? advice, suggested, StartAsked(p, clean));
        }

        static string? StartSaid(string clean) => clean.Trim() switch
        {
            Advisor.Trial => "Then the defaults are right, and SQLite is fine: only the four things I need are left.",
            Advisor.Others => "Good, then you need not chase anybody. For each part that belongs to somebody else, I write them a request with a link that reaches only that part.",
            _ => null
        };

        JsonArray? StartAsked(Participant p, string clean) => clean.Trim() != Advisor.Others || !p.IsLead ? null
            : new JsonArray(new[] { "database", "email" }.Where(n => _ws.Section(n) != null).Select(n => (JsonNode?)new JsonObject
            {
                ["type"] = "invite", ["sections"] = new JsonArray(n), ["department"] = _ws.Section(n)!.Owner,
                ["why"] = $"Usually known by {Lower(_ws.Section(n)!.Owner)}."
            }).ToArray());

        /// <summary>The next of the server's own questions for this person, or the review when nothing is open.</summary>
        void AskNext(Participant p, List<Receipt>? receipts, string? preface = null, List<Proposal>? proposals = null, JsonArray? extra = null)
        {
            receipts ??= new List<Receipt>();
            FieldDef? next = null;
            SectionDef? owner = null;
            var waiting = false;
            bool OnACard(string section, string field)
            {
                lock (_ws.Sync) return _ws.Proposals.Any(x => x.State == "open" && x.ParticipantId == p.Id && x.Section == section && x.Field == field);
            }
            foreach (var section in _ws.Catalogue.Where(s => p.May(s.Name)))
            {
                var missing = (_ws.StatusOf(section.Name)?["missing"] as JsonArray ?? new JsonArray()).Select(m => m!.ToString()).ToList();
                // A colleague asked for a section nobody has touched starts with its first value.
                if (missing.Count == 0 && !p.IsLead && _ws.StatusOf(section.Name)?["status"]?.ToString() == "default")
                    missing.Add(section.Fields[0].Name);
                var first = section.Fields.FirstOrDefault(f => missing.Contains(f.Name) && !f.Held);
                var unasked = section.Fields.FirstOrDefault(f => missing.Contains(f.Name) && !f.Held && !OnACard(section.Name, f.Name));
                // A value waiting on a card is not asked for again; what it waits for can still be typed instead.
                if (first != null && unasked == null && next == null && !waiting) { waiting = true; p.Pending = $"{section.Name}.{first.Name}"; }
                if (unasked != null) { next = unasked; owner = section; break; }
            }

            var ask = new JsonArray();
            string say;
            if (next == null && waiting) say = "The card above is still waiting for you: accept it, or tell me what it should say.";
            else if (next == null)
            {
                p.Pending = null;
                say = receipts.Any(r => !r.Ok) ? "That did not all go through; see below. Correct it here or on the board."
                    : p.IsLead
                    ? _ws.ReadyForReview ? "That is everything I need. The rest is on sensible defaults, which the plan lists; have a look before I install anything."
                        : "Something is still not right; the board shows what."
                    : "Thank you. Anything else you want to add or correct, use the board on the right.";
                if (p.IsLead && _ws.ReadyForReview) ask.Add(new JsonObject { ["type"] = "review" });
            }
            else
            {
                p.Pending = $"{owner!.Name}.{next.Name}";
                say = next.Ask;
                if (next.Secret) ask.Add(new JsonObject { ["type"] = "secret", ["section"] = owner.Name, ["field"] = next.Name, ["label"] = next.Description });
                else if (next.Values != null) ask.Add(new JsonObject { ["type"] = "choices", ["options"] = new JsonArray(next.Values.Select(v => (JsonNode?)JsonValue.Create(v)).ToArray()) });
                else if (next.Type == "boolean") ask.Add(new JsonObject { ["type"] = "choices", ["options"] = new JsonArray("Yes", "No") });
            }
            foreach (var item in extra ?? new JsonArray())
                // One row of buttons at a time: those of the question itself come first.
                if (item != null && (item["type"]?.ToString() != "choices" || ask.All(a => a?["type"]?.ToString() != "choices"))) ask.Add(item.DeepClone());
            Finish(p, preface == null ? say : $"{preface}\n{say}", receipts, proposals ?? new List<Proposal>(), ask, owner?.Name ?? "-");
        }

        // ------------------------------------------------------------ a turn with a small model

        /// <summary>
        /// The model is the last thing tried, not the first. Most of a conversation needs none: an
        /// answer to the question just asked, a button, a connection string, small talk, the kind
        /// of organization somebody describes. What is left is free text to pick values out of, or
        /// a question about a setting, and that is one short call. What the model read is shown for
        /// the person to accept; nothing it says is stored on its word.
        /// </summary>
        async Task SmallTurnAsync(Participant p, string clean, List<Detection> found, List<Receipt> receipts, int room, CancellationToken cancel)
        {
            var remainder = Brain.SmallModel.Remainder(clean);
            var detected = found.Any(d => d.Section != null);
            var answered = Asked(p) is { } asked && !asked.Field.Secret && Brain.SmallModel.IsAnswer(clean, 6)
                           && Brain.SmallModel.Shape(asked.Key, Brain.SmallModel.Answer(clean)).Problem == null
                           // "SMTP is smtp.acme.com" is six words, and no answer to "what is the organization's name?"
                           && (asked.Field.Type != "string" || asked.Field.Values != null || !MentionsAnother(p, asked.Key, clean));
            if (answered || Advisor.IsStart(clean) || Brain.SmallModel.IsSmallTalk(clean) || (detected && Brain.SmallModel.Words(remainder) <= 14))
            {
                _ws.ModelNotice = null;
                await GuidedAsync(p, clean, found, receipts, cancel);
                return;
            }

            await FileDetectedAsync(p, found, receipts, cancel);
            if (receipts.Count > 0) await RefreshAsync(cancel);
            var (advice, suggested) = Advisor.Posture(_ws, p, clean);
            try
            {
                if (Brain.SmallModel.IsQuestion(clean))
                {
                    var question = suggested.Count > 0 ? null : Brain.SmallModel.Question(_ws, p, clean, room);
                    var reply = advice ?? (question == null
                        ? "I can only answer questions about the settings on the board, and that is not one of them."
                        : Brain.SmallModel.Plain(await _model!.CompleteAsync("", question, cancel)));
                    _ws.ModelNotice = null;
                    AskNext(p, receipts, reply.Length > 0 ? reply : null, suggested);
                    return;
                }

                // Code first. The model is asked only when something is left that it might find: an
                // essential nobody has given, or a sentence that seems to be about a setting.
                var stated = Brain.SmallModel.Stated(remainder, p).Where(x => x.Key.Split('.') is [var sec, _] && p.May(sec)).ToList();
                var said = new Brain.SmallModel.Reading();
                foreach (var (key, value) in stated) said.Values.Add((key, JsonValue.Create(value)));
                var proposals = Readable(p, $"{clean}\n{p.Name}", said);

                var unread = Brain.SmallModel.Unread(remainder, stated.Select(x => x.Value));
                var taken = stated.Select(x => x.Key).ToHashSet(StringComparer.Ordinal);
                var openStill = new[] { "organization.company_name", "server.base_url", "administrator.username" }
                    .Any(k => p.May(k.Split('.')[0]) && !_ws.Has(k) && !taken.Contains(k) && !_ws.Proposals.Any(x => x.State == "open" && x.ParticipantId == p.Id && $"{x.Section}.{x.Field}" == k));
                var touches = Brain.SmallModel.Relevant(_ws, p, unread, 3, withOpenEssentials: false).Any(o => o.Score >= (p.IsLead ? 4 : 2) && !taken.Contains(o.Key));
                var skimmed = false;
                if (unread.Length > 0 && (touches || (openStill && stated.Count == 0)))
                {
                    var (prompt, keys, cut) = Brain.SmallModel.Extraction(_ws, p, unread, room, taken);
                    skimmed = cut;
                    try
                    {
                        var reading = Brain.SmallModel.Parse(await _model!.CompleteAsync("", prompt, cancel), keys);
                        foreach (var x in Readable(p, unread, reading))
                            if (!proposals.Any(y => y.Section == x.Section && y.Field == x.Field)) proposals.Add(x);
                        _ws.ModelNotice = null;
                    }
                    catch (ArkAgentModelException ex) when (proposals.Count > 0)
                    {
                        // What code read is worth showing without the rest.
                        NoteAbsence(ex);
                    }
                }
                else _ws.ModelNotice = null;

                foreach (var x in suggested)
                    if (!proposals.Any(y => y.Section == x.Section && y.Field == x.Field)) proposals.Add(x);

                // The organization's name is in: its short form goes on the same card.
                if (proposals.FirstOrDefault(x => x is { Section: "organization", Field: "company_name" }) is { } company && p.May("server") && !_ws.Has("server.tenant_id")
                    && proposals.All(x => x.Field != "tenant_id") && Advisor.TenantIdFor(company.Value!.ToString()) is { } tenant
                    && Proposable(p, "server", "tenant_id", JsonValue.Create(tenant)) is { } shortForm)
                {
                    shortForm.Why = $"A short form of “{company.Value}”. It becomes part of every token's issuer and cannot be renamed later.";
                    proposals.Add(shortForm);
                }

                var ask = new JsonArray();
                if (p.IsLead)
                    foreach (var (theirs, name) in Brain.SmallModel.Colleagues(remainder, p.Name))
                        if (_ws.Section(theirs) is { } section)
                            ask.Add(new JsonObject
                            {
                                ["type"] = "invite", ["sections"] = new JsonArray(section.Name), ["department"] = section.Owner, ["name"] = name,
                                ["why"] = name != null ? $"You said {name} knows this." : "You said somebody else knows this."
                            });

                var partly = skimmed ? " It was long, so I only read the parts that looked like settings." : "";
                if (proposals.Count == 0 && ask.Count == 0)
                {
                    AskNext(p, receipts, receipts.Count > 0 ? null : "I did not find a setting in that." + partly);
                    return;
                }
                Finish(p, (proposals.Count > 0 ? $"This is what I read. Please check it before I keep it.{partly}" : "Noted." + partly),
                    receipts, proposals, ask, "-");
            }
            catch (ArkAgentModelException ex)
            {
                NoteAbsence(ex);
                // What was recognised in code is filed already: not a second time.
                if (Asked(p) != null && Brain.SmallModel.IsAnswer(clean, 12)) await GuidedAsync(p, clean, new List<Detection>(), receipts, cancel);
                else AskNext(p, receipts, advice ?? "I could not read that just now. Please send it again in a few minutes, or put it on the board.", suggested);
            }
        }

        void NoteAbsence(ArkAgentModelException ex)
        {
            _log.LogInformation("Onboarding agent: going on without the model for this turn ({Reason}).", ex.Message);
            _ws.ModelNotice = $"I am going on without my language model for now: {ex.Message.TrimEnd('.')}. I ask one question at a time meanwhile, and the board works as always.";
        }

        /// <summary>Whether a short message names a different setting than the one that was asked for.</summary>
        bool MentionsAnother(Participant p, string askedKey, string text) =>
            Brain.SmallModel.Words(text) > 2 && Brain.SmallModel.Relevant(_ws, p, text, 1, withOpenEssentials: false) is [var best] && best.Score >= 4
            && best.Key != askedKey && best.Section.Name != askedKey.Split('.')[0];

        /// <summary>
        /// What a small model read, as proposals: only values that are in the message, only where
        /// the value is the kind the setting takes.
        /// </summary>
        List<Proposal> Readable(Participant p, string message, Brain.SmallModel.Reading reading)
        {
            var proposals = new List<Proposal>();
            var corpus = message.ToLowerInvariant();
            foreach (var (key, given) in reading.Values)
            {
                if (key.Split('.') is not [var sectionName, var fieldName] || _ws.Section(sectionName)?.Field(fieldName) is not { Secret: false } field || given == null) continue;
                JsonNode? value;
                if (field.Type == "array")
                {
                    var items = (given as JsonArray)?.Select(x => x?.ToString() ?? "") ?? given.ToString().Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    var kept = items.Where(x => Grounded(corpus, x)).Select(x => Brain.SmallModel.Shape(key, Brain.SmallModel.WholeToken(message, x)).Value).OfType<string>().Distinct().ToList();
                    if (kept.Count == 0) continue;
                    value = new JsonArray(kept.Select(x => (JsonNode?)JsonValue.Create(x)).ToArray());
                }
                else if (field.Type == "integer")
                {
                    if (Coerce(field, given) is not JsonValue v || !v.TryGetValue<int>(out var number) || !Regex.IsMatch(corpus, $@"(?<!\d){number}(?!\d)")) continue;
                    value = JsonValue.Create(number);
                }
                else if (field.Type == "boolean")
                {
                    // Nothing to find in the text but the subject: at least that has to be there.
                    if (Coerce(field, given) is not JsonValue v || !v.TryGetValue<bool>(out var flag)
                        || !fieldName.Split('_').Any(w => w.Length > 4 && corpus.Contains(w, StringComparison.Ordinal))) continue;
                    value = JsonValue.Create(flag);
                }
                else
                {
                    var text = given.ToString().Trim();
                    if (field.Values == null) text = Brain.SmallModel.WholeToken(message, text);
                    if (!Grounded(corpus, text) && !(field.Values != null && Grounded(corpus, text.Replace('_', ' ')))) continue;
                    if (Brain.SmallModel.Shape(key, text).Value is not { Length: > 0 } shaped) continue;
                    value = JsonValue.Create(shaped);
                }
                if (Proposable(p, sectionName, fieldName, value) is not { } proposal) continue;
                proposal.Confirm = Permanent.Contains(key);
                proposal.Why = key == "administrator.name" && value!.ToString() == p.Name ? "You said it is you." : key == "server.base_url" ? "Read from your message. It becomes part of every token's issuer and cannot be changed after the install."
                    : key == "server.tenant_id" ? "Read from your message. It becomes part of every token's issuer and cannot be renamed."
                    : "Read from your message.";
                proposals.Add(proposal);
            }
            return proposals;
        }

        // ------------------------------------------------------------ colleagues

        public Invite Invite(Participant lead, IEnumerable<string> sections, string department, string? name)
        {
            var known = sections.Where(s => _ws.Section(s) != null).Distinct().ToList();
            var invite = new Invite
            {
                Id = Workspace.NewId(), Sections = known, Department = department.Trim(), Name = string.IsNullOrWhiteSpace(name) ? null : name.Trim(),
                CreatedBy = lead.Name, CreatedAt = DateTime.UtcNow, ExpiresAt = DateTime.UtcNow.AddHours(Math.Clamp(_options.InviteLifetimeHours, 1, 24 * 30))
            };
            lock (_ws.Sync) _ws.Invites.Add(invite);
            _ws.Log($"{Who(lead)} asked {invite.Name ?? "a colleague"} in {invite.Department} for {string.Join(", ", known.Select(s => _ws.Section(s)!.Title))}.");
            _ws.Touch();
            return invite;
        }

        /// <summary>A note the lead can send as it is. <c>{link}</c> is filled in by the page, which knows its own address.</summary>
        public string InviteNote(Participant lead, Invite invite)
        {
            var company = _ws.ValueText("organization.company_name");
            var questions = Questions(invite.Sections).Take(6).ToList();
            var note = new StringBuilder($"Hi{(invite.Name != null ? " " + First(invite.Name) : "")},\n\n")
                .Append($"I am setting up {(company != null ? company + "'s" : "our")} sign-in service (Ark Identity Server) and need a few things that {invite.Department} knows:\n\n");
            foreach (var q in questions) note.Append("  • ").Append(q).Append('\n');
            if (invite.Sections.Any(s => _ws.Section(s)?.Fields.Any(f => f.Secret && !f.Held) == true))
                note.Append("\nPlease do not send a password or key by email: the page has a lock button for those, and they go straight to the server.\n");
            note.Append("\nThis link opens a short guided chat that asks only for those. It takes a couple of minutes, it tests what you enter, ")
                .Append("and nothing is installed without my sign-off:\n\n{link}\n\n")
                .Append($"It works until {invite.ExpiresAt:d MMMM, HH:mm} UTC and only for this.\n\nThanks,\n{lead.Name}");
            return note.ToString();
        }

        // ------------------------------------------------------------ review and install

        public async Task ReviewAsync(Participant p, CancellationToken cancel)
        {
            if (!p.IsLead) return;
            await RefreshAsync(cancel);
            // A plan is worth more with its database proven. For SQLite this only says the file is new.
            if (_ws.StatusOf("database")?["test"]?["ok"]?.GetValue<bool>() != true)
                await TestAsync("database", "setup_test_database", null, cancel);

            var review = await _mcp.CallAsync("setup_review", null, cancel);
            var content = review.Content;
            var publicUrl = content["plan"]?["public_url"]?.ToString();
            bool reached;
            lock (_ws.Sync)
                reached = publicUrl != null && _ws.People.Values.Any(x => string.Equals(x.Origin?.TrimEnd('/'), publicUrl.TrimEnd('/'), StringComparison.OrdinalIgnoreCase));

            // The server sees this agent calling from the same machine and warns that the public
            // address is a different one. Whether that address leads here is something the agent
            // can know better: somebody has opened this page at it, or nobody has.
            var warnings = new JsonArray();
            foreach (var w in content["warnings"] as JsonArray ?? new JsonArray())
            {
                var text = w?.ToString() ?? "";
                if (!text.StartsWith("You reached this server at", StringComparison.Ordinal)) warnings.Add(text);
                else if (!reached)
                    warnings.Add($"Nobody has opened this page at {publicUrl} yet, so I cannot confirm that address leads to this server. People and tokens go through it.");
            }
            content["warnings"] = warnings;
            _ws.Review = content;
            await RefreshAsync(cancel);

            if (content["ready"]?.GetValue<bool>() == true)
                _ws.Say(p, "Here is exactly what I will install. Nothing happens until you press the button, and after that the address and the tenant id are permanent.",
                    new JsonArray(new JsonObject { ["type"] = "plan", ["review_id"] = content["review_id"]?.ToString() }));
            else
            {
                var problems = (content["problems"] as JsonArray ?? new JsonArray())
                    .Select(x => x?["message"]?.ToString() ?? x?["problem"]?["message"]?.ToString() ?? "").Where(x => x.Length > 0).ToList();
                _ws.Say(p, "It is not ready to install yet:\n" + string.Join('\n', problems.Select(x => "- " + x)));
            }
            _ws.Touch();
        }

        public async Task<(bool Ok, string Text)> InstallAsync(Participant p, string reviewId, CancellationToken cancel)
        {
            if (!p.IsLead) return (false, "Only the person running the setup can install.");
            var tenant = _ws.ValueText("server.tenant_id") ?? "";
            var result = await _mcp.CallAsync("setup_complete", new JsonObject { ["review_id"] = reviewId, ["confirm"] = tenant }, cancel);
            if (result.IsError)
            {
                var changed = result.Error == "not_reviewed";
                _ws.Say(p, changed
                    ? "Something changed after you read the plan, so I did not install it. Here is the plan as it stands now."
                    : $"The install did not go through: {result.Message}");
                if (changed) await ReviewAsync(p, cancel);
                _ws.Touch();
                return (false, result.Message);
            }

            _log.LogInformation("Onboarding agent: tenant {Tenant} was installed, approved by {Lead}.", tenant, p.Name);
            _ws.Handover = result.Content;
            _ws.HandoverSince = DateTime.UtcNow;
            _ws.Vault.Clear();
            _ws.Review = null;
            List<Participant> everyone;
            lock (_ws.Sync) everyone = _ws.People.Values.Where(x => x.Greeted).ToList();
            foreach (var other in everyone.Where(x => !x.IsLead))
                _ws.Say(other, "The identity server is installed. Thank you for your part in it; this page can be closed.");
            _ws.Say(p, "Installed. This server is now your identity provider. Two things below are shown **once**: store them before you leave this page.");
            // Last: from here on nothing is written to the state file, and what was is removed.
            _ws.SetPhase(AgentPhase.Installed);
            _ws.Forget();
            _ws.Touch();
            return (true, "Installed.");
        }
    }
}
