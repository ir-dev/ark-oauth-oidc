using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Ark.Agents.TenantOnboarding.Brain;
using Ark.Agents.TenantOnboarding.Mcp;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace Ark.Agents.TenantOnboarding.Hosting
{
    /// <summary>
    /// The agent's page and the API behind it, as middleware in front of the setup wizard.
    ///
    /// In front of it because an identity server that is not set up answers every other request
    /// with its wizard: a page mapped the usual way would never be reached. Nothing here needs
    /// routing, authentication or MVC, so in an application that is not the identity server it can be,
    /// and is, the first thing in the pipeline.
    /// </summary>
    internal sealed class AgentMiddleware
    {
        const string CsrfHeader = "X-Ark-Agent";
        const int MaxMessage = 40_000;
        const int MaxBody = 2_500_000;

        static readonly Dictionary<string, (string Resource, string Type)> Assets = new(StringComparer.Ordinal)
        {
            ["agent.css"] = ("agent.css", "text/css; charset=utf-8"),
            ["agent.js"] = ("agent.js", "text/javascript; charset=utf-8")
        };

        readonly RequestDelegate _next;
        readonly AgentRuntime _rt;
        readonly AgentAccess _access;
        readonly IServer _server;
        readonly ConcurrentDictionary<string, byte> _busy = new(StringComparer.Ordinal);

        public AgentMiddleware(RequestDelegate next, AgentRuntime runtime, AgentAccess access, IServer server)
        {
            _next = next;
            _rt = runtime;
            _access = access;
            _server = server;
        }

        /// <summary>
        /// The https address to use instead, for a request that came over plain http to a host that
        /// has one; null when the connection will do. A host's UseHttpsRedirection sits behind this
        /// middleware and never sees these requests, and the setup code is among what they carry.
        /// </summary>
        string? BetterAddress(HttpContext context)
        {
            if (!_rt.Options.RedirectToHttps || AgentAccess.Encrypted(context)) return null;
            var host = context.Request.Host.Host;
            if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase) || (IPAddress.TryParse(host.Trim('[', ']'), out var ip) && IPAddress.IsLoopback(ip))) return null;
            int? port = null;
            foreach (var name in new[] { "https_port", "HTTPS_PORT", "ANCM_HTTPS_PORT" })
                if (int.TryParse(_rt.Configuration[name], out var configured) && configured > 0) { port = configured; break; }
            foreach (var address in _server.Features.Get<IServerAddressesFeature>()?.Addresses ?? Array.Empty<string>())
                if (port == null && address.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                    && int.TryParse(address[(address.LastIndexOf(':') + 1)..].TrimEnd('/'), out var bound)) port = bound;
            if (port == null) return null;
            return $"https://{host}{(port == 443 ? "" : ":" + port)}{context.Request.PathBase}{context.Request.Path}{context.Request.QueryString}";
        }

        Workspace Ws => _rt.Workspace;

        public async Task InvokeAsync(HttpContext context)
        {
            if (!_rt.Options.Enabled)
            {
                await _next(context);
                return;
            }
            var request = context.Request;
            var active = Ws.Phase is AgentPhase.Starting or AgentPhase.Collecting or AgentPhase.Installed;

            if (!request.Path.StartsWithSegments(_rt.Prefix, out var rest))
            {
                // A browser that opens an unconfigured server meets the agent, not the wizard. The
                // wizard is one link away, and still where it always was.
                if (_rt.Options.GreetAtRoot && _rt.SameProcess && Ws.Phase is AgentPhase.Starting or AgentPhase.Collecting && !_rt.ServerConfigured
                    && HttpMethods.IsGet(request.Method) && request.Path.Value is "/" or ""
                    && request.Headers.Accept.ToString().Contains("text/html", StringComparison.OrdinalIgnoreCase))
                {
                    context.Response.Redirect($"{request.PathBase}{_rt.Prefix}");
                    return;
                }
                await _next(context);
                return;
            }

            var path = rest.Value ?? "";
            var headers = context.Response.Headers;
            headers.XContentTypeOptions = "nosniff";
            headers["Referrer-Policy"] = "no-referrer";

            if (active && BetterAddress(context) is { } secure)
            {
                headers.CacheControl = "no-store";
                if (HttpMethods.IsGet(request.Method)) context.Response.Redirect(secure, permanent: false, preserveMethod: true);
                else await Fail(context, 400, "Use this server's https address: this one is not encrypted.");
                return;
            }

            if (HttpMethods.IsGet(request.Method))
            {
                if (path is "" or "/")
                {
                    if (!active)
                    {
                        context.Response.Redirect($"{request.PathBase}/");
                        return;
                    }
                    await PageAsync(context);
                    return;
                }
                if (path.StartsWith("/assets/", StringComparison.Ordinal))
                {
                    await AssetAsync(context, path["/assets/".Length..]);
                    return;
                }
                if (path.StartsWith("/join/", StringComparison.Ordinal))
                {
                    Join(context, path["/join/".Length..]);
                    return;
                }
                if (path == "/api/state")
                {
                    await StateAsync(context);
                    return;
                }
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
            }

            if (!HttpMethods.IsPost(request.Method) || !path.StartsWith("/api/", StringComparison.Ordinal))
            {
                context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                return;
            }
            headers.CacheControl = "no-store";
            // A JSON body and a header a form cannot send: another site's page cannot make this request.
            if (request.Headers[CsrfHeader] != "1" || !(request.ContentType ?? "").StartsWith("application/json", StringComparison.OrdinalIgnoreCase))
            {
                await Fail(context, 400, $"Calls are JSON POSTs carrying {CsrfHeader}: 1.");
                return;
            }

            JsonObject body;
            try
            {
                if (request.ContentLength > MaxBody) { await Fail(context, 413, "That is too large."); return; }
                // A body sent in chunks declares no length: the server stops reading at the same size.
                if (context.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } limit) limit.MaxRequestBodySize = MaxBody;
                body = await JsonSerializer.DeserializeAsync<JsonObject>(request.Body, cancellationToken: context.RequestAborted) ?? new JsonObject();
            }
            catch (JsonException)
            {
                await Fail(context, 400, "The request is not JSON.");
                return;
            }
            catch (BadHttpRequestException ex)
            {
                await Fail(context, ex.StatusCode, "The request could not be read.");
                return;
            }

            try
            {
                await ApiAsync(context, path["/api/".Length..], body);
            }
            catch (McpUnauthorizedException)
            {
                await Fail(context, 409, "The identity server no longer takes the setup code: setup was finished another way.");
            }
            catch (McpException ex)
            {
                // Addresses inside the network are the lead's business.
                await Fail(context, 502, "I could not reach the identity server's setup tools" + (_access.Who(context) is { IsLead: true } ? $": {ex.Message}" : "."));
            }
            catch (System.Text.RegularExpressions.RegexMatchTimeoutException)
            {
                // Not read for secrets is not passed on.
                await Fail(context, 400, "I could not read that safely. Please send it in smaller parts.");
            }
        }

        // ------------------------------------------------------------ page

        async Task PageAsync(HttpContext context)
        {
            var basePath = WebUtility.HtmlEncode($"{context.Request.PathBase}{_rt.Prefix}");
            var html = Resource("agent.html").Replace("{{BASE}}", basePath).Replace("{{AGENT}}", WebUtility.HtmlEncode(_rt.Options.AgentName));
            var headers = context.Response.Headers;
            headers.ContentType = "text/html; charset=utf-8";
            headers.CacheControl = "no-store";
            headers.ContentSecurityPolicy =
                "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
                "form-action 'none'; frame-ancestors 'none'; base-uri 'none'";
            await context.Response.WriteAsync(html);
        }

        async Task AssetAsync(HttpContext context, string file)
        {
            if (!Assets.TryGetValue(file, out var asset))
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
            }
            context.Response.ContentType = asset.Type;
            context.Response.Headers.CacheControl = "no-cache";
            await context.Response.WriteAsync(Resource(asset.Resource));
        }

        static string Resource(string name)
        {
            var assembly = typeof(AgentMiddleware).Assembly;
            using var stream = assembly.GetManifestResourceStream($"Ark.Agents.TenantOnboarding.wwwroot.{name}")
                ?? throw new InvalidOperationException($"embedded resource '{name}' is missing");
            using var reader = new StreamReader(stream);
            return reader.ReadToEnd();
        }

        /// <summary>A colleague's link: it signs them in to their part of the conversation and leaves the address bar.</summary>
        void Join(HttpContext context, string token)
        {
            var home = $"{context.Request.PathBase}{_rt.Prefix}";
            context.Response.Headers.CacheControl = "no-store";
            // The lead trying out their own link, or being sent one: they stay who they are.
            if (_access.Who(context) is { IsLead: true })
            {
                context.Response.Redirect(home);
                return;
            }
            var payload = _access.Verify(token);
            Invite? invite = null;
            if (payload?["k"]?.ToString() == "invite")
                lock (Ws.Sync) invite = Ws.Invites.FirstOrDefault(i => i.Id == payload["i"]?.ToString());
            if (invite == null || invite.Revoked || DateTime.UtcNow > invite.ExpiresAt || Ws.Phase != AgentPhase.Collecting)
            {
                context.Response.Redirect(home + "?link=expired");
                return;
            }

            Participant person;
            lock (Ws.Sync)
            {
                // One link, one seat: whoever opens it again continues the same conversation.
                person = invite.ParticipantId != null && Ws.People.TryGetValue(invite.ParticipantId, out var seated) ? seated
                    : new Participant
                    {
                        Id = Workspace.NewId(), Role = "contributor", InviteId = invite.Id, Sections = invite.Sections.ToList(),
                        Department = invite.Department, Name = invite.Name ?? ""
                    };
                Ws.People[person.Id] = person;
                invite.ParticipantId = person.Id;
                if (invite.OpenedAt == null)
                {
                    invite.OpenedAt = DateTime.UtcNow;
                    Ws.Log($"{invite.Name ?? "The colleague"} in {invite.Department} opened the link.");
                }
            }
            _access.SignIn(context, person);
            Ws.Touch();
            context.Response.Redirect(home);
        }

        // ------------------------------------------------------------ state

        async Task StateAsync(HttpContext context)
        {
            context.Response.Headers.CacheControl = "no-store";
            var person = _access.Who(context);

            if (Ws.Phase == AgentPhase.NotNeeded)
            {
                await Json(context, new JsonObject { ["phase"] = "not_needed", ["home"] = $"{context.Request.PathBase}/" });
                return;
            }
            if (person == null && _access.IsLocal(context) && _rt.Code.Code != null)
            {
                // At the machine itself: the setup lead, as for the wizard.
                person = new Participant { Id = Workspace.NewId(), Role = "lead", Department = "Setup lead" };
                lock (Ws.Sync) Ws.People[person.Id] = person;
                _access.SignIn(context, person);
            }

            // Which model, and what its gateway answers when it fails, is for the people taking part:
            // an error can name hosts, accounts and limits, and that part is the lead's.
            var agent = new JsonObject
            {
                ["name"] = _rt.Options.AgentName,
                ["model"] = person == null ? null : _rt.Brain.ModelLabel,
                ["guided"] = person != null && _rt.Brain.ModelLabel == null,
                ["small"] = person != null && _rt.Brain.SmallModel,
                ["notice"] = person == null || Ws.ModelNotice == null ? null : person.IsLead ? Ws.ModelNotice
                    : "I am going on without my language model for now, one question at a time. The board works as always.",
                ["wizard"] = _rt.SameProcess ? $"{context.Request.PathBase}/ark-idp/setup" : null
            };
            if (Ws.Phase == AgentPhase.Starting)
            {
                await Json(context, new JsonObject { ["phase"] = "starting", ["why"] = person is { IsLead: true } || _access.IsLocal(context) ? Ws.StartingWhy : "The server is starting.", ["agent"] = agent });
                return;
            }
            if (person == null)
            {
                await Json(context, new JsonObject { ["phase"] = Phase(), ["needs"] = "unlock", ["agent"] = agent });
                return;
            }
            if (!person.Greeted)
            {
                // Before the first word: who is this? Every value is recorded with who supplied it.
                await Json(context, new JsonObject
                {
                    ["phase"] = Phase(), ["needs"] = "name", ["agent"] = agent,
                    ["me"] = new JsonObject { ["name"] = person.Name, ["department"] = person.Department, ["role"] = person.Role }
                });
                return;
            }

            // Hold the request until something changes: the page is current without polling hard.
            if (long.TryParse(context.Request.Query["v"], out var seen) && seen == Ws.Version)
                await Task.WhenAny(Ws.WaitAsync(seen), Task.Delay(TimeSpan.FromSeconds(25), context.RequestAborted));
            if (context.RequestAborted.IsCancellationRequested) return;

            await Json(context, Build(person, agent, context.Request.PathBase));
        }

        string Phase() => Ws.Phase switch
        {
            AgentPhase.Collecting => "collecting",
            AgentPhase.Installed => "installed",
            AgentPhase.NotNeeded => "not_needed",
            _ => "starting"
        };

        JsonObject Build(Participant p, JsonObject agent, PathString pathBase)
        {
            lock (Ws.Sync)
            {
                var now = DateTime.UtcNow;
                var sections = new JsonArray();
                foreach (var section in Ws.Catalogue.Where(s => p.May(s.Name)))
                {
                    var status = Ws.StatusOf(section.Name);
                    var fields = new JsonArray();
                    foreach (var f in section.Fields)
                    {
                        var key = $"{section.Name}.{f.Name}";
                        JsonObject? source = null;
                        if (Ws.Sources.TryGetValue(key, out var from))
                            source = new JsonObject
                            {
                                ["by"] = from["provided_by"]?.ToString(), ["department"] = from["department"]?.ToString(),
                                ["note"] = from["note"]?.ToString(), ["at"] = from["at"]?.ToString()
                            };
                        fields.Add(new JsonObject
                        {
                            ["name"] = f.Name, ["type"] = f.Type, ["required"] = f.Required, ["description"] = f.Description, ["ask"] = f.Ask,
                            ["default"] = f.Default, ["values"] = f.Values == null ? null : new JsonArray(f.Values.Select(v => (JsonNode?)JsonValue.Create(v)).ToArray()),
                            ["secret"] = f.Secret, ["held"] = f.Held,
                            ["value"] = Ws.Values.TryGetValue(key, out var value) ? value?.DeepClone() : null,
                            ["source"] = source
                        });
                    }
                    var invite = Ws.Invites.LastOrDefault(i => !i.Revoked && i.Sections.Contains(section.Name));
                    sections.Add(new JsonObject
                    {
                        ["name"] = section.Name, ["title"] = section.Title, ["owner"] = section.Owner, ["purpose"] = section.Purpose,
                        ["status"] = status?["status"]?.ToString() ?? "default",
                        ["optional"] = status?["optional"]?.GetValue<bool>() == true,
                        ["missing"] = status?["missing"]?.DeepClone() ?? new JsonArray(),
                        ["problems"] = status?["problems"]?.DeepClone() ?? new JsonArray(),
                        ["test"] = status?["test"]?.DeepClone(),
                        ["fields"] = fields,
                        ["asked"] = invite == null ? null : new JsonObject
                        {
                            ["name"] = invite.Name, ["department"] = invite.Department, ["status"] = invite.Status(now, _rt.Options.QuietAfterHours)
                        }
                    });
                }

                var state = new JsonObject
                {
                    ["version"] = Ws.Version,
                    ["phase"] = Phase(),
                    ["agent"] = agent,
                    ["me"] = new JsonObject
                    {
                        ["id"] = p.Id, ["name"] = p.Name, ["department"] = p.Department, ["role"] = p.Role,
                        ["sections"] = new JsonArray(p.Sections.Select(s => (JsonNode?)JsonValue.Create(s)).ToArray())
                    },
                    ["busy"] = _busy.ContainsKey(p.Id),
                    ["board"] = new JsonObject
                    {
                        ["ready"] = Ws.ReadyForReview,
                        ["essentials"] = new JsonObject { ["done"] = Workspace.Essentials.Count(Ws.Values.ContainsKey), ["total"] = Workspace.Essentials.Length },
                        ["company"] = Ws.ValueText("organization.company_name"),
                        ["sections"] = sections
                    },
                    ["proposals"] = new JsonArray(Ws.Proposals.Where(x => x.ParticipantId == p.Id).TakeLast(60).Select(x => (JsonNode?)new JsonObject
                    {
                        ["id"] = x.Id, ["section"] = x.Section, ["field"] = x.Field, ["title"] = Ws.Catalogue.FirstOrDefault(s => s.Name == x.Section)?.Title,
                        ["value"] = x.Value?.DeepClone(), ["why"] = x.Why, ["confirm"] = x.Confirm, ["state"] = x.State
                    }).ToArray()),
                    ["messages"] = new JsonArray((Ws.Conversations.TryGetValue(p.Id, out var list) ? list : new List<ChatMessage>()).Select(m => (JsonNode?)new JsonObject
                    {
                        ["id"] = m.Id, ["from"] = m.From, ["text"] = m.Text, ["widgets"] = m.Widgets?.DeepClone(), ["at"] = m.At.ToString("O")
                    }).ToArray())
                };

                if (p.IsLead)
                {
                    state["team"] = new JsonArray(Ws.Invites.Select(i => (JsonNode?)new JsonObject
                    {
                        ["id"] = i.Id, ["name"] = i.Name, ["department"] = i.Department,
                        ["sections"] = new JsonArray(i.Sections.Select(s => (JsonNode?)JsonValue.Create(Ws.Catalogue.FirstOrDefault(c => c.Name == s)?.Title ?? s)).ToArray()),
                        ["status"] = i.Status(now, _rt.Options.QuietAfterHours), ["created_at"] = i.CreatedAt.ToString("O"),
                        ["expires_at"] = i.ExpiresAt.ToString("O"),
                        ["path"] = i.Revoked || i.AnsweredAt != null ? null : $"{pathBase}{_rt.Prefix}/join/{_access.InviteToken(i)}"
                    }).ToArray());
                    state["activity"] = new JsonArray(Ws.Activities.TakeLast(40).Reverse().Select(a => (JsonNode?)new JsonObject
                    {
                        ["at"] = a.At.ToString("O"), ["text"] = a.Text
                    }).ToArray());
                    state["review"] = Ws.Review?.DeepClone();
                    state["handover"] = Ws.Handover?.DeepClone();
                }
                return state;
            }
        }

        // ------------------------------------------------------------ API

        async Task ApiAsync(HttpContext context, string action, JsonObject body)
        {
            static string Text(JsonObject o, string name) => o[name] is JsonValue v && v.TryGetValue<string>(out var s) ? s.Trim() : "";
            // A name goes into the log and the record: one line, nothing that could pass for another entry.
            static string Line(string text) => new string(text.Select(c => char.IsControl(c) || c is '\u2028' or '\u2029' ? ' ' : c).ToArray()).Trim();

            if (action == "unlock")
            {
                if (!_access.CodeMatches(Text(body, "code")))
                {
                    await Fail(context, 403, "That is not the setup code in this server's start-up log.");
                    return;
                }
                // The wizard presents the code here too, each time its page is opened: whoever is the
                // lead already stays the same person, with the conversation they have.
                if (_access.Who(context) is not { IsLead: true })
                {
                    var lead = new Participant { Id = Workspace.NewId(), Role = "lead", Department = "Setup lead" };
                    lock (Ws.Sync) Ws.People[lead.Id] = lead;
                    _access.SignIn(context, lead);
                }
                await Json(context, new JsonObject { ["ok"] = true });
                return;
            }

            var p = _access.Who(context);
            if (p == null)
            {
                await Fail(context, 401, "Open the page again: you are not signed in to this conversation.");
                return;
            }
            // The work a person asked for is finished even if they close the tab meanwhile.
            using var limit = new CancellationTokenSource(TimeSpan.FromMinutes(5));
            var cancel = limit.Token;

            if (action == "ack" && p.IsLead && Ws.Phase == AgentPhase.Installed)
            {
                // The lead has the credentials: nothing is left that this agent should hold.
                Ws.Handover = null;
                Ws.SetPhase(AgentPhase.NotNeeded);
                await Json(context, new JsonObject { ["ok"] = true, ["home"] = $"{context.Request.PathBase}/" });
                return;
            }
            if (Ws.Phase != AgentPhase.Collecting)
            {
                await Fail(context, 409, "Setup is no longer in progress.");
                return;
            }

            switch (action)
            {
                case "hello":
                {
                    var name = Line(Text(body, "name"));
                    if (name.Length is 0 or > 120) { await Fail(context, 400, "Please give your name, so the record shows who supplied what."); return; }
                    p.Name = name;
                    var department = Line(Text(body, "department"));
                    if (department.Length is > 0 and <= 120) p.Department = department;
                    // The address the browser is on: where this server can demonstrably be reached.
                    var origin = Text(body, "origin");
                    if (Uri.TryCreate(origin, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https") p.Origin = uri.GetLeftPart(UriPartial.Authority);
                    else p.Origin ??= "";
                    using (await _rt.Brain.EnterAsync(p, cancel))
                    {
                        await _rt.Brain.RefreshAsync(cancel);
                        _rt.Brain.Greet(p);
                    }
                    Ws.Touch();
                    await Json(context, new JsonObject { ["ok"] = true });
                    return;
                }
                case "message":
                {
                    var text = Text(body, "text");
                    if (text.Length == 0) { await Fail(context, 400, "Say something first."); return; }
                    if (text.Length > MaxMessage)
                    {
                        await Fail(context, 413, $"That is {text.Length:N0} characters; I read up to {MaxMessage:N0} at a time. Paste the part that matters.");
                        return;
                    }
                    await Busy(p, async () => await _rt.Brain.TurnAsync(p, text, cancel), cancel);
                    await Json(context, new JsonObject { ["ok"] = true });
                    return;
                }
                case "set" or "secret":
                {
                    var values = action == "secret"
                        ? new JsonObject { [Text(body, "field")] = body["value"]?.DeepClone() }
                        : body["values"] as JsonObject is { } given ? (JsonObject)given.DeepClone() : new JsonObject();
                    var (ok, text) = await _rt.Brain.SetAsync(p, Text(body, "section"), values,
                        action == "secret" ? "entered through the lock button" : "entered on the board", cancel);
                    await Json(context, new JsonObject { ["ok"] = ok, ["msg"] = text });
                    return;
                }
                case "proposal":
                {
                    var ids = (body["ids"] as JsonArray ?? new JsonArray()).Select(x => x?.ToString() ?? "").ToList();
                    var accept = body["accept"] is JsonValue yes && yes.TryGetValue<bool>(out var said) && said;
                    await Busy(p, async () => await _rt.Brain.AcceptAsync(p, ids, accept, cancel), cancel);
                    await Json(context, new JsonObject { ["ok"] = true });
                    return;
                }
                case "test":
                {
                    var (ok, text) = await _rt.Brain.RunTestAsync(p, Text(body, "section"), Text(body, "to"), cancel);
                    await Json(context, new JsonObject { ["ok"] = ok, ["msg"] = text });
                    return;
                }
            }

            if (!p.IsLead)
            {
                await Fail(context, 403, "That is for the person running the setup.");
                return;
            }
            switch (action)
            {
                case "invite":
                {
                    var sections = (body["sections"] as JsonArray ?? new JsonArray()).Select(x => x?.ToString() ?? "").ToList();
                    var department = Line(Text(body, "department"));
                    if (department.Length > 120) department = department[..120];
                    var invitee = Line(Text(body, "name"));
                    if (invitee.Length > 120) invitee = invitee[..120];
                    if (sections.Count == 0) { await Fail(context, 400, "Choose what to ask for."); return; }
                    if (department.Length == 0) department = Ws.Section(sections[0])?.Owner ?? "A colleague";
                    var invite = _rt.Brain.Invite(p, sections, department, invitee);
                    if (invite.Sections.Count == 0) { await Fail(context, 400, "Choose what to ask for."); return; }
                    await Json(context, new JsonObject
                    {
                        ["ok"] = true, ["id"] = invite.Id, ["path"] = $"{context.Request.PathBase}{_rt.Prefix}/join/{_access.InviteToken(invite)}",
                        ["note"] = _rt.Brain.InviteNote(p, invite), ["expires_at"] = invite.ExpiresAt.ToString("O")
                    });
                    return;
                }
                case "invite/revoke":
                {
                    lock (Ws.Sync)
                        if (Ws.Invites.FirstOrDefault(i => i.Id == Text(body, "id")) is { } invite)
                        {
                            invite.Revoked = true;
                            Ws.Log($"The link for {invite.Name ?? "the colleague"} in {invite.Department} was withdrawn.");
                        }
                    Ws.Touch();
                    await Json(context, new JsonObject { ["ok"] = true });
                    return;
                }
                case "review":
                    await Busy(p, async () => await _rt.Brain.ReviewAsync(p, cancel), cancel);
                    await Json(context, new JsonObject { ["ok"] = true });
                    return;
                case "install":
                {
                    (bool Ok, string Text) done = (false, "");
                    await Busy(p, async () => done = await _rt.Brain.InstallAsync(p, Text(body, "review_id"), cancel), cancel);
                    await Json(context, new JsonObject { ["ok"] = done.Ok, ["msg"] = done.Text });
                    return;
                }
                default:
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    return;
            }
        }

        /// <summary>Runs one person's turn, with the page showing the agent at work meanwhile.</summary>
        async Task Busy(Participant p, Func<Task> work, CancellationToken cancel)
        {
            using (await _rt.Brain.EnterAsync(p, cancel))
            {
                _busy[p.Id] = 1;
                Ws.Touch();
                try
                {
                    await work();
                }
                finally
                {
                    _busy.TryRemove(p.Id, out _);
                    Ws.Touch();
                }
            }
        }

        static Task Json(HttpContext context, JsonObject body)
        {
            context.Response.ContentType = "application/json; charset=utf-8";
            return context.Response.WriteAsync(body.ToJsonString());
        }

        static Task Fail(HttpContext context, int status, string message)
        {
            context.Response.StatusCode = status;
            return Json(context, new JsonObject { ["ok"] = false, ["msg"] = message });
        }
    }
}
