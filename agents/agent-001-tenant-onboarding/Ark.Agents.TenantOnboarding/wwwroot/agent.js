/* Ark Pilot: the onboarding agent's page.
   One long-held request keeps the page current (api/state?v=N answers when something changes), so
   what a colleague enters on their own link shows up here as they enter it. Everything a person
   or the model wrote is put into the page as text nodes, never as markup. */
(function () {
    "use strict";

    var base = document.body.dataset.base;
    var agentName = document.body.dataset.agent;
    var $ = function (id) { return document.getElementById(id); };
    var state = null, version = 0, sending = false;
    var openSecs = {}, editing = null, rendered = {}, boardStale = false, sheetOpen = false;
    var expired = /[?&]link=expired/.test(location.search);
    var busySince = 0, busyTimer = null;

    // ------------------------------------------------------------ small tools

    function h(tag, props) {
        var el = document.createElement(tag);
        for (var k in props || {}) {
            var v = props[k];
            if (v == null || v === false) continue;
            if (k === "class") el.className = v;
            else if (k === "text") el.textContent = v;
            else if (k.slice(0, 2) === "on") el.addEventListener(k.slice(2), v);
            else if (k === "value") el.value = v;
            else if (v === true) el.setAttribute(k, "");
            else el.setAttribute(k, v);
        }
        for (var i = 2; i < arguments.length; i++) add(el, arguments[i]);
        return el;
    }
    function add(el, child) {
        if (child == null || child === false) return;
        if (Array.isArray(child)) child.forEach(function (c) { add(el, c); });
        else el.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
    }
    function icon(name) {
        var ns = "http://www.w3.org/2000/svg";
        var svg = document.createElementNS(ns, "svg"), use = document.createElementNS(ns, "use");
        use.setAttribute("href", "#i-" + name);
        svg.setAttribute("aria-hidden", "true");
        svg.appendChild(use);
        return svg;
    }
    function toast(text) {
        var t = $("toast");
        t.textContent = text;
        t.hidden = false;
        clearTimeout(toast.timer);
        toast.timer = setTimeout(function () { t.hidden = true; }, 3200);
    }
    function copy(text, what) {
        var done = function () { toast((what || "Copied") + " copied"); };
        if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(done, function () { toast("Could not copy; select it and copy by hand"); });
        else {
            var area = h("textarea", { value: text });
            document.body.appendChild(area);
            area.select();
            try { document.execCommand("copy"); done(); } catch (e) { toast("Could not copy; select it and copy by hand"); }
            area.remove();
        }
    }
    function ago(iso) {
        var s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
        if (s < 50) return "just now";
        if (s < 3600) return Math.round(s / 60) + " min ago";
        if (s < 86400) return Math.round(s / 3600) + " h ago";
        return Math.round(s / 86400) + " d ago";
    }
    function human(name) { return name.replace(/_/g, " "); }
    function show(value) {
        if (value == null) return "";
        if (Array.isArray(value)) return value.join(", ");
        if (value === true) return "yes";
        if (value === false) return "no";
        return String(value);
    }

    function post(action, body) {
        return fetch(base + "/api/" + action, {
            method: "POST", headers: { "Content-Type": "application/json", "X-Ark-Agent": "1" }, body: JSON.stringify(body || {})
        }).then(function (r) {
            return r.json().catch(function () { return { ok: false, msg: "The server answered " + r.status + "." }; });
        }, function () { return { ok: false, msg: "The server did not answer. Is it still running?" }; });
    }

    // ------------------------------------------------------------ text: **bold**, `code`, links, lists, secrets

    function inline(text, into) {
        var re = /(\*\*[^*]+\*\*|\*[^*\s][^*\n]*\*|`[^`]+`|\[\[vault:\d+\]\]|https?:\/\/[^\s<>()]+[^\s<>().,;:!?'"])/g, last = 0, m;
        while ((m = re.exec(text))) {
            if (m.index > last) into.appendChild(document.createTextNode(text.slice(last, m.index)));
            var t = m[0];
            if (t.slice(0, 2) === "**") into.appendChild(h("strong", { text: t.slice(2, -2) }));
            else if (t[0] === "*") into.appendChild(h("em", { text: t.slice(1, -1) }));
            else if (t[0] === "`") into.appendChild(h("code", { text: t.slice(1, -1) }));
            else if (t.slice(0, 2) === "[[") into.appendChild(h("span", { class: "vault", title: "Held for the identity server. Not in this conversation, and never shown to the language model." }, icon("lock"), "kept safe"));
            else into.appendChild(h("a", { href: t, target: "_blank", rel: "noopener noreferrer", text: t }));
            last = m.index + t.length;
        }
        if (last < text.length) into.appendChild(document.createTextNode(text.slice(last)));
        return into;
    }
    function prose(text) {
        var out = [], list = null;
        text.split(/\n/).forEach(function (line) {
            var item = /^\s*[-•*]\s+(.*)$/.exec(line);
            if (item) {
                if (!list) { list = h("ul"); out.push(list); }
                list.appendChild(inline(item[1], h("li")));
            } else {
                list = null;
                if (line.trim()) out.push(inline(line, h("p")));
            }
        });
        return out;
    }

    // ------------------------------------------------------------ keeping current

    function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

    async function watch() {
        for (;;) {
            var held = state && state.version != null;
            try {
                var r = await fetch(base + "/api/state?v=" + (held ? version : 0), { cache: "no-store", headers: { Accept: "application/json" } });
                apply(await r.json());
            } catch (e) {
                await sleep(2500);
                continue;
            }
            if (!(state && state.version != null)) await sleep(1200);
        }
    }
    async function refresh() {
        try {
            var r = await fetch(base + "/api/state?v=0", { cache: "no-store" });
            apply(await r.json());
        } catch (e) { /* the watcher will catch up */ }
    }
    function apply(s) {
        if (s.version != null && state && state.version != null && s.version < state.version) return;
        state = s;
        if (s.version != null) version = s.version;
        render();
    }

    // ------------------------------------------------------------ what to show

    function render() {
        var s = state, gate = $("gate"), work = $("work"), hand = $("handover");
        var agent = s.agent || {};
        if (agent.model) { $("model-chip").textContent = agent.model; $("model-chip").hidden = false; }
        else if (agent.guided) { $("model-chip").textContent = "Guided mode"; $("model-chip").hidden = false; }
        var lead = s.me && s.me.role === "lead";
        // The form is the lead's alternative. A colleague with a link has no business there.
        if (agent.wizard && s.phase !== "installed" && (lead || s.needs === "unlock" && !expired)) { $("wizard-link").href = agent.wizard; $("wizard-link").hidden = false; }
        else $("wizard-link").hidden = true;

        var mode = s.phase === "not_needed" || s.phase === "starting" || s.needs ? "gate"
            : s.phase === "installed" ? (lead && s.handover ? "handover" : "gate") : "work";
        gate.hidden = mode !== "gate";
        work.hidden = mode !== "work";
        hand.hidden = mode !== "handover";
        $("board-toggle").hidden = mode !== "work";

        if (mode === "gate") renderGate(s);
        else if (mode === "handover") renderHandover(s);
        else renderWork(s);
    }

    // ------------------------------------------------------------ before the conversation

    var gateKind = null;
    function renderGate(s) {
        var kind = s.phase === "not_needed" ? "done" : s.phase === "starting" ? "starting:" + s.why
            : s.needs === "unlock" ? "unlock" : s.needs === "name" ? "name" : "thanks";
        if (kind === gateKind) return;
        gateKind = kind;
        var card = $("gate-card");
        card.textContent = "";

        if (kind === "done") {
            add(card, [h("h1", { text: "This identity server is set up" }), h("p", { text: "There is nothing left for me to do here. Taking you to it…" }),
                h("div", { class: "actions" }, h("a", { class: "primary ghost", href: s.home || "/", text: "Open the server" }))]);
            setTimeout(function () { location.href = s.home || "/"; }, 1800);
        } else if (kind.indexOf("starting") === 0) {
            add(card, [h("div", { class: "spinner" }), h("h1", { text: "Getting ready" }), h("p", { text: s.why || "The server is starting." })]);
        } else if (kind === "thanks") {
            add(card, [h("h1", { text: "All done. Thank you" }), h("p", { text: "The identity server has been installed. You can close this page." })]);
        } else if (kind === "unlock") {
            var code = h("input", { id: "code", autocomplete: "off", spellcheck: "false", placeholder: "XXXX-XXXX-XXXX", "aria-label": "Setup code" });
            var err = h("div", { class: "error", role: "alert" });
            var go = function (e) {
                e.preventDefault();
                post("unlock", { code: code.value }).then(function (r) { if (r.ok) { gateKind = null; refresh(); } else err.textContent = r.msg; });
            };
            add(card, [
                h("h1", { text: expired ? "This link no longer works" : "One check before we start" }),
                h("p", { text: expired
                    ? "It has expired, was withdrawn, or the setup is finished. Ask the person who sent it for a new one. If you are running the setup yourself, enter the setup code."
                    : "Whoever sets this server up becomes its administrator, so I need to know you can see the server. Enter the setup code from its start-up log (it is also in setup-code.txt in the data directory)." }),
                h("form", { onsubmit: go }, h("label", { for: "code", text: "Setup code" }), code, err,
                    h("div", { class: "actions" }, h("button", { class: "primary", type: "submit", text: "Continue" })))
            ]);
            code.focus();
        } else {
            var me = s.me || {}, contributor = me.role !== "lead";
            var name = h("input", { id: "who", autocomplete: "name", value: me.name || "", maxlength: "120" });
            var dept = h("input", { id: "dept", value: contributor ? me.department || "" : "", maxlength: "120", placeholder: contributor ? "" : "e.g. Platform engineering" });
            var err2 = h("div", { class: "error", role: "alert" });
            var hello = function (e) {
                e.preventDefault();
                if (!name.value.trim()) { err2.textContent = "Please give your name."; return; }
                post("hello", { name: name.value, department: dept.value, origin: location.origin }).then(function (r) {
                    if (r.ok) { gateKind = null; refresh(); } else err2.textContent = r.msg;
                });
            };
            add(card, [
                h("h1", { text: contributor ? "Thanks for helping with this" : "Hi, I'm " + agentName }),
                h("p", { text: contributor
                    ? "A colleague is setting up your organization's sign-in service and asked for a few things you know. It takes a couple of minutes."
                    : "I set this identity server up by conversation: you tell me about it in your own words, I do the filing, the testing and the chasing. First, who am I talking to? Every value is recorded with who supplied it." }),
                h("form", { onsubmit: hello },
                    h("label", { for: "who", text: "Your name" }), name,
                    h("label", { for: "dept" }, "Your team ", h("em", { text: contributor ? "" : "(optional)" })), dept, err2,
                    h("div", { class: "actions" }, h("button", { class: "primary", type: "submit", text: "Start" })))
            ]);
            (name.value ? dept : name).focus();
        }
    }

    // ------------------------------------------------------------ the conversation

    function renderWork(s) {
        gateKind = null;
        var company = s.board.company, lead = s.me.role === "lead";
        $("subtitle").textContent = lead ? "Setting up " + (company ? company + "'s identity server" : "this identity server")
            : "Helping with " + (company ? company + "'s" : "the") + " identity server";
        var notice = $("notice");
        notice.hidden = !s.agent.notice;
        notice.textContent = s.agent.notice || "";
        if (location.protocol === "http:" && !/^(localhost|127\.|\[::1\])/.test(location.host)) {
            notice.hidden = false;
            notice.textContent = "This page is on plain http: what you type crosses the network unencrypted. Use the server's https address.";
        }

        var box = $("messages"), nearEnd = box.scrollHeight - box.scrollTop - box.clientHeight < 140;
        var lastAgent = null, lastPlan = null;
        s.messages.forEach(function (m) {
            if (m.from === "agent") lastAgent = m.id;
            (m.widgets || []).forEach(function (w) { if (w.type === "plan") lastPlan = m.id; });
        });
        var proposals = {};
        s.proposals.forEach(function (p) { proposals[p.id] = p; });

        var seen = {}, grew = false;
        s.messages.forEach(function (m) {
            seen[m.id] = true;
            var live = m.id === lastAgent && !s.busy && s.messages[s.messages.length - 1].id === m.id;
            var sig = JSON.stringify([m.text, m.widgets, live, m.id === lastPlan, (m.widgets || []).map(function (w) {
                if (w.type === "proposal") return w.ids.map(function (id) { return proposals[id] && proposals[id].state; });
                if (w.type === "plan") return s.review && s.review.review_id;
                if (w.type === "secret") return fieldValue(s, w.section, w.field);
                return 0;
            })]);
            var old = rendered[m.id];
            if (old && old.sig === sig) return;
            var node = message(s, m, live, m.id === lastPlan, proposals);
            if (old) box.replaceChild(node, old.node);
            else { box.appendChild(node); grew = true; }
            rendered[m.id] = { sig: sig, node: node };
        });
        Object.keys(rendered).forEach(function (id) { if (!seen[id]) { rendered[id].node.remove(); delete rendered[id]; } });
        $("typing").hidden = !s.busy;
        // A slow gateway is not a hung page: say so once the wait is noticeable.
        if (s.busy && !busySince) {
            busySince = Date.now();
            clearTimeout(busyTimer);
            $("typing-note").textContent = "";
            busyTimer = setTimeout(function () {
                $("typing-note").textContent = s.agent.small ? "Reading. This model runs on a small server, so a long message can take a minute. The board works meanwhile."
                    : "Still working. The model sometimes needs a second attempt.";
            }, s.agent.small ? 5000 : 15000);
        } else if (!s.busy) { busySince = 0; clearTimeout(busyTimer); $("typing-note").textContent = ""; }
        if (grew && nearEnd || s.busy && nearEnd) box.scrollTop = box.scrollHeight;

        renderBoard(s);
    }

    function fieldValue(s, section, field) {
        var sec = s.board.sections.filter(function (x) { return x.name === section; })[0];
        var f = sec && sec.fields.filter(function (x) { return x.name === field; })[0];
        return f ? f.value : null;
    }

    function message(s, m, live, latestPlan, proposals) {
        var bubble = h("div", { class: "bubble" + (m.from === "user" && m.text.length > 900 ? " long" : "") });
        if (m.from === "user") inline(m.text, bubble);
        else add(bubble, prose(m.text));
        (m.widgets || []).forEach(function (w, i) {
            var node = widget(s, m, w, i, live, latestPlan, proposals);
            if (node) bubble.appendChild(h("div", { class: "widget" }, node));
        });
        return h("div", { class: "msg " + m.from }, bubble);
    }

    function widget(s, m, w, index, live, latestPlan, proposals) {
        var lead = s.me.role === "lead";
        switch (w.type) {
            case "found":
                return h("ul", { class: "found" }, w.items.map(function (t) { return inline(t, h("li")); }));
            case "receipts":
                return h("ul", { class: "receipts" }, w.items.map(function (r) { return h("li", { class: r.ok ? "" : "bad", text: r.text }); }));
            case "choices":
                if (!live) return null;
                return h("div", { class: "choices" }, w.options.map(function (o) {
                    return h("button", { type: "button", text: o, onclick: function () { say(o); } });
                }));
            case "review":
                if (!live || !lead) return null;
                return h("button", { class: "primary", type: "button", text: "Review the plan", onclick: review });
            case "secret": return secretCard(s, w);
            case "invite":
                if (!lead) return null;
                return h("div", { class: "card" },
                    h("h4", { text: "Someone else knows this" }),
                    h("div", { text: "Ask " + w.department + " for " + w.sections.map(function (n) { return title(s, n); }).join(" and ") + "." }),
                    w.why ? h("div", { class: "why", text: w.why }) : null,
                    h("div", { class: "foot" }, h("button", { class: "primary small", type: "button", text: "Write them a request",
                        onclick: function () { inviteSheet(w.sections, w.department, w.name); } })));
            case "proposal": return proposalCard(w, proposals);
            case "plan": return planCard(s, w, latestPlan);
        }
        return null;
    }

    function title(s, section) {
        var sec = s.board.sections.filter(function (x) { return x.name === section; })[0];
        return sec ? sec.title : human(section);
    }

    function proposalCard(w, proposals) {
        var items = w.ids.map(function (id) { return proposals[id]; }).filter(Boolean);
        if (!items.length) return null;
        var open = items.filter(function (p) { return p.state === "open"; });
        var confirm = items.every(function (p) { return p.confirm; });
        var decide = function (ids, accept) { return function () { post("proposal", { ids: ids, accept: accept }).then(failed); }; };
        var some = items.some(function (p) { return p.confirm; });
        var theirs = items.filter(function (p) { return /^(Read from your message|You said)/.test(p.why || ""); }).length;
        var card = h("div", { class: "card" + (confirm ? " confirm" : "") },
            h("h4", { text: theirs === items.length ? "What I read" : theirs ? "What I read, and what I would suggest" : confirm ? "Please confirm" : some ? "To confirm, and what I would suggest" : items.length > 1 ? "My suggestions" : "My suggestion" }));
        items.forEach(function (p) {
            card.appendChild(h("div", { class: "row" },
                h("div", null,
                    h("div", { class: "what", text: (p.title || human(p.section)) + " · " + human(p.field) }),
                    h("div", { class: "val", text: show(p.value) }),
                    p.why ? h("div", { class: "why", text: p.why }) : null),
                p.state === "open" && open.length > 1
                    ? h("button", { class: "small", type: "button", text: p.confirm ? "Confirm" : "Accept", onclick: decide([p.id], true) })
                    : p.state !== "open" ? h("span", { class: "state" + (p.state === "accepted" ? " yes" : ""), text: p.state === "accepted" ? "✓ stored" : "not used" }) : null));
        });
        if (open.length) {
            var ids = open.map(function (p) { return p.id; });
            card.appendChild(h("div", { class: "foot" },
                h("button", { class: "primary small", type: "button", text: open.length > 1 ? (confirm ? "Confirm all" : "Accept all") : confirm ? "Confirm" : "Accept", onclick: decide(ids, true) }),
                h("button", { class: "small", type: "button", text: open.length > 1 ? "None of these" : "Not this", onclick: decide(ids, false) }),
                h("span", { class: "hint", text: "…or just tell me what it should be." })));
        }
        return card;
    }

    function secretCard(s, w) {
        var set = fieldValue(s, w.section, w.field) != null;
        var input = h("input", { type: "password", autocomplete: "new-password", placeholder: set ? "Stored. Type to replace it" : "Type or paste it here", "aria-label": w.label });
        var note = h("p", { class: "hint", text: set ? "✓ Stored with the identity server." : "It goes straight to the identity server. It is not kept in this conversation and the language model never sees it." });
        var save = function (e) {
            e.preventDefault();
            if (!input.value) return;
            post("secret", { section: w.section, field: w.field, value: input.value }).then(function (r) {
                if (r.ok) { input.value = ""; toast("Stored safely"); } else note.textContent = r.msg;
            });
        };
        return h("form", { class: "card", onsubmit: save },
            h("h4", null, icon("lock"), " " + w.label),
            h("div", { class: "inline" }, input, h("button", { class: "primary small", type: "submit", text: set ? "Replace" : "Store" })), note);
    }

    function planCard(s, w, latest) {
        var r = s.review;
        if (!latest || !r || r.review_id !== w.review_id || !r.plan)
            return h("div", { class: "card plan stale" }, h("h4", { text: "An earlier plan" }), h("div", { class: "why", text: "Something changed after this one. The current plan is further down, or ask me to review again." }));
        var p = r.plan, dl = h("dl");
        var row = function (k, v, strong) { if (v == null || v === "") return; add(dl, [h("dt", { text: k }), h("dd", null, strong ? h("b", { text: v }) : v)]); };
        row("Organization", p.organization);
        row("Issuer", p.issuer, true);
        row("Tenant id", p.tenant_id, true);
        row("Database", p.database.provider + ": " + p.database.action);
        row("Signing key", p.signing_key);
        row("Administrator", p.administrator.username + " (" + p.administrator.name + "). Password: " + p.administrator.password);
        row("New people", human(p.new_people));
        row("Email", p.email);
        row("Automation", p.machine_client.client_id + ", secret " + p.machine_client.secret);
        row("Audit trail", p.audit_trail);
        if (p.cors_origins && p.cors_origins.length) row("Browser apps", p.cors_origins.join(", "));

        var agree = h("input", { type: "checkbox", id: "agree-" + w.review_id });
        var go = h("button", { class: "primary", type: "button", disabled: true, text: "Install “" + p.tenant_id + "”" });
        agree.addEventListener("change", function () { go.disabled = !agree.checked; });
        go.addEventListener("click", function () {
            go.disabled = true;
            go.textContent = "Installing…";
            post("install", { review_id: w.review_id }).then(function (res) { if (!res.ok) { toast(res.msg || "The install did not go through"); } refresh(); });
        });
        var supplied = Object.keys(r.supplied_by || {}).map(function (k) {
            var by = r.supplied_by[k];
            return h("li", { text: k + ": " + [by.provided_by, by.department].filter(Boolean).join(", ") });
        });
        return h("div", { class: "card plan" },
            h("h4", { text: "The plan" }), dl,
            (r.warnings || []).length ? h("ul", { class: "warns" }, r.warnings.map(function (t) { return h("li", { text: t }); })) : null,
            (r.assumed_defaults || []).length ? h("details", null, h("summary", { text: r.assumed_defaults.length + " defaults I am assuming" }),
                h("ul", null, r.assumed_defaults.map(function (t) { return h("li", { text: t }); }))) : null,
            supplied.length ? h("details", null, h("summary", { text: "Who supplied what" }), h("ul", null, supplied)) : null,
            h("label", { class: "agree", for: agree.id }, agree, h("span", { text: "I have read the plan. I understand that the address and the tenant id cannot be changed after the install." })),
            h("div", { class: "foot" }, go, h("span", { class: "hint", text: "To change something first, just tell me." })));
    }

    function failed(r) { if (r && r.ok === false && r.msg) toast(r.msg); }

    function say(text) {
        if (sending || !text.trim()) return;
        sending = true;
        $("send").disabled = true;
        $("typing").hidden = false;
        post("message", { text: text }).then(function (r) {
            sending = false;
            $("send").disabled = false;
            failed(r);
        });
    }
    function review() { post("review", {}).then(failed); }

    // ------------------------------------------------------------ the board

    function renderBoard(s) {
        var board = $("board"), focus = document.activeElement;
        if (focus && board.contains(focus) && /^(INPUT|SELECT|TEXTAREA)$/.test(focus.tagName)) { boardStale = true; return; }
        boardStale = false;
        var lead = s.me.role === "lead", top = board.scrollTop;
        board.textContent = "";

        var e = s.board.essentials, r = 23, c = 2 * Math.PI * r, ns = "http://www.w3.org/2000/svg";
        var ring = document.createElementNS(ns, "svg");
        ring.setAttribute("class", "ring" + (s.board.ready ? " full" : ""));
        ring.setAttribute("viewBox", "0 0 58 58");
        [["track", c], ["value", c * (s.board.ready ? 1 : e.done / e.total)]].forEach(function (x) {
            var circle = document.createElementNS(ns, "circle");
            circle.setAttribute("class", x[0]); circle.setAttribute("cx", 29); circle.setAttribute("cy", 29); circle.setAttribute("r", r);
            circle.setAttribute("stroke-dasharray", x[1] + " " + c);
            ring.appendChild(circle);
        });
        var label = document.createElementNS(ns, "text");
        label.setAttribute("x", 29); label.setAttribute("y", 29);
        label.textContent = s.board.ready ? "✓" : e.done + "/" + e.total;
        ring.appendChild(label);

        if (lead)
            board.appendChild(h("div", { class: "ready" }, ring, h("div", { class: "ready-text" },
                h("strong", { text: s.board.ready ? "Ready to review" : e.done + " of the " + e.total + " things I need" }),
                h("span", { text: s.board.ready ? "Everything else is on a sensible default." : "Everything else has a sensible default." }),
                s.board.ready ? h("div", null, h("button", { class: "primary small", type: "button", text: "Review the plan", onclick: review })) : null)));
        else
            board.appendChild(h("div", { class: "ready" }, h("div", { class: "ready-text" },
                h("strong", { text: "What you were asked for" }), h("span", { text: "Answer in the chat, or fill it in here. Either way is fine." }))));

        var needed = s.board.sections.filter(function (x) { return !x.optional; });
        var optional = s.board.sections.filter(function (x) { return x.optional; });
        if (lead) board.appendChild(h("h3", { text: "The essentials" }));
        needed.forEach(function (sec) { board.appendChild(sectionCard(s, sec)); });
        if (optional.length) {
            if (lead) board.appendChild(h("h3", { text: "On defaults unless you say otherwise" }));
            optional.forEach(function (sec) { board.appendChild(sectionCard(s, sec)); });
        }

        if (lead) {
            board.appendChild(h("h3", { text: "Colleagues" }));
            var team = h("ul", { class: "list" });
            (s.team || []).forEach(function (t) {
                var tag = { sent: ["Sent", ""], opened: ["Opened", "wait"], quiet: ["No answer yet", "wait"], answered: ["Done", "ok"], expired: ["Expired", "bad"], revoked: ["Withdrawn", ""] }[t.status] || [t.status, ""];
                team.appendChild(h("li", null,
                    h("div", { class: "who" }, h("b", { text: (t.name || "A colleague") + " · " + t.department }), h("span", { class: "tag " + tag[1], text: tag[0] })),
                    h("div", { class: "sub", text: t.sections.join(", ") + " · asked " + ago(t.created_at) }),
                    t.path && t.status !== "expired" ? h("div", { class: "acts" },
                        h("button", { class: "link", type: "button", text: "Copy link", onclick: function () { copy(location.origin + t.path, "Link"); } }),
                        h("button", { class: "link", type: "button", text: "Withdraw", onclick: function () { post("invite/revoke", { id: t.id }).then(failed); } })) : null));
            });
            if (!(s.team || []).length) team.appendChild(h("li", { class: "sub", text: "Nobody yet. When a section belongs to someone else (the database, email, the signing key), I can write them a request with a link that reaches only that section." }));
            board.appendChild(team);
            board.appendChild(h("button", { class: "small", type: "button", onclick: function () { inviteSheet([], ""); } }, icon("people"), " Ask a colleague"));

            if ((s.activity || []).length) {
                board.appendChild(h("h3", { text: "What has happened" }));
                board.appendChild(h("ul", { class: "feed" }, s.activity.map(function (a) { return h("li", null, h("time", { text: ago(a.at) }), a.text); })));
            }
        }
        board.scrollTop = top;
    }

    function summary(sec) {
        var set = sec.fields.filter(function (f) { return f.value != null && !f.secret; }).map(function (f) { return show(f.value); });
        if (set.length) return set.slice(0, 3).join(" · ");
        var owner = /^[A-Z][a-z]/.test(sec.owner) ? sec.owner.charAt(0).toLowerCase() + sec.owner.slice(1) : sec.owner;
        return "Usually known by " + owner;
    }

    function sectionCard(s, sec) {
        var lead = s.me.role === "lead";
        var tag = sec.status === "missing" ? h("span", { class: "tag need", text: "Needed" })
            : sec.status === "invalid" ? h("span", { class: "tag bad", text: "Check" })
            : lead && sec.asked && sec.asked.status !== "answered" && sec.status !== "complete" ? h("span", { class: "tag wait", text: "Asked " + (sec.asked.name || sec.asked.department) })
            : sec.status === "complete" ? h("span", { class: "tag ok", text: sec.test && sec.test.ok ? "Tested" : "Set" })
            : h("span", { class: "tag", text: "Default" });
        var d = h("details", { class: "sec " + sec.status, open: !!openSecs[sec.name] || (!lead && s.board.sections.length <= 2) },
            h("summary", null, h("span", { class: "dot" }, icon("check")),
                h("span", { class: "sec-title" }, h("b", { text: sec.title }), h("span", { text: summary(sec) })), tag, h("span", { class: "chev" }, icon("chevron"))));
        d.addEventListener("toggle", function () { openSecs[sec.name] = d.open; });

        var body = h("div", { class: "sec-body" }, h("p", { text: sec.purpose }));
        (sec.problems || []).forEach(function (p) { body.appendChild(h("div", { class: "problem", text: p.message })); });
        if (sec.test) body.appendChild(h("div", { class: "tested" + (sec.test.ok ? "" : " bad"), text: (sec.test.ok ? "Tested: " : "Test failed: ") + sec.test.message }));
        sec.fields.forEach(function (f) { body.appendChild(fieldRow(s, sec, f)); });

        var actions = h("div", { class: "sec-actions" },
            h("button", { class: "small", type: "button", text: "Talk about this", onclick: function () {
                var input = $("input");
                input.value = "About " + sec.title.toLowerCase() + ": ";
                document.body.classList.remove("board-open");
                input.focus();
            } }));
        if (sec.name === "database" || ((sec.name === "email" || sec.name === "audit") && fieldValue(s, sec.name, "enabled") === true))
            actions.appendChild(h("button", { class: "small", type: "button", text: "Test it", onclick: function () {
                var to = sec.name === "email" ? prompt("Send the test email to:") : null;
                if (sec.name === "email" && !to) return;
                toast("Testing…");
                post("test", { section: sec.name, to: to }).then(function (r) { toast(r.msg || (r.ok ? "Passed" : "Failed")); });
            } }));
        if (lead)
            actions.appendChild(h("button", { class: "small", type: "button", onclick: function () { inviteSheet([sec.name], sec.owner); } }, icon("people"), " Ask a colleague"));
        body.appendChild(actions);
        d.appendChild(body);
        return d;
    }

    function fieldRow(s, sec, f) {
        var key = sec.name + "." + f.name, isSet = f.value != null;
        var row = h("div", { class: "f" });
        if (key === "administrator.password") {
            add(row, [h("div", { class: "f-name", text: "password" }), h("div", { class: "f-val unset", text: "Chosen by the administrator, through a one-time link after the install. Nobody else ever holds it." })]);
            return row;
        }
        var needed = (sec.missing || []).indexOf(f.name) >= 0;
        var name = h("span", { class: "f-name", title: f.description }, human(f.name), needed ? h("i", { text: "  needed" }) : null);
        var edit = h("button", { class: "link small", type: "button", text: isSet ? "Change" : "Set", onclick: function () { editing = key; boardStale = false; renderBoard(state); } });
        row.appendChild(h("div", { class: "f-head" }, name, editing === key ? null : edit));

        if (editing !== key) {
            row.appendChild(h("div", { class: "f-val" + (isSet ? "" : " unset"), text: isSet ? (f.secret ? "•••••••• (stored)" : show(f.value)) : f.default ? "default: " + f.default : "not set" }));
            if (f.source && f.source.by) row.appendChild(h("div", { class: "f-src", text: "from " + f.source.by + (f.source.department ? ", " + f.source.department : "") + (f.source.at ? " · " + ago(f.source.at) : "") }));
            return row;
        }

        var input;
        if (f.values) input = h("select", null, f.values.map(function (v) { return h("option", { value: v, text: v, selected: f.value === v }); }));
        else if (f.type === "boolean") input = h("select", null, h("option", { value: "true", text: "yes", selected: f.value === true }), h("option", { value: "false", text: "no", selected: f.value === false }));
        else input = h("input", { type: f.secret ? "password" : f.type === "integer" ? "number" : "text", value: f.secret || !isSet ? "" : show(f.value),
            placeholder: f.type === "array" ? "one or more, separated by commas" : f.description, autocomplete: f.secret ? "new-password" : "off" });
        var close = function () { editing = null; boardStale = false; renderBoard(state); };
        var save = function () {
            var raw = input.value, value = f.type === "boolean" ? raw === "true" : f.type === "integer" && raw !== "" ? Number(raw)
                : f.type === "array" ? raw.split(/[,\s]+/).filter(Boolean) : raw;
            var done = function (r) { if (r.ok) { toast("Stored"); close(); } else toast(r.msg || "That was not accepted"); };
            if (f.secret) post("secret", { section: sec.name, field: f.name, value: raw }).then(done);
            else { var values = {}; values[f.name] = value; post("set", { section: sec.name, values: values }).then(done); }
        };
        input.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); save(); } if (e.key === "Escape") close(); });
        var controls = h("div", { class: "f-edit" }, input, h("button", { class: "primary small", type: "button", text: "Save", onclick: save }),
            h("button", { class: "small", type: "button", text: "Cancel", onclick: close }));
        row.appendChild(controls);
        if (/_logo$/.test(f.name)) {
            var file = h("input", { type: "file", accept: "image/*" });
            file.addEventListener("change", function () {
                var picked = file.files[0];
                if (!picked) return;
                if (picked.size > 1000000) { toast("That image is over 1 MB"); return; }
                var reader = new FileReader();
                reader.onload = function () { var values = {}; values[f.name] = reader.result; post("set", { section: sec.name, values: values }).then(function (r) { if (r.ok) { toast("Logo stored"); close(); } else toast(r.msg); }); };
                reader.readAsDataURL(picked);
            });
            row.appendChild(h("div", { class: "f-edit" }, file));
        }
        row.appendChild(h("div", { class: "f-src", text: f.ask }));
        setTimeout(function () { input.focus(); }, 0);
        return row;
    }

    // ------------------------------------------------------------ sheets

    function sheet(build) {
        var back = $("sheet-back"), box = $("sheet");
        box.textContent = "";
        var close = function () { back.hidden = true; sheetOpen = false; document.removeEventListener("keydown", esc); };
        var esc = function (e) { if (e.key === "Escape") close(); };
        build(box, close);
        back.hidden = false;
        sheetOpen = true;
        document.addEventListener("keydown", esc);
        back.onclick = function (e) { if (e.target === back) close(); };
        var first = box.querySelector("input, select, textarea, button");
        if (first) first.focus();
    }

    function inviteSheet(sections, department, who) {
        var s = state;
        sheet(function (box, close) {
            var name = h("input", { class: "field", placeholder: "e.g. Priya Nair", maxlength: "120", value: who || "" });
            var dept = h("input", { class: "field", value: department || "", placeholder: "e.g. Database administration", maxlength: "120" });
            var checks = h("div", { class: "checks" }, s.board.sections.map(function (sec) {
                var box2 = h("input", { type: "checkbox", value: sec.name, checked: sections.indexOf(sec.name) >= 0 });
                box2.addEventListener("change", function () { if (box2.checked && !dept.value) dept.value = sec.owner; });
                return h("label", null, box2, sec.title);
            }));
            var err = h("div", { class: "error" });
            var create = function () {
                var chosen = Array.prototype.filter.call(checks.querySelectorAll("input"), function (c) { return c.checked; }).map(function (c) { return c.value; });
                if (!chosen.length) { err.textContent = "Choose what to ask them for."; return; }
                post("invite", { sections: chosen, department: dept.value, name: name.value }).then(function (r) {
                    if (!r.ok) { err.textContent = r.msg; return; }
                    var link = location.origin + r.path, note = r.note.replace("{link}", link);
                    box.textContent = "";
                    var area = h("textarea", { class: "note", value: note });
                    add(box, [
                        h("h2", { text: "Ready to send" }),
                        h("p", { text: "The link reaches only what you chose, works until " + new Date(r.expires_at).toLocaleString() + ", and stops working when setup is finished. I will tell you when they answer." }),
                        h("label", { text: "Their link" }),
                        h("div", { class: "linkbox" }, h("input", { class: "field", readonly: true, value: link, onclick: function (e) { e.target.select(); } }),
                            h("button", { type: "button", text: "Copy", onclick: function () { copy(link, "Link"); } })),
                        h("label", { text: "A note you can send as it is" }), area,
                        h("div", { class: "actions" },
                            h("a", { class: "ghost", href: "mailto:?subject=" + encodeURIComponent("A few details for our sign-in service") + "&body=" + encodeURIComponent(note), text: "Open in email" }),
                            h("button", { type: "button", text: "Copy the note", onclick: function () { copy(area.value, "Note"); } }),
                            h("button", { class: "primary", type: "button", text: "Done", onclick: close }))
                    ]);
                });
            };
            add(box, [
                h("h2", { text: "Ask a colleague" }),
                h("p", { text: "They get a link to a short chat with me that asks only for what you pick here. They never see the setup code or anything else on this board." }),
                h("label", { text: "What should I ask them for?" }), checks,
                h("label", { text: "Their name (optional)" }), name,
                h("label", { text: "Their team" }), dept, err,
                h("div", { class: "actions" }, h("button", { type: "button", text: "Cancel", onclick: close }), h("button", { class: "primary", type: "button", text: "Create the link", onclick: create }))
            ]);
        });
    }

    function secretSheet() {
        var s = state, options = [];
        s.board.sections.forEach(function (sec) {
            sec.fields.forEach(function (f) { if (f.secret && sec.name + "." + f.name !== "administrator.password") options.push({ sec: sec, f: f }); });
        });
        sheet(function (box, close) {
            var which = h("select", { class: "field" }, options.map(function (o, i) { return h("option", { value: i, text: o.sec.title + ": " + human(o.f.name) }); }));
            var value = h("textarea", { class: "field", rows: "3", autocomplete: "off", spellcheck: "false", placeholder: "Paste it here" });
            var hint = h("p", { class: "hint" });
            var describe = function () { hint.textContent = options[which.value].f.description; };
            which.addEventListener("change", describe);
            describe();
            var err = h("div", { class: "error" });
            add(box, [
                h("h2", null, icon("lock"), " Send a secret"),
                h("p", { text: "It goes straight to the identity server. It is not written into this conversation, and the language model never sees it." }),
                h("label", { text: "Which one is it?" }), which, hint,
                h("label", { text: "The secret" }), value, err,
                h("div", { class: "actions" }, h("button", { type: "button", text: "Cancel", onclick: close }),
                    h("button", { class: "primary", type: "button", text: "Store it", onclick: function () {
                        var o = options[which.value];
                        if (!value.value.trim()) { err.textContent = "Paste the secret first."; return; }
                        post("secret", { section: o.sec.name, field: o.f.name, value: value.value.trim() }).then(function (r) {
                            if (r.ok) { close(); toast("Stored safely"); } else err.textContent = r.msg;
                        });
                    } }))
            ]);
        });
    }

    // ------------------------------------------------------------ hand-over

    var handed = false;
    function renderHandover(s) {
        if (handed) return;
        handed = true;
        var d = s.handover, root = $("handover"), inner = h("div", { class: "handover-inner" });
        root.textContent = "";
        $("subtitle").textContent = "Installed";
        var kv = function (rows) {
            var grid = h("div", { class: "kv" });
            rows.forEach(function (r) {
                if (!r[1]) return;
                add(grid, [h("span", { text: r[0] }), h("code", { text: r[1] }), h("button", { class: "small", type: "button", text: "Copy", onclick: function () { copy(r[1], r[0]); } })]);
            });
            return grid;
        };
        add(inner, [h("h1", { text: (s.board.company ? s.board.company + "'s" : "Your") + " identity server is live" }),
            h("p", { class: "lede", text: "Tenant “" + d.tenant_id + "” is installed and this server is now your identity provider. Two things below are shown once, here and now. Store them before you leave this page." })]);

        var admin = d.administrator || {};
        if (admin.password_link)
            inner.appendChild(h("section", { class: "once" },
                h("h2", null, "The administrator's sign-in link ", h("span", { class: "tag wait", text: "shown once" })),
                h("p", { text: admin.note || "" }), kv([["Administrator", admin.username], ["One-time link", admin.password_link]])));

        var machine = d.machine_client || {};
        if (machine.client_secret) {
            var download = h("button", { class: "small", type: "button", text: "Download as a file", onclick: function () {
                var blob = new Blob([JSON.stringify({ issuer: d.issuer, client_id: machine.client_id, client_secret: machine.client_secret, mcp: d.mcp && d.mcp.tenant }, null, 2)], { type: "application/json" });
                var a = h("a", { href: URL.createObjectURL(blob), download: d.tenant_id + "-machine-credential.json" });
                document.body.appendChild(a); a.click(); a.remove();
            } });
            inner.appendChild(h("section", { class: "once" },
                h("h2", null, "The automation credential ", h("span", { class: "tag wait", text: "shown once" })),
                h("p", { text: machine.note || "" }), kv([["Client id", machine.client_id], ["Client secret", machine.client_secret]]),
                h("div", { class: "sec-actions" }, download)));
        } else if (machine.note)
            inner.appendChild(h("section", { class: "once" }, h("h2", { text: "The automation credential" }), h("p", { text: machine.note })));

        inner.appendChild(h("section", { class: "once" }, h("h2", { text: "Where everything is" }),
            kv([["Issuer", d.issuer], ["Discovery", d.discovery], ["Admin console", d.console], ["Settings file", d.settings_file],
                ["Keys file (signing key and credential)", d.keys_file]])));
        if (d.mcp && d.mcp.config)
            inner.appendChild(h("section", { class: "once" }, h("h2", { text: "For the next agent" }),
                h("p", { text: "This tenant has its own MCP endpoint, which the automation credential opens. An agent can go on from here: register the first application, add people." }),
                h("pre", { text: JSON.stringify(d.mcp.config, null, 2) }),
                h("div", { class: "sec-actions" }, h("button", { class: "small", type: "button", text: "Copy", onclick: function () { copy(JSON.stringify(d.mcp.config, null, 2), "Configuration"); } }))));
        if ((d.next_steps || []).length)
            inner.appendChild(h("section", { class: "once" }, h("h2", { text: "What I would do next" }), h("ol", null, d.next_steps.map(function (t) { return h("li", { text: t }); }))));

        var stored = h("input", { type: "checkbox", id: "stored" });
        var finish = h("button", { class: "primary", type: "button", disabled: true, text: "Finish and open the server" });
        stored.addEventListener("change", function () { finish.disabled = !stored.checked; });
        finish.addEventListener("click", function () { post("ack", {}).then(function () { location.href = d.console || "/"; }); });
        inner.appendChild(h("div", { class: "finish" }, h("label", { class: "agree", for: "stored" }, stored, h("span", { text: "I have stored the link and the credential. Forget them." })), finish));
        root.appendChild(inner);
    }

    // ------------------------------------------------------------ the composer

    var input = $("input");
    function grow() { input.style.height = "auto"; input.style.height = Math.min(input.scrollHeight, 180) + "px"; }
    input.addEventListener("input", grow);
    input.addEventListener("keydown", function (e) {
        if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); $("composer").requestSubmit(); }
    });
    $("composer").addEventListener("submit", function (e) {
        e.preventDefault();
        var text = input.value.trim();
        if (!text || sending) return;
        input.value = "";
        grow();
        say(text);
    });
    function readFile(file) {
        if (!file) return;
        if (file.size > 200000) { toast("That file is over 200 KB. Paste the part that matters instead."); return; }
        var reader = new FileReader();
        reader.onload = function () {
            var text = String(reader.result);
            if (/\u0000/.test(text)) { toast("I can only read text files."); return; }
            var lead = input.value.trim();
            input.value = "";
            grow();
            say((lead ? lead + "\n\n" : "") + "Here is " + file.name + ":\n\n" + text);
        };
        reader.readAsText(file);
    }
    $("attach").addEventListener("click", function () { $("file").click(); });
    $("file").addEventListener("change", function () { readFile($("file").files[0]); $("file").value = ""; });
    $("secret-open").addEventListener("click", secretSheet);
    var composer = $("composer"), drags = 0;
    composer.addEventListener("dragenter", function (e) { e.preventDefault(); drags++; $("drop-hint").hidden = false; });
    composer.addEventListener("dragover", function (e) { e.preventDefault(); });
    composer.addEventListener("dragleave", function () { if (--drags <= 0) { drags = 0; $("drop-hint").hidden = true; } });
    composer.addEventListener("drop", function (e) { e.preventDefault(); drags = 0; $("drop-hint").hidden = true; readFile(e.dataTransfer.files[0]); });

    $("board-toggle").addEventListener("click", function () { document.body.classList.toggle("board-open"); });
    $("board").addEventListener("focusout", function () { setTimeout(function () { if (boardStale && state && state.board) renderBoard(state); }, 50); });

    watch();
})();
