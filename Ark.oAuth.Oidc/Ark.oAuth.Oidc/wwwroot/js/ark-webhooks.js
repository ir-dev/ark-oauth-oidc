/* ---------------------------------------------------------------------------
   Ark IdP admin console — the Webhooks page (/{tenant}/admin/webhooks).

   Talks only to the webhook management API (/api/oauth/v1/webhooks/...). Every
   value from the server reaches the page through textContent or an attribute,
   never innerHTML: an endpoint name, a receiver's response body or an error
   string is somebody else's text.

   Writes are POSTs with a JSON body, which a cross-site page cannot send
   without a CORS preflight the server never grants — the same protection the
   rest of the console relies on.
   --------------------------------------------------------------------------- */
(function () {
    "use strict";

    var root = document.getElementById("ark-webhooks");
    if (!root) return;
    var APP_ROOT = root.dataset.appRoot || "";
    var API = APP_ROOT + "/api/oauth/v1/webhooks";

    var state = {
        meta: null,
        endpoints: [],
        analytics: null,
        selected: null,
        historyItems: [],
        historyMore: false,
        deadItems: [],
        editing: null,
        planTimer: null
    };

    // ---------------------------------------------------------------- helpers

    function byId(id) { return document.getElementById(id); }

    function on(id, event, handler) {
        var element = byId(id);
        if (element) element.addEventListener(event, handler);
        return element;
    }

    /** Builds an element. Children are nodes or strings (as text, never markup). */
    function el(tag, attrs, children) {
        var node = document.createElement(tag);
        if (attrs) Object.keys(attrs).forEach(function (k) {
            var v = attrs[k];
            if (v === null || v === undefined || v === false) return;
            if (k === "class") node.className = v;
            else if (k === "text") node.textContent = v;
            else if (k.indexOf("on") === 0 && typeof v === "function") node.addEventListener(k.substring(2), v);
            else node.setAttribute(k, v === true ? "" : String(v));
        });
        (children || []).forEach(function (c) {
            if (c === null || c === undefined || c === false) return;
            node.appendChild(typeof c === "string" || typeof c === "number" ? document.createTextNode(String(c)) : c);
        });
        return node;
    }

    function svg(tag, attrs) {
        var node = document.createElementNS("http://www.w3.org/2000/svg", tag);
        Object.keys(attrs || {}).forEach(function (k) { node.setAttribute(k, String(attrs[k])); });
        return node;
    }

    function clear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); return node; }

    function toast(kind, message, ms) {
        var host = byId("ark-toasts");
        var t = el("div", { class: "ark-toast ark-toast-" + kind, text: message });
        host.appendChild(t);
        setTimeout(function () { t.remove(); }, ms || 3500);
    }

    function request(url, options) {
        return fetch(url, options).then(function (r) {
            return r.text().then(function (text) {
                var payload = null;
                try { payload = text ? JSON.parse(text) : null; } catch (e) { payload = null; }
                if (r.ok && payload && !payload.error) return payload.data;
                var err = new Error((payload && payload.msg) || (r.status === 401 ? "your session has expired - reload the page to sign in again." : r.status + " " + r.statusText));
                err.status = r.status;
                err.payload = payload;
                throw err;
            });
        });
    }

    function getJson(path, params) {
        var q = [];
        Object.keys(params || {}).forEach(function (k) {
            if (params[k] !== null && params[k] !== undefined && params[k] !== "") q.push(encodeURIComponent(k) + "=" + encodeURIComponent(params[k]));
        });
        return request(API + path + (q.length ? "?" + q.join("&") : ""), { headers: { Accept: "application/json" }, credentials: "same-origin" });
    }

    function postJson(path, body) {
        return request(API + path, {
            method: "POST",
            credentials: "same-origin",
            body: JSON.stringify(body || {}),
            headers: { Accept: "application/json", "Content-Type": "application/json" }
        });
    }

    function fail(err) { toast("f", err.message || String(err), 7000); }

    /** Every timestamp from the server is UTC; SQLite hands some back without the zone. */
    function parseDate(value) {
        if (!value) return null;
        var s = String(value);
        if (!/[zZ]|[+-]\d\d:?\d\d$/.test(s)) s += "Z";
        var d = new Date(s);
        return isNaN(d.getTime()) ? null : d;
    }

    function fmtDate(value) {
        var d = parseDate(value);
        return d ? d.toLocaleString() : "—";
    }

    function fmtAgo(value) {
        var d = parseDate(value);
        if (!d) return "never";
        var s = Math.round((Date.now() - d.getTime()) / 1000);
        var future = s < 0;
        s = Math.abs(s);
        var text = s < 60 ? s + " s" : s < 3600 ? Math.round(s / 60) + " min" : s < 86400 ? Math.round(s / 3600) + " h" : Math.round(s / 86400) + " d";
        return future ? "in " + text : text + " ago";
    }

    function fmtNum(n) { return n === null || n === undefined ? "—" : Number(n).toLocaleString(); }
    function fmtPct(n) { return n === null || n === undefined ? "—" : n.toFixed(1) + "%"; }
    function fmtSecs(s) {
        if (s < 60) return Math.round(s) + "s";
        if (s < 3600) return Math.round(s / 60) + "m";
        if (s < 86400) return (Math.round(s / 360) / 10) + "h";
        return (Math.round(s / 8640) / 10) + "d";
    }

    function tenantFilter() { return byId("wh-tenant").value; }
    function hours() { return parseInt(byId("wh-hours").value, 10) || 24; }

    function endpoint(id) { return state.endpoints.filter(function (e) { return e.id === id; })[0] || null; }
    function stats(id) {
        var a = state.analytics;
        return a ? (a.endpoints.filter(function (e) { return e.id === id; })[0] || null) : null;
    }

    function statusBadge(e) {
        if (e.status === "disabled") {
            return el("span", { class: "ark-badge ark-badge-bad", title: e.disabled_reason || "" }, [
                el("span", { class: "wh-badge-icon", "aria-hidden": "true", text: "⚠" }),
                e.auto_disabled ? "Disabled · failures" : "Disabled"
            ]);
        }
        if (e.status === "paused") {
            return el("span", { class: "ark-badge ark-badge-off" }, [el("span", { class: "wh-badge-icon", "aria-hidden": "true", text: "⏸" }), "Paused"]);
        }
        if (e.consecutive_failures > 0) {
            return el("span", { class: "ark-badge ark-badge-warn", title: e.last_error || "" }, [
                el("span", { class: "wh-badge-icon", "aria-hidden": "true", text: "▲" }),
                "Failing " + e.consecutive_failures + (e.failure_threshold > 0 ? "/" + e.failure_threshold : "")
            ]);
        }
        return el("span", { class: "ark-badge ark-badge-ok" }, [el("span", { class: "wh-badge-icon", "aria-hidden": "true", text: "●" }), "Active"]);
    }

    function deliveryBadge(status) {
        var map = {
            delivered: ["ark-badge-ok", "delivered"],
            pending: ["ark-badge-off", "pending"],
            in_flight: ["ark-badge-off", "in flight"],
            retrying: ["ark-badge-warn", "retrying"],
            dead: ["ark-badge-bad", "dead-lettered"],
            cancelled: ["ark-badge-off", "cancelled"],
            test_failed: ["ark-badge-bad", "test failed"]
        };
        var m = map[status] || ["ark-badge-off", status];
        return el("span", { class: "ark-badge " + m[0], text: m[1] });
    }

    // ---------------------------------------------------------------- loading

    function loadAll() {
        return Promise.all([
            getJson("/meta"),
            getJson("/list", { tenant_id: tenantFilter() }),
            getJson("/analytics", { tenant_id: tenantFilter(), hours: hours() })
        ]).then(function (r) {
            state.meta = r[0];
            state.endpoints = r[1] || [];
            state.analytics = r[2];
            renderMeta();
            renderKpis();
            if (state.selected && !endpoint(state.selected)) state.selected = null;
            renderRows();
            if (state.selected) {
                renderDetail(true);
                loadEndpointAnalytics(state.selected);
            } else {
                byId("wh-detail").hidden = true;
                renderChart(state.analytics);
            }
        }).catch(fail);
    }

    /** The chart and the health tab for the selected endpoint only. */
    function loadEndpointAnalytics(id) {
        return getJson("/analytics", { tenant_id: tenantFilter(), endpoint_id: id, hours: hours() }).then(function (a) {
            if (state.selected !== id) return;
            state.endpointAnalytics = a;
            renderChart(a);
            renderHealth(a.endpoints[0]);
        }).catch(fail);
    }

    function deselect() {
        state.selected = null;
        state.endpointAnalytics = null;
        byId("wh-detail").hidden = true;
        renderRows();
        renderChart(state.analytics);
    }

    function renderMeta() {
        var meta = state.meta;
        var select = byId("wh-tenant");
        if (select.options.length <= 1) {
            meta.tenants.forEach(function (t) { select.add(new Option(t.tenant_id + (t.name && t.name !== t.tenant_id ? " — " + t.name : ""), t.tenant_id)); });
        }
        var alert = byId("wh-module-alert");
        var problems = [];
        if (!meta.enabled) problems.push("Webhooks are switched off (ark_oauth_server:Webhooks:Enabled = false): nothing is queued or sent. Configuration and history are kept.");
        if (meta.status.registry_error) problems.push("The webhook configuration could not be read: " + meta.status.registry_error);
        if (meta.status.dispatcher_error) problems.push("Last dispatcher problem: " + meta.status.dispatcher_error);
        alert.hidden = problems.length === 0;
        clear(alert);
        problems.forEach(function (p) { alert.appendChild(el("div", { text: p })); });

        var s = meta.status;
        byId("wh-runtime").textContent = "This instance (" + s.worker_id + "): " + s.in_flight + " in flight of " + meta.options.max_concurrency +
            " · " + fmtNum(s.delivered) + " delivered, " + fmtNum(s.failed_attempts) + " failed attempts, " + fmtNum(s.dead_lettered) +
            " dead-lettered since start · " + fmtNum(s.queued_events) + " events queued · housekeeping " + (s.last_housekeeping ? fmtAgo(s.last_housekeeping) : "not yet run") +
            " · retention " + meta.options.retention_days + " d (dead letters " + meta.options.dead_letter_retention_days + " d)";
    }

    function renderKpis() {
        var t = state.analytics.totals;
        var host = clear(byId("wh-kpis"));
        var period = hours() === 24 ? "24 h" : hours() === 168 ? "7 days" : "30 days";
        function kpi(label, value, sub, tone) {
            host.appendChild(el("div", { class: "wh-kpi", "data-tone": tone || null }, [
                el("div", { class: "wh-kpi-label", text: label }),
                el("div", { class: "wh-kpi-value", text: value }),
                sub ? el("div", { class: "wh-kpi-sub", text: sub }) : null
            ]));
        }
        kpi("Webhooks", fmtNum(t.endpoints), t.active + " active · " + t.paused + " paused · " + t.disabled + " disabled");
        kpi("Disabled by failures", fmtNum(t.auto_disabled), t.failing + " failing now", t.auto_disabled > 0 ? "bad" : (t.failing > 0 ? "warn" : null));
        kpi("Delivered", fmtNum(t.delivered), "last " + period);
        kpi("Success rate", fmtPct(t.success_rate), fmtNum(t.attempts) + " attempts", t.success_rate !== null && t.success_rate < 90 ? "warn" : null);
        kpi("Failed attempts", fmtNum(t.failed_attempts), "last " + period, t.failed_attempts > 0 ? "warn" : null);
        kpi("Waiting", fmtNum(t.backlog), "pending or retrying");
        kpi("Dead letters", fmtNum(t.open_dead_letters), "open, not yet replayed", t.open_dead_letters > 0 ? "bad" : null);
    }

    // ---------------------------------------------------------------- chart

    function niceMax(v) {
        if (v <= 4) return 4;
        var p = Math.pow(10, Math.floor(Math.log10(v)));
        var n = v / p;
        var step = n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10;
        return step * p;
    }

    function bucketLabel(d, bucketHours, withDate) {
        if (bucketHours >= 24) return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
        var time = d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
        return withDate ? d.toLocaleDateString(undefined, { month: "short", day: "numeric" }) + " " + time : time;
    }

    /** A column with only its data end (the top) rounded, 4px. */
    function columnPath(x, y, w, h, radius) {
        var r = Math.min(radius, w / 2, h);
        if (h <= 0) return "";
        return "M" + x + "," + (y + h) + "V" + (y + r) + "Q" + x + "," + y + " " + (x + r) + "," + y +
            "H" + (x + w - r) + "Q" + (x + w) + "," + y + " " + (x + w) + "," + (y + r) + "V" + (y + h) + "Z";
    }

    function renderChart(a) {
        var host = clear(byId("wh-chart"));
        var tip = byId("wh-tooltip");
        tip.hidden = true;
        var series = (a && a.series) || [];
        var titleScope = state.selected ? " — " + ((endpoint(state.selected) || {}).name || "") : (tenantFilter() ? " — tenant " + tenantFilter() : "");
        byId("wh-chart-title").textContent = "Delivery attempts per " + (a && a.bucket_hours >= 24 ? "day" : a && a.bucket_hours > 1 ? a.bucket_hours + " hours" : "hour") + titleScope;

        var table = clear(byId("wh-chart-table"));
        var total = series.reduce(function (s, b) { return s + b.ok + b.failed; }, 0);
        if (!series.length || total === 0) {
            host.appendChild(el("div", { class: "wh-chart-empty", text: "No delivery attempts in this period." }));
            table.appendChild(el("p", { class: "ark-empty", text: "No data." }));
            return;
        }

        var width = Math.max(320, host.clientWidth || 700);
        var height = 190, padL = 40, padR = 8, padT = 10, padB = 24;
        var plotW = width - padL - padR, plotH = height - padT - padB;
        var max = niceMax(Math.max.apply(null, series.map(function (b) { return b.ok + b.failed; })));
        var chart = svg("svg", { viewBox: "0 0 " + width + " " + height, preserveAspectRatio: "none", "aria-hidden": "true" });

        for (var g = 0; g <= 4; g++) {
            var gy = padT + plotH - (plotH * g / 4);
            chart.appendChild(svg("line", { class: g === 0 ? "wh-axis" : "wh-grid", x1: padL, x2: width - padR, y1: gy, y2: gy }));
            var label = svg("text", { class: "wh-tick", x: padL - 6, y: gy + 3.5, "text-anchor": "end" });
            label.textContent = fmtNum(Math.round(max * g / 4));
            chart.appendChild(label);
        }

        var slot = plotW / series.length;
        var barW = Math.max(2, Math.min(28, slot * 0.7));
        var every = Math.max(1, Math.ceil(series.length / Math.max(2, Math.floor(plotW / 64))));
        var card = host.parentElement;

        series.forEach(function (b, i) {
            var x = padL + i * slot + (slot - barW) / 2;
            var okH = plotH * b.ok / max;
            var failH = plotH * b.failed / max;
            var base = padT + plotH;
            var hl = svg("rect", { class: "wh-col-hl", x: padL + i * slot, y: padT, width: slot, height: plotH });
            var hit = svg("rect", { class: "wh-hit", x: padL + i * slot, y: padT, width: slot, height: plotH + padB, tabindex: 0 });
            chart.appendChild(hit);
            chart.appendChild(hl);
            // Succeeded at the base, failed stacked on top; only the top segment has the rounded end,
            // and a 2px surface gap separates the two.
            var topIsFail = b.failed > 0;
            if (okH > 0) chart.appendChild(svg("path", { class: "wh-bar-ok", d: topIsFail ? "M" + x + "," + base + "V" + (base - okH) + "H" + (x + barW) + "V" + base + "Z" : columnPath(x, base - okH, barW, okH, 4) }));
            if (failH > 0) {
                var gap = okH > 0 ? 2 : 0;
                chart.appendChild(svg("path", { class: "wh-bar-fail", d: columnPath(x, base - okH - failH - gap, barW, failH, 4) }));
            }
            if (i % every === 0) {
                var t = svg("text", { class: "wh-tick", x: padL + i * slot + slot / 2, y: height - 6, "text-anchor": "middle" });
                t.textContent = bucketLabel(parseDate(b.at), a.bucket_hours, false);
                chart.appendChild(t);
            }

            function show() {
                hl.setAttribute("data-on", "true");
                var start = parseDate(b.at);
                var end = new Date(start.getTime() + a.bucket_hours * 3600000);
                var n = b.ok + b.failed;
                clear(tip);
                tip.appendChild(el("div", { text: bucketLabel(start, a.bucket_hours, true) + " – " + bucketLabel(end, a.bucket_hours, false) }));
                tip.appendChild(el("div", null, ["Succeeded ", el("strong", { text: fmtNum(b.ok) })]));
                tip.appendChild(el("div", null, ["Failed ", el("strong", { text: fmtNum(b.failed) })]));
                if (n > 0) tip.appendChild(el("div", null, ["Success rate ", el("strong", { text: fmtPct(100 * b.ok / n) })]));
                tip.hidden = false;
                var rect = card.getBoundingClientRect();
                var col = hit.getBoundingClientRect();
                var left = col.left - rect.left + col.width / 2 - tip.offsetWidth / 2;
                tip.style.left = Math.max(4, Math.min(rect.width - tip.offsetWidth - 4, left)) + "px";
                tip.style.top = (col.top - rect.top - 4) + "px";
            }
            function hide() { hl.removeAttribute("data-on"); tip.hidden = true; }
            hit.addEventListener("mouseenter", show);
            hit.addEventListener("focus", show);
            hit.addEventListener("mouseleave", hide);
            hit.addEventListener("blur", hide);
        });
        host.appendChild(chart);

        var tbl = el("table", { class: "ark-table" }, [
            el("thead", null, [el("tr", null, [el("th", { text: "From" }), el("th", { class: "ark-num", text: "Succeeded" }), el("th", { class: "ark-num", text: "Failed" })])]),
            el("tbody", null, series.slice().reverse().map(function (b) {
                return el("tr", null, [el("td", { text: bucketLabel(parseDate(b.at), a.bucket_hours, true) }), el("td", { class: "ark-num", text: fmtNum(b.ok) }), el("td", { class: "ark-num", text: fmtNum(b.failed) })]);
            }))
        ]);
        table.appendChild(tbl);
    }

    // ---------------------------------------------------------------- endpoint list

    function renderRows() {
        var body = clear(byId("wh-rows"));
        if (!state.endpoints.length) {
            body.appendChild(el("tr", null, [el("td", { colspan: 9, class: "ark-empty" }, [
                "No webhooks yet. ",
                el("a", { href: "#", text: "Create the first one", onclick: function (e) { e.preventDefault(); openEditor(null); } }),
                "."
            ])]));
            return;
        }
        state.endpoints.forEach(function (e) {
            var s = stats(e.id) || {};
            var events = e.events.slice(0, 4).map(function (x) { return el("span", { class: "wh-tag", text: x }); });
            if (e.events.length > 4) events.push(el("span", { class: "wh-tag", text: "+" + (e.events.length - 4) }));
            var tr = el("tr", {
                tabindex: 0,
                "aria-selected": state.selected === e.id ? "true" : "false",
                onclick: function () { select(e.id); },
                onkeydown: function (ev) { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); select(e.id); } }
            }, [
                el("td", null, [
                    el("div", { class: "wh-name", text: e.name }),
                    el("div", { class: "wh-sub", text: e.url, title: e.url }),
                    tenantFilter() ? null : el("div", { class: "wh-sub", text: "tenant " + e.tenant_id })
                ]),
                el("td", null, [statusBadge(e)]),
                el("td", null, [el("div", { class: "wh-tags" }, events)]),
                el("td", { class: "ark-num", text: fmtNum(s.delivered) }),
                el("td", { class: "ark-num" + (s.success_rate !== null && s.success_rate !== undefined && s.success_rate < 90 ? " ark-num-bad" : ""), text: fmtPct(s.success_rate) }),
                el("td", { class: "ark-num", text: fmtNum(s.backlog) }),
                el("td", { class: "ark-num" + (s.open_dead_letters > 0 ? " ark-num-bad" : ""), text: fmtNum(s.open_dead_letters) }),
                el("td", null, [el("div", { text: e.shard.strategy + (e.shard.strategy === "hashed" ? " × " + e.shard.count : "") }), el("div", { class: "wh-sub", text: e.shard.databases.join(", ") })]),
                el("td", null, [
                    el("div", { text: e.last_success_at ? fmtAgo(e.last_success_at) : "—", title: e.last_success_at ? fmtDate(e.last_success_at) : "" }),
                    e.last_failure_at ? el("div", { class: "wh-sub", text: "failed " + fmtAgo(e.last_failure_at), title: e.last_error || "" }) : null
                ])
            ]);
            body.appendChild(tr);
        });
    }

    // ---------------------------------------------------------------- one endpoint

    function select(id) {
        if (state.selected === id) { deselect(); return; }
        state.selected = id;
        clear(byId("wh-test-result"));
        setTab("history");
        renderRows();
        renderDetail(false);
        loadEndpointAnalytics(id);
        byId("wh-detail").scrollIntoView({ behavior: "smooth", block: "start" });
    }

    function renderDetail(refresh) {
        var e = endpoint(state.selected);
        if (!e) { byId("wh-detail").hidden = true; return; }
        byId("wh-detail").hidden = false;
        byId("wh-detail-title").textContent = e.name;
        clear(byId("wh-detail-badge")).appendChild(statusBadge(e));
        byId("wh-detail-url").textContent = e.url;
        byId("wh-detail-url").title = e.url;
        var statusBtn = byId("wh-act-status");
        statusBtn.textContent = e.status === "active" ? "Pause" : e.status === "paused" ? "Resume" : "Enable";
        statusBtn.dataset.action = e.status === "active" ? "pause" : e.status === "paused" ? "resume" : "enable";

        var alert = clear(byId("wh-detail-alert"));
        if (e.status === "disabled") {
            alert.appendChild(el("div", { class: "ark-alert" }, [
                el("strong", { text: e.auto_disabled ? "Disabled after repeated failures. " : "Disabled. " }),
                e.disabled_reason || "",
                el("div", { text: "Disabled " + fmtDate(e.disabled_at) + ". New events are not queued; what was waiting is in the dead-letter queue. Fix the receiver, use Send test to check it, then Enable and replay the dead letters." })
            ]));
        } else if (e.consecutive_failures > 0) {
            alert.appendChild(el("div", { class: "ark-alert ark-alert-warn" }, [
                el("strong", { text: e.consecutive_failures + " failed attempt" + (e.consecutive_failures === 1 ? "" : "s") + " in a row. " }),
                e.failure_threshold > 0 ? "It is disabled automatically at " + e.failure_threshold + ". " : "",
                e.last_error ? "Last: " + e.last_error : ""
            ]));
        }
        if (e.secrets_problem) alert.appendChild(el("div", { class: "ark-alert", text: e.secrets_problem }));

        loadHistory(true);
        loadDead();
        if (!refresh) {
            var s = stats(e.id);
            if (s) renderHealth(s);
        }
    }

    function setTab(name) {
        ["history", "dead", "health"].forEach(function (t) {
            byId("wh-tab-" + t).hidden = t !== name;
            byId("wh-tab-btn-" + t).setAttribute("aria-selected", t === name ? "true" : "false");
        });
    }

    function loadHistory(reset) {
        var id = state.selected;
        if (!id) return;
        var before = null;
        if (!reset && state.historyItems.length) {
            var last = parseDate(state.historyItems[state.historyItems.length - 1].created_at);
            before = last ? last.toISOString() : null;
        }
        getJson("/deliveries", { endpoint_id: id, status: byId("wh-history-status").value, limit: 50, before: before }).then(function (r) {
            if (state.selected !== id) return;
            state.historyItems = reset ? r.items : state.historyItems.concat(r.items);
            state.historyMore = r.more;
            renderHistory();
        }).catch(fail);
    }

    function renderHistory() {
        var body = clear(byId("wh-history"));
        byId("wh-history-more").hidden = !state.historyMore;
        if (!state.historyItems.length) {
            body.appendChild(el("tr", null, [el("td", { colspan: 7, class: "ark-empty", text: "No deliveries match." })]));
            return;
        }
        state.historyItems.forEach(function (d) {
            body.appendChild(el("tr", null, [
                el("td", { title: d.id }, [el("div", { text: fmtDate(d.created_at) }), d.trigger !== "system" ? el("div", { class: "wh-sub", text: d.trigger + (d.replay_of ? " of " + d.replay_of.split("/").pop() : "") }) : null]),
                el("td", null, [el("code", { text: d.event_type }), el("div", { class: "wh-sub", text: d.event_id })]),
                el("td", null, [deliveryBadge(d.status)]),
                el("td", { class: "ark-num", text: String(d.attempt_count) }),
                el("td", null, [
                    d.last_status_code ? el("div", { text: "HTTP " + d.last_status_code }) : null,
                    d.last_error ? el("div", { class: "wh-err", text: d.last_error, title: d.last_error }) : (d.last_status_code ? null : el("span", { text: "—" }))
                ]),
                el("td", { text: d.next_attempt_at ? fmtAgo(d.next_attempt_at) : "—", title: d.next_attempt_at ? fmtDate(d.next_attempt_at) : "" }),
                el("td", null, [el("button", { type: "button", class: "ark-btn-ghost ark-btn-sm", text: "Details", onclick: function () { openDelivery(d.shard, d.id); } })])
            ]));
        });
    }

    function openDelivery(shard, id) {
        getJson("/delivery", { shard: shard, id: id }).then(function (r) {
            var d = r.delivery;
            var body = el("div");
            var payload = d.payload;
            try { payload = JSON.stringify(JSON.parse(d.payload), null, 2); } catch (e) { }
            body.appendChild(el("dl", { class: "ark-kv" }, [
                el("dt", { text: "Delivery" }), el("dd", null, [el("code", { text: d.id })]),
                el("dt", { text: "Shard" }), el("dd", null, [el("code", { text: shard })]),
                el("dt", { text: "Event" }), el("dd", null, [el("code", { text: d.event_type + " · " + d.event_id })]),
                el("dt", { text: "Status" }), el("dd", null, [deliveryBadge(d.status), " ", d.attempt_count + " attempt" + (d.attempt_count === 1 ? "" : "s")]),
                el("dt", { text: "Created" }), el("dd", { text: fmtDate(d.created_at) }),
                d.delivered_at ? el("dt", { text: "Delivered" }) : null, d.delivered_at ? el("dd", { text: fmtDate(d.delivered_at) }) : null,
                d.replay_of ? el("dt", { text: "Replay of" }) : null, d.replay_of ? el("dd", null, [el("code", { text: d.replay_of })]) : null,
                r.dead_letter ? el("dt", { text: "Dead letter" }) : null,
                r.dead_letter ? el("dd", { text: r.dead_letter.reason + " · " + fmtDate(r.dead_letter.dead_at) + (r.dead_letter.replayed_at ? " · replayed " + fmtDate(r.dead_letter.replayed_at) + " by " + (r.dead_letter.replayed_by || "?") : "") }) : null
            ]));
            body.appendChild(el("h4", { text: "Attempts" }));
            if (!r.attempts.length) body.appendChild(el("p", { class: "ark-empty", text: "Not attempted yet." }));
            else body.appendChild(el("div", { class: "ark-table-wrap" }, [el("table", { class: "ark-table" }, [
                el("thead", null, [el("tr", null, [el("th", { text: "#" }), el("th", { text: "At" }), el("th", { text: "Result" }), el("th", { class: "ark-num", text: "ms" }), el("th", { text: "Worker" })])]),
                el("tbody", null, r.attempts.map(function (a) {
                    return el("tr", null, [
                        el("td", { text: String(a.attempt_no) }),
                        el("td", { text: fmtDate(a.started_at) }),
                        el("td", null, [
                            el("span", { class: a.success ? "wh-ok" : "wh-bad", text: a.success ? "✓ " + (a.status_code || "") : "✕ " + (a.status_code ? "HTTP " + a.status_code : "") }),
                            a.error ? el("div", { class: "wh-err", text: a.error }) : null,
                            a.response_body ? el("details", null, [el("summary", { text: "response" }), el("pre", { text: a.response_body })]) : null
                        ]),
                        el("td", { class: "ark-num", text: String(a.duration_ms) }),
                        el("td", { class: "wh-sub", text: a.worker || "" })
                    ]);
                }))
            ])]));
            body.appendChild(el("h4", { text: "Body sent" }));
            body.appendChild(el("pre", { text: payload }));

            var foot = [];
            if (["pending", "retrying"].indexOf(d.status) >= 0) {
                foot.push(el("button", { type: "button", class: "ark-btn-danger", text: "Cancel delivery", onclick: function () {
                    postJson("/delivery/cancel", { shard: shard, id: d.id }).then(function () { toast("s", "cancelled"); closeModal(); refreshSelected(); }).catch(fail);
                } }));
            }
            if (["delivered", "dead", "cancelled", "test_failed"].indexOf(d.status) >= 0) {
                foot.push(el("button", { type: "button", text: "Replay", onclick: function () {
                    postJson("/delivery/replay", { shard: shard, id: d.id }).then(function () { toast("s", "queued for delivery again"); closeModal(); refreshSelected(); }).catch(fail);
                } }));
            }
            openModal("Delivery", body, foot);
        }).catch(fail);
    }

    function loadDead() {
        var id = state.selected;
        if (!id) return;
        getJson("/deadletters", { endpoint_id: id, include_replayed: byId("wh-dead-replayed").checked, limit: 200 }).then(function (r) {
            if (state.selected !== id) return;
            state.deadItems = r.items;
            byId("wh-dead-count").textContent = r.open ? String(r.open) : "";
            renderDead();
        }).catch(fail);
    }

    function selectedDead() {
        return Array.prototype.slice.call(document.querySelectorAll("#wh-dead input[type=checkbox]:checked")).map(function (c) {
            return { shard: c.dataset.shard, id: c.dataset.id };
        });
    }

    function syncDeadButtons() {
        var n = selectedDead().length;
        byId("wh-dead-replay-sel").disabled = n === 0;
        byId("wh-dead-purge-sel").disabled = n === 0;
    }

    function renderDead() {
        var body = clear(byId("wh-dead"));
        byId("wh-dead-all").checked = false;
        syncDeadButtons();
        var reasons = {
            max_attempts: "retries exhausted",
            non_retryable: "refused (not retryable)",
            endpoint_disabled: "endpoint disabled",
            expired: "expired"
        };
        if (!state.deadItems.length) {
            body.appendChild(el("tr", null, [el("td", { colspan: 8, class: "ark-empty", text: "The dead-letter queue is empty." })]));
            return;
        }
        state.deadItems.forEach(function (l) {
            body.appendChild(el("tr", null, [
                el("td", null, [l.replayed_at ? null : el("input", { type: "checkbox", "data-shard": l.shard, "data-id": l.id, "aria-label": "Select", onchange: syncDeadButtons })]),
                el("td", { text: fmtDate(l.dead_at) }),
                el("td", null, [el("code", { text: l.event_type }), el("div", { class: "wh-sub", text: l.event_id })]),
                el("td", { text: reasons[l.reason] || l.reason }),
                el("td", { class: "ark-num", text: String(l.attempts) }),
                el("td", null, [
                    l.last_status_code ? el("div", { text: "HTTP " + l.last_status_code }) : null,
                    l.last_error ? el("div", { class: "wh-err", text: l.last_error, title: l.last_error }) : null
                ]),
                el("td", { text: l.replayed_at ? fmtAgo(l.replayed_at) + (l.replayed_by ? " by " + l.replayed_by : "") : "—" }),
                el("td", null, [el("button", { type: "button", class: "ark-btn-ghost ark-btn-sm", text: "Details", onclick: function () { openDelivery(l.shard, l.delivery_id); } })])
            ]));
        });
    }

    function renderHealth(s) {
        var e = endpoint(state.selected);
        var host = clear(byId("wh-health"));
        if (!e) return;
        s = s || {};
        var failPct = e.failure_threshold > 0 ? Math.min(100, 100 * e.consecutive_failures / e.failure_threshold) : 0;
        var meter = el("div", { class: "wh-meter", role: "meter", "aria-valuemin": 0, "aria-valuemax": e.failure_threshold || 1, "aria-valuenow": e.consecutive_failures, "aria-label": "Consecutive failures" }, [el("span")]);
        meter.firstChild.style.width = failPct + "%";

        host.appendChild(el("div", null, [
            el("h4", { text: "Last " + (hours() === 24 ? "24 hours" : hours() === 168 ? "7 days" : "30 days") }),
            el("dl", { class: "ark-kv" }, [
                el("dt", { text: "Delivered" }), el("dd", { text: fmtNum(s.delivered) }),
                el("dt", { text: "Dead-lettered" }), el("dd", { text: fmtNum(s.dead) }),
                el("dt", { text: "Attempts" }), el("dd", { text: fmtNum(s.attempts) + " (" + fmtNum(s.failed_attempts) + " failed)" }),
                el("dt", { text: "Success rate" }), el("dd", { text: fmtPct(s.success_rate) }),
                el("dt", { text: "Latency" }), el("dd", { text: s.avg_ms !== null && s.avg_ms !== undefined ? "avg " + s.avg_ms + " ms · p95 " + s.p95_ms + " ms" : "—" }),
                el("dt", { text: "Waiting now" }), el("dd", { text: fmtNum(s.backlog) }),
                el("dt", { text: "Open dead letters" }), el("dd", { text: fmtNum(s.open_dead_letters) })
            ])
        ]));
        host.appendChild(el("div", null, [
            el("h4", { text: "Failure threshold" }),
            el("div", { text: e.consecutive_failures + " consecutive failure" + (e.consecutive_failures === 1 ? "" : "s") + (e.failure_threshold > 0 ? " of " + e.failure_threshold + " allowed" : " (never disabled automatically)") }),
            e.failure_threshold > 0 ? meter : null,
            el("dl", { class: "ark-kv" }, [
                el("dt", { text: "Last success" }), el("dd", { text: fmtDate(e.last_success_at) }),
                el("dt", { text: "Last failure" }), el("dd", { text: fmtDate(e.last_failure_at) }),
                el("dt", { text: "Last error" }), el("dd", { class: "wh-err", text: e.last_error || "—" }),
                el("dt", { text: "Retry policy" }), el("dd", { text: e.retry.max_attempts + " attempts, " + e.retry.backoff + " from " + fmtSecs(e.retry.initial_delay_seconds) + " to " + fmtSecs(e.retry.max_delay_seconds) + (e.retry.retry_on_4xx ? ", 4xx retried" : "") }),
                el("dt", { text: "Auth" }), el("dd", { text: e.auth.type + (e.auth.type === "jwt" ? " (" + e.auth.jwt_alg + ")" : e.auth.type === "oauth2" ? " (" + e.auth.oauth_grant + ")" : "") }),
                el("dt", { text: "Signing secret" }), el("dd", { text: e.has_signing_secret ? "set (Standard Webhooks, v1)" : "none" })
            ])
        ]));
        host.appendChild(el("div", null, [
            el("h4", { text: "Storage plan" }),
            el("div", { text: e.shard.strategy + (e.shard.strategy === "hashed" ? " over " + e.shard.count + " shards by " + e.shard.partition_key.replace("_", " ") : "") + " on " + e.shard.databases.join(", ") }),
            el("ul", { class: "ark-list" }, e.shard.targets.map(function (t) {
                return el("li", null, [el("code", { text: t.shard }), el("div", { class: "wh-sub", text: t.tables.join(", ") })]);
            }))
        ]));
    }

    function refreshSelected() {
        loadAll().then(function () { if (state.selected) { loadHistory(true); loadDead(); } });
    }

    // ---------------------------------------------------------------- actions

    function test() {
        var e = endpoint(state.selected);
        if (!e) return;
        var out = clear(byId("wh-test-result"));
        out.appendChild(el("p", { class: "ark-note", text: "Sending a webhook.test event to " + e.url + "…" }));
        postJson("/test", { id: e.id }).then(function (r) {
            clear(out);
            out.appendChild(el("div", { class: "wh-result ark-alert" + (r.success ? " wh-alert-ok" : "") }, [
                el("strong", { class: r.success ? "wh-ok" : "wh-bad", text: r.success ? "✓ Test delivered" : "✕ Test failed" }),
                " — " + (r.status_code ? "HTTP " + r.status_code + " · " : "") + r.duration_ms + " ms" + (r.error ? " · " + r.error : ""),
                r.response_body ? el("details", null, [el("summary", { text: "response body" }), el("pre", { text: r.response_body })]) : null
            ]));
            loadHistory(true);
        }).catch(function (err) { clear(out); fail(err); });
    }

    function changeStatus() {
        var e = endpoint(state.selected);
        var action = byId("wh-act-status").dataset.action;
        if (!e || !action) return;
        postJson("/status", { id: e.id, action: action }).then(function (r) {
            toast("s", "'" + e.name + "' " + (action === "pause" ? "paused" : action === "resume" ? "resumed" : "enabled") + (r.dead_lettered ? " — " + r.dead_lettered + " moved to dead letters" : ""));
            refreshSelected();
        }).catch(fail);
    }

    function rotate() {
        var e = endpoint(state.selected);
        if (!e) return;
        if (!confirm("Rotate the signing secret of '" + e.name + "'? Signatures made with the old secret stop verifying at once: update the receiver straight away.")) return;
        postJson("/secret/rotate", { id: e.id }).then(function (r) { showSecret(e.name, r.signing_secret, false); }).catch(fail);
    }

    function remove() {
        var e = endpoint(state.selected);
        if (!e) return;
        var body = el("div", null, [
            el("p", { text: "Delete '" + e.name + "'? Deliveries still waiting are cancelled." }),
            el("div", { class: "ark-check" }, [el("input", { type: "checkbox", id: "wh-del-purge" }), el("label", { for: "wh-del-purge", text: "Also delete its delivery history and dead letters" })])
        ]);
        openModal("Delete webhook", body, [el("button", { type: "button", class: "ark-btn-danger-solid", text: "Delete", onclick: function () {
            postJson("/delete", { id: e.id, purge: byId("wh-del-purge").checked }).then(function (r) {
                toast("s", "deleted" + (r.cancelled ? " — " + r.cancelled + " waiting deliveries cancelled" : ""));
                closeModal();
                state.selected = null;
                loadAll();
                loadShards();
            }).catch(fail);
        } })]);
    }

    function replayDead(items, all) {
        var id = state.selected;
        var body = all ? { endpoint_id: id } : { items: items };
        postJson("/deadletters/replay", body).then(function (r) {
            toast(r.failed.length ? "w" : "s", r.replayed + " replayed" + (r.failed.length ? ", " + r.failed.length + " not: " + r.failed[0].error : ""), 6000);
            refreshSelected();
        }).catch(fail);
    }

    function purgeDead(items) {
        if (!confirm("Delete " + items.length + " dead letter(s)? They cannot be replayed afterwards.")) return;
        postJson("/deadletters/purge", { items: items }).then(function (r) { toast("s", r.removed + " removed"); loadDead(); }).catch(fail);
    }

    // ---------------------------------------------------------------- modal

    function openModal(title, body, footButtons) {
        byId("wh-modal-title").textContent = title;
        clear(byId("wh-modal-body")).appendChild(body);
        var foot = clear(byId("wh-modal-foot"));
        foot.appendChild(el("span"));
        (footButtons || []).forEach(function (b) { foot.appendChild(b); });
        byId("wh-modal").hidden = false;
        byId("wh-modal-backdrop").hidden = false;
    }

    function closeModal() {
        byId("wh-modal").hidden = true;
        byId("wh-modal-backdrop").hidden = true;
    }

    function showSecret(name, secret, created) {
        var code = el("code", { text: secret });
        var body = el("div", null, [
            el("p", { text: (created ? "'" + name + "' was created. " : "") + "This is its signing secret. Copy it now: it is stored encrypted and not shown again." }),
            el("div", { class: "wh-secret" }, [code, el("button", { type: "button", class: "ark-btn-ghost ark-btn-sm", text: "Copy", onclick: function () {
                if (navigator.clipboard) navigator.clipboard.writeText(secret).then(function () { toast("s", "copied"); });
            } })]),
            el("p", { class: "ark-note", text: "Verify each request per Standard Webhooks: HMAC-SHA256 over \"{webhook-id}.{webhook-timestamp}.{body}\" with the base64 key after \"whsec_\", compared with the v1 value in webhook-signature. Reject timestamps more than five minutes old." })
        ]);
        openModal("Signing secret", body, []);
    }

    // ---------------------------------------------------------------- editor

    function openEditor(e) {
        state.editing = e;
        var meta = state.meta;
        var d = meta.defaults;
        byId("wh-drawer-title").textContent = e ? "Edit " + e.name : "New webhook";
        byId("wh-form-error").hidden = true;
        byId("wh-save-note").textContent = "";

        var tenant = byId("f-tenant");
        clear(tenant);
        meta.tenants.forEach(function (t) { tenant.add(new Option(t.tenant_id + (t.name && t.name !== t.tenant_id ? " — " + t.name : ""), t.tenant_id)); });
        tenant.value = e ? e.tenant_id : (tenantFilter() || root.dataset.tenantId);
        byId("f-name").value = e ? e.name : "";
        byId("f-url").value = e ? e.url : "";
        byId("f-description").value = e ? (e.description || "") : "";
        byId("f-status-field").hidden = !!e;
        byId("f-status").value = "active";

        // events
        var known = meta.events.map(function (x) { return x.type; });
        var chosen = e ? e.events : [];
        byId("f-ev-all").checked = chosen.indexOf("*") >= 0;
        var host = clear(byId("f-events"));
        var group = null;
        meta.events.forEach(function (x) {
            if (x.type === "webhook.test") return;
            if (x.group !== group) { group = x.group; host.appendChild(el("h5", { text: group })); }
            var id = "f-ev-" + x.type.replace(/[^a-z0-9]/g, "-");
            host.appendChild(el("span", { class: "ark-check", title: x.description }, [
                el("input", { type: "checkbox", id: id, value: x.type, checked: chosen.indexOf(x.type) >= 0 }),
                el("label", { for: id }, [el("code", { text: x.type })])
            ]));
        });
        byId("f-events-custom").value = chosen.filter(function (x) { return x !== "*" && known.indexOf(x) < 0; }).join(" ");
        syncEventsAll();

        // auth
        var a = e ? e.auth : { type: "none" };
        byId("f-auth-type").value = a.type || "none";
        byId("f-basic-user").value = a.basic_username || "";
        byId("f-bearer-header").value = a.bearer_header || "";
        byId("f-bearer-scheme").value = a.bearer_scheme === undefined || a.bearer_scheme === null ? "Bearer" : a.bearer_scheme;
        byId("f-jwt-alg").value = a.jwt_alg || "HS256";
        byId("f-jwt-iss").value = a.jwt_issuer || "";
        byId("f-jwt-aud").value = a.jwt_audience || "";
        byId("f-jwt-life").value = a.jwt_lifetime_seconds || 300;
        byId("f-jwt-header").value = a.jwt_header || "";
        byId("f-jwt-claims").value = a.jwt_claims || "";
        byId("f-oauth-grant").value = a.oauth_grant || "refresh_token";
        byId("f-oauth-auth").value = a.oauth_client_auth || "client_secret_post";
        byId("f-oauth-url").value = a.oauth_token_url || "";
        byId("f-oauth-client").value = a.oauth_client_id || "";
        byId("f-oauth-scope").value = a.oauth_scope || "";
        byId("f-oauth-aud").value = a.oauth_audience || "";
        ["f-basic-pass", "f-bearer-token", "f-jwt-secret", "f-oauth-secret", "f-oauth-refresh"].forEach(function (id) { byId(id).value = ""; });
        var has = {
            basic_password: a.has_basic_password, bearer_token: a.has_bearer_token, jwt_secret: a.has_jwt_secret,
            oauth_client_secret: a.has_oauth_client_secret, oauth_refresh_token: a.has_oauth_refresh_token
        };
        document.querySelectorAll("[data-secret-note]").forEach(function (n) {
            if (!n.dataset.base) n.dataset.base = n.textContent;
            n.textContent = (has[n.dataset.secretNote] ? "Stored — leave blank to keep it. " : "") + n.dataset.base;
        });
        syncAuth();

        // headers
        var hh = clear(byId("f-headers"));
        (e ? e.headers : []).forEach(function (h) { addHeaderRow(h.name, h.has_value); });
        if (!hh.childNodes.length) hh.appendChild(el("p", { class: "ark-note", id: "f-headers-empty", text: "None." }));

        // retry
        var r = e ? e.retry : d;
        byId("f-max-attempts").value = r.max_attempts;
        byId("f-backoff").value = r.backoff;
        byId("f-initial-delay").value = r.initial_delay_seconds;
        byId("f-max-delay").value = r.max_delay_seconds;
        byId("f-retry-4xx").checked = e ? !!e.retry.retry_on_4xx : false;
        byId("f-timeout").value = e ? e.timeout_seconds : d.timeout_seconds;
        byId("f-concurrency").value = e ? e.max_concurrency : d.max_concurrency;
        byId("f-threshold").value = e ? e.failure_threshold : d.failure_threshold;
        renderSchedule();

        // shard plan
        var s = e ? e.shard : { strategy: "shared", databases: ["main"], count: 4, partition_key: "subject" };
        document.querySelectorAll("input[name=f-strategy]").forEach(function (x) { x.checked = x.value === s.strategy; });
        var dbs = clear(byId("f-databases"));
        meta.databases.forEach(function (db) {
            var id = "f-db-" + db.name;
            dbs.appendChild(el("span", { class: "ark-check" }, [
                el("input", { type: "checkbox", id: id, value: db.name, disabled: !db.configured, checked: s.databases.indexOf(db.name) >= 0 }),
                el("label", { for: id }, [db.name, " ", el("span", { class: "ark-hint", text: db.name === "main" ? "IdP database, " + db.provider : (db.configured ? db.provider : "not configured") })])
            ]));
        });
        byId("f-shard-count").value = s.strategy === "hashed" ? s.count : 4;
        byId("f-partition").value = s.partition_key || "subject";
        syncPlan();

        byId("wh-drawer").setAttribute("data-open", "true");
        byId("wh-drawer-backdrop").setAttribute("data-open", "true");
        byId("f-name").focus();
    }

    function closeEditor() {
        byId("wh-drawer").removeAttribute("data-open");
        byId("wh-drawer-backdrop").removeAttribute("data-open");
        state.editing = null;
    }

    function syncEventsAll() {
        var all = byId("f-ev-all").checked;
        document.querySelectorAll("#f-events input[type=checkbox]").forEach(function (c) { c.disabled = all; });
    }

    function syncAuth() {
        var type = byId("f-auth-type").value;
        document.querySelectorAll("[data-auth]").forEach(function (n) { n.hidden = n.dataset.auth !== type; });
        byId("f-jwt-secret-field").hidden = byId("f-jwt-alg").value !== "HS256";
        byId("f-oauth-refresh-field").hidden = byId("f-oauth-grant").value !== "refresh_token";
    }

    function addHeaderRow(name, hasValue) {
        var empty = byId("f-headers-empty");
        if (empty) empty.remove();
        var row = el("div", { class: "wh-header-row", "data-existing": hasValue ? "true" : "false" }, [
            el("input", { type: "text", class: "f-h-name", placeholder: "X-Api-Key", value: name || "", "aria-label": "Header name", spellcheck: "false" }),
            el("input", { type: "password", class: "f-h-value", placeholder: hasValue ? "stored — blank keeps it" : "value", "aria-label": "Header value", autocomplete: "new-password" }),
            el("button", { type: "button", class: "ark-btn-ghost ark-btn-sm", text: "Remove", onclick: function () { row.remove(); } })
        ]);
        byId("f-headers").appendChild(row);
        return row;
    }

    function renderSchedule() {
        var n = parseInt(byId("f-max-attempts").value, 10) || 1;
        var initial = Math.max(1, parseInt(byId("f-initial-delay").value, 10) || 1);
        var max = Math.max(initial, parseInt(byId("f-max-delay").value, 10) || initial);
        var backoff = byId("f-backoff").value;
        var waits = [], total = 0;
        for (var i = 1; i < n && i <= 50; i++) {
            var s = backoff === "linear" ? initial * i : backoff === "fixed" ? initial : initial * Math.pow(2, i - 1);
            s = Math.min(s, max);
            waits.push(s);
            total += s;
        }
        byId("f-schedule").textContent = n <= 1
            ? "One attempt, no retries: a failure goes straight to the dead-letter queue."
            : "Retries after " + waits.slice(0, 10).map(fmtSecs).join(", ") + (waits.length > 10 ? ", …" : "") +
              " (±20% jitter) — the last attempt about " + fmtSecs(total) + " after the first. Then the dead-letter queue.";
    }

    function strategy() {
        var c = document.querySelector("input[name=f-strategy]:checked");
        return c ? c.value : "shared";
    }

    function chosenDatabases() {
        var list = Array.prototype.slice.call(document.querySelectorAll("#f-databases input:checked")).map(function (c) { return c.value; });
        return list.length ? list : ["main"];
    }

    function syncPlan() {
        var hashed = strategy() === "hashed";
        document.querySelectorAll("[data-plan=hashed]").forEach(function (n) { n.hidden = !hashed; });
        if (!hashed) {
            // One database outside the hashed plan: keep the first ticked.
            var ticked = Array.prototype.slice.call(document.querySelectorAll("#f-databases input:checked"));
            ticked.slice(1).forEach(function (c) { c.checked = false; });
        }
        clearTimeout(state.planTimer);
        state.planTimer = setTimeout(previewPlan, 250);
    }

    function shardPayload() {
        return {
            strategy: strategy(),
            databases: chosenDatabases(),
            count: strategy() === "hashed" ? parseInt(byId("f-shard-count").value, 10) || 2 : 1,
            partition_key: byId("f-partition").value
        };
    }

    function previewPlan() {
        var host = byId("f-plan");
        postJson("/plan", { id: state.editing ? state.editing.id : null, shard: shardPayload() }).then(function (p) {
            clear(host);
            host.appendChild(el("p", { text: p.explain }));
            var bad = p.databases.filter(function (d) { return !d.reachable; });
            bad.forEach(function (d) { host.appendChild(el("div", { class: "ark-alert", text: "Database '" + d.name + "' cannot be reached: " + d.error })); });
            host.appendChild(el("ul", null, p.targets.map(function (t) {
                return el("li", null, [
                    el("code", { text: t.shard }), " ",
                    el("span", { class: "ark-hint", text: t.exists ? "exists" : "created on save" }),
                    el("div", { class: "wh-sub", text: t.tables.join(", ") })
                ]);
            })));
        }).catch(function (err) {
            clear(host).appendChild(el("div", { class: "ark-alert", text: err.message }));
        });
    }

    function val(id) { return byId(id).value; }
    function secret(id) { var v = byId(id).value; return v === "" ? null : v; }
    function num(id) { var v = parseInt(byId(id).value, 10); return isNaN(v) ? null : v; }

    function save() {
        var events = [];
        if (byId("f-ev-all").checked) events.push("*");
        else document.querySelectorAll("#f-events input:checked").forEach(function (c) { events.push(c.value); });
        val("f-events-custom").split(/[\s,]+/).forEach(function (x) { if (x) events.push(x); });

        var headers = [];
        document.querySelectorAll("#f-headers .wh-header-row").forEach(function (row) {
            var name = row.querySelector(".f-h-name").value.trim();
            if (!name) return;
            var value = row.querySelector(".f-h-value").value;
            headers.push({ name: name, value: value === "" && row.dataset.existing === "true" ? null : value });
        });

        var body = {
            id: state.editing ? state.editing.id : null,
            tenant_id: val("f-tenant"),
            name: val("f-name"),
            description: val("f-description"),
            url: val("f-url").trim(),
            events: events,
            status: state.editing ? null : val("f-status"),
            failure_threshold: num("f-threshold"),
            timeout_seconds: num("f-timeout"),
            max_concurrency: num("f-concurrency"),
            retry: {
                max_attempts: num("f-max-attempts"),
                backoff: val("f-backoff"),
                initial_delay_seconds: num("f-initial-delay"),
                max_delay_seconds: num("f-max-delay"),
                retry_on_4xx: byId("f-retry-4xx").checked
            },
            auth: {
                type: val("f-auth-type"),
                basic_username: val("f-basic-user"),
                basic_password: secret("f-basic-pass"),
                bearer_token: secret("f-bearer-token"),
                bearer_header: val("f-bearer-header"),
                bearer_scheme: val("f-bearer-scheme"),
                jwt_alg: val("f-jwt-alg"),
                jwt_secret: secret("f-jwt-secret"),
                jwt_issuer: val("f-jwt-iss"),
                jwt_audience: val("f-jwt-aud"),
                jwt_lifetime_seconds: num("f-jwt-life"),
                jwt_header: val("f-jwt-header"),
                jwt_claims: val("f-jwt-claims"),
                oauth_grant: val("f-oauth-grant"),
                oauth_token_url: val("f-oauth-url"),
                oauth_client_id: val("f-oauth-client"),
                oauth_client_secret: secret("f-oauth-secret"),
                oauth_refresh_token: secret("f-oauth-refresh"),
                oauth_scope: val("f-oauth-scope"),
                oauth_audience: val("f-oauth-aud"),
                oauth_client_auth: val("f-oauth-auth")
            },
            headers: headers,
            shard: shardPayload()
        };

        var button = byId("wh-save");
        button.disabled = true;
        byId("wh-save-note").textContent = "Saving — preparing the shard tables…";
        byId("wh-form-error").hidden = true;
        postJson("/upsert", body).then(function (r) {
            closeEditor();
            toast("s", "saved");
            state.selected = r.endpoint.id;
            if (r.signing_secret) showSecret(r.endpoint.name, r.signing_secret, true);
            refreshSelected();
            loadShards();
        }).catch(function (err) {
            var box = byId("wh-form-error");
            box.textContent = err.message;
            box.hidden = false;
            box.scrollIntoView({ block: "nearest" });
        }).then(function () {
            button.disabled = false;
            byId("wh-save-note").textContent = "";
        });
    }

    // ---------------------------------------------------------------- shards

    function loadShards() {
        getJson("/shards").then(function (r) {
            var body = clear(byId("wh-shards"));
            if (!r.items.length) {
                body.appendChild(el("tr", null, [el("td", { colspan: 8, class: "ark-empty", text: "No shards yet — the first webhook creates its tables." })]));
                return;
            }
            r.items.forEach(function (s) {
                var c = s.counts || { by_status: {} };
                var waiting = (c.by_status.pending || 0) + (c.by_status.retrying || 0) + (c.by_status.in_flight || 0);
                body.appendChild(el("tr", null, [
                    el("td", null, [el("code", { text: s.id })]),
                    el("td", { text: s.strategy }),
                    el("td", { text: s.endpoint_name || (s.endpoint_id ? s.endpoint_id : "shared") }),
                    el("td", null, [el("span", { class: "ark-badge " + (s.status === "active" ? "ark-badge-ok" : "ark-badge-off"), text: s.status })]),
                    el("td", { class: "ark-num", text: s.counts ? fmtNum(c.deliveries) : "—" }),
                    el("td", { class: "ark-num", text: s.counts ? fmtNum(waiting) : "—" }),
                    el("td", { class: "ark-num", text: s.counts ? fmtNum(c.dead_letters) : "—" }),
                    el("td", null, s.error ? [el("span", { class: "wh-err", text: s.error })] : [el("div", { class: "wh-sub", text: s.tables.join(", "), title: s.tables.join("\n") })])
                ]));
            });
        }).catch(fail);
    }

    // ---------------------------------------------------------------- wiring

    on("wh-refresh", "click", function () { loadAll(); loadShards(); });
    on("wh-tenant", "change", function () { state.selected = null; loadAll(); });
    on("wh-hours", "change", function () { loadAll(); });
    on("wh-act-close", "click", deselect);
    on("wh-new", "click", function () { openEditor(null); });
    on("wh-act-test", "click", test);
    on("wh-act-status", "click", changeStatus);
    on("wh-act-edit", "click", function () { var e = endpoint(state.selected); if (e) openEditor(e); });
    on("wh-act-rotate", "click", rotate);
    on("wh-act-delete", "click", remove);
    on("wh-tab-btn-history", "click", function () { setTab("history"); });
    on("wh-tab-btn-dead", "click", function () { setTab("dead"); });
    on("wh-tab-btn-health", "click", function () { setTab("health"); });
    on("wh-history-status", "change", function () { loadHistory(true); });
    on("wh-history-reload", "click", function () { loadHistory(true); });
    on("wh-history-more", "click", function () { loadHistory(false); });
    on("wh-dead-replayed", "change", loadDead);
    on("wh-dead-all", "change", function (ev) {
        document.querySelectorAll("#wh-dead input[type=checkbox]").forEach(function (c) { c.checked = ev.target.checked; });
        syncDeadButtons();
    });
    on("wh-dead-replay-sel", "click", function () { replayDead(selectedDead(), false); });
    on("wh-dead-replay-all", "click", function () { replayDead(null, true); });
    on("wh-dead-purge-sel", "click", function () { purgeDead(selectedDead()); });
    on("wh-shards-refresh", "click", loadShards);
    on("wh-modal-close", "click", closeModal);
    on("wh-modal-backdrop", "click", closeModal);
    on("wh-drawer-close", "click", closeEditor);
    on("wh-cancel", "click", closeEditor);
    on("wh-drawer-backdrop", "click", closeEditor);
    on("wh-save", "click", save);
    on("f-ev-all", "change", syncEventsAll);
    on("f-auth-type", "change", syncAuth);
    on("f-jwt-alg", "change", syncAuth);
    on("f-oauth-grant", "change", syncAuth);
    on("f-header-add", "click", function () { addHeaderRow("", false).querySelector("input").focus(); });
    ["f-max-attempts", "f-backoff", "f-initial-delay", "f-max-delay"].forEach(function (id) { on(id, "input", renderSchedule); on(id, "change", renderSchedule); });
    document.querySelectorAll("input[name=f-strategy]").forEach(function (r) { r.addEventListener("change", syncPlan); });
    on("f-databases", "change", function (ev) {
        if (strategy() !== "hashed" && ev.target.checked) {
            document.querySelectorAll("#f-databases input:checked").forEach(function (c) { if (c !== ev.target) c.checked = false; });
        }
        syncPlan();
    });
    on("f-shard-count", "input", syncPlan);
    on("f-partition", "change", syncPlan);
    document.addEventListener("keydown", function (ev) {
        if (ev.key !== "Escape") return;
        if (!byId("wh-modal").hidden) closeModal();
        else if (byId("wh-drawer").hasAttribute("data-open")) closeEditor();
    });
    var resizeTimer = null;
    window.addEventListener("resize", function () {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(function () {
            var a = state.selected ? state.endpointAnalytics : state.analytics;
            if (a) renderChart(a);
        }, 150);
    });

    loadAll();
    loadShards();
    // The numbers move on their own while deliveries are in flight.
    setInterval(function () {
        if (document.hidden || byId("wh-drawer").hasAttribute("data-open") || !byId("wh-modal").hidden) return;
        loadAll();
    }, 30000);
})();
