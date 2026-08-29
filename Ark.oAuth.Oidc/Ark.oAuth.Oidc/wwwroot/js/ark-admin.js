/* ---------------------------------------------------------------------------
   Ark IdP admin console.

   Talks only to the current management API (/api/oauth/v1/...) and links out to
   the current protocol surface (/{tenant}/oauth2/..., /{tenant}/.well-known/...).

   Differences from the v1 console this replaces, beyond the routes:

     * Columns are declared rather than generated with autoColumns. The client
       record grew RFC 7591 registration metadata, and a generated grid renders
       every column of it — including the tenant's rsa_private — as an editable
       text box. Clients are now edited in a form, and private keys are never
       sent back to the server or drawn on screen.
     * Entities that store a JSON list in a string column expose both shapes
       (`scopes` and `scopes_`). Both are written on save, so a payload cannot
       depend on JSON property order to be interpreted correctly.
     * No third-party helper libraries. Tabulator is the single external
       dependency, pinned; the toast and DOM helpers below are ~20 lines.

   One script, two pages. The console (/{tenant}/admin) and the provisioning page
   (/{tenant}/admin/provisioning) share it, and neither draws all of it, so every
   section here is wired only when the elements it drives are actually present —
   see byId/on/fillSelect below. A section that binds blindly throws on the page
   that does not have it, which stops the script before the sections that page
   does have have been wired at all.
   --------------------------------------------------------------------------- */
(function () {
    "use strict";

    var root = document.getElementById("ark-admin");
    var APP_ROOT = root.dataset.appRoot || "";
    var TENANT_ID = root.dataset.tenantId || "";
    var PAGE = root.dataset.page || "console";
    var API = APP_ROOT + "/api/oauth/v1";

    // ---------------------------------------------------------------- helpers

    function byId(id) { return document.getElementById(id); }

    /** Binds an event only if the element is on this page. Returns the element, or null. */
    function on(id, event, handler) {
        var element = byId(id);
        if (element) element.addEventListener(event, handler);
        return element;
    }

    /**
     * Repopulates a select, keeping the current selection when it still exists.
     *
     * Several selects are filled from the same three lists on both pages, and the load functions
     * run again after every save — rebuilding them by hand each time is how one of them ends up
     * silently resetting to its first option while the operator is looking at another panel.
     */
    function fillSelect(id, options, fallback, placeholder) {
        var select = byId(id);
        if (!select) return null;
        var current = select.value;
        select.innerHTML = "";
        if (placeholder) select.add(new Option(placeholder, ""));
        options.forEach(function (o) { select.add(new Option(o.label, o.value)); });
        var wanted = current || fallback || "";
        select.value = wanted;
        // A selection that no longer exists leaves value "" — which is the placeholder when there
        // is one, and the first real option when there is not.
        if (select.value !== wanted && !placeholder && select.options.length) select.selectedIndex = 0;
        return select;
    }

    function toast(kind, message, ms) {
        var host = document.getElementById("ark-toasts");
        var el = document.createElement("div");
        el.className = "ark-toast ark-toast-" + kind;
        el.textContent = message;
        host.appendChild(el);
        setTimeout(function () { el.remove(); }, ms || 3500);
    }

    /**
     * One request path for the whole console.
     *
     * The body is read before the status is judged, because the provisioning and activation
     * endpoints answer a refusal with a real HTTP status *and* an { error, code, msg } body —
     * "that client name is taken" is a 409. Throwing on !r.ok before reading would have replaced
     * that sentence with "409 Conflict", which tells the operator nothing they can act on.
     */
    function request(url, options) {
        return fetch(url, options).then(function (r) {
            return r.text().then(function (text) {
                var payload = null;
                try { payload = text ? JSON.parse(text) : null; } catch (e) { payload = null; }
                if (r.ok) return payload || {};
                // No JSON body means something other than the API answered — most often the
                // sign-in page, because the session expired.
                var err = new Error((payload && payload.msg) || (r.status + " " + r.statusText));
                err.status = r.status;
                err.payload = payload;
                throw err;
            });
        });
    }

    function getJson(url) {
        return request(url, { headers: { Accept: "application/json" } });
    }

    function postJson(url, body) {
        return request(url, {
            method: "POST",
            body: JSON.stringify(body),
            headers: { Accept: "application/json", "Content-Type": "application/json" }
        });
    }

    // Every management endpoint answers { error, msg, data }. Surface both outcomes the
    // same way so a failed save is never mistaken for a successful one. `reported` marks an
    // error whose message is already on screen, so a caller's own catch cannot toast it twice.
    function save(url, body, okMessage) {
        return postJson(url, body).then(function (res) {
            if (res && res.error) {
                var err = new Error(res.msg || "request failed");
                err.payload = res;
                err.reported = true;
                toast("f", err.message, 6000);
                throw err;
            }
            toast("s", okMessage || (res && res.msg) || "saved", 3000);
            return res;
        }).catch(function (err) {
            if (!err.reported) {
                toast("f", err.message, 6000);
                err.reported = true;
            }
            throw err;
        });
    }

    // ------------------------------------------------------------------- logos

    /**
     * Draws a logo into a fixed frame, or marks the frame empty.
     *
     * One helper for all three places a logo appears — the client editor, the provisioning form
     * and the grid thumbnail — so they cannot drift apart. The frame keeps its size either way:
     * a grid whose row height depends on whether a logo happens to be set combs up and down as
     * images load, and "no logo" is a state worth being able to see rather than blank space.
     */
    function paintLogo(box, value, alt) {
        box.innerHTML = "";
        var url = (value || "").trim();
        box.dataset.empty = url ? "false" : "true";
        if (!url) return;
        var img = document.createElement("img");
        img.alt = alt || "";
        // A URL that 404s must not leave an empty frame claiming a logo is set.
        img.addEventListener("error", function () {
            box.innerHTML = "";
            box.dataset.empty = "true";
        });
        img.src = url;
        box.appendChild(img);
    }

    var LOGO_MAX_BYTES = 256 * 1024;

    /**
     * Wires up one logo field: text box, live preview, upload and remove.
     *
     * Uploads are inlined as data URIs rather than written to disk, so a logo needs no upload
     * directory, no static file route and no second thing to back up — at the cost of a size
     * limit, since the value travels in every page that renders it.
     */
    function bindLogoField(prefix) {
        var input = document.getElementById(prefix + "-client_logo");
        var preview = document.getElementById(prefix + "-logo-preview");
        var file = document.getElementById(prefix + "-logo-file");
        if (!input || !preview) return;

        function repaint() { paintLogo(preview, input.value, ""); }

        input.addEventListener("input", repaint);
        var pick = document.getElementById(prefix + "-logo-pick");
        if (pick) pick.addEventListener("click", function () { file.click(); });
        var clear = document.getElementById(prefix + "-logo-clear");
        if (clear) clear.addEventListener("click", function () {
            input.value = "";
            if (file) file.value = "";
            repaint();
        });
        if (file) file.addEventListener("change", function (e) {
            var chosen = e.target.files && e.target.files[0];
            if (!chosen) return;
            if (chosen.size > LOGO_MAX_BYTES) {
                toast("w", "that image is larger than 256 KB - host it and paste the URL instead", 5000);
                file.value = "";
                return;
            }
            var reader = new FileReader();
            reader.onload = function (ev) {
                input.value = ev.target.result;
                repaint();
            };
            reader.readAsDataURL(chosen);
        });
        repaint();
    }

    function el(html) {
        var t = document.createElement("template");
        t.innerHTML = html.trim();
        return t.content.firstElementChild;
    }

    function lines(value) {
        return (value || "").split("\n").map(function (s) { return s.trim(); }).filter(Boolean);
    }

    /**
     * Whether a login identifier is an email address rather than a plain username.
     * Only used to decide whether a mailbox exists to send to — the server is what validates.
     */
    function isEmailAddress(value) {
        return /^[^@\s]+@[^@\s.]+\.[^@\s]+$/.test(value || "");
    }

    /** Writes a JSON-list property in both the shapes the entity exposes. */
    function setList(target, field, values) {
        target[field] = values;
        target[field + "_"] = JSON.stringify(values);
    }

    function listOf(record, field) {
        var v = record ? record[field] : null;
        if (Array.isArray(v)) return v;
        var raw = record ? record[field + "_"] : null;
        if (!raw) return [];
        try { return JSON.parse(raw) || []; } catch (e) { return []; }
    }

    function checkboxes(container, options, selected) {
        container.innerHTML = "";
        var chosen = selected || [];
        options.forEach(function (opt) {
            var id = container.id + "-" + opt.replace(/[^a-z0-9]+/gi, "_");
            var row = el('<div class="ark-check"><input type="checkbox" id="' + id + '" /><label for="' + id + '"></label></div>');
            var input = row.querySelector("input");
            input.value = opt;
            input.checked = chosen.indexOf(opt) > -1;
            row.querySelector("label").textContent = opt;
            container.appendChild(row);
        });
    }

    function checkedValues(container) {
        return Array.prototype.slice
            .call(container.querySelectorAll("input[type=checkbox]:checked"))
            .map(function (i) { return i.value; });
    }

    var GRANT_TYPES = [
        "authorization_code",
        "refresh_token",
        "client_credentials",
        "urn:ietf:params:oauth:grant-type:device_code"
    ];
    var RESPONSE_TYPES = ["code"];

    // ------------------------------------------------------------------ state

    var state = { tenants: [], clients: [], users: [], claims: [], scopes: [] };
    var tables = {};

    function tenantOptions() {
        return state.tenants.reduce(function (acc, t) {
            acc[t.tenant_id] = t.name || t.tenant_id;
            return acc;
        }, {});
    }

    // ---------------------------------------------------------------- tenants

    /**
     * `applies` is optional: when given, the button is only drawn for rows it accepts, so an
     * action that cannot succeed for a row is not offered on that row at all.
     */
    function actionColumn(label, cls, handler, width, applies) {
        return {
            title: "",
            field: "__" + label.toLowerCase().replace(/\W+/g, "_"),
            width: width || 80,
            hozAlign: "center",
            headerSort: false,
            formatter: function (cell) {
                if (applies && !applies(cell.getRow().getData())) return "";
                return '<button type="button" class="' + (cls || "") + '">' + label + "</button>";
            },
            cellClick: function (e, cell) {
                if (applies && !applies(cell.getRow().getData())) return;
                handler(cell);
            }
        };
    }

    function loadTenants() {
        return getJson(API + "/tenant/list").then(function (res) {
            state.tenants = res.data || [];

            if (byId("tbl_tenant") && !tables.tenant) {
                tables.tenant = new Tabulator("#tbl_tenant", {
                    data: state.tenants,
                    layout: "fitColumns",
                    columns: [
                        { title: "tenant_id", field: "tenant_id", editor: "input", widthGrow: 2 },
                        { title: "name", field: "name", editor: "input", widthGrow: 2 },
                        { title: "display", field: "display", editor: "input", widthGrow: 2 },
                        { title: "issuer (v1)", field: "issuer", editor: "input", widthGrow: 3 },
                        { title: "audience (v1)", field: "audience", editor: "input", widthGrow: 3 },
                        { title: "expire_mins", field: "expire_mins", editor: "number", width: 110 },
                        {
                            title: "key", field: "rsa_public", width: 80, hozAlign: "center", headerSort: false,
                            // The key itself is deliberately not rendered or editable. Rotation is a
                            // two-phase operation against the signing_keys table, not a text edit.
                            formatter: function (cell) {
                                return cell.getValue()
                                    ? '<span class="ark-badge ark-badge-ok">present</span>'
                                    : '<span class="ark-badge ark-badge-warn">on save</span>';
                            }
                        },
                        actionColumn("Save", "", function (cell) {
                            var row = Object.assign({}, cell.getRow().getData());
                            // Never send the key material back. The server keeps the stored pair
                            // when it is absent, and mints one for a tenant that has none.
                            delete row.rsa_private;
                            delete row.rsa_public;
                            save(API + "/tenant/upsert", row, "tenant saved").then(loadTenants).catch(function () { });
                        }),
                        {
                            title: "", width: 90, hozAlign: "center", headerSort: false,
                            formatter: function (cell) {
                                var d = cell.getRow().getData();
                                if (!d.tenant_id) return "";
                                return '<a href="' + APP_ROOT + "/" + encodeURIComponent(d.tenant_id) +
                                    '/.well-known/openid-configuration" target="_blank" rel="noopener">discovery</a>';
                            }
                        }
                    ]
                });
            } else if (tables.tenant) {
                tables.tenant.setData(state.tenants);
            }

            var options = state.tenants.map(function (t) {
                return { value: t.tenant_id, label: t.name || t.tenant_id };
            });
            fillSelect("sel-tenant", options, TENANT_ID, "Select tenant");   // access mapping
            fillSelect("pv-tenant_id", options, TENANT_ID);                  // provisioning
            fillSelect("av-tenant_id", options, TENANT_ID);                  // activation
        });
    }

    // ----------------------------------------------------------------- scopes

    function loadScopes() {
        return getJson(API + "/scope/list").then(function (res) {
            state.scopes = res.data || [];

            if (byId("tbl_scope") && !tables.scope) {
                tables.scope = new Tabulator("#tbl_scope", {
                    data: state.scopes,
                    layout: "fitColumns",
                    columns: [
                        { title: "name", field: "name", editor: "input", widthGrow: 2 },
                        { title: "display", field: "display", editor: "input", widthGrow: 2 },
                        { title: "description", field: "description", editor: "input", widthGrow: 3 },
                        {
                            // Edited as a comma separated list; normalised back to an array on save,
                            // so the cell holds a string between the edit and the save.
                            title: "claims unlocked", field: "claims", editor: "input", widthGrow: 3,
                            formatter: function (cell) {
                                var v = cell.getValue();
                                return Array.isArray(v) ? v.join(", ") : (v || "");
                            }
                        },
                        { title: "default", field: "is_default", editor: "tickCross", formatter: "tickCross", width: 90 },
                        { title: "consent", field: "require_consent", editor: "tickCross", formatter: "tickCross", width: 90 },
                        { title: "protocol", field: "is_protocol", formatter: "tickCross", width: 90 },
                        actionColumn("Save", "", function (cell) {
                            var row = Object.assign({}, cell.getRow().getData());
                            var claims = row.claims;
                            if (!Array.isArray(claims)) {
                                claims = (claims || "").split(",").map(function (s) { return s.trim(); }).filter(Boolean);
                            }
                            setList(row, "claims", claims);
                            save(API + "/scope/upsert", row, "scope saved")
                                .then(loadScopes).then(refreshScopePickers).catch(function () { });
                        }),
                        actionColumn("Delete", "ark-btn-danger", function (cell) {
                            var row = cell.getRow().getData();
                            if (!row.name) { cell.getRow().delete(); return; }
                            if (!confirm("Delete scope '" + row.name + "'?")) return;
                            save(API + "/scope/delete", row, "scope deleted")
                                .then(loadScopes).then(refreshScopePickers).catch(function () { });
                        })
                    ]
                });
            } else if (tables.scope) {
                tables.scope.setData(state.scopes);
            }
        });
    }

    function refreshScopePickers() {
        var box = byId("cl-scopes");
        if (box && box.dataset.clientOpen === "true") {
            var selected = checkedValues(box);
            checkboxes(box, state.scopes.map(function (s) { return s.name; }), selected);
        }
    }

    // ---------------------------------------------------------------- clients

    function loadClients() {
        return getJson(API + "/client/list").then(function (res) {
            state.clients = res.data || [];

            if (byId("tbl_client") && !tables.client) {
                tables.client = new Tabulator("#tbl_client", {
                    data: state.clients,
                    layout: "fitColumns",
                    columns: [
                        {
                            title: "", field: "client_logo", width: 54, hozAlign: "center", headerSort: false,
                            formatter: function (cell) {
                                var box = document.createElement("span");
                                box.className = "ark-logo-cell";
                                paintLogo(box, cell.getValue(), "");
                                return box;
                            }
                        },
                        { title: "tenant", field: "tenant_id", widthGrow: 1 },
                        { title: "client_id", field: "client_id", widthGrow: 2 },
                        {
                            title: "name", field: "client_name", widthGrow: 2,
                            formatter: function (cell) {
                                var d = cell.getRow().getData();
                                return d.client_name || d.display || d.name || "";
                            }
                        },
                        { title: "type", field: "application_type", width: 90 },
                        {
                            title: "auth", field: "token_endpoint_auth_method", width: 165,
                            formatter: function (cell) {
                                var v = cell.getValue() || "";
                                var cls = v === "none" ? "ark-badge-warn" : "ark-badge-off";
                                return '<span class="ark-badge ' + cls + '">' + (v === "none" ? "public" : v) + "</span>";
                            }
                        },
                        {
                            title: "active", field: "is_active", width: 80, hozAlign: "center",
                            formatter: function (cell) {
                                return cell.getValue()
                                    ? '<span class="ark-badge ark-badge-ok">yes</span>'
                                    : '<span class="ark-badge ark-badge-off">no</span>';
                            }
                        },
                        actionColumn("Edit", "", function (cell) { openClient(cell.getRow().getData()); }),
                        {
                            title: "", width: 90, hozAlign: "center", headerSort: false,
                            formatter: function (cell) {
                                var d = cell.getRow().getData();
                                if (!d.client_id || !d.tenant_id) return "";
                                return '<a href="' + integrateUrl(d) + '" target="_blank" rel="noopener">setup</a>';
                            }
                        }
                    ]
                });
            } else if (tables.client) {
                tables.client.setData(state.clients);
            }
            renderActivation();
            renderActivationTargets();
        });
    }

    function integrateUrl(client) {
        return APP_ROOT + "/" + encodeURIComponent(client.tenant_id) +
            "/oauth2/integrate/" + encodeURIComponent(client.client_id);
    }

    // ------------------------------------------------------------ client form

    // Only on the console page; the provisioning page has no client editor.
    var drawer = byId("client-drawer");
    var backdrop = byId("client-drawer-backdrop");
    var editing = null;

    function field(id) { return byId("cl-" + id); }

    var TEXT_FIELDS = [
        "client_id", "client_name", "display", "name", "domain", "client_logo",
        "client_uri", "policy_uri", "tos_uri", "jwks_uri", "backchannel_logout_uri",
        "redirect_url", "logout_url", "redirect_relative"
    ];
    var NUMBER_FIELDS = [
        "access_token_lifetime_seconds", "id_token_lifetime_seconds",
        "refresh_token_lifetime_seconds", "authorization_code_lifetime_seconds", "expire_mins"
    ];
    var FLAG_FIELDS = ["is_active", "require_pkce", "require_par", "require_consent", "refresh_token_rotation",
        "backchannel_logout_session_required"];

    function openClient(client) {
        editing = client ? Object.assign({}, client) : {
            application_type: "web",
            token_endpoint_auth_method: "client_secret_basic",
            is_active: true,
            require_pkce: true,
            refresh_token_rotation: true,
            backchannel_logout_session_required: true,
            access_token_lifetime_seconds: 3600,
            id_token_lifetime_seconds: 3600,
            refresh_token_lifetime_seconds: 1209600,
            authorization_code_lifetime_seconds: 60,
            expire_mins: 480,
            tenant_id: TENANT_ID
        };

        document.getElementById("client-drawer-title").textContent =
            editing.id ? (editing.client_id || "Client") : "New client";

        var tenantSelect = field("tenant_id");
        tenantSelect.innerHTML = "";
        state.tenants.forEach(function (t) { tenantSelect.add(new Option(t.name || t.tenant_id, t.tenant_id)); });
        tenantSelect.value = editing.tenant_id || TENANT_ID;

        TEXT_FIELDS.forEach(function (f) { field(f).value = editing[f] || ""; });
        paintLogo(document.getElementById("cl-logo-preview"), editing.client_logo, "");
        NUMBER_FIELDS.forEach(function (f) { field(f).value = editing[f] != null ? editing[f] : ""; });
        FLAG_FIELDS.forEach(function (f) { field(f).checked = !!editing[f]; });
        field("application_type").value = editing.application_type || "web";
        field("token_endpoint_auth_method").value = editing.token_endpoint_auth_method || "client_secret_basic";

        field("redirect_uris").value = listOf(editing, "redirect_uris").join("\n");
        field("post_logout_redirect_uris").value = listOf(editing, "post_logout_redirect_uris").join("\n");
        field("contacts").value = listOf(editing, "contacts").join("\n");

        var grants = listOf(editing, "grant_types");
        checkboxes(field("grant_types"), GRANT_TYPES, grants.length ? grants : ["authorization_code", "refresh_token"]);
        var responses = listOf(editing, "response_types");
        checkboxes(field("response_types"), RESPONSE_TYPES, responses.length ? responses : ["code"]);
        var scopes = listOf(editing, "scopes");
        var box = field("scopes");
        box.dataset.clientOpen = "true";
        checkboxes(box, state.scopes.map(function (s) { return s.name; }),
            scopes.length ? scopes : ["openid", "profile", "email", "offline_access"]);

        document.getElementById("cl-secret-state").textContent = editing.client_secret_hash
            ? "A secret is set. Regenerating replaces it immediately."
            : "No secret set.";
        var out = document.getElementById("cl-secret-value");
        out.hidden = true;
        out.innerHTML = "";
        document.getElementById("cl-secret-reset").disabled = !editing.id;
        document.getElementById("client-delete").disabled = !editing.id;
        document.getElementById("client-integrate").disabled = !editing.id;

        drawer.dataset.open = "true";
        backdrop.dataset.open = "true";
    }

    function closeClient() {
        drawer.dataset.open = "false";
        backdrop.dataset.open = "false";
        field("scopes").dataset.clientOpen = "false";
        editing = null;
    }

    function readClientForm() {
        var out = Object.assign({}, editing);
        out.tenant_id = field("tenant_id").value;
        TEXT_FIELDS.forEach(function (f) { out[f] = field(f).value.trim() || null; });
        NUMBER_FIELDS.forEach(function (f) {
            var raw = field(f).value;
            if (raw !== "") out[f] = parseInt(raw, 10);
        });
        FLAG_FIELDS.forEach(function (f) { out[f] = field(f).checked; });
        out.application_type = field("application_type").value;
        out.token_endpoint_auth_method = field("token_endpoint_auth_method").value;

        setList(out, "redirect_uris", lines(field("redirect_uris").value));
        setList(out, "post_logout_redirect_uris", lines(field("post_logout_redirect_uris").value));
        setList(out, "contacts", lines(field("contacts").value));
        setList(out, "grant_types", checkedValues(field("grant_types")));
        setList(out, "response_types", checkedValues(field("response_types")));
        setList(out, "scopes", checkedValues(field("scopes")));

        // Navigation properties are not part of the payload; sending a populated `tenant`
        // makes the change tracker try to insert the tenant again.
        delete out.tenant;
        return out;
    }

    on("client-add", "click", function () { openClient(null); });
    on("client-drawer-close", "click", closeClient);
    if (backdrop) backdrop.addEventListener("click", closeClient);
    document.addEventListener("keydown", function (e) {
        if (e.key === "Escape" && drawer && drawer.dataset.open === "true") closeClient();
    });

    on("client-save", "click", function () {
        var payload = readClientForm();
        if (!payload.client_id) { toast("w", "client_id is required", 4000); return; }
        if (!payload.tenant_id) { toast("w", "a tenant is required", 4000); return; }
        save(API + "/client/upsert", payload, "client saved").then(function (res) {
            editing = res.data || payload;
            return loadClients();
        }).then(function () {
            // Pick the saved record back up so the drawer holds the server's id.
            var match = state.clients.filter(function (c) {
                return c.tenant_id === payload.tenant_id && c.client_id === payload.client_id;
            })[0];
            if (match) openClient(match);
        }).catch(function () { });
    });

    on("client-delete", "click", function () {
        if (!editing || !editing.id) return;
        if (!confirm("Delete client '" + editing.client_id + "'? Applications using it will stop being able to sign in.")) return;
        save(API + "/client/delete", { id: editing.id, client_id: editing.client_id, tenant_id: editing.tenant_id }, "client deleted")
            .then(function () { closeClient(); return loadClients(); })
            .catch(function () { });
    });

    on("client-integrate", "click", function () {
        if (!editing || !editing.client_id) return;
        window.open(integrateUrl(editing), "_blank", "noopener");
    });

    on("cl-secret-reset", "click", function () {
        if (!editing || !editing.client_id) return;
        if (!confirm("Regenerate the secret for '" + editing.client_id + "'? The current one stops working immediately.")) return;
        save(API + "/client/secret/reset", { client_id: editing.client_id, tenant_id: editing.tenant_id })
            .then(function (res) {
                var out = document.getElementById("cl-secret-value");
                out.hidden = false;
                out.innerHTML = "";
                out.appendChild(el('<div class="ark-field"><label>client_secret (shown once)</label></div>'));
                var input = document.createElement("input");
                input.type = "text";
                input.readOnly = true;
                input.value = res.data.client_secret;
                input.addEventListener("focus", function () { input.select(); });
                out.appendChild(input);
                document.getElementById("cl-secret-state").textContent = "A secret is set. Regenerating replaces it immediately.";
                return loadClients();
            })
            .catch(function () { });
    });

    bindLogoField("cl");

    // ------------------------------------------------------------------ users

    function loadUsers() {
        return getJson(API + "/user/list").then(function (res) {
            state.users = res.data || [];

            if (byId("tbl_user") && !tables.user) {
                tables.user = new Tabulator("#tbl_user", {
                    data: state.users,
                    layout: "fitColumns",
                    columns: [
                        // The login identifier. It is stored in `email`, but it does not have to
                        // be an address — `admin` and the service accounts are usernames.
                        { title: "username / email", field: "email", editor: "input", widthGrow: 3 },
                        { title: "name", field: "name", editor: "input", widthGrow: 2 },
                        {
                            title: "type", field: "type", editor: "list", width: 110,
                            editorParams: { values: ["user", "service"] }
                        },
                        {
                            // Read-only here on purpose. Deactivating has to revoke the account's
                            // sessions and refresh tokens as well, or a signed-in browser carries
                            // on working — so it is done from the Activation panel, which calls
                            // the endpoint that does both.
                            title: "active", field: "is_active", width: 80, hozAlign: "center",
                            formatter: function (cell) {
                                return cell.getValue() === false
                                    ? '<span class="ark-badge ark-badge-warn">no</span>'
                                    : '<span class="ark-badge ark-badge-ok">yes</span>';
                            }
                        },
                        { title: "reset_mode", field: "reset_mode", editor: "tickCross", formatter: "tickCross", width: 110 },
                        { title: "emailed", field: "emailed", formatter: "tickCross", width: 95 },
                        { title: "ref_uid", field: "ref_uid", widthGrow: 2 },
                        { title: "at", field: "at", width: 165 },
                        actionColumn("Save", "", function (cell) {
                            var row = cell.getRow().getData();
                            if (!row.email) { toast("w", "a username or email is required", 4000); return; }
                            save(API + "/user/upsert", row, "user saved").then(loadUsers).catch(function () { });
                        }),
                        // A reset link needs a mailbox, so this only applies to accounts whose
                        // login id is an address. The server refuses the rest with a message; not
                        // drawing the button avoids inviting the error in the first place.
                        actionColumn("Reset password", "", function (cell) {
                            var row = cell.getRow().getData();
                            save(API + "/user/pw/reset/init", row).then(loadUsers).catch(function () { });
                        }, 150, function (row) { return isEmailAddress(row.email); })
                    ]
                });
            } else if (tables.user) {
                tables.user.setData(state.users);
            }

            var options = state.users.map(function (u) {
                return { value: u.email, label: u.name ? u.name + " — " + u.email : u.email };
            });
            fillSelect("sel-user", options, "", "Select user");
            fillSelect("av-user_name", options, "", "Select an account");
            renderActivation();
        });
    }

    // ----------------------------------------------------------------- claims

    function loadClaims() {
        return getJson(API + "/claim/list").then(function (res) {
            state.claims = res.data || [];
            renderClaims();
        });
    }

    function renderClaims() {
        var host = byId("claim-list");
        if (!host) return;
        host.innerHTML = "";
        state.claims.forEach(function (claim) {
            var tag = el('<span class="tag" draggable="true"><span></span><button type="button" title="Delete claim">&times;</button></span>');
            tag.querySelector("span").textContent = claim.key;
            tag.addEventListener("dragstart", function (e) {
                e.dataTransfer.setData("text/plain", claim.key);
                e.dataTransfer.effectAllowed = "copy";
            });
            tag.querySelector("button").addEventListener("click", function () {
                if (!confirm("Delete claim '" + claim.key + "' from the catalogue?")) return;
                save(API + "/claim/delete", claim, "claim deleted").then(loadClaims).catch(function () { });
            });
            host.appendChild(tag);
        });
    }

    on("claim-new", "keypress", function (e) {
        if (e.key !== "Enter") return;
        var value = e.target.value.trim();
        if (!value) return;
        if (state.claims.some(function (c) { return c.key === value; })) {
            toast("w", "'" + value + "' is already in the catalogue", 3000);
            return;
        }
        save(API + "/claim/upsert", { key: value, display: value }, "claim added")
            .then(function () { e.target.value = ""; return loadClaims(); })
            .catch(function () { });
    });

    // ---------------------------------------------------------- access mapping

    function clientOptionsFor(tenantId) {
        // ArkUserClientClaim.client_id holds the client's surrogate id, not its client_id
        // string — that is what the token endpoint joins on when it resolves ark_claims.
        return state.clients
            .filter(function (c) { return c.tenant_id === tenantId; })
            .reduce(function (acc, c) {
                acc[c.id] = (c.client_name || c.display || c.client_id) + " (" + c.client_id + ")";
                return acc;
            }, {});
    }

    function claimsCell(cell) {
        var row = cell.getRow();
        var values = cell.getValue() || [];
        var box = el('<div class="ark-drop-cell"></div>');

        function redraw() {
            box.innerHTML = "";
            if (!values.length) box.appendChild(el('<span class="ark-drop-empty">drop claims here</span>'));
            values.forEach(function (claim, index) {
                var tag = el('<span class="tag"><span></span><button type="button">&times;</button></span>');
                tag.querySelector("span").textContent = claim;
                tag.querySelector("button").addEventListener("click", function () {
                    values.splice(index, 1);
                    row.update({ claims: values });
                    redraw();
                });
                box.appendChild(tag);
            });
        }

        box.addEventListener("dragover", function (e) { e.preventDefault(); box.classList.add("ark-drop-over"); });
        box.addEventListener("dragleave", function () { box.classList.remove("ark-drop-over"); });
        box.addEventListener("drop", function (e) {
            e.preventDefault();
            box.classList.remove("ark-drop-over");
            var claim = e.dataTransfer.getData("text/plain");
            if (!claim || values.indexOf(claim) > -1) return;
            values.push(claim);
            row.update({ claims: values });
            redraw();
        });

        redraw();
        return box;
    }

    function loadMapping() {
        if (!byId("tbl_mapping")) return Promise.resolve();
        var email = byId("sel-user").value;
        var tenantId = byId("sel-tenant").value;

        var build = function (data) {
            if (tables.mapping) {
                tables.mapping.setData(data);
                return;
            }
            tables.mapping = new Tabulator("#tbl_mapping", {
                data: data,
                height: "320px",
                layout: "fitColumns",
                columns: [
                    { title: "email", field: "email", widthGrow: 2 },
                    { title: "tenant", field: "tenant_id", widthGrow: 1 },
                    {
                        title: "client", field: "client_id", editor: "list", widthGrow: 2,
                        editorParams: function () {
                            return { values: clientOptionsFor(byId("sel-tenant").value) };
                        },
                        formatter: function (cell) {
                            var options = clientOptionsFor(cell.getRow().getData().tenant_id);
                            return options[cell.getValue()] || cell.getValue() || "";
                        }
                    },
                    { title: "claims", field: "claims", widthGrow: 3, formatter: claimsCell },
                    actionColumn("Save", "", function (cell) {
                        var row = Object.assign({}, cell.getRow().getData());
                        if (!row.client_id) { toast("w", "pick a client first", 4000); return; }
                        setList(row, "claims", row.claims || []);
                        delete row.client;
                        delete row.tenant;
                        save(API + "/user/client/claims/upsert", row, "mapping saved")
                            .then(loadMapping).catch(function () { });
                    }),
                    actionColumn("Delete", "ark-btn-danger", function (cell) {
                        var row = cell.getRow().getData();
                        if (!row.id) { cell.getRow().delete(); return; }
                        save(API + "/user/client/claims/delete", row, "mapping deleted")
                            .then(function () { cell.getRow().delete(); }).catch(function () { });
                    }),
                    {
                        title: "", width: 165, hozAlign: "center", headerSort: false,
                        // Service accounts hold their long-lived token in place of a password;
                        // this reissues it.
                        formatter: function (cell) {
                            var row = cell.getRow().getData();
                            var isService = (row.claims || []).indexOf("service_role") > -1;
                            return isService ? '<button type="button" class="ark-btn-ghost">Regenerate token</button>' : "";
                        },
                        cellClick: function (e, cell) {
                            var row = cell.getRow().getData();
                            if ((row.claims || []).indexOf("service_role") < 0) return;
                            save(API + "/service/pw/reset", row).catch(function () { });
                        }
                    }
                ]
            });
        };

        if (!email || !tenantId) { build([]); return Promise.resolve(); }
        return getJson(API + "/user/list/client/claims/mapping/" +
            encodeURIComponent(email) + "/" + encodeURIComponent(tenantId))
            .then(function (res) { build(res.data || []); });
    }

    on("sel-user", "change", loadMapping);
    on("sel-tenant", "change", loadMapping);

    on("mapping-add", "click", function () {
        var email = byId("sel-user").value;
        var tenantId = byId("sel-tenant").value;
        if (!email || !tenantId) {
            toast("w", "select both a user and a tenant before adding a mapping", 4000);
            return;
        }
        if (!tables.mapping) { loadMapping().then(function () { tables.mapping.addRow({ email: email, tenant_id: tenantId, claims: [] }); }); return; }
        tables.mapping.addRow({ email: email, tenant_id: tenantId, claims: [] });
    });

    // ------------------------------------------------------------ provisioning

    /**
     * The provisioning panel.
     *
     * Registering an application is four operations in a fixed order — client, redirect URIs,
     * account, access mapping — and the mapping is the one that gets forgotten, because its
     * absence shows up on the sign-in page as "that username and password combination was not
     * recognised" rather than as anything about a missing mapping. This posts all four to
     * /provision/client as one call, and reports back which of them it actually had to do.
     */
    var provisionIdEdited = false;

    /** Mirrors ArkProvisioning.Slug on the server, so the box shows what will actually be used. */
    function slug(value) {
        return (value || "").trim().toLowerCase()
            .replace(/[^a-z0-9._-]+/g, "_")
            .replace(/^[_.\-]+|[_.\-]+$/g, "");
    }

    on("pv-client_id", "input", function (e) {
        // Once it has been typed in by hand, stop overwriting it.
        provisionIdEdited = e.target.value.trim().length > 0;
    });
    on("pv-client_name", "input", function (e) {
        if (provisionIdEdited) return;
        byId("pv-client_id").value = slug(e.target.value);
    });

    /**
     * The provisioning request as the API would receive it, or null when the form does not yet
     * describe one it would accept.
     *
     * Shared with the curl preview on purpose: the command shown has to be the same call this
     * page makes, down to the defaults, or it is documentation of something else.
     */
    function provisionPayload() {
        if (!byId("pv-client_name")) return null;
        var clientName = byId("pv-client_name").value.trim();
        var userName = byId("pv-user_name").value.trim();
        if (!clientName || !userName) return null;

        return {
            tenant_id: byId("pv-tenant_id").value || TENANT_ID,
            client_name: clientName,
            client_id: byId("pv-client_id").value.trim() || null,
            client_logo: byId("pv-client_logo").value.trim() || null,
            application_type: byId("pv-application_type").value,
            redirect_uris: lines(byId("pv-redirect_uris").value),
            user_name: userName,
            user_display_name: byId("pv-user_display_name").value.trim() || null,
            claims: (byId("pv-claims").value || "")
                .split(",").map(function (c) { return c.trim(); }).filter(Boolean),
            send_activation_email: byId("pv-send_activation_email").checked
        };
    }

    function provisionResult(kind, heading, facts, links) {
        var host = byId("pv-result");
        if (!host) return;
        host.innerHTML = "";
        var title = document.createElement("h4");
        title.textContent = "Result";
        host.appendChild(title);

        var alert = el('<div class="ark-toast ark-toast-' + kind + '" style="margin-bottom:12px"></div>');
        alert.textContent = heading;
        host.appendChild(alert);

        if (facts && facts.length) {
            var list = el("<ul></ul>");
            facts.forEach(function (line) {
                var li = document.createElement("li");
                var text = document.createElement("span");
                text.textContent = line;
                li.appendChild(text);
                list.appendChild(li);
            });
            host.appendChild(list);
        }
        if (links && links.length) {
            var box = el('<div class="ark-result-links"></div>');
            links.forEach(function (link) {
                var a = document.createElement("a");
                a.className = "ark-btn ark-btn-ghost ark-btn-sm";
                a.href = link.href;
                a.target = "_blank";
                a.rel = "noopener";
                a.textContent = link.label;
                box.appendChild(a);
            });
            host.appendChild(box);
        }
    }

    on("pv-submit", "click", function () {
        var button = this;
        if (!byId("pv-client_name").value.trim()) { toast("w", "an application name is required", 4000); return; }
        if (!byId("pv-user_name").value.trim()) { toast("w", "a user name or email is required", 4000); return; }

        var payload = provisionPayload();

        button.disabled = true;
        save(API + "/provision/client", payload).then(function (res) {
            var d = res.data || {};
            var facts = [
                "Client " + d.client_id + " registered in tenant " + d.tenant_id + ".",
                d.user_created
                    ? (d.user_credential === "activation_email"
                        ? "Account " + d.user_name + " created; an activation link has been emailed."
                        : "Account " + d.user_name + " created on the configured default password.")
                    : "Existing account " + d.user_name + " reused.",
                d.mapping_created
                    ? "Access mapping added with: " + (d.claims || []).join(", ") + "."
                    : "That account was already mapped to this client; its claims were updated.",
                (d.redirect_uris || []).length
                    ? "Redirect URIs: " + d.redirect_uris.join(", ")
                    : "No redirect URI registered yet - add one before the first sign-in."
            ];
            provisionResult("s", res.msg, facts, [
                { label: "Setup page", href: d.setup_url },
                { label: "Discovery", href: d.discovery }
            ]);
            provisionIdEdited = false;
            byId("pv-client_name").value = "";
            byId("pv-client_id").value = "";
            byId("pv-redirect_uris").value = "";
            byId("pv-client_logo").value = "";
            paintLogo(byId("pv-logo-preview"), "", "");
            renderCurl();
            return loadClients().then(loadUsers).then(loadClaims);
        }).catch(function (err) {
            // The refusals worth acting on carry a code; anything else is reported as it came.
            var code = (err.payload && err.payload.code) || "";
            var hint = code === "client_exists"
                ? "Nothing was created. Pick a different name, or add the user to the existing client from the Access mapping panel."
                : code === "unknown_tenant"
                    ? "Create the tenant first, in the Tenants panel above."
                    : "";
            provisionResult("f", err.message, hint ? [hint] : null, null);
        }).then(function () { button.disabled = false; },
                function () { button.disabled = false; });
    });

    bindLogoField("pv");

    // -------------------------------------------------------------- activation

    /**
     * The activation panel: both switches side by side.
     *
     * "Why can this person not sign in" is one question with two possible answers — the account
     * is off, or the application is — and chasing it across two grids is how the wrong one gets
     * flipped. Deactivating goes through /activation/{client|user} rather than a plain upsert
     * because those endpoints also revoke the sessions and refresh tokens already handed out;
     * without that the switch would not take effect until they aged out.
     */
    function activationRow(item) {
        var row = el('<div class="ark-activation-row"><div class="ark-activation-main">' +
            '<div class="ark-activation-name"></div><div class="ark-activation-sub"></div></div></div>');
        row.dataset.active = item.active ? "true" : "false";
        row.querySelector(".ark-activation-name").textContent = item.name;
        row.querySelector(".ark-activation-sub").textContent = item.sub;

        var badge = el('<span class="ark-badge"></span>');
        badge.className = "ark-badge " + (item.active ? "ark-badge-ok" : "ark-badge-warn");
        badge.textContent = item.active ? "active" : "deactivated";
        row.appendChild(badge);

        var button = document.createElement("button");
        button.type = "button";
        button.className = item.active ? "ark-btn-danger ark-btn-sm" : "ark-btn-sm";
        button.textContent = item.active ? "Deactivate" : "Activate";
        button.addEventListener("click", function () {
            if (item.active && !confirm(item.confirm)) return;
            button.disabled = true;
            save(item.url, item.payload(!item.active))
                .then(item.reload)
                .catch(function () { button.disabled = false; });
        });
        row.appendChild(button);
        return row;
    }

    function renderActivation() {
        var clientHost = byId("act-clients");
        var userHost = byId("act-users");
        if (!clientHost || !userHost) return;

        var filter = ((byId("act-filter") || {}).value || "").toLowerCase().trim();
        var matches = function (haystack) { return !filter || haystack.toLowerCase().indexOf(filter) > -1; };

        clientHost.innerHTML = "";
        var clients = state.clients.filter(function (c) {
            return matches((c.client_name || "") + " " + (c.display || "") + " " + c.client_id + " " + c.tenant_id);
        });
        if (!clients.length) {
            clientHost.appendChild(el('<div class="ark-empty">No applications match.</div>'));
        } else {
            clients.forEach(function (c) {
                clientHost.appendChild(activationRow({
                    name: c.client_name || c.display || c.client_id,
                    sub: c.client_id + " · " + c.tenant_id,
                    active: c.is_active !== false,
                    url: API + "/activation/client",
                    confirm: "Deactivate '" + (c.client_name || c.client_id) + "'?\n\n" +
                        "Sign-ins to it are refused with a message naming the application, and the " +
                        "refresh tokens it already holds are revoked.",
                    payload: function (active) {
                        return { tenant_id: c.tenant_id, client_id: c.client_id, is_active: active };
                    },
                    reload: loadClients
                }));
            });
        }

        userHost.innerHTML = "";
        var users = state.users.filter(function (u) {
            return matches((u.name || "") + " " + u.email + " " + (u.type || ""));
        });
        if (!users.length) {
            userHost.appendChild(el('<div class="ark-empty">No accounts match.</div>'));
        } else {
            users.forEach(function (u) {
                userHost.appendChild(activationRow({
                    name: u.name || u.email,
                    sub: u.email + (u.type && u.type !== "user" ? " · " + u.type : ""),
                    active: u.is_active !== false,
                    url: API + "/activation/user",
                    confirm: "Deactivate '" + u.email + "'?\n\n" +
                        "They are signed out everywhere, their refresh tokens are revoked, and the " +
                        "sign-in page tells them the account is deactivated.",
                    payload: function (active) { return { user_name: u.email, is_active: active }; },
                    reload: loadUsers
                }));
            });
        }
    }

    on("act-filter", "input", renderActivation);

    // ------------------------------------------------- activation, as a request

    /**
     * The activation panel's form: the endpoint's own body, as three fields.
     *
     * The two lists below it flip one row at a time and are the fastest way to answer "why can
     * this person not sign in". This is the same operation stated as a request — which is what
     * the curl block downstream turns into a command, and what an onboarding script would send.
     */
    function activationLevel() {
        return ((byId("av-target") || {}).value === "user") ? "user" : "client";
    }

    /** null until the form describes a request the endpoint would accept. */
    function activationRequest() {
        if (!byId("av-target")) return null;
        var level = activationLevel();
        var isActive = byId("av-is_active").value === "true";
        var reason = (byId("av-reason").value || "").trim();

        var body;
        if (level === "user") {
            var user = byId("av-user_name").value;
            if (!user) return null;
            body = { user_name: user, is_active: isActive };
        } else {
            var clientId = byId("av-client_id").value;
            if (!clientId) return null;
            body = {
                tenant_id: byId("av-tenant_id").value || TENANT_ID,
                client_id: clientId,
                is_active: isActive
            };
        }
        if (reason) body.reason = reason;

        return {
            level: level,
            path: "/activation/" + level,
            body: body,
            subject: level === "user" ? body.user_name : body.client_id
        };
    }

    /** Keeps the two target pickers in step with the tenant and with the loaded data. */
    function renderActivationTargets() {
        if (!byId("av-client_id")) return;
        var tenantId = byId("av-tenant_id").value || TENANT_ID;
        fillSelect("av-client_id", state.clients
            .filter(function (c) { return c.tenant_id === tenantId; })
            .map(function (c) {
                return {
                    value: c.client_id,
                    label: (c.client_name || c.display || c.client_id) +
                        (c.is_active === false ? " — deactivated" : "")
                };
            }), "", "Select an application");
    }

    // Only the level being switched is asked for. Both fields visible at once reads as though
    // one request could do both, which is two endpoints and two different revocations.
    function renderActivationLevel() {
        if (!byId("av-target")) return;
        var user = activationLevel() === "user";
        byId("av-user-field").hidden = !user;
        byId("av-client-field").hidden = user;
        byId("av-tenant-field").hidden = user;
    }

    on("av-target", "change", function () { renderActivationLevel(); renderCurl(); });
    on("av-tenant_id", "change", function () { renderActivationTargets(); renderCurl(); });
    renderActivationLevel();

    on("av-submit", "click", function () {
        var request = activationRequest();
        if (!request) {
            toast("w", "pick the application or the account to switch", 4000);
            return;
        }
        if (!request.body.is_active && !confirm(
            "Deactivate '" + request.subject + "'?\n\n" +
            (request.level === "user"
                ? "They are signed out everywhere, their refresh tokens are revoked, and the sign-in page tells them the account is deactivated."
                : "Sign-ins to it are refused with a message naming the application, and the refresh tokens it already holds are revoked."))) return;

        var button = this;
        button.disabled = true;
        save(API + request.path, request.body)
            .then(function () { return loadClients().then(loadUsers); })
            .catch(function () { })
            .then(function () { button.disabled = false; }, function () { button.disabled = false; });
    });

    // -------------------------------------------------------------- curl preview

    /**
     * The two requests above, as a command that can be pasted into a shell.
     *
     * It appears by itself as soon as either form holds a request the API would accept, and
     * carries the values that are in the forms at that moment — the point being that provisioning
     * is meant to be driven by another system, and the console is the only place that knows what
     * a valid body for this deployment looks like.
     *
     * The credential is the one thing it cannot read off the page. The console's own session is
     * an HttpOnly cookie — unreadable from script, deliberately — so the command authenticates
     * the way a script would instead: client_credentials against the machine client seeded beside
     * the console. That secret is stored only as a PBKDF2 hash, so the button that mints a new
     * one is the single moment its value can be put into the command; until then the placeholder
     * stays in, rather than the command looking complete and failing with invalid_client.
     */
    var TOKEN_ENDPOINT = root.dataset.tokenEndpoint || "";
    var API_ROOT = root.dataset.apiRoot || "";
    var MACHINE_HAS_SECRET = root.dataset.machineHasSecret === "true";
    var SECRET_PLACEHOLDER = "<client secret>";

    /** Single-quotes a value for a POSIX shell, including values that contain a quote. */
    function shellQuote(value) {
        return "'" + String(value == null ? "" : value).replace(/'/g, "'\\''") + "'";
    }

    function tokenCommand(step) {
        var clientId = (byId("cu-client_id").value || "").trim();
        var secret = (byId("cu-client_secret").value || "").trim() || SECRET_PLACEHOLDER;
        return [
            "# " + step + ". an access token for the management API",
            "TOKEN=$(curl -s -X POST " + TOKEN_ENDPOINT + " \\",
            "  -d 'grant_type=client_credentials' \\",
            "  -d " + shellQuote("client_id=" + clientId) + " \\",
            "  -d " + shellQuote("client_secret=" + secret) + " \\",
            "  | jq -r .access_token)"
        ].join("\n");
    }

    function postCommand(step, title, path, body) {
        return [
            "# " + step + ". " + title,
            "curl -s -X POST " + API_ROOT + path + " \\",
            '  -H "Authorization: Bearer $TOKEN" \\',
            "  -H 'Content-Type: application/json' \\",
            "  -d " + shellQuote(JSON.stringify(body, null, 2))
        ].join("\n");
    }

    function renderCurl() {
        var panel = byId("cu-panel");
        if (!panel) return;

        var provision = provisionPayload();
        var activation = activationRequest();
        if (!provision && !activation) {
            panel.hidden = true;
            return;
        }

        var step = 0;
        var blocks = [tokenCommand(++step)];
        if (provision) {
            blocks.push(postCommand(++step,
                "register '" + provision.client_name + "', create or reuse " + provision.user_name +
                ", and map the two together",
                "/provision/client", provision));
        }
        if (activation) {
            blocks.push(postCommand(++step,
                (activation.body.is_active ? "reactivate " : "deactivate ") + activation.subject,
                activation.path, activation.body));
        }

        byId("cu-out").textContent = blocks.join("\n\n");
        byId("cu-note").textContent = (byId("cu-client_secret").value || "").trim()
            ? "The secret above is in the command. It is not stored anywhere readable, so this page is the only place it exists — copy the command before leaving."
            : MACHINE_HAS_SECRET
                ? "The command carries a placeholder for the secret. Generate one above to have it filled in, or paste the value you kept."
                : "This client has no secret yet, so the token request will be refused until one is generated above.";
        panel.hidden = false;
    }

    on("cu-secret-reset", "click", function () {
        var clientId = (byId("cu-client_id").value || "").trim();
        if (!clientId) { toast("w", "name the client the script should authenticate as", 4000); return; }
        var known = state.clients.filter(function (c) { return c.client_id === clientId; })[0];
        if (!confirm("Generate a new secret for '" + clientId + "'?\n\nThe current one stops working immediately.")) return;

        save(API + "/client/secret/reset", {
            client_id: clientId,
            tenant_id: (known && known.tenant_id) || TENANT_ID
        }).then(function (res) {
            byId("cu-client_secret").value = (res.data || {}).client_secret || "";
            renderCurl();
        }).catch(function () { });
    });

    on("cu-copy", "click", function () {
        var text = byId("cu-out").textContent;
        if (!text) return;
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(
                function () { toast("s", "command copied", 2500); },
                function () { toast("f", "the browser refused clipboard access - select and copy it by hand", 5000); });
            return;
        }
        // No clipboard API without a secure context; selecting it is the next best thing.
        var range = document.createRange();
        range.selectNodeContents(byId("cu-out"));
        var selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
        toast("w", "this browser exposes no clipboard here - the command is selected, copy it", 5000);
    });

    // Every field on the page feeds one of the two requests, so the preview follows the whole
    // form rather than a list of ids that would have to be kept in step with the markup.
    if (byId("cu-panel")) {
        byId("cu-client_id").value = root.dataset.machineClient || "";
        root.addEventListener("input", renderCurl);
        root.addEventListener("change", renderCurl);
    }

    // -------------------------------------------------------------- new rows

    on("tenant-add", "click", function () {
        tables.tenant.addRow({ expire_mins: 480 });
    });
    on("user-add", "click", function () {
        tables.user.addRow({ type: "user" });
    });
    on("scope-add", "click", function () {
        tables.scope.addRow({ claims: [], require_consent: true, is_default: false, is_protocol: false });
    });

    // ----------------------------------------------------------------- start

    // Each page loads what it draws. The provisioning page needs the three lists its selects and
    // activation rows are built from, and none of the catalogue the console's editors use.
    var boot = PAGE === "provisioning"
        ? loadTenants().then(loadClients).then(loadUsers).then(renderCurl)
        : Promise.all([loadTenants(), loadScopes(), loadClaims()])
            .then(loadClients)
            .then(loadUsers)
            .then(loadMapping);

    boot.catch(function (err) {
        toast("f", "could not load the console: " + err.message, 8000);
    });
})();
