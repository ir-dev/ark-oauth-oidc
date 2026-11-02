/* ---------------------------------------------------------------------------
   Ark IdP appearance: themes and text size, chosen by whoever is looking.

   One script for every page the package draws — the sign-in pages
   (Views/Oidc/_ArkLayout.cshtml), the admin console (Views/Admin/*) and the
   setup wizard (wwwroot/setup/wizard.html). All three style themselves from the
   same --ark-* tokens, so a theme is nothing more than a set of values for
   those tokens, and text size is one multiplier (--ark-text-scale) that every
   font-size in those stylesheets is written against.

   Load it in <head>, synchronously. The saved choice is applied to <html>
   before the body is parsed, so a page never flashes the default theme first.
   The picker itself is built later, into every [data-ark-appearance] element.

   Constraints it is written to:

     * The wizard is served with script-src 'self' and style-src 'self'. Token
       values are set through CSSOM (style.setProperty), which CSP permits, and
       never through a style attribute or an injected <style> element, which it
       does not. The picker's own styling is in ark-theme.css.
     * Storage is per browser, per origin, and can be missing or throw (private
       windows, blocked site data). Every read and write is guarded, and with no
       storage the page simply shows its defaults. The choice is shared by every
       page on the IdP's origin, which is the point: pick once at sign-in and the
       console looks the same.
     * Nothing here is needed to sign in. If this file fails to load, the pages
       render exactly as they did before it existed.
   --------------------------------------------------------------------------- */
(function () {
    "use strict";

    var KEY = "ark-ui";
    var root = document.documentElement;

    // ------------------------------------------------------------------ palettes

    // Every token a theme sets. Radii are deliberately left alone: they are
    // layout, not colour, and the pages are tuned around them.
    var TOKENS = [
        "bg", "bg-accent", "surface", "surface-2", "fg", "fg-muted", "border", "border-strong",
        "accent", "accent-hover", "accent-fg", "accent-soft", "danger", "danger-soft",
        "success", "success-soft", "warn", "warn-soft", "shadow"
    ];

    // The stylesheets' own two palettes, verbatim, so "Light" and "Dark" mean
    // exactly what the OS-following default would have drawn.
    var LIGHT = {
        "bg": "#f4f6fb", "bg-accent": "#e8edf9", "surface": "#ffffff", "surface-2": "#f7f9fc",
        "fg": "#16192b", "fg-muted": "#5b6478", "border": "#dfe4ee", "border-strong": "#c6cddc",
        "accent": "#3457d5", "accent-hover": "#2b48b4", "accent-fg": "#ffffff", "accent-soft": "#eef2fe",
        "danger": "#c0362c", "danger-soft": "#fdecea", "success": "#1c7a4a", "success-soft": "#e7f6ee",
        "warn": "#8a5a00", "warn-soft": "#fdf3e2",
        "shadow": "0 1px 2px rgba(16,24,40,.04), 0 12px 32px -8px rgba(16,24,40,.12)"
    };
    var DARK = {
        "bg": "#0d1017", "bg-accent": "#131826", "surface": "#171c28", "surface-2": "#1e2432",
        "fg": "#e8ecf5", "fg-muted": "#99a3b8", "border": "#2a3244", "border-strong": "#3a445c",
        "accent": "#7b96ff", "accent-hover": "#93a9ff", "accent-fg": "#0d1017", "accent-soft": "#1b2440",
        "danger": "#ff8b80", "danger-soft": "#2c1a1a", "success": "#6ede9f", "success-soft": "#14271e",
        "warn": "#f3c56b", "warn-soft": "#2a2312",
        "shadow": "0 1px 2px rgba(0,0,0,.3), 0 16px 40px -12px rgba(0,0,0,.6)"
    };

    // The rest are derived from four seeds, the same way a custom theme is, so
    // a hand-picked theme and a user's own one are built by one rule.
    var THEMES = [
        { id: "system", name: "System", scheme: null },
        { id: "light", name: "Light", scheme: "light", tokens: LIGHT },
        { id: "dark", name: "Dark", scheme: "dark", tokens: DARK },
        { id: "midnight", name: "Midnight", seed: { dark: true, bg: "#0a0f1f", surface: "#111a2e", fg: "#e6ecff", accent: "#38bdf8" } },
        { id: "graphite", name: "Graphite", seed: { dark: true, bg: "#121214", surface: "#1c1c1f", fg: "#ececee", accent: "#a78bfa" } },
        { id: "forest", name: "Forest", seed: { dark: false, bg: "#eff5f1", surface: "#ffffff", fg: "#14231b", accent: "#1f7a52" } },
        { id: "rose", name: "Rose", seed: { dark: false, bg: "#fbf3f6", surface: "#ffffff", fg: "#2a1720", accent: "#c2185b" } },
        { id: "paper", name: "Paper", seed: { dark: false, bg: "#f3ebdc", surface: "#fbf6ec", fg: "#2e2618", accent: "#9a5b1e" } },
        {
            id: "contrast", name: "High contrast", scheme: "light", tokens: {
                "bg": "#ffffff", "bg-accent": "#ffffff", "surface": "#ffffff", "surface-2": "#ffffff",
                "fg": "#000000", "fg-muted": "#1f1f1f", "border": "#000000", "border-strong": "#000000",
                "accent": "#0030c0", "accent-hover": "#001c78", "accent-fg": "#ffffff", "accent-soft": "#e3e9ff",
                "danger": "#a00000", "danger-soft": "#ffe8e8", "success": "#005c26", "success-soft": "#e2f5e9",
                "warn": "#6b4200", "warn-soft": "#fff2d6", "shadow": "none"
            }
        },
        {
            id: "contrast-dark", name: "High contrast dark", scheme: "dark", tokens: {
                "bg": "#000000", "bg-accent": "#000000", "surface": "#000000", "surface-2": "#0a0a0a",
                "fg": "#ffffff", "fg-muted": "#e6e6e6", "border": "#ffffff", "border-strong": "#ffffff",
                "accent": "#ffd60a", "accent-hover": "#ffe55c", "accent-fg": "#000000", "accent-soft": "#2b2400",
                "danger": "#ff6b6b", "danger-soft": "#2a0000", "success": "#5cff9d", "success-soft": "#002a12",
                "warn": "#ffc04d", "warn-soft": "#2a1c00", "shadow": "none"
            }
        },
        { id: "custom", name: "Custom", custom: true }
    ];

    var CUSTOM_DEFAULT = { dark: false, accent: "#3457d5", bg: "#f4f6fb" };

    // Text size, as a multiplier on every font-size. The slider covers anything in between.
    var SIZES = [
        { value: 0.9, label: "A", hint: "Small" },
        { value: 1, label: "A", hint: "Default" },
        { value: 1.125, label: "A", hint: "Large" },
        { value: 1.25, label: "A", hint: "Larger" },
        { value: 1.4, label: "A", hint: "Largest" }
    ];
    var SCALE_MIN = 0.8, SCALE_MAX = 1.6;

    // ------------------------------------------------------------------ colour math

    function parse(hex) {
        var h = String(hex || "").replace("#", "");
        if (h.length === 3) h = h[0] + h[0] + h[1] + h[1] + h[2] + h[2];
        if (!/^[0-9a-f]{6}$/i.test(h)) return null;
        return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)];
    }

    function hex(rgb) {
        return "#" + rgb.map(function (c) {
            var v = Math.max(0, Math.min(255, Math.round(c)));
            return (v < 16 ? "0" : "") + v.toString(16);
        }).join("");
    }

    /** a, moved t of the way towards b. */
    function mix(a, b, t) {
        var x = parse(a), y = parse(b);
        return hex([0, 1, 2].map(function (i) { return x[i] + (y[i] - x[i]) * t; }));
    }

    function luminance(color) {
        var c = parse(color).map(function (v) {
            v /= 255;
            return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
        });
        return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
    }

    function contrast(a, b) {
        var x = luminance(a), y = luminance(b);
        return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
    }

    /**
     * A full token set from four seeds. Status colours come from the matching
     * built-in palette; everything else is mixed from the seeds, so any accent
     * and background a user picks still produce readable borders, muted text
     * and button labels.
     */
    function derive(seed) {
        var base = seed.dark ? DARK : LIGHT;
        var bg = seed.bg, surface = seed.surface, fg = seed.fg, accent = seed.accent;
        var tint = seed.dark ? 0.16 : 0.09;
        var t = {
            "bg": bg,
            "bg-accent": mix(bg, accent, seed.dark ? 0.1 : 0.08),
            "surface": surface,
            "surface-2": seed.dark ? mix(surface, fg, 0.05) : mix(surface, bg, 0.6),
            "fg": fg,
            "fg-muted": mix(fg, surface, seed.dark ? 0.36 : 0.4),
            "border": mix(surface, fg, seed.dark ? 0.15 : 0.11),
            "border-strong": mix(surface, fg, seed.dark ? 0.24 : 0.2),
            "accent": accent,
            "accent-hover": seed.dark ? mix(accent, "#ffffff", 0.16) : mix(accent, "#000000", 0.16),
            "accent-fg": contrast(accent, "#ffffff") >= contrast(accent, "#0d1017") ? "#ffffff" : "#0d1017",
            "accent-soft": mix(surface, accent, tint),
            "shadow": base.shadow
        };
        ["danger", "success", "warn"].forEach(function (k) {
            t[k] = base[k];
            t[k + "-soft"] = mix(surface, base[k], seed.dark ? 0.14 : 0.1);
        });
        return t;
    }

    /** The seeds behind a custom theme: surface and text follow from mode and background. */
    function customSeed(c) {
        var dark = !!c.dark;
        var bg = parse(c.bg) ? c.bg : (dark ? DARK.bg : LIGHT.bg);
        var accent = parse(c.accent) ? c.accent : CUSTOM_DEFAULT.accent;
        return {
            dark: dark,
            bg: bg,
            surface: dark ? mix(bg, "#ffffff", 0.06) : mix(bg, "#ffffff", 0.82),
            fg: dark ? mix("#eef1f8", bg, 0.04) : mix("#14172a", bg, 0.04),
            accent: accent
        };
    }

    // ------------------------------------------------------------------ state

    function load() {
        try {
            var v = JSON.parse(window.localStorage.getItem(KEY) || "{}");
            return v && typeof v === "object" ? v : {};
        } catch (e) {
            return {};
        }
    }

    function save(prefs) {
        try { window.localStorage.setItem(KEY, JSON.stringify(prefs)); } catch (e) { /* no storage: this page only */ }
    }

    function clampScale(v) {
        v = Number(v);
        if (!isFinite(v) || v <= 0) return 1;
        return Math.round(Math.max(SCALE_MIN, Math.min(SCALE_MAX, v)) * 1000) / 1000;
    }

    function themeById(id) {
        for (var i = 0; i < THEMES.length; i++) if (THEMES[i].id === id) return THEMES[i];
        return THEMES[0];
    }

    var systemDark = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

    /** The tokens and scheme a theme resolves to; null tokens means "leave the stylesheet's own". */
    function resolve(theme, prefs) {
        if (theme.custom) {
            var seed = customSeed(prefs.custom || CUSTOM_DEFAULT);
            return { scheme: seed.dark ? "dark" : "light", tokens: derive(seed) };
        }
        if (theme.seed) return { scheme: theme.seed.dark ? "dark" : "light", tokens: derive(theme.seed) };
        if (theme.tokens) return { scheme: theme.scheme, tokens: theme.tokens };
        return { scheme: systemDark && systemDark.matches ? "dark" : "light", tokens: null };
    }

    function apply(prefs) {
        var theme = themeById(prefs.theme);
        var r = resolve(theme, prefs);

        TOKENS.forEach(function (k) {
            if (r.tokens) root.style.setProperty("--ark-" + k, r.tokens[k]);
            else root.style.removeProperty("--ark-" + k);
        });
        // A forced theme forces the UA's own controls (scrollbars, date pickers) to
        // match; "System" hands that back to the stylesheet's "light dark".
        if (r.tokens) root.style.setProperty("color-scheme", r.scheme);
        else root.style.removeProperty("color-scheme");

        var scale = clampScale(prefs.scale);
        if (scale === 1) root.style.removeProperty("--ark-text-scale");
        else root.style.setProperty("--ark-text-scale", String(scale));

        // For the few rules that need to know which way the page is drawn (a
        // logo that needs a backing plate, say) rather than which theme it is.
        root.setAttribute("data-ark-theme", theme.id);
        root.setAttribute("data-ark-scheme", r.scheme);
    }

    var prefs = load();
    apply(prefs);

    if (systemDark) {
        var onSystem = function () { if (themeById(prefs.theme).id === "system") apply(prefs); };
        if (systemDark.addEventListener) systemDark.addEventListener("change", onSystem);
        else if (systemDark.addListener) systemDark.addListener(onSystem);
    }

    // Another tab on the same origin changed it: follow, so the console and a
    // sign-in tab do not disagree until one is reloaded.
    window.addEventListener("storage", function (e) {
        if (e.key !== KEY) return;
        prefs = load();
        apply(prefs);
        pickers.forEach(function (p) { p.sync(); });
    });

    function update(patch) {
        for (var k in patch) if (Object.prototype.hasOwnProperty.call(patch, k)) prefs[k] = patch[k];
        save(prefs);
        apply(prefs);
        pickers.forEach(function (p) { p.sync(); });
    }

    // ------------------------------------------------------------------ picker

    var pickers = [];
    var uid = 0;

    function el(tag, cls, text) {
        var e = document.createElement(tag);
        if (cls) e.className = cls;
        if (text != null) e.textContent = text;
        return e;
    }

    var ICON =
        '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">' +
        '<circle cx="8" cy="8" r="6.25" stroke="currentColor" stroke-width="1.5"/>' +
        '<path d="M8 1.75a6.25 6.25 0 0 1 0 12.5z" fill="currentColor"/></svg>';

    // "System" has no colours of its own; its swatch is drawn half light, half dark in CSS.
    function swatchColors(theme) {
        return theme.id === "system" ? null : resolve(theme, prefs).tokens;
    }

    function mount(host) {
        var n = ++uid;
        var wrap = el("div", "ark-ap");
        var btn = el("button", "ark-ap-btn");
        btn.type = "button";
        btn.setAttribute("aria-haspopup", "dialog");
        btn.setAttribute("aria-expanded", "false");
        btn.setAttribute("aria-controls", "ark-ap-panel-" + n);
        btn.title = "Appearance: theme and text size";
        // The visible label is dropped in narrow top bars, so the name cannot depend on it.
        btn.setAttribute("aria-label", "Appearance");
        btn.innerHTML = ICON;
        btn.appendChild(el("span", "ark-ap-btn-label", host.getAttribute("data-label") || "Appearance"));

        var panel = el("div", "ark-ap-panel");
        panel.id = "ark-ap-panel-" + n;
        panel.setAttribute("role", "dialog");
        panel.setAttribute("aria-label", "Appearance");
        panel.hidden = true;

        // --- theme
        var themeSet = el("fieldset", "ark-ap-group");
        themeSet.appendChild(el("legend", null, "Theme"));
        var grid = el("div", "ark-ap-themes");
        var themeInputs = [];
        THEMES.forEach(function (theme) {
            var label = el("label", "ark-ap-theme");
            var input = el("input");
            input.type = "radio";
            input.name = "ark-ap-theme-" + n;
            input.value = theme.id;
            input.addEventListener("change", function () {
                if (!input.checked) return;
                var patch = { theme: theme.id };
                if (theme.custom && !prefs.custom) patch.custom = seedCustomFromCurrent();
                update(patch);
            });
            var sw = el("span", "ark-ap-swatch");
            sw.setAttribute("aria-hidden", "true");
            sw.appendChild(el("i"));
            sw.appendChild(el("i"));
            sw.appendChild(el("i"));
            if (theme.id === "system") sw.classList.add("ark-ap-swatch--system");
            label.appendChild(input);
            label.appendChild(sw);
            label.appendChild(el("span", "ark-ap-theme-name", theme.name));
            grid.appendChild(label);
            themeInputs.push({ theme: theme, input: input, swatch: sw });
        });
        themeSet.appendChild(grid);

        // --- custom theme
        var custom = el("div", "ark-ap-custom");
        var modeRow = el("div", "ark-ap-row");
        modeRow.appendChild(el("span", "ark-ap-row-label", "Mode"));
        var modeSeg = el("div", "ark-ap-seg");
        var modeBtns = ["Light", "Dark"].map(function (name) {
            var b = el("button", null, name);
            b.type = "button";
            b.addEventListener("click", function () {
                var c = currentCustom();
                var dark = name === "Dark";
                if (c.dark === dark) return;
                // A background picked for one mode is unreadable in the other, so
                // switching mode brings the background along with it.
                c.dark = dark;
                c.bg = dark ? DARK.bg : LIGHT.bg;
                update({ custom: c });
            });
            modeSeg.appendChild(b);
            return b;
        });
        modeRow.appendChild(modeSeg);
        custom.appendChild(modeRow);

        function colorRow(text, key) {
            var row = el("label", "ark-ap-row");
            row.appendChild(el("span", "ark-ap-row-label", text));
            var input = el("input", "ark-ap-color");
            input.type = "color";
            input.addEventListener("input", function () {
                var c = currentCustom();
                c[key] = input.value;
                update({ custom: c });
            });
            row.appendChild(input);
            custom.appendChild(row);
            return input;
        }
        var accentInput = colorRow("Accent", "accent");
        var bgInput = colorRow("Background", "bg");
        themeSet.appendChild(custom);

        // --- text size
        var sizeSet = el("fieldset", "ark-ap-group");
        sizeSet.appendChild(el("legend", null, "Text size"));
        var sizes = el("div", "ark-ap-seg ark-ap-sizes");
        var sizeBtns = SIZES.map(function (s, i) {
            var b = el("button", null, s.label);
            b.type = "button";
            b.title = s.hint;
            b.setAttribute("aria-label", s.hint + " text");
            b.classList.add("ark-ap-size-" + i);
            b.addEventListener("click", function () { update({ scale: s.value }); });
            sizes.appendChild(b);
            return b;
        });
        sizeSet.appendChild(sizes);
        var rangeRow = el("div", "ark-ap-row");
        var range = el("input", "ark-ap-range");
        range.type = "range";
        range.min = String(SCALE_MIN * 100);
        range.max = String(SCALE_MAX * 100);
        range.step = "5";
        range.setAttribute("aria-label", "Text size, percent");
        var out = el("output", "ark-ap-out");
        range.addEventListener("input", function () { update({ scale: Number(range.value) / 100 }); });
        rangeRow.appendChild(range);
        rangeRow.appendChild(out);
        sizeSet.appendChild(rangeRow);

        // --- reset
        var foot = el("div", "ark-ap-foot");
        foot.appendChild(el("small", null, "Saved in this browser only."));
        var reset = el("button", "ark-ap-reset", "Reset");
        reset.type = "button";
        reset.addEventListener("click", function () {
            prefs = {};
            save(prefs);
            apply(prefs);
            pickers.forEach(function (p) { p.sync(); });
        });
        foot.appendChild(reset);

        panel.appendChild(themeSet);
        panel.appendChild(sizeSet);
        panel.appendChild(foot);
        wrap.appendChild(btn);
        wrap.appendChild(panel);
        host.appendChild(wrap);

        function currentCustom() {
            var c = prefs.custom || CUSTOM_DEFAULT;
            return { dark: !!c.dark, accent: c.accent, bg: c.bg };
        }

        // Starting a custom theme from whatever is on screen is friendlier than
        // starting it from the default every time.
        function seedCustomFromCurrent() {
            var r = resolve(themeById(prefs.theme), prefs);
            var t = r.tokens || (r.scheme === "dark" ? DARK : LIGHT);
            return { dark: r.scheme === "dark", accent: t.accent, bg: t.bg };
        }

        function sync() {
            var active = themeById(prefs.theme);
            themeInputs.forEach(function (x) {
                x.input.checked = x.theme.id === active.id;
                var t = swatchColors(x.theme);
                var dots = x.swatch.children;
                if (!t) return;
                x.swatch.style.setProperty("--sw-bg", t.bg);
                dots[0].style.setProperty("background", t.surface);
                dots[1].style.setProperty("background", t.fg);
                dots[2].style.setProperty("background", t.accent);
            });

            custom.hidden = !active.custom;
            var c = customSeed(prefs.custom || CUSTOM_DEFAULT);
            accentInput.value = c.accent;
            bgInput.value = c.bg;
            modeBtns[0].setAttribute("aria-pressed", String(!c.dark));
            modeBtns[1].setAttribute("aria-pressed", String(c.dark));

            var scale = clampScale(prefs.scale);
            sizeBtns.forEach(function (b, i) { b.setAttribute("aria-pressed", String(Math.abs(SIZES[i].value - scale) < 0.001)); });
            range.value = String(Math.round(scale * 100));
            out.textContent = Math.round(scale * 100) + "%";
            if (!panel.hidden) place();
        }

        // Fixed positioning against the button, flipped above it when there is
        // no room below: the same picker opens from a page footer and from a top
        // bar, and must stay on screen on a phone in both.
        function place() {
            var r = btn.getBoundingClientRect();
            var w = panel.offsetWidth, h = panel.offsetHeight;
            var vw = document.documentElement.clientWidth, vh = window.innerHeight;
            var below = vh - r.bottom - 8, above = r.top - 8;
            var top = (below >= h || below >= above) ? r.bottom + 8 : r.top - 8 - h;
            top = Math.max(8, Math.min(top, vh - h - 8));
            var left = Math.max(8, Math.min(r.left + r.width / 2 - w / 2, vw - w - 8));
            panel.style.setProperty("top", top + "px");
            panel.style.setProperty("left", left + "px");
        }

        function open() {
            pickers.forEach(function (p) { if (p !== api) p.close(); });
            panel.hidden = false;
            btn.setAttribute("aria-expanded", "true");
            place();
            var checked = panel.querySelector("input:checked");
            if (checked) checked.focus();
        }

        function close(refocus) {
            if (panel.hidden) return;
            panel.hidden = true;
            btn.setAttribute("aria-expanded", "false");
            if (refocus) btn.focus();
        }

        btn.addEventListener("click", function () { panel.hidden ? open() : close(); });
        document.addEventListener("mousedown", function (e) { if (!wrap.contains(e.target)) close(); });
        document.addEventListener("keydown", function (e) { if (e.key === "Escape" && !panel.hidden) close(true); });
        window.addEventListener("resize", function () { if (!panel.hidden) place(); });
        window.addEventListener("scroll", function () { if (!panel.hidden) place(); }, true);

        var api = { sync: sync, close: close };
        pickers.push(api);
        sync();
    }

    function mountAll() {
        var hosts = document.querySelectorAll("[data-ark-appearance]");
        for (var i = 0; i < hosts.length; i++) mount(hosts[i]);
    }

    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", mountAll);
    else mountAll();
})();
