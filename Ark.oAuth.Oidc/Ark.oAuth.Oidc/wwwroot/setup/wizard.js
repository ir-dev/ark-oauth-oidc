// Ark IdP setup wizard. Served by ArkSetupMiddleware under a script-src 'self' policy, so there is
// no inline script or handler anywhere: every behaviour is wired here.
(() => {
    'use strict';

    const base = document.body.dataset.base;
    const $ = (sel, root = document) => root.querySelector(sel);
    const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
    const form = $('#wizard');
    const field = name => form.elements[name];
    const val = name => {
        const el = field(name);
        if (!el) return '';
        if (el instanceof RadioNodeList) return el.value;
        if (el.type === 'checkbox') return el.checked;
        return (el.value || '').trim();
    };
    const setVal = (name, value) => {
        const el = field(name);
        if (!el) return;
        if (el instanceof RadioNodeList) { el.value = value; return; }
        if (el.type === 'checkbox') el.checked = !!value; else el.value = value ?? '';
    };
    const num = name => { const v = val(name); return v === '' ? null : Number(v); };

    const steps = $$('section.step').filter(s => s.dataset.step !== 'done');
    const DRAFT = 'ark-idp-setup-draft';
    // Never persisted, even for the life of a tab.
    const SECRET_FIELDS = new Set(['admin_password', 'admin_password2', 'db_password', 'raw_connection', 'smtp_password',
        'default_password', 'machine_secret', 'import_key', 'setup_code']);

    let env = null;
    let initialized = false;
    let current = 0;
    let reached = 0;
    let setupCode = '';
    let codeOk = false;
    let key = null;
    let dbOkFor = null;
    let existingTenants = [];
    const logos = { host_logo: '', app_logo: '' };

    // ------------------------------------------------------------------ server calls

    async function call(action, body) {
        const headers = { 'Content-Type': 'application/json', 'X-Ark-Setup': '1' };
        if (setupCode) headers['X-Ark-Setup-Code'] = setupCode;
        const res = await fetch(`${base}/api/${action}`, {
            method: 'POST', headers, credentials: 'same-origin', body: JSON.stringify(body || {})
        });
        let data = {};
        try { data = await res.json(); } catch { /* empty body */ }
        if (!res.ok) {
            const err = new Error(data.msg || `The server answered ${res.status}.`);
            err.field = data.field;
            err.code = data.error;
            throw err;
        }
        return data;
    }

    async function busy(button, work) {
        button.disabled = true;
        button.classList.add('busy');
        try { return await work(); } finally { button.disabled = false; button.classList.remove('busy'); }
    }

    function showResult(el, kind, text) {
        el.hidden = !text;
        el.className = `result ${kind}`;
        el.textContent = text || '';
    }

    // ------------------------------------------------------------------ field errors

    function clearErrors(scope = form) {
        $$('.invalid', scope).forEach(el => el.classList.remove('invalid'));
        $$('.field-error', scope).forEach(el => el.remove());
    }

    function invalid(name, message) {
        const el = field(name);
        const target = el instanceof RadioNodeList ? el[0] : el;
        if (!target) return message;
        if (!(el instanceof RadioNodeList)) target.classList.add('invalid');
        const host = target.closest('.field') || target.closest('.choices') || target.parentElement;
        if (host && !$('.field-error', host)) {
            const small = document.createElement('small');
            small.className = 'field-error';
            small.textContent = message;
            host.appendChild(small);
        }
        return message;
    }

    form.addEventListener('input', e => {
        if (!e.target.name) return;
        e.target.classList.remove('invalid');
        const host = e.target.closest('.field');
        if (host) $$('.field-error', host).forEach(x => x.remove());
        saveDraft();
    });

    // ------------------------------------------------------------------ navigation

    function renderRail() {
        const list = $('#stepList');
        list.innerHTML = '';
        steps.forEach((step, i) => {
            const li = document.createElement('li');
            if (i < reached || (i < current)) li.classList.add('done');
            if (i === current) li.classList.add('current');
            if (step.dataset.error) li.classList.add('error');
            const b = document.createElement('button');
            b.type = 'button';
            b.disabled = i > reached;
            const label = document.createElement('span');
            label.innerHTML = step.dataset.title;
            b.appendChild(label);
            b.addEventListener('click', () => go(i));
            li.appendChild(b);
            list.appendChild(li);
        });
        $('#stepCount').textContent = `Step ${current + 1} of ${steps.length}`;
        $('#back').hidden = current === 0;
        const next = $('#next');
        next.textContent = current === steps.length - 1 ? 'Install' : 'Continue';
        next.classList.toggle('large', current === steps.length - 1);
    }

    function go(index) {
        steps.forEach((s, i) => { s.hidden = i !== index; });
        current = index;
        reached = Math.max(reached, index);
        if (steps[index].dataset.step === 'review') renderSummary();
        // Attaching to an existing database: no key to make, no account to create.
        $$('[data-attach-note]').forEach(n => { n.hidden = !existingTenants.length; });
        $$('[data-new-only]').forEach(n => { n.hidden = !!existingTenants.length; });
        if (existingTenants.length) $('#keyCard').hidden = true;
        if (steps[index].dataset.step === 'security') $('#machineId').textContent = `${val('tenant_id') || 'ark_idp'}_machine`;
        renderRail();
        saveDraft();
        window.scrollTo({ top: 0, behavior: 'smooth' });
        const first = $('input:not([type=hidden]):not([type=radio]):not([type=checkbox]), textarea', steps[index]);
        if (first && !first.value) first.focus({ preventScroll: true });
    }

    $('#back').addEventListener('click', () => current > 0 && go(current - 1));
    $('#next').addEventListener('click', async () => {
        const step = steps[current];
        const button = $('#next');
        const problem = await busy(button, () => validate(step.dataset.step));
        step.dataset.error = problem ? '1' : '';
        if (problem) { renderRail(); return; }
        if (current === steps.length - 1) await install();
        else go(current + 1);
    });

    // ------------------------------------------------------------------ validation

    const TENANT = /^[A-Za-z0-9][A-Za-z0-9_-]{1,62}$/;
    const isUrl = (v, https = false) => {
        try { const u = new URL(v); return https ? u.protocol === 'https:' : /^https?:$/.test(u.protocol); } catch { return false; }
    };
    const isLocalHost = h => h === 'localhost' || h === '127.0.0.1' || h === '[::1]' || h.endsWith('.localhost');
    const isEmail = v => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);

    async function validate(step) {
        clearErrors(steps[current]);
        switch (step) {
            case 'welcome':
                if (!env) return 'The server could not be reached.';
                if (env.code_required && !codeOk) return invalid('setup_code', 'Enter the setup code from the server log, then Verify.');
                if (!env.data_directory_writable || !env.can_apply) return 'This server cannot save its settings. See the checks above.';
                return null;

            case 'organization': {
                let p = null;
                if (!val('company_name')) p = invalid('company_name', 'Enter your organization’s name.');
                for (const n of ['website_url', 'terms_url', 'privacy_url'])
                    if (val(n) && !isUrl(val(n))) p = invalid(n, 'Enter a full URL, starting with https://');
                return p;
            }

            case 'server': {
                let p = null;
                const b = val('base_url');
                if (!isUrl(b)) p = invalid('base_url', 'Enter the full address, e.g. https://id.example.com');
                else {
                    const u = new URL(b);
                    if (u.protocol === 'http:' && !isLocalHost(u.hostname)) p = invalid('base_url', 'Use https. Only localhost may use http.');
                    if (u.search || u.hash) p = invalid('base_url', 'No query string or fragment.');
                }
                if (!TENANT.test(val('tenant_id'))) p = invalid('tenant_id', '2–63 letters, digits, _ or -, starting with a letter or digit.');
                if (val('base_path') && !/^[A-Za-z0-9_\-/]+$/.test(val('base_path'))) p = invalid('base_path', 'Letters, digits, _, - and / only.');
                return p;
            }

            case 'database': {
                if (!connection()) return invalid(val('provider') === 'sqlite' ? 'sqlite_file' : 'db_host', 'Enter where the database is.');
                if (dbOkFor !== signature()) {
                    const ok = await testDatabase();
                    if (!ok) return 'The database test failed.';
                }
                if (existingTenants.length && !existingTenants.includes(val('tenant_id')))
                    return showResult($('#dbResult'), 'error',
                        `This database belongs to tenant(s) ${existingTenants.join(', ')}. Go back to “Server address” and use one of them as the tenant id, or choose an empty database.`) || 'tenant';
                return null;
            }

            case 'keys':
                if (!key && !existingTenants.length) { showResult($('#keyResult'), 'error', 'Generate a key pair, or import an existing private key.'); return 'key'; }
                return null;

            case 'admin': {
                let p = null;
                const u = val('admin_username');
                if (!u || /\s/.test(u)) p = invalid('admin_username', 'A username with no spaces.');
                if (!existingTenants.length) {
                    const pw = field('admin_password').value;
                    if (pw.length < 10) p = invalid('admin_password', 'At least 10 characters.');
                    else if (pw !== field('admin_password2').value) p = invalid('admin_password2', 'The two passwords differ.');
                }
                return p;
            }

            case 'users': {
                let p = null;
                const mode = val('password_mode');
                if (!mode) p = invalid('password_mode', 'Choose one.');
                if (mode === 'email_based' && !val('email_enabled')) p = invalid('password_mode', 'Activation emails need email turned on below.');
                const dp = field('default_password').value;
                if (dp && dp.length < 8) p = invalid('default_password', 'At least 8 characters, or leave it empty.');
                if (val('email_enabled')) {
                    if (!val('smtp')) p = invalid('smtp', 'Enter the SMTP server.');
                    const port = num('smtp_port') ?? 587;
                    if (!(port >= 1 && port <= 65535)) p = invalid('smtp_port', '1–65535');
                    if (!isEmail(val('smtp_from'))) p = invalid('smtp_from', 'Enter the address mail is sent from.');
                }
                return p;
            }

            case 'security': {
                let p = null;
                const s = field('machine_secret').value.trim();
                if (s && s.length < 16) p = invalid('machine_secret', 'At least 16 characters. Use Generate.');
                for (const o of origins()) {
                    let ok = false;
                    try { const u = new URL(o); ok = /^https?:$/.test(u.protocol) && u.origin === o; } catch { /* not a URL */ }
                    if (!ok) { p = invalid('cors_origins', `“${o}” is not an origin: scheme://host[:port], nothing after it.`); break; }
                }
                return p;
            }
            default:
                return null;
        }
    }

    // ------------------------------------------------------------------ welcome

    function renderChecks() {
        const list = $('#envChecks');
        list.innerHTML = '';
        const add = (kind, html) => { const li = document.createElement('li'); li.className = kind; li.innerHTML = html; list.appendChild(li); };
        const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);

        $('#codeCard').hidden = !env.code_required;
        // Until the code is accepted the server says nothing about itself.
        if (!env.defaults) {
            add('warn', 'This server is not configured yet. Enter the setup code to begin.');
            return;
        }
        if (env.data_directory_writable)
            add('', `Settings will be saved in <code>${esc(env.data_directory)}</code>`);
        else
            add('bad', `This server cannot write to <code>${esc(env.data_directory)}</code>. Set <code>ark_oauth_server__Setup__DataPath</code> to a writable directory (in a container, a mounted volume) and restart.`);
        if (!env.can_apply)
            add('bad', 'This host’s configuration cannot be extended at run time. Build it with <code>WebApplication.CreateBuilder</code>.');
        if (!env.defaults.https && !isLocalHost(location.hostname))
            add('warn', 'You are on plain http. Passwords and the signing key you enter here cross the network unencrypted.');
        add('', `Ark.oAuth.Oidc ${esc(env.version)}, environment <code>${esc(env.environment)}</code>`);
        if (!env.console_sign_in)
            add('warn', 'This host signs the admin console in itself. After setup, point its client at the issuer shown at the end.');
    }

    $('#verifyCode').addEventListener('click', e => busy(e.currentTarget, async () => {
        setupCode = val('setup_code').toUpperCase();
        try {
            await call('verify-code', { code: setupCode });
            codeOk = true;
            showResult($('#codeResult'), 'ok', 'Verified. You can continue.');
            steps[0].dataset.error = '';
            await loadState();
            initialize();
        } catch (err) {
            codeOk = false;
            setupCode = '';
            showResult($('#codeResult'), 'error', err.message);
        }
    }));

    // ------------------------------------------------------------------ organization & logos

    const LOGO_TYPES = ['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/svg+xml', 'image/x-icon', 'image/vnd.microsoft.icon'];

    $$('.logo-picker').forEach(picker => {
        const name = picker.dataset.logo;
        const img = $('img', picker);
        const empty = $('.logo-empty', picker);
        const urlInput = $('input.url', picker);
        const show = src => {
            logos[name] = src || '';
            img.hidden = !src;
            empty.hidden = !!src;
            if (src) img.src = src; else img.removeAttribute('src');
            renderPreview();
        };
        $('input[type=file]', picker).addEventListener('change', e => {
            const file = e.target.files[0];
            e.target.value = '';
            if (!file) return;
            if (!LOGO_TYPES.includes(file.type)) { alert('Use a PNG, JPEG, GIF, WebP, SVG or ICO image.'); return; }
            if (file.size > 1024 * 1024) { alert('Logos must be 1 MB or smaller.'); return; }
            const reader = new FileReader();
            reader.onload = () => { urlInput.value = ''; show(reader.result); };
            reader.readAsDataURL(file);
        });
        urlInput.addEventListener('change', () => {
            const v = urlInput.value.trim();
            if (!v) { show(''); return; }
            if (!isUrl(v)) { alert('Enter a full image URL, starting with https://'); return; }
            show(v);
        });
        $('[data-action=clear]', picker).addEventListener('click', () => { urlInput.value = ''; show(''); });
        picker.showLogo = show;
    });

    function renderPreview() {
        const lockup = $('#previewLockup');
        lockup.innerHTML = '';
        const marks = [logos.host_logo, logos.app_logo].filter(Boolean);
        marks.forEach((src, i) => {
            if (i) lockup.appendChild(document.createElement('i'));
            const img = document.createElement('img');
            img.alt = '';
            img.src = src;
            lockup.appendChild(img);
        });
        $('#previewName').textContent = displayName();
    }

    const displayName = () => val('display_name') || `${val('company_name') || 'Your organization'} Identity`;
    ['company_name', 'display_name'].forEach(n => field(n).addEventListener('input', renderPreview));

    // ------------------------------------------------------------------ server

    function appRoot() {
        const b = val('base_url').replace(/\/+$/, '');
        const p = val('base_path').replace(/^\/+|\/+$/g, '');
        return p && !b.toLowerCase().endsWith('/' + p.toLowerCase()) ? `${b}/${p}` : b;
    }

    function renderServer() {
        const issuer = `${appRoot()}/${val('tenant_id') || '…'}`;
        $('#issuerPreview').textContent = issuer;
        $('#discoveryPreview').textContent = `${issuer}/.well-known/openid-configuration`;
        let warn = '';
        try {
            const u = new URL(val('base_url'));
            if (u.origin !== location.origin)
                warn = `You are using this wizard at ${location.origin}, but the public URL is ${u.origin}. After install, the admin console signs you in through the public URL, so it must reach this server.`;
        } catch { /* invalid, flagged on Continue */ }
        const w = $('#baseUrlWarn');
        w.hidden = !warn;
        w.textContent = warn;
        if (!field('tenant_display').dataset.touched)
            field('tenant_display').placeholder = `${val('company_name') || val('tenant_id') || 'Ark'} Admin Console`;
    }
    ['base_url', 'base_path', 'tenant_id', 'company_name'].forEach(n => field(n).addEventListener('input', renderServer));
    field('tenant_display').addEventListener('input', e => { e.target.dataset.touched = '1'; });

    // ------------------------------------------------------------------ database

    const PORTS = { postgres: 5432, mysql: 3306 };

    function connection() {
        const raw = field('raw_connection').value.trim();
        if (raw) return raw;
        const provider = val('provider');
        if (provider === 'sqlite') return val('sqlite_file') ? `Data Source=${val('sqlite_file')}` : '';
        const host = val('db_host');
        if (!host) return '';
        const port = val('db_port') || PORTS[provider];
        const db = val('db_name');
        const user = val('db_user');
        const pw = field('db_password').value;
        const ssl = val('db_ssl');
        if (provider === 'postgres')
            return `Host=${host};Port=${port};Database=${db};Username=${user};Password=${pw};SSL Mode=${{ prefer: 'Prefer', require: 'Require', disable: 'Disable' }[ssl]}`;
        return `Server=${host};Port=${port};Database=${db};User ID=${user};Password=${pw};SslMode=${{ prefer: 'Preferred', require: 'Required', disable: 'None' }[ssl]}`;
    }

    const signature = () => `${val('provider')}|${connection()}`;

    function renderDatabase() {
        const provider = val('provider');
        $('[data-db=sqlite]').hidden = provider !== 'sqlite';
        $('[data-db=server]').hidden = provider === 'sqlite';
        field('db_port').placeholder = PORTS[provider] || '';
        const conn = connection();
        $('#connPreview').textContent = conn ? conn.replace(/(Password=)[^;]*/i, '$1••••••') : '—';
        if (dbOkFor && dbOkFor !== signature()) { dbOkFor = null; $('#dbResult').hidden = true; }
    }
    $$('[data-step=database] input, [data-step=database] select, [data-step=database] textarea')
        .forEach(el => el.addEventListener(el.type === 'radio' || el.tagName === 'SELECT' ? 'change' : 'input', renderDatabase));

    async function testDatabase() {
        const out = $('#dbResult');
        showResult(out, 'info', 'Connecting…');
        try {
            const r = await call('database/test', { provider: val('provider'), connection_string: connection() });
            existingTenants = r.tenants || [];
            showResult(out, r.ok ? (existingTenants.length ? 'info' : 'ok') : 'error', r.msg);
            dbOkFor = r.ok ? signature() : null;
            return r.ok;
        } catch (err) {
            showResult(out, 'error', err.message);
            dbOkFor = null;
            return false;
        }
    }
    $('#testDb').addEventListener('click', e => busy(e.currentTarget, testDatabase));

    // ------------------------------------------------------------------ keys

    $$('[data-keymode]').forEach(tab => tab.addEventListener('click', () => {
        $$('[data-keymode]').forEach(t => t.setAttribute('aria-selected', String(t === tab)));
        $$('[data-keypane]').forEach(p => { p.hidden = p.dataset.keypane !== tab.dataset.keymode; });
    }));

    function setKey(k) {
        key = k;
        $('#keyCard').hidden = false;
        $('#keyKid').textContent = k.kid;
        $('#keyAlg').textContent = `${k.algorithm}, RSA ${k.key_size} bits`;
        $('#keyPublic').value = k.public_pem;
        $('#keyPrivate').value = k.private_pem;
        $('#keyPrivate').hidden = true;
        $('#revealKey').textContent = 'Show';
        showResult($('#keyResult'), 'ok', `Key ready: ${k.kid}`);
        steps[current].dataset.error = '';
    }

    $('#genKey').addEventListener('click', e => busy(e.currentTarget, async () => {
        try { setKey(await call('keys/generate', { key_size: Number(val('key_size')) })); }
        catch (err) { showResult($('#keyResult'), 'error', err.message); }
    }));
    $('#importKey').addEventListener('click', e => busy(e.currentTarget, async () => {
        try { setKey(await call('keys/import', { private_key: field('import_key').value })); field('import_key').value = ''; }
        catch (err) { showResult($('#keyResult'), 'error', err.message); }
    }));
    $('#revealKey').addEventListener('click', e => {
        const t = $('#keyPrivate');
        t.hidden = !t.hidden;
        e.currentTarget.textContent = t.hidden ? 'Show' : 'Hide';
    });
    $('#downloadKey').addEventListener('click', () => {
        if (!key) return;
        const a = document.createElement('a');
        a.href = URL.createObjectURL(new Blob([key.private_pem], { type: 'application/x-pem-file' }));
        a.download = `ark-idp-signing-${key.kid}.pem`;
        a.click();
        setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    });

    // ------------------------------------------------------------------ secrets

    function randomSecret(length, alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789') {
        const bytes = new Uint32Array(length);
        crypto.getRandomValues(bytes);
        return [...bytes].map(n => alphabet[n % alphabet.length]).join('');
    }

    $('#genAdminPw').addEventListener('click', () => {
        const pw = randomSecret(20, 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#%+=?@');
        setVal('admin_password', pw);
        setVal('admin_password2', pw);
        $('#genAdminPwValue').textContent = pw;
        $('#genAdminPwNote').hidden = false;
        renderStrength();
    });
    $('#genDefaultPw').addEventListener('click', () => {
        setVal('default_password', randomSecret(14));
        field('default_password').type = 'text';
    });
    $('#genMachine').addEventListener('click', () => {
        setVal('machine_secret', randomSecret(40));
        field('machine_secret').type = 'text';
    });

    $$('[data-toggle-password]').forEach(b => b.addEventListener('click', () => {
        const input = field(b.dataset.togglePassword);
        input.type = input.type === 'password' ? 'text' : 'password';
        b.textContent = input.type === 'password' ? 'Show' : 'Hide';
    }));

    function renderStrength() {
        const pw = field('admin_password').value;
        let score = Math.min(pw.length, 24) / 24 * 60;
        score += [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter(r => r.test(pw)).length * 10;
        const bar = $('#pwMeter');
        bar.style.width = `${Math.min(100, score)}%`;
        bar.style.background = score < 50 ? 'var(--ark-danger)' : score < 80 ? 'var(--ark-warn)' : 'var(--ark-success)';
        $('#pwHint').textContent = pw.length < 10 ? 'At least 10 characters.' : score < 80 ? 'Acceptable. Longer is stronger.' : 'Strong.';
    }
    field('admin_password').addEventListener('input', renderStrength);

    // ------------------------------------------------------------------ email

    const renderEmail = () => { $('#emailFields').hidden = !val('email_enabled'); };
    field('email_enabled').addEventListener('change', renderEmail);

    function emailPayload() {
        return {
            enabled: !!val('email_enabled'),
            smtp: val('smtp'),
            port: num('smtp_port') ?? 587,
            username: val('smtp_user'),
            password: field('smtp_password').value,
            from: val('smtp_from'),
            display: val('smtp_display') || displayName(),
            subject: val('smtp_subject')
        };
    }

    $('#testEmail').addEventListener('click', e => busy(e.currentTarget, async () => {
        const out = $('#emailResult');
        showResult(out, 'info', 'Sending…');
        try {
            const r = await call('email/test', { email: emailPayload(), to: val('test_to') });
            showResult(out, r.ok ? 'ok' : 'error', r.msg);
        } catch (err) { showResult(out, 'error', err.message); }
    }));

    // ------------------------------------------------------------------ copy

    document.addEventListener('click', async e => {
        const b = e.target.closest('[data-copy]');
        if (!b) return;
        const src = $(b.dataset.copy);
        const text = src.value ?? src.textContent;
        try { await navigator.clipboard.writeText(text); }
        catch {
            const t = document.createElement('textarea');
            t.value = text;
            document.body.appendChild(t);
            t.select();
            document.execCommand('copy');
            t.remove();
        }
        const label = b.textContent;
        b.textContent = 'Copied';
        setTimeout(() => { b.textContent = label; }, 1200);
    });

    // ------------------------------------------------------------------ review & install

    const origins = () => field('cors_origins').value.split(/\s+/).map(s => s.trim().replace(/\/+$/, '')).filter(Boolean);

    function payload() {
        return {
            organization: {
                company_name: val('company_name'), display_name: val('display_name'),
                website_url: val('website_url'), terms_url: val('terms_url'), privacy_url: val('privacy_url')
            },
            branding: { host_logo: logos.host_logo, app_logo: logos.app_logo },
            server: {
                tenant_id: val('tenant_id'), tenant_display: val('tenant_display') || `${val('company_name') || val('tenant_id')} Admin Console`,
                base_url: val('base_url'), base_path: val('base_path')
            },
            database: { provider: val('provider'), connection_string: connection() },
            keys: { private_key: key ? key.private_key : '' },
            admin: { username: val('admin_username'), name: val('admin_name'), password: field('admin_password').value },
            users: { password_mode: val('password_mode'), default_password: field('default_password').value },
            email: emailPayload(),
            protocol: {
                enable_device_flow: !!val('enable_device_flow'),
                enable_pushed_authorization_requests: !!val('enable_par'),
                require_pushed_authorization_requests: !!val('require_par'),
                enable_dynamic_registration: !!val('enable_dynamic_registration'),
                always_require_consent: !!val('always_consent'),
                enable_back_channel_logout: !!val('enable_backchannel_logout'),
                session_lifetime_minutes: num('session_minutes'),
                max_failed_sign_ins: num('max_failed'),
                lockout_minutes: num('lockout_minutes'),
                cors_origins: origins()
            },
            management: { machine_client_secret: field('machine_secret').value.trim() }
        };
    }

    function renderSummary() {
        const p = payload();
        const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
        const yes = b => (b ? 'On' : 'Off');
        const logo = src => (src ? `<img src="${esc(src)}" alt="">` : '<span class="muted">none</span>');
        const modes = { admin_managed: 'Administrators set them', email_based: 'Activation email', auto: 'Decided per user' };
        const sections = [
            ['organization', 'Organization & branding', [
                ['Organization', esc(p.organization.company_name)],
                ['Sign-in page name', esc(displayName())],
                ['Logos', `${logo(p.branding.host_logo)} ${logo(p.branding.app_logo)}`],
                ['Website', esc(p.organization.website_url || '—')]
            ]],
            ['server', 'Server address', [
                ['Issuer', `<code>${esc(appRoot())}/${esc(p.server.tenant_id)}</code>`],
                ['Tenant', `${esc(p.server.tenant_id)}: ${esc(p.server.tenant_display)}`]
            ]],
            ['database', 'Database', [
                ['Provider', esc(p.database.provider)],
                ['Connection', `<code>${esc(p.database.connection_string.replace(/(Password=)[^;]*/i, '$1••••••'))}</code>`],
                ...(existingTenants.length ? [['Mode', `Attach to the existing database (tenants ${esc(existingTenants.join(', '))})`]] : [])
            ]],
            ['keys', 'Signing key', [['Key', existingTenants.length ? 'the existing database’s keys' : key ? `<code>${esc(key.kid)}</code>, RSA ${key.key_size}` : '—']]],
            ['admin', 'Administrator', [
                ['Username', esc(p.admin.username)],
                ['Name', esc(p.admin.name || 'Administrator')],
                ['Password', existingTenants.length ? 'unchanged (existing database)' : '•'.repeat(10)]
            ]],
            ['users', 'Users & email', [
                ['New user passwords', esc(modes[p.users.password_mode] || p.users.password_mode)],
                ['Default password', p.users.default_password ? 'set' : 'not set'],
                ['Email', p.email.enabled ? `${esc(p.email.smtp)}:${esc(p.email.port)} as ${esc(p.email.from)}` : 'Off']
            ]],
            ['security', 'Protocol & security', [
                ['Device flow / PAR', `${yes(p.protocol.enable_device_flow)} / ${yes(p.protocol.enable_pushed_authorization_requests)}${p.protocol.require_pushed_authorization_requests ? ' (required)' : ''}`],
                ['Dynamic registration', yes(p.protocol.enable_dynamic_registration)],
                ['Back-channel logout', yes(p.protocol.enable_back_channel_logout)],
                ['CORS origins', esc(p.protocol.cors_origins.join(', ') || 'none')],
                ['Machine client secret', p.management.machine_client_secret ? 'set (shown once after install)' : 'none yet']
            ]]
        ];
        const root = $('#summary');
        root.innerHTML = sections.map(([step, title, rows]) => `
            <section>
                <header><h3>${title}</h3><button type="button" class="link" data-goto="${step}">Edit</button></header>
                <dl>${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl>
            </section>`).join('');
        $$('[data-goto]', root).forEach(b => b.addEventListener('click', () => go(steps.findIndex(s => s.dataset.step === b.dataset.goto))));
        $('#settingsPath').textContent = env ? env.settings_file : '';
    }

    // Server field names, as returned in { field }, to the step and input that hold them.
    const FIELD_MAP = {
        tenant_id: ['server', 'tenant_id'], base_url: ['server', 'base_url'], base_path: ['server', 'base_path'],
        provider: ['database', null], connection_string: ['database', null],
        private_key: ['keys', null], key_size: ['keys', null],
        admin_username: ['admin', 'admin_username'], admin_password: ['admin', 'admin_password'],
        password_mode: ['users', 'password_mode'], default_password: ['users', 'default_password'],
        smtp: ['users', 'smtp'], port: ['users', 'smtp_port'], from: ['users', 'smtp_from'],
        cors_origins: ['security', 'cors_origins'], machine_client_secret: ['security', 'machine_secret'],
        host_logo: ['organization', null], app_logo: ['organization', null]
    };

    async function install() {
        const overlay = $('#overlay');
        const text = $('#overlayText');
        const messages = ['Writing settings…', 'Creating the database…', 'Storing the signing key…', 'Creating the administrator…', 'Almost there…'];
        let i = 0;
        text.textContent = messages[0];
        overlay.hidden = false;
        const timer = setInterval(() => { i = Math.min(i + 1, messages.length - 1); text.textContent = messages[i]; }, 900);
        try {
            const r = await call('complete', payload());
            done(r);
        } catch (err) {
            const out = $('#installResult');
            showResult(out, 'error', err.message);
            const target = FIELD_MAP[err.field];
            if (target) {
                const index = steps.findIndex(s => s.dataset.step === target[0]);
                steps[index].dataset.error = '1';
                go(index);
                if (target[1]) invalid(target[1], err.message);
                else if (target[0] === 'database') showResult($('#dbResult'), 'error', err.message);
                else if (target[0] === 'keys') showResult($('#keyResult'), 'error', err.message);
                else alert(err.message);
            }
        } finally {
            clearInterval(timer);
            overlay.hidden = true;
        }
    }

    function done(r) {
        try { sessionStorage.removeItem(DRAFT); } catch { /* storage unavailable */ }
        steps.forEach(s => { s.hidden = true; });
        $('[data-step=done]').hidden = false;
        $('#shell').classList.add('finished');
        $('#actions').hidden = true;
        $('#doneAdmin').textContent = r.admin_username;
        $('#doneIssuer').textContent = r.issuer;
        $('#doneDiscovery').textContent = r.discovery;
        $('#doneSettings').textContent = r.settings_file;
        $('#doneConsole').href = r.console;
        if (r.machine_client_secret) {
            $('#doneSecretCard').hidden = false;
            $('#doneMachineId').textContent = `client_id: ${r.machine_client_id}`;
            $('#doneSecret').textContent = r.machine_client_secret;
        }
        // Secrets the page no longer needs.
        key = null;
        ['admin_password', 'admin_password2', 'db_password', 'smtp_password', 'machine_secret', 'raw_connection'].forEach(n => setVal(n, ''));
        window.scrollTo({ top: 0 });
    }

    // ------------------------------------------------------------------ draft

    function saveDraft() {
        // Not before the defaults are in: an empty form saved first would restore over them.
        if (!initialized) return;
        try {
            const values = {};
            for (const el of form.elements) {
                if (!el.name || SECRET_FIELDS.has(el.name) || el.type === 'file') continue;
                if (el.type === 'radio') { if (el.checked) values[el.name] = el.value; }
                else if (el.type === 'checkbox') values[el.name] = el.checked;
                else values[el.name] = el.value;
            }
            sessionStorage.setItem(DRAFT, JSON.stringify({ values, reached: Math.min(reached, 3) }));
        } catch { /* storage unavailable: the draft is a convenience */ }
    }

    function loadDraft() {
        try {
            const draft = JSON.parse(sessionStorage.getItem(DRAFT) || 'null');
            if (!draft) return false;
            Object.entries(draft.values || {}).forEach(([k, v]) => { if (v !== '') setVal(k, v); });
            return true;
        } catch { return false; }
    }

    // ------------------------------------------------------------------ start

    function defaults() {
        const d = env.defaults;
        setVal('base_url', d.base_url);
        setVal('tenant_id', d.tenant_id);
        setVal('provider', d.provider);
        setVal('sqlite_file', d.sqlite_file);
        setVal('admin_username', 'admin');
        setVal('admin_name', 'Administrator');
        setVal('password_mode', 'admin_managed');
        setVal('key_size', '2048');
        setVal('db_ssl', 'prefer');
        ['enable_device_flow', 'enable_par', 'enable_backchannel_logout'].forEach(n => setVal(n, true));
    }

    async function loadState() {
        const headers = { Accept: 'application/json' };
        if (setupCode) headers['X-Ark-Setup-Code'] = setupCode;
        const res = await fetch(`${base}/api/state`, { credentials: 'same-origin', headers });
        // Already set up: the setup routes are gone.
        if (res.status === 404) { location.href = `${base.replace(/\/ark-idp\/setup$/, '')}/`; return false; }
        env = await res.json();
        return true;
    }

    function initialize() {
        if (env.defaults && !initialized) {
            initialized = true;
            defaults();
            loadDraft();
        }
        renderChecks();
        renderPreview();
        renderServer();
        renderDatabase();
        renderEmail();
        renderRail();
    }

    async function start() {
        try {
            if (!await loadState()) return;
        } catch {
            document.querySelector('.lead').textContent = 'The server did not answer. Reload the page to try again.';
            return;
        }
        initialize();
        go(0);
    }

    start();
})();
