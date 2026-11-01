// Ark IdP host — landing page behaviour: copy buttons, code tabs and the live discovery check.
// No framework and no third-party script; the page reads fine with this file blocked.
(function () {
    'use strict';

    var copyIcon = document.querySelector('.lp-copy svg');

    function copy(button, text) {
        if (!navigator.clipboard) return;
        navigator.clipboard.writeText(text).then(function () {
            button.classList.add('done');
            button.setAttribute('title', 'Copied');
            setTimeout(function () { button.classList.remove('done'); button.removeAttribute('title'); }, 1400);
        });
    }

    // Every code panel gets a copy button for whichever panel is showing.
    document.querySelectorAll('.lp-code').forEach(function (panel) {
        if (!copyIcon) return;
        var button = document.createElement('button');
        button.type = 'button';
        button.className = 'lp-copy';
        button.setAttribute('aria-label', 'Copy code');
        button.appendChild(copyIcon.cloneNode(true));
        button.addEventListener('click', function () {
            var visible = panel.querySelector('pre:not([hidden])');
            if (visible) copy(button, visible.innerText.trim());
        });
        panel.appendChild(button);
    });

    document.addEventListener('click', function (e) {
        var target = e.target.closest('[data-copy]');
        if (target) copy(target, target.getAttribute('data-copy'));
    });

    document.querySelectorAll('[data-tabs]').forEach(function (group) {
        var tabs = group.querySelectorAll('[data-tab]');
        tabs.forEach(function (tab) {
            tab.addEventListener('click', function () {
                tabs.forEach(function (t) { t.setAttribute('aria-selected', t === tab ? 'true' : 'false'); });
                group.querySelectorAll('[data-panel]').forEach(function (p) {
                    p.hidden = p.getAttribute('data-panel') !== tab.getAttribute('data-tab');
                });
            });
        });
    });

    // Fetch this host's own discovery document and key set: the green dot means a client
    // pointed at the issuer above would configure itself successfully right now.
    var dot = document.querySelector('[data-live-dot]');
    var text = document.querySelector('[data-live-text]');
    var discoveryLink = document.querySelector('.lp-live a[href*="openid-configuration"]');
    if (!dot || !discoveryLink || !window.fetch) return;

    fetch(discoveryLink.href, { headers: { Accept: 'application/json' } })
        .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
        .then(function (doc) {
            return fetch(doc.jwks_uri).then(function (r) { return r.ok ? r.json() : { keys: [] }; })
                .then(function (jwks) {
                    var keys = (jwks.keys || []).length;
                    var grants = (doc.grant_types_supported || []).length;
                    dot.className = 'lp-dot ok';
                    text.textContent = 'Live · ' + grants + ' grant types · ' + keys + ' signing key' + (keys === 1 ? '' : 's');
                });
        })
        .catch(function () {
            dot.className = 'lp-dot bad';
            text.textContent = 'Discovery not responding';
        });
})();
