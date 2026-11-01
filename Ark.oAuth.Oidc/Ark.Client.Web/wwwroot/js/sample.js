// Ark client sample — page helpers shared by every view: copy buttons and code tabs.
// Plain script, no dependencies; every page still works with it blocked.
(function () {
    'use strict';

    var ICON = '<svg class="sx-i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" ' +
        'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
        '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>';

    function copy(button, text) {
        if (!navigator.clipboard || !text) return;
        navigator.clipboard.writeText(text).then(function () {
            button.classList.add('done');
            button.setAttribute('title', 'Copied');
            setTimeout(function () { button.classList.remove('done'); button.setAttribute('title', 'Copy'); }, 1400);
        });
    }

    function copyButton(label) {
        var b = document.createElement('button');
        b.type = 'button';
        b.className = 'sx-copy';
        b.title = 'Copy';
        b.setAttribute('aria-label', label);
        b.innerHTML = ICON;
        return b;
    }

    // Values marked data-copy get their button rendered server-side; fill in the icon here.
    document.querySelectorAll('button.sx-copy[data-copy]').forEach(function (b) {
        if (!b.innerHTML.trim()) b.innerHTML = ICON;
    });

    document.addEventListener('click', function (e) {
        var b = e.target.closest('button.sx-copy[data-copy]');
        if (b) copy(b, b.getAttribute('data-copy'));
    });

    // Every <pre> on every page — tokens, configuration, responses — gets a copy button.
    document.querySelectorAll('main pre').forEach(function (pre) {
        if (pre.closest('.sx-pre') || pre.hasAttribute('data-no-copy')) return;
        var wrap = document.createElement('div');
        wrap.className = 'sx-pre';
        pre.parentNode.insertBefore(wrap, pre);
        wrap.appendChild(pre);
        // A hidden tab panel hides with its button, so the wrapper takes over the attribute.
        if (pre.hidden) { wrap.hidden = true; pre.hidden = false; }
        var b = copyButton('Copy block');
        b.addEventListener('click', function () { copy(b, pre.innerText.trim()); });
        wrap.appendChild(b);
    });

    document.querySelectorAll('[data-tabs]').forEach(function (group) {
        var tabs = group.querySelectorAll('[data-tab]');
        var file = group.querySelector('.sx-file');
        tabs.forEach(function (tab) {
            tab.addEventListener('click', function () {
                tabs.forEach(function (t) { t.setAttribute('aria-selected', t === tab ? 'true' : 'false'); });
                group.querySelectorAll('[data-panel]').forEach(function (p) {
                    var show = p.getAttribute('data-panel') === tab.getAttribute('data-tab');
                    (p.closest('.sx-pre') || p).hidden = !show;
                });
                if (file) file.textContent = tab.getAttribute('data-file') || '';
            });
        });
    });
})();
