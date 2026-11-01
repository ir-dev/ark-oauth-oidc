import { localOrDefault } from './access.js';
import { VERSION } from './version.js';

/**
 * The built-in dead end, at `accountSwitch.accessDeniedPath`.
 *
 * Self-contained HTML with inlined styles and no script: it has to render in an application with no
 * views, no static files and a strict Content-Security-Policy, and it is the one page a stuck user
 * sees, so it cannot itself depend on anything. The markup is the Python and .NET clients' page.
 *
 * Replace it by pointing `accessDeniedPath` at a route of your own and turning `serveDefaultPage`
 * off; `req.ark.deniedAccount()` gives that route the same information.
 */

const STYLE =
  ':root{--bg:#f7f7f8;--surface:#fff;--border:#e2e2e6;--fg:#17171a;--muted:#6a6a73;--accent:#4f46e5;--accent-fg:#fff}' +
  '@media(prefers-color-scheme:dark){:root{--bg:#111114;--surface:#1a1a1f;--border:#313139;--fg:#ececf1;--muted:#9a9aa5;--accent:#8b85ff;--accent-fg:#16161c}}' +
  '*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;' +
  'background:var(--bg);color:var(--fg);font:15px/1.55 ui-sans-serif,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}' +
  '.card{width:100%;max-width:480px;background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:28px}' +
  'h1{margin:0 0 10px;font-size:19px;font-weight:640}p{margin:0 0 14px;color:var(--muted)}p.lede{color:var(--fg)}' +
  'form{margin:0}.actions{display:flex;flex-direction:column;gap:10px;margin-top:20px}' +
  'button{width:100%;padding:11px 14px;border-radius:8px;border:1px solid var(--accent);background:var(--accent);color:var(--accent-fg);' +
  'font:inherit;font-weight:560;cursor:pointer}button.secondary{background:transparent;color:var(--fg);border-color:var(--border)}' +
  '.foot{margin-top:18px;padding-top:14px;border-top:1px solid var(--border);font-size:13px;color:var(--muted)}.foot a{color:var(--accent)}' +
  '.ver{margin:18px 0 0;padding-top:14px;border-top:1px solid var(--border);font-size:12px;color:var(--muted);text-align:center}' +
  '.foot+.ver{margin-top:8px;padding-top:0;border-top:0}';

/**
 * No script, no frames, nothing fetched. `form-action` is left out on purpose: Chrome applies it to
 * the redirect that follows a submission, and the switch-user POST redirects to the provider.
 */
export const DENIED_PAGE_CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'";

const ENTITIES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
export const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ENTITIES[c]);

/**
 * @param {ReturnType<import('./access.js').normalizeAccountSwitch>} options
 * @param {{ app?: string|null, account?: string|null, returnUrl: string }} model
 */
export function renderAccessDeniedPage(options, { app, account = null, returnUrl }) {
  const appName = escapeHtml(app?.trim() || 'this application');
  const lede = account
    ? `You are signed in as <strong>${escapeHtml(account)}</strong>, and that account does not have access to ${appName}.`
    : `The account you are signed in with does not have access to ${appName}.`;

  const parts = [
    '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    `<title>No access — ${appName}</title><style>${STYLE}</style></head>`,
    '<body><main class="card">',
    `<h1>You do not have access to ${appName}</h1>`,
    `<p class="lede">${lede}</p>`,
    `<p>If somebody else was using this browser, their sign-in is still active and it is the one being offered to ${appName}. ` +
      'Choose “Sign in as a different user” to enter your own credentials.</p>',
    '<div class="actions">',
    `<form method="post" action="${escapeHtml(options.switchUserPath)}">`,
    `<input type="hidden" name="returnUrl" value="${escapeHtml(returnUrl)}">`,
    '<button type="submit">Sign in as a different user</button></form>'
  ];

  if (options.allowFullSignOut) {
    parts.push(
      `<form method="post" action="${escapeHtml(options.signOutPath)}">`,
      `<input type="hidden" name="returnUrl" value="${escapeHtml(localOrDefault(options.homePath))}">`,
      '<button class="secondary" type="submit">Sign out completely</button></form>'
    );
  }
  parts.push('</div>');

  if (options.supportUrl || options.supportEmail) {
    const link = options.supportUrl
      ? `<a href="${escapeHtml(options.supportUrl)}">Request it here</a>`
      : `<a href="mailto:${escapeHtml(options.supportEmail)}">${escapeHtml(options.supportEmail)}</a>`;
    parts.push(`<p class="foot">Need access to ${appName}? ${link}</p>`);
  }

  // Which client library drew this page: it is the one screen a stuck user is looking at while
  // somebody else works out why the account is wrong, and they cannot run `npm ls` on the host.
  parts.push(`<p class="ver">ark-oauth-client ${escapeHtml(VERSION)}</p>`, '</main></body></html>');
  return parts.join('');
}
