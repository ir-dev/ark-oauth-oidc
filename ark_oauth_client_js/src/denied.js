import { VERSION } from './version.js';

/**
 * The built-in dead end for a refused sign-in, for apps without a framework (or that want one
 * ready-made). The same wording as the access-denied page of the .NET, Python and Node clients.
 *
 * Built with DOM calls and `textContent` only (no innerHTML, so nothing from a token can become
 * markup) and styled through the CSSOM, which a strict Content-Security-Policy allows where an
 * injected <style> element or a `style` attribute would be blocked. Pass `unstyled: true` and style
 * the `ark-denied*` classes yourself to match the app.
 *
 *   ark.subscribe((s) => { if (s.status === 'denied') renderAccessDenied(document.body, ark); });
 */

const PALETTE = {
  light: { bg: '#f7f7f8', surface: '#ffffff', border: '#e2e2e6', fg: '#17171a', muted: '#6a6a73', accent: '#4f46e5', accentFg: '#ffffff' },
  dark: { bg: '#111114', surface: '#1a1a1f', border: '#313139', fg: '#ececf1', muted: '#9a9aa5', accent: '#8b85ff', accentFg: '#16161c' }
};

function el(doc, tag, className, text) {
  const node = doc.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function css(node, styles) {
  for (const [key, value] of Object.entries(styles)) node.style.setProperty(key, value);
}

/**
 * Renders the access-denied card into `container`, replacing its content.
 *
 * @param {Element} container
 * @param {import('./client.js').ArkBrowserClient} client
 * @param {{ unstyled?: boolean, appName?: string }} [options]
 * @returns {() => void} removes the card again
 */
export function renderAccessDenied(container, client, options = {}) {
  const doc = container.ownerDocument ?? globalThis.document;
  const config = client.config.accountSwitch;
  const denial = client.getSnapshot().denial;
  const appName = (options.appName ?? config.appDisplayName ?? '').trim() || client.clientId || 'this application';
  const account = config.showSignedInAccount ? (denial?.email ?? denial?.name ?? denial?.subject ?? null) : null;
  const dark = Boolean(doc.defaultView?.matchMedia?.('(prefers-color-scheme: dark)').matches);
  const c = PALETTE[dark ? 'dark' : 'light'];
  const styled = !options.unstyled;

  const root = el(doc, 'main', 'ark-denied');
  root.setAttribute('role', 'alert');
  const card = el(doc, 'div', 'ark-denied__card');
  root.append(card);

  card.append(el(doc, 'h1', 'ark-denied__title', `You do not have access to ${appName}`));

  const lede = el(doc, 'p', 'ark-denied__lede');
  if (account) {
    lede.append('You are signed in as ', el(doc, 'strong', null, account), `, and that account does not have access to ${appName}.`);
  } else {
    lede.textContent = `The account you are signed in with does not have access to ${appName}.`;
  }
  card.append(lede);
  card.append(
    el(
      doc,
      'p',
      'ark-denied__hint',
      `If somebody else was using this browser, their sign-in is still active and it is the one being offered to ${appName}. ` +
        'Choose “Sign in as a different user” to enter your own credentials.'
    )
  );

  const actions = el(doc, 'div', 'ark-denied__actions');
  const switchButton = el(doc, 'button', 'ark-denied__switch', 'Sign in as a different user');
  switchButton.type = 'button';
  switchButton.addEventListener('click', () => client.switchUser({ returnTo: denial?.returnTo ?? undefined }));
  actions.append(switchButton);

  let signOutButton = null;
  if (config.allowFullSignOut) {
    signOutButton = el(doc, 'button', 'ark-denied__signout', 'Sign out completely');
    signOutButton.type = 'button';
    signOutButton.addEventListener('click', () => client.signoutRedirect({ returnTo: config.homePath }));
    actions.append(signOutButton);
  }
  card.append(actions);

  let foot = null;
  if (config.supportUrl || config.supportEmail) {
    foot = el(doc, 'p', 'ark-denied__foot', `Need access to ${appName}? `);
    const link = el(doc, 'a', null, config.supportUrl ? 'Request it here' : config.supportEmail);
    link.href = config.supportUrl ? config.supportUrl : `mailto:${config.supportEmail}`;
    foot.append(link);
    card.append(foot);
  }
  const version = el(doc, 'p', 'ark-denied__version', `ark-oauth-client-js ${VERSION}`);
  card.append(version);

  if (styled) {
    const font = 'ui-sans-serif, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif';
    css(root, { 'min-height': '100vh', display: 'flex', 'align-items': 'center', 'justify-content': 'center', padding: '24px', 'box-sizing': 'border-box', background: c.bg, color: c.fg, font: `15px/1.55 ${font}` });
    css(card, { width: '100%', 'max-width': '480px', background: c.surface, border: `1px solid ${c.border}`, 'border-radius': '12px', padding: '28px', 'box-sizing': 'border-box' });
    for (const p of card.querySelectorAll('p')) css(p, { margin: '0 0 14px', color: c.muted });
    css(lede, { color: c.fg });
    css(card.querySelector('h1'), { margin: '0 0 10px', 'font-size': '19px', 'font-weight': '640' });
    css(actions, { display: 'flex', 'flex-direction': 'column', gap: '10px', 'margin-top': '20px' });
    const button = { width: '100%', padding: '11px 14px', 'border-radius': '8px', font: 'inherit', 'font-weight': '560', cursor: 'pointer' };
    css(switchButton, { ...button, border: `1px solid ${c.accent}`, background: c.accent, color: c.accentFg });
    if (signOutButton) css(signOutButton, { ...button, border: `1px solid ${c.border}`, background: 'transparent', color: c.fg });
    if (foot) {
      css(foot, { 'margin-top': '18px', 'padding-top': '14px', 'border-top': `1px solid ${c.border}`, 'font-size': '13px' });
      css(foot.querySelector('a'), { color: c.accent });
    }
    css(version, { margin: '18px 0 0', 'padding-top': '14px', 'border-top': foot ? '0' : `1px solid ${c.border}`, 'font-size': '12px', 'text-align': 'center' });
  }

  container.replaceChildren(root);
  return () => root.remove();
}
