// The whole integration, in plain JavaScript. In an app with a bundler, import from
// 'ark-oauth-client-js' instead of the relative path.
import { ArkBrowserClient, renderAccessDenied } from '../../src/index.js';

const config = await (await fetch('/config.json')).json();

const ark = new ArkBrowserClient({
  authority: config.authority, // {BaseUrl}/{TenantId}
  clientId: config.clientId, // a public client: no secret
  storage: config.storage,
  accountSwitch: config.requiredClaims.length ? { requireArkClaims: true, requiredClaims: config.requiredClaims, appDisplayName: 'Ark SPA demo' } : {}
});
window.ark = ark; // for poking at from the console (and for the end-to-end test)

const $ = (id) => document.getElementById(id);
const out = (value) => ($('output').textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2));
const log = (text) => $('events').append(Object.assign(document.createElement('li'), { textContent: `${new Date().toLocaleTimeString()} ${text}` }));

// Render from the state: the one place the UI reads authentication from.
ark.subscribe((state) => {
  $('status').textContent = state.error ? `${state.status} (${state.error.message})` : state.status;
  $('status').dataset.status = state.status;
  $('user').hidden = !state.isAuthenticated;
  $('email').textContent = state.user?.email ?? state.user?.sub ?? '';
  $('claims').textContent = state.arkClaims.join(', ') || '(none)';
  $('expires').textContent = state.expiresAt ? new Date(state.expiresAt * 1000).toLocaleTimeString() : '';
  for (const id of ['userinfo', 'refresh', 'signout', 'signout-local']) $(id).disabled = !state.isAuthenticated;
  if (state.status === 'denied') {
    $('app').hidden = true;
    renderAccessDenied($('denied'), ark);
  } else {
    $('app').hidden = false;
    $('denied').replaceChildren();
  }
});

for (const name of ['signedIn', 'signedOut', 'tokensRefreshed', 'refreshFailed', 'sessionExpired', 'accessDenied', 'error']) {
  ark.on(name, (detail) => log(`${name}${detail?.reason ? ` (${detail.reason})` : ''}`));
}

$('signin').onclick = () => ark.signinRedirect();
// Called straight from the click, before any await, so the browser allows the popup.
$('signin-popup').onclick = () => ark.signinPopup().then((r) => log(`popup sign-in finished${r.denied ? ' (denied)' : ''}`), (e) => out(`${e.name}: ${e.message}`));
$('userinfo').onclick = async () => out(await ark.userInfo());
$('refresh').onclick = async () => {
  await ark.refresh();
  out('refreshed');
};
$('switch').onclick = () => ark.switchUser();
$('signout').onclick = () => ark.signoutRedirect();
$('signout-local').onclick = () => ark.signoutLocal();
$('setup').onclick = async () => out(await ark.checkSetup());

await ark.init(); // completes /signin-oidc and /signout-callback-oidc, or restores the session
