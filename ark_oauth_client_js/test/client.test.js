import { test, describe, before, after, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { APP_ORIGIN, FakeWindow, MemoryStorage, Tab, makeClient, sleep, startIdp, until } from './harness.js';
import { ArkBrowserClient } from '../src/client.js';
import { ArkCallbackError, ArkConfigError, ArkLoginRequiredError, ArkOAuthError, ArkPopupError, ArkTokenError } from '../src/errors.js';

let idp;
let tab;

before(async () => {
  idp = await startIdp();
});
after(async () => {
  await idp.close();
});
beforeEach(() => {
  idp.misbehave = {};
  idp.arkClaims = ['billing.admin', 'reports.read'];
  idp.accessTokenLifetime = 3600;
  idp.rotateRefreshTokens = true;
  idp.browserSession = null;
  idp.tokenDelayMs = 0;
  for (const list of ['authorizeRequests', 'tokenRequests', 'revocations', 'logouts', 'requests']) idp[list].length = 0;
  idp.familyRevocations = 0;
  tab = new Tab(idp);
});
afterEach(() => tab.destroy());

const tokensKey = (client) => `ark.oidc:spa-app@${client.authority}:tokens`;

/** Moves the stored tokens back in time, as if the page had been closed for `seconds`. */
function ageStored(storage, client, seconds) {
  const data = JSON.parse(storage.getItem(tokensKey(client)));
  data.issued_at -= seconds;
  data.expires_at -= seconds;
  storage.setItem(tokensKey(client), JSON.stringify(data));
}

describe('signing in with a redirect', () => {
  test('completes the code flow, validates the ID token and returns to where the user started', async () => {
    const { client, state } = await tab.signIn('/orders?page=2');

    assert.equal(state.status, 'authenticated');
    assert.equal(state.isAuthenticated, true);
    assert.equal(state.user.email, 'alice@example.com');
    assert.deepEqual([...state.arkClaims], ['billing.admin', 'reports.read']);
    assert.ok(state.scopes.includes('offline_access'));
    assert.equal(state.error, null);

    // the code, state and iss are gone from the address bar, and the user is back where they started
    assert.equal(tab.win.path, '/orders?page=2');
    assert.deepEqual(tab.win.popstates, ['/orders?page=2']);

    // the authorization request was a public-client PKCE request with nonce and state
    const req = idp.authorizeRequests.at(-1);
    assert.equal(req.client_id, 'spa-app');
    assert.equal(req.code_challenge_method, 'S256');
    assert.equal(req.redirect_uri, `${APP_ORIGIN}/signin-oidc`);
    assert.equal(req.scope, 'openid profile email offline_access');
    assert.ok(req.nonce && req.state);

    // the token request carried no secret, only the client id and the verifier
    const token = idp.tokenRequests.at(-1);
    assert.equal(token.grant_type, 'authorization_code');
    assert.equal(token.client_secret, undefined);
    assert.ok(token.code_verifier.length >= 43);

    // tokens persisted to sessionStorage; the transaction was consumed
    const stored = JSON.parse(tab.sessionStorage.getItem(tokensKey(client)));
    assert.ok(stored.access_token && stored.refresh_token && stored.id_token);
    const leftovers = [...Array(tab.sessionStorage.length).keys()].map((i) => tab.sessionStorage.key(i)).filter((k) => k.includes(':tx:'));
    assert.deepEqual(leftovers, []);
    assert.equal(await client.getAccessToken(), stored.access_token);
  });

  test('restores the session on the next page load without asking the provider', async () => {
    await tab.signIn();
    const before = idp.tokenRequests.length;
    const reloaded = tab.load('/reports');
    const state = await reloaded.init();
    assert.equal(state.status, 'authenticated');
    assert.equal(idp.tokenRequests.length, before);
  });

  test('uses onRedirectCallback instead of history when given (a router navigate)', async () => {
    const seen = [];
    const client = tab.load('/a');
    await client.init();
    await client.signinRedirect({ returnTo: '/deep/link#tab-2' });
    const callback = await idp.authorize(tab.win.lastNavigation);
    const landed = tab.load(callback);
    await landed.init({ onRedirectCallback: (to) => seen.push(to) });
    assert.deepEqual(seen, ['/deep/link#tab-2']);
    assert.deepEqual(tab.win.popstates, []);
  });

  test('refuses an off-site returnTo: sign-in cannot be turned into an open redirect', async () => {
    const client = tab.load('/');
    await client.init();
    await client.signinRedirect({ returnTo: 'https://evil.example/phish' });
    const landed = tab.load(await idp.authorize(tab.win.lastNavigation));
    await landed.init();
    assert.equal(tab.win.path, '/');
  });

  test('works with response_mode=fragment', async () => {
    const { state } = await tab.signIn('/x', {}, { responseMode: 'fragment' });
    assert.equal(state.status, 'authenticated');
    assert.equal(idp.authorizeRequests.at(-1).response_mode, 'fragment');
    assert.equal(tab.win.path, '/x');
  });

  test('a replayed callback (reload of the callback URL) is refused and the session survives', async () => {
    const { callback } = await tab.signIn();
    const again = tab.load(callback);
    const state = await again.init();
    assert.ok(state.error instanceof ArkCallbackError);
    assert.equal(state.status, 'authenticated'); // the stored session from the first sign-in
  });

  test('a callback whose state was started in another tab is refused', async () => {
    const other = new Tab(idp);
    const starter = other.load('/');
    await starter.init();
    await starter.signinRedirect();
    const callback = await idp.authorize(other.win.lastNavigation);
    const state = await tab.load(callback).init(); // a different tab's storage
    assert.ok(state.error instanceof ArkCallbackError);
    assert.equal(state.status, 'unauthenticated');
    assert.equal(idp.tokenRequests.length, 0, 'nothing was redeemed');
    assert.equal(tab.win.path, '/signin-oidc', 'the response parameters were removed');
    other.destroy();
  });

  test('an error response surfaces as ArkOAuthError and nothing is stored', async () => {
    idp.misbehave.authorizeError = 'access_denied';
    const { state } = await tab.signIn();
    assert.ok(state.error instanceof ArkOAuthError);
    assert.equal(state.error.error, 'access_denied');
    assert.equal(state.status, 'unauthenticated');
  });

  test('an error with no state (as Ark sends for a refused /authorize) is still surfaced', async () => {
    const client = tab.load('/signin-oidc?error=unauthorized_client&error_description=client%20deactivated');
    const state = await client.init();
    assert.equal(state.error.error, 'unauthorized_client');
  });

  test('an iss from another provider is refused (RFC 9207 mix-up defence)', async () => {
    idp.misbehave.responseIss = 'https://evil.example/tenant';
    const { state } = await tab.signIn();
    assert.ok(state.error instanceof ArkCallbackError);
    assert.match(state.error.message, /evil\.example/);
    assert.equal(idp.tokenRequests.length, 0);
  });

  test('an ID token with the wrong nonce is refused', async () => {
    idp.misbehave.nonce = 'not-the-nonce';
    const { state } = await tab.signIn();
    assert.ok(state.error instanceof ArkTokenError);
    assert.equal(state.error.claim, 'nonce');
    assert.equal(state.status, 'unauthenticated');
  });

  test('an ID token whose at_hash does not cover the access token is refused', async () => {
    idp.misbehave.atHash = 'AAAAAAAAAAAAAAAAAAAAAA';
    const { state } = await tab.signIn();
    assert.equal(state.error.claim, 'at_hash');
  });

  test('an ID token for another audience is refused', async () => {
    idp.misbehave.idTokenAudience = 'someone-else';
    const { state } = await tab.signIn();
    assert.equal(state.error.claim, 'aud');
  });

  test('an ID token signed by an unpublished key is refused', async () => {
    idp.misbehave.rogueSigner = true;
    const { state } = await tab.signIn();
    assert.ok(state.error instanceof ArkTokenError);
    assert.match(state.error.message, /rogue/);
  });

  test('a discovery document for another issuer is refused', async () => {
    idp.misbehave.discoveryIssuer = 'https://elsewhere.example/t';
    const client = tab.load('/');
    await client.init();
    await assert.rejects(client.signinRedirect(), ArkConfigError);
  });

  test('a tenant that requires PAR is reported, since a browser cannot push', async () => {
    idp.misbehave.requirePar = true;
    const client = tab.load('/');
    await client.init();
    await assert.rejects(client.signinRedirect(), /pushed authorization requests/);
  });

  test('passes prompt, login_hint, max_age and extra parameters, but extras cannot replace state or PKCE', async () => {
    const client = tab.load('/');
    await client.init();
    await client.signinRedirect({ prompt: 'login', loginHint: 'bob@example.com', maxAge: 300, extra: { ui_locales: 'en', state: 'forged', code_challenge: 'forged' } });
    const req = Object.fromEntries(new URL(tab.win.lastNavigation).searchParams);
    assert.equal(req.prompt, 'login');
    assert.equal(req.login_hint, 'bob@example.com');
    assert.equal(req.max_age, '300');
    assert.equal(req.ui_locales, 'en');
    assert.notEqual(req.state, 'forged');
    assert.notEqual(req.code_challenge, 'forged');
  });
});

describe('keeping the session alive', () => {
  test('an access token that expired while the page was closed is refreshed at start-up', async () => {
    const { client } = await tab.signIn();
    const firstRefresh = JSON.parse(tab.sessionStorage.getItem(tokensKey(client))).refresh_token;
    client.destroy();
    ageStored(tab.sessionStorage, client, 3700);

    const reloaded = tab.load('/');
    const state = await reloaded.init();
    assert.equal(state.status, 'authenticated');
    assert.equal(idp.tokenRequests.at(-1).grant_type, 'refresh_token');
    const stored = JSON.parse(tab.sessionStorage.getItem(tokensKey(reloaded)));
    assert.notEqual(stored.refresh_token, firstRefresh, 'the rotated refresh token was stored');
    assert.ok(stored.id_token);
  });

  test('concurrent getAccessToken() calls share one refresh', async () => {
    const { client: signedIn } = await tab.signIn();
    signedIn.destroy();
    ageStored(tab.sessionStorage, signedIn, 3590);
    const client = tab.load('/');
    idp.tokenDelayMs = 50;
    const before = idp.tokenRequests.length;
    const tokens = await Promise.all([client.getAccessToken(), client.getAccessToken(), client.getAccessToken()]);
    assert.equal(new Set(tokens).size, 1);
    assert.equal(idp.tokenRequests.length - before, 1);
    assert.equal(idp.familyRevocations, 0);
  });

  test('two tabs sharing localStorage refresh once between them, so the token family is not revoked', async () => {
    const shared = new MemoryStorage();
    const tabA = new Tab(idp, { localStorage: shared, options: { storage: 'local' } });
    const { client: signedIn } = await tabA.signIn();
    signedIn.destroy();
    ageStored(shared, signedIn, 3590);
    const a = tabA.load('/');

    const tabB = new Tab(idp, { localStorage: shared, options: { storage: 'local' } });
    const b = tabB.load('/');
    // b restores the same (shared) session; both now race to renew it
    idp.tokenDelayMs = 80;
    const before = idp.tokenRequests.length;
    const [ta, tb] = await Promise.all([a.getAccessToken(), b.init().then(() => b.getAccessToken())]);
    assert.equal(ta, tb);
    assert.equal(idp.tokenRequests.length - before, 1, 'one refresh request across both tabs');
    assert.equal(idp.familyRevocations, 0);
    tabA.destroy();
    tabB.destroy();
  });

  test('a second instance on the same page (hot reload) adopts the first one\'s refresh instead of replaying it', async () => {
    const { client: first } = await tab.signIn();
    const second = makeClient(idp, tab.win); // same tab, same sessionStorage, stale in-memory tokens once first refreshes
    await second.init();
    await first.refresh();
    const before = idp.tokenRequests.length;
    await second.refresh();
    assert.equal(idp.tokenRequests.length, before, 'second adopted the stored tokens without a request');
    assert.equal(idp.familyRevocations, 0);
    assert.equal(await second.getAccessToken(), await first.getAccessToken());
    second.destroy();
  });

  test('keeps the previous refresh and ID token when the server does not rotate', async () => {
    idp.rotateRefreshTokens = false;
    const { client } = await tab.signIn();
    const before = JSON.parse(tab.sessionStorage.getItem(tokensKey(client)));
    await client.refresh();
    const after = JSON.parse(tab.sessionStorage.getItem(tokensKey(client)));
    assert.equal(after.refresh_token, before.refresh_token);
    assert.notEqual(after.access_token, before.access_token);
  });

  test('a refused refresh ends the session and says so', async () => {
    const { client } = await tab.signIn();
    const events = [];
    client.on('sessionExpired', (e) => events.push(e.reason));
    client.on('signedOut', (e) => events.push(`signedOut:${e.reason}`));
    idp.sessions.clear(); // the provider session ended (logged out elsewhere)
    assert.equal(await client.getAccessToken({ forceRefresh: true }), null);
    assert.equal(client.getSnapshot().status, 'unauthenticated');
    assert.deepEqual(events, ['signedOut:expired', 'refresh_refused']);
    assert.equal(tab.sessionStorage.getItem(tokensKey(client)), null);
  });

  test('refreshes automatically before expiry, at most half-way through a short token\'s life (no tight loop)', async () => {
    idp.accessTokenLifetime = 4; // shorter than refreshBeforeSeconds (60): renew at 2s, not at once
    const { client } = await tab.signIn();
    const before = idp.tokenRequests.length;
    await sleep(1000);
    assert.equal(idp.tokenRequests.length, before, 'not renewed the moment it arrived');
    idp.accessTokenLifetime = 3600;
    await new Promise((resolve) => client.on('tokensRefreshed', resolve));
    assert.equal(idp.tokenRequests.length - before, 1);
    assert.ok(client.getSnapshot().expiresAt > Math.floor(Date.now() / 1000) + 3000);
  });

  test('with automaticRefresh off, an expired access token is renewed on demand, not dropped', async () => {
    idp.accessTokenLifetime = 1;
    const { client } = await tab.signIn('/', {}, { automaticRefresh: false });
    idp.accessTokenLifetime = 3600;
    await sleep(1500);
    assert.equal(client.getSnapshot().status, 'authenticated');
    assert.ok(await client.getAccessToken());
    assert.equal(idp.tokenRequests.at(-1).grant_type, 'refresh_token');
  });

  test('a failure after the server rotated (JWKS unreachable) keeps the new refresh token, so the retry does not replay', async () => {
    let jwksDown = false;
    const flakyFetch = (input, init) => (jwksDown && String(input).includes('jwks') ? Promise.reject(new TypeError('Failed to fetch')) : fetch(input, init));
    await tab.signIn();
    const client = makeClient(idp, tab.win, { fetch: flakyFetch, jwksTtlMs: 0 }); // every ID token check refetches JWKS
    await client.init();
    const presented = JSON.parse(tab.sessionStorage.getItem(tokensKey(client))).refresh_token;
    jwksDown = true;
    await assert.rejects(client.refresh(), /Failed to fetch/);
    const kept = JSON.parse(tab.sessionStorage.getItem(tokensKey(client))).refresh_token;
    assert.notEqual(kept, presented, 'the rotated refresh token was stored before the ID token check');
    assert.equal(client.getSnapshot().status, 'authenticated');
    jwksDown = false;
    await client.refresh();
    assert.equal(idp.familyRevocations, 0);
    assert.equal(client.getSnapshot().status, 'authenticated');
    client.destroy();
  });

  test('a duplicated tab (copied sessionStorage) signs in afresh instead of replaying the copied refresh token', async () => {
    const shared = new MemoryStorage();
    const original = new Tab(idp, { localStorage: shared });
    const { client: a } = await original.signIn();
    const duplicate = new Tab(idp, { localStorage: shared });
    for (let i = 0; i < original.sessionStorage.length; i++) {
      const key = original.sessionStorage.key(i);
      duplicate.sessionStorage.setItem(key, original.sessionStorage.getItem(key));
    }
    const b = duplicate.load('/');
    await b.init();
    assert.equal(b.getSnapshot().status, 'authenticated');

    await a.refresh();
    const reasons = [];
    b.on('sessionExpired', (e) => reasons.push(e.reason));
    await assert.rejects(b.refresh(), ArkLoginRequiredError);
    assert.deepEqual(reasons, ['refresh_token_spent']);
    assert.equal(b.getSnapshot().status, 'unauthenticated');
    assert.equal(idp.familyRevocations, 0, 'the original tab keeps its session');
    await a.refresh();
    assert.equal(a.getSnapshot().status, 'authenticated');
    original.destroy();
    duplicate.destroy();
  });

  test('a refresh whose ID token names another user is refused (OIDC Core 12.2)', async () => {
    const { client } = await tab.signIn();
    idp.misbehave.idTokenSubject = 'mallory@example.com';
    await assert.rejects(client.refresh(), ArkTokenError);
    assert.equal(client.getSnapshot().status, 'unauthenticated');
  });
});

describe('calling APIs', () => {
  test('fetch() attaches the bearer token to the app origin and apiOrigins only', async () => {
    const calls = [];
    const fakeFetch = async (input, init) => {
      calls.push({ url: String(input), auth: new Headers(init?.headers).get('Authorization') });
      return new Response('{}', { status: 200 });
    };
    const { client } = await tab.signIn('/', {}, { apiOrigins: ['https://api.example.com'] });
    const realFetch = client.config.fetch;
    assert.equal(realFetch, undefined);
    const withFake = makeClient(idp, tab.win, { apiOrigins: ['https://api.example.com'], fetch: fakeFetch });
    // same tab, same storage: restore then call
    await withFake.init();
    await withFake.fetch('/api/orders');
    await withFake.fetch('https://api.example.com/v1/x', { headers: { 'X-Trace': '1' } });
    assert.match(calls[0].auth, /^Bearer /);
    assert.match(calls[1].auth, /^Bearer /);
    await assert.rejects(withFake.fetch('https://tracker.example/collect'), /refusing to send the access token/);
    assert.equal(calls.length, 2);
    withFake.destroy();
  });

  test('fetch() retries a 401 invalid_token once after a refresh', async () => {
    let first = true;
    const fakeFetch = async (input, init) => {
      if (String(input).includes('/oauth2/') || String(input).includes('.well-known')) return fetch(input, init);
      if (first) {
        first = false;
        return new Response('', { status: 401, headers: { 'WWW-Authenticate': 'Bearer error="invalid_token"' } });
      }
      return new Response('ok', { status: 200 });
    };
    await tab.signIn();
    const client = makeClient(idp, tab.win, { fetch: fakeFetch });
    await client.init();
    const res = await client.fetch('/api/me');
    assert.equal(res.status, 200);
    assert.equal(idp.tokenRequests.at(-1).grant_type, 'refresh_token');
    client.destroy();
  });

  test('fetch() without a session throws ArkLoginRequiredError', async () => {
    const client = tab.load('/');
    await client.init();
    await assert.rejects(client.fetch('/api/x'), ArkLoginRequiredError);
  });

  test('userInfo() calls the provider with the access token', async () => {
    const { client } = await tab.signIn();
    const info = await client.userInfo();
    assert.equal(info.email, 'alice@example.com');
  });
});

describe('signing out', () => {
  test('signoutRedirect() drops the tokens, revokes the refresh token and ends the provider session with id_token_hint', async () => {
    const { client } = await tab.signIn();
    const { refresh_token: refreshToken, id_token: idToken } = JSON.parse(tab.sessionStorage.getItem(tokensKey(client)));
    const events = [];
    client.on('signedOut', (e) => events.push(e.reason));

    await client.signoutRedirect({ returnTo: '/goodbye' });
    assert.equal(client.getSnapshot().status, 'unauthenticated');
    assert.equal(tab.sessionStorage.getItem(tokensKey(client)), null);
    assert.deepEqual(events, ['signout']);
    await until(() => idp.revocations.length === 1);
    assert.equal(idp.revocations[0].token, refreshToken);
    assert.equal(idp.revocations[0].client_id, 'spa-app');

    const logout = new URL(tab.win.lastNavigation);
    assert.equal(logout.pathname, `/${idp.tenant}/oauth2/logout`);
    assert.equal(logout.searchParams.get('id_token_hint'), idToken);
    assert.equal(logout.searchParams.get('post_logout_redirect_uri'), `${APP_ORIGIN}/signout-callback-oidc`);
    assert.ok(logout.searchParams.get('state'));

    // the provider sends the browser back; the app finishes on the requested page
    const res = await fetch(logout, { redirect: 'manual' });
    const back = tab.load(res.headers.get('location'));
    await back.init();
    assert.equal(tab.win.path, '/goodbye');
    assert.equal(back.getSnapshot().status, 'unauthenticated');
  });

  test('signoutLocal() leaves the provider session alone', async () => {
    const { client } = await tab.signIn();
    await client.signoutLocal();
    assert.equal(client.getSnapshot().status, 'unauthenticated');
    assert.equal(idp.logouts.length, 0);
    assert.ok(idp.browserSession, 'provider session still alive');
  });

  test('signing out in one tab signs the other tabs out', async () => {
    const other = new Tab(idp);
    const { client: a } = await tab.signIn();
    const { client: b } = await other.signIn();
    assert.equal(b.getSnapshot().status, 'authenticated');
    await a.signoutLocal();
    await until(() => b.getSnapshot().status === 'unauthenticated');
    other.destroy();
  });
});

describe('account switching on a shared browser', () => {
  test('switchUser() signs in again with prompt=login', async () => {
    const { client } = await tab.signIn();
    await client.switchUser({ returnTo: '/reports' });
    const req = Object.fromEntries(new URL(tab.win.lastNavigation).searchParams);
    assert.equal(req.prompt, 'login');
    assert.equal(client.getSnapshot().status, 'unauthenticated');
  });

  test('requireArkClaims refuses an account with no claims for the app: nothing stored, the denial named', async () => {
    idp.arkClaims = [];
    const events = [];
    const { client, state } = await tab.signIn('/billing', {}, { accountSwitch: { requireArkClaims: true } });
    client.on('accessDenied', (d) => events.push(d));
    assert.equal(state.status, 'denied');
    assert.equal(state.denial.email, 'alice@example.com');
    assert.equal(state.denial.reason, 'no_app_access');
    assert.equal(state.denial.returnTo, '/billing');
    assert.equal(state.denial.idTokenHint, undefined, 'the ID token stays internal');
    assert.equal(tab.sessionStorage.getItem(tokensKey(client)), null);
    await until(() => idp.revocations.length === 1); // the refused session's refresh token

    // the denial survives a reload of the page (for five minutes), so the dead end can still name the account
    const reloaded = tab.load('/billing', { accountSwitch: { requireArkClaims: true } });
    assert.equal((await reloaded.init()).status, 'denied');

    // and the way out: sign in as somebody else, back to where they were going
    await reloaded.switchUser();
    const req = Object.fromEntries(new URL(tab.win.lastNavigation).searchParams);
    assert.equal(req.prompt, 'login');
    assert.equal(reloaded.getSnapshot().status, 'unauthenticated');
  });

  test('requiredClaims narrows the check: identity-only claims do not grant access', async () => {
    idp.arkClaims = ['email', 'sub'];
    const { state } = await tab.signIn('/', {}, { accountSwitch: { requireArkClaims: true, requiredClaims: ['billing.admin'] } });
    assert.equal(state.status, 'denied');
  });

  test('onEvaluateAccess replaces the configured rule', async () => {
    idp.arkClaims = [];
    const { state } = await tab.signIn('/', {}, { accountSwitch: { requireArkClaims: true }, onEvaluateAccess: ({ claims }) => claims.email.endsWith('@example.com') });
    assert.equal(state.status, 'authenticated');
  });

  test('endProviderSessionOnSwitch logs out at the provider, then signs in with prompt=login on return', async () => {
    const options = { accountSwitch: { endProviderSessionOnSwitch: true } };
    const { client } = await tab.signIn('/', {}, options);
    await client.switchUser({ returnTo: '/reports' });
    const logout = new URL(tab.win.lastNavigation);
    assert.equal(logout.pathname, `/${idp.tenant}/oauth2/logout`);
    const res = await fetch(logout, { redirect: 'manual' });
    const back = tab.load(res.headers.get('location'), options);
    const state = await back.init();
    assert.equal(state.status, 'loading', 'never published as signed out, so no guard starts a sign-in of its own');
    const req = Object.fromEntries(new URL(tab.win.lastNavigation).searchParams);
    assert.equal(req.prompt, 'login');
    assert.equal(idp.authorizeRequests.length, 1, 'the new sign-in is about to start');
  });
});

describe('signing in with a popup', () => {
  test('the popup lands on the callback, hands the response to the opener and closes', async () => {
    const opener = tab.load('/dashboard');
    await opener.init();
    const done = opener.signinPopup();
    const popup = tab.win.opened.at(-1);
    await until(() => popup.navigations.length === 1);

    // the provider, then the callback page loading in the popup (its own sessionStorage)
    const callback = await idp.authorize(popup.navigations[0]);
    const popupWindow = new FakeWindow(callback, { opener: tab.win });
    const popupClient = makeClient(idp, popupWindow);
    await popupClient.init();
    await until(() => popupWindow.closed);

    const result = await done;
    assert.equal(result.denied, false);
    assert.equal(opener.getSnapshot().status, 'authenticated');
    assert.equal(tab.win.path, '/dashboard', 'the opener never navigated');
    assert.equal(popupClient.getSnapshot().status, 'loading', 'the popup did not sign in itself');
    popupClient.destroy();
  });

  test('a blocked popup is reported, not left hanging', async () => {
    const client = tab.load('/');
    tab.win.blockPopups = true;
    await assert.rejects(client.signinPopup(), (e) => e instanceof ArkPopupError && e.reason === 'blocked');
  });

  test('a popup closed by the user rejects with reason closed', async () => {
    const client = tab.load('/');
    await client.init();
    const done = client.signinPopup();
    const popup = tab.win.opened.at(-1);
    await until(() => popup.navigations.length === 1);
    popup.close();
    await assert.rejects(done, (e) => e instanceof ArkPopupError && e.reason === 'closed');
  });

  test('a message with the wrong state is ignored', async () => {
    const client = tab.load('/');
    await client.init();
    const done = client.signinPopup();
    const popup = tab.win.opened.at(-1);
    await until(() => popup.navigations.length === 1);
    tab.win.postMessage({ type: 'ark-oidc:callback', state: 'forged', url: `${APP_ORIGIN}/signin-oidc?code=x&state=forged` }, APP_ORIGIN);
    await sleep(30);
    popup.close();
    await assert.rejects(done, (e) => e.reason === 'closed');
    assert.equal(idp.tokenRequests.length, 0);
  });
});

describe('state for frameworks', () => {
  test('getSnapshot() is the same object until something changes', async () => {
    const client = tab.load('/');
    const a = client.getSnapshot();
    assert.equal(client.getSnapshot(), a);
    await client.init();
    const b = client.getSnapshot();
    assert.notEqual(b, a);
    assert.equal(client.getSnapshot(), b);
    assert.ok(Object.isFrozen(b));
  });

  test('subscribe() hears every change, and the Svelte store contract is met', async () => {
    const client = tab.load('/');
    const seen = [];
    const off = client.subscribe((s) => seen.push(s.status));
    const svelte = [];
    const offStore = client.state.subscribe((s) => svelte.push(s.status));
    await client.init();
    off();
    offStore();
    assert.deepEqual(seen, ['unauthenticated']);
    assert.deepEqual(svelte, ['loading', 'unauthenticated']);
  });

  test('hasArkClaims / hasAnyArkClaim / hasScopes', async () => {
    const { client } = await tab.signIn();
    assert.equal(client.hasArkClaims('billing.admin'), true);
    assert.equal(client.hasArkClaims('billing.admin', 'nope'), false);
    assert.equal(client.hasAnyArkClaim('nope', 'reports.read'), true);
    assert.equal(client.hasScopes('openid', 'offline_access'), true);
  });
});

describe('server-side rendering', () => {
  test('without a window the client is inert: loading, no token, init resolves', async () => {
    const client = new ArkBrowserClient({ authority: idp.issuer, clientId: 'spa-app', window: null });
    assert.equal(client.getSnapshot().status, 'loading');
    assert.equal((await client.init()).status, 'loading');
    assert.equal(await client.getAccessToken(), null);
    await assert.rejects(client.signinRedirect(), /needs a browser window/);
    assert.equal(client.getServerSnapshot().status, 'loading');
  });
});

describe('diagnostics', () => {
  test('checkSetup() reports a healthy setup with no problems beyond the expected', async () => {
    const client = tab.load('/');
    const report = await client.checkSetup();
    assert.equal(report.discoveryOk, true);
    assert.equal(report.jwksOk, true);
    assert.equal(report.tokenEndpointCorsOk, true);
    assert.equal(report.redirectUri, `${APP_ORIGIN}/signin-oidc`);
    assert.deepEqual(report.problems, []);
    assert.equal(report.signingKeys[0].kid, 'key-1');
  });

  test('checkSetup() names an unknown client and an unregistered scope', async () => {
    const client = makeClient(idp, new FakeWindow(`${APP_ORIGIN}/`), { clientId: 'nobody', scopes: ['openid', 'payroll'] });
    const report = await client.checkSetup();
    assert.ok(report.problems.some((p) => /refused client 'nobody'/.test(p)));
    assert.ok(report.problems.some((p) => /payroll/.test(p)));
    assert.ok(report.problems.some((p) => /offline_access is not requested/.test(p)));
  });

  test('checkSetup() explains an unreachable provider', async () => {
    const client = makeClient({ issuer: 'http://127.0.0.1:9/t' }, new FakeWindow(`${APP_ORIGIN}/`), { timeoutMs: 2000 });
    const report = await client.checkSetup();
    assert.equal(report.discoveryOk, false);
    assert.match(report.problems[0], /CorsOrigins/);
  });
});

describe('key rotation', () => {
  test('a JWKS served from the browser cache just after a rotation still gets one revalidating fetch', async () => {
    // A fetch with an HTTP cache: `default` is answered from it, `no-cache` goes to the server.
    const httpCache = new Map();
    const cachingFetch = async (input, init = {}) => {
      const url = String(input);
      if (url.includes('jwks') && init.cache === 'default' && httpCache.has(url)) return new Response(httpCache.get(url), { headers: { 'content-type': 'application/json' } });
      const res = await fetch(input, init);
      if (url.includes('jwks')) httpCache.set(url, await res.clone().text());
      return res;
    };
    await tab.signIn('/', {}, { fetch: cachingFetch });
    idp.rotateKey('key-rotated'); // the server now signs with a kid the cached JWKS does not have
    const fresh = makeClient(idp, tab.win, { fetch: cachingFetch }); // a new page load: empty in-memory JWKS cache
    await fresh.init();
    await fresh.refresh();
    assert.equal(fresh.getSnapshot().status, 'authenticated');
    fresh.destroy();
  });
});
