import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { ArkOAuthClient } from '../src/client.js';
import { arkBearer, arkExpress } from '../src/express.js';
import { MemorySessionStore, parseCookies, unsignSessionId } from '../src/session.js';
import { StubIdp } from './stub-idp.js';
import { Browser, app, route, serve } from './harness.js';

let idp;

before(async () => {
  idp = await new StubIdp().listen();
});
after(async () => {
  await idp.close();
});

function buildApp({ authOptions = {}, clientOptions = {}, store = new MemorySessionStore({ sweepIntervalMs: 0 }) } = {}) {
  const holder = {};
  const server = app(
    (req, res, next) => holder.auth(req, res, next),
    route('/', (req, res) => {
      res.setHeader('Content-Type', 'text/plain');
      res.end(req.ark.isAuthenticated ? `signed in as ${req.ark.user.email}` : 'anonymous');
    }),
    route('/profile', (req, res, next) => holder.auth.requireAuth()(req, res, next), (req, res) => {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ sub: req.ark.sub, claims: req.ark.claims, scopes: req.ark.scopes }));
    }),
    route('/billing', (req, res, next) => holder.auth.requireClaims('billing.admin')(req, res, next), (req, res) => res.end('billing')),
    route('/secrets', (req, res, next) => holder.auth.requireClaims('not.granted')(req, res, next), (req, res) => res.end('secrets')),
    route('/token', async (req, res) => {
      res.setHeader('Content-Type', 'text/plain');
      res.end((await req.ark.accessToken()) ?? 'none');
    }),
    // Reads the token, yields, and reads it again — the second read is where a request that waited
    // on somebody else's refresh would present the retired refresh token.
    route('/token-twice', async (req, res) => {
      const first = await req.ark.accessToken();
      await new Promise((resolve) => setTimeout(resolve, 20));
      const second = await req.ark.accessToken();
      res.setHeader('Content-Type', 'text/plain');
      res.end(`${first ?? 'none'}|${second ?? 'none'}`);
    })
  );

  return { server, store, holder, clientOptions, authOptions };
}

async function startApp(options = {}) {
  const built = buildApp(options);
  const origin = await serve(built.server);
  const client = new ArkOAuthClient({
    authority: idp.issuer,
    clientId: 'web-app',
    redirectUri: `${origin}/signin-oidc`,
    scopes: ['openid', 'profile', 'email', 'offline_access'],
    ...built.clientOptions
  });
  built.holder.auth = arkExpress({
    client,
    secret: 'a-test-secret-of-sufficient-length',
    store: built.store,
    cookie: { secure: false },
    ...built.authOptions
  });
  return { ...built, origin, client, close: async () => new Promise((resolve) => built.server.close(resolve)) };
}

describe('interactive sign-in', () => {
  test('signs a user in and back out again', async () => {
    const web = await startApp();
    const browser = new Browser();
    try {
      const anonymous = await browser.go(`${web.origin}/`);
      assert.equal(anonymous.body, 'anonymous');

      const signedIn = await browser.go(`${web.origin}/login`);
      assert.equal(signedIn.body, 'signed in as alice@example.com');
      assert.equal(signedIn.url, `${web.origin}/`, 'lands on the default return address');
      // The token never reaches the browser; only an opaque session id does.
      const cookie = browser.cookies.get('ark_session');
      assert.ok(cookie && !cookie.includes('.ey'), 'the cookie must not carry a JWT');

      const profile = await browser.go(`${web.origin}/profile`);
      const body = JSON.parse(profile.body);
      assert.equal(body.sub, 'alice@example.com');
      assert.deepEqual(body.claims, ['billing.admin', 'reports.read']);
      assert.ok(body.scopes.includes('offline_access'));

      const out = await browser.go(`${web.origin}/logout`);
      assert.equal(out.body, 'anonymous', 'the session is gone');
      assert.equal(web.store.size, 0, 'and so is the server-side record');
    } finally {
      await web.close();
    }
  });

  test('returns the user to where they were going', async () => {
    const web = await startApp();
    const browser = new Browser();
    try {
      const guarded = await browser.go(`${web.origin}/profile`, { headers: { accept: 'text/html' } });
      // requireAuth sent the browser to /login?returnTo=/profile, which came back to /profile.
      assert.equal(guarded.url, `${web.origin}/profile`);
      assert.equal(JSON.parse(guarded.body).sub, 'alice@example.com');
    } finally {
      await web.close();
    }
  });

  test('an off-site returnTo is ignored', async () => {
    const web = await startApp();
    const browser = new Browser();
    try {
      const result = await browser.go(`${web.origin}/login?returnTo=https://evil.example.com/phish`);
      assert.equal(result.url, `${web.origin}/`, 'an absolute returnTo must not be followed');
    } finally {
      await web.close();
    }
  });

  // Browsers read `\` as `/` and drop tabs/newlines, so each of these is another host.
  for (const sneaky of ['/\\evil.example.com/phish', '/\t/evil.example.com/phish', '//evil.example.com/phish']) {
    test(`a returnTo that a browser reads as off-site is ignored: ${JSON.stringify(sneaky)}`, async () => {
      const web = await startApp();
      const browser = new Browser();
      try {
        const result = await browser.go(`${web.origin}/login?returnTo=${encodeURIComponent(sneaky)}`);
        assert.equal(result.url, `${web.origin}/`);
      } finally {
        await web.close();
      }
    });
  }

  test('authorization claims gate a route', async () => {
    const web = await startApp();
    const browser = new Browser();
    try {
      await browser.go(`${web.origin}/login`);
      assert.equal((await browser.go(`${web.origin}/billing`)).body, 'billing');

      const denied = await browser.go(`${web.origin}/secrets`);
      assert.equal(denied.response.status, 403);
      assert.match(denied.body, /insufficient_scope/);
    } finally {
      await web.close();
    }
  });

  test('an API request gets 401 with a bearer challenge, not a redirect to a login page', async () => {
    const web = await startApp();
    try {
      const response = await fetch(`${web.origin}/profile`, { headers: { accept: 'application/json' }, redirect: 'manual' });
      assert.equal(response.status, 401);
      assert.match(response.headers.get('www-authenticate') ?? '', /Bearer realm="ark"/);
    } finally {
      await web.close();
    }
  });

  test('a forged callback is refused', async () => {
    const web = await startApp();
    const browser = new Browser();
    try {
      const forged = await browser.go(`${web.origin}/signin-oidc?code=made-up&state=made-up`);
      assert.equal(forged.response.status, 400);
      assert.match(forged.body, /could not be matched to a request from this browser/);
    } finally {
      await web.close();
    }
  });

  test('the session id changes at sign-in, so a planted one is never authenticated', async () => {
    const web = await startApp();
    const browser = new Browser();
    try {
      await browser.go(`${web.origin}/login`); // creates a session holding the transaction
      const beforeCallback = browser.cookies.get('ark_session');
      await browser.go(`${web.origin}/login`);
      const afterSignIn = browser.cookies.get('ark_session');
      assert.notEqual(afterSignIn, beforeCallback, 'session fixation: the id must be replaced at sign-in');
    } finally {
      await web.close();
    }
  });

  test('two tabs can sign in at once without clobbering each other', async () => {
    const web = await startApp();
    const browser = new Browser();
    try {
      // Two tabs start a sign-in before either finishes, so both transactions are outstanding in
      // the one session this browser has.
      const first = await browser.go(`${web.origin}/login`, { follow: false });
      const second = await browser.go(`${web.origin}/login`, { follow: false });

      const results = [];
      for (const authorizeUrl of [first.location, second.location]) {
        const authorize = await fetch(authorizeUrl, { redirect: 'manual' });
        const callback = await browser.go(authorize.headers.get('location'), { follow: false });
        results.push(callback.response.status);
      }

      // The first callback rotates the session id; the second must still find its transaction.
      assert.deepEqual(results, [302, 302], 'both outstanding transactions complete');
      assert.equal((await browser.go(`${web.origin}/`)).body, 'signed in as alice@example.com');
    } finally {
      await web.close();
    }
  });

  test('the middleware refuses to start without a usable secret', () => {
    assert.throws(
      () => arkExpress({ authority: idp.issuer, clientId: 'web-app', secret: 'short' }),
      /must be at least 16 characters/
    );
  });
});

describe('token freshness', () => {
  /** Ages the stored access token so the next request has to refresh, as it would after an hour. */
  async function expireStoredToken(web, browser) {
    const id = unsignSessionId(browser.cookies.get('ark_session'), 'a-test-secret-of-sufficient-length');
    const session = await web.store.get(id);
    session.tokens.expires_at = Math.floor(Date.now() / 1000) - 10;
    return id;
  }

  test('an expiring access token is refreshed before it is handed out', async () => {
    const web = await startApp();
    const browser = new Browser();
    try {
      await browser.go(`${web.origin}/login`);
      const first = (await browser.go(`${web.origin}/token`)).body;
      assert.notEqual(first, 'none');

      // A fresh token is reused: refreshing per request would double every page's cost.
      assert.equal((await browser.go(`${web.origin}/token`)).body, first);

      await expireStoredToken(web, browser);
      const renewed = (await browser.go(`${web.origin}/token`)).body;
      assert.notEqual(renewed, first, 'the stale token was renewed rather than handed out dead');
      assert.equal((await browser.go(`${web.origin}/`)).body, 'signed in as alice@example.com');
    } finally {
      await web.close();
    }
  });

  test('concurrent requests share one refresh, so rotation does not revoke the family', async () => {
    const web = await startApp();
    const browser = new Browser();
    try {
      await browser.go(`${web.origin}/login`);
      await expireStoredToken(web, browser);
      const cookie = browser.cookieHeader();

      // Ten requests arrive at once with the access token already stale. Serialised into a single
      // refresh they all succeed; racing, they would present the same rotated refresh token more
      // than once, and the server would read that as theft and revoke the whole family.
      idp.grants.length = 0;
      const bodies = await Promise.all(
        Array.from({ length: 10 }, async () => (await fetch(`${web.origin}/token`, { headers: { cookie } })).text())
      );

      assert.equal(idp.grants.filter((g) => g === 'refresh_token').length, 1, 'exactly one refresh for the burst');
      assert.equal(new Set(bodies).size, 1, 'and every request got the same new token');
      assert.ok(!bodies.includes('none'));

      const stillIn = await browser.go(`${web.origin}/`);
      assert.equal(stillIn.body, 'signed in as alice@example.com');
    } finally {
      await web.close();
    }
  });

  test('a session whose refresh token has been revoked is dropped', async () => {
    const web = await startApp();
    const browser = new Browser();
    try {
      await browser.go(`${web.origin}/login`);
      await expireStoredToken(web, browser);
      // Everything the session could refresh with is gone at the provider.
      idp.refreshTokens.clear();

      const result = await browser.go(`${web.origin}/`);
      assert.equal(result.body, 'anonymous');
      assert.equal(browser.cookies.has('ark_session'), false, 'the cookie is cleared too');
    } finally {
      await web.close();
    }
  });
});

describe('protecting an API with arkBearer', () => {
  async function apiFixture(options = {}) {
    const client = new ArkOAuthClient({ authority: idp.issuer, clientId: 'confidential-app', clientSecret: 'top-secret', audience: 'test_idp_api' });
    const bearer = arkBearer({ client, ...options });
    const server = app(
      bearer,
      route('/me', (req, res) => {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ sub: req.ark.sub, clientId: req.ark.clientId, claims: req.ark.claims }));
      }),
      route('/reports', (req, res, next) => bearer.require({ claims: ['reports.read'] })(req, res, next), (req, res) => res.end('reports')),
      route('/admin', (req, res, next) => bearer.require({ claims: ['tenant.root'] })(req, res, next), (req, res) => res.end('admin'))
    );
    const origin = await serve(server);
    return { origin, client, close: () => new Promise((resolve) => server.close(resolve)) };
  }

  async function userToken() {
    const client = new ArkOAuthClient({ authority: idp.issuer, clientId: 'web-app', redirectUri: 'http://127.0.0.1:9999/signin-oidc' });
    const tx = await client.createAuthorizationUrl();
    const authorize = await fetch(tx.url, { redirect: 'manual' });
    const params = Object.fromEntries(new URL(authorize.headers.get('location')).searchParams);
    return (await client.handleCallback(params, tx)).accessToken;
  }

  test('accepts a valid token and exposes its subject and claims', async () => {
    const api = await apiFixture();
    try {
      const token = await userToken();
      const response = await fetch(`${api.origin}/me`, { headers: { authorization: `Bearer ${token}` } });
      assert.equal(response.status, 200);
      const body = await response.json();
      assert.equal(body.sub, 'alice@example.com');
      assert.equal(body.clientId, 'web-app');
      assert.deepEqual(body.claims, ['billing.admin', 'reports.read']);
    } finally {
      await api.close();
    }
  });

  test('challenges a missing, malformed or foreign token', async () => {
    const api = await apiFixture();
    try {
      const none = await fetch(`${api.origin}/me`);
      assert.equal(none.status, 401);
      assert.match(none.headers.get('www-authenticate'), /error="invalid_token"/);

      const garbage = await fetch(`${api.origin}/me`, { headers: { authorization: 'Bearer not-a-jwt' } });
      assert.equal(garbage.status, 401);

      const other = await new StubIdp({ tenant: 'test_idp' }).listen();
      try {
        const otherClient = new ArkOAuthClient({ authority: other.issuer, clientId: 'web-app', redirectUri: 'http://127.0.0.1:9999/signin-oidc' });
        const tx = await otherClient.createAuthorizationUrl();
        const authorize = await fetch(tx.url, { redirect: 'manual' });
        const params = Object.fromEntries(new URL(authorize.headers.get('location')).searchParams);
        const foreign = (await otherClient.handleCallback(params, tx)).accessToken;

        const response = await fetch(`${api.origin}/me`, { headers: { authorization: `Bearer ${foreign}` } });
        assert.equal(response.status, 401, 'a token from another provider is not this API\'s token');
      } finally {
        await other.close();
      }
    } finally {
      await api.close();
    }
  });

  test('a per-route claim requirement answers 403, not 401', async () => {
    const api = await apiFixture();
    try {
      const token = await userToken();
      const allowed = await fetch(`${api.origin}/reports`, { headers: { authorization: `Bearer ${token}` } });
      assert.equal(allowed.status, 200);

      const denied = await fetch(`${api.origin}/admin`, { headers: { authorization: `Bearer ${token}` } });
      assert.equal(denied.status, 403);
      assert.match(denied.headers.get('www-authenticate'), /insufficient_scope/);
    } finally {
      await api.close();
    }
  });

  test('optional mode lets an anonymous request through', async () => {
    const api = await apiFixture({ optional: true });
    try {
      const response = await fetch(`${api.origin}/me`);
      assert.equal(response.status, 200);
      assert.equal((await response.json()).sub, undefined);
    } finally {
      await api.close();
    }
  });
});

describe('session cookies', () => {
  test('the cookie is HttpOnly, SameSite=Lax and carries only a signed id', async () => {
    const web = await startApp();
    try {
      const response = await fetch(`${web.origin}/login`, { redirect: 'manual' });
      const [cookie] = response.headers.getSetCookie();
      assert.match(cookie, /HttpOnly/);
      assert.match(cookie, /SameSite=Lax/);
      const value = parseCookies(cookie.split(';')[0]).ark_session;
      assert.match(value, /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/, 'an opaque id and its signature, nothing else');
    } finally {
      await web.close();
    }
  });

  test('a tampered cookie is treated as no session at all', async () => {
    const web = await startApp();
    const browser = new Browser();
    try {
      await browser.go(`${web.origin}/login`);
      const good = browser.cookies.get('ark_session');
      const tampered = `${good.split('.')[0]}xyz.${good.split('.')[1]}`;

      const response = await fetch(`${web.origin}/`, { headers: { cookie: `ark_session=${tampered}` } });
      assert.equal(await response.text(), 'anonymous');
    } finally {
      await web.close();
    }
  });
});

/** A store that copies on every read and write, as Redis or a database table does. */
class SerializingStore {
  #map = new Map();
  async get(id) {
    const raw = this.#map.get(id);
    return raw ? JSON.parse(raw) : null;
  }
  async set(id, data) {
    this.#map.set(id, JSON.stringify(data));
  }
  async destroy(id) {
    this.#map.delete(id);
  }
}

describe('token freshness against a store that copies', () => {
  test('a request that waited on another refresh never presents the retired refresh token', async () => {
    const store = new SerializingStore();
    const web = await startApp({ store });
    const browser = new Browser();
    try {
      await browser.go(`${web.origin}/login`);
      const id = unsignSessionId(browser.cookies.get('ark_session'), 'a-test-secret-of-sufficient-length');
      const session = await store.get(id);
      session.tokens.expires_at = Math.floor(Date.now() / 1000) - 10;
      await store.set(id, session);

      // Each request loads its own copy. The one that waits on the other's refresh must come away
      // holding the rotated tokens, or its second read re-presents the retired refresh token and
      // the provider revokes the family.
      idp.grants.length = 0;
      const cookie = browser.cookieHeader();
      const bodies = await Promise.all(
        Array.from({ length: 4 }, async () => (await fetch(`${web.origin}/token-twice`, { headers: { cookie } })).text())
      );

      assert.equal(idp.grants.filter((g) => g === 'refresh_token').length, 1, 'one refresh for the burst');
      for (const body of bodies) {
        const [first, second] = body.split('|');
        assert.notEqual(first, 'none');
        assert.equal(first, second, 'the second read is served from the rotated tokens');
      }
      assert.equal((await browser.go(`${web.origin}/`)).body, 'signed in as alice@example.com', 'the family survived');
    } finally {
      await web.close();
    }
  });

  test('a transient refresh failure keeps the session rather than failing the request', async () => {
    const store = new SerializingStore();
    const web = await startApp({ store });
    const browser = new Browser();
    try {
      await browser.go(`${web.origin}/login`);
      const id = unsignSessionId(browser.cookies.get('ark_session'), 'a-test-secret-of-sufficient-length');
      const session = await store.get(id);
      session.tokens.expires_at = Math.floor(Date.now() / 1000) + 30; // inside the refresh window
      await store.set(id, session);

      const realFetch = globalThis.fetch;
      globalThis.fetch = (url, init) =>
        String(url).includes('/oauth2/token') ? Promise.reject(new TypeError('connect ECONNREFUSED')) : realFetch(url, init);
      let result;
      try {
        result = await browser.go(`${web.origin}/`);
      } finally {
        globalThis.fetch = realFetch;
      }
      assert.equal(result.response.status, 200);
      assert.equal(result.body, 'signed in as alice@example.com');
    } finally {
      await web.close();
    }
  });
});

describe('account switching on a shared browser', () => {
  const ALICE = { sub: 'alice@example.com', name: 'Alice Example', email: 'alice@example.com', email_verified: true };
  const BOB = { sub: 'bob@example.com', name: 'Bob Example', email: 'bob@example.com', email_verified: true };
  const CLAIMS = ['billing.admin', 'reports.read'];

  /** Runs a test with the provider's user and claims changed, restoring them afterwards. */
  async function withProvider({ user = ALICE, arkClaims = CLAIMS } = {}, fn) {
    idp.user = { ...user };
    idp.arkClaims = [...arkClaims];
    try {
      await fn();
    } finally {
      idp.user = { ...ALICE };
      idp.arkClaims = [...CLAIMS];
    }
  }

  const requireClaims = { accountSwitch: { requireArkClaims: true, appDisplayName: 'Billing <Portal>' } };

  test('an account with no ark_claims is refused at the callback, before any session is written', () =>
    withProvider({ arkClaims: [] }, async () => {
      const web = await startApp({ authOptions: requireClaims });
      const browser = new Browser();
      try {
        const result = await browser.go(`${web.origin}/login?returnTo=/profile`);
        assert.equal(result.response.status, 403);
        assert.equal(new URL(result.url).pathname, '/ark/no-access');
        assert.match(result.body, /You are signed in as <strong>alice@example\.com<\/strong>/);
        assert.match(result.body, /Billing &lt;Portal&gt;/, 'the display name is escaped');
        assert.match(result.body, /action="\/ark\/switch-user"/);
        assert.match(result.body, /name="returnUrl" value="\/profile"/);
        assert.match(result.body, /ark-oauth-client \d+\.\d+\.\d+/);
        assert.match(result.response.headers.get('content-security-policy'), /default-src 'none'/);
        assert.equal(result.response.headers.get('cache-control'), 'no-store');

        assert.equal((await browser.go(`${web.origin}/`)).body, 'anonymous', 'nobody is signed in');
        assert.equal(browser.cookies.has('ark_denied'), false, 'the denial cookie is spent on read');
        const id = unsignSessionId(browser.cookies.get('ark_session'), 'a-test-secret-of-sufficient-length');
        assert.equal((await web.store.get(id))?.tokens, undefined, 'the session holds no tokens for the refused account');
      } finally {
        await web.close();
      }
    }));

  test('the same account signs in when the check is off, so an upgrade changes nothing', () =>
    withProvider({ arkClaims: [] }, async () => {
      const web = await startApp();
      const browser = new Browser();
      try {
        assert.equal((await browser.go(`${web.origin}/login`)).body, 'signed in as alice@example.com');
      } finally {
        await web.close();
      }
    }));

  test('"sign in as a different user" challenges with prompt=login and completes as the new account', () =>
    withProvider({ arkClaims: [] }, async () => {
      const web = await startApp({ authOptions: requireClaims });
      const browser = new Browser();
      try {
        const denied = await browser.go(`${web.origin}/login?returnTo=/profile`);
        assert.equal(denied.response.status, 403);

        // Bob sits down. The provider would answer from Alice's session unless told prompt=login.
        idp.user = { ...BOB };
        idp.arkClaims = [...CLAIMS];
        idp.authorizeRequests.length = 0;
        const switched = await browser.post(`${web.origin}/ark/switch-user`, { returnUrl: '/profile' });

        assert.equal(idp.authorizeRequests.at(-1).prompt, 'login', 'without this the old session answers');
        assert.equal(new URL(switched.url).pathname, '/profile');
        assert.equal(JSON.parse(switched.body).sub, 'bob@example.com');
      } finally {
        await web.close();
      }
    }));

  test('switching drops the previous session before the challenge, and revokes its refresh token', async () => {
    const web = await startApp();
    const browser = new Browser();
    try {
      await browser.go(`${web.origin}/login`);
      const before = unsignSessionId(browser.cookies.get('ark_session'), 'a-test-secret-of-sufficient-length');
      const { refresh_token: refreshToken } = (await web.store.get(before)).tokens;

      const out = await browser.post(`${web.origin}/ark/switch-user`, { returnUrl: '/' }, { follow: false });
      assert.match(out.location, /\/oauth2\/authorize\?/);
      assert.equal(await web.store.get(before), null, 'the old session is gone');
      assert.equal(idp.refreshTokens.has(refreshToken), false, 'and its refresh token is dead at the provider');
    } finally {
      await web.close();
    }
  });

  test('the switch and sign-out endpoints accept only a same-origin POST', async () => {
    const web = await startApp();
    try {
      const get = await fetch(`${web.origin}/ark/switch-user`, { redirect: 'manual' });
      assert.equal(get.status, 405);
      assert.equal(get.headers.get('allow'), 'POST');

      const crossSite = await fetch(`${web.origin}/ark/sign-out`, {
        method: 'POST',
        redirect: 'manual',
        headers: { 'sec-fetch-site': 'cross-site' }
      });
      assert.equal(crossSite.status, 400);

      const foreignOrigin = await fetch(`${web.origin}/ark/switch-user`, {
        method: 'POST',
        redirect: 'manual',
        headers: { origin: 'https://evil.example.com' }
      });
      assert.equal(foreignOrigin.status, 400);
    } finally {
      await web.close();
    }
  });

  test('an off-site returnUrl on the switch is replaced with the home path', async () => {
    const web = await startApp();
    const browser = new Browser();
    try {
      for (const sneaky of ['//evil.example.com', 'https://evil.example.com', '/\\evil.example.com']) {
        const result = await browser.post(`${web.origin}/ark/switch-user`, { returnUrl: sneaky });
        assert.equal(result.url, `${web.origin}/`, `${JSON.stringify(sneaky)} must not be followed`);
      }
    } finally {
      await web.close();
    }
  });

  test('"sign out completely" ends the provider session too', async () => {
    const web = await startApp();
    const browser = new Browser();
    try {
      await browser.go(`${web.origin}/login`);
      const out = await browser.post(`${web.origin}/ark/sign-out`, { returnUrl: '/' }, { follow: false });
      assert.match(out.location, /\/oauth2\/logout\?/);
      assert.equal(browser.cookies.has('ark_session'), false);
    } finally {
      await web.close();
    }
  });

  test('a signed-in browser missing a claim reaches the page, not a bare 403', async () => {
    const web = await startApp();
    const browser = new Browser();
    try {
      await browser.go(`${web.origin}/login`);
      const result = await browser.go(`${web.origin}/secrets`, { headers: { accept: 'text/html' } });
      assert.equal(result.response.status, 403);
      assert.equal(new URL(result.url).pathname, '/ark/no-access');
      assert.match(result.body, /alice@example\.com/);
      assert.match(result.body, /name="returnUrl" value="\/secrets"/);

      // An API caller still gets JSON it can act on.
      const api = await browser.go(`${web.origin}/secrets`, { headers: { accept: 'application/json' } });
      assert.equal(api.response.status, 403);
      assert.equal(JSON.parse(api.body).error, 'insufficient_scope');
    } finally {
      await web.close();
    }
  });

  test('onEvaluateAccess replaces the configured rule', () =>
    withProvider({ arkClaims: ['something.else'] }, async () => {
      const seen = [];
      const web = await startApp({
        authOptions: {
          events: {
            onEvaluateAccess: async (ctx) => {
              seen.push(ctx);
              return ctx.arkClaims.includes('billing.admin');
            }
          }
        }
      });
      const browser = new Browser();
      try {
        const result = await browser.go(`${web.origin}/login`);
        assert.equal(result.response.status, 403, 'refused by the rule even though requireArkClaims is off');
        assert.equal(seen[0].allowedByConfiguration, true);
        assert.equal(seen[0].claims.email, 'alice@example.com');
      } finally {
        await web.close();
      }
    }));

  test('onAccessDenied can draw a page of its own', () =>
    withProvider({ arkClaims: [] }, async () => {
      const web = await startApp({
        authOptions: {
          ...requireClaims,
          events: {
            onAccessDenied: (denied, req, res) => {
              res.statusCode = 451;
              res.end(`no entry for ${denied.email} (${denied.reason})`);
            }
          }
        }
      });
      const browser = new Browser();
      try {
        const result = await browser.go(`${web.origin}/login`);
        assert.equal(result.response.status, 451);
        assert.equal(result.body, 'no entry for alice@example.com (no_app_access)');
      } finally {
        await web.close();
      }
    }));

  test('a tampered denial cookie is ignored and the page stays unnamed', async () => {
    const web = await startApp();
    const browser = new Browser();
    try {
      browser.cookies.set('ark_denied', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
      const result = await browser.go(`${web.origin}/ark/no-access`);
      assert.equal(result.response.status, 403);
      assert.match(result.body, /The account you are signed in with does not have access/);
    } finally {
      await web.close();
    }
  });

  test('form_post with a SameSite=Lax cookie is refused at startup, since it can never work', () => {
    assert.throws(
      () =>
        arkExpress({
          authority: idp.issuer,
          clientId: 'web-app',
          responseMode: 'form_post',
          secret: 'a-test-secret-of-sufficient-length'
        }),
      /sameSite: 'None'/
    );
  });
});

describe('hardening', () => {
  test('a bearer token whose kid carries CR/LF is refused cleanly, not with a crash', async () => {
    const server = app(arkBearer({ authority: idp.issuer, clientId: 'web-app', requireHttps: false }), (req, res) => res.end('ok'));
    const origin = await serve(server);
    try {
      const header = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'x\r\nSet-Cookie: pwned=1' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ sub: 'x' })).toString('base64url');
      const response = await fetch(`${origin}/`, { headers: { authorization: `Bearer ${header}.${payload}.sig` } });
      assert.equal(response.status, 401);
      const challenge = response.headers.get('www-authenticate');
      assert.ok(challenge.startsWith('Bearer realm="ark", error="invalid_token"'));
      assert.doesNotMatch(challenge, /[\r\n]/);
      assert.equal(response.headers.get('set-cookie'), null);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  test('a form_post callback larger than any sign-in response is refused', async () => {
    const web = await startApp();
    try {
      const response = await fetch(`${web.origin}/signin-oidc`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: `state=${'x'.repeat(70 * 1024)}`
      });
      assert.equal(response.status, 400);
      assert.match(await response.text(), /larger than any sign-in response/);
    } finally {
      await web.close();
    }
  });

  test('a provider error that arrives without state still names the real problem', async () => {
    const web = await startApp();
    try {
      // What the real host sends when it refuses the request outright: error, iss, and no state.
      const response = await fetch(`${web.origin}/signin-oidc?error=invalid_request&error_description=code_challenge%20is%20required%20(PKCE).`);
      assert.equal(response.status, 400);
      assert.match(await response.text(), /invalid_request: code_challenge is required/);
    } finally {
      await web.close();
    }
  });

  test('a callback whose state names an inherited property is not mistaken for a transaction', async () => {
    const web = await startApp();
    const browser = new Browser();
    try {
      await browser.go(`${web.origin}/login`, { follow: false });
      const result = await browser.go(`${web.origin}/signin-oidc?state=__proto__&code=x`);
      assert.equal(result.response.status, 400);
      assert.match(result.body, /could not be matched/);
    } finally {
      await web.close();
    }
  });

  test('one forwarded header without the other does not move the redirect URI', async () => {
    const built = buildApp();
    const origin = await serve(built.server);
    built.holder.auth = arkExpress({
      authority: idp.issuer,
      clientId: 'web-app',
      requireHttps: false,
      secret: 'a-test-secret-of-sufficient-length',
      store: built.store,
      cookie: { secure: false }
    });
    try {
      const response = await fetch(`${origin}/login`, { redirect: 'manual', headers: { 'x-forwarded-host': 'evil.example.com' } });
      const redirectUri = new URL(response.headers.get('location')).searchParams.get('redirect_uri');
      assert.equal(redirectUri, `${origin}/signin-oidc`);
    } finally {
      await new Promise((resolve) => built.server.close(resolve));
    }
  });
});
