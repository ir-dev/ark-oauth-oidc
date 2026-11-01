import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { ArkOAuthClient } from '../src/client.js';
import { arkBearer, arkExpress } from '../src/express.js';
import { MemorySessionStore, parseCookies, unsignSessionId } from '../src/session.js';
import { StubIdp } from './stub-idp.js';

let idp;

before(async () => {
  idp = await new StubIdp().listen();
});
after(async () => {
  await idp.close();
});

/**
 * The smallest thing that behaves like Express: a middleware chain over node:http, so the tests
 * exercise the middleware exactly as a real application mounts it — without depending on Express.
 */
function app(...middlewares) {
  const server = createServer((req, res) => {
    let i = 0;
    const next = (error) => {
      if (error) {
        res.statusCode = 500;
        return res.end(`error: ${error.message}`);
      }
      const handler = middlewares[i++];
      if (!handler) {
        res.statusCode = 404;
        return res.end('not found');
      }
      Promise.resolve(handler(req, res, next)).catch(next);
    };
    next();
  });
  return server;
}

function route(path, ...handlers) {
  return (req, res, next) => {
    if (new URL(req.url, 'http://x').pathname !== path) return next();
    let i = 0;
    const step = () => {
      const handler = handlers[i++];
      return handler ? handler(req, res, step) : undefined;
    };
    return step();
  };
}

/** A browser: keeps cookies, follows redirects, and reports where it ended up. */
class Browser {
  constructor() {
    this.cookies = new Map();
  }

  cookieHeader() {
    return [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
  }

  async go(url, { method = 'GET', maxRedirects = 10, headers = {}, follow = true } = {}) {
    let current = url;
    const trail = [];
    for (let i = 0; i <= maxRedirects; i += 1) {
      const response = await fetch(current, {
        method,
        redirect: 'manual',
        headers: { ...headers, ...(this.cookies.size ? { cookie: this.cookieHeader() } : {}) }
      });

      for (const raw of response.headers.getSetCookie?.() ?? []) {
        const [pair] = raw.split(';');
        const eq = pair.indexOf('=');
        const name = pair.slice(0, eq).trim();
        const value = pair.slice(eq + 1).trim();
        if (value === '' || /max-age=0/i.test(raw)) this.cookies.delete(name);
        else this.cookies.set(name, value);
      }

      trail.push({ url: current, status: response.status });
      const location = response.headers.get('location');
      if (!follow) return { response, location, body: await response.text(), url: current, trail };
      if (response.status >= 300 && response.status < 400 && location) {
        current = new URL(location, current).toString();
        method = 'GET';
        continue;
      }
      return { response, body: await response.text(), url: current, trail };
    }
    throw new Error('too many redirects');
  }
}

async function serve(server) {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${server.address().port}`;
}

function buildApp({ authOptions = {}, clientOptions = {} } = {}) {
  const store = new MemorySessionStore({ sweepIntervalMs: 0 });
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
