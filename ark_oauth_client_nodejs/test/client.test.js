import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { ArkOAuthClient } from '../src/client.js';
import { ArkCallbackError, ArkOAuthError, ArkTokenError } from '../src/errors.js';
import { createServer } from 'node:http';
import { StubIdp } from './stub-idp.js';

let idp;
const CALLBACK = 'http://127.0.0.1:9999/signin-oidc';

before(async () => {
  idp = await new StubIdp().listen();
});
after(async () => {
  await idp.close();
});

function publicClient(overrides = {}) {
  return new ArkOAuthClient({
    authority: idp.issuer,
    clientId: 'web-app',
    redirectUri: CALLBACK,
    scopes: ['openid', 'profile', 'email', 'offline_access'],
    ...overrides
  });
}

function confidentialClient(overrides = {}) {
  return new ArkOAuthClient({
    authority: idp.issuer,
    clientId: 'confidential-app',
    clientSecret: 'top-secret',
    redirectUri: CALLBACK,
    ...overrides
  });
}

/** Plays the part of the browser: follows the authorization redirect and returns the callback query. */
async function visit(url) {
  const response = await fetch(url, { redirect: 'manual' });
  const location = response.headers.get('location');
  assert.ok(location, `expected a redirect from ${url}, got HTTP ${response.status}`);
  return Object.fromEntries(new URL(location).searchParams);
}

describe('discovery', () => {
  test('reads the document and caches it', async () => {
    const client = publicClient();
    const first = await client.metadata();
    assert.equal(first.issuer, idp.issuer);
    assert.equal(first.token_endpoint, `${idp.issuer}/oauth2/token`);

    const before = idp.requests.filter((r) => r.path.includes('openid-configuration')).length;
    await client.metadata();
    const after = idp.requests.filter((r) => r.path.includes('openid-configuration')).length;
    assert.equal(after, before, 'a second call should be served from cache');
  });

  test('a trailing slash on the authority is normalised away', async () => {
    const client = new ArkOAuthClient({ authority: `${idp.baseUrl}/test_idp/`, clientId: 'web-app' });
    assert.equal((await client.metadata()).issuer, idp.issuer);
  });

  test('refuses a provider whose issuer is not the configured authority', async () => {
    // A document that names a different issuer than the URL it was read from is the shape of a
    // mix-up attack, and far more often a stray path segment in configuration.
    const liar = createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ issuer: 'https://somewhere.else/tenant', token_endpoint: 'https://somewhere.else/tenant/oauth2/token' }));
    });
    await new Promise((resolve) => liar.listen(0, '127.0.0.1', resolve));
    try {
      const client = new ArkOAuthClient({ authority: `http://127.0.0.1:${liar.address().port}/my_idp`, clientId: 'web-app' });
      await assert.rejects(() => client.metadata(), /identifies itself as 'https:\/\/somewhere\.else\/tenant'/);
    } finally {
      await new Promise((resolve) => liar.close(resolve));
    }
  });
});

describe('authorization code + PKCE', () => {
  test('the authorization URL carries everything the server requires', async () => {
    const client = publicClient();
    const tx = await client.createAuthorizationUrl({ loginHint: 'alice@example.com', maxAge: 300 });
    const url = new URL(tx.url);

    assert.equal(url.pathname, `/${idp.tenant}/oauth2/authorize`);
    assert.equal(url.searchParams.get('response_type'), 'code');
    assert.equal(url.searchParams.get('client_id'), 'web-app');
    assert.equal(url.searchParams.get('redirect_uri'), CALLBACK);
    assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
    assert.equal(url.searchParams.get('scope'), 'openid profile email offline_access');
    assert.equal(url.searchParams.get('state'), tx.state);
    assert.equal(url.searchParams.get('nonce'), tx.nonce);
    assert.equal(url.searchParams.get('login_hint'), 'alice@example.com');
    assert.equal(url.searchParams.get('max_age'), '300');
    // The verifier is the one thing that must never appear in the URL.
    assert.ok(!tx.url.includes(tx.codeVerifier));
  });

  test('completes a sign-in and validates the ID token', async () => {
    const client = publicClient();
    const tx = await client.createAuthorizationUrl();
    const tokens = await client.handleCallback(await visit(tx.url), tx);

    assert.ok(tokens.accessToken);
    assert.ok(tokens.refreshToken, 'offline_access was granted, so a refresh token is expected');
    assert.ok(tokens.idToken);
    assert.equal(tokens.tokenType, 'Bearer');
    assert.equal(tokens.claims.sub, 'alice@example.com');
    assert.equal(tokens.claims.nonce, tx.nonce);
    assert.equal(tokens.claims.aud, 'web-app');
    assert.equal(tokens.subject, 'alice@example.com');
    assert.ok(tokens.expiresIn() > 3500);
    assert.deepEqual(tokens.arkClaims(), ['billing.admin', 'reports.read']);
    assert.ok(tokens.hasScope('openid', 'offline_access'));
  });

  test('a mismatched state is refused before the code is redeemed', async () => {
    const client = publicClient();
    const tx = await client.createAuthorizationUrl();
    const params = await visit(tx.url);

    await assert.rejects(
      () => client.handleCallback({ ...params, state: 'not-the-state-we-sent' }, tx),
      (error) => error instanceof ArkCallbackError && /CSRF/.test(error.message)
    );

    // The code was never presented, so it is still redeemable — proof the check ran first.
    const tokens = await client.handleCallback(params, tx);
    assert.ok(tokens.accessToken);
  });

  test('a response from another issuer is refused (RFC 9207)', async () => {
    const client = publicClient();
    const tx = await client.createAuthorizationUrl();
    const params = await visit(tx.url);

    await assert.rejects(
      () => client.handleCallback({ ...params, iss: 'https://evil.example.com/idp' }, tx),
      (error) => error instanceof ArkCallbackError && /came from/.test(error.message)
    );
    await assert.rejects(
      () => client.handleCallback({ ...params, iss: undefined }, tx),
      /advertises `iss`/
    );
  });

  test('an error response surfaces as the error the server sent', async () => {
    const client = publicClient();
    const tx = await client.createAuthorizationUrl();
    await assert.rejects(
      () => client.handleCallback({ state: tx.state, error: 'access_denied', error_description: 'the user denied the request.' }, tx),
      (error) => error instanceof ArkOAuthError && error.error === 'access_denied'
    );
  });

  test('the wrong PKCE verifier is rejected by the server', async () => {
    const client = publicClient();
    const tx = await client.createAuthorizationUrl();
    const params = await visit(tx.url);

    const attacker = { ...tx, codeVerifier: 'x'.repeat(43) };
    await assert.rejects(
      () => client.handleCallback(params, attacker),
      (error) => error instanceof ArkOAuthError && error.error === 'invalid_grant'
    );
  });

  test('a code cannot be redeemed twice', async () => {
    const client = publicClient();
    const tx = await client.createAuthorizationUrl();
    const params = await visit(tx.url);

    await client.handleCallback(params, tx);
    await assert.rejects(
      () => client.handleCallback(params, tx),
      (error) => error instanceof ArkOAuthError && /already been used/.test(error.errorDescription)
    );
  });

  test('a callback with no transaction is refused rather than guessed at', async () => {
    const client = publicClient();
    await assert.rejects(() => client.handleCallback({ code: 'x', state: 'y' }, null), /no login transaction/);
  });

  test('reads callback parameters from a URL, a query string or a parsed body', () => {
    const expected = { code: 'abc', state: 'xyz' };
    assert.deepEqual(ArkOAuthClient.readCallbackParams('https://app/cb?code=abc&state=xyz'), expected);
    assert.deepEqual(ArkOAuthClient.readCallbackParams('?code=abc&state=xyz'), expected);
    assert.deepEqual(ArkOAuthClient.readCallbackParams(new URLSearchParams('code=abc&state=xyz')), expected);
    assert.deepEqual(ArkOAuthClient.readCallbackParams({ code: 'abc', state: 'xyz' }), expected);
  });
});

describe('refresh', () => {
  test('rotates the refresh token and reissues the ID token', async () => {
    const client = publicClient();
    const tx = await client.createAuthorizationUrl();
    const first = await client.handleCallback(await visit(tx.url), tx);

    const second = await client.refresh(first.refreshToken);
    assert.ok(second.accessToken);
    assert.notEqual(second.refreshToken, first.refreshToken, 'rotation should return a new refresh token');
    assert.equal(second.claims.sub, 'alice@example.com');
  });

  test('replaying a retired refresh token revokes the family', async () => {
    const client = publicClient();
    const tx = await client.createAuthorizationUrl();
    const first = await client.handleCallback(await visit(tx.url), tx);
    const second = await client.refresh(first.refreshToken);

    await assert.rejects(
      () => client.refresh(first.refreshToken),
      (error) => error instanceof ArkOAuthError && error.error === 'invalid_grant'
    );
    // The whole family went with it, so the token that was legitimately current is dead too.
    await assert.rejects(() => client.refresh(second.refreshToken), /invalid_grant/);
  });

  test('scope may be narrowed but never widened', async () => {
    const client = publicClient();
    const tx = await client.createAuthorizationUrl();
    const tokens = await client.handleCallback(await visit(tx.url), tx);

    const narrowed = await client.refresh(tokens.refreshToken, { scopes: ['openid', 'offline_access'] });
    assert.deepEqual(narrowed.scopes(), ['openid', 'offline_access']);

    await assert.rejects(
      () => client.refresh(narrowed.refreshToken, { scopes: ['openid', 'offline_access', 'admin'] }),
      (error) => error instanceof ArkOAuthError && error.error === 'invalid_scope'
    );
  });
});

describe('client credentials', () => {
  test('authenticates with client_secret_basic and caches the token', async () => {
    const client = confidentialClient();
    const first = await client.clientCredentials({ scopes: ['reports.read'] });
    assert.ok(first.accessToken);
    assert.equal(first.refreshToken, null, 'RFC 6749 §4.4.3: no refresh token for this grant');
    assert.equal(first.subject, 'confidential-app', 'the client acts as itself');

    const second = await client.clientCredentials({ scopes: ['reports.read'] });
    assert.equal(second.accessToken, first.accessToken, 'the second call should be served from cache');

    const forced = await client.clientCredentials({ scopes: ['reports.read'], force: true });
    assert.notEqual(forced.accessToken, first.accessToken);
  });

  test('client_secret_post is sent in the body when the client is registered for it', async () => {
    const client = new ArkOAuthClient({
      authority: idp.issuer,
      clientId: 'post-app',
      clientSecret: 'post-secret',
      tokenEndpointAuthMethod: 'client_secret_post'
    });
    assert.ok((await client.clientCredentials()).accessToken);
  });

  test('a public client is told why it cannot use the grant', async () => {
    await assert.rejects(() => publicClient().clientCredentials(), /requires client authentication/);
  });

  test('a bad secret comes back as invalid_client', async () => {
    const client = confidentialClient({ clientSecret: 'wrong' });
    await assert.rejects(
      () => client.clientCredentials(),
      (error) => error instanceof ArkOAuthError && error.error === 'invalid_client' && error.status === 401
    );
  });
});

describe('userinfo, introspection, revocation and logout', () => {
  test('userinfo returns the claims the scopes unlocked', async () => {
    const client = publicClient();
    const tx = await client.createAuthorizationUrl();
    const tokens = await client.handleCallback(await visit(tx.url), tx);

    const info = await client.userInfo(tokens.accessToken);
    assert.equal(info.sub, 'alice@example.com');
    assert.equal(info.email, 'alice@example.com');

    await assert.rejects(() => client.userInfo('not-a-token'), /invalid_token|error/);
  });

  test('introspection reports a live refresh token and an unknown one', async () => {
    const client = confidentialClient();
    const tx = await client.createAuthorizationUrl({ scopes: ['openid', 'offline_access'] });
    const tokens = await client.handleCallback(await visit(tx.url), tx);

    const active = await client.introspect(tokens.refreshToken, { tokenTypeHint: 'refresh_token' });
    assert.equal(active.active, true);
    assert.equal(active.sub, 'alice@example.com');

    const unknown = await client.introspect('nonsense');
    assert.equal(unknown.active, false);
  });

  test('revoking a refresh token ends the family', async () => {
    const client = confidentialClient();
    const tx = await client.createAuthorizationUrl({ scopes: ['openid', 'offline_access'] });
    const tokens = await client.handleCallback(await visit(tx.url), tx);

    assert.equal(await client.revoke(tokens.refreshToken), true);
    await assert.rejects(() => client.refresh(tokens.refreshToken), /invalid_grant/);
    // §2.2: revoking something unknown is still a success.
    assert.equal(await client.revoke('never-existed'), true);
  });

  test('the end-session URL carries the hint, the return address and state', async () => {
    const client = publicClient({ postLogoutRedirectUri: 'http://127.0.0.1:9999/signed-out' });
    const url = new URL(await client.endSessionUrl({ idTokenHint: 'the.id.token', state: 's1' }));
    assert.equal(url.pathname, `/${idp.tenant}/oauth2/logout`);
    assert.equal(url.searchParams.get('id_token_hint'), 'the.id.token');
    assert.equal(url.searchParams.get('post_logout_redirect_uri'), 'http://127.0.0.1:9999/signed-out');
    assert.equal(url.searchParams.get('client_id'), 'web-app');
    assert.equal(url.searchParams.get('state'), 's1');
  });
});

describe('device authorization grant', () => {
  test('polls through authorization_pending and slow_down to a token', async () => {
    const client = confidentialClient();
    const authorization = await client.deviceAuthorization({ scopes: ['openid', 'profile'] });

    assert.ok(authorization.device_code);
    assert.equal(authorization.user_code, 'WDJB-MJHT');
    assert.ok(authorization.verification_uri_complete.includes(authorization.user_code));

    const pending = [];
    const polling = client.pollDeviceToken(authorization, { onPending: (e) => pending.push(e.error) });

    // The user takes their time, then the server asks us to slow down, then they approve.
    await new Promise((resolve) => setTimeout(resolve, 30));
    idp.deviceCodes.get(authorization.device_code).status = 'slow_down';
    await new Promise((resolve) => setTimeout(resolve, 30));
    idp.deviceCodes.get(authorization.device_code).status = 'approved';

    const tokens = await polling;
    assert.ok(tokens.accessToken);
    assert.equal(tokens.claims.sub, 'alice@example.com');
    assert.ok(pending.includes('authorization_pending'));
    assert.ok(pending.includes('slow_down'));
  });

  test('a denied request ends the poll with access_denied', async () => {
    const client = confidentialClient();
    const authorization = await client.deviceAuthorization({ scopes: ['openid'] });
    idp.deviceCodes.get(authorization.device_code).status = 'denied';
    await assert.rejects(
      () => client.pollDeviceToken(authorization),
      (error) => error instanceof ArkOAuthError && error.error === 'access_denied'
    );
  });
});

describe('pushed authorization requests', () => {
  test('the browser only ever sees a request_uri', async () => {
    const client = confidentialClient({ usePar: true });
    const tx = await client.createAuthorizationUrl();
    const url = new URL(tx.url);

    assert.ok(url.searchParams.get('request_uri').startsWith('urn:ietf:params:oauth:request_uri:'));
    assert.equal(url.searchParams.get('scope'), null, 'the parameters went over the back channel');
    assert.equal(url.searchParams.get('code_challenge'), null);

    const tokens = await client.handleCallback(await visit(tx.url), tx);
    assert.ok(tokens.accessToken);
  });
});

describe('access token verification', () => {
  test('accepts a live token and reads its scopes and ark_claims', async () => {
    const client = publicClient();
    const tx = await client.createAuthorizationUrl();
    const tokens = await client.handleCallback(await visit(tx.url), tx);

    const payload = await client.verifyAccessToken(tokens.accessToken, { audience: 'test_idp_api' });
    assert.equal(payload.sub, 'alice@example.com');
    assert.equal(payload.client_id, 'web-app');
    assert.deepEqual(payload.ark_claims, ['billing.admin', 'reports.read']);

    assert.ok(await client.verifyAccessToken(tokens.accessToken, { scopes: ['openid'], arkClaims: ['billing.admin'] }));
  });

  test('rejects an ID token presented as an access token', async () => {
    const client = publicClient();
    const tx = await client.createAuthorizationUrl();
    const tokens = await client.handleCallback(await visit(tx.url), tx);
    await assert.rejects(() => client.verifyAccessToken(tokens.idToken), /at\+jwt/);
  });

  test('reports missing scopes and claims as insufficient_scope', async () => {
    const client = publicClient();
    const tx = await client.createAuthorizationUrl();
    const tokens = await client.handleCallback(await visit(tx.url), tx);

    await assert.rejects(
      () => client.verifyAccessToken(tokens.accessToken, { scopes: ['admin.everything'] }),
      (error) => error instanceof ArkOAuthError && error.error === 'insufficient_scope' && error.status === 403
    );
    await assert.rejects(
      () => client.verifyAccessToken(tokens.accessToken, { arkClaims: ['not.granted'] }),
      /missing the authorization claim/
    );
  });

  test('follows a key rotation without restarting', async () => {
    // The refetch on an unknown kid is rate-limited; a rotation is exactly the moment that limit
    // has to give way, so the window is set to zero here rather than sleeping through the default.
    const client = publicClient({ jwksMinRefreshIntervalMs: 0 });
    const tx = await client.createAuthorizationUrl();
    const before = await client.handleCallback(await visit(tx.url), tx);
    await client.verifyAccessToken(before.accessToken); // warms the JWKS cache

    idp.rotateKey('key-rotated');
    const tx2 = await client.createAuthorizationUrl();
    const after = await client.handleCallback(await visit(tx2.url), tx2);

    // Signed by a kid the cache has never seen: it refetches rather than failing.
    assert.ok(await client.verifyAccessToken(after.accessToken));
    // And the previous key is still published, so tokens in flight keep validating.
    assert.ok(await client.verifyAccessToken(before.accessToken));
  });

  test('refuses a token signed by a key this provider does not publish', async () => {
    const other = await new StubIdp({ tenant: 'test_idp' }).listen();
    try {
      const otherClient = new ArkOAuthClient({ authority: other.issuer, clientId: 'web-app', redirectUri: CALLBACK });
      const tx = await otherClient.createAuthorizationUrl();
      const foreign = await otherClient.handleCallback(await visit(tx.url), tx);

      await assert.rejects(
        () => publicClient().verifyAccessToken(foreign.accessToken),
        (error) => error instanceof ArkTokenError
      );
    } finally {
      await other.close();
    }
  });
});

describe('dynamic client registration', () => {
  test('registers a client with an initial access token', async () => {
    const machine = confidentialClient();
    const initial = await machine.clientCredentials({ scopes: ['client.register'], force: true });

    const registered = await machine.registerClient(
      { client_name: 'My Service', grant_types: ['client_credentials'], token_endpoint_auth_method: 'client_secret_basic', scope: 'reports.read' },
      initial.accessToken
    );

    assert.ok(registered.client_id);
    assert.ok(registered.client_secret, 'the secret is returned exactly once');
    assert.ok(registered.registration_access_token);
  });

  test('registration without the client.register scope is refused', async () => {
    const machine = confidentialClient();
    const weak = await machine.clientCredentials({ scopes: ['reports.read'], force: true });
    await assert.rejects(
      () => machine.registerClient({ client_name: 'Nope' }, weak.accessToken),
      (error) => error instanceof ArkOAuthError && error.error === 'insufficient_scope'
    );
  });
});

describe('setup probe', () => {
  test('reports a healthy configuration with no problems', async () => {
    const report = await publicClient().checkSetup();
    assert.equal(report.discoveryOk, true);
    assert.equal(report.provider.issuer, idp.issuer);
    assert.deepEqual(report.problems, []);
    assert.ok(report.signingKeys.length >= 1);
  });

  test('names the scopes the tenant does not publish', async () => {
    const report = await publicClient({ scopes: ['openid', 'invented.scope'] }).checkSetup();
    assert.match(report.problems.join(' '), /invented\.scope/);
  });

  test('turns an unreachable provider into a sentence', async () => {
    const dead = new ArkOAuthClient({ authority: 'http://127.0.0.1:1/nowhere', clientId: 'x', requireHttps: false });
    const report = await dead.checkSetup();
    assert.equal(report.discoveryOk, false);
    assert.equal(report.problems.length, 1);
    assert.match(report.problems[0], /discovery document could not be read/);
  });
});
