import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeConfig } from '../src/config.js';
import { codeChallengeFor, createCodeVerifier, createPkcePair, createState } from '../src/pkce.js';
import { localOrDefault } from '../src/access.js';
import { discoveryUrls } from '../src/discovery.js';
import { resolveStorage, MemoryStorage } from '../src/storage.js';
import { ArkConfigError } from '../src/errors.js';

const base = { authority: 'https://idp.example.com/my_idp', clientId: 'spa' };

describe('configuration', () => {
  test('defaults: the Ark callback paths, the four default scopes, query mode, session storage', () => {
    const c = normalizeConfig(base);
    assert.equal(c.redirectUri, '/signin-oidc');
    assert.equal(c.postLogoutRedirectUri, '/signout-callback-oidc');
    assert.deepEqual([...c.scopes], ['openid', 'profile', 'email', 'offline_access']);
    assert.equal(c.responseMode, 'query');
    assert.equal(c.storage, 'session');
    assert.equal(c.accountSwitch.requireArkClaims, false);
  });

  test('authServerUrl + tenantId are joined, a trailing slash is dropped', () => {
    assert.equal(normalizeConfig({ authServerUrl: 'https://idp.example.com/', tenantId: 't1', clientId: 'x' }).authority, 'https://idp.example.com/t1');
    assert.equal(normalizeConfig({ ...base, authority: 'https://idp.example.com/t1/' }).authority, 'https://idp.example.com/t1');
  });

  const refuses = (options, pattern) => assert.throws(() => normalizeConfig(options), (e) => e instanceof ArkConfigError && pattern.test(e.message));

  test('refuses what a browser can never do safely, with the reason', () => {
    refuses({ ...base, clientSecret: 's3cret' }, /cannot keep a client secret/);
    refuses({ ...base, privateKeyJwt: { privateKey: '...' } }, /cannot keep a client secret/);
    refuses({ ...base, tokenEndpointAuthMethod: 'client_secret_basic' }, /public client/);
    refuses({ ...base, usePar: true }, /not available in a browser/);
    refuses({ ...base, responseMode: 'form_post' }, /form_post POSTs to a server/);
    refuses({ ...base, apiOrigins: ['*'] }, /cannot be '\*'/);
  });

  test('refuses a missing or plain-http authority (loopback excepted) and a missing client id', () => {
    refuses({ clientId: 'x' }, /set 'authority'/);
    refuses({ ...base, authority: 'http://idp.example.com/t' }, /plain http/);
    assert.doesNotThrow(() => normalizeConfig({ ...base, authority: 'http://localhost:5000/t' }));
    assert.doesNotThrow(() => normalizeConfig({ ...base, authority: 'http://idp.lan/t', requireHttps: false }));
    refuses({ authority: base.authority }, /'clientId' is required/);
  });

  test('redirect URIs: a path or an absolute URL, never a fragment, http only on loopback', () => {
    assert.equal(normalizeConfig({ ...base, redirectUri: 'https://app.example.com/cb' }).redirectUri, 'https://app.example.com/cb');
    refuses({ ...base, redirectUri: '/cb#x' }, /fragment/);
    refuses({ ...base, redirectUri: 'https://app.example.com/cb#x' }, /fragment/);
    refuses({ ...base, redirectUri: 'http://app.example.com/cb' }, /loopback/);
    refuses({ ...base, postLogoutRedirectUri: 'javascript:alert(1)' }, /http or https/);
    assert.equal(normalizeConfig({ ...base, postLogoutRedirectUri: null }).postLogoutRedirectUri, null);
  });

  test('apiOrigins are normalised to origins', () => {
    assert.deepEqual([...normalizeConfig({ ...base, apiOrigins: ['https://api.example.com/v1/'] }).apiOrigins], ['https://api.example.com']);
  });

  test('accountSwitch paths must be local', () => {
    refuses({ ...base, accountSwitch: { accessDeniedPath: 'https://evil.example' } }, /local path/);
    refuses({ ...base, accountSwitch: { supportUrl: 'javascript:alert(1)' } }, /http\(s\) URL/);
  });
});

describe('PKCE', () => {
  test('the RFC 7636 Appendix B vector', async () => {
    assert.equal(await codeChallengeFor('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'), 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });

  test('verifiers are 43 unreserved characters and never repeat', async () => {
    const seen = new Set();
    for (let i = 0; i < 200; i++) {
      const v = createCodeVerifier();
      assert.match(v, /^[A-Za-z0-9\-._~]{43}$/);
      seen.add(v);
    }
    assert.equal(seen.size, 200);
    const pair = await createPkcePair();
    assert.equal(pair.codeChallengeMethod, 'S256');
    assert.notEqual(createState(), createState());
  });
});

describe('localOrDefault keeps return URLs on this site', () => {
  for (const evil of ['https://evil.example', '//evil.example', '/\\evil.example', '/\t/evil.example', 'javascript:alert(1)', '', null]) {
    test(`refuses ${JSON.stringify(evil)}`, () => assert.equal(localOrDefault(evil, '/home'), '/home'));
  }
  test('keeps a local path with query and fragment', () => assert.equal(localOrDefault('/a/b?c=1#d'), '/a/b?c=1#d'));
});

describe('discovery and storage', () => {
  test('both discovery spellings', () => {
    assert.deepEqual(discoveryUrls('https://idp.example.com/t1'), [
      'https://idp.example.com/t1/.well-known/openid-configuration',
      'https://idp.example.com/.well-known/oauth-authorization-server/t1'
    ]);
  });

  test('storage falls back to memory where Web Storage throws', () => {
    const broken = { get sessionStorage() { throw new Error('SecurityError'); } };
    assert.equal(resolveStorage('session', broken).kind, 'memory');
    const custom = new MemoryStorage();
    assert.equal(resolveStorage(custom, null).storage, custom);
    assert.throws(() => resolveStorage('cookies', {}), ArkConfigError);
  });
});
