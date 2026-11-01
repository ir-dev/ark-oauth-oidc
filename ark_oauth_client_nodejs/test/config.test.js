import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeConfig } from '../src/config.js';
import { ArkConfigError } from '../src/errors.js';
import { TokenSet } from '../src/tokens.js';

const base = { authority: 'https://idp.example.com/my_idp', clientId: 'my-app' };

test('the authority can be given whole or as server + tenant', () => {
  assert.equal(normalizeConfig(base).authority, 'https://idp.example.com/my_idp');
  assert.equal(normalizeConfig({ ...base, authority: 'https://idp.example.com/my_idp/' }).authority, 'https://idp.example.com/my_idp');
  assert.equal(
    normalizeConfig({ authServerUrl: 'https://idp.example.com/', tenantId: 'my_idp', clientId: 'my-app' }).authority,
    'https://idp.example.com/my_idp'
  );
});

test('a missing authority or clientId is named, not guessed at', () => {
  assert.throws(() => normalizeConfig({ clientId: 'x' }), (e) => e instanceof ArkConfigError && /'authority'/.test(e.message));
  assert.throws(() => normalizeConfig({ authority: base.authority }), /'clientId' is required/);
});

test('plain http is refused unless it is loopback', () => {
  assert.throws(() => normalizeConfig({ ...base, authority: 'http://idp.example.com/my_idp' }), /plain http/);
  assert.equal(normalizeConfig({ ...base, authority: 'http://localhost:5001/my_idp' }).authority, 'http://localhost:5001/my_idp');
  assert.equal(normalizeConfig({ ...base, authority: 'http://127.0.0.1:5001/my_idp' }).authority, 'http://127.0.0.1:5001/my_idp');
  assert.ok(normalizeConfig({ ...base, authority: 'http://idp.example.com/my_idp', requireHttps: false }));
});

test('the auth method is derived from what was configured, and contradictions are refused', () => {
  assert.equal(normalizeConfig(base).tokenEndpointAuthMethod, 'none');
  assert.equal(normalizeConfig({ ...base, clientSecret: 's' }).tokenEndpointAuthMethod, 'client_secret_basic');
  assert.equal(normalizeConfig({ ...base, privateKeyJwt: { privateKey: 'pem' } }).tokenEndpointAuthMethod, 'private_key_jwt');

  assert.throws(() => normalizeConfig({ ...base, tokenEndpointAuthMethod: 'client_secret_post' }), /needs a 'clientSecret'/);
  assert.throws(() => normalizeConfig({ ...base, tokenEndpointAuthMethod: 'private_key_jwt' }), /privateKeyJwt\.privateKey/);
  assert.throws(() => normalizeConfig({ ...base, clientSecret: 's', tokenEndpointAuthMethod: 'none' }), /matches the registered method exactly/);
  assert.throws(() => normalizeConfig({ ...base, tokenEndpointAuthMethod: 'client_secret_jwt' }), /the server supports/);
});

test('redirect URIs are held to what the server will accept', () => {
  assert.throws(() => normalizeConfig({ ...base, redirectUri: '/signin-oidc' }), /must be an absolute URL/);
  assert.throws(() => normalizeConfig({ ...base, redirectUri: 'https://app.example.com/cb#frag' }), /must not contain a fragment/);
  assert.throws(() => normalizeConfig({ ...base, redirectUri: 'http://app.example.com/cb' }), /loopback/);
  assert.ok(normalizeConfig({ ...base, redirectUri: 'http://127.0.0.1:8080/cb' }));
  assert.ok(normalizeConfig({ ...base, redirectUri: 'https://app.example.com/signin-oidc' }));
});

test('an unsupported response mode is refused', () => {
  assert.throws(() => normalizeConfig({ ...base, responseMode: 'web_message' }), /the server supports query, fragment and form_post/);
});

test('the default scopes are the ones the server seeds', () => {
  assert.deepEqual(normalizeConfig(base).scopes, ['openid', 'profile', 'email', 'offline_access']);
  assert.deepEqual(normalizeConfig({ ...base, scopes: ['openid'] }).scopes, ['openid']);
});

test('the config object cannot be mutated after construction', () => {
  const config = normalizeConfig(base);
  assert.throws(() => {
    config.clientId = 'someone-else';
  }, TypeError);
});

test('a TokenSet round-trips through a session store', () => {
  const original = new TokenSet(
    { access_token: 'at', refresh_token: 'rt', id_token: 'it', token_type: 'Bearer', expires_in: 3600, scope: 'openid profile' },
    { claims: { sub: 'u' } }
  );
  const revived = TokenSet.fromJSON(JSON.parse(JSON.stringify(original)));

  assert.equal(revived.accessToken, 'at');
  assert.equal(revived.refreshToken, 'rt');
  assert.equal(revived.expiresAt, original.expiresAt, 'the absolute expiry survives the trip');
  assert.deepEqual(revived.scopes(), ['openid', 'profile']);
  assert.equal(revived.claims.sub, 'u');
  assert.equal(revived.authorizationHeader(), 'Bearer at');
});

test('a token with no lifetime never counts as expired', () => {
  const tokens = new TokenSet({ access_token: 'at' });
  assert.equal(tokens.expiresIn(), null);
  assert.equal(tokens.expired(), false);
});

test('arkClaims survives a non-JWT access token', () => {
  assert.deepEqual(new TokenSet({ access_token: 'opaque-token' }).arkClaims(), []);
  assert.equal(new TokenSet({}).accessTokenClaims(), null);
});
