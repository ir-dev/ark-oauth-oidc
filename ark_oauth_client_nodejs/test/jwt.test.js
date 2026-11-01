import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { decodeJwt, signJwt, validateClaims, validateTokenHashes, verifyJwt, verifySignature } from '../src/jwt.js';
import { base64UrlEncode, leftHalfHash } from '../src/crypto.js';
import { ArkTokenError } from '../src/errors.js';

function keypair(kid = 'k1') {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return { privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg: 'RS256' }, kid };
}

const now = () => Math.floor(Date.now() / 1000);

/** A one-key JWKS, as the client's JwksCache would present it. */
const jwksOf = (...keys) => ({
  async getSigningKey(kid) {
    const match = keys.find((k) => k.kid === kid);
    if (!match) throw new ArkTokenError(`no key with kid '${kid}'.`);
    return match.jwk;
  }
});

test('a token signed with the published key verifies', () => {
  const key = keypair();
  const token = signJwt({ sub: 'u', exp: now() + 60 }, { key: key.privateKey, kid: key.kid });
  assert.ok(verifySignature(decodeJwt(token), key.jwk));
});

test('a token signed with a different key does not verify', () => {
  const signer = keypair('k1');
  const other = keypair('k1');
  const token = signJwt({ sub: 'u', exp: now() + 60 }, { key: signer.privateKey, kid: 'k1' });
  assert.throws(() => verifySignature(decodeJwt(token), other.jwk), /signature does not verify/);
});

test('a tampered payload does not verify', () => {
  const key = keypair();
  const token = signJwt({ sub: 'alice', exp: now() + 60 }, { key: key.privateKey, kid: key.kid });
  const [header, , signature] = token.split('.');
  const forged = `${header}.${base64UrlEncode(JSON.stringify({ sub: 'admin', exp: now() + 60 }))}.${signature}`;
  assert.throws(() => verifySignature(decodeJwt(forged), key.jwk), /signature does not verify/);
});

test('alg: none is refused outright', () => {
  const header = base64UrlEncode(JSON.stringify({ alg: 'none', typ: 'JWT' }));
  const payload = base64UrlEncode(JSON.stringify({ sub: 'admin', exp: now() + 60 }));
  assert.throws(() => verifySignature(decodeJwt(`${header}.${payload}.`), keypair().jwk), /unsigned tokens are never accepted/);
});

test('an algorithm outside the allowed list is refused even when the signature is good', () => {
  const key = keypair();
  const token = signJwt({ sub: 'u', exp: now() + 60 }, { key: key.privateKey, kid: key.kid, alg: 'RS512' });
  assert.throws(() => verifySignature(decodeJwt(token), { ...key.jwk, alg: undefined }, { algorithms: ['RS256'] }), /does not accept/);
});

test('claim validation rejects the wrong issuer, audience, expiry and future iat', () => {
  const base = { iss: 'https://idp/t', aud: 'app', sub: 'u', exp: now() + 60, iat: now() };
  assert.ok(validateClaims(base, { issuer: 'https://idp/t', audience: 'app' }));
  assert.throws(() => validateClaims(base, { issuer: 'https://idp/other' }), /was issued by/);
  assert.throws(() => validateClaims(base, { audience: 'other-app' }), /addressed to/);
  assert.throws(() => validateClaims({ ...base, exp: now() - 120 }, {}), /expired at/);
  assert.throws(() => validateClaims({ ...base, iat: now() + 600 }, {}), /issued in the future/);
  assert.throws(() => validateClaims({ ...base, nbf: now() + 600 }, {}), /not valid before/);
  assert.throws(() => validateClaims({ iss: 'https://idp/t' }, {}), /no `exp` claim/);
});

test('a token expired inside the clock tolerance is still accepted', () => {
  const payload = { exp: now() - 30 };
  assert.ok(validateClaims(payload, { clockToleranceSeconds: 60 }));
  assert.throws(() => validateClaims(payload, { clockToleranceSeconds: 5 }), /expired at/);
});

test('azp is checked when the token names several audiences', () => {
  const payload = { aud: ['app', 'other'], azp: 'other', exp: now() + 60 };
  assert.throws(() => validateClaims(payload, { audience: 'app' }), /authorized party/);
  assert.ok(validateClaims({ ...payload, azp: 'app' }, { audience: 'app' }));
});

test('a missing nonce fails as hard as a wrong one', () => {
  assert.throws(() => validateClaims({ exp: now() + 60 }, { nonce: 'n1' }), /no `nonce`/);
  assert.throws(() => validateClaims({ exp: now() + 60, nonce: 'n2' }, { nonce: 'n1' }), /does not match/);
  assert.ok(validateClaims({ exp: now() + 60, nonce: 'n1' }, { nonce: 'n1' }));
});

test('max_age is enforced against auth_time', () => {
  const payload = { exp: now() + 60, auth_time: now() - 3600 };
  assert.throws(() => validateClaims(payload, { maxAgeSeconds: 300 }), /beyond the requested max_age/);
  assert.ok(validateClaims(payload, { maxAgeSeconds: 7200 }));
  assert.throws(() => validateClaims({ exp: now() + 60 }, { maxAgeSeconds: 300 }), /no `auth_time`/);
});

test('at_hash and c_hash catch a substituted access token or code', () => {
  const accessToken = 'the-real-access-token';
  const code = 'the-real-code';
  const payload = { at_hash: leftHalfHash(accessToken), c_hash: leftHalfHash(code) };

  assert.ok(validateTokenHashes(payload, { accessToken, code }));
  assert.throws(() => validateTokenHashes(payload, { accessToken: 'someone-elses-token' }), /at_hash` does not cover/);
  assert.throws(() => validateTokenHashes(payload, { code: 'someone-elses-code' }), /c_hash` does not cover/);
  assert.throws(() => validateTokenHashes({}, { accessToken }), /no `at_hash`/);
  assert.ok(validateTokenHashes({}, { accessToken, require: false }));
});

test('verifyJwt resolves the key by kid and refuses an unknown one', async () => {
  const active = keypair('key-2');
  const rollover = keypair('key-1');
  const jwks = jwksOf(active, rollover);

  const fresh = signJwt({ iss: 'https://idp/t', aud: 'app', exp: now() + 60, iat: now() }, { key: active.privateKey, kid: 'key-2' });
  const old = signJwt({ iss: 'https://idp/t', aud: 'app', exp: now() + 60, iat: now() }, { key: rollover.privateKey, kid: 'key-1' });

  // Both phases of a rotation validate: the new key signs, the old one is still published.
  assert.equal((await verifyJwt(fresh, jwks, { issuer: 'https://idp/t', audience: 'app' })).aud, 'app');
  assert.equal((await verifyJwt(old, jwks, { issuer: 'https://idp/t', audience: 'app' })).aud, 'app');

  const retired = keypair('key-0');
  const stale = signJwt({ iss: 'https://idp/t', exp: now() + 60 }, { key: retired.privateKey, kid: 'key-0' });
  await assert.rejects(() => verifyJwt(stale, jwks, {}), /no key with kid 'key-0'/);
});

test('verifyJwt enforces the RFC 9068 at+jwt type header when asked', async () => {
  const key = keypair();
  const jwks = jwksOf(key);
  const idToken = signJwt({ exp: now() + 60 }, { key: key.privateKey, kid: key.kid });
  const accessToken = signJwt({ exp: now() + 60 }, { key: key.privateKey, kid: key.kid, typ: 'at+jwt' });

  await assert.rejects(() => verifyJwt(idToken, jwks, { typ: 'at+jwt' }), /expected a token of type 'at\+jwt'/);
  assert.ok(await verifyJwt(accessToken, jwks, { typ: 'at+jwt' }));
});

test('decodeJwt refuses anything that is not a compact JWS', () => {
  assert.throws(() => decodeJwt('not.a.jwt.at.all'), /expected 3 segments/);
  assert.throws(() => decodeJwt('abc'), /expected 3 segments/);
  assert.throws(() => decodeJwt(`${base64UrlEncode('{')}.${base64UrlEncode('{')}.x`), /not valid JSON/);
});

test('EC and PSS signatures verify, so the same client works against other providers', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const ecJwk = { ...publicKey.export({ format: 'jwk' }), kid: 'ec1', use: 'sig' };
  const ecToken = signJwt({ exp: now() + 60 }, { key: privateKey, kid: 'ec1', alg: 'ES256' });
  assert.ok(verifySignature(decodeJwt(ecToken), ecJwk));

  const rsa = keypair('ps1');
  const psToken = signJwt({ exp: now() + 60 }, { key: rsa.privateKey, kid: 'ps1', alg: 'PS256' });
  assert.ok(verifySignature(decodeJwt(psToken), { ...rsa.jwk, alg: undefined }));
});
