import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { constants, createHash, generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { decodeJwt, validateClaims, validateTokenHashes, verifyJwt, verifySignature } from '../src/jwt.js';
import { JwksCache } from '../src/jwks.js';
import { base64UrlDecode, base64UrlEncode, constantTimeEqual, leftHalfHash } from '../src/crypto.js';
import { ArkTokenError } from '../src/errors.js';

const b64u = (v) => Buffer.from(v).toString('base64url');

function keyPair(alg) {
  if (alg.startsWith('ES')) {
    const curve = { ES256: 'P-256', ES384: 'P-384', ES512: 'P-521' }[alg];
    return generateKeyPairSync('ec', { namedCurve: curve });
  }
  return generateKeyPairSync('rsa', { modulusLength: 2048 });
}

function signToken(payload, { alg = 'RS256', kid = 'k1', privateKey, header = {} }) {
  const head = { alg, typ: 'JWT', ...(kid ? { kid } : {}), ...header };
  const input = `${b64u(JSON.stringify(head))}.${b64u(JSON.stringify(payload))}`;
  const hash = `sha${alg.slice(2)}`;
  const opts = { key: privateKey };
  if (alg.startsWith('PS')) Object.assign(opts, { padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST });
  if (alg.startsWith('ES')) opts.dsaEncoding = 'ieee-p1363';
  return `${input}.${nodeSign(hash, Buffer.from(input), opts).toString('base64url')}`;
}

const now = () => Math.floor(Date.now() / 1000);
const claims = (extra = {}) => ({ iss: 'https://idp/t', aud: 'spa', sub: 'u1', iat: now(), exp: now() + 300, ...extra });

describe('signature verification with Web Crypto', () => {
  for (const alg of ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512']) {
    test(`verifies ${alg}, and rejects a tampered payload`, async () => {
      const { privateKey, publicKey } = keyPair(alg);
      const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg };
      const token = signToken(claims(), { alg, privateKey });
      assert.equal(await verifySignature(decodeJwt(token), jwk), true);

      const [h, , s] = token.split('.');
      const forged = `${h}.${b64u(JSON.stringify(claims({ sub: 'admin' })))}.${s}`;
      await assert.rejects(verifySignature(decodeJwt(forged), jwk), /does not verify/);
    });
  }

  test('alg none is never accepted', async () => {
    const token = `${b64u('{"alg":"none"}')}.${b64u(JSON.stringify(claims()))}.`;
    await assert.rejects(verifySignature(decodeJwt(token), { kty: 'RSA' }), /unsigned tokens are never accepted/);
  });

  test('HS256 (the RSA-public-key-as-HMAC-secret confusion) is not an accepted algorithm', async () => {
    const token = `${b64u('{"alg":"HS256"}')}.${b64u(JSON.stringify(claims()))}.${b64u('x')}`;
    await assert.rejects(verifySignature(decodeJwt(token), { kty: 'RSA' }), /does not accept/);
  });

  test('a key published for a different algorithm or key type is refused', async () => {
    const { privateKey, publicKey } = keyPair('RS256');
    const token = signToken(claims(), { privateKey });
    await assert.rejects(verifySignature(decodeJwt(token), { ...publicKey.export({ format: 'jwk' }), alg: 'PS256' }), /registered for PS256/);
    await assert.rejects(verifySignature(decodeJwt(token), { kty: 'EC', crv: 'P-256' }), /EC key/);
    await assert.rejects(verifySignature(decodeJwt(token), { ...publicKey.export({ format: 'jwk' }), use: 'enc' }), /not signing/);
  });

  test('the allow-list is enforced', async () => {
    const { privateKey, publicKey } = keyPair('PS256');
    const token = signToken(claims(), { alg: 'PS256', privateKey });
    await assert.rejects(verifySignature(decodeJwt(token), publicKey.export({ format: 'jwk' }), { algorithms: ['RS256'] }), /does not accept/);
  });
});

describe('decodeJwt', () => {
  test('rejects what is not a compact JWS', () => {
    assert.throws(() => decodeJwt('a.b'), ArkTokenError);
    assert.throws(() => decodeJwt(42), ArkTokenError);
    assert.throws(() => decodeJwt(`${b64u('[1]')}.${b64u('{}')}.x`), /JSON objects/);
    assert.throws(() => decodeJwt('###.###.###'), ArkTokenError);
  });

  test('reads UTF-8 claims', () => {
    const token = `${b64u('{"alg":"RS256"}')}.${b64u(JSON.stringify({ name: 'Zoë Ångström 李' }))}.sig`;
    assert.equal(decodeJwt(token).payload.name, 'Zoë Ångström 李');
  });
});

describe('claims', () => {
  test('issuer, audience, azp, subject, exp, nbf, iat, nonce, auth_time', () => {
    const ok = claims({ nonce: 'n1', auth_time: now() - 10 });
    assert.doesNotThrow(() => validateClaims(ok, { issuer: 'https://idp/t', audience: 'spa', nonce: 'n1', maxAgeSeconds: 60 }));
    const fails = (payload, options, claim) => assert.throws(() => validateClaims(payload, options), (e) => e.claim === claim);
    fails(ok, { issuer: 'https://other/t' }, 'iss');
    fails(ok, { audience: 'other' }, 'aud');
    fails(claims({ aud: ['spa', 'api'], azp: 'api' }), { audience: 'spa' }, 'azp');
    fails(ok, { subject: 'u2' }, 'sub');
    fails(claims({ exp: now() - 120 }), {}, 'exp');
    fails(claims({ exp: '9999999999' }), {}, 'exp');
    fails(claims({ nbf: now() + 600 }), {}, 'nbf');
    fails(claims({ iat: now() + 600 }), {}, 'iat');
    fails(claims({ iat: 'yesterday' }), {}, 'iat');
    fails(claims(), { nonce: 'n1' }, 'nonce');
    fails(ok, { nonce: 'n2' }, 'nonce');
    fails(claims({ auth_time: now() - 1000 }), { maxAgeSeconds: 60 }, 'auth_time');
    fails(claims({ iat: undefined }), { requireIat: true }, 'iat');
  });

  test('clock tolerance', () => {
    assert.doesNotThrow(() => validateClaims(claims({ exp: now() - 30 }), { clockToleranceSeconds: 60 }));
    assert.throws(() => validateClaims(claims({ exp: now() - 30 }), { clockToleranceSeconds: 0 }));
  });

  test('at_hash and c_hash follow the algorithm, and a missing one is an error by default', async () => {
    const at = 'access-token-value';
    const sha256Half = createHash('sha256').update(at).digest().subarray(0, 16).toString('base64url');
    assert.equal(await leftHalfHash(at), sha256Half);
    await validateTokenHashes({ at_hash: sha256Half }, { accessToken: at });
    const sha384Half = createHash('sha384').update(at).digest().subarray(0, 24).toString('base64url');
    await validateTokenHashes({ at_hash: sha384Half }, { alg: 'RS384', accessToken: at });
    await assert.rejects(validateTokenHashes({ at_hash: sha256Half }, { alg: 'RS384', accessToken: at }), /substituted/);
    await assert.rejects(validateTokenHashes({}, { code: 'c' }), (e) => e.claim === 'c_hash');
    await validateTokenHashes({}, { code: 'c', require: false });
  });
});

describe('JwksCache and verifyJwt', () => {
  function jwksServer(keys) {
    let calls = 0;
    const fetchImpl = async () => {
      calls++;
      return new Response(JSON.stringify({ keys: keys() }), { headers: { 'content-type': 'application/json' } });
    };
    return { fetchImpl, calls: () => calls };
  }

  test('a new kid after rotation earns one refetch; the same unknown kid does not earn another', async () => {
    const k1 = keyPair('RS256');
    const k2 = keyPair('RS256');
    let published = [{ ...k1.publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' }];
    const server = jwksServer(() => published);
    const cache = new JwksCache('https://idp/jwks', { fetch: server.fetchImpl, minRefreshIntervalMs: 0 });

    await verifyJwt(signToken(claims(), { privateKey: k1.privateKey }), cache, { issuer: 'https://idp/t', audience: 'spa' });
    assert.equal(server.calls(), 1);

    published = [{ ...k2.publicKey.export({ format: 'jwk' }), kid: 'k2', alg: 'RS256', use: 'sig' }, ...published];
    await verifyJwt(signToken(claims(), { kid: 'k2', privateKey: k2.privateKey }), cache, {});
    assert.equal(server.calls(), 2, 'rotation picked up');

    const bogus = signToken(claims(), { kid: 'nope', privateKey: k2.privateKey });
    await assert.rejects(verifyJwt(bogus, cache, {}), /no key with kid 'nope'/);
    await assert.rejects(verifyJwt(bogus, cache, {}), /no key with kid 'nope'/);
    assert.equal(server.calls(), 3, 'one refetch for the unknown kid, not one per token');
  });

  test('a token without kid resolves only against a single published key', async () => {
    const k1 = keyPair('RS256');
    const k2 = keyPair('RS256');
    const one = new JwksCache('https://idp/jwks', { fetch: jwksServer(() => [k1.publicKey.export({ format: 'jwk' })]).fetchImpl });
    const token = signToken(claims(), { privateKey: k1.privateKey, kid: null });
    await verifyJwt(token, one, {});
    const two = new JwksCache('https://idp/jwks', {
      minRefreshIntervalMs: 0,
      fetch: jwksServer(() => [k1.publicKey.export({ format: 'jwk' }), k2.publicKey.export({ format: 'jwk' })]).fetchImpl
    });
    await assert.rejects(verifyJwt(token, two, {}), /ambiguous/);
  });
});

describe('crypto helpers', () => {
  test('base64url round-trips bytes and strings', () => {
    const bytes = new Uint8Array([0, 255, 251, 239, 190, 62, 63]);
    assert.deepEqual(base64UrlDecode(base64UrlEncode(bytes)), bytes);
    assert.equal(base64UrlEncode('hello?'), Buffer.from('hello?').toString('base64url'));
    assert.equal(base64UrlEncode(new Uint8Array(100_000)).length, Buffer.alloc(100_000).toString('base64url').length);
  });

  test('constantTimeEqual', () => {
    assert.equal(constantTimeEqual('abc', 'abc'), true);
    assert.equal(constantTimeEqual('abc', 'abd'), false);
    assert.equal(constantTimeEqual('abc', 'abcd'), false);
    assert.equal(constantTimeEqual('abc', null), false);
  });
});
