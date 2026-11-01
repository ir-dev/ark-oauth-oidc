import { test } from 'node:test';
import assert from 'node:assert/strict';
import { codeChallengeFor, createCodeVerifier, createNonce, createPkcePair, createState } from '../src/pkce.js';
import { base64UrlDecode, base64UrlEncode, fixedTimeEqual, leftHalfHash } from '../src/crypto.js';

test('the S256 challenge matches the RFC 7636 appendix B vector', () => {
  assert.equal(
    codeChallengeFor('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'),
    'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
  );
});

test('verifiers satisfy the RFC 7636 §4.1 format the server enforces', () => {
  for (let i = 0; i < 50; i += 1) {
    const verifier = createCodeVerifier();
    assert.ok(verifier.length >= 43 && verifier.length <= 128, `length ${verifier.length}`);
    assert.match(verifier, /^[A-Za-z0-9\-._~]+$/);
  }
});

test('every unguessable value is distinct across calls', () => {
  const values = new Set();
  for (let i = 0; i < 200; i += 1) {
    values.add(createCodeVerifier());
    values.add(createState());
    values.add(createNonce());
  }
  assert.equal(values.size, 600);
});

test('createPkcePair reports S256, which is the only method the server accepts', () => {
  const pair = createPkcePair();
  assert.equal(pair.codeChallengeMethod, 'S256');
  assert.equal(pair.codeChallenge, codeChallengeFor(pair.codeVerifier));
});

test('base64url round-trips and carries no padding', () => {
  const bytes = Buffer.from([0xfb, 0xff, 0x00, 0x10, 0x3e, 0x3f]);
  const encoded = base64UrlEncode(bytes);
  assert.doesNotMatch(encoded, /[+/=]/);
  assert.deepEqual(base64UrlDecode(encoded), bytes);
});

test('fixedTimeEqual compares by value and rejects non-strings', () => {
  assert.ok(fixedTimeEqual('abc', 'abc'));
  assert.ok(!fixedTimeEqual('abc', 'abd'));
  assert.ok(!fixedTimeEqual('abc', 'abcd'));
  assert.ok(!fixedTimeEqual(null, 'abc'));
  assert.ok(!fixedTimeEqual('abc', undefined));
});

test('leftHalfHash produces the OIDC at_hash construction', () => {
  // OIDC Core §3.1.3.6 example: the left-most 128 bits of the SHA-256 of the access token.
  assert.equal(leftHalfHash('jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y'), '77QmUPtjPfzWtF2AnpK9RQ');
});
