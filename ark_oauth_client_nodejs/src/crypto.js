import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * The small cryptographic primitives the protocol is built out of.
 *
 * All of it comes from `node:crypto` — this package has no runtime dependencies, so nothing in
 * the chain that mints a PKCE verifier or compares a `state` can be replaced by a typosquatted
 * package on install.
 */

/** base64url without padding (RFC 7515 §2). */
export function base64UrlEncode(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf8');
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Decodes base64url to a Buffer, tolerating the padding some encoders leave on. */
export function base64UrlDecode(value) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(padded, 'base64');
}

/**
 * Cryptographically random bytes as base64url.
 *
 * Every unguessable value in the protocol — `state`, `nonce`, the PKCE verifier, a session id —
 * comes from here and only from here. The .NET client this one mirrors exists because its
 * predecessor derived the PKCE verifier from a timestamp, which made it predictable and meant
 * PKCE protected nothing at all.
 */
export function randomToken(bytes = 32) {
  return base64UrlEncode(randomBytes(bytes));
}

export function sha256(input) {
  return createHash('sha256').update(input, typeof input === 'string' ? 'utf8' : undefined).digest();
}

/**
 * Constant-time string comparison.
 *
 * Used for `state` and for the session cookie signature. A length-dependent early return would
 * leak how much of a guess was right, which is enough to reconstruct a value one character at a
 * time; hashing both sides first keeps the compared buffers equal-length so the comparison itself
 * cannot be timed either.
 */
export function fixedTimeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  return timingSafeEqual(sha256(a), sha256(b));
}

/**
 * The left-most half of the SHA-256 of a value, base64url encoded — the construction OIDC Core
 * §3.1.3.6 uses for `at_hash` and `c_hash`.
 */
export function leftHalfHash(value) {
  const digest = sha256(value);
  return base64UrlEncode(digest.subarray(0, digest.length / 2));
}
