import { ArkConfigError, ArkTokenError } from './errors.js';

/**
 * The small cryptographic primitives the protocol is built from, on the Web Crypto API.
 *
 * No dependency supplies any of it: nothing in the chain that mints a PKCE verifier or checks an
 * ID token signature can be swapped out by a typosquatted package on install.
 *
 * `crypto.subtle` exists only in a secure context, meaning https, or http on localhost/127.0.0.1.
 * A page served over plain http from a LAN address has no SubtleCrypto at all. That is reported
 * by name here, because otherwise it surfaces as "cannot read properties of undefined" deep inside
 * a sign-in.
 */

function webCrypto() {
  const c = globalThis.crypto;
  if (!c?.getRandomValues) {
    throw new ArkConfigError('ark_oauth_client: this environment has no Web Crypto API (globalThis.crypto).');
  }
  return c;
}

export function subtle() {
  const s = webCrypto().subtle;
  if (!s) {
    throw new ArkConfigError(
      'ark_oauth_client: crypto.subtle is unavailable because this page is not a secure context. ' +
        'Serve the app over https, or over http only on localhost / 127.0.0.1 during development.'
    );
  }
  return s;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function toBytes(input) {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (ArrayBuffer.isView(input)) return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  return encoder.encode(String(input));
}

/** base64url without padding (RFC 7515 §2). Accepts bytes or a string (encoded as UTF-8). */
export function base64UrlEncode(input) {
  const bytes = toBytes(input);
  let binary = '';
  // Chunked, so a large input cannot overflow the argument list of String.fromCharCode.
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Decodes base64url to bytes, tolerating the padding some encoders leave on. */
export function base64UrlDecode(value) {
  const normalized = String(value).replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  let binary;
  try {
    binary = atob(padded);
  } catch (cause) {
    throw new ArkTokenError('a token segment is not valid base64url.', { cause });
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** base64url to a UTF-8 string. */
export function base64UrlDecodeToString(value) {
  return decoder.decode(base64UrlDecode(value));
}

/**
 * Cryptographically random bytes as base64url.
 *
 * Every unguessable value in the flow (`state`, `nonce`, the PKCE verifier) comes from here and
 * only from here. The .NET client this family descends from was rewritten because its predecessor
 * derived the PKCE verifier from a timestamp, which made it guessable and PKCE worthless.
 */
export function randomToken(bytes = 32) {
  const buffer = new Uint8Array(bytes);
  webCrypto().getRandomValues(buffer);
  return base64UrlEncode(buffer);
}

/** A digest as bytes. `hash` is a Web Crypto name: SHA-256, SHA-384 or SHA-512. */
export async function digest(input, hash = 'SHA-256') {
  return new Uint8Array(await subtle().digest(hash, toBytes(input)));
}

export function sha256(input) {
  return digest(input, 'SHA-256');
}

/**
 * The left-most half of a digest, base64url encoded: the construction OIDC Core §3.1.3.6 uses for
 * `at_hash` and `c_hash`. The hash follows the ID token's `alg` (SHA-256 for RS256, which is what
 * Ark signs with).
 */
export async function leftHalfHash(value, hash = 'SHA-256') {
  const full = await digest(value, hash);
  return base64UrlEncode(full.subarray(0, full.length / 2));
}

/**
 * Compares two strings without returning early on the first difference.
 *
 * Used for `state`. A browser comparing its own state is not much of a timing oracle, but the
 * comparison costs nothing to get right, and it keeps this check the same shape as the server
 * clients'.
 */
export function constantTimeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const x = encoder.encode(a);
  const y = encoder.encode(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}
