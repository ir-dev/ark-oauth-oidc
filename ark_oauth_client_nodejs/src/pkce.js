import { base64UrlEncode, randomToken, sha256 } from './crypto.js';

/**
 * PKCE (RFC 7636), `state` and `nonce`.
 *
 * The Ark server requires PKCE for every public client and accepts `S256` only — `plain` is not
 * implemented, because a plain challenge is the verifier and protects nothing once the
 * authorization request has been observed.
 */

/**
 * A code verifier: 32 random bytes as base64url, which lands at 43 characters — the minimum
 * RFC 7636 §4.1 allows, and entirely within its unreserved character set.
 */
export function createCodeVerifier() {
  return randomToken(32);
}

/** BASE64URL(SHA256(verifier)) — the `code_challenge` for `code_challenge_method=S256`. */
export function codeChallengeFor(verifier) {
  return base64UrlEncode(sha256(verifier));
}

/** A `state` value: CSRF protection for the authorization response, and the key a login transaction is stored under. */
export function createState() {
  return randomToken(24);
}

/** A `nonce`: binds the ID token to this authorization request so a captured one cannot be replayed. */
export function createNonce() {
  return randomToken(24);
}

/** Verifier, challenge and method in one object, for callers driving the flow by hand. */
export function createPkcePair() {
  const codeVerifier = createCodeVerifier();
  return {
    codeVerifier,
    codeChallenge: codeChallengeFor(codeVerifier),
    codeChallengeMethod: 'S256'
  };
}
