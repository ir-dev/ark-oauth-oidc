import { base64UrlEncode, randomToken, sha256 } from './crypto.js';

/**
 * PKCE (RFC 7636), `state` and `nonce`.
 *
 * A browser app is a public client, and the Ark server requires PKCE from every public client and
 * accepts `S256` only. `plain` is not implemented: a plain challenge is the verifier, so it
 * protects nothing once the authorization request has been seen.
 */

/** 32 random bytes as base64url: 43 characters, the minimum RFC 7636 §4.1 allows. */
export function createCodeVerifier() {
  return randomToken(32);
}

/** BASE64URL(SHA256(verifier)), the `code_challenge` for `code_challenge_method=S256`. */
export async function codeChallengeFor(verifier) {
  return base64UrlEncode(await sha256(verifier));
}

/** CSRF protection for the authorization response, and the key the sign-in transaction is stored under. */
export function createState() {
  return randomToken(24);
}

/** Binds the ID token to this authorization request, so a captured one cannot be replayed. */
export function createNonce() {
  return randomToken(24);
}

/** Verifier, challenge and method in one object, for callers driving the flow by hand. */
export async function createPkcePair() {
  const codeVerifier = createCodeVerifier();
  return { codeVerifier, codeChallenge: await codeChallengeFor(codeVerifier), codeChallengeMethod: 'S256' };
}
