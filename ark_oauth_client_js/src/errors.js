/**
 * The error types this library throws.
 *
 * Every failure that came from the authorization server arrives as an ArkOAuthError carrying the
 * `error` code the spec defines, because that code is the only part a caller can branch on. A
 * library that collapses `invalid_grant` and a CORS failure into one thrown string forces the
 * application to parse English to decide whether to retry, sign the user in again, or give up.
 *
 * The names and fields match `ark-oauth-client-node`, so code that handles errors from one
 * reads the same against the other.
 */

/** Base class, so `catch (e) { if (e instanceof ArkError) ... }` covers everything from here. */
export class ArkError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = new.target.name;
  }
}

/**
 * The client is misconfigured: a missing authority, a client secret handed to a browser, a
 * redirect URI with a fragment. Thrown at construction wherever possible, so the mistake shows up
 * the first time the page loads and not on a user's failed sign-in.
 */
export class ArkConfigError extends ArkError {}

/**
 * An RFC 6749 §5.2 error: the server (or the authorization response) said `error=...`.
 *
 * `error` is the machine-readable code (`invalid_grant`, `access_denied`, `login_required`, ...),
 * `status` the HTTP status it came with (0 for a redirect), and `endpoint` the URL that produced
 * it, which tells "the token endpoint refused the code" apart from "userinfo refused the token".
 */
export class ArkOAuthError extends ArkError {
  constructor(error, description, { status = 0, endpoint = null, errorUri = null, body = null } = {}) {
    super(description ? `${error}: ${description}` : error);
    this.error = error;
    this.errorDescription = description ?? null;
    this.errorUri = errorUri;
    this.status = status;
    this.endpoint = endpoint;
    this.body = body;
  }

  /** Builds the error from a parsed response body, falling back to the HTTP status. */
  static fromResponse(status, body, endpoint) {
    if (body && typeof body === 'object' && typeof body.error === 'string') {
      return new ArkOAuthError(body.error, body.error_description, {
        status,
        endpoint,
        errorUri: body.error_uri ?? null,
        body
      });
    }
    return new ArkOAuthError('server_error', `the endpoint returned HTTP ${status}.`, { status, endpoint, body });
  }
}

/**
 * A token arrived but did not survive validation: a bad signature, the wrong issuer or audience,
 * an expired `exp`, a `nonce` that is not the one sent, an `at_hash` that does not cover the
 * access token beside it.
 *
 * Separate from ArkOAuthError on purpose. An OAuth error means the server refused; this means the
 * server answered and the answer cannot be trusted, which is worse and must never be retried.
 */
export class ArkTokenError extends ArkError {
  constructor(message, { claim = null } = {}) {
    super(message);
    this.claim = claim;
  }
}

/**
 * The authorization response could not be tied to a sign-in this page started: an unknown or
 * missing `state`, an expired transaction, an `iss` that is not the provider the user was sent to
 * (RFC 9207). Treat it as an attempted CSRF or mix-up attack, not as a user error.
 */
export class ArkCallbackError extends ArkError {}

/**
 * The request did not complete: offline, DNS, timeout, aborted, or (in a browser, and much more
 * often than the others) refused by CORS. A browser reports all of those as the same opaque
 * `TypeError: Failed to fetch`, so the message says which one is likely and what to change.
 */
export class ArkNetworkError extends ArkError {}

/**
 * The action needs a signed-in user and there is none, or the session can no longer be renewed.
 * `ark.fetch()` throws it; the remedy is `ark.signinRedirect()`.
 */
export class ArkLoginRequiredError extends ArkError {
  constructor(message = 'no user is signed in, or the session has ended. Call signinRedirect() to sign in.') {
    super(message);
    this.error = 'login_required';
  }
}

/**
 * The popup sign-in did not finish. `reason` is `blocked` (the browser refused to open it, almost
 * always because `signinPopup()` was not called straight from a click), `closed` (the user closed
 * it) or `timeout`.
 */
export class ArkPopupError extends ArkError {
  constructor(reason, message) {
    super(message);
    this.reason = reason;
  }
}
