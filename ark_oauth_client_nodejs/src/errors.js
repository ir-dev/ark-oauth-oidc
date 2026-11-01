/**
 * The error types this library throws.
 *
 * Every failure that came from the authorization server arrives as an ArkOAuthError carrying the
 * `error` code the spec defines, because that code is the only part a caller can branch on. A
 * library that collapses `invalid_grant` and a DNS failure into one thrown string forces the
 * application to parse English to decide whether to retry, re-authenticate, or give up.
 */

/** Base class, so `catch (e) { if (e instanceof ArkError) ... }` covers everything from here. */
export class ArkError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = new.target.name;
    Error.captureStackTrace?.(this, new.target);
  }
}

/**
 * The client is misconfigured — a missing authority, a redirect_uri that is not absolute, a
 * private_key_jwt method with no key. Thrown at construction time wherever possible, so the
 * mistake surfaces at startup rather than on the first user's sign-in.
 */
export class ArkConfigError extends ArkError {}

/**
 * An RFC 6749 §5.2 error response: a JSON body with `error` and, usually, `error_description`.
 *
 * `error` is the machine-readable code (`invalid_grant`, `invalid_client`, `slow_down`, …);
 * `status` is the HTTP status it arrived with; `endpoint` is the URL that produced it, which is
 * what makes the difference between "the token endpoint rejected the code" and "the userinfo
 * endpoint rejected the token" readable in a log.
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
    return new ArkOAuthError('server_error', `the endpoint returned HTTP ${status}.`, {
      status,
      endpoint,
      body
    });
  }
}

/**
 * A token was received but did not survive validation: a bad signature, the wrong issuer or
 * audience, an expired `exp`, a `nonce` that does not match the one sent, an `at_hash` that does
 * not cover the access token that came with it.
 *
 * Kept separate from ArkOAuthError on purpose. An OAuth error means the server refused; this
 * means the server answered and the answer cannot be trusted, which is the more serious of the
 * two and should never be retried.
 */
export class ArkTokenError extends ArkError {
  constructor(message, { claim = null, token = null } = {}) {
    super(message);
    this.claim = claim;
    this.token = token;
  }
}

/**
 * The authorization response could not be tied back to a request this client started — an unknown
 * or missing `state`, an expired login transaction, an `iss` that is not the provider we sent the
 * user to (RFC 9207). Treat it as an attempted CSRF or mix-up attack rather than a user error.
 */
export class ArkCallbackError extends ArkError {}

/** The remote call did not complete: connection refused, DNS failure, timeout, aborted. */
export class ArkNetworkError extends ArkError {}
