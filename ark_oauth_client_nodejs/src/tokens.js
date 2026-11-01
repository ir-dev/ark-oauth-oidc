import { decodeJwt } from './jwt.js';

/**
 * One token endpoint response, with the parts an application actually asks for.
 *
 * `expires_in` is converted to an absolute `expiresAt` the moment the response arrives. A relative
 * lifetime is only meaningful at the instant it is received, and a token set that has sat in a
 * session store for six minutes cannot answer "are you still valid" from a number that was
 * relative to a moment nobody recorded.
 */
export class TokenSet {
  /**
   * @param {object} response the raw JSON from /oauth2/token
   * @param {object} [options]
   * @param {number} [options.issuedAt] epoch seconds; defaults to now
   * @param {object} [options.claims] validated ID token claims, when there was an ID token
   */
  constructor(response = {}, { issuedAt = Math.floor(Date.now() / 1000), claims = null } = {}) {
    this.accessToken = response.access_token ?? null;
    this.tokenType = response.token_type ?? 'Bearer';
    this.refreshToken = response.refresh_token ?? null;
    this.idToken = response.id_token ?? null;
    this.scope = response.scope ?? null;
    this.issuedAt = issuedAt;
    this.expiresAt =
      typeof response.expires_in === 'number'
        ? issuedAt + response.expires_in
        : (response.expires_at ?? null);

    /** Validated ID token claims — who the user is. Null for a client credentials or API token. */
    this.claims = claims;

    /** Anything else the server returned, so a provider extension is never silently dropped. */
    this.raw = response;
  }

  /** Seconds until expiry; negative once it has passed. Null when the server gave no lifetime. */
  expiresIn(now = Math.floor(Date.now() / 1000)) {
    return this.expiresAt === null ? null : this.expiresAt - now;
  }

  /**
   * Whether the access token should be treated as spent.
   *
   * `leewaySeconds` exists so a token is renewed *before* it dies rather than after: a token with
   * four seconds left will not survive the downstream call it is about to be attached to.
   */
  expired(leewaySeconds = 0, now = Math.floor(Date.now() / 1000)) {
    if (this.expiresAt === null) return false;
    return now >= this.expiresAt - leewaySeconds;
  }

  /** The granted scopes, as an array. */
  scopes() {
    return this.scope ? this.scope.split(' ').filter(Boolean) : [];
  }

  hasScope(...wanted) {
    const granted = new Set(this.scopes());
    return wanted.flat().every((s) => granted.has(s));
  }

  /**
   * The tenant's authorization claims from the access token — Ark's `ark_claims`.
   *
   * These, not the scopes, are what an application authorises against: scopes say what the client
   * asked for, `ark_claims` says what this user may do in this client.
   */
  arkClaims() {
    if (!this.accessToken) return [];
    try {
      const { payload } = decodeJwt(this.accessToken);
      const claims = payload.ark_claims;
      if (Array.isArray(claims)) return claims;
      return typeof claims === 'string' ? [claims] : [];
    } catch {
      // A non-JWT access token (another provider's opaque token) simply carries no ark_claims.
      return [];
    }
  }

  /** The access token's own claims, unverified — for logging and for reading `sub`, never for authorising. */
  accessTokenClaims() {
    if (!this.accessToken) return null;
    try {
      return decodeJwt(this.accessToken).payload;
    } catch {
      return null;
    }
  }

  get subject() {
    return this.claims?.sub ?? this.accessTokenClaims()?.sub ?? null;
  }

  /** The value for an `Authorization` header. */
  authorizationHeader() {
    return `${this.tokenType} ${this.accessToken}`;
  }

  /** JSON-safe, and round-trips through a session store without losing the absolute expiry. */
  toJSON() {
    return {
      access_token: this.accessToken,
      token_type: this.tokenType,
      refresh_token: this.refreshToken,
      id_token: this.idToken,
      scope: this.scope,
      expires_at: this.expiresAt,
      issued_at: this.issuedAt,
      claims: this.claims
    };
  }

  static fromJSON(data) {
    if (!data) return null;
    if (data instanceof TokenSet) return data;
    return new TokenSet(data, { issuedAt: data.issued_at ?? Math.floor(Date.now() / 1000), claims: data.claims ?? null });
  }
}
