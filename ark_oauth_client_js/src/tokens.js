import { decodeJwt } from './jwt.js';

/**
 * One token endpoint response, with the parts an application asks for.
 *
 * `expires_in` becomes an absolute `expiresAt` the moment the response arrives. A relative lifetime
 * means something only at the instant it is received, and a token set read back from sessionStorage
 * after a reload cannot answer "are you still valid" from a number relative to a forgotten moment.
 *
 * The same class, fields and JSON shape as `TokenSet` in `ark-oauth-client-node`.
 */
export class TokenSet {
  /**
   * @param {object} response the raw JSON from /oauth2/token
   * @param {{ issuedAt?: number, claims?: object|null }} [options]
   */
  constructor(response = {}, { issuedAt = Math.floor(Date.now() / 1000), claims = null } = {}) {
    this.accessToken = response.access_token ?? null;
    this.tokenType = response.token_type ?? 'Bearer';
    this.refreshToken = response.refresh_token ?? null;
    this.idToken = response.id_token ?? null;
    this.scope = response.scope ?? null;
    this.issuedAt = issuedAt;
    this.expiresAt = typeof response.expires_in === 'number' ? issuedAt + response.expires_in : (response.expires_at ?? null);
    /** Validated ID token claims: who the user is. */
    this.claims = claims;
  }

  /** Seconds until expiry; negative once passed; null when the server gave no lifetime. */
  expiresIn(now = Math.floor(Date.now() / 1000)) {
    return this.expiresAt === null ? null : this.expiresAt - now;
  }

  /** Whether the access token should be treated as spent, `leewaySeconds` early. */
  expired(leewaySeconds = 0, now = Math.floor(Date.now() / 1000)) {
    if (this.expiresAt === null) return false;
    return now >= this.expiresAt - leewaySeconds;
  }

  scopes() {
    return this.scope ? this.scope.split(' ').filter(Boolean) : [];
  }

  hasScope(...wanted) {
    const granted = new Set(this.scopes());
    return wanted.flat().every((s) => granted.has(s));
  }

  /**
   * The tenant's authorization claims from the access token: Ark's `ark_claims`.
   *
   * These, not scopes, are what an app authorises against. Scopes say what the client asked for;
   * `ark_claims` say what this user may do in this client.
   */
  arkClaims() {
    const claims = this.accessTokenClaims()?.ark_claims;
    if (Array.isArray(claims)) return claims.map(String);
    return typeof claims === 'string' ? [claims] : [];
  }

  /** The access token's own claims, unverified: for display and `sub`, never for authorising. */
  accessTokenClaims() {
    if (!this.accessToken) return null;
    try {
      return decodeJwt(this.accessToken).payload;
    } catch {
      return null; // an opaque token from another provider simply has no readable claims
    }
  }

  get subject() {
    return this.claims?.sub ?? this.accessTokenClaims()?.sub ?? null;
  }

  authorizationHeader() {
    return `${this.tokenType} ${this.accessToken}`;
  }

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
