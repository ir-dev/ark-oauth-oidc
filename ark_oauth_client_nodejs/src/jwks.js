import { getJson } from './http.js';
import { ArkTokenError } from './errors.js';

const KTY_FOR_ALG = { RS: 'RSA', PS: 'RSA', ES: 'EC' };

/**
 * The provider's signing keys, cached and refreshed on rotation.
 *
 * Ark rotates in two phases: the new key becomes `active` and starts signing, the previous one
 * moves to `rollover` and stays published until the last token it signed has expired. Both are in
 * the JWKS at once, so a client that caches the document keeps validating tokens across the
 * change — provided it refreshes when it meets a `kid` it has never seen. That refresh is the
 * whole point of this class, and it is what the old Ark client could not do at all: its public key
 * was a base64 string pasted into appsettings.json, so a rotation broke every deployment by hand.
 *
 * The refresh is rate-limited. Without a cooldown, a stream of tokens bearing a bogus `kid` would
 * turn into a stream of requests to the provider's JWKS endpoint — a denial-of-service amplifier
 * pointed at your own identity server.
 */
export class JwksCache {
  #uri;
  #ttlMs;
  #cooldownMs;
  #http;
  #keys = null;
  #fetchedAt = 0;
  #inFlight = null;
  #missing = new Set();

  constructor(jwksUri, { ttlMs = 5 * 60_000, minRefreshIntervalMs = 10_000, ...http } = {}) {
    this.#uri = jwksUri;
    this.#ttlMs = ttlMs;
    this.#cooldownMs = minRefreshIntervalMs;
    this.#http = http;
  }

  get uri() {
    return this.#uri;
  }

  /** Every published key, fetching or refreshing as needed. */
  async keys({ force = false } = {}) {
    const stale = Date.now() - this.#fetchedAt > this.#ttlMs;
    if (this.#keys && !force && !stale) return this.#keys;
    return this.#load();
  }

  /**
   * The key that signed a token, chosen by `kid` and constrained to the algorithm's key type.
   *
   * A token with no `kid` is resolved only when the provider publishes exactly one usable key —
   * guessing among several would mean trying each until one verifies, which turns an
   * unauthenticated caller into an oracle for which keys are live.
   */
  async getSigningKey(kid, alg) {
    let candidates = this.#select(await this.keys(), kid, alg);

    if (candidates.length === 0) {
      // An unknown kid is the normal signal that the provider has rotated, so the first sight of
      // one earns a refetch. The second sight of the *same* unknown kid does not: it is either a
      // token from another provider or a probe, and re-reading JWKS for each one would point a
      // request amplifier at the identity server. The rate limit covers the remaining case, a
      // flood of tokens each carrying a different invented kid.
      const marker = kid ?? '\u0000none';
      if (!this.#missing.has(marker) && Date.now() - this.#fetchedAt >= this.#cooldownMs) {
        candidates = this.#select(await this.keys({ force: true }), kid, alg);
      }
      if (candidates.length === 0) this.#missing.add(marker);
    }

    if (candidates.length === 0) {
      throw new ArkTokenError(
        kid
          ? `no key with kid '${kid}' is published at ${this.#uri}; the token may have been signed by a different provider.`
          : `the token carries no 'kid' and ${this.#uri} publishes more than one key, so the signing key is ambiguous.`
      );
    }
    return candidates[0];
  }

  /** Drops the cache — for tests, and for a deployment that knows a rotation just happened. */
  clear() {
    this.#keys = null;
    this.#fetchedAt = 0;
    this.#missing.clear();
  }

  #select(keys, kid, alg) {
    const wantedKty = KTY_FOR_ALG[String(alg ?? '').slice(0, 2)];
    const usable = keys.filter(
      (k) => (!k.use || k.use === 'sig') && (!wantedKty || k.kty === wantedKty) && (!k.alg || !alg || k.alg === alg)
    );
    if (kid) return usable.filter((k) => k.kid === kid);
    return usable.length === 1 ? usable : [];
  }

  async #load() {
    // Collapse concurrent misses into one request: a burst of traffic arriving just after a
    // rotation should cost the provider one JWKS fetch, not one per request.
    this.#inFlight ??= (async () => {
      try {
        const document = await getJson(this.#uri, this.#http);
        const keys = Array.isArray(document.keys) ? document.keys : [];
        if (keys.length === 0) throw new ArkTokenError(`${this.#uri} published no keys.`);
        this.#keys = keys;
        this.#fetchedAt = Date.now();
        // A fresh document may well contain the kid that was missing a moment ago.
        this.#missing.clear();
        return keys;
      } finally {
        this.#inFlight = null;
      }
    })();
    return this.#inFlight;
  }
}
