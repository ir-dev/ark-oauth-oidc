import { getJson } from './http.js';
import { importVerifyKey } from './jwt.js';
import { ArkTokenError } from './errors.js';

const KTY_FOR_ALG = { RS: 'RSA', PS: 'RSA', ES: 'EC' };
const MAX_REMEMBERED_MISSES = 64;

/**
 * The provider's signing keys, cached and refreshed on rotation.
 *
 * Ark rotates in two phases: the new key starts signing and the old one stays published until the
 * last token it signed has expired. A client that caches the JWKS keeps validating across the change,
 * as long as it refetches when it meets a `kid` it has never seen. That refetch is the point of this
 * class. The v1 Ark client could not do it at all: its key was pasted into configuration, so every
 * rotation broke every deployment.
 *
 * Refetches are rate-limited and each unknown `kid` earns only one, so a page fed tokens with
 * invented key ids cannot turn into a request flood against the identity server.
 */
export class JwksCache {
  #uri;
  #ttlMs;
  #cooldownMs;
  #http;
  #keys = null;
  #fetchedAt = 0;
  #forcedAt = 0;
  #inFlight = null;
  #missing = new Set();
  #imported = new Map();

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
    return this.#load(force);
  }

  /**
   * The key that signed a token, as `{ jwk, key }` where `key` is the imported CryptoKey.
   *
   * A token with no `kid` resolves only when exactly one usable key is published: guessing among
   * several would mean trying each until one verifies.
   */
  async getSigningKey(kid, alg) {
    let candidates = this.#select(await this.keys(), kid, alg);

    if (candidates.length === 0) {
      const marker = kid ?? '\u0000none';
      // The cooldown runs from the last *revalidated* fetch. A normal load may be answered by the
      // browser's HTTP cache (Ark sends max-age=300), so just after a rotation it can hand back the
      // old document: the first miss after that must still get one revalidating fetch.
      if (!this.#missing.has(marker) && Date.now() - this.#forcedAt >= this.#cooldownMs) {
        candidates = this.#select(await this.keys({ force: true }), kid, alg);
      }
      if (candidates.length === 0) {
        if (this.#missing.size >= MAX_REMEMBERED_MISSES) this.#missing.clear();
        this.#missing.add(marker);
      }
    }

    if (candidates.length === 0) {
      throw new ArkTokenError(
        kid
          ? `no key with kid '${kid}' is published at ${this.#uri}; the token may have been signed by a different provider.`
          : `the token carries no 'kid' and ${this.#uri} publishes more than one key, so the signing key is ambiguous.`
      );
    }

    const jwk = candidates[0];
    const cacheKey = `${jwk.kid ?? ''}|${alg}|${jwk.n ?? jwk.x ?? ''}`;
    let key = this.#imported.get(cacheKey);
    if (!key) {
      key = await importVerifyKey(jwk, alg);
      this.#imported.set(cacheKey, key);
    }
    return { jwk, key };
  }

  clear() {
    this.#keys = null;
    this.#fetchedAt = 0;
    this.#forcedAt = 0;
    this.#missing.clear();
    this.#imported.clear();
  }

  #select(keys, kid, alg) {
    const wantedKty = KTY_FOR_ALG[String(alg ?? '').slice(0, 2)];
    const usable = keys.filter((k) => (!k.use || k.use === 'sig') && (!wantedKty || k.kty === wantedKty) && (!k.alg || !alg || k.alg === alg));
    if (kid) return usable.filter((k) => k.kid === kid);
    return usable.length === 1 ? usable : [];
  }

  async #load(force) {
    if (force) this.#forcedAt = Date.now();
    // Concurrent misses share one request: a burst just after a rotation costs one JWKS fetch.
    this.#inFlight ??= (async () => {
      try {
        const document = await getJson(this.#uri, { ...this.#http, cache: force ? 'no-cache' : 'default' });
        const keys = Array.isArray(document.keys) ? document.keys : [];
        if (keys.length === 0) throw new ArkTokenError(`${this.#uri} published no keys.`);
        this.#keys = keys;
        this.#fetchedAt = Date.now();
        this.#missing.clear();
        return keys;
      } finally {
        this.#inFlight = null;
      }
    })();
    return this.#inFlight;
  }
}
