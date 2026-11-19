import { getJson } from './http.js';
import { ArkConfigError, ArkOAuthError } from './errors.js';

/**
 * The discovery document (OpenID Connect Discovery 1.0 / RFC 8414).
 *
 * The issuer is the only URL an Ark app is told. Every endpoint comes from here, which is what lets
 * the provider move an endpoint or rotate a key without a single SPA being rebuilt.
 */

const DEFAULT_TTL_MS = 5 * 60_000; // the server sends Cache-Control: max-age=300

/** Both spellings of the metadata URL: OIDC appends the well-known path, RFC 8414 inserts it. */
export function discoveryUrls(authority) {
  const base = authority.replace(/\/+$/, '');
  const url = new URL(base);
  const path = url.pathname.replace(/\/+$/, '');
  return [`${base}/.well-known/openid-configuration`, `${url.origin}/.well-known/oauth-authorization-server${path}`];
}

/** Fetches and caches provider metadata for one authority. Concurrent callers share one request. */
export class MetadataResolver {
  #authority;
  #ttlMs;
  #http;
  #entry = null;

  constructor(authority, { ttlMs = DEFAULT_TTL_MS, ...http } = {}) {
    this.#authority = authority.replace(/\/+$/, '');
    this.#ttlMs = ttlMs;
    this.#http = http;
  }

  get(force = false) {
    const hit = this.#entry;
    if (hit && !force && (hit.pending || Date.now() - hit.fetchedAt <= this.#ttlMs)) return hit.promise;

    const entry = { fetchedAt: Date.now(), pending: true };
    entry.promise = this.#fetch(force).then(
      (metadata) => {
        entry.pending = false;
        return metadata;
      },
      (error) => {
        // A failed lookup is not cached, or one bad moment would wedge the page for the whole TTL.
        if (this.#entry === entry) this.#entry = null;
        throw error;
      }
    );
    this.#entry = entry;
    return entry.promise;
  }

  clear() {
    this.#entry = null;
  }

  async #fetch(force) {
    const [primary, fallback] = discoveryUrls(this.#authority);
    // `default` lets the browser's HTTP cache answer within the server's max-age, which saves a
    // round trip on every page load; a forced read revalidates instead.
    const options = { ...this.#http, cache: force ? 'no-cache' : 'default' };
    let metadata;
    try {
      metadata = await getJson(primary, options);
    } catch (error) {
      if (error instanceof ArkOAuthError && error.status === 404) metadata = await getJson(fallback, options);
      else throw error;
    }

    if (!metadata.issuer) {
      throw new ArkOAuthError('server_error', `${primary} returned a document with no 'issuer'.`, { endpoint: primary });
    }
    // OIDC Discovery §4.3: the document's issuer must equal the one used to look it up. A mismatch
    // is the shape of a mix-up attack, and far more often a missing tenant id in configuration.
    if (metadata.issuer.replace(/\/+$/, '') !== this.#authority) {
      throw new ArkConfigError(
        `the provider at ${primary} identifies itself as '${metadata.issuer}', but this client is configured for ` +
          `'${this.#authority}'. Set 'authority' to exactly the issuer value: for Ark that is {BaseUrl}/{TenantId}.`
      );
    }
    return Object.freeze(metadata);
  }
}
