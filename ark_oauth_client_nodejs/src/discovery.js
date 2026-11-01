import { getJson } from './http.js';
import { ArkConfigError, ArkOAuthError } from './errors.js';

/**
 * The discovery document (OpenID Connect Discovery 1.0 / RFC 8414).
 *
 * There is one URL to configure — the issuer — and every endpoint this client uses comes from
 * here. That is not indirection for its own sake: it is what lets the provider move an endpoint,
 * turn PAR on, or start advertising the device grant without every application redeploying, and
 * it is why the issuer is the only thing an Ark application has to be told.
 */

const DEFAULT_TTL_MS = 5 * 60_000; // the server sends Cache-Control: max-age=300

/** Both spellings of the metadata URL: OIDC appends the well-known path, RFC 8414 inserts it. */
export function discoveryUrls(authority) {
  const base = authority.replace(/\/+$/, '');
  const url = new URL(base);
  const path = url.pathname.replace(/\/+$/, '');
  return [
    `${base}/.well-known/openid-configuration`,
    `${url.origin}/.well-known/oauth-authorization-server${path}`
  ];
}

/**
 * Fetches and caches provider metadata, one entry per authority.
 *
 * Instances are shared through the client, so an application that creates one ArkOAuthClient makes
 * one discovery request per five minutes no matter how many sign-ins it serves.
 */
export class MetadataResolver {
  #cache = new Map();
  #ttlMs;
  #http;

  constructor({ ttlMs = DEFAULT_TTL_MS, ...http } = {}) {
    this.#ttlMs = ttlMs;
    this.#http = http;
  }

  async get(authority, { force = false } = {}) {
    if (!authority) throw new ArkConfigError('no authority was given; set `authority` to the issuer URL of your Ark tenant.');
    const key = authority.replace(/\/+$/, '');

    const hit = this.#cache.get(key);
    if (hit && !force) {
      if (Date.now() - hit.fetchedAt <= this.#ttlMs) return hit.promise;
      if (hit.pending) return hit.promise;
    }

    const entry = { fetchedAt: Date.now(), pending: true };
    entry.promise = this.#fetch(key).then(
      (metadata) => {
        entry.pending = false;
        return metadata;
      },
      (error) => {
        // A failed lookup must not be cached, or one restart during a provider outage would
        // wedge the application for the whole TTL.
        this.#cache.delete(key);
        throw error;
      }
    );
    this.#cache.set(key, entry);
    return entry.promise;
  }

  clear() {
    this.#cache.clear();
  }

  async #fetch(authority) {
    const [primary, fallback] = discoveryUrls(authority);
    let metadata;
    try {
      metadata = await getJson(primary, this.#http);
    } catch (error) {
      // Ark serves the OIDC spelling. The RFC 8414 form is tried second so the same client can be
      // pointed at a provider that only publishes that one.
      if (error instanceof ArkOAuthError && error.status === 404) metadata = await getJson(fallback, this.#http);
      else throw error;
    }

    if (!metadata.issuer) {
      throw new ArkOAuthError('server_error', `${primary} returned a document with no 'issuer'.`, { endpoint: primary });
    }

    // OIDC Discovery §4.3: the issuer in the document must equal the one used to look it up.
    // A mismatch means the URL is not the authority it claims to be — the shape of a mix-up
    // attack, and much more often a stray /auth or a missing tenant id in configuration.
    if (metadata.issuer.replace(/\/+$/, '') !== authority) {
      throw new ArkConfigError(
        `the provider at ${primary} identifies itself as '${metadata.issuer}', but this client is configured for '${authority}'. ` +
          'Set `authority` to exactly the issuer value — for Ark that is {BaseUrl}/{TenantId}.'
      );
    }

    return Object.freeze(metadata);
  }
}
