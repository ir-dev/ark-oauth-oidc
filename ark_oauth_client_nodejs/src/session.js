import { createHmac } from 'node:crypto';
import { base64UrlEncode, fixedTimeEqual, randomToken } from './crypto.js';

/**
 * Where a signed-in user's tokens live between requests.
 *
 * The tokens themselves never go to the browser. The cookie carries an opaque session id and a
 * signature over it, and everything else — access token, refresh token, ID token claims — stays in
 * the store on the server. That ordering is the point: a cookie the client can read is a cookie an
 * XSS bug can exfiltrate, and a refresh token in one is a session that outlives the fix.
 */

/**
 * The default store: a Map with expiry, good for one process.
 *
 * Fine for a single instance and for development. Behind a load balancer, or across a restart,
 * every session lives in one process's heap and disappears with it — supply a shared store (Redis,
 * a database table) with the same four methods for anything that runs more than once.
 */
export class MemorySessionStore {
  #entries = new Map();
  #sweepTimer = null;

  constructor({ sweepIntervalMs = 60_000 } = {}) {
    if (sweepIntervalMs > 0) {
      this.#sweepTimer = setInterval(() => this.sweep(), sweepIntervalMs);
      // Never hold the process open just to expire sessions.
      this.#sweepTimer.unref?.();
    }
  }

  async get(id) {
    const entry = this.#entries.get(id);
    if (!entry) return null;
    if (entry.expiresAt <= Date.now()) {
      this.#entries.delete(id);
      return null;
    }
    return entry.data;
  }

  async set(id, data, ttlSeconds) {
    this.#entries.set(id, { data, expiresAt: Date.now() + ttlSeconds * 1000 });
  }

  async destroy(id) {
    this.#entries.delete(id);
  }

  async touch(id, ttlSeconds) {
    const entry = this.#entries.get(id);
    if (entry) entry.expiresAt = Date.now() + ttlSeconds * 1000;
  }

  sweep(now = Date.now()) {
    for (const [id, entry] of this.#entries) {
      if (entry.expiresAt <= now) this.#entries.delete(id);
    }
  }

  get size() {
    return this.#entries.size;
  }

  /** Stops the sweep timer — for tests and for a clean shutdown. */
  close() {
    if (this.#sweepTimer) clearInterval(this.#sweepTimer);
    this.#sweepTimer = null;
  }
}

/** A fresh session id: 32 random bytes, never derived from anything about the user. */
export function createSessionId() {
  return randomToken(32);
}

/**
 * Signs a session id for the cookie.
 *
 * The signature is not confidentiality — the id is opaque and means nothing on its own. It stops
 * the store being probed with guessed ids, so an attacker cannot mine for a live session by
 * sending a stream of cookies and watching which ones take longer to come back.
 */
export function signSessionId(id, secret) {
  const mac = createHmac('sha256', secret).update(id).digest();
  return `${id}.${base64UrlEncode(mac)}`;
}

/** Verifies a cookie value and returns the session id, or null when the signature does not hold. */
export function unsignSessionId(value, secret) {
  if (typeof value !== 'string') return null;
  const dot = value.lastIndexOf('.');
  if (dot <= 0) return null;
  const id = value.slice(0, dot);
  return fixedTimeEqual(value, signSessionId(id, secret)) ? id : null;
}

/** Parses a Cookie header. */
export function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of String(header).split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim();
    if (!key || key in out) continue;
    try {
      out[key] = decodeURIComponent(part.slice(eq + 1).trim());
    } catch {
      out[key] = part.slice(eq + 1).trim();
    }
  }
  return out;
}

/** Builds a Set-Cookie value. */
export function serializeCookie(name, value, options = {}) {
  const { maxAge, domain, path = '/', expires, httpOnly = true, secure = true, sameSite = 'Lax' } = options;
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (path) parts.push(`Path=${path}`);
  if (domain) parts.push(`Domain=${domain}`);
  if (maxAge !== undefined) parts.push(`Max-Age=${Math.floor(maxAge)}`);
  if (expires) parts.push(`Expires=${new Date(expires).toUTCString()}`);
  if (httpOnly) parts.push('HttpOnly');
  if (secure) parts.push('Secure');
  if (sameSite) parts.push(`SameSite=${sameSite}`);
  return parts.join('; ');
}

/** Appends a Set-Cookie header without dropping any already set on the response. */
export function appendCookie(res, cookie) {
  const existing = res.getHeader('Set-Cookie');
  if (!existing) res.setHeader('Set-Cookie', [cookie]);
  else res.setHeader('Set-Cookie', Array.isArray(existing) ? [...existing, cookie] : [existing, cookie]);
}
