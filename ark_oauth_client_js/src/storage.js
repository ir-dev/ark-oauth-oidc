import { ArkConfigError } from './errors.js';

/**
 * Where the token set lives between page loads.
 *
 * - `session` (default): sessionStorage. Survives a reload, is private to the tab, and is gone
 *   when the tab closes. Each tab signs in on its own (silently, through the provider's session).
 * - `local`: localStorage. Shared by every tab of the app and kept across browser restarts.
 *   Refreshes are coordinated across tabs (see lock.js), because two tabs redeeming the same
 *   rotating refresh token would get the whole token family revoked.
 * - `memory`: nothing written anywhere. The safest against XSS, but every reload is a round trip
 *   to the provider (silent if its session is alive).
 * - any object with getItem/setItem/removeItem, for an encrypted or native store.
 *
 * Whatever is chosen, anything that can run script on the page can read a token the page can use.
 * Storage choice changes how long a stolen token is good for, not whether XSS can reach it. A
 * Content-Security-Policy is what stops XSS, and short access-token lifetimes are what limit it.
 */

export class MemoryStorage {
  #map = new Map();

  getItem(key) {
    return this.#map.has(key) ? this.#map.get(key) : null;
  }

  setItem(key, value) {
    this.#map.set(key, String(value));
  }

  removeItem(key) {
    this.#map.delete(key);
  }

  key(index) {
    return [...this.#map.keys()][index] ?? null;
  }

  get length() {
    return this.#map.size;
  }

  clear() {
    this.#map.clear();
  }
}

function isStorageLike(value) {
  return value && typeof value.getItem === 'function' && typeof value.setItem === 'function' && typeof value.removeItem === 'function';
}

/** Web Storage can exist and still throw: Safari private mode, a sandboxed iframe, cookies blocked. */
function probe(storage) {
  try {
    const key = '__ark_probe__';
    storage.setItem(key, '1');
    storage.removeItem(key);
    return storage;
  } catch {
    return null;
  }
}

/**
 * @param {'session'|'local'|'memory'|Storage} option
 * @param {Window|null} win
 * @returns {{ storage: Storage, kind: string }}
 */
export function resolveStorage(option, win) {
  if (isStorageLike(option)) return { storage: option, kind: 'custom' };
  if (option === 'memory' || !win) return { storage: new MemoryStorage(), kind: 'memory' };
  if (option === 'session' || option === 'local') {
    let candidate = null;
    try {
      candidate = option === 'session' ? win.sessionStorage : win.localStorage;
    } catch {
      candidate = null;
    }
    const usable = candidate ? probe(candidate) : null;
    // Falling back to memory keeps the app working (each reload signs in again) rather than
    // failing outright where storage is blocked.
    return usable ? { storage: usable, kind: option } : { storage: new MemoryStorage(), kind: 'memory' };
  }
  throw new ArkConfigError(`ark_oauth_client: 'storage' must be 'session', 'local', 'memory' or a Storage-like object, not '${option}'.`);
}

/** JSON read that treats a corrupt or foreign value as absent rather than crashing the page. */
export function readJson(storage, key) {
  try {
    const raw = storage.getItem(key);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function writeJson(storage, key, value) {
  try {
    storage.setItem(key, JSON.stringify(value));
    return true;
  } catch {
    return false; // quota exceeded or storage revoked: the session lives on in memory
  }
}

export function remove(storage, key) {
  try {
    storage.removeItem(key);
  } catch {
    /* nothing to do */
  }
}

/** Keys in a storage that start with a prefix, for sweeping expired transactions. */
export function keysWithPrefix(storage, prefix) {
  const found = [];
  try {
    const count = storage.length ?? 0;
    for (let i = 0; i < count; i++) {
      const key = storage.key(i);
      if (key && key.startsWith(prefix)) found.push(key);
    }
  } catch {
    /* a custom store without key()/length simply is not swept */
  }
  return found;
}
