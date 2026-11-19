/**
 * The authentication state as an observable value, the one thing every framework adapter binds to.
 *
 * The contract is the smallest one React, Vue, Angular, Svelte, Solid and plain DOM code all
 * understand:
 *
 * - `getSnapshot()` returns an immutable object, and the *same* object until something changes.
 *   React's `useSyncExternalStore` depends on that identity: a fresh object on every call would
 *   render forever.
 * - `subscribe(listener)` registers a callback for every change and returns the unsubscribe.
 */

export const INITIAL_SNAPSHOT = Object.freeze({
  status: 'loading',
  isLoading: true,
  isAuthenticated: false,
  user: null,
  arkClaims: Object.freeze([]),
  scopes: Object.freeze([]),
  expiresAt: null,
  error: null,
  denial: null
});

export class ArkStore {
  #state = INITIAL_SNAPSHOT;
  #listeners = new Set();

  get() {
    return this.#state;
  }

  /** Replaces the state with `patch` merged in, and notifies, unless nothing changed. */
  set(patch) {
    const next = { ...this.#state, ...patch };
    next.isLoading = next.status === 'loading';
    next.isAuthenticated = next.status === 'authenticated';
    if (Object.keys(next).every((key) => Object.is(next[key], this.#state[key]))) return this.#state;
    this.#state = Object.freeze(next);
    for (const listener of [...this.#listeners]) {
      try {
        listener(this.#state);
      } catch (error) {
        // One broken subscriber must not stop the others hearing about a sign-out.
        queueMicrotask(() => {
          throw error;
        });
      }
    }
    return this.#state;
  }

  subscribe(listener) {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }
}
