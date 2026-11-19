/**
 * Cross-tab mutual exclusion for refreshing tokens.
 *
 * Ark rotates refresh tokens and treats a retired one coming back as theft: the whole family is
 * revoked and the user is signed out everywhere. Two tabs sharing localStorage that both notice the
 * access token expiring would each present the same refresh token, and the second presentation
 * looks exactly like that theft. The Web Locks API serialises them across every tab of the origin;
 * the tab that waited then re-reads storage and finds the tokens the first one already obtained.
 *
 * Where Web Locks is missing (it is in every current browser), the refresh still runs, and the
 * in-tab de-duplication in the client is the only protection.
 */
export async function withLock(name, fn, win) {
  const locks = win?.navigator?.locks ?? globalThis.navigator?.locks;
  if (locks && typeof locks.request === 'function') {
    return locks.request(name, { mode: 'exclusive' }, () => fn());
  }
  return fn();
}
