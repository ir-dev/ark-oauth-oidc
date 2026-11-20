import { useSyncExternalStore } from 'react';
import { ArkBrowserClient } from 'ark-oauth-client-js';
import { useArk } from 'ark-oauth-client-js/react';
import { settings } from './config.js';

// ONE client for the whole app, created once at module scope (never inside a component).
//
// Only `authority` and `clientId` are required. Everything else below is the library default,
// spelled out so you can see what the app sends and what has to be registered on the IdP:
//
//   - the redirect URIs resolve against this page's origin, so on http://localhost:5173 they are
//     http://localhost:5173/signin-oidc and http://localhost:5173/signout-callback-oidc;
//   - offline_access is what earns a refresh token, which is how the session is renewed (a SPA
//     cannot use hidden-iframe renewal against Ark);
//   - tokens live in sessionStorage: they survive a reload and stay private to the tab.
//
// There is no clientSecret, and the constructor refuses one: anything in a browser bundle is
// readable by every visitor. A browser app is a public client and PKCE protects its sign-in.
function createClient() {
  if (!settings.source) return { ark: null, error: null };
  try {
    const ark = new ArkBrowserClient({
      authority: settings.authority, // the issuer: {BaseUrl}/{TenantId}
      clientId: settings.clientId, // registered with token_endpoint_auth_method "none"
      redirectUri: '/signin-oidc',
      postLogoutRedirectUri: '/signout-callback-oidc',
      scopes: ['openid', 'profile', 'email', 'offline_access'],
      storage: 'session',
      // Origins other than this app's own that ark.fetch() may send the access token to.
      // Add your API's origin here, e.g. ['https://api.example.com'].
      apiOrigins: [],
      // The name the built-in "You do not have access" page uses (the librarian desk shows it).
      accountSwitch: { appDisplayName: 'Team Library' }
    });
    return { ark, error: null };
  } catch (error) {
    // ArkConfigError: a value that can be rejected without the network (e.g. a plain-http
    // authority that is not localhost). Shown on the landing page.
    return { ark: null, error };
  }
}

const created = createClient();

/** The client, or null until the app is configured. */
export const ark = created.ark;

/** Why the client could not be created from the settings given, if it could not. */
export const configError = created.error;

/** What components see before the app is configured: signed out, with nothing to call. */
const UNCONFIGURED = Object.freeze({
  status: 'unconfigured',
  isLoading: false,
  isAuthenticated: false,
  user: null,
  arkClaims: [],
  scopes: [],
  expiresAt: null,
  error: null,
  denial: null,
  client: null,
  hasArkClaims: () => false,
  hasAnyArkClaim: () => false
});

/**
 * useArk() when the app is configured, a signed-out stand-in when it is not. Picked once at
 * module load, so every render calls the same hook.
 */
export const useSession = ark ? useArk : () => UNCONFIGURED;

// ---------------------------------------------------------------------------------------------
// Leaving: sign-out and account switch.
//
// Both drop the local session a moment before the browser leaves for the IdP. A page wrapped in
// <RequireArk> sees "signed out" in that moment and starts a sign-in of its own, which races the
// redirect: if it wins, single sign-on signs the same user straight back in (and an account
// switch loses its prompt=login). So the app's buttons go through these two functions, which raise
// a flag first, and <Guard> stops rendering <RequireArk> while it is up.
// ---------------------------------------------------------------------------------------------

let leaving = false; // false | 'signout' | 'switch'
const leavingListeners = new Set();

function setLeaving(value) {
  leaving = value;
  leavingListeners.forEach((listener) => listener());
}

/** false, or 'signout' / 'switch' while the browser is on its way to the IdP. */
export function useLeaving() {
  return useSyncExternalStore(
    (listener) => {
      leavingListeners.add(listener);
      return () => leavingListeners.delete(listener);
    },
    () => leaving,
    () => false
  );
}

// A sign-in without a page load (a popup) ends any leaving state.
ark?.on('signedIn', () => setLeaving(false));

/** Sign out of this app AND the IdP (so the next sign-in asks for a password). */
export function signOut() {
  setLeaving('signout');
  return ark.signoutRedirect().catch((error) => {
    setLeaving(false);
    throw error;
  });
}

/** "Sign in as a different user": prompt=login, so the IdP shows its form instead of SSO. */
export function switchAccount({ returnTo } = {}) {
  setLeaving('switch');
  return ark.switchUser({ returnTo }).catch((error) => {
    setLeaving(false);
    throw error;
  });
}
