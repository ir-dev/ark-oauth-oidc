'use client';
/**
 * React bindings: a provider, hooks and three small components. Works with React 18 and 19, with
 * or without a router, and in Next.js as a client component (see `ark-oauth-client-js/next` for the
 * App Router wiring).
 *
 *   const ark = new ArkBrowserClient({ authority, clientId });   // module scope: one per app
 *
 *   <ArkProvider client={ark} onRedirectCallback={(to) => navigate(to, { replace: true })}>
 *     <App />
 *   </ArkProvider>
 *
 *   const { isAuthenticated, user, signinRedirect, fetch } = useArk();
 *
 * Written with createElement rather than JSX so the package ships as plain JavaScript that every
 * bundler can consume without a build step of its own.
 */
import { createContext, createElement, useContext, useEffect, useMemo, useRef, useSyncExternalStore } from 'react';
import { ArkBrowserClient } from './client.js';
import { VERSION } from './version.js';

export const ArkContext = createContext(null);

/**
 * Makes the client available to `useArk()` and starts it once.
 *
 * Pass `client` (created at module scope, so every render sees the same one) or `options`.
 * `onRedirectCallback(returnTo)` is where the user is sent after signing in: give it your router's
 * navigate so the move happens inside the router.
 */
export function ArkProvider({ client, options, onRedirectCallback, autoInit = true, children }) {
  const created = useRef(null);
  if (!client && !created.current) {
    if (!options) throw new Error('<ArkProvider> needs a `client` (an ArkBrowserClient) or `options` to create one.');
    created.current = new ArkBrowserClient(options); // construction is side-effect free, so StrictMode's double render is harmless
  }
  const ark = client ?? created.current;

  const callback = useRef(onRedirectCallback);
  callback.current = onRedirectCallback;

  // A client this provider created is destroyed with it (timers, channel, listeners). Deferred a
  // tick, because StrictMode unmounts and remounts every effect once in development: the remount
  // cancels the pending destroy, so the client that may be mid-way through a sign-in survives.
  const owned = created.current;
  const pendingDestroy = useRef(null);
  useEffect(() => {
    if (!owned) return undefined;
    clearTimeout(pendingDestroy.current);
    return () => {
      pendingDestroy.current = setTimeout(() => owned.destroy(), 0);
    };
  }, [owned]);

  useEffect(() => {
    if (!autoInit) return;
    ark.init({ onRedirectCallback: callback.current ? (to, result) => callback.current(to, result) : undefined });
  }, [ark, autoInit]);

  return createElement(ArkContext.Provider, { value: ark }, children);
}

/** The ArkBrowserClient from the nearest <ArkProvider>. */
export function useArkClient() {
  const client = useContext(ArkContext);
  if (!client) throw new Error('useArk() was called outside <ArkProvider>. Wrap the app (or this part of it) in <ArkProvider>.');
  return client;
}

/**
 * The authentication state plus the client's actions. Re-renders when the state changes.
 *
 * During server rendering and hydration the state is `loading`, which keeps the server and the
 * first browser render identical.
 */
export function useArk() {
  const client = useArkClient();
  const state = useSyncExternalStore(client.subscribe, client.getSnapshot, client.getServerSnapshot);
  return useMemo(
    () => ({
      ...state,
      client,
      signinRedirect: (options) => client.signinRedirect(options),
      signinPopup: (options) => client.signinPopup(options),
      signoutRedirect: (options) => client.signoutRedirect(options),
      signoutLocal: (options) => client.signoutLocal(options),
      switchUser: (options) => client.switchUser(options),
      getAccessToken: client.getAccessToken,
      fetch: client.fetch,
      hasArkClaims: (...claims) => claims.flat().every((c) => state.arkClaims.includes(c)),
      hasAnyArkClaim: (...claims) => claims.flat().some((c) => state.arkClaims.includes(c))
    }),
    [client, state]
  );
}

/** Only the signed-in user's claims; re-renders only when the user changes. */
export function useArkUser() {
  const client = useArkClient();
  return useSyncExternalStore(
    client.subscribe,
    () => client.getSnapshot().user,
    () => null
  );
}

// ---------------------------------------------------------------------------
// Components
// ---------------------------------------------------------------------------

const box = { maxWidth: 480, margin: '15vh auto', padding: 28, borderRadius: 12, border: '1px solid rgba(127,127,127,.3)', font: '15px/1.55 ui-sans-serif, -apple-system, "Segoe UI", Roboto, sans-serif' };
const primary = { width: '100%', padding: '11px 14px', borderRadius: 8, border: '1px solid #4f46e5', background: '#4f46e5', color: '#fff', font: 'inherit', fontWeight: 560, cursor: 'pointer' };
const secondary = { ...primary, background: 'transparent', color: 'inherit', borderColor: 'rgba(127,127,127,.4)' };

function renderProp(value, ...args) {
  return typeof value === 'function' ? value(...args) : value;
}

/**
 * The page a refused account sees, with the way out: "Sign in as a different user" (prompt=login)
 * and "Sign out completely". The same wording as the server clients' access-denied page.
 */
export function ArkAccessDenied({ appName, className, style }) {
  const ark = useArk();
  const options = ark.client.config.accountSwitch;
  const name = (appName ?? options.appDisplayName ?? '').trim() || ark.client.clientId || 'this application';
  const who = ark.denial ?? ark.user;
  const account = options.showSignedInAccount ? (who?.email ?? who?.preferred_username ?? who?.name ?? who?.subject ?? who?.sub ?? null) : null;
  const returnTo = ark.denial?.returnTo ?? undefined;

  return createElement(
    'main',
    { className: className ?? 'ark-denied', role: 'alert', style: style ?? box },
    createElement('h1', { style: { margin: '0 0 10px', fontSize: 19 } }, `You do not have access to ${name}`),
    createElement(
      'p',
      null,
      account
        ? ['You are signed in as ', createElement('strong', { key: 'a' }, account), `, and that account does not have access to ${name}.`]
        : `The account you are signed in with does not have access to ${name}.`
    ),
    createElement(
      'p',
      { style: { opacity: 0.75 } },
      `If somebody else was using this browser, their sign-in is still active and it is the one being offered to ${name}. ` +
        'Choose “Sign in as a different user” to enter your own credentials.'
    ),
    createElement(
      'div',
      { style: { display: 'flex', flexDirection: 'column', gap: 10, marginTop: 20 } },
      createElement('button', { type: 'button', style: primary, onClick: () => ark.switchUser({ returnTo }) }, 'Sign in as a different user'),
      options.allowFullSignOut
        ? createElement('button', { type: 'button', style: secondary, onClick: () => ark.signoutRedirect({ returnTo: options.homePath }) }, 'Sign out completely')
        : null
    ),
    options.supportUrl || options.supportEmail
      ? createElement(
          'p',
          { style: { marginTop: 18, fontSize: 13, opacity: 0.75 } },
          `Need access to ${name}? `,
          createElement('a', { href: options.supportUrl ?? `mailto:${options.supportEmail}` }, options.supportUrl ? 'Request it here' : options.supportEmail)
        )
      : null,
    createElement('p', { style: { marginTop: 18, fontSize: 12, opacity: 0.6, textAlign: 'center' } }, `ark-oauth-client-js ${VERSION}`)
  );
}

function DefaultError({ error, retry }) {
  return createElement(
    'div',
    { role: 'alert', className: 'ark-error', style: box },
    createElement('p', { style: { margin: '0 0 14px' } }, 'Sign-in did not complete.'),
    createElement('p', { style: { margin: '0 0 14px', opacity: 0.75, fontSize: 13 } }, error?.message ?? String(error)),
    createElement('button', { type: 'button', style: primary, onClick: retry }, 'Try again')
  );
}

/**
 * Renders `children` only for a signed-in user (holding `claims`, when given), and starts the
 * sign-in otherwise. Shows `fallback` while that is being decided.
 *
 * - `claims`: every one of these Ark claims is needed; `anyClaims`: at least one.
 * - `forbidden`: shown to a signed-in user missing a claim (default: <ArkAccessDenied />).
 * - `denied`: shown when the sign-in itself was refused by `accountSwitch` (default: <ArkAccessDenied />).
 * - `error(error, retry)`: shown when the sign-in failed (default: a message and a retry button).
 *
 * After an error it does not sign in again by itself, so a misconfigured client cannot loop
 * between the app and the provider.
 */
export function RequireArk({ children, fallback = null, claims, anyClaims, forbidden, denied, error: renderError, signinOptions }) {
  const ark = useArk();
  const shouldSignIn = !ark.isLoading && !ark.isAuthenticated && ark.status !== 'denied' && !ark.error;
  const options = useRef(signinOptions);
  options.current = signinOptions;

  useEffect(() => {
    if (shouldSignIn) ark.client.signinRedirect(options.current).catch(() => {});
  }, [shouldSignIn, ark.client]);

  if (ark.isLoading || shouldSignIn) return fallback;
  if (ark.status === 'denied') return denied !== undefined ? renderProp(denied, ark.denial) : createElement(ArkAccessDenied);
  if (!ark.isAuthenticated) {
    const retry = () => ark.client.signinRedirect(options.current);
    return renderError !== undefined ? renderProp(renderError, ark.error, retry) : createElement(DefaultError, { error: ark.error, retry });
  }
  const missing = (claims?.length && !ark.hasArkClaims(claims)) || (anyClaims?.length && !ark.hasAnyArkClaim(anyClaims));
  if (missing) return forbidden !== undefined ? renderProp(forbidden, ark.user) : createElement(ArkAccessDenied);
  return children;
}

/**
 * The element for the redirect URI's route (`/signin-oidc`). The provider init()s and completes the
 * sign-in, then moves on; this only shows `children` meanwhile, or the error when it failed.
 *
 * A single-page app does need a route here (a server-side client must not have one, because it
 * would shadow the handler): without it the router renders its not-found page during the exchange.
 */
export function ArkCallback({ children = null, error: renderError }) {
  const ark = useArk();
  if (ark.error && !ark.isAuthenticated) {
    const retry = () => ark.client.signinRedirect({ returnTo: '/' });
    return renderError !== undefined ? renderProp(renderError, ark.error, retry) : createElement(DefaultError, { error: ark.error, retry });
  }
  return children;
}
