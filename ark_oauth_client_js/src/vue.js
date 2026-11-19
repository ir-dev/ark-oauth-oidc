/**
 * Vue 3 bindings: a plugin, a composable and a vue-router guard.
 *
 *   const ark = createArk({ authority, clientId });
 *   app.use(router).use(ark);                         // router first: ark sends the user back through it
 *   router.beforeEach(createArkGuard(ark, { requireMeta: true }));   // routes with meta.requiresAuth
 *
 *   // in a component
 *   const { isAuthenticated, user, signinRedirect } = useArk();
 *
 * Works in Nuxt too: on the server the plugin installs but does not start the client.
 */
import { computed, inject, shallowRef } from 'vue';
import { ArkBrowserClient } from './client.js';

export const ARK_INJECTION_KEY = Symbol.for('ark-oauth-client-js');

/**
 * Creates the Ark plugin: the client, its state as a reactive `shallowRef`, computed shortcuts and
 * the client's actions. `app.use(ark)` provides it to `useArk()` and `$ark`, and starts the client.
 *
 * @param {object|ArkBrowserClient} optionsOrClient
 * @param {{ router?: { replace(to: string): unknown }, autoInit?: boolean }} [settings]
 */
export function createArk(optionsOrClient, { router = null, autoInit = true } = {}) {
  const client = optionsOrClient instanceof ArkBrowserClient ? optionsOrClient : new ArkBrowserClient(optionsOrClient);
  const state = shallowRef(client.getSnapshot());
  client.subscribe((snapshot) => {
    state.value = snapshot;
  });

  const ark = {
    client,
    /** The whole snapshot, reactive. */
    state,
    status: computed(() => state.value.status),
    isLoading: computed(() => state.value.isLoading),
    isAuthenticated: computed(() => state.value.isAuthenticated),
    user: computed(() => state.value.user),
    arkClaims: computed(() => state.value.arkClaims),
    scopes: computed(() => state.value.scopes),
    error: computed(() => state.value.error),
    denial: computed(() => state.value.denial),
    signinRedirect: (options) => client.signinRedirect(options),
    signinPopup: (options) => client.signinPopup(options),
    signoutRedirect: (options) => client.signoutRedirect(options),
    signoutLocal: (options) => client.signoutLocal(options),
    switchUser: (options) => client.switchUser(options),
    getAccessToken: client.getAccessToken,
    fetch: client.fetch,
    hasArkClaims: (...claims) => claims.flat().every((c) => state.value.arkClaims.includes(c)),
    hasAnyArkClaim: (...claims) => claims.flat().some((c) => state.value.arkClaims.includes(c)),

    install(app) {
      app.provide(ARK_INJECTION_KEY, ark);
      app.config.globalProperties.$ark = ark;
      if (!autoInit || typeof window === 'undefined') return;
      // vue-router reverts a URL it did not change itself, so the move after sign-in has to go
      // through the router. Found on the app when the router was installed first.
      const r = router ?? app.config.globalProperties.$router ?? null;
      client.init({ onRedirectCallback: r ? (to) => r.replace(to) : undefined });
    }
  };
  return ark;
}

/** The plugin instance from `app.use(createArk(...))`. */
export function useArk() {
  const ark = inject(ARK_INJECTION_KEY, null);
  if (!ark) throw new Error('useArk() found no Ark plugin. Call app.use(createArk({ authority, clientId })) first.');
  return ark;
}

/**
 * A vue-router navigation guard: a signed-out user is sent to sign in and comes back to the route
 * they asked for; a signed-in one without the required claims is refused.
 *
 *   router.beforeEach(createArkGuard(ark, { requireMeta: true }))             // only meta.requiresAuth routes
 *   { path: '/billing', beforeEnter: createArkGuard(ark, { claims: ['billing.admin'] }) }
 *
 * @param {{ claims?: string[], anyClaims?: string[], requireMeta?: boolean,
 *           onDenied?: (to: object, state: object) => unknown }} [options]
 *   `onDenied` decides what a refused navigation does (return a route location to redirect);
 *   by default the navigation is cancelled.
 */
export function createArkGuard(ark, { claims = [], anyClaims = [], requireMeta = false, onDenied = null } = {}) {
  return async (to) => {
    if (requireMeta && !to.meta?.requiresAuth) return true;
    // Server rendering (Nuxt) knows nobody: cancel without starting a sign-in, which needs a
    // window. The browser runs the guard again after hydration and decides there.
    if (!ark.client.isBrowser) return false;
    const state = await ark.client.init();
    // Still loading after start-up means the browser is already on its way to the provider (the
    // second half of an account switch): starting another sign-in would replace that one.
    if (state.isLoading) return false;
    const needed = [...claims, ...(to.meta?.arkClaims ?? [])];

    if (!state.isAuthenticated) {
      if (state.status === 'denied' || state.error) return onDenied ? onDenied(to, state) : false;
      await ark.client.signinRedirect({ returnTo: to.fullPath });
      return false;
    }
    const held = state.arkClaims;
    const missing = needed.some((c) => !held.includes(c)) || (anyClaims.length > 0 && !anyClaims.some((c) => held.includes(c)));
    if (missing) return onDenied ? onDenied(to, state) : false;
    return true;
  };
}

export { ArkBrowserClient };
