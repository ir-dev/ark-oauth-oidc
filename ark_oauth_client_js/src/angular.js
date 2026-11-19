/**
 * Angular bindings (Angular 16+, standalone or NgModule, zone.js or zoneless): providers, signals,
 * functional guards and an HttpClient interceptor.
 *
 *   // app.config.ts
 *   providers: [
 *     provideArk({ authority, clientId, apiOrigins: ['https://api.example.com'] }),
 *     provideHttpClient(withInterceptors([arkInterceptor])),
 *     provideRouter(routes)
 *   ]
 *
 *   // routes
 *   { path: 'billing', canActivate: [arkClaimsGuard('billing.admin')], component: BillingComponent }
 *
 *   // a component
 *   ark = injectArk();   // ark.isAuthenticated(), ark.user(), ark.signinRedirect()
 *
 * Plain JavaScript with no decorators: everything is a factory, `inject()` and functional APIs, so
 * the package needs no Angular compilation step and works with any Angular CLI builder.
 */
import * as ng from '@angular/core';
import { catchError, from, switchMap, throwError } from 'rxjs';
import { ArkBrowserClient } from './client.js';

/** The ArkBrowserClient. */
export const ARK_CLIENT = new ng.InjectionToken('ark-oauth-client-js: ArkBrowserClient');
/** The signal-based facade returned by `injectArk()`. */
export const ARK = new ng.InjectionToken('ark-oauth-client-js: Ark');

function createFacade(client) {
  const state = ng.signal(client.getSnapshot());
  client.subscribe((snapshot) => state.set(snapshot));
  return {
    client,
    state: state.asReadonly(),
    status: ng.computed(() => state().status),
    isLoading: ng.computed(() => state().isLoading),
    isAuthenticated: ng.computed(() => state().isAuthenticated),
    user: ng.computed(() => state().user),
    arkClaims: ng.computed(() => state().arkClaims),
    scopes: ng.computed(() => state().scopes),
    error: ng.computed(() => state().error),
    denial: ng.computed(() => state().denial),
    signinRedirect: (options) => client.signinRedirect(options),
    signinPopup: (options) => client.signinPopup(options),
    signoutRedirect: (options) => client.signoutRedirect(options),
    signoutLocal: (options) => client.signoutLocal(options),
    switchUser: (options) => client.switchUser(options),
    getAccessToken: client.getAccessToken,
    fetch: client.fetch,
    hasArkClaims: (...claims) => claims.flat().every((c) => state().arkClaims.includes(c)),
    hasAnyArkClaim: (...claims) => claims.flat().some((c) => state().arkClaims.includes(c))
  };
}

/**
 * Registers the client and starts it before the app's first navigation.
 *
 * Starting it in an app initializer means the sign-in callback is completed, and the address bar
 * already reads the page the user started from, by the time the router reads the URL. Guards then
 * see the final state on their first run.
 *
 * @param {object|ArkBrowserClient} optionsOrClient
 * @param {{ autoInit?: boolean, onRedirectCallback?: (returnTo: string) => unknown }} [settings]
 */
export function provideArk(optionsOrClient, { autoInit = true, onRedirectCallback } = {}) {
  // inject() runs in the factory, which is always an injection context; the function it returns
  // only starts the client. Older Angular does not run APP_INITIALIZER functions in one.
  const prepare = () => {
    const client = ng.inject(ARK_CLIENT);
    ng.inject(ARK); // the facade subscribes before the first state change
    return () => (autoInit ? client.init(onRedirectCallback ? { onRedirectCallback } : {}) : undefined);
  };
  // provideAppInitializer arrived in Angular 19 and APP_INITIALIZER is deprecated from then on;
  // use whichever this Angular has.
  const initializer =
    typeof ng.provideAppInitializer === 'function'
      ? ng.provideAppInitializer(() => prepare()())
      : { provide: ng.APP_INITIALIZER, multi: true, useFactory: prepare };

  return ng.makeEnvironmentProviders([
    {
      provide: ARK_CLIENT,
      useFactory: () => (optionsOrClient instanceof ArkBrowserClient ? optionsOrClient : new ArkBrowserClient(optionsOrClient))
    },
    { provide: ARK, useFactory: () => createFacade(ng.inject(ARK_CLIENT)) },
    initializer
  ]);
}

/** The facade: signals for the state, plus the client's actions. Call in an injection context. */
export function injectArk() {
  return ng.inject(ARK);
}

let warnedServerGuard = false;

/**
 * A guarded route rendered on the server can only be cancelled, and Angular reports a cancelled
 * prerender as "The content returned was empty", which says nothing about why. Said once, here.
 */
function warnServerGuard(url) {
  if (warnedServerGuard) return;
  warnedServerGuard = true;
  console.warn(
    `ark-oauth-client-js: an Ark route guard ran during server rendering${url ? ` (${url})` : ''}. Who is signed in is known only ` +
      "in the browser, so the guard cancelled. Render routes behind an Ark guard on the client: { path: '…', renderMode: RenderMode.Client } " +
      'in app.routes.server.ts.'
  );
}

function guard({ claims = [], anyClaims = [], onDenied = null } = {}) {
  return async (route, routerState) => {
    const client = ng.inject(ARK_CLIENT);
    // Server rendering knows nobody: cancel without starting a sign-in (which needs a window).
    // The browser runs the guard again after hydration and decides there.
    if (!client.isBrowser) {
      warnServerGuard(routerState?.url);
      return false;
    }
    const state = await client.init();
    // Still loading after start-up means the browser is already on its way to the provider (the
    // second half of an account switch): starting another sign-in would replace that one.
    if (state.isLoading) return false;
    if (!state.isAuthenticated) {
      if (state.status === 'denied' || state.error) return onDenied ? onDenied(route, routerState) : false;
      await client.signinRedirect({ returnTo: routerState?.url ?? undefined });
      return false;
    }
    const held = state.arkClaims;
    const missing = claims.some((c) => !held.includes(c)) || (anyClaims.length > 0 && !anyClaims.some((c) => held.includes(c)));
    if (missing) return onDenied ? onDenied(route, routerState) : false;
    return true;
  };
}

/** CanActivateFn: a signed-out user is sent to sign in and returns to the route they asked for. */
export const arkAuthGuard = guard();

/** CanActivateFn requiring every one of these Ark authorization claims. */
export function arkClaimsGuard(...claims) {
  return guard({ claims: claims.flat() });
}

/**
 * A configurable CanActivateFn. `onDenied(route, state)` decides what a refused navigation does;
 * return `inject(Router).parseUrl('/no-access')` from it to redirect.
 */
export function createArkGuard(options) {
  return guard(options);
}

/**
 * HttpInterceptorFn: attaches the access token to requests for the app's own origin and the
 * origins in `apiOrigins` (never to anything else), and retries a 401 once after a refresh.
 */
export const arkInterceptor = (req, next) => {
  const client = ng.inject(ARK_CLIENT);
  if (!client.isApiUrl(req.url)) return next(req);
  const withToken = (token) => (token ? req.clone({ setHeaders: { Authorization: `Bearer ${token}` } }) : req);
  return from(client.getAccessToken()).pipe(
    switchMap((token) =>
      next(withToken(token)).pipe(
        catchError((error) => {
          if (!token || error?.status !== 401) return throwError(() => error);
          return from(client.getAccessToken({ forceRefresh: true }).catch(() => null)).pipe(
            switchMap((renewed) => (renewed ? next(withToken(renewed)) : throwError(() => error)))
          );
        })
      )
    )
  );
};

export { ArkBrowserClient };
