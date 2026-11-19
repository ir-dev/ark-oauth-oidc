// @angular/common/http ships partially compiled; outside the CLI's linker it needs the JIT compiler.
import '@angular/compiler';
import { test, describe, before, after, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { APP_INITIALIZER, EnvironmentInjector, Injector, createEnvironmentInjector, runInInjectionContext } from '@angular/core';
import { HttpErrorResponse, HttpRequest, HttpResponse } from '@angular/common/http';
import { firstValueFrom, of, throwError } from 'rxjs';
import { ARK, ARK_CLIENT, arkAuthGuard, arkClaimsGuard, arkInterceptor, createArkGuard, injectArk, provideArk } from '../src/angular.js';
import { Tab, startIdp, until } from './harness.js';
import { ArkBrowserClient } from '../src/client.js';

let idp;
let tab;
let injector;

before(async () => {
  idp = await startIdp();
});
after(async () => {
  await idp.close();
});
beforeEach(() => {
  idp.arkClaims = ['billing.admin'];
  idp.browserSession = null;
  tab = new Tab(idp);
});
afterEach(() => {
  injector?.destroy();
  injector = null;
  tab.destroy();
});

/** An environment injector with provideArk(), and its app initializers run as Angular would. */
async function bootstrap(client, settings) {
  injector = createEnvironmentInjector([provideArk(client, settings)], Injector.NULL);
  assert.ok(injector instanceof EnvironmentInjector);
  for (const init of injector.get(APP_INITIALIZER, [])) await runInInjectionContext(injector, () => init());
  return injector;
}

const inCtx = (fn) => runInInjectionContext(injector, fn);

describe('Angular adapter', () => {
  test('provideArk registers the client and starts it in an app initializer; the facade is signals', async () => {
    await tab.signIn();
    const client = tab.load('/');
    await bootstrap(client);
    assert.equal(injector.get(ARK_CLIENT), client);
    const ark = inCtx(() => injectArk());
    assert.equal(ark, injector.get(ARK));
    assert.equal(ark.isAuthenticated(), true, 'already started when the router would first read the URL');
    assert.equal(ark.user().email, 'alice@example.com');
    assert.equal(ark.hasArkClaims('billing.admin'), true);

    await client.signoutLocal();
    assert.equal(ark.isAuthenticated(), false);
    assert.equal(ark.status(), 'unauthenticated');
  });

  test('the callback is completed before routing, so the router starts on the return URL', async () => {
    const starter = tab.load('/billing');
    await starter.init();
    await starter.signinRedirect();
    const callback = await idp.authorize(tab.win.lastNavigation);
    const client = tab.load(callback);
    await bootstrap(client);
    assert.equal(tab.win.path, '/billing');
    assert.equal(inCtx(() => injectArk()).isAuthenticated(), true);
  });

  test('arkAuthGuard / arkClaimsGuard / createArkGuard', async () => {
    await bootstrap(tab.load('/'), { autoInit: false });
    assert.equal(await inCtx(() => arkAuthGuard({}, { url: '/billing' })), false);
    await until(() => tab.win.navigations.length === 1);
    assert.equal(new URL(tab.win.lastNavigation).pathname, `/${idp.tenant}/oauth2/authorize`);
    injector.destroy();

    await tab.signIn();
    await bootstrap(tab.load('/'));
    assert.equal(await inCtx(() => arkAuthGuard({}, { url: '/x' })), true);
    assert.equal(await inCtx(() => arkClaimsGuard('billing.admin')({}, { url: '/x' })), true);
    assert.equal(await inCtx(() => arkClaimsGuard('payroll.admin')({}, { url: '/x' })), false);
    const redirect = { redirectTo: '/no-access' };
    assert.equal(await inCtx(() => createArkGuard({ claims: ['payroll.admin'], onDenied: () => redirect })({}, { url: '/x' })), redirect);
  });

  test('arkInterceptor adds the bearer to the app origin and apiOrigins only, and retries a 401 once', async () => {
    await tab.signIn();
    await bootstrap(tab.load('/', { apiOrigins: ['https://api.example.com'] }));

    const seen = [];
    const ok = (req) => {
      seen.push([req.url, req.headers.get('Authorization')]);
      return of(new HttpResponse({ status: 200 }));
    };
    await firstValueFrom(inCtx(() => arkInterceptor(new HttpRequest('GET', '/api/orders'), ok)));
    await firstValueFrom(inCtx(() => arkInterceptor(new HttpRequest('GET', 'https://api.example.com/v1'), ok)));
    await firstValueFrom(inCtx(() => arkInterceptor(new HttpRequest('GET', 'https://cdn.example.net/x.json'), ok)));
    assert.match(seen[0][1], /^Bearer /);
    assert.match(seen[1][1], /^Bearer /);
    assert.equal(seen[2][1], null, 'no token for a third party');

    const before = idp.tokenRequests.length;
    let calls = 0;
    const unauthorizedOnce = (req) => {
      calls++;
      return calls === 1 ? throwError(() => new HttpErrorResponse({ status: 401 })) : ok(req);
    };
    const res = await firstValueFrom(inCtx(() => arkInterceptor(new HttpRequest('GET', '/api/me'), unauthorizedOnce)));
    assert.equal(res.status, 200);
    assert.equal(calls, 2);
    assert.equal(idp.tokenRequests.length - before, 1, 'one refresh between the two attempts');
  });

  test('on the server the guards cancel quietly instead of starting a sign-in (SSR prerender)', async () => {
    const server = new ArkBrowserClient({ authority: idp.issuer, clientId: 'spa-app', window: null });
    await bootstrap(server);
    assert.equal(server.isBrowser, false);
    assert.equal(await inCtx(() => arkAuthGuard({}, { url: '/billing' })), false);
    assert.equal(await inCtx(() => arkClaimsGuard('billing.admin')({}, { url: '/billing' })), false);
    assert.equal(inCtx(() => injectArk()).status(), 'loading');
  });
});

