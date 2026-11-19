import { dom } from './dom-first.js';
import { test, describe, before, after, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createApp, defineComponent, h, nextTick } from 'vue';
import { createArk, createArkGuard, useArk } from '../src/vue.js';
import { Tab, startIdp, until } from './harness.js';

let idp;
let tab;
let app;

before(async () => {
  idp = await startIdp();
});
after(async () => {
  await dom.uninstall();
  await idp.close();
});
beforeEach(() => {
  idp.arkClaims = ['billing.admin'];
  idp.browserSession = null;
  tab = new Tab(idp);
});
afterEach(() => {
  app?.unmount();
  app = null;
  tab.destroy();
});

const Status = defineComponent({
  setup() {
    const ark = useArk();
    return () => h('p', `${ark.status.value}|${ark.user.value?.email ?? '-'}|${ark.hasArkClaims('billing.admin')}`);
  }
});

function mount(ark, router) {
  const container = dom.container();
  app = createApp(Status);
  if (router) app.config.globalProperties.$router = router; // as app.use(router) leaves it
  app.use(ark);
  app.mount(container);
  return container;
}

describe('Vue adapter', () => {
  test('the plugin starts the client and the state is reactive', async () => {
    const ark = createArk(tab.load('/'));
    const container = mount(ark);
    assert.equal(container.textContent, 'loading|-|false');
    await ark.client.init();
    await nextTick();
    assert.equal(container.textContent, 'unauthenticated|-|false');
  });

  test('a restored session renders the user', async () => {
    await tab.signIn();
    const ark = createArk(tab.load('/'));
    const container = mount(ark);
    await ark.client.init();
    await nextTick();
    assert.equal(container.textContent, 'authenticated|alice@example.com|true');
  });

  test('after the callback the user is sent on through the installed router', async () => {
    const starter = tab.load('/reports?x=1');
    await starter.init();
    await starter.signinRedirect();
    const callback = await idp.authorize(tab.win.lastNavigation);
    const replaced = [];
    const ark = createArk(tab.load(callback));
    mount(ark, { replace: (to) => replaced.push(to) });
    await ark.client.init();
    assert.deepEqual(replaced, ['/reports?x=1']);
    assert.deepEqual(tab.win.popstates, [], 'no history poke behind the router');
  });

  test('createArkGuard: signed out is sent to sign in; signed in passes; a missing claim is refused', async () => {
    const out = createArk(tab.load('/'), { autoInit: false });
    const guard = createArkGuard(out, { requireMeta: true });
    assert.equal(await guard({ fullPath: '/public', meta: {} }), true);
    assert.equal(await guard({ fullPath: '/billing', meta: { requiresAuth: true } }), false);
    await until(() => tab.win.navigations.length === 1);
    const req = new URL(tab.win.lastNavigation);
    assert.equal(req.pathname, `/${idp.tenant}/oauth2/authorize`);
    out.client.destroy();

    await tab.signIn();
    const signedIn = createArk(tab.load('/'), { autoInit: false });
    assert.equal(await createArkGuard(signedIn)({ fullPath: '/x', meta: {} }), true);
    assert.equal(await createArkGuard(signedIn, { claims: ['payroll.admin'] })({ fullPath: '/x', meta: {} }), false);
    assert.equal(await createArkGuard(signedIn)({ fullPath: '/x', meta: { arkClaims: ['payroll.admin'] } }), false);
    assert.deepEqual(
      await createArkGuard(signedIn, { claims: ['payroll.admin'], onDenied: () => ({ path: '/no-access' }) })({ fullPath: '/x', meta: {} }),
      { path: '/no-access' }
    );
    signedIn.client.destroy();
  });

  test('on the server (Nuxt) the guard cancels quietly instead of starting a sign-in', async () => {
    const ark = createArk({ authority: idp.issuer, clientId: 'spa-app', window: null }, { autoInit: false });
    assert.equal(await createArkGuard(ark)({ fullPath: '/billing', meta: {} }), false);
  });

  test('on the server the plugin installs without starting the client', () => {
    const saved = globalThis.window;
    delete globalThis.window;
    try {
      const ark = createArk({ authority: idp.issuer, clientId: 'spa-app', window: null });
      const fakeApp = { provide() {}, config: { globalProperties: {} } };
      ark.install(fakeApp);
      assert.equal(ark.status.value, 'loading');
      assert.equal(fakeApp.config.globalProperties.$ark, ark);
    } finally {
      globalThis.window = saved;
    }
  });
});
