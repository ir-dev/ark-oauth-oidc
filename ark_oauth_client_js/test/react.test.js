import { test, describe, before, after, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createElement as h, act } from 'react';
import { createRoot } from 'react-dom/client';
import { renderToString } from 'react-dom/server';
import { ArkProvider, ArkCallback, RequireArk, useArk, useArkUser } from '../src/react.js';
import { Tab, startIdp, until } from './harness.js';
import { installDom } from './dom.js';

let idp;
let dom;
let tab;
let root;

before(async () => {
  idp = await startIdp();
  dom = installDom();
});
after(async () => {
  await dom.uninstall();
  await idp.close();
});
beforeEach(() => {
  idp.arkClaims = ['billing.admin'];
  idp.browserSession = null;
  idp.misbehave = {};
  tab = new Tab(idp);
});
afterEach(async () => {
  if (root) await act(async () => root.unmount());
  root = null;
  tab.destroy();
});

async function render(element) {
  const container = dom.container();
  root = createRoot(container);
  await act(async () => root.render(element));
  return container;
}

function Status() {
  const ark = useArk();
  const user = useArkUser();
  return h('p', { id: 'status' }, `${ark.status}|${user?.email ?? '-'}|${ark.hasArkClaims('billing.admin')}`);
}

describe('React adapter', () => {
  test('ArkProvider starts the client and useArk() re-renders on change', async () => {
    const client = tab.load('/');
    const container = await render(h(ArkProvider, { client }, h(Status)));
    await act(async () => client.init());
    assert.equal(container.textContent, 'unauthenticated|-|false');
  });

  test('a restored session renders the user and claims', async () => {
    await tab.signIn();
    const client = tab.load('/');
    const container = await render(h(ArkProvider, { client }, h(Status)));
    await act(async () => client.init());
    assert.equal(container.textContent, 'authenticated|alice@example.com|true');
  });

  test('on the callback route, the provider completes the sign-in and calls onRedirectCallback', async () => {
    const starter = tab.load('/orders');
    await starter.init();
    await starter.signinRedirect();
    const callback = await idp.authorize(tab.win.lastNavigation);
    const client = tab.load(callback);
    const went = [];
    const container = await render(
      h(ArkProvider, { client, onRedirectCallback: (to) => went.push(to) }, h(ArkCallback, null, h('p', null, 'Signing you in…')), h(Status))
    );
    await act(async () => client.init());
    assert.deepEqual(went, ['/orders']);
    assert.match(container.textContent, /authenticated\|alice@example.com/);
  });

  test('ArkProvider can create the client from options', async () => {
    const container = await render(h(ArkProvider, { options: { authority: idp.issuer, clientId: 'spa-app', window: tab.load('/').config && tab.win } }, h(Status)));
    await until(() => container.textContent.startsWith('unauthenticated'));
  });

  test('RequireArk starts the sign-in for a signed-out user and shows the fallback meanwhile', async () => {
    const client = tab.load('/secret');
    const container = await render(h(ArkProvider, { client }, h(RequireArk, { fallback: h('i', null, 'loading') }, h('p', null, 'secret'))));
    await act(async () => client.init());
    await until(() => tab.win.navigations.length === 1);
    assert.equal(container.textContent, 'loading');
    const req = new URL(tab.win.lastNavigation);
    assert.equal(req.pathname, `/${idp.tenant}/oauth2/authorize`);
  });

  test('RequireArk renders children for a signed-in user, and the access-denied card when a claim is missing', async () => {
    await tab.signIn();
    const client = tab.load('/');
    const container = await render(
      h(ArkProvider, { client }, h(RequireArk, null, h('p', null, 'ok')), h(RequireArk, { claims: ['payroll.admin'] }, h('p', null, 'payroll')))
    );
    await act(async () => client.init());
    assert.match(container.textContent, /^ok/);
    assert.match(container.textContent, /You do not have access to spa-app/);
    assert.match(container.textContent, /signed in as alice@example.com/);
    assert.doesNotMatch(container.textContent, /payroll$/);
  });

  test('a refused sign-in renders the dead end, and "Sign in as a different user" sends prompt=login', async () => {
    idp.arkClaims = [];
    const options = { accountSwitch: { requireArkClaims: true, appDisplayName: 'Billing' } };
    await tab.signIn('/billing', {}, options);
    const client = tab.load('/billing', options);
    const container = await render(h(ArkProvider, { client }, h(RequireArk, null, h('p', null, 'billing'))));
    await act(async () => client.init());
    assert.match(container.textContent, /You do not have access to Billing/);
    const button = [...container.querySelectorAll('button')].find((b) => b.textContent === 'Sign in as a different user');
    await act(async () => {
      button.click();
    });
    await until(() => tab.win.navigations.length > 0);
    assert.equal(new URL(tab.win.lastNavigation).searchParams.get('prompt'), 'login');
  });

  test('after a failed sign-in RequireArk shows the error with a retry, and does not loop', async () => {
    idp.misbehave.authorizeError = 'access_denied';
    const starter = tab.load('/');
    await starter.init();
    await starter.signinRedirect();
    const callback = await idp.authorize(tab.win.lastNavigation);
    const client = tab.load(callback);
    const container = await render(h(ArkProvider, { client }, h(RequireArk, null, h('p', null, 'x'))));
    await act(async () => client.init());
    assert.match(container.textContent, /Sign-in did not complete/);
    assert.match(container.textContent, /access_denied/);
    assert.equal(tab.win.navigations.length, 0, 'no automatic retry');
  });

  test('server rendering shows the loading state (and so matches the first browser render)', () => {
    const client = tab.load('/');
    const html = renderToString(h(ArkProvider, { client }, h(Status)));
    assert.match(html, /loading\|-\|false/);
  });
});
