import { dom } from './dom-first.js';
import { test, describe, before, after, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { renderAccessDenied } from '../src/denied.js';
import { Tab, startIdp, until } from './harness.js';

let idp;
let tab;

before(async () => {
  idp = await startIdp();
});
after(async () => {
  await dom.uninstall();
  await idp.close();
});
afterEach(() => tab?.destroy());

describe('renderAccessDenied (no framework)', () => {
  test('names the refused account without interpreting it as markup, and wires the two ways out', async () => {
    idp.arkClaims = [];
    idp.user = { ...idp.user, email: '<img src=x onerror=alert(1)>@example.com' };
    tab = new Tab(idp);
    const options = { accountSwitch: { requireArkClaims: true, appDisplayName: 'Payroll', supportEmail: 'it@example.com' } };
    const { client, state } = await tab.signIn('/payroll', {}, options);
    assert.equal(state.status, 'denied');

    const container = dom.container();
    const remove = renderAccessDenied(container, client);
    assert.match(container.textContent, /You do not have access to Payroll/);
    assert.match(container.textContent, /<img src=x onerror=alert\(1\)>@example\.com/);
    assert.equal(container.querySelector('img'), null, 'the address stayed text');
    assert.equal(container.querySelector('a').getAttribute('href'), 'mailto:it@example.com');
    assert.ok(container.querySelector('.ark-denied__card').style.getPropertyValue('border-radius'), 'styled through the CSSOM');

    const [switchButton, signOutButton] = container.querySelectorAll('button');
    assert.equal(signOutButton.textContent, 'Sign out completely');
    switchButton.click();
    await until(() => tab.win.navigations.length > 0);
    const req = new URL(tab.win.lastNavigation);
    assert.equal(req.searchParams.get('prompt'), 'login');

    remove();
    assert.equal(container.children.length, 0);
  });

  test('unstyled leaves the classes for the app to style', async () => {
    tab = new Tab(idp);
    const client = tab.load('/');
    const container = dom.container();
    renderAccessDenied(container, client, { unstyled: true, appName: 'Reports' });
    assert.equal(container.querySelector('.ark-denied__card').getAttribute('style'), null);
    assert.match(container.textContent, /The account you are signed in with does not have access to Reports/);
  });
});
