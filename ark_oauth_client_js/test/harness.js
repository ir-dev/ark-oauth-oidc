import { ArkBrowserClient } from '../src/client.js';
import { MemoryStorage } from '../src/storage.js';
import { StubIdp } from './stub-idp.js';
import { APP_ORIGIN, FakeWindow } from './browser-env.js';

export { APP_ORIGIN, FakeWindow, StubIdp, MemoryStorage };

export async function startIdp(options) {
  return new StubIdp(options).listen();
}

/** A client in a fake tab, with the defaults every test shares. */
export function makeClient(idp, win, options = {}) {
  return new ArkBrowserClient({
    authority: idp.issuer,
    clientId: 'spa-app',
    window: win,
    ...options
  });
}

/**
 * One tab, one browser session: `sessionStorage` survives navigations within the tab, so every page
 * load of the "same tab" gets a new FakeWindow and a new client sharing it, like a real reload.
 */
export class Tab {
  constructor(idp, { localStorage = new MemoryStorage(), options = {} } = {}) {
    this.idp = idp;
    this.sessionStorage = new MemoryStorage();
    this.localStorage = localStorage;
    this.options = options;
    this.clients = [];
  }

  /** Loads a page of the app: a fresh window and client, sharing this tab's storage. */
  load(path = '/', options = {}) {
    this.win = new FakeWindow(new URL(path, APP_ORIGIN).toString(), { sessionStorage: this.sessionStorage, localStorage: this.localStorage });
    this.client = makeClient(this.idp, this.win, { ...this.options, ...options });
    this.clients.push(this.client);
    return this.client;
  }

  /** Signs in end to end: start on `from`, go through the provider, land on the callback, init(). */
  async signIn(from = '/orders?page=2', signinOptions = {}, clientOptions = {}) {
    const client = this.load(from, clientOptions);
    await client.init();
    await client.signinRedirect(signinOptions);
    const callback = await this.idp.authorize(this.win.lastNavigation);
    const landed = this.load(callback, clientOptions);
    const state = await landed.init();
    return { client: landed, state, callback };
  }

  destroy() {
    for (const client of this.clients) client.destroy();
  }
}

export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Waits until `predicate()` is truthy, polling; fails after `timeoutMs`. */
export async function until(predicate, { timeoutMs = 5000, stepMs = 10 } = {}) {
  const start = Date.now();
  while (!(await predicate())) {
    if (Date.now() - start > timeoutMs) throw new Error('condition not met in time');
    await sleep(stepMs);
  }
}
