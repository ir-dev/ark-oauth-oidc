import { MemoryStorage } from '../src/storage.js';

/**
 * A browser window, reduced to what the client touches: location and history, Web Storage, events,
 * window.open/opener/postMessage, a document with visibility. Node supplies the real Web Crypto,
 * fetch, BroadcastChannel and navigator.locks, and those are process-wide, so two FakeWindows in one
 * test behave like two tabs of one origin: they share locks and broadcast channels, and share
 * localStorage when handed the same object.
 *
 * Navigation away from the app (to the provider) does not change the page; it is recorded in
 * `navigations` for the test to follow, which is what lets a test play the provider's part.
 */

class PopStateEvent extends Event {
  constructor(type, init = {}) {
    super(type);
    this.state = init.state ?? null;
  }
}

export class FakeWindow {
  constructor(href, { sessionStorage = new MemoryStorage(), localStorage = new MemoryStorage(), opener = null, name = '' } = {}) {
    this.url = new URL(href);
    this.sessionStorage = sessionStorage;
    this.localStorage = localStorage;
    this.opener = opener;
    this.name = name;
    this.closed = false;
    this.navigations = [];
    this.popstates = [];
    this.opened = [];
    this.blockPopups = false;
    this.isSecureContext = true;
    this.events = new EventTarget();
    this.document = Object.assign(new EventTarget(), { visibilityState: 'visible' });
    this.navigator = globalThis.navigator;
    this.BroadcastChannel = globalThis.BroadcastChannel;
    this.PopStateEvent = PopStateEvent;
    this.historyState = null;

    const win = this;
    this.location = {
      get href() {
        return win.url.toString();
      },
      set href(value) {
        win.navigations.push(String(value));
      },
      get origin() {
        return win.url.origin;
      },
      get pathname() {
        return win.url.pathname;
      },
      get search() {
        return win.url.search;
      },
      get hash() {
        return win.url.hash;
      },
      assign(value) {
        win.navigations.push(String(value));
      },
      replace(value) {
        win.navigations.push(String(value));
      }
    };
    this.history = {
      get state() {
        return win.historyState;
      },
      replaceState(state, _title, url) {
        win.historyState = state;
        if (url !== undefined && url !== null) win.url = new URL(url, win.url);
      },
      pushState(state, _title, url) {
        this.replaceState(state, _title, url);
      }
    };
    this.addEventListener('popstate', () => this.popstates.push(this.url.pathname + this.url.search + this.url.hash));
  }

  addEventListener(type, handler, options) {
    this.events.addEventListener(type, handler, options);
  }

  removeEventListener(type, handler, options) {
    this.events.removeEventListener(type, handler, options);
  }

  dispatchEvent(event) {
    return this.events.dispatchEvent(event);
  }

  /** Delivers a message as if posted by a window of `fromOrigin`. */
  postMessage(data, targetOrigin) {
    if (targetOrigin !== '*' && targetOrigin !== this.url.origin) return;
    const event = new MessageEvent('message', { data, origin: this.sender ?? this.url.origin });
    queueMicrotask(() => this.dispatchEvent(event));
  }

  open(_url, name) {
    if (this.blockPopups) return null;
    // about:blank inherits the opener's origin, which is all the client relies on.
    const popup = new FakeWindow(`${this.url.origin}/__blank`, { opener: this, name });
    this.opened.push(popup);
    return popup;
  }

  close() {
    this.closed = true;
  }

  /** The page path, as the router would see it. */
  get path() {
    return this.url.pathname + this.url.search + this.url.hash;
  }

  /** The last address this window was sent to (the provider, usually). */
  get lastNavigation() {
    return this.navigations.at(-1);
  }
}

export const APP_ORIGIN = 'http://127.0.0.1:5173';
