import { ArkPopupError } from './errors.js';

/**
 * Popup sign-in: the authorization request runs in a small window and its answer is handed back to
 * the page that opened it, which never navigates away.
 *
 * Opening the window is synchronous and happens before anything is awaited. Browsers let a page
 * open a popup only in direct response to a click, and the sign-in URL needs a SHA-256 (async) and
 * possibly a discovery fetch before it exists, so the window is opened blank first and pointed at
 * the provider once the URL is ready.
 *
 * The callback reaches the opener two ways, and whichever arrives first wins: `postMessage` to
 * `window.opener` (restricted to this origin), and a BroadcastChannel, for the case where a
 * Cross-Origin-Opener-Policy along the way has severed `opener`. Either way the opener accepts only
 * a response whose `state` is the one it is waiting for.
 */

export const POPUP_MESSAGE_TYPE = 'ark-oidc:callback';

export function popupChannelName(authority, clientId) {
  return `ark-oidc:${authority}|${clientId}:popup`;
}

/** Opens the (blank) popup window. Throws ArkPopupError('blocked') when the browser refuses. */
export function openPopupWindow(win, { width = 520, height = 680 } = {}) {
  const screenLeft = win.screenX ?? win.screenLeft ?? 0;
  const screenTop = win.screenY ?? win.screenTop ?? 0;
  const outerWidth = win.outerWidth ?? width;
  const outerHeight = win.outerHeight ?? height;
  const left = Math.max(0, Math.round(screenLeft + (outerWidth - width) / 2));
  const top = Math.max(0, Math.round(screenTop + (outerHeight - height) / 2));
  const features = `popup=yes,width=${width},height=${height},left=${left},top=${top},resizable=yes,scrollbars=yes`;
  let popup = null;
  try {
    popup = win.open('', 'ark-oidc-popup', features);
  } catch {
    popup = null;
  }
  if (!popup) {
    throw new ArkPopupError(
      'blocked',
      'the browser blocked the sign-in popup. Call signinPopup() directly from a click handler, before any await, or use signinRedirect().'
    );
  }
  return popup;
}

/**
 * Waits for the popup to report back with the URL it landed on.
 *
 * @returns {{ promise: Promise<string>, cancel: () => void }}
 */
export function waitForPopupCallback(win, popup, { state, channelName, timeoutMs }) {
  let settle;
  const promise = new Promise((resolve, reject) => {
    let done = false;
    let channel = null;
    let closedTimer = null;
    let closedGrace = null;
    let timeoutTimer = null;

    const cleanup = () => {
      done = true;
      win.removeEventListener('message', onMessage);
      if (channel) {
        channel.onmessage = null;
        channel.close();
      }
      clearInterval(closedTimer);
      clearTimeout(closedGrace);
      clearTimeout(timeoutTimer);
    };

    const accept = (data) => {
      if (done || !data || data.type !== POPUP_MESSAGE_TYPE || data.state !== state || typeof data.url !== 'string') return;
      cleanup();
      resolve(data.url);
    };

    const onMessage = (event) => {
      if (event.origin !== win.location.origin) return;
      accept(event.data);
    };

    win.addEventListener('message', onMessage);
    const Channel = win.BroadcastChannel ?? globalThis.BroadcastChannel;
    if (typeof Channel === 'function') {
      channel = new Channel(channelName);
      channel.onmessage = (event) => accept(event.data);
    }

    // The popup posts its result and then closes itself, so a closed window may be one whose
    // message is still in flight. A short grace period tells that apart from the user closing it.
    closedTimer = setInterval(() => {
      let closed = false;
      try {
        closed = popup.closed;
      } catch {
        closed = false;
      }
      if (closed && !done && !closedGrace) {
        closedGrace = setTimeout(() => {
          if (done) return;
          cleanup();
          reject(new ArkPopupError('closed', 'the sign-in popup was closed before the sign-in finished.'));
        }, 400);
      }
    }, 250);

    timeoutTimer = setTimeout(() => {
      if (done) return;
      cleanup();
      try {
        popup.close();
      } catch {
        /* already gone */
      }
      reject(new ArkPopupError('timeout', `the sign-in popup did not finish within ${Math.round(timeoutMs / 1000)}s.`));
    }, timeoutMs);

    settle = (error) => {
      if (done) return;
      cleanup();
      reject(error);
    };
  });
  return { promise, cancel: (error) => settle(error ?? new ArkPopupError('closed', 'the sign-in popup was cancelled.')) };
}

/**
 * Runs in the popup when it lands back on the redirect URI: hands the URL to the opener, then
 * closes. Returns false when this window is not a popup we can report to.
 */
export function relayToOpener(win, url, state, channelName) {
  let delivered = false;
  const message = { type: POPUP_MESSAGE_TYPE, url, state };

  try {
    const opener = win.opener;
    if (opener && opener !== win) {
      // targetOrigin is our own origin: the code and state are never posted to another site, even
      // if something navigated the opener away in the meantime.
      opener.postMessage(message, win.location.origin);
      delivered = true;
    }
  } catch {
    /* opener inaccessible */
  }

  const Channel = win.BroadcastChannel ?? globalThis.BroadcastChannel;
  if (typeof Channel === 'function') {
    try {
      const channel = new Channel(channelName);
      channel.postMessage(message);
      channel.close();
      delivered = delivered || Boolean(win.opener) || win.name === 'ark-oidc-popup';
    } catch {
      /* no channel */
    }
  }
  return delivered;
}
