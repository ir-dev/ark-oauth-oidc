import { DEFAULT_POST_LOGOUT_PATH, normalizeConfig } from './config.js';
import { MetadataResolver } from './discovery.js';
import { JwksCache } from './jwks.js';
import { TokenSet } from './tokens.js';
import { getJson, postForm, postFormNoCors } from './http.js';
import { createNonce, createPkcePair, createState } from './pkce.js';
import { base64UrlEncode, constantTimeEqual, sha256 } from './crypto.js';
import { verifyJwt } from './jwt.js';
import { ArkStore, INITIAL_SNAPSHOT } from './store.js';
import { keysWithPrefix, readJson, remove, resolveStorage, writeJson } from './storage.js';
import { withLock } from './lock.js';
import { openPopupWindow, popupChannelName, relayToOpener, waitForPopupCallback } from './popup.js';
import { ArkAccessDeniedReasons, describeDenial, evaluateAccess, localOrDefault } from './access.js';
import {
  ArkCallbackError,
  ArkConfigError,
  ArkError,
  ArkLoginRequiredError,
  ArkNetworkError,
  ArkOAuthError,
  ArkTokenError
} from './errors.js';

/** Parameters of an authorization response, stripped from the URL once read. */
const RESPONSE_PARAMS = ['code', 'state', 'iss', 'error', 'error_description', 'error_uri', 'session_state'];
const DENIAL_TTL_SECONDS = 300;
const RETRY_AFTER_NETWORK_FAILURE_MS = 15_000;
const SPENT_TOKENS_REMEMBERED = 50;
const MAX_TIMER_MS = 2_147_483_647;
const EVENTS = ['signedIn', 'signedOut', 'tokensRefreshed', 'refreshFailed', 'sessionExpired', 'accessDenied', 'error'];

const now = () => Math.floor(Date.now() / 1000);
let instanceCounter = 0;

/**
 * Lets a long-lived timer or channel not hold a Node process open (unit tests of an app, SSR).
 * Browsers return a number from setTimeout and have no unref, so this is a no-op there.
 */
function unref(handle) {
  if (handle && typeof handle.unref === 'function') handle.unref();
  return handle;
}

/**
 * The Ark OpenID Connect client for browser apps: React, Next.js, Vue, Angular, Svelte, or none.
 *
 * One instance per app. It runs the authorization code flow with PKCE as a public client, validates
 * the ID token (signature, issuer, audience, nonce, at_hash, c_hash) in the browser, keeps the
 * session renewed with rotating refresh tokens, and exposes the result as a small observable state
 * that any framework can bind to. The framework adapters (`ark-oauth-client-js/react`, `/vue`,
 * `/angular`, `/next`) are thin wrappers over exactly this object.
 *
 *   const ark = new ArkBrowserClient({ authority: 'https://idp.example.com/my_idp', clientId: 'my-spa' });
 *   await ark.init();                          // handles /signin-oidc, restores the session
 *   if (!ark.getSnapshot().isAuthenticated) await ark.signinRedirect();
 *   const res = await ark.fetch('/api/orders'); // bearer attached, refreshed when needed
 *
 * Nothing touches `window` until `init()` or a sign-in method is called, so creating the client
 * during server-side rendering is safe; on the server it simply stays in the `loading` state.
 */
export class ArkBrowserClient {
  #config;
  #win;
  #metadata;
  #jwks = null;
  #store = new ArkStore();
  #events = new Map(EVENTS.map((name) => [name, new Set()]));
  #id = `ark-${++instanceCounter}-${Math.random().toString(36).slice(2, 8)}`;

  #ready = false;
  #storage = null;
  #storageKind = 'memory';
  #txStorage = null;
  #spentStorage = null;
  #prefix;

  #tokens = null;
  #derived = { claims: null, arkClaims: Object.freeze([]), scopes: Object.freeze([]) };
  #denial = null;

  #initPromise = null;
  #refreshPromise = null;
  #timer = null;
  #channel = null;
  #detach = [];
  #destroyed = false;

  constructor(options = {}) {
    this.#config = normalizeConfig(options);
    this.#win = options.window !== undefined ? options.window : typeof window !== 'undefined' ? window : null;
    this.#prefix = `ark.oidc:${this.#config.clientId}@${this.#config.authority}:`;
    this.#metadata = new MetadataResolver(this.#config.authority, {
      ttlMs: this.#config.metadataTtlMs,
      timeoutMs: this.#config.timeoutMs,
      fetch: this.#config.fetch
    });

    // Stable references: React's useSyncExternalStore and Svelte's `$store` call these detached.
    this.subscribe = this.subscribe.bind(this);
    this.getSnapshot = this.getSnapshot.bind(this);
    this.getServerSnapshot = this.getServerSnapshot.bind(this);
    this.fetch = this.fetch.bind(this);
    this.getAccessToken = this.getAccessToken.bind(this);
  }

  get config() {
    return this.#config;
  }

  get authority() {
    return this.#config.authority;
  }

  get clientId() {
    return this.#config.clientId;
  }

  /**
   * False during server-side rendering (no window): the client stays `loading` and every action
   * that needs a browser waits for one. Route guards use it to cancel quietly on the server and
   * decide in the browser, after hydration.
   */
  get isBrowser() {
    return Boolean(this.#win);
  }

  // =================================================================
  // State: the framework-agnostic surface
  // =================================================================

  /** The current state. The same frozen object until something changes. */
  getSnapshot() {
    return this.#store.get();
  }

  /** The state during server-side rendering and hydration: always `loading`. */
  getServerSnapshot() {
    return INITIAL_SNAPSHOT;
  }

  /** Calls `listener(snapshot)` on every change. Returns the unsubscribe function. */
  subscribe(listener) {
    return this.#store.subscribe(listener);
  }

  /**
   * The state as a Svelte-compatible store (`$ark.state` in a component): `subscribe` calls the
   * listener straight away with the current value, then on every change.
   */
  get state() {
    return {
      subscribe: (run) => {
        run(this.#store.get());
        return this.#store.subscribe(run);
      }
    };
  }

  /** The signed-in user's ID token claims, or null. */
  getUser() {
    return this.#store.get().user;
  }

  /**
   * Listens for one event: `signedIn`, `signedOut`, `tokensRefreshed`, `refreshFailed`,
   * `sessionExpired`, `accessDenied` or `error`. Returns the unsubscribe function.
   */
  on(event, handler) {
    const set = this.#events.get(event);
    if (!set) throw new ArkConfigError(`ark_oauth_client: unknown event '${event}'. Known events: ${EVENTS.join(', ')}.`);
    set.add(handler);
    return () => set.delete(handler);
  }

  /** True when the user holds every one of these Ark authorization claims. */
  hasArkClaims(...claims) {
    const held = this.#store.get().arkClaims;
    return claims.flat().every((c) => held.includes(c));
  }

  /** True when the user holds at least one of these Ark authorization claims. */
  hasAnyArkClaim(...claims) {
    const held = this.#store.get().arkClaims;
    return claims.flat().some((c) => held.includes(c));
  }

  /** True when every one of these scopes was granted. */
  hasScopes(...scopes) {
    const granted = this.#store.get().scopes;
    return scopes.flat().every((s) => granted.includes(s));
  }

  // =================================================================
  // Start-up
  // =================================================================

  /**
   * Starts the client: completes a sign-in when the page is the redirect URI, completes a sign-out
   * when it is the post-logout URI, otherwise restores the stored session (refreshing it if the
   * access token expired while the page was closed). Resolves with the snapshot; never rejects: a
   * failure lands in `snapshot.error` and the `error` event.
   *
   * Idempotent: every call after the first returns the first call's promise, so React StrictMode's
   * double effects and several components calling it at once all share one start-up.
   *
   * After a completed sign-in the browser is sent to the page the user started from, through
   * `onRedirectCallback(returnTo)` when given (pass your router's navigate here), otherwise through
   * `history.replaceState` plus a `popstate` event, which React Router and the Angular router follow.
   *
   * @param {{ handleCallback?: boolean, onRedirectCallback?: (returnTo: string, result: object) => unknown }} [options]
   */
  init(options = {}) {
    if (!this.#win) return Promise.resolve(this.#store.get());
    this.#initPromise ??= this.#runInit(options);
    return this.#initPromise;
  }

  async #runInit({ handleCallback = true, onRedirectCallback } = {}) {
    this.#ensureReady();
    this.#attachListeners();
    this.#sweepTransactions();

    const href = this.#win.location.href;
    // Not awaited: a router navigation runs the app's guards, and a guard that awaits init() would
    // otherwise wait on the very promise that is waiting on it.
    const navigate = (to, result) => {
      const handler = onRedirectCallback ?? this.#config.onRedirectCallback;
      if (!handler) return this.#navigate(to);
      try {
        Promise.resolve(handler(to, result)).catch((error) => this.#emit('error', error));
      } catch (error) {
        this.#emit('error', error);
      }
    };

    try {
      const kind = handleCallback ? this.#classify(href) : null;

      if (kind === 'signin') {
        let result;
        try {
          result = await this.handleRedirectCallback(href);
        } catch (error) {
          // The page stays on the (now cleaned) callback URL with the error in the state: sending
          // the user back to a guarded page would start the same failing sign-in again, in a loop.
          this.#restore();
          await this.#renewIfNeeded();
          return this.#fail(error);
        }
        if (result.relayed) return this.#store.get(); // a popup, about to close
        navigate(result.returnTo, result);
        return this.#store.get();
      }

      if (kind === 'signout') {
        const next = this.#takeLogoutTransaction(href);
        if (next?.then === 'signin') {
          // The second half of an account switch. The state stays `loading` until the browser has
          // left: published as `unauthenticated`, a route guard would start a sign-in of its own,
          // without the prompt=login this one carries.
          await this.signinRedirect({ prompt: next.prompt ?? this.#config.accountSwitch.prompt, returnTo: next.returnTo, loginHint: next.loginHint });
          return this.#store.get();
        }
        this.#publish({ error: null });
        navigate(next?.returnTo ?? localOrDefault(this.#config.accountSwitch.homePath), { signedOut: true });
        return this.#store.get();
      }

      this.#restore();
      await this.#renewIfNeeded();
      this.#publish();
      this.#schedule();
    } catch (error) {
      return this.#fail(error);
    }
    return this.#store.get();
  }

  // =================================================================
  // Signing in
  // =================================================================

  /**
   * Builds the authorization request and the transaction that must survive until the user comes
   * back. For custom flows; `signinRedirect()` and `signinPopup()` use it.
   *
   * @returns {Promise<{ url: string, transaction: object }>}
   */
  async createAuthorizationUrl(options = {}) {
    const win = this.#requireWindow();
    const config = this.#config;
    const metadata = await this.metadata();

    if (metadata.require_pushed_authorization_requests === true) {
      throw new ArkConfigError(
        'the tenant requires pushed authorization requests, which a browser app cannot make (/oauth2/par needs client ' +
          'authentication and serves no CORS). Turn RequirePushedAuthorizationRequests off for this tenant, or the client\'s ' +
          'require_par flag, or sign in through a server-side client.'
      );
    }
    if (!metadata.authorization_endpoint) {
      throw new ArkOAuthError('server_error', "the provider's metadata has no 'authorization_endpoint'.", { endpoint: config.authority });
    }

    const redirectUri = this.#resolve(options.redirectUri ?? config.redirectUri);
    const scopes = options.scopes?.length ? [...options.scopes] : [...config.scopes];
    const { codeVerifier, codeChallenge, codeChallengeMethod } = await createPkcePair();
    const state = createState();
    const nonce = scopes.includes('openid') ? createNonce() : null;
    const prompt = options.prompt ?? config.prompt;
    const acrValues = options.acrValues ?? config.acrValues;
    const responseMode = options.responseMode ?? config.responseMode;

    // Extra parameters go first so they can add to the request but never replace what its security
    // rests on: an `extra` carrying its own state or code_challenge would detach the response from
    // the transaction returned here.
    const params = {
      ...config.extraAuthorizationParams,
      ...options.extra,
      response_type: 'code',
      client_id: config.clientId,
      redirect_uri: redirectUri,
      scope: scopes.join(' '),
      state,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod,
      response_mode: responseMode,
      ...(nonce ? { nonce } : {}),
      ...(prompt ? { prompt } : {}),
      ...(options.loginHint ? { login_hint: options.loginHint } : {}),
      ...(options.maxAge !== undefined && options.maxAge !== null ? { max_age: String(options.maxAge) } : {}),
      ...(acrValues ? { acr_values: acrValues } : {})
    };
    const query = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== ''));

    const here = `${win.location.pathname}${win.location.search}${win.location.hash}`;
    const returnTo = localOrDefault(options.returnTo ?? (this.#classify(win.location.href) ? '/' : here), '/');

    return {
      url: `${metadata.authorization_endpoint}${metadata.authorization_endpoint.includes('?') ? '&' : '?'}${query}`,
      transaction: {
        state,
        nonce,
        codeVerifier,
        redirectUri,
        responseMode,
        scope: scopes.join(' '),
        maxAge: options.maxAge ?? null,
        returnTo,
        createdAt: now()
      }
    };
  }

  /**
   * Sends the browser to the provider's sign-in page. The promise resolves as the page unloads.
   *
   * @param {{ returnTo?: string, prompt?: string, loginHint?: string, scopes?: string[], maxAge?: number,
   *           acrValues?: string, extra?: Record<string, string> }} [options]
   */
  async signinRedirect(options = {}) {
    this.#ensureReady();
    const { url, transaction } = await this.createAuthorizationUrl(options);
    this.#saveTransaction(transaction);
    await this.#redirect(url);
  }

  /**
   * Signs in through a popup window; the page never navigates. Call it straight from a click
   * handler, before any `await`, or the browser blocks the popup. The popup lands on the redirect
   * URI, whose page (this same app, calling `init()`) passes the result back here and closes.
   *
   * @returns {Promise<{ user: object|null, denied: boolean, returnTo: string }>}
   */
  async signinPopup(options = {}) {
    const win = this.#requireWindow();
    // Synchronously, before anything is awaited: see popup.js.
    const popup = options.popupWindow ?? openPopupWindow(win, this.#config.popup);
    let waiter = null;
    try {
      this.#ensureReady();
      const { url, transaction } = await this.createAuthorizationUrl(options);
      waiter = waitForPopupCallback(win, popup, {
        state: transaction.state,
        channelName: popupChannelName(this.#config.authority, this.#config.clientId),
        timeoutMs: this.#config.popup.timeoutMs
      });
      popup.location.href = url;
      const responseUrl = await waiter.promise;
      const params = this.#responseParams(new URL(responseUrl), transaction.responseMode);
      if (params.error) throw this.#authorizationError(params);
      return await this.#completeSignin(params, transaction);
    } catch (error) {
      waiter?.cancel(error);
      this.#publish({ error: error instanceof ArkError ? error : new ArkError(String(error?.message ?? error)) });
      this.#emit('error', error);
      throw error;
    } finally {
      try {
        if (!popup.closed) popup.close();
      } catch {
        /* already gone */
      }
    }
  }

  /** Whether a URL is this client's sign-in callback: the redirect URI carrying a code or an error. */
  isSigninCallback(url) {
    return this.#classify(String(url ?? this.#requireWindow().location.href)) === 'signin';
  }

  /**
   * Completes a sign-in from the authorization response in `url` (default: the current URL).
   * `init()` calls this for you; call it yourself only with `init({ handleCallback: false })`.
   *
   * The checks, in order: an `error` response surfaces as an error; `state` must match a sign-in this
   * tab started (constant-time, single use); `iss` must be the provider (RFC 9207); the code is
   * redeemed with the PKCE verifier only this tab holds; the ID token is verified against the
   * provider's keys, the `nonce`, `at_hash` and `c_hash`; then the access check, when configured.
   * The response parameters are removed from the address bar either way, so a reload cannot replay them.
   *
   * @returns {Promise<{ returnTo: string, user: object|null, denied: boolean, relayed?: boolean }>}
   */
  async handleRedirectCallback(url) {
    const win = this.#requireWindow();
    this.#ensureReady();
    const href = String(url ?? win.location.href);
    const parsed = new URL(href, win.location.href);
    const params = this.#responseParams(parsed);
    const transaction = params.state ? this.#takeTransaction(params.state) : null;

    if (!transaction && params.state) {
      // No sign-in with this state started in this tab: if this window is a sign-in popup, the
      // opener holds the transaction. Hand the response over and close.
      if (relayToOpener(win, href, params.state, popupChannelName(this.#config.authority, this.#config.clientId))) {
        setTimeout(() => {
          try {
            win.close();
          } catch {
            /* not closable */
          }
        }, 50);
        return { relayed: true, returnTo: null, user: null, denied: false };
      }
    }

    this.#cleanResponseFromUrl(parsed);

    if (params.error) throw this.#authorizationError(params);
    if (!params.state) throw new ArkCallbackError('the authorization response carried no `state`.');
    if (!transaction) {
      throw new ArkCallbackError(
        'the authorization response does not belong to a sign-in started in this tab (unknown or expired `state`). ' +
          'Start the sign-in again. If this keeps happening, check that the redirect URI is served by this same origin, ' +
          'and that storage is not being cleared between the two pages.'
      );
    }
    if (!constantTimeEqual(String(params.state), String(transaction.state))) {
      throw new ArkCallbackError('the authorization response `state` does not match the request. Treat this as a CSRF attempt.');
    }
    return this.#completeSignin(params, transaction);
  }

  async #completeSignin(params, transaction) {
    const metadata = await this.metadata();

    // RFC 9207. Ark always sends `iss`; when the provider advertises it, a response without one is
    // as suspect as a wrong one, because stripping the parameter is how a mix-up attack hides.
    if (params.iss || metadata.authorization_response_iss_parameter_supported) {
      if (!params.iss) throw new ArkCallbackError('the provider advertises `iss` in authorization responses but this one has none.');
      if (params.iss !== metadata.issuer) throw new ArkCallbackError(`the authorization response came from '${params.iss}', not from '${metadata.issuer}'.`);
    }
    if (!params.code) throw new ArkCallbackError('the authorization response carried no `code`.');

    const tokens = await this.#exchangeCode({
      code: params.code,
      codeVerifier: transaction.codeVerifier,
      redirectUri: transaction.redirectUri,
      nonce: transaction.nonce ?? null,
      maxAge: transaction.maxAge ?? null
    });

    const returnTo = localOrDefault(transaction.returnTo, '/');
    const arkClaims = tokens.arkClaims();
    const allowed = await evaluateAccess(this.#config.accountSwitch, this.#config.onEvaluateAccess, {
      claims: tokens.claims ?? {},
      arkClaims,
      tokens
    });

    if (!allowed) {
      // No token is stored for an account that cannot use the app. The refused identity is kept
      // briefly, tab-local, so the dead end can say whose session it is and offer the way out.
      const denial = describeDenial(ArkAccessDeniedReasons.NO_APP_ACCESS, tokens.claims, arkClaims, returnTo);
      this.#setDenial({ ...denial, idTokenHint: tokens.idToken, createdAt: now() });
      this.#setTokens(null);
      if (tokens.refreshToken) this.#revokeQuietly(tokens.refreshToken);
      this.#publish({ error: null });
      this.#emit('accessDenied', this.#store.get().denial);
      return { returnTo: this.#config.accountSwitch.accessDeniedPath ?? returnTo, user: tokens.claims, denied: true };
    }

    this.#setDenial(null);
    this.#setTokens(tokens);
    this.#publish({ error: null });
    this.#schedule();
    this.#emit('signedIn', { user: tokens.claims, returnTo });
    this.#broadcast('signed-in');
    return { returnTo, user: tokens.claims, denied: false };
  }

  // =================================================================
  // Using the session
  // =================================================================

  /**
   * The access token for an API call, refreshed first when it is about to expire; null when nobody
   * is signed in or the session can no longer be renewed.
   *
   * Read it per call and never keep it: the client replaces it underneath you on every refresh.
   */
  async getAccessToken({ forceRefresh = false } = {}) {
    if (!this.#win) return null;
    this.#ensureReady();
    if (this.#initPromise) await this.#initPromise;
    else this.#restore();

    if (!this.#tokens) return null;
    if (forceRefresh || this.#tokens.expired(this.#leeway(this.#tokens))) {
      if (!this.#tokens.refreshToken) {
        if (this.#tokens.expired(0)) {
          this.#endLocalSession('expired', { broadcast: false });
          this.#emit('sessionExpired', { reason: 'expired' });
          return null;
        }
        return this.#tokens.accessToken;
      }
      try {
        await this.refresh();
      } catch (error) {
        if (!this.#tokens) return null; // the session ended (refresh token refused)
        if (this.#tokens.expired(0)) throw error; // offline with a dead token: say so
      }
    }
    return this.#tokens?.accessToken ?? null;
  }

  /**
   * Redeems the refresh token now. Concurrent calls, in this tab and (with Web Locks) across tabs,
   * share one request: Ark rotates refresh tokens and revokes the whole family if a retired one is
   * presented again, so two refreshes racing with the same token would sign the user out.
   */
  refresh() {
    this.#refreshPromise ??= this.#refreshUnderLock().finally(() => {
      this.#refreshPromise = null;
    });
    return this.#refreshPromise;
  }

  async #refreshUnderLock() {
    this.#ensureReady();
    if (!this.#tokens?.refreshToken) throw new ArkLoginRequiredError('there is no refresh token to renew the session with.');

    return withLock(`${this.#prefix}refresh`, async () => {
      if (this.#destroyed) throw new ArkError('the client was destroyed.');
      let current = this.#tokens;
      if (!current?.refreshToken) throw new ArkLoginRequiredError();

      if (this.#storageKind !== 'memory') {
        // Another tab (localStorage), or another instance on this page (a hot-module reload, a
        // micro-frontend; sessionStorage too), may have refreshed or signed out while this one
        // waited for the lock. Redeeming the token it already spent would revoke the family.
        const stored = this.#readStoredTokens();
        if (!stored) {
          this.#endLocalSession('signout', { broadcast: false });
          throw new ArkLoginRequiredError();
        }
        if (stored.refreshToken !== current.refreshToken) {
          if (!stored.expired(this.#leeway(stored))) {
            this.#setTokens(stored, { persist: false });
            this.#publish({ error: null });
            this.#schedule();
            return stored;
          }
          current = stored;
        }
      }

      if (await this.#isSpent(current.refreshToken)) {
        // Redeemed already, from a copy of this tab's storage ("Duplicate tab" copies
        // sessionStorage). Presenting it again would look like theft to the server and revoke the
        // family for both tabs; this tab signs in afresh instead (silently, while SSO lasts).
        this.#endLocalSession('expired', { broadcast: false });
        this.#emit('sessionExpired', { reason: 'refresh_token_spent' });
        throw new ArkLoginRequiredError('this tab\'s refresh token was already redeemed by a copy of it (a duplicated tab). Sign in again.');
      }

      let tokens;
      try {
        const metadata = await this.metadata();
        const response = await this.#tokenRequest(metadata.token_endpoint, {
          grant_type: 'refresh_token',
          refresh_token: current.refreshToken
        });
        if (response.refresh_token && response.refresh_token !== current.refreshToken) {
          // The server has rotated: the token just presented is spent, whatever happens next. Keep
          // the new one before anything else can fail (the ID token check below may fetch JWKS),
          // or a retry would present the spent token and the whole family would be revoked.
          await this.#markSpent(current.refreshToken);
          current = TokenSet.fromJSON({ ...current.toJSON(), refresh_token: response.refresh_token });
          this.#setTokens(current);
        }
        tokens = await this.#toTokenSet(response, { nonce: null, subject: current.claims?.sub ?? null, previous: current });
      } catch (error) {
        this.#onRefreshFailure(error);
        throw error;
      }

      // Stored even by a client destroyed mid-request: the server has already rotated, so the old
      // refresh token in storage is spent, and the next instance must find the new one there.
      this.#setTokens(tokens);
      if (this.#destroyed) return tokens;
      this.#publish({ error: null });
      this.#schedule();
      this.#emit('tokensRefreshed', { expiresAt: tokens.expiresAt });
      this.#broadcast('tokens');
      return tokens;
    }, this.#win);
  }

  #onRefreshFailure(error) {
    const fatal =
      error instanceof ArkTokenError ||
      (error instanceof ArkOAuthError && ['invalid_grant', 'invalid_client', 'unauthorized_client'].includes(error.error));
    if (fatal) {
      // The refresh token was refused (expired, revoked, its session ended, the account or the
      // client deactivated) or what came back cannot be trusted. Either way the session is over.
      // Other tabs hear about it only when they share these tokens; with per-tab storage each tab
      // holds its own refresh token and finds out for itself.
      const untrusted = error instanceof ArkTokenError ? this.#tokens?.refreshToken : null;
      this.#endLocalSession('expired', { broadcast: this.#sharedStorage() });
      // A response that failed validation may still have rotated: withdraw the token it brought.
      if (untrusted) this.#revokeQuietly(untrusted);
      this.#emit('sessionExpired', { reason: 'refresh_refused', error });
      return;
    }
    this.#emit('refreshFailed', { error });
    if (this.#config.automaticRefresh && this.#tokens && !this.#destroyed) {
      clearTimeout(this.#timer);
      this.#timer = unref(setTimeout(() => this.refresh().catch(() => {}), RETRY_AFTER_NETWORK_FAILURE_MS));
    }
  }

  /** Whether `ark.fetch()` may attach the access token to this URL: the app's own origin or one in `apiOrigins`. */
  isApiUrl(url) {
    const win = this.#win;
    let target;
    try {
      target = new URL(String(url), win?.location?.href);
    } catch {
      return false;
    }
    const own = win?.location?.origin;
    return target.origin === own || this.#config.apiOrigins.includes(target.origin);
  }

  /**
   * `fetch` with the access token attached, for the app's own API.
   *
   * The token is sent only to the page's own origin and the origins in `apiOrigins`; anything else
   * is refused rather than quietly handed a bearer token. A 401 that says the token is invalid is
   * retried once after a refresh. Throws ArkLoginRequiredError when nobody is signed in.
   */
  async fetch(input, init = {}) {
    const win = this.#requireWindow();
    const rawUrl = typeof input === 'string' || input instanceof URL ? String(input) : input?.url;
    if (!this.isApiUrl(rawUrl)) {
      const origin = (() => {
        try {
          return new URL(rawUrl, win.location.href).origin;
        } catch {
          return rawUrl;
        }
      })();
      throw new ArkConfigError(
        `ark_oauth_client: refusing to send the access token to ${origin}. Add that origin to 'apiOrigins' if it is your API, ` +
          'or call it with plain fetch().'
      );
    }

    const fetchImpl = this.#config.fetch ?? globalThis.fetch;
    const send = (token) => {
      const headers = new Headers(init.headers ?? (typeof Request !== 'undefined' && input instanceof Request ? input.headers : undefined));
      headers.set('Authorization', `Bearer ${token}`);
      return fetchImpl(input, { ...init, headers });
    };

    const token = await this.getAccessToken();
    if (!token) throw new ArkLoginRequiredError();
    let response = await send(token);

    const replayable = !(typeof Request !== 'undefined' && input instanceof Request) && !(init.body && typeof init.body.getReader === 'function');
    if (response.status === 401 && replayable && this.#tokens?.refreshToken) {
      const challenge = response.headers.get('WWW-Authenticate') ?? '';
      if (!challenge || /invalid_token/i.test(challenge)) {
        const renewed = await this.getAccessToken({ forceRefresh: true }).catch(() => null);
        if (renewed) response = await send(renewed);
      }
    }
    return response;
  }

  /** The UserInfo endpoint (OIDC Core §5.3), with the current access token. */
  async userInfo() {
    const token = await this.getAccessToken();
    if (!token) throw new ArkLoginRequiredError();
    const metadata = await this.metadata();
    return getJson(metadata.userinfo_endpoint, {
      headers: { Authorization: `Bearer ${token}` },
      timeoutMs: this.#config.timeoutMs,
      fetch: this.#config.fetch
    });
  }

  // =================================================================
  // Signing out and switching account
  // =================================================================

  /**
   * Signs out of this app and the provider: drops the tokens here, revokes the refresh token, then
   * sends the browser to the provider's end-session endpoint with `id_token_hint`, so the provider
   * ends its session without asking and returns to `postLogoutRedirectUri`.
   *
   * Both halves matter. Dropping only the local tokens leaves the provider's session alive, and the
   * next sign-in is silent, as the same person.
   *
   * @param {{ returnTo?: string, postLogoutRedirectUri?: string, revoke?: boolean }} [options]
   */
  async signoutRedirect({ returnTo, postLogoutRedirectUri, revoke = true, ...internal } = {}) {
    this.#requireWindow();
    this.#ensureReady();
    const idTokenHint = this.#tokens?.idToken ?? this.#denial?.idTokenHint ?? null;
    const refreshToken = this.#tokens?.refreshToken ?? null;
    let metadata = null;
    try {
      metadata = await this.metadata();
    } catch {
      metadata = null; // provider unreachable: still sign out locally
    }

    this.#endLocalSession('signout', { broadcast: true });
    if (revoke && refreshToken && metadata?.revocation_endpoint) await this.#revokeQuietly(refreshToken, metadata);

    const home = localOrDefault(returnTo ?? this.#config.accountSwitch.homePath, '/');
    if (!metadata?.end_session_endpoint) {
      this.#navigate(home);
      return;
    }

    const params = new URLSearchParams({ client_id: this.#config.clientId });
    if (idTokenHint) params.set('id_token_hint', idTokenHint);
    const target = postLogoutRedirectUri ?? this.#config.postLogoutRedirectUri;
    if (target) {
      const state = createState();
      params.set('post_logout_redirect_uri', this.#resolve(target));
      params.set('state', state);
      writeJson(this.#txStorage, `${this.#prefix}logout:${state}`, {
        returnTo: home,
        then: internal.then ?? null,
        prompt: internal.prompt ?? null,
        loginHint: internal.loginHint ?? null,
        createdAt: now()
      });
    }
    const endpoint = metadata.end_session_endpoint;
    await this.#redirect(`${endpoint}${endpoint.includes('?') ? '&' : '?'}${params}`);
  }

  /**
   * Signs out of this app only: tokens dropped and the refresh token revoked, the provider's session
   * left alone (the user's other apps stay signed in, and the next sign-in here is silent).
   */
  async signoutLocal({ revoke = true } = {}) {
    this.#ensureReady();
    const refreshToken = this.#tokens?.refreshToken ?? null;
    this.#endLocalSession('signout', { broadcast: true });
    if (revoke && refreshToken) await this.#revokeQuietly(refreshToken);
  }

  /**
   * "Sign in as a different user": drops this app's session and signs in again with
   * `prompt=login`, so the provider draws its sign-in form instead of answering from the session
   * already in this browser. With `accountSwitch.endProviderSessionOnSwitch`, the provider session
   * is ended first and the sign-in follows when the browser comes back.
   */
  async switchUser({ returnTo, loginHint } = {}) {
    const options = this.#config.accountSwitch;
    const target = localOrDefault(returnTo ?? this.#denial?.returnTo ?? null, options.homePath);
    if (options.endProviderSessionOnSwitch) {
      await this.signoutRedirect({ returnTo: target, then: 'signin', prompt: options.prompt, loginHint });
      return;
    }
    await this.signoutLocal();
    await this.signinRedirect({ prompt: options.prompt || 'login', returnTo: target, loginHint });
  }

  /** Clears a refused sign-in's state without signing in again. */
  clearDenial() {
    this.#ensureReady();
    this.#setDenial(null);
    this.#publish();
  }

  // =================================================================
  // Provider metadata and token checks
  // =================================================================

  /** The provider's discovery document, cached. */
  metadata({ force = false } = {}) {
    return this.#metadata.get(force);
  }

  async jwks() {
    const { jwks_uri: uri } = await this.metadata();
    if (!uri) throw new ArkOAuthError('server_error', "the provider's metadata has no 'jwks_uri'.", { endpoint: this.#config.authority });
    if (!this.#jwks || this.#jwks.uri !== uri) {
      this.#jwks = new JwksCache(uri, {
        ttlMs: this.#config.jwksTtlMs,
        minRefreshIntervalMs: this.#config.jwksMinRefreshIntervalMs,
        timeoutMs: this.#config.timeoutMs,
        fetch: this.#config.fetch
      });
    }
    return this.#jwks;
  }

  /** Verifies an ID token against the provider's keys and the values of the sign-in it belongs to. */
  async verifyIdToken(idToken, { nonce = null, accessToken = null, code = null, maxAge = null, subject = null } = {}) {
    const metadata = await this.metadata();
    return verifyJwt(idToken, await this.jwks(), {
      issuer: metadata.issuer,
      audience: this.#config.clientId,
      subject: subject ?? undefined,
      nonce,
      accessToken,
      code,
      maxAgeSeconds: maxAge,
      requireTokenHashes: this.#config.requireTokenHashes,
      requireIat: true,
      clockToleranceSeconds: this.#config.clockToleranceSeconds,
      algorithms: this.#config.idTokenSigningAlgorithms ?? metadata.id_token_signing_alg_values_supported ?? undefined
    });
  }

  // =================================================================
  // Diagnostics
  // =================================================================

  /**
   * Pairs this app's configuration with the provider's live metadata and reports what does not
   * line up: the browser counterpart of `checkSetup()` in the Node client and `ArkSetupProbe` in
   * .NET. In a browser it also proves CORS, which is the usual first failure of a new SPA and
   * otherwise surfaces as a bare "Failed to fetch". Render it on a setup or health page.
   */
  async checkSetup() {
    const win = this.#win;
    const config = this.#config;
    const cut = config.authority.lastIndexOf('/');
    const tenantId = config.authority.slice(cut + 1);
    const report = {
      authority: config.authority,
      clientId: config.clientId,
      tenantId,
      origin: win?.location?.origin ?? null,
      secureContext: Boolean(win?.isSecureContext ?? globalThis.isSecureContext),
      webCrypto: Boolean(globalThis.crypto?.subtle),
      storage: (this.#ensureReady(), this.#storageKind),
      scopes: [...config.scopes],
      responseMode: config.responseMode,
      redirectUri: win ? this.#resolve(config.redirectUri) : config.redirectUri,
      postLogoutRedirectUri: config.postLogoutRedirectUri && win ? this.#resolve(config.postLogoutRedirectUri) : config.postLogoutRedirectUri,
      adminConsoleUrl: `${config.authority}/admin`,
      integrationPageUrl: `${config.authority}/oauth2/integrate/${encodeURIComponent(config.clientId)}`,
      discoveryUrl: `${config.authority}/.well-known/openid-configuration`,
      discoveryOk: false,
      jwksOk: false,
      tokenEndpointCorsOk: null,
      provider: null,
      signingKeys: [],
      problems: []
    };

    if (!report.secureContext || !report.webCrypto) {
      report.problems.push('This page is not a secure context, so crypto.subtle is unavailable. Serve it over https, or over http on localhost only.');
    }

    let metadata;
    try {
      metadata = await this.metadata({ force: true });
      report.discoveryOk = true;
    } catch (error) {
      report.problems.push(`The provider's discovery document could not be read: ${error.message}`);
      return report;
    }

    report.provider = {
      issuer: metadata.issuer,
      authorizationEndpoint: metadata.authorization_endpoint,
      tokenEndpoint: metadata.token_endpoint,
      userInfoEndpoint: metadata.userinfo_endpoint,
      jwksUri: metadata.jwks_uri,
      endSessionEndpoint: metadata.end_session_endpoint ?? null,
      revocationEndpoint: metadata.revocation_endpoint ?? null,
      scopesSupported: metadata.scopes_supported ?? [],
      grantTypesSupported: metadata.grant_types_supported ?? [],
      responseModesSupported: metadata.response_modes_supported ?? [],
      codeChallengeMethodsSupported: metadata.code_challenge_methods_supported ?? [],
      tokenEndpointAuthMethodsSupported: metadata.token_endpoint_auth_methods_supported ?? [],
      requirePushedAuthorizationRequests: metadata.require_pushed_authorization_requests === true
    };

    try {
      const keys = await (await this.jwks()).keys({ force: true });
      report.jwksOk = true;
      report.signingKeys = keys.map((k) => ({ kid: k.kid ?? null, kty: k.kty, alg: k.alg ?? null, use: k.use ?? null }));
    } catch (error) {
      report.problems.push(`The provider's signing keys could not be read: ${error.message}`);
    }

    // A refresh with a token that cannot exist. Any OAuth error back proves the token endpoint is
    // reachable *and* answers this origin; a network error means CORS (or the endpoint) is missing.
    // Nothing is created or changed on the server.
    try {
      await postForm(
        metadata.token_endpoint,
        { grant_type: 'refresh_token', refresh_token: 'ark-setup-probe', client_id: config.clientId },
        { timeoutMs: config.timeoutMs, fetch: config.fetch }
      );
      report.tokenEndpointCorsOk = true;
    } catch (error) {
      report.tokenEndpointCorsOk = !(error instanceof ArkNetworkError);
      if (!report.tokenEndpointCorsOk) report.problems.push(`The token endpoint is not reachable from this page: ${error.message}`);
      else if (error instanceof ArkOAuthError && ['invalid_client', 'unauthorized_client'].includes(error.error)) {
        report.problems.push(
          `The token endpoint refused client '${config.clientId}' (${error.error}${error.errorDescription ? `: ${error.errorDescription}` : ''}). ` +
            "Check the client id, that the client is active, and that it is registered as a public client ('none') for authorization_code and refresh_token."
        );
      }
    }

    const supportedScopes = new Set(metadata.scopes_supported ?? []);
    const unknown = supportedScopes.size ? config.scopes.filter((s) => !supportedScopes.has(s)) : [];
    if (unknown.length) {
      report.problems.push(`The tenant does not publish the scope(s) ${unknown.join(', ')}. A scope the client is not registered for is rejected outright, not dropped.`);
    }
    if (!(metadata.code_challenge_methods_supported ?? []).includes('S256')) {
      report.problems.push('The tenant does not advertise the S256 PKCE method, which this client always sends.');
    }
    const methods = metadata.token_endpoint_auth_methods_supported ?? [];
    if (methods.length && !methods.includes('none')) {
      report.problems.push("The tenant does not list the 'none' token endpoint auth method, which a browser (public) client needs.");
    }
    const modes = metadata.response_modes_supported ?? [];
    if (modes.length && !modes.includes(config.responseMode)) {
      report.problems.push(`The tenant does not support response_mode '${config.responseMode}' (it lists ${modes.join(', ')}).`);
    }
    if (config.scopes.includes('offline_access') && !(metadata.grant_types_supported ?? ['refresh_token']).includes('refresh_token')) {
      report.problems.push('offline_access is requested but the tenant does not serve the refresh_token grant.');
    }
    if (!config.scopes.includes('offline_access')) {
      report.problems.push('offline_access is not requested, so there is no refresh token: the session ends when the access token expires.');
    }
    if (metadata.require_pushed_authorization_requests === true) {
      report.problems.push('The tenant requires pushed authorization requests, which a browser app cannot make.');
    }
    if (!metadata.end_session_endpoint) {
      report.problems.push('The provider has no end_session_endpoint, so sign-out can only end the local session.');
    }
    return report;
  }

  /** Stops timers and listeners. For tests, hot-module reloading, and micro-frontends that unmount. */
  destroy() {
    this.#destroyed = true;
    clearTimeout(this.#timer);
    this.#timer = null;
    for (const off of this.#detach.splice(0)) off();
    if (this.#channel) {
      this.#channel.onmessage = null;
      this.#channel.close();
      this.#channel = null;
    }
  }

  // =================================================================
  // internals: tokens
  // =================================================================

  async #exchangeCode({ code, codeVerifier, redirectUri, nonce, maxAge }) {
    const metadata = await this.metadata();
    const response = await this.#tokenRequest(metadata.token_endpoint, {
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier
    });
    return this.#toTokenSet(response, { nonce, code, maxAge });
  }

  /** A public client authenticates with nothing but its id, which goes in the body. */
  #tokenRequest(endpoint, form) {
    if (!endpoint) throw new ArkOAuthError('server_error', "the provider's metadata has no 'token_endpoint'.", { endpoint: this.#config.authority });
    return postForm(endpoint, { ...form, client_id: this.#config.clientId }, { timeoutMs: this.#config.timeoutMs, fetch: this.#config.fetch });
  }

  async #toTokenSet(response, { nonce, code = null, maxAge = null, subject = null, previous = null }) {
    if (!response.access_token) throw new ArkTokenError('the token response contains no access_token.');
    let claims = null;
    if (response.id_token) {
      // On refresh, OIDC Core §12.2: the new ID token must be about the same user.
      claims = await this.verifyIdToken(response.id_token, { nonce, accessToken: response.access_token, code, maxAge, subject });
    } else if (nonce !== null && String(response.scope ?? '').split(' ').includes('openid')) {
      throw new ArkTokenError('the token response contains no id_token, although the openid scope was granted.');
    }
    const merged = { ...response };
    if (previous) {
      // Rotation off: the server sends no new refresh token and the old one stays valid. A refresh
      // response may also omit the ID token; the last one still serves as id_token_hint at sign-out.
      merged.refresh_token ??= previous.refreshToken;
      merged.id_token ??= previous.idToken;
    }
    return new TokenSet(merged, { claims: claims ?? previous?.claims ?? null });
  }

  #setTokens(tokens, { persist = true } = {}) {
    this.#tokens = tokens;
    this.#derived = tokens
      ? { claims: tokens.claims ? Object.freeze({ ...tokens.claims }) : null, arkClaims: Object.freeze(tokens.arkClaims()), scopes: Object.freeze(tokens.scopes()) }
      : { claims: null, arkClaims: Object.freeze([]), scopes: Object.freeze([]) };
    if (!persist) return;
    if (tokens) writeJson(this.#storage, `${this.#prefix}tokens`, tokens.toJSON());
    else remove(this.#storage, `${this.#prefix}tokens`);
  }

  #readStoredTokens() {
    const data = readJson(this.#storage, `${this.#prefix}tokens`);
    return data?.access_token ? TokenSet.fromJSON(data) : null;
  }

  #restore() {
    if (!this.#tokens) {
      const stored = this.#readStoredTokens();
      if (stored) this.#setTokens(stored, { persist: false });
    }
    if (!this.#denial) {
      const denial = readJson(this.#txStorage, `${this.#prefix}denied`);
      if (denial && now() - (denial.createdAt ?? 0) <= DENIAL_TTL_SECONDS) this.#denial = denial;
      else if (denial) remove(this.#txStorage, `${this.#prefix}denied`);
    }
  }

  async #renewIfNeeded() {
    if (!this.#tokens || !this.#tokens.expired(this.#leeway(this.#tokens))) return;
    if (!this.#tokens.refreshToken) {
      if (this.#tokens.expired(0)) this.#endLocalSession('expired', { broadcast: false });
      return;
    }
    try {
      await this.refresh();
    } catch {
      /* already reflected in the state: session ended, or a retry is scheduled */
    }
  }

  #endLocalSession(reason, { broadcast }) {
    const hadSession = Boolean(this.#tokens || this.#denial);
    clearTimeout(this.#timer);
    this.#timer = null;
    this.#setTokens(null);
    this.#setDenial(null);
    this.#publish();
    if (hadSession) this.#emit('signedOut', { reason });
    if (broadcast) this.#broadcast('signed-out');
  }

  async #revokeQuietly(token, metadata = null) {
    try {
      const md = metadata ?? (await this.metadata());
      if (!md.revocation_endpoint) return;
      await postFormNoCors(
        md.revocation_endpoint,
        { token, token_type_hint: 'refresh_token', client_id: this.#config.clientId },
        { timeoutMs: Math.min(this.#config.timeoutMs, 5000), fetch: this.#config.fetch }
      );
    } catch {
      // Best effort. The provider-side logout ends the session behind the token anyway, and a
      // refresh token whose session has ended is refused.
    }
  }

  #schedule() {
    clearTimeout(this.#timer);
    this.#timer = null;
    const tokens = this.#tokens;
    if (this.#destroyed || !tokens || tokens.expiresAt === null || !this.#win) return;
    const renew = Boolean(this.#config.automaticRefresh && tokens.refreshToken);
    // automaticRefresh off with a refresh token in hand: nothing to time; getAccessToken() renews on demand.
    if (!renew && tokens.refreshToken) return;
    const at = renew ? tokens.expiresAt - this.#lead(tokens) : tokens.expiresAt;
    const delay = Math.min(MAX_TIMER_MS, Math.max(0, (at - now()) * 1000));
    this.#timer = unref(setTimeout(() => {
      if (renew) {
        this.refresh().catch(() => {});
      } else if (this.#tokens === tokens) {
        this.#endLocalSession('expired', { broadcast: false });
        this.#emit('sessionExpired', { reason: 'expired' });
      }
    }, delay));
  }

  #sharedStorage() {
    return this.#storageKind === 'local' || this.#storageKind === 'custom';
  }

  /**
   * How early to renew: `refreshBeforeSeconds`, but never more than half the token's lifetime. A
   * client record with 30- or 60-second access tokens would otherwise be due for renewal the moment
   * each one arrived, and refresh in a tight loop.
   */
  #lead(tokens, max = this.#config.refreshBeforeSeconds) {
    if (!tokens || tokens.expiresAt === null) return max;
    const lifetime = tokens.expiresAt - tokens.issuedAt;
    return lifetime > 0 ? Math.min(max, lifetime / 2) : max;
  }

  /** The margin within which a token is renewed on use rather than handed out. */
  #leeway(tokens) {
    return this.#lead(tokens, Math.min(30, this.#config.refreshBeforeSeconds));
  }

  async #spentHash(token) {
    return base64UrlEncode(await sha256(`${this.#config.clientId}|${token}`)).slice(0, 24);
  }

  async #isSpent(token) {
    const hash = await this.#spentHash(token);
    return (readJson(this.#spentStorage, `${this.#prefix}spent`) ?? []).some((entry) => entry?.h === hash);
  }

  async #markSpent(token) {
    const hash = await this.#spentHash(token);
    const list = (readJson(this.#spentStorage, `${this.#prefix}spent`) ?? []).filter((entry) => entry && entry.h !== hash);
    list.push({ h: hash, at: now() });
    writeJson(this.#spentStorage, `${this.#prefix}spent`, list.slice(-SPENT_TOKENS_REMEMBERED));
  }

  // =================================================================
  // internals: state, storage, transactions
  // =================================================================

  #ensureReady() {
    if (this.#ready) return;
    this.#ready = true;
    const { storage, kind } = resolveStorage(this.#config.storage, this.#win);
    this.#storage = storage;
    this.#storageKind = kind;
    // The sign-in transaction has to survive one navigation to the provider and back, in this tab
    // only. sessionStorage is exactly that, whatever the token storage is.
    this.#txStorage = kind === 'session' ? storage : resolveStorage('session', this.#win).storage;
    // Shared by every tab of the origin, so a duplicated tab can see that a refresh token it copied
    // has been redeemed already. Holds hashes, never tokens.
    this.#spentStorage = kind === 'local' ? storage : resolveStorage('local', this.#win).storage;
  }

  #publish(extra = {}) {
    const tokens = this.#tokens;
    const denial = this.#denial;
    this.#store.set({
      status: tokens ? 'authenticated' : denial ? 'denied' : 'unauthenticated',
      user: this.#derived.claims,
      arkClaims: this.#derived.arkClaims,
      scopes: this.#derived.scopes,
      expiresAt: tokens?.expiresAt ?? null,
      denial: denial ? this.#publicDenial(denial) : null,
      ...extra
    });
  }

  #publicDenial(denial) {
    if (this.#publicDenialCache?.source === denial) return this.#publicDenialCache.value;
    // The ID token kept for the sign-out hint stays internal.
    const { idTokenHint: _hint, createdAt: _created, ...visible } = denial;
    const value = Object.freeze({ ...visible, arkClaims: Object.freeze([...(visible.arkClaims ?? [])]) });
    this.#publicDenialCache = { source: denial, value };
    return value;
  }

  #publicDenialCache = null;

  #setDenial(denial) {
    this.#denial = denial;
    if (denial) writeJson(this.#txStorage, `${this.#prefix}denied`, denial);
    else remove(this.#txStorage, `${this.#prefix}denied`);
  }

  #fail(error) {
    const wrapped = error instanceof ArkError ? error : new ArkError(String(error?.message ?? error), { cause: error });
    this.#publish({ error: wrapped });
    this.#schedule();
    this.#emit('error', wrapped);
    return this.#store.get();
  }

  #saveTransaction(transaction) {
    writeJson(this.#txStorage, `${this.#prefix}tx:${transaction.state}`, transaction);
  }

  /** Reads and deletes a transaction: each one completes at most one sign-in. */
  #takeTransaction(state) {
    const key = `${this.#prefix}tx:${state}`;
    const transaction = readJson(this.#txStorage, key);
    remove(this.#txStorage, key);
    if (!transaction) return null;
    if (now() - (transaction.createdAt ?? 0) > this.#config.transactionTtlSeconds) return null;
    return transaction;
  }

  #takeLogoutTransaction(href) {
    const state = this.#responseParams(new URL(href)).state;
    if (!state) return null;
    const key = `${this.#prefix}logout:${state}`;
    const transaction = readJson(this.#txStorage, key);
    remove(this.#txStorage, key);
    this.#cleanResponseFromUrl(new URL(href));
    return transaction;
  }

  #sweepTransactions() {
    const limit = this.#config.transactionTtlSeconds;
    for (const key of keysWithPrefix(this.#txStorage, this.#prefix)) {
      if (!key.includes(':tx:') && !key.includes(':logout:')) continue;
      const entry = readJson(this.#txStorage, key);
      if (!entry || now() - (entry.createdAt ?? 0) > limit) remove(this.#txStorage, key);
    }
  }

  // =================================================================
  // internals: URLs and navigation
  // =================================================================

  #requireWindow() {
    if (!this.#win) {
      throw new ArkConfigError(
        'ark_oauth_client: this needs a browser window. On the server (SSR), create the client but call its methods from the browser only, e.g. in an effect.'
      );
    }
    return this.#win;
  }

  /** A path becomes an absolute URL on the page's origin; an absolute URL is used as it is. */
  #resolve(value) {
    if (!value) return value;
    if (/^https?:\/\//i.test(value)) return value;
    return new URL(value, this.#requireWindow().location.origin).toString();
  }

  /** The response parameters, from the query or the fragment depending on the response mode. */
  #responseParams(url, responseMode = this.#config.responseMode) {
    const fromQuery = url.searchParams;
    const fromHash = new URLSearchParams(url.hash.startsWith('#') ? url.hash.slice(1) : url.hash);
    const pick = responseMode === 'fragment' ? [fromHash, fromQuery] : [fromQuery, fromHash];
    const source = pick.find((p) => p.has('state') || p.has('code') || p.has('error')) ?? pick[0];
    const result = {};
    for (const name of RESPONSE_PARAMS) {
      const value = source.get(name);
      if (value !== null) result[name] = value;
    }
    return result;
  }

  #classify(href) {
    if (!this.#win) return null;
    let url;
    try {
      url = new URL(href, this.#win.location.href);
    } catch {
      return null;
    }
    const same = (target) => {
      if (!target) return false;
      const t = new URL(this.#resolve(target));
      return t.origin === url.origin && t.pathname === url.pathname;
    };
    const params = this.#responseParams(url);
    if (same(this.#config.redirectUri) && (params.code || params.error)) return 'signin';
    if (same(this.#config.postLogoutRedirectUri ?? DEFAULT_POST_LOGOUT_PATH) && params.state) {
      this.#ensureReady();
      if (readJson(this.#txStorage, `${this.#prefix}logout:${params.state}`)) return 'signout';
    }
    return null;
  }

  #cleanResponseFromUrl(url) {
    const win = this.#win;
    if (!win?.history?.replaceState) return;
    const clean = new URL(url.toString());
    for (const name of RESPONSE_PARAMS) clean.searchParams.delete(name);
    if (clean.hash) {
      const hash = new URLSearchParams(clean.hash.slice(1));
      if (RESPONSE_PARAMS.some((name) => hash.has(name))) {
        for (const name of RESPONSE_PARAMS) hash.delete(name);
        const rest = hash.toString();
        clean.hash = rest ? `#${rest}` : '';
      }
    }
    const relative = `${clean.pathname}${clean.search}${clean.hash}`;
    try {
      win.history.replaceState(win.history.state, '', relative);
    } catch {
      /* sandboxed: nothing to clean */
    }
  }

  #authorizationError(params) {
    return new ArkOAuthError(params.error, params.error_description, {
      endpoint: `${this.#config.authority}/oauth2/authorize`,
      errorUri: params.error_uri ?? null,
      body: params
    });
  }

  async #redirect(url) {
    if (this.#config.redirect) return this.#config.redirect(url);
    this.#requireWindow().location.assign(url);
  }

  /** In-app navigation to a local path without reloading. See init(). */
  #navigate(to) {
    if (this.#config.navigate) return this.#config.navigate(to);
    const win = this.#win;
    if (!win) return;
    try {
      win.history.replaceState(null, '', to);
      const PopState = win.PopStateEvent ?? globalThis.PopStateEvent;
      if (typeof PopState === 'function') win.dispatchEvent(new PopState('popstate', { state: null }));
    } catch {
      win.location.replace(to);
    }
  }

  // =================================================================
  // internals: events and cross-tab sync
  // =================================================================

  #emit(event, detail) {
    for (const handler of [...(this.#events.get(event) ?? [])]) {
      try {
        handler(detail);
      } catch (error) {
        queueMicrotask(() => {
          throw error;
        });
      }
    }
  }

  #broadcast(type) {
    try {
      this.#channel?.postMessage({ type, from: this.#id });
    } catch {
      /* channel closed */
    }
  }

  #attachListeners() {
    const win = this.#win;
    if (!win || this.#detach.length) return;

    if (this.#config.syncTabs) {
      const Channel = win.BroadcastChannel ?? globalThis.BroadcastChannel;
      if (typeof Channel === 'function') {
        this.#channel = unref(new Channel(`ark-oidc:${this.#config.authority}|${this.#config.clientId}`));
        this.#channel.onmessage = (event) => this.#onTabMessage(event.data);
      }
    }

    // Timers in a background tab are throttled or frozen; coming back is the moment to catch up.
    const doc = win.document;
    if (doc?.addEventListener) {
      const onVisible = () => {
        if (doc.visibilityState !== 'visible' || !this.#tokens) return;
        if (this.#sharedStorage()) this.#adoptStoredTokens();
        if (this.#tokens?.expired(this.#lead(this.#tokens))) this.#renewIfNeeded();
      };
      doc.addEventListener('visibilitychange', onVisible);
      this.#detach.push(() => doc.removeEventListener('visibilitychange', onVisible));
    }
  }

  #onTabMessage(message) {
    if (!message || message.from === this.#id) return;
    if (message.type === 'signed-out') {
      if (this.#tokens || this.#denial) this.#endLocalSession('signout', { broadcast: false });
      return;
    }
    if ((message.type === 'tokens' || message.type === 'signed-in') && this.#sharedStorage()) this.#adoptStoredTokens();
  }

  #adoptStoredTokens() {
    const stored = this.#readStoredTokens();
    if (!stored) {
      if (this.#tokens) this.#endLocalSession('signout', { broadcast: false });
      return;
    }
    if (stored.accessToken === this.#tokens?.accessToken) return;
    this.#setTokens(stored, { persist: false });
    this.#setDenial(null);
    this.#publish({ error: null });
    this.#schedule();
  }
}

/** Convenience factory, for callers who prefer not to write `new`. */
export function createArkClient(options) {
  return new ArkBrowserClient(options);
}
