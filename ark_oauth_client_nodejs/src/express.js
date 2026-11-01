import { ArkOAuthClient } from './client.js';
import { TokenSet } from './tokens.js';
import { ArkCallbackError, ArkConfigError, ArkOAuthError } from './errors.js';
import {
  ArkAccessDeniedReasons,
  ArkChallengeProperties,
  DENIED_COOKIE,
  DENIED_MAX_AGE_SECONDS,
  checkSameOrigin,
  deniedUrl,
  describeDenial,
  evaluateAccess,
  localOrDefault,
  normalizeAccountSwitch,
  protectState,
  unprotectState
} from './access.js';
import { DENIED_PAGE_CSP, renderAccessDeniedPage } from './denied-page.js';
import {
  MemorySessionStore,
  appendCookie,
  createSessionId,
  parseCookies,
  serializeCookie,
  signSessionId,
  unsignSessionId
} from './session.js';

/**
 * Interactive sign-in for Express, Connect, and anything else that hands a middleware a Node
 * request and response — Fastify through `@fastify/middie`, Koa through `koa-connect`, or a plain
 * `http.createServer`.
 *
 * It is one middleware rather than a router because a router would mean depending on Express, and
 * this package has no runtime dependencies. The middleware claims its paths (`/login`, the
 * callback, `/logout`, and the three account-switch endpoints under `/ark/`), attaches `req.ark` to
 * everything else, and calls `next()`. Claiming them ahead of the application's own routes is
 * deliberate: the access-denied page has to render for a user who is not allowed in, so it must not
 * sit behind the application's guard.
 *
 * What it takes care of, all of which is easy to get subtly wrong by hand:
 *
 *  * the login transaction — `state`, `nonce` and the PKCE verifier, stored server-side, one per
 *    concurrent sign-in, so two tabs do not overwrite each other;
 *  * the callback checks, in the order that makes them meaningful;
 *  * silent refresh shortly before the access token expires, serialised per session, because this
 *    server rotates refresh tokens and treats a reused one as theft of the whole family;
 *  * sign-out that actually ends the session — the refresh token revoked at the provider, the
 *    server-side session destroyed, the cookie cleared, and only then the redirect to the IdP;
 *  * the shared-browser case: the entitlement check at the callback, the access-denied page, and the
 *    `prompt=login` switch that is the only way out of it.
 */

const DEFAULT_SESSION_TTL_SECONDS = 8 * 60 * 60; // matches the server's default SessionLifetimeMinutes
const TRANSACTION_TTL_SECONDS = 10 * 60;
const MAX_CONCURRENT_TRANSACTIONS = 5;
/** Refresh a little before expiry so a request in flight never carries a dead token — the .NET and Python window. */
const REFRESH_WINDOW_SECONDS = 120;
/** A sign-in response or an account-switch form is a few hundred bytes; anything near this is not one. */
const MAX_FORM_BYTES = 64 * 1024;

/** Paths compare as the Python and .NET clients compare them: case-insensitive, trailing slash ignored. */
const samePath = (path, configured) =>
  Boolean(configured) && path.replace(/\/+$/, '').toLowerCase() === String(configured).replace(/\/+$/, '').toLowerCase();

const wantsHtml = (req) => (req.headers?.accept ?? '').includes('text/html');

/** Plain responses this middleware writes itself: never cached, never content-sniffed. */
function send(res, status, body, { type = 'text/plain; charset=utf-8', headers = {} } = {}) {
  res.statusCode = status;
  res.setHeader('Content-Type', type);
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
  res.end(body);
}

function redirect(res, location) {
  res.statusCode = 302;
  res.setHeader('Location', location);
  res.setHeader('Cache-Control', 'no-store');
  res.end();
}

/**
 * Reads a urlencoded POST body when no body parser has already done it, and keeps only string
 * values: `express.urlencoded({ extended: true })` turns `state[]=x` into an array, and nothing in
 * this protocol is anything but a string.
 */
async function readForm(req) {
  let body = req.body;
  if (!body || typeof body !== 'object') {
    body = {};
    if ((req.headers?.['content-type'] ?? '').includes('application/x-www-form-urlencoded')) {
      const chunks = [];
      let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > MAX_FORM_BYTES) throw new ArkCallbackError('the form body is larger than any sign-in response.');
        chunks.push(chunk);
      }
      body = Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString('utf8')));
    }
  }
  return Object.fromEntries(Object.entries(body).filter(([, value]) => typeof value === 'string'));
}

export function arkExpress(options = {}) {
  const {
    client: providedClient,
    secret,
    loginPath = '/login',
    callbackPath,
    logoutPath = '/logout',
    store = new MemorySessionStore(),
    cookieName = 'ark_session',
    cookie: cookieOptions = {},
    sessionTtlSeconds = DEFAULT_SESSION_TTL_SECONDS,
    refreshLeewaySeconds = REFRESH_WINDOW_SECONDS,
    fetchUserInfo = false,
    returnToParam = 'returnTo',
    defaultReturnTo = '/',
    errorPath = null,
    onError = null,
    trustProxy = true,
    accountSwitch: accountSwitchOptions = {},
    events = {},
    ...clientOptions
  } = options;

  const client = providedClient ?? new ArkOAuthClient(clientOptions);
  const switchOptions = normalizeAccountSwitch(accountSwitchOptions);

  if (!secret || String(secret).length < 16) {
    throw new ArkConfigError(
      "arkExpress: 'secret' is required and must be at least 16 characters. It signs the session cookie; keep it in an " +
        'environment variable, and use the same value across every instance behind a load balancer.'
    );
  }

  const configuredCallbackPath =
    callbackPath ?? (client.config.redirectUri ? new URL(client.config.redirectUri).pathname : '/signin-oidc');

  const cookieDefaults = { httpOnly: true, secure: true, sameSite: 'Lax', path: '/', ...cookieOptions };

  // A form_post callback is a cross-site POST, and a browser does not send a SameSite=Lax (or
  // Strict) cookie with one. The callback would never find its login transaction, and every sign-in
  // would fail with "could not be matched to a request from this browser".
  if (client.config.responseMode === 'form_post' && String(cookieDefaults.sameSite).toLowerCase() !== 'none') {
    throw new ArkConfigError(
      "arkExpress: responseMode 'form_post' needs cookie: { sameSite: 'None', secure: true }. The provider posts the callback " +
        'cross-site, and a browser withholds a SameSite=Lax cookie from that request. Or leave responseMode at query.'
    );
  }

  // Refreshes in flight, keyed by session id. With rotation on, two requests refreshing the same
  // session at once would present the same refresh token twice — which the server reads as theft
  // and answers by revoking the entire family, signing the user out of everything. Within one
  // process this collapses them into a single exchange; across processes, a shared store needs a
  // lock of its own.
  const refreshes = new Map();

  // ---------------------------------------------------------------
  // request helpers
  // ---------------------------------------------------------------

  /**
   * This application's origin as the browser sees it. Behind a proxy that is the forwarded pair —
   * both headers or neither, as the Python client reads them, so a lone X-Forwarded-Host cannot
   * graft another host onto this request's scheme. Turn `trustProxy` off when nothing in front of
   * the app sets them; then nothing a client sends can move the redirect URI.
   */
  function originOf(req) {
    const headers = req.headers ?? {};
    if (trustProxy) {
      const proto = headers['x-forwarded-proto']?.split(',')[0].trim();
      const host = headers['x-forwarded-host']?.split(',')[0].trim();
      if (proto && host) return `${proto}://${host}`;
    }
    return `${req.socket?.encrypted ? 'https' : 'http'}://${headers.host}`;
  }

  const urlOf = (req) => new URL(req.originalUrl ?? req.url ?? '/', originOf(req));
  const absolute = (req, path) => new URL(path, originOf(req)).toString();
  const redirectUriFor = (req) => client.config.redirectUri ?? absolute(req, configuredCallbackPath);

  function fail(req, res, next, error) {
    if (onError) return onError(error, req, res, next);
    if (errorPath) return redirect(res, `${errorPath}?auth_error=${encodeURIComponent(error.message)}`);
    send(res, error instanceof ArkOAuthError && error.status === 403 ? 403 : 400, `Sign-in failed: ${error.message}`);
  }

  // ---------------------------------------------------------------
  // session
  // ---------------------------------------------------------------

  async function loadSession(req) {
    const cookies = parseCookies(req.headers?.cookie);
    const id = unsignSessionId(cookies[cookieName], secret);
    if (!id) return { id: null, data: null };
    const data = await store.get(id);
    return { id: data ? id : null, data };
  }

  async function saveSession(res, id, data) {
    const sessionId = id ?? createSessionId();
    data.updatedAt = Math.floor(Date.now() / 1000);
    await store.set(sessionId, data, sessionTtlSeconds);
    if (!id) {
      appendCookie(res, serializeCookie(cookieName, signSessionId(sessionId, secret), { ...cookieDefaults, maxAge: sessionTtlSeconds }));
    }
    return sessionId;
  }

  const expireCookie = (res, name) => appendCookie(res, serializeCookie(name, '', { ...cookieDefaults, maxAge: 0 }));

  async function dropSession(res, id) {
    if (id) await store.destroy(id);
    expireCookie(res, cookieName);
  }

  /**
   * Revokes a session's refresh token at the provider. Without it, a session ended here leaves a
   * live refresh token behind until it expires; revoking takes its whole rotation family down.
   */
  async function revokeQuietly(tokens) {
    if (!tokens?.refreshToken) return;
    try {
      await client.revoke(tokens.refreshToken, { tokenTypeHint: 'refresh_token' });
    } catch {
      // Best effort: a provider that is down must not prevent a local sign-out.
    }
  }

  /** Prunes expired and surplus login transactions, so a bot hitting /login cannot grow a session forever. */
  function pruneTransactions(txs) {
    const now = Math.floor(Date.now() / 1000);
    const live = Object.entries(txs ?? {}).filter(([, tx]) => now - tx.createdAt < TRANSACTION_TTL_SECONDS);
    live.sort((a, b) => b[1].createdAt - a[1].createdAt);
    return Object.fromEntries(live.slice(0, MAX_CONCURRENT_TRANSACTIONS));
  }

  // ---------------------------------------------------------------
  // sign-in, callback, sign-out
  // ---------------------------------------------------------------

  async function startLogin(req, res, { returnTo, prompt, loginHint, scopes, maxAge, freshSession = false } = {}) {
    const url = urlOf(req);
    const transaction = await client.createAuthorizationUrl({
      redirectUri: redirectUriFor(req),
      returnTo: returnTo ?? localOrDefault(url.searchParams.get(returnToParam), null) ?? defaultReturnTo,
      prompt,
      loginHint: loginHint ?? url.searchParams.get('login_hint') ?? undefined,
      scopes,
      maxAge
    });

    // A switch starts from nothing: the previous account's session has just been destroyed, and
    // loading it back would resurrect a dead id.
    const { id, data } = freshSession ? { id: null, data: null } : await loadSession(req);
    const session = data ?? { createdAt: Math.floor(Date.now() / 1000), txs: {} };
    session.txs = pruneTransactions({
      ...session.txs,
      [transaction.state]: {
        codeVerifier: transaction.codeVerifier,
        nonce: transaction.nonce,
        redirectUri: transaction.redirectUri,
        returnTo: transaction.returnTo,
        maxAge: transaction.maxAge,
        createdAt: transaction.createdAt
      }
    });

    await saveSession(res, id, session);
    redirect(res, transaction.url);
  }

  async function completeLogin(req, res, next) {
    let params;
    try {
      params = req.method === 'POST' ? await readForm(req) : Object.fromEntries(urlOf(req).searchParams);
    } catch (error) {
      return fail(req, res, next, error);
    }

    const { id, data } = await loadSession(req);
    const state = params.state;
    const stored = state && data?.txs && Object.hasOwn(data.txs, state) ? data.txs[state] : null;

    if (!stored) {
      // An error the provider sent without our state (Ark omits it when it refuses the request
      // outright) still names the real problem. Shown, never acted on: nothing is redeemed.
      if (params.error) {
        return fail(
          req,
          res,
          next,
          new ArkOAuthError(params.error, params.error_description ?? null, { body: params, endpoint: 'authorization response' })
        );
      }
      // No transaction means the response cannot be tied to a sign-in this browser started: an
      // expired login, a session lost to a restart with an in-memory store, or a forged callback.
      return fail(
        req,
        res,
        next,
        new ArkCallbackError(
          'this sign-in could not be matched to a request from this browser. It may have expired — start again from the login page.'
        )
      );
    }

    // The transaction is single-use whatever happens next.
    delete data.txs[state];

    let tokens;
    try {
      tokens = await client.handleCallback(params, { state, ...stored });
    } catch (error) {
      await saveSession(res, id, data);
      return fail(req, res, next, error);
    }

    // Read off the access token without re-verifying it: it arrived over TLS from the token
    // endpoint in this exchange, bound to the verified ID token by at_hash.
    const arkClaims = tokens.arkClaims();

    // The last point before a session is written. Refusing here rather than at the first guarded
    // page is the whole difference: the browser never holds a session for an account that cannot
    // use this application.
    if (switchOptions.requireArkClaims || events.onEvaluateAccess) {
      const allowed = await evaluateAccess(switchOptions, events, { claims: tokens.claims ?? {}, arkClaims, tokens });
      if (!allowed) {
        await saveSession(res, id, data);
        await revokeQuietly(tokens);
        const returnUrl = localOrDefault(stored.returnTo, switchOptions.homePath);
        return deny(req, res, ArkAccessDeniedReasons.NO_APP_ACCESS, tokens.claims, arkClaims, returnUrl);
      }
    }

    // A fresh session id at the moment privileges change, so a session id an attacker planted
    // before sign-in is not the one that ends up authenticated (session fixation).
    //
    // Sign-ins still outstanding in other tabs move across to the new session. They are bound to
    // this browser and nothing else — dropping them along with the old session id is what turns a
    // second open tab into "this sign-in could not be matched to a request from this browser".
    const carried = pruneTransactions(data.txs);
    await dropSession(res, id);

    const session = {
      createdAt: Math.floor(Date.now() / 1000),
      txs: carried,
      tokens: tokens.toJSON(),
      user: tokens.claims,
      arkClaims,
      sub: tokens.subject
    };

    if (fetchUserInfo && tokens.accessToken && tokens.hasScope('openid')) {
      try {
        session.user = { ...session.user, ...(await client.userInfo(tokens.accessToken)) };
      } catch {
        // UserInfo is supplementary; the ID token already carries what the scopes unlocked.
      }
    }

    clearDenied(req, res);
    await saveSession(res, null, session);
    redirect(res, localOrDefault(stored.returnTo, defaultReturnTo));
  }

  async function endSession(req, res, { returnTo } = {}) {
    const { id, data } = await loadSession(req);
    const tokens = TokenSet.fromJSON(data?.tokens);
    await revokeQuietly(tokens);
    await dropSession(res, id);

    const landing = localOrDefault(returnTo, defaultReturnTo);
    let target = landing;
    try {
      target = await client.endSessionUrl({
        idTokenHint: tokens?.idToken ?? undefined,
        postLogoutRedirectUri: client.config.postLogoutRedirectUri ?? absolute(req, landing)
      });
    } catch {
      // A tenant with no end_session_endpoint still gets a clean local sign-out.
    }
    redirect(res, target);
  }

  // ---------------------------------------------------------------
  // account switching
  // ---------------------------------------------------------------

  function clearDenied(req, res) {
    if (parseCookies(req.headers?.cookie)[DENIED_COOKIE]) expireCookie(res, DENIED_COOKIE);
  }

  /**
   * Abandons the account this application is signed in as and asks the provider for its sign-in
   * form, so the person at the keyboard can enter their own credentials. The local session goes
   * first: a user who abandons the provider's form must not come back to the previous person's.
   */
  async function switchUser(req, res, { returnUrl, loginHint } = {}) {
    const target = localOrDefault(returnUrl, switchOptions.homePath);
    clearDenied(req, res);

    // Ending the provider session too signs the previous user out of every application they had
    // open; they land back here anonymous, and the next guarded page draws the sign-in form.
    if (switchOptions.endProviderSessionOnSwitch) return endSession(req, res, { returnTo: target });

    const { id, data } = await loadSession(req);
    await revokeQuietly(TokenSet.fromJSON(data?.tokens));
    if (id) await store.destroy(id);

    return startLogin(req, res, { ...ArkChallengeProperties.switchUser(target, loginHint, switchOptions.prompt), freshSession: true });
  }

  /** RP-initiated logout: this application's session and the provider's. */
  async function signOutEverywhere(req, res, { returnUrl } = {}) {
    clearDenied(req, res);
    return endSession(req, res, { returnTo: localOrDefault(returnUrl, switchOptions.homePath) });
  }

  /** Ends this application's session only, leaving the provider session intact. */
  async function signOutLocally(req, res, { returnUrl } = {}) {
    const { id, data } = await loadSession(req);
    await revokeQuietly(TokenSet.fromJSON(data?.tokens));
    await dropSession(res, id);
    clearDenied(req, res);
    redirect(res, localOrDefault(returnUrl, switchOptions.homePath));
  }

  /** The account the last denial was about, for an application drawing its own page; else null. */
  function deniedAccount(req) {
    const value = parseCookies(req.headers?.cookie)[DENIED_COOKIE];
    const payload = value ? unprotectState(secret, value) : null;
    if (!payload) return null;
    const { return_url: returnUrl = null, ...rest } = payload;
    return { subject: null, email: null, name: null, reason: null, ...rest, returnUrl };
  }

  async function deny(req, res, reason, claims, arkClaims, returnUrl) {
    const denied = describeDenial(reason, claims, arkClaims, returnUrl);
    if (events.onAccessDenied) {
      await events.onAccessDenied(denied, req, res);
      // The handler drew a page of its own, or said it had.
      if (denied.handled || res.headersSent) return;
    }

    const { subject, email, name } = denied;
    appendCookie(
      res,
      serializeCookie(DENIED_COOKIE, protectState(secret, { subject, email, name, reason, return_url: returnUrl ?? null }), {
        ...cookieDefaults,
        sameSite: 'Lax',
        maxAge: DENIED_MAX_AGE_SECONDS
      })
    );
    redirect(res, deniedUrl(switchOptions, returnUrl));
  }

  function renderDeniedPage(req, res) {
    const denied = deniedAccount(req);
    let email = denied?.email;
    let name = denied?.name;
    if (!email && !name) {
      // Arrived from a 403 rather than from a refused callback, so there is a session to read.
      const user = req.ark?.user ?? {};
      email = user.email ?? user.preferred_username;
      name = user.name;
    }

    const html = renderAccessDeniedPage(switchOptions, {
      app: switchOptions.appDisplayName ?? client.config.clientId,
      account: switchOptions.showSignedInAccount ? email || name || null : null,
      returnUrl: localOrDefault(urlOf(req).searchParams.get('returnUrl') || denied?.returnUrl, switchOptions.homePath)
    });

    // Spent on read: a stale cookie must not name the wrong account on a later visit.
    clearDenied(req, res);
    send(res, 403, html, {
      type: 'text/html; charset=utf-8',
      headers: { 'Content-Security-Policy': DENIED_PAGE_CSP, 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY' }
    });
  }

  /** Serves the three account endpoints. Returns true when the request was one of them. */
  async function serveAccountEndpoints(req, res, path) {
    if (!switchOptions.enabled) return false;

    const isSwitch = samePath(path, switchOptions.switchUserPath);
    const isSignOut = samePath(path, switchOptions.signOutPath);
    if (isSwitch || isSignOut) {
      if (isSignOut && !switchOptions.allowFullSignOut) {
        send(res, 404, 'Not Found');
        return true;
      }
      const guard = checkSameOrigin(req.method, req.headers, originOf(req));
      if (!guard.ok) {
        send(res, guard.status, guard.message, { headers: guard.status === 405 ? { Allow: 'POST' } : {} });
        return true;
      }
      // Form first, then the query string — a returnUrl left out of the form is not lost.
      const form = await readForm(req);
      const query = urlOf(req).searchParams;
      const field = (name) => form[name] || query.get(name) || null;
      if (isSwitch) await switchUser(req, res, { returnUrl: field('returnUrl'), loginHint: field('login_hint') });
      else await signOutEverywhere(req, res, { returnUrl: field('returnUrl') });
      return true;
    }

    if (switchOptions.serveDefaultPage && samePath(path, switchOptions.accessDeniedPath)) {
      await attachContext(req, res);
      renderDeniedPage(req, res);
      return true;
    }
    return false;
  }

  // ---------------------------------------------------------------
  // token freshness
  // ---------------------------------------------------------------

  /**
   * The session's tokens, refreshed first when the access token is about to expire.
   *
   * Every caller ends up holding the rotated tokens, including one that waited on another request's
   * refresh: a request left holding the retired refresh token would present it on its next refresh,
   * and the server answers a reused refresh token by revoking the whole family.
   */
  async function freshTokens(sessionId, session, res) {
    const tokens = TokenSet.fromJSON(session.tokens);
    if (!tokens?.refreshToken || !tokens.expired(refreshLeewaySeconds)) return tokens;

    let pending = refreshes.get(sessionId);
    if (!pending) {
      pending = refreshSession(sessionId, tokens).finally(() => refreshes.delete(sessionId));
      refreshes.set(sessionId, pending);
    }

    const result = await pending;
    if (result.signedOut) {
      if (res && !res.headersSent) expireCookie(res, cookieName);
      return null;
    }
    if (result.session) Object.assign(session, result.session);
    return result.tokens;
  }

  /** Runs one refresh. Never throws: the answer is new tokens, the old ones, or "signed out". */
  async function refreshSession(sessionId, tokens) {
    // The store is the source of truth: another request, or another instance sharing the store,
    // may have refreshed since this one loaded the session.
    const latest = await store.get(sessionId);
    if (!latest) return { signedOut: true };
    const current = TokenSet.fromJSON(latest.tokens) ?? tokens;
    if (!current.expired(refreshLeewaySeconds) || !current.refreshToken) return { tokens: current, session: latest };

    try {
      const refreshed = await client.refresh(current.refreshToken);
      const session = {
        ...latest,
        tokens: refreshed.toJSON(),
        // The ID token is reissued on refresh; keep the identity in step with it.
        user: refreshed.claims ? { ...latest.user, ...refreshed.claims } : latest.user,
        arkClaims: refreshed.arkClaims()
      };
      await store.set(sessionId, session, sessionTtlSeconds);
      return { tokens: refreshed, session };
    } catch (error) {
      // invalid_grant means the refresh token is spent, revoked, or its session ended at the
      // provider. There is nothing to retry: the user has to sign in again.
      if (error instanceof ArkOAuthError && error.error === 'invalid_grant') {
        await store.destroy(sessionId);
        return { signedOut: true };
      }
      // A transient failure must not sign the user out; the next request tries again.
      return { tokens: current, session: latest };
    }
  }

  // ---------------------------------------------------------------
  // the middleware
  // ---------------------------------------------------------------

  async function attachContext(req, res) {
    const { id, data } = await loadSession(req);
    let session = data;
    let tokens = null;
    if (id && session) {
      tokens = await freshTokens(id, session, res);
      if (!tokens) session = null;
    }

    const authenticated = Boolean(session?.tokens && tokens);
    const claims = () => (authenticated ? session.arkClaims ?? [] : []);
    const scopes = tokens?.scopes() ?? [];

    req.ark = {
      client,
      store,
      sessionId: authenticated ? id : null,
      isAuthenticated: authenticated,
      user: authenticated ? (session.user ?? null) : null,
      sub: authenticated ? (session.sub ?? null) : null,
      claims: claims(),
      scopes,
      tokens: authenticated ? tokens : null,
      idToken: authenticated ? tokens.idToken : null,

      /** The current access token, refreshed first if it is about to expire. Read it per call; never cache it. */
      async accessToken() {
        if (!authenticated) return null;
        const current = await freshTokens(id, session, res);
        return current?.accessToken ?? null;
      },

      /** Attaches the access token to a downstream request's headers. */
      async authorize(headers = {}) {
        const token = await this.accessToken();
        if (token) headers.Authorization = `Bearer ${token}`;
        return headers;
      },

      hasClaim: (...wanted) => wanted.flat().every((c) => claims().includes(c)),
      hasScope: (...wanted) => wanted.flat().every((s) => scopes.includes(s)),

      login: (opts) => startLogin(req, res, opts),
      logout: (opts) => endSession(req, res, opts),
      switchUser: (opts) => switchUser(req, res, opts),
      signOutEverywhere: (opts) => signOutEverywhere(req, res, opts),
      signOutLocally: (opts) => signOutLocally(req, res, opts),
      deniedAccount: () => deniedAccount(req)
    };
  }

  const middleware = async function arkMiddleware(req, res, next) {
    try {
      const path = urlOf(req).pathname;

      // The account endpoints first: they must answer even when everything else refuses to.
      if (await serveAccountEndpoints(req, res, path)) return;
      if (samePath(path, loginPath)) return await startLogin(req, res);
      if (samePath(path, configuredCallbackPath)) return await completeLogin(req, res, next);
      if (samePath(path, logoutPath)) return await endSession(req, res);

      await attachContext(req, res);
      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Guards a route. An unauthenticated browser request is sent to the login page with a
   * `returnTo`; an API or fetch request gets 401 and an RFC 6750 challenge, because redirecting
   * XHR to a sign-in page produces a CORS error rather than anything the caller can act on. A
   * signed-in browser missing a claim reaches the access-denied page — with the way out — rather
   * than a bare 403.
   */
  middleware.requireAuth = ({ claims = [], scopes = [] } = {}) =>
    function arkRequireAuth(req, res, next) {
      const ark = req.ark;
      if (!ark) {
        return next(new ArkConfigError('req.ark is missing — mount the arkExpress() middleware before requireAuth().'));
      }

      if (!ark.isAuthenticated) {
        if (!(wantsHtml(req) && req.method === 'GET')) {
          return send(res, 401, JSON.stringify({ error: 'invalid_token', error_description: 'authentication is required.' }), {
            type: 'application/json',
            headers: { 'WWW-Authenticate': 'Bearer realm="ark", error="invalid_token"' }
          });
        }
        return redirect(res, `${loginPath}?${returnToParam}=${encodeURIComponent(req.originalUrl ?? req.url ?? '/')}`);
      }

      const missingClaims = [claims].flat().filter((c) => !ark.claims.includes(c));
      const missingScopes = [scopes].flat().filter((s) => !ark.scopes.includes(s));
      if (missingClaims.length || missingScopes.length) {
        if (switchOptions.enabled && wantsHtml(req)) {
          const here = localOrDefault(req.originalUrl ?? req.url, switchOptions.homePath);
          return deny(req, res, ArkAccessDeniedReasons.FORBIDDEN, ark.user, ark.claims, here).catch(next);
        }
        const description = [
          missingClaims.length ? `missing claim(s): ${missingClaims.join(', ')}` : null,
          missingScopes.length ? `missing scope(s): ${missingScopes.join(', ')}` : null
        ]
          .filter(Boolean)
          .join('; ');
        return send(res, 403, JSON.stringify({ error: 'insufficient_scope', error_description: description }), { type: 'application/json' });
      }

      next();
    };

  /** Shorthand for requireAuth({ claims }) — Ark authorization claims, the thing to authorise on. */
  middleware.requireClaims = (...claims) => middleware.requireAuth({ claims: claims.flat() });
  middleware.requireScopes = (...scopes) => middleware.requireAuth({ scopes: scopes.flat() });

  /**
   * This application's configuration beside the provider's live metadata, for a setup or health
   * page — with the redirect URI this request would really send, which is the one to register.
   */
  middleware.checkSetup = async (req) => {
    const report = await client.checkSetup({ origin: originOf(req), callbackPath: configuredCallbackPath });
    return {
      ...report,
      isAuthenticated: Boolean(req.ark?.isAuthenticated),
      signedInAs: req.ark?.user?.name ?? req.ark?.user?.email ?? null,
      authError: urlOf(req).searchParams.get('auth_error')
    };
  };

  middleware.switchUser = switchUser;
  middleware.signOutEverywhere = signOutEverywhere;
  middleware.signOutLocally = signOutLocally;
  middleware.deniedAccount = deniedAccount;

  middleware.client = client;
  middleware.store = store;
  middleware.accountSwitch = switchOptions;
  middleware.loginPath = loginPath;
  middleware.callbackPath = configuredCallbackPath;
  middleware.logoutPath = logoutPath;

  return middleware;
}

/**
 * Makes text safe for a quoted-string in a header. A token's `kid` reaches error messages, and a
 * CR or LF in one would make `setHeader` throw — from inside an async handler, an unhandled
 * rejection, which can take the process down.
 */
const headerText = (value) =>
  String(value)
    .replace(/[^\x20-\x7e]/g, '?')
    .replace(/["\\]/g, "'")
    .slice(0, 200);

/**
 * Bearer-token authentication for an API — the resource-server half.
 *
 * Verification is local, against the cached JWKS, so this costs no network call per request once
 * the keys are loaded. Failures follow RFC 6750: a `WWW-Authenticate` challenge naming the reason,
 * 401 when the token is missing or bad, 403 when it is valid but not allowed to do this.
 */
export function arkBearer(options = {}) {
  const { client: providedClient, scopes = [], claims = [], audience, optional = false, requireTypeHeader = true, ...clientOptions } = options;
  const client = providedClient ?? new ArkOAuthClient(clientOptions);

  const challenge = (res, status, error, description) => {
    const text = headerText(description);
    send(res, status, JSON.stringify({ error, error_description: text }), {
      type: 'application/json',
      headers: { 'WWW-Authenticate': `Bearer realm="ark", error="${error}", error_description="${text}"` }
    });
  };

  const middleware = async function arkBearerMiddleware(req, res, next) {
    try {
      const header = req.headers?.authorization ?? '';
      const token = header.toLowerCase().startsWith('bearer ') ? header.slice(7).trim() : null;

      if (!token) {
        if (optional) {
          req.ark = { isAuthenticated: false, token: null, claims: [], scopes: [], hasClaim: () => false, hasScope: () => false, client };
          return next();
        }
        return challenge(res, 401, 'invalid_token', 'an access token is required.');
      }

      let payload;
      try {
        payload = await client.verifyAccessToken(token, { audience, scopes, arkClaims: claims, requireTypeHeader });
      } catch (error) {
        if (error instanceof ArkOAuthError && error.error === 'insufficient_scope') {
          return challenge(res, 403, 'insufficient_scope', error.errorDescription ?? error.message);
        }
        return challenge(res, 401, 'invalid_token', error.message);
      }

      const arkClaims = Array.isArray(payload.ark_claims) ? payload.ark_claims : payload.ark_claims ? [payload.ark_claims] : [];
      const granted = String(payload.scope ?? '').split(' ').filter(Boolean);
      req.ark = {
        isAuthenticated: true,
        token,
        payload,
        sub: payload.sub,
        clientId: payload.client_id ?? null,
        sessionId: payload.sid ?? null,
        scopes: granted,
        claims: arkClaims,
        hasClaim: (...wanted) => wanted.flat().every((c) => arkClaims.includes(c)),
        hasScope: (...wanted) => wanted.flat().every((s) => granted.includes(s)),
        client
      };
      next();
    } catch (error) {
      next(error);
    }
  };

  /** A per-route guard, for when different endpoints need different scopes or claims. */
  middleware.require = ({ scopes: needScopes = [], claims: needClaims = [] } = {}) =>
    function arkBearerRequire(req, res, next) {
      const ark = req.ark;
      if (!ark?.isAuthenticated) return challenge(res, 401, 'invalid_token', 'an access token is required.');
      const missing = [
        ...[needScopes].flat().filter((s) => !ark.scopes.includes(s)).map((s) => `scope '${s}'`),
        ...[needClaims].flat().filter((c) => !ark.claims.includes(c)).map((c) => `claim '${c}'`)
      ];
      if (missing.length) return challenge(res, 403, 'insufficient_scope', `the token is missing ${missing.join(', ')}.`);
      next();
    };

  middleware.client = client;
  return middleware;
}
