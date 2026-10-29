import { ArkOAuthClient } from './client.js';
import { TokenSet } from './tokens.js';
import { ArkCallbackError, ArkConfigError, ArkOAuthError } from './errors.js';
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
 * this package has no runtime dependencies. The middleware claims three paths (`/login`,
 * the callback, `/logout`), attaches `req.ark` to everything else, and calls `next()`.
 *
 * What it takes care of, all of which is easy to get subtly wrong by hand:
 *
 *  * the login transaction — `state`, `nonce` and the PKCE verifier, stored server-side, one per
 *    concurrent sign-in, so two tabs do not overwrite each other;
 *  * the callback checks, in the order that makes them meaningful;
 *  * silent refresh a minute before the access token expires, serialised per session, because this
 *    server rotates refresh tokens and treats a reused one as theft of the whole family;
 *  * sign-out that actually ends the session — the refresh token revoked at the provider, the
 *    server-side session destroyed, the cookie cleared, and only then the redirect to the IdP.
 */

const DEFAULT_SESSION_TTL_SECONDS = 8 * 60 * 60; // matches the server's default SessionLifetimeMinutes
const TRANSACTION_TTL_SECONDS = 10 * 60;
const MAX_CONCURRENT_TRANSACTIONS = 5;

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
    refreshLeewaySeconds = 60,
    fetchUserInfo = false,
    returnToParam = 'returnTo',
    defaultReturnTo = '/',
    errorPath = null,
    onError = null,
    trustProxy = true,
    ...clientOptions
  } = options;

  const client = providedClient ?? new ArkOAuthClient(clientOptions);

  if (!secret || String(secret).length < 16) {
    throw new ArkConfigError(
      "arkExpress: 'secret' is required and must be at least 16 characters. It signs the session cookie; keep it in an " +
        'environment variable, and use the same value across every instance behind a load balancer.'
    );
  }

  const configuredCallbackPath =
    callbackPath ?? (client.config.redirectUri ? new URL(client.config.redirectUri).pathname : '/signin-oidc');

  const cookieDefaults = { httpOnly: true, secure: true, sameSite: 'Lax', path: '/', ...cookieOptions };

  // Refreshes in flight, keyed by session id. With rotation on, two requests refreshing the same
  // session at once would present the same refresh token twice — which the server reads as theft
  // and answers by revoking the entire family, signing the user out of everything. Within one
  // process this collapses them into a single exchange; across processes, a shared store needs a
  // lock of its own.
  const refreshes = new Map();

  // ---------------------------------------------------------------
  // request helpers
  // ---------------------------------------------------------------

  function originOf(req) {
    const headers = req.headers ?? {};
    const proto = (trustProxy && headers['x-forwarded-proto']?.split(',')[0].trim()) || (req.socket?.encrypted ? 'https' : 'http');
    const host = (trustProxy && headers['x-forwarded-host']?.split(',')[0].trim()) || headers.host;
    return `${proto}://${host}`;
  }

  function urlOf(req) {
    return new URL(req.originalUrl ?? req.url ?? '/', originOf(req));
  }

  function redirectUriFor(req) {
    return client.config.redirectUri ?? new URL(configuredCallbackPath, originOf(req)).toString();
  }

  function redirect(res, location) {
    res.statusCode = 302;
    res.setHeader('Location', location);
    res.setHeader('Cache-Control', 'no-store');
    res.end();
  }

  /** Reads a form_post callback body when no body parser has already done it. */
  async function readFormBody(req) {
    if (req.body && typeof req.body === 'object') return req.body;
    const type = req.headers?.['content-type'] ?? '';
    if (!type.includes('application/x-www-form-urlencoded')) return {};
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    return Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString('utf8')));
  }

  /**
   * Only same-origin relative paths are followed after sign-in. An open redirect on the login
   * route is how a phishing link keeps your domain in the address bar right up to the moment it
   * hands the user to somebody else's page.
   */
  function safeReturnTo(value) {
    if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//')) return null;
    // Browsers read `\` as `/` in a URL path, so `/\evil.example` is `//evil.example` — another
    // host. Control characters are refused for the same reason: a browser strips tabs and
    // newlines before parsing, so `/\t/evil.example` collapses to the same thing. These are the
    // checks the .NET (LocalOrDefault) and Python (local_or_default) clients already make.
    if (value.startsWith('/\\')) return null;
    // eslint-disable-next-line no-control-regex
    if (/[\u0000-\u001f\u007f]/.test(value)) return null;
    return value;
  }

  function fail(req, res, next, error) {
    if (onError) return onError(error, req, res, next);
    if (errorPath) return redirect(res, `${errorPath}?auth_error=${encodeURIComponent(error.message)}`);
    res.statusCode = error instanceof ArkOAuthError && error.status === 403 ? 403 : 400;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.end(`Sign-in failed: ${error.message}`);
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

  async function dropSession(res, id) {
    if (id) await store.destroy(id);
    appendCookie(res, serializeCookie(cookieName, '', { ...cookieDefaults, maxAge: 0 }));
  }

  /** Prunes expired and surplus login transactions, so a bot hitting /login cannot grow a session forever. */
  function pruneTransactions(txs) {
    const now = Math.floor(Date.now() / 1000);
    const live = Object.entries(txs).filter(([, tx]) => now - tx.createdAt < TRANSACTION_TTL_SECONDS);
    live.sort((a, b) => b[1].createdAt - a[1].createdAt);
    return Object.fromEntries(live.slice(0, MAX_CONCURRENT_TRANSACTIONS));
  }

  // ---------------------------------------------------------------
  // the three routes
  // ---------------------------------------------------------------

  async function startLogin(req, res, { returnTo, prompt, loginHint, scopes, maxAge } = {}) {
    const url = urlOf(req);
    const transaction = await client.createAuthorizationUrl({
      redirectUri: redirectUriFor(req),
      returnTo: returnTo ?? safeReturnTo(url.searchParams.get(returnToParam)) ?? defaultReturnTo,
      prompt,
      loginHint: loginHint ?? url.searchParams.get('login_hint') ?? undefined,
      scopes,
      maxAge
    });

    const { id, data } = await loadSession(req);
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
    const url = urlOf(req);
    const params =
      req.method === 'POST' ? await readFormBody(req) : Object.fromEntries(url.searchParams);

    const { id, data } = await loadSession(req);
    const state = params.state;
    const stored = state ? data?.txs?.[state] : null;

    if (!stored) {
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

    let tokens;
    try {
      tokens = await client.handleCallback(params, { state, ...stored });
    } catch (error) {
      delete data.txs[state];
      await saveSession(res, id, data);
      return fail(req, res, next, error);
    }

    // A fresh session id at the moment privileges change, so a session id an attacker planted
    // before sign-in is not the one that ends up authenticated (session fixation).
    //
    // Sign-ins still outstanding in other tabs move across to the new session. They are bound to
    // this browser and nothing else — dropping them along with the old session id is what turns a
    // second open tab into "this sign-in could not be matched to a request from this browser".
    const carried = pruneTransactions({ ...(data.txs ?? {}) });
    delete carried[state];
    await dropSession(res, id);

    const session = {
      createdAt: Math.floor(Date.now() / 1000),
      txs: carried,
      tokens: tokens.toJSON(),
      user: tokens.claims,
      arkClaims: tokens.arkClaims(),
      sub: tokens.subject
    };

    if (fetchUserInfo && tokens.accessToken && tokens.hasScope('openid')) {
      try {
        session.user = { ...session.user, ...(await client.userInfo(tokens.accessToken)) };
      } catch {
        // UserInfo is supplementary; the ID token already carries what the scopes unlocked.
      }
    }

    await saveSession(res, null, session);
    redirect(res, safeReturnTo(stored.returnTo) ?? defaultReturnTo);
  }

  async function endSession(req, res) {
    const { id, data } = await loadSession(req);
    const tokens = TokenSet.fromJSON(data?.tokens);

    if (tokens?.refreshToken) {
      try {
        // Ending the local session leaves the refresh token live at the provider until it expires;
        // revoking takes down its whole family, which is what "sign out" is expected to mean.
        await client.revoke(tokens.refreshToken, { tokenTypeHint: 'refresh_token' });
      } catch {
        // Best effort: a provider that is down must not prevent a local sign-out.
      }
    }

    await dropSession(res, id);

    let target = defaultReturnTo;
    try {
      target = await client.endSessionUrl({
        idTokenHint: tokens?.idToken ?? undefined,
        postLogoutRedirectUri: client.config.postLogoutRedirectUri ?? new URL(defaultReturnTo, originOf(req)).toString()
      });
    } catch {
      // A tenant with no end_session_endpoint still gets a clean local sign-out.
    }
    redirect(res, target);
  }

  // ---------------------------------------------------------------
  // token freshness
  // ---------------------------------------------------------------

  async function freshTokens(sessionId, session, res) {
    const tokens = TokenSet.fromJSON(session.tokens);
    if (!tokens || !tokens.expired(refreshLeewaySeconds) || !tokens.refreshToken) return tokens;

    let pending = refreshes.get(sessionId);
    if (!pending) {
      pending = (async () => {
        try {
          const refreshed = await client.refresh(tokens.refreshToken);
          session.tokens = refreshed.toJSON();
          // The ID token is reissued on refresh; keep the identity in step with it.
          if (refreshed.claims) session.user = { ...session.user, ...refreshed.claims };
          session.arkClaims = refreshed.arkClaims();
          await store.set(sessionId, session, sessionTtlSeconds);
          return refreshed;
        } catch (error) {
          // invalid_grant means the refresh token is spent, revoked, or its session ended at the
          // provider. There is nothing to retry: the user has to sign in again.
          if (error instanceof ArkOAuthError && error.error === 'invalid_grant') {
            await store.destroy(sessionId);
            if (res) appendCookie(res, serializeCookie(cookieName, '', { ...cookieDefaults, maxAge: 0 }));
            return null;
          }
          throw error;
        } finally {
          refreshes.delete(sessionId);
        }
      })();
      refreshes.set(sessionId, pending);
    }
    return pending;
  }

  // ---------------------------------------------------------------
  // the middleware
  // ---------------------------------------------------------------

  const middleware = async function arkMiddleware(req, res, next) {
    try {
      const url = urlOf(req);
      const path = url.pathname;

      if (path === loginPath) return await startLogin(req, res);
      if (path === configuredCallbackPath) return await completeLogin(req, res, next);
      if (path === logoutPath) return await endSession(req, res);

      const { id, data } = await loadSession(req);
      let tokens = null;
      let session = data;

      if (id && session) {
        tokens = await freshTokens(id, session, res);
        if (!tokens) session = null;
      }

      const authenticated = Boolean(session?.tokens && tokens);

      req.ark = {
        client,
        store,
        sessionId: authenticated ? id : null,
        isAuthenticated: authenticated,
        user: authenticated ? (session.user ?? null) : null,
        sub: authenticated ? (session.sub ?? null) : null,
        claims: authenticated ? (session.arkClaims ?? []) : [],
        scopes: tokens?.scopes() ?? [],
        tokens: authenticated ? tokens : null,
        idToken: authenticated ? tokens.idToken : null,

        /** The current access token, refreshed first if it is about to expire. */
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

        hasClaim: (...wanted) => wanted.flat().every((c) => (session?.arkClaims ?? []).includes(c)),
        hasScope: (...wanted) => wanted.flat().every((s) => (tokens?.scopes() ?? []).includes(s)),

        login: (opts) => startLogin(req, res, opts),
        logout: () => endSession(req, res)
      };

      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Guards a route. An unauthenticated browser request is sent to the login page with a
   * `returnTo`; an API or fetch request gets 401 and an RFC 6750 challenge, because redirecting
   * XHR to a sign-in page produces a CORS error rather than anything the caller can act on.
   */
  middleware.requireAuth = ({ claims = [], scopes = [] } = {}) =>
    function arkRequireAuth(req, res, next) {
      const ark = req.ark;
      if (!ark) {
        return next(new ArkConfigError('req.ark is missing — mount the arkExpress() middleware before requireAuth().'));
      }

      if (!ark.isAuthenticated) {
        const wantsHtml = (req.headers?.accept ?? '').includes('text/html') && req.method === 'GET';
        if (!wantsHtml) {
          res.statusCode = 401;
          res.setHeader('WWW-Authenticate', 'Bearer realm="ark", error="invalid_token"');
          res.setHeader('Content-Type', 'application/json');
          return res.end(JSON.stringify({ error: 'invalid_token', error_description: 'authentication is required.' }));
        }
        const returnTo = encodeURIComponent(req.originalUrl ?? req.url ?? '/');
        res.statusCode = 302;
        res.setHeader('Location', `${loginPath}?${returnToParam}=${returnTo}`);
        return res.end();
      }

      const missingClaims = [claims].flat().filter((c) => !ark.claims.includes(c));
      const missingScopes = [scopes].flat().filter((s) => !ark.scopes.includes(s));
      if (missingClaims.length || missingScopes.length) {
        res.statusCode = 403;
        res.setHeader('Content-Type', 'application/json');
        return res.end(
          JSON.stringify({
            error: 'insufficient_scope',
            error_description: [
              missingClaims.length ? `missing claim(s): ${missingClaims.join(', ')}` : null,
              missingScopes.length ? `missing scope(s): ${missingScopes.join(', ')}` : null
            ]
              .filter(Boolean)
              .join('; ')
          })
        );
      }

      next();
    };

  /** Shorthand for requireAuth({ claims }) — Ark authorization claims, the thing to authorise on. */
  middleware.requireClaims = (...claims) => middleware.requireAuth({ claims: claims.flat() });
  middleware.requireScopes = (...scopes) => middleware.requireAuth({ scopes: scopes.flat() });

  middleware.client = client;
  middleware.store = store;
  middleware.loginPath = loginPath;
  middleware.callbackPath = configuredCallbackPath;
  middleware.logoutPath = logoutPath;

  return middleware;
}

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
    res.statusCode = status;
    res.setHeader('WWW-Authenticate', `Bearer realm="ark", error="${error}", error_description="${description.replace(/"/g, "'")}"`);
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error, error_description: description }));
  };

  const middleware = async function arkBearerMiddleware(req, res, next) {
    const header = req.headers?.authorization ?? '';
    const token = header.toLowerCase().startsWith('bearer ') ? header.slice(7).trim() : null;

    if (!token) {
      if (optional) {
        req.ark = { isAuthenticated: false, token: null, claims: [], scopes: [] };
        return next();
      }
      return challenge(res, 401, 'invalid_token', 'an access token is required.');
    }

    try {
      const payload = await client.verifyAccessToken(token, { audience, scopes, arkClaims: claims, requireTypeHeader });
      const arkClaims = Array.isArray(payload.ark_claims) ? payload.ark_claims : payload.ark_claims ? [payload.ark_claims] : [];
      req.ark = {
        isAuthenticated: true,
        token,
        payload,
        sub: payload.sub,
        clientId: payload.client_id ?? null,
        sessionId: payload.sid ?? null,
        scopes: String(payload.scope ?? '').split(' ').filter(Boolean),
        claims: arkClaims,
        hasClaim: (...wanted) => wanted.flat().every((c) => arkClaims.includes(c)),
        hasScope: (...wanted) => wanted.flat().every((s) => String(payload.scope ?? '').split(' ').includes(s)),
        client
      };
      next();
    } catch (error) {
      if (error instanceof ArkOAuthError && error.error === 'insufficient_scope') {
        return challenge(res, 403, 'insufficient_scope', error.errorDescription ?? error.message);
      }
      return challenge(res, 401, 'invalid_token', error.message);
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
