import { createServer } from 'node:http';
import { createHash, generateKeyPairSync, randomUUID, sign as cryptoSign } from 'node:crypto';

/**
 * A stand-in for the Ark identity server, close enough on the wire to test a browser client.
 *
 * It mirrors what `Ark.oAuth.Oidc` does: the paths under `/{tenant}/oauth2/…`; RS256 with a `kid`;
 * `at+jwt` access tokens with `ark_claims`; ID tokens with `at_hash`/`c_hash`/`sid`/`auth_time`;
 * `iss` on the authorization response (RFC 9207); public clients authenticating with `client_id`
 * alone and PKCE S256 required; refresh-token rotation where replaying a retired token revokes the
 * family; `prompt=none`/`prompt=login`; RP-initiated logout appending `state` only for a registered
 * post-logout URI; and CORS exactly where the server grants it: discovery, JWKS, token and userinfo,
 * never revoke. (Node's fetch does not enforce CORS; the headers are here so a browser run against
 * this stub behaves like one against the real server.)
 *
 * `misbehave` lets a test make the server lie (wrong nonce, wrong at_hash, wrong issuer, an unknown
 * key) to prove the client refuses.
 */

const b64u = (input) => Buffer.from(input).toString('base64url');
const leftHalfHash = (value) => {
  const digest = createHash('sha256').update(value).digest();
  return digest.subarray(0, digest.length / 2).toString('base64url');
};

export class StubIdp {
  constructor({ tenant = 'test_idp', corsOrigins = ['http://127.0.0.1:5173'] } = {}) {
    this.tenant = tenant;
    this.corsOrigins = corsOrigins;
    this.keys = [];
    this.addKey('key-1');
    this.rogueKey = this.#makeKey('rogue');
    this.codes = new Map();
    this.refreshTokens = new Map();
    this.families = new Map();
    this.sessions = new Map();
    this.browserSession = null; // the provider's own session cookie, as one browser would carry it
    this.requests = [];
    this.authorizeRequests = [];
    this.tokenRequests = [];
    this.revocations = [];
    this.logouts = [];
    this.user = { sub: 'alice@example.com', name: 'Alice Example', email: 'alice@example.com', email_verified: true };
    this.arkClaims = ['billing.admin', 'reports.read'];
    this.accessTokenLifetime = 3600;
    this.rotateRefreshTokens = true;
    this.misbehave = {};
    this.tokenDelayMs = 0;
    this.clients = {
      'spa-app': {
        redirectUris: ['http://127.0.0.1:5173/signin-oidc'],
        postLogoutRedirectUris: ['http://127.0.0.1:5173/signout-callback-oidc'],
        grants: ['authorization_code', 'refresh_token']
      }
    };
  }

  #makeKey(kid) {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    return { kid, privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg: 'RS256' } };
  }

  addKey(kid) {
    this.keys.unshift(this.#makeKey(kid));
    return kid;
  }

  rotateKey(kid = `key-${this.keys.length + 1}`) {
    this.addKey(kid);
    this.keys = this.keys.slice(0, 2);
    return kid;
  }

  sign(payload, { typ = 'JWT', key = this.keys[0] } = {}) {
    const header = { alg: 'RS256', typ, kid: key.kid };
    const input = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;
    return `${input}.${cryptoSign('sha256', Buffer.from(input), key.privateKey).toString('base64url')}`;
  }

  async listen() {
    this.server = createServer((req, res) => this.#handle(req, res).catch((error) => this.#json(req, res, 500, { error: 'server_error', error_description: error.message })));
    await new Promise((resolve) => this.server.listen(0, '127.0.0.1', resolve));
    this.port = this.server.address().port;
    this.baseUrl = `http://127.0.0.1:${this.port}`;
    this.issuer = `${this.baseUrl}/${this.tenant}`;
    return this;
  }

  async close() {
    this.server.closeAllConnections?.();
    await new Promise((resolve) => this.server.close(resolve));
  }

  /** Follows the authorize redirect the way a browser would, returning the callback URL. */
  async authorize(url) {
    const res = await fetch(url, { redirect: 'manual' });
    if (res.status !== 302) throw new Error(`authorize answered ${res.status}: ${await res.text()}`);
    return res.headers.get('location');
  }

  // -----------------------------------------------------------------

  #cors(req, headers) {
    const origin = req.headers.origin;
    if (origin && this.corsOrigins.includes(origin)) {
      headers['Access-Control-Allow-Origin'] = origin;
      headers.Vary = 'Origin';
      headers['Access-Control-Expose-Headers'] = 'WWW-Authenticate';
    }
    return headers;
  }

  #json(req, res, status, body, { cors = false, headers = {} } = {}) {
    const all = { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers };
    res.writeHead(status, cors ? this.#cors(req, all) : all);
    res.end(JSON.stringify(body));
  }

  async #body(req) {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    return Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString('utf8')));
  }

  #accessToken({ clientId, subject, scopes, sessionId }) {
    const now = Math.floor(Date.now() / 1000);
    return this.sign(
      {
        iss: this.issuer,
        aud: `${this.tenant}_api`,
        sub: subject,
        client_id: clientId,
        jti: randomUUID(),
        iat: now,
        nbf: now,
        exp: now + this.accessTokenLifetime,
        scope: scopes.join(' '),
        sid: sessionId,
        ...(this.arkClaims.length ? { ark_claims: this.arkClaims } : {})
      },
      { typ: 'at+jwt' }
    );
  }

  #idToken({ clientId, subject, nonce, sessionId, accessToken, code, authTime }) {
    const now = Math.floor(Date.now() / 1000);
    const m = this.misbehave;
    return this.sign(
      {
        iss: m.idTokenIssuer ?? this.issuer,
        aud: m.idTokenAudience ?? clientId,
        azp: clientId,
        sub: m.idTokenSubject ?? subject,
        iat: now,
        nbf: now,
        exp: now + 300,
        auth_time: authTime,
        ...(nonce ? { nonce: m.nonce ?? nonce } : {}),
        sid: sessionId,
        at_hash: m.atHash ?? leftHalfHash(accessToken),
        ...(code ? { c_hash: leftHalfHash(code) } : {}),
        name: this.user.name,
        email: this.user.email,
        email_verified: this.user.email_verified,
        preferred_username: this.user.email
      },
      m.rogueSigner ? { key: this.rogueKey } : {}
    );
  }

  #issue(req, res, { clientId, subject, scopes, sessionId, nonce, code, familyId, authTime, isRefresh }) {
    const accessToken = this.#accessToken({ clientId, subject, scopes, sessionId });
    const body = { access_token: accessToken, token_type: 'Bearer', expires_in: this.accessTokenLifetime, scope: scopes.join(' ') };
    if (scopes.includes('offline_access') && (!isRefresh || this.rotateRefreshTokens)) {
      const refreshToken = b64u(randomUUID() + randomUUID());
      const family = familyId ?? randomUUID();
      this.refreshTokens.set(refreshToken, { clientId, subject, scopes, sessionId, family, used: false, authTime });
      this.families.set(family, [...(this.families.get(family) ?? []), refreshToken]);
      body.refresh_token = refreshToken;
    }
    if (scopes.includes('openid')) body.id_token = this.#idToken({ clientId, subject, nonce, sessionId, accessToken, code, authTime });
    this.#json(req, res, 200, body, { cors: true });
  }

  async #handle(req, res) {
    const url = new URL(req.url, this.baseUrl);
    const path = url.pathname.replace(`/${this.tenant}`, '');
    this.requests.push({ method: req.method, path, origin: req.headers.origin ?? null });

    const corsEndpoints = ['/.well-known/openid-configuration', '/.well-known/jwks.json', '/oauth2/token', '/oauth2/userinfo'];
    if (req.method === 'OPTIONS') {
      const headers = corsEndpoints.includes(path)
        ? this.#cors(req, {
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Authorization, Content-Type, Accept',
            'Access-Control-Max-Age': '600'
          })
        : {};
      res.writeHead(204, headers);
      return res.end();
    }

    if (path === '/.well-known/openid-configuration') {
      return this.#json(
        req,
        res,
        200,
        {
          issuer: this.misbehave.discoveryIssuer ?? this.issuer,
          authorization_endpoint: `${this.issuer}/oauth2/authorize`,
          token_endpoint: `${this.issuer}/oauth2/token`,
          userinfo_endpoint: `${this.issuer}/oauth2/userinfo`,
          jwks_uri: `${this.issuer}/.well-known/jwks.json`,
          revocation_endpoint: `${this.issuer}/oauth2/revoke`,
          end_session_endpoint: `${this.issuer}/oauth2/logout`,
          scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
          response_types_supported: ['code'],
          response_modes_supported: ['query', 'fragment', 'form_post'],
          grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
          id_token_signing_alg_values_supported: ['RS256'],
          token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'private_key_jwt', 'none'],
          code_challenge_methods_supported: ['S256'],
          authorization_response_iss_parameter_supported: true,
          require_pushed_authorization_requests: Boolean(this.misbehave.requirePar)
        },
        { cors: true, headers: { 'Cache-Control': 'max-age=300' } }
      );
    }

    if (path === '/.well-known/jwks.json') {
      return this.#json(req, res, 200, { keys: this.keys.map((k) => k.jwk) }, { cors: true });
    }

    if (path === '/oauth2/authorize') {
      const p = Object.fromEntries(url.searchParams);
      this.authorizeRequests.push(p);
      const client = this.clients[p.client_id];
      if (!client) return this.#json(req, res, 400, { error: 'invalid_request', error_description: 'unknown client_id.' });
      if (!client.redirectUris.includes(p.redirect_uri)) {
        return this.#json(req, res, 400, { error: 'invalid_request', error_description: 'redirect_uri does not match a registered value.' });
      }
      const back = new URL(p.redirect_uri);
      const respond = (params) => {
        const target = new URLSearchParams({ ...params, ...(p.state ? { state: p.state } : {}), iss: this.misbehave.responseIss ?? this.issuer });
        if (p.response_mode === 'fragment') back.hash = target.toString();
        else for (const [k, v] of target) back.searchParams.set(k, v);
        res.writeHead(302, { Location: back.toString() });
        res.end();
      };
      if (this.misbehave.authorizeError) return respond({ error: this.misbehave.authorizeError, error_description: 'refused by the stub.' });
      if (!p.code_challenge || p.code_challenge_method !== 'S256') return respond({ error: 'invalid_request', error_description: 'code_challenge is required (PKCE).' });

      const prompts = (p.prompt ?? '').split(' ').filter(Boolean);
      if (prompts.includes('login')) this.browserSession = null;
      if (!this.browserSession) {
        if (prompts.includes('none')) return respond({ error: 'login_required', error_description: 'the user is not signed in.' });
        // The stub "signs in" at once: a real server would draw its form here.
        this.browserSession = { sessionId: `sid_${randomUUID()}`, subject: this.user.sub, authTime: Math.floor(Date.now() / 1000) };
        this.sessions.set(this.browserSession.sessionId, this.browserSession);
      }

      const code = `code_${randomUUID()}`;
      this.codes.set(code, {
        clientId: p.client_id,
        redirectUri: p.redirect_uri,
        scopes: (p.scope ?? '').split(' ').filter(Boolean),
        challenge: p.code_challenge,
        nonce: p.nonce,
        sessionId: this.browserSession.sessionId,
        authTime: this.browserSession.authTime,
        consumed: false
      });
      return respond({ code });
    }

    if (path === '/oauth2/token' && req.method === 'POST') {
      const form = await this.#body(req);
      this.tokenRequests.push(form);
      if (this.tokenDelayMs) await new Promise((r) => setTimeout(r, this.tokenDelayMs));
      const fail = (status, error, description) => this.#json(req, res, status, { error, error_description: description }, { cors: true });
      if (form.client_secret || req.headers.authorization) return fail(400, 'invalid_client', 'this client is public and must not present a secret.');
      const client = this.clients[form.client_id];
      if (!client) return fail(400, 'invalid_client', 'client authentication failed: unknown client.');
      if (!client.grants.includes(form.grant_type)) return fail(400, 'unauthorized_client', `this client is not registered for the '${form.grant_type}' grant.`);

      if (form.grant_type === 'authorization_code') {
        const entry = this.codes.get(form.code);
        if (!entry) return fail(400, 'invalid_grant', 'authorization code is invalid.');
        if (entry.consumed) return fail(400, 'invalid_grant', 'authorization code has already been used.');
        if (entry.clientId !== form.client_id) return fail(400, 'invalid_grant', 'the code was issued to a different client.');
        if (entry.redirectUri !== form.redirect_uri) return fail(400, 'invalid_grant', 'redirect_uri does not match the authorization request.');
        if (!form.code_verifier || createHash('sha256').update(form.code_verifier).digest('base64url') !== entry.challenge) {
          return fail(400, 'invalid_grant', 'code_verifier does not match the code_challenge.');
        }
        entry.consumed = true;
        return this.#issue(req, res, { ...entry, subject: this.user.sub, code: form.code });
      }

      if (form.grant_type === 'refresh_token') {
        const entry = this.refreshTokens.get(form.refresh_token);
        if (!entry) return fail(400, 'invalid_grant', 'refresh token is invalid.');
        if (entry.used) {
          for (const token of this.families.get(entry.family) ?? []) this.refreshTokens.delete(token);
          this.familyRevocations = (this.familyRevocations ?? 0) + 1;
          return fail(400, 'invalid_grant', 'refresh token has already been used.');
        }
        if (!this.sessions.has(entry.sessionId)) return fail(400, 'invalid_grant', 'the session behind this refresh token has ended.');
        if (this.rotateRefreshTokens) entry.used = true;
        return this.#issue(req, res, { ...entry, familyId: entry.family, isRefresh: true });
      }
      return fail(400, 'unsupported_grant_type', `grant_type '${form.grant_type}' is not supported.`);
    }

    if (path === '/oauth2/userinfo') {
      const token = (req.headers.authorization ?? '').replace(/^Bearer /i, '');
      if (!token) return this.#json(req, res, 401, { error: 'invalid_token' }, { cors: true, headers: { 'WWW-Authenticate': 'Bearer error="invalid_token"' } });
      const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
      return this.#json(req, res, 200, { sub: payload.sub, ...this.user }, { cors: true });
    }

    if (path === '/oauth2/revoke' && req.method === 'POST') {
      // No CORS here, as on the real server: a browser can only deliver this, never read it.
      const form = await this.#body(req);
      this.revocations.push(form);
      const entry = this.refreshTokens.get(form.token);
      if (entry && entry.clientId === form.client_id) for (const token of this.families.get(entry.family) ?? []) this.refreshTokens.delete(token);
      res.writeHead(200, { 'Cache-Control': 'no-store' });
      return res.end();
    }

    if (path === '/oauth2/logout') {
      const p = Object.fromEntries(url.searchParams);
      this.logouts.push(p);
      if (this.browserSession) this.sessions.delete(this.browserSession.sessionId);
      this.browserSession = null;
      const client = this.clients[p.client_id];
      if (p.post_logout_redirect_uri && client?.postLogoutRedirectUris.includes(p.post_logout_redirect_uri)) {
        const back = new URL(p.post_logout_redirect_uri);
        if (p.state) back.searchParams.set('state', p.state);
        res.writeHead(302, { Location: back.toString() });
        return res.end();
      }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end('<p>You have been signed out.</p>');
    }

    return this.#json(req, res, 404, { error: 'invalid_request', error_description: `no endpoint at ${path}.` });
  }
}
