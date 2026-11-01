import { createServer } from 'node:http';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { base64UrlEncode, leftHalfHash, sha256 } from '../src/crypto.js';
import { signJwt } from '../src/jwt.js';

/**
 * A stand-in for the Ark identity server, close enough on the wire to test a client against.
 *
 * It mirrors what `Ark.oAuth.Oidc` actually does rather than what the specs merely permit: the
 * same paths under `/{tenant}/oauth2/…`, RS256 with a `kid` and two published keys across a
 * rotation, `at+jwt` access tokens carrying `ark_claims`, ID tokens with `at_hash`/`c_hash`,
 * `iss` on the authorization response (RFC 9207), refresh-token rotation where replaying a
 * retired token revokes the family, and RFC 6749 §5.2 error bodies with the right status codes.
 *
 * The tests are only worth as much as this file's fidelity, so where it differs from the server it
 * does so by being stricter, never by being more forgiving.
 */
export class StubIdp {
  constructor({ tenant = 'test_idp', clients } = {}) {
    this.tenant = tenant;
    this.keys = [];
    this.addKey('key-1');
    this.codes = new Map();
    this.refreshTokens = new Map();
    this.families = new Map();
    this.deviceCodes = new Map();
    this.parRequests = new Map();
    this.sessions = new Map();
    this.requests = [];
    this.grants = [];
    this.user = { sub: 'alice@example.com', name: 'Alice Example', email: 'alice@example.com', email_verified: true };
    this.arkClaims = ['billing.admin', 'reports.read'];
    this.clients = clients ?? {
      'web-app': { secret: null, method: 'none', redirectUris: ['http://127.0.0.1:0/signin-oidc'], grants: ['authorization_code', 'refresh_token'] },
      'confidential-app': {
        secret: 'top-secret',
        method: 'client_secret_basic',
        redirectUris: [],
        grants: ['authorization_code', 'refresh_token', 'client_credentials', 'urn:ietf:params:oauth:grant-type:device_code']
      },
      'post-app': { secret: 'post-secret', method: 'client_secret_post', redirectUris: [], grants: ['client_credentials'] }
    };
  }

  addKey(kid) {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    this.keys.unshift({ kid, privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg: 'RS256' } });
    return kid;
  }

  /** Two-phase rotation: the new key signs, the old one stays published until its tokens expire. */
  rotateKey(kid = `key-${this.keys.length + 1}`) {
    this.addKey(kid);
    this.keys = this.keys.slice(0, 2);
    return kid;
  }

  get activeKey() {
    return this.keys[0];
  }

  async listen() {
    this.server = createServer((req, res) => this.#handle(req, res).catch((error) => this.#fail(res, 500, 'server_error', error.message)));
    await new Promise((resolve) => this.server.listen(0, '127.0.0.1', resolve));
    this.port = this.server.address().port;
    this.baseUrl = `http://127.0.0.1:${this.port}`;
    this.issuer = `${this.baseUrl}/${this.tenant}`;
    return this;
  }

  async close() {
    await new Promise((resolve) => this.server.close(resolve));
  }

  // -----------------------------------------------------------------

  #fail(res, status, error, description, headers = {}) {
    res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers });
    res.end(JSON.stringify({ error, error_description: description }));
  }

  #json(res, status, body) {
    res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify(body));
  }

  async #body(req) {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString('utf8');
    if ((req.headers['content-type'] ?? '').includes('json')) return raw ? JSON.parse(raw) : {};
    return Object.fromEntries(new URLSearchParams(raw));
  }

  /** Mirrors ArkClientAuthenticator: one method only, and the registered method must match. */
  #authenticateClient(req, form, { allowPublic = true } = {}) {
    const header = req.headers.authorization ?? '';
    const hasBasic = header.startsWith('Basic ');
    const hasPost = Boolean(form.client_secret);
    const hasAssertion = Boolean(form.client_assertion);
    if ([hasBasic, hasPost, hasAssertion].filter(Boolean).length > 1) {
      throw Object.assign(new Error('more than one client authentication method was used.'), { oauth: 'invalid_request' });
    }

    let clientId;
    let secret = null;
    let method = 'none';

    if (hasBasic) {
      const [id, pw] = Buffer.from(header.slice(6), 'base64').toString('utf8').split(':');
      clientId = decodeURIComponent(id.replace(/\+/g, ' '));
      secret = decodeURIComponent((pw ?? '').replace(/\+/g, ' '));
      method = 'client_secret_basic';
    } else if (hasPost) {
      clientId = form.client_id;
      secret = form.client_secret;
      method = 'client_secret_post';
    } else {
      clientId = form.client_id;
    }

    const client = this.clients[clientId];
    if (!client) throw Object.assign(new Error('client authentication failed: unknown client.'), { oauth: 'invalid_client', status: hasBasic ? 401 : 400 });
    if (method !== 'none' && (client.secret !== secret || client.method !== method)) {
      throw Object.assign(new Error('client authentication failed.'), { oauth: 'invalid_client', status: hasBasic ? 401 : 400 });
    }
    if (method === 'none' && client.secret && !allowPublic) {
      throw Object.assign(new Error('this client is confidential and must authenticate.'), { oauth: 'invalid_client' });
    }
    return { clientId, client, method };
  }

  #accessToken({ clientId, subject, scopes, sessionId }) {
    const now = Math.floor(Date.now() / 1000);
    return signJwt(
      {
        iss: this.issuer,
        aud: `${this.tenant}_api`,
        sub: subject,
        client_id: clientId,
        jti: randomUUID(),
        iat: now,
        nbf: now,
        exp: now + 3600,
        ...(scopes.length ? { scope: scopes.join(' ') } : {}),
        ...(sessionId ? { sid: sessionId } : {}),
        ...(this.arkClaims.length && subject !== clientId ? { ark_claims: this.arkClaims } : {})
      },
      { key: this.activeKey.privateKey, kid: this.activeKey.kid, typ: 'at+jwt' }
    );
  }

  #idToken({ clientId, subject, nonce, sessionId, accessToken, code, authTime }) {
    const now = Math.floor(Date.now() / 1000);
    return signJwt(
      {
        iss: this.issuer,
        aud: clientId,
        azp: clientId,
        sub: subject,
        iat: now,
        nbf: now,
        exp: now + 300,
        auth_time: authTime ?? now,
        ...(nonce ? { nonce } : {}),
        ...(sessionId ? { sid: sessionId } : {}),
        ...(accessToken ? { at_hash: leftHalfHash(accessToken) } : {}),
        ...(code ? { c_hash: leftHalfHash(code) } : {}),
        name: this.user.name,
        email: this.user.email,
        email_verified: this.user.email_verified,
        preferred_username: this.user.email
      },
      { key: this.activeKey.privateKey, kid: this.activeKey.kid }
    );
  }

  #issue(res, { clientId, subject, scopes, sessionId, nonce, code, familyId }) {
    const accessToken = this.#accessToken({ clientId, subject, scopes, sessionId });
    const body = { access_token: accessToken, token_type: 'Bearer', expires_in: 3600 };
    if (scopes.length) body.scope = scopes.join(' ');

    if (scopes.includes('offline_access')) {
      const refreshToken = base64UrlEncode(randomUUID() + randomUUID());
      const family = familyId ?? randomUUID();
      this.refreshTokens.set(refreshToken, { clientId, subject, scopes, sessionId, family, used: false });
      this.families.set(family, [...(this.families.get(family) ?? []), refreshToken]);
      body.refresh_token = refreshToken;
    }

    if (scopes.includes('openid')) {
      body.id_token = this.#idToken({ clientId, subject, nonce, sessionId, accessToken, code });
    }
    this.#json(res, 200, body);
  }

  // -----------------------------------------------------------------

  async #handle(req, res) {
    const url = new URL(req.url, this.baseUrl);
    const path = url.pathname.replace(`/${this.tenant}`, '');
    this.requests.push({ method: req.method, path, url: url.toString() });

    if (!url.pathname.startsWith(`/${this.tenant}/`)) return this.#fail(res, 400, 'invalid_request', `unknown tenant.`);

    if (path === '/.well-known/openid-configuration' || path === '/.well-known/oauth-authorization-server') {
      return this.#json(res, 200, {
        issuer: this.issuer,
        authorization_endpoint: `${this.issuer}/oauth2/authorize`,
        token_endpoint: `${this.issuer}/oauth2/token`,
        userinfo_endpoint: `${this.issuer}/oauth2/userinfo`,
        jwks_uri: `${this.issuer}/.well-known/jwks.json`,
        introspection_endpoint: `${this.issuer}/oauth2/introspect`,
        revocation_endpoint: `${this.issuer}/oauth2/revoke`,
        end_session_endpoint: `${this.issuer}/oauth2/logout`,
        device_authorization_endpoint: `${this.issuer}/oauth2/device_authorization`,
        pushed_authorization_request_endpoint: `${this.issuer}/oauth2/par`,
        registration_endpoint: `${this.issuer}/oauth2/register`,
        scopes_supported: ['openid', 'profile', 'email', 'address', 'phone', 'offline_access', 'client.register'],
        response_types_supported: ['code'],
        response_modes_supported: ['query', 'fragment', 'form_post'],
        grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials', 'urn:ietf:params:oauth:grant-type:device_code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'private_key_jwt', 'none'],
        code_challenge_methods_supported: ['S256'],
        authorization_response_iss_parameter_supported: true,
        require_pushed_authorization_requests: false
      });
    }

    if (path === '/.well-known/jwks.json') {
      return this.#json(res, 200, { keys: this.keys.map((k) => k.jwk) });
    }

    if (path === '/oauth2/authorize') {
      const p = url.searchParams;
      let params = p;
      if (p.get('request_uri')) {
        const pushed = this.parRequests.get(p.get('request_uri'));
        if (!pushed) return this.#fail(res, 400, 'invalid_request_uri', 'unknown or expired request_uri.');
        this.parRequests.delete(p.get('request_uri'));
        params = new URLSearchParams(pushed);
      }

      if (params.get('response_type') !== 'code') return this.#fail(res, 400, 'unsupported_response_type', 'only code is supported.');
      if (!params.get('code_challenge')) return this.#fail(res, 400, 'invalid_request', 'code_challenge is required (PKCE).');
      if ((params.get('code_challenge_method') ?? 'S256') !== 'S256') return this.#fail(res, 400, 'invalid_request', 'code_challenge_method must be S256.');

      const code = `code_${randomUUID()}`;
      const sessionId = `sid_${randomUUID()}`;
      this.sessions.set(sessionId, { subject: this.user.sub });
      this.codes.set(code, {
        clientId: params.get('client_id'),
        redirectUri: params.get('redirect_uri'),
        scopes: (params.get('scope') ?? '').split(' ').filter(Boolean),
        challenge: params.get('code_challenge'),
        nonce: params.get('nonce'),
        sessionId,
        consumed: false
      });

      const back = new URL(params.get('redirect_uri'));
      back.searchParams.set('code', code);
      if (params.get('state')) back.searchParams.set('state', params.get('state'));
      back.searchParams.set('iss', this.issuer); // RFC 9207
      res.writeHead(302, { Location: back.toString() });
      return res.end();
    }

    if (path === '/oauth2/par' && req.method === 'POST') {
      const form = await this.#body(req);
      try {
        this.#authenticateClient(req, form);
      } catch (error) {
        return this.#fail(res, error.status ?? 400, error.oauth ?? 'invalid_request', error.message);
      }
      const requestUri = `urn:ietf:params:oauth:request_uri:${randomUUID()}`;
      const { client_secret: _s, client_assertion: _a, client_assertion_type: _t, ...rest } = form;
      this.parRequests.set(requestUri, rest);
      return this.#json(res, 201, { request_uri: requestUri, expires_in: 90 });
    }

    if (path === '/oauth2/token' && req.method === 'POST') {
      const form = await this.#body(req);
      let auth;
      try {
        auth = this.#authenticateClient(req, form);
      } catch (error) {
        return this.#fail(res, error.status ?? 400, error.oauth ?? 'invalid_client', error.message, error.status === 401 ? { 'WWW-Authenticate': 'Basic realm="ark"' } : {});
      }

      const grant = form.grant_type;
      this.grants.push(grant);
      if (!auth.client.grants.includes(grant)) {
        return this.#fail(res, 400, 'unauthorized_client', `this client is not registered for the '${grant}' grant.`);
      }

      if (grant === 'authorization_code') {
        const entry = this.codes.get(form.code);
        if (!entry) return this.#fail(res, 400, 'invalid_grant', 'authorization code is invalid.');
        if (entry.consumed) {
          this.codes.delete(form.code);
          return this.#fail(res, 400, 'invalid_grant', 'authorization code has already been used.');
        }
        if (entry.clientId !== auth.clientId) return this.#fail(res, 400, 'invalid_grant', 'the code was issued to a different client.');
        if (entry.redirectUri !== form.redirect_uri) return this.#fail(res, 400, 'invalid_grant', 'redirect_uri does not match the authorization request.');
        if (!form.code_verifier) return this.#fail(res, 400, 'invalid_grant', 'code_verifier is required.');
        if (form.code_verifier.length < 43 || form.code_verifier.length > 128) {
          return this.#fail(res, 400, 'invalid_grant', 'code_verifier must be between 43 and 128 characters.');
        }
        if (base64UrlEncode(sha256(form.code_verifier)) !== entry.challenge) {
          return this.#fail(res, 400, 'invalid_grant', 'code_verifier does not match the code_challenge.');
        }
        entry.consumed = true;
        return this.#issue(res, { ...entry, subject: this.user.sub, code: form.code });
      }

      if (grant === 'refresh_token') {
        const entry = this.refreshTokens.get(form.refresh_token);
        if (!entry) return this.#fail(res, 400, 'invalid_grant', 'refresh token is invalid.');
        if (entry.used) {
          // Replay means the token leaked: the whole family goes.
          for (const token of this.families.get(entry.family) ?? []) this.refreshTokens.delete(token);
          return this.#fail(res, 400, 'invalid_grant', 'refresh token has already been used.');
        }
        let scopes = entry.scopes;
        if (form.scope) {
          const wanted = form.scope.split(' ').filter(Boolean);
          const widened = wanted.filter((s) => !scopes.includes(s));
          if (widened.length) return this.#fail(res, 400, 'invalid_scope', `scope cannot be widened on refresh: ${widened.join(', ')}.`);
          scopes = wanted;
        }
        entry.used = true;
        return this.#issue(res, { ...entry, scopes, familyId: entry.family });
      }

      if (grant === 'client_credentials') {
        if (auth.method === 'none') return this.#fail(res, 400, 'invalid_client', 'the client_credentials grant requires client authentication.');
        const scopes = (form.scope ?? '').split(' ').filter((s) => s && s !== 'openid' && s !== 'offline_access');
        return this.#issue(res, { clientId: auth.clientId, subject: auth.clientId, scopes });
      }

      if (grant === 'urn:ietf:params:oauth:grant-type:device_code') {
        const entry = this.deviceCodes.get(form.device_code);
        if (!entry) return this.#fail(res, 400, 'invalid_grant', 'device_code is invalid.');
        if (entry.status === 'pending') return this.#fail(res, 400, 'authorization_pending', 'the user has not yet approved the request.');
        if (entry.status === 'slow_down') {
          entry.status = 'pending';
          return this.#fail(res, 400, 'slow_down', 'polling too fast.');
        }
        if (entry.status === 'denied') return this.#fail(res, 400, 'access_denied', 'the user denied the request.');
        this.deviceCodes.delete(form.device_code);
        return this.#issue(res, { clientId: auth.clientId, subject: this.user.sub, scopes: entry.scopes, sessionId: entry.sessionId });
      }

      return this.#fail(res, 400, 'unsupported_grant_type', `grant_type '${grant}' is not supported.`);
    }

    if (path === '/oauth2/device_authorization' && req.method === 'POST') {
      const form = await this.#body(req);
      try {
        this.#authenticateClient(req, form, { allowPublic: false });
      } catch (error) {
        return this.#fail(res, error.status ?? 400, error.oauth ?? 'invalid_client', error.message);
      }
      const deviceCode = `device_${randomUUID()}`;
      const userCode = 'WDJB-MJHT';
      this.deviceCodes.set(deviceCode, { status: 'pending', scopes: (form.scope ?? '').split(' ').filter(Boolean), sessionId: `sid_${randomUUID()}` });
      return this.#json(res, 200, {
        device_code: deviceCode,
        user_code: userCode,
        verification_uri: `${this.issuer}/oauth2/device`,
        verification_uri_complete: `${this.issuer}/oauth2/device?user_code=${userCode}`,
        expires_in: 600,
        interval: 0 // tests must not wait five seconds per poll
      });
    }

    if (path === '/oauth2/userinfo') {
      const token = (req.headers.authorization ?? '').replace(/^Bearer /i, '');
      if (!token) {
        res.writeHead(401, { 'WWW-Authenticate': 'Bearer realm="ark", error="invalid_token"', 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'invalid_token', error_description: 'an access token is required.' }));
      }
      const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
      if (!String(payload.scope ?? '').split(' ').includes('openid')) {
        res.writeHead(403, { 'WWW-Authenticate': 'Bearer realm="ark", error="insufficient_scope"', 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'insufficient_scope', error_description: "the 'openid' scope is required." }));
      }
      return this.#json(res, 200, { sub: payload.sub, ...this.user });
    }

    if (path === '/oauth2/introspect' && req.method === 'POST') {
      const form = await this.#body(req);
      try {
        const auth = this.#authenticateClient(req, form);
        if (auth.method === 'none') return this.#fail(res, 400, 'invalid_client', 'the introspection endpoint requires client authentication.');
      } catch (error) {
        return this.#fail(res, error.status ?? 400, error.oauth ?? 'invalid_client', error.message);
      }
      const refresh = this.refreshTokens.get(form.token);
      if (refresh && !refresh.used) {
        return this.#json(res, 200, { active: true, sub: refresh.subject, client_id: refresh.clientId, scope: refresh.scopes.join(' '), token_type: 'refresh_token' });
      }
      try {
        const payload = JSON.parse(Buffer.from(form.token.split('.')[1], 'base64url').toString('utf8'));
        if (payload.exp * 1000 > Date.now()) {
          return this.#json(res, 200, { active: true, sub: payload.sub, scope: payload.scope, client_id: payload.client_id, exp: payload.exp, iat: payload.iat, token_type: 'Bearer' });
        }
      } catch {
        /* not a JWT: inactive */
      }
      return this.#json(res, 200, { active: false });
    }

    if (path === '/oauth2/revoke' && req.method === 'POST') {
      const form = await this.#body(req);
      try {
        this.#authenticateClient(req, form);
      } catch (error) {
        return this.#fail(res, error.status ?? 400, error.oauth ?? 'invalid_client', error.message);
      }
      const entry = this.refreshTokens.get(form.token);
      if (entry) for (const token of this.families.get(entry.family) ?? []) this.refreshTokens.delete(token);
      res.writeHead(200, { 'Cache-Control': 'no-store' });
      return res.end();
    }

    if (path === '/oauth2/logout') {
      const target = url.searchParams.get('post_logout_redirect_uri');
      if (target) {
        const back = new URL(target);
        if (url.searchParams.get('state')) back.searchParams.set('state', url.searchParams.get('state'));
        res.writeHead(302, { Location: back.toString() });
        return res.end();
      }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end('<p>You have been signed out.</p>');
    }

    if (path === '/oauth2/register' && req.method === 'POST') {
      const token = (req.headers.authorization ?? '').replace(/^Bearer /i, '');
      if (!token) return this.#fail(res, 400, 'invalid_client', 'an initial access token is required to register a client.');
      const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
      if (!String(payload.scope ?? '').split(' ').includes('client.register')) {
        return this.#fail(res, 403, 'insufficient_scope', "the initial access token needs the 'client.register' scope.");
      }
      const metadata = await this.#body(req);
      const clientId = `c_${randomUUID().slice(0, 12)}`;
      const secret = metadata.token_endpoint_auth_method === 'none' ? null : `s_${randomUUID()}`;
      this.clients[clientId] = {
        secret,
        method: metadata.token_endpoint_auth_method ?? 'client_secret_basic',
        redirectUris: metadata.redirect_uris ?? [],
        grants: metadata.grant_types ?? ['authorization_code']
      };
      return this.#json(res, 201, {
        client_id: clientId,
        ...(secret ? { client_secret: secret, client_secret_expires_at: 0 } : {}),
        client_name: metadata.client_name,
        grant_types: this.clients[clientId].grants,
        token_endpoint_auth_method: this.clients[clientId].method,
        registration_access_token: `rat_${randomUUID()}`,
        registration_client_uri: `${this.issuer}/oauth2/register/${clientId}`
      });
    }

    return this.#fail(res, 404, 'invalid_request', `no endpoint at ${path}.`);
  }
}
