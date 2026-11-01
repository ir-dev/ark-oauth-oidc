import { normalizeConfig } from './config.js';
import { MetadataResolver } from './discovery.js';
import { JwksCache } from './jwks.js';
import { TokenSet } from './tokens.js';
import { basicAuthHeader, getJson, postForm, request } from './http.js';
import { createNonce, createPkcePair, createState } from './pkce.js';
import { fixedTimeEqual, randomToken } from './crypto.js';
import { signJwt, verifyJwt } from './jwt.js';
import { ArkCallbackError, ArkConfigError, ArkOAuthError, ArkTokenError } from './errors.js';

/**
 * The Ark OAuth 2.1 / OpenID Connect client.
 *
 * One object per application, holding the configuration, the cached discovery document and the
 * cached JWKS. It is stateless with respect to users: a sign-in produces a *transaction* the
 * caller stores (the `state`, `nonce` and PKCE verifier), and a token set the caller stores. That
 * is what makes it safe to share one instance across every request in a process, and what lets
 * the session live wherever the application already keeps sessions rather than in this library.
 *
 * For an Express or Connect application, `arkExpress()` in ./express.js drives all of this — the
 * transaction, the session, the silent refresh — and is the thing to reach for first. Use this
 * class directly for CLIs, workers, Fastify/Koa/Hapi, or any flow without a browser.
 */
export class ArkOAuthClient {
  #config;
  #metadata;
  #jwks = new Map();
  #serviceTokens = new Map();

  constructor(options = {}) {
    this.#config = normalizeConfig(options);
    const http = { timeoutMs: this.#config.timeoutMs, fetch: this.#config.fetch };
    this.#metadata = options.metadataResolver ?? new MetadataResolver({ ttlMs: this.#config.metadataTtlMs, ...http });
  }

  get config() {
    return this.#config;
  }

  get authority() {
    return this.#config.authority;
  }

  /** The provider's discovery document, cached. Every endpoint below is read from it. */
  async metadata({ force = false } = {}) {
    return this.#metadata.get(this.#config.authority, { force });
  }

  /** The provider's published signing keys, cached and refreshed across key rotation. */
  async jwks() {
    const { jwks_uri: uri } = await this.metadata();
    if (!uri) throw new ArkOAuthError('server_error', "the provider's metadata has no 'jwks_uri'.", { endpoint: this.#config.authority });
    let cache = this.#jwks.get(uri);
    if (!cache) {
      cache = new JwksCache(uri, {
        ttlMs: this.#config.jwksTtlMs,
        minRefreshIntervalMs: this.#config.jwksMinRefreshIntervalMs,
        timeoutMs: this.#config.timeoutMs,
        fetch: this.#config.fetch
      });
      this.#jwks.set(uri, cache);
    }
    return cache;
  }

  // =================================================================
  // Interactive sign-in: authorization code + PKCE
  // =================================================================

  /**
   * Starts a sign-in: builds the URL to send the browser to, and returns the transaction that has
   * to survive until the user comes back.
   *
   * The returned `state`, `nonce` and `codeVerifier` are the entire security of the flow — store
   * them somewhere the user cannot read or edit (a server-side session, an encrypted cookie) and
   * pass the same object to `handleCallback`. Putting them in a plain cookie or a hidden form
   * field hands the attacker exactly the three values the checks are made of.
   *
   * @returns {Promise<{url: string, state: string, nonce: string, codeVerifier: string, redirectUri: string, createdAt: number, returnTo?: string}>}
   */
  async createAuthorizationUrl(options = {}) {
    const config = this.#config;
    const metadata = await this.metadata();

    const redirectUri = options.redirectUri ?? config.redirectUri;
    if (!redirectUri) {
      throw new ArkConfigError("ark_oauth_client: no 'redirectUri' is configured, and none was passed to createAuthorizationUrl().");
    }

    const scopes = options.scopes ?? config.scopes;
    const { codeVerifier, codeChallenge, codeChallengeMethod } = createPkcePair();
    const state = options.state ?? createState();
    const scopeValue = [...scopes].join(' ');
    const wantsIdToken = scopes.includes('openid');
    const nonce = options.nonce ?? (wantsIdToken ? createNonce() : null);

    const params = {
      response_type: 'code',
      client_id: config.clientId,
      redirect_uri: redirectUri,
      scope: scopeValue,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod,
      response_mode: options.responseMode ?? config.responseMode,
      ...(nonce ? { nonce } : {}),
      ...(options.prompt ?? config.prompt ? { prompt: options.prompt ?? config.prompt } : {}),
      ...(options.loginHint ? { login_hint: options.loginHint } : {}),
      ...(options.maxAge !== undefined && options.maxAge !== null ? { max_age: String(options.maxAge) } : {}),
      ...(options.acrValues ?? config.acrValues ? { acr_values: options.acrValues ?? config.acrValues } : {}),
      ...config.extraAuthorizationParams,
      ...options.extra
    };

    const authorizationEndpoint = metadata.authorization_endpoint;
    if (!authorizationEndpoint) {
      throw new ArkOAuthError('server_error', "the provider's metadata has no 'authorization_endpoint'.", { endpoint: config.authority });
    }

    // Pushed authorization requests (RFC 9126): the parameters travel over the authenticated back
    // channel and the browser only carries a one-time reference to them, so nothing in the URL can
    // be logged, tampered with or replayed. Used when asked for, and when the tenant requires it.
    const usePar = options.usePar ?? config.usePar ?? metadata.require_pushed_authorization_requests === true;
    let url;
    if (usePar) {
      const pushed = await this.pushAuthorizationRequest(params);
      url = `${authorizationEndpoint}?${new URLSearchParams({ client_id: config.clientId, request_uri: pushed.request_uri })}`;
    } else {
      url = `${authorizationEndpoint}?${new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined && v !== null))}`;
    }

    return {
      url,
      state,
      nonce,
      codeVerifier,
      redirectUri,
      scope: scopeValue,
      maxAge: options.maxAge ?? null,
      createdAt: Math.floor(Date.now() / 1000),
      ...(options.returnTo ? { returnTo: options.returnTo } : {})
    };
  }

  /**
   * Reads the authorization response out of whatever the web framework handed you: a full URL, a
   * query string, a URLSearchParams, or the parsed body of a `form_post` callback.
   */
  static readCallbackParams(input) {
    if (!input) return {};
    if (input instanceof URLSearchParams) return Object.fromEntries(input);
    if (typeof input === 'string') {
      const query = input.includes('?') ? input.slice(input.indexOf('?') + 1) : input.replace(/^[?#]/, '');
      return Object.fromEntries(new URLSearchParams(query));
    }
    if (typeof input === 'object') return { ...input };
    return {};
  }

  /**
   * Completes a sign-in: checks the response against the transaction, redeems the code, and
   * validates the ID token.
   *
   * Everything that makes the authorization code flow safe happens in this method, in this order:
   * an error response is surfaced as an error rather than as a missing code; `state` is compared
   * in constant time, so a response that belongs to no request of ours is refused before anything
   * is redeemed; `iss` is checked (RFC 9207) so a response cannot be replayed from one provider to
   * another; the code is exchanged with the PKCE verifier that only this process holds; and the ID
   * token is verified against the provider's keys, its `nonce`, and its `at_hash`/`c_hash`.
   *
   * @param {string|URLSearchParams|object} responseParams
   * @param {object} transaction the object returned by createAuthorizationUrl
   */
  async handleCallback(responseParams, transaction, options = {}) {
    const params = ArkOAuthClient.readCallbackParams(responseParams);
    const metadata = await this.metadata();

    if (!transaction?.state || !transaction?.codeVerifier) {
      throw new ArkCallbackError(
        'no login transaction was supplied. The state, nonce and PKCE verifier from createAuthorizationUrl() must be stored ' +
          'when the sign-in starts and passed back here.'
      );
    }

    // The user denied consent, the client is disabled, the tenant rejected the request: all
    // arrive here as a redirect carrying `error`, and all of them mean there is no code to redeem.
    if (params.error) {
      throw new ArkOAuthError(params.error, params.error_description, {
        endpoint: metadata.authorization_endpoint,
        errorUri: params.error_uri ?? null,
        body: params
      });
    }

    if (!params.state) throw new ArkCallbackError('the authorization response carried no `state`.');
    if (!fixedTimeEqual(String(params.state), String(transaction.state))) {
      throw new ArkCallbackError('the authorization response `state` does not match the request. Treat this as a CSRF attempt.');
    }

    // RFC 9207. Ark always sends `iss`; when the provider advertises it, a response without one is
    // as suspect as a wrong one, because stripping the parameter is how a mix-up attack hides.
    if (params.iss || metadata.authorization_response_iss_parameter_supported) {
      if (!params.iss) throw new ArkCallbackError('the provider advertises `iss` in authorization responses but this one has none.');
      if (params.iss !== metadata.issuer) {
        throw new ArkCallbackError(`the authorization response came from '${params.iss}', not from '${metadata.issuer}'.`);
      }
    }

    if (!params.code) throw new ArkCallbackError('the authorization response carried no `code`.');

    return this.exchangeCode({
      code: params.code,
      codeVerifier: transaction.codeVerifier,
      redirectUri: options.redirectUri ?? transaction.redirectUri ?? this.#config.redirectUri,
      nonce: transaction.nonce ?? null,
      maxAge: transaction.maxAge ?? null
    });
  }

  /** The bare `authorization_code` exchange, for callers doing their own callback handling. */
  async exchangeCode({ code, codeVerifier, redirectUri, nonce = null, maxAge = null }) {
    const metadata = await this.metadata();
    const endpoint = metadata.token_endpoint;

    const response = await this.#tokenRequest(endpoint, {
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier
    });

    return this.#toTokenSet(response, { nonce, code, maxAge });
  }

  /**
   * Exchanges a refresh token for a new access token.
   *
   * Rotation is on by default on this server: the response carries a *new* refresh token and the
   * one just presented is retired. Store what comes back. Presenting a retired token is treated as
   * theft and revokes the entire family, which is the point of rotation, and also the reason a
   * client that keeps re-sending its original token locks itself out on the second refresh.
   */
  async refresh(refreshToken, { scopes } = {}) {
    if (!refreshToken) throw new ArkConfigError('refresh() needs a refresh token.');
    const metadata = await this.metadata();

    const response = await this.#tokenRequest(metadata.token_endpoint, {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      // RFC 6749 §6: scope may be narrowed here, never widened. The server rejects a widening.
      ...(scopes?.length ? { scope: [...scopes].join(' ') } : {})
    });

    return this.#toTokenSet(response, { nonce: null });
  }

  /**
   * The client credentials grant — the service authenticating as itself, with no user involved.
   *
   * Tokens are cached per client and scope set until shortly before they expire. A service that
   * asks for a fresh token on every outbound call turns one request into two and rate-limits
   * itself against its own identity provider.
   */
  async clientCredentials({ scopes = [], clientId, clientSecret, force = false, renewBeforeSeconds = 60 } = {}) {
    if (this.#config.tokenEndpointAuthMethod === 'none' && !clientSecret) {
      throw new ArkConfigError(
        'the client_credentials grant requires client authentication; a public client cannot use it. ' +
          'Register a confidential client (client_secret_basic or private_key_jwt) for service-to-service calls.'
      );
    }

    const id = clientId ?? this.#config.clientId;
    const scopeValue = [...scopes].join(' ');
    const key = `${this.#config.authority}|${id}|${scopeValue}`;

    const cached = this.#serviceTokens.get(key);
    if (!force && cached && !cached.expired(renewBeforeSeconds)) return cached;

    const metadata = await this.metadata();
    const response = await this.#tokenRequest(
      metadata.token_endpoint,
      { grant_type: 'client_credentials', ...(scopeValue ? { scope: scopeValue } : {}) },
      { clientId: id, clientSecret }
    );

    const tokens = new TokenSet(response);
    this.#serviceTokens.set(key, tokens);
    return tokens;
  }

  // =================================================================
  // Device authorization grant (RFC 8628)
  // =================================================================

  /** Step one of the device grant: ask for a code, then show the user `verification_uri_complete`. */
  async deviceAuthorization({ scopes } = {}) {
    const metadata = await this.metadata();
    const endpoint = metadata.device_authorization_endpoint;
    if (!endpoint) {
      throw new ArkOAuthError('unsupported_grant_type', 'this tenant does not serve the device authorization grant.', {
        endpoint: this.#config.authority
      });
    }

    const scopeValue = [...(scopes ?? this.#config.scopes)].join(' ');
    const { form, headers } = await this.#clientAuthentication({ scope: scopeValue }, endpoint);
    return postForm(endpoint, form, { headers, timeoutMs: this.#config.timeoutMs, fetch: this.#config.fetch });
  }

  /**
   * Step two: poll the token endpoint until the user approves on their other device.
   *
   * The two error codes that are not failures are handled here — `authorization_pending` means
   * keep waiting, and `slow_down` means the server wants a longer interval and will keep saying so
   * until it gets one (RFC 8628 §3.5). Everything else ends the wait.
   */
  async pollDeviceToken(deviceAuthorization, { signal, onPending, intervalSeconds, timeoutSeconds } = {}) {
    const metadata = await this.metadata();
    const deviceCode = deviceAuthorization.device_code ?? deviceAuthorization;
    let interval = (intervalSeconds ?? deviceAuthorization.interval ?? 5) * 1000;
    const deadline = Date.now() + (timeoutSeconds ?? deviceAuthorization.expires_in ?? 600) * 1000;

    for (;;) {
      if (signal?.aborted) throw new ArkOAuthError('access_denied', 'the device flow was cancelled.', { endpoint: metadata.token_endpoint });
      if (Date.now() >= deadline) {
        throw new ArkOAuthError('expired_token', 'the device code expired before the user approved it.', {
          endpoint: metadata.token_endpoint
        });
      }

      await new Promise((resolve) => {
        const timer = setTimeout(resolve, interval);
        signal?.addEventListener('abort', () => {
          clearTimeout(timer);
          resolve();
        }, { once: true });
      });

      try {
        const response = await this.#tokenRequest(metadata.token_endpoint, {
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code: deviceCode
        });
        return await this.#toTokenSet(response, { nonce: null });
      } catch (error) {
        if (!(error instanceof ArkOAuthError)) throw error;
        if (error.error === 'authorization_pending') {
          onPending?.(error);
          continue;
        }
        if (error.error === 'slow_down') {
          interval += 5000; // §3.5: add five seconds and keep going
          onPending?.(error);
          continue;
        }
        throw error;
      }
    }
  }

  // =================================================================
  // Pushed authorization requests (RFC 9126)
  // =================================================================

  async pushAuthorizationRequest(params) {
    const metadata = await this.metadata();
    const endpoint = metadata.pushed_authorization_request_endpoint;
    if (!endpoint) {
      throw new ArkOAuthError('invalid_request', 'this tenant does not serve pushed authorization requests.', {
        endpoint: this.#config.authority
      });
    }

    const body = Object.fromEntries(Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== ''));
    const { form, headers } = await this.#clientAuthentication(body, endpoint);
    return postForm(endpoint, form, { headers, timeoutMs: this.#config.timeoutMs, fetch: this.#config.fetch });
  }

  // =================================================================
  // Using and inspecting tokens
  // =================================================================

  /**
   * The UserInfo endpoint (OIDC Core §5.3).
   *
   * Returns only the claims the presented token was granted scope for. Worth calling when a claim
   * is needed that the ID token did not carry; not worth calling on every request, since the ID
   * token already holds what the scopes unlocked at sign-in.
   */
  async userInfo(accessToken) {
    const metadata = await this.metadata();
    if (!accessToken) throw new ArkConfigError('userInfo() needs an access token.');
    return getJson(metadata.userinfo_endpoint, {
      headers: { Authorization: `Bearer ${accessToken}` },
      timeoutMs: this.#config.timeoutMs,
      fetch: this.#config.fetch
    });
  }

  /**
   * Token introspection (RFC 7662). Requires client authentication, so a public client cannot use
   * it — which is deliberate on the server side: an unauthenticated introspection endpoint is an
   * oracle for testing captured tokens.
   *
   * For a JWT access token from this server, `verifyAccessToken` answers the same question locally
   * and without a network call; reach for introspection to learn whether a *refresh* token is
   * still live, or when the token is opaque.
   */
  async introspect(token, { tokenTypeHint } = {}) {
    const metadata = await this.metadata();
    const endpoint = metadata.introspection_endpoint;
    const { form, headers } = await this.#clientAuthentication(
      { token, ...(tokenTypeHint ? { token_type_hint: tokenTypeHint } : {}) },
      endpoint
    );
    return postForm(endpoint, form, { headers, timeoutMs: this.#config.timeoutMs, fetch: this.#config.fetch });
  }

  /**
   * Token revocation (RFC 7009). Revoking a refresh token takes down its whole rotation family, so
   * this is the call that really ends a session's access — sign-out should make it.
   *
   * An unknown token is a success (§2.2): the caller's goal is already met.
   */
  async revoke(token, { tokenTypeHint = 'refresh_token' } = {}) {
    const metadata = await this.metadata();
    const endpoint = metadata.revocation_endpoint;
    const { form, headers } = await this.#clientAuthentication(
      { token, ...(tokenTypeHint ? { token_type_hint: tokenTypeHint } : {}) },
      endpoint
    );
    await postForm(endpoint, form, { headers, timeoutMs: this.#config.timeoutMs, fetch: this.#config.fetch });
    return true;
  }

  /**
   * The RP-initiated logout URL.
   *
   * `idTokenHint` is what lets the provider know which session to end and which client asked, and
   * without it the `post_logout_redirect_uri` cannot be matched against a registration — so the
   * user is left on the provider's "signed out" page instead of coming back to the application.
   */
  async endSessionUrl({ idTokenHint, postLogoutRedirectUri, state, clientId } = {}) {
    const metadata = await this.metadata();
    const endpoint = metadata.end_session_endpoint;
    if (!endpoint) throw new ArkOAuthError('server_error', "the provider's metadata has no 'end_session_endpoint'.", { endpoint: this.#config.authority });

    const params = new URLSearchParams({ client_id: clientId ?? this.#config.clientId });
    if (idTokenHint) params.set('id_token_hint', idTokenHint);
    const target = postLogoutRedirectUri ?? this.#config.postLogoutRedirectUri;
    if (target) params.set('post_logout_redirect_uri', target);
    if (state) params.set('state', state);
    return `${endpoint}?${params}`;
  }

  /** Verifies an ID token against the provider's keys and the values from the sign-in transaction. */
  async verifyIdToken(idToken, { nonce = null, accessToken = null, code = null, maxAge = null } = {}) {
    const metadata = await this.metadata();
    const jwks = await this.jwks();
    return verifyJwt(idToken, jwks, {
      issuer: metadata.issuer,
      audience: this.#config.clientId,
      nonce,
      accessToken,
      code,
      maxAgeSeconds: maxAge,
      requireTokenHashes: this.#config.requireTokenHashes,
      requireIat: true,
      clockToleranceSeconds: this.#config.clockToleranceSeconds,
      algorithms: this.#config.idTokenSigningAlgorithms ?? undefined
    });
  }

  /**
   * Verifies an access token this server issued — the resource-server side of the library.
   *
   * Local verification against the cached JWKS, so protecting an API costs no network call per
   * request. `scopes` and `arkClaims` are checked here rather than left to the caller, because
   * "the token is valid" and "the token is allowed to do this" are different questions and only
   * the second one is the authorization decision.
   */
  async verifyAccessToken(token, { audience, scopes = [], arkClaims = [], requireTypeHeader = true } = {}) {
    const metadata = await this.metadata();
    const jwks = await this.jwks();

    const payload = await verifyJwt(token, jwks, {
      issuer: metadata.issuer,
      audience: audience ?? this.#config.audience ?? undefined,
      typ: requireTypeHeader ? 'at+jwt' : undefined,
      requireIat: true,
      clockToleranceSeconds: this.#config.clockToleranceSeconds
    });

    const granted = new Set(String(payload.scope ?? '').split(' ').filter(Boolean));
    const missingScopes = [...scopes].flat().filter((s) => !granted.has(s));
    if (missingScopes.length > 0) {
      throw new ArkOAuthError('insufficient_scope', `the token is missing the scope(s): ${missingScopes.join(', ')}.`, { status: 403 });
    }

    const held = new Set(Array.isArray(payload.ark_claims) ? payload.ark_claims : payload.ark_claims ? [payload.ark_claims] : []);
    const missingClaims = [...arkClaims].flat().filter((c) => !held.has(c));
    if (missingClaims.length > 0) {
      throw new ArkOAuthError('insufficient_scope', `the token is missing the authorization claim(s): ${missingClaims.join(', ')}.`, { status: 403 });
    }

    return payload;
  }

  // =================================================================
  // Dynamic client registration (RFC 7591 / 7592)
  // =================================================================

  /**
   * Registers a client. Off by default on the server, and when on it wants an initial access token
   * carrying the `client.register` scope — which itself comes from the client credentials grant,
   * so registration is a two-step chain rather than an open endpoint.
   *
   * The response carries `client_secret` exactly once; it is stored only as a hash and cannot be
   * read back afterwards.
   */
  async registerClient(clientMetadata, initialAccessToken) {
    const metadata = await this.metadata();
    const endpoint = metadata.registration_endpoint;
    if (!endpoint) {
      throw new ArkOAuthError('registration_not_supported', 'this tenant does not serve dynamic client registration.', {
        endpoint: this.#config.authority
      });
    }
    const { body } = await request(endpoint, {
      method: 'POST',
      json: clientMetadata,
      headers: initialAccessToken ? { Authorization: `Bearer ${initialAccessToken}` } : {},
      timeoutMs: this.#config.timeoutMs,
      fetch: this.#config.fetch
    });
    return body;
  }

  /** Reads a registration back (RFC 7592 §2.1), using the registration access token from creation. */
  async readRegistration(clientId, registrationAccessToken) {
    const metadata = await this.metadata();
    return getJson(`${metadata.registration_endpoint}/${encodeURIComponent(clientId)}`, {
      headers: { Authorization: `Bearer ${registrationAccessToken}` },
      timeoutMs: this.#config.timeoutMs,
      fetch: this.#config.fetch
    });
  }

  /** Deletes a registration (RFC 7592 §2.3). */
  async deleteRegistration(clientId, registrationAccessToken) {
    const metadata = await this.metadata();
    await request(`${metadata.registration_endpoint}/${encodeURIComponent(clientId)}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${registrationAccessToken}` },
      timeoutMs: this.#config.timeoutMs,
      fetch: this.#config.fetch
    });
    return true;
  }

  // =================================================================
  // Diagnostics
  // =================================================================

  /**
   * Pairs this application's configuration with the provider's live metadata and reports what does
   * not line up.
   *
   * The same idea as `ArkSetupProbe` in the .NET client, and it earns its place for the same
   * reason: without it, the first symptom of a wrong port, a stopped provider, a missing tenant id
   * or a scope the client was never registered for is `invalid_request` on a page the user is
   * looking at. Render this on a health or setup page and the mistake reads as a sentence.
   */
  async checkSetup({ origin } = {}) {
    const config = this.#config;
    const report = {
      authority: config.authority,
      clientId: config.clientId,
      isConfidential: config.tokenEndpointAuthMethod !== 'none',
      tokenEndpointAuthMethod: config.tokenEndpointAuthMethod,
      scopes: [...config.scopes],
      redirectUri: config.redirectUri ?? (origin ? `${origin.replace(/\/+$/, '')}/signin-oidc` : null),
      postLogoutRedirectUri: config.postLogoutRedirectUri,
      discoveryUrl: `${config.authority}/.well-known/openid-configuration`,
      discoveryOk: false,
      discoveryError: null,
      provider: null,
      problems: []
    };

    let metadata;
    try {
      metadata = await this.metadata({ force: true });
      report.discoveryOk = true;
    } catch (error) {
      report.discoveryError = error.message;
      report.problems.push(`The provider's discovery document could not be read: ${error.message}`);
      return report;
    }

    report.provider = {
      issuer: metadata.issuer,
      authorizationEndpoint: metadata.authorization_endpoint,
      tokenEndpoint: metadata.token_endpoint,
      userInfoEndpoint: metadata.userinfo_endpoint,
      jwksUri: metadata.jwks_uri,
      endSessionEndpoint: metadata.end_session_endpoint,
      deviceAuthorizationEndpoint: metadata.device_authorization_endpoint ?? null,
      pushedAuthorizationRequestEndpoint: metadata.pushed_authorization_request_endpoint ?? null,
      registrationEndpoint: metadata.registration_endpoint ?? null,
      scopesSupported: metadata.scopes_supported ?? [],
      grantTypesSupported: metadata.grant_types_supported ?? [],
      codeChallengeMethodsSupported: metadata.code_challenge_methods_supported ?? [],
      responseModesSupported: metadata.response_modes_supported ?? [],
      tokenEndpointAuthMethodsSupported: metadata.token_endpoint_auth_methods_supported ?? [],
      requirePushedAuthorizationRequests: metadata.require_pushed_authorization_requests === true
    };

    try {
      const keys = await (await this.jwks()).keys({ force: true });
      report.signingKeys = keys.map((k) => ({ kid: k.kid, kty: k.kty, alg: k.alg ?? null, use: k.use ?? null }));
    } catch (error) {
      report.problems.push(`The provider's signing keys could not be read: ${error.message}`);
    }

    const supported = new Set(metadata.scopes_supported ?? []);
    const unknown = supported.size > 0 ? config.scopes.filter((s) => !supported.has(s)) : [];
    if (unknown.length > 0) {
      report.problems.push(
        `The tenant does not publish the scope(s) ${unknown.join(', ')}. A scope this client is not registered for is rejected outright, not dropped.`
      );
    }

    if (!(metadata.code_challenge_methods_supported ?? []).includes('S256')) {
      report.problems.push('The tenant does not advertise the S256 PKCE method, which this client always sends.');
    }

    const methods = metadata.token_endpoint_auth_methods_supported ?? [];
    if (methods.length > 0 && !methods.includes(config.tokenEndpointAuthMethod)) {
      report.problems.push(
        `This client authenticates with '${config.tokenEndpointAuthMethod}', which the tenant does not list (${methods.join(', ')}).`
      );
    }

    if (config.usePar && !metadata.pushed_authorization_request_endpoint) {
      report.problems.push('usePar is on, but the tenant does not serve /oauth2/par.');
    }
    if (metadata.require_pushed_authorization_requests === true && !config.usePar) {
      report.problems.push('The tenant requires pushed authorization requests; set usePar:true or plain /authorize calls will be refused.');
    }

    if (!report.redirectUri) {
      report.problems.push('No redirectUri is configured, so an interactive sign-in cannot be started.');
    }

    return report;
  }

  // =================================================================
  // internals
  // =================================================================

  /** POSTs to the token endpoint with whatever client authentication this client is registered for. */
  async #tokenRequest(endpoint, body, credentials) {
    const { form, headers } = await this.#clientAuthentication(body, endpoint, credentials);
    return postForm(endpoint, form, { headers, timeoutMs: this.#config.timeoutMs, fetch: this.#config.fetch });
  }

  /**
   * Applies the client's registered authentication method.
   *
   * RFC 6749 §2.3 forbids presenting more than one set of credentials in a single request and the
   * Ark server rejects rather than resolves that, so exactly one of these branches may contribute
   * a credential. `client_id` in the body is not a credential and always goes along: the `none`
   * method needs it, and with Basic the server reads the header regardless.
   */
  async #clientAuthentication(body, endpoint, credentials = {}) {
    const config = this.#config;
    const clientId = credentials.clientId ?? config.clientId;
    const clientSecret = credentials.clientSecret ?? config.clientSecret;
    const method = credentials.clientSecret && config.tokenEndpointAuthMethod === 'none' ? 'client_secret_basic' : config.tokenEndpointAuthMethod;

    const form = { ...body, client_id: clientId };
    const headers = {};

    switch (method) {
      case 'client_secret_basic':
        headers.Authorization = basicAuthHeader(clientId, clientSecret);
        break;
      case 'client_secret_post':
        form.client_secret = clientSecret;
        break;
      case 'private_key_jwt': {
        form.client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
        form.client_assertion = this.#clientAssertion(clientId, endpoint);
        break;
      }
      case 'none':
      default:
        break;
    }

    return { form, headers };
  }

  /**
   * A `private_key_jwt` client assertion (OIDC Core §9).
   *
   * `jti` is random and the lifetime is short because the server refuses a `jti` it has already
   * seen — a captured assertion is worth nothing on its second use.
   */
  #clientAssertion(clientId, endpoint) {
    const { privateKey, kid, alg = 'RS256', lifetimeSeconds = 60 } = this.#config.privateKeyJwt ?? {};
    const now = Math.floor(Date.now() / 1000);
    return signJwt(
      {
        iss: clientId,
        sub: clientId, // §9: both must be the client id
        aud: endpoint,
        jti: randomToken(16),
        iat: now,
        nbf: now,
        exp: now + lifetimeSeconds
      },
      { key: privateKey, alg, kid }
    );
  }

  /** Turns a token response into a TokenSet, validating the ID token when there is one. */
  async #toTokenSet(response, { nonce, code = null, maxAge = null }) {
    let claims = null;

    if (response.id_token) {
      claims = await this.verifyIdToken(response.id_token, {
        nonce,
        accessToken: response.access_token ?? null,
        code,
        maxAge
      });
    } else if (nonce !== null && this.#requestedOpenId(response)) {
      // openid was granted but nothing came back to prove who signed in.
      throw new ArkTokenError('the token response contains no id_token, although the openid scope was granted.');
    }

    return new TokenSet(response, { claims });
  }

  #requestedOpenId(response) {
    return String(response.scope ?? '')
      .split(' ')
      .includes('openid');
  }
}

/** Convenience factory, for callers who prefer not to write `new`. */
export function createArkClient(options) {
  return new ArkOAuthClient(options);
}
