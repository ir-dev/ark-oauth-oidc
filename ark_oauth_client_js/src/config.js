import { ArkConfigError } from './errors.js';
import { normalizeAccountSwitch } from './access.js';

/**
 * Normalises and checks what the application configured.
 *
 * Everything that can be caught without the network is caught here, when the client is created,
 * because the alternative is finding out from a user's failed sign-in. A client secret shipped to
 * a browser, an authority that is really a base URL with the tenant id missing, a redirect URI with
 * a fragment: each produces an `invalid_request` page later and an afternoon of reading server
 * logs, or one sentence here.
 *
 * Nothing in here touches `window`, so a client can be created during server-side rendering
 * (Next.js, Nuxt, Angular SSR). Relative URIs are resolved against the page's origin later, in the
 * browser.
 */

export const DEFAULT_SCOPES = Object.freeze(['openid', 'profile', 'email', 'offline_access']);
export const DEFAULT_REDIRECT_PATH = '/signin-oidc';
export const DEFAULT_POST_LOGOUT_PATH = '/signout-callback-oidc';

function isLoopback(url) {
  return ['localhost', '127.0.0.1', '[::1]', '::1'].includes(url.hostname);
}

function parseAbsolute(value, setting) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new ArkConfigError(`ark_oauth_client: '${setting}' must be an absolute URL, but is '${value}'.`);
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new ArkConfigError(`ark_oauth_client: '${setting}' must be an http or https URL, but is '${value}'.`);
  }
  return url;
}

/**
 * A redirect target: an absolute URL, or a path starting with `/` that is resolved against the
 * page's origin at runtime. The server matches redirect URIs byte for byte, so what is registered
 * must be exactly what this resolves to.
 */
function checkRedirect(value, setting) {
  if (value === null || value === undefined || value === '') return null;
  const text = String(value);
  if (text.startsWith('/') && !text.startsWith('//')) {
    if (text.includes('#')) throw new ArkConfigError(`ark_oauth_client: '${setting}' must not contain a fragment: ${text}`);
    return text;
  }
  const url = parseAbsolute(text, setting);
  if (url.hash) throw new ArkConfigError(`ark_oauth_client: '${setting}' must not contain a fragment: ${text}`);
  if (url.protocol !== 'https:' && !isLoopback(url)) {
    throw new ArkConfigError(`ark_oauth_client: '${setting}' is ${text}. The server accepts http only for loopback addresses (RFC 8252 §7.3).`);
  }
  return text;
}

function normalizeOrigins(list) {
  return Object.freeze(
    [...(list ?? [])].map((value) => {
      if (value === '*') {
        throw new ArkConfigError("ark_oauth_client: 'apiOrigins' cannot be '*'. List the exact origins the access token may be sent to.");
      }
      return parseAbsolute(String(value), 'apiOrigins').origin;
    })
  );
}

export function normalizeConfig(options = {}) {
  const {
    authority,
    authServerUrl,
    tenantId,
    clientId,
    clientSecret,
    privateKeyJwt,
    tokenEndpointAuthMethod,
    usePar,
    redirectUri = DEFAULT_REDIRECT_PATH,
    postLogoutRedirectUri = DEFAULT_POST_LOGOUT_PATH,
    scopes,
    responseMode = 'query',
    prompt = null,
    acrValues = null,
    extraAuthorizationParams = null,
    storage = 'session',
    automaticRefresh = true,
    refreshBeforeSeconds = 60,
    apiOrigins = [],
    syncTabs = true,
    accountSwitch,
    onEvaluateAccess = null,
    onRedirectCallback = null,
    navigate = null,
    redirect = null,
    popup = {},
    transactionTtlSeconds = 600,
    clockToleranceSeconds = 60,
    requireHttps = true,
    requireTokenHashes = true,
    idTokenSigningAlgorithms = null,
    timeoutMs = 10_000,
    metadataTtlMs = 5 * 60_000,
    jwksTtlMs = 5 * 60_000,
    jwksMinRefreshIntervalMs = 10_000,
    fetch: fetchImpl = undefined
  } = options;

  // The .NET client accepts AuthServerUrl + TenantId as well as Authority, so the values already in
  // an appsettings.json or a .env can be used as they are.
  let resolvedAuthority = String(authority ?? '').trim();
  if (!resolvedAuthority && authServerUrl && tenantId) resolvedAuthority = `${String(authServerUrl).replace(/\/+$/, '')}/${tenantId}`;
  if (!resolvedAuthority) {
    throw new ArkConfigError(
      "ark_oauth_client: set 'authority' to the issuer URL of your Ark tenant, {BaseUrl}/{TenantId}, e.g. " +
        'https://idp.example.com/my_idp. (Or set authServerUrl + tenantId and they are joined for you.)'
    );
  }
  resolvedAuthority = resolvedAuthority.replace(/\/+$/, '');
  const authorityUrl = parseAbsolute(resolvedAuthority, 'authority');
  if (requireHttps && authorityUrl.protocol !== 'https:' && !isLoopback(authorityUrl)) {
    throw new ArkConfigError(
      `ark_oauth_client: 'authority' is ${resolvedAuthority}, which is plain http. Tokens would cross the network in the clear. ` +
        'Use https, or set requireHttps:false, only ever for local development.'
    );
  }

  if (!clientId || typeof clientId !== 'string') {
    throw new ArkConfigError("ark_oauth_client: 'clientId' is required: the client id registered with the tenant.");
  }

  // Everything shipped to a browser is public. A secret in a bundle is a secret on every visitor's
  // disk, and the server cannot tell the app from anyone who copied it. Register the SPA as a
  // public client (token_endpoint_auth_method "none"); keep confidential clients on a server.
  if (clientSecret || privateKeyJwt || (tokenEndpointAuthMethod && tokenEndpointAuthMethod !== 'none')) {
    throw new ArkConfigError(
      'ark_oauth_client: a browser app cannot keep a client secret or a private key: anything in the bundle is readable by ' +
        "every visitor. Register this app as a public client (token endpoint auth method 'none'; PKCE protects the code), " +
        'or keep the confidential client on a server with ark-oauth-client (Node), ark-oauth-client (Python) or Ark.oAuth.Client (.NET).'
    );
  }

  // The pushed authorization request endpoint needs client authentication and grants no CORS, so a
  // browser cannot use it. Said now rather than as a failed preflight later.
  if (usePar) {
    throw new ArkConfigError(
      "ark_oauth_client: 'usePar' is not available in a browser app: /oauth2/par needs client authentication and serves no CORS. " +
        'Leave PAR to a server-side client.'
    );
  }

  if (!['query', 'fragment'].includes(responseMode)) {
    throw new ArkConfigError(
      `ark_oauth_client: 'responseMode' is '${responseMode}'. A browser app reads the response from its own URL, so use 'query' or 'fragment'` +
        (responseMode === 'form_post' ? '; form_post POSTs to a server, which a single-page app does not have.' : '.')
    );
  }

  if (!Number.isFinite(refreshBeforeSeconds) || refreshBeforeSeconds < 0) {
    throw new ArkConfigError(`ark_oauth_client: 'refreshBeforeSeconds' must be a number of seconds, not '${refreshBeforeSeconds}'.`);
  }

  return Object.freeze({
    authority: resolvedAuthority,
    clientId,
    redirectUri: checkRedirect(redirectUri, 'redirectUri') ?? DEFAULT_REDIRECT_PATH,
    postLogoutRedirectUri: checkRedirect(postLogoutRedirectUri, 'postLogoutRedirectUri'),
    scopes: Object.freeze(scopes?.length ? [...scopes] : [...DEFAULT_SCOPES]),
    responseMode,
    prompt,
    acrValues,
    extraAuthorizationParams: extraAuthorizationParams ? Object.freeze({ ...extraAuthorizationParams }) : null,
    storage,
    automaticRefresh: Boolean(automaticRefresh),
    refreshBeforeSeconds,
    apiOrigins: normalizeOrigins(apiOrigins),
    syncTabs: Boolean(syncTabs),
    accountSwitch: normalizeAccountSwitch(accountSwitch),
    onEvaluateAccess,
    onRedirectCallback,
    navigate,
    redirect,
    popup: Object.freeze({ width: 520, height: 680, timeoutMs: 5 * 60_000, ...popup }),
    transactionTtlSeconds,
    clockToleranceSeconds,
    requireHttps,
    requireTokenHashes,
    idTokenSigningAlgorithms: idTokenSigningAlgorithms ? Object.freeze([...idTokenSigningAlgorithms]) : null,
    timeoutMs,
    metadataTtlMs,
    jwksTtlMs,
    jwksMinRefreshIntervalMs,
    fetch: fetchImpl
  });
}
