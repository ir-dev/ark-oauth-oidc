import { ArkConfigError } from './errors.js';

/**
 * Normalises and checks what the application configured.
 *
 * Everything that can be caught without talking to the network is caught here, at construction,
 * because the alternative is finding out from a user's failed sign-in. A redirect_uri with a
 * fragment, an authority that is really a base URL with the tenant id missing, `private_key_jwt`
 * with no key: all of those produce an `invalid_request` page hours later and half a day of
 * reading server logs, or one sentence here.
 */

const DEFAULT_SCOPES = ['openid', 'profile', 'email', 'offline_access'];

const AUTH_METHODS = new Set(['client_secret_basic', 'client_secret_post', 'private_key_jwt', 'none']);

function isLoopback(url) {
  return ['localhost', '127.0.0.1', '::1', '[::1]'].includes(url.hostname);
}

function requireAbsoluteUrl(value, setting) {
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

export function normalizeConfig(options = {}) {
  const {
    authority,
    authServerUrl,
    tenantId,
    clientId,
    clientSecret = null,
    tokenEndpointAuthMethod,
    privateKeyJwt = null,
    redirectUri = null,
    postLogoutRedirectUri = null,
    scopes,
    audience = null,
    responseMode = 'query',
    usePar = false,
    prompt = null,
    acrValues = null,
    extraAuthorizationParams = null,
    clockToleranceSeconds = 60,
    requireHttps = true,
    requireTokenHashes = true,
    idTokenSigningAlgorithms = null,
    timeoutMs = 10_000,
    metadataTtlMs = 5 * 60_000,
    jwksTtlMs = 5 * 60_000,
    jwksMinRefreshIntervalMs = 10_000,
    fetch: fetchImpl = undefined,
    roleClaim = 'role'
  } = options;

  // The .NET client accepts AuthServerUrl + TenantId as well as Authority; the same two-part form
  // is honoured here so a Node app can be configured from the values already in appsettings.json.
  let resolvedAuthority = (authority ?? '').trim();
  if (!resolvedAuthority && authServerUrl && tenantId) {
    resolvedAuthority = `${String(authServerUrl).replace(/\/+$/, '')}/${tenantId}`;
  }
  if (!resolvedAuthority) {
    throw new ArkConfigError(
      "ark_oauth_client: set 'authority' to the issuer URL of your Ark tenant — {BaseUrl}/{TenantId}, " +
        'e.g. https://idp.example.com/my_idp. (Or set authServerUrl + tenantId and it will be joined for you.)'
    );
  }
  resolvedAuthority = resolvedAuthority.replace(/\/+$/, '');
  const authorityUrl = requireAbsoluteUrl(resolvedAuthority, 'authority');
  if (requireHttps && authorityUrl.protocol !== 'https:' && !isLoopback(authorityUrl)) {
    throw new ArkConfigError(
      `ark_oauth_client: 'authority' is ${resolvedAuthority}, which is plain http. Tokens would cross the network in the clear. ` +
        'Use https, or set requireHttps:false — only ever for local development.'
    );
  }

  if (!clientId || typeof clientId !== 'string') {
    throw new ArkConfigError("ark_oauth_client: 'clientId' is required — the client id registered with the tenant.");
  }

  let method = tokenEndpointAuthMethod;
  if (!method) {
    // Match what the server expects by default: a client with a secret authenticates with it, a
    // public client (SPA, native, CLI) has nothing to present and says so.
    method = privateKeyJwt ? 'private_key_jwt' : clientSecret ? 'client_secret_basic' : 'none';
  }
  if (!AUTH_METHODS.has(method)) {
    throw new ArkConfigError(
      `ark_oauth_client: 'tokenEndpointAuthMethod' is '${method}'; the server supports ${[...AUTH_METHODS].join(', ')}.`
    );
  }
  if ((method === 'client_secret_basic' || method === 'client_secret_post') && !clientSecret) {
    throw new ArkConfigError(`ark_oauth_client: '${method}' needs a 'clientSecret'.`);
  }
  if (method === 'private_key_jwt' && !privateKeyJwt?.privateKey) {
    throw new ArkConfigError(
      "ark_oauth_client: 'private_key_jwt' needs privateKeyJwt.privateKey (a PEM string, a JWK, or a node:crypto KeyObject) " +
        'and the matching public key published at the jwks_uri registered for this client.'
    );
  }
  if (method === 'none' && clientSecret) {
    throw new ArkConfigError(
      "ark_oauth_client: a 'clientSecret' was given but tokenEndpointAuthMethod is 'none'. The server matches the registered " +
        'method exactly, so pick the one this client is registered for.'
    );
  }

  let redirect = null;
  if (redirectUri) {
    const url = requireAbsoluteUrl(redirectUri, 'redirectUri');
    // The server validates all three of these at registration and matches the value exactly at
    // /authorize, so a mismatch here can never be recovered from at runtime.
    if (url.hash) throw new ArkConfigError(`ark_oauth_client: 'redirectUri' must not contain a fragment: ${redirectUri}`);
    if (url.protocol !== 'https:' && !isLoopback(url)) {
      throw new ArkConfigError(
        `ark_oauth_client: 'redirectUri' is ${redirectUri}. The server accepts http only for loopback addresses (RFC 8252 §7.3).`
      );
    }
    redirect = url.toString();
  }

  if (postLogoutRedirectUri) requireAbsoluteUrl(postLogoutRedirectUri, 'postLogoutRedirectUri');

  if (!['query', 'fragment', 'form_post'].includes(responseMode)) {
    throw new ArkConfigError(`ark_oauth_client: 'responseMode' is '${responseMode}'; the server supports query, fragment and form_post.`);
  }

  return Object.freeze({
    authority: resolvedAuthority,
    clientId,
    clientSecret,
    tokenEndpointAuthMethod: method,
    privateKeyJwt: privateKeyJwt ? Object.freeze({ alg: 'RS256', ...privateKeyJwt }) : null,
    redirectUri: redirect,
    postLogoutRedirectUri,
    scopes: Object.freeze(scopes?.length ? [...scopes] : [...DEFAULT_SCOPES]),
    audience,
    responseMode,
    usePar,
    prompt,
    acrValues,
    extraAuthorizationParams: extraAuthorizationParams ? Object.freeze({ ...extraAuthorizationParams }) : null,
    clockToleranceSeconds,
    requireHttps,
    requireTokenHashes,
    idTokenSigningAlgorithms: idTokenSigningAlgorithms ? Object.freeze([...idTokenSigningAlgorithms]) : null,
    timeoutMs,
    metadataTtlMs,
    jwksTtlMs,
    jwksMinRefreshIntervalMs,
    fetch: fetchImpl,
    roleClaim
  });
}

export { DEFAULT_SCOPES };
