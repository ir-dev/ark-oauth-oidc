import { ArkNetworkError, ArkOAuthError } from './errors.js';

/**
 * The HTTP layer: the one place that knows how the server answers and how a browser fails.
 *
 * Every non-2xx response becomes an ArkOAuthError carrying the server's own `error` code. Every
 * request has a timeout. And because a browser reports a CORS refusal, a DNS failure and a dead
 * server as the same bare `TypeError`, a failed fetch is turned into a message that names the
 * likeliest cause (the app's origin missing from the provider's `CorsOrigins`) and how to fix it.
 */

const DEFAULT_TIMEOUT_MS = 10_000;

function timeoutSignal(signal, timeoutMs) {
  let timeout;
  if (typeof AbortSignal.timeout === 'function') {
    timeout = AbortSignal.timeout(timeoutMs);
  } else {
    const controller = new AbortController();
    setTimeout(() => controller.abort(new DOMException('The operation timed out.', 'TimeoutError')), timeoutMs);
    timeout = controller.signal;
  }
  if (!signal) return timeout;
  if (typeof AbortSignal.any === 'function') return AbortSignal.any([signal, timeout]);
  const controller = new AbortController();
  const forward = (source) => () => controller.abort(source.reason);
  if (signal.aborted) controller.abort(signal.reason);
  signal.addEventListener('abort', forward(signal), { once: true });
  timeout.addEventListener('abort', forward(timeout), { once: true });
  return controller.signal;
}

async function readBody(response) {
  const text = await response.text();
  if (!text) return null;
  const type = response.headers.get('content-type') ?? '';
  const trimmed = text.trimStart();
  if (type.includes('json') || trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }
  return text;
}

function currentOrigin() {
  try {
    return globalThis.location?.origin ?? null;
  } catch {
    return null;
  }
}

/** The explanation attached to a fetch that failed without a response. */
export function describeFetchFailure(method, url, cause, timeoutMs) {
  const timedOut = cause?.name === 'TimeoutError' || cause?.cause?.name === 'TimeoutError';
  if (timedOut) return `${method} ${url} timed out after ${timeoutMs}ms.`;
  if (cause?.name === 'AbortError') return `${method} ${url} was aborted.`;
  const origin = currentOrigin();
  return (
    `${method} ${url} failed: ${cause?.message ?? cause}. In a browser this is most often CORS: the provider must list ` +
    `this app's origin${origin && origin !== 'null' ? ` (${origin})` : ''} in ark_oauth_server:Oidc:CorsOrigins ` +
    '(the Protocol step of the setup wizard). Otherwise the provider is unreachable from here: wrong host or port, offline, or stopped.'
  );
}

/**
 * Performs one request and returns `{ status, body, headers }`.
 *
 * @param {string} url
 * @param {object} [options]
 * @param {'GET'|'POST'} [options.method]
 * @param {Record<string, string|undefined|null>} [options.form] form-urlencoded body; empty entries dropped
 * @param {Record<string, string>} [options.headers]
 * @param {RequestCache} [options.cache] GETs of metadata and keys honour the server's Cache-Control
 * @param {number} [options.timeoutMs]
 * @param {AbortSignal} [options.signal]
 * @param {typeof fetch} [options.fetch]
 */
export async function request(url, options = {}) {
  const {
    method = 'GET',
    form,
    headers = {},
    cache,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    signal,
    fetch: fetchImpl = globalThis.fetch
  } = options;

  if (typeof fetchImpl !== 'function') {
    throw new ArkNetworkError('no fetch implementation is available; pass `fetch` in the client options.');
  }

  const init = {
    method,
    headers: { Accept: 'application/json', ...headers },
    signal: timeoutSignal(signal, timeoutMs),
    // Token and userinfo responses are never cached: a cached userinfo keyed on a bearer token is
    // a different user's tomorrow. Discovery and JWKS pass `default` to reuse the server's max-age.
    cache: cache ?? 'no-store',
    // The provider grants CORS without credentials, and nothing here should ever carry the
    // provider's session cookie: a bearer token in a header is the whole of the authentication.
    credentials: 'omit',
    // A GET of metadata or keys may follow a redirect (http to https is common), and the issuer
    // check on the document is what establishes trust. A POST carries a code or a refresh token,
    // and a redirect would forward it somewhere else.
    redirect: method === 'GET' ? 'follow' : 'manual'
  };

  if (form) {
    const body = new URLSearchParams();
    for (const [key, value] of Object.entries(form)) {
      if (value === undefined || value === null || value === '') continue;
      body.set(key, String(value));
    }
    init.body = body;
    init.headers['Content-Type'] = 'application/x-www-form-urlencoded';
  }

  let response;
  try {
    response = await fetchImpl(url, init);
  } catch (cause) {
    throw new ArkNetworkError(describeFetchFailure(method, url, cause, timeoutMs), { cause });
  }

  if (response.type === 'opaqueredirect' || (response.status >= 300 && response.status < 400)) {
    throw new ArkOAuthError('server_error', `${method} ${url} answered with a redirect, which is not followed for a token request.`, {
      status: response.status,
      endpoint: url
    });
  }

  const body = await readBody(response);
  if (!response.ok) throw ArkOAuthError.fromResponse(response.status, body, url);
  return { status: response.status, body, headers: response.headers };
}

/** GET returning a JSON object. */
export async function getJson(url, options) {
  const { body } = await request(url, { ...options, method: 'GET' });
  if (!body || typeof body !== 'object') {
    throw new ArkOAuthError('server_error', `${url} did not return a JSON object.`, { endpoint: url, body });
  }
  return body;
}

/** POST a form, returning the JSON response. */
export async function postForm(url, form, options) {
  const { body, status } = await request(url, { ...options, method: 'POST', form });
  if (body === null) return {};
  if (typeof body !== 'object') {
    throw new ArkOAuthError('server_error', `${url} returned HTTP ${status} with a non-JSON body.`, { endpoint: url, status, body });
  }
  return body;
}

/**
 * POST a form without reading the answer: `mode: 'no-cors'`.
 *
 * For token revocation. The Ark server grants CORS on the token, userinfo, discovery and JWKS
 * endpoints, but not on `/revoke`, so a normal fetch from a page is delivered and then refused at
 * the response. A form-urlencoded POST with no custom header is a CORS-safelisted request, so in
 * `no-cors` mode it is delivered just the same, and the browser hands back an opaque response
 * rather than an error. Revocation answers 200 whether or not the token existed (RFC 7009 §2.2),
 * so there is nothing in the response worth reading anyway: resolving means it was delivered.
 */
export async function postFormNoCors(url, form, { timeoutMs = DEFAULT_TIMEOUT_MS, fetch: fetchImpl = globalThis.fetch } = {}) {
  const body = new URLSearchParams();
  for (const [key, value] of Object.entries(form)) {
    if (value !== undefined && value !== null && value !== '') body.set(key, String(value));
  }
  try {
    await fetchImpl(url, {
      method: 'POST',
      mode: 'no-cors',
      credentials: 'omit',
      cache: 'no-store',
      // Survives the page navigating away, which is exactly what a sign-out does next.
      keepalive: true,
      body,
      signal: timeoutSignal(undefined, timeoutMs)
    });
  } catch (cause) {
    throw new ArkNetworkError(describeFetchFailure('POST', url, cause, timeoutMs), { cause });
  }
}
