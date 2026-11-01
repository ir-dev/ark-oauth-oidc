import { ArkNetworkError, ArkOAuthError } from './errors.js';

/**
 * The HTTP layer: one place that knows how this server answers, so nothing above it has to.
 *
 * Two rules are worth stating because the rest of the library depends on them. Every non-2xx
 * response is turned into an ArkOAuthError carrying the server's own `error` code — the Ark
 * server never answers a protocol failure with HTTP 200 and a message in the body, so there is no
 * "success that is really an error" case to unpick. And every request is bounded by a timeout,
 * because a token endpoint that accepts a connection and then stops talking would otherwise hang
 * a request thread until the client gives up, which it never does.
 */

const DEFAULT_TIMEOUT_MS = 10_000;

/** Merges the caller's abort signal with our own timeout, on whichever Node version is running. */
function withTimeout(signal, timeoutMs) {
  const timeout = AbortSignal.timeout(timeoutMs);
  if (!signal) return timeout;
  if (typeof AbortSignal.any === 'function') return AbortSignal.any([signal, timeout]);

  // Node 20.0–20.2 has no AbortSignal.any; forward the first abort by hand.
  const controller = new AbortController();
  const abort = (reason) => controller.abort(reason);
  if (signal.aborted) abort(signal.reason);
  else signal.addEventListener('abort', () => abort(signal.reason), { once: true });
  timeout.addEventListener('abort', () => abort(timeout.reason), { once: true });
  return controller.signal;
}

async function readBody(response) {
  const text = await response.text();
  if (!text) return null;
  const type = response.headers.get('content-type') ?? '';
  if (type.includes('json') || text.trimStart().startsWith('{') || text.trimStart().startsWith('[')) {
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }
  return text;
}

/**
 * Performs one request and returns the parsed body.
 *
 * @param {string} url
 * @param {object} [options]
 * @param {'GET'|'POST'|'DELETE'} [options.method]
 * @param {Record<string,string|undefined|null>} [options.form] form-urlencoded body; null/undefined entries are dropped
 * @param {object} [options.json] JSON body
 * @param {Record<string,string>} [options.headers]
 * @param {number} [options.timeoutMs]
 * @param {AbortSignal} [options.signal]
 * @param {typeof fetch} [options.fetch]
 */
export async function request(url, options = {}) {
  const {
    method = 'GET',
    form,
    json,
    headers = {},
    timeoutMs = DEFAULT_TIMEOUT_MS,
    signal,
    fetch: fetchImpl = globalThis.fetch
  } = options;

  if (typeof fetchImpl !== 'function') {
    throw new ArkNetworkError(
      'no fetch implementation is available. Node 20 or newer provides one globally; otherwise pass `fetch` in the client options.'
    );
  }

  const init = {
    method,
    headers: { Accept: 'application/json', ...headers },
    signal: withTimeout(signal, timeoutMs),
    // A token response must never be cached, and neither must a userinfo response keyed on a
    // bearer token that will be a different user's tomorrow.
    cache: 'no-store',
    // A GET of metadata or keys may follow a redirect — an http-to-https hop is common, and the
    // issuer check on the document is what actually establishes trust. A POST may not: it carries
    // a client secret or an authorization code, and a redirect would forward them somewhere else.
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
  } else if (json !== undefined) {
    init.body = JSON.stringify(json);
    init.headers['Content-Type'] = 'application/json';
  }

  let response;
  try {
    response = await fetchImpl(url, init);
  } catch (cause) {
    const timedOut = cause?.name === 'TimeoutError' || cause?.cause?.name === 'TimeoutError';
    throw new ArkNetworkError(
      timedOut ? `${method} ${url} timed out after ${timeoutMs}ms.` : `${method} ${url} failed: ${cause?.message ?? cause}`,
      { cause }
    );
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

/** POST a form-urlencoded body, returning the JSON response. */
export async function postForm(url, form, options) {
  const { body, status } = await request(url, { ...options, method: 'POST', form });
  // Revocation answers 200 with an empty body (RFC 7009 §2.2) — that is a success, not a shape error.
  if (body === null) return {};
  if (typeof body !== 'object') {
    throw new ArkOAuthError('server_error', `${url} returned HTTP ${status} with a non-JSON body.`, {
      endpoint: url,
      status,
      body
    });
  }
  return body;
}

/**
 * The `Authorization: Basic` value for `client_secret_basic`.
 *
 * RFC 6749 §2.3.1 requires both halves to be form-urlencoded *before* they are joined and
 * base64'd, which matters the moment a generated client secret contains a `+` or a `:`. The Ark
 * server URL-decodes both halves on the way in, so a client that skips the encoding authenticates
 * fine until the day it is issued a secret with a reserved character in it.
 */
export function basicAuthHeader(clientId, clientSecret) {
  const encode = (value) => encodeURIComponent(value).replace(/%20/g, '+');
  const raw = `${encode(clientId)}:${encode(clientSecret ?? '')}`;
  return `Basic ${Buffer.from(raw, 'utf8').toString('base64')}`;
}
