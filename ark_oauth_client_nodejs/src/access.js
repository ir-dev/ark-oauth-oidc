import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';
import { base64UrlDecode, base64UrlEncode } from './crypto.js';
import { ArkConfigError } from './errors.js';

/**
 * Account switching on a shared browser, and the page that makes it recoverable.
 *
 * Single sign-on is browser-wide: once one person signs in anywhere, the provider's session answers
 * the authorize request of every other client in that browser. A second person opens this
 * application, is silently signed in as the first, and is told they have no access — for an account
 * that is not even theirs. The sign-in link goes back to the same session and gives the same answer,
 * so the loop only ends when somebody knows to clear cookies.
 *
 * Breaking it needs two things, and both live here: a dead end that is honest about whose session
 * it is, and a challenge that says `prompt=login` — the one parameter a provider must honour by
 * ignoring its session and drawing the sign-in form (OIDC Core §3.1.2.1).
 *
 * The same feature, under the same names, as `AccountSwitch` in the .NET client and
 * `account_switch` in the Python one. Every part is off or unchanged by default.
 */

/** Why a user was sent to the access-denied page. */
export const ArkAccessDeniedReasons = Object.freeze({
  /** The provider authenticated them, but they hold no authorization claims for this client. */
  NO_APP_ACCESS: 'no_app_access',
  /** They are signed in here, but a guard refused the page they asked for. */
  FORBIDDEN: 'forbidden'
});

export const ACCOUNT_SWITCH_DEFAULTS = Object.freeze({
  /** Serve the three endpoints below, and send an HTML 403 to the page rather than a JSON body. */
  enabled: true,
  /**
   * Refuse the sign-in when the provider issues no `ark_claims` for this client. Off, the wrong
   * account is signed in and every guarded page answers 403. On, the callback is stopped before the
   * session is written and the user is sent to `accessDeniedPath`, where they can switch.
   */
  requireArkClaims: false,
  /** Narrow that check: at least one of these claim values. Empty means any `ark_claims` will do. */
  requiredClaims: Object.freeze([]),
  accessDeniedPath: '/ark/no-access',
  switchUserPath: '/ark/switch-user',
  signOutPath: '/ark/sign-out',
  /** Draw the built-in page. Turn off when `accessDeniedPath` is a route of your own. */
  serveDefaultPage: true,
  /** The application's name as users know it. Defaults to the client id. */
  appDisplayName: null,
  /** Name the signed-in account on the page — on a shared browser, somebody else's address. */
  showSignedInAccount: true,
  /** Offer "Sign out completely" beside "Sign in as a different user". */
  allowFullSignOut: true,
  /**
   * Make switching a full RP-initiated logout. Off, only this application's session is dropped and
   * the previous user's other tabs are left alone; on, they are signed out of everything — right for
   * a kiosk, heavy-handed for a laptop.
   */
  endProviderSessionOnSwitch: false,
  /** Sent as `prompt` when switching. `login` is the one every provider honours. */
  prompt: 'login',
  /** "Back to safety", and the fallback for an absent or off-site return URL. */
  homePath: '/',
  supportUrl: null,
  supportEmail: null
});

const PATH_SETTINGS = ['accessDeniedPath', 'switchUserPath', 'signOutPath', 'homePath'];

/** Fills in the defaults and refuses what could only fail later, in front of a user. */
export function normalizeAccountSwitch(options = {}) {
  const merged = { ...ACCOUNT_SWITCH_DEFAULTS };
  for (const [key, value] of Object.entries(options ?? {})) {
    if (Object.hasOwn(ACCOUNT_SWITCH_DEFAULTS, key) && value !== undefined) merged[key] = value;
  }

  for (const key of PATH_SETTINGS) {
    if (localOrDefault(merged[key], null) !== merged[key]) {
      throw new ArkConfigError(`ark_oauth_client: accountSwitch.${key} must be a local path starting with '/', but is '${merged[key]}'.`);
    }
  }
  // Rendered into an href: anything but http(s) would be a script URL waiting to be clicked.
  if (merged.supportUrl && !/^https?:\/\//i.test(merged.supportUrl)) {
    throw new ArkConfigError(`ark_oauth_client: accountSwitch.supportUrl must be an http(s) URL, but is '${merged.supportUrl}'.`);
  }

  merged.requiredClaims = Object.freeze([...(merged.requiredClaims ?? [])].map(String));
  return Object.freeze(merged);
}

/**
 * The authorization-request options that make "sign in as a different user" work. Without
 * `prompt=login` the provider answers from the session it already has, and the wrong person is
 * signed in again. The result is what `req.ark.login()` and `createAuthorizationUrl()` accept.
 */
export const ArkChallengeProperties = Object.freeze({
  switchUser(returnUrl = null, loginHint = null, prompt = 'login') {
    return { returnTo: returnUrl || '/', prompt: prompt || 'login', ...(loginHint ? { loginHint } : {}) };
  },

  /** The provider's account picker. A provider without one falls back to its sign-in form. */
  selectAccount(returnUrl = null) {
    return ArkChallengeProperties.switchUser(returnUrl, null, 'select_account');
  }
});

/**
 * Keeps a return URL inside this application. Echoing an arbitrary one would make the login route
 * and the access-denied page open redirects — a phishing link that keeps your domain in the address
 * bar right up to the moment it hands the user to somebody else.
 */
export function localOrDefault(url, fallback = '/') {
  const home = typeof fallback === 'string' && fallback.trim() ? fallback : fallback === null ? null : '/';
  if (typeof url !== 'string' || !url.trim()) return home;
  const candidate = url.trim();
  if (!candidate.startsWith('/') || candidate.startsWith('//')) return home;
  // Browsers read `\` as `/`, so `/\evil.example` is `//evil.example` — another host. They also
  // strip tabs and newlines before parsing, so `/\t/evil.example` collapses to the same thing.
  if (candidate.startsWith('/\\')) return home;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(candidate)) return home;
  return candidate;
}

/**
 * POST, from this origin. Neither account endpoint is a security boundary — the worst a forged
 * request achieves is an unwanted sign-out — but a cross-site page should not be able to end a
 * user's session, and requiring a same-origin POST costs nothing.
 */
export function checkSameOrigin(method, headers, origin) {
  if (String(method).toUpperCase() !== 'POST') return { ok: false, status: 405, message: 'POST required.' };

  const fetchSite = headers?.['sec-fetch-site'];
  if (fetchSite) {
    return fetchSite === 'same-origin' || fetchSite === 'none'
      ? { ok: true }
      : { ok: false, status: 400, message: 'cross-site request rejected.' };
  }

  const from = headers?.origin;
  if (!from) return { ok: true }; // not a browser form post
  const same = from.replace(/\/+$/, '').toLowerCase() === String(origin).replace(/\/+$/, '').toLowerCase();
  return same ? { ok: true } : { ok: false, status: 400, message: 'cross-site request rejected.' };
}

/**
 * The entitlement decision, made once per sign-in at the callback — not "may this user open that
 * page" but "may this user use this application at all". Refusing there means no session is ever
 * written, so the person at the keyboard is not left holding somebody else's.
 *
 * `onEvaluateAccess` replaces the configured rule rather than being ANDed with it; a handler that
 * wants both reads `allowedByConfiguration` and says so.
 */
export async function evaluateAccess(options, events, { claims = {}, arkClaims = [], tokens = null } = {}) {
  const required = options.requiredClaims.map((c) => c.toLowerCase());
  const allowedByConfiguration =
    !options.requireArkClaims ||
    (required.length ? arkClaims.some((c) => required.includes(String(c).toLowerCase())) : arkClaims.length > 0);

  if (!events?.onEvaluateAccess) return allowedByConfiguration;
  return Boolean(
    await events.onEvaluateAccess({ claims: { ...claims }, arkClaims: [...arkClaims], allowedByConfiguration, tokens })
  );
}

/** What is known about a denial, read off whatever identity there is. */
export function describeDenial(reason, claims, arkClaims, returnUrl) {
  const first = (...names) => {
    for (const name of names) if (claims?.[name]) return String(claims[name]);
    return null;
  };
  return {
    reason,
    subject: first('sub'),
    email: first('email', 'preferred_username'),
    name: first('name'),
    arkClaims: [...(arkClaims ?? [])],
    returnUrl: returnUrl ?? null,
    /** Set from `onAccessDenied` when the handler has written the response itself. */
    handled: false
  };
}

export function deniedUrl(options, returnUrl) {
  const path = options.accessDeniedPath;
  if (!returnUrl) return path;
  return `${path}${path.includes('?') ? '&' : '?'}returnUrl=${encodeURIComponent(returnUrl)}`;
}

// ---------------------------------------------------------------------------
// The denial cookie
// ---------------------------------------------------------------------------

/**
 * Carries the refused identity from the callback to the page. The denial happens before any session
 * is written — that is the point — so a short-lived cookie names the account instead: AES-256-GCM
 * under a key derived from the session secret for this one purpose, so the browser cannot read it,
 * tampering is detected rather than parsed, and it cannot be replayed as anything else. The format
 * and key derivation are the Python client's, byte for byte.
 */
export const DENIED_COOKIE = 'ark_denied';
export const DENIED_MAX_AGE_SECONDS = 300;
const PURPOSE = Buffer.from('Ark.oAuth.Client.AccessDenied.v1', 'utf8');

function deniedKey(secret) {
  return Buffer.from(hkdfSync('sha256', Buffer.from(String(secret), 'utf8'), Buffer.alloc(0), PURPOSE, 32));
}

export function protectState(secret, payload) {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', deniedKey(secret), nonce, { authTagLength: 16 });
  cipher.setAAD(PURPOSE);
  const body = Buffer.from(JSON.stringify({ ...payload, _iat: Math.floor(Date.now() / 1000) }), 'utf8');
  return base64UrlEncode(Buffer.concat([nonce, cipher.update(body), cipher.final(), cipher.getAuthTag()]));
}

/** The payload, or null when the value is tampered, from another key, or older than `maxAgeSeconds`. */
export function unprotectState(secret, value, maxAgeSeconds = DENIED_MAX_AGE_SECONDS) {
  let payload;
  try {
    const raw = base64UrlDecode(String(value));
    if (raw.length < 12 + 16) return null;
    const decipher = createDecipheriv('aes-256-gcm', deniedKey(secret), raw.subarray(0, 12), { authTagLength: 16 });
    decipher.setAAD(PURPOSE);
    decipher.setAuthTag(raw.subarray(raw.length - 16));
    payload = JSON.parse(Buffer.concat([decipher.update(raw.subarray(12, raw.length - 16)), decipher.final()]).toString('utf8'));
  } catch {
    // Tampered, or sealed by a secret this instance no longer holds. The page falls back to the
    // unnamed wording rather than failing.
    return null;
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
  const { _iat: issued, ...rest } = payload;
  if (maxAgeSeconds && (typeof issued !== 'number' || Date.now() / 1000 - issued > maxAgeSeconds)) return null;
  return rest;
}
