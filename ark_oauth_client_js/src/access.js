import { ArkConfigError } from './errors.js';

/**
 * Account switching on a shared browser.
 *
 * Single sign-on is browser-wide: once one person signs in anywhere, the provider's session answers
 * every other app's sign-in in that browser. The next person opens this app, is signed in as the
 * previous one, and is told they have no access, for an account that is not even theirs. Signing in
 * again goes back to the same provider session and gives the same answer.
 *
 * Breaking that loop needs two things: a dead end that is honest about whose session it is, and a
 * sign-in that sends `prompt=login`, the one parameter a provider must honour by ignoring its
 * session and drawing the sign-in form (OIDC Core §3.1.2.1).
 *
 * The same feature, under the same names, as `AccountSwitch` in the .NET client, `account_switch`
 * in Python and `accountSwitch` in Node. Off by default, as there.
 */

export const ArkAccessDeniedReasons = Object.freeze({
  /** The provider authenticated them, but they hold no authorization claims for this client. */
  NO_APP_ACCESS: 'no_app_access',
  /** They are signed in, but a guard refused the page they asked for. */
  FORBIDDEN: 'forbidden'
});

export const ACCOUNT_SWITCH_DEFAULTS = Object.freeze({
  /**
   * Refuse the sign-in when the access token carries no `ark_claims` for this client. Off, the wrong
   * account is signed in and every guarded view says "forbidden". On, the callback stops before any
   * token is stored and the state becomes `denied`, from where the user can switch.
   *
   * Ark issues the user's whole claim mapping as `ark_claims`, identity names like `email`
   * included, so this check alone admits a user with an identity-only mapping. Name the claims
   * that mean "may use this app" in `requiredClaims`.
   */
  requireArkClaims: false,
  /** Narrow that check: at least one of these. Empty means any `ark_claims` will do. */
  requiredClaims: Object.freeze([]),
  /** Where to send the browser after a refused sign-in. Null stays on the page the user asked for. */
  accessDeniedPath: null,
  /** Sent as `prompt` when switching. `login` is the one every provider honours. */
  prompt: 'login',
  /**
   * Make switching a full RP-initiated logout first. Off, only this app's tokens are dropped and
   * the previous user's other apps are left alone; on, they are signed out everywhere (right for a
   * kiosk, heavy-handed for a laptop).
   */
  endProviderSessionOnSwitch: false,
  /** The app's name on the built-in page. Defaults to the client id. */
  appDisplayName: null,
  /** Name the refused account on the page. On a shared browser it is somebody else's address. */
  showSignedInAccount: true,
  /** Offer "Sign out completely" beside "Sign in as a different user". */
  allowFullSignOut: true,
  /** Where "Sign out completely" lands, and the fallback for an absent or off-site return URL. */
  homePath: '/',
  supportUrl: null,
  supportEmail: null
});

/**
 * Keeps a return URL inside this app. Echoing an arbitrary one would make sign-in an open redirect:
 * a phishing link that keeps your domain in the address bar until it hands the user to somebody else.
 */
export function localOrDefault(url, fallback = '/') {
  const home = typeof fallback === 'string' && fallback.trim() ? fallback : fallback === null ? null : '/';
  if (typeof url !== 'string' || !url.trim()) return home;
  const candidate = url.trim();
  if (!candidate.startsWith('/') || candidate.startsWith('//')) return home;
  // Browsers read `\` as `/`, so `/\evil.example` is `//evil.example`, another host. They also
  // strip tabs and newlines before parsing, so `/\t/evil.example` collapses to the same thing.
  if (candidate.startsWith('/\\')) return home;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(candidate)) return home;
  return candidate;
}

/** Fills in the defaults and refuses what could only fail later, in front of a user. */
export function normalizeAccountSwitch(options = {}) {
  const merged = { ...ACCOUNT_SWITCH_DEFAULTS };
  for (const [key, value] of Object.entries(options ?? {})) {
    if (Object.prototype.hasOwnProperty.call(ACCOUNT_SWITCH_DEFAULTS, key) && value !== undefined) merged[key] = value;
  }
  for (const key of ['accessDeniedPath', 'homePath']) {
    if (merged[key] !== null && localOrDefault(merged[key], null) !== merged[key]) {
      throw new ArkConfigError(`ark_oauth_client: accountSwitch.${key} must be a local path starting with '/', but is '${merged[key]}'.`);
    }
  }
  if (merged.supportUrl && !/^https?:\/\//i.test(merged.supportUrl)) {
    throw new ArkConfigError(`ark_oauth_client: accountSwitch.supportUrl must be an http(s) URL, but is '${merged.supportUrl}'.`);
  }
  merged.requiredClaims = Object.freeze([...(merged.requiredClaims ?? [])].map(String));
  return Object.freeze(merged);
}

/**
 * The sign-in options that make "sign in as a different user" work. Without `prompt=login` the
 * provider answers from the session it already has, and the wrong person is signed in again.
 * The result is what `signinRedirect()` and `signinPopup()` accept.
 */
export const ArkChallengeProperties = Object.freeze({
  switchUser(returnTo = null, loginHint = null, prompt = 'login') {
    return { returnTo: returnTo || '/', prompt: prompt || 'login', ...(loginHint ? { loginHint } : {}) };
  },

  /** The provider's account picker. A provider without one falls back to its sign-in form. */
  selectAccount(returnTo = null) {
    return ArkChallengeProperties.switchUser(returnTo, null, 'select_account');
  }
});

/**
 * The entitlement decision, made once per sign-in at the callback: not "may this user open that
 * view" but "may this user use this app at all". Refusing there means no token is ever stored.
 *
 * `onEvaluateAccess` replaces the configured rule rather than being ANDed with it; a handler that
 * wants both reads `allowedByConfiguration` and says so.
 */
export async function evaluateAccess(options, onEvaluateAccess, { claims = {}, arkClaims = [], tokens = null } = {}) {
  const required = options.requiredClaims.map((c) => c.toLowerCase());
  const allowedByConfiguration =
    !options.requireArkClaims || (required.length ? arkClaims.some((c) => required.includes(String(c).toLowerCase())) : arkClaims.length > 0);
  if (typeof onEvaluateAccess !== 'function') return allowedByConfiguration;
  return Boolean(await onEvaluateAccess({ claims: { ...claims }, arkClaims: [...arkClaims], allowedByConfiguration, tokens }));
}

/** What is known about a refused account, read off whatever identity there is. */
export function describeDenial(reason, claims, arkClaims, returnTo) {
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
    returnTo: returnTo ?? null
  };
}
