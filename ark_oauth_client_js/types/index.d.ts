// Type definitions for ark-oauth-client-js (the browser client for Ark.oAuth.Oidc).

export const VERSION: string;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** A Web Storage-like object, for a custom (e.g. encrypted or native) token store. */
export interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
  key?(index: number): string | null;
  readonly length?: number;
}

export interface AccountSwitchOptions {
  /** Refuse a sign-in whose access token carries no `ark_claims` for this client. Default false. */
  requireArkClaims?: boolean;
  /** Narrow that check: at least one of these. Ark puts identity names (email, sub) in ark_claims too, so name the real ones. */
  requiredClaims?: string[];
  /** Where to go after a refused sign-in; null (default) stays on the page asked for, with state `denied`. */
  accessDeniedPath?: string | null;
  /** The `prompt` sent when switching. Default 'login'. */
  prompt?: string;
  /** Make switching a full provider logout first. Default false. */
  endProviderSessionOnSwitch?: boolean;
  appDisplayName?: string | null;
  showSignedInAccount?: boolean;
  allowFullSignOut?: boolean;
  homePath?: string;
  supportUrl?: string | null;
  supportEmail?: string | null;
}

export interface EvaluateAccessContext {
  claims: Record<string, unknown>;
  arkClaims: string[];
  allowedByConfiguration: boolean;
  tokens: TokenSet;
}

export interface RedirectCallbackResult {
  returnTo: string | null;
  user: IdTokenClaims | null;
  denied: boolean;
  relayed?: boolean;
  signedOut?: boolean;
}

export interface ArkClientOptions {
  /** The issuer: `{BaseUrl}/{TenantId}`, e.g. https://idp.example.com/my_idp. */
  authority?: string;
  /** With tenantId, an alternative to `authority` (the .NET client's two settings). */
  authServerUrl?: string;
  tenantId?: string;
  /** The client id registered with the tenant, as a public client (auth method 'none'). */
  clientId: string;
  /** A path on this origin or an absolute URL; must match a registered redirect URI byte for byte. Default '/signin-oidc'. */
  redirectUri?: string;
  /** Default '/signout-callback-oidc'. Must be registered as a post-logout redirect URI. Null to omit. */
  postLogoutRedirectUri?: string | null;
  /** Default ['openid', 'profile', 'email', 'offline_access']. offline_access is what produces a refresh token. */
  scopes?: string[];
  responseMode?: 'query' | 'fragment';
  prompt?: string | null;
  acrValues?: string | null;
  extraAuthorizationParams?: Record<string, string> | null;
  /** Where tokens live between page loads. Default 'session'. */
  storage?: 'session' | 'local' | 'memory' | StorageLike;
  /** Refresh before expiry with the refresh token. Default true. */
  automaticRefresh?: boolean;
  /** How early to refresh. Default 60. */
  refreshBeforeSeconds?: number;
  /** Origins besides the app's own that `fetch()` and the interceptors may send the access token to. */
  apiOrigins?: string[];
  /** Sign-out and token sync across tabs over BroadcastChannel. Default true. */
  syncTabs?: boolean;
  accountSwitch?: AccountSwitchOptions;
  /** Replaces the configured access rule at the callback. */
  onEvaluateAccess?: ((context: EvaluateAccessContext) => boolean | Promise<boolean>) | null;
  /** Where to send the user after a sign-in completes. Default: history.replaceState + popstate. */
  onRedirectCallback?: ((returnTo: string, result: RedirectCallbackResult) => unknown) | null;
  /** In-app navigation used when there is no onRedirectCallback. */
  navigate?: ((to: string) => unknown) | null;
  /** How to leave for the provider. Default: location.assign. */
  redirect?: ((url: string) => unknown) | null;
  popup?: { width?: number; height?: number; timeoutMs?: number };
  transactionTtlSeconds?: number;
  clockToleranceSeconds?: number;
  /** Refuse a plain-http authority (loopback excepted). Default true. */
  requireHttps?: boolean;
  requireTokenHashes?: boolean;
  idTokenSigningAlgorithms?: string[] | null;
  timeoutMs?: number;
  metadataTtlMs?: number;
  jwksTtlMs?: number;
  jwksMinRefreshIntervalMs?: number;
  fetch?: typeof fetch;
  /** The window to use; defaults to the global one. `null` behaves as on the server. */
  window?: Window | null;
}

export interface NormalizedConfig {
  readonly authority: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly postLogoutRedirectUri: string | null;
  readonly scopes: readonly string[];
  readonly responseMode: 'query' | 'fragment';
  readonly storage: ArkClientOptions['storage'];
  readonly automaticRefresh: boolean;
  readonly refreshBeforeSeconds: number;
  readonly apiOrigins: readonly string[];
  readonly accountSwitch: Readonly<Required<AccountSwitchOptions>>;
  readonly [key: string]: unknown;
}

export function normalizeConfig(options: ArkClientOptions): NormalizedConfig;
export const DEFAULT_SCOPES: readonly string[];
export const DEFAULT_REDIRECT_PATH: '/signin-oidc';
export const DEFAULT_POST_LOGOUT_PATH: '/signout-callback-oidc';

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

export interface IdTokenClaims {
  sub: string;
  iss: string;
  aud: string | string[];
  exp: number;
  iat: number;
  auth_time?: number;
  nonce?: string;
  sid?: string;
  name?: string;
  email?: string;
  email_verified?: boolean;
  preferred_username?: string;
  [claim: string]: unknown;
}

export interface ArkDenial {
  reason: 'no_app_access' | 'forbidden';
  subject: string | null;
  email: string | null;
  name: string | null;
  arkClaims: readonly string[];
  returnTo: string | null;
}

export type ArkStatus = 'loading' | 'authenticated' | 'unauthenticated' | 'denied';

/** The authentication state. Immutable; a new object on every change. */
export interface ArkSnapshot {
  readonly status: ArkStatus;
  readonly isLoading: boolean;
  readonly isAuthenticated: boolean;
  readonly user: Readonly<IdTokenClaims> | null;
  readonly arkClaims: readonly string[];
  readonly scopes: readonly string[];
  /** Access token expiry, epoch seconds. */
  readonly expiresAt: number | null;
  readonly error: ArkError | null;
  readonly denial: ArkDenial | null;
}

export const INITIAL_SNAPSHOT: ArkSnapshot;

export interface ArkEvents {
  signedIn: { user: IdTokenClaims | null; returnTo: string };
  signedOut: { reason: 'signout' | 'expired' };
  tokensRefreshed: { expiresAt: number | null };
  refreshFailed: { error: unknown };
  sessionExpired: { reason: 'expired' | 'refresh_refused'; error?: unknown };
  accessDenied: ArkDenial;
  error: unknown;
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

export interface SigninOptions {
  /** A local path to return to; defaults to the current page. Off-site values are ignored. */
  returnTo?: string;
  prompt?: 'login' | 'none' | 'consent' | 'select_account' | (string & {});
  loginHint?: string;
  scopes?: string[];
  maxAge?: number;
  acrValues?: string;
  responseMode?: 'query' | 'fragment';
  redirectUri?: string;
  /** Extra authorization parameters; they cannot replace state, nonce or PKCE. */
  extra?: Record<string, string>;
}

export interface PopupSigninOptions extends SigninOptions {
  /** A window you opened yourself, synchronously, in the click handler. */
  popupWindow?: Window;
}

export interface SigninResult {
  returnTo: string;
  user: IdTokenClaims | null;
  denied: boolean;
}

export interface SignoutOptions {
  returnTo?: string;
  postLogoutRedirectUri?: string;
  /** Revoke the refresh token. Default true. */
  revoke?: boolean;
}

export interface AuthorizationTransaction {
  state: string;
  nonce: string | null;
  codeVerifier: string;
  redirectUri: string;
  responseMode: 'query' | 'fragment';
  scope: string;
  maxAge: number | null;
  returnTo: string;
  createdAt: number;
}

export interface SetupReport {
  authority: string;
  clientId: string;
  tenantId: string;
  origin: string | null;
  secureContext: boolean;
  webCrypto: boolean;
  storage: string;
  scopes: string[];
  responseMode: string;
  redirectUri: string;
  postLogoutRedirectUri: string | null;
  adminConsoleUrl: string;
  integrationPageUrl: string;
  discoveryUrl: string;
  discoveryOk: boolean;
  jwksOk: boolean;
  /** null when not reached; false means the token endpoint does not answer this origin (CORS). */
  tokenEndpointCorsOk: boolean | null;
  provider: Record<string, unknown> | null;
  signingKeys: Array<{ kid: string | null; kty: string; alg: string | null; use: string | null }>;
  problems: string[];
}

/** A Svelte-compatible readable store. */
export interface Readable<T> {
  subscribe(run: (value: T) => void): () => void;
}

export class ArkBrowserClient {
  constructor(options: ArkClientOptions);
  readonly config: NormalizedConfig;
  readonly authority: string;
  readonly clientId: string;
  /** False during server-side rendering (no window). */
  readonly isBrowser: boolean;

  /** The current state; the same object until it changes. Bound: safe to pass detached. */
  getSnapshot(): ArkSnapshot;
  /** Always the `loading` state: for SSR and hydration. */
  getServerSnapshot(): ArkSnapshot;
  /** Bound: safe to pass detached (useSyncExternalStore). */
  subscribe(listener: (snapshot: ArkSnapshot) => void): () => void;
  /** Svelte store: `$client.state` (calls the listener immediately). */
  readonly state: Readable<ArkSnapshot>;
  getUser(): Readonly<IdTokenClaims> | null;
  on<E extends keyof ArkEvents>(event: E, handler: (detail: ArkEvents[E]) => void): () => void;
  hasArkClaims(...claims: Array<string | string[]>): boolean;
  hasAnyArkClaim(...claims: Array<string | string[]>): boolean;
  hasScopes(...scopes: Array<string | string[]>): boolean;

  /** Completes a callback or restores the session. Idempotent; never rejects. */
  init(options?: { handleCallback?: boolean; onRedirectCallback?: (returnTo: string, result: RedirectCallbackResult) => unknown }): Promise<ArkSnapshot>;
  createAuthorizationUrl(options?: SigninOptions): Promise<{ url: string; transaction: AuthorizationTransaction }>;
  signinRedirect(options?: SigninOptions): Promise<void>;
  signinPopup(options?: PopupSigninOptions): Promise<SigninResult>;
  isSigninCallback(url?: string | URL): boolean;
  handleRedirectCallback(url?: string | URL): Promise<RedirectCallbackResult>;

  /** Bound. Null when nobody is signed in or the session cannot be renewed. Read it per call. */
  getAccessToken(options?: { forceRefresh?: boolean }): Promise<string | null>;
  refresh(): Promise<TokenSet>;
  isApiUrl(url: string | URL): boolean;
  /** Bound. fetch with the access token, for the app's origin and apiOrigins only. */
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
  userInfo(): Promise<Record<string, unknown>>;

  signoutRedirect(options?: SignoutOptions): Promise<void>;
  signoutLocal(options?: { revoke?: boolean }): Promise<void>;
  switchUser(options?: { returnTo?: string; loginHint?: string }): Promise<void>;
  clearDenial(): void;

  metadata(options?: { force?: boolean }): Promise<Record<string, any>>;
  jwks(): Promise<JwksCache>;
  verifyIdToken(
    idToken: string,
    options?: { nonce?: string | null; accessToken?: string | null; code?: string | null; maxAge?: number | null; subject?: string | null }
  ): Promise<IdTokenClaims>;
  checkSetup(): Promise<SetupReport>;
  destroy(): void;
}

export function createArkClient(options: ArkClientOptions): ArkBrowserClient;

export class TokenSet {
  constructor(response?: Record<string, unknown>, options?: { issuedAt?: number; claims?: IdTokenClaims | null });
  accessToken: string | null;
  tokenType: string;
  refreshToken: string | null;
  idToken: string | null;
  scope: string | null;
  issuedAt: number;
  expiresAt: number | null;
  claims: IdTokenClaims | null;
  expiresIn(now?: number): number | null;
  expired(leewaySeconds?: number, now?: number): boolean;
  scopes(): string[];
  hasScope(...wanted: Array<string | string[]>): boolean;
  arkClaims(): string[];
  accessTokenClaims(): Record<string, unknown> | null;
  readonly subject: string | null;
  authorizationHeader(): string;
  toJSON(): Record<string, unknown>;
  static fromJSON(data: unknown): TokenSet | null;
}

export class MemoryStorage implements StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
  key(index: number): string | null;
  readonly length: number;
  clear(): void;
}

/** Renders the built-in access-denied card; returns a function that removes it. */
export function renderAccessDenied(container: Element, client: ArkBrowserClient, options?: { unstyled?: boolean; appName?: string }): () => void;

// ---------------------------------------------------------------------------
// Account switching
// ---------------------------------------------------------------------------

export const ArkAccessDeniedReasons: { readonly NO_APP_ACCESS: 'no_app_access'; readonly FORBIDDEN: 'forbidden' };
export const ACCOUNT_SWITCH_DEFAULTS: Readonly<Required<AccountSwitchOptions>>;
export function normalizeAccountSwitch(options?: AccountSwitchOptions): Readonly<Required<AccountSwitchOptions>>;
export const ArkChallengeProperties: {
  switchUser(returnTo?: string | null, loginHint?: string | null, prompt?: string): SigninOptions;
  selectAccount(returnTo?: string | null): SigninOptions;
};
export function localOrDefault(url: unknown, fallback?: string | null): string | null;

// ---------------------------------------------------------------------------
// Lower level
// ---------------------------------------------------------------------------

export class MetadataResolver {
  constructor(authority: string, options?: { ttlMs?: number; timeoutMs?: number; fetch?: typeof fetch });
  get(force?: boolean): Promise<Record<string, any>>;
  clear(): void;
}
export function discoveryUrls(authority: string): [string, string];

export class JwksCache {
  constructor(jwksUri: string, options?: { ttlMs?: number; minRefreshIntervalMs?: number; timeoutMs?: number; fetch?: typeof fetch });
  readonly uri: string;
  keys(options?: { force?: boolean }): Promise<Array<Record<string, any>>>;
  getSigningKey(kid: string | undefined, alg: string): Promise<{ jwk: Record<string, any>; key: CryptoKey }>;
  clear(): void;
}

export function createCodeVerifier(): string;
export function codeChallengeFor(verifier: string): Promise<string>;
export function createPkcePair(): Promise<{ codeVerifier: string; codeChallenge: string; codeChallengeMethod: 'S256' }>;
export function createState(): string;
export function createNonce(): string;

export interface DecodedJwt {
  header: Record<string, any>;
  payload: Record<string, any>;
  signature: Uint8Array;
  signingInput: string;
}
export function decodeJwt(token: string): DecodedJwt;
export function verifySignature(decoded: DecodedJwt, jwk: Record<string, any>, options?: { algorithms?: readonly string[]; key?: CryptoKey }): Promise<true>;
export function validateClaims(payload: Record<string, any>, options?: Record<string, unknown>): Record<string, any>;
export function validateTokenHashes(
  payload: Record<string, any>,
  options?: { alg?: string; accessToken?: string; code?: string; require?: boolean }
): Promise<Record<string, any>>;
export function verifyJwt(token: string, jwks: Pick<JwksCache, 'getSigningKey'>, options?: Record<string, unknown>): Promise<Record<string, any>>;
export const SUPPORTED_ALGORITHMS: readonly string[];
export function base64UrlEncode(input: Uint8Array | ArrayBuffer | string): string;
export function base64UrlDecode(value: string): Uint8Array;
export function randomToken(bytes?: number): string;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class ArkError extends Error {}
export class ArkConfigError extends ArkError {}
export class ArkOAuthError extends ArkError {
  constructor(error: string, description?: string | null, options?: { status?: number; endpoint?: string | null; errorUri?: string | null; body?: unknown });
  readonly error: string;
  readonly errorDescription: string | null;
  readonly errorUri: string | null;
  readonly status: number;
  readonly endpoint: string | null;
  readonly body: unknown;
  static fromResponse(status: number, body: unknown, endpoint: string): ArkOAuthError;
}
export class ArkTokenError extends ArkError {
  readonly claim: string | null;
}
export class ArkCallbackError extends ArkError {}
export class ArkNetworkError extends ArkError {}
export class ArkLoginRequiredError extends ArkError {
  readonly error: 'login_required';
}
export class ArkPopupError extends ArkError {
  readonly reason: 'blocked' | 'closed' | 'timeout';
}
