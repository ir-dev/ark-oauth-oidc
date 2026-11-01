/**
 * Type declarations for ark-oauth-client.
 *
 * Hand-written rather than generated, so the documentation an editor shows is the documentation
 * the source carries. Everything below mirrors src/ exactly; when one changes, so does the other.
 */

// =====================================================================
// errors
// =====================================================================

export class ArkError extends Error {}
export class ArkConfigError extends ArkError {}
export class ArkNetworkError extends ArkError {}
export class ArkCallbackError extends ArkError {}

export class ArkTokenError extends ArkError {
  /** The claim that failed validation, when one claim is to blame. */
  claim: string | null;
  token: string | null;
}

export class ArkOAuthError extends ArkError {
  /** The RFC 6749 §5.2 code: `invalid_grant`, `invalid_client`, `slow_down`, … */
  error: string;
  errorDescription: string | null;
  errorUri: string | null;
  /** The HTTP status the error arrived with. */
  status: number;
  /** The URL that produced it. */
  endpoint: string | null;
  body: unknown;
  static fromResponse(status: number, body: unknown, endpoint: string): ArkOAuthError;
}

// =====================================================================
// configuration
// =====================================================================

export type TokenEndpointAuthMethod = 'client_secret_basic' | 'client_secret_post' | 'private_key_jwt' | 'none';
export type ResponseMode = 'query' | 'fragment' | 'form_post';

export interface PrivateKeyJwtOptions {
  /** A PEM string, a JWK object, or a node:crypto KeyObject. */
  privateKey: unknown;
  /** Published in the assertion header so the server can pick the right key from your JWKS. */
  kid?: string;
  alg?: string;
  lifetimeSeconds?: number;
}

export interface ArkClientOptions {
  /** The issuer URL of the tenant: `{BaseUrl}/{TenantId}`. The only value that is really required. */
  authority?: string;
  /** Alternative to `authority`, matching the .NET client's configuration shape. */
  authServerUrl?: string;
  tenantId?: string;

  clientId: string;
  /** Omit for public clients (SPA, native, CLI). */
  clientSecret?: string | null;
  /** Derived from what you configure: `none`, `client_secret_basic` or `private_key_jwt`. */
  tokenEndpointAuthMethod?: TokenEndpointAuthMethod;
  privateKeyJwt?: PrivateKeyJwtOptions | null;

  /** Absolute, no fragment, https unless loopback — the server matches it exactly. */
  redirectUri?: string;
  postLogoutRedirectUri?: string;
  /** Defaults to openid, profile, email, offline_access. */
  scopes?: string[];
  /** Expected `aud` when verifying access tokens in an API. */
  audience?: string | null;

  responseMode?: ResponseMode;
  /** Send authorization parameters over the back channel (RFC 9126). */
  usePar?: boolean;
  prompt?: string | null;
  acrValues?: string | null;
  extraAuthorizationParams?: Record<string, string> | null;

  clockToleranceSeconds?: number;
  /** Only ever false for local development against a plain-http provider. */
  requireHttps?: boolean;
  /** Require at_hash/c_hash on ID tokens. On by default; Ark always sends them. */
  requireTokenHashes?: boolean;
  idTokenSigningAlgorithms?: string[] | null;

  timeoutMs?: number;
  metadataTtlMs?: number;
  jwksTtlMs?: number;
  /** How long before an unknown `kid` may trigger another JWKS fetch. Default 10s. */
  jwksMinRefreshIntervalMs?: number;
  fetch?: typeof fetch;
  roleClaim?: string;
}

export type ArkResolvedConfig = Readonly<Required<Pick<ArkClientOptions, 'clientId'>> & Record<string, unknown>> & {
  authority: string;
  clientId: string;
  clientSecret: string | null;
  tokenEndpointAuthMethod: TokenEndpointAuthMethod;
  redirectUri: string | null;
  postLogoutRedirectUri: string | null;
  scopes: readonly string[];
};

export function normalizeConfig(options: ArkClientOptions): ArkResolvedConfig;
export const DEFAULT_SCOPES: readonly string[];

// =====================================================================
// tokens
// =====================================================================

export interface TokenResponse {
  access_token?: string;
  token_type?: string;
  expires_in?: number;
  expires_at?: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
  [key: string]: unknown;
}

export class TokenSet {
  constructor(response?: TokenResponse, options?: { issuedAt?: number; claims?: Record<string, any> | null });
  accessToken: string | null;
  tokenType: string;
  refreshToken: string | null;
  idToken: string | null;
  scope: string | null;
  issuedAt: number;
  /** Absolute expiry in epoch seconds — computed on arrival, so it survives a session store. */
  expiresAt: number | null;
  /** Validated ID token claims. Null for a client credentials token. */
  claims: Record<string, any> | null;
  raw: TokenResponse;

  expiresIn(now?: number): number | null;
  /** True once the token is spent. `leewaySeconds` renews it before it dies rather than after. */
  expired(leewaySeconds?: number, now?: number): boolean;
  scopes(): string[];
  hasScope(...wanted: Array<string | string[]>): boolean;
  /** The tenant's authorization claims from the access token — what to authorise on. */
  arkClaims(): string[];
  accessTokenClaims(): Record<string, any> | null;
  readonly subject: string | null;
  authorizationHeader(): string;
  toJSON(): Record<string, any>;
  static fromJSON(data: any): TokenSet | null;
}

// =====================================================================
// discovery, keys, JWT
// =====================================================================

export interface ProviderMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  jwks_uri: string;
  introspection_endpoint?: string;
  revocation_endpoint?: string;
  end_session_endpoint?: string;
  device_authorization_endpoint?: string;
  pushed_authorization_request_endpoint?: string;
  registration_endpoint?: string;
  scopes_supported?: string[];
  grant_types_supported?: string[];
  response_modes_supported?: string[];
  code_challenge_methods_supported?: string[];
  token_endpoint_auth_methods_supported?: string[];
  authorization_response_iss_parameter_supported?: boolean;
  require_pushed_authorization_requests?: boolean;
  [key: string]: unknown;
}

export function discoveryUrls(authority: string): [string, string];

export class MetadataResolver {
  constructor(options?: { ttlMs?: number; timeoutMs?: number; fetch?: typeof fetch });
  get(authority: string, options?: { force?: boolean }): Promise<ProviderMetadata>;
  clear(): void;
}

export interface Jwk {
  kty: string;
  kid?: string;
  use?: string;
  alg?: string;
  [key: string]: unknown;
}

export class JwksCache {
  constructor(jwksUri: string, options?: { ttlMs?: number; minRefreshIntervalMs?: number; timeoutMs?: number; fetch?: typeof fetch });
  readonly uri: string;
  keys(options?: { force?: boolean }): Promise<Jwk[]>;
  getSigningKey(kid: string | undefined, alg: string): Promise<Jwk>;
  clear(): void;
}

export interface DecodedJwt {
  header: Record<string, any>;
  payload: Record<string, any>;
  signature: Buffer;
  signingInput: string;
}

/** Decodes without verifying. Never authorise on the result. */
export function decodeJwt(token: string): DecodedJwt;
export function verifySignature(decoded: DecodedJwt, jwk: Jwk, options?: { algorithms?: string[] }): true;

export interface ClaimValidationOptions {
  issuer?: string;
  audience?: string;
  subject?: string;
  nonce?: string | null;
  maxAgeSeconds?: number | null;
  clockToleranceSeconds?: number;
  requireExp?: boolean;
  requireIat?: boolean;
  now?: number;
}

export function validateClaims(payload: Record<string, any>, options?: ClaimValidationOptions): Record<string, any>;
export function validateTokenHashes(
  payload: Record<string, any>,
  options?: { accessToken?: string | null; code?: string | null; require?: boolean }
): Record<string, any>;

export function verifyJwt(
  token: string,
  jwks: { getSigningKey(kid: string | undefined, alg: string): Promise<Jwk> },
  options?: ClaimValidationOptions & {
    typ?: string;
    algorithms?: string[];
    accessToken?: string | null;
    code?: string | null;
    requireTokenHashes?: boolean;
  }
): Promise<Record<string, any>>;

export function signJwt(
  payload: Record<string, any>,
  options: { key: unknown; alg?: string; kid?: string; typ?: string; header?: Record<string, any> }
): string;

// =====================================================================
// PKCE and encoding
// =====================================================================

export function createCodeVerifier(): string;
export function codeChallengeFor(verifier: string): string;
export function createPkcePair(): { codeVerifier: string; codeChallenge: string; codeChallengeMethod: 'S256' };
export function createState(): string;
export function createNonce(): string;
export function base64UrlEncode(input: Buffer | string): string;
export function base64UrlDecode(value: string): Buffer;
export function leftHalfHash(value: string): string;
export function randomToken(bytes?: number): string;

// =====================================================================
// the client
// =====================================================================

/** What createAuthorizationUrl returns and handleCallback needs back. Store it server-side. */
export interface ArkLoginTransaction {
  url: string;
  state: string;
  nonce: string | null;
  codeVerifier: string;
  redirectUri: string;
  scope: string;
  maxAge: number | null;
  createdAt: number;
  returnTo?: string;
}

export interface AuthorizationUrlOptions {
  scopes?: string[];
  state?: string;
  nonce?: string;
  redirectUri?: string;
  responseMode?: ResponseMode;
  prompt?: string;
  loginHint?: string;
  maxAge?: number;
  acrValues?: string;
  usePar?: boolean;
  returnTo?: string;
  extra?: Record<string, string>;
}

export interface DeviceAuthorizationResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
  interval: number;
}

export interface IntrospectionResponse {
  active: boolean;
  sub?: string;
  scope?: string;
  client_id?: string;
  token_type?: string;
  exp?: number;
  iat?: number;
  [key: string]: unknown;
}

export interface ArkSetupReport {
  authority: string;
  clientId: string;
  isConfidential: boolean;
  tokenEndpointAuthMethod: TokenEndpointAuthMethod;
  scopes: string[];
  redirectUri: string | null;
  postLogoutRedirectUri: string | null;
  origin: string | null;
  tenantId: string;
  /** The tenant's admin console, where the client is registered. */
  adminConsoleUrl: string;
  /** The provider's own page of what it expects from this client. */
  integrationPageUrl: string;
  discoveryUrl: string;
  discoveryOk: boolean;
  discoveryError: string | null;
  supportsClientCredentials: boolean;
  supportsDynamicRegistration: boolean;
  provider: Record<string, any> | null;
  signingKeys?: Array<{ kid?: string; kty: string; alg: string | null; use: string | null }>;
  /** Empty when local configuration and the provider's metadata agree. */
  problems: string[];
}

export class ArkOAuthClient {
  constructor(options: ArkClientOptions);
  readonly config: ArkResolvedConfig;
  readonly authority: string;

  metadata(options?: { force?: boolean }): Promise<ProviderMetadata>;
  jwks(): Promise<JwksCache>;

  createAuthorizationUrl(options?: AuthorizationUrlOptions): Promise<ArkLoginTransaction>;
  static readCallbackParams(input: string | URLSearchParams | Record<string, any>): Record<string, string>;
  handleCallback(
    responseParams: string | URLSearchParams | Record<string, any>,
    transaction: ArkLoginTransaction | (Partial<ArkLoginTransaction> & { state: string; codeVerifier: string }),
    options?: { redirectUri?: string }
  ): Promise<TokenSet>;
  exchangeCode(options: {
    code: string;
    codeVerifier: string;
    redirectUri: string;
    nonce?: string | null;
    maxAge?: number | null;
  }): Promise<TokenSet>;

  refresh(refreshToken: string, options?: { scopes?: string[] }): Promise<TokenSet>;
  clientCredentials(options?: {
    scopes?: string[];
    clientId?: string;
    clientSecret?: string;
    force?: boolean;
    renewBeforeSeconds?: number;
  }): Promise<TokenSet>;

  deviceAuthorization(options?: { scopes?: string[] }): Promise<DeviceAuthorizationResponse>;
  pollDeviceToken(
    deviceAuthorization: DeviceAuthorizationResponse | string,
    options?: { signal?: AbortSignal; onPending?: (error: ArkOAuthError) => void; intervalSeconds?: number; timeoutSeconds?: number }
  ): Promise<TokenSet>;

  pushAuthorizationRequest(params: Record<string, string>): Promise<{ request_uri: string; expires_in: number }>;

  userInfo(accessToken: string): Promise<Record<string, any>>;
  introspect(token: string, options?: { tokenTypeHint?: 'access_token' | 'refresh_token' }): Promise<IntrospectionResponse>;
  revoke(token: string, options?: { tokenTypeHint?: 'access_token' | 'refresh_token' }): Promise<true>;
  endSessionUrl(options?: { idTokenHint?: string; postLogoutRedirectUri?: string; state?: string; clientId?: string }): Promise<string>;

  verifyIdToken(
    idToken: string,
    options?: { nonce?: string | null; accessToken?: string | null; code?: string | null; maxAge?: number | null }
  ): Promise<Record<string, any>>;
  verifyAccessToken(
    token: string,
    options?: { audience?: string; scopes?: string[]; arkClaims?: string[]; requireTypeHeader?: boolean }
  ): Promise<Record<string, any>>;

  registerClient(clientMetadata: Record<string, any>, initialAccessToken?: string): Promise<Record<string, any>>;
  readRegistration(clientId: string, registrationAccessToken: string): Promise<Record<string, any>>;
  deleteRegistration(clientId: string, registrationAccessToken: string): Promise<true>;

  /** Pairs local configuration with the provider's live metadata and reports what does not line up. */
  checkSetup(options?: { origin?: string; callbackPath?: string }): Promise<ArkSetupReport>;
}

export function createArkClient(options: ArkClientOptions): ArkOAuthClient;

// =====================================================================
// sessions
// =====================================================================

export interface SessionStore {
  get(id: string): Promise<any | null>;
  set(id: string, data: any, ttlSeconds: number): Promise<void>;
  destroy(id: string): Promise<void>;
  touch?(id: string, ttlSeconds: number): Promise<void>;
}

export class MemorySessionStore implements SessionStore {
  constructor(options?: { sweepIntervalMs?: number });
  get(id: string): Promise<any | null>;
  set(id: string, data: any, ttlSeconds: number): Promise<void>;
  destroy(id: string): Promise<void>;
  touch(id: string, ttlSeconds: number): Promise<void>;
  sweep(now?: number): void;
  readonly size: number;
  close(): void;
}

export function createSessionId(): string;
export function signSessionId(id: string, secret: string): string;
export function unsignSessionId(value: string, secret: string): string | null;
export function parseCookies(header?: string): Record<string, string>;
export function serializeCookie(
  name: string,
  value: string,
  options?: { maxAge?: number; domain?: string; path?: string; expires?: Date | number; httpOnly?: boolean; secure?: boolean; sameSite?: string }
): string;

// =====================================================================
// account switching on a shared browser
// =====================================================================

export const ArkAccessDeniedReasons: Readonly<{ NO_APP_ACCESS: 'no_app_access'; FORBIDDEN: 'forbidden' }>;
export type ArkAccessDeniedReason = 'no_app_access' | 'forbidden';

/** `accountSwitch` — the same settings as AccountSwitch (.NET) and account_switch (Python). Everything is off or unchanged by default. */
export interface ArkAccountSwitchOptions {
  /** Serve the three endpoints, and send an HTML 403 to the page. Default true. */
  enabled?: boolean;
  /** Refuse, at the callback, an account the provider issued no ark_claims for. Default false. */
  requireArkClaims?: boolean;
  /** Narrow that check to at least one of these values (case-insensitive). */
  requiredClaims?: string[];
  /** Default /ark/no-access. */
  accessDeniedPath?: string;
  /** Default /ark/switch-user. */
  switchUserPath?: string;
  /** Default /ark/sign-out. */
  signOutPath?: string;
  /** Draw the built-in page. Turn off when accessDeniedPath is a route of your own. Default true. */
  serveDefaultPage?: boolean;
  /** Defaults to the client id. */
  appDisplayName?: string | null;
  showSignedInAccount?: boolean;
  allowFullSignOut?: boolean;
  /** Switching also ends the provider session — for a kiosk. Default false. */
  endProviderSessionOnSwitch?: boolean;
  /** Default 'login'. */
  prompt?: string;
  homePath?: string;
  /** http(s) only. */
  supportUrl?: string | null;
  supportEmail?: string | null;
}

export const ACCOUNT_SWITCH_DEFAULTS: Readonly<Required<ArkAccountSwitchOptions>>;
export function normalizeAccountSwitch(options?: ArkAccountSwitchOptions): Readonly<Required<ArkAccountSwitchOptions>>;

export interface ArkAccessEvaluationContext {
  /** ID token claims. */
  claims: Record<string, any>;
  arkClaims: string[];
  /** What the configured rule concluded before your handler ran. */
  allowedByConfiguration: boolean;
  tokens: TokenSet | null;
}

export interface ArkAccessDeniedContext {
  reason: ArkAccessDeniedReason;
  subject: string | null;
  email: string | null;
  name: string | null;
  arkClaims: string[];
  returnUrl: string | null;
  /** Set true when you have written the response yourself. */
  handled: boolean;
}

export interface ArkDeniedAccount {
  subject: string | null;
  email: string | null;
  name: string | null;
  reason: ArkAccessDeniedReason | null;
  returnUrl: string | null;
}

export interface ArkClientEvents {
  /** Your entitlement rule. Replaces the configured one; read allowedByConfiguration to combine them. */
  onEvaluateAccess?: (context: ArkAccessEvaluationContext) => boolean | Promise<boolean>;
  /** Log a denial, or write a response of your own (then set `handled` or just respond). */
  onAccessDenied?: (context: ArkAccessDeniedContext, req: any, res: any) => void | Promise<void>;
}

export interface ArkChallengeOptions {
  returnTo?: string;
  prompt?: string;
  loginHint?: string;
  scopes?: string[];
  maxAge?: number;
}

export const ArkChallengeProperties: Readonly<{
  /** prompt=login: the provider draws its sign-in form instead of answering from its session. */
  switchUser(returnUrl?: string | null, loginHint?: string | null, prompt?: string): ArkChallengeOptions;
  selectAccount(returnUrl?: string | null): ArkChallengeOptions;
}>;

/** A same-origin path, or `fallback`. Guards every return URL against open redirects. */
export function localOrDefault(url: string | null | undefined, fallback?: string | null): string | null;

export function renderAccessDeniedPage(
  options: Readonly<Required<ArkAccountSwitchOptions>>,
  model: { app?: string | null; account?: string | null; returnUrl: string }
): string;

/** Binds an appsettings.json `ark_oauth_client` section (C#, camel or snake keys) into arkExpress()/ArkOAuthClient options. */
export const ArkAuthConfig: Readonly<{
  fromMapping(data: Record<string, any>): Partial<ArkExpressOptions>;
}>;

/** This package's version, read from its package.json. */
export const VERSION: string;

// =====================================================================
// middleware
// =====================================================================

/** What the middleware attaches to every request. */
export interface ArkRequestContext {
  client: ArkOAuthClient;
  store: SessionStore;
  sessionId: string | null;
  isAuthenticated: boolean;
  /** ID token claims, plus UserInfo when fetchUserInfo is on. */
  user: Record<string, any> | null;
  sub: string | null;
  /** Ark authorization claims — the thing to authorise on. */
  claims: string[];
  scopes: string[];
  tokens: TokenSet | null;
  idToken: string | null;
  /** The current access token, refreshed first if it is about to expire. */
  accessToken(): Promise<string | null>;
  /** Adds `Authorization: Bearer …` to a headers object for a downstream call. */
  authorize(headers?: Record<string, string>): Promise<Record<string, string>>;
  hasClaim(...wanted: Array<string | string[]>): boolean;
  hasScope(...wanted: Array<string | string[]>): boolean;
  login(options?: ArkChallengeOptions): Promise<void>;
  /** Revokes the refresh token, ends the local session, then RP-initiated logout at the provider. */
  logout(options?: { returnTo?: string }): Promise<void>;
  /** Drops this session and challenges with prompt=login, so somebody else can sign in. */
  switchUser(options?: { returnUrl?: string; loginHint?: string }): Promise<void>;
  /** This application's session and the provider's. */
  signOutEverywhere(options?: { returnUrl?: string }): Promise<void>;
  /** This application's session only. */
  signOutLocally(options?: { returnUrl?: string }): Promise<void>;
  /** The account the last denial was about, for a page of your own; null otherwise. */
  deniedAccount(): ArkDeniedAccount | null;
}

/** What arkBearer attaches when a token is presented. */
export interface ArkBearerContext {
  isAuthenticated: boolean;
  token: string | null;
  payload?: Record<string, any>;
  sub?: string;
  clientId?: string | null;
  sessionId?: string | null;
  scopes: string[];
  claims: string[];
  hasClaim?(...wanted: Array<string | string[]>): boolean;
  hasScope?(...wanted: Array<string | string[]>): boolean;
  client?: ArkOAuthClient;
}

type Middleware = (req: any, res: any, next: (error?: any) => void) => void | Promise<void>;

export interface ArkExpressOptions extends Partial<ArkClientOptions> {
  /** Reuse an existing client instead of configuring one here. */
  client?: ArkOAuthClient;
  /** Signs the session cookie. At least 16 characters, and the same value across every instance. */
  secret: string;
  loginPath?: string;
  /** Defaults to the path of `redirectUri`, or /signin-oidc. */
  callbackPath?: string;
  logoutPath?: string;
  /** Defaults to an in-process Map. Supply a shared store for more than one instance. */
  store?: SessionStore;
  cookieName?: string;
  cookie?: { httpOnly?: boolean; secure?: boolean; sameSite?: string; domain?: string; path?: string };
  sessionTtlSeconds?: number;
  /** Renew the access token this many seconds before it expires. Default 120, as in the .NET and Python clients. */
  refreshLeewaySeconds?: number;
  /** Also call /userinfo at sign-in and merge the result into `req.ark.user`. */
  fetchUserInfo?: boolean;
  returnToParam?: string;
  defaultReturnTo?: string;
  /** Where a failed sign-in lands, with ?auth_error=… */
  errorPath?: string | null;
  onError?: (error: Error, req: any, res: any, next: (error?: any) => void) => void;
  /** Read X-Forwarded-Proto + X-Forwarded-Host (both, or neither). Turn off when no proxy sets them. Default true. */
  trustProxy?: boolean;
  /** The shared-browser case: entitlement at the callback, the access-denied page, prompt=login switching. */
  accountSwitch?: ArkAccountSwitchOptions;
  events?: ArkClientEvents;
}

export interface ArkExpressMiddleware extends Middleware {
  /** Redirects a browser to sign in; answers 401 with a bearer challenge for anything else. */
  requireAuth(options?: { claims?: string[]; scopes?: string[] }): Middleware;
  requireClaims(...claims: Array<string | string[]>): Middleware;
  requireScopes(...scopes: Array<string | string[]>): Middleware;
  /** checkSetup() for this request: the redirect URI it would really send, and who is signed in. */
  checkSetup(req: any): Promise<ArkSetupReport & { isAuthenticated: boolean; signedInAs: string | null; authError: string | null }>;
  switchUser(req: any, res: any, options?: { returnUrl?: string; loginHint?: string }): Promise<void>;
  signOutEverywhere(req: any, res: any, options?: { returnUrl?: string }): Promise<void>;
  signOutLocally(req: any, res: any, options?: { returnUrl?: string }): Promise<void>;
  deniedAccount(req: any): ArkDeniedAccount | null;
  readonly client: ArkOAuthClient;
  readonly store: SessionStore;
  readonly accountSwitch: Readonly<Required<ArkAccountSwitchOptions>>;
  readonly loginPath: string;
  readonly callbackPath: string;
  readonly logoutPath: string;
}

export function arkExpress(options: ArkExpressOptions): ArkExpressMiddleware;

export interface ArkBearerOptions extends Partial<ArkClientOptions> {
  client?: ArkOAuthClient;
  /** Required on every request this middleware guards. */
  scopes?: string[];
  /** Required Ark authorization claims. */
  claims?: string[];
  audience?: string;
  /** Let unauthenticated requests through with `req.ark.isAuthenticated === false`. */
  optional?: boolean;
  /** Require the RFC 9068 `at+jwt` type header. On by default. */
  requireTypeHeader?: boolean;
}

export interface ArkBearerMiddleware extends Middleware {
  require(options?: { scopes?: string[]; claims?: string[] }): Middleware;
  readonly client: ArkOAuthClient;
}

export function arkBearer(options?: ArkBearerOptions): ArkBearerMiddleware;

declare global {
  namespace Express {
    interface Request {
      ark?: ArkRequestContext | ArkBearerContext;
    }
  }
}
