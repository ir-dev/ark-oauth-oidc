/**
 * ark-oauth-client-js: the OpenID Connect client for browser apps signing in against an Ark
 * identity server. Framework-agnostic; adapters for React (`/react`), Next.js (`/next`), Vue
 * (`/vue`) and Angular (`/angular`) sit on top of the same client.
 *
 * Two settings are required: the issuer, `{BaseUrl}/{TenantId}`, and the client id. Every endpoint
 * and signing key comes from the provider's discovery document.
 *
 *   import { ArkBrowserClient } from 'ark-oauth-client-js';
 *
 *   const ark = new ArkBrowserClient({ authority: 'https://idp.example.com/my_idp', clientId: 'my-spa' });
 *   ark.subscribe((state) => render(state));
 *   await ark.init();
 */

export { VERSION } from './version.js';
export { ArkBrowserClient, createArkClient } from './client.js';
export { TokenSet } from './tokens.js';
export { INITIAL_SNAPSHOT } from './store.js';
export { MemoryStorage } from './storage.js';
export { renderAccessDenied } from './denied.js';
export {
  ArkAccessDeniedReasons,
  ArkChallengeProperties,
  ACCOUNT_SWITCH_DEFAULTS,
  normalizeAccountSwitch,
  localOrDefault
} from './access.js';
export { normalizeConfig, DEFAULT_SCOPES, DEFAULT_REDIRECT_PATH, DEFAULT_POST_LOGOUT_PATH } from './config.js';
export { MetadataResolver, discoveryUrls } from './discovery.js';
export { JwksCache } from './jwks.js';
export { createCodeVerifier, codeChallengeFor, createPkcePair, createState, createNonce } from './pkce.js';
export { decodeJwt, verifyJwt, verifySignature, validateClaims, validateTokenHashes, SUPPORTED_ALGORITHMS } from './jwt.js';
export { base64UrlEncode, base64UrlDecode, randomToken } from './crypto.js';
export {
  ArkError,
  ArkConfigError,
  ArkOAuthError,
  ArkTokenError,
  ArkCallbackError,
  ArkNetworkError,
  ArkLoginRequiredError,
  ArkPopupError
} from './errors.js';
