/**
 * ark-oauth-client — the OAuth 2.1 / OpenID Connect client for Node applications talking to an
 * Ark identity server.
 *
 * There is one URL to configure: the issuer, `{BaseUrl}/{TenantId}`. Every endpoint, signing key
 * and capability is read from the provider's discovery document, so an application does not need
 * to be redeployed when the provider rotates a key or moves an endpoint.
 *
 *   import { ArkOAuthClient, arkExpress } from 'ark-oauth-client';
 *
 *   const auth = arkExpress({
 *     authority: 'https://idp.example.com/my_idp',
 *     clientId: 'my-app',
 *     redirectUri: 'https://app.example.com/signin-oidc',
 *     secret: process.env.ARK_SESSION_SECRET
 *   });
 *
 *   app.use(auth);
 *   app.get('/billing', auth.requireClaims('billing.admin'), handler);
 */

export { ArkOAuthClient, createArkClient } from './client.js';
export { arkExpress, arkBearer } from './express.js';
export { TokenSet } from './tokens.js';
export { MetadataResolver, discoveryUrls } from './discovery.js';
export { JwksCache } from './jwks.js';
export { MemorySessionStore, createSessionId, parseCookies, serializeCookie, signSessionId, unsignSessionId } from './session.js';
export { createCodeVerifier, codeChallengeFor, createPkcePair, createState, createNonce } from './pkce.js';
export { decodeJwt, verifyJwt, signJwt, validateClaims, validateTokenHashes, verifySignature } from './jwt.js';
export { base64UrlDecode, base64UrlEncode, leftHalfHash, randomToken } from './crypto.js';
export { normalizeConfig, DEFAULT_SCOPES } from './config.js';
export { ArkError, ArkConfigError, ArkOAuthError, ArkTokenError, ArkCallbackError, ArkNetworkError } from './errors.js';
