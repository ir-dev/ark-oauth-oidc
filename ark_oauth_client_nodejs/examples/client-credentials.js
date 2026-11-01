/**
 * Service-to-service: a job or daemon authenticating as itself, with no user involved.
 *
 *   ARK_CLIENT_ID=my-service ARK_CLIENT_SECRET=… node examples/client-credentials.js
 *
 * The token this returns carries the *service's* authority, not a person's. Never use it to act
 * on behalf of a signed-in user: nothing downstream can tell the difference, and the audit trail
 * says the service did it.
 */
import { ArkOAuthClient } from '../src/index.js';
import { authority, clientId, clientSecret } from './config.js';

const client = new ArkOAuthClient({ authority, clientId, clientSecret });

// Cached until shortly before it expires — asking for a token per outbound call turns one request
// into two and rate-limits the service against its own identity provider.
const token = await client.clientCredentials({ scopes: ['reports.read'] });

console.log('access token :', `${token.accessToken.slice(0, 32)}…`);
console.log('expires in   :', token.expiresIn(), 'seconds');
console.log('scopes       :', token.scopes().join(' ') || '(none)');
console.log('subject      :', token.subject, '(the client itself)');

const again = await client.clientCredentials({ scopes: ['reports.read'] });
console.log('cached       :', again.accessToken === token.accessToken);

const response = await fetch(`${authority}/oauth2/userinfo`, {
  headers: { Authorization: token.authorizationHeader() }
});
console.log('userinfo     :', response.status, '(403 is correct — there is no user in this flow)');
