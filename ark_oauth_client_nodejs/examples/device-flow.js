/**
 * The device authorization grant: signing in from a CLI, a TV, or anything without a browser.
 *
 *   ARK_CLIENT_ID=my-device ARK_CLIENT_SECRET=… node examples/device-flow.js
 *
 * The device asks for a code, shows the user a short one to type on their phone, and polls until
 * they approve. `pollDeviceToken` handles the two RFC 8628 responses that are not failures —
 * `authorization_pending` and `slow_down`.
 */
import { ArkOAuthClient } from '../src/index.js';
import { authority, clientId, clientSecret } from './config.js';

const client = new ArkOAuthClient({ authority, clientId, clientSecret });

const authorization = await client.deviceAuthorization({ scopes: ['openid', 'profile', 'offline_access'] });

console.log('\n  To sign in, visit:\n');
console.log(`     ${authorization.verification_uri}`);
console.log(`\n  and enter the code:  ${authorization.user_code}`);
console.log(`\n  or open this directly:\n     ${authorization.verification_uri_complete}\n`);

// Ctrl-C stops the wait cleanly rather than leaving a polling loop behind.
const cancel = new AbortController();
process.on('SIGINT', () => cancel.abort());

try {
  const tokens = await client.pollDeviceToken(authorization, {
    signal: cancel.signal,
    onPending: (error) => process.stdout.write(error.error === 'slow_down' ? '~' : '.')
  });

  console.log('\n\nSigned in as', tokens.claims?.name ?? tokens.subject);
  console.log('claims       :', tokens.arkClaims().join(', ') || 'none');
  console.log('refresh token:', tokens.refreshToken ? 'issued' : 'not issued (offline_access was not granted)');
} catch (error) {
  console.error('\n\nDevice sign-in failed:', error.message);
  process.exitCode = 1;
}
