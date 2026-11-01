/**
 * Checks this application's configuration against the provider's live metadata.
 *
 *   node examples/setup-check.js
 *
 * Worth running in CI, or rendering on a health page. Without it, the first symptom of a wrong
 * port, a stopped provider, a missing tenant id or a scope the client was never registered for is
 * `invalid_request` on a page a user is looking at.
 */
import { ArkOAuthClient } from '../src/index.js';
import { authority, clientId, clientSecret, origin } from './config.js';

const client = new ArkOAuthClient({
  authority,
  clientId,
  clientSecret,
  redirectUri: `${origin}/signin-oidc`,
  requireHttps: origin.startsWith('https')
});

const report = await client.checkSetup();

console.log(`authority     ${report.authority}`);
console.log(`client        ${report.clientId} (${report.tokenEndpointAuthMethod})`);
console.log(`redirect_uri  ${report.redirectUri}`);
console.log(`discovery     ${report.discoveryOk ? 'ok' : `FAILED — ${report.discoveryError}`}`);

if (report.discoveryOk) {
  console.log(`issuer        ${report.provider.issuer}`);
  console.log(`token         ${report.provider.tokenEndpoint}`);
  console.log(`keys          ${report.signingKeys?.map((k) => `${k.kid} (${k.kty})`).join(', ')}`);
  console.log(`scopes        ${report.provider.scopesSupported.join(' ')}`);
  console.log(`grants        ${report.provider.grantTypesSupported.join(' ')}`);
}

if (report.problems.length === 0) {
  console.log('\nNo problems found.');
} else {
  console.log(`\n${report.problems.length} problem(s):`);
  for (const problem of report.problems) console.log(`  • ${problem}`);
  process.exitCode = 1;
}
