// End-to-end against a REAL Ark identity server, in real browsers (Chrome and WebKit), through
// the vanilla example app. Not part of `npm test`: it needs a running Ark.oAuth.Oidc.Host.
//
//   ARK_E2E_PASSWORD=… npm run e2e            # or: node e2e/real-idp.mjs [chrome|webkit|all]
//
// Needs `playwright-core` (a devDependency), Google Chrome for the Chrome run, and Playwright's
// WebKit build for the WebKit run (`npx playwright-core install webkit`).
//
// The provider, set up once on a SCRATCH host (never a real one):
//
//   cd Ark.oAuth.Oidc/Ark.oAuth.Oidc.Host
//   ConnectionStrings__ArkAuthConnection="Data Source=/tmp/ark-e2e/ark_idp.db" \
//   ark_oauth_server__BaseUrl=http://127.0.0.1:5399 \
//   ark_oauth_server__AdminUser__Password="$ARK_E2E_PASSWORD" \
//   ark_oauth_server__Oidc__CorsOrigins__0=http://127.0.0.1:5173 \
//   dotnet run --no-launch-profile --urls http://127.0.0.1:5399
//
// then a public client for the example app, cloned from the seeded one, with a short access-token
// lifetime so the automatic-refresh step fires within the run, and the admin mapped to it:
//
//   sqlite3 /tmp/ark-e2e/ark_idp.db <<'SQL'
//   CREATE TEMP TABLE t AS SELECT * FROM clients WHERE client_id='ark_idp_client';
//   UPDATE t SET id=lower(hex(randomblob(4)))||'-'||lower(hex(randomblob(2)))||'-4'||substr(lower(hex(randomblob(2))),2)||'-a'||substr(lower(hex(randomblob(2))),2)||'-'||lower(hex(randomblob(6))),
//     client_id='spa-demo', name='spa-demo', display='Ark SPA Demo',
//     redirect_url='http://127.0.0.1:5173/signin-oidc', logout_url='http://127.0.0.1:5173/signout-callback-oidc',
//     redirect_uris_='["http://127.0.0.1:5173/signin-oidc"]',
//     post_logout_redirect_uris_='["http://127.0.0.1:5173/signout-callback-oidc"]', access_token_lifetime_seconds=75;
//   INSERT INTO clients SELECT * FROM t;
//   INSERT INTO user_client_claims (id, email, client_id, tenant_id, claims_, at)
//     SELECT lower(hex(randomblob(4)))||'-'||lower(hex(randomblob(2)))||'-4'||substr(lower(hex(randomblob(2))),2)||'-a'||substr(lower(hex(randomblob(2))),2)||'-'||lower(hex(randomblob(6))), 'admin', id, 'ark_idp', '["billing.admin","reports.read"]', datetime('now')
//     FROM clients WHERE client_id='spa-demo';
//   SQL
//
// Verified 2026-11-18 against Ark.oAuth.Oidc 2.1.x: every step below passed in Chrome and WebKit.
import { chromium, webkit } from 'playwright-core';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const PKG = fileURLToPath(new URL('..', import.meta.url));
const APP = 'http://127.0.0.1:5173';
const AUTHORITY = process.env.ARK_E2E_AUTHORITY ?? 'http://127.0.0.1:5399/ark_idp';
const CLIENT_ID = process.env.ARK_E2E_CLIENT_ID ?? 'spa-demo';
const USER = process.env.ARK_E2E_USER ?? 'admin';
const PW = process.env.ARK_E2E_PASSWORD;
const EXPECT_CLAIMS = process.env.ARK_E2E_EXPECT_CLAIMS ?? 'billing.admin, reports.read';
const which = process.argv[2] ?? 'all';
if (!PW) {
  console.error('Set ARK_E2E_PASSWORD to the scratch host\'s admin password (see the header of this file).');
  process.exit(2);
}

let server = null;
async function startApp(env = {}) {
  if (server) {
    server.kill();
    await new Promise((r) => server.once('exit', r));
  }
  server = spawn(process.execPath, ['examples/serve.mjs'], {
    cwd: PKG,
    env: { ...process.env, ARK_AUTHORITY: AUTHORITY, ARK_CLIENT_ID: CLIENT_ID, ...env },
    stdio: ['ignore', 'pipe', 'inherit']
  });
  await new Promise((resolve) => server.stdout.once('data', resolve));
}

async function signInOnProvider(page) {
  await page.waitForSelector('input[name=username]', { timeout: 15000 });
  await page.fill('input[name=username]', USER);
  await page.fill('input[name=password]', PW);
  await page.click('button[type=submit]');
  // The real server shows a consent page the first time offline_access is asked for.
  const consent = await page.waitForSelector('button[value=consent]', { timeout: 4000 }).catch(() => null);
  if (consent) await consent.click();
}

async function scenario(browserType, launch, label) {
  const browser = await browserType.launch(launch);
  try {
    await run(browser, label);
  } finally {
    await browser.close();
  }
}

async function run(browser, label) {
  const context = await browser.newContext();
  const page = await context.newPage();
  const problems = [];
  const watch = (p) => {
    p.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`));
    p.on('console', (m) => {
      if (m.type() === 'error' && !/status of 40[014]/.test(m.text())) problems.push(`console: ${m.text()}`);
    });
  };
  watch(page);
  const requests = [];
  context.on('request', (r) => requests.push(`${r.method()} ${r.url()}`));
  context.on('response', (r) => {
    if (r.status() === 404) problems.push(`404: ${r.url()}`);
  });
  const step = (text) => console.log(`[${label}] ✔ ${text}`);
  const status = (s) => page.waitForSelector(`#status[data-status="${s}"]`, { timeout: 20000 });
  const events = () => page.$$eval('#events li', (lis) => lis.map((li) => li.textContent));

  await startApp();

  // 1. first load, and the setup check proves CORS against the real server
  await page.goto(`${APP}/`);
  await status('unauthenticated');
  await page.click('#setup');
  await page.waitForFunction(() => document.getElementById('output').textContent.includes('"problems"'));
  const report = JSON.parse(await page.textContent('#output'));
  assert.equal(report.discoveryOk, true, 'discovery over CORS');
  assert.equal(report.jwksOk, true, 'JWKS over CORS');
  assert.equal(report.tokenEndpointCorsOk, true, 'token endpoint answers this origin');
  assert.deepEqual(report.problems, [], `setup problems: ${report.problems.join(' | ')}`);
  step('checkSetup: discovery, JWKS and token endpoint reachable over CORS, no problems');

  // 2. redirect sign-in from a deep link
  await page.goto(`${APP}/orders?page=2`);
  await status('unauthenticated');
  await page.click('#signin');
  await page.waitForURL(/\/ark_idp\/oauth2\/authorize/);
  const authorize = new URL(page.url());
  assert.equal(authorize.searchParams.get('code_challenge_method'), 'S256');
  assert.ok(authorize.searchParams.get('nonce'));
  await signInOnProvider(page);
  await status('authenticated');
  assert.equal(new URL(page.url()).pathname + new URL(page.url()).search, '/orders?page=2', 'back on the deep link, code/state/iss stripped');
  assert.equal(await page.textContent('#claims'), EXPECT_CLAIMS);
  const email = await page.textContent('#email');
  step(`redirect sign-in completed in the browser (ID token verified with Web Crypto), user ${email}, ark_claims shown`);

  // 3. userinfo (CORS + bearer) and a manual refresh (rotation)
  await page.click('#userinfo');
  await page.waitForFunction(() => document.getElementById('output').textContent.includes('"sub"'));
  step('userinfo answered with the access token');
  const before = await page.evaluate(() => JSON.parse(sessionStorage.getItem(Object.keys(sessionStorage).find((k) => k.endsWith(':tokens')))).refresh_token);
  await page.click('#refresh');
  await page.waitForFunction(() => document.getElementById('output').textContent === 'refreshed');
  const after = await page.evaluate(() => JSON.parse(sessionStorage.getItem(Object.keys(sessionStorage).find((k) => k.endsWith(':tokens')))).refresh_token);
  assert.notEqual(after, before, 'refresh token rotated');
  step('refresh_token grant over CORS; the rotated refresh token was stored');

  // 4. a reload restores the session without the provider
  const authorizeCount = requests.filter((r) => r.includes('/oauth2/authorize')).length;
  await page.reload();
  await status('authenticated');
  assert.equal(requests.filter((r) => r.includes('/oauth2/authorize')).length, authorizeCount);
  step('reload restored the session from sessionStorage');

  // 5. automatic refresh: the client's access tokens live 75s and are renewed 60s early
  await page.waitForFunction(() => [...document.querySelectorAll('#events li')].some((li) => li.textContent.includes('tokensRefreshed')), null, { timeout: 40000 });
  step('automatic refresh fired before expiry');

  // 6. a second tab of the app, then RP-initiated logout in the first: the second hears of it
  const tab2 = await context.newPage();
  watch(tab2);
  await tab2.goto(`${APP}/`);
  await tab2.waitForSelector('#status[data-status="unauthenticated"]'); // sessionStorage is per tab
  await tab2.click('#signin');
  await tab2.waitForURL(`${APP}/`, { timeout: 20000 }); // silent: the provider session answers
  await tab2.waitForSelector('#status[data-status="authenticated"]');
  step('second tab signed in silently through the provider session (SSO)');

  await page.click('#signout');
  await page.waitForURL(`${APP}/`, { timeout: 20000 });
  await status('unauthenticated');
  assert.ok(requests.some((r) => r.startsWith('POST') && r.includes('/oauth2/revoke')), 'refresh token revoked (no-cors)');
  const logout = requests.find((r) => r.includes('/oauth2/logout'));
  assert.ok(logout && new URL(logout.split(' ')[1]).searchParams.get('id_token_hint'), 'logout carried id_token_hint');
  assert.ok(!requests.some((r) => r.includes('LogoutConfirm')), 'no confirmation page');
  await tab2.waitForSelector('#status[data-status="unauthenticated"]', { timeout: 10000 });
  step('signoutRedirect: revoked, provider logout with id_token_hint (no confirm page), back on the app; the other tab signed out too');

  // 7. the provider session really ended: signing in shows the form again; this time in a popup
  await tab2.close();
  const popupPromise = context.waitForEvent('page');
  await page.click('#signin-popup');
  const popup = await popupPromise;
  watch(popup);
  await signInOnProvider(popup);
  if (!popup.isClosed()) await popup.waitForEvent('close', { timeout: 20000 });
  await status('authenticated');
  assert.equal(new URL(page.url()).pathname, '/', 'the opener never navigated');
  step('popup sign-in: the form was shown again (provider session had ended), popup relayed and closed');

  // 8. switch user: prompt=login forces the form although a provider session exists
  await page.click('#switch');
  await page.waitForURL(/\/ark_idp\/oauth2\/authorize/);
  assert.equal(new URL(page.url()).searchParams.get('prompt'), 'login');
  await signInOnProvider(page);
  await status('authenticated');
  step('switchUser sent prompt=login; the provider drew the sign-in form despite its session');

  // 9. accountSwitch: a sign-in without the required claim is refused at the callback
  await startApp({ ARK_REQUIRED_CLAIMS: 'payroll.admin' });
  await page.evaluate(() => sessionStorage.clear());
  await page.goto(`${APP}/payroll`);
  await status('unauthenticated');
  await page.click('#signin');
  await page.waitForURL(`${APP}/payroll`, { timeout: 20000 }); // silent (provider session)
  await page.waitForSelector('.ark-denied', { timeout: 10000 });
  const deniedText = await page.textContent('.ark-denied');
  assert.match(deniedText, /You do not have access to Ark SPA demo/);
  assert.ok(await page.evaluate(() => !Object.keys(sessionStorage).some((k) => k.endsWith(':tokens'))), 'no tokens stored for the refused account');
  await page.click('.ark-denied__switch');
  await page.waitForURL(/prompt=login/);
  step('requiredClaims refused the account at the callback; the dead end (CSP-safe) offered "Sign in as a different user" with prompt=login');

  // 10. the <script src> build (window.ArkOAuth)
  await startApp({ EXAMPLE: 'script-tag' });
  await page.goto(`${APP}/`);
  await page.waitForFunction(() => document.getElementById('status').textContent === 'unauthenticated');
  // Silent when the provider session from step 8 is still alive, the form otherwise.
  await Promise.all([page.waitForURL((u) => u.pathname.startsWith('/signin-oidc') || u.pathname.includes('/oauth2/authorize')), page.click('#signin')]);
  if (page.url().includes('/oauth2/authorize')) await signInOnProvider(page);
  await page.waitForFunction(() => document.getElementById('status')?.textContent.startsWith('Signed in as'), null, { timeout: 20000 });
  step(`IIFE build from a plain <script> tag: ${await page.textContent('#status')}`);

  assert.deepEqual(problems, [], `browser errors:\n${problems.join('\n')}`);
  step('no page errors and no CSP violations under a strict policy (script-src/style-src self)');
}

try {
  if (which === 'chrome' || which === 'all') await scenario(chromium, { channel: 'chrome', headless: true }, 'Chrome');
  if (which === 'webkit' || which === 'all') await scenario(webkit, { headless: true }, 'WebKit');
  console.log('E2E PASSED');
} catch (error) {
  console.error('E2E FAILED:', error);
  process.exitCode = 1;
} finally {
  server?.kill();
}
