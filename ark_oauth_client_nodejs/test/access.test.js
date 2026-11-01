import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ArkChallengeProperties,
  checkSameOrigin,
  evaluateAccess,
  localOrDefault,
  normalizeAccountSwitch,
  protectState,
  unprotectState
} from '../src/access.js';
import { renderAccessDeniedPage } from '../src/denied-page.js';
import { ArkAuthConfig } from '../src/app-config.js';
import { VERSION } from '../src/index.js';
import { ArkConfigError } from '../src/errors.js';

const SECRET = 'a-test-secret-of-sufficient-length';

describe('return URLs', () => {
  test('only same-origin paths survive', () => {
    assert.equal(localOrDefault('/billing?tab=2', '/'), '/billing?tab=2');
    for (const sneaky of ['https://evil.example.com', '//evil.example.com', '/\\evil.example.com', '/\t/evil.example.com', 'billing', '', null]) {
      assert.equal(localOrDefault(sneaky, '/home'), '/home', JSON.stringify(sneaky));
    }
    assert.equal(localOrDefault('//evil.example.com', null), null, 'a null fallback lets the caller tell refusal apart');
  });
});

describe('the denial cookie', () => {
  test('round-trips, and cannot be read, altered or carried to another secret', () => {
    const sealed = protectState(SECRET, { email: 'alice@example.com', reason: 'no_app_access' });
    assert.doesNotMatch(Buffer.from(sealed, 'base64url').toString('latin1'), /alice/, 'the browser cannot read it');
    assert.deepEqual(unprotectState(SECRET, sealed), { email: 'alice@example.com', reason: 'no_app_access' });

    const bytes = Buffer.from(sealed, 'base64url');
    bytes[20] ^= 1;
    assert.equal(unprotectState(SECRET, bytes.toString('base64url')), null, 'tampering is detected, not parsed');
    assert.equal(unprotectState('a-different-secret-entirely', sealed), null);
    assert.equal(unprotectState(SECRET, 'not-a-cookie'), null);
  });

  test('expires', () => {
    const sealed = protectState(SECRET, { email: 'alice@example.com' });
    assert.equal(unprotectState(SECRET, sealed, -1), null);
  });
});

describe('account switch options', () => {
  test('defaults leave every behaviour off', () => {
    const options = normalizeAccountSwitch();
    assert.equal(options.requireArkClaims, false);
    assert.equal(options.endProviderSessionOnSwitch, false);
    assert.equal(options.accessDeniedPath, '/ark/no-access');
    assert.ok(Object.isFrozen(options));
  });

  test('a path that is not local, or a support link that is not http(s), is refused at startup', () => {
    assert.throws(() => normalizeAccountSwitch({ accessDeniedPath: 'https://evil.example.com' }), ArkConfigError);
    assert.throws(() => normalizeAccountSwitch({ homePath: '//evil.example.com' }), ArkConfigError);
    assert.throws(() => normalizeAccountSwitch({ supportUrl: 'javascript:alert(1)' }), ArkConfigError);
    assert.equal(normalizeAccountSwitch({ toString: 'x' }).toString, Object.prototype.toString, 'unknown keys are ignored');
  });

  test('the configured rule: any claim, or one of the required ones, case-insensitively', async () => {
    const on = normalizeAccountSwitch({ requireArkClaims: true });
    assert.equal(await evaluateAccess(on, {}, { arkClaims: [] }), false);
    assert.equal(await evaluateAccess(on, {}, { arkClaims: ['x'] }), true);
    const narrowed = normalizeAccountSwitch({ requireArkClaims: true, requiredClaims: ['Billing.Admin'] });
    assert.equal(await evaluateAccess(narrowed, {}, { arkClaims: ['reports.read'] }), false);
    assert.equal(await evaluateAccess(narrowed, {}, { arkClaims: ['billing.admin'] }), true);
    assert.equal(await evaluateAccess(normalizeAccountSwitch(), {}, { arkClaims: [] }), true, 'off allows everyone');
  });

  test('the switch challenge says prompt=login', () => {
    assert.deepEqual(ArkChallengeProperties.switchUser('/x', 'bob@example.com'), { returnTo: '/x', prompt: 'login', loginHint: 'bob@example.com' });
    assert.equal(ArkChallengeProperties.selectAccount().prompt, 'select_account');
  });
});

describe('same-origin guard', () => {
  test('POST from this origin only', () => {
    const origin = 'https://app.example.com';
    assert.equal(checkSameOrigin('GET', {}, origin).status, 405);
    assert.equal(checkSameOrigin('POST', { 'sec-fetch-site': 'same-origin' }, origin).ok, true);
    assert.equal(checkSameOrigin('POST', { 'sec-fetch-site': 'same-site' }, origin).ok, false);
    assert.equal(checkSameOrigin('POST', { origin: 'https://APP.example.com/' }, origin).ok, true);
    assert.equal(checkSameOrigin('POST', { origin: 'https://evil.example.com' }, origin).ok, false);
    assert.equal(checkSameOrigin('POST', {}, origin).ok, true, 'a non-browser client sends neither header');
  });
});

describe('the access-denied page', () => {
  test('escapes everything it prints and names the library version', () => {
    const html = renderAccessDeniedPage(normalizeAccountSwitch({ supportEmail: 'help@example.com' }), {
      app: '<script>x</script>',
      account: '"><img src=x onerror=alert(1)>',
      returnUrl: '/a"b'
    });
    assert.doesNotMatch(html, /<script>|<img/);
    assert.match(html, /&lt;script&gt;/);
    assert.match(html, /value="\/a&quot;b"/);
    assert.match(html, /mailto:help@example\.com/);
    assert.ok(html.includes(`ark-oauth-client ${VERSION}`));
    assert.doesNotMatch(html, /<script/i, 'the page carries no script of any kind');
  });

  test('can leave the account unnamed and the full sign-out out', () => {
    const html = renderAccessDeniedPage(normalizeAccountSwitch({ allowFullSignOut: false }), { app: null, returnUrl: '/' });
    assert.match(html, /The account you are signed in with/);
    assert.doesNotMatch(html, /Sign out completely/);
  });
});

describe('binding appsettings.json', () => {
  test('reads the C# section unchanged and ignores the v1 keys', () => {
    const options = ArkAuthConfig.fromMapping({
      ark_oauth_client: {
        AuthServerUrl: 'https://idp.example.com/',
        TenantId: 'my_idp',
        ClientId: 'my-app',
        ClientSecret: 's3cret',
        Scopes: ['openid', 'offline_access'],
        CallbackPath: '/signin-oidc',
        RequireHttpsMetadata: false,
        ExpireMins: 30,
        RedirectUri: 'https://app.example.com/v1/callback',
        RsaPublic: 'MIIB...',
        AccountSwitch: { RequireArkClaims: true, AppDisplayName: 'Billing' }
      }
    });
    assert.deepEqual(options, {
      authServerUrl: 'https://idp.example.com/',
      tenantId: 'my_idp',
      clientId: 'my-app',
      clientSecret: 's3cret',
      scopes: ['openid', 'offline_access'],
      callbackPath: '/signin-oidc',
      requireHttps: false,
      sessionTtlSeconds: 1800,
      accountSwitch: { requireArkClaims: true, appDisplayName: 'Billing' }
    });
  });

  test('accepts the snake spelling and a space-separated scope string', () => {
    const options = ArkAuthConfig.fromMapping({ authority: 'https://idp.example.com/t', client_id: 'x', scopes: 'openid profile', auth_error_path: '/oops' });
    assert.deepEqual(options, { authority: 'https://idp.example.com/t', clientId: 'x', scopes: ['openid', 'profile'], errorPath: '/oops' });
  });
});
