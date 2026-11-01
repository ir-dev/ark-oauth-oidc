/**
 * The shared browser.
 *
 *   npm i express && node examples/account-switch.js
 *
 * Single sign-on is browser-wide: once one person has signed in anywhere, the provider's session
 * answers the authorize request of every other client in that browser. The second person opens a
 * different application, is silently signed in as the first, is told they do not have access — and
 * has no way back, because the sign-in link returns to the same session and gives the same answer.
 *
 * This example turns on every part of the way out. Nothing here is on by default; a host that sets
 * none of it behaves exactly as it did before.
 */
import express from 'express';
import { arkExpress } from '../src/index.js';
import { authority, clientId, clientSecret, origin, port, sessionSecret } from './config.js';

const app = express();

const auth = arkExpress({
  authority,
  clientId,
  clientSecret,
  redirectUri: `${origin}/signin-oidc`,
  postLogoutRedirectUri: `${origin}/`,
  secret: sessionSecret,
  cookie: { secure: origin.startsWith('https') },
  requireHttps: origin.startsWith('https'),

  accountSwitch: {
    // The check that makes the case recoverable: an account with no ark_claims for this client is
    // refused at the callback, before the session is written, so the browser never holds a session
    // for somebody who cannot use the application.
    requireArkClaims: true,

    // What the built-in page at /ark/no-access says.
    appDisplayName: 'Billing Portal',
    supportEmail: 'help@example.com',
    showSignedInAccount: true,

    // Local switch (the default): drop our session and challenge with prompt=login, so the person
    // at the keyboard signs in as themselves while the previous user's other tabs are left alone.
    // Set this true for a kiosk, where ending the provider session too is the right call.
    endProviderSessionOnSwitch: false
  },

  events: {
    // A rule of your own, instead of the configured one. Return true to let the sign-in complete.
    onEvaluateAccess: (ctx) => ctx.allowedByConfiguration || ctx.arkClaims.includes('tenant.root'),

    // Called before the redirect to the access-denied page. Log it, raise a request-access ticket,
    // or write a response of your own to draw your own page instead.
    onAccessDenied: (denied) => console.log(`[access denied] ${denied.email} (${denied.reason}) wanted ${denied.returnUrl}`)
  }
});

app.use(auth);

app.get('/', (req, res) => {
  if (!req.ark.isAuthenticated) return res.send('<a href="/login">Sign in</a>');
  res.send(
    `Signed in as ${req.ark.user.email ?? req.ark.sub}. ` +
      // The switch is a POST, as the built-in page sends it.
      '<form method="post" action="/ark/switch-user" style="display:inline">' +
      '<input type="hidden" name="returnUrl" value="/"><button>Not you? Switch user</button></form>'
  );
});

app.get('/billing', auth.requireClaims('billing.admin'), (req, res) => res.send('billing'));

app.listen(port, () => console.log(`Account-switch example on ${origin}`));
