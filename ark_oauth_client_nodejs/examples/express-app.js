/**
 * The same application, written the way an Express project would.
 *
 *   npm i express && node examples/express-app.js
 *
 * `arkExpress()` returns a plain middleware, so it mounts with `app.use()` and its guards drop
 * into a route's handler chain like any other.
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
  // Land somewhere useful when a sign-in fails, instead of on a stack trace.
  errorPath: '/'
});

// One line: /login, /signin-oidc and /logout are served, and req.ark is on every other request.
app.use(auth);

app.get('/', (req, res) => {
  if (!req.ark.isAuthenticated) return res.send('<a href="/login">Sign in</a>');
  res.send(`Signed in as ${req.ark.user.name ?? req.ark.sub} — <a href="/logout">sign out</a>`);
});

app.get('/profile', auth.requireAuth(), (req, res) => {
  res.json({ user: req.ark.user, claims: req.ark.claims, scopes: req.ark.scopes });
});

// Ark authorization claims, checked before the handler runs.
app.get('/billing', auth.requireClaims('billing.admin'), (req, res) => {
  res.send('billing');
});

// A downstream call carrying the user's access token, renewed if it is about to expire.
app.get('/orders', auth.requireAuth(), async (req, res) => {
  const upstream = await fetch('https://api.example.com/orders', { headers: await req.ark.authorize() });
  res.status(upstream.status).send(await upstream.text());
});

app.listen(port, () => console.log(`Express example on ${origin}`));
