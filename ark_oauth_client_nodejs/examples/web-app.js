/**
 * A web application that signs users in — the common case, with no framework at all.
 *
 *   node examples/web-app.js     then open http://localhost:3000
 *
 * The middleware is plain Connect-style, so this file and an Express application differ only in
 * how routes are declared. Register the client with:
 *
 *   redirect_uri              http://localhost:3000/signin-oidc
 *   post_logout_redirect_uri  http://localhost:3000/
 *   grant types               authorization_code, refresh_token
 *   PKCE                      required (it is, for public clients)
 */
import { createServer } from 'node:http';
import { arkExpress } from '../src/index.js';
import { authority, clientId, clientSecret, origin, port, sessionSecret } from './config.js';

const auth = arkExpress({
  authority,
  clientId,
  clientSecret,
  redirectUri: `${origin}/signin-oidc`,
  postLogoutRedirectUri: `${origin}/`,
  scopes: ['openid', 'profile', 'email', 'offline_access'],
  secret: sessionSecret,
  // Only because this example runs on http://localhost. In production the cookie must be Secure.
  cookie: { secure: origin.startsWith('https') },
  requireHttps: origin.startsWith('https')
});

const page = (title, body) => `<!doctype html><meta charset="utf-8"><title>${title}</title>
<style>body{font:16px/1.6 system-ui,sans-serif;max-width:44rem;margin:4rem auto;padding:0 1rem}
code,pre{background:#f4f4f5;padding:.15rem .35rem;border-radius:.25rem}a{color:#2563eb}</style>
<h1>${title}</h1>${body}`;

const routes = {
  '/'(req, res) {
    const ark = req.ark;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end(
      page(
        'Ark OAuth client',
        ark.isAuthenticated
          ? `<p>Signed in as <strong>${ark.user.name ?? ark.sub}</strong> (${ark.sub}).</p>
             <p>Authorization claims: <code>${ark.claims.join(', ') || 'none'}</code></p>
             <p>Scopes: <code>${ark.scopes.join(' ')}</code></p>
             <ul>
               <li><a href="/profile">Everything in the ID token</a></li>
               <li><a href="/billing">A page that needs the <code>billing.admin</code> claim</a></li>
               <li><a href="/api-call">Call a downstream API with the access token</a></li>
               <li><a href="/logout">Sign out</a></li>
             </ul>`
          : '<p>You are not signed in.</p><p><a href="/login">Sign in</a></p>'
      )
    );
  },

  '/profile': [
    auth.requireAuth(),
    (req, res) => {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ user: req.ark.user, claims: req.ark.claims, scopes: req.ark.scopes }, null, 2));
    }
  ],

  // Ark's per-user-per-client authorization claims are what an application authorises against —
  // scopes say what the client asked for, these say what this user may do in it.
  '/billing': [
    auth.requireClaims('billing.admin'),
    (req, res) => {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(page('Billing', '<p>Only holders of <code>billing.admin</code> reach this page.</p><p><a href="/">Back</a></p>'));
    }
  ],

  '/api-call': [
    auth.requireAuth(),
    async (req, res) => {
      // accessToken() renews the token first if it is close to expiring, so a long-lived session
      // never attaches a token that dies mid-flight.
      const response = await fetch(`${origin}/api/me`, { headers: await req.ark.authorize() });
      res.setHeader('Content-Type', 'application/json');
      res.end(await response.text());
    }
  ]
};

const server = createServer((req, res) => {
  auth(req, res, (error) => {
    if (error) {
      res.statusCode = 500;
      return res.end(`error: ${error.message}`);
    }

    const path = new URL(req.url, origin).pathname;
    const handler = routes[path];
    if (!handler) {
      res.statusCode = 404;
      return res.end('not found');
    }

    const chain = [handler].flat();
    let i = 0;
    const step = () => {
      const fn = chain[i++];
      return fn ? fn(req, res, step) : undefined;
    };
    Promise.resolve(step()).catch((e) => {
      res.statusCode = 500;
      res.end(`error: ${e.message}`);
    });
  });
});

server.listen(port, () => {
  console.log(`Ark web example on ${origin}`);
  console.log(`  provider ${authority}`);
  console.log(`  callback ${origin}/signin-oidc  — register exactly this value`);
});
