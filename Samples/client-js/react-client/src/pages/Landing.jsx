import { Link, useLocation } from 'react-router';
import { configError, signOut, useSession } from '../ark.js';
import { settings } from '../config.js';
import { LIBRARIAN_CLAIM, displayName } from '../library.js';
import { Pill } from '../components/Bits.jsx';
import { hintFor } from '../components/Guard.jsx';
import SetupGuide from '../components/SetupGuide.jsx';

export default function Landing() {
  const session = useSession();
  const { state } = useLocation();

  return (
    <div className="landing">
      {state?.signedOut && (
        <p className="banner" role="status">
          You are signed out, of this app and of the identity provider. Signing in again asks for your password.
        </p>
      )}

      <section className="hero">
        <div className="hero-text">
          <p className="eyebrow">Ark React sample · browser only</p>
          <h1>Team Library</h1>
          <p className="lede">
            A team's shared bookshelf. Anyone can browse it, members sign in to borrow, and librarians, whose Ark account
            carries the <code>{LIBRARIAN_CLAIM}</code> claim, run the desk. It is a React single-page app with no server of
            its own: it signs in against an Ark identity provider with <code>ark-oauth-client-js</code>, entirely in the
            browser.
          </p>
          <div className="row">
            {session.status === 'unconfigured' ? (
              <a className="btn primary" href="#guide">Set it up</a>
            ) : !session.isAuthenticated ? (
              <button type="button" className="btn primary" onClick={() => session.signinRedirect()} disabled={session.isLoading}>
                Sign in
              </button>
            ) : (
              <Link className="btn primary" to="/shelf">Go to the shelf</Link>
            )}
            <Link className="btn" to="/shelf">Browse the shelf</Link>
            {session.status !== 'unconfigured' && <a className="btn ghost" href="#guide">Setup guide</a>}
          </div>
        </div>
        <ConnectionCard session={session} />
      </section>

      <section aria-labelledby="levels-title">
        <h2 id="levels-title" className="sr-only">What the sample shows</h2>
        <div className="levels">
          <Level
            title="Browse the shelf"
            to="/shelf"
            rule="Open to everyone"
            text="A public page. No sign-in, no token: the same as your marketing or catalogue pages."
            access={{ tone: 'ok', label: 'Open' }}
          />
          <Level
            title="Borrow books"
            to="/loans"
            rule="Signed in"
            text="Wrapped in <RequireArk>: a signed-out visitor goes to the IdP and comes back to this page. Loans are kept against the user's sub."
            access={session.isAuthenticated ? { tone: 'ok', label: 'You are signed in' } : { tone: 'muted', label: 'Needs sign-in' }}
          />
          <Level
            title="Run the librarian desk"
            to="/desk"
            rule={`Ark claim ${LIBRARIAN_CLAIM}`}
            text="<RequireArk claims={[…]}>: without the claim the user sees who they are signed in as, and a way to sign in as someone else."
            access={
              !session.isAuthenticated
                ? { tone: 'muted', label: 'Needs sign-in' }
                : session.hasArkClaims(LIBRARIAN_CLAIM)
                  ? { tone: 'ok', label: 'You hold the claim' }
                  : { tone: 'warn', label: 'You lack the claim' }
            }
          />
        </div>
      </section>

      <SetupGuide />

      <HowItWorks />
      <Troubleshooting />
    </div>
  );
}

function ConnectionCard({ session }) {
  let body;
  if (configError) {
    body = (
      <>
        <Pill tone="bad">Settings refused</Pill>
        <p className="error-text">{configError.message}</p>
        <p>Fix them in step 5 below.</p>
      </>
    );
  } else if (session.status === 'unconfigured') {
    body = (
      <>
        <Pill tone="warn">Not connected</Pill>
        <p>The app does not know which identity provider to use yet. Follow the six steps below; step 5 connects it.</p>
      </>
    );
  } else if (session.isLoading) {
    body = (
      <>
        <Pill tone="info">Connecting…</Pill>
        <p>Restoring your session from <code>{settings.authority}</code>.</p>
      </>
    );
  } else if (session.isAuthenticated) {
    body = (
      <>
        <Pill tone="ok">Signed in</Pill>
        <p className="who">
          <strong>{displayName(session.user)}</strong>
          {session.user.email && session.user.email !== displayName(session.user) && <span>{session.user.email}</span>}
        </p>
        <p className="claims">
          {session.arkClaims.length ? session.arkClaims.map((c) => <code key={c}>{c}</code>) : <span className="note">no Ark claims</span>}
        </p>
        <div className="row">
          <Link className="btn small" to="/session">See the tokens</Link>
          <button type="button" className="btn small ghost" onClick={() => signOut()}>Sign out</button>
        </div>
      </>
    );
  } else {
    body = (
      <>
        <Pill tone="muted">Signed out</Pill>
        {session.error ? (
          <>
            <p className="error-text">{session.error.message}</p>
            <p className="note">{hintFor(session.error)}</p>
          </>
        ) : (
          <p>Connected to the IdP. Sign in to borrow books.</p>
        )}
        <div className="row">
          <button type="button" className="btn small primary" onClick={() => session.signinRedirect()}>Sign in</button>
          {/* A popup must open straight from the click, before any await, or the browser blocks it. */}
          <button type="button" className="btn small" onClick={() => session.signinPopup().catch(() => session.signinRedirect())}>
            Sign in with a popup
          </button>
        </div>
      </>
    );
  }

  return (
    <aside className="panel connection" aria-label="Connection">
      <h2>Connection</h2>
      {body}
      {settings.source && (
        <dl className="kv">
          <dt>Authority</dt>
          <dd><code>{settings.authority}</code></dd>
          <dt>Client</dt>
          <dd><code>{settings.clientId}</code></dd>
          <dt>From</dt>
          <dd>{settings.source === 'env' ? '.env.local / build environment' : 'saved in this browser'}</dd>
        </dl>
      )}
    </aside>
  );
}

function Level({ title, to, rule, text, access }) {
  return (
    <Link className="level" to={to}>
      <span className="level-rule">{rule}</span>
      <strong>{title}</strong>
      <span className="level-text">{text}</span>
      <Pill tone={access.tone}>{access.label}</Pill>
    </Link>
  );
}

function HowItWorks() {
  return (
    <section className="panel prose" aria-labelledby="how-title">
      <h2 id="how-title">How it works without a server</h2>
      <ul>
        <li>
          <b>Public client, authorization code + PKCE.</b> The app has no secret, since anything in a bundle is readable by
          every visitor. A one-time PKCE verifier, held only by this tab, proves to the IdP that the code is being redeemed by the
          page that asked for it.
        </li>
        <li>
          <b>Tokens are verified in the browser.</b> The ID token's signature is checked against the IdP's published keys (Web
          Crypto), along with its issuer, audience, expiry and <code>nonce</code>. Endpoints and keys come from discovery, so a key
          rotation needs no rebuild.
        </li>
        <li>
          <b>The session renews itself with refresh tokens.</b> They are kept in <code>sessionStorage</code>, rotated on every use,
          and refreshes are serialised across tabs, because presenting a spent one revokes the whole family.
        </li>
        <li>
          <b>Sign-out ends both sessions.</b> <code>signoutRedirect()</code> drops the tokens, revokes the refresh token and ends the
          IdP session, so the next sign-in asks for a password again.
        </li>
        <li>
          <b>Calling an API.</b> <code>ark.fetch(url)</code> attaches the access token, refreshing it first if it is due, and sends
          it only to this origin and the origins in <code>apiOrigins</code>. The API validates the token and its{' '}
          <code>ark_claims</code> itself. Hiding a page in the browser is not security. See <Link to="/session">Session</Link> for
          a live call to the IdP's userinfo endpoint.
        </li>
      </ul>
      <p className="note">
        All of the wiring is in <code>src/ark.js</code>, <code>src/main.jsx</code>, <code>src/App.jsx</code> and{' '}
        <code>src/components/Guard.jsx</code>. Everything else is the sample's own UI.
      </p>
    </section>
  );
}

const PROBLEMS = [
  ['"Failed to fetch" / the setup check says CORS', 'This origin is missing from the IdP\'s CorsOrigins (step 2), the IdP is not running, or its certificate is not trusted (dotnet dev-certs https --trust).'],
  ['The password is right but sign-in says it is wrong', 'The user is not mapped to this client. Provisioning does it (step 3), or Manage → Access mapping.'],
  ['"redirect_uri" error on the IdP', 'The registered URI differs by a character. Compare it with what the setup check prints, and open the app at the same host (localhost vs 127.0.0.1).'],
  ['invalid_scope', 'The client record lacks one of openid, profile, email, offline_access. Scopes are a whitelist.'],
  ['Sign-out ends on the IdP\'s own "signed out" page instead of coming back', 'post_logout_redirect_uris is missing or differs by a character (step 4). The IdP only redirects to a registered address, so it stops on its own page. You are signed out either way.'],
  ['Vite says port 5173 is in use', 'Stop the other process. The port is pinned on purpose: it is part of the registered redirect URI.'],
  ['The librarian desk says "no access"', `The user's mapping for this client lacks ${LIBRARIAN_CLAIM}. Add it, then sign out and in again: claims are read at sign-in.`]
];

function Troubleshooting() {
  return (
    <section className="panel" aria-labelledby="trouble-title">
      <h2 id="trouble-title">Troubleshooting</h2>
      <table className="trouble">
        <thead>
          <tr>
            <th scope="col">Symptom</th>
            <th scope="col">Cause and fix</th>
          </tr>
        </thead>
        <tbody>
          {PROBLEMS.map(([symptom, fix]) => (
            <tr key={symptom}>
              <td>{symptom}</td>
              <td>{fix}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
