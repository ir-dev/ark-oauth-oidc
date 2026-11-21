import { Link } from 'react-router';
import { QUICKSTART, settings, splitAuthority } from '../config.js';
import { useSession } from '../ark.js';
import { LIBRARIAN_CLAIM } from '../library.js';
import { CodeBlock, CopyValue, FieldTable, Pill } from './Bits.jsx';
import ConnectForm from './ConnectForm.jsx';
import SetupCheck from './SetupCheck.jsx';

/**
 * Six steps from nothing to signed in, against the QuickStart IdP in this repository.
 *
 * Every value is worked out from this page's own origin and the settings in effect, so what it
 * tells you to register is exactly what the app will send.
 */
export default function SetupGuide() {
  const session = useSession();
  const origin = window.location.origin;
  const { baseUrl, tenantId } = settings.source ? splitAuthority(settings.authority) : QUICKSTART;
  const issuer = `${baseUrl}/${tenantId}`;
  const clientId = settings.clientId || QUICKSTART.clientId;
  const consoleUrl = `${issuer}/admin`;
  const provisioningUrl = `${issuer}/admin/provisioning`;
  const redirectUri = `${origin}/signin-oidc`;
  const postLogoutUri = `${origin}/signout-callback-oidc`;

  return (
    <section className="guide" id="guide" aria-labelledby="guide-title">
      <div className="section-head">
        <p className="eyebrow">Step by step</p>
        <h2 id="guide-title">Get it running against the QuickStart IdP</h2>
        <p className="lede">
          About five minutes. You start the identity provider from this repository, register this app on it as a
          client, then point the app at it. You need the .NET 10 SDK and Node 20.19 or later.
        </p>
      </div>

      <Flow origin={origin} issuer={issuer} />

      <ol className="steps">
        <Step n={1} title="Start the QuickStart identity provider">
          <p>
            <code>Ark.oAuth.Oidc.QuickStart</code> is a complete IdP with nothing configured: two lines of C# and a setup
            wizard. From the repository root:
          </p>
          <CodeBlock code={'dotnet dev-certs https --trust\ncd Ark.oAuth.Oidc/Ark.oAuth.Oidc.QuickStart\ndotnet run'} />
          <p>
            It opens <a href={baseUrl} target="_blank" rel="noreferrer">{baseUrl}</a>, which serves the setup wizard
            while nothing is configured. Trust the development certificate first: this app calls the IdP with{' '}
            <code>fetch()</code>, and the browser reports an untrusted certificate there only as "Failed to fetch".
          </p>
        </Step>

        <Step n={2} title="Run the setup wizard">
          <p>Defaults are fine wherever this table says nothing. The values that matter:</p>
          <FieldTable
            rows={[
              ['Organization name', 'Team Library Demo', 'Anything. It appears on the sign-in page.'],
              ['Public URL', QUICKSTART.baseUrl],
              ['Tenant id', QUICKSTART.tenantId, <>The issuer becomes <code>{QUICKSTART.baseUrl}/{QUICKSTART.tenantId}</code>.</>],
              ['Database', <b key="db">SQLite</b>, 'A single file beside the settings. Nothing to install.'],
              ['Signing key', <b key="key">Generate key pair</b>, 'Click it before Continue. 2048 bits is fine.'],
              ['Administrator', <span key="admin">a username and password of your choice</span>, 'You sign in to the console with it, and to this app in step 6.'],
              [
                'Browser origins allowed to call the token endpoint (CORS)',
                origin,
                'On the Protocol & security step. Exactly this: no trailing slash, no wildcard. A single-page app redeems its code from the browser, so the IdP must allow its origin.'
              ]
            ]}
          />
          <p>
            Then <b>Review &amp; install → Install</b>, and <b>Sign in to the admin console</b> from the done screen.
          </p>
          <details className="callout">
            <summary>Wizard already finished, without this origin?</summary>
            <p>
              The wizard runs once. Add the origin to <code>ark-idp-data/settings.json</code> in the QuickStart folder
              instead, keeping everything else in the file. The IdP reads the change without a restart.
            </p>
            <CodeBlock code={`"ark_oauth_server": {\n  "Oidc": {\n    "CorsOrigins": [ "${origin}" ]\n  }\n}`} />
          </details>
        </Step>

        <Step n={3} title="Register this app as a client">
          <p>
            In the console open <b>Provisioning</b> (<a href={provisioningUrl} target="_blank" rel="noreferrer">{provisioningUrl}</a>).
            One click registers the client, reuses or creates the user, and maps the user to the client. Ark maps users to
            clients explicitly, and with no mapping the sign-in fails with what reads exactly like a wrong password.
          </p>
          <FieldTable
            rows={[
              ['Tenant', tenantId],
              ['Application name', 'Team Library'],
              ['client_id', clientId],
              ['application_type', 'spa'],
              ['User name or email', <span key="user">your administrator's username</span>, 'Or a new email address: a new account signs in with the default password from the wizard.'],
              ['redirect_uris', redirectUri],
              [
                'Claims for the mapping',
                `sub, name, email, email_verified, ${LIBRARIAN_CLAIM}`,
                <><code>{LIBRARIAN_CLAIM}</code> opens the librarian desk. Leave it out to see the "no access" page there instead.</>
              ]
            ]}
          />
          <p>
            <b>Provision.</b> The result should say the client and the mapping were created. Provisioning makes a{' '}
            <b>public client</b>: <code>token_endpoint_auth_method: none</code> (no secret), grants{' '}
            <code>authorization_code</code> and <code>refresh_token</code>, scopes{' '}
            <code>openid profile email offline_access</code>, PKCE required.
          </p>
        </Step>

        <Step n={4} title="Add the sign-out return address">
          <p>
            The Provisioning form has no field for it. Open <b>Manage</b> (<a href={consoleUrl} target="_blank" rel="noreferrer">{consoleUrl}</a>),
            click <b>Edit</b> on the <code>{clientId}</code> row under <b>Clients</b>, and in the editor:
          </p>
          <FieldTable
            rows={[
              ['post_logout_redirect_uris', postLogoutUri],
              ['token_endpoint_auth_method', <code key="m">none (public client)</code>, 'Already set by Provisioning. Check it.'],
              ['grant_types', <code key="g">authorization_code, refresh_token</code>],
              ['scopes', <code key="s">openid, profile, email, offline_access</code>, 'A whitelist: a scope the app asks for but the client lacks is rejected, not dropped. offline_access is what earns the refresh token.']
            ]}
          />
          <p>
            <b>Save client.</b> Both URIs are matched byte for byte: scheme, host, port and path. <code>http://127.0.0.1:5173</code>{' '}
            is a different origin from <code>http://localhost:5173</code>, so open the app at the address you registered.
          </p>
        </Step>

        <Step n={5} title="Point this app at the IdP" done={Boolean(settings.source)}>
          <p>Two values, neither of them a secret. What a real app does, a file next to <code>package.json</code>:</p>
          <CodeBlock
            label=".env.local (copy .env.example)"
            code={`VITE_ARK_AUTHORITY=${issuer}\nVITE_ARK_CLIENT_ID=${clientId}`}
          />
          <p>
            Then restart <code>npm run dev</code>. Or, for this sample only, paste them here and skip the restart:
          </p>
          <ConnectForm issuer={issuer} clientId={clientId} />
        </Step>

        <Step n={6} title="Check, then sign in" done={session.isAuthenticated}>
          <SetupCheck />
          <div className="row spaced">
            {session.client && !session.isAuthenticated && (
              <button type="button" className="btn primary" onClick={() => session.signinRedirect()}>Sign in</button>
            )}
            {session.isAuthenticated && <Pill tone="ok">Signed in. You're done.</Pill>}
          </div>
          <p>
            The first sign-in may ask you to allow offline access: that is the refresh token. If you are still signed in to
            the console, the IdP signs you in here without asking for a password, because that is single sign-on. Then borrow
            a book on the <Link to="/shelf">Shelf</Link>, find it under <Link to="/loans">My loans</Link>, open the{' '}
            <Link to="/desk">Librarian desk</Link>, look at your tokens on <Link to="/session">Session</Link>, and sign out.
          </p>
        </Step>
      </ol>
    </section>
  );
}

function Step({ n, title, done, children }) {
  return (
    <li className={`step${done ? ' step-done' : ''}`}>
      <div className="step-num" aria-hidden="true">{done ? '✓' : n}</div>
      <div className="step-body">
        <h3>
          <span className="sr-only">Step {n}: </span>
          {title}
        </h3>
        {children}
      </div>
    </li>
  );
}

/** The whole protocol in one picture: the browser talks to the IdP, nothing else is involved. */
function Flow({ origin, issuer }) {
  return (
    <figure className="flow" aria-label="How the sign-in flows">
      <div className="flow-node">
        <span className="flow-kind">This app, in the browser</span>
        <code>{origin}</code>
        <span className="flow-sub">public client, no secret</span>
      </div>
      <ol className="flow-arrows">
        <li><span>1</span> redirect to <code>/authorize</code> with PKCE →</li>
        <li><span>2</span> ← back to <code>/signin-oidc</code> with a code</li>
        <li><span>3</span> <code>fetch</code> the code into tokens (CORS) →</li>
        <li><span>4</span> refresh before expiry, sign out at the IdP</li>
      </ol>
      <div className="flow-node">
        <span className="flow-kind">Ark identity provider</span>
        <code>{issuer}</code>
        <span className="flow-sub">QuickStart, on this machine</span>
      </div>
      <figcaption>No server of your own: there is nothing between the two boxes.</figcaption>
    </figure>
  );
}
