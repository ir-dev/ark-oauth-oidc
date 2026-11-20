import { Link, useLocation } from 'react-router';
import { ArkCallbackError, ArkNetworkError, ArkOAuthError, ArkTokenError } from 'ark-oauth-client-js';
import { ArkCallback, RequireArk, useArk } from 'ark-oauth-client-js/react';
import { ark, signOut, switchAccount, useLeaving } from '../ark.js';
import { settings } from '../config.js';
import { Busy } from './Bits.jsx';

/**
 * A page that needs a signed-in user (and, with `claims`, Ark claims). <RequireArk> does the work:
 * a signed-out visitor is sent to the IdP and brought back here; a user missing a claim gets the
 * "You do not have access" page with "Sign in as a different user" (prompt=login), which is the
 * way out on a shared browser where SSO signed in the previous person.
 *
 * While a sign-out or account switch is under way, <RequireArk> is not rendered at all, so it
 * cannot start a sign-in of its own in the moment the local session is gone (see src/ark.js).
 *
 * Hiding a page is UI, not security: an API behind this app must check the token itself.
 */
export function Guard({ claims, children }) {
  const leaving = useLeaving();
  if (!ark) return <NeedsSetup />;
  if (leaving) return <Busy>{leaving === 'switch' ? 'Switching account…' : 'Signing you out…'}</Busy>;
  return (
    <RequireArk
      claims={claims}
      fallback={<Busy>Checking your sign-in…</Busy>}
      forbidden={() => <Forbidden claims={claims} />}
      error={(error, retry) => <SignInError error={error} retry={retry} />}
    >
      {children}
    </RequireArk>
  );
}

/** The redirect URI's route. The provider completes the sign-in; this shows progress or the error. */
export function Callback() {
  if (!ark) return <NeedsSetup />;
  return (
    <ArkCallback error={(error, retry) => <SignInError error={error} retry={retry} />}>
      <Busy>Signing you in…</Busy>
    </ArkCallback>
  );
}

function NeedsSetup() {
  return (
    <section className="panel narrow">
      <h1>Connect the app first</h1>
      <p>
        This page needs a signed-in user, and the app does not know which identity provider to use yet.
        Follow the guide on the home page; it takes about five minutes with the QuickStart IdP.
      </p>
      <Link className="btn primary" to="/#guide">Open the setup guide</Link>
    </section>
  );
}

/**
 * The "no access" page. The same content as the library's <ArkAccessDenied>, but its two buttons go
 * through switchAccount() / signOut() from src/ark.js, which take this page out of <RequireArk>
 * first. With <ArkAccessDenied>'s own buttons, the guard around it would start a plain sign-in in
 * the moment the session is dropped and could win over the prompt=login one.
 */
function Forbidden({ claims }) {
  const { user } = useArk();
  const { pathname } = useLocation();
  const who = user?.email ?? user?.preferred_username ?? user?.name ?? user?.sub;
  return (
    <div className="stack narrow">
      <section className="panel denied" role="alert">
        <h1>You do not have access to the librarian desk</h1>
        <p>
          You are signed in as <strong>{who}</strong>, and that account does not have access to the librarian desk.
        </p>
        <p className="note">
          If somebody else was using this browser, their sign-in is still active and it is the one being offered to this
          app. Choose “Sign in as a different user” to enter your own credentials.
        </p>
        <div className="row">
          <button type="button" className="btn primary" onClick={() => switchAccount({ returnTo: pathname })}>
            Sign in as a different user
          </button>
          <button type="button" className="btn" onClick={() => signOut()}>Sign out completely</button>
        </div>
      </section>
      <aside className="panel dev-note">
        <h2>For the developer</h2>
        <p>
          This page needs the Ark claim{claims.length > 1 ? 's' : ''} <code>{claims.join(', ')}</code> for the client{' '}
          <code>{settings.clientId}</code>. In the IdP's admin console open <b>Manage → Access mapping</b>, pick your user
          and tenant, add the claim to the row for this client and <b>Save</b>. Claims are read at sign-in, so sign out
          and in again afterwards.
        </p>
      </aside>
    </div>
  );
}

/** What went wrong with a sign-in, in words, with the likely fix. */
export function SignInError({ error, retry }) {
  return (
    <section className="panel narrow" role="alert">
      <h1>Sign-in did not complete</h1>
      <p className="error-text">{error?.message ?? String(error)}</p>
      <p>{hintFor(error)}</p>
      <div className="row">
        <button type="button" className="btn primary" onClick={retry}>Try again</button>
        <Link className="btn" to="/#check">Run the setup check</Link>
      </div>
    </section>
  );
}

// instanceof, not error.name: a production build minifies class names.
export function hintFor(error) {
  const origin = window.location.origin;
  if (error instanceof ArkNetworkError) {
    return `The IdP could not be reached from this page. Most often that is CORS: ${origin} must be listed in the IdP's ark_oauth_server:Oidc:CorsOrigins (guide step 2). Otherwise the IdP is not running, or the browser does not trust its certificate (dotnet dev-certs https --trust).`;
  }
  if (error instanceof ArkCallbackError) {
    return 'The answer from the IdP could not be matched to a sign-in started in this tab (it expired, or began in another tab). Try again from here.';
  }
  if (error instanceof ArkTokenError) {
    return "A token came back but did not validate. Check that the authority is exactly the issuer the IdP publishes, and that this machine's clock is right.";
  }
  if (error instanceof ArkOAuthError) {
    if (['invalid_client', 'unauthorized_client'].includes(error.error)) {
      return `The IdP does not accept client "${settings.clientId}". Check the client id, that the client is active, and that it is a public client (token_endpoint_auth_method "none") with the authorization_code and refresh_token grants.`;
    }
    if (error.error === 'invalid_scope') {
      return 'A scope the client is not registered for was requested. Scopes on an Ark client are a whitelist: register openid, profile, email and offline_access.';
    }
    if (/redirect/i.test(`${error.errorDescription ?? ''} ${error.message ?? ''}`)) {
      return `The redirect URI is not registered byte for byte. Register ${origin}/signin-oidc on the client.`;
    }
    if (error.error === 'access_denied') {
      return 'The sign-in was cancelled or refused. If the password was right, the user is probably not mapped to this client.';
    }
    return 'The IdP refused the request; its description is above.';
  }
  return 'The setup check usually names the cause.';
}
