import { useEffect, useState } from 'react';
import { decodeJwt } from 'ark-oauth-client-js';
import { useArk } from 'ark-oauth-client-js/react';
import { CodeBlock, Pill } from '../components/Bits.jsx';
import { signOut } from '../ark.js';

/**
 * What the app holds for the signed-in user. Inside <Guard>, so there is always a user here.
 *
 * The access token is read with getAccessToken() each time it is needed, never kept in state for
 * later: the client replaces it underneath you on every refresh.
 */
export default function Session() {
  const ark = useArk();
  const { client, user, arkClaims, scopes, expiresAt } = ark;
  const [accessClaims, setAccessClaims] = useState(null);
  const [userInfo, setUserInfo] = useState({ busy: false, data: null, error: null });
  const [events, setEvents] = useState([]);
  const now = useNow();

  // Decode the current access token for display whenever it changes (expiresAt moves on refresh).
  useEffect(() => {
    let live = true;
    client.getAccessToken().then((token) => {
      if (live && token) setAccessClaims(decodeJwt(token).payload);
    });
    return () => {
      live = false;
    };
  }, [client, expiresAt]);

  // The client's events, as a log.
  useEffect(() => {
    const log = (name) => () => setEvents((list) => [{ name, at: new Date() }, ...list].slice(0, 6));
    const off = ['tokensRefreshed', 'refreshFailed', 'sessionExpired'].map((name) => client.on(name, log(name)));
    return () => off.forEach((unsubscribe) => unsubscribe());
  }, [client]);

  const callUserInfo = async () => {
    setUserInfo({ busy: true, data: null, error: null });
    try {
      setUserInfo({ busy: false, data: await client.userInfo(), error: null });
    } catch (error) {
      setUserInfo({ busy: false, data: null, error });
    }
  };

  const secondsLeft = expiresAt ? Math.max(0, Math.round(expiresAt - now / 1000)) : null;

  return (
    <section>
      <div className="page-head">
        <h1>Your session</h1>
        <p className="lede">What this app received from the IdP, and what it does with it.</p>
      </div>

      <div className="grid-2">
        <div className="panel">
          <h2>Who you are</h2>
          <p className="note">The ID token's claims, verified in the browser (signature, issuer, audience, expiry, nonce).</p>
          <Claims value={user} />
        </div>

        <div className="stack">
          <div className="panel">
            <h2>What you may do</h2>
            <p className="note">Ark claims for this client, from your access mapping. Authorise against these, not scopes.</p>
            <p className="claims">{arkClaims.length ? arkClaims.map((c) => <code key={c}>{c}</code>) : <span className="note">none</span>}</p>
            <p className="note">Granted scopes</p>
            <p className="claims">{scopes.map((s) => <code key={s}>{s}</code>)}</p>
          </div>

          <div className="panel">
            <h2>Access token</h2>
            <p>
              Expires in <strong>{secondsLeft == null ? 'n/a' : formatDuration(secondsLeft)}</strong>. It is renewed with the
              refresh token shortly before then, in the background, while the tab is open.
            </p>
            <div className="row">
              <button type="button" className="btn" onClick={() => client.getAccessToken({ forceRefresh: true }).catch(() => {})}>
                Refresh now
              </button>
              <button type="button" className="btn" onClick={callUserInfo} disabled={userInfo.busy}>
                {userInfo.busy ? 'Calling…' : 'Call the userinfo API'}
              </button>
              <button type="button" className="btn ghost" onClick={() => signOut()}>Sign out</button>
            </div>
            {events.length > 0 && (
              <ul className="events">
                {events.map((event) => (
                  <li key={`${event.name}-${event.at.getTime()}`}>
                    <Pill tone={event.name === 'tokensRefreshed' ? 'ok' : 'warn'}>{event.name}</Pill> {event.at.toLocaleTimeString()}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </div>

      <div className="grid-2">
        <div className="panel">
          <h2>Calling an API</h2>
          <p className="note">
            This sample has no API of its own, so the button above calls the IdP's userinfo endpoint, a real API protected by
            the access token. The response:
          </p>
          {userInfo.error && <p className="error-text">{userInfo.error.message}</p>}
          {userInfo.data ? <pre className="json">{JSON.stringify(userInfo.data, null, 2)}</pre> : <p className="note">Not called yet.</p>}
          <p className="note">Your own API, with its origin listed in <code>apiOrigins</code> in <code>src/ark.js</code>:</p>
          <CodeBlock
            code={`const { fetch } = useArk();\n// Bearer token attached, refreshed first if it is due:\nconst res = await fetch('https://api.example.com/loans');`}
          />
        </div>

        <div className="panel">
          <h2>Inside the access token</h2>
          <p className="note">
            Decoded for display only. The app never reads authorisation from here: the API validates the token's signature and{' '}
            <code>ark_claims</code> itself.
          </p>
          <Claims value={accessClaims} />
        </div>
      </div>
    </section>
  );
}

function Claims({ value }) {
  if (!value) return <p className="note">…</p>;
  return (
    <table className="claims-table">
      <tbody>
        {Object.entries(value).map(([key, claim]) => (
          <tr key={key}>
            <th scope="row"><code>{key}</code></th>
            <td>{formatClaim(key, claim)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function formatClaim(key, value) {
  if (['exp', 'iat', 'nbf', 'auth_time'].includes(key) && typeof value === 'number') {
    return `${value} (${new Date(value * 1000).toLocaleString()})`;
  }
  return typeof value === 'object' ? JSON.stringify(value) : String(value);
}

function formatDuration(seconds) {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return m ? `${m} min ${String(s).padStart(2, '0')} s` : `${s} s`;
}

function useNow() {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);
  return now;
}
