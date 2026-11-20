import { useState } from 'react';
import { ark } from '../ark.js';
import { CopyValue, Pill } from './Bits.jsx';

/**
 * ark.checkSetup(): reads discovery and the signing keys, and probes the token endpoint with a
 * refresh token that cannot exist. An OAuth error back proves the endpoint answers this origin
 * (CORS is right) and says whether the client id is accepted. Nothing is created on the IdP.
 */
export default function SetupCheck() {
  const [run, setRun] = useState({ busy: false, report: null, error: null });

  if (!ark) {
    return <p className="note">Available once the app is connected (step 5).</p>;
  }

  const start = async () => {
    setRun({ busy: true, report: null, error: null });
    try {
      setRun({ busy: false, report: await ark.checkSetup(), error: null });
    } catch (error) {
      setRun({ busy: false, report: null, error });
    }
  };

  const { busy, report, error } = run;
  const clientRefused = report?.problems.some((p) => p.includes('refused client'));

  return (
    <div className="check" id="check">
      <button type="button" className="btn" onClick={start} disabled={busy}>
        {busy ? 'Checking…' : report ? 'Run the check again' : 'Run the setup check'}
      </button>
      {error && <p className="error-text">{error.message}</p>}
      {report && (
        <>
          <ul className="check-list">
            <Row ok={report.discoveryOk} label="IdP reachable (discovery document)">
              <a href={report.discoveryUrl} target="_blank" rel="noreferrer">{report.discoveryUrl}</a>
            </Row>
            <Row ok={report.jwksOk} label="Signing keys published (JWKS)">
              {report.jwksOk ? `${report.signingKeys.length} key(s)` : 'not read'}
            </Row>
            <Row ok={report.tokenEndpointCorsOk} label={`Token endpoint answers ${report.origin} (CORS)`}>
              {report.tokenEndpointCorsOk === false ? 'add this origin to CorsOrigins (step 2)' : null}
            </Row>
            <Row ok={report.tokenEndpointCorsOk ? !clientRefused : null} label={`Client "${report.clientId}" accepted`}>
              {clientRefused ? 'see the problem below (steps 3 and 4)' : null}
            </Row>
          </ul>
          {report.problems.length > 0 ? (
            <div className="problems" role="alert">
              <strong>What to fix</strong>
              <ul>
                {report.problems.map((problem) => <li key={problem}>{problem}</li>)}
              </ul>
            </div>
          ) : (
            <p className="all-good">Everything the browser can check is in order. Sign in.</p>
          )}
          <p className="note">
            What this app sends, to compare byte for byte with the client record:
            redirect URI <CopyValue value={report.redirectUri} /> and post-logout redirect URI{' '}
            <CopyValue value={report.postLogoutRedirectUri ?? '(none)'} />.
            The IdP's own page for this client:{' '}
            <a href={report.integrationPageUrl} target="_blank" rel="noreferrer">integration page</a>.
            The check cannot see the redirect URIs or the user mapping: those show up at sign-in. Its probe of the
            token endpoint is refused on purpose, so the browser console shows one 400 from it; that is expected.
          </p>
        </>
      )}
    </div>
  );
}

function Row({ ok, label, children }) {
  const tone = ok === true ? 'ok' : ok === false ? 'bad' : 'muted';
  const word = ok === true ? 'OK' : ok === false ? 'Fix' : 'Not checked';
  return (
    <li>
      <Pill tone={tone}>{word}</Pill>
      <span className="check-label">{label}</span>
      {children && <span className="check-detail">{children}</span>}
    </li>
  );
}
