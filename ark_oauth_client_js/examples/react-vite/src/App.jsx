import { Link, Route, Routes } from 'react-router';
import { ArkCallback, RequireArk, useArk } from 'ark-oauth-client-js/react';

function Home() {
  const { status, user, arkClaims, signinRedirect, signinPopup, signoutRedirect } = useArk();
  return (
    <main>
      <p>Status: {status}</p>
      {user && <p>Signed in as {user.email} with claims {arkClaims.join(', ') || '(none)'}</p>}
      <button onClick={() => signinRedirect()}>Sign in</button>
      <button onClick={() => signinPopup()}>Sign in with a popup</button>
      <button onClick={() => signoutRedirect()}>Sign out</button>
      <p><Link to="/orders">Orders</Link> (needs the billing.admin claim)</p>
    </main>
  );
}

function Orders() {
  const { fetch } = useArk();
  // fetch() attaches the access token (refreshed as needed) to this origin and apiOrigins only.
  const load = async () => console.log(await (await fetch('/api/orders')).json());
  return <button onClick={load}>Load orders</button>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/orders" element={<RequireArk fallback={<p>Loading…</p>} claims={['billing.admin']}><Orders /></RequireArk>} />
      {/* The redirect URI needs a route in a SPA: the provider completes the sign-in, this only shows progress. */}
      <Route path="/signin-oidc" element={<ArkCallback><p>Signing you in…</p></ArkCallback>} />
      <Route path="/signout-callback-oidc" element={<p>Signing you out…</p>} />
    </Routes>
  );
}
