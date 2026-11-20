import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, useNavigate } from 'react-router';
import { ArkProvider } from 'ark-oauth-client-js/react';
import { ark } from './ark.js';
import App from './App.jsx';
import './styles.css';

// <ArkProvider> sits INSIDE the router, so the return after sign-in (and after sign-out) goes
// through the router's navigate instead of a full page load. It starts the client once: on
// /signin-oidc that completes the sign-in, anywhere else it restores the session from the last
// visit, refreshing it if the access token expired while the tab was closed.
function AuthRoot() {
  const navigate = useNavigate();

  // Not configured yet: render the app without auth so the landing page and its guide still work.
  if (!ark) return <App />;

  return (
    <ArkProvider
      client={ark}
      onRedirectCallback={(to, result) => navigate(to, { replace: true, state: result?.signedOut ? { signedOut: true } : null })}
    >
      <App />
    </ArkProvider>
  );
}

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <BrowserRouter>
      <AuthRoot />
    </BrowserRouter>
  </StrictMode>
);
