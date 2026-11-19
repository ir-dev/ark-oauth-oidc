import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, useNavigate } from 'react-router';
import { ArkProvider } from 'ark-oauth-client-js/react';
import { ark } from './ark.js';
import App from './App.jsx';

// The provider sits inside the router so the return after sign-in goes through it.
function AuthRoot() {
  const navigate = useNavigate();
  return (
    <ArkProvider client={ark} onRedirectCallback={(to) => navigate(to, { replace: true })}>
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
