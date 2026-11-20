import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The address this app is served from is part of its registration on the IdP: the redirect URIs
// and the CORS origin are matched byte for byte. So the host and port are pinned, and
// strictPort stops Vite from quietly moving to 5174 when 5173 is busy (which would break sign-in
// with a redirect_uri mismatch). Change all three together if you need another port.
//
// Both servers answer /signin-oidc and /signout-callback-oidc with index.html (SPA history
// fallback), which is all a single-page app needs for its callback routes.
const address = { host: 'localhost', port: 5173, strictPort: true };

export default defineConfig({
  plugins: [react()],
  server: address,
  preview: address
});
