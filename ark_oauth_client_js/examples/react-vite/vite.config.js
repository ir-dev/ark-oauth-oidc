import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The dev server answers /signin-oidc and /signout-callback-oidc with index.html (history fallback),
// which is all a single-page app needs for its callback routes.
export default defineConfig({ plugins: [react()] });
