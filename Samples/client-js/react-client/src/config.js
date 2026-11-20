// Where the two settings come from.
//
// A real app reads them from build-time environment variables and nothing else: put
// VITE_ARK_AUTHORITY and VITE_ARK_CLIENT_ID in .env.local (see .env.example).
//
// This sample also lets you paste them into the landing page, so you can start it before the IdP
// exists and connect it once you have followed the guide. Those values are kept in this browser's
// localStorage under SAVED_KEY. That convenience is sample-only: do not copy it into an app.

const SAVED_KEY = 'team-library.ark-settings';

/** The QuickStart IdP with the values the guide asks for in its setup wizard. */
export const QUICKSTART = Object.freeze({
  baseUrl: 'https://localhost:7300',
  tenantId: 'ark_idp',
  clientId: 'team-library'
});

const clean = (value) => (typeof value === 'string' ? value.trim().replace(/\/+$/, '') : '');

function readSaved() {
  try {
    const raw = window.localStorage.getItem(SAVED_KEY);
    const value = raw ? JSON.parse(raw) : null;
    return value && typeof value === 'object' ? value : null;
  } catch {
    return null; // storage blocked (private window) or not JSON: treat as nothing saved
  }
}

/**
 * The settings in effect and where they came from: `source` is 'env' (.env.local), 'browser'
 * (saved from the landing page) or null (not configured yet).
 */
function resolveSettings() {
  const env = {
    authority: clean(import.meta.env.VITE_ARK_AUTHORITY),
    clientId: clean(import.meta.env.VITE_ARK_CLIENT_ID)
  };
  if (env.authority && env.clientId) return { ...env, source: 'env' };

  const saved = readSaved();
  if (saved && clean(saved.authority) && clean(saved.clientId)) {
    return { authority: clean(saved.authority), clientId: clean(saved.clientId), source: 'browser' };
  }
  return { authority: env.authority, clientId: env.clientId, source: null };
}

export const settings = Object.freeze(resolveSettings());

/** Saves settings typed into the landing page, then reloads so the client is built from them. */
export function saveSettings({ authority, clientId }) {
  window.localStorage.setItem(SAVED_KEY, JSON.stringify({ authority: clean(authority), clientId: clean(clientId) }));
  window.location.assign('/');
}

export function forgetSettings() {
  try {
    window.localStorage.removeItem(SAVED_KEY);
  } catch {
    // nothing to forget
  }
  window.location.assign('/');
}

/** `https://host/tenant` → { baseUrl: 'https://host', tenantId: 'tenant' }, for the guide's links. */
export function splitAuthority(authority) {
  const value = clean(authority);
  const cut = value.lastIndexOf('/');
  if (!value || cut < 'https://'.length) return { baseUrl: QUICKSTART.baseUrl, tenantId: QUICKSTART.tenantId };
  return { baseUrl: value.slice(0, cut), tenantId: value.slice(cut + 1) };
}
