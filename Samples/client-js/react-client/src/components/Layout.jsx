import { useEffect } from 'react';
import { Link, NavLink, Outlet, useLocation } from 'react-router';
import { VERSION } from 'ark-oauth-client-js';
import { signOut, useSession } from '../ark.js';
import { displayName } from '../library.js';

export default function Layout() {
  useScrollToHash();
  return (
    <div className="app">
      <header className="topbar">
        <div className="topbar-inner">
          <Link to="/" className="brand" aria-label="Team Library home">
            <img src="/favicon.svg" alt="" width="28" height="28" />
            <span>Team Library</span>
          </Link>
          <nav className="nav" aria-label="Main">
            <NavLink to="/" end>Home</NavLink>
            <NavLink to="/shelf">Shelf</NavLink>
            <NavLink to="/loans">My loans</NavLink>
            <NavLink to="/desk">Librarian desk</NavLink>
            <NavLink to="/session">Session</NavLink>
          </nav>
          <SessionChip />
        </div>
      </header>
      <main className="content">
        <Outlet />
      </main>
      <footer className="footer">
        <span>
          A sample for <a href="https://www.npmjs.com/package/ark-oauth-client-js" target="_blank" rel="noreferrer">ark-oauth-client-js</a> {VERSION}.
        </span>
        <span>No server: the sign-in, the tokens and the library all live in this browser.</span>
      </footer>
    </div>
  );
}

function SessionChip() {
  const session = useSession();
  if (session.status === 'unconfigured') {
    return <Link className="chip chip-warn" to="/#guide">Not connected</Link>;
  }
  if (session.isLoading) return <span className="chip">Checking…</span>;
  if (session.isAuthenticated) {
    const name = displayName(session.user);
    return (
      <div className="chip-group">
        <Link className="chip" to="/session" title={session.user.email ?? name}>
          <span className="avatar" aria-hidden="true">{name.slice(0, 1).toUpperCase()}</span>
          <span className="chip-name">{name}</span>
        </Link>
        <button type="button" className="btn small" onClick={() => signOut()}>Sign out</button>
      </div>
    );
  }
  return (
    <button type="button" className="btn small primary" onClick={() => session.signinRedirect()}>
      Sign in
    </button>
  );
}

/** /#guide from another page: scroll to the anchor once the page has rendered. */
function useScrollToHash() {
  const { hash, pathname } = useLocation();
  useEffect(() => {
    if (!hash) {
      window.scrollTo(0, 0);
      return;
    }
    const target = document.getElementById(decodeURIComponent(hash.slice(1)));
    if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, [hash, pathname]);
}
