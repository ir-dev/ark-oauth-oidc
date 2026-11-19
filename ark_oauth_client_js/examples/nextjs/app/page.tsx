'use client';
import Link from 'next/link';
import { useArk } from 'ark-oauth-client-js/next';

export default function Home() {
  const { status, user, arkClaims, signinRedirect, signoutRedirect } = useArk();
  return (
    <main>
      <p id="status">{status}</p>
      {user && <p id="email">{user.email}</p>}
      <p id="claims">{arkClaims.join(', ')}</p>
      <button id="signin" onClick={() => signinRedirect()}>Sign in</button>
      <button id="signout" onClick={() => signoutRedirect()}>Sign out</button>
      <Link id="orders-link" href="/orders">Orders</Link>
    </main>
  );
}
