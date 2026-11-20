import { Route, Routes } from 'react-router';
import Layout from './components/Layout.jsx';
import { Busy } from './components/Bits.jsx';
import { Callback, Guard } from './components/Guard.jsx';
import Landing from './pages/Landing.jsx';
import Shelf from './pages/Shelf.jsx';
import Loans from './pages/Loans.jsx';
import Desk from './pages/Desk.jsx';
import Session from './pages/Session.jsx';
import NotFound from './pages/NotFound.jsx';
import { LIBRARIAN_CLAIM } from './library.js';

// Three levels of access, the ones most single-page apps need:
//   /, /shelf        open to everyone
//   /loans, /session signed in
//   /desk            signed in AND holding an Ark claim
//
// The two callback routes must exist in a SPA: the provider does the work, these only render
// while it happens (without them the router would show "not found" mid sign-in).
export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Landing />} />
        <Route path="shelf" element={<Shelf />} />
        <Route path="loans" element={<Guard><Loans /></Guard>} />
        <Route path="session" element={<Guard><Session /></Guard>} />
        <Route path="desk" element={<Guard claims={[LIBRARIAN_CLAIM]}><Desk /></Guard>} />
        <Route path="signin-oidc" element={<Callback />} />
        <Route path="signout-callback-oidc" element={<Busy>Signing you out…</Busy>} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}
