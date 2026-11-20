import { Link } from 'react-router';
import { useArk } from 'ark-oauth-client-js/react';
import { displayName, giveBack, useLibrary } from '../library.js';

/** Signed in only (the route is wrapped in <Guard>). Loans are matched on the ID token's `sub`. */
export default function Loans() {
  const { user } = useArk(); // inside <Guard>, so the user is always signed in here
  const { books } = useLibrary();
  const mine = books.filter((book) => book.loan?.sub === user.sub);

  return (
    <section>
      <div className="page-head">
        <h1>My loans</h1>
        <p className="lede">
          {displayName(user)}, these are recorded against your subject id <code>{user.sub}</code>, the one value in the
          ID token that never changes for a user.
        </p>
      </div>
      {mine.length === 0 ? (
        <div className="panel empty">
          <p>Nothing borrowed yet.</p>
          <Link className="btn primary" to="/shelf">Pick something from the shelf</Link>
        </div>
      ) : (
        <ul className="books">
          {mine.map((book) => (
            <li key={book.id} className="book">
              <div className="book-spine" aria-hidden="true">{book.title.slice(0, 1)}</div>
              <div className="book-body">
                <strong>{book.title}</strong>
                <span className="note">{book.author}</span>
                <span className="book-state on-loan">Borrowed {new Date(book.loan.at).toLocaleString()}</span>
              </div>
              <button type="button" className="btn small ghost" onClick={() => giveBack(book.id)}>Return</button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
