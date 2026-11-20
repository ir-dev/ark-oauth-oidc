import { Link } from 'react-router';
import { useSession } from '../ark.js';
import { borrow, giveBack, useLibrary } from '../library.js';

/** Public: anyone can browse. Borrowing needs a user, so a signed-out visitor is offered a sign-in. */
export default function Shelf() {
  const session = useSession();
  const { books } = useLibrary();
  const me = session.user?.sub;

  return (
    <section>
      <div className="page-head">
        <h1>The shelf</h1>
        <p className="lede">
          Open to everyone. {session.isAuthenticated ? 'Borrow anything that is free.' : 'Sign in to borrow.'}
        </p>
      </div>
      <ul className="books">
        {books.map((book) => {
          const mine = book.loan && book.loan.sub === me;
          return (
            <li key={book.id} className="book">
              <div className="book-spine" aria-hidden="true">{book.title.slice(0, 1)}</div>
              <div className="book-body">
                <strong>{book.title}</strong>
                <span className="note">
                  {book.author}
                  {book.year ? `, ${book.year}` : ''}
                </span>
                <span className={`book-state${book.loan ? ' on-loan' : ''}`}>
                  {!book.loan ? 'On the shelf' : mine ? 'On loan to you' : `On loan to ${book.loan.name}`}
                </span>
              </div>
              <BookAction book={book} mine={mine} session={session} />
            </li>
          );
        })}
      </ul>
    </section>
  );
}

function BookAction({ book, mine, session }) {
  if (session.status === 'unconfigured') {
    return <Link className="btn small" to="/#guide">Connect to borrow</Link>;
  }
  if (!session.isAuthenticated) {
    return (
      <button type="button" className="btn small" onClick={() => session.signinRedirect({ returnTo: '/shelf' })} disabled={session.isLoading}>
        Sign in to borrow
      </button>
    );
  }
  if (mine) {
    return <button type="button" className="btn small ghost" onClick={() => giveBack(book.id)}>Return</button>;
  }
  if (book.loan) return <span className="note">Unavailable</span>;
  return <button type="button" className="btn small primary" onClick={() => borrow(book.id, session.user)}>Borrow</button>;
}
