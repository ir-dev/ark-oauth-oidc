import { useState } from 'react';
import { LIBRARIAN_CLAIM, addBook, giveBack, resetLibrary, useLibrary } from '../library.js';

/**
 * Needs the Ark claim library.librarian (the route is wrapped in <Guard claims={[…]}>). The claim
 * comes from the IdP's access mapping for this user and this client, and arrives in the access
 * token as `ark_claims`. An API would check that same claim on every call.
 */
export default function Desk() {
  const { books } = useLibrary();
  const out = books.filter((book) => book.loan);
  const [form, setForm] = useState({ title: '', author: '', year: '' });

  const submit = (event) => {
    event.preventDefault();
    if (!form.title.trim() || !form.author.trim()) return;
    addBook(form);
    setForm({ title: '', author: '', year: '' });
  };

  return (
    <section>
      <div className="page-head">
        <h1>Librarian desk</h1>
        <p className="lede">
          You are here because your access token carries <code>{LIBRARIAN_CLAIM}</code>.
        </p>
      </div>

      <div className="grid-2">
        <div className="panel">
          <h2>Out on loan ({out.length})</h2>
          {out.length === 0 ? (
            <p className="note">Every book is on the shelf.</p>
          ) : (
            <table className="loans-table">
              <thead>
                <tr>
                  <th scope="col">Book</th>
                  <th scope="col">Borrower</th>
                  <th scope="col"><span className="sr-only">Action</span></th>
                </tr>
              </thead>
              <tbody>
                {out.map((book) => (
                  <tr key={book.id}>
                    <td>{book.title}</td>
                    <td>
                      {book.loan.name}
                      <div className="note">{new Date(book.loan.at).toLocaleDateString()}</div>
                    </td>
                    <td>
                      <button type="button" className="btn small ghost" onClick={() => giveBack(book.id)}>Check in</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <form className="panel" onSubmit={submit}>
          <h2>Add a book</h2>
          <label className="field">
            <span>Title</span>
            <input value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} required />
          </label>
          <label className="field">
            <span>Author</span>
            <input value={form.author} onChange={(e) => setForm({ ...form, author: e.target.value })} required />
          </label>
          <label className="field">
            <span>Year</span>
            <input value={form.year} onChange={(e) => setForm({ ...form, year: e.target.value })} inputMode="numeric" />
          </label>
          <div className="row">
            <button type="submit" className="btn primary">Add to the shelf</button>
            <button type="button" className="btn ghost" onClick={resetLibrary}>Reset the sample data</button>
          </div>
        </form>
      </div>
    </section>
  );
}
