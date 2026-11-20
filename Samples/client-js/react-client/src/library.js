import { useSyncExternalStore } from 'react';

// The library's data. This sample has no server, so it lives in this browser's localStorage and
// stands in for what would be your API. Loans are recorded against the signed-in user's `sub`
// (the stable subject id from the ID token), which is the field to key user data on: email
// addresses and names change, `sub` does not.
//
// In a real app each function below would be a call like
//   await ark.fetch('https://api.example.com/loans', { method: 'POST', body })
// and the API would check the access token, and the `library.librarian` claim inside it, itself.

/** The Ark claim the librarian desk needs. Granted per user, per client, in the IdP's access mapping. */
export const LIBRARIAN_CLAIM = 'library.librarian';

const KEY = 'team-library.data.v1';

const SHELF = [
  { id: 'pride', title: 'Pride and Prejudice', author: 'Jane Austen', year: 1813 },
  { id: 'moby', title: 'Moby-Dick', author: 'Herman Melville', year: 1851 },
  { id: 'frank', title: 'Frankenstein', author: 'Mary Shelley', year: 1818 },
  { id: 'walden', title: 'Walden', author: 'Henry David Thoreau', year: 1854 },
  { id: 'alice', title: "Alice's Adventures in Wonderland", author: 'Lewis Carroll', year: 1865 },
  { id: 'meditations', title: 'Meditations', author: 'Marcus Aurelius', year: 180 },
  { id: 'origin', title: 'On the Origin of Species', author: 'Charles Darwin', year: 1859 },
  { id: 'sherlock', title: 'The Adventures of Sherlock Holmes', author: 'Arthur Conan Doyle', year: 1892 }
];

const EMPTY = Object.freeze({ added: [], loans: {} });

let cache = null;
const listeners = new Set();

function read() {
  if (cache) return cache;
  try {
    const parsed = JSON.parse(window.localStorage.getItem(KEY) ?? 'null');
    cache = parsed && typeof parsed === 'object' ? { added: parsed.added ?? [], loans: parsed.loans ?? {} } : EMPTY;
  } catch {
    cache = EMPTY;
  }
  return cache;
}

function write(next) {
  cache = next;
  try {
    window.localStorage.setItem(KEY, JSON.stringify(next));
  } catch {
    // storage blocked: the change lasts until the page is reloaded
  }
  listeners.forEach((listener) => listener());
}

function subscribe(listener) {
  listeners.add(listener);
  // Another tab changed the library: drop the cache and re-render.
  const onStorage = (event) => {
    if (event.key === KEY) {
      cache = null;
      listener();
    }
  };
  window.addEventListener('storage', onStorage);
  return () => {
    listeners.delete(listener);
    window.removeEventListener('storage', onStorage);
  };
}

/** { books, loans }: every book with its loan (or null), re-rendering on any change. */
export function useLibrary() {
  const data = useSyncExternalStore(subscribe, read, () => EMPTY);
  const books = [...SHELF, ...data.added].map((book) => ({ ...book, loan: data.loans[book.id] ?? null }));
  return { books, loans: data.loans };
}

/** Who a user is, for display: the ID token's name, else email, else the subject id. */
export function displayName(user) {
  return user?.name || user?.email || user?.preferred_username || user?.sub || 'someone';
}

export function borrow(bookId, user) {
  const data = read();
  if (data.loans[bookId]) return;
  write({
    ...data,
    loans: { ...data.loans, [bookId]: { sub: user.sub, name: displayName(user), email: user.email ?? null, at: new Date().toISOString() } }
  });
}

export function giveBack(bookId) {
  const data = read();
  const loans = { ...data.loans };
  delete loans[bookId];
  write({ ...data, loans });
}

export function addBook({ title, author, year }) {
  const data = read();
  const id = `book-${Date.now().toString(36)}`;
  write({ ...data, added: [...data.added, { id, title: title.trim(), author: author.trim(), year: Number(year) || null }] });
}

export function resetLibrary() {
  write(EMPTY);
}
