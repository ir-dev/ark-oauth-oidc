import { Link } from 'react-router';

export default function NotFound() {
  return (
    <section className="panel narrow">
      <h1>Not found</h1>
      <p>There is no page at this address.</p>
      <Link className="btn primary" to="/">Home</Link>
    </section>
  );
}
