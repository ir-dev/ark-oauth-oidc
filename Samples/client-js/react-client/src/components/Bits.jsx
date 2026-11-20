import { useState } from 'react';

/** A centred "working on it" message, for loading and callback routes. */
export function Busy({ children }) {
  return (
    <div className="busy" role="status" aria-live="polite">
      <span className="spinner" aria-hidden="true" />
      <span>{children}</span>
    </div>
  );
}

/** A small coloured label. tone: ok | warn | bad | info | muted */
export function Pill({ tone = 'muted', children }) {
  return <span className={`pill pill-${tone}`}>{children}</span>;
}

function useCopy() {
  const [copied, setCopied] = useState(false);
  const copy = async (value) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1400);
    } catch {
      // clipboard refused (not a secure context, or permission): the value is still selectable
    }
  };
  return [copied, copy];
}

/** An exact value to paste somewhere, with a copy button. */
export function CopyValue({ value }) {
  const [copied, copy] = useCopy();
  return (
    <span className="copy-value">
      <code>{value}</code>
      <button type="button" className="copy-btn" onClick={() => copy(value)} aria-label={`Copy ${value}`}>
        {copied ? 'Copied' : 'Copy'}
      </button>
    </span>
  );
}

/** A block of commands or code, with a copy button. */
export function CodeBlock({ code, label }) {
  const [copied, copy] = useCopy();
  return (
    <div className="code-block">
      {label && <div className="code-label">{label}</div>}
      <pre>
        <code>{code}</code>
      </pre>
      <button type="button" className="copy-btn floating" onClick={() => copy(code)} aria-label="Copy to clipboard">
        {copied ? 'Copied' : 'Copy'}
      </button>
    </div>
  );
}

/** Field → value rows, e.g. what to type into the wizard. */
export function FieldTable({ rows }) {
  return (
    <table className="field-table">
      <tbody>
        {rows.map(([field, value, note]) => (
          <tr key={field}>
            <th scope="row">{field}</th>
            <td>
              {typeof value === 'string' ? <CopyValue value={value} /> : value}
              {note && <div className="note">{note}</div>}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
