import { useState } from 'react';
import { configError } from '../ark.js';
import { forgetSettings, saveSettings, settings } from '../config.js';

/**
 * Shows the settings in effect, and (sample-only) lets you type them in instead of editing
 * .env.local. A real app takes them from the build environment and has no such form.
 */
export default function ConnectForm({ issuer, clientId }) {
  const [editing, setEditing] = useState(!settings.source);
  const [authority, setAuthority] = useState(settings.authority || issuer);
  const [client, setClient] = useState(settings.clientId || clientId);

  const failure = configError && (
    <p className="error-text" role="alert">
      These settings were refused: {configError.message}
    </p>
  );

  if (settings.source === 'env') {
    return (
      <div className="connect">
        {failure}
        <p>
          Connected from <code>.env.local</code> (or the environment at build time): authority{' '}
          <code>{settings.authority}</code>, client <code>{settings.clientId}</code>. Edit the file and restart{' '}
          <code>npm run dev</code> to change them.
        </p>
      </div>
    );
  }

  if (settings.source === 'browser' && !editing) {
    return (
      <div className="connect">
        {failure}
        <p>
          Connected from values saved in this browser: authority <code>{settings.authority}</code>, client{' '}
          <code>{settings.clientId}</code>. A <code>.env.local</code> file, once present, takes precedence.
        </p>
        <div className="row">
          <button type="button" className="btn" onClick={() => setEditing(true)}>Change</button>
          <button type="button" className="btn ghost" onClick={forgetSettings}>Forget them</button>
        </div>
      </div>
    );
  }

  const submit = (event) => {
    event.preventDefault();
    if (authority.trim() && client.trim()) saveSettings({ authority, clientId: client });
  };

  return (
    <form className="connect" onSubmit={submit}>
      {failure}
      <label className="field">
        <span>Authority (the issuer)</span>
        <input value={authority} onChange={(e) => setAuthority(e.target.value)} placeholder={issuer} spellCheck="false" required />
      </label>
      <label className="field">
        <span>Client id</span>
        <input value={client} onChange={(e) => setClient(e.target.value)} placeholder={clientId} spellCheck="false" required />
      </label>
      <div className="row">
        <button type="submit" className="btn primary">Save and connect</button>
        {settings.source === 'browser' && (
          <button type="button" className="btn ghost" onClick={() => setEditing(false)}>Cancel</button>
        )}
      </div>
      <p className="note">Kept in this browser's localStorage, for this sample only. Nothing here is secret.</p>
    </form>
  );
}
