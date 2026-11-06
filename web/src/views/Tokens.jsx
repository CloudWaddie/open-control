import { useState } from 'react';
import { api } from '../api.js';
import { ErrorLine } from '../ui.jsx';

// Minting only: the API does not list tokens (only hashes are stored, and
// they are not useful to show). Revocation is a planned API addition.
export default function Tokens() {
  const [form, setForm] = useState({ name: '', role: 'viewer' });
  const [minted, setMinted] = useState(null);
  const [error, setError] = useState('');

  async function mint(e) {
    e.preventDefault();
    setError('');
    try {
      setMinted(await api('POST', '/tokens', form));
      setForm({ ...form, name: '' });
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="stack">
      <section className="card">
        <h2>Mint an API token</h2>
        <ErrorLine error={error} />
        <form className="grid" onSubmit={mint}>
          <input
            placeholder="name, e.g. grafana-dashboard"
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
          />
          <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
            <option value="viewer">viewer (read)</option>
            <option value="operator">operator (read + change)</option>
            <option value="admin">admin (all + tokens + audit)</option>
          </select>
          <button disabled={!form.name.trim()}>Mint</button>
        </form>
      </section>

      {minted && (
        <section className="card notice">
          <p>
            Token for <strong>{minted.name}</strong> ({minted.role}). Copy it now:
            it is not shown again and cannot be recovered.
          </p>
          <code className="block">{minted.token}</code>
          <button className="link" onClick={() => setMinted(null)}>dismiss</button>
        </section>
      )}
    </div>
  );
}
