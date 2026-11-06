import { useEffect, useState } from 'react';
import { api } from '../api.js';
import { ErrorLine, Confirm } from '../ui.jsx';

export default function Tokens({ me }) {
  const [tokens, setTokens] = useState(null);
  const [form, setForm] = useState({ name: '', role: 'viewer' });
  const [minted, setMinted] = useState(null);
  const [error, setError] = useState('');

  const load = () =>
    api('GET', '/tokens')
      .then(setTokens)
      .catch((e) => setError(e.message));

  useEffect(() => {
    load();
  }, []);

  async function mint(e) {
    e.preventDefault();
    setError('');
    try {
      setMinted(await api('POST', '/tokens', form));
      setForm({ ...form, name: '' });
      load();
    } catch (err) {
      setError(err.message);
    }
  }

  async function revoke(id) {
    setError('');
    try {
      await api('DELETE', `/tokens/${id}`);
      load();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="stack">
      <section className="card">
        <h2>API tokens</h2>
        <p className="muted">
          Revoking a token takes effect on its next request. You cannot revoke the
          token you are signed in with.
        </p>
        <ErrorLine error={error} />
        {!tokens ? (
          <p className="muted">Loading…</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Role</th>
                <th>Created</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {tokens.map((t) => (
                <tr key={t.id}>
                  <td>
                    {t.name} {t.name === me.name && <span className="muted">(you)</span>}
                  </td>
                  <td><span className="pill">{t.role}</span></td>
                  <td>{t.created_at}</td>
                  <td>
                    {t.name !== me.name && (
                      <Confirm label="revoke" onConfirm={() => revoke(t.id)} />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="card">
        <h2>Mint a token</h2>
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
