import { useEffect, useState } from 'react';
import { api, can } from '../api.js';
import { ErrorLine, Confirm } from '../ui.jsx';

export default function Blocklists({ me }) {
  const [lists, setLists] = useState(null);
  const [error, setError] = useState('');
  const [form, setForm] = useState({ url: '', format: 'hosts' });
  const writable = can(me.role, 'operator');

  const load = () =>
    api('GET', '/blocklists')
      .then(setLists)
      .catch((e) => setError(e.message));

  useEffect(() => {
    load();
  }, []);

  async function add(e) {
    e.preventDefault();
    setError('');
    try {
      await api('POST', '/blocklists', form);
      setForm({ url: '', format: 'hosts' });
      load();
    } catch (err) {
      setError(err.message);
    }
  }

  async function remove(id) {
    try {
      await api('DELETE', `/blocklists/${id}`);
      load();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="stack">
      <section className="card">
        <h2>Blocklists</h2>
        <p className="muted">
          Subscribed lists are cached on disk and refreshed hourly. Changes take
          effect after the next refresh; a SIGHUP reloads rules immediately.
        </p>
        <ErrorLine error={error} />
        {!lists ? (
          <p className="muted">Loading…</p>
        ) : lists.length === 0 ? (
          <p className="muted">No subscriptions.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>URL</th>
                <th>Format</th>
                <th>Last synced</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {lists.map((l) => (
                <tr key={l.id}>
                  <td className="wrap"><code>{l.url}</code></td>
                  <td>{l.format}</td>
                  <td>{l.last_synced || <span className="muted">never</span>}</td>
                  <td>
                    {writable && <Confirm label="remove" onConfirm={() => remove(l.id)} />}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {writable && (
        <section className="card">
          <h2>Subscribe</h2>
          <form className="grid" onSubmit={add}>
            <input
              placeholder="https://example.org/hosts.txt"
              value={form.url}
              onChange={(e) => setForm({ ...form, url: e.target.value })}
            />
            <select value={form.format} onChange={(e) => setForm({ ...form, format: e.target.value })}>
              <option value="hosts">hosts</option>
              <option value="dnsmasq">dnsmasq</option>
              <option value="adguard">adguard</option>
            </select>
            <button disabled={!form.url.trim()}>Subscribe</button>
          </form>
        </section>
      )}
    </div>
  );
}
