import { useEffect, useState } from 'react';
import { api } from '../api.js';
import { ErrorLine } from '../ui.jsx';

export default function Audit() {
  const [entries, setEntries] = useState(null);
  const [error, setError] = useState('');

  const load = () =>
    api('GET', '/audit?limit=200')
      .then(setEntries)
      .catch((e) => setError(e.message));

  useEffect(() => {
    load();
  }, []);

  return (
    <section className="card">
      <div className="row between">
        <h2>Audit log</h2>
        <button className="link" onClick={load}>refresh</button>
      </div>
      <ErrorLine error={error} />
      {!entries ? (
        <p className="muted">Loading…</p>
      ) : entries.length === 0 ? (
        <p className="muted">No activity yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Target</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((a) => (
              <tr key={a.id}>
                <td>{new Date(a.ts * 1000).toLocaleString()}</td>
                <td>{a.actor}</td>
                <td><code>{a.action}</code></td>
                <td className="wrap">{a.target}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
