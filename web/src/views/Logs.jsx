import { useEffect, useRef, useState } from 'react';
import { api } from '../api.js';
import { ErrorLine } from '../ui.jsx';

const MAX_ROWS = 500;

function query(params) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== '' && v != null) q.set(k, v);
  const s = q.toString();
  return s ? `?${s}` : '';
}

// Live tail: newest queries first. "Live" polls for rows newer than the newest
// one on screen, so nothing is fetched twice.
export default function Logs() {
  const [rows, setRows] = useState(null);
  const [action, setAction] = useState('');
  const [client, setClient] = useState('');
  const [live, setLive] = useState(true);
  const [error, setError] = useState('');
  const newest = useRef(0);

  const filters = { action, client };

  // Full reload when filters change.
  useEffect(() => {
    let cancelled = false;
    api('GET', `/logs${query({ ...filters, limit: 200 })}`)
      .then((r) => {
        if (cancelled) return;
        setRows(r);
        newest.current = r[0]?.id ?? 0;
        setError('');
      })
      .catch((e) => !cancelled && setError(e.message));
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [action, client]);

  // Tail: fetch anything newer than what's on screen.
  useEffect(() => {
    if (!live) return;
    const timer = setInterval(() => {
      api('GET', `/logs${query({ ...filters, after: newest.current, limit: 200 })}`)
        .then((fresh) => {
          if (fresh.length === 0) return;
          newest.current = fresh[0].id;
          setRows((prev) => [...fresh, ...(prev || [])].slice(0, MAX_ROWS));
        })
        .catch((e) => setError(e.message));
    }, 2000);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live, action, client]);

  return (
    <section className="card">
      <div className="row between">
        <h2>Query log</h2>
        <label className="inline">
          <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} />
          live
        </label>
      </div>
      <div className="grid">
        <select value={action} onChange={(e) => setAction(e.target.value)}>
          <option value="">all actions</option>
          <option value="block">blocked</option>
          <option value="forward">forwarded</option>
          <option value="rewrite">rewritten</option>
          <option value="refused">refused</option>
          <option value="error">error</option>
        </select>
        <input
          placeholder="client address"
          value={client}
          onChange={(e) => setClient(e.target.value)}
        />
      </div>
      <ErrorLine error={error} />
      {!rows ? (
        <p className="muted">Loading…</p>
      ) : rows.length === 0 ? (
        <p className="muted">No queries yet. Point a device at this resolver.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Client</th>
              <th>Name</th>
              <th>Type</th>
              <th>Action</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td>{new Date(r.ts * 1000).toLocaleTimeString()}</td>
                <td><code>{r.client}</code></td>
                <td className="wrap"><code>{r.qname}</code></td>
                <td>{r.qtype}</td>
                <td><span className={`pill ${r.action}`}>{r.action}</span></td>
                <td className="wrap muted">{r.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
