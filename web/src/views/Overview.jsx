import { useEffect, useState } from 'react';
import { api } from '../api.js';
import { ErrorLine } from '../ui.jsx';

const WINDOWS = [
  { id: '1h', label: 'last hour' },
  { id: '24h', label: 'last 24 hours' },
  { id: '7d', label: 'last 7 days' },
];

export default function Overview() {
  const [windowId, setWindowId] = useState('1h');
  const [stats, setStats] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    const load = () =>
      api('GET', `/stats?window=${windowId}`)
        .then((s) => {
          if (!cancelled) {
            setStats(s);
            setError('');
          }
        })
        .catch((e) => !cancelled && setError(e.message));
    load();
    const timer = setInterval(load, 10000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [windowId]);

  return (
    <div className="stack">
      <div className="row between">
        <h2>Overview</h2>
        <select value={windowId} onChange={(e) => setWindowId(e.target.value)} style={{ width: 'auto' }}>
          {WINDOWS.map((w) => (
            <option key={w.id} value={w.id}>{w.label}</option>
          ))}
        </select>
      </div>
      <ErrorLine error={error} />
      {!stats ? (
        <p className="muted">Loading…</p>
      ) : (
        <>
          <div className="cards">
            <Card label="Queries" value={stats.total.toLocaleString()} />
            <Card label="Blocked" value={stats.blocked.toLocaleString()} />
            <Card label="Blocked %" value={`${stats.blocked_pct.toFixed(1)}%`} />
          </div>
          <div className="split">
            <TopList title="Top blocked domains" rows={stats.top_blocked} empty="Nothing blocked in this window." />
            <TopList title="Top clients" rows={stats.top_clients} empty="No traffic in this window." />
          </div>
          <TopList title="Most queried domains" rows={stats.top_domains} empty="No traffic in this window." />
        </>
      )}
    </div>
  );
}

function Card({ label, value }) {
  return (
    <div className="card stat">
      <div className="muted">{label}</div>
      <div className="big">{value}</div>
    </div>
  );
}

function TopList({ title, rows, empty }) {
  return (
    <section className="card">
      <h2>{title}</h2>
      {rows.length === 0 ? (
        <p className="muted">{empty}</p>
      ) : (
        <table>
          <tbody>
            {rows.map((r) => (
              <tr key={r.key}>
                <td className="wrap"><code>{r.key}</code></td>
                <td style={{ textAlign: 'right' }}>{r.count.toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
