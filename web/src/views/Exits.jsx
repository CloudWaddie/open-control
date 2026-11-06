import { useEffect, useState } from 'react';
import { api, can } from '../api.js';
import { ErrorLine, Confirm } from '../ui.jsx';

// Exit nodes are egress points for redirect rules. "down" exits are skipped and
// their queries resolve normally; "unknown" (WireGuard, which cannot be probed
// without a tunnel) counts as usable.
export default function Exits({ me }) {
  const [exits, setExits] = useState(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [form, setForm] = useState({ name: '', kind: 'socks5', address: '', answer_ip: '' });
  const writable = can(me.role, 'operator');

  const load = () =>
    api('GET', '/exits')
      .then(setExits)
      .catch((e) => setError(e.message));

  useEffect(() => {
    load();
  }, []);

  async function add(e) {
    e.preventDefault();
    setError('');
    setNotice('');
    try {
      await api('POST', '/exits', form);
      setForm({ name: '', kind: 'socks5', address: '', answer_ip: '' });
      load();
    } catch (err) {
      setError(err.message);
    }
  }

  async function check(id) {
    setError('');
    try {
      const ex = await api('POST', `/exits/${id}/check`);
      setNotice(`${ex.name} is ${ex.health}`);
      load();
    } catch (err) {
      setError(err.message);
    }
  }

  async function remove(id) {
    setError('');
    try {
      const res = await api('DELETE', `/exits/${id}`);
      setNotice(`Deleted. ${res.removed_rules} redirect rule(s) that pointed at it were removed.`);
      load();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="stack">
      <section className="card">
        <h2>Exit nodes</h2>
        <p className="muted">
          A redirect rule answers matching names with an exit's address, so that
          traffic goes out through that exit. The answer address must route to the
          exit on your network. Health is checked every 30 seconds; a down exit is
          skipped and queries resolve normally.
        </p>
        <ErrorLine error={error} />
        {notice && <p className="notice-line">{notice}</p>}
        {!exits ? (
          <p className="muted">Loading…</p>
        ) : exits.length === 0 ? (
          <p className="muted">No exit nodes yet.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Kind</th>
                <th>Address</th>
                <th>Answer IP</th>
                <th>Health</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {exits.map((x) => (
                <tr key={x.id}>
                  <td>{x.name}</td>
                  <td>{x.kind}</td>
                  <td><code>{x.address}</code></td>
                  <td><code>{x.answer_ip}</code></td>
                  <td><span className={`pill health-${x.health}`}>{x.health}</span></td>
                  <td>
                    {writable && (
                      <>
                        <button className="link" onClick={() => check(x.id)}>check</button>{' '}
                        <Confirm label="delete" onConfirm={() => remove(x.id)} />
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {writable && (
        <section className="card">
          <h2>Add an exit</h2>
          <form className="grid" onSubmit={add}>
            <input
              placeholder="name, e.g. frankfurt-vps"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
            <select value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}>
              <option value="socks5">SOCKS5 proxy (probed)</option>
              <option value="wireguard">WireGuard endpoint (not probed)</option>
            </select>
            <input
              placeholder="host:port of the proxy"
              value={form.address}
              onChange={(e) => setForm({ ...form, address: e.target.value })}
            />
            <input
              placeholder="answer IPv4, e.g. 10.77.0.1"
              value={form.answer_ip}
              onChange={(e) => setForm({ ...form, answer_ip: e.target.value })}
            />
            <button disabled={!form.name.trim() || !form.address.trim() || !form.answer_ip.trim()}>
              Add exit
            </button>
          </form>
        </section>
      )}
    </div>
  );
}
