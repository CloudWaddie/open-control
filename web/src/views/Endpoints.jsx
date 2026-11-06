import { useEffect, useState } from 'react';
import { api, can } from '../api.js';
import { ErrorLine, Confirm } from '../ui.jsx';

export default function Endpoints({ me }) {
  const [endpoints, setEndpoints] = useState(null);
  const [profiles, setProfiles] = useState([]);
  const [error, setError] = useState('');
  const [created, setCreated] = useState(null); // { endpoint, token } shown once
  const [form, setForm] = useState({ name: '', profile_id: '', cidrs: '' });
  const writable = can(me.role, 'operator');

  const load = () =>
    Promise.all([api('GET', '/endpoints'), api('GET', '/profiles')])
      .then(([e, p]) => {
        setEndpoints(e);
        setProfiles(p);
        setForm((f) => ({ ...f, profile_id: f.profile_id || p[0]?.id || '' }));
      })
      .catch((e) => setError(e.message));

  useEffect(() => {
    load();
  }, []);

  const profileName = (id) => profiles.find((p) => p.id === id)?.name ?? `#${id}`;

  async function create(e) {
    e.preventDefault();
    setError('');
    try {
      const cidrs = form.cidrs
        .split(',')
        .map((c) => c.trim())
        .filter(Boolean);
      const res = await api('POST', '/endpoints', {
        name: form.name.trim(),
        profile_id: Number(form.profile_id),
        cidrs,
      });
      setCreated(res);
      setForm({ ...form, name: '', cidrs: '' });
      load();
    } catch (err) {
      setError(err.message);
    }
  }

  async function remove(id) {
    try {
      await api('DELETE', `/endpoints/${id}`);
      load();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="stack">
      <section className="card">
        <h2>Endpoints</h2>
        <p className="muted">
          A client whose source address falls in one of an endpoint's CIDRs is
          filtered by that endpoint's profile. The most specific match wins.
        </p>
        <ErrorLine error={error} />
        {!endpoints ? (
          <p className="muted">Loading…</p>
        ) : endpoints.length === 0 ? (
          <p className="muted">No endpoints.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Profile</th>
                <th>Source CIDRs</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {endpoints.map((e) => (
                <tr key={e.id}>
                  <td>{e.name}</td>
                  <td>{profileName(e.profile_id)}</td>
                  <td><code>{e.cidrs.join(', ')}</code></td>
                  <td>
                    {writable && <Confirm label="delete" onConfirm={() => remove(e.id)} />}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {created && (
        <section className="card notice">
          <p>
            Endpoint <strong>{created.endpoint.name}</strong> created. Token
            (an identifier for future DoT/DoH enrollment, not a secret):
          </p>
          <code className="block">{created.token}</code>
          <button className="link" onClick={() => setCreated(null)}>dismiss</button>
        </section>
      )}

      {writable && (
        <section className="card">
          <h2>New endpoint</h2>
          <form className="grid" onSubmit={create}>
            <input
              placeholder="name, e.g. kids-laptop"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
            <select
              value={form.profile_id}
              onChange={(e) => setForm({ ...form, profile_id: e.target.value })}
            >
              {profiles.map((p) => (
                <option key={p.id} value={p.id}>{p.name}</option>
              ))}
            </select>
            <input
              placeholder="10.9.0.0/16, 192.0.2.7"
              value={form.cidrs}
              onChange={(e) => setForm({ ...form, cidrs: e.target.value })}
            />
            <button disabled={!form.name.trim() || !form.cidrs.trim() || !form.profile_id}>
              Create
            </button>
          </form>
        </section>
      )}
    </div>
  );
}
