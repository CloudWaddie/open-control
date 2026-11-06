import { useEffect, useState } from 'react';
import { api, can } from '../api.js';
import { ErrorLine, Confirm } from '../ui.jsx';

export default function Profiles({ me }) {
  const [profiles, setProfiles] = useState(null);
  const [selected, setSelected] = useState(null);
  const [error, setError] = useState('');
  const [name, setName] = useState('');

  const load = () =>
    api('GET', '/profiles')
      .then((p) => {
        setProfiles(p);
        setSelected((s) => s ?? p[0] ?? null);
      })
      .catch((e) => setError(e.message));

  useEffect(() => {
    load();
  }, []);

  async function create(e) {
    e.preventDefault();
    try {
      const p = await api('POST', '/profiles', { name: name.trim() });
      setName('');
      setSelected(p);
      await load();
    } catch (err) {
      setError(err.message);
    }
  }

  if (!profiles) return error ? <ErrorLine error={error} /> : <p className="muted">Loading…</p>;

  return (
    <div className="split">
      <section className="card">
        <h2>Profiles</h2>
        <ErrorLine error={error} />
        <ul className="list">
          {profiles.map((p) => (
            <li key={p.id}>
              <button
                className={`link ${selected?.id === p.id ? 'active' : ''}`}
                onClick={() => setSelected(p)}
              >
                {p.name} <span className="muted">#{p.id}</span>
              </button>
            </li>
          ))}
        </ul>
        {can(me.role, 'operator') && (
          <form className="row" onSubmit={create}>
            <input
              placeholder="new profile name"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
            <button disabled={!name.trim()}>Add</button>
          </form>
        )}
      </section>

      <section className="card">
        {selected ? (
          <Rules key={selected.id} profile={selected} me={me} onError={setError} />
        ) : (
          <p className="muted">Create a profile to add rules.</p>
        )}
      </section>
    </div>
  );
}

function Rules({ profile, me, onError }) {
  const [rules, setRules] = useState(null);
  const [exits, setExits] = useState([]);
  const [form, setForm] = useState({ kind: 'block', matcher: 'domain', pattern: '', answer: '', exit_id: '' });
  const writable = can(me.role, 'operator');

  const load = () =>
    api('GET', `/profiles/${profile.id}/rules`)
      .then(setRules)
      .catch((e) => onError(e.message));

  useEffect(() => {
    load();
    api('GET', '/exits')
      .then((list) => {
        setExits(list);
        setForm((f) => ({ ...f, exit_id: f.exit_id || list[0]?.id || '' }));
      })
      .catch(() => {});
  }, [profile.id]);

  const exitName = (id) => exits.find((x) => String(x.id) === String(id))?.name ?? `exit #${id}`;

  async function add(e) {
    e.preventDefault();
    try {
      const body = { ...form, exit_id: Number(form.exit_id) };
      await api('POST', `/profiles/${profile.id}/rules`, body);
      setForm({ ...form, pattern: '', answer: '' });
      load();
    } catch (err) {
      onError(err.message);
    }
  }

  async function remove(id) {
    try {
      await api('DELETE', `/rules/${id}`);
      load();
    } catch (err) {
      onError(err.message);
    }
  }

  return (
    <>
      <h2>{profile.name} rules</h2>
      {!rules ? (
        <p className="muted">Loading…</p>
      ) : rules.length === 0 ? (
        <p className="muted">No custom rules yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Kind</th>
              <th>Matcher</th>
              <th>Pattern</th>
              <th>Answer</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rules.map((r) => (
              <tr key={r.id}>
                <td><span className={`pill ${r.kind}`}>{r.kind}</span></td>
                <td>{r.matcher}</td>
                <td><code>{r.pattern}</code></td>
                <td>{r.kind === 'redirect' ? `→ ${exitName(r.answer)}` : r.answer}</td>
                <td>
                  {writable && (
                    <Confirm label="delete" onConfirm={() => remove(r.id)} />
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {writable && (
        <form className="grid" onSubmit={add}>
          <select
            value={form.kind}
            onChange={(e) =>
              // rewrites are exact-domain only; the API rejects anything else
              setForm({
                ...form,
                kind: e.target.value,
                matcher: e.target.value === 'rewrite' ? 'domain' : form.matcher,
              })
            }
          >
            <option value="block">block</option>
            <option value="allow">allow</option>
            <option value="rewrite">rewrite</option>
            <option value="redirect">redirect via exit</option>
          </select>
          <select
            value={form.matcher}
            onChange={(e) => setForm({ ...form, matcher: e.target.value })}
            disabled={form.kind === 'rewrite'}
          >
            <option value="domain">domain (exact)</option>
            <option value="wildcard">wildcard (+ subdomains)</option>
            <option value="tld">tld</option>
          </select>
          <input
            placeholder={form.matcher === 'tld' ? 'xyz' : 'example.com'}
            value={form.pattern}
            onChange={(e) => setForm({ ...form, pattern: e.target.value })}
          />
          {form.kind === 'rewrite' && (
            <input
              placeholder="answer IP or name"
              value={form.answer}
              onChange={(e) => setForm({ ...form, answer: e.target.value })}
            />
          )}
          {form.kind === 'redirect' && (
            exits.length === 0 ? (
              <span className="muted">Add an exit first (Exits page).</span>
            ) : (
              <select value={form.exit_id} onChange={(e) => setForm({ ...form, exit_id: e.target.value })}>
                {exits.map((x) => (
                  <option key={x.id} value={x.id}>{x.name}</option>
                ))}
              </select>
            )
          )}
          <button disabled={!form.pattern.trim()}>Add rule</button>
        </form>
      )}
    </>
  );
}
