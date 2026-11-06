import { useEffect, useState } from 'react';
import { api, can, getToken, setToken } from './api.js';
import Overview from './views/Overview.jsx';
import Logs from './views/Logs.jsx';
import Profiles from './views/Profiles.jsx';
import Endpoints from './views/Endpoints.jsx';
import Blocklists from './views/Blocklists.jsx';
import Tokens from './views/Tokens.jsx';
import Audit from './views/Audit.jsx';

// Each nav entry names the minimum role it needs. Viewers see read-only
// versions of the first three; tokens and audit are admin-only.
const NAV = [
  { id: 'overview', label: 'Overview', min: 'viewer', view: Overview },
  { id: 'logs', label: 'Logs', min: 'viewer', view: Logs },
  { id: 'profiles', label: 'Profiles', min: 'viewer', view: Profiles },
  { id: 'endpoints', label: 'Endpoints', min: 'viewer', view: Endpoints },
  { id: 'blocklists', label: 'Blocklists', min: 'viewer', view: Blocklists },
  { id: 'tokens', label: 'Tokens', min: 'admin', view: Tokens },
  { id: 'audit', label: 'Audit', min: 'admin', view: Audit },
];

function currentRoute() {
  return window.location.hash.replace(/^#\/?/, '') || 'overview';
}

export default function App() {
  const [me, setMe] = useState(null); // { name, role } once signed in
  const [checking, setChecking] = useState(!!getToken());
  const [route, setRoute] = useState(currentRoute());

  useEffect(() => {
    const onHash = () => setRoute(currentRoute());
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  // Restore the session from a token already in this tab.
  useEffect(() => {
    if (!getToken()) return;
    api('GET', '/whoami')
      .then(setMe)
      .catch(() => setToken(''))
      .finally(() => setChecking(false));
  }, []);

  if (checking) return <div className="center muted">Loading…</div>;
  if (!me) return <Login onSignedIn={setMe} />;

  const visible = NAV.filter((n) => can(me.role, n.min));
  const active = visible.find((n) => n.id === route) || visible[0];
  const View = active.view;

  return (
    <div className="shell">
      <header className="topbar">
        <strong>Open Control</strong>
        <nav>
          {visible.map((n) => (
            <a
              key={n.id}
              href={`#/${n.id}`}
              className={n.id === active.id ? 'active' : ''}
            >
              {n.label}
            </a>
          ))}
        </nav>
        <span className="who">
          {me.name} <span className="pill">{me.role}</span>
          <button
            className="link"
            onClick={() => {
              setToken('');
              setMe(null);
            }}
          >
            Sign out
          </button>
        </span>
      </header>
      <main>
        <View me={me} />
      </main>
    </div>
  );
}

function Login({ onSignedIn }) {
  const [token, setTokenInput] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError('');
    setToken(token.trim());
    try {
      onSignedIn(await api('GET', '/whoami'));
    } catch (err) {
      setToken('');
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="center">
      <form className="card login" onSubmit={submit}>
        <h1>Open Control</h1>
        <p className="muted">
          Paste an API token. Mint one with <code>opencontrol addtoken</code>.
        </p>
        <input
          type="password"
          autoFocus
          placeholder="oc_…"
          value={token}
          onChange={(e) => setTokenInput(e.target.value)}
        />
        <button disabled={busy || !token.trim()}>Sign in</button>
        {error && <p className="error">{error}</p>}
      </form>
    </div>
  );
}
