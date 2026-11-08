import { useEffect, useState } from 'react';
import { ArrowDownIcon, FlaskConicalIcon, SearchIcon } from 'lucide-react';
import { api } from '../api.js';
import { EmptyState, ErrorLine, Mono, SimpleSelect, Tag } from '../ui.jsx';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';

const QTYPES = [
  { value: 'A', label: 'A' },
  { value: 'AAAA', label: 'AAAA' },
  { value: 'CNAME', label: 'CNAME' },
  { value: 'TXT', label: 'TXT' },
  { value: 'MX', label: 'MX' },
  { value: 'NS', label: 'NS' },
  { value: 'SRV', label: 'SRV' },
  { value: 'HTTPS', label: 'HTTPS' },
];

// Domain test: ask any profile what it would do with a name, without sending
// the query anywhere. The result shows the decision, why, and the exact reply
// a client would receive.
export default function DomainTest({ me }) {
  const [profiles, setProfiles] = useState(null);
  const [form, setForm] = useState({ profile: '', qname: '', qtype: 'A' });
  const [results, setResults] = useState([]); // most recent first
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    api('GET', '/profiles')
      .then((p) => {
        setProfiles(p);
        setForm((f) => ({ ...f, profile: f.profile || String(p[0]?.id ?? '') }));
      })
      .catch((e) => setError(e.message));
  }, []);

  async function ask(e) {
    e.preventDefault();
    const qname = form.qname.trim();
    if (!qname || !form.profile) return;
    setBusy(true);
    setError('');
    try {
      const res = await api(
        'GET',
        `/profiles/${form.profile}/test?qname=${encodeURIComponent(qname)}&qtype=${form.qtype}`,
      );
      setResults((r) => [res, ...r].slice(0, 20));
      setForm((f) => ({ ...f, qname: '' }));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Domain test</h1>
        <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
          Ask a profile what it would do with a name and record type. Nothing is sent upstream and
          nothing is logged — this replays the live rules, lists and options against the name.
        </p>
      </div>
      <ErrorLine error={error} onDismiss={() => setError('')} />

      <Card>
        <CardContent>
          <form onSubmit={ask} className="flex flex-col gap-3 sm:flex-row sm:items-end">
            <label className="grid gap-1.5 text-sm sm:w-64">
              <span className="text-muted-foreground">Profile</span>
              <SimpleSelect
                value={form.profile}
                options={(profiles || []).map((p) => ({ value: String(p.id), label: p.name }))}
                onChange={(v) => setForm({ ...form, profile: v })}
              />
            </label>
            <label className="grid flex-1 gap-1.5 text-sm">
              <span className="text-muted-foreground">Domain</span>
              <div className="relative">
                <SearchIcon className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  className="pl-8 font-mono"
                  placeholder="example.com"
                  autoFocus
                  value={form.qname}
                  onChange={(e) => setForm({ ...form, qname: e.target.value })}
                />
              </div>
            </label>
            <label className="grid gap-1.5 text-sm sm:w-28">
              <span className="text-muted-foreground">Type</span>
              <SimpleSelect value={form.qtype} options={QTYPES} onChange={(v) => setForm({ ...form, qtype: v })} />
            </label>
            <Button type="submit" disabled={busy || !form.qname.trim() || !form.profile}>
              <FlaskConicalIcon /> Test
            </Button>
          </form>
        </CardContent>
      </Card>

      {results.length === 0 ? (
        <Card>
          <CardContent>
            <EmptyState icon={FlaskConicalIcon} title="No lookups yet">
              Enter a domain above — blocked, rewritten and redirected names all show exactly why.
            </EmptyState>
          </CardContent>
        </Card>
      ) : (
        <div className="flex flex-col gap-2">
          {results.map((r, i) => (
            <Card key={i}>
              <CardContent className="flex flex-col gap-2 py-4">
                <div className="flex flex-wrap items-center gap-3">
                  <Tag tone={ACTION_TONE[r.action] || 'unknown'} dot>
                    {r.action}
                  </Tag>
                  <Mono className="font-medium">{r.qname}</Mono>
                  <span className="text-xs text-muted-foreground">type {r.qtype}</span>
                  <span className="ml-auto text-xs text-muted-foreground">{r.reason}</span>
                </div>
                <div className="flex items-center gap-2 rounded-lg bg-muted/40 px-3 py-2 text-sm">
                  <span className="font-medium">{r.answer}</span>
                  {r.exit_name && (
                    <span className="text-xs text-muted-foreground">
                      via exit {r.exit_name}
                      {!r.exit_healthy && ' (down — still forwards)'}
                    </span>
                  )}
                </div>
                {r.target && (
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <ArrowDownIcon className="size-3" /> target <Mono className="text-xs">{r.target}</Mono>
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

const ACTION_TONE = {
  block: 'block',
  rewrite: 'rewrite',
  redirect: 'redirect',
  forward: 'forward',
};
