import { useEffect, useState } from 'react';
import { CheckCircle2Icon, PlusIcon, RefreshCwIcon, Trash2Icon, WaypointsIcon } from 'lucide-react';
import { api, can } from '../api.js';
import { Confirm, EmptyState, ErrorLine, Mono, PageHeader, SimpleSelect, TableSkeleton, Tag } from '../ui.jsx';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Field, FieldDescription, FieldLabel } from '@/components/ui/field';
import { Input } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

const KINDS = [
  { value: 'socks5', label: 'SOCKS5 proxy' },
  { value: 'wireguard', label: 'WireGuard endpoint' },
];

// Exit nodes are egress points for redirect rules. "down" exits are skipped and
// their queries resolve normally; "unknown" (WireGuard, which cannot be probed
// without a tunnel) counts as usable.
export default function Exits({ me }) {
  const [exits, setExits] = useState(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [checking, setChecking] = useState(null);
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
    setChecking(id);
    try {
      const ex = await api('POST', `/exits/${id}/check`);
      setNotice(`${ex.name} is ${ex.health}.`);
      load();
    } catch (err) {
      setError(err.message);
    } finally {
      setChecking(null);
    }
  }

  async function remove(id) {
    setError('');
    try {
      const res = await api('DELETE', `/exits/${id}`);
      setNotice(`Exit deleted. ${res.removed_rules} redirect rule(s) that pointed at it were removed.`);
      load();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Exit nodes"
        description="A redirect rule answers matching names with an exit's address, so that traffic leaves through that exit. Health is checked every 30 seconds; a down exit is skipped and queries resolve normally."
      />
      <ErrorLine error={error} onDismiss={() => setError('')} />
      {notice && (
        <Alert>
          <CheckCircle2Icon className="text-ok" />
          <AlertDescription className="text-foreground">{notice}</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardContent>
          {!exits ? (
            <TableSkeleton />
          ) : exits.length === 0 ? (
            <EmptyState icon={WaypointsIcon} title="No exit nodes">
              Add a SOCKS5 proxy or WireGuard endpoint, then point redirect rules at it from a profile.
            </EmptyState>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Health</TableHead>
                  <TableHead className="hidden md:table-cell">Address</TableHead>
                  <TableHead className="hidden sm:table-cell">Answer IP</TableHead>
                  {writable && <TableHead className="w-0" />}
                </TableRow>
              </TableHeader>
              <TableBody>
                {exits.map((x) => (
                  <TableRow key={x.id}>
                    <TableCell>
                      <div className="font-medium">{x.name}</div>
                      <div className="text-xs text-muted-foreground">
                        {x.kind === 'socks5' ? 'SOCKS5' : 'WireGuard'}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Tag tone={x.health} dot>
                        {x.health}
                      </Tag>
                    </TableCell>
                    <TableCell className="hidden md:table-cell">
                      <Mono>{x.address}</Mono>
                    </TableCell>
                    <TableCell className="hidden sm:table-cell">
                      <Mono>{x.answer_ip}</Mono>
                    </TableCell>
                    {writable && (
                      <TableCell>
                        <div className="flex justify-end gap-1">
                          <Button variant="ghost" size="sm" disabled={checking === x.id} onClick={() => check(x.id)}>
                            <RefreshCwIcon className={checking === x.id ? 'animate-spin' : ''} />
                            Check
                          </Button>
                          <Confirm
                            label="Delete"
                            icon={<Trash2Icon />}
                            title={`Delete ${x.name}?`}
                            description="Redirect rules that point at this exit are deleted too."
                            onConfirm={() => remove(x.id)}
                          />
                        </div>
                      </TableCell>
                    )}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {writable && (
        <Card>
          <CardHeader>
            <CardTitle>Add an exit</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={add} className="flex flex-col gap-4">
              <div className="grid gap-4 sm:grid-cols-2">
                <Field>
                  <FieldLabel htmlFor="ex-name">Name</FieldLabel>
                  <Input
                    id="ex-name"
                    placeholder="frankfurt-vps"
                    value={form.name}
                    onChange={(e) => setForm({ ...form, name: e.target.value })}
                  />
                </Field>
                <Field>
                  <FieldLabel>Kind</FieldLabel>
                  <SimpleSelect value={form.kind} options={KINDS} onChange={(kind) => setForm({ ...form, kind })} />
                  <FieldDescription>
                    {form.kind === 'socks5'
                      ? 'Probed with a SOCKS5 handshake.'
                      : 'Not probed; health shows as unknown and the exit is treated as usable.'}
                  </FieldDescription>
                </Field>
                <Field>
                  <FieldLabel htmlFor="ex-addr">Address</FieldLabel>
                  <Input
                    id="ex-addr"
                    className="font-mono"
                    placeholder="host:port"
                    value={form.address}
                    onChange={(e) => setForm({ ...form, address: e.target.value })}
                  />
                </Field>
                <Field>
                  <FieldLabel htmlFor="ex-answer">Answer IP</FieldLabel>
                  <Input
                    id="ex-answer"
                    className="font-mono"
                    placeholder="10.77.0.1"
                    value={form.answer_ip}
                    onChange={(e) => setForm({ ...form, answer_ip: e.target.value })}
                  />
                  <FieldDescription>IPv4 returned to clients. Must route to the exit on your network.</FieldDescription>
                </Field>
              </div>
              <Button
                type="submit"
                className="self-start"
                disabled={!form.name.trim() || !form.address.trim() || !form.answer_ip.trim()}
              >
                <PlusIcon /> Add exit
              </Button>
            </form>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
