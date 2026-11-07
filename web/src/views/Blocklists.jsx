import { useEffect, useState } from 'react';
import { ListXIcon, PlusIcon, Trash2Icon } from 'lucide-react';
import { api, can } from '../api.js';
import { Confirm, EmptyState, ErrorLine, Mono, PageHeader, SimpleSelect, TableSkeleton } from '../ui.jsx';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Field, FieldLabel } from '@/components/ui/field';
import { Input } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

const FORMATS = [
  { value: 'hosts', label: 'hosts' },
  { value: 'dnsmasq', label: 'dnsmasq' },
  { value: 'adguard', label: 'AdGuard' },
];

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
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Blocklists"
        description="Your own list subscriptions, refreshed hourly. A new list is turned on for every profile; switch it per profile on that profile's Filters tab. For common categories, use the built-in filters instead."
      />
      <ErrorLine error={error} onDismiss={() => setError('')} />

      <Card>
        <CardContent>
          {!lists ? (
            <TableSkeleton />
          ) : lists.length === 0 ? (
            <EmptyState icon={ListXIcon} title="No subscriptions">
              {writable ? 'Subscribe to a hosts, dnsmasq or AdGuard list below.' : 'An operator can add blocklists.'}
            </EmptyState>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>URL</TableHead>
                  <TableHead className="hidden sm:table-cell">Format</TableHead>
                  <TableHead className="hidden md:table-cell">Last synced</TableHead>
                  {writable && <TableHead className="w-0" />}
                </TableRow>
              </TableHeader>
              <TableBody>
                {lists.map((l) => (
                  <TableRow key={l.id}>
                    <TableCell className="max-w-md whitespace-normal">
                      <Mono>{l.url}</Mono>
                    </TableCell>
                    <TableCell className="hidden text-muted-foreground sm:table-cell">{l.format}</TableCell>
                    <TableCell className="hidden text-muted-foreground md:table-cell">
                      {l.last_synced || 'Never'}
                    </TableCell>
                    {writable && (
                      <TableCell className="text-right">
                        <Confirm
                          label="Remove"
                          icon={<Trash2Icon />}
                          title="Remove this blocklist?"
                          description={l.url}
                          onConfirm={() => remove(l.id)}
                        />
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
            <CardTitle>Subscribe</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={add} className="flex flex-col gap-4 sm:flex-row sm:items-end">
              <Field className="sm:flex-1">
                <FieldLabel htmlFor="bl-url">List URL</FieldLabel>
                <Input
                  id="bl-url"
                  type="url"
                  className="font-mono"
                  placeholder="https://example.org/hosts.txt"
                  value={form.url}
                  onChange={(e) => setForm({ ...form, url: e.target.value })}
                />
              </Field>
              <Field className="sm:w-40">
                <FieldLabel>Format</FieldLabel>
                <SimpleSelect
                  value={form.format}
                  options={FORMATS}
                  onChange={(format) => setForm({ ...form, format })}
                />
              </Field>
              <Button type="submit" disabled={!form.url.trim()}>
                <PlusIcon /> Subscribe
              </Button>
            </form>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
