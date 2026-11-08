import { useEffect, useState } from 'react';
import { KeyRoundIcon, NetworkIcon, PlusIcon, RotateCwIcon, Trash2Icon } from 'lucide-react';
import { api, can } from '../api.js';
import { Confirm, EmptyState, ErrorLine, Mono, PageHeader, SimpleSelect, TableSkeleton } from '../ui.jsx';
import ResolverDialog from './ResolverDialog.jsx';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Field, FieldDescription, FieldLabel } from '@/components/ui/field';
import { Input } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

export default function Endpoints({ me }) {
  const [endpoints, setEndpoints] = useState(null);
  const [profiles, setProfiles] = useState([]);
  const [error, setError] = useState('');
  const [viewing, setViewing] = useState(); // endpoint whose resolver-ID dialog is open
  const [setup, setSetup] = useState(null);
  const [form, setForm] = useState({ name: '', profile_id: '', cidrs: '' });
  const writable = can(me.role, 'operator');

  const load = () =>
    Promise.all([api('GET', '/endpoints'), api('GET', '/profiles'), api('GET', '/setup')])
      .then(([e, p, s]) => {
        setEndpoints(e);
        setProfiles(p);
        setSetup(s);
        setForm((f) => ({ ...f, profile_id: f.profile_id || String(p[0]?.id ?? '') }));
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
      setViewing(res.endpoint); // show the new resolver IDs right away
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

  // Rotating invalidates the previous token immediately, so anything using it
  // (a phone's Private DNS, a router) must be updated with the new one.
  async function rotate(e) {
    setError('');
    try {
      await api('POST', `/endpoints/${e.id}/rotate`);
      setViewing(e); // the dialog re-reads the new token
    } catch (err) {
      setError(err.message);
    }
  }

  async function showToken(e) {
    try {
      const { token } = await api('GET', `/endpoints/${e.id}/token`);
      setViewing({ ...e, token });
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Endpoints"
        description="A client whose source address falls in one of an endpoint's CIDRs is filtered by that endpoint's profile. The most specific match wins."
      />
      <ErrorLine error={error} onDismiss={() => setError('')} />

      <ResolverDialog endpoint={viewing} setup={setup} onClose={() => setViewing(null)} />

      <Card>
        <CardContent>
          {!endpoints ? (
            <TableSkeleton />
          ) : endpoints.length === 0 ? (
            <EmptyState icon={NetworkIcon} title="No endpoints">
              {writable
                ? 'Create one below to filter a network or device with a profile.'
                : 'An operator can add endpoints.'}
            </EmptyState>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Profile</TableHead>
                  <TableHead className="hidden sm:table-cell">Source CIDRs</TableHead>
                  {writable && <TableHead className="w-0" />}
                </TableRow>
              </TableHeader>
              <TableBody>
                {endpoints.map((e) => (
                  <TableRow key={e.id}>
                    <TableCell className="font-medium">
                      {e.name}
                      <div className="mt-0.5 font-normal sm:hidden">
                        <Mono className="text-xs text-muted-foreground">{e.cidrs.join(', ')}</Mono>
                      </div>
                    </TableCell>
                    <TableCell>{profileName(e.profile_id)}</TableCell>
                    <TableCell className="hidden whitespace-normal sm:table-cell">
                      <div className="flex flex-wrap gap-1">
                        {e.cidrs.map((c) => (
                          <Mono key={c} className="rounded bg-muted px-1.5 py-0.5 text-xs">
                            {c}
                          </Mono>
                        ))}
                      </div>
                    </TableCell>
                    {writable && (
                      <TableCell>
                        <div className="flex justify-end gap-1">
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            className="text-muted-foreground"
                            aria-label={`Show resolver IDs for ${e.name}`}
                            title="Show resolver IDs"
                            onClick={() => showToken(e)}
                          >
                            <KeyRoundIcon />
                          </Button>
                          <Confirm
                            label="Rotate"
                            icon={<RotateCwIcon />}
                            title={`Rotate the token for ${e.name}?`}
                            description="The current token stops working immediately. Devices using it for DoT or DoH must be updated."
                            action="Rotate token"
                            onConfirm={() => rotate(e)}
                          />
                          <Confirm
                            label="Delete"
                            icon={<Trash2Icon />}
                            title={`Delete ${e.name}?`}
                            description="Its CIDRs stop matching this profile and its DoT/DoH token stops working."
                            onConfirm={() => remove(e.id)}
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
            <CardTitle>New endpoint</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={create} className="flex flex-col gap-4">
              <div className="grid gap-4 md:grid-cols-3">
                <Field>
                  <FieldLabel htmlFor="ep-name">Name</FieldLabel>
                  <Input
                    id="ep-name"
                    placeholder="kids-laptop"
                    value={form.name}
                    onChange={(e) => setForm({ ...form, name: e.target.value })}
                  />
                </Field>
                <Field>
                  <FieldLabel>Profile</FieldLabel>
                  <SimpleSelect
                    value={form.profile_id}
                    placeholder="No profiles"
                    options={profiles.map((p) => ({ value: String(p.id), label: p.name }))}
                    onChange={(profile_id) => setForm({ ...form, profile_id })}
                  />
                </Field>
                <Field>
                  <FieldLabel htmlFor="ep-cidrs">Source CIDRs</FieldLabel>
                  <Input
                    id="ep-cidrs"
                    className="font-mono"
                    placeholder="10.9.0.0/16, 192.0.2.7"
                    value={form.cidrs}
                    onChange={(e) => setForm({ ...form, cidrs: e.target.value })}
                  />
                  <FieldDescription>Comma-separated. A bare IP means a single address.</FieldDescription>
                </Field>
              </div>
              <Button
                type="submit"
                className="self-start"
                disabled={!form.name.trim() || !form.cidrs.trim() || !form.profile_id}
              >
                <PlusIcon /> Create endpoint
              </Button>
            </form>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
