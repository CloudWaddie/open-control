import { useEffect, useState } from 'react';
import { KeyRoundIcon, PlusIcon, Trash2Icon, XIcon } from 'lucide-react';
import { api } from '../api.js';
import { Confirm, ErrorLine, PageHeader, SecretValue, SimpleSelect, TableSkeleton } from '../ui.jsx';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Field, FieldLabel } from '@/components/ui/field';
import { Input } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

const ROLES = [
  { value: 'viewer', label: 'Viewer — read only' },
  { value: 'operator', label: 'Operator — read and change' },
  { value: 'admin', label: 'Admin — everything, incl. tokens and audit' },
];

export default function Tokens({ me }) {
  const [tokens, setTokens] = useState(null);
  const [form, setForm] = useState({ name: '', role: 'viewer' });
  const [minted, setMinted] = useState(null);
  const [error, setError] = useState('');

  const load = () =>
    api('GET', '/tokens')
      .then(setTokens)
      .catch((e) => setError(e.message));

  useEffect(() => {
    load();
  }, []);

  async function mint(e) {
    e.preventDefault();
    setError('');
    try {
      setMinted(await api('POST', '/tokens', form));
      setForm({ ...form, name: '' });
      load();
    } catch (err) {
      setError(err.message);
    }
  }

  async function revoke(id) {
    setError('');
    try {
      await api('DELETE', `/tokens/${id}`);
      load();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="API tokens"
        description="Revoking a token takes effect on its next request. You cannot revoke the token you are signed in with."
      />
      <ErrorLine error={error} onDismiss={() => setError('')} />

      {minted && (
        <Card className="ring-primary/40 bg-accent/40">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <KeyRoundIcon className="size-4 text-primary" />
              Token for {minted.name}
            </CardTitle>
            <CardDescription>
              Role: {minted.role}. Copy it now; it is not shown again and cannot be recovered.
            </CardDescription>
            <CardAction>
              <Button variant="ghost" size="icon-sm" aria-label="Dismiss" onClick={() => setMinted(null)}>
                <XIcon />
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent>
            <SecretValue value={minted.token} />
          </CardContent>
        </Card>
      )}

      <Card>
        <CardContent>
          {!tokens ? (
            <TableSkeleton />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead className="hidden sm:table-cell">Created</TableHead>
                  <TableHead className="w-0" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {tokens.map((t) => (
                  <TableRow key={t.id}>
                    <TableCell className="font-medium">
                      {t.name}
                      {t.name === me.name && <span className="ml-2 font-normal text-muted-foreground">(you)</span>}
                    </TableCell>
                    <TableCell>
                      <Badge variant={t.role === 'admin' ? 'default' : 'secondary'} className="capitalize">
                        {t.role}
                      </Badge>
                    </TableCell>
                    <TableCell className="hidden text-muted-foreground sm:table-cell">{t.created_at}</TableCell>
                    <TableCell className="text-right">
                      {t.name !== me.name && (
                        <Confirm
                          label="Revoke"
                          icon={<Trash2Icon />}
                          title={`Revoke ${t.name}?`}
                          description="Anything using this token loses access on its next request."
                          onConfirm={() => revoke(t.id)}
                        />
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Mint a token</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={mint} className="flex flex-col gap-4 sm:flex-row sm:items-end">
            <Field className="sm:flex-1">
              <FieldLabel htmlFor="tok-name">Name</FieldLabel>
              <Input
                id="tok-name"
                placeholder="grafana-dashboard"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
              />
            </Field>
            <Field className="sm:w-80">
              <FieldLabel>Role</FieldLabel>
              <SimpleSelect value={form.role} options={ROLES} onChange={(role) => setForm({ ...form, role })} />
            </Field>
            <Button type="submit" disabled={!form.name.trim()}>
              <PlusIcon /> Mint
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
