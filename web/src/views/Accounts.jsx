import { useEffect, useState } from 'react';
import { KeyRoundIcon, PlusIcon, Trash2Icon, UserRoundIcon } from 'lucide-react';
import { api, can } from '../api.js';
import { Confirm, EmptyState, ErrorLine, PageHeader, SimpleSelect, TableSkeleton, Tag } from '../ui.jsx';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';

const ROLES = [
  { value: 'admin', label: 'Admin — everything, incl. accounts and audit' },
  { value: 'operator', label: 'Operator — change profiles, rules, endpoints' },
  { value: 'viewer', label: 'Viewer — dashboard, read-only' },
];

// Accounts are dashboard sign-ins; API tokens (the Tokens page) authenticate
// scripts and the CLI.
export default function Accounts({ me }) {
  const [users, setUsers] = useState(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [dialog, setDialog] = useState(null); // { mode, user?, form }
  const [busy, setBusy] = useState(false);

  const load = () =>
    api('GET', '/users')
      .then(setUsers)
      .catch((e) => setError(e.message));

  useEffect(() => {
    load();
  }, []);

  function openCreate() {
    setDialog({ mode: 'create', form: { name: '', password: '', role: 'operator' } });
  }

  function openEdit(u) {
    setDialog({ mode: 'edit', user: u, form: { name: u.name, password: '', role: u.role } });
  }

  async function save(e) {
    e.preventDefault();
    setBusy(true);
    setError('');
    const { mode, user, form } = dialog;
    try {
      if (mode === 'create') {
        await api('POST', '/users', form);
        setNotice(`${form.name} can now sign in.`);
      } else {
        const patch = { role: form.role };
        if (form.password) patch.password = form.password;
        await api('PATCH', `/users/${user.id}`, patch);
        setNotice(`${form.name} updated. A password change signs out their sessions.`);
      }
      setDialog(null);
      load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function remove(u) {
    setError('');
    try {
      await api('DELETE', `/users/${u.id}`);
      setNotice(`${u.name} can no longer sign in.`);
      load();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Accounts"
        description="Dashboard sign-ins with a username and password. Scripts and the CLI keep using API tokens; sessions show up on the API tokens page where they can be revoked."
      >
        {!dialog && (
          <Button onClick={openCreate}>
            <PlusIcon /> Add account
          </Button>
        )}
      </PageHeader>
      <ErrorLine error={error} onDismiss={() => setError('')} />
      {notice && (
        <Alert>
          <AlertDescription className="text-foreground">{notice}</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardContent>
          {!users ? (
            <TableSkeleton />
          ) : users.length === 0 ? (
            <EmptyState icon={UserRoundIcon} title="No accounts">
              Create one with a username and password, or sign in with an API token from the CLI's
              <code className="ml-1 rounded bg-muted px-1 font-mono text-xs">opencontrol adduser</code>.
            </EmptyState>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Username</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead className="hidden sm:table-cell">Created</TableHead>
                  <TableHead className="w-0" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.map((u) => (
                  <TableRow key={u.id}>
                    <TableCell>
                      <div className="font-medium">
                        {u.name}
                        {u.name === me.name && <span className="ml-2 text-xs text-muted-foreground">you</span>}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Tag>{u.role}</Tag>
                    </TableCell>
                    <TableCell className="hidden text-muted-foreground sm:table-cell">{u.created_at}</TableCell>
                    <TableCell>
                      <div className="flex justify-end gap-1">
                        <Button variant="ghost" size="icon-sm" aria-label={`Edit ${u.name}`} onClick={() => openEdit(u)}>
                          <KeyRoundIcon />
                        </Button>
                        {u.name !== me.name && (
                          <Confirm
                            label="Delete"
                            icon={<Trash2Icon />}
                            title={`Delete ${u.name}?`}
                            description="Their sign-in sessions are revoked immediately."
                            onConfirm={() => remove(u)}
                          />
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Sheet open={!!dialog} onOpenChange={(open) => !open && setDialog(null)}>
        <SheetContent className="sm:max-w-md">
          {dialog && (
            <form onSubmit={save} className="flex h-full flex-col gap-4">
              <SheetHeader>
                <SheetTitle>{dialog.mode === 'create' ? 'Add an account' : `Edit ${dialog.user.name}`}</SheetTitle>
                <SheetDescription>
                  {dialog.mode === 'create'
                    ? 'They sign in with this username and password.'
                    : 'Leave the password empty to keep the current one.'}
                </SheetDescription>
              </SheetHeader>

              <div className="grid gap-4">
                <label className="text-sm font-medium" htmlFor="acct-name">
                  Username
                </label>
                <Input
                  id="acct-name"
                  autoFocus
                  autoComplete="off"
                  placeholder="edward"
                  disabled={dialog.mode === 'edit'}
                  value={dialog.form.name}
                  onChange={(e) => setDialog({ ...dialog, form: { ...dialog.form, name: e.target.value } })}
                />
                <label className="text-sm font-medium" htmlFor="acct-pass">
                  Password
                </label>
                <Input
                  id="acct-pass"
                  type="password"
                  autoComplete="new-password"
                  placeholder={dialog.mode === 'create' ? 'at least 8 characters' : 'unchanged'}
                  value={dialog.form.password}
                  onChange={(e) => setDialog({ ...dialog, form: { ...dialog.form, password: e.target.value } })}
                />
                <label className="text-sm font-medium" htmlFor="acct-role">
                  Role
                </label>
                <SimpleSelect
                  value={dialog.form.role}
                  options={ROLES}
                  onChange={(role) => setDialog({ ...dialog, form: { ...dialog.form, role } })}
                />
              </div>

              <SheetFooter className="mt-auto">
                <Button type="button" variant="outline" onClick={() => setDialog(null)}>
                  Cancel
                </Button>
                <Button
                  type="submit"
                  disabled={
                    busy ||
                    !dialog.form.name.trim() ||
                    (dialog.mode === 'create' && dialog.form.password.length < 8) ||
                    (dialog.mode === 'edit' && dialog.form.password && dialog.form.password.length < 8)
                  }
                >
                  {busy ? 'Saving…' : dialog.mode === 'create' ? 'Create account' : 'Save changes'}
                </Button>
              </SheetFooter>
            </form>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
