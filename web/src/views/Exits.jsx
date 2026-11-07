import { useEffect, useState } from 'react';
import { CheckCircle2Icon, PencilIcon, PlusIcon, RefreshCwIcon, Trash2Icon, WaypointsIcon } from 'lucide-react';
import { api, can } from '../api.js';
import { Confirm, EmptyState, ErrorLine, Mono, PageHeader, SimpleSelect, TableSkeleton, Tag } from '../ui.jsx';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Field, FieldDescription, FieldLabel } from '@/components/ui/field';
import { Input } from '@/components/ui/input';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { cn } from '@/lib/utils';

const KINDS = [
  { value: 'socks5', label: 'SOCKS5 proxy' },
  { value: 'http', label: 'HTTP proxy' },
  { value: 'wireguard', label: 'WireGuard endpoint' },
];

const EMPTY = {
  name: '',
  kind: 'socks5',
  address: '',
  answer_ip: '',
  username: '',
  password: '',
  wg_private_key: '',
  wg_peer_key: '',
  wg_preshared_key: '',
  wg_allowed_ips: '',
  config: '',
};

// Exit nodes are egress points for redirect rules. A redirect answers matching
// names with an exit's answer IP, so traffic leaves through that exit. Health
// is checked every 30 seconds; a down exit is skipped and queries resolve
// normally.
export default function Exits({ me }) {
  const [exits, setExits] = useState(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [checking, setChecking] = useState(null);
  const [dialog, setDialog] = useState(null); // { mode, exit?, form }
  const [busy, setBusy] = useState(false);
  const writable = can(me.role, 'operator');

  const load = () =>
    api('GET', '/exits')
      .then(setExits)
      .catch((e) => setError(e.message));

  useEffect(() => {
    load();
  }, []);

  function openCreate() {
    setDialog({ mode: 'create', form: { ...EMPTY } });
  }

  // Editing shows what is on file (the credentials are dial secrets and can be
  // viewed like endpoint tokens).
  async function openEdit(ex) {
    setError('');
    try {
      const secrets = await api('GET', `/exits/${ex.id}/secrets`);
      setDialog({
        mode: 'edit',
        exit: ex,
        form: {
          ...EMPTY,
          name: ex.name,
          kind: ex.kind,
          address: ex.address,
          answer_ip: ex.answer_ip,
          username: secrets.username || '',
          password: secrets.password || '',
          wg_private_key: secrets.wg_private || '',
          wg_peer_key: secrets.wg_peer || '',
          wg_preshared_key: secrets.wg_preshared || '',
          wg_allowed_ips: secrets.wg_allowed || '',
          config: '',
        },
      });
    } catch (err) {
      setError(err.message);
    }
  }

  async function save(e) {
    e.preventDefault();
    setBusy(true);
    setError('');
    const { form, mode, exit } = dialog;
    try {
      if (mode === 'create') {
        await api('POST', '/exits', form);
        setNotice(`${form.name} added.`);
      } else {
        await api('PATCH', `/exits/${exit.id}`, form);
        setNotice(`${form.name} updated.`);
      }
      setDialog(null);
      load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
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

  const proxyKind = dialog?.form.kind !== 'wireguard';
  const wireguard = dialog?.form.kind === 'wireguard';
  const valid =
    dialog &&
    dialog.form.name.trim() &&
    dialog.form.address.trim() &&
    dialog.form.answer_ip.trim() &&
    (proxyKind || wireguard);

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Exit nodes"
        description="A redirect rule answers matching names with an exit's address, so that traffic leaves through that exit. Health is checked every 30 seconds; a down exit is skipped and queries resolve normally."
      >
        {writable && !dialog && (
          <Button onClick={openCreate}>
            <PlusIcon /> Add exit
          </Button>
        )}
      </PageHeader>
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
              Add a proxy or WireGuard endpoint, then point redirect rules at it from a profile.
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
                        {x.kind === 'socks5' ? 'SOCKS5' : x.kind === 'http' ? 'HTTP proxy' : 'WireGuard'}
                        {x.username && ' · auth'}
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
                          <Button variant="ghost" size="icon-sm" aria-label={`Edit ${x.name}`} onClick={() => openEdit(x)}>
                            <PencilIcon />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            disabled={checking === x.id}
                            onClick={() => check(x.id)}
                            title={x.kind === 'wireguard' ? 'WireGuard cannot be probed without a tunnel; stays unknown' : ''}
                          >
                            <RefreshCwIcon className={cn(checking === x.id && 'animate-spin')} />
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

      <Sheet open={!!dialog} onOpenChange={(open) => !open && setDialog(null)}>
        <SheetContent className="overflow-y-auto sm:max-w-lg">
          {dialog && (
            <form onSubmit={save} className="flex h-full flex-col gap-4">
              <SheetHeader>
                <SheetTitle>{dialog.mode === 'create' ? 'Add an exit' : `Edit ${dialog.exit.name}`}</SheetTitle>
                <SheetDescription>
                  A redirect rule sends matching names to the answer IP; the exit carries the traffic out.
                </SheetDescription>
              </SheetHeader>

              <div className="grid gap-4">
                <div className="grid grid-cols-2 gap-4">
                  <Field>
                    <FieldLabel htmlFor="ex-name">Name</FieldLabel>
                    <Input
                      id="ex-name"
                      placeholder="frankfurt-vps"
                      value={dialog.form.name}
                      onChange={(e) => setDialog({ ...dialog, form: { ...dialog.form, name: e.target.value } })}
                    />
                  </Field>
                  <Field>
                    <FieldLabel>Kind</FieldLabel>
                    <SimpleSelect
                      value={dialog.form.kind}
                      options={KINDS}
                      onChange={(kind) => setDialog({ ...dialog, form: { ...dialog.form, kind } })}
                    />
                  </Field>
                </div>

                <Field>
                  <FieldLabel htmlFor="ex-addr">{wireguard ? 'Endpoint' : 'Address'}</FieldLabel>
                  <Input
                    id="ex-addr"
                    className="font-mono"
                    placeholder={wireguard ? '203.0.113.9:51820' : 'proxy.example:1080'}
                    value={dialog.form.address}
                    onChange={(e) => setDialog({ ...dialog, form: { ...dialog.form, address: e.target.value } })}
                  />
                </Field>

                <Field>
                  <FieldLabel htmlFor="ex-answer">Answer IP</FieldLabel>
                  <Input
                    id="ex-answer"
                    className="font-mono"
                    placeholder="10.77.0.1"
                    value={dialog.form.answer_ip}
                    onChange={(e) => setDialog({ ...dialog, form: { ...dialog.form, answer_ip: e.target.value } })}
                  />
                  <FieldDescription>IPv4 returned to clients. Must route to the exit on your network.</FieldDescription>
                </Field>

                {proxyKind && (
                  <div className="grid grid-cols-2 gap-4">
                    <Field>
                      <FieldLabel htmlFor="ex-user">Username</FieldLabel>
                      <Input
                        id="ex-user"
                        className="font-mono"
                        autoComplete="off"
                        placeholder="optional"
                        value={dialog.form.username}
                        onChange={(e) => setDialog({ ...dialog, form: { ...dialog.form, username: e.target.value } })}
                      />
                    </Field>
                    <Field>
                      <FieldLabel htmlFor="ex-pass">Password</FieldLabel>
                      <Input
                        id="ex-pass"
                        className="font-mono"
                        type="password"
                        autoComplete="new-password"
                        placeholder="optional"
                        value={dialog.form.password}
                        onChange={(e) => setDialog({ ...dialog, form: { ...dialog.form, password: e.target.value } })}
                      />
                    </Field>
                  </div>
                )}

                {wireguard && (
                  <>
                    <Field data-invalid={!!dialog.form.config_err}>
                      <FieldLabel htmlFor="ex-wg">WireGuard config</FieldLabel>
                      <textarea
                        id="ex-wg"
                        className="h-40 w-full resize-none rounded-lg border bg-background p-3 font-mono text-xs outline-none focus:ring-2 focus:ring-ring/50"
                        spellCheck={false}
                        placeholder={`[Interface]\nPrivateKey = …\n\n[Peer]\nPublicKey = …\nEndpoint = 203.0.113.9:51820\nAllowedIPs = 0.0.0.0/0`}
                        value={dialog.form.config}
                        onChange={(e) => setDialog({ ...dialog, form: { ...dialog.form, config: e.target.value } })}
                      />
                      <FieldDescription>
                        Paste a wg-quick config to fill the tunnel keys below. The keys are stored here and loaded
                        again when you edit this exit.
                      </FieldDescription>
                    </Field>
                    <div className="grid gap-4">
                      <p className="text-xs text-muted-foreground">Or enter the tunnel fields directly:</p>
                      <label className="text-xs font-medium text-muted-foreground" htmlFor="wg-priv">
                        Private key
                      </label>
                      <Input
                        id="wg-priv"
                        className="font-mono text-xs"
                        autoComplete="off"
                        value={dialog.form.wg_private_key}
                        onChange={(e) => setDialog({ ...dialog, form: { ...dialog.form, wg_private_key: e.target.value } })}
                      />
                      <label className="text-xs font-medium text-muted-foreground" htmlFor="wg-peer">
                        Peer public key
                      </label>
                      <Input
                        id="wg-peer"
                        className="font-mono text-xs"
                        autoComplete="off"
                        value={dialog.form.wg_peer_key}
                        onChange={(e) => setDialog({ ...dialog, form: { ...dialog.form, wg_peer_key: e.target.value } })}
                      />
                      <div className="grid grid-cols-2 gap-4">
                        <Field>
                          <FieldLabel htmlFor="wg-psk">Preshared key</FieldLabel>
                          <Input
                            id="wg-psk"
                            className="font-mono text-xs"
                            autoComplete="off"
                            value={dialog.form.wg_preshared_key}
                            onChange={(e) =>
                              setDialog({ ...dialog, form: { ...dialog.form, wg_preshared_key: e.target.value } })
                            }
                          />
                        </Field>
                        <Field>
                          <FieldLabel htmlFor="wg-allowed">Allowed IPs</FieldLabel>
                          <Input
                            id="wg-allowed"
                            className="font-mono text-xs"
                            placeholder="0.0.0.0/0"
                            value={dialog.form.wg_allowed_ips}
                            onChange={(e) =>
                              setDialog({ ...dialog, form: { ...dialog.form, wg_allowed_ips: e.target.value } })
                            }
                          />
                        </Field>
                      </div>
                    </div>
                    <Alert>
                      <AlertDescription className="text-muted-foreground">
                        WireGuard cannot be probed without bringing up a tunnel, so health stays unknown and the exit
                        is treated as usable.
                      </AlertDescription>
                    </Alert>
                  </>
                )}
              </div>

              <SheetFooter className="mt-auto">
                <Button type="button" variant="outline" onClick={() => setDialog(null)}>
                  Cancel
                </Button>
                <Button type="submit" disabled={!valid || busy}>
                  {busy ? 'Saving…' : dialog.mode === 'create' ? 'Add exit' : 'Save changes'}
                </Button>
              </SheetFooter>
            </form>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
