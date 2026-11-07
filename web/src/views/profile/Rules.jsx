import { useEffect, useState } from 'react';
import { ArrowRightIcon, PlusIcon, ShieldIcon, Trash2Icon } from 'lucide-react';
import { api, can } from '../../api.js';
import { Confirm, EmptyState, ErrorLine, Mono, SimpleSelect, TableSkeleton, Tag } from '../../ui.jsx';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Field, FieldLabel } from '@/components/ui/field';
import { Input } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

const KINDS = [
  { value: 'block', label: 'Block' },
  { value: 'allow', label: 'Allow' },
  { value: 'rewrite', label: 'Rewrite' },
  { value: 'redirect', label: 'Redirect via exit' },
];

const MATCHERS = [
  { value: 'domain', label: 'Exact domain' },
  { value: 'wildcard', label: 'Domain + subdomains' },
  { value: 'tld', label: 'Top-level domain' },
];

export default function Rules({ me, profile }) {
  const writable = can(me.role, 'operator');
  const [error, onError] = useState('');
  const [rules, setRules] = useState(null);
  const [exits, setExits] = useState([]);
  const [form, setForm] = useState({
    kind: 'block',
    matcher: 'domain',
    pattern: '',
    answer: '',
    exit_id: '',
  });

  const load = () =>
    api('GET', `/profiles/${profile.id}/rules`)
      .then(setRules)
      .catch((e) => onError(e.message));

  useEffect(() => {
    load();
    api('GET', '/exits')
      .then((list) => {
        setExits(list);
        setForm((f) => ({ ...f, exit_id: f.exit_id || String(list[0]?.id ?? '') }));
      })
      .catch(() => {});
  }, [profile.id]);

  const exitName = (id) => exits.find((x) => String(x.id) === String(id))?.name ?? `exit #${id}`;

  async function add(e) {
    e.preventDefault();
    onError('');
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

  const needsExit = form.kind === 'redirect' && exits.length === 0;
  const canAdd = form.pattern.trim() && (form.kind !== 'rewrite' || form.answer.trim()) && !needsExit;

  return (
    <div className="flex flex-col gap-4">
      <ErrorLine error={error} onDismiss={() => onError('')} />
      <Card>
        <CardHeader>
          <CardTitle>Custom rules</CardTitle>
          <CardDescription>
            Rules win over services and filters. Block, allow, answer with your own address, or send a domain
            through an exit.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-6">
          {!rules ? (
            <TableSkeleton />
          ) : rules.length === 0 ? (
            <EmptyState icon={ShieldIcon} title="No custom rules">
              Blocklist subscriptions still apply. Add a rule to block, allow, rewrite or redirect specific
              names.
            </EmptyState>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Kind</TableHead>
                  <TableHead>Pattern</TableHead>
                  <TableHead className="hidden sm:table-cell">Matcher</TableHead>
                  <TableHead>Answer</TableHead>
                  {writable && <TableHead className="w-0" />}
                </TableRow>
              </TableHeader>
              <TableBody>
                {rules.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell>
                      <Tag tone={r.kind}>{r.kind}</Tag>
                    </TableCell>
                    <TableCell className="whitespace-normal">
                      <Mono>
                        {r.matcher === 'wildcard'
                          ? `*.${r.pattern}`
                          : r.matcher === 'tld'
                            ? `.${r.pattern.replace(/^\./, '')}`
                            : r.pattern}
                      </Mono>
                    </TableCell>
                    <TableCell className="hidden text-muted-foreground sm:table-cell">
                      {MATCHERS.find((m) => m.value === r.matcher)?.label ?? r.matcher}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {r.kind === 'redirect' ? (
                        <span className="inline-flex items-center gap-1">
                          <ArrowRightIcon className="size-3.5" />
                          {exitName(r.answer)}
                        </span>
                      ) : r.answer ? (
                        <Mono>{r.answer}</Mono>
                      ) : (
                        '—'
                      )}
                    </TableCell>
                    {writable && (
                      <TableCell className="text-right">
                        <Confirm
                          label="Delete"
                          icon={<Trash2Icon />}
                          title="Delete this rule?"
                          description={`${r.kind} ${r.pattern} stops applying to clients on ${profile.name}.`}
                          onConfirm={() => remove(r.id)}
                        />
                      </TableCell>
                    )}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}

          {writable && (
            <form onSubmit={add} className="flex flex-col gap-4 rounded-lg bg-muted/50 p-4">
              <div className="text-sm font-medium">Add a rule</div>
              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                <Field>
                  <FieldLabel>Action</FieldLabel>
                  <SimpleSelect
                    value={form.kind}
                    options={KINDS}
                    // rewrites are exact-domain only; the API rejects anything else
                    onChange={(kind) =>
                      setForm({ ...form, kind, matcher: kind === 'rewrite' ? 'domain' : form.matcher })
                    }
                  />
                </Field>
                <Field>
                  <FieldLabel>Match</FieldLabel>
                  <SimpleSelect
                    value={form.matcher}
                    options={MATCHERS}
                    disabled={form.kind === 'rewrite'}
                    onChange={(matcher) => setForm({ ...form, matcher })}
                  />
                </Field>
                <Field>
                  <FieldLabel htmlFor="rule-pattern">Pattern</FieldLabel>
                  <Input
                    id="rule-pattern"
                    className="font-mono"
                    placeholder={form.matcher === 'tld' ? 'xyz' : 'example.com'}
                    value={form.pattern}
                    onChange={(e) => setForm({ ...form, pattern: e.target.value })}
                  />
                </Field>
                {form.kind === 'rewrite' && (
                  <Field>
                    <FieldLabel htmlFor="rule-answer">Answer</FieldLabel>
                    <Input
                      id="rule-answer"
                      className="font-mono"
                      placeholder="IP or hostname"
                      value={form.answer}
                      onChange={(e) => setForm({ ...form, answer: e.target.value })}
                    />
                  </Field>
                )}
                {form.kind === 'redirect' && (
                  <Field>
                    <FieldLabel>Exit</FieldLabel>
                    {exits.length === 0 ? (
                      <p className="py-1.5 text-sm text-muted-foreground">
                        No exits yet.{' '}
                        <a className="text-primary underline-offset-4 hover:underline" href="#/exits">
                          Add one
                        </a>
                        .
                      </p>
                    ) : (
                      <SimpleSelect
                        value={String(form.exit_id)}
                        options={exits.map((x) => ({ value: String(x.id), label: x.name }))}
                        onChange={(exit_id) => setForm({ ...form, exit_id })}
                      />
                    )}
                  </Field>
                )}
              </div>
              <Button type="submit" className="self-start" disabled={!canAdd}>
                <PlusIcon /> Add rule
              </Button>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
