import { useEffect, useRef, useState } from 'react';
import { ActivityIcon, SearchIcon } from 'lucide-react';
import { api } from '../api.js';
import { EmptyState, ErrorLine, Mono, PageHeader, SimpleSelect, TableSkeleton, Tag } from '../ui.jsx';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

const MAX_ROWS = 500;

const ACTIONS = [
  { value: 'all', label: 'All actions' },
  { value: 'block', label: 'Blocked' },
  { value: 'forward', label: 'Forwarded' },
  { value: 'rewrite', label: 'Rewritten' },
  { value: 'refused', label: 'Refused' },
  { value: 'error', label: 'Error' },
];

function query(params) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== '' && v != null) q.set(k, v);
  const s = q.toString();
  return s ? `?${s}` : '';
}

// Live tail: newest queries first. "Live" polls for rows newer than the newest
// one on screen, so nothing is fetched twice.
export default function Logs() {
  const [rows, setRows] = useState(null);
  const [action, setAction] = useState('');
  const [client, setClient] = useState('');
  const [live, setLive] = useState(true);
  const [error, setError] = useState('');
  const newest = useRef(0);

  const filters = { action, client };

  // Full reload when filters change.
  useEffect(() => {
    let cancelled = false;
    setRows(null);
    api('GET', `/logs${query({ ...filters, limit: 200 })}`)
      .then((r) => {
        if (cancelled) return;
        setRows(r);
        newest.current = r[0]?.id ?? 0;
        setError('');
      })
      .catch((e) => !cancelled && setError(e.message));
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [action, client]);

  // Tail: fetch anything newer than what's on screen.
  useEffect(() => {
    if (!live) return;
    const timer = setInterval(() => {
      api('GET', `/logs${query({ ...filters, after: newest.current, limit: 200 })}`)
        .then((fresh) => {
          if (fresh.length === 0) return;
          newest.current = fresh[0].id;
          setRows((prev) => [...fresh, ...(prev || [])].slice(0, MAX_ROWS));
        })
        .catch((e) => setError(e.message));
    }, 2000);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live, action, client]);

  return (
    <div className="flex flex-col gap-6">
      <PageHeader title="Query log" description="Newest first. Live mode checks for new queries every 2 seconds.">
        <Label className="flex items-center gap-2 rounded-lg border px-3 py-1.5">
          {live && (
            <span className="relative flex size-2">
              <span className="absolute inline-flex size-full animate-ping rounded-full bg-ok opacity-60 motion-reduce:hidden" />
              <span className="relative inline-flex size-2 rounded-full bg-ok" />
            </span>
          )}
          Live
          <Switch checked={live} onCheckedChange={setLive} />
        </Label>
      </PageHeader>

      <ErrorLine error={error} />

      <Card>
        <CardContent className="flex flex-col gap-4">
          <div className="flex flex-col gap-2 sm:flex-row">
            <SimpleSelect
              className="sm:w-44"
              value={action || 'all'}
              onChange={(v) => setAction(v === 'all' ? '' : v)}
              options={ACTIONS}
            />
            <div className="relative sm:max-w-xs sm:flex-1">
              <SearchIcon className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                className="pl-8"
                placeholder="Client address"
                value={client}
                onChange={(e) => setClient(e.target.value)}
              />
            </div>
          </div>

          {!rows ? (
            <TableSkeleton rows={6} />
          ) : rows.length === 0 ? (
            <EmptyState icon={ActivityIcon} title="No queries yet">
              {action || client
                ? 'Nothing matches these filters.'
                : 'Point a device at this resolver and its queries will show up here.'}
            </EmptyState>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-24">Time</TableHead>
                  <TableHead className="hidden md:table-cell">Client</TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead className="hidden sm:table-cell">Type</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead className="hidden lg:table-cell">Reason</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell className="text-muted-foreground tabular-nums">
                      {new Date(r.ts * 1000).toLocaleTimeString()}
                    </TableCell>
                    <TableCell className="hidden md:table-cell">
                      <Mono>{r.client}</Mono>
                    </TableCell>
                    <TableCell className="max-w-72 whitespace-normal">
                      <Mono>{r.qname}</Mono>
                      <div className="mt-0.5 text-xs text-muted-foreground md:hidden">{r.client}</div>
                    </TableCell>
                    <TableCell className="hidden text-muted-foreground sm:table-cell">{r.qtype}</TableCell>
                    <TableCell>
                      <Tag tone={r.action}>{r.action}</Tag>
                    </TableCell>
                    <TableCell className="hidden max-w-64 truncate text-muted-foreground lg:table-cell" title={r.reason}>
                      {r.reason}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
