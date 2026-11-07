import { useEffect, useState } from 'react';
import { RefreshCwIcon, ScrollTextIcon } from 'lucide-react';
import { api } from '../api.js';
import { EmptyState, ErrorLine, Mono, PageHeader, TableSkeleton } from '../ui.jsx';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

export default function Audit() {
  const [entries, setEntries] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const load = () => {
    setLoading(true);
    return api('GET', '/audit?limit=200')
      .then((e) => {
        setEntries(e);
        setError('');
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="flex flex-col gap-6">
      <PageHeader title="Audit log" description="Changes made through the API, most recent 200.">
        <Button variant="outline" onClick={load} disabled={loading}>
          <RefreshCwIcon className={loading ? 'animate-spin' : ''} /> Refresh
        </Button>
      </PageHeader>
      <ErrorLine error={error} />

      <Card>
        <CardContent>
          {!entries ? (
            <TableSkeleton rows={6} />
          ) : entries.length === 0 ? (
            <EmptyState icon={ScrollTextIcon} title="No activity yet">
              Changes to profiles, endpoints, blocklists, exits and tokens are recorded here.
            </EmptyState>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>Actor</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead className="hidden md:table-cell">Target</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {entries.map((a) => (
                  <TableRow key={a.id}>
                    <TableCell className="text-muted-foreground tabular-nums">
                      {new Date(a.ts * 1000).toLocaleString()}
                    </TableCell>
                    <TableCell className="font-medium">{a.actor}</TableCell>
                    <TableCell className="whitespace-normal">
                      <Mono className="rounded bg-muted px-1.5 py-0.5 text-xs">{a.action}</Mono>
                      <div className="mt-1 text-xs break-all text-muted-foreground md:hidden">{a.target}</div>
                    </TableCell>
                    <TableCell className="hidden max-w-sm whitespace-normal break-all text-muted-foreground md:table-cell">
                      {a.target}
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
