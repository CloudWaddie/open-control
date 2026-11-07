import { useEffect, useState } from 'react';
import { ActivityIcon, GlobeIcon, MonitorSmartphoneIcon, ShieldBanIcon } from 'lucide-react';
import { api } from '../api.js';
import { EmptyState, ErrorLine, Mono, PageHeader } from '../ui.jsx';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { ToggleGroup, ToggleGroupItem } from '@/components/ui/toggle-group';

const WINDOWS = [
  { id: '1h', label: '1h' },
  { id: '24h', label: '24h' },
  { id: '7d', label: '7d' },
];

export default function Overview() {
  const [windowId, setWindowId] = useState('1h');
  const [stats, setStats] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    const load = () =>
      api('GET', `/stats?window=${windowId}`)
        .then((s) => {
          if (!cancelled) {
            setStats(s);
            setError('');
          }
        })
        .catch((e) => !cancelled && setError(e.message));
    load();
    const timer = setInterval(load, 10000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [windowId]);

  return (
    <div className="flex flex-col gap-6">
      <PageHeader title="Overview" description="Query volume and the busiest names and clients. Refreshes every 10 seconds.">
        <ToggleGroup
          variant="outline"
          spacing={0}
          value={[windowId]}
          onValueChange={(v) => v[0] && setWindowId(v[0])}
          aria-label="Time window"
        >
          {WINDOWS.map((w) => (
            <ToggleGroupItem key={w.id} value={w.id} className="px-3 data-pressed:bg-accent data-pressed:text-accent-foreground">
              {w.label}
            </ToggleGroupItem>
          ))}
        </ToggleGroup>
      </PageHeader>

      <ErrorLine error={error} />

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
        <Stat label="Queries" value={stats?.total.toLocaleString()} />
        <Stat label="Blocked" value={stats?.blocked.toLocaleString()} tone="text-block" />
        <Stat className="col-span-2 sm:col-span-1" label="Blocked share" value={stats && `${stats.blocked_pct.toFixed(1)}%`}>
          {stats && (
            <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-muted">
              <div
                className="h-full rounded-full bg-block transition-[width] duration-500"
                style={{ width: `${Math.min(stats.blocked_pct, 100)}%` }}
              />
            </div>
          )}
        </Stat>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <TopList
          title="Top blocked"
          icon={ShieldBanIcon}
          rows={stats?.top_blocked}
          barClass="bg-block/15"
          empty="Nothing blocked in this window."
        />
        <TopList
          title="Top clients"
          icon={MonitorSmartphoneIcon}
          rows={stats?.top_clients}
          barClass="bg-primary/12"
          empty="No traffic in this window."
        />
      </div>
      <TopList
        title="Most queried"
        icon={GlobeIcon}
        rows={stats?.top_domains}
        barClass="bg-rewrite/12"
        empty="No traffic in this window."
      />
    </div>
  );
}

function Stat({ label, value, tone, className, children }) {
  return (
    <Card className={className}>
      <CardContent>
        <div className="text-sm text-muted-foreground">{label}</div>
        {value == null ? (
          <Skeleton className="mt-2 h-8 w-24" />
        ) : (
          <div className={`mt-1 text-3xl font-semibold tracking-tight tabular-nums ${tone || ''}`}>{value}</div>
        )}
        {children}
      </CardContent>
    </Card>
  );
}

// Each row gets a faint bar behind it, scaled to the top entry.
function TopList({ title, icon: Icon, rows, barClass, empty }) {
  const max = rows?.[0]?.count || 1;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Icon className="size-4 text-muted-foreground" />
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {!rows ? (
          <div className="flex flex-col gap-2">
            {[0, 1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-7" />
            ))}
          </div>
        ) : rows.length === 0 ? (
          <EmptyState icon={ActivityIcon} title={empty} />
        ) : (
          <ol className="flex flex-col gap-1">
            {rows.map((r) => (
              <li key={r.key} className="relative flex items-center justify-between gap-4 rounded-md px-2.5 py-1.5">
                <span
                  className={`absolute inset-y-0 left-0 rounded-md ${barClass}`}
                  style={{ width: `${(r.count / max) * 100}%` }}
                />
                <Mono className="relative min-w-0">{r.key}</Mono>
                <span className="relative text-sm tabular-nums text-muted-foreground">{r.count.toLocaleString()}</span>
              </li>
            ))}
          </ol>
        )}
      </CardContent>
    </Card>
  );
}
