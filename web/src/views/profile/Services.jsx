import { useEffect, useMemo, useState } from 'react';
import { BoxIcon, SearchIcon } from 'lucide-react';
import { api, can } from '../../api.js';
import { EmptyState, ErrorLine, SimpleSelect } from '../../ui.jsx';
import { cn } from '@/lib/utils';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { ToggleGroup, ToggleGroupItem } from '@/components/ui/toggle-group';
import { useProfileFilters } from './useProfileFilters.js';

const STATE_STYLE = {
  block: 'ring-block/40 bg-block-soft/40',
  allow: 'ring-ok/40 bg-ok-soft/40',
  redirect: 'ring-redirect/40 bg-redirect-soft/40',
};

const TRIGGER_STYLE = {
  block: 'text-block',
  allow: 'text-ok',
  redirect: 'text-redirect',
};

export default function Services({ me, profile }) {
  const [catalog, setCatalog] = useState(null);
  const [exits, setExits] = useState([]);
  const [query, setQuery] = useState('');
  const [group, setGroup] = useState('all');
  const { entries, error, setError, pending, update } = useProfileFilters(profile.id);
  const writable = can(me.role, 'operator');

  useEffect(() => {
    api('GET', '/catalog/services').then(setCatalog).catch((e) => setError(e.message));
    api('GET', '/exits').then(setExits).catch(() => {});
  }, [setError]);

  const options = useMemo(
    () => [
      { value: 'off', label: 'Not set' },
      { value: 'block', label: 'Block' },
      { value: 'allow', label: 'Allow' },
      ...exits.map((x) => ({ value: `exit:${x.id}`, label: `Route via ${x.name}` })),
    ],
    [exits],
  );

  const counts = useMemo(() => {
    const c = { block: 0, allow: 0, redirect: 0 };
    for (const e of Object.values(entries || {})) if (e.kind === 'service') c[e.state]++;
    return c;
  }, [entries]);

  const shown = useMemo(() => {
    if (!catalog) return [];
    const q = query.trim().toLowerCase();
    return catalog.services.filter(
      (s) =>
        (group === 'all' || (group === 'set' ? !!entries?.[`service:${s.id}`] : s.group === group)) &&
        (!q || s.name.toLowerCase().includes(q) || s.id.includes(q)),
    );
  }, [catalog, query, group, entries]);

  function change(service, value) {
    if (value.startsWith('exit:')) {
      update('service', service.id, { state: 'redirect', exit_id: Number(value.slice(5)) });
    } else {
      update('service', service.id, { state: value });
    }
  }

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <ErrorLine error={error} onDismiss={() => setError('')} />

      <div className="flex flex-col gap-3">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div className="relative sm:w-72">
            <SearchIcon className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              className="pl-8"
              placeholder="Search services"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
          <div className="flex gap-3 text-sm text-muted-foreground">
            <span><span className="font-medium text-block tabular-nums">{counts.block}</span> blocked</span>
            <span><span className="font-medium text-ok tabular-nums">{counts.allow}</span> allowed</span>
            <span><span className="font-medium text-redirect tabular-nums">{counts.redirect}</span> routed</span>
          </div>
        </div>
        {catalog && (
          <div className="-mx-1 max-w-[calc(100%+0.5rem)] overflow-x-auto px-1 pb-1">
            <ToggleGroup
              size="sm"
              value={[group]}
              onValueChange={(v) => v[0] && setGroup(v[0])}
              className="w-max"
            >
              {[{ id: 'all', name: 'All' }, { id: 'set', name: 'Configured' }, ...catalog.groups].map((g) => (
                <ToggleGroupItem
                  key={g.id}
                  value={g.id}
                  className="rounded-full px-3 data-pressed:bg-accent data-pressed:text-accent-foreground"
                >
                  {g.name}
                </ToggleGroupItem>
              ))}
            </ToggleGroup>
          </div>
        )}
        {exits.length === 0 && writable && (
          <p className="text-sm text-muted-foreground">
            To route a service through another location, add an{' '}
            <a className="text-primary underline-offset-4 hover:underline" href="#/exits">exit node</a> first.
          </p>
        )}
      </div>

      {!catalog || !entries ? (
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 9 }, (_, i) => (
            <Skeleton key={i} className="h-16 rounded-xl" />
          ))}
        </div>
      ) : shown.length === 0 ? (
        <Card>
          <CardContent>
            <EmptyState icon={BoxIcon} title="No services match">
              {group === 'set' ? 'Nothing is configured on this profile yet.' : 'Try a different search.'}
            </EmptyState>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-3">
          {shown.map((s) => {
            const entry = entries[`service:${s.id}`];
            const state = entry?.state || 'off';
            const value = state === 'redirect' ? `exit:${entry.exit_id}` : state;
            return (
              <div
                key={s.id}
                className={cn(
                  'flex items-center gap-3 rounded-xl bg-card p-3 ring-1 ring-foreground/10 transition-colors',
                  STATE_STYLE[state],
                )}
              >
                <ServiceIcon svg={s.icon_svg} />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-medium">{s.name}</div>
                  <div className="text-xs text-muted-foreground">
                    {s.domains} {s.domains === 1 ? 'domain' : 'domains'}
                  </div>
                </div>
                <SimpleSelect
                  className={cn('w-36 shrink-0', TRIGGER_STYLE[state])}
                  value={value}
                  options={options}
                  disabled={!writable || !!pending[`service:${s.id}`]}
                  onChange={(v) => change(s, v)}
                />
              </div>
            );
          })}
        </div>
      )}
      {catalog && (
        <p className="text-xs text-muted-foreground">
          Service definitions and icons from AdGuard's HostlistsRegistry, refreshed hourly.
        </p>
      )}
    </div>
  );
}

// The registry's SVGs use currentColor. Drawing them as a CSS mask over the
// text colour makes them follow the theme, and a mask can never run script.
function ServiceIcon({ svg }) {
  const url = `url("data:image/svg+xml,${encodeURIComponent(svg)}")`;
  return (
    <span className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-muted">
      <span
        aria-hidden="true"
        className="size-5 bg-foreground"
        style={{ maskImage: url, WebkitMaskImage: url, maskSize: 'contain', maskRepeat: 'no-repeat', maskPosition: 'center' }}
      />
    </span>
  );
}
