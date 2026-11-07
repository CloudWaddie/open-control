import { useEffect, useState } from 'react';
import {
  AppWindowIcon,
  BadgeAlertIcon,
  BugIcon,
  DicesIcon,
  EyeOffIcon,
  GlobeLockIcon,
  LinkIcon,
  ListIcon,
  ListXIcon,
  MegaphoneIcon,
  RefreshCwIcon,
  SkullIcon,
  UnplugIcon,
  UsersIcon,
} from 'lucide-react';
import { api, can } from '../../api.js';
import { EmptyState, ErrorLine, Mono } from '../../ui.jsx';
import { cn } from '@/lib/utils';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { Switch } from '@/components/ui/switch';
import { ToggleGroup, ToggleGroupItem } from '@/components/ui/toggle-group';
import { useProfileFilters } from './useProfileFilters.js';

const ICONS = {
  megaphone: MegaphoneIcon,
  bug: BugIcon,
  'badge-alert': BadgeAlertIcon,
  'eye-off': EyeOffIcon,
  dices: DicesIcon,
  users: UsersIcon,
  skull: SkullIcon,
  'app-window': AppWindowIcon,
  unplug: UnplugIcon,
  'refresh-cw': RefreshCwIcon,
  link: LinkIcon,
  'globe-lock': GlobeLockIcon,
};

// Each category gets its own tint so the grid is scannable at a glance.
const TINTS = {
  ads: 'bg-rewrite-soft text-rewrite',
  malware: 'bg-block-soft text-block',
  fakes: 'bg-warn-soft text-warn',
  adult: 'bg-redirect-soft text-redirect',
  gambling: 'bg-ok-soft text-ok',
  social: 'bg-rewrite-soft text-rewrite',
  piracy: 'bg-muted text-foreground',
  popups: 'bg-warn-soft text-warn',
  bypass: 'bg-redirect-soft text-redirect',
  dyndns: 'bg-muted text-foreground',
  shorteners: 'bg-accent text-accent-foreground',
  spamtlds: 'bg-block-soft text-block',
};

export default function Filters({ me, profile }) {
  const [catalog, setCatalog] = useState(null);
  const [lists, setLists] = useState(null);
  const { entries, error, setError, pending, update } = useProfileFilters(profile.id);
  const writable = can(me.role, 'operator');

  useEffect(() => {
    api('GET', '/catalog/filters').then(setCatalog).catch((e) => setError(e.message));
    api('GET', '/blocklists').then(setLists).catch((e) => setError(e.message));
  }, [setError]);

  const loading = !catalog || !entries;
  const enabled = entries ? Object.values(entries).filter((e) => e.kind === 'filter').length : 0;

  return (
    <div className="flex flex-col gap-6">
      <ErrorLine error={error} onDismiss={() => setError('')} />

      <section className="flex flex-col gap-3">
        <div className="flex items-baseline justify-between gap-4">
          <h2 className="font-medium">Categories</h2>
          {!loading && <span className="text-sm text-muted-foreground">{enabled} on</span>}
        </div>
        <div className="grid gap-3 md:grid-cols-2">
          {loading
            ? Array.from({ length: 6 }, (_, i) => <Skeleton key={i} className="h-24 rounded-xl" />)
            : catalog.map((f) => (
                <FilterCard
                  key={f.id}
                  filter={f}
                  entry={entries[`filter:${f.id}`]}
                  busy={!!pending[`filter:${f.id}`]}
                  writable={writable}
                  onChange={(change) => update('filter', f.id, change)}
                />
              ))}
        </div>
        <p className="text-xs text-muted-foreground">
          Lists by HaGeZi, OISD and Phishing Army, refreshed hourly. Newly enabled lists download in the background
          and apply within a few seconds.
        </p>
      </section>

      <Card>
        <CardHeader>
          <CardTitle>Your blocklists</CardTitle>
          <CardDescription>
            Subscriptions added on the <a className="text-primary underline-offset-4 hover:underline" href="#/blocklists">Blocklists</a> page.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {!lists || !entries ? (
            <Skeleton className="h-10" />
          ) : lists.length === 0 ? (
            <EmptyState icon={ListXIcon} title="No custom blocklists" />
          ) : (
            <ul className="flex flex-col divide-y">
              {lists.map((l) => {
                const key = `list:${l.id}`;
                return (
                  <li key={l.id} className="flex items-center gap-3 py-2.5 first:pt-0 last:pb-0">
                    <ListIcon className="size-4 shrink-0 text-muted-foreground" />
                    <Mono className="min-w-0 flex-1 truncate">{l.url}</Mono>
                    <Switch
                      checked={!!entries[key]}
                      disabled={!writable || !!pending[key]}
                      onCheckedChange={(on) => update('list', String(l.id), { state: on ? 'block' : 'off' })}
                      aria-label={`Use ${l.url}`}
                    />
                  </li>
                );
              })}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function FilterCard({ filter, entry, busy, writable, onChange }) {
  const Icon = ICONS[filter.icon] || ListIcon;
  const on = !!entry;
  const level = entry?.level || filter.levels[0].id;
  const levelInfo = filter.levels.find((l) => l.id === level);
  // First level marked "Recommended", else the first one.
  const defaultLevel = (filter.levels.find((l) => l.note === 'Recommended') || filter.levels[0]).id;

  return (
    <div
      className={cn(
        'flex flex-col gap-3 rounded-xl bg-card p-4 ring-1 ring-foreground/10 transition-shadow',
        on && 'ring-primary/40',
      )}
    >
      <div className="flex items-start gap-3">
        <span className={cn('flex size-10 shrink-0 items-center justify-center rounded-lg', TINTS[filter.id] || 'bg-muted')}>
          <Icon className="size-5" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="font-medium">{filter.name}</div>
          <p className="mt-0.5 text-sm text-muted-foreground">{filter.description}</p>
        </div>
        <Switch
          checked={on}
          disabled={!writable || busy}
          onCheckedChange={(v) => onChange(v ? { state: 'block', level: defaultLevel } : { state: 'off' })}
          aria-label={`Block ${filter.name}`}
        />
      </div>
      {on && filter.levels.length > 1 && (
        <div className="flex flex-col gap-1.5 pl-13">
          <ToggleGroup
            variant="outline"
            size="sm"
            spacing={0}
            value={[level]}
            disabled={!writable || busy}
            onValueChange={(v) => v[0] && v[0] !== level && onChange({ state: 'block', level: v[0] })}
            className="flex-wrap"
          >
            {filter.levels.map((l) => (
              <ToggleGroupItem
                key={l.id}
                value={l.id}
                className="data-pressed:bg-accent data-pressed:text-accent-foreground"
              >
                {l.name}
              </ToggleGroupItem>
            ))}
          </ToggleGroup>
          {levelInfo?.note && <span className="text-xs text-muted-foreground">{levelInfo.note}</span>}
        </div>
      )}
    </div>
  );
}
