import { useEffect, useState } from 'react';
import {
  AppWindowIcon,
  BadgeAlertIcon,
  BiohazardIcon,
  ChevronDownIcon,
  DicesIcon,
  EyeIcon,
  EyeOffIcon,
  FishIcon,
  GlobeLockIcon,
  InfoIcon,
  LinkIcon,
  ListIcon,
  PlusIcon,
  RadioIcon,
  RefreshCwIcon,
  ServerCrashIcon,
  ShieldIcon,
  SkullIcon,
  SparklesIcon,
  Trash2Icon,
  UnplugIcon,
  UsersIcon,
} from 'lucide-react';
import { api, can } from '../../api.js';
import { Confirm, ErrorLine, SimpleSelect } from '../../ui.jsx';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Field, FieldDescription, FieldLabel } from '@/components/ui/field';
import { Input } from '@/components/ui/input';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Skeleton } from '@/components/ui/skeleton';
import { Switch } from '@/components/ui/switch';
import { useProfileFilters } from './useProfileFilters.js';

const ICONS = {
  eye: EyeIcon,
  biohazard: BiohazardIcon,
  fish: FishIcon,
  sparkles: SparklesIcon,
  'badge-alert': BadgeAlertIcon,
  'eye-off': EyeOffIcon,
  dices: DicesIcon,
  users: UsersIcon,
  skull: SkullIcon,
  unplug: UnplugIcon,
  radio: RadioIcon,
  'refresh-cw': RefreshCwIcon,
  'server-crash': ServerCrashIcon,
  link: LinkIcon,
  'app-window': AppWindowIcon,
  'globe-lock': GlobeLockIcon,
  shield: ShieldIcon,
};

const FORMATS = [
  { value: 'hosts', label: 'Hosts file or domain list' },
  { value: 'adguard', label: 'AdGuard / Adblock syntax' },
  { value: 'dnsmasq', label: 'dnsmasq' },
];

export default function Filters({ me, profile }) {
  const [catalog, setCatalog] = useState(null);
  const [lists, setLists] = useState(null);
  const [adding, setAdding] = useState(false);
  const { entries, error, setError, pending, update, reload } = useProfileFilters(profile.id);
  const writable = can(me.role, 'operator');

  const loadLists = () => api('GET', '/blocklists').then(setLists).catch((e) => setError(e.message));
  useEffect(() => {
    api('GET', '/catalog/filters').then(setCatalog).catch((e) => setError(e.message));
    loadLists();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const ready = catalog && entries && lists;
  const categories = catalog?.filter((f) => f.group === 'category') || [];
  const thirdParty = catalog?.filter((f) => f.group === 'list') || [];
  const onCount = (group) => (ready ? group.filter((f) => entries[`filter:${f.id}`]).length : 0);

  async function removeList(id) {
    try {
      await api('DELETE', `/blocklists/${id}`);
      await Promise.all([loadLists(), reload()]);
    } catch (e) {
      setError(e.message);
    }
  }

  return (
    <div className="flex flex-col gap-8">
      <ErrorLine error={error} onDismiss={() => setError('')} />

      <Section title="Categories" count={ready ? `${onCount(categories)} blocked` : null}>
        {ready
          ? categories.map((f) => (
              <FilterTile
                key={f.id}
                filter={f}
                entry={entries[`filter:${f.id}`]}
                busy={!!pending[`filter:${f.id}`]}
                writable={writable}
                onChange={(change) => update('filter', f.id, change)}
              />
            ))
          : Array.from({ length: 8 }, (_, i) => <Skeleton key={i} className="h-[7.5rem] rounded-xl" />)}
      </Section>

      <Section
        title="Third-party lists"
        count={ready ? `${onCount(thirdParty)} on` : null}
        note="Published as-is by their maintainers. Overlaps with the categories above are fine."
      >
        {ready
          ? thirdParty.map((f) => (
              <FilterTile
                key={f.id}
                filter={f}
                entry={entries[`filter:${f.id}`]}
                busy={!!pending[`filter:${f.id}`]}
                writable={writable}
                onChange={(change) => update('filter', f.id, change)}
              />
            ))
          : Array.from({ length: 4 }, (_, i) => <Skeleton key={i} className="h-[7.5rem] rounded-xl" />)}
      </Section>

      <Section title="Custom lists" note="Any hosts file, domain list or AdGuard-syntax list by URL. Refreshed hourly.">
        {ready &&
          lists.map((l) => {
            const key = `list:${l.id}`;
            const on = !!entries[key];
            let host = l.url;
            try {
              host = new URL(l.url).hostname;
            } catch {
              /* keep the raw URL */
            }
            return (
              <Tile
                key={l.id}
                on={on}
                icon={<ListIcon />}
                tint="bg-accent text-accent-foreground"
                title={host}
                status={on ? <span className="text-block">Blocking</span> : 'Off'}
                info={
                  <>
                    <div className="font-mono text-xs break-all">{l.url}</div>
                    <div className="text-muted-foreground">
                      {l.last_synced ? `Last downloaded ${l.last_synced} UTC` : 'Not downloaded yet'}
                    </div>
                    {writable && (
                      <Confirm
                        label="Delete list"
                        icon={<Trash2Icon />}
                        title="Delete this list?"
                        description="It is removed from every profile that uses it."
                        onConfirm={() => removeList(l.id)}
                      />
                    )}
                  </>
                }
                control={
                  <Switch
                    checked={on}
                    disabled={!writable || !!pending[key]}
                    onCheckedChange={(v) => update('list', String(l.id), { state: v ? 'block' : 'off' })}
                    aria-label={`Use ${l.url}`}
                  />
                }
              />
            );
          })}
        {ready && writable && (
          <button
            type="button"
            onClick={() => setAdding(true)}
            className="flex min-h-[7.5rem] flex-col items-center justify-center gap-2 rounded-xl border border-dashed text-sm text-muted-foreground transition-colors hover:border-primary/50 hover:bg-accent/40 hover:text-foreground"
          >
            <PlusIcon className="size-5" />
            Add custom list
          </button>
        )}
        {ready && !writable && lists.length === 0 && (
          <p className="text-sm text-muted-foreground">No custom lists.</p>
        )}
      </Section>

      <AddListDialog
        open={adding}
        onOpenChange={setAdding}
        profile={profile}
        onAdded={() => Promise.all([loadLists(), reload()])}
      />
    </div>
  );
}

function Section({ title, count, note, children }) {
  return (
    <section className="flex flex-col gap-3">
      <div className="flex items-baseline justify-between gap-4">
        <h2 className="font-medium">{title}</h2>
        {count && <span className="text-sm text-muted-foreground">{count}</span>}
      </div>
      {note && <p className="-mt-2 text-sm text-muted-foreground">{note}</p>}
      <div className="grid grid-cols-2 gap-2.5 sm:gap-3 lg:grid-cols-3 xl:grid-cols-4">{children}</div>
    </section>
  );
}

function Tile({ on, icon, tint, title, status, info, control }) {
  return (
    <div
      className={cn(
        'flex min-w-0 flex-col gap-3 rounded-xl bg-card p-3 ring-1 ring-foreground/10 transition-shadow sm:p-4',
        on && 'ring-primary/50',
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <span
          className={cn(
            'flex size-9 shrink-0 items-center justify-center rounded-lg transition-colors [&_svg]:size-[1.15rem]',
            on ? tint : 'bg-muted text-muted-foreground',
          )}
        >
          {icon}
        </span>
        {control}
      </div>
      <div className="min-w-0">
        <div className="truncate text-sm font-medium sm:text-base">{title}</div>
        <div className="mt-0.5 flex items-center justify-between gap-2 text-xs text-muted-foreground">
          <span className="flex min-w-0 items-center gap-1.5">{status}</span>
          <Popover>
            <PopoverTrigger
              render={
                <Button variant="ghost" size="icon-xs" className="-mr-1 shrink-0 text-muted-foreground" aria-label="About" />
              }
            >
              <InfoIcon />
            </PopoverTrigger>
            <PopoverContent align="end" className="w-72 gap-2">
              {info}
            </PopoverContent>
          </Popover>
        </div>
      </div>
    </div>
  );
}

const TINT = 'bg-block-soft text-block';

function FilterTile({ filter, entry, busy, writable, onChange }) {
  const Icon = ICONS[filter.icon] || ShieldIcon;
  const on = !!entry;
  const defaultLevel = (filter.levels.find((l) => l.id === 'balanced') || filter.levels[0]).id;
  const level = filter.levels.find((l) => l.id === entry?.level) || filter.levels.find((l) => l.id === defaultLevel);
  const leveled = filter.levels.length > 1;

  const status = !on ? (
    filter.group === 'list' ? 'Off' : 'Allowed'
  ) : (
    <>
      <span className="text-block">{filter.group === 'list' ? 'Blocking' : 'Blocked'}</span>
      {leveled && (
        <>
          <span className="text-border">|</span>
          <DropdownMenu>
            <DropdownMenuTrigger
              disabled={!writable || busy}
              className="inline-flex items-center gap-0.5 rounded px-1 -mx-1 text-foreground outline-none hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring/50 disabled:opacity-60"
            >
              {level.name}
              <ChevronDownIcon className="size-3" />
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start" className="w-64">
              <DropdownMenuRadioGroup
                value={level.id}
                onValueChange={(v) => v !== level.id && onChange({ state: 'block', level: v })}
              >
                {filter.levels.map((l) => (
                  <DropdownMenuRadioItem key={l.id} value={l.id} className="items-start py-1.5">
                    <span className="flex flex-col">
                      <span>{l.name}</span>
                      {l.note && <span className="text-xs text-muted-foreground">{l.note}</span>}
                    </span>
                  </DropdownMenuRadioItem>
                ))}
              </DropdownMenuRadioGroup>
            </DropdownMenuContent>
          </DropdownMenu>
        </>
      )}
    </>
  );

  return (
    <Tile
      on={on}
      icon={<Icon />}
      tint={filter.group === 'list' ? 'bg-accent text-accent-foreground' : TINT}
      title={filter.name}
      status={status}
      info={
        <>
          <div className="font-medium">{filter.name}</div>
          <p className="text-muted-foreground">{filter.description}</p>
          {leveled && on && level.note && <p>{level.note}</p>}
          <p className="text-xs text-muted-foreground">Source: {filter.source}</p>
        </>
      }
      control={
        <Switch
          checked={on}
          disabled={!writable || busy}
          onCheckedChange={(v) => onChange(v ? { state: 'block', level: defaultLevel } : { state: 'off' })}
          aria-label={`Block ${filter.name}`}
        />
      }
    />
  );
}

function AddListDialog({ open, onOpenChange, profile, onAdded }) {
  const [url, setUrl] = useState('');
  const [format, setFormat] = useState('hosts');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      await api('POST', '/blocklists', { url: url.trim(), format, profile_id: profile.id });
      await onAdded();
      setUrl('');
      onOpenChange(false);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <form onSubmit={submit} className="flex flex-col gap-4">
          <DialogHeader>
            <DialogTitle>Add custom list</DialogTitle>
            <DialogDescription>
              The list is turned on for {profile.name}. Other profiles can switch it on from their Filters tab.
            </DialogDescription>
          </DialogHeader>
          <Field data-invalid={!!error || undefined}>
            <FieldLabel htmlFor="list-url">List URL</FieldLabel>
            <Input
              id="list-url"
              type="url"
              className="font-mono"
              placeholder="https://example.org/hosts.txt"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              aria-invalid={!!error || undefined}
              autoFocus
            />
            {error ? (
              <FieldDescription className="text-destructive">{error}</FieldDescription>
            ) : (
              <FieldDescription>It is downloaded right away and refreshed hourly.</FieldDescription>
            )}
          </Field>
          <Field>
            <FieldLabel>Format</FieldLabel>
            <SimpleSelect value={format} options={FORMATS} onChange={setFormat} />
          </Field>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={busy || !url.trim()}>
              {busy ? 'Adding…' : 'Add list'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
