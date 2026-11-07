import { useEffect, useState } from 'react';
import { ArrowLeftIcon, ChevronRightIcon, PlusIcon, ShieldIcon } from 'lucide-react';
import { api, can } from '../api.js';
import { EmptyState, ErrorLine, PageHeader } from '../ui.jsx';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import Filters from './profile/Filters.jsx';
import Services from './profile/Services.jsx';
import Rules from './profile/Rules.jsx';

const TABS = [
  { id: 'filters', label: 'Filters', view: Filters },
  { id: 'services', label: 'Services', view: Services },
  { id: 'rules', label: 'Custom rules', view: Rules },
];

export default function Profiles({ me, params }) {
  const [profiles, setProfiles] = useState(null);
  const [error, setError] = useState('');

  const load = () =>
    api('GET', '/profiles')
      .then(setProfiles)
      .catch((e) => setError(e.message));

  useEffect(() => {
    load();
  }, []);

  const id = Number(params[0]);
  if (id) {
    const profile = profiles?.find((p) => p.id === id);
    if (profiles && !profile) {
      return <ErrorLine error={`Profile #${id} does not exist.`} />;
    }
    return <ProfileDetail me={me} profile={profile} tab={params[1]} />;
  }
  return <ProfileIndex me={me} profiles={profiles} error={error} onCreated={load} />;
}

function ProfileIndex({ me, profiles, error, onCreated }) {
  const [name, setName] = useState('');
  const [createError, setCreateError] = useState('');
  const writable = can(me.role, 'operator');

  async function create(e) {
    e.preventDefault();
    setCreateError('');
    try {
      const p = await api('POST', '/profiles', { name: name.trim() });
      setName('');
      await onCreated();
      window.location.hash = `#/profiles/${p.id}/filters`;
    } catch (err) {
      setCreateError(err.message);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Profiles"
        description="A profile is a set of filters, services and rules. Each endpoint uses one profile."
      >
        {writable && (
          <form onSubmit={create} className="flex gap-2">
            <Input
              className="w-44"
              placeholder="New profile"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
            <Button type="submit" disabled={!name.trim()}>
              <PlusIcon /> Create
            </Button>
          </form>
        )}
      </PageHeader>
      <ErrorLine error={error || createError} />

      {!profiles ? (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {[0, 1, 2].map((i) => (
            <Skeleton key={i} className="h-20 rounded-xl" />
          ))}
        </div>
      ) : profiles.length === 0 ? (
        <Card>
          <CardContent>
            <EmptyState icon={ShieldIcon} title="No profiles">
              Create a profile to choose what gets blocked.
            </EmptyState>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {profiles.map((p) => (
            <a
              key={p.id}
              href={`#/profiles/${p.id}/filters`}
              className="group flex items-center gap-3 rounded-xl bg-card p-4 ring-1 ring-foreground/10 transition-colors hover:bg-accent/50 hover:ring-primary/30"
            >
              <span className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-accent text-accent-foreground">
                <ShieldIcon className="size-5" />
              </span>
              <span className="min-w-0 flex-1">
                <span className="block truncate font-medium">{p.name}</span>
                <span className="text-sm text-muted-foreground">#{p.id}</span>
              </span>
              <ChevronRightIcon className="size-4 text-muted-foreground transition-transform group-hover:translate-x-0.5" />
            </a>
          ))}
        </div>
      )}
    </div>
  );
}

function ProfileDetail({ me, profile, tab }) {
  const active = TABS.find((t) => t.id === tab) || TABS[0];
  const View = active.view;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-4">
        <a
          href="#/profiles"
          className="inline-flex w-fit items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeftIcon className="size-4" /> Profiles
        </a>
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          {profile ? (
            <h1 className="text-xl font-semibold tracking-tight">{profile.name}</h1>
          ) : (
            <Skeleton className="h-7 w-40" />
          )}
          <Tabs value={active.id} onValueChange={(v) => (window.location.hash = `#/profiles/${profile?.id}/${v}`)}>
            <TabsList>
              {TABS.map((t) => (
                <TabsTrigger key={t.id} value={t.id} className="px-3">
                  {t.label}
                </TabsTrigger>
              ))}
            </TabsList>
          </Tabs>
        </div>
      </div>
      {profile && <View key={`${profile.id}-${active.id}`} me={me} profile={profile} />}
    </div>
  );
}
