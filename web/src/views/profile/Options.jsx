import { useEffect, useState } from 'react';
import { ClockIcon, LockIcon, ShieldCheckIcon, WaypointsIcon, ZapIcon } from 'lucide-react';
import { api, can } from '../../api.js';
import { ErrorLine, SimpleSelect } from '../../ui.jsx';
import { cn } from '@/lib/utils';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Field, FieldDescription, FieldLabel } from '@/components/ui/field';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { Switch } from '@/components/ui/switch';

const BLOCK_RESPONSES = [
  { value: 'nxdomain', label: 'NXDOMAIN — name does not exist' },
  { value: 'zero', label: '0.0.0.0 / ::' },
  { value: 'nodata', label: 'NODATA — empty answer' },
  { value: 'refused', label: 'REFUSED' },
  { value: 'custom', label: 'Custom IP addresses' },
];

const YOUTUBE = [
  { value: '', label: 'Off' },
  { value: 'moderate', label: 'Moderate restriction' },
  { value: 'strict', label: 'Strict restriction' },
];

const UPSTREAMS = [
  { value: '', label: 'Server default' },
  { value: 'cloudflare', label: 'Cloudflare (1.1.1.1)' },
  { value: 'quad9', label: 'Quad9 (9.9.9.9)' },
  { value: 'google', label: 'Google (8.8.8.8)' },
  { value: 'adguard', label: 'AdGuard unfiltered (94.140.14.140)' },
  { value: 'custom', label: 'Custom addresses…' },
];

const ECS_MODES = [
  { value: '', label: 'Off' },
  { value: 'client', label: "The client's own network (/24 IPv4, /56 IPv6)" },
  { value: 'custom', label: 'A fixed network…' },
];

const PAUSES = [
  { label: '1 min', seconds: 60 },
  { label: '5 min', seconds: 300 },
  { label: '30 min', seconds: 1800 },
  { label: '1 hour', seconds: 3600 },
];

const DEFAULTS = {
  block_response: 'nxdomain',
  block_ipv4: '',
  block_ipv6: '',
  block_ttl: undefined,
  redirect_ttl: undefined,
  bypass_ttl: undefined,
  safe_search: false,
  youtube: '',
  rebind_protection: false,
  block_exfil: false,
  upstream: '',
  disable_dnssec: false,
  ecs: '',
  compat_mode: false,
  dns64: false,
  dns64_prefix: '',
  cname_flatten: false,
  disabled_until: 0,
  locked: false,
  lock_message: '',
};

// load fills presentation-only fields: a stored upstream that is not a preset,
// and a fixed ECS network, show up as the "custom…" select entries.
function load(p) {
  const v = { ...DEFAULTS, ...p, block_response: p.block_response || 'nxdomain' };
  if (!UPSTREAMS.some((u) => u.value === v.upstream)) v.upstream = 'custom';
  if (v.ecs && v.ecs !== 'client') {
    v.ecsText = v.ecs;
    v.ecs = 'custom';
  }
  return v;
}

export default function Options({ me, profile }) {
  const writable = can(me.role, 'operator');
  const admin = can(me.role, 'admin');
  const [o, setO] = useState(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  useEffect(() => {
    api('GET', `/profiles/${profile.id}/options`)
      .then((p) => setO(load(p)))
      .catch((e) => setError(e.message));
  }, [profile.id]);

  async function save(patch, msg) {
    if (!writable) return;
    const next = { ...o, ...patch };
    setO(next);
    setError('');
    setNotice('');
    try {
      const saved = await api('PUT', `/profiles/${profile.id}/options`, next);
      setO(load(saved));
      if (msg) setNotice(msg);
    } catch (e) {
      setError(e.message);
      api('GET', `/profiles/${profile.id}/options`)
        .then((s) => setO(load(s)))
        .catch(() => {});
    }
  }

  if (!o) {
    return <Skeleton className="h-96 w-full" />;
  }

  const paused = o.disabled_until > Date.now() / 1000;

  return (
    <div className="flex flex-col gap-6">
      <ErrorLine error={error} onDismiss={() => setError('')} />
      {notice && (
        <Alert>
          <AlertDescription className="text-foreground">{notice}</AlertDescription>
        </Alert>
      )}

      {/* Pause and lock state, mirroring Control D's profile banners */}
      {paused && (
        <Alert className="border-ok/40 bg-ok-soft/30">
          <AlertDescription className="flex items-center gap-2 text-foreground">
            <ClockIcon className="size-4 text-ok" />
            Filtering is paused for this profile for {humanUntil(o.disabled_until)} — everything resolves unfiltered.
            {writable && (
              <Button variant="outline" size="sm" className="ml-2" onClick={() => save({ disabled_until: 0 }, 'Filtering resumed.')}>
                Resume
              </Button>
            )}
          </AlertDescription>
        </Alert>
      )}
      {o.locked && (
        <Alert className="border-warn/40 bg-warn-soft/30">
          <AlertDescription className="flex items-center gap-2 text-foreground">
            <LockIcon className="size-4 text-warn" />
            {o.lock_message || 'This profile is locked — its settings can only be changed by an admin.'}
          </AlertDescription>
        </Alert>
      )}

      <PauseCard writable={writable} paused={paused} onPause={(secs) => save({ disabled_until: Math.floor(Date.now() / 1000) + secs })} onResume={() => save({ disabled_until: 0 }, 'Filtering resumed.')} />

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ZapIcon className="size-4 text-muted-foreground" /> Blocked answers
          </CardTitle>
          <CardDescription>What the resolver sends back when a domain is blocked.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-6">
          <Field>
            <FieldLabel htmlFor="opt-block-resp">Block response</FieldLabel>
            <SimpleSelect
              id="opt-block-resp"
              value={o.block_response}
              options={BLOCK_RESPONSES}
              disabled={!writable || o.locked}
              onChange={(v) => save({ block_response: v })}
            />
          </Field>
          {o.block_response === 'custom' && (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <Field>
                <FieldLabel htmlFor="opt-bipv4">IPv4 answer</FieldLabel>
                <Input
                  id="opt-bipv4"
                  className="font-mono"
                  placeholder="0.0.0.0"
                  disabled={!writable || o.locked}
                  value={o.block_ipv4 || ''}
                  onChange={(e) => setO({ ...o, block_ipv4: e.target.value })}
                  onBlur={() => save({ block_ipv4: o.block_ipv4 })}
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="opt-bipv6">IPv6 answer</FieldLabel>
                <Input
                  id="opt-bipv6"
                  className="font-mono"
                  placeholder="::"
                  disabled={!writable || o.locked}
                  value={o.block_ipv6 || ''}
                  onChange={(e) => setO({ ...o, block_ipv6: e.target.value })}
                  onBlur={() => save({ block_ipv6: o.block_ipv6 })}
                />
              </Field>
            </div>
          )}
          <div className="grid gap-4 sm:grid-cols-3">
            <Field>
              <FieldLabel htmlFor="opt-bttl">Block TTL (s)</FieldLabel>
              <Input
                id="opt-bttl"
                type="number"
                min="0"
                max="86400"
                placeholder="10"
                disabled={!writable || o.locked}
                value={o.block_ttl ?? ''}
                onChange={(e) => setO({ ...o, block_ttl: e.target.value === '' ? undefined : Number(e.target.value) })}
                onBlur={() => save({ block_ttl: o.block_ttl })}
              />
              <FieldDescription>How long a blocked answer may be cached.</FieldDescription>
            </Field>
            <Field>
              <FieldLabel htmlFor="opt-rttl">Redirect TTL (s)</FieldLabel>
              <Input
                id="opt-rttl"
                type="number"
                min="0"
                max="86400"
                placeholder="60"
                disabled={!writable || o.locked}
                value={o.redirect_ttl ?? ''}
                onChange={(e) => setO({ ...o, redirect_ttl: e.target.value === '' ? undefined : Number(e.target.value) })}
                onBlur={() => save({ redirect_ttl: o.redirect_ttl })}
              />
              <FieldDescription>TTL for rewrite and redirect answers.</FieldDescription>
            </Field>
            <Field>
              <FieldLabel htmlFor="opt-pttl">Allowed-TTL cap (s)</FieldLabel>
              <Input
                id="opt-pttl"
                type="number"
                min="0"
                max="86400"
                placeholder="upstream TTL"
                disabled={!writable || o.locked}
                value={o.bypass_ttl ?? ''}
                onChange={(e) => setO({ ...o, bypass_ttl: e.target.value === '' ? undefined : Number(e.target.value) })}
                onBlur={() => save({ bypass_ttl: o.bypass_ttl })}
              />
              <FieldDescription>Caps every normal answer's TTL; empty leaves it.</FieldDescription>
            </Field>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheckIcon className="size-4 text-muted-foreground" /> Content
          </CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4">
          <ToggleRow
            title="SafeSearch"
            description="Forces safe search on Google, Bing, DuckDuckGo, Brave and Yandex."
            checked={o.safe_search}
            writable={writable}
            locked={o.locked}
            onChange={(v) => save({ safe_search: v })}
          />
          <ToggleRow
            title="Block exfiltration"
            description="Blocks data-exfiltration domains (e.g. passwords sent inside DNS lookups past your network)."
            checked={o.block_exfil}
            writable={writable}
            locked={o.locked}
            onChange={(v) => save({ block_exfil: v })}
          />
          <ToggleRow
            title="Rebind protection"
            description="Drops answers that point inside private networks — defends against DNS rebinding attacks."
            checked={o.rebind_protection}
            writable={writable}
            locked={o.locked}
            onChange={(v) => save({ rebind_protection: v })}
          />
          <Field>
            <FieldLabel htmlFor="opt-yt">Restricted YouTube</FieldLabel>
            <SimpleSelect id="opt-yt" value={o.youtube} options={YOUTUBE} disabled={!writable || o.locked} onChange={(v) => save({ youtube: v })} />
          </Field>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <WaypointsIcon className="size-4 text-muted-foreground" /> Resolution
          </CardTitle>
          <CardDescription>Where this profile forwards and how answers are shaped.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-6">
          <Field>
            <FieldLabel htmlFor="opt-up">Upstream</FieldLabel>
            <SimpleSelect
              id="opt-up"
              value={o.upstream || ''}
              options={UPSTREAMS}
              disabled={!writable || o.locked}
              onChange={(v) => (v === 'custom' ? setO({ ...o, upstream: 'custom' }) : save({ upstream: v }))}
            />
            {o.upstream === 'custom' && (
              <div className="mt-2">
                <Input
                  className="font-mono"
                  placeholder="1.1.1.1:53, 8.8.8.8:53"
                  disabled={!writable || o.locked}
                  value={o.upstreamText || ''}
                  onChange={(e) => setO({ ...o, upstreamText: e.target.value })}
                  onBlur={() => save({ upstream: o.upstreamText || '' })}
                />
                <FieldDescription>Comma-separated IP[:port] addresses.</FieldDescription>
              </div>
            )}
          </Field>
          <ToggleRow
            title="Disable DNSSEC"
            description="Clears the DNSSEC OK bit on upstream queries; for resolvers without DNSSEC support."
            checked={o.disable_dnssec}
            writable={writable}
            locked={o.locked}
            onChange={(v) => save({ disable_dnssec: v })}
          />

          {/* ECS is a small cluster: master switch + mode + optional network */}
          <EcsCluster o={o} setO={setO} save={save} writable={writable} />

          <ToggleRow
            title="Compatibility mode"
            description="Domains that only have IPv4 still answer AAAA — synthesized v6 keeps broken IPv6 stacks from bypassing the resolver."
            checked={o.compat_mode}
            writable={writable}
            locked={o.locked}
            onChange={(v) => save({ compat_mode: v })}
          />

          {/* DNS64: switch + optional custom prefix */}
          <div>
            <ToggleRow
              title="DNS64"
              description="Synthesizes IPv6 addresses from IPv4 answers under a /96 prefix, for NAT64 networks."
              checked={o.dns64}
              writable={writable}
              locked={o.locked}
              onChange={(v) => save({ dns64: v })}
            />
            {o.dns64 && (
              <div className="mt-2 pl-4">
                <Input
                  className="w-72 font-mono"
                  placeholder="64:ff9b::/96"
                  disabled={!writable || o.locked}
                  value={o.dns64_prefix || ''}
                  onChange={(e) => setO({ ...o, dns64_prefix: e.target.value })}
                  onBlur={() => save({ dns64_prefix: o.dns64_prefix })}
                />
                <FieldDescription>Leave empty for the default 64:ff9b::/96.</FieldDescription>
              </div>
            )}
          </div>

          <ToggleRow
            title="CNAME flattening"
            description="Follows alias chains itself and hands the client plain record answers."
            checked={o.cname_flatten}
            writable={writable}
            locked={o.locked}
            onChange={(v) => save({ cname_flatten: v })}
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <LockIcon className="size-4 text-muted-foreground" /> Lock
          </CardTitle>
          <CardDescription>
            A locked profile ignores settings changes. Only an admin can lock (or unlock) it.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ToggleRow
            title="Locked"
            description="Prevents everything below — including this switch — from being changed by non-admins."
            checked={o.locked}
            writable={admin}
            locked={false}
            onChange={(v) => save({ locked: v }, v ? 'Profile locked.' : 'Profile unlocked.')}
          />
          {o.locked && admin && (
            <div className="mt-3">
              <Input
                placeholder="Message shown on this profile's pages (optional)"
                value={o.lock_message || ''}
                onChange={(e) => setO({ ...o, lock_message: e.target.value })}
                onBlur={() => save({ lock_message: o.lock_message })}
              />
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// EcsCluster: one master switch; when on, the mode select, and for the fixed
// mode the CIDR input.
function EcsCluster({ o, setO, save, writable }) {
  const on = o.ecs === 'client' || o.ecs === 'custom';
  return (
    <div className="rounded-lg border p-4">
      <ToggleRow
        title="EDNS Client Subnet"
        description="Lets upstream resolvers see roughly where the client is so CDN answers are nearby."
        checked={on}
        writable={writable}
        locked={o.locked}
        onChange={(v) => (v ? setO({ ...o, ecs: 'client' }) : save({ ecs: '' }))}
      />
      {on && (
        <div className="mt-3 grid gap-3 pl-4">
          <SimpleSelect
            value={o.ecs}
            options={ECS_MODES}
            disabled={!writable || o.locked}
            onChange={(v) => (v === 'custom' ? setO({ ...o, ecs: 'custom' }) : save({ ecs: 'client' }))}
          />
          {o.ecs === 'custom' && (
            <div>
              <Input
                className="w-72 font-mono"
                placeholder="203.0.113.0/24"
                disabled={!writable || o.locked}
                value={o.ecsText || ''}
                onChange={(e) => setO({ ...o, ecsText: e.target.value })}
                onBlur={() => save({ ecs: o.ecsText || '' })}
              />
              <FieldDescription>CIDR network sent in place of the client's.</FieldDescription>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function PauseCard({ writable, paused, onPause, onResume }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ClockIcon className="size-4 text-muted-foreground" /> Pause filtering
        </CardTitle>
        <CardDescription>Everything resolves unfiltered for this profile, without turning filtering off elsewhere.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-wrap items-center gap-2">
        {PAUSES.map((p) => (
          <Button key={p.seconds} variant="outline" disabled={!writable} onClick={() => onPause(p.seconds)}>
            {p.label}
          </Button>
        ))}
        <Button variant="ghost" size="sm" disabled={!writable || !paused} onClick={onResume}>
          Off
        </Button>
      </CardContent>
    </Card>
  );
}

function ToggleRow({ title, description, checked, writable, locked, onChange }) {
  const disabled = !writable || locked;
  return (
    <div className={cn('flex items-center justify-between gap-4 rounded-lg border p-4', disabled && 'opacity-60')}>
      <div className="grid gap-1">
        <span className="text-sm font-medium leading-none">{title}</span>
        <span className="text-xs text-muted-foreground">{description}</span>
      </div>
      <Switch checked={checked} disabled={disabled} onCheckedChange={onChange} />
    </div>
  );
}

function humanUntil(unix) {
  const left = Math.max(1, Math.round(unix - Date.now() / 1000));
  if (left < 90) return `${left} second${left === 1 ? '' : 's'}`;
  if (left < 5400) return `${Math.round(left / 60)} minutes`;
  if (left < 86400) return `${(left / 3600).toFixed(left % 3600 ? 1 : 0)} hours`;
  return `${Math.round(left / 86400)} days`;
}
