import { useEffect, useState } from 'react';
import { CheckIcon, CopyIcon, GlobeIcon, LinkIcon, ShieldCheckIcon, StarIcon } from 'lucide-react';
import { api, can } from '../api.js';
import { ErrorLine, Mono, Tag } from '../ui.jsx';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';

// Setup shows how to point devices at each profile: the server's public
// address (if configured), every endpoint's resolver IDs, and which profile
// unrouted plain-DNS clients land on.
export default function Setup({ me }) {
  const [setup, setSetup] = useState(null);
  const [profiles, setProfiles] = useState(null);
  const [endpoints, setEndpoints] = useState(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const writable = can(me.role, 'operator');

  useEffect(() => {
    Promise.all([api('GET', '/setup'), api('GET', '/profiles'), api('GET', '/endpoints')])
      .then(([s, p, e]) => {
        setSetup(s);
        setProfiles(p);
        setEndpoints(e);
      })
      .catch((err) => setError(err.message));
  }, []);

  async function makeDefault(id) {
    setError('');
    try {
      await api('PUT', `/profiles/${id}/default`);
      setNotice('Default profile updated. Clients without an endpoint now use it.');
      // profiles list does not carry the flag; refetch to see the new default
      api('GET', '/profiles').then(setProfiles).catch(() => {});
    } catch (err) {
      setError(err.message);
    }
  }

  const host = setup?.host;
  const suffix = host ? (setup?.doh_port && setup.doh_port !== 443 ? `:${setup.doh_port}` : '') : '';

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Setup</h1>
        <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
          Point a device at any endpoint's resolver ID or DoH URL, and everything it resolves is
          filtered by that endpoint's profile. Everything below can be copied straight into the
          device.
        </p>
      </div>
      <ErrorLine error={error} onDismiss={() => setError('')} />
      {notice && (
        <Card>
          <CardContent className="flex items-center gap-2 py-3 text-sm text-ok">
            <ShieldCheckIcon className="size-4" /> {notice}
          </CardContent>
        </Card>
      )}

      {/* Public address state */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <GlobeIcon className="size-4 text-muted-foreground" /> Server address
          </CardTitle>
          <CardDescription>
            {host
              ? 'Public name this server is reachable at. Full DoH and DoT addresses below use it.'
              : 'No public name is configured yet — set public_host (and the DoH/DoT ports) in the config, then restart. Encryption-only endpoints still work by resolver ID on DoT/DoH-capable clients that accept IP addresses.'}
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 text-sm">
          {!setup ? (
            <Skeleton className="h-6 w-64" />
          ) : (
            <>
              <CopyOr label="Plain DNS" value={host ? `${host}` : undefined} missing="Not applicable without a public name." />
              <CopyOr label="DoH base URL" value={host && setup.doh ? `https://${host}${suffix}/dns-query/` : undefined} missing="DoH is not configured on this server." />
              <CopyOr label="DoT suffix" value={host && setup.dot ? `. resolves under ${tokenLabel(host)}` : undefined} missing="DoT is not configured on this server." />
            </>
          )}
        </CardContent>
      </Card>

      {/* Per-profile endpoint sheets */}
      {profiles?.map((p) => {
        const eps = (endpoints || []).filter((e) => e.profile_id === p.id);
        return (
          <Card key={p.id} className={cn(p.default && 'border-primary/40')}>
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle className="flex items-center gap-2">
                  {p.name}
                  {p.default && (
                    <Tag tone="healthy">
                      <StarIcon className="size-3" /> default
                    </Tag>
                  )}
                </CardTitle>
                <CardDescription>
                  {eps.length === 0
                    ? 'No endpoints on this profile yet — create one on the endpoints page.'
                    : `${eps.length} endpoint${eps.length === 1 ? '' : 's'}`}
                </CardDescription>
              </div>
              {writable && !p.default && (
                <Button variant="outline" size="sm" onClick={() => makeDefault(p.id)}>
                  <StarIcon /> Make default
                </Button>
              )}
            </CardHeader>
            <CardContent className="flex flex-col gap-4">
              {eps.map((e) => (
                <EndpointRows key={e.id} endpoint={e} host={host} setup={setup} />
              ))}
            </CardContent>
          </Card>
        );
      })}
      {!profiles && <Skeleton className="h-40 w-full" />}
    </div>
  );
}

function tokenLabel(host) {
  return `<token>.${host}`;
}

// EndpointRows: every copyable address of one endpoint, Control-D style.
function EndpointRows({ endpoint, host, setup }) {
  const t = endpoint.token;
  const doh = host && setup?.doh ? `https://${host}${setup.doh_port && setup.doh_port !== 443 ? `:${setup.doh_port}` : ''}/dns-query/${t}` : null;
  const dot = host && setup?.dot ? `${t}.${host}` : null;
  return (
    <div className="grid gap-2 rounded-lg border p-3">
      <div className="flex items-center justify-between text-sm font-medium">
        {endpoint.name}
        <span className="text-xs font-normal text-muted-foreground">
          CIDRs: <Mono className="text-xs">{endpoint.cidrs?.join(', ') || 'token-only'}</Mono>
        </span>
      </div>
      <CopyOr label="Resolver ID" value={t} />
      <CopyOr label="DNS over HTTPS" value={doh} missing="DoH is not configured on this server." />
      <CopyOr label="DNS over TLS" value={dot} missing="DoT is not configured on this server." />
    </div>
  );
}

// CopyOr: a copy row when there is something to show, an explanation if not.
function CopyOr({ label, value, missing }) {
  return <CopyField label={label} value={value} missingText={missing} />;
}

function CopyField({ label, value, missingText }) {
  const [copied, setCopied] = useState(false);
  if (!value) {
    return (
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <LinkIcon className="size-3.5" /> {label}: {missingText || 'not configured'}
      </div>
    );
  }
  return (
    <div className="flex items-center justify-between gap-3">
      <div className="min-w-0">
        <div className="text-xs text-muted-foreground">{label}</div>
        <Mono className="block truncate">{value}</Mono>
      </div>
      <Button
        variant="ghost"
        size="icon-sm"
        aria-label={`Copy ${label}`}
        className={cn(copied && 'text-ok')}
        onClick={() => navigator.clipboard?.writeText(value).then(() => setCopied(true)).catch(() => {})}
      >
        {copied ? <CheckIcon /> : <CopyIcon />}
      </Button>
    </div>
  );
}
