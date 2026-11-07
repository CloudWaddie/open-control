import { useEffect, useState } from 'react';
import { CheckIcon, CopyIcon, KeyRoundIcon } from 'lucide-react';
import { api } from '../api.js';
import { ErrorLine, Mono } from '../ui.jsx';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';

// ResolverDialog shows everything a device needs to use an endpoint: its
// resolver ID (the DoH/DoT token), the DoH URL and the DoT name. Tokens are
// device identifiers, so this stays open any time from the endpoints page.
export default function ResolverDialog({ endpoint, setup, onClose }) {
  const [token, setToken] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    setError('');
    setToken(endpoint?.token || '');
    if (endpoint && !endpoint.token) {
      api('GET', `/endpoints/${endpoint.id}/token`)
        .then((res) => setToken(res.token))
        .catch((e) => setError(e.message));
    }
  }, [endpoint]);

  if (!endpoint) return null;

  const host = setup?.host;
  const doh =
    host && setup?.doh
      ? `https://${host}${setup.doh_port !== 443 && setup.doh_port ? `:${setup.doh_port}` : ''}/dns-query/${token}`
      : `/dns-query/${token}`; // no public name configured yet
  const dot = host && setup?.dot ? `${token}.${host}` : null;

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <KeyRoundIcon className="size-4 text-primary" />
            Resolver IDs — {endpoint.name}
          </DialogTitle>
          <DialogDescription>
            Point a device at this endpoint with encrypted DNS. The token also stands in for its
            source addresses, so it works from any network.
          </DialogDescription>
        </DialogHeader>

        <ErrorLine error={error} onDismiss={() => setError('')} />

        <div className="flex flex-col gap-3">
          <CopyRow label="Resolver ID" value={token} />
          <CopyRow label="DNS over HTTPS" value={doh} mono={!!host} />
          {dot ? (
            <CopyRow label="DNS over TLS" value={dot} />
          ) : (
            host && <p className="text-xs text-muted-foreground">DoT needs a server name; it is not configured.</p>
          )}
        </div>

        {host || (
          <p className="text-xs text-muted-foreground">
            Set a public server name in the config (<Mono>public_host</Mono>) to see full DoH and DoT
            addresses here.
          </p>
        )}
      </DialogContent>
    </Dialog>
  );
}

function CopyRow({ label, value, mono }) {
  const [copied, setCopied] = useState(false);
  const canCopy = typeof navigator !== 'undefined' && !!navigator.clipboard && window.isSecureContext;

  async function copy() {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <div>
      <div className="mb-1 text-xs font-medium text-muted-foreground">{label}</div>
      <div className="flex items-center gap-2 rounded-lg border bg-background p-1 pl-3">
        <code
          className={`min-w-0 flex-1 text-sm break-all select-all ${mono ? 'font-mono' : 'font-mono lowercase'}`}
        >
          {value}
        </code>
        {canCopy && (
          <Button variant="ghost" size="icon-sm" aria-label={`Copy ${label}`} onClick={copy}>
            {copied ? <CheckIcon className="text-emerald-500" /> : <CopyIcon />}
          </Button>
        )}
      </div>
    </div>
  );
}
